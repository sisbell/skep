//! The pre-pass's walk: the scenario replayed in shadow space under the
//! seeds inferred so far. Each play-pass handler's effect on the shadow is
//! restated here, in a `Sim::sim_<verb>` method named for its `h_<verb>`:
//! `create`'s, `write`'s and `link`'s writes and creations, and the reads'
//! register moves together with the whole-document comparisons their
//! handlers make (`sim_retrieve_contents`, `sim_observe`,
//! `sim_retrieve_vspanset`, `sim_retrieve_endsets`, `sim_find_documents`,
//! `sim_compare_versions`). Every content write is logged for the seed undo,
//! every content the play pass compares a document's whole content against
//! is probed against the shadow, and the macro forms' plans are built where
//! they stand. Nothing but review keeps a `sim_` method and its handler
//! alike: change them together.
//!
//! The walk reads each op through the grammar the play pass reads it
//! through (`fields`: the verb `normalize` names, which it dispatches on,
//! the document an op aims at, a vcopy's sources, a version's source and
//! names, a swap's regions, the documents a plural create makes, a probe's
//! recorded content), skips every op udanax never carried out
//! (`evidence::took_effect`), and decides what an op did by the
//! recorded-evidence policies the play pass applies (`evidence`: where an
//! insert or a vcopy lands, what a delete removed, what a read read); what
//! this module holds is the reconstruction alone. The corpus extension
//! records its own setup (MANIFEST-NEW), so its `probe` checkpoints seed
//! nothing ([`observes_state`]).

use std::collections::BTreeMap;

use serde_json::Value;

use super::cover::{
    comparison_pairs, cover_from_comparisons, cover_with_sources, has_later_copy_into,
    later_appends_text, SharedPair,
};
use super::{Edit, SetupStep};
use crate::evidence::{
    delete_is_noop, follow_landing, next_content_probe, reply_narrowing, resolve_delete_span,
    resolve_insert, scoped_read, took_effect, vcopy_destination, vcopy_ordinal,
};
use crate::fields::{
    aim_doc, arrow_results, as_text, compare_operands, created_addresses, cuts_of,
    distributed_insert_texts, distribution_targets, documents_created, endsets_in_link_space,
    field, is_conflict_copy, is_position_marker, locate, normalize, op_name, per_doc_replies,
    position_from_op_name, probed_content, quoted, recorded_content, recorded_count,
    recorded_spanset, resolve_position, role_vspan_count, span_dict, str_field, strings_of,
    swap_regions, target_replies, vcopy_sources, version_names, version_result, version_source,
    vspec_dict, DocAim, DocSpans, Probe, Verb, BUILD_BUDGET, CONTENT_READS,
};
use crate::shadow::Shadow;
use crate::tum::{link_home_docid, parse_vpos, parse_width, VPoint, VRegion};

/// One replay of the scenario: the shadow it built, each document's edit
/// log, the first probe it found contradicted, the empty documents links
/// were made over, and the plans the macro forms expanded to.
#[derive(Debug)]
pub(super) struct Sim {
    pub(super) shadow: Shadow,
    logs: BTreeMap<String, Vec<Edit>>,
    /// First probe whose expectation disagreed with the shadow this pass.
    pub(super) failed_probe: Option<(String, String)>,
    /// Docs that were empty while participating in a link op.
    pub(super) empty_link_participants: Vec<String>,
    pub(super) plans: BTreeMap<usize, Vec<SetupStep>>,
    /// The reconstruction strategy that produced each plan.
    pub(super) plan_strategies: BTreeMap<usize, &'static str>,
}

impl Sim {
    /// The shadow before op 0, as the play pass's `run_lead_in` leaves it:
    /// the implied creates, each seed inserted into its document (minted
    /// when no implied create made it), and the register on the first
    /// document created.
    fn new(implied: &[String], seeds: &BTreeMap<String, Vec<u8>>) -> Sim {
        let mut sim = Sim {
            shadow: Shadow::new(),
            logs: BTreeMap::new(),
            failed_probe: None,
            empty_link_participants: Vec::new(),
            plans: BTreeMap::new(),
            plan_strategies: BTreeMap::new(),
        };
        for d in implied {
            sim.shadow.create_doc(d, None);
        }
        for (d, bytes) in seeds {
            if !sim.shadow.knows(d) {
                sim.shadow.create_doc(d, None);
            }
            sim.shadow.insert(d, 1, bytes);
        }
        if let Some(first) = sim.shadow.created().first().cloned() {
            sim.shadow.set_current(&first);
        }
        sim
    }

    /// The scenario replayed in shadow space from scratch under `seeds` —
    /// the walk every inference round, and the final pass, take.
    pub(super) fn replay(
        implied: &[String],
        seeds: &BTreeMap<String, Vec<u8>>,
        ops: &[Value],
    ) -> Sim {
        let mut sim = Sim::new(implied, seeds);
        for (i, op) in ops.iter().enumerate() {
            sim.step(i, op, ops);
        }
        sim
    }

    fn apply_step(&mut self, step: &SetupStep) {
        // Insert/Copy contributions are RECORDED as edits: undo-based seed
        // inference must be able to walk back through plan-built content
        // (link_chain_with_transclusion: the embed plan builds B, a later
        // recorded insert appends, and the probe undo crosses both).
        match step {
            SetupStep::Insert { doc, bytes } => {
                if !self.shadow.knows(doc) {
                    self.shadow.create_doc(doc, None);
                }
                let end = self.shadow.text_len(doc) + 1;
                self.shadow.insert(doc, end, bytes);
                self.record(doc, Edit::Insert { at: None, bytes: bytes.clone() });
            }
            SetupStep::Copy { doc, src, ord, width } => {
                let bytes = self.shadow.slice(src, *ord, *width);
                if !self.shadow.knows(doc) {
                    self.shadow.create_doc(doc, None);
                }
                let end = self.shadow.text_len(doc) + 1;
                self.shadow.insert(doc, end, &bytes);
                self.record(doc, Edit::Insert { at: None, bytes });
            }
            SetupStep::Link { from, to: _, golden } => {
                // Home = the golden id's own prefix, else the FROM doc — the
                // home the play pass's setup step makes the link in.
                let home = golden
                    .as_ref()
                    .and_then(|g| link_home_docid(g))
                    .or_else(|| from.first().map(|(d, _, _)| d.clone()));
                if let Some(home) = home {
                    self.shadow.enter_link(&home, golden.as_deref());
                }
            }
        }
    }

    fn plan(&mut self, i: usize, steps: Vec<SetupStep>) {
        for s in &steps {
            self.apply_step(s);
        }
        self.plans.insert(i, steps);
    }

    /// A vcopy's expansion plan, carried out as the play pass's `h_vcopy`
    /// carries out a planned vcopy: each target the op lists made sure of
    /// first ([`Sim::ensure_document`]: one the shadow holds becomes the
    /// register, any other is minted), then the plan's steps, then each
    /// target's recorded contents probed whole (`fields::target_replies`).
    fn plan_vcopy(&mut self, i: usize, op: &Value, steps: Vec<SetupStep>) {
        let targets = field(op, &["targets"]).and_then(Value::as_array);
        for t in targets.into_iter().flatten() {
            if let Some(id) = t.as_str().or_else(|| t.get("docid").and_then(Value::as_str)) {
                self.ensure_document(id, None);
            }
        }
        self.plan(i, steps);
        for (doc, strings) in target_replies(op, &self.shadow) {
            if let Some(text) = as_text(&strings) {
                self.probe(&doc, &text);
            }
        }
    }

    /// Probe `doc` with the content `op` records as a probe of `kind`
    /// (`fields::probed_content`) — what the play pass's `probe_state`
    /// compares the document's whole content against.
    fn probe_recorded(&mut self, doc: &str, op: &Value, kind: Probe) {
        if let Some(text) = probed_content(op, kind).and_then(|(_, s)| as_text(&s)) {
            self.probe(doc, &text);
        }
    }

    pub(super) fn log_for(&self, doc: &str) -> &[Edit] {
        self.logs.get(doc).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Record edit `e` in `doc`'s log — when the shadow holds `doc`. An edit
    /// of a document the shadow does not hold changes nothing (`Shadow`'s
    /// edit mirror), so its log stays as empty as its text.
    fn record(&mut self, doc: &str, e: Edit) {
        if self.shadow.knows(doc) {
            self.logs.entry(doc.to_string()).or_default().push(e);
        }
    }

    /// The op's document, read as the play pass's `Cx::doc_arg` reads it
    /// (`fields::aim_doc`). An explicit reference that resolves to nothing
    /// aims at nothing: the op changes nothing here, as it executes nothing
    /// there.
    fn doc_arg(&mut self, op: &Value, keys: &[&str]) -> Option<String> {
        match aim_doc(&mut self.shadow, op, keys) {
            DocAim::Named(d) | DocAim::FromOpName(d) | DocAim::Register(d) => Some(d),
            DocAim::Unresolved(_) => None,
            DocAim::FirstTouch => {
                // A scenario whose opening op needs a document before any
                // create (endsets/endsets_after_pivot) — create one, exactly
                // as the play pass will.
                let id = self.shadow.synthesize_docid();
                self.shadow.create_doc(&id, None);
                Some(id)
            }
        }
    }

    /// Op `i` restated on the shadow as the play-pass handler `run_op`
    /// dispatches it to plays it: each write's content effect, each
    /// creation, each read's register move, and each whole-document
    /// comparison the handler makes, probed AFTER the op's own edit, never
    /// before — a write's own result expectation compared against the
    /// pre-edit state would forge a false seed. The op dispatches on the
    /// verb the play pass dispatches on (`fields::normalize`), so the two
    /// passes cannot disagree about what kind of op a name reads as; one
    /// udanax never carried out (`evidence::took_effect`) changes nothing,
    /// and one the play pass plays nothing for — no `op` field, a raw wire
    /// request — is read as nothing. A drift between this and the play
    /// pass is never an honest divergence: the lead-in and plans this walk
    /// builds would run against a world the play pass never aims at, and
    /// the difference would read as skep's.
    fn step(&mut self, i: usize, op: &Value, ops: &[Value]) {
        if !took_effect(op) || op_name(op).is_empty() || op_name(op) == "raw_request" {
            return;
        }
        let name = op_name(op).to_ascii_lowercase();
        let Some(verb) = normalize(&name, op) else { return };
        match verb {
            Verb::CreateChain => self.sim_create_chain(i, op, ops),
            Verb::CreateDocuments => self.sim_create_documents(i, op, ops),
            Verb::Setup => {
                if let Some(steps) = self.expand_keyed_setup(op, i, ops) {
                    self.plan(i, steps);
                } else if let Some(desc) = str_field(op, &["description", "desc"]) {
                    if let Some(steps) = self.expand_setup_description(desc) {
                        self.plan(i, steps);
                    }
                }
            }
            Verb::CreateDocument => self.sim_create_document(op),
            Verb::OpenDocument => self.sim_open_document(op),
            Verb::CreateVersion => self.sim_create_version(op),
            Verb::InteriorTyping => self.sim_interior_typing(op),
            Verb::InsertLoop => self.sim_insert_loop(op),
            Verb::Insert => self.sim_insert(i, op, ops),
            Verb::DeleteAll => self.sim_delete_all(i, op, ops),
            Verb::Delete => self.sim_delete(i, op, ops),
            Verb::Vcopy if name.starts_with("vcopy_to_multiple") => {
                self.sim_vcopy_to_multiple(i, op)
            }
            Verb::Vcopy if name.starts_with("create_and_transclude") => {
                self.sim_create_and_transclude(i, op)
            }
            Verb::Vcopy => self.sim_vcopy(i, op, ops, &name),
            Verb::Pivot | Verb::Swap | Verb::Rearrange => self.sim_rearrange(op, verb),
            Verb::CreateLink => self.sim_create_link(op),
            Verb::RetrieveContents => {
                for (doc, text) in self.sim_retrieve_contents(i, op, ops) {
                    self.probe(&doc, &text);
                }
            }
            Verb::Observe => self.sim_observe(i, op, ops, &name),
            Verb::RetrieveVspan | Verb::RetrieveVspanset => self.sim_retrieve_vspanset(op),
            Verb::RetrieveEndsets => self.sim_retrieve_endsets(op),
            Verb::FindDocuments => self.sim_find_documents(op),
            Verb::CompareVersions => self.sim_compare_versions(op),
            // Their handlers change nothing on the shadow.
            Verb::FindLinks
            | Verb::FollowLink
            | Verb::Traverse
            | Verb::CloseDocument
            | Verb::Meta
            | Verb::Account
            | Verb::Connect
            | Verb::CreateNode => {}
        }
    }

    /// Golden document `id`, for an op that records it, as the play pass's
    /// `ensure_document` makes it: one the shadow already holds — an implied
    /// create, or a plan's earlier step — is named `name` and made the
    /// register; any other is minted under `name`.
    fn ensure_document(&mut self, id: &str, name: Option<&str>) {
        if self.shadow.knows(id) {
            if let Some(n) = name {
                self.shadow.bind_name(n, id);
            }
            self.shadow.set_current(id);
        } else {
            self.shadow.create_doc(id, name);
        }
    }

    fn sim_create_document(&mut self, op: &Value) {
        let name = crate::fields::create_name_of(op);
        let ids = created_addresses(op).unwrap_or_else(|| vec![self.shadow.synthesize_docid()]);
        for (k, id) in ids.iter().enumerate() {
            // The op's name names its first document.
            self.ensure_document(id, if k == 0 { name.as_deref() } else { None });
        }
    }

    fn sim_open_document(&mut self, op: &Value) {
        if let Some(doc) = self.doc_arg(op, &["doc", "docid", "document"]) {
            if is_conflict_copy(op) {
                // A result the shadow already holds names another document,
                // which the fork never overwrites.
                if let Some(res) = str_field(op, &["result"]).filter(|r| !self.shadow.knows(r)) {
                    self.shadow.version(&doc, res, &[]);
                }
            } else {
                self.shadow.set_current(&doc);
            }
        }
    }

    fn sim_create_version(&mut self, op: &Value) {
        let src = version_source(op, &self.shadow, &mut Vec::new());
        let (Some(src), Some(res)) = (src, version_result(op)) else { return };
        // A result the shadow already holds names another document: the
        // version neither overwrites nor renames it.
        if self.shadow.knows(&res) {
            return;
        }
        self.shadow.version(&src, &res, &version_names(op));
    }

    fn sim_interior_typing(&mut self, op: &Value) {
        let Some(doc) = self.doc_arg(op, &["doc", "docid"]) else { return };
        if let Some(results) = field(op, &["results"]).and_then(Value::as_array) {
            for r in results {
                let (Some(ch), Some(pos)) = (
                    r.get("char").and_then(Value::as_str),
                    r.get("position").and_then(Value::as_str),
                ) else {
                    continue;
                };
                let at = resolve_position(&self.shadow, &doc, pos).map(|(at, _)| at);
                if let Some(VPoint { sub: 1, ord }) = at {
                    self.shadow.insert(&doc, ord, ch.as_bytes());
                    let bytes = ch.as_bytes().to_vec();
                    self.record(&doc, Edit::Insert { at: Some(ord), bytes });
                    // Each grounded step's own probe, as `h_interior_typing`
                    // compares it; a step that does not ground compares
                    // nothing.
                    self.probe_recorded(&doc, r, Probe::Step);
                } else {
                    self.record(&doc, Edit::Opaque);
                }
            }
        }
    }

    fn sim_insert_loop(&mut self, op: &Value) {
        let Some(doc) = self.doc_arg(op, &["doc", "docid"]) else { return };
        // A count past the build budget, or none at all, is an op the play
        // pass refuses, so its bytes are never built here either; the write
        // udanax made is unknown to the walk, and no undo crosses it.
        let Ok(Some(count)) = recorded_count(op) else {
            self.record(&doc, Edit::Opaque);
            return;
        };
        let bytes: Vec<u8> = (0..count).map(|k| b'A' + (k % 26) as u8).collect();
        let end = self.shadow.text_len(&doc) + 1;
        self.shadow.insert(&doc, end, &bytes);
        self.record(&doc, Edit::Insert { at: None, bytes });
        self.probe_recorded(&doc, op, Probe::PostWrite);
    }

    fn sim_insert(&mut self, i: usize, op: &Value, ops: &[Value]) {
        // insert_all + texts: one text per created doc, in creation order
        // (links/link_chain_three_hops fills its four documents through one
        // op) — never a single concatenated insert.
        if let Some(texts) = distributed_insert_texts(op) {
            let docs: Vec<String> = distribution_targets(&self.shadow, texts.len());
            for (d, t) in docs.iter().zip(&texts) {
                let end = self.shadow.text_len(d) + 1;
                self.shadow.insert(d, end, t.as_bytes());
                self.record(d, Edit::Insert { at: None, bytes: t.as_bytes().to_vec() });
            }
            return;
        }
        // Where the insert lands — re-aim, position, recorded-vspanset pad
        // — is the one reading the play pass applies
        // (`evidence::resolve_insert`). An insert that reading cannot place
        // changes nothing, as it executes nothing in the play pass.
        let Some(doc) = self.doc_arg(op, &["doc", "docid"]) else { return };
        let Ok(landing) = resolve_insert(ops, i, &self.shadow, &doc, &mut Vec::new()) else {
            self.record(&doc, Edit::Opaque);
            return;
        };
        if landing.doc != doc {
            self.shadow.set_current(&landing.doc);
        }
        // A link-subspace insert has no content effect; its post-state is
        // compared all the same.
        if landing.at.sub == 1 {
            self.shadow.insert(&landing.doc, landing.at.ord, &landing.bytes);
            let at = (!landing.appended).then_some(landing.at.ord);
            self.record(&landing.doc, Edit::Insert { at, bytes: landing.bytes });
        }
        self.probe_recorded(&landing.doc, op, Probe::PostWrite);
    }

    fn sim_delete_all(&mut self, i: usize, op: &Value, ops: &[Value]) {
        let Some(doc) = self.doc_arg(op, &["doc", "docid"]) else { return };
        if delete_is_noop(ops, i, &self.shadow, &doc) {
            return; // recorded post-state shows udanax removed nothing
        }
        let n = self.shadow.text_len(&doc);
        if n == 0 {
            return; // an empty document: the play pass deletes nothing
        }
        let bytes = self.shadow.slice(&doc, 1, n);
        self.shadow.delete(&doc, 1, n);
        self.record(&doc, Edit::Delete { at: 1, bytes: Some(bytes), explicit: true });
        self.probe_recorded(&doc, op, Probe::PostWrite);
    }

    fn sim_delete(&mut self, i: usize, op: &Value, ops: &[Value]) {
        let Some(doc) = self.doc_arg(op, &["doc", "docid"]) else { return };
        if delete_is_noop(ops, i, &self.shadow, &doc) {
            return; // recorded post-state shows udanax removed nothing
        }
        if let Some((VRegion { ord, width: w, .. }, how)) =
            resolve_delete_span(ops, i, &self.shadow, &doc)
        {
            // Bytes removed: the sim slice when it covers the whole width,
            // else the op's own DESCRIPTION of the removed text (the
            // "(CDEFG)" parenthetical, a quoted 'Shared ') at exactly that
            // width — the sim's state cannot cover it until a seed is in
            // place. Knowing neither, the delete is recorded as removing
            // bytes the walk never knew, and no undo crosses it.
            let slice = self.shadow.slice(&doc, ord, w);
            let bytes = if slice.len() as u64 == w {
                Some(slice)
            } else {
                delete_described_bytes(op, w)
            };
            self.shadow.delete(&doc, ord, w);
            self.record(&doc, Edit::Delete { at: ord, bytes, explicit: how.position_pinned() });
        } else {
            // A content delete this grammar cannot place is one the play
            // pass finds inexpressible: the write udanax made is unknown, and
            // nothing is compared after it. A link-subspace delete has no
            // content effect, and its post-state is compared.
            let start = str_field(op, &["start", "address", "at"]).and_then(parse_vpos);
            if start.is_none_or(|at| at.sub == 1) {
                self.record(&doc, Edit::Opaque);
                return;
            }
        }
        self.probe_recorded(&doc, op, Probe::PostWrite);
    }

    fn sim_create_and_transclude(&mut self, i: usize, op: &Value) {
        let src = self.shadow.resolve_doc("source").or_else(|| self.shadow.current());
        let Some(src) = src else { return };
        let n = self.shadow.text_len(&src);
        if let Some(targets) = field(op, &["targets"]).and_then(Value::as_array) {
            let steps = targets
                .iter()
                .filter_map(Value::as_str)
                .map(|t| SetupStep::Copy { doc: t.to_string(), src: src.clone(), ord: 1, width: n })
                .collect();
            self.plan_vcopy(i, op, steps);
        }
    }

    /// Pivot (three cuts) or swap (four), as the verb names it; a bare
    /// `rearrange` takes its shape from its cut count.
    fn sim_rearrange(&mut self, op: &Value, verb: Verb) {
        let Some(doc) = self.doc_arg(op, &["doc", "docid"]) else { return };
        let mut cuts = cuts_of(op);
        if cuts.is_empty() && verb == Verb::Swap {
            // Two texts to exchange, read as the play pass reads them
            // (`fields::swap_regions`).
            cuts = swap_regions(op, &self.shadow, &doc, &mut Vec::new()).unwrap_or_default();
        }
        match (verb, cuts.as_slice()) {
            (Verb::Pivot | Verb::Rearrange, &[a, b, c]) => {
                self.shadow.pivot(&doc, a, b, c);
                self.record(&doc, Edit::Pivot { a, b, c });
            }
            (Verb::Swap | Verb::Rearrange, &[s1, e1, s2, e2]) => {
                self.shadow.swap(&doc, s1, e1, s2, e2);
                self.record(&doc, Edit::Swap { s1, e1, s2, e2 });
            }
            _ => self.record(&doc, Edit::Opaque),
        }
    }

    fn sim_create_link(&mut self, op: &Value) {
        let mut participants: Vec<String> = Vec::new();
        for keys in [&["source", "from"][..], &["target", "to"][..]] {
            if let Some(s) = str_field(op, keys) {
                if let Some(d) = self.shadow.resolve_doc(s) {
                    participants.push(d);
                }
            }
        }
        for role in ["source", "target"] {
            if let Some(d) = self.shadow.resolve_doc(role) {
                if !participants.contains(&d) {
                    participants.push(d);
                }
            }
        }
        for d in participants {
            if self.shadow.text_len(&d) == 0 && !self.empty_link_participants.contains(&d) {
                self.empty_link_participants.push(d);
            }
        }
        let results: Vec<String> = match field(op, &["result", "results", "link_id"]) {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(a)) => {
                a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
            }
            _ => arrow_results(op).into_iter().map(|(_, _, r)| r).collect(),
        };
        // Each recorded link enters at the home its id names, as the play
        // pass's `Cx::make_link` enters it: a home no op made stays unmade,
        // where the play pass, finding no α-image there, makes no link.
        for r in &results {
            if let Some(home) = link_home_docid(r) {
                self.shadow.enter_link(&home, Some(r));
            }
        }
        for (f, t, r) in arrow_results(op) {
            self.shadow.add_arrow(&f, &t, &r);
        }
    }

    /// A content read, restated from `play::read::h_retrieve_contents`: its
    /// register moves — the op's document (`doc_arg`), a reply's link home,
    /// the last-written document a `full_*` probe naming none reads — and the
    /// (document, recorded text) pairs it compares a document's whole content
    /// against, for the caller to probe with. A read the handler narrows — a
    /// `positions` map, a spec set, a span, a follow's landing
    /// (`evidence::follow_landing`), a position, a reply the script read
    /// narrower (`evidence::scoped_read`, `evidence::reply_narrowing`) —
    /// compares no whole document, and tells no seed.
    fn sim_retrieve_contents(
        &mut self,
        i: usize,
        op: &Value,
        ops: &[Value],
    ) -> Vec<(String, String)> {
        let whole = |doc: String, strings: &[String]| as_text(strings).map(|text| (doc, text));
        if let Some(map) = op.get("docs").and_then(Value::as_object) {
            return map
                .iter()
                .filter_map(|(name, exp)| whole(self.shadow.resolve_doc(name)?, &strings_of(exp)?))
                .collect();
        }
        let targets = target_replies(op, &self.shadow);
        if !targets.is_empty() {
            return targets.into_iter().filter_map(|(doc, strings)| whole(doc, &strings)).collect();
        }
        let replies = per_doc_replies(op, &self.shadow);
        if !replies.is_empty() {
            return replies
                .into_iter()
                .filter(|(_, doc, strings)| reply_narrowing(strings, &self.shadow, doc).is_none())
                .filter_map(|(_, doc, strings)| whole(doc, &strings))
                .collect();
        }
        if op.get("positions").and_then(Value::as_object).is_some() {
            self.doc_arg(op, &["doc", "docid"]);
            return Vec::new();
        }
        let strings = recorded_content(op, CONTENT_READS).map(|(_, strings)| strings);
        // A reply naming a link address names its home: the register moves
        // there.
        let home = strings.iter().flatten().find_map(|s| link_home_docid(s));
        if let Some(home) = home.filter(|h| self.shadow.knows(h)) {
            self.shadow.set_current(&home);
        }
        if field(op, &["specset", "specs"]).and_then(Value::as_array).is_some()
            || str_field(op, &["specset"]).is_some()
        {
            return Vec::new(); // a spec set names its own regions
        }
        if field(op, &["span", "spans", "vspan"]).is_some() {
            self.doc_arg(op, &["doc", "docid"]);
            return Vec::new(); // a narrowing span reads part of its document
        }
        if follow_landing(ops, i).is_some() {
            return Vec::new(); // the follow's landing, read narrow
        }
        let full = op_name(op).to_ascii_lowercase().starts_with("full_");
        let last_written = self.shadow.last_written().map(str::to_string);
        let doc = match last_written {
            Some(d) if full && str_field(op, &["doc", "docid"]).is_none() => {
                self.shadow.set_current(&d);
                Some(d)
            }
            _ => self.doc_arg(op, &["doc", "docid"]),
        };
        let Some(doc) = doc else { return Vec::new() };
        if str_field(op, &["address", "at", "position"]).and_then(parse_vpos).is_some()
            || position_from_op_name(op_name(op)).is_some()
        {
            return Vec::new(); // one position, read narrow
        }
        let Some(strings) = strings else { return Vec::new() };
        if scoped_read(&strings, &self.shadow, &doc).is_some() {
            return Vec::new(); // a narrower extent the script read
        }
        whole(doc, &strings).into_iter().collect()
    }

    /// An observation bundle, restated from `play::read::h_observe`: one
    /// recording several documents is a content read
    /// ([`Sim::sim_retrieve_contents`]); any other aims at the op's document
    /// and compares it whole with the bundle's reply. The walk probes the
    /// shadow with a bundle only when its name says it observes a state
    /// ([`observes_state`]).
    fn sim_observe(&mut self, i: usize, op: &Value, ops: &[Value], name: &str) {
        let several = op.get("docs").and_then(Value::as_object).is_some()
            || op.get("targets").and_then(Value::as_array).is_some()
            || op.get("positions").and_then(Value::as_object).is_some()
            || !per_doc_replies(op, &self.shadow).is_empty();
        let compared = if several {
            self.sim_retrieve_contents(i, op, ops)
        } else {
            let Some(doc) = self.doc_arg(op, &["doc", "docid"]) else { return };
            let text = probed_content(op, Probe::Bundle).and_then(|(_, s)| as_text(&s));
            text.map(|text| (doc, text)).into_iter().collect()
        };
        if observes_state(name) {
            for (doc, text) in compared {
                self.probe(&doc, &text);
            }
        }
    }

    /// A vspan or vspanset probe, restated from `play::read::
    /// h_retrieve_vspanset`: the register moves to the document its recorded
    /// span set names, else to the one a `<role>_vspan_count` counts
    /// (`fields::role_vspan_count`), else to the op's own. It compares no
    /// content.
    fn sim_retrieve_vspanset(&mut self, op: &Value) {
        let named = recorded_spanset(op).and_then(|(_, d, _)| self.shadow.resolve_doc(&d?));
        let role_doc = match role_vspan_count(op) {
            Some((role, _)) => match self.shadow.resolve_doc(role) {
                Some(d) => Some(d),
                None => return, // a role naming no document aims nowhere
            },
            None => None,
        };
        if let Some(doc) = named.or(role_doc).or_else(|| self.doc_arg(op, &["doc", "docid"])) {
            self.shadow.set_current(&doc);
        }
    }

    /// A retrieve_endsets, restated from `play::find::h_retrieve_endsets`: a
    /// query in the link's own space (`fields::endsets_in_link_space`) moves
    /// nothing; a region query moves the register to the document it
    /// searches — its search's first document, else the op's own. It
    /// compares no content.
    fn sim_retrieve_endsets(&mut self, op: &Value) {
        if endsets_in_link_space(op) {
            return;
        }
        let doc = match field(op, &["search", "specs", "specset"]).and_then(Value::as_array) {
            Some(search) => {
                let specs: Option<Vec<DocSpans>> = search.iter().map(vspec_dict).collect();
                specs.and_then(|specs| specs.into_iter().next()).map(|(docid, _)| docid)
            }
            None => self.doc_arg(op, &["doc", "docid"]),
        };
        if let Some(doc) = doc {
            self.shadow.set_current(&doc);
        }
    }

    /// A find_documents, restated from `play::find::h_find_documents`: a
    /// search the op spells out — a spec set, a region, a query text — moves
    /// nothing; a `search_from` document becomes the register; a bare search
    /// aims as its handler's bare aim does — the op's document, else the
    /// source-role document, else the register's. It compares no content.
    fn sim_find_documents(&mut self, op: &Value) {
        if field(op, &["specset", "specs", "search", "regions"]).is_some()
            || str_field(op, &["query", "search_text", "text"]).is_some()
        {
            return;
        }
        if let Some(s) = str_field(op, &["search_from", "search_doc", "search_document"]) {
            if let Some(d) = self.shadow.resolve_doc(s) {
                self.shadow.set_current(&d);
            }
            return;
        }
        if str_field(op, &["doc", "docid"]).is_none() {
            if let Some(d) = self.shadow.find_named_containing("source") {
                self.shadow.set_current(&d);
                return;
            }
        }
        self.doc_arg(op, &["doc", "docid"]);
    }

    /// A compare_versions, restated from `play::correspondence::
    /// h_compare_versions`: only a compare of identity among one document's
    /// positions — a `positions` list with a `results` map, and neither two
    /// explicit operands (`fields::compare_operands`) nor a per-source
    /// comparison list before it — aims at the op's document (`doc_arg`);
    /// every other compare names its documents and moves nothing. It
    /// compares no content.
    fn sim_compare_versions(&mut self, op: &Value) {
        let per_source = field(op, &["results", "comparisons"])
            .and_then(Value::as_array)
            .is_some_and(|e| !e.is_empty() && e.iter().all(|e| e.get("shared").is_some()));
        let identity_pairs = field(op, &["positions"]).and_then(Value::as_array).is_some()
            && field(op, &["results"]).and_then(Value::as_object).is_some();
        if compare_operands(op).len() != 2 && !per_source && identity_pairs {
            self.doc_arg(op, &["doc", "docid"]);
        }
    }

    fn sim_create_documents(&mut self, i: usize, op: &Value, ops: &[Value]) {
        // The documents the op makes, read as the play pass reads them
        // (`fields::documents_created`); a count past the build budget is an
        // op the play pass refuses, so nothing is created here either.
        let Ok(created) = documents_created(op) else { return };
        let counted = created.counted;
        let mut created_empty: Vec<String> = Vec::new();
        for doc in created.docs {
            let id = doc.id.unwrap_or_else(|| self.shadow.synthesize_docid());
            let mut names = doc.names.iter();
            self.ensure_document(&id, names.next().map(String::as_str));
            for name in names {
                self.shadow.bind_name(name, &id);
            }
            match doc.text {
                Some(t) => {
                    self.shadow.insert(&id, 1, t.as_bytes());
                    self.record(&id, Edit::Insert { at: Some(1), bytes: t.into_bytes() });
                }
                None if counted => created_empty.push(id),
                None => {}
            }
        }
        // World-construction completeness (round-3): a counted doc created
        // empty whose later probe records content gets a cover plan — shared
        // regions as real copies from the docs that already hold them, so
        // the transclusions the scenario descriptions imply actually exist
        // (identity_multi_document_sharing expects five docs SHARING).
        let mut steps: Vec<SetupStep> = Vec::new();
        for id in created_empty {
            let Some(expected) = next_content_probe(ops, i, &self.shadow, &id) else { continue };
            let sources = self.shadow.content_docs_except(&id);
            let cover = cover_from_comparisons(&self.shadow, &id, &expected, ops)
                .unwrap_or_else(|| cover_with_sources(&self.shadow, &id, &sources, &expected));
            for s in &cover {
                self.apply_step(s);
            }
            steps.extend(cover);
        }
        if !steps.is_empty() {
            self.plans.insert(i, steps);
        }
    }

    /// `create_chain` (identity/find_documents_transitive): docs created in
    /// golden-id order; each doc's content is reconstructed from the next
    /// docs-map probe, with substrings shared with ALREADY-BUILT chain docs
    /// as real copies (transitive identity preserved).
    fn sim_create_chain(&mut self, i: usize, op: &Value, ops: &[Value]) {
        let Some(map) = op.get("docs").and_then(Value::as_object) else { return };
        let mut by_id: Vec<(String, String)> = map
            .iter()
            .filter_map(|(n, id)| id.as_str().map(|i| (i.to_string(), n.clone())))
            .collect();
        by_id.sort();
        for (id, name) in &by_id {
            self.ensure_document(id, Some(name));
        }
        let mut steps: Vec<SetupStep> = Vec::new();
        let mut built: Vec<String> = Vec::new();
        for (id, name) in &by_id {
            let Some(expected) = next_docs_map_probe(ops, i, name) else {
                built.push(id.clone());
                continue;
            };
            let cover = cover_with_sources(&self.shadow, id, &built, &expected);
            for s in &cover {
                self.apply_step(s);
            }
            steps.extend(cover);
            built.push(id.clone());
        }
        self.plans.insert(i, steps);
    }

    /// Keyed setup (subspace/insert_text_check_both_link_positions):
    /// `doc1_text: "ABCDE", doc2_text: "12345", link: "doc1[1.2-1.4] ->
    /// doc2[1.2-1.4]", link_id: "…"` — each `<name>_text` key creates a doc
    /// bound to `<name>` and inserts its text; the `link` spec grounds both
    /// endsets against the just-built content, then a later recorded follow
    /// result for the same link id (the golden's own evidence of the exact
    /// endset extent) overrides the spec-derived spans. `None` when the op
    /// carries no `<name>_text` keys (the clause grammar then gets its turn).
    fn expand_keyed_setup(
        &mut self,
        op: &Value,
        i: usize,
        ops: &[Value],
    ) -> Option<Vec<SetupStep>> {
        let o = op.as_object()?;
        // Both spellings occur: `<name>_text` (insert_text_check_both_link_
        // positions) and `text_<name>` (createlink_check_text_positions).
        let mut texts: Vec<(String, String)> = o
            .iter()
            .filter_map(|(k, v)| {
                let name = k.strip_suffix("_text").or_else(|| k.strip_prefix("text_"))?;
                Some((name.to_string(), v.as_str()?.to_string()))
            })
            .collect();
        if texts.is_empty() {
            return None;
        }
        texts.sort();
        let mut steps: Vec<SetupStep> = Vec::new();
        let mut trial = self.shadow.clone();
        for (name, text) in &texts {
            let golden = trial
                .resolve_doc(name)
                .filter(|g| trial.knows(g))
                .unwrap_or_else(|| trial.synthesize_docid());
            if trial.knows(&golden) {
                trial.bind_name(name, &golden);
                self.shadow.bind_name(name, &golden);
            } else {
                trial.create_doc(&golden, Some(name));
                self.shadow.create_doc(&golden, Some(name));
            }
            trial.insert(&golden, 1, text.as_bytes());
            steps.push(SetupStep::Insert { doc: golden, bytes: text.as_bytes().to_vec() });
        }
        if let Some(spec) = str_field(op, &["link", "links"]) {
            if let Some((f, t)) = spec.split_once("->") {
                let ground_side = |shadow: &Shadow, side: &str| -> Option<(String, u64, u64)> {
                    let side = side.trim();
                    if let Some(l) = locate(shadow, None, side) {
                        return Some((l.doc, l.ord, l.width));
                    }
                    let doc = shadow.resolve_doc(side)?;
                    let n = shadow.text_len(&doc);
                    (n > 0).then_some((doc, 1, n))
                };
                let golden_link = str_field(op, &["link_id", "result"]).map(str::to_string);
                let sides = (ground_side(&trial, f), ground_side(&trial, t));
                if let (Some(mut fs), Some(mut ts)) = sides {
                    // Follow-result evidence: a later op recording this
                    // link's spans pins the side whose doc it names.
                    if let Some(g) = &golden_link {
                        for later in &ops[i + 1..] {
                            let mentions =
                                str_field(later, &["link", "link_id", "id"]) == Some(g.as_str());
                            if !mentions {
                                continue;
                            }
                            let Some(v) = field(later, &["result"]) else { continue };
                            let Some((Some(doc), spans)) = crate::fields::raw_spanset_of(v) else {
                                continue;
                            };
                            let Some((start, width)) = spans.first() else { continue };
                            let (Some(VPoint { sub: 1, ord }), Some(w)) =
                                (parse_vpos(start), parse_width(width))
                            else {
                                continue;
                            };
                            for side in [&mut fs, &mut ts] {
                                if side.0 == doc {
                                    *side = (doc.clone(), ord, w);
                                }
                            }
                            break;
                        }
                    }
                    steps.push(SetupStep::Link {
                        from: vec![fs],
                        to: vec![ts],
                        golden: golden_link,
                    });
                }
            }
        }
        Some(steps)
    }

    /// "C='ABCDEFGHIJ', B=vcopy(C), A=vcopy('DEFGH' from B)" — clauses
    /// resolved IN ORDER against the evolving shadow, so each copy's
    /// (ord, width) is concrete by the time it is emitted.
    fn expand_setup_description(&mut self, desc: &str) -> Option<Vec<SetupStep>> {
        let mut steps = Vec::new();
        let mut trial = self.shadow.clone();
        for clause in desc.split(',') {
            let clause = clause.trim();
            let (name, rhs) = clause.split_once('=')?;
            let (name, rhs) = (name.trim(), rhs.trim());
            let doc = trial.resolve_doc(name)?;
            let step = if let Some(q) = rhs.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')) {
                SetupStep::Insert { doc: doc.clone(), bytes: q.as_bytes().to_vec() }
            } else {
                let inner = rhs.strip_prefix("vcopy(")?.strip_suffix(')')?;
                if let Some((text, srcref)) = inner.split_once(" from ") {
                    let text = text.trim().trim_matches('\'');
                    let src = trial.resolve_doc(srcref.trim())?;
                    let (_, ord) = trial.find_text(Some(&src), text)?;
                    SetupStep::Copy { doc: doc.clone(), src, ord, width: text.len() as u64 }
                } else {
                    let src = trial.resolve_doc(inner.trim())?;
                    let n = trial.text_len(&src);
                    SetupStep::Copy { doc: doc.clone(), src, ord: 1, width: n }
                }
            };
            // Apply to the trial shadow so later clauses see earlier effects.
            match &step {
                SetupStep::Insert { doc, bytes } => {
                    let end = trial.text_len(doc) + 1;
                    trial.insert(doc, end, bytes);
                }
                SetupStep::Copy { doc, src, ord, width } => {
                    let bytes = trial.slice(src, *ord, *width);
                    let end = trial.text_len(doc) + 1;
                    trial.insert(doc, end, &bytes);
                }
                SetupStep::Link { .. } => {} // clause grammar never emits links
            }
            steps.push(step);
        }
        Some(steps)
    }

    fn sim_vcopy_to_multiple(&mut self, i: usize, op: &Value) {
        let src_span = field(op, &["source_span"]).and_then(span_dict);
        let src = self
            .shadow
            .current()
            .filter(|d| self.shadow.text_len(d) > 0)
            .or_else(|| self.shadow.content_docs_except("").first().cloned());
        let (Some(VRegion { sub: 1, ord, width: w }), Some(src)) = (src_span, src) else { return };
        let copied = self.shadow.slice(&src, ord, w);
        let Some(targets) = field(op, &["targets"]).and_then(Value::as_array) else { return };
        // Each target is built by plan steps — a prefix its recorded contents
        // show ahead of the copy, then the copy — carried out as the play
        // pass carries out a planned vcopy ([`Sim::plan_vcopy`]), recorded
        // edits included: a target the shadow does not hold yet is minted
        // first, one an implied create made is built where it stands.
        let copied_text = String::from_utf8_lossy(&copied).into_owned();
        let mut steps = Vec::new();
        for t in targets {
            let Some(id) = t.get("docid").and_then(Value::as_str) else { continue };
            if let Some(exp) = t.get("contents").and_then(strings_of) {
                let e = exp.join("");
                if let Some(prefix) = e.strip_suffix(copied_text.as_str()) {
                    if !prefix.is_empty() {
                        steps.push(SetupStep::Insert {
                            doc: id.to_string(),
                            bytes: prefix.as_bytes().to_vec(),
                        });
                    }
                }
            }
            steps.push(SetupStep::Copy { doc: id.to_string(), src: src.clone(), ord, width: w });
        }
        self.plan_vcopy(i, op, steps);
    }

    fn sim_vcopy(&mut self, i: usize, op: &Value, ops: &[Value], op_name: &str) {
        // Macro forms: grounded by the destination's next content probe.
        let from_list = field(op, &["from", "sources", "order"]).and_then(Value::as_array).map(
            |a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect::<Vec<_>>(),
        );
        let is_macro = from_list.is_some()
            || op_name.starts_with("vcopy_multiple")
            || op_name.starts_with("vcopy_all")
            || op_name.starts_with("vcopy_from_both");
        if is_macro {
            // A macro's destination is read here alone — the play pass runs
            // the plan built from it: an explicit reference, else the op's
            // document. "end"/"start"/"end of doc" are position markers over
            // the register's document, not references.
            let explicit_dest = match str_field(op, &["to", "dest", "target", "target_doc"]) {
                Some(s) if is_position_marker(s) => self.shadow.current(),
                Some(s) => self.shadow.resolve_doc(s),
                None => str_field(op, &["doc", "docid"]).and_then(|s| self.shadow.resolve_doc(s)),
            };
            let Some(dest) = explicit_dest.or_else(|| self.doc_arg(op, &["doc", "docid"])) else {
                return;
            };
            let sources: Vec<String> = from_list
                .map(|names| names.iter().filter_map(|n| self.shadow.resolve_doc(n)).collect())
                .unwrap_or_else(|| self.shadow.content_docs_except(&dest));
            let Some(expected) = next_content_probe(ops, i, &self.shadow, &dest) else { return };
            let existing = self.shadow.text_string(&dest);
            let remainder = expected.strip_prefix(&existing).unwrap_or(&expected).to_string();
            // Recorded comparison pairs pin the exact cover when present.
            let steps = cover_from_comparisons(&self.shadow, &dest, &remainder, ops)
                .unwrap_or_else(|| {
                    cover_with_sources(&self.shadow, &dest, &sources, &remainder)
                });
            self.plan_vcopy(i, op, steps);
            return;
        }

        // Ordinary vcopy: the source regions the play pass reads, through
        // the same reading (`fields::vcopy_sources`), each contiguous
        // content-subspace region kept as a (doc, ord, width) spec. An op
        // the play pass cannot ground copies nothing here either.
        let Ok(sources) = vcopy_sources(op, &self.shadow, &mut Vec::new()) else { return };
        let spec_list: Vec<(String, u64, u64)> = sources
            .iter()
            .filter(|s| s.region.sub == 1)
            .map(|s| (s.doc.clone(), s.region.ord, s.region.width))
            .collect();
        let copied: Vec<u8> =
            spec_list.iter().flat_map(|(d, o, w)| self.shadow.slice(d, *o, *w)).collect();
        if copied.is_empty() {
            return;
        }
        // Where the copy lands is the one reading the play pass applies
        // (`evidence::vcopy_destination`, `evidence::vcopy_ordinal`): a
        // destination reference that resolves to nothing copies nothing
        // here, as it executes nothing there; a copy that names and
        // evidences no document aims by `doc_arg`; and an ordinal that
        // reading cannot ground is a write the walk never knew.
        let dest = match vcopy_destination(ops, i, &self.shadow, &sources, &mut Vec::new()) {
            Ok(Some(dest)) => dest,
            Ok(None) => match self.doc_arg(op, &["doc", "docid"]) {
                Some(dest) => dest,
                None => return,
            },
            Err(_) => return,
        };
        let Ok(at) = vcopy_ordinal(op, &self.shadow, &dest, &mut Vec::new()) else {
            self.record(&dest, Edit::Opaque);
            return;
        };
        // Append-shaped copies may carry unrecorded world structure the
        // scenario's own evidence pins — recorded comparison pairs and
        // content probes reconstruct it as an expansion plan (round-4
        // prefix-insert cluster: "Copied: ", "Link doc: ", "B prefix: ").
        if at.is_none() {
            if let Some(plan) = self.vcopy_reconstruction(i, ops, &dest, &copied, &spec_list) {
                self.plan_vcopy(i, op, plan);
                return;
            }
        }
        let ord = at.unwrap_or_else(|| self.shadow.text_len(&dest) + 1);
        self.shadow.insert(&dest, ord, &copied);
        self.record(&dest, Edit::Insert { at, bytes: copied });
        // The post-write probe `h_vcopy` compares — at the copy's
        // destination, wherever the register stands.
        self.probe_recorded(&dest, op, Probe::PostWrite);
    }

    /// Evidence-driven reconstruction of an append-shaped vcopy whose direct
    /// execution would not reproduce the recorded world. Four strategies, in
    /// authority order; `None` = no evidence demands a plan (the caller runs
    /// the copy directly).
    fn vcopy_reconstruction(
        &mut self,
        i: usize,
        ops: &[Value],
        dest: &str,
        copied: &[u8],
        spec_list: &[(String, u64, u64)],
    ) -> Option<Vec<SetupStep>> {
        let append_ord = self.shadow.text_len(dest) + 1;
        let pairs: Vec<SharedPair> =
            comparison_pairs(ops, &self.shadow).into_iter().filter(|p| p.dest == dest).collect();
        let probe = next_content_probe(ops, i, &self.shadow, dest);

        // 1. Full pair-cover of an empty destination's probe (content/
        //    vcopy_multiple_spans: the compare's pairs pin "Copied: " +
        //    both copies at their recorded widths — including the trailing
        //    period the text-located span misses). Only when no later copy
        //    op also builds this destination (a second builder would
        //    double-apply the cover).
        if self.shadow.text_len(dest) == 0 && !pairs.is_empty() {
            if let Some(probed) = &probe {
                if !has_later_copy_into(ops, i, dest, &self.shadow) {
                    if let Some(cover) = cover_from_comparisons(&self.shadow, dest, probed, ops) {
                        if cover.iter().any(|s| matches!(s, SetupStep::Copy { .. })) {
                            self.plan_strategies.insert(i, "vcopy-cover-from-comparisons");
                            return Some(cover);
                        }
                    }
                }
            }
        }

        // 2. Recorded pair landing exactly at the append position overrides
        //    the located source span (versions/cross_version_vcopy: the
        //    compare records source ordinal 15 width 12 where the described
        //    text located ordinal 20).
        if spec_list.len() == 1 {
            if let Some(pair) = pairs.iter().find(|pair| pair.dest_ord == append_ord) {
                let own = spec_list[0] == (pair.src.clone(), pair.src_ord, pair.width);
                let bytes = self.shadow.slice(&pair.src, pair.src_ord, pair.width);
                if !own && bytes.len() as u64 == pair.width && pair.width > 0 {
                    self.plan_strategies.insert(i, "vcopy-span-from-comparison");
                    return Some(vec![SetupStep::Copy {
                        doc: dest.to_string(),
                        src: pair.src.clone(),
                        ord: pair.src_ord,
                        width: pair.width,
                    }]);
                }
            }
        }

        // 3. Recorded pair landing PAST the append position, matching this
        //    op's own source span: the gap is an unrecorded prefix insert
        //    (content/vcopy_preserves_identity: the copy landed at 9, so 8
        //    filler bytes precede it; no probe records them, so spaces). A
        //    gap past the build budget is filler no comparison could read,
        //    so it is never built.
        if spec_list.len() == 1 {
            let (s0, o0, w0) = &spec_list[0];
            if let Some(pair) = pairs.iter().find(|pair| {
                pair.dest_ord > append_ord
                    && pair.dest_ord - append_ord <= BUILD_BUDGET
                    && (&pair.src, &pair.src_ord, &pair.width) == (s0, o0, w0)
            }) {
                let fill = (pair.dest_ord - append_ord) as usize;
                let start = (append_ord - 1) as usize;
                let bytes = match &probe {
                    Some(probed) if probed.len() >= start + fill => {
                        probed.as_bytes()[start..start + fill].to_vec()
                    }
                    _ => vec![b' '; fill],
                };
                self.plan_strategies.insert(i, "vcopy-prefix-from-comparison");
                return Some(vec![
                    SetupStep::Insert { doc: dest.to_string(), bytes },
                    SetupStep::Copy {
                        doc: dest.to_string(),
                        src: s0.clone(),
                        ord: *o0,
                        width: *w0,
                    },
                ]);
            }
        }

        // 4. Probe embed: the destination's next content probe shows the
        //    copied bytes at an offset past the current end — the script
        //    inserted filler first (interactions/link_both_endpoints_
        //    transcluded "Link doc: ", " -> "). When the probe suffix is
        //    exactly the later recorded appends, the copy extends to meet
        //    it if (and only if) the source continues with those very bytes
        //    (links/link_chain_with_transclusion's copied trailing space).
        let probed = probe?;
        let c = self.shadow.text_string(dest);
        let rest = probed.strip_prefix(c.as_str())?;
        let copied_text = String::from_utf8_lossy(copied).into_owned();
        let k = rest.find(&copied_text)?;
        let mut ext = 0u64;
        if let Some(suffix) = later_appends_text(ops, i, dest, &self.shadow) {
            if rest.ends_with(&suffix) {
                let appends_at = rest.len() - suffix.len();
                let end = k + copied_text.len();
                if end < appends_at {
                    if let Some((ls, lo, lw)) = spec_list.last() {
                        let need = (appends_at - end) as u64;
                        // Saturating: a recorded span at the top of the
                        // range continues into nothing.
                        let cont = self.shadow.slice(ls, lo.saturating_add(*lw), need);
                        if cont.len() as u64 == need && cont == rest.as_bytes()[end..appends_at] {
                            ext = need;
                        }
                    }
                }
            }
        }
        if k == 0 && ext == 0 {
            return None; // direct execution already reproduces the probe
        }
        self.plan_strategies.insert(i, "vcopy-embed-plan");
        let mut steps = Vec::new();
        if k > 0 {
            steps.push(SetupStep::Insert {
                doc: dest.to_string(),
                bytes: rest.as_bytes()[..k].to_vec(),
            });
        }
        for (j, (s, so, w)) in spec_list.iter().enumerate() {
            let w = if j + 1 == spec_list.len() { *w + ext } else { *w };
            steps.push(SetupStep::Copy { doc: dest.to_string(), src: s.clone(), ord: *so, width: w });
        }
        Some(steps)
    }

    /// Note `expected` as `doc`'s probed content — recorded text, never an
    /// address or a client repr (`fields::as_text`: the repr guard is what
    /// keeps retrieve_vspan_empty's "<VSpan …>" out of the seeds): the first
    /// probe this pass that disagrees with the shadow is the one the next
    /// round infers a seed from. A probe of a document the shadow does not
    /// hold tests nothing — the walk infers the setup of documents the
    /// scenario makes, and a seed for one it never made would mint, in the
    /// lead-in, a document no op created.
    fn probe(&mut self, doc: &str, expected: &str) {
        if !self.shadow.knows(doc) {
            return;
        }
        if self.shadow.text_string(doc) != expected && self.failed_probe.is_none() {
            self.failed_probe = Some((doc.to_string(), expected.to_string()));
        }
    }
}

/// Is a bundle named `name` one the walk probes the shadow with — a
/// snapshot of the state it observes (`snapshot`, `dump_state`,
/// `initial_state`, `final_state`, `verify_*`, `after_*`) or of a document's
/// content? A snapshot WITH a content expectation is a content probe of its
/// document (isolation/delete_does_not_affect_other_documents seeds doc B
/// only through its snapshots). Never the corpus extension's `probe`
/// checkpoints: their scenarios record their own setup (MANIFEST-NEW), so a
/// mismatch there is the walk's own gap, never setup to infer.
fn observes_state(name: &str) -> bool {
    const STATE_PREFIXES: &[&str] =
        &["content", "retrieve", "full_", "after_", "verify", "snapshot"];
    STATE_PREFIXES.iter().any(|p| name.starts_with(p)) || name.contains("state")
}

/// The docs-map probe for a NAMED doc after op `i` (create_chain contents).
fn next_docs_map_probe(ops: &[Value], i: usize, name: &str) -> Option<String> {
    for op in &ops[i + 1..] {
        if let Some(map) = op.get("docs").and_then(Value::as_object) {
            // An id map holds addresses, never content: as_text refuses it.
            if let Some(s) = map.get(name).and_then(strings_of).as_deref().and_then(as_text) {
                return Some(s);
            }
        }
    }
    None
}

/// The deleted bytes as the recording DESCRIBES them: the trailing
/// parenthetical of a span/text field ("1.3 for 0.5 (CDEFG)"), else its
/// first quoted segment ("1.11 for 0.7 (delete 'Shared ')" — isolation/
/// cross_document_transclusion_isolation) — each accepted only at exactly
/// the resolved width, so a reminder word never masquerades as the removed
/// bytes.
fn delete_described_bytes(op: &Value, w: u64) -> Option<Vec<u8>> {
    let at_width = |s: &str| (s.len() as u64 == w).then(|| s.as_bytes().to_vec());
    for key in ["span", "vspan", "text", "removed"] {
        let Some(s) = str_field(op, &[key]) else { continue };
        let parenthetical = s.rfind('(').and_then(|open| s[open + 1..].strip_suffix(')'));
        if let Some(bytes) = parenthetical.and_then(at_width) {
            return Some(bytes);
        }
        if let Some(bytes) = quoted(s).as_deref().and_then(at_width) {
            return Some(bytes);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// A delete's own description names its removed bytes — a trailing
    /// parenthetical, else a quoted segment — only at exactly its width.
    #[test]
    fn a_described_delete_names_its_bytes_at_its_width() {
        let quoted = json!({"op": "remove", "span": "1.11 for 0.7 (delete 'Shared ')"});
        assert_eq!(delete_described_bytes(&quoted, 7), Some(b"Shared ".to_vec()));
        assert_eq!(delete_described_bytes(&quoted, 8), None);
        let parenthetical = json!({"op": "delete", "span": "1.3 for 0.5 (CDEFG)"});
        assert_eq!(delete_described_bytes(&parenthetical, 5), Some(b"CDEFG".to_vec()));
    }
}
