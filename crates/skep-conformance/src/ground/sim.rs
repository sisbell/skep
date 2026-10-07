//! The pre-pass's walk: the scenario replayed in shadow space under the
//! seeds inferred so far. Each verb's effect on the shadow is restated here,
//! in a `Sim::sim_<verb>` method, from the play pass's `h_<verb>` handler —
//! in `create`, `write` and `link`, and the reads' register moves in
//! `sim_read`; every content write is logged for the seed undo, every
//! recorded probe checked, and the macro forms' plans are built where they
//! stand. Nothing but review keeps a `sim_` method and its handler alike:
//! change them together.
//!
//! The walk reads each op through the grammar the play pass reads it
//! through (`fields`: the verb `normalize` names, which it dispatches on,
//! a vcopy's sources, a version's source, a swap's regions), skips every op
//! udanax never carried out (`evidence::took_effect`), and decides what an
//! edit did by the recorded-evidence policies the play pass applies
//! (`evidence`: where an insert or a vcopy lands, what a delete removed);
//! what this module holds is the reconstruction alone. The corpus
//! extension records its own setup (MANIFEST-NEW): its `probe` checkpoints
//! carry no docs map, the one shape of them this walk reads, so nothing is
//! inferred there.

use std::collections::BTreeMap;

use serde_json::Value;

use super::cover::{
    comparison_pairs, cover_from_comparisons, cover_with_sources, has_later_copy_into,
    later_appends_text, SharedPair,
};
use super::{Edit, SetupStep};
use crate::evidence::{
    delete_is_noop, next_content_probe, resolve_delete_span, resolve_insert, took_effect,
    vcopy_destination, vcopy_ordinal,
};
use crate::fields::{
    aim_doc, arrow_results, as_text, created_addresses, cuts_of, distributed_insert_texts,
    distribution_targets, field, group_word, is_conflict_copy, is_position_marker, locate,
    normalize, op_name, per_doc_replies, quoted, recorded_content, recorded_count,
    resolve_position, roster, span_dict, str_field, strings_of, swap_regions, vcopy_sources,
    verb_of, version_result, version_source, DocAim, Verb, BUILD_BUDGET, POST_WRITE_KEYS,
};
use crate::shadow::Shadow;
use crate::tum::{link_home_docid, parse_dotted, parse_vpos, parse_width, VPoint, VRegion};

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
                // Home = the golden id's own prefix, else the FROM doc.
                let home = golden
                    .as_ref()
                    .and_then(|g| link_home_docid(g))
                    .or_else(|| from.first().map(|(d, _, _)| d.clone()));
                if let Some(home) = home {
                    if !self.shadow.knows(&home) {
                        self.shadow.create_doc(&home, None);
                    }
                    self.shadow.seat_link(&home);
                    self.shadow.set_current(&home);
                }
                if let Some(g) = golden {
                    self.shadow.last_link = Some(g.clone());
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

    /// Mirror of the play-pass shadow effects, content only. Any drift
    /// between this and the play pass surfaces as an honest divergence.
    /// An op udanax never carried out (`evidence::took_effect`) changes
    /// nothing; the rest dispatch on the verb the play pass dispatches on
    /// (`fields::normalize`), so the two passes cannot disagree about what
    /// kind of op a name reads as. Probes run AFTER an op's own edit (write
    /// branches call check_probes themselves) or in the read fall-through —
    /// never before, or a write's own result expectation would be compared
    /// against the pre-edit state and forge a false seed.
    fn step(&mut self, i: usize, op: &Value, ops: &[Value]) {
        if !took_effect(op) {
            return;
        }
        let name = op_name(op).to_ascii_lowercase();
        match normalize(&name, op) {
            Some(Verb::CreateChain) => self.sim_create_chain(i, op, ops),
            Some(Verb::CreateDocuments) => self.sim_create_documents(i, op, ops),
            Some(Verb::Setup) => {
                if let Some(steps) = self.expand_keyed_setup(op, i, ops) {
                    self.plan(i, steps);
                } else if let Some(desc) = str_field(op, &["description", "desc"]) {
                    if let Some(steps) = self.expand_setup_description(desc) {
                        self.plan(i, steps);
                    }
                }
            }
            Some(Verb::CreateDocument) => self.sim_create_document(op),
            Some(Verb::OpenDocument) => self.sim_open_document(op),
            Some(Verb::CreateVersion) => self.sim_create_version(op),
            Some(Verb::InteriorTyping) => self.sim_interior_typing(op),
            Some(Verb::InsertLoop) => self.sim_insert_loop(op),
            Some(Verb::Insert) => self.sim_insert(i, op, ops),
            Some(Verb::DeleteAll) => self.sim_delete_all(i, op, ops),
            Some(Verb::Delete) => self.sim_delete(i, op, ops),
            Some(Verb::Vcopy) if name.starts_with("vcopy_to_multiple") => {
                self.sim_vcopy_to_multiple(i, op)
            }
            Some(Verb::Vcopy) if name.starts_with("create_and_transclude") => {
                self.sim_create_and_transclude(i, op)
            }
            Some(Verb::Vcopy) => self.sim_vcopy(i, op, ops, &name),
            Some(verb @ (Verb::Pivot | Verb::Swap | Verb::Rearrange)) => {
                self.sim_rearrange(op, verb)
            }
            Some(Verb::CreateLink) => self.sim_create_link(op),
            _ => self.sim_read(op),
        }
    }

    fn sim_create_document(&mut self, op: &Value) {
        let name = crate::fields::create_name_of(op);
        let ids = created_addresses(op).unwrap_or_else(|| vec![self.shadow.synthesize_docid()]);
        for (k, id) in ids.iter().enumerate() {
            if !self.shadow.knows(id) {
                self.shadow.create_doc(id, if k == 0 { name.as_deref() } else { None });
            } else {
                if let Some(n) = &name {
                    self.shadow.bind_name(n, id);
                }
                self.shadow.set_current(id);
            }
        }
    }

    fn sim_open_document(&mut self, op: &Value) {
        if let Some(doc) = self.doc_arg(op, &["doc", "docid", "document"]) {
            if is_conflict_copy(op) {
                // A result the shadow already holds names another document,
                // which the fork never overwrites.
                if let Some(res) = str_field(op, &["result"]).filter(|r| !self.shadow.knows(r)) {
                    self.shadow.version(&doc, res);
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
        self.shadow.version(&src, &res);
        for key in ["doc", "name", "label"] {
            if let Some(name) = str_field(op, &[key]) {
                if parse_dotted(name).is_none() && self.shadow.resolve_doc(name).is_none() {
                    self.shadow.bind_name(name, &res);
                }
            }
        }
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
                } else {
                    self.record(&doc, Edit::Opaque);
                }
                self.check_probes(r);
            }
        }
    }

    fn sim_insert_loop(&mut self, op: &Value) {
        let Some(doc) = self.doc_arg(op, &["doc", "docid"]) else { return };
        // A count past the build budget is an op the play pass refuses, so
        // its bytes are never built here either; the write udanax made is
        // unknown to the walk, and no undo crosses it.
        let Ok(count) = recorded_count(op) else {
            self.record(&doc, Edit::Opaque);
            return;
        };
        let bytes: Vec<u8> = (0..count.unwrap_or(0)).map(|k| b'A' + (k % 26) as u8).collect();
        let end = self.shadow.text_len(&doc) + 1;
        self.shadow.insert(&doc, end, &bytes);
        self.record(&doc, Edit::Insert { at: None, bytes });
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
        if landing.at.sub != 1 {
            return; // a link-subspace insert: no content effect
        }
        self.shadow.insert(&landing.doc, landing.at.ord, &landing.bytes);
        let at = (!landing.appended).then_some(landing.at.ord);
        self.record(&landing.doc, Edit::Insert { at, bytes: landing.bytes });
        self.check_probes(op);
    }

    fn sim_delete_all(&mut self, i: usize, op: &Value, ops: &[Value]) {
        if let Some(doc) = self.doc_arg(op, &["doc", "docid"]) {
            if delete_is_noop(ops, i, &self.shadow, &doc) {
                return; // recorded post-state shows udanax removed nothing
            }
            let n = self.shadow.text_len(&doc);
            let bytes = self.shadow.slice(&doc, 1, n);
            self.shadow.delete(&doc, 1, n);
            self.record(&doc, Edit::Delete { at: 1, bytes: Some(bytes), explicit: true });
        }
    }

    fn sim_delete(&mut self, i: usize, op: &Value, ops: &[Value]) {
        let Some(doc) = self.doc_arg(op, &["doc", "docid"]) else { return };
        if delete_is_noop(ops, i, &self.shadow, &doc) {
            self.check_probes(op);
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
            // A content delete this grammar cannot place; a link-subspace
            // delete has no content effect.
            let start = str_field(op, &["start", "address", "at"]).and_then(parse_vpos);
            if start.is_none_or(|at| at.sub == 1) {
                self.record(&doc, Edit::Opaque);
            }
        }
        self.check_probes(op);
    }

    fn sim_create_and_transclude(&mut self, i: usize, op: &Value) {
        let src = self.shadow.resolve_doc("source").or_else(|| self.shadow.current());
        let Some(src) = src else { return };
        let n = self.shadow.text_len(&src);
        if let Some(targets) = field(op, &["targets"]).and_then(Value::as_array) {
            let mut steps = Vec::new();
            for t in targets.iter().filter_map(Value::as_str) {
                if !self.shadow.knows(t) {
                    self.shadow.create_doc(t, None);
                }
                steps.push(SetupStep::Copy {
                    doc: t.to_string(),
                    src: src.clone(),
                    ord: 1,
                    width: n,
                });
            }
            self.plan(i, steps);
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
        for r in &results {
            if let Some(home) = link_home_docid(r) {
                if !self.shadow.knows(&home) {
                    self.shadow.create_doc(&home, None);
                }
                self.shadow.seat_link(&home);
                // A link's home anchors the scope: the scripts' probes and
                // doc-less edits after a create_link target it.
                self.shadow.set_current(&home);
            }
            self.shadow.last_link = Some(r.clone());
        }
        for (f, t, r) in arrow_results(op) {
            self.shadow.arrow_links.insert((f, t), r);
        }
    }

    /// Reads / meta: probe consistency, then register updates from the doc
    /// field or, failing that, from an expectation's own docid / a
    /// link-result's home — the recording scripts' probes anchor the scope
    /// for later doc-less writes (subspace/insert_text_check_link_positions:
    /// the vspanset probe's docid names doc1 right before the doc-less
    /// INSERT).
    fn sim_read(&mut self, op: &Value) {
        self.check_probes(op);
        if let Some(s) = str_field(op, &["doc", "docid"]) {
            if let Some(d) = self.shadow.resolve_doc(s) {
                self.shadow.set_current(&d);
                return;
            }
        }
        self.register_from_expectation(op);
    }

    fn register_from_expectation(&mut self, op: &Value) {
        if let Some(o) = op.as_object() {
            for (k, v) in o {
                if matches!(k.as_str(), "op" | "comment" | "label" | "note" | "interpretation") {
                    continue;
                }
                if let Some((Some(docid), _)) = crate::fields::raw_spanset_of(v) {
                    let d = docid;
                    if self.shadow.knows(&d) {
                        self.shadow.set_current(&d);
                        return;
                    }
                }
                if let Some(strings) = strings_of(v) {
                    for s in &strings {
                        if let Some(home) = link_home_docid(s) {
                            if self.shadow.knows(&home) {
                                self.shadow.set_current(&home);
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    fn sim_create_documents(&mut self, i: usize, op: &Value, ops: &[Value]) {
        if let Some(map) = op.get("docs").and_then(Value::as_object) {
            let mut by_id: Vec<(String, String)> = map
                .iter()
                .filter_map(|(n, id)| id.as_str().map(|i| (i.to_string(), n.clone())))
                .collect();
            if !by_id.is_empty() {
                by_id.sort();
                for (id, name) in by_id {
                    if !self.shadow.knows(&id) {
                        self.shadow.create_doc(&id, Some(&name));
                    } else {
                        self.shadow.bind_name(&name, &id);
                    }
                }
                return;
            }
        }
        // A roster of `<name>: <docid>` fields (`fields::roster`): each
        // names a document, created here unless an implied create already
        // made it.
        let named = roster(op);
        if !named.is_empty() {
            for (name, id) in named {
                if self.shadow.knows(&id) {
                    self.shadow.bind_name(&name, &id);
                    self.shadow.set_current(&id);
                } else {
                    self.shadow.create_doc(&id, Some(&name));
                }
            }
            return;
        }
        let results: Vec<String> = field(op, &["results"])
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let names: Vec<String> = field(op, &["docs"])
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let texts: Vec<String> = field(op, &["texts"])
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let group = group_word(op);
        // A count past the build budget is an op the play pass refuses:
        // nothing is created here either.
        let Ok(count) = recorded_count(op) else { return };
        let count = count
            .map(|c| c as usize)
            .unwrap_or_else(|| results.len().max(names.len()).max(1));
        let mut created_here: Vec<String> = Vec::new();
        for k in 0..count.max(results.len()) {
            let id = results.get(k).cloned().unwrap_or_else(|| self.shadow.synthesize_docid());
            let name = names
                .get(k)
                .cloned()
                .or_else(|| group.as_ref().map(|t| format!("{t}{}", k + 1)));
            // A document an implied create already made is named and made
            // current, as the play pass's `ensure_document` does.
            if self.shadow.knows(&id) {
                if let Some(n) = &name {
                    self.shadow.bind_name(n, &id);
                }
                self.shadow.set_current(&id);
            } else {
                self.shadow.create_doc(&id, name.as_deref());
            }
            // Alternate spellings the scripts use for group members:
            // singular ("peripheral2" for group "peripherals") and 0-based
            // underscore ("target_0" — identity_multi_document_sharing).
            if let Some(g) = &group {
                let singular = g.trim_end_matches('s');
                self.shadow.bind_name(&format!("{singular}{}", k + 1), &id);
                self.shadow.bind_name(&format!("{singular}_{k}"), &id);
            }
            if let Some(t) = texts.get(k) {
                self.shadow.insert(&id, 1, t.as_bytes());
                self.record(&id, Edit::Insert { at: Some(1), bytes: t.as_bytes().to_vec() });
            } else {
                created_here.push(id);
            }
        }
        // World-construction completeness (round-3): a created-empty doc
        // whose later probe records content gets a cover plan — shared
        // regions as real copies from the docs that already hold them, so
        // the transclusions the scenario descriptions imply actually exist
        // (identity_multi_document_sharing expects five docs SHARING).
        let mut steps: Vec<SetupStep> = Vec::new();
        for id in created_here {
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
            if !self.shadow.knows(id) {
                self.shadow.create_doc(id, Some(name));
            } else {
                self.shadow.bind_name(name, id);
            }
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
        // show ahead of the copy, then the copy — which the plan applies as
        // the play pass executes them, recorded edits included: a target the
        // shadow does not hold yet is minted by its first step, one an
        // implied create made is built where it stands.
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
        self.plan(i, steps);
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
            self.plan(i, steps);
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
                self.plan(i, plan);
                return;
            }
        }
        let ord = at.unwrap_or_else(|| self.shadow.text_len(&dest) + 1);
        self.shadow.insert(&dest, ord, &copied);
        self.record(&dest, Edit::Insert { at, bytes: copied });
        self.check_probes(op);
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

    /// Compare any full-content expectations this op carries against the
    /// shadow; record the first mismatch for inference. Recorded content is
    /// read as the play pass reads it (`fields::as_text`, `recorded_content`,
    /// `per_doc_replies`).
    fn check_probes(&mut self, op: &Value) {
        if let Some(map) = op.get("docs").and_then(Value::as_object) {
            for (name, exp) in map {
                // create_documents docs-maps hold ID strings, not content.
                let (Some(doc), Some(text)) =
                    (self.shadow.resolve_doc(name), strings_of(exp).as_deref().and_then(as_text))
                else {
                    continue;
                };
                self.probe(&doc, &text);
            }
            return;
        }
        // Ops with narrowing arguments are not whole-document reads.
        let narrowing = ["span", "spans", "specs", "specset", "positions", "address", "at"];
        if op
            .as_object()
            .is_some_and(|o| narrowing.iter().any(|k| o.get(*k).is_some_and(|v| !v.is_null())))
        {
            return;
        }
        let name = op_name(op).to_ascii_lowercase();
        let recorded = if verb_of(op).is_some_and(Verb::writes_content) {
            // The play pass's post-write keys: a write's text is its argument.
            field(op, POST_WRITE_KEYS).and_then(strings_of)
        } else if matches!(verb_of(op), Some(Verb::RetrieveContents | Verb::Observe))
            && (name.starts_with("content")
                || name.starts_with("retrieve")
                || name.starts_with("full_")
                || name.contains("state")
                || name.starts_with("after_")
                || name.starts_with("verify")
                // A snapshot op WITH a content expectation is a contents
                // probe of the named doc, or the register's (isolation/
                // delete_does_not_affect_other_documents seeds doc B only
                // through its snapshots); content-less snapshots stay meta.
                || name.starts_with("snapshot"))
        {
            // Per-document replies probe each document they name — save a
            // reply strictly inside its document's content, which is the
            // play pass's narrowed read, not the whole document
            // (ispan_partial_overlap's `source: ["CDEFG"]`).
            let replies = per_doc_replies(op, &self.shadow);
            if !replies.is_empty() {
                for (_, doc, strings) in replies {
                    let Some(text) = as_text(&strings) else { continue };
                    let held = self.shadow.text_string(&doc);
                    if text != held && held.contains(&text) {
                        continue;
                    }
                    self.probe(&doc, &text);
                }
                return;
            }
            recorded_content(op, &["doc", "docid"]).map(|(_, strings)| strings)
        } else {
            return;
        };
        // Address strings and recording-client python reprs are never
        // content bytes: the repr guard is what keeps retrieve_vspan_empty's
        // "<VSpan …>" out of the seeds.
        let Some(text) = recorded.as_deref().and_then(as_text) else { return };
        // A full_* probe reads the doc the last CONTENT write touched
        // (mirror of the play pass's `full-probe-targets-last-write`).
        if name.starts_with("full_") && str_field(op, &["doc", "docid"]).is_none() {
            if let Some(d) = self.shadow.last_written.clone().filter(|d| self.shadow.knows(d)) {
                self.probe(&d, &text);
                return;
            }
        }
        let Some(doc) = self.doc_arg(op, &["doc", "docid"]) else { return };
        self.probe(&doc, &text);
    }

    /// Note `expected` as `doc`'s probed content: the first probe this pass
    /// that disagrees with the shadow is the one the next round infers a seed
    /// from. A probe of a document the shadow does not hold tests nothing —
    /// the walk infers the setup of documents the scenario makes, and a seed
    /// for one it never made would mint, in the lead-in, a document no op
    /// created.
    fn probe(&mut self, doc: &str, expected: &str) {
        if !self.shadow.knows(doc) {
            return;
        }
        if self.shadow.text_string(doc) != expected && self.failed_probe.is_none() {
            self.failed_probe = Some((doc.to_string(), expected.to_string()));
        }
    }
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
