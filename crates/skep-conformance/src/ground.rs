//! The grounding pre-pass: a shadow-only walk over a scenario BEFORE any
//! skep execution, reconstructing the setup the recording scripts performed
//! but did not record as operations.
//!
//! The goldens prove such setup exists: content/vcopy_source_modified's
//! target doc shows "Target: Original content" though only the vcopy of
//! "Original content" was recorded; endsets/endsets_after_source_insert
//! opens with a create_link into a document no recorded op ever created or
//! filled. The pre-pass derives that setup from the scenario's own recorded
//! evidence — never invents it:
//!
//! * **Implied creates** — dotted docids referenced by ops but never bound
//!   by a recorded create.
//! * **Seeds** — initial content per doc, obtained by BACKWARD-UNDOING the
//!   recorded edits from the doc's first full-content probe (each undo step
//!   verifies the removed bytes equal the recorded insert/copy, so a wrong
//!   inference aborts instead of guessing).
//! * **Expansion plans** — macro ops (`create_chain`, parseable `setup`
//!   descriptions, `vcopy_multiple`/`vcopy_all`/`vcopy_from_both`,
//!   `create_and_transclude`) expand to concrete insert+copy step lists,
//!   guided by the scenario's later content probes: probe text is greedily
//!   covered by substrings of the source docs (real copies, so shared
//!   IDENTITY is reproduced — a later find_documents/compare over sharing
//!   is then a real comparison) with the gaps inserted as filler text.
//!   content/vcopy_from_multiple_documents's own comparisons op confirms
//!   the copied regions land exactly where the script put them.
//! * **Placeholder seeds** — a doc that participates in link creation while
//!   empty (its content neither recorded nor probed) gets a marker string,
//!   because a link needs a nonempty endset on both sides; tagged loudly.
//!
//! Everything inferred is tagged into the report's `groundings` list. A doc
//! whose probes stay inconsistent after inference is left alone — the play
//! pass then reports the disagreement honestly.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use serde_json::Value;

use crate::fields::{
    doc_from_label, expect_strings, field, label_of, link_home_docid, locate, resolve_position,
    span_dict, str_field, vspec_dict,
};
use crate::shadow::Shadow;
use crate::tum::parse_dotted;

/// One step of reconstructed setup, fully concrete: executed against skep by
/// the runner (lead-in) or by the macro-op handlers (plans). Inserts append
/// at the doc's then-current end; copies append the source region
/// `[ord, ord+width)` (content subspace).
#[derive(Clone, Debug)]
pub enum SetupStep {
    Insert { doc: String, bytes: Vec<u8> },
    Copy { doc: String, src: String, ord: u64, width: u64 },
}

#[derive(Default)]
pub struct Grounding {
    /// Docs referenced but never created, in golden-id order.
    pub implied_creates: Vec<String>,
    /// Setup executed before op 0 (after implied creates): the inferred
    /// initial content, one Insert per seeded doc.
    pub lead_in: Vec<SetupStep>,
    /// Per-op expansion for macro forms, keyed by op index. The play pass
    /// executes these verbatim instead of re-deriving.
    pub plans: BTreeMap<usize, Vec<SetupStep>>,
    /// Every inference made, for the report's `groundings` list.
    pub tags: Vec<String>,
}

/// A recorded edit, kept symbolically so undo works whatever seed is in
/// place (`at: None` = appended at then-current end).
#[derive(Clone)]
enum Edit {
    Ins { at: Option<u64>, bytes: Vec<u8> },
    Del,
    Pivot { a: u64, b: u64, c: u64 },
    Swap { s1: u64, e1: u64, s2: u64, e2: u64 },
}

pub fn ground(ops: &[Value]) -> Grounding {
    let mut g = Grounding { implied_creates: implied_creates(ops), ..Grounding::default() };
    if !g.implied_creates.is_empty() {
        g.tags.push(format!("implied-create: {}", g.implied_creates.join(", ")));
    }

    let mut seeds: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    // Fixpoint: each round replays the scenario in shadow space under the
    // current seeds and may add at most one newly-inferred seed. Bounded by
    // the number of documents a scenario touches (≤ a handful).
    for _round in 0..8 {
        let mut sim = Sim::new(&g.implied_creates, &seeds);
        for (i, op) in ops.iter().enumerate() {
            sim.step(i, op, ops);
        }
        let Some((doc, exp)) = sim.failed_probe.take() else { break };
        if seeds.contains_key(&doc) {
            break; // already seeded and still inconsistent — leave honest
        }
        let Some(initial) = undo_to_initial(&exp, sim.log_for(&doc)) else { break };
        g.tags.push(format!(
            "implied-setup: {doc} starts with {:?} (derived by undoing recorded edits from its \
             first content probe)",
            String::from_utf8_lossy(&initial)
        ));
        seeds.insert(doc, initial);
    }

    // Placeholder seeds for empty link participants, discovered on a replay
    // under the settled seeds.
    {
        let mut sim = Sim::new(&g.implied_creates, &seeds);
        for (i, op) in ops.iter().enumerate() {
            sim.step(i, op, ops);
        }
        for doc in sim.link_participants_empty {
            if let Entry::Vacant(slot) = seeds.entry(doc) {
                let marker = format!("[{}]", slot.key());
                g.tags.push(format!(
                    "implied-setup:placeholder: {} participates in a link while empty and no \
                     recorded probe reveals its content; seeded {marker:?}",
                    slot.key()
                ));
                slot.insert(marker.into_bytes());
            }
        }
    }

    // Final pass under the settled seeds builds the definitive plans.
    let mut sim = Sim::new(&g.implied_creates, &seeds);
    for (i, op) in ops.iter().enumerate() {
        sim.step(i, op, ops);
    }
    for (i, plan) in &sim.plans {
        g.tags.push(format!(
            "expansion-plan: op {i} `{}` → {} concrete steps",
            label_of(&ops[*i]),
            plan.len()
        ));
    }
    g.plans = sim.plans;
    for (doc, bytes) in &seeds {
        g.lead_in.push(SetupStep::Insert { doc: doc.clone(), bytes: bytes.clone() });
    }
    g
}

/// Dotted docids referenced anywhere but never bound by a create op —
/// counting count-only `create_documents` ops as covering the next N root
/// ordinals (their synthesized ids), so a scenario that creates unnamed
/// docs is not double-created.
fn implied_creates(ops: &[Value]) -> Vec<String> {
    fn walk(v: &Value, f: &mut dyn FnMut(&str)) {
        match v {
            Value::String(s) => f(s),
            Value::Array(a) => a.iter().for_each(|x| walk(x, f)),
            Value::Object(o) => o.values().for_each(|x| walk(x, f)),
            _ => {}
        }
    }
    let mut created: Vec<String> = Vec::new();
    let mut created_count: u64 = 0;
    let mut referenced: Vec<String> = Vec::new();
    for op in ops {
        let label = label_of(op).to_ascii_lowercase();
        let creates = label.starts_with("create_doc")
            || label.starts_with("create_version")
            || label.starts_with("version")
            || label.starts_with("open_document")
            || label.starts_with("create_and_transclude")
            || label.starts_with("create_chain")
            || label.starts_with("create_sources")
            || label.starts_with("create_target")
            || label.starts_with("create_multiple");
        if creates {
            walk(op, &mut |s| {
                if s.contains('.') && parse_dotted(s).is_some() && link_home_docid(s).is_none() {
                    created.push(s.to_string());
                }
            });
            // Prospective creations without recorded ids.
            let explicit = field(op, &["results"])
                .and_then(Value::as_array)
                .map(|a| a.len() as u64)
                .or_else(|| op.get("docs").and_then(Value::as_object).map(|m| m.len() as u64));
            created_count += explicit
                .or_else(|| field(op, &["count"]).and_then(Value::as_u64))
                .or_else(|| {
                    field(op, &["targets"]).and_then(Value::as_array).map(|a| a.len() as u64)
                })
                .unwrap_or(1);
        }
        walk(op, &mut |s| {
            if let Some(home) = link_home_docid(s) {
                referenced.push(home);
            } else if s.contains('.') && parse_dotted(s).is_some() {
                referenced.push(s.to_string());
            }
        });
    }
    let mut out: Vec<String> = referenced
        .into_iter()
        .filter(|r| {
            !created.contains(r) && !created.iter().any(|c| r.starts_with(&format!("{c}.")))
        })
        .collect();
    out.sort();
    out.dedup();
    // Only document roots (node·account·0·n — ≥ 6 components, so the
    // account "1.1.0.1" itself is never implied-created) beyond what the
    // scenario's own creates will mint. Version sub-addresses and
    // V-positions are minted by the ops themselves.
    out.retain(|r| {
        let c = parse_dotted(r).unwrap_or_default();
        c.len() >= 6
            && c[c.len() - 2] == 0
            && c[c.len() - 1] > 0
            && c.len().is_multiple_of(2)
            && c[c.len() - 1] > created_count
    });
    out
}

/// Undo the recorded edits (latest first) from a probed content string back
/// to the doc's initial content. Every removal is verified byte-for-byte;
/// any mismatch or un-invertible edit (a delete) aborts the inference.
fn undo_to_initial(probed: &str, edits: &[Edit]) -> Option<Vec<u8>> {
    let mut cur: Vec<u8> = probed.as_bytes().to_vec();
    for e in edits.iter().rev() {
        match e {
            Edit::Ins { at, bytes } => {
                let n = bytes.len();
                let start = match at {
                    Some(ord) => (*ord as usize).checked_sub(1)?,
                    None => cur.len().checked_sub(n)?,
                };
                if start + n > cur.len() || &cur[start..start + n] != bytes.as_slice() {
                    return None;
                }
                cur.drain(start..start + n);
            }
            Edit::Del => return None, // deleted bytes are unrecoverable
            Edit::Pivot { a, b, c } => {
                // pivot(a,b,c) moved [b,c) before [a,b); inverse is
                // pivot(a, a+(c-b), c). Degenerate cuts (zero, non-monotone,
                // out of range) were a Shadow::pivot no-op in the forward
                // sim, so the undo mirrors the no-op rather than underflow
                // on c - b: udanax ACCEPTED such calls with effects the
                // shadow does not model (rearrange_semantics/
                // pivot_v3_inside_source records cuts (2,4,3) succeeding),
                // and the resulting probe mismatch then aborts inference
                // honestly at the insert undo. Pivot preserves length, so
                // cur.len() here is the length the forward call saw.
                if *a > 0 && a <= b && b <= c && *c as usize <= cur.len() + 1 {
                    let mut s = scratch(&cur);
                    s.pivot("x", *a, a + (c - b), *c);
                    cur = s.text_string("x").into_bytes();
                }
            }
            Edit::Swap { s1, e1, s2, e2 } => {
                // Same no-op mirror of Shadow::swap's guard as Pivot above.
                if *s1 > 0 && s1 <= e1 && e1 <= s2 && s2 <= e2 && *e2 as usize <= cur.len() + 1 {
                    let (w1, w2) = (e1 - s1, e2 - s2);
                    let mut s = scratch(&cur);
                    s.swap("x", *s1, s1 + w2, s2 + w2 - w1, *e2);
                    cur = s.text_string("x").into_bytes();
                }
            }
        }
    }
    Some(cur)
}

fn scratch(bytes: &[u8]) -> Shadow {
    let mut s = Shadow::new();
    s.create_doc("x", None);
    s.insert("x", 1, bytes);
    s
}

// ───────────────────────────── the simulation ──────────────────────────────

struct Sim {
    shadow: Shadow,
    logs: BTreeMap<String, Vec<Edit>>,
    /// First probe whose expectation disagreed with the shadow this pass.
    failed_probe: Option<(String, String)>,
    /// Docs that were empty while participating in a link op.
    link_participants_empty: Vec<String>,
    plans: BTreeMap<usize, Vec<SetupStep>>,
}

impl Sim {
    fn new(implied: &[String], seeds: &BTreeMap<String, Vec<u8>>) -> Sim {
        let mut sim = Sim {
            shadow: Shadow::new(),
            logs: BTreeMap::new(),
            failed_probe: None,
            link_participants_empty: Vec::new(),
            plans: BTreeMap::new(),
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

    fn apply_step(&mut self, s: &SetupStep) {
        match s {
            SetupStep::Insert { doc, bytes } => {
                if !self.shadow.knows(doc) {
                    self.shadow.create_doc(doc, None);
                }
                let end = self.shadow.text_len(doc) + 1;
                self.shadow.insert(doc, end, bytes);
            }
            SetupStep::Copy { doc, src, ord, width } => {
                let bytes = self.shadow.slice(src, *ord, *width);
                if !self.shadow.knows(doc) {
                    self.shadow.create_doc(doc, None);
                }
                let end = self.shadow.text_len(doc) + 1;
                self.shadow.insert(doc, end, &bytes);
            }
        }
    }

    fn plan(&mut self, i: usize, steps: Vec<SetupStep>) {
        for s in &steps {
            self.apply_step(s);
        }
        self.plans.insert(i, steps);
    }

    fn log_for(&self, doc: &str) -> &[Edit] {
        self.logs.get(doc).map(Vec::as_slice).unwrap_or(&[])
    }

    fn record(&mut self, doc: &str, e: Edit) {
        self.logs.entry(doc.to_string()).or_default().push(e);
    }

    fn doc_ref(&mut self, op: &Value, keys: &[&str]) -> Option<String> {
        if let Some(s) = str_field(op, keys) {
            if let Some(d) = self.shadow.resolve_doc(s) {
                return Some(d);
            }
        }
        if let Some(name) = doc_from_label(label_of(op)) {
            if let Some(d) = self.shadow.resolve_doc(&name) {
                return Some(d);
            }
        }
        if let Some(d) = self.shadow.scoped() {
            return Some(d);
        }
        // First-touch: a scenario whose opening op needs a document before
        // any create (endsets/endsets_after_pivot) — create one, exactly as
        // the play pass will.
        let id = self.shadow.synthesize_docid();
        self.shadow.create_doc(&id, None);
        Some(id)
    }

    /// Mirror of the play-pass shadow effects, content only. Any drift
    /// between this and the translator surfaces as an honest divergence.
    /// Probes run AFTER an op's own edit (write branches call check_probes
    /// themselves) or in the read fall-through — never before, or a write's
    /// own result expectation would be compared against the pre-edit state
    /// and forge a false seed.
    fn step(&mut self, i: usize, op: &Value, all: &[Value]) {
        let label = label_of(op).to_ascii_lowercase();

        if label.starts_with("create_chain") {
            self.sim_create_chain(i, op, all);
            return;
        }
        if label == "setup" {
            if let Some(desc) = str_field(op, &["description", "desc"]) {
                if let Some(steps) = self.parse_setup_description(desc) {
                    self.plan(i, steps);
                }
            }
            return;
        }
        if label.starts_with("create_documents") {
            self.sim_create_documents(op);
            return;
        }
        if label.starts_with("create_doc")
            || label.starts_with("create_sources")
            || label.starts_with("create_target")
            || label.starts_with("create_multiple")
        {
            let name = str_field(op, &["doc", "name", "label"])
                .filter(|s| parse_dotted(s).is_none())
                .map(str::to_string);
            let ids: Vec<String> = match field(op, &["result", "results"]) {
                Some(Value::String(s)) => vec![s.clone()],
                Some(Value::Array(a)) => {
                    a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
                }
                _ => vec![self.shadow.synthesize_docid()],
            };
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
            return;
        }
        if label.starts_with("open_document") {
            let conflict_copy = str_field(op, &["conflict"]).is_some_and(|c| c == "copy");
            if let Some(doc) = self.doc_ref(op, &["doc", "docid", "document"]) {
                if conflict_copy {
                    if let Some(res) = str_field(op, &["result"]) {
                        self.shadow.version(&doc, res);
                    }
                } else {
                    self.shadow.set_current(&doc);
                }
            }
            return;
        }
        if label.starts_with("create_version") || label.starts_with("version") {
            let src = str_field(op, &["from", "source", "of", "original"])
                .and_then(|s| self.shadow.resolve_doc(s))
                .or_else(|| {
                    str_field(op, &["doc"]).and_then(|s| self.shadow.resolve_doc(s))
                })
                .or_else(|| self.shadow.scoped());
            let (Some(src), Some(res)) = (src, result_str(op)) else { return };
            self.shadow.version(&src, &res);
            for key in ["doc", "name", "label"] {
                if let Some(name) = str_field(op, &[key]) {
                    if parse_dotted(name).is_none() && self.shadow.resolve_doc(name).is_none() {
                        self.shadow.bind_name(name, &res);
                    }
                }
            }
            return;
        }
        if label.starts_with("interior_typing") {
            let Some(doc) = self.doc_ref(op, &["doc", "docid"]) else { return };
            if let Some(results) = field(op, &["results"]).and_then(Value::as_array) {
                for r in results {
                    let (Some(ch), Some(pos)) = (
                        r.get("char").and_then(Value::as_str),
                        r.get("position").and_then(Value::as_str),
                    ) else {
                        continue;
                    };
                    if let Some((1, ord, _)) = resolve_position(&self.shadow, &doc, pos) {
                        self.shadow.insert(&doc, ord, ch.as_bytes());
                        self.record(
                            &doc,
                            Edit::Ins { at: Some(ord), bytes: ch.as_bytes().to_vec() },
                        );
                    }
                    self.check_probes(r);
                }
            }
            return;
        }
        if label.starts_with("insert_loop") {
            let Some(doc) = self.doc_ref(op, &["doc", "docid"]) else { return };
            let count = field(op, &["count"]).and_then(Value::as_u64).unwrap_or(0);
            let bytes: Vec<u8> = (0..count).map(|k| b'A' + (k % 26) as u8).collect();
            let end = self.shadow.text_len(&doc) + 1;
            self.shadow.insert(&doc, end, &bytes);
            self.record(&doc, Edit::Ins { at: None, bytes });
            return;
        }
        if label.starts_with("insert") || label == "append" {
            let Some(doc) = self.doc_ref(op, &["doc", "docid"]) else { return };
            let Some(text) = insert_text(op) else { return };
            let pos = str_field(op, &["address", "at", "position", "vaddr"]);
            let (at, ord) = match pos.and_then(|p| resolve_position(&self.shadow, &doc, p)) {
                Some((1, o, _)) => (Some(o), o),
                Some(_) => return, // link-subspace insert: no content effect
                None => (None, self.shadow.text_len(&doc) + 1),
            };
            self.shadow.insert(&doc, ord, text.as_bytes());
            self.record(&doc, Edit::Ins { at, bytes: text.into_bytes() });
            self.check_probes(op);
            return;
        }
        if label.starts_with("delete_all") || label.starts_with("remove_all") {
            if let Some(doc) = self.doc_ref(op, &["doc", "docid"]) {
                let n = self.shadow.text_len(&doc);
                self.shadow.delete(&doc, 1, n);
                self.record(&doc, Edit::Del);
            }
            return;
        }
        if label.starts_with("delete") || label.starts_with("remove") {
            let Some(doc) = self.doc_ref(op, &["doc", "docid"]) else { return };
            if let Some((ord, w)) = delete_region(&self.shadow, &doc, op) {
                self.shadow.delete(&doc, ord, w);
                self.record(&doc, Edit::Del);
            }
            self.check_probes(op);
            return;
        }
        if label.starts_with("vcopy_to_multiple") {
            self.sim_vcopy_to_multiple(i, op);
            return;
        }
        if label.starts_with("create_and_transclude") {
            let src = self.shadow.resolve_doc("source").or_else(|| self.shadow.scoped());
            let Some(src) = src else { return };
            let n = self.shadow.text_len(&src);
            if let Some(targets) = field(op, &["targets"]).and_then(Value::as_array) {
                let mut steps = Vec::new();
                for t in targets.iter().filter_map(Value::as_str) {
                    self.shadow.create_doc(t, None);
                    steps.push(SetupStep::Copy {
                        doc: t.to_string(),
                        src: src.clone(),
                        ord: 1,
                        width: n,
                    });
                }
                self.plan(i, steps);
            }
            return;
        }
        if label.starts_with("vcopy") || label == "copy" {
            self.sim_vcopy(i, op, all, &label);
            return;
        }
        if label.starts_with("pivot") || (label.starts_with("rearrange") && cuts_of(op).len() == 3)
        {
            let Some(doc) = self.doc_ref(op, &["doc", "docid"]) else { return };
            let cuts = cuts_of(op);
            if cuts.len() == 3 {
                self.shadow.pivot(&doc, cuts[0], cuts[1], cuts[2]);
                self.record(&doc, Edit::Pivot { a: cuts[0], b: cuts[1], c: cuts[2] });
            }
            return;
        }
        if label.starts_with("swap") || label.starts_with("rearrange") {
            let Some(doc) = self.doc_ref(op, &["doc", "docid"]) else { return };
            let cuts = cuts_of(op);
            if cuts.len() == 4 {
                self.shadow.swap(&doc, cuts[0], cuts[1], cuts[2], cuts[3]);
                self.record(&doc, Edit::Swap { s1: cuts[0], e1: cuts[1], s2: cuts[2], e2: cuts[3] });
            }
            return;
        }
        if label.starts_with("create_link") || label.starts_with("makelink") {
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
                if self.shadow.text_len(&d) == 0 && !self.link_participants_empty.contains(&d) {
                    self.link_participants_empty.push(d);
                }
            }
            let results: Vec<String> = match field(op, &["result", "results"]) {
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
                    // A link's home anchors the scope: the scripts' probes
                    // and doc-less edits after a create_link target it.
                    self.shadow.set_current(&home);
                }
                self.shadow.last_link = Some(r.clone());
            }
            for (f, t, r) in arrow_results(op) {
                self.shadow.arrow_links.insert((f, t), r);
            }
            return;
        }
        // Reads / meta: probe consistency, then register updates from the
        // doc field or, failing that, from an expectation's own docid / a
        // link-result's home — the recording scripts' probes anchor the
        // scope for later doc-less writes (subspace/insert_text_check_link_
        // positions: the vspanset probe's docid names doc1 right before the
        // doc-less INSERT).
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
                if let Some((Some(docid), _)) = crate::fields::expect_spans_raw(v) {
                    let d = docid;
                    if self.shadow.knows(&d) {
                        self.shadow.set_current(&d);
                        return;
                    }
                }
                if let Some(strings) = expect_strings(v) {
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

    fn sim_create_documents(&mut self, op: &Value) {
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
        // doc1/doc2 keyed fields (subspace/insert_text_check_link_positions).
        let mut keyed = false;
        if let Some(o) = op.as_object() {
            let mut pairs: Vec<(String, String)> = o
                .iter()
                .filter(|(k, _)| k.starts_with("doc") && k[3..].parse::<u64>().is_ok())
                .filter_map(|(k, v)| v.as_str().map(|id| (k.clone(), id.to_string())))
                .collect();
            pairs.sort();
            for (k, id) in pairs {
                self.shadow.create_doc(&id, Some(&k));
                keyed = true;
            }
        }
        if keyed {
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
        let group = str_field(op, &["type", "doc"]).map(str::to_string);
        let count = field(op, &["count"])
            .and_then(Value::as_u64)
            .map(|c| c as usize)
            .unwrap_or_else(|| results.len().max(names.len()).max(1));
        for k in 0..count.max(results.len()) {
            let id = results.get(k).cloned().unwrap_or_else(|| self.shadow.synthesize_docid());
            let name = names
                .get(k)
                .cloned()
                .or_else(|| group.as_ref().map(|t| format!("{t}{}", k + 1)));
            self.shadow.create_doc(&id, name.as_deref());
            if let Some(t) = texts.get(k) {
                self.shadow.insert(&id, 1, t.as_bytes());
                self.record(&id, Edit::Ins { at: Some(1), bytes: t.as_bytes().to_vec() });
            }
        }
    }

    /// `create_chain` (identity/find_documents_transitive): docs created in
    /// golden-id order; each doc's content is reconstructed from the next
    /// docs-map probe, with substrings shared with ALREADY-BUILT chain docs
    /// as real copies (transitive identity preserved).
    fn sim_create_chain(&mut self, i: usize, op: &Value, all: &[Value]) {
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
            let Some(expected) = next_docs_map_probe(all, i, name) else {
                built.push(id.clone());
                continue;
            };
            let sub = cover_with_sources(&self.shadow, id, &built, &expected);
            for s in &sub {
                self.apply_step(s);
            }
            steps.extend(sub);
            built.push(id.clone());
        }
        self.plans.insert(i, steps);
    }

    /// "C='ABCDEFGHIJ', B=vcopy(C), A=vcopy('DEFGH' from B)" — clauses
    /// resolved IN ORDER against the evolving shadow, so each copy's
    /// (ord, width) is concrete by the time it is emitted.
    fn parse_setup_description(&mut self, desc: &str) -> Option<Vec<SetupStep>> {
        let mut steps = Vec::new();
        let mut probe = self.shadow.clone();
        for clause in desc.split(',') {
            let clause = clause.trim();
            let (name, rhs) = clause.split_once('=')?;
            let (name, rhs) = (name.trim(), rhs.trim());
            let doc = probe.resolve_doc(name)?;
            let step = if let Some(q) = rhs.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')) {
                SetupStep::Insert { doc: doc.clone(), bytes: q.as_bytes().to_vec() }
            } else {
                let inner = rhs.strip_prefix("vcopy(")?.strip_suffix(')')?;
                if let Some((text, srcref)) = inner.split_once(" from ") {
                    let text = text.trim().trim_matches('\'');
                    let src = probe.resolve_doc(srcref.trim())?;
                    let (_, ord) = probe.find_text(Some(&src), text)?;
                    SetupStep::Copy { doc: doc.clone(), src, ord, width: text.len() as u64 }
                } else {
                    let src = probe.resolve_doc(inner.trim())?;
                    let n = probe.text_len(&src);
                    SetupStep::Copy { doc: doc.clone(), src, ord: 1, width: n }
                }
            };
            // Apply to the probe shadow so later clauses see earlier effects.
            match &step {
                SetupStep::Insert { doc, bytes } => {
                    let end = probe.text_len(doc) + 1;
                    probe.insert(doc, end, bytes);
                }
                SetupStep::Copy { doc, src, ord, width } => {
                    let bytes = probe.slice(src, *ord, *width);
                    let end = probe.text_len(doc) + 1;
                    probe.insert(doc, end, &bytes);
                }
            }
            steps.push(step);
        }
        Some(steps)
    }

    fn sim_vcopy_to_multiple(&mut self, i: usize, op: &Value) {
        let src_span = field(op, &["source_span"]).and_then(span_dict);
        let src = self
            .shadow
            .scoped()
            .filter(|d| self.shadow.text_len(d) > 0)
            .or_else(|| self.shadow.content_docs_except("").first().cloned());
        let (Some((1, ord, w)), Some(src)) = (src_span, src) else { return };
        let copied = self.shadow.slice(&src, ord, w);
        let Some(targets) = field(op, &["targets"]).and_then(Value::as_array) else { return };
        let mut steps = Vec::new();
        for t in targets {
            let Some(id) = t.get("docid").and_then(Value::as_str) else { continue };
            self.shadow.create_doc(id, None);
            if let Some(exp) = t.get("contents").and_then(expect_strings) {
                let e = exp.join("");
                let copied_s = String::from_utf8_lossy(&copied).into_owned();
                if let Some(prefix) = e.strip_suffix(copied_s.as_str()) {
                    if !prefix.is_empty() {
                        steps.push(SetupStep::Insert {
                            doc: id.to_string(),
                            bytes: prefix.as_bytes().to_vec(),
                        });
                        self.shadow.insert(id, 1, prefix.as_bytes());
                    }
                }
            }
            steps.push(SetupStep::Copy { doc: id.to_string(), src: src.clone(), ord, width: w });
            let end = self.shadow.text_len(id) + 1;
            self.shadow.insert(id, end, &copied);
        }
        self.plans.insert(i, steps);
    }

    fn sim_vcopy(&mut self, i: usize, op: &Value, all: &[Value], label: &str) {
        let to_raw = str_field(op, &["to", "dest", "target", "target_doc"]);
        let dest: Option<String> = match to_raw {
            Some("end") | Some("start") => self.shadow.scoped(),
            Some(s) => self.shadow.resolve_doc(s),
            None => self.doc_ref(op, &["doc", "docid"]),
        };

        // Macro forms: grounded by the destination's next content probe.
        let from_list = field(op, &["from", "sources"]).and_then(Value::as_array).map(|a| {
            a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect::<Vec<_>>()
        });
        let is_macro = from_list.is_some()
            || label.starts_with("vcopy_multiple")
            || label.starts_with("vcopy_all")
            || label.starts_with("vcopy_from_both");
        if is_macro {
            let Some(dest) = dest else { return };
            let sources: Vec<String> = from_list
                .map(|names| names.iter().filter_map(|n| self.shadow.resolve_doc(n)).collect())
                .unwrap_or_else(|| self.shadow.content_docs_except(&dest));
            let Some(expected) = next_content_probe(all, i, &dest, &self.shadow) else { return };
            let existing = self.shadow.text_string(&dest);
            let remainder = expected.strip_prefix(&existing).unwrap_or(&expected).to_string();
            let steps = cover_with_sources(&self.shadow, &dest, &sources, &remainder);
            self.plan(i, steps);
            return;
        }

        // Ordinary vcopy: capture bytes exactly as the translator will.
        let mut copied: Vec<u8> = Vec::new();
        if let Some(arr) =
            field(op, &["specs", "specset", "source", "sources"]).and_then(Value::as_array)
        {
            for v in arr {
                if let Some((docid, spans)) = vspec_dict(v) {
                    for (sub, ord, w) in spans {
                        if sub == 1 {
                            copied.extend(self.shadow.slice(&docid, ord, w));
                        }
                    }
                } else if let Some(t) = v.as_str() {
                    if let Some(l) = locate(&self.shadow, None, t) {
                        copied.extend(self.shadow.slice(&l.doc, l.ord, l.width));
                    }
                }
            }
        } else if let Some(arr) = field(op, &["spans"]).and_then(Value::as_array) {
            for t in arr.iter().filter_map(Value::as_str) {
                if let Some(l) = locate(&self.shadow, None, t) {
                    copied.extend(self.shadow.slice(&l.doc, l.ord, l.width));
                }
            }
        } else if let Some((1, ord, w)) = field(op, &["source_span", "span"]).and_then(span_dict) {
            let src = str_field(op, &["from", "source_doc"])
                .and_then(|s| self.shadow.resolve_doc(s))
                .or_else(|| {
                    dest.as_ref().and_then(|d| self.shadow.content_docs_except(d).first().cloned())
                });
            if let Some(src) = src {
                copied.extend(self.shadow.slice(&src, ord, w));
            }
        } else if let Some(t) = str_field(op, &["text", "span"]) {
            let hint =
                str_field(op, &["from", "source_doc"]).and_then(|s| self.shadow.resolve_doc(s));
            if let Some(l) = locate(&self.shadow, hint.as_deref(), t) {
                copied.extend(self.shadow.slice(&l.doc, l.ord, l.width));
            }
        } else if let Some(from) =
            str_field(op, &["from", "source"]).and_then(|s| self.shadow.resolve_doc(s))
        {
            // `from: <doc>` with no span: whole current extent (mirrors the
            // translator's fallback).
            let n = self.shadow.text_len(&from);
            copied.extend(self.shadow.slice(&from, 1, n));
        }
        let Some(dest) = dest else { return };
        if copied.is_empty() {
            return;
        }
        let ord = str_field(op, &["address", "at", "position"])
            .and_then(|p| resolve_position(&self.shadow, &dest, p))
            .and_then(|(s, o, _)| if s == 1 { Some(o) } else { None });
        let (at, o) = match (ord, to_raw) {
            (Some(o), _) => (Some(o), o),
            (None, Some("start")) => (Some(1), 1),
            (None, _) => (None, self.shadow.text_len(&dest) + 1),
        };
        self.shadow.insert(&dest, o, &copied);
        self.record(&dest, Edit::Ins { at, bytes: copied });
        self.check_probes(op);
    }

    /// Compare any full-content expectations this op carries against the
    /// shadow; record the first mismatch for inference.
    fn check_probes(&mut self, op: &Value) {
        if let Some(map) = op.get("docs").and_then(Value::as_object) {
            for (name, exp) in map {
                let (Some(doc), Some(strings)) =
                    (self.shadow.resolve_doc(name), expect_strings(exp))
                else {
                    continue;
                };
                // create_documents docs-maps hold ID strings, not content.
                if strings.iter().any(|s| s.contains('.') && parse_dotted(s).is_some()) {
                    continue;
                }
                self.probe(&doc, &strings.join(""));
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
        let label = label_of(op).to_ascii_lowercase();
        let content_keys: &[&str] = if label.starts_with("insert")
            || label.starts_with("delete")
            || label.starts_with("remove")
            || label.starts_with("vcopy")
        {
            // Mirrors the translator's Probe::PostWrite key set.
            &["remaining", "result", "expected_contents"]
        } else if label.starts_with("content")
            || label.starts_with("retrieve")
            || label.starts_with("full_")
            || label.contains("state")
            || label.starts_with("after_")
            || label.starts_with("verify")
        {
            &[
                "result", "before", "after", "content", "contents", "sample", "remaining",
                "empty", "expected_contents",
            ]
        } else {
            return;
        };
        let Some(v) = field(op, content_keys) else { return };
        let Some(strings) = expect_strings(v) else { return };
        // Address strings are never content bytes (mirrors the translator).
        if strings.iter().any(|s| s.contains('.') && parse_dotted(s).is_some()) {
            return;
        }
        let Some(doc) = self.doc_ref(op, &["doc", "docid"]) else { return };
        self.probe(&doc, &strings.join(""));
    }

    fn probe(&mut self, doc: &str, expected: &str) {
        if self.shadow.text_string(doc) != expected && self.failed_probe.is_none() {
            self.failed_probe = Some((doc.to_string(), expected.to_string()));
        }
    }
}

/// Greedy cover of `expected` by substrings of the sources (copies, ≥ 4
/// chars) with literal fillers between — the reconstruction of an
/// unrecorded insert/vcopy interleaving. Verified downstream by the
/// scenario's own compare/find ops.
fn cover_with_sources(
    shadow: &Shadow,
    dest: &str,
    sources: &[String],
    expected: &str,
) -> Vec<SetupStep> {
    const MIN_COPY: usize = 4;
    let e = expected.as_bytes();
    let mut steps: Vec<SetupStep> = Vec::new();
    let mut filler: Vec<u8> = Vec::new();
    let mut i = 0usize;
    while i < e.len() {
        let mut best: Option<(String, u64, usize)> = None; // (src, ord, len)
        for src in sources {
            let text = shadow.text_string(src);
            let t = text.as_bytes();
            let hi = (e.len() - i).min(t.len());
            let mut found: Option<(u64, usize)> = None;
            let mut lo = MIN_COPY;
            while lo <= hi {
                let needle = &e[i..i + lo];
                match t.windows(lo).position(|w| w == needle) {
                    Some(p) => {
                        found = Some((p as u64 + 1, lo));
                        lo += 1;
                    }
                    None => break,
                }
            }
            if let Some((ord, len)) = found {
                if best.as_ref().is_none_or(|(_, _, bl)| len > *bl) {
                    best = Some((src.clone(), ord, len));
                }
            }
        }
        match best {
            Some((src, ord, len)) => {
                if !filler.is_empty() {
                    steps.push(SetupStep::Insert {
                        doc: dest.to_string(),
                        bytes: std::mem::take(&mut filler),
                    });
                }
                steps.push(SetupStep::Copy { doc: dest.to_string(), src, ord, width: len as u64 });
                i += len;
            }
            None => {
                filler.push(e[i]);
                i += 1;
            }
        }
    }
    if !filler.is_empty() {
        steps.push(SetupStep::Insert { doc: dest.to_string(), bytes: filler });
    }
    steps
}

/// The next full-content probe of `doc` after op `i` (doc-field probes and
/// docs-map probes both count).
fn next_content_probe(all: &[Value], i: usize, doc: &str, shadow: &Shadow) -> Option<String> {
    let content = |s: Vec<String>| -> Option<String> {
        if s.iter().any(|x| x.contains('.') && parse_dotted(x).is_some()) {
            None // an address string is an id map, not content
        } else {
            Some(s.join(""))
        }
    };
    for op in &all[i + 1..] {
        if let Some(map) = op.get("docs").and_then(Value::as_object) {
            for (name, exp) in map {
                if shadow.resolve_doc(name).as_deref() == Some(doc) {
                    if let Some(s) = expect_strings(exp).and_then(&content) {
                        return Some(s);
                    }
                }
            }
        }
        let label = label_of(op).to_ascii_lowercase();
        if !(label.starts_with("content") || label.starts_with("retrieve")) {
            continue;
        }
        let target = str_field(op, &["doc", "docid"]).and_then(|s| shadow.resolve_doc(s));
        if target.as_deref() != Some(doc) {
            continue;
        }
        if let Some(v) = field(op, &["result", "content", "contents"]) {
            if let Some(s) = expect_strings(v).and_then(&content) {
                return Some(s);
            }
        }
    }
    None
}

/// The docs-map probe for a NAMED doc after op `i` (create_chain contents).
fn next_docs_map_probe(all: &[Value], i: usize, name: &str) -> Option<String> {
    for op in &all[i + 1..] {
        if let Some(map) = op.get("docs").and_then(Value::as_object) {
            if let Some(exp) = map.get(name) {
                if let Some(s) = expect_strings(exp) {
                    if s.iter().any(|x| x.contains('.') && parse_dotted(x).is_some()) {
                        continue; // an id map, not content
                    }
                    return Some(s.join(""));
                }
            }
        }
    }
    None
}

/// The inserted text: field, strings array, or label-borne
/// (`insert_1_AAA` = ordinal 1 text AAA; `insert_A` = text A).
pub fn insert_text(op: &Value) -> Option<String> {
    if let Some(t) = str_field(op, &["text", "content", "string"]) {
        return Some(t.to_string());
    }
    if let Some(a) = field(op, &["strings", "texts"]).and_then(Value::as_array) {
        return Some(a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(""));
    }
    let label = label_of(op);
    let rest = label.strip_prefix("insert_")?;
    if let Some((ordtok, text)) = rest.split_once('_') {
        if ordtok.parse::<u64>().is_ok() {
            return Some(text.to_string());
        }
        return None; // insert_after_delete etc.: descriptive, not text
    }
    // Single trailing token: the text itself (insert_A, insert_1), unless a
    // known descriptive word.
    if rest.is_empty() || matches!(rest, "loop" | "text" | "attempt" | "all") {
        return None;
    }
    Some(rest.to_string())
}

/// The delete region in any of the goldens' shapes (dict span, decorated
/// span string, text, start+width/end/count).
pub fn delete_region(shadow: &Shadow, doc: &str, op: &Value) -> Option<(u64, u64)> {
    if let Some((sub, ord, w)) = field(op, &["span", "vspan"]).and_then(span_dict) {
        return if sub == 1 { Some((ord, w)) } else { None };
    }
    if let Some(s) = str_field(op, &["span", "vspan", "text"]) {
        let l = locate(shadow, Some(doc), s)?;
        return Some((l.ord, l.width));
    }
    if let Some(start) = str_field(op, &["start", "address", "at"]) {
        let (sub, ord, _) = resolve_position(shadow, doc, start)?;
        if sub != 1 {
            return None;
        }
        if let Some(w) = str_field(op, &["width"]).and_then(crate::tum::parse_width) {
            return Some((ord, w));
        }
        if let Some(e) = str_field(op, &["end"]) {
            return match parse_dotted(e)?.as_slice() {
                [0, w] => Some((ord, *w)),
                [1, eord] if *eord >= ord => Some((ord, eord - ord)),
                _ => None,
            };
        }
        if let Some(n) = field(op, &["count"]).and_then(Value::as_u64) {
            return Some((ord, n));
        }
    }
    None
}

/// Rearrange cut ordinals from `cuts` array or cut1..cut4 / v1..v3 /
/// starta..endb keyed fields.
pub fn cuts_of(op: &Value) -> Vec<u64> {
    let parse_cut = |v: &Value| -> Option<u64> {
        if let Some(n) = v.as_u64() {
            return Some(n);
        }
        match crate::tum::parse_vpos(v.as_str()?) {
            Some((1, o)) => Some(o),
            _ => None,
        }
    };
    if let Some(arr) = field(op, &["cuts"]).and_then(Value::as_array) {
        return arr.iter().filter_map(parse_cut).collect();
    }
    let mut cuts = Vec::new();
    for keys in [
        &["cut1", "v1", "starta"][..],
        &["cut2", "v2", "enda"][..],
        &["cut3", "v3", "startb"][..],
        &["cut4", "endb"][..],
    ] {
        match field(op, keys).and_then(parse_cut) {
            Some(c) => cuts.push(c),
            None => break,
        }
    }
    cuts
}

fn result_str(op: &Value) -> Option<String> {
    match field(op, &["result"]) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Object(o)) => o.get("version").and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}

/// `"A->B": "<link id>"` arrow-keyed create_link results
/// (links/multi_hop_reverse_traversal).
pub fn arrow_results(op: &Value) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    if let Some(o) = op.as_object() {
        for (k, v) in o {
            if let Some((f, t)) = k.split_once("->") {
                if let Some(r) = v.as_str() {
                    if link_home_docid(r).is_some() {
                        out.push((f.trim().to_string(), t.trim().to_string(), r.to_string()));
                    }
                }
            }
        }
    }
    out
}
