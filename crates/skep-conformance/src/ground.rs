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
//! * **Comparison-pair seeds** (round 3) — a compare op pairing a probed
//!   dest region with a source's ordinal-1 span testifies to that source's
//!   unrecorded content; the same recorded pairs pin macro-vcopy covers
//!   exactly (the minimal cover consistent with the recorded widths).
//! * **Placeholder seeds** — a doc that participates in link creation while
//!   empty (its content neither recorded nor probed) gets the uniform
//!   follow-evidence text when the scenario records one, else a marker
//!   string, because a link needs a nonempty endset on both sides; tagged
//!   loudly either way.
//! * **Keyed setup expansion** (round 3) — `<name>_text` fields plus a
//!   `link: "doc1[…] -> doc2[…]"` spec expand to creates, inserts, and a
//!   [`SetupStep::Link`], with later follow results overriding the
//!   label-derived link extents.
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
/// `[ord, ord+width)` (content subspace); links carry located content
/// endsets per side plus the golden id the recording assigned (subspace/
/// insert_text_check_both_link_positions's keyed setup records
/// `link: "doc1[1.2-1.4] -> doc2[1.2-1.4]"` with its `link_id`).
#[derive(Clone, Debug)]
pub enum SetupStep {
    Insert { doc: String, bytes: Vec<u8> },
    Copy { doc: String, src: String, ord: u64, width: u64 },
    Link { from: Vec<(String, u64, u64)>, to: Vec<(String, u64, u64)>, golden: Option<String> },
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
/// place (`at: None` = appended at then-current end). A delete carries the
/// bytes it removed and the ordinal it removed them at IN THE SIM PASS THAT
/// RECORDED IT — under a different seed the true position may differ, so the
/// undo tries the recorded position and the append position (see
/// [`undo_to_initial`]); discovery/find_documents_after_delete's
/// "Prefix: " + delete("Findable") world is recoverable only through this.
#[derive(Clone)]
enum Edit {
    Ins { at: Option<u64>, bytes: Vec<u8> },
    /// `explicit` = the position was numerically recorded (client-sent), so
    /// the undo reinserts there FIRST; a text-located position tries the end
    /// first (the seed-shift shape).
    Del { at: u64, bytes: Vec<u8>, explicit: bool },
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

    // Comparison-pair seeds: a compare op pairing dest[t..t+w] with
    // src[1..w+1] testifies to a source doc's unrecorded content — the
    // bytes the dest's probe shows at the paired region (identity/
    // identity_mixed_sources: two sources never filled on the record, each
    // pinned by its compare against the target).
    {
        let mut sim = Sim::new(&g.implied_creates, &seeds);
        for (i, op) in ops.iter().enumerate() {
            sim.step(i, op, ops);
        }
        for (dest, tord, src, sord, w) in comparison_pairs(ops, &sim.shadow) {
            if sord != 1 || seeds.contains_key(&src) || sim.shadow.text_len(&src) > 0 {
                continue;
            }
            let Some(probe) = next_content_probe(ops, 0, &dest, &sim.shadow) else { continue };
            let b = probe.as_bytes();
            let (t0, w) = ((tord - 1) as usize, w as usize);
            if t0 + w > b.len() {
                continue;
            }
            let bytes = b[t0..t0 + w].to_vec();
            g.tags.push(format!(
                "implied-setup:comparison-seed: {src} starts with {:?} (its compare against \
                 {dest} pairs that region at source ordinal 1)",
                String::from_utf8_lossy(&bytes)
            ));
            seeds.insert(src, bytes);
        }
    }

    // Placeholder seeds for empty link participants, discovered on a replay
    // under the settled seeds. When every follow/traverse expectation in the
    // scenario records one uniform text, that text IS the evidence of what
    // the script filled such docs with (star_hub); otherwise a loud marker.
    {
        let mut sim = Sim::new(&g.implied_creates, &seeds);
        for (i, op) in ops.iter().enumerate() {
            sim.step(i, op, ops);
        }
        let evidence = uniform_follow_text(ops);
        for doc in sim.link_participants_empty {
            // Endset-anchored construction first: a later retrieve_endsets
            // recording this doc's endset coordinates, together with the
            // create_links' own source_text/target_text, pins the content
            // exactly (link_poom/link_poom_no_shift: "First" at 1.1 w 5,
            // "second" at 1.16 w 6 — gaps filled with spaces).
            if let Some(seed) = endset_anchored_seed(ops, &sim.shadow, &doc) {
                if let Entry::Vacant(slot) = seeds.entry(doc.clone()) {
                    g.tags.push(format!(
                        "implied-setup:endset-anchored-seed: {doc} starts with {:?} (link texts \
                         placed at the recorded endset ordinals)",
                        String::from_utf8_lossy(&seed)
                    ));
                    slot.insert(seed);
                }
                continue;
            }
            // Per-doc landing evidence next: a traverse hop whose to-side
            // resolves to this doc records exactly what the script filled
            // it with (diamond_link_pattern's "Path B"/"Path C"/
            // "Destination"); the scenario-uniform text and the loud marker
            // remain the fallbacks.
            let landing = follow_landing_text(ops, &sim.shadow, &doc);
            if let Entry::Vacant(slot) = seeds.entry(doc) {
                match (&landing, &evidence) {
                    (Some(t), _) => {
                        g.tags.push(format!(
                            "implied-setup:placeholder-from-landing: {} participates in a link \
                             while empty; the traverse evidence lands {t:?} there, seeded that",
                            slot.key()
                        ));
                        slot.insert(t.as_bytes().to_vec());
                    }
                    (None, Some(t)) => {
                        g.tags.push(format!(
                            "implied-setup:placeholder-from-evidence: {} participates in a link \
                             while empty; every follow expectation records {t:?}, seeded that",
                            slot.key()
                        ));
                        slot.insert(t.as_bytes().to_vec());
                    }
                    (None, None) => {
                        let marker = format!("[{}]", slot.key());
                        g.tags.push(format!(
                            "implied-setup:placeholder: {} participates in a link while empty \
                             and no recorded probe reveals its content; seeded {marker:?}",
                            slot.key()
                        ));
                        slot.insert(marker.into_bytes());
                    }
                }
            }
        }
    }

    // Final pass under the settled seeds builds the definitive plans.
    let mut sim = Sim::new(&g.implied_creates, &seeds);
    for (i, op) in ops.iter().enumerate() {
        sim.step(i, op, ops);
    }
    for (i, plan) in &sim.plans {
        let strategy = sim.plan_notes.get(i).map(|s| format!(" [{s}]")).unwrap_or_default();
        g.tags.push(format!(
            "expansion-plan: op {i} `{}` → {} concrete steps{strategy}",
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
/// any mismatch aborts the inference. Recursive because a delete's undo has
/// two candidate reinsertion points (the recorded ordinal, and the end for
/// the seed-shifted append shape) — the candidate that lets the REST of the
/// chain verify wins; depth is the edit count (single digits).
fn undo_to_initial(probed: &str, edits: &[Edit]) -> Option<Vec<u8>> {
    undo_edits(probed.as_bytes().to_vec(), edits)
}

fn undo_edits(cur: Vec<u8>, edits: &[Edit]) -> Option<Vec<u8>> {
    let Some((last, rest)) = edits.split_last() else { return Some(cur) };
    match last {
        Edit::Ins { at, bytes } => {
            let n = bytes.len();
            let start = match at {
                Some(ord) => (*ord as usize).checked_sub(1)?,
                None => cur.len().checked_sub(n)?,
            };
            if start + n > cur.len() || &cur[start..start + n] != bytes.as_slice() {
                return None;
            }
            let mut next = cur;
            next.drain(start..start + n);
            undo_edits(next, rest)
        }
        Edit::Del { at, bytes, explicit } => {
            // Candidate reinsertion points. Explicit (client-sent) position:
            // the recorded ordinal first — it is authoritative (isolation/
            // delete_does_not_affect_other_documents "1.3 for 0.5 (CDEFG)"
            // must reinsert at 3, not the end). Text-located: the end first
            // (a seed prefix shifts an append-built doc's delete rightward —
            // the recorded position undercounts by the seed length).
            let rec = (*at as usize).saturating_sub(1).min(cur.len());
            let mut cands =
                if *explicit { vec![rec, cur.len()] } else { vec![cur.len(), rec] };
            cands.dedup();
            for k in cands {
                let mut next = cur.clone();
                next.splice(k..k, bytes.iter().copied());
                if let Some(initial) = undo_edits(next, rest) {
                    return Some(initial);
                }
            }
            None
        }
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
            let mut next = cur;
            if *a > 0 && a <= b && b <= c && *c as usize <= next.len() + 1 {
                let mut s = scratch(&next);
                s.pivot("x", *a, a + (c - b), *c);
                next = s.text_string("x").into_bytes();
            }
            undo_edits(next, rest)
        }
        Edit::Swap { s1, e1, s2, e2 } => {
            // Same no-op mirror of Shadow::swap's guard as Pivot above.
            let mut next = cur;
            if *s1 > 0 && s1 <= e1 && e1 <= s2 && s2 <= e2 && *e2 as usize <= next.len() + 1 {
                let (w1, w2) = (e1 - s1, e2 - s2);
                let mut s = scratch(&next);
                s.swap("x", *s1, s1 + w2, s2 + w2 - w1, *e2);
                next = s.text_string("x").into_bytes();
            }
            undo_edits(next, rest)
        }
    }
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
    /// Per-plan policy tag (which reconstruction strategy produced it).
    plan_notes: BTreeMap<usize, &'static str>,
}

impl Sim {
    fn new(implied: &[String], seeds: &BTreeMap<String, Vec<u8>>) -> Sim {
        let mut sim = Sim {
            shadow: Shadow::new(),
            logs: BTreeMap::new(),
            failed_probe: None,
            link_participants_empty: Vec::new(),
            plans: BTreeMap::new(),
            plan_notes: BTreeMap::new(),
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
        // Insert/Copy contributions are RECORDED as edits: undo-based seed
        // inference must be able to walk back through plan-built content
        // (link_chain_with_transclusion: the embed plan builds B, a later
        // recorded insert appends, and the probe undo crosses both).
        match s {
            SetupStep::Insert { doc, bytes } => {
                if !self.shadow.knows(doc) {
                    self.shadow.create_doc(doc, None);
                }
                let end = self.shadow.text_len(doc) + 1;
                self.shadow.insert(doc, end, bytes);
                self.record(doc, Edit::Ins { at: None, bytes: bytes.clone() });
            }
            SetupStep::Copy { doc, src, ord, width } => {
                let bytes = self.shadow.slice(src, *ord, *width);
                if !self.shadow.knows(doc) {
                    self.shadow.create_doc(doc, None);
                }
                let end = self.shadow.text_len(doc) + 1;
                self.shadow.insert(doc, end, &bytes);
                self.record(doc, Edit::Ins { at: None, bytes });
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
        if label.starts_with("create_documents")
            || label.starts_with("create_sources")
            || label.starts_with("create_multiple")
        {
            self.sim_create_documents(i, op, all);
            return;
        }
        if label == "setup" {
            if let Some(steps) = self.parse_keyed_setup(op, i, all) {
                self.plan(i, steps);
            } else if let Some(desc) = str_field(op, &["description", "desc"]) {
                if let Some(steps) = self.parse_setup_description(desc) {
                    self.plan(i, steps);
                }
            }
            return;
        }
        if label.starts_with("create_doc") || label.starts_with("create_target") {
            let name = crate::fields::create_name_of(op);
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
            // insert_all + texts: one text per created doc, in creation
            // order (links/link_chain_three_hops fills its four documents
            // through one op) — never a single concatenated insert.
            if let Some(texts) = distributed_insert_texts(op) {
                let docs: Vec<String> = distribution_targets(&self.shadow, texts.len());
                for (d, t) in docs.iter().zip(&texts) {
                    let end = self.shadow.text_len(d) + 1;
                    self.shadow.insert(d, end, t.as_bytes());
                    self.record(d, Edit::Ins { at: None, bytes: t.as_bytes().to_vec() });
                }
                return;
            }
            let Some(mut doc) = self.doc_ref(op, &["doc", "docid"]) else { return };
            let Some(mut text) = insert_text(op) else { return };
            // Doc-less insert aim: the next recorded vspanset probe names
            // the doc the script observed changed (content/
            // insert_vspace_mapping: register held the version, the probe
            // pins the original) — mirror of the translator's policy.
            if str_field(op, &["doc", "docid"]).is_none()
                && doc_from_label(label_of(op)).is_none()
            {
                if let Some(d2) = insert_aim_from_probe(all, i, &self.shadow, &doc, &text) {
                    self.shadow.set_current(&d2);
                    doc = d2;
                }
            }
            let pos = str_field(op, &["address", "at", "position", "vaddr"]);
            let (at, ord) = match pos.and_then(|p| resolve_position(&self.shadow, &doc, p)) {
                Some((1, o, _)) => (Some(o), o),
                Some(_) => return, // link-subspace insert: no content effect
                None => match insert_pos_from_post_state(op, &self.shadow, &doc, &text) {
                    // Post-state-pinned position (mirror of the translator's
                    // `insert-position-from-post-state`).
                    Some(o) => (Some(o), o),
                    None => (None, self.shadow.text_len(&doc) + 1),
                },
            };
            // Recorded-vspanset width authority: pad an append-shaped insert
            // whose doc's next clean vspanset probe records more than the
            // field text supplies (provenance/createnewversion_text_vs_links
            // 0.34 over a 33-char text) — mirror of the translator's policy.
            if at.is_none() || self.shadow.text_len(&doc) == 0 {
                let new_len = self.shadow.text_len(&doc) + text.len() as u64;
                if let Some(pad) = insert_pad_width(all, i, &self.shadow, &doc, new_len) {
                    text.push_str(&" ".repeat(pad as usize));
                }
            }
            self.shadow.insert(&doc, ord, text.as_bytes());
            self.record(&doc, Edit::Ins { at, bytes: text.into_bytes() });
            self.check_probes(op);
            return;
        }
        if label.starts_with("delete_all") || label.starts_with("remove_all") {
            if let Some(doc) = self.doc_ref(op, &["doc", "docid"]) {
                if delete_is_noop(&self.shadow, all, i, &doc) {
                    return; // recorded post-state shows udanax removed nothing
                }
                let n = self.shadow.text_len(&doc);
                let bytes = self.shadow.slice(&doc, 1, n);
                self.shadow.delete(&doc, 1, n);
                self.record(&doc, Edit::Del { at: 1, bytes, explicit: true });
            }
            return;
        }
        if label.starts_with("delete") || label.starts_with("remove") {
            let Some(doc) = self.doc_ref(op, &["doc", "docid"]) else { return };
            if delete_is_noop(&self.shadow, all, i, &doc) {
                self.check_probes(op);
                return; // recorded post-state shows udanax removed nothing
            }
            if let Some((ord, w, how)) = resolve_delete_span(&self.shadow, all, i, &doc, op) {
                // Bytes removed: the sim slice — unless the op DESCRIBES the
                // removed text (the "(CDEFG)" parenthetical) and the sim's
                // state cannot yet cover the width (seed not in place); the
                // description then feeds the undo the true bytes.
                let mut bytes = self.shadow.slice(&doc, ord, w);
                if bytes.len() as u64 != w {
                    if let Some(d) = delete_described_bytes(op, w) {
                        bytes = d;
                    }
                }
                let explicit = !matches!(how, "text-located" | "delete-text-from-label");
                self.shadow.delete(&doc, ord, w);
                self.record(&doc, Edit::Del { at: ord, bytes, explicit });
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

    fn sim_create_documents(&mut self, i: usize, op: &Value, all: &[Value]) {
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
        // Role-keyed fields: doc1/doc2 (subspace/insert_text_check_link_
        // positions), source1/source2 (identity/identity_mixed_sources),
        // targetN — any `<role><n>` key holding a dotted docid.
        let mut keyed = false;
        if let Some(o) = op.as_object() {
            let mut pairs: Vec<(String, String)> = o
                .iter()
                .filter(|(k, _)| keyed_role(k))
                .filter_map(|(k, v)| {
                    let id = v.as_str()?;
                    parse_dotted(id)?;
                    Some((k.clone(), id.to_string()))
                })
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
        let group = group_word(op);
        let count = field(op, &["count"])
            .and_then(Value::as_u64)
            .map(|c| c as usize)
            .unwrap_or_else(|| results.len().max(names.len()).max(1));
        let mut created_here: Vec<String> = Vec::new();
        for k in 0..count.max(results.len()) {
            let id = results.get(k).cloned().unwrap_or_else(|| self.shadow.synthesize_docid());
            let name = names
                .get(k)
                .cloned()
                .or_else(|| group.as_ref().map(|t| format!("{t}{}", k + 1)));
            self.shadow.create_doc(&id, name.as_deref());
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
                self.record(&id, Edit::Ins { at: Some(1), bytes: t.as_bytes().to_vec() });
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
            let Some(expected) = next_content_probe(all, i, &id, &self.shadow) else { continue };
            let sources = self.shadow.content_docs_except(&id);
            let sub = cover_from_comparisons(&self.shadow, &id, &expected, all)
                .unwrap_or_else(|| cover_with_sources(&self.shadow, &id, &sources, &expected));
            for s in &sub {
                self.apply_step(s);
            }
            steps.extend(sub);
        }
        if !steps.is_empty() {
            self.plans.insert(i, steps);
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

    /// Keyed setup (subspace/insert_text_check_both_link_positions):
    /// `doc1_text: "ABCDE", doc2_text: "12345", link: "doc1[1.2-1.4] ->
    /// doc2[1.2-1.4]", link_id: "…"` — each `<name>_text` key creates a doc
    /// bound to `<name>` and inserts its text; the `link` spec grounds both
    /// endsets against the just-built content, then a later recorded follow
    /// result for the same link id (the golden's own evidence of the exact
    /// endset extent) overrides the label-derived spans. `None` when the op
    /// carries no `<name>_text` keys (the clause grammar then gets its turn).
    fn parse_keyed_setup(&mut self, op: &Value, i: usize, all: &[Value]) -> Option<Vec<SetupStep>> {
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
        let mut probe = self.shadow.clone();
        for (name, text) in &texts {
            let golden = probe
                .resolve_doc(name)
                .filter(|g| probe.knows(g))
                .unwrap_or_else(|| probe.synthesize_docid());
            if probe.knows(&golden) {
                probe.bind_name(name, &golden);
                self.shadow.bind_name(name, &golden);
            } else {
                probe.create_doc(&golden, Some(name));
                self.shadow.create_doc(&golden, Some(name));
            }
            probe.insert(&golden, 1, text.as_bytes());
            steps.push(SetupStep::Insert { doc: golden, bytes: text.as_bytes().to_vec() });
        }
        if let Some(spec) = str_field(op, &["link", "links"]) {
            if let Some((f, t)) = spec.split_once("->") {
                let ground = |probe: &Shadow, side: &str| -> Option<(String, u64, u64)> {
                    let side = side.trim();
                    if let Some(l) = locate(probe, None, side) {
                        return Some((l.doc, l.ord, l.width));
                    }
                    let doc = probe.resolve_doc(side)?;
                    let n = probe.text_len(&doc);
                    (n > 0).then_some((doc, 1, n))
                };
                let golden_link = str_field(op, &["link_id", "result"]).map(str::to_string);
                if let (Some(mut fs), Some(mut ts)) = (ground(&probe, f), ground(&probe, t)) {
                    // Follow-result evidence: a later op recording this
                    // link's spans pins the side whose doc it names.
                    if let Some(g) = &golden_link {
                        for later in &all[i + 1..] {
                            let mentions =
                                str_field(later, &["link", "link_id", "id"]) == Some(g.as_str());
                            if !mentions {
                                continue;
                            }
                            let Some(v) = field(later, &["result"]) else { continue };
                            let Some((Some(doc), spans)) = crate::fields::expect_spans_raw(v)
                            else {
                                continue;
                            };
                            let Some((start, width)) = spans.first() else { continue };
                            let (Some((1, ord)), Some(w)) = (
                                crate::tum::parse_vpos(start),
                                crate::tum::parse_width(width),
                            ) else {
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
        // Explicit destination only — the register fallback waits until the
        // copied bytes are known, so forward evidence can aim first.
        // "end"/"start"/"end of doc" are position markers, not doc refs
        // (edgecases/vcopy_to_same_document).
        let explicit_dest: Option<String> = match to_raw {
            Some(s) if is_position_marker(s) => self.shadow.scoped(),
            Some(s) => self.shadow.resolve_doc(s),
            None => str_field(op, &["doc", "docid"]).and_then(|s| self.shadow.resolve_doc(s)),
        };

        // Macro forms: grounded by the destination's next content probe.
        let from_list = field(op, &["from", "sources", "order"]).and_then(Value::as_array).map(
            |a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect::<Vec<_>>(),
        );
        let is_macro = from_list.is_some()
            || label.starts_with("vcopy_multiple")
            || label.starts_with("vcopy_all")
            || label.starts_with("vcopy_from_both");
        if is_macro {
            let Some(dest) = explicit_dest.or_else(|| self.doc_ref(op, &["doc", "docid"]))
            else {
                return;
            };
            let sources: Vec<String> = from_list
                .map(|names| names.iter().filter_map(|n| self.shadow.resolve_doc(n)).collect())
                .unwrap_or_else(|| self.shadow.content_docs_except(&dest));
            let Some(expected) = next_content_probe(all, i, &dest, &self.shadow) else { return };
            let existing = self.shadow.text_string(&dest);
            let remainder = expected.strip_prefix(&existing).unwrap_or(&expected).to_string();
            // Recorded comparison pairs pin the exact cover when present.
            let steps = cover_from_comparisons(&self.shadow, &dest, &remainder, all)
                .unwrap_or_else(|| {
                    cover_with_sources(&self.shadow, &dest, &sources, &remainder)
                });
            self.plan(i, steps);
            return;
        }

        // Ordinary vcopy: capture bytes exactly as the translator will,
        // keeping each contiguous source region as a (doc, ord, width) spec.
        let mut copied: Vec<u8> = Vec::new();
        let mut spec_list: Vec<(String, u64, u64)> = Vec::new();
        if let Some(arr) =
            field(op, &["specs", "specset", "source", "sources"]).and_then(Value::as_array)
        {
            for v in arr {
                if let Some((docid, spans)) = vspec_dict(v) {
                    for (sub, ord, w) in spans {
                        if sub == 1 {
                            copied.extend(self.shadow.slice(&docid, ord, w));
                            spec_list.push((docid.clone(), ord, w));
                        }
                    }
                } else if let Some(t) = v.as_str() {
                    if let Some(l) = locate(&self.shadow, None, t) {
                        copied.extend(self.shadow.slice(&l.doc, l.ord, l.width));
                        spec_list.push((l.doc, l.ord, l.width));
                    }
                }
            }
        } else if let Some(arr) = field(op, &["spans"]).and_then(Value::as_array) {
            for t in arr.iter().filter_map(Value::as_str) {
                if let Some(l) = locate(&self.shadow, None, t) {
                    copied.extend(self.shadow.slice(&l.doc, l.ord, l.width));
                    spec_list.push((l.doc, l.ord, l.width));
                }
            }
        } else if let Some((1, ord, w)) = field(op, &["source_span", "span"]).and_then(span_dict) {
            let src = str_field(op, &["from", "source_doc"])
                .and_then(|s| self.shadow.resolve_doc(s))
                .or_else(|| {
                    let hint = explicit_dest.clone().unwrap_or_default();
                    self.shadow.content_docs_except(&hint).first().cloned()
                });
            if let Some(src) = src {
                copied.extend(self.shadow.slice(&src, ord, w));
                spec_list.push((src, ord, w));
            }
        } else if let Some(t) = str_field(op, &["text", "span"]) {
            let hint =
                str_field(op, &["from", "source_doc"]).and_then(|s| self.shadow.resolve_doc(s));
            if let Some(l) = locate(&self.shadow, hint.as_deref(), t) {
                copied.extend(self.shadow.slice(&l.doc, l.ord, l.width));
                spec_list.push((l.doc, l.ord, l.width));
            }
        } else if let Some(s) = str_field(op, &["from", "source"]) {
            if let Some(from) = self.shadow.resolve_doc(s) {
                // `from: <doc>` with no span: whole current extent (mirrors
                // the translator's fallback).
                let n = self.shadow.text_len(&from);
                copied.extend(self.shadow.slice(&from, 1, n));
                spec_list.push((from, 1, n));
            } else if let Some(l) = locate(&self.shadow, None, s) {
                // A described region, not a doc ("positions 1-4 (Orig)" —
                // vcopy_to_same_document); mirrors the translator.
                copied.extend(self.shadow.slice(&l.doc, l.ord, l.width));
                spec_list.push((l.doc, l.ord, l.width));
            }
        }
        if copied.is_empty() {
            return;
        }
        let first_src: Option<String> = spec_list.first().map(|(d, _, _)| d.clone());
        // Destination: explicit reference first; else the doc whose later
        // probe shows the copied bytes embedded (endsets/endsets_transcluded_
        // source: the dest-less vcopy built a SECOND doc the register never
        // pointed at); the register only for genuinely bare evidence-less
        // ops. Prefer an evidenced doc other than the source, falling back
        // to the source itself (internal transclusion is real).
        let dest = explicit_dest.or_else(|| {
            let copied_s = String::from_utf8_lossy(&copied).into_owned();
            let evidenced: Vec<String> = self
                .shadow
                .all_docs()
                .into_iter()
                .filter(|d| {
                    next_content_probe(all, i, d, &self.shadow)
                        .is_some_and(|p| p.contains(&copied_s))
                })
                .collect();
            evidenced
                .iter()
                .find(|d| Some(d.as_str()) != first_src.as_deref())
                .or_else(|| evidenced.first())
                .cloned()
                .or_else(|| self.doc_ref(op, &["doc", "docid"]))
        });
        let Some(dest) = dest else { return };
        let ord = str_field(op, &["address", "at", "position"])
            .and_then(|p| resolve_position(&self.shadow, &dest, p))
            .and_then(|(s, o, _)| if s == 1 { Some(o) } else { None });
        let (at, o) = match (ord, to_raw) {
            (Some(o), _) => (Some(o), o),
            (None, Some(s)) if s.starts_with("start") => (Some(1), 1),
            (None, _) => (None, self.shadow.text_len(&dest) + 1),
        };
        // Append-shaped copies may carry unrecorded world structure the
        // scenario's own evidence pins — recorded comparison pairs and
        // content probes reconstruct it as an expansion plan (round-4
        // prefix-insert cluster: "Copied: ", "Link doc: ", "B prefix: ").
        if at.is_none() {
            if let Some(plan) = self.vcopy_reconstruction(i, all, &dest, &copied, &spec_list) {
                self.plan(i, plan);
                return;
            }
        }
        self.shadow.insert(&dest, o, &copied);
        self.record(&dest, Edit::Ins { at, bytes: copied });
        self.check_probes(op);
    }

    /// Evidence-driven reconstruction of an append-shaped vcopy whose direct
    /// execution would not reproduce the recorded world. Four strategies, in
    /// authority order; `None` = no evidence demands a plan (the caller runs
    /// the copy directly).
    fn vcopy_reconstruction(
        &mut self,
        i: usize,
        all: &[Value],
        dest: &str,
        copied: &[u8],
        spec_list: &[(String, u64, u64)],
    ) -> Option<Vec<SetupStep>> {
        let o = self.shadow.text_len(dest) + 1;
        let pairs: Vec<(u64, String, u64, u64)> = comparison_pairs(all, &self.shadow)
            .into_iter()
            .filter(|(d, _, _, _, _)| d == dest)
            .map(|(_, tord, src, sord, w)| (tord, src, sord, w))
            .collect();
        let probe = next_content_probe(all, i, dest, &self.shadow);

        // 1. Full pair-cover of an empty destination's probe (content/
        //    vcopy_multiple_spans: the compare's pairs pin "Copied: " +
        //    both copies at their recorded widths — including the trailing
        //    period the text-located span misses). Only when no later copy
        //    op also builds this destination (a second builder would
        //    double-apply the cover).
        if self.shadow.text_len(dest) == 0 && !pairs.is_empty() {
            if let Some(p) = &probe {
                if !later_copy_into(all, i, dest, &self.shadow) {
                    if let Some(cover) = cover_from_comparisons(&self.shadow, dest, p, all) {
                        if cover.iter().any(|s| matches!(s, SetupStep::Copy { .. })) {
                            self.plan_notes.insert(i, "vcopy-cover-from-comparisons");
                            return Some(cover);
                        }
                    }
                }
            }
        }

        // 2. Recorded pair landing exactly at the append position overrides
        //    the located source span (versions/cross_version_vcopy: the
        //    compare records source ordinal 15 width 12 where the label
        //    text located ordinal 20).
        if spec_list.len() == 1 {
            if let Some((_, s2, o2, w2)) = pairs.iter().find(|(t, _, _, _)| *t == o) {
                let own = spec_list[0] == (s2.clone(), *o2, *w2);
                let bytes = self.shadow.slice(s2, *o2, *w2);
                if !own && bytes.len() as u64 == *w2 && *w2 > 0 {
                    self.plan_notes.insert(i, "vcopy-span-from-comparison");
                    return Some(vec![SetupStep::Copy {
                        doc: dest.to_string(),
                        src: s2.clone(),
                        ord: *o2,
                        width: *w2,
                    }]);
                }
            }
        }

        // 3. Recorded pair landing PAST the append position, matching this
        //    op's own source span: the gap is an unrecorded prefix insert
        //    (content/vcopy_preserves_identity: the copy landed at 9, so 8
        //    filler bytes precede it; no probe records them, so spaces).
        if spec_list.len() == 1 {
            let (s0, o0, w0) = &spec_list[0];
            if let Some((t, _, _, _)) = pairs
                .iter()
                .find(|(t, s, so, w)| *t > o && (s, so, w) == (s0, o0, w0))
            {
                let fill = (*t - o) as usize;
                let bytes = match &probe {
                    Some(p) if p.len() >= (o - 1) as usize + fill => {
                        p.as_bytes()[(o - 1) as usize..(o - 1) as usize + fill].to_vec()
                    }
                    _ => vec![b' '; fill],
                };
                self.plan_notes.insert(i, "vcopy-prefix-from-comparison");
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
        let p = probe?;
        let c = self.shadow.text_string(dest);
        let r = p.strip_prefix(c.as_str())?;
        let copied_s = String::from_utf8_lossy(copied).into_owned();
        let k = r.find(&copied_s)?;
        let mut ext = 0u64;
        if let Some(suffix) = later_appends_text(all, i, dest, &self.shadow) {
            if r.ends_with(&suffix) {
                let rprime = r.len() - suffix.len();
                let end = k + copied_s.len();
                if end < rprime {
                    if let Some((ls, lo, lw)) = spec_list.last() {
                        let need = (rprime - end) as u64;
                        let cont = self.shadow.slice(ls, lo + lw, need);
                        if cont.len() as u64 == need
                            && cont == r.as_bytes()[end..rprime]
                        {
                            ext = need;
                        }
                    }
                }
            }
        }
        if k == 0 && ext == 0 {
            return None; // direct execution already reproduces the probe
        }
        self.plan_notes.insert(i, "vcopy-embed-plan");
        let mut steps = Vec::new();
        if k > 0 {
            steps.push(SetupStep::Insert {
                doc: dest.to_string(),
                bytes: r.as_bytes()[..k].to_vec(),
            });
        }
        for (j, (s, so, w)) in spec_list.iter().enumerate() {
            let w = if j + 1 == spec_list.len() { *w + ext } else { *w };
            steps.push(SetupStep::Copy { doc: dest.to_string(), src: s.clone(), ord: *so, width: w });
        }
        Some(steps)
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
            // A snapshot op WITH a content expectation is a contents probe
            // of the named/scoped doc (isolation/delete_does_not_affect_
            // other_documents seeds doc B only through its snapshots);
            // content-less snapshots stay meta.
            || label.starts_with("snapshot")
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
        // Address strings and recording-client python reprs are never
        // content bytes (mirrors the translator; the repr guard is what
        // keeps retrieve_vspan_empty's "<VSpan …>" out of the seeds).
        if strings.iter().any(|s| {
            (s.contains('.') && parse_dotted(s).is_some()) || crate::fields::is_python_repr(s)
        }) {
            return;
        }
        // A full_* probe reads the doc the last CONTENT write touched
        // (mirror of the translator's `full-probe-targets-last-write`).
        if label.starts_with("full_") && str_field(op, &["doc", "docid"]).is_none() {
            if let Some(d) = self.shadow.last_written.clone().filter(|d| self.shadow.knows(d)) {
                self.probe(&d, &strings.join(""));
                return;
            }
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
/// scenario's own compare/find ops. A matched copy never keeps trailing
/// whitespace (round-3: content/vcopy_from_multiple_documents's own
/// comparisons record width 8 "Source A" where the greedy match took
/// "Source A " — the scripts copied word-shaped regions and joined with
/// literal separators), so the maximal match is trimmed back to its last
/// non-space byte before it drops below the copy floor.
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
            if let Some((ord, mut len)) = found {
                while len > MIN_COPY && e[i + len - 1].is_ascii_whitespace() {
                    len -= 1;
                }
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

/// Does a later vcopy/copy op (before `dest`'s next content probe) also
/// build `dest`? Guard for the full pair-cover strategy.
fn later_copy_into(all: &[Value], i: usize, dest: &str, shadow: &Shadow) -> bool {
    for op in &all[i + 1..] {
        let label = label_of(op).to_ascii_lowercase();
        if !(label.starts_with("vcopy") || label.starts_with("copy")) {
            continue;
        }
        let target = str_field(op, &["to", "dest", "target", "target_doc", "doc", "docid"])
            .and_then(|s| shadow.resolve_doc(s));
        if target.as_deref() == Some(dest) || target.is_none() {
            return true; // an unaimed later copy is conservatively a builder
        }
    }
    false
}

/// The concatenated text of the recorded APPEND edits into `dest` between
/// op `i` and `dest`'s next content probe — the probe suffix those later
/// ops will contribute. `None` when any later edit into `dest` is not a
/// derivable append (position args, deletes, rearranges, underivable copy
/// text) — the caller then skips the copy-extension heuristic.
fn later_appends_text(all: &[Value], i: usize, dest: &str, shadow: &Shadow) -> Option<String> {
    let mut out = String::new();
    for op in &all[i + 1..] {
        let label = label_of(op).to_ascii_lowercase();
        let is_probe = label.starts_with("content") || label.starts_with("retrieve");
        if is_probe {
            let target = str_field(op, &["doc", "docid"]).and_then(|s| shadow.resolve_doc(s));
            if target.as_deref() == Some(dest) {
                return Some(out); // reached the probe
            }
        }
        let writes = ["insert", "append", "delete", "remove", "vcopy", "copy", "pivot", "swap",
            "rearrange"];
        if !writes.iter().any(|w| label.starts_with(w)) {
            continue;
        }
        let target = str_field(op, &["to", "dest", "target", "target_doc", "doc", "docid"])
            .and_then(|s| shadow.resolve_doc(s));
        if target.as_deref() != Some(dest) {
            continue; // a write to another doc
        }
        let positioned = str_field(op, &["address", "at", "position", "vaddr"]).is_some();
        if positioned || !(label.starts_with("insert") || label == "append") {
            return None; // not a derivable append into dest
        }
        out.push_str(&insert_text(op)?);
    }
    Some(out)
}

/// `insert_all`-style distribution: a texts array of ≥ 2 entries under a
/// label that names no single position — one text per document, never one
/// concatenated insert.
pub fn distributed_insert_texts(op: &Value) -> Option<Vec<String>> {
    let label = label_of(op).to_ascii_lowercase();
    if !(label == "insert_all" || label == "insert_each") {
        return None;
    }
    let texts: Vec<String> = field(op, &["texts", "strings"])
        .and_then(Value::as_array)?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    (texts.len() >= 2).then_some(texts)
}

/// The n most recently created docs, creation order — the targets an
/// `insert_all` distributes over (its creates immediately precede it).
pub fn distribution_targets(shadow: &Shadow, n: usize) -> Vec<String> {
    let created = shadow.all_docs();
    let start = created.len().saturating_sub(n);
    created[start..].to_vec()
}

/// A doc-less insert's re-aim: the next recorded clean single-span vspanset
/// probe (before any other write) whose width equals ITS doc's current
/// extent plus this insert's length — the golden's own testimony of which
/// document the script inserted into (content/insert_vspace_mapping: the
/// register held the fresh version; the probe pins the original). Returns
/// the re-aimed doc only when it differs from `current`.
pub fn insert_aim_from_probe(
    all: &[Value],
    i: usize,
    shadow: &Shadow,
    current: &str,
    text: &str,
) -> Option<String> {
    let writes = ["insert", "append", "delete", "remove", "vcopy", "copy", "pivot", "swap",
        "rearrange"];
    for op in &all[i + 1..] {
        let label = label_of(op).to_ascii_lowercase();
        if writes.iter().any(|w| label.starts_with(w)) {
            return None; // another write intervenes — probe no longer pins this insert
        }
        let Some((_, docid, spans)) = crate::fields::harvest_spanset(op) else { continue };
        let Some(docref) =
            docid.or_else(|| str_field(op, &["doc", "docid"]).map(str::to_string))
        else {
            continue;
        };
        let Some(d) = shadow.resolve_doc(&docref) else { continue };
        let [(start, w)] = spans.as_slice() else { continue };
        if start != "1.1" {
            continue;
        }
        let Some(w) = crate::tum::parse_width(w) else { continue };
        if d != current && shadow.text_len(&d) + text.len() as u64 == w {
            return Some(d);
        }
        return None; // the probe is satisfied by the current aim (or ambiguous)
    }
    None
}

/// Recorded-vspanset width authority for an append-shaped insert: the doc's
/// (or an intervening version-of-the-doc's) next clean single-span vspanset
/// probe records `new_len + pad` for a small pad — the script inserted more
/// than the golden's text field carries (provenance/createnewversion_text_
/// vs_links records 0.34 for a 33-char text; the retrieve was 33 wide, so
/// the padding byte is never content-compared). Returns the pad width.
pub fn insert_pad_width(
    all: &[Value],
    i: usize,
    shadow: &Shadow,
    doc: &str,
    new_len: u64,
) -> Option<u64> {
    let writes = ["insert", "append", "delete", "remove", "vcopy", "copy", "pivot", "swap",
        "rearrange"];
    let mut aliases: Vec<String> = vec![doc.to_string()];
    for op in &all[i + 1..] {
        let label = label_of(op).to_ascii_lowercase();
        if writes.iter().any(|w| label.starts_with(w)) {
            // A write into the doc ends the probe's authority over THIS
            // insert. A NAMED target that resolves elsewhere — or resolves
            // nowhere YET because it names a doc created between here and
            // there ("target" at scan time of versions/version_copies_link_
            // subspace op1) — is a write to another doc; only a doc-less or
            // alias-named write kills the scan.
            let raw = str_field(op, &["to", "dest", "target", "target_doc", "doc", "docid"]);
            let target = raw.and_then(|s| shadow.resolve_doc(s));
            match (raw, target) {
                (_, Some(t)) if !aliases.contains(&t) => continue,
                (Some(r), None) if !aliases.iter().any(|a| a.as_str() == r) => continue,
                _ => return None,
            }
        }
        if label.starts_with("create_version") || label.starts_with("version") {
            let src = str_field(op, &["from", "source", "of", "original"])
                .and_then(|s| shadow.resolve_doc(s));
            if src.as_deref() == Some(doc) || src.map_or(false, |s| aliases.contains(&s)) {
                if let Some(Value::String(res)) = field(op, &["result"]) {
                    aliases.push(res.clone());
                }
                aliases.push("version".to_string());
            }
            continue;
        }
        let Some((_, docid, spans)) = crate::fields::harvest_spanset(op) else { continue };
        let docref = docid
            .or_else(|| str_field(op, &["doc", "docid"]).map(str::to_string));
        let Some(docref) = docref else { continue };
        let matches = aliases.contains(&docref)
            || shadow.resolve_doc(&docref).is_some_and(|d| aliases.contains(&d));
        if !matches {
            continue;
        }
        let [(start, w)] = spans.as_slice() else { continue };
        if start != "1.1" {
            continue; // the malformed two-subspace pair never reaches here
        }
        let Some(w) = crate::tum::parse_width(w) else { continue };
        if w > new_len && w - new_len <= 2 {
            return Some(w - new_len);
        }
        return None; // clean probe consistent with (or below) the field text
    }
    None
}

/// A doc-less, position-less insert whose own recorded post-state shows the
/// text embedded MID-document: the position is recoverable as the single
/// gap where `post == pre[..k] + text + pre[k..]` — recorded post-state as
/// first authority (iaddress_allocation/interleaved_insert_delete's
/// insert_2 "BBB" turns "AA" into "ABBBA"). Returns the 1-based ordinal
/// only when the append shape does NOT already reproduce the post-state.
pub fn insert_pos_from_post_state(op: &Value, shadow: &Shadow, doc: &str, text: &str) -> Option<u64> {
    let v = field(op, &["result", "remaining", "expected_contents"])?;
    let strings = expect_strings(v)?;
    if strings.iter().any(|s| {
        (s.contains('.') && parse_dotted(s).is_some()) || crate::fields::is_python_repr(s)
    }) {
        return None;
    }
    let post = strings.join("");
    let pre = shadow.text_string(doc);
    if post.len() != pre.len() + text.len() || text.is_empty() {
        return None;
    }
    if post == format!("{pre}{text}") {
        return None; // the append shape already explains it
    }
    // Byte-level gap scan (no char-boundary slicing risk).
    let (p, t, q) = (post.as_bytes(), text.as_bytes(), pre.as_bytes());
    (0..=q.len())
        .find(|&k| p[..k] == q[..k] && p[k..k + t.len()] == *t && p[k + t.len()..] == q[k..])
        .map(|k| k as u64 + 1)
}

/// Was this delete a no-op in udanax? The doc's recorded post-delete content
/// equals its pre-delete content byte-for-byte (delete_all/delete_all_with_
/// links: `remove "entire document"` followed by a retrieve recording the
/// FULL text — udanax removed nothing, whatever the label claims). The
/// harness then also executes nothing, same family as `client-error:no-op`.
pub fn delete_is_noop(shadow: &Shadow, all: &[Value], i: usize, doc: &str) -> bool {
    let pre = shadow.text_string(doc);
    if pre.is_empty() {
        return false;
    }
    post_state_of(all, i, doc, shadow, &all[i]) == Some(pre)
}

/// The single text a scenario's follow/traverse evidence records as the
/// LANDING at `doc` (hop entries whose to-side resolves to it) — what the
/// recording script must have filled an otherwise-unprobed link target
/// with (links/diamond_link_pattern: four empty docs, every landing text
/// recorded only in the traverse entries).
fn follow_landing_text(ops: &[Value], shadow: &Shadow, doc: &str) -> Option<String> {
    for op in ops {
        let label = label_of(op).to_ascii_lowercase();
        if !(label.starts_with("follow") || label.starts_with("traverse") || label.contains("traversal"))
        {
            continue;
        }
        for key in ["results", "path", "traversal", "steps", "result"] {
            let Some(entries) = field(op, &[key]).and_then(Value::as_array) else { continue };
            for e in entries {
                let Some(eo) = e.as_object() else { continue };
                let landing_tok: Option<&str> = eo
                    .get("step")
                    .and_then(Value::as_str)
                    .and_then(|s| s.split_once("->").map(|(_, t)| t))
                    .or_else(|| eo.get("to").and_then(Value::as_str))
                    .and_then(|t| t.split_whitespace().next());
                let Some(tok) = landing_tok else { continue };
                if shadow.resolve_doc(tok).as_deref() != Some(doc) {
                    continue;
                }
                for k in ["text", "target_text", "content"] {
                    if let Some(ss) = eo.get(k).and_then(expect_strings) {
                        let text = ss.join("");
                        if !text.is_empty()
                            && !(text.contains('.') && parse_dotted(&text).is_some())
                            && !crate::fields::is_python_repr(&text)
                        {
                            return Some(text);
                        }
                    }
                }
            }
        }
    }
    None
}

/// A `to`/`dest` value that is a position marker, not a document reference:
/// "end", "start", "end of doc" (edgecases/vcopy_to_same_document).
pub fn is_position_marker(s: &str) -> bool {
    let t = s.trim().to_ascii_lowercase();
    t == "end" || t == "start" || t.starts_with("end of") || t.starts_with("start of")
}

/// Is this key a `<role><n>` docid holder (`doc1`, `source2`, `target3`)?
pub fn keyed_role(k: &str) -> bool {
    ["doc", "source", "target"].iter().any(|stem| {
        k.strip_prefix(stem)
            .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
    })
}

/// The group word a plural create names its members with: an explicit
/// type/doc field ("peripherals" — links/star_hub_outgoing), else the role
/// the label itself carries ("create_multiple_targets" → "target").
pub fn group_word(op: &Value) -> Option<String> {
    if let Some(s) = str_field(op, &["type", "doc"]) {
        if parse_dotted(s).is_none() {
            return Some(s.to_string());
        }
    }
    let label = label_of(op).to_ascii_lowercase();
    if label.starts_with("create_") {
        for word in ["target", "source", "peripheral"] {
            if label.contains(word) {
                return Some(word.to_string());
            }
        }
    }
    None
}

/// Endset-anchored seed for a doc filled only implicitly: a later
/// retrieve_endsets records the doc's endset spans, and the create_link
/// ops' source_text/target_text supply the bytes those spans held — each
/// text is placed at the recorded ordinal whose width equals its length,
/// gaps filled with spaces. Constructible only when EVERY recorded span
/// finds a width-matched text (never fabricate).
fn endset_anchored_seed(ops: &[Value], shadow: &Shadow, doc: &str) -> Option<Vec<u8>> {
    let mut spans: Vec<(u64, u64)> = Vec::new();
    for op in ops {
        let label = label_of(op).to_ascii_lowercase();
        if !(label.starts_with("retrieve_endsets") || label.starts_with("endsets")) {
            continue;
        }
        for key in ["source", "from", "target", "to"] {
            let Some(arr) = field(op, &[key]).and_then(Value::as_array) else { continue };
            for v in arr {
                if let Some((docid, ss)) = vspec_dict(v) {
                    if docid == doc || shadow.resolve_doc(&docid).as_deref() == Some(doc) {
                        for (sub, ord, w) in ss {
                            if sub == 1 && w > 0 {
                                spans.push((ord, w));
                            }
                        }
                    }
                }
            }
        }
    }
    spans.sort();
    spans.dedup();
    if spans.is_empty() {
        return None;
    }
    let mut texts: Vec<String> = Vec::new();
    for op in ops {
        let label = label_of(op).to_ascii_lowercase();
        if !(label.starts_with("create_link") || label.starts_with("makelink")) {
            continue;
        }
        for key in ["source_text", "target_text"] {
            if let Some(t) = str_field(op, &[key]) {
                texts.push(t.to_string());
            }
        }
    }
    if texts.is_empty() {
        return None;
    }
    let n = spans.iter().map(|(o, w)| o + w - 1).max()?;
    let mut seed = vec![b' '; n as usize];
    let mut used = vec![false; texts.len()];
    for (ord, w) in &spans {
        let k = (0..texts.len()).find(|&i| !used[i] && texts[i].len() as u64 == *w)?;
        used[k] = true;
        let s = (*ord - 1) as usize;
        seed[s..s + *w as usize].copy_from_slice(texts[k].as_bytes());
    }
    Some(seed)
}

/// The single text every follow/traverse expectation in the scenario
/// records, when they are uniform — evidence for what the recording script
/// filled its unprobed link-endpoint docs with (links/star_hub_outgoing:
/// three empty peripherals, every follow records "Target document").
fn uniform_follow_text(ops: &[Value]) -> Option<String> {
    let mut texts: Vec<String> = Vec::new();
    let mut collect = |v: &Value| {
        if let Some(ss) = expect_strings(v) {
            for s in ss {
                if !s.is_empty()
                    && !(s.contains('.') && parse_dotted(&s).is_some())
                    && !crate::fields::is_python_repr(&s)
                {
                    texts.push(s);
                }
            }
        }
    };
    for op in ops {
        let label = label_of(op).to_ascii_lowercase();
        if !(label.starts_with("follow") || label.starts_with("traverse") || label.contains("traversal"))
        {
            continue;
        }
        if let Some(v) = field(op, &["result"]) {
            if !v.is_object() {
                collect(v);
            }
        }
        for key in ["results", "path", "traversal", "steps"] {
            if let Some(entries) = field(op, &[key]).and_then(Value::as_array) {
                for e in entries {
                    for k in ["target_text", "source_text", "text", "result"] {
                        if let Some(v) = e.get(k) {
                            collect(v);
                        }
                    }
                }
            }
        }
    }
    texts.sort();
    texts.dedup();
    match texts.as_slice() {
        [one] => Some(one.clone()),
        _ => None,
    }
}

/// One recorded shared-span evidence pair: dest doc, dest ordinal, source
/// doc, source ordinal, width — the scenario's own testimony of which
/// region came from where.
pub type SharedPair = (String, u64, String, u64, u64);

/// Harvest every recorded comparison pair in the scenario, both shapes:
/// entries `{source: "A", shared: [{target: {…}, source: {…}}]}` inside a
/// results/comparisons array (content/vcopy_from_multiple_documents — the
/// dest is the scenario's target-role doc), and compare ops labeled
/// `"<x>_vs_<y>"` whose top-level `shared` items key the sides `a`/`b`
/// positionally (identity/identity_mixed_sources).
pub fn comparison_pairs(all: &[Value], shadow: &Shadow) -> Vec<SharedPair> {
    let mut out: Vec<SharedPair> = Vec::new();
    for op in all {
        let label = label_of(op).to_ascii_lowercase();
        if !label.starts_with("compar") {
            continue;
        }
        if let Some(entries) = field(op, &["results", "comparisons"]).and_then(Value::as_array) {
            let dest = shadow.resolve_doc("target").or_else(|| shadow.scoped());
            for entry in entries {
                let (Some(dest), Some(src)) = (
                    dest.clone(),
                    entry.get("source").and_then(Value::as_str).and_then(|s| shadow.resolve_doc(s)),
                ) else {
                    continue;
                };
                let Some(shared) = entry.get("shared").and_then(Value::as_array) else { continue };
                for item in shared {
                    let tgt = item.get("target").and_then(span_dict);
                    let ssp = item.get("source").and_then(span_dict);
                    if let (Some((1, tord, w)), Some((1, sord, sw))) = (tgt, ssp) {
                        if w == sw {
                            out.push((dest.clone(), tord, src.clone(), sord, w));
                        }
                    }
                }
            }
            continue;
        }
        // "<x>_vs_<y>" label + top-level shared, sides keyed a/b.
        if let Some((dx, dy)) = str_field(op, &["label"])
            .and_then(|l| l.split_once("_vs_"))
            .and_then(|(x, y)| Some((shadow.resolve_doc(x)?, shadow.resolve_doc(y)?)))
        {
            let Some(shared) = field(op, &["shared"]).and_then(Value::as_array) else { continue };
            for item in shared {
                let a = item.get("a").and_then(span_dict);
                let b = item.get("b").and_then(span_dict);
                if let (Some((1, aord, w)), Some((1, bord, bw))) = (a, b) {
                    if w == bw {
                        out.push((dx.clone(), aord, dy.clone(), bord, w));
                    }
                }
            }
            continue;
        }
        // Named sides with docids inline or resolvable key names
        // (content/vcopy_multiple_spans: items keyed source/target with
        // docid+span dicts; versions/cross_version_vcopy: items keyed
        // original/version with bare span dicts). Direction is unknowable
        // here, so BOTH orientations are emitted; consumers filter by their
        // destination and verify bytes, so a wrong orientation never binds.
        let Some(shared) =
            field(op, &["shared", "result", "shared_spans", "pairs"]).and_then(Value::as_array)
        else {
            continue;
        };
        for item in shared {
            let Some(io) = item.as_object() else { continue };
            let sides: Vec<(String, u64, u64)> = io
                .iter()
                .filter_map(|(k, v)| {
                    let (docref, sub, ord, w) = if let Some((sub, ord, w)) = span_dict(v) {
                        (k.as_str(), sub, ord, w)
                    } else {
                        let o = v.as_object()?;
                        let d = o.get("docid").and_then(Value::as_str);
                        let sp = o.get("span").or_else(|| {
                            o.get("spans").and_then(Value::as_array).and_then(|a| a.first())
                        })?;
                        let (sub, ord, w) = span_dict(sp)?;
                        (d.unwrap_or(k.as_str()), sub, ord, w)
                    };
                    if sub != 1 {
                        return None;
                    }
                    let doc = shadow.resolve_doc(docref)?;
                    Some((doc, ord, w))
                })
                .collect();
            if let [(da, oa, wa), (db, ob, wb)] = sides.as_slice() {
                if wa == wb && da != db {
                    out.push((da.clone(), *oa, db.clone(), *ob, *wa));
                    out.push((db.clone(), *ob, da.clone(), *oa, *wa));
                }
            }
        }
    }
    out
}

/// Evidence-driven cover: when the scenario's later comparisons record
/// exactly which (source, span) each shared region came from and where it
/// landed in `dest`, build the plan from THOSE pairs — the minimal cover
/// consistent with the recorded widths. Every pair is verified byte-for-byte
/// against the sources and the expected text; any mismatch abandons the
/// evidence path (caller falls back to the greedy cover).
fn cover_from_comparisons(
    shadow: &Shadow,
    dest: &str,
    expected: &str,
    all: &[Value],
) -> Option<Vec<SetupStep>> {
    let mut pairs: Vec<(u64, String, u64, u64)> = comparison_pairs(all, shadow)
        .into_iter()
        .filter(|(d, _, _, _, _)| d == dest)
        .map(|(_, tord, src, sord, w)| (tord, src, sord, w))
        .collect();
    if pairs.is_empty() {
        return None;
    }
    pairs.sort();
    let e = expected.as_bytes();
    let mut steps: Vec<SetupStep> = Vec::new();
    let mut at = 0usize; // 0-based cursor into expected
    for (tord, src, sord, w) in pairs {
        let (t0, w) = ((tord - 1) as usize, w as usize);
        if t0 < at || t0 + w > e.len() {
            return None; // overlapping or out-of-range evidence
        }
        let src_bytes = shadow.slice(&src, sord, w as u64);
        if src_bytes != e[t0..t0 + w] {
            return None; // evidence disagrees with the probe text
        }
        if t0 > at {
            steps.push(SetupStep::Insert { doc: dest.to_string(), bytes: e[at..t0].to_vec() });
        }
        steps.push(SetupStep::Copy { doc: dest.to_string(), src, ord: sord, width: w as u64 });
        at = t0 + w;
    }
    if at < e.len() {
        steps.push(SetupStep::Insert { doc: dest.to_string(), bytes: e[at..].to_vec() });
    }
    Some(steps)
}

/// The next full-content probe of `doc` after op `i` (doc-field probes,
/// docs-map probes, and per-target `targets` entries — identity/
/// identity_multi_document_sharing records each created target's content
/// only inside a `targets` array).
pub fn next_content_probe(all: &[Value], i: usize, doc: &str, shadow: &Shadow) -> Option<String> {
    let content = |s: Vec<String>| -> Option<String> {
        if s.iter().any(|x| {
            (x.contains('.') && parse_dotted(x).is_some()) || crate::fields::is_python_repr(x)
        }) {
            None // an address string / client repr is not content
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
        if let Some(entries) = op.get("targets").and_then(Value::as_array) {
            for e in entries {
                let named = e
                    .get("docid")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| {
                        e.get("doc")
                            .and_then(Value::as_str)
                            .and_then(|n| shadow.resolve_doc(n))
                    });
                if named.as_deref() == Some(doc) {
                    if let Some(s) =
                        e.get("contents").and_then(expect_strings).and_then(&content)
                    {
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
/// span string, text, start+width/end/count), with the round-3 boundary
/// discipline: a numeric span (dict, start+width, positional description)
/// is what the client sent — authoritative. A TEXT-located span is a
/// reconstruction, and the recorded post-state, where present, tells
/// exactly what udanax removed (the whitespace-diff cluster: recorded
/// deletes took a boundary space the located text missed) — so the
/// post-state diff overrides it, and absent post-state the flanked-by-
/// spaces configuration widens by the trailing space. Returns
/// (ord, width, grounding tag).
pub fn resolve_delete_span(
    shadow: &Shadow,
    all: &[Value],
    i: usize,
    doc: &str,
    op: &Value,
) -> Option<(u64, u64, &'static str)> {
    if let Some((sub, ord, w)) = field(op, &["span", "vspan"]).and_then(span_dict) {
        return if sub == 1 { Some((ord, w, "explicit")) } else { None };
    }
    if let Some(start) = str_field(op, &["start", "address", "at"]) {
        if let Some((sub, ord, _)) = resolve_position(shadow, doc, start) {
            if sub != 1 {
                return None;
            }
            if let Some(w) = str_field(op, &["width"]).and_then(crate::tum::parse_width) {
                return Some((ord, w, "explicit"));
            }
            if let Some(e) = str_field(op, &["end"]) {
                return match parse_dotted(e)?.as_slice() {
                    [0, w] => Some((ord, *w, "explicit")),
                    [1, eord] if *eord >= ord => Some((ord, eord - ord, "explicit")),
                    _ => None,
                };
            }
            if let Some(n) = field(op, &["count"]).and_then(Value::as_u64) {
                return Some((ord, n, "explicit"));
            }
        }
    }
    // `removed`/`deleted` field: a V-position ("1.2" = one element) or an
    // inclusive range ("1.3-1.4") — the client's numeric record
    // (iaddress_allocation/interleaved_insert_delete).
    if let Some(r) = str_field(op, &["removed", "deleted"]) {
        if let Some((ord, w)) = removed_range(r) {
            return Some((ord, w, "explicit"));
        }
    }
    let pre = shadow.text_string(doc);
    let post = post_state_of(all, i, doc, shadow, op);
    if let Some(desc) = str_field(op, &["span", "vspan", "text"]) {
        if let Some(l) = locate(shadow, Some(doc), desc) {
            if l.how != "text-located" {
                // Numeric-precise description ("1.1 length 3", "1.3 for
                // 0.5", ranges): keep as sent.
                return Some((l.ord, l.width, "explicit"));
            }
            // A text-located span is a reconstruction; the recorded
            // post-state, where present, tells exactly what udanax removed.
            if let Some(post) = &post {
                if let Some((ord, w)) = single_gap_diff(pre.as_bytes(), post.as_bytes()) {
                    let tag = if (ord, w) == (l.ord, l.width) {
                        "text-located"
                    } else {
                        "delete-span-from-post-state"
                    };
                    return Some((ord, w, tag));
                }
            }
            let b = pre.as_bytes();
            let after = b.get((l.ord - 1 + l.width) as usize);
            let before = if l.ord >= 2 { b.get(l.ord as usize - 2) } else { None };
            if after == Some(&b' ') && (l.ord == 1 || before == Some(&b' ')) {
                return Some((l.ord, l.width + 1, "delete-span-widened-boundary"));
            }
            return Some((l.ord, l.width, "text-located"));
        }
    }
    // No groundable description at all: the recorded post-state is the
    // first authority (delete_A carries only its result.content), then a
    // label-borne text ("delete_A" removed "A") — round-5 item 9's
    // restored grounding order.
    if !pre.is_empty() {
        if let Some(post) = &post {
            if let Some((ord, w)) = single_gap_diff(pre.as_bytes(), post.as_bytes()) {
                return Some((ord, w, "delete-span-from-post-state"));
            }
        }
    }
    if let Some(t) = delete_text_from_label(op) {
        if let Some((_, ord)) = shadow.find_text(Some(doc), &t) {
            return Some((ord, t.len() as u64, "delete-text-from-label"));
        }
    }
    None
}

/// `removed`-field forms: "1.2" (V-position, one element) or "1.3-1.4"
/// (inclusive ordinal range) → (ordinal, width).
fn removed_range(s: &str) -> Option<(u64, u64)> {
    let s = s.trim();
    if let Some((ord, w)) = crate::fields::ordinal_range(s) {
        return Some((ord, w));
    }
    match crate::tum::parse_vpos(s) {
        Some((1, ord)) => Some((ord, 1)),
        _ => None,
    }
}

/// Label-borne deleted text, mirroring `insert_text`'s label grammar:
/// `delete_A` → "A" (iaddress_allocation/delete_does_not_affect_next_
/// insert). Descriptive tails (delete_all, delete_vspan…) carry no text.
fn delete_text_from_label(op: &Value) -> Option<String> {
    let label = label_of(op);
    let rest = label.strip_prefix("delete_").or_else(|| label.strip_prefix("remove_"))?;
    if rest.is_empty()
        || rest.contains('_')
        || matches!(rest, "all" | "vspan" | "text" | "attempt" | "loop")
    {
        return None;
    }
    Some(rest.to_string())
}

/// The deleted bytes as the recording DESCRIBES them: the trailing
/// parenthetical of a span/text field ("1.3 for 0.5 (CDEFG)") or a quoted
/// segment — accepted only at exactly the resolved width, so a reminder
/// word never masquerades as the removed bytes.
fn delete_described_bytes(op: &Value, w: u64) -> Option<Vec<u8>> {
    for key in ["span", "vspan", "text", "removed"] {
        let Some(s) = str_field(op, &[key]) else { continue };
        if let Some(open) = s.rfind('(') {
            if let Some(inner) = s[open + 1..].strip_suffix(')') {
                if inner.len() as u64 == w {
                    return Some(inner.as_bytes().to_vec());
                }
            }
        }
    }
    None
}

/// The doc's recorded content right after op `i`: the op's own post-write
/// keys, else the next full-content probe with no intervening write.
fn post_state_of(
    all: &[Value],
    i: usize,
    doc: &str,
    shadow: &Shadow,
    op: &Value,
) -> Option<String> {
    let content = |v: &Value| -> Option<String> {
        let s = expect_strings(v)?;
        if s.iter().any(|x| {
            (x.contains('.') && parse_dotted(x).is_some()) || crate::fields::is_python_repr(x)
        }) {
            return None;
        }
        Some(s.join(""))
    };
    // Own keys; "after" only in structured form — a bare string under
    // "after" is a phase label ("link1"), never content.
    let own = field(op, &["remaining", "result", "expected_contents"])
        .or_else(|| field(op, &["after"]).filter(|v| !v.is_string()));
    if let Some(v) = own {
        if let Some(s) = content(v) {
            return Some(s);
        }
    }
    let writes = ["insert", "delete", "remove", "vcopy", "copy", "pivot", "swap", "rearrange"];
    for later in &all[i + 1..] {
        let label = label_of(later).to_ascii_lowercase();
        if writes.iter().any(|w| label.starts_with(w)) {
            return None;
        }
        if let Some(map) = later.get("docs").and_then(Value::as_object) {
            for (name, exp) in map {
                if shadow.resolve_doc(name).as_deref() == Some(doc) {
                    if let Some(s) = content(exp) {
                        return Some(s);
                    }
                }
            }
        }
        if !(label.starts_with("content") || label.starts_with("retrieve")) {
            continue;
        }
        // A doc-less content probe targets the register — the same doc the
        // write did, per the scripts' scope discipline (delete_all_with_
        // links' post-remove retrieve carries no doc field).
        let probe_doc = str_field(later, &["doc", "docid"]).and_then(|s| shadow.resolve_doc(s));
        if probe_doc.is_some() && probe_doc.as_deref() != Some(doc) {
            continue;
        }
        // A narrowed read is not a whole-document post-state.
        if field(later, &["span", "spans", "specs", "specset", "positions", "address", "at"])
            .is_some()
        {
            continue;
        }
        // "after"-keyed replies count too (delete_all/delete_all_with_links
        // records its post-remove retrieve under "after"), structured only.
        let reply = field(later, &["result", "content", "contents"])
            .or_else(|| field(later, &["after"]).filter(|v| !v.is_string()));
        if let Some(v) = reply {
            if let Some(s) = content(v) {
                return Some(s);
            }
        }
    }
    None
}

/// A single contiguous deletion explaining pre → post: the longest common
/// prefix that leaves a matching suffix. `None` when no single gap explains
/// the difference (the delete then stays as located and diverges honestly).
fn single_gap_diff(pre: &[u8], post: &[u8]) -> Option<(u64, u64)> {
    if post.len() >= pre.len() {
        return None;
    }
    let width = pre.len() - post.len();
    let mut a = pre.iter().zip(post).take_while(|(x, y)| x == y).count();
    loop {
        if pre[a + width..] == post[a..] {
            return Some((a as u64 + 1, width as u64));
        }
        if a == 0 {
            return None;
        }
        a -= 1;
    }
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
