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
//!   verifies the removed bytes equal the recorded insert/copy, and undoes
//!   a delete only with the bytes it is known to have removed, so a wrong
//!   inference aborts instead of guessing). A version is never seeded: its
//!   content at creation is its source's, which the recorded create_version
//!   provides.
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
//!   spec-derived link extents.
//!
//! Everything inferred is tagged into the report's `groundings` list. A doc
//! whose probes stay inconsistent after inference is left alone — the play
//! pass then reports the disagreement honestly.
//!
//! The walk reads each op through the grammar the play pass reads it
//! through (`fields`: the verb `normalize` names, which it dispatches on,
//! and the vcopy sources `vcopy_sources` reads), skips every op udanax
//! never carried out (`evidence::took_effect`), and decides what an edit did
//! by the recorded-evidence policies the play pass applies (`evidence`);
//! what this module holds is the reconstruction alone. The corpus
//! extension records its own setup (MANIFEST-NEW): its `probe` checkpoints
//! carry no docs map, the one shape of them this walk reads, so nothing is
//! inferred there.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::ops::Range;

use serde_json::Value;

use crate::evidence::{
    delete_is_noop, next_content_probe, resolve_delete_span, resolve_insert, took_effect,
};
use crate::fields::{
    aim_doc, arrow_results, as_text, cuts_of, distributed_insert_texts, distribution_targets,
    expect_strings, field, group_word, is_position_marker, locate, normalize, op_name,
    per_doc_replies, quoted, recorded_content, recorded_count, resolve_position, roster,
    span_dict, str_field, vcopy_sources, verb_of, vspec_dict, DocAim, Verb, BUILD_BUDGET,
    POST_WRITE_KEYS,
};
use crate::shadow::Shadow;
use crate::tum::{link_home_docid, parse_dotted, parse_vpos, parse_width, VPoint, VRegion};

// Expansion-plan covers built from recorded comparison pairs or source text.
mod cover;

use cover::{
    comparison_pairs, cover_from_comparisons, cover_with_sources, later_appends_text,
    later_copy_into, SharedPair,
};

/// One step of the implied setup, fully concrete: executed against skep by
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

/// The setup the scenario's recording performed but never recorded as ops,
/// implied by its own evidence: the documents the runner creates and the
/// content it inserts before op 0, the plans the macro ops execute, and the
/// inferences behind them all, which the report lists as `groundings`.
#[derive(Debug, Default)]
pub struct ImpliedSetup {
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
#[derive(Clone, Debug)]
enum Edit {
    Ins { at: Option<u64>, bytes: Vec<u8> },
    /// `bytes` = what the delete removed, when the walk knew all of it —
    /// from its own state, or from the op's description of the removed
    /// text; `None` when it knew less than the delete's width, and then the
    /// delete cannot be undone. `explicit` = the position is pinned (sent
    /// numerically, or read off the recorded post-state), so the undo
    /// reinserts there FIRST; a text-located position tries the end first
    /// (the seed-shift shape).
    Del { at: u64, bytes: Option<Vec<u8>>, explicit: bool },
    Pivot { a: u64, b: u64, c: u64 },
    Swap { s1: u64, e1: u64, s2: u64, e2: u64 },
    /// A content write udanax made that the walk could not reproduce — a
    /// position, region or cut set its grammar does not ground (the play
    /// pass finds the op inexpressible). Its effect is unknown, so no undo
    /// crosses it: undoing past it would credit its bytes to the seed.
    Opaque,
}

pub fn ground(ops: &[Value]) -> ImpliedSetup {
    let mut g = ImpliedSetup { implied_creates: implied_creates(ops), ..ImpliedSetup::default() };
    if !g.implied_creates.is_empty() {
        g.tags.push(format!("implied-create: {}", g.implied_creates.join(", ")));
    }

    let mut seeds: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    // Fixpoint: each round replays the scenario in shadow space under the
    // current seeds and may add at most one newly-inferred seed. Bounded by
    // the number of documents a scenario touches (≤ a handful).
    for _round in 0..8 {
        let mut sim = Sim::replay(&g.implied_creates, &seeds, ops);
        let Some((doc, exp)) = sim.failed_probe.take() else { break };
        if seeds.contains_key(&doc) {
            break; // already seeded and still inconsistent — leave honest
        }
        // A version's content at creation is its source's, which the
        // recorded create_version provides: nothing precedes it to seed. A
        // seed here would mint a plain document under the version's golden
        // address holding the very answer its probe expects.
        if sim.shadow.version_of.contains_key(&doc) {
            break;
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
        let sim = Sim::replay(&g.implied_creates, &seeds, ops);
        for pair in comparison_pairs(ops, &sim.shadow) {
            let SharedPair { dest, dest_ord, src, src_ord, width } = pair;
            if src_ord != 1 || seeds.contains_key(&src) || sim.shadow.text_len(&src) > 0 {
                continue;
            }
            let Some(probe) = next_content_probe(ops, 0, &sim.shadow, &dest) else { continue };
            // A region the probe does not hold — ordinal 0, or an end past
            // the probe's — pins nothing.
            let Some(held) = held_range(probe.len(), dest_ord, width) else { continue };
            let bytes = probe.as_bytes()[held].to_vec();
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
        let sim = Sim::replay(&g.implied_creates, &seeds, ops);
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
    let sim = Sim::replay(&g.implied_creates, &seeds, ops);
    for (i, plan) in &sim.plans {
        let strategy = sim.plan_notes.get(i).map(|s| format!(" [{s}]")).unwrap_or_default();
        g.tags.push(format!(
            "expansion-plan: op {i} `{}` → {} concrete steps{strategy}",
            op_name(&ops[*i]),
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
        let creates = match verb_of(op) {
            Some(
                Verb::CreateDocument
                | Verb::CreateDocuments
                | Verb::CreateChain
                | Verb::CreateVersion
                | Verb::OpenDocument,
            ) => true,
            // A vcopy form that mints its targets first.
            Some(Verb::Vcopy) => {
                op_name(op).to_ascii_lowercase().starts_with("create_and_transclude")
            }
            _ => false,
        };
        if creates {
            walk(op, &mut |s| {
                if s.contains('.') && parse_dotted(s).is_some() && link_home_docid(s).is_none() {
                    created.push(s.to_string());
                }
            });
            // Prospective creations without recorded ids — each amount an
            // array the golden holds, or a count within the build budget.
            let explicit = field(op, &["results"])
                .and_then(Value::as_array)
                .map(|a| a.len() as u64)
                .or_else(|| op.get("docs").and_then(Value::as_object).map(|m| m.len() as u64));
            created_count += explicit
                .or_else(|| recorded_count(op).ok().flatten())
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

/// The byte range `[ord, ord + width)` names in a `len`-byte text,
/// 1-based: `None` when the text does not hold all of it — an ordinal 0, or
/// an end past the text's, however large the recorded numbers. The one
/// reading every recorded region a reconstruction slices goes through.
fn held_range(len: usize, ord: u64, width: u64) -> Option<Range<usize>> {
    let start = usize::try_from(ord.checked_sub(1)?).ok()?;
    let end = start.checked_add(usize::try_from(width).ok()?)?;
    (end <= len).then_some(start..end)
}

/// Undo the recorded edits (latest first) from a probed content string back
/// to the doc's initial content. Every removal is verified byte-for-byte;
/// any mismatch abandons the path it lies on. A delete's undo has two
/// candidate reinsertion points (the recorded ordinal, and the end for the
/// seed-shifted append shape), and the candidate that lets the REST of the
/// chain verify wins: a depth-first search over those choices, on an
/// explicit stack, so a log's length costs heap and never the thread's
/// stack. A log holding a write whose effect the walk never knew is refused
/// before any search — every path through such a write fails, so no
/// placement of the deletes above it is tried in vain.
fn undo_to_initial(probed: &str, edits: &[Edit]) -> Option<Vec<u8>> {
    // A delete whose removed bytes the walk never knew cannot be undone:
    // reinserting nothing would hand back the post-delete content as the
    // seed, a world no recorded op built. Nor can a write the walk could not
    // reproduce at all.
    if edits.iter().any(|e| matches!(e, Edit::Del { bytes: None, .. } | Edit::Opaque)) {
        return None;
    }
    // Each entry: the edits still to undo, and the content so far.
    let mut stack: Vec<(&[Edit], Vec<u8>)> = vec![(edits, probed.as_bytes().to_vec())];
    while let Some((edits, cur)) = stack.pop() {
        let Some((last, rest)) = edits.split_last() else { return Some(cur) };
        match last {
            Edit::Ins { at, bytes } => {
                let held = match at {
                    Some(ord) => held_range(cur.len(), *ord, bytes.len() as u64),
                    None => cur.len().checked_sub(bytes.len()).map(|start| start..cur.len()),
                };
                let Some(held) = held.filter(|h| cur[h.clone()] == bytes[..]) else { continue };
                let mut next = cur;
                next.drain(held);
                stack.push((rest, next));
            }
            Edit::Del { bytes: None, .. } | Edit::Opaque => {} // refused before the search
            Edit::Del { at, bytes: Some(bytes), explicit } => {
                // Candidate reinsertion points. Explicit (client-sent)
                // position: the recorded ordinal first — it is
                // authoritative (isolation/delete_does_not_affect_other_
                // documents "1.3 for 0.5 (CDEFG)" must reinsert at 3, not the
                // end). Text-located: the end first (a seed prefix shifts an
                // append-built doc's delete rightward — the recorded position
                // undercounts by the seed length). Pushed last-first, so the
                // first is tried first.
                let rec = (*at as usize).saturating_sub(1).min(cur.len());
                let mut cands =
                    if *explicit { vec![rec, cur.len()] } else { vec![cur.len(), rec] };
                cands.dedup();
                for k in cands.into_iter().rev() {
                    let mut next = cur.clone();
                    next.splice(k..k, bytes.iter().copied());
                    stack.push((rest, next));
                }
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
                stack.push((rest, next));
            }
            Edit::Swap { s1, e1, s2, e2 } => {
                // Same no-op mirror of Shadow::swap's guard as Pivot above.
                let mut next = cur;
                if *s1 > 0 && s1 <= e1 && e1 <= s2 && s2 <= e2 && *e2 as usize <= next.len() + 1
                {
                    let (w1, w2) = (e1 - s1, e2 - s2);
                    let mut s = scratch(&next);
                    s.swap("x", *s1, s1 + w2, s2 + w2 - w1, *e2);
                    next = s.text_string("x").into_bytes();
                }
                stack.push((rest, next));
            }
        }
    }
    None
}

fn scratch(bytes: &[u8]) -> Shadow {
    let mut s = Shadow::new();
    s.create_doc("x", None);
    s.insert("x", 1, bytes);
    s
}

// ───────────────────────────── the simulation ──────────────────────────────

#[derive(Debug)]
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

    /// The scenario replayed in shadow space from scratch under `seeds` —
    /// the walk every inference round, and the final pass, take.
    fn replay(implied: &[String], seeds: &BTreeMap<String, Vec<u8>>, ops: &[Value]) -> Sim {
        let mut sim = Sim::new(implied, seeds);
        for (i, op) in ops.iter().enumerate() {
            sim.step(i, op, ops);
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

    /// The op's document, read as the play pass reads it (`fields::aim_doc`).
    /// An explicit reference that resolves to nothing aims at nothing: the
    /// op changes nothing here, as it executes nothing there.
    fn doc_ref(&mut self, op: &Value, keys: &[&str]) -> Option<String> {
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
    fn step(&mut self, i: usize, op: &Value, all: &[Value]) {
        if !took_effect(op) {
            return;
        }
        let name = op_name(op).to_ascii_lowercase();
        match normalize(&name, op) {
            Some(Verb::CreateChain) => self.sim_create_chain(i, op, all),
            Some(Verb::CreateDocuments) => self.sim_create_documents(i, op, all),
            Some(Verb::Setup) => {
                if let Some(steps) = self.parse_keyed_setup(op, i, all) {
                    self.plan(i, steps);
                } else if let Some(desc) = str_field(op, &["description", "desc"]) {
                    if let Some(steps) = self.parse_setup_description(desc) {
                        self.plan(i, steps);
                    }
                }
            }
            Some(Verb::CreateDocument) => self.sim_create_document(op),
            Some(Verb::OpenDocument) => self.sim_open_document(op),
            Some(Verb::CreateVersion) => self.sim_create_version(op),
            Some(Verb::InteriorTyping) => self.sim_interior_typing(op),
            Some(Verb::InsertLoop) => self.sim_insert_loop(op),
            Some(Verb::Insert) => self.sim_insert(i, op, all),
            Some(Verb::DeleteAll) => self.sim_delete_all(i, op, all),
            Some(Verb::Delete) => self.sim_delete(i, op, all),
            Some(Verb::Vcopy) if name.starts_with("vcopy_to_multiple") => {
                self.sim_vcopy_to_multiple(i, op)
            }
            Some(Verb::Vcopy) if name.starts_with("create_and_transclude") => {
                self.sim_create_and_transclude(i, op)
            }
            Some(Verb::Vcopy) => self.sim_vcopy(i, op, all, &name),
            Some(verb @ (Verb::Pivot | Verb::Swap | Verb::Rearrange)) => {
                self.sim_rearrange(op, verb)
            }
            Some(Verb::CreateLink) => self.sim_create_link(op),
            _ => self.sim_read(op),
        }
    }

    fn sim_create_document(&mut self, op: &Value) {
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
    }

    fn sim_open_document(&mut self, op: &Value) {
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
    }

    fn sim_create_version(&mut self, op: &Value) {
        let src = str_field(op, &["from", "source", "of", "original"])
            .and_then(|s| self.shadow.resolve_doc(s))
            .or_else(|| str_field(op, &["doc"]).and_then(|s| self.shadow.resolve_doc(s)))
            .or_else(|| self.shadow.current());
        let (Some(src), Some(res)) = (src, result_str(op)) else { return };
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
        let Some(doc) = self.doc_ref(op, &["doc", "docid"]) else { return };
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
                    self.record(&doc, Edit::Ins { at: Some(ord), bytes: ch.as_bytes().to_vec() });
                } else {
                    self.record(&doc, Edit::Opaque);
                }
                self.check_probes(r);
            }
        }
    }

    fn sim_insert_loop(&mut self, op: &Value) {
        let Some(doc) = self.doc_ref(op, &["doc", "docid"]) else { return };
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
        self.record(&doc, Edit::Ins { at: None, bytes });
    }

    fn sim_insert(&mut self, i: usize, op: &Value, all: &[Value]) {
        // insert_all + texts: one text per created doc, in creation order
        // (links/link_chain_three_hops fills its four documents through one
        // op) — never a single concatenated insert.
        if let Some(texts) = distributed_insert_texts(op) {
            let docs: Vec<String> = distribution_targets(&self.shadow, texts.len());
            for (d, t) in docs.iter().zip(&texts) {
                let end = self.shadow.text_len(d) + 1;
                self.shadow.insert(d, end, t.as_bytes());
                self.record(d, Edit::Ins { at: None, bytes: t.as_bytes().to_vec() });
            }
            return;
        }
        // Where the insert lands — re-aim, position, recorded-vspanset pad
        // — is the one reading the play pass applies
        // (`evidence::resolve_insert`). An insert that reading cannot place
        // changes nothing, as it executes nothing in the play pass.
        let Some(doc) = self.doc_ref(op, &["doc", "docid"]) else { return };
        let Ok(landing) = resolve_insert(all, i, &self.shadow, &doc, &mut Vec::new()) else {
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
        self.record(&landing.doc, Edit::Ins { at, bytes: landing.bytes });
        self.check_probes(op);
    }

    fn sim_delete_all(&mut self, i: usize, op: &Value, all: &[Value]) {
        if let Some(doc) = self.doc_ref(op, &["doc", "docid"]) {
            if delete_is_noop(all, i, &self.shadow, &doc) {
                return; // recorded post-state shows udanax removed nothing
            }
            let n = self.shadow.text_len(&doc);
            let bytes = self.shadow.slice(&doc, 1, n);
            self.shadow.delete(&doc, 1, n);
            self.record(&doc, Edit::Del { at: 1, bytes: Some(bytes), explicit: true });
        }
    }

    fn sim_delete(&mut self, i: usize, op: &Value, all: &[Value]) {
        let Some(doc) = self.doc_ref(op, &["doc", "docid"]) else { return };
        if delete_is_noop(all, i, &self.shadow, &doc) {
            self.check_probes(op);
            return; // recorded post-state shows udanax removed nothing
        }
        if let Some((VRegion { ord, width: w, .. }, how)) =
            resolve_delete_span(all, i, &self.shadow, &doc)
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
            self.record(&doc, Edit::Del { at: ord, bytes, explicit: how.position_pinned() });
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
    }

    /// Pivot (three cuts) or swap (four), as the verb names it; a bare
    /// `rearrange` takes its shape from its cut count.
    fn sim_rearrange(&mut self, op: &Value, verb: Verb) {
        let Some(doc) = self.doc_ref(op, &["doc", "docid"]) else { return };
        let cuts = cuts_of(op);
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
            let Some(expected) = next_content_probe(all, i, &self.shadow, &id) else { continue };
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
    /// endset extent) overrides the spec-derived spans. `None` when the op
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
            .current()
            .filter(|d| self.shadow.text_len(d) > 0)
            .or_else(|| self.shadow.content_docs_except("").first().cloned());
        let (Some(VRegion { sub: 1, ord, width: w }), Some(src)) = (src_span, src) else { return };
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

    fn sim_vcopy(&mut self, i: usize, op: &Value, all: &[Value], op_name: &str) {
        let to_raw = str_field(op, &["to", "dest", "target", "target_doc"]);
        // Explicit destination only — the register fallback waits until the
        // copied bytes are known, so forward evidence can aim first.
        // "end"/"start"/"end of doc" are position markers, not doc refs
        // (edgecases/vcopy_to_same_document).
        let explicit_dest: Option<String> = match to_raw {
            Some(s) if is_position_marker(s) => self.shadow.current(),
            Some(s) => self.shadow.resolve_doc(s),
            None => str_field(op, &["doc", "docid"]).and_then(|s| self.shadow.resolve_doc(s)),
        };

        // Macro forms: grounded by the destination's next content probe.
        let from_list = field(op, &["from", "sources", "order"]).and_then(Value::as_array).map(
            |a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect::<Vec<_>>(),
        );
        let is_macro = from_list.is_some()
            || op_name.starts_with("vcopy_multiple")
            || op_name.starts_with("vcopy_all")
            || op_name.starts_with("vcopy_from_both");
        if is_macro {
            let Some(dest) = explicit_dest.or_else(|| self.doc_ref(op, &["doc", "docid"]))
            else {
                return;
            };
            let sources: Vec<String> = from_list
                .map(|names| names.iter().filter_map(|n| self.shadow.resolve_doc(n)).collect())
                .unwrap_or_else(|| self.shadow.content_docs_except(&dest));
            let Some(expected) = next_content_probe(all, i, &self.shadow, &dest) else { return };
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

        // Ordinary vcopy: the source regions the play pass reads, through
        // the same reading (`fields::vcopy_sources`), each contiguous
        // content-subspace region kept as a (doc, ord, width) spec. An op
        // the play pass cannot ground copies nothing here either.
        let Ok(sources) = vcopy_sources(op, &self.shadow, &mut Vec::new()) else { return };
        let spec_list: Vec<(String, u64, u64)> = sources
            .into_iter()
            .filter(|s| s.region.sub == 1)
            .map(|s| (s.doc, s.region.ord, s.region.width))
            .collect();
        let copied: Vec<u8> =
            spec_list.iter().flat_map(|(d, o, w)| self.shadow.slice(d, *o, *w)).collect();
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
                .created
                .iter()
                .filter(|d| {
                    next_content_probe(all, i, &self.shadow, d)
                        .is_some_and(|p| p.contains(&copied_s))
                })
                .cloned()
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
            .and_then(|(at, _)| (at.sub == 1).then_some(at.ord));
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
        let pairs: Vec<SharedPair> =
            comparison_pairs(all, &self.shadow).into_iter().filter(|p| p.dest == dest).collect();
        let probe = next_content_probe(all, i, &self.shadow, dest);

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
        //    compare records source ordinal 15 width 12 where the described
        //    text located ordinal 20).
        if spec_list.len() == 1 {
            if let Some(p) = pairs.iter().find(|p| p.dest_ord == o) {
                let own = spec_list[0] == (p.src.clone(), p.src_ord, p.width);
                let bytes = self.shadow.slice(&p.src, p.src_ord, p.width);
                if !own && bytes.len() as u64 == p.width && p.width > 0 {
                    self.plan_notes.insert(i, "vcopy-span-from-comparison");
                    return Some(vec![SetupStep::Copy {
                        doc: dest.to_string(),
                        src: p.src.clone(),
                        ord: p.src_ord,
                        width: p.width,
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
            if let Some(p) = pairs.iter().find(|p| {
                p.dest_ord > o
                    && p.dest_ord - o <= BUILD_BUDGET
                    && (&p.src, &p.src_ord, &p.width) == (s0, o0, w0)
            }) {
                let fill = (p.dest_ord - o) as usize;
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
                        // Saturating: a recorded span at the top of the
                        // range continues into nothing.
                        let cont = self.shadow.slice(ls, lo.saturating_add(*lw), need);
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
    /// shadow; record the first mismatch for inference. Recorded content is
    /// read as the play pass reads it (`fields::as_text`, `recorded_content`,
    /// `per_doc_replies`).
    fn check_probes(&mut self, op: &Value) {
        if let Some(map) = op.get("docs").and_then(Value::as_object) {
            for (name, exp) in map {
                // create_documents docs-maps hold ID strings, not content.
                let (Some(doc), Some(text)) = (
                    self.shadow.resolve_doc(name),
                    expect_strings(exp).as_deref().and_then(as_text),
                ) else {
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
            field(op, POST_WRITE_KEYS).and_then(expect_strings)
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
        let Some(doc) = self.doc_ref(op, &["doc", "docid"]) else { return };
        self.probe(&doc, &text);
    }

    fn probe(&mut self, doc: &str, expected: &str) {
        if self.shadow.text_string(doc) != expected && self.failed_probe.is_none() {
            self.failed_probe = Some((doc.to_string(), expected.to_string()));
        }
    }
}

/// The single text a scenario's follow/traverse evidence records as the
/// LANDING at `doc` (hop entries whose to-side resolves to it) — what the
/// recording script must have filled an otherwise-unprobed link target
/// with (links/diamond_link_pattern: four empty docs, every landing text
/// recorded only in the traverse entries).
fn follow_landing_text(ops: &[Value], shadow: &Shadow, doc: &str) -> Option<String> {
    for op in ops {
        if !matches!(verb_of(op), Some(Verb::FollowLink | Verb::Traverse)) {
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
                    let text = eo.get(k).and_then(expect_strings).as_deref().and_then(as_text);
                    if let Some(text) = text.filter(|t| !t.is_empty()) {
                        return Some(text);
                    }
                }
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
/// finds a width-matched text (never fabricate), and every span lies within
/// reach: an ordinal 0, or an end past the build budget, is a span no seed
/// can hold, and builds nothing.
fn endset_anchored_seed(ops: &[Value], shadow: &Shadow, doc: &str) -> Option<Vec<u8>> {
    let mut spans: Vec<(u64, u64)> = Vec::new();
    for op in ops {
        if verb_of(op) != Some(Verb::RetrieveEndsets) {
            continue;
        }
        for key in ["source", "from", "target", "to"] {
            let Some(arr) = field(op, &[key]).and_then(Value::as_array) else { continue };
            for v in arr {
                if let Some((docid, regions)) = vspec_dict(v) {
                    if docid == doc || shadow.resolve_doc(&docid).as_deref() == Some(doc) {
                        for r in regions {
                            if r.sub == 1 && r.width > 0 {
                                let last = r.ord.checked_add(r.width - 1)?;
                                if r.ord == 0 || last > BUILD_BUDGET {
                                    return None;
                                }
                                spans.push((r.ord, r.width));
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
        if verb_of(op) != Some(Verb::CreateLink) {
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
        for s in expect_strings(v).unwrap_or_default() {
            if !s.is_empty() && as_text(std::slice::from_ref(&s)).is_some() {
                texts.push(s);
            }
        }
    };
    for op in ops {
        if !matches!(verb_of(op), Some(Verb::FollowLink | Verb::Traverse)) {
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

/// The docs-map probe for a NAMED doc after op `i` (create_chain contents).
fn next_docs_map_probe(all: &[Value], i: usize, name: &str) -> Option<String> {
    for op in &all[i + 1..] {
        if let Some(map) = op.get("docs").and_then(Value::as_object) {
            // An id map holds addresses, never content: as_text refuses it.
            if let Some(s) = map.get(name).and_then(expect_strings).as_deref().and_then(as_text) {
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

fn result_str(op: &Value) -> Option<String> {
    match field(op, &["result"]) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Object(o)) => o.get("version").and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
