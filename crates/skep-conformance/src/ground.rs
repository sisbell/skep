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
//!   provides. Nor is a document the walk never made: an edit of one
//!   changes nothing, and a probe of one tests nothing.
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
//! This file holds the inference: the fixpoint over seeds, the implied
//! creates, the undo a seed is derived by, and the evidence readers the
//! placeholder seeds come from. The walk each round replays is `sim`'s, and
//! the expansion-plan covers the walk builds are `cover`'s.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::ops::Range;

use serde_json::Value;

use crate::evidence::next_content_probe;
use crate::fields::{
    as_text, field, op_name, recorded_count, str_field, strings_of, vcopy_form, verb_of,
    vspec_dict, VcopyForm, Verb, BUILD_BUDGET,
};
use crate::shadow::Shadow;
use crate::tum::{link_home_docid, parse_dotted};

// Expansion-plan covers built from recorded comparison pairs or source text.
mod cover;
// The walk: the scenario replayed in shadow space, each verb's effect restated.
mod sim;

use cover::{comparison_pairs, SharedPair};
use sim::Sim;

/// One step of the implied setup, fully concrete: executed against skep by
/// `play::run_lead_in` (lead-in) or by the macro-op handlers (plans).
/// Inserts append at the doc's then-current end; copies append the source
/// region `[ord, ord+width)` (content subspace); links carry located
/// content endsets per side plus the golden id the recording assigned
/// (subspace/insert_text_check_both_link_positions's keyed setup records
/// `link: "doc1[1.2-1.4] -> doc2[1.2-1.4]"` with its `link_id`).
#[derive(Clone, Debug)]
pub enum SetupStep {
    Insert { doc: String, bytes: Vec<u8> },
    Copy { doc: String, src: String, ord: u64, width: u64 },
    Link { from: Vec<(String, u64, u64)>, to: Vec<(String, u64, u64)>, golden: Option<String> },
}

/// The setup the scenario's recording performed but never recorded as ops,
/// implied by its own evidence: the documents created and the content
/// inserted before op 0 (`play::run_lead_in`), the plans the macro ops
/// execute, and the inferences behind them all, which the report lists as
/// `groundings`.
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
    /// Every inference made: the report's `groundings` list.
    pub groundings: Vec<String>,
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
    Insert { at: Option<u64>, bytes: Vec<u8> },
    /// `bytes` = what the delete removed, when the walk knew all of it —
    /// from its own state, or from the op's description of the removed
    /// text; `None` when it knew less than the delete's width, and then the
    /// delete cannot be undone. `explicit` = the position is pinned (sent
    /// numerically, or read off the recorded post-state), so the undo
    /// reinserts there FIRST; a text-located position tries the end first
    /// (the seed-shift shape).
    Delete { at: u64, bytes: Option<Vec<u8>>, explicit: bool },
    Pivot { a: u64, b: u64, c: u64 },
    Swap { s1: u64, e1: u64, s2: u64, e2: u64 },
    /// A content write udanax made that the walk could not reproduce — a
    /// position, region or cut set its grammar does not ground (the play
    /// pass finds the op inexpressible). Its effect is unknown, so no undo
    /// crosses it: undoing past it would credit its bytes to the seed.
    Opaque,
}

pub fn ground(ops: &[Value]) -> ImpliedSetup {
    let mut setup =
        ImpliedSetup { implied_creates: implied_creates(ops), ..ImpliedSetup::default() };
    if !setup.implied_creates.is_empty() {
        setup.groundings.push(format!("implied-create: {}", setup.implied_creates.join(", ")));
    }

    let mut seeds: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    // Fixpoint: each round replays the scenario in shadow space under the
    // current seeds and may add at most one newly-inferred seed. Bounded by
    // the number of documents a scenario touches (≤ a handful).
    for _round in 0..8 {
        let mut sim = Sim::replay(&setup.implied_creates, &seeds, ops);
        let Some((doc, exp)) = sim.failed_probe.take() else { break };
        if seeds.contains_key(&doc) {
            break; // already seeded and still inconsistent — leave honest
        }
        // A version's content at creation is its source's, which the
        // recorded create_version provides: nothing precedes it to seed. A
        // seed here would mint a plain document under the version's golden
        // address holding the very answer its probe expects.
        if sim.shadow.is_version(&doc) {
            break;
        }
        let Some(initial) = undo_to_initial(&exp, sim.log_for(&doc)) else { break };
        setup.groundings.push(format!(
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
        let sim = Sim::replay(&setup.implied_creates, &seeds, ops);
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
            setup.groundings.push(format!(
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
        let sim = Sim::replay(&setup.implied_creates, &seeds, ops);
        let evidence = uniform_follow_text(ops);
        for doc in sim.empty_link_participants {
            // Endset-anchored construction first: a later retrieve_endsets
            // recording this doc's endset coordinates, together with the
            // create_links' own source_text/target_text, pins the content
            // exactly (link_poom/link_poom_no_shift: "First" at 1.1 w 5,
            // "second" at 1.16 w 6 — gaps filled with spaces).
            if let Some(seed) = endset_anchored_seed(ops, &sim.shadow, &doc) {
                if let Entry::Vacant(slot) = seeds.entry(doc.clone()) {
                    setup.groundings.push(format!(
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
                        setup.groundings.push(format!(
                            "implied-setup:placeholder-from-landing: {} participates in a link \
                             while empty; the traverse evidence lands {t:?} there, seeded that",
                            slot.key()
                        ));
                        slot.insert(t.as_bytes().to_vec());
                    }
                    (None, Some(t)) => {
                        setup.groundings.push(format!(
                            "implied-setup:placeholder-from-evidence: {} participates in a link \
                             while empty; every follow expectation records {t:?}, seeded that",
                            slot.key()
                        ));
                        slot.insert(t.as_bytes().to_vec());
                    }
                    (None, None) => {
                        let marker = format!("[{}]", slot.key());
                        setup.groundings.push(format!(
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
    let sim = Sim::replay(&setup.implied_creates, &seeds, ops);
    for (i, plan) in &sim.plans {
        let strategy = sim.plan_strategies.get(i).map(|s| format!(" [{s}]")).unwrap_or_default();
        setup.groundings.push(format!(
            "expansion-plan: op {i} `{}` → {} concrete steps{strategy}",
            op_name(&ops[*i]),
            plan.len()
        ));
    }
    setup.plans = sim.plans;
    for (doc, bytes) in &seeds {
        setup.lead_in.push(SetupStep::Insert { doc: doc.clone(), bytes: bytes.clone() });
    }
    setup
}

/// The document roots the ops reference that no creating op names, in id
/// order, beyond what the scenario's own creating ops make. Every creating
/// op — a create, a version, an open, a `create_and_transclude` — counts the
/// documents it makes (its `results`, docs map, `count` or `targets`, else
/// one), and a referenced root at or below that count is taken to be one of
/// them, so a scenario that creates unnamed documents is not double-created.
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
            Some(Verb::Vcopy) => vcopy_form(op) == VcopyForm::CreateAndTransclude,
            _ => false,
        };
        if creates {
            walk(op, &mut |s| {
                if s.contains('.') && parse_dotted(s).is_some() && link_home_docid(s).is_none() {
                    created.push(s.to_string());
                }
            });
            // The documents the op makes, counted whether or not it recorded
            // their ids — a `results` array or a docs map the golden holds, a
            // `count` within the build budget, or a `targets` list; else one.
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
    if edits.iter().any(|e| matches!(e, Edit::Delete { bytes: None, .. } | Edit::Opaque)) {
        return None;
    }
    // Each entry: the edits still to undo, and the content so far.
    let mut stack: Vec<(&[Edit], Vec<u8>)> = vec![(edits, probed.as_bytes().to_vec())];
    while let Some((edits, cur)) = stack.pop() {
        let Some((last, rest)) = edits.split_last() else { return Some(cur) };
        match last {
            Edit::Insert { at, bytes } => {
                let held = match at {
                    Some(ord) => held_range(cur.len(), *ord, bytes.len() as u64),
                    None => cur.len().checked_sub(bytes.len()).map(|start| start..cur.len()),
                };
                let Some(held) = held.filter(|h| cur[h.clone()] == bytes[..]) else { continue };
                let mut next = cur;
                next.drain(held);
                stack.push((rest, next));
            }
            Edit::Delete { bytes: None, .. } | Edit::Opaque => {} // refused before the search
            Edit::Delete { at, bytes: Some(bytes), explicit } => {
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
                    let text = eo.get(k).and_then(strings_of).as_deref().and_then(as_text);
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
        for s in strings_of(v).unwrap_or_default() {
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

#[cfg(test)]
mod tests;
