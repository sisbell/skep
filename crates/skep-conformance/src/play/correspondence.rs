//! Correspondence: `compare_versions` — skep's COMPARE report normalized to
//! (ordinal A, ordinal B, width) triples, coalesced as the recording client
//! coalesced its own, and judged against what the recording says the
//! compare found: the shared-span pairs it listed, or only how many there
//! were. A compare over `positions` records identity among one document's
//! positions instead, judged through their live images.

use serde_json::{Map, Value};

use skep_address::Nat;
use skep_febe::{Op, Response};
use skep_retrieval::RegionSpec;

use super::{compared_nothing, inexpressible, refusal, Cx, Tally};
use crate::evidence::version_made_before;
use crate::fields::{compare_operands, field, locate, span_dict, str_field, CompareOperand};
use crate::outcome::{Disagreement, OpOutcome};
use crate::tum::{parse_vpos, VPoint};

/// The keys a compare names its documents by, beside its operand fields
/// and `<ref>_span` windows.
const COMPARE_READS: &[&str] = &[
    "docs", "documents", "comparing", "doc_a", "doc1", "a", "doc_b", "doc2", "b", "doc", "docid",
];

/// What the recording says a compare found: the shared-span pairs it
/// listed, or only how many there were.
#[derive(Clone, Copy, Debug)]
enum RecordedShared<'v> {
    Pairs(&'v [Value]),
    Count(u64),
}

impl<'v> RecordedShared<'v> {
    /// The recorded answer: a pair list, unless it is empty or absent and a
    /// count (`pair_count`, `shared_span_pairs`) stands beside it. `None`
    /// when the recording kept neither.
    fn of(pairs: Option<&'v [Value]>, count: Option<u64>) -> Option<RecordedShared<'v>> {
        match (pairs, count) {
            (Some(items), _) if !items.is_empty() => Some(RecordedShared::Pairs(items)),
            (_, Some(n)) => Some(RecordedShared::Count(n)),
            (Some(items), None) => Some(RecordedShared::Pairs(items)),
            (None, None) => None,
        }
    }
}

/// One side of a recorded shared-span pair: (optional docid, ord, width).
type PairSide = (Option<String>, u64, u64);

/// A shared-span pair side: bare `{start,width}`, `{docid, span}`, or
/// `{docid, spans:[…]}` — returns (optional docid, ord, width), content
/// subspace only.
fn pair_side(v: &Value) -> Option<PairSide> {
    if let Some(r) = span_dict(v) {
        return (r.sub == 1).then_some((None, r.ord, r.width));
    }
    let o = v.as_object()?;
    let docid = o.get("docid").and_then(Value::as_str).map(str::to_string);
    let r = match (o.get("span"), o.get("spans").and_then(Value::as_array)) {
        (Some(sp), _) => span_dict(sp)?,
        (None, Some(arr)) => arr.first().and_then(span_dict)?,
        (None, None) => return None,
    };
    (r.sub == 1).then_some((docid, r.ord, r.width))
}

/// One recorded shared-span pair → (A-side, B-side), oriented by docid
/// match first, then key-name match against the two doc references, then
/// the source/dest role convention.
fn orient_pair(
    item: &Value,
    ga: &str,
    gb: &str,
    ref_a: &str,
    ref_b: &str,
) -> Option<((u64, u64), (u64, u64))> {
    let o = item.as_object()?;
    let sides: Vec<(String, PairSide)> =
        o.iter().filter_map(|(k, v)| pair_side(v).map(|s| (k.clone(), s))).collect();
    if sides.len() < 2 {
        return None;
    }
    let score_a = |k: &str, doc: &Option<String>| -> i32 {
        if doc.as_deref() == Some(ga) {
            return 3;
        }
        if k == ref_a || k.contains(ref_a) || ref_a.contains(k) {
            return 2;
        }
        if matches!(k, "a" | "source" | "original" | "doc1" | "first") {
            return 1;
        }
        0
    };
    let score_b = |k: &str, doc: &Option<String>| -> i32 {
        if doc.as_deref() == Some(gb) {
            return 3;
        }
        if k == ref_b || k.contains(ref_b) || ref_b.contains(k) {
            return 2;
        }
        if matches!(k, "b" | "dest" | "target" | "version" | "doc2" | "second") {
            return 1;
        }
        0
    };
    let mut best: Option<(usize, usize, i32)> = None;
    for (i, (ki, (di, _, _))) in sides.iter().enumerate() {
        for (j, (kj, (dj, _, _))) in sides.iter().enumerate() {
            if i == j {
                continue;
            }
            let s = score_a(ki, di) + score_b(kj, dj);
            if best.is_none_or(|(_, _, bs)| s > bs) {
                best = Some((i, j, s));
            }
        }
    }
    let (i, j, _) = best?;
    let (_, (_, oa, wa)) = &sides[i];
    let (_, (_, ob, _)) = &sides[j];
    Some(((*oa, *wa), (*ob, *wa)))
}

/// One side of a compare: its golden docid, the reference the golden names
/// it by (which orients the recorded pairs), and the operand window that
/// narrows its ρ, if any.
#[derive(Debug)]
struct CompareSide<'a> {
    doc: &'a str,
    reference: &'a str,
    window: Option<Vec<(u64, u64)>>,
}

/// skep's coalesced (ordinal A, ordinal B, width) triples, and any pair it
/// reported between documents other than the two compared, judged against
/// the recording. A recorded pair that names no two content-subspace sides
/// is a part the comparison cannot aim at, never dropped; skep's foreign
/// pairs are a disagreement either way.
fn judge_shared(
    recorded: RecordedShared,
    a: &CompareSide,
    b: &CompareSide,
    merged: &[(u64, u64, u64)],
    foreign: &[String],
) -> Tally {
    let mut tally = Tally::default();
    let with_foreign = |mut actual: String| {
        if !foreign.is_empty() {
            actual.push_str(&format!(" + foreign docs {foreign:?}"));
        }
        actual
    };
    match recorded {
        RecordedShared::Pairs(items) => {
            let mut want: Vec<(u64, u64, u64)> = Vec::new();
            for item in items {
                match orient_pair(item, a.doc, b.doc, a.reference, b.reference) {
                    Some(((oa, wa), (ob, _))) => want.push((oa, ob, wa)),
                    None => tally.unaimed(format!(
                        "shared pair {item} names no two content-subspace sides"
                    )),
                }
            }
            want.sort();
            if want == merged && foreign.is_empty() {
                tally.agree();
            } else {
                let actual = with_foreign(format!("{merged:?}"));
                tally.differ(Disagreement { expected: format!("{want:?}"), actual });
            }
        }
        RecordedShared::Count(n) => {
            let found = merged.len() as u64;
            if found == n && foreign.is_empty() {
                tally.agree();
            } else {
                tally.differ(Disagreement {
                    expected: format!("{n} shared pairs"),
                    actual: with_foreign(format!("{found} shared pairs")),
                });
            }
        }
    }
    tally
}

fn run_compare_pair(
    cx: &mut Cx,
    out: &mut OpOutcome,
    a: CompareSide,
    b: CompareSide,
    recorded: RecordedShared,
) {
    let (Some(da), Some(db)) = (cx.alpha.translate(a.doc), cx.alpha.translate(b.doc)) else {
        out.never_bound("compare over never-bound documents".into());
        return;
    };
    // An operand window (compare_partial's "shared (13-18)"; the corpus
    // extension's operand vspec spans) narrows that side's ρ; without one
    // the side is the whole extent.
    let region_of =
        |cx: &Cx, g: &str, d: &skep_address::Address, win: &Option<Vec<(u64, u64)>>| -> RegionSpec {
            let spans = match win {
                Some(list) => list
                    .iter()
                    .filter_map(|&(ord, w)| VPoint::content(ord).region(w).span())
                    .collect(),
                None => {
                    let whole = VPoint::content(1).region(cx.shadow.text_len(g));
                    whole.span().into_iter().collect()
                }
            };
            RegionSpec { doc: d.clone(), spans }
        };
    let rho1 = vec![region_of(cx, a.doc, &da, &a.window)];
    let rho2 = vec![region_of(cx, b.doc, &db, &b.window)];
    let rep = match cx.rig.exec(Op::Compare { rho1, rho2 }) {
        Response::Compare { rep, .. } => rep,
        other => {
            let expected = "a compare report".to_string();
            out.disagree("correspondence", Disagreement { expected, actual: refusal(&other) });
            return;
        }
    };
    // Normalize skep's pairs to (ordA, ordB, width) triples, then coalesce
    // adjacent runs exactly as client.py's collapse_sharedspans did on the
    // recording side (the golden is already collapsed; symmetric treatment).
    // A number past u64 saturates, and so never matches a recorded one.
    let nat_u64 = |n: &Nat| -> u64 { u64::try_from(n).unwrap_or(u64::MAX) };
    let mut triples: Vec<(u64, u64, u64)> = Vec::new();
    let mut foreign: Vec<String> = Vec::new();
    for p in rep.0 {
        let (o1, o2, w) = (nat_u64(&p.u1.ordinal), nat_u64(&p.u2.ordinal), nat_u64(&p.width));
        if nat_u64(&p.u1.subspace) != 1 || nat_u64(&p.u2.subspace) != 1 {
            continue;
        }
        if p.d1 == da && p.d2 == db {
            triples.push((o1, o2, w));
        } else if p.d1 == db && p.d2 == da {
            triples.push((o2, o1, w));
        } else {
            foreign.push(format!("({},{})", p.d1, p.d2));
        }
    }
    triples.sort();
    let mut merged: Vec<(u64, u64, u64)> = Vec::new();
    for t in triples {
        if let Some(last) = merged.last_mut() {
            if last.0 + last.2 == t.0 && last.1 + last.2 == t.1 {
                last.2 += t.2;
                continue;
            }
        }
        merged.push(t);
    }
    let comparator = match recorded {
        RecordedShared::Pairs(_) => "correspondence",
        RecordedShared::Count(_) => "count",
    };
    judge_shared(recorded, &a, &b, &merged, &foreign).settle(out, comparator);
}

pub(super) fn h_compare_versions(cx: &mut Cx, index: usize, op: &Value, out: &mut OpOutcome) {
    // Corpus-extension operands (policy `compare-operands-explicit`,
    // `fields::compare_operands`): two top-level role-keyed vspec-dict
    // fields name the sides and their windows explicitly (ms_version_race
    // `version_a1`/`original`, fanout `dest`/`source` and self-compare
    // `whole`/`whole_again`, the marathon's `doc`/`vbase`). The
    // original/version convention never applies when they exist — it aims
    // at the LATEST version, which these recordings demonstrably do not
    // mean. Verified absent from the 263-scenario corpus, so the legacy
    // paths are untouched.
    let operands = compare_operands(op);
    if let Ok([(ka, da, wa), (kb, db, wb)]) = <[CompareOperand; 2]>::try_from(operands) {
        out.adaptations.push("compare-operands-explicit".into());
        let pairs = field(op, &["result", "shared", "pairs"]).and_then(Value::as_array);
        let count = field(op, &["pair_count"]).and_then(Value::as_u64);
        let Some(recorded) = RecordedShared::of(pairs.map(Vec::as_slice), count) else {
            let mut reads: Vec<&str> = COMPARE_READS.to_vec();
            reads.extend([ka.as_str(), kb.as_str()]);
            compared_nothing(out, op, &reads);
            return;
        };
        let a = CompareSide { doc: &da, reference: &ka, window: (!wa.is_empty()).then_some(wa) };
        let b = CompareSide { doc: &db, reference: &kb, window: (!wb.is_empty()).then_some(wb) };
        run_compare_pair(cx, out, a, b, recorded);
        return;
    }

    // Per-source comparison list (content/vcopy_from_multiple_documents
    // `comparisons`): entries {source: name, shared: […]} against the
    // destination doc.
    if let Some(entries) = field(op, &["results", "comparisons"]).and_then(Value::as_array) {
        if entries.iter().all(|e| e.get("shared").is_some()) && !entries.is_empty() {
            let dest = cx
                .shadow
                .resolve_doc("target")
                .or_else(|| cx.shadow.current());
            let Some(dest) = dest else {
                inexpressible(out, "comparisons with no destination doc in scope".into());
                return;
            };
            let mut tally = Tally::default();
            for e in entries {
                let Some(srcname) = e.get("source").and_then(Value::as_str) else {
                    tally.unaimed("a comparison entry names no source".into());
                    continue;
                };
                let Some(src) = cx.shadow.resolve_doc(srcname) else {
                    tally.unaimed(format!("comparison source `{srcname}` resolves to nothing"));
                    continue;
                };
                let shared: &[Value] =
                    e.get("shared").and_then(Value::as_array).map_or(&[], Vec::as_slice);
                // Each source is compared as an op of its own and folded in
                // as one part.
                let mut part = OpOutcome::new(out.index, &out.op_name);
                let a = CompareSide { doc: &dest, reference: "target", window: None };
                let b = CompareSide { doc: &src, reference: "source", window: None };
                run_compare_pair(cx, &mut part, a, b, RecordedShared::Pairs(shared));
                tally.absorb(out, part, &format!("{srcname}: "));
            }
            tally.settle(out, "correspondence");
            return;
        }
    }

    // Identity among one document's positions (policy
    // `identity-pairs-by-position`): `positions` lists V-positions, and a
    // `results` map records, per "i_j" (1-based into the list), whether
    // positions i and j share their I-address.
    if let (Some(positions), Some(pairs)) = (
        field(op, &["positions"]).and_then(Value::as_array),
        field(op, &["results"]).and_then(Value::as_object),
    ) {
        identity_pairs(cx, op, out, positions, pairs);
        return;
    }

    // The two documents, as referenced by the golden (names or addresses):
    // explicit fields, then the op's `label` field when it is a "<x>_vs_<y>"
    // pair (identity_mixed_sources's "target_vs_source1"), then the
    // original/version convention — the one pair of references the op
    // itself does not name.
    let named_by_op = field(op, &["docs", "documents", "comparing"])
        .and_then(Value::as_array)
        .is_some()
        || (str_field(op, &["doc_a", "doc1", "a"]).is_some()
            && str_field(op, &["doc_b", "doc2", "b"]).is_some())
        || str_field(op, &["label"]).is_some_and(|l| l.contains("_vs_"));
    let mut defaulted = false;
    let (ref_a, ref_b): (String, String) = if let Some(docs) =
        field(op, &["docs", "documents", "comparing"]).and_then(Value::as_array)
    {
        let refs: Vec<String> =
            docs.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
        match refs.as_slice() {
            [a, b] => (a.clone(), b.clone()),
            _ => {
                inexpressible(out, "compare needs exactly two documents".into());
                return;
            }
        }
    } else if let (Some(a), Some(b)) = (
        str_field(op, &["doc_a", "doc1", "a"]),
        str_field(op, &["doc_b", "doc2", "b"]),
    ) {
        (a.to_string(), b.to_string())
    } else if let Some((a, b)) = str_field(op, &["label"])
        .and_then(|l| l.split_once("_vs_"))
        .filter(|(a, b)| {
            cx.shadow.resolve_doc(a).is_some() && cx.shadow.resolve_doc(b).is_some()
        })
    {
        (a.to_string(), b.to_string())
    } else {
        defaulted = true;
        ("original".to_string(), "version".to_string())
    };
    // The default's version is the one the recording made before this op —
    // a reference the recording uses, so one skep refused to make names
    // nothing and leaves the op inexpressible (rulings 20, 20a). A
    // recording that made none compared the scenario's first two documents
    // (policy `compare-default:second-document`), or its one document with
    // itself (`compare:self`).
    let versioned = defaulted && version_made_before(cx.ops, index);
    // Shared pairs: a bare array, or wrapped in a result object
    // (`result: {shared_span_pairs, shared: […]}` —
    // iaddress_allocation/delete_does_not_affect_next_insert's
    // compare_via_transclusion).
    let shared: Option<&Vec<Value>> = field(op, &["shared", "result", "pairs", "shared_spans"])
        .and_then(|v| v.as_array().or_else(|| v.get("shared").and_then(Value::as_array)));
    let shared_items: &[Value] = shared.map_or(&[], Vec::as_slice);
    // Resolve refs; fall back to the docids carried inside the shared items
    // (identity_through_rearrange_pivot's "rearranged"/"original_version").
    let docids_in_items: Vec<String> = shared_items
        .iter()
        .filter_map(Value::as_object)
        .flat_map(|o| o.values())
        .filter_map(|v| v.get("docid").and_then(Value::as_str).map(str::to_string))
        .collect();
    let resolve_side = |cx: &Cx, r: &str, idx: usize| -> Option<String> {
        cx.shadow
            .resolve_doc(r)
            .or_else(|| docids_in_items.get(idx).cloned().filter(|d| cx.shadow.knows(d)))
    };
    // A reference the recording uses: one the op names, the version the
    // recording made, or one a recorded shared pair is keyed by
    // (compare_versions_with_different_links keys its pairs
    // `original`/`version` without naming the documents).
    let recorded_ref = |r: &str| {
        named_by_op
            || (versioned && r == ref_b)
            || shared_items.iter().any(|item| item.as_object().is_some_and(|o| o.contains_key(r)))
    };
    let side_a = resolve_side(cx, &ref_a, 0);
    let mut side_b = resolve_side(cx, &ref_b, 1);
    if side_b.is_none() && defaulted && !versioned {
        if let Some(second) = cx.shadow.created().get(1).cloned() {
            out.adaptations.push("compare-default:second-document".into());
            side_b = Some(second);
        }
    }
    let (ga, gb) = match (side_a, side_b) {
        (Some(a), Some(b)) => (a, b),
        // One side resolvable, the other a reference the recording never
        // uses, and the items carrying no second docid: the script compared
        // the document WITH ITSELF (internal/insert_only_baseline's
        // source/dest pairs over one doc). A second reference the recording
        // does use but the shadow cannot ground — a version skep refused to
        // mint (ruling 20a) — is no such comparison; the op is inexpressible.
        (Some(a), None) if !recorded_ref(&ref_b) && docids_in_items.iter().all(|d| d == &a) => {
            out.adaptations.push("compare:self".into());
            (a.clone(), a)
        }
        (None, Some(b)) if !recorded_ref(&ref_a) && docids_in_items.iter().all(|d| d == &b) => {
            out.adaptations.push("compare:self".into());
            (b.clone(), b)
        }
        _ => {
            inexpressible(out, format!("compare documents `{ref_a}`/`{ref_b}` resolve to nothing"));
            return;
        }
    };
    // Operand windows: top-level `<ref>_span` keys narrow that side's ρ —
    // compare ops honor their windows (compare_partial's descriptive
    // "shared (13-18)" grounds to doc1[13..19]; round 2 ran whole-document).
    let mut reads: Vec<&str> = COMPARE_READS.to_vec();
    let mut win_a: Option<Vec<(u64, u64)>> = None;
    let mut win_b: Option<Vec<(u64, u64)>> = None;
    if let Some(o) = op.as_object() {
        for (k, v) in o {
            let Some(stem) = k.strip_suffix("_span") else { continue };
            reads.push(k);
            let Some(side_doc) = cx.shadow.resolve_doc(stem) else { continue };
            let win = if let Some(r) = span_dict(v) {
                (r.sub == 1).then_some((r.ord, r.width))
            } else if let Some(s) = v.as_str() {
                locate(cx.shadow, Some(&side_doc), s).map(|l| (l.ord, l.width))
            } else {
                None
            };
            let Some(win) = win else { continue };
            if side_doc == ga && win_a.is_none() {
                win_a = Some(vec![win]);
                out.adaptations.push("compare-window".into());
            } else if side_doc == gb && win_b.is_none() {
                win_b = Some(vec![win]);
                out.adaptations.push("compare-window".into());
            }
        }
    }
    let count = field(op, &["shared_span_pairs"]).and_then(Value::as_u64);
    let Some(recorded) = RecordedShared::of(shared.map(Vec::as_slice), count) else {
        compared_nothing(out, op, &reads);
        return;
    };
    let a = CompareSide { doc: &ga, reference: &ref_a, window: win_a };
    let b = CompareSide { doc: &gb, reference: &ref_b, window: win_b };
    run_compare_pair(cx, out, a, b, recorded);
}

/// Policy `identity-pairs-by-position` (internal/internal_transclusion_
/// multiple_copies): each recorded pair "i_j" of `positions` — 1-based —
/// judged by whether skep's live images of the two positions start at one
/// I-address, against the recorded bool.
fn identity_pairs(
    cx: &mut Cx,
    op: &Value,
    out: &mut OpOutcome,
    positions: &[Value],
    pairs: &Map<String, Value>,
) {
    out.adaptations.push("identity-pairs-by-position".into());
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        inexpressible(out, "position identity compare with no document in scope".into());
        return;
    };
    let Some(d) = cx.skep_doc(&doc) else {
        out.never_bound(format!("position identity compare of never-bound doc {doc}"));
        return;
    };
    let image = |pos: &str| -> Option<skep_address::Address> {
        let span = parse_vpos(pos)?.region(1).span()?;
        match cx.rig.exec(Op::Image { d: d.clone(), region: vec![span] }) {
            Response::Runs { runs, .. } => runs.first().map(|r| r.i_start().clone()),
            _ => None,
        }
    };
    let position = |n: Option<usize>| n?.checked_sub(1).and_then(|i| positions.get(i)?.as_str());
    let mut tally = Tally::default();
    for (key, want) in pairs {
        let (i, j) = key
            .split_once('_')
            .map_or((None, None), |(i, j)| (i.parse().ok(), j.parse().ok()));
        let (Some(pi), Some(pj), Some(want)) = (position(i), position(j), want.as_bool()) else {
            tally.unaimed(format!("pair `{key}` names no two recorded positions"));
            continue;
        };
        let label = format!("{pi}~{pj} share an I-address: ");
        let expected = format!("{label}{want}");
        match (image(pi), image(pj)) {
            (Some(a), Some(b)) if (a == b) == want => tally.agree(),
            (Some(a), Some(b)) => {
                tally.differ(Disagreement { expected, actual: format!("{label}{}", a == b) })
            }
            _ => {
                let actual = "a position has no live image".to_string();
                tally.differ(Disagreement { expected, actual })
            }
        }
    }
    tally.settle(out, "identity-pairs");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outcome::Status;

    fn side<'a>(doc: &'a str, reference: &'a str) -> CompareSide<'a> {
        CompareSide { doc, reference, window: None }
    }

    /// A count-only recording is judged as a count: two recorded pairs
    /// against none found disagree, where a pair list read as empty would
    /// have agreed with skep's empty report.
    #[test]
    fn a_recorded_count_is_judged_as_a_count() {
        let (a, b) = (side("1.1.0.1.0.1", "original"), side("1.1.0.1.0.2", "version"));
        let mut out = OpOutcome::new(0, "compare");
        judge_shared(RecordedShared::Count(2), &a, &b, &[], &[]).settle(&mut out, "count");
        assert_eq!(out.status, Status::Disagreed);
        let counted =
            Disagreement { expected: "2 shared pairs".into(), actual: "0 shared pairs".into() };
        assert_eq!(out.disagreement, Some(counted));

        let mut out = OpOutcome::new(0, "compare");
        judge_shared(RecordedShared::Count(1), &a, &b, &[(1, 1, 5)], &[]).settle(&mut out, "count");
        assert_eq!(out.status, Status::Agreed);
    }

    /// A recorded pair the comparison cannot orient is never dropped: it
    /// leaves the op short of a full comparison.
    #[test]
    fn an_unreadable_recorded_pair_is_not_dropped() {
        let (a, b) = (side("1.1.0.1.0.1", "original"), side("1.1.0.1.0.2", "version"));
        let pairs = [serde_json::json!({"original": {"start": "2.1", "width": "0.1"}})];
        let mut out = OpOutcome::new(0, "compare");
        judge_shared(RecordedShared::Pairs(&pairs), &a, &b, &[], &[]).settle(&mut out, "pairs");
        assert_eq!(out.status, Status::Inexpressible);
    }

    /// A pair skep reports between documents other than the two compared
    /// disagrees, even beside an answer that matches the recording.
    #[test]
    fn a_pair_between_other_documents_is_a_disagreement() {
        let (a, b) = (side("1.1.0.1.0.1", "original"), side("1.1.0.1.0.2", "version"));
        let pairs = [serde_json::json!({
            "original": {"start": "1.1", "width": "0.5"},
            "version": {"start": "1.3", "width": "0.5"},
        })];
        let judged = |foreign: &[String]| {
            let mut out = OpOutcome::new(0, "compare");
            judge_shared(RecordedShared::Pairs(&pairs), &a, &b, &[(1, 3, 5)], foreign)
                .settle(&mut out, "pairs");
            out.status
        };
        assert_eq!(judged(&[]), Status::Agreed);
        assert_eq!(judged(&["(1.0.1.0.7,1.0.1.0.8)".to_string()]), Status::Disagreed);
    }
}
