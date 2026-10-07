//! Correspondence: `compare_versions` — skep's COMPARE report normalized to
//! (ordinal A, ordinal B, width) triples, coalesced as the recording client
//! coalesced its own, and matched against the recorded shared-span pairs.

use serde_json::Value;

use skep_address::Nat;
use skep_febe::{Op, Response};
use skep_retrieval::RegionSpec;

use super::{fail_response, inexpressible, Cx};
use crate::fields::{field, locate, span_dict, str_field, vspec_dict};
use crate::outcome::{OpOutcome, Status};
use crate::tum::vspan;

/// One side of a recorded shared-span pair: (optional docid, ord, width).
type PairSide = (Option<String>, u64, u64);

/// A shared-span pair side: bare `{start,width}`, `{docid, span}`, or
/// `{docid, spans:[…]}` — returns (optional docid, ord, width), content
/// subspace only.
fn pair_side(v: &Value) -> Option<PairSide> {
    if let Some((sub, ord, w)) = span_dict(v) {
        if sub == 1 {
            return Some((None, ord, w));
        }
        return None;
    }
    let o = v.as_object()?;
    let docid = o.get("docid").and_then(Value::as_str).map(str::to_string);
    if let Some(sp) = o.get("span") {
        let (sub, ord, w) = span_dict(sp)?;
        if sub == 1 {
            return Some((docid, ord, w));
        }
        return None;
    }
    if let Some(arr) = o.get("spans").and_then(Value::as_array) {
        let (sub, ord, w) = arr.first().and_then(span_dict)?;
        if sub == 1 {
            return Some((docid, ord, w));
        }
    }
    None
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
struct CompareSide<'a> {
    doc: &'a str,
    reference: &'a str,
    window: Option<Vec<(u64, u64)>>,
}

fn run_compare_pair(
    cx: &mut Cx,
    out: &mut OpOutcome,
    a: CompareSide,
    b: CompareSide,
    shared: &[Value],
) -> Option<()> {
    let (Some(da), Some(db)) = (cx.alpha.translate(a.doc), cx.alpha.translate(b.doc)) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some("compare over unresolvable documents".into());
        return None;
    };
    // An operand window (compare_partial's "shared (13-18)"; the corpus
    // extension's operand vspec spans) narrows that side's ρ; without one
    // the side is the whole extent.
    let region_of =
        |cx: &Cx, g: &str, d: &skep_address::Address, win: Option<Vec<(u64, u64)>>| -> RegionSpec {
            let spans = match win {
                Some(list) => {
                    list.into_iter().filter_map(|(ord, w)| vspan(1, ord, w)).collect()
                }
                None => {
                    let n = cx.shadow.text_len(g);
                    vspan(1, 1, n).into_iter().collect()
                }
            };
            RegionSpec { doc: d.clone(), spans }
        };
    let rho1 = vec![region_of(cx, a.doc, &da, a.window)];
    let rho2 = vec![region_of(cx, b.doc, &db, b.window)];
    let rep = match cx.rig.exec(Op::Compare { rho1, rho2 }) {
        Response::Compare { rep, .. } => rep,
        other => {
            fail_response(out, "correspondence", "a compare report", &other);
            return None;
        }
    };
    // Normalize skep's pairs to (ordA, ordB, width) triples, then coalesce
    // adjacent runs exactly as client.py's collapse_sharedspans did on the
    // recording side (the golden is already collapsed; symmetric treatment).
    let nat_u64 = |n: &Nat| -> u64 { n.to_string().parse().unwrap_or(u64::MAX) };
    let a_str = crate::tum::addr_str(&da);
    let b_str = crate::tum::addr_str(&db);
    let mut triples: Vec<(u64, u64, u64)> = Vec::new();
    let mut foreign: Vec<String> = Vec::new();
    for p in rep.0 {
        let (d1, d2) = (crate::tum::addr_str(&p.d1), crate::tum::addr_str(&p.d2));
        let (o1, o2, w) = (nat_u64(&p.u1.ordinal), nat_u64(&p.u2.ordinal), nat_u64(&p.width));
        if nat_u64(&p.u1.subspace) != 1 || nat_u64(&p.u2.subspace) != 1 {
            continue;
        }
        if d1 == a_str && d2 == b_str {
            triples.push((o1, o2, w));
        } else if d1 == b_str && d2 == a_str {
            triples.push((o2, o1, w));
        } else {
            foreign.push(format!("({d1},{d2})"));
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
    let mut want: Vec<(u64, u64, u64)> = Vec::new();
    for item in shared {
        if let Some(((oa, wa), (ob, _))) = orient_pair(item, a.doc, b.doc, a.reference, b.reference)
        {
            want.push((oa, ob, wa));
        }
    }
    want.sort();
    out.comparator = Some("correspondence".into());
    if want == merged && foreign.is_empty() {
        out.status = Status::Agreed;
    } else {
        out.status = Status::Disagreed;
        out.expected = Some(format!("{want:?}"));
        let mut act = format!("{merged:?}");
        if !foreign.is_empty() {
            act.push_str(&format!(" + foreign docs {foreign:?}"));
        }
        out.actual = Some(act);
    }
    Some(())
}

/// A compare operand named by a top-level vspec-dict field: (field key,
/// golden docid, content-subspace (ord, width) windows).
type Operand = (String, String, Vec<(u64, u64)>);

pub(super) fn h_compare(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    // Corpus-extension operands (policy `compare-operands-explicit`): two
    // top-level role-keyed vspec-dict fields name the sides and their
    // windows explicitly (ms_version_race `version_a1`/`original`, fanout
    // `dest`/`source` and self-compare `whole`/`whole_again`, the marathon's
    // `doc`/`vbase`). The original/version convention never applies when
    // they exist — it aims at the LATEST version, which these recordings
    // demonstrably do not mean. Verified absent from the 263-scenario
    // corpus, so the legacy paths are untouched.
    const NOT_OPERAND: &[&str] = &["result", "pairs", "shared", "shared_spans"];
    let operands: Vec<Operand> = op
        .as_object()
        .map(|o| {
            o.iter()
                .filter(|(k, _)| !NOT_OPERAND.contains(&k.as_str()))
                .filter_map(|(k, v)| {
                    let (docid, spans) = vspec_dict(v)?;
                    let wins: Vec<(u64, u64)> = spans
                        .iter()
                        .filter(|(s, _, _)| *s == 1)
                        .map(|(_, ord, w)| (*ord, *w))
                        .collect();
                    Some((k.clone(), docid, wins))
                })
                .collect()
        })
        .unwrap_or_default();
    if operands.len() == 2 {
        out.adaptations.push("compare-operands-explicit".into());
        let (ka, da, wa) = operands[0].clone();
        let (kb, db, wb) = operands[1].clone();
        let shared: Vec<Value> = field(op, &["result", "shared", "pairs"])
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let a = CompareSide { doc: &da, reference: &ka, window: (!wa.is_empty()).then_some(wa) };
        let b = CompareSide { doc: &db, reference: &kb, window: (!wb.is_empty()).then_some(wb) };
        if run_compare_pair(cx, out, a, b, &shared).is_none() {
            return;
        }
        // A bare pair_count (no recorded pair list) re-judges as a count.
        if let (Some(n), true) =
            (field(op, &["pair_count"]).and_then(Value::as_u64), shared.is_empty())
        {
            if out.status == Status::Disagreed && out.expected.as_deref() == Some("[]") {
                let actual = out.actual.as_deref().unwrap_or("").matches('(').count();
                out.comparator = Some("count".into());
                if actual as u64 == n {
                    out.status = Status::Agreed;
                    out.expected = None;
                    out.actual = None;
                } else {
                    out.expected = Some(format!("{n} shared pairs"));
                    out.actual = Some(format!("{actual} shared pairs"));
                }
            }
        }
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
                .or_else(|| cx.shadow.scoped());
            let Some(dest) = dest else {
                inexpressible(out, "comparisons with no destination doc in scope".into());
                return;
            };
            let mut fails: Vec<(String, String)> = Vec::new();
            for e in entries {
                let Some(srcname) = e.get("source").and_then(Value::as_str) else { continue };
                let Some(src) = cx.shadow.resolve_doc(srcname) else { continue };
                let shared: Vec<Value> =
                    e.get("shared").and_then(Value::as_array).cloned().unwrap_or_default();
                let mut sub = OpOutcome::new(out.index, &out.label);
                let a = CompareSide { doc: &dest, reference: "target", window: None };
                let b = CompareSide { doc: &src, reference: "source", window: None };
                run_compare_pair(cx, &mut sub, a, b, &shared);
                if sub.status == Status::Disagreed {
                    fails.push((
                        format!("{srcname}: {}", sub.expected.unwrap_or_default()),
                        sub.actual.unwrap_or_else(|| sub.note.unwrap_or_default()),
                    ));
                }
            }
            out.comparator = Some("correspondence".into());
            if fails.is_empty() {
                out.status = Status::Agreed;
            } else {
                out.status = Status::Disagreed;
                out.expected =
                    Some(fails.iter().map(|f| f.0.clone()).collect::<Vec<_>>().join(" | "));
                out.actual =
                    Some(fails.iter().map(|f| f.1.clone()).collect::<Vec<_>>().join(" | "));
            }
            return;
        }
    }

    // The two documents, as referenced by the golden (names or addresses):
    // explicit fields, then the op's own label when it is a "<x>_vs_<y>"
    // pair (identity_mixed_sources's "target_vs_source1"), then the
    // original/version convention.
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
        ("original".to_string(), "version".to_string())
    };
    // Shared pairs: a bare array, or wrapped in a result object
    // (`result: {shared_span_pairs, shared: […]}` —
    // iaddress_allocation/delete_does_not_affect_next_insert's
    // compare_via_transclusion).
    let shared: Vec<Value> = field(op, &["shared", "result", "pairs", "shared_spans"])
        .and_then(|v| {
            v.as_array().cloned().or_else(|| v.get("shared").and_then(Value::as_array).cloned())
        })
        .unwrap_or_default();
    // Resolve refs; fall back to the docids carried inside the shared items
    // (identity_through_rearrange_pivot's "rearranged"/"original_version").
    let docids_in_items: Vec<String> = shared
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
    let (ga, gb) = match (resolve_side(cx, &ref_a, 0), resolve_side(cx, &ref_b, 1)) {
        (Some(a), Some(b)) => (a, b),
        // One side resolvable and the items carry no second docid: the
        // script compared the document WITH ITSELF (internal/
        // insert_only_baseline's source/dest pairs over one doc).
        (Some(a), None) | (None, Some(a)) if docids_in_items.iter().all(|d| d == &a) => {
            out.adaptations.push("compare:self".into());
            (a.clone(), a)
        }
        _ => {
            inexpressible(out, format!("compare documents `{ref_a}`/`{ref_b}` unresolvable"));
            return;
        }
    };
    if shared.is_empty() && field(op, &["shared", "result", "pairs"]).is_none() {
        // Count-only expectation (insert_only_baseline `shared_span_pairs`)
        // or nothing to compare.
        if field(op, &["shared_span_pairs"]).and_then(Value::as_u64).is_none() {
            out.status = Status::NotCompared;
            return;
        }
    }
    // Operand windows: top-level `<ref>_span` keys narrow that side's ρ —
    // compare ops honor their windows (compare_partial's descriptive
    // "shared (13-18)" grounds to doc1[13..19]; round 2 ran whole-document).
    let mut win_a: Option<Vec<(u64, u64)>> = None;
    let mut win_b: Option<Vec<(u64, u64)>> = None;
    if let Some(o) = op.as_object() {
        for (k, v) in o {
            let Some(stem) = k.strip_suffix("_span") else { continue };
            let Some(side_doc) = cx.shadow.resolve_doc(stem) else { continue };
            let win = if let Some((sub, ord, w)) = span_dict(v) {
                (sub == 1).then_some((ord, w))
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
    let a = CompareSide { doc: &ga, reference: &ref_a, window: win_a };
    let b = CompareSide { doc: &gb, reference: &ref_b, window: win_b };
    if run_compare_pair(cx, out, a, b, &shared).is_none() {
        return;
    }
    // shared_span_pairs count check rides on top when present and the span
    // list was absent.
    if let (Some(n), true) =
        (field(op, &["shared_span_pairs"]).and_then(Value::as_u64), shared.is_empty())
    {
        if out.status == Status::Disagreed && out.expected.as_deref() == Some("[]") {
            // Re-judge as a count comparison.
            let actual = out.actual.as_deref().unwrap_or("").matches('(').count();
            out.comparator = Some("count".into());
            if actual as u64 == n {
                out.status = Status::Agreed;
                out.expected = None;
                out.actual = None;
            } else {
                out.expected = Some(format!("{n} shared pairs"));
                out.actual = Some(format!("{actual} shared pairs"));
            }
        }
    }
}
