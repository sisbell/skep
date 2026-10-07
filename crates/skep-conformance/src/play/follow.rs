//! Following links: `follow_link` — a slot projected into the document the
//! golden names, or the recorded endset rendered by identity (operator
//! ruling 11) — and the traversal macros, whose hops resolve from the
//! shadow's links rather than by text re-search.

use serde_json::Value;

use skep_discovery::{FourSet, SlotSpec};
use skep_febe::{Op, Response};
use skep_retrieval::{DeliveryItem, Spec};

use super::{
    compared_nothing, elem_range, inexpressible, refusal, settle_unaccepted, Cx, ImageRow, Tally,
};
use crate::allowlist::Adjustments;
use crate::compare::{compare_addr_sets, compare_spansets};
use crate::fields::{
    expected_failure, field, op_name, parse_python_spec, raw_spanset_of, str_field, strings_of,
    vspec_dict, DocSpans, RawSpan,
};
use crate::outcome::{Disagreement, OpOutcome};
use crate::tum::{is_link_address, VPoint};

/// The arguments a follow_link carries: the link, and the end it follows.
const FOLLOW_READS: &[&str] =
    &["end", "direction", "linkend", "which", "link", "link_id", "id", "doc", "docid"];

/// The arguments a traversal carries beside a follow's: where it starts and
/// ends.
const TRAVERSE_READS: &[&str] = &[
    "end", "direction", "linkend", "which", "link", "link_id", "id", "doc", "docid", "start",
];

/// Resolve a link-slot name to M7's positional index (FROM=1, TO=2, TYPE=3).
/// "three" is the new corpus's name for the third endset (`end: "three"`).
fn slot_of(name: &str) -> Option<usize> {
    if name.contains("source") || name == "from" {
        return Some(1);
    }
    if name.contains("target") || name == "to" {
        return Some(2);
    }
    if name.contains("type") || name.contains("three") {
        return Some(3);
    }
    None
}

pub(super) fn h_follow_link(
    cx: &mut Cx,
    op: &Value,
    out: &mut OpOutcome,
    adjustments: &Adjustments,
) {
    out.adaptations.push("follow_as_projection".into());
    let name = op_name(op);
    let explicit_slot = str_field(op, &["end", "direction", "linkend", "which"])
        .and_then(|e| {
            if e.contains("->") {
                // "direction": "A->B" follows the link forward: TARGET end.
                Some(2)
            } else {
                slot_of(e)
            }
        })
        .or_else(|| {
            if name.contains("source") {
                Some(1)
            } else if name.contains("target") {
                Some(2)
            } else if name.contains("type") {
                Some(3)
            } else {
                None
            }
        });
    let (mut slot, defaulted) = match explicit_slot {
        Some(s) => (s, false),
        None => {
            // Bare follow records the SOURCE end (pinned by isolation/
            // insert_text_does_not_affect_links_in_same_document, whose
            // recorded before/after results are the source spans).
            out.adaptations.push("default-slot:source".into());
            (1, true)
        }
    };
    let link_golden = str_field(op, &["link", "link_id", "id"])
        .filter(|s| is_link_address(s))
        .map(str::to_string)
        .or_else(|| {
            out.adaptations.push("implicit_last_link".into());
            cx.shadow.last_link.clone()
        });
    let Some(link_golden) = link_golden else {
        inexpressible(out, "follow_link with no link in scope".into());
        return;
    };
    let Some(link) = cx.alpha.translate(&link_golden) else {
        out.never_bound(format!("follow of never-bound link {link_golden}"));
        return;
    };
    let Some(expected) = field(op, &["result", "content", "contents", "expected", "spans"]) else {
        // No recorded result but a recorded FAILURE (nary_empty_endset_shapes:
        // green's `?` following an empty or marker-typed end): ask skep to
        // follow the slot and reconcile. An empty/invalid answer is the same
        // observable — nothing followable — as green's refusal; delivered
        // spans are a divergence.
        if let Some(err) = expected_failure(op) {
            match cx.rig.exec(Op::FollowLink { a: link.clone(), slot }) {
                Response::Follow { result: Err(_), .. } => {
                    out.agree("expected-failure");
                    out.add_note("both sides refuse the slot (skep: invalid slot)".into());
                }
                Response::Follow { result: Ok(set), .. } => {
                    // Types-doc spans are harness infrastructure (policy
                    // `types_document`) — a marker-typed link's slot 3 holds
                    // only the types-document position, which the golden
                    // cannot speak; excluded before judging.
                    let real = set
                        .iter()
                        .filter(|sp| {
                            skep_address::validate(sp.start().clone())
                                .map(|a| !cx.rig.is_infra_addr(&a))
                                .unwrap_or(true)
                        })
                        .count();
                    if real == 0 {
                        out.adaptations.push("types_document".into());
                        out.agree("expected-failure");
                        out.add_note(
                            "both sides surface nothing followable (green: ?, skep: empty or \
                             types-document-only endset)"
                                .into(),
                        );
                    } else {
                        let expected = format!("failure: {err:?}");
                        let actual = format!("skep followed the slot to {real} span(s)");
                        out.disagree("expected-failure", Disagreement { expected, actual });
                    }
                }
                other => settle_unaccepted(out, Some(err), &other),
            }
            return;
        }
        compared_nothing(out, op, FOLLOW_READS);
        return;
    };
    // A defaulted slot yields to the recorded result's own document: the
    // slot whose projection lands in it is the end the script followed
    // (subspace/insert_text_check_both_link_positions's bare follow records
    // the TARGET vspec).
    if defaulted {
        if let Some((Some(docid), spans)) = raw_spanset_of(expected) {
            if !spans.is_empty() {
                if let Some(d) = cx.alpha.peek_translate(&docid) {
                    let nonempty = |cx: &mut Cx, s: usize| -> bool {
                        matches!(
                            cx.rig.exec(Op::Project { a: link.clone(), slot: s, d: d.clone() }),
                            Response::SpanSet { set, .. } if set.iter().next().is_some()
                        )
                    };
                    if !nonempty(cx, 1) && nonempty(cx, 2) {
                        slot = 2;
                        out.adaptations.push("slot-from-evidence-doc".into());
                    }
                }
            }
        }
    }
    follow_compare(cx, out, adjustments, &link, slot, expected);
}

/// Project a link slot and compare against a recorded expectation (vspec
/// dicts, a python VSpec string, or endset-content strings).
fn follow_compare(
    cx: &mut Cx,
    out: &mut OpOutcome,
    adjustments: &Adjustments,
    link: &skep_address::Address,
    slot: usize,
    expected: &Value,
) {
    let project = |cx: &mut Cx, d: &skep_address::Address| -> Result<skep_address::SpanSet, String> {
        match cx.rig.exec(Op::Project { a: link.clone(), slot, d: d.clone() }) {
            Response::SpanSet { set, .. } => Ok(set),
            r => Err(refusal(&r)),
        }
    };

    // Shape 1: vspec dicts (possibly several docs) — compare spans per doc.
    let as_vspecs: Option<Vec<DocSpans>> =
        expected.as_array().and_then(|arr| arr.iter().map(vspec_dict).collect());
    if let Some(vspecs) = as_vspecs {
        if !vspecs.is_empty() {
            let mut tally = Tally::default();
            for (docid, regions) in vspecs {
                let expected = format!("{docid}: spans");
                let Some(d) = cx.alpha.translate(&docid) else {
                    let actual = format!("{docid}: never bound");
                    tally.differ(Disagreement { expected, actual });
                    continue;
                };
                let want: Vec<RawSpan> = regions
                    .iter()
                    .map(|r| (format!("{}.{}", r.sub, r.ord), format!("0.{}", r.width)))
                    .collect();
                let label = format!("{docid}: ");
                match project(cx, &d) {
                    Ok(set) => tally.judge(
                        compare_spansets(&want, &set, adjustments, &mut out.adaptations),
                        &label,
                    ),
                    Err(code) => {
                        let actual = format!("{docid}: {code}");
                        tally.differ(Disagreement { expected, actual })
                    }
                }
            }
            tally.settle(out, "projection");
            return;
        }
    }
    // Shape 2: python VSpec string.
    if let Some(s) = expected.as_str() {
        if let Some((Some(docid), spans)) = parse_python_spec(s) {
            let target = cx.alpha.translate(&docid);
            let projected = match target {
                Some(d) => project(cx, &d),
                None => Err("never bound".to_string()),
            };
            match projected {
                Ok(set) => match compare_spansets(&spans, &set, adjustments, &mut out.adaptations) {
                    Ok(()) => out.agree("projection"),
                    Err(d) => out.disagree("projection", d),
                },
                Err(code) => {
                    let expected = format!("{docid}: spans");
                    let actual = format!("{docid}: {code}");
                    out.disagree("projection", Disagreement { expected, actual })
                }
            }
            return;
        }
    }
    // Shape 3: strings (endset CONTENT) or the empty list — operator ruling
    // 11 (policy `render-by-identity`): render the RECORDED endset's bytes
    // once per I-span, in span order, never once per projected occurrence.
    let Some(strings) = strings_of(expected) else {
        inexpressible(out, "follow_link expectation in an unrecognized shape".into());
        return;
    };
    out.adaptations.push("render-by-identity".into());
    let want = strings.join("");
    match cx.render_recorded_endset(link, slot) {
        Ok((rendered, notes)) => {
            if !notes.is_empty() {
                out.add_note(notes.join("; "));
            }
            if rendered == want {
                out.agree("follow-recorded-endset");
            } else {
                let (expected, actual) = (format!("{want:?}"), format!("{rendered:?}"));
                out.disagree("follow-recorded-endset", Disagreement { expected, actual });
            }
        }
        Err(code) => {
            let (expected, actual) = (format!("{want:?}"), format!("followlink: {code}"));
            out.disagree("follow-recorded-endset", Disagreement { expected, actual })
        }
    }
}

impl Cx<'_> {
    /// Ruling 11's follow rendering (policy `render-by-identity`): the
    /// RECORDED endset from `Op::FollowLink`, rendered as bytes ONCE per
    /// I-span in span order — each portion read from the first live
    /// arrangement (creation order) that still speaks for it. Portions no
    /// arrangement holds render nothing (udanax's orphan follows recorded
    /// empty; live-only keeps that agreement) and are counted in the note.
    fn render_recorded_endset(
        &self,
        link: &skep_address::Address,
        slot: usize,
    ) -> Result<(String, Vec<String>), String> {
        let set = match self.rig.exec(Op::FollowLink { a: link.clone(), slot }) {
            Response::Follow { result: Ok(set), .. } => set,
            Response::Follow { result: Err(_), .. } => {
                return Ok((String::new(), vec!["followlink: invalid slot".into()]))
            }
            r => return Err(refusal(&r)),
        };
        // Index every doc's live V→I rows once.
        let mut doc_rows: Vec<(String, Vec<ImageRow>)> = Vec::new();
        for docid in self.shadow.created() {
            if self.shadow.text_len(docid) == 0 {
                continue;
            }
            let rows = self.image_rows(docid);
            if !rows.is_empty() {
                doc_rows.push((docid.clone(), rows));
            }
        }
        let mut notes = Vec::new();
        let mut rendered_bytes: Vec<u8> = Vec::new();
        let mut missing = 0u64;
        for ispan in set.iter() {
            let Some(range) = elem_range(ispan) else {
                notes.push("non-element endset span skipped".into());
                continue;
            };
            let mut buf: Vec<Option<u8>> = vec![None; range.width as usize];
            for (docid, rows) in &doc_rows {
                if buf.iter().all(Option::is_some) {
                    break;
                }
                let Some(d) = self.alpha.peek_exact(docid) else { continue };
                for row in rows {
                    if row.iextent.prefix != range.prefix {
                        continue;
                    }
                    let a = row.iextent.lo.max(range.lo);
                    let b = row.iextent.hi().min(range.hi());
                    if a >= b {
                        continue;
                    }
                    let off = (a - range.lo) as usize;
                    let len = (b - a) as usize;
                    if buf[off..off + len].iter().all(Option::is_some) {
                        continue;
                    }
                    let at = VPoint::content(row.v_ord + (a - row.iextent.lo));
                    let Some(span) = at.region(b - a).span() else { continue };
                    let items = match self
                        .rig
                        .exec(Op::RetrieveV { specs: vec![Spec { doc: d.clone(), span }] })
                    {
                        Response::Delivery { items, .. } => items.0,
                        r => {
                            notes.push(format!("{docid}: retrieve {}", refusal(&r)));
                            continue;
                        }
                    };
                    let mut k = off;
                    for it in items {
                        if k >= off + len {
                            break;
                        }
                        if let DeliveryItem::Content(val) = it {
                            for byte in val.as_bytes() {
                                if k >= off + len {
                                    break;
                                }
                                if buf[k].is_none() {
                                    buf[k] = Some(*byte);
                                }
                                k += 1;
                            }
                        } else {
                            k += 1; // a link ref is never endset text
                        }
                    }
                }
            }
            for cell in &buf {
                match cell {
                    Some(b) => rendered_bytes.push(*b),
                    None => missing += 1,
                }
            }
        }
        if missing > 0 {
            notes.push(format!(
                "{missing} recorded endset element(s) have no live arrangement (deleted \
                 everywhere); rendered without them"
            ));
        }
        Ok((String::from_utf8_lossy(&rendered_bytes).into_owned(), notes))
    }
}

/// Traversal macros: reverse_traversal / traverse_* / follow_links_* —
/// per-entry link follows with optional per-hop find_links checks. An op in
/// this family without a step list is a single follow (follow_links_target).
///
/// Hop links resolve from the WORLD (policy `traverse-hops-from-world`):
/// arrow-keyed edges first, then the shadow's links — the link
/// whose FROM endset lives in the hop's from-doc (narrowed by the to-doc
/// when the entry names one). Text is never re-searched to find a link.
pub(super) fn h_traverse(cx: &mut Cx, op: &Value, out: &mut OpOutcome, adjustments: &Adjustments) {
    let name = op_name(op).to_ascii_lowercase();
    let entries = field(op, &["path", "traversal", "results", "steps"])
        .and_then(Value::as_array)
        .or_else(|| {
            // A `result`/`results` list of step OBJECTS is a traversal; a
            // list of strings/vspecs is a single follow's expectation.
            field(op, &["result", "results"])
                .and_then(Value::as_array)
                .filter(|a| a.iter().all(|v| v.is_object() && vspec_dict(v).is_none()))
        });
    let Some(entries) = entries else {
        h_follow_link(cx, op, out, adjustments);
        return;
    };
    let reverse = name.contains("reverse");
    let default_slot = if name.contains("source") || reverse { 1 } else { 2 };
    out.adaptations.push("traverse-hops-from-world".into());
    let mut tally = Tally::default();
    // Where the traversal stands (a golden doc) and the last link followed —
    // landing-content entries compare against them.
    let mut here: Option<String> = None;
    let mut last_followed: Option<String> = None;
    for entry in entries {
        let Some(e) = entry.as_object() else { continue };
        // The entry's own doc anchors (step token / step "F->T" / from / at).
        let step_raw = e.get("step").and_then(Value::as_str);
        let (step_from, step_to) = match step_raw.and_then(|s| s.split_once("->")) {
            Some((f, t)) => (
                Some(f.trim().to_string()),
                t.split_whitespace().next().map(str::to_string),
            ),
            None => (
                step_raw.and_then(|s| s.split_whitespace().next()).map(str::to_string),
                None,
            ),
        };
        let from_tok = e
            .get("from")
            .and_then(Value::as_str)
            .map(|s| s.trim().to_string())
            .or(step_from);
        let to_tok = e
            .get("to")
            .and_then(Value::as_str)
            .and_then(|t| t.split_whitespace().next())
            .map(str::to_string)
            .or(step_to);
        let from_doc = from_tok.as_deref().and_then(|t| cx.shadow.resolve_doc(t));
        let to_doc = to_tok.as_deref().and_then(|t| cx.shadow.resolve_doc(t));
        if let Some(d) = &from_doc {
            here = Some(d.clone());
        }

        // links_found — a count (u64) or a golden id list — checked with a
        // REAL FindLinksFtt at the hop's doc.
        if let Some(v) = e.get("links_found") {
            let at = e
                .get("at")
                .and_then(Value::as_str)
                .and_then(|s| cx.shadow.resolve_doc(s))
                .or_else(|| from_doc.clone())
                .or_else(|| here.clone());
            if let Some(at_doc) = at {
                let found = find_links_at(cx, &at_doc, reverse);
                if let Some(n) = v.as_u64() {
                    if found.len() as u64 == n {
                        tally.agree();
                    } else {
                        tally.differ(Disagreement {
                            expected: format!("{at_doc}: {n} links"),
                            actual: format!("{at_doc}: {}", found.len()),
                        });
                    }
                } else if let Some(arr) = v.as_array() {
                    let want: Vec<String> =
                        arr.iter().filter_map(|x| x.as_str().map(str::to_string)).collect();
                    let comparison =
                        compare_addr_sets(&want, &found, cx.alpha, &mut out.adaptations);
                    tally.judge(comparison, &format!("{at_doc}: "));
                }
            }
            // A links_found entry may still carry landing content below.
            if !e.contains_key("content") && !e.contains_key("text") {
                continue;
            }
        }

        // The link this hop follows: recorded arrows first, then the
        // shadow's links (links FROM the hop's doc, narrowed by its to-doc).
        let link_golden: Option<String> = e
            .get("link")
            .and_then(Value::as_str)
            .filter(|s| is_link_address(s))
            .map(str::to_string)
            .or_else(|| {
                let (f, t) = (from_tok.as_deref()?, to_tok.as_deref()?);
                cx.shadow.arrow_links.get(&(f.to_string(), t.to_string())).cloned()
            })
            .or_else(|| {
                // reverse_traversal: at X, the link ARRIVING from
                // found_link_from — the arrow (from, X).
                let at = e.get("at").and_then(Value::as_str)?.trim();
                let from = e.get("found_link_from").and_then(Value::as_str)?.trim();
                cx.shadow.arrow_links.get(&(from.to_string(), at.to_string())).cloned()
            })
            .or_else(|| {
                let d = from_doc.as_deref()?;
                let hits = cx.shadow.links_from(d, to_doc.as_deref());
                hits.first().map(|l| l.golden.clone())
            });

        let expectation: Option<(usize, &Value)> = if let Some(t) = e.get("target_text") {
            Some((2, t))
        } else if let Some(t) = e.get("source_text") {
            Some((1, t))
        } else if let Some(t) = e.get("text") {
            Some((default_slot, t))
        } else if let Some(t) = e.get("content") {
            Some((default_slot, t))
        } else if let Some(t) = e.get("result") {
            Some((default_slot, t))
        } else {
            None
        };

        let link_golden = link_golden.or_else(|| {
            // A landing-content entry without an outgoing link: the link
            // ARRIVING at this entry's doc (preferring the one leaving the
            // previous position), else the last followed link.
            expectation?;
            let land = from_doc.clone().or_else(|| here.clone())?;
            let inbound = cx.shadow.links_to(&land);
            inbound
                .iter()
                .find(|l| {
                    last_followed.as_deref() == Some(l.golden.as_str())
                        || l.from.iter().any(|(d, _, _)| Some(d) == here.as_ref())
                })
                .or_else(|| inbound.first())
                .map(|l| l.golden.clone())
                .or_else(|| last_followed.clone())
        });

        let Some((slot, expected)) = expectation else { continue };
        let Some(link_golden) = link_golden else {
            let actual = "no link resolvable for this hop".to_string();
            tally.differ(Disagreement { expected: "hop link".into(), actual });
            continue;
        };
        let Some(link) = cx.alpha.translate(&link_golden) else {
            let actual = "never-bound link".to_string();
            tally.differ(Disagreement { expected: link_golden.clone(), actual });
            continue;
        };
        // Each hop is judged as a follow of its own and folded in as one
        // part of the traversal.
        let mut hop = OpOutcome::new(out.index, &out.op_name);
        follow_compare(cx, &mut hop, &Adjustments::default(), &link, slot, expected);
        tally.absorb(out, hop, &format!("{link_golden}: "));
        // Land: the followed link's TO doc is where the traversal stands.
        last_followed = Some(link_golden.clone());
        if slot == 2 {
            if let Some(l) = cx.shadow.links.iter().find(|l| l.golden == link_golden) {
                if let Some((d, _, _)) = l.to.first() {
                    here = Some(d.clone());
                }
            }
        }
    }
    // The entry list is the traversal's recorded answer: entries that
    // carried nothing comparable leave it unread.
    tally.settle_read(out, "traversal", op, TRAVERSE_READS);
}

/// Links whose TO (reverse) / FROM (forward) endset touches `doc`'s extent
/// — the traversal macros' real per-hop FindLinksFtt query.
fn find_links_at(cx: &mut Cx, doc: &str, reverse: bool) -> Vec<skep_address::Address> {
    let n = cx.shadow.text_len(doc);
    let (e, _, _) = cx.image_endset(doc, &[VPoint::content(1).region(n.max(1))]);
    let spec = if e.is_empty() { SlotSpec::Empty } else { SlotSpec::Spans(e) };
    let q = if reverse {
        FourSet { home: SlotSpec::Any, from: SlotSpec::Any, to: spec, ty: SlotSpec::Any }
    } else {
        FourSet { home: SlotSpec::Any, from: spec, to: SlotSpec::Any, ty: SlotSpec::Any }
    };
    match cx.rig.exec(Op::FindLinksFtt { q }) {
        // The rig's setup grant (ruling 21) is FROM the account's subtree
        // span, so every forward hop over a rig account's content surfaces
        // it: harness infrastructure, dropped here so neither the per-hop
        // count nor the address set nor the landing follow ever sees it.
        Response::Addrs { addrs, .. } => {
            addrs.into_iter().filter(|a| !cx.rig.is_infra_addr(a)).collect()
        }
        _ => Vec::new(),
    }
}
