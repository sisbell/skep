//! Content writes: insert (with its distributed, looped and interior-typing
//! forms), delete, vcopy, and the rearranges (pivot, swap). Each executes on
//! skep and mirrors its effect into the shadow whatever skep answered — the
//! shadow follows the recorded reality, never skep's verdict; the inserts,
//! deletes and vcopys then compare the post-write state the golden
//! recorded, where it recorded one.

use serde_json::Value;

use skep_address::Nat;
use skep_arrangement::VSpec;
use skep_content::Val;
use skep_febe::{Deposit, Op};

use super::{
    create_one, inexpressible, probe_state, rejection_code, run_plan, settle_ack, vpos, Cx, Grants,
    Probe,
};
use crate::compare::compare_content;
use crate::evidence::{
    delete_is_noop, insert_aim_from_probe, insert_pad_width, insert_pos_from_post_state,
    next_content_probe, resolve_delete_span,
};
use crate::fields::{
    self, cuts_of, distributed_insert_texts, distribution_targets, doc_from_label, expect_strings,
    expected_failure, field, insert_text, is_position_marker, label_of, locate, resolve_position,
    span_dict, str_field, vspec_dict,
};
use crate::outcome::{OpOutcome, Status};
use crate::tum::{parse_vpos, vspan};

pub(super) fn h_insert(
    cx: &mut Cx,
    index: usize,
    op: &Value,
    out: &mut OpOutcome,
    grants: &Grants,
) {
    // insert_all + texts: one text per created doc, creation order (policy
    // `insert-all:distributed`; mirrors the grounding pre-pass exactly).
    if let Some(texts) = distributed_insert_texts(op) {
        out.adaptations.push("insert-all:distributed".into());
        let docs = distribution_targets(cx.shadow, texts.len());
        for (docid, t) in docs.iter().zip(&texts) {
            let Some(d) = cx.skep_doc(docid) else {
                out.status = Status::Disagreed;
                out.comparator = Some("alpha".into());
                out.note = Some(format!("insert_all target {docid} unresolvable"));
                return;
            };
            let at = cx.shadow.text_len(docid) + 1;
            let values: Vec<Val> = t.bytes().map(|b| Val::new(vec![b])).collect();
            let r = cx.rig.exec(Op::Insert { doc: d, at: vpos(1, at), values, deposit: Deposit::Undeclared });
            cx.shadow.insert(docid, at, t.as_bytes());
            if let Some(code) = rejection_code(&r) {
                out.status = Status::Disagreed;
                out.comparator = Some("rejection".into());
                out.expected = Some(format!("insert_all into {docid} succeeds"));
                out.actual = Some(format!("Rejected({code})"));
                return;
            }
        }
        out.status = Status::NotCompared;
        return;
    }
    let Some(mut doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        inexpressible(out, "insert with no document in scope".into());
        return;
    };
    let Some(mut text) = insert_text(op) else {
        inexpressible(out, "insert without text".into());
        return;
    };
    if str_field(op, &["text"]).is_none() && label_of(op).starts_with("insert_") {
        out.adaptations.push("args-from-label".into());
    }
    // Doc-less insert re-aim from the next recorded vspanset probe (policy
    // `insert-aim-from-recorded-vspanset`; mirrors the grounding pre-pass).
    if str_field(op, &["doc", "docid"]).is_none() && doc_from_label(label_of(op)).is_none() {
        if let Some(d2) = insert_aim_from_probe(cx.ops, index, cx.shadow, &doc, &text) {
            out.adaptations.push("insert-aim-from-recorded-vspanset".into());
            cx.shadow.set_current(&d2);
            doc = d2;
        }
    }
    let (sub, ord) = match str_field(op, &["address", "at", "position", "vaddr"]) {
        Some(p) => match resolve_position(cx.shadow, &doc, p) {
            Some((s, o, how)) => {
                if how != "explicit-position" {
                    out.adaptations.push(how.into());
                }
                (s, o)
            }
            None => {
                inexpressible(out, format!("insert position `{p}` is not groundable"));
                return;
            }
        },
        None => {
            // insert_<n>_<TEXT> labels carry the sequence number, not a
            // position; those and bare inserts append — unless the op's own
            // recorded post-state shows the text embedded mid-document,
            // which pins the position exactly (policy
            // `insert-position-from-post-state`; interleaved_insert_delete's
            // insert_2 "BBB" turns "AA" into "ABBBA").
            match insert_pos_from_post_state(op, cx.shadow, &doc, &text) {
                Some(o) => {
                    out.adaptations.push("insert-position-from-post-state".into());
                    (1, o)
                }
                None => {
                    out.adaptations.push("position-end".into());
                    (1, cx.shadow.text_len(&doc) + 1)
                }
            }
        }
    };
    // Recorded-vspanset width authority (policy `insert-padded-to-recorded-
    // vspanset`; mirrors the grounding pre-pass byte-for-byte).
    if sub == 1
        && (str_field(op, &["address", "at", "position", "vaddr"]).is_none()
            || cx.shadow.text_len(&doc) == 0)
    {
        let new_len = cx.shadow.text_len(&doc) + text.len() as u64;
        if let Some(pad) = insert_pad_width(cx.ops, index, cx.shadow, &doc, new_len) {
            out.adaptations.push(format!("insert-padded-to-recorded-vspanset:+{pad}"));
            text.push_str(&" ".repeat(pad as usize));
        }
    }
    let Some(d) = cx.skep_doc(&doc) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("insert into unresolvable doc {doc}"));
        return;
    };
    let xf = expected_failure(op);
    let values: Vec<Val> = text.bytes().map(|b| Val::new(vec![b])).collect();
    let r = cx.rig.exec(Op::Insert { doc: d, at: vpos(sub, ord), values, deposit: Deposit::Undeclared });
    // Shadow mirrors the RECORDED reality regardless of skep's verdict, so
    // later translations stay grounded in what udanax saw.
    if sub == 1 {
        cx.shadow.insert(&doc, ord, text.as_bytes());
    }
    if !settle_ack(out, xf, rejection_code(&r)) {
        return;
    }
    probe_state(cx, op, out, grants, &doc, Probe::PostWrite);
}

pub(super) fn h_insert_loop(cx: &mut Cx, op: &Value, out: &mut OpOutcome, grants: &Grants) {
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        inexpressible(out, "insert_loop with no document in scope".into());
        return;
    };
    let Some(count) = field(op, &["count"]).and_then(Value::as_u64) else {
        inexpressible(out, "insert_loop without a count".into());
        return;
    };
    // The recorded sample (edgecases/many_small_inserts) shows A–Z cycling,
    // one insert per character, appended.
    out.adaptations.push("insert-loop:a-z-cycle".into());
    let Some(d) = cx.skep_doc(&doc) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("insert_loop into unresolvable doc {doc}"));
        return;
    };
    for k in 0..count {
        let b = b'A' + (k % 26) as u8;
        let at = cx.shadow.text_len(&doc) + 1;
        let r = cx.rig.exec(Op::Insert {
            doc: d.clone(),
            at: vpos(1, at),
            values: vec![Val::new(vec![b])],
            deposit: Deposit::Undeclared,
        });
        cx.shadow.insert(&doc, at, &[b]);
        if let Some(code) = rejection_code(&r) {
            out.status = Status::Disagreed;
            out.comparator = Some("rejection".into());
            out.expected = Some(format!("insert {} of {count} succeeds", k + 1));
            out.actual = Some(format!("Rejected({code})"));
            return;
        }
    }
    probe_state(cx, op, out, grants, &doc, Probe::PostWrite);
}

pub(super) fn h_interior_typing(cx: &mut Cx, op: &Value, out: &mut OpOutcome, grants: &Grants) {
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        inexpressible(out, "interior_typing with no document in scope".into());
        return;
    };
    let Some(results) = field(op, &["results"]).and_then(Value::as_array) else {
        inexpressible(out, "interior_typing without a results list".into());
        return;
    };
    out.adaptations.push("expansion-plan:interior-typing".into());
    let Some(d) = cx.skep_doc(&doc) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("interior_typing into unresolvable doc {doc}"));
        return;
    };
    let mut fails: Vec<(String, String)> = Vec::new();
    for r in results {
        let (Some(ch), Some(pos)) =
            (r.get("char").and_then(Value::as_str), r.get("position").and_then(Value::as_str))
        else {
            continue;
        };
        let Some((1, ord, _)) = resolve_position(cx.shadow, &doc, pos) else { continue };
        let resp = cx.rig.exec(Op::Insert {
            doc: d.clone(),
            at: vpos(1, ord),
            values: ch.bytes().map(|b| Val::new(vec![b])).collect(),
            deposit: Deposit::Undeclared,
        });
        cx.shadow.insert(&doc, ord, ch.as_bytes());
        if let Some(code) = rejection_code(&resp) {
            fails.push((format!("insert '{ch}' at {pos}"), format!("Rejected({code})")));
            continue;
        }
        // Per-step probes: vspanset + contents recorded per character.
        let mut step = OpOutcome::new(out.index, &out.label);
        probe_state(cx, r, &mut step, grants, &doc, Probe::Step);
        if step.status == Status::Disagreed {
            fails.push((
                format!("step '{ch}': {}", step.expected.unwrap_or_default()),
                step.actual.unwrap_or_default(),
            ));
        }
    }
    if fails.is_empty() {
        out.status = Status::Agreed;
        out.comparator = Some("state-probe".into());
    } else {
        out.status = Status::Disagreed;
        out.comparator = Some("state-probe".into());
        out.expected = Some(fails.iter().map(|f| f.0.clone()).collect::<Vec<_>>().join(" | "));
        out.actual = Some(fails.iter().map(|f| f.1.clone()).collect::<Vec<_>>().join(" | "));
    }
}

pub(super) fn h_delete(
    cx: &mut Cx,
    index: usize,
    op: &Value,
    out: &mut OpOutcome,
    grants: &Grants,
    all: bool,
) {
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        inexpressible(out, "delete with no document in scope".into());
        return;
    };
    // Policy `delete-noop-from-post-state`: the recorded post-delete content
    // equals the pre-delete content — udanax removed nothing (client-crash
    // family), so the harness executes nothing and later probes compare
    // against the intact document honestly.
    if delete_is_noop(cx.shadow, cx.ops, index, &doc) {
        out.adaptations.push("delete-noop-from-post-state".into());
        out.status = Status::NotCompared;
        let mut note = String::from(
            "recorded post-delete content equals pre-delete content; udanax removed nothing \
             from the content subspace",
        );
        // Adjudication analysis (round-5 item 8, delete_all_with_links):
        // when the SAME recording later reports the doc's links unfindable
        // (find_links count 0 / empty) while its content probe still reads
        // the full text, udanax's whole-document remove split the
        // subspaces — content intact, link-subspace occupancy removed.
        // Skep cannot reproduce that split without violating the ruled
        // subspace-confinement invariant (udanax-no-subspace-confinement,
        // adjudication/decisions.md ruling 2), so the harness keeps the
        // content no-op and leaves the later link-findability divergence
        // raw for adjudication.
        let links_vanish = cx.shadow.link_count(&doc) > 0
            && cx.ops[index + 1..].iter().any(|later| {
                let l = label_of(later).to_ascii_lowercase();
                if !(l.starts_with("find_links") || l.starts_with("links")) {
                    return false;
                }
                ["result", "links", "expected", "before_delete", "after_delete", "before",
                 "after"]
                .iter()
                .any(|k| {
                    let Some(v) = later.get(*k) else { return false };
                    v.as_array().is_some_and(|a| a.is_empty())
                        || v.get("count").and_then(Value::as_u64) == Some(0)
                })
            });
        if links_vanish {
            note.push_str(
                "; ANALYSIS: this recording's later find_links expects the home link \
                 unfindable (count 0) while the content probe still reads the full text — \
                 udanax's remove deleted link-subspace occupancy only; skep cannot reproduce \
                 the split without violating the ruled subspace-confinement invariant \
                 (decisions.md ruling 2), so the link-findability divergence downstream is \
                 left raw for adjudication",
            );
        }
        out.note = Some(note);
        return;
    }
    let xf = expected_failure(op);
    let (sub, ord, width) = if all {
        let n = cx.shadow.text_len(&doc);
        if n == 0 {
            out.adaptations.push("delete_all:empty-noop".into());
            out.status = Status::NotCompared;
            out.note = Some("document already empty; nothing to delete".into());
            return;
        }
        (1, 1, n)
    } else if let Some((ord, w, how)) = resolve_delete_span(cx.shadow, cx.ops, index, &doc, op) {
        if how != "explicit" {
            out.adaptations.push(how.into());
        }
        (1, ord, w)
    } else if let Some(start) = str_field(op, &["start", "address", "at"]) {
        // A link-subspace delete (delete_middle_link_check_gap_closure).
        match parse_vpos(start) {
            Some((sub, ord)) if sub != 1 => {
                let w = str_field(op, &["width"]).and_then(crate::tum::parse_width).unwrap_or(1);
                (sub, ord, w)
            }
            _ => {
                inexpressible(out, format!("delete start `{start}` is not groundable"));
                return;
            }
        }
    } else {
        if xf.is_some() {
            out.status = Status::Agreed;
            out.comparator = Some("expected-failure".into());
            out.note = Some("delete region not groundable; golden also recorded failure".into());
            return;
        }
        inexpressible(out, "delete without a groundable region".into());
        return;
    };
    let Some(d) = cx.skep_doc(&doc) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("delete in unresolvable doc {doc}"));
        return;
    };
    // I-coverage capture (ruling 10): image the doomed content region while
    // the arrangement still speaks for it, so later searches can reach it
    // through I-history.
    if sub == 1 {
        let bytes = cx.shadow.slice(&doc, ord, width);
        cx.rig.capture_deletion(&doc, &d, ord, bytes);
    }
    let r = cx.rig.exec(Op::Delete { doc: d, p: vpos(sub, ord), width: Nat::from(width) });
    if sub == 1 {
        cx.shadow.delete(&doc, ord, width);
    }
    if !settle_ack(out, xf, rejection_code(&r)) {
        return;
    }
    probe_state(cx, op, out, grants, &doc, Probe::PostWrite);
}

pub(super) fn h_vcopy(cx: &mut Cx, index: usize, op: &Value, out: &mut OpOutcome, grants: &Grants) {
    // Pre-pass expansion plans cover the macro forms (vcopy_multiple /
    // vcopy_all / vcopy_from_both / vcopy_to_multiple / create_and_
    // transclude): fillers as inserts, shared regions as real copies.
    if cx.plans.contains_key(&index) {
        // vcopy_to_multiple / create_and_transclude bind their target ids.
        if let Some(targets) = field(op, &["targets"]).and_then(Value::as_array) {
            for t in targets {
                let id = t.as_str().or_else(|| t.get("docid").and_then(Value::as_str));
                if let Some(id) = id {
                    create_one(cx, out, id, None);
                }
            }
        }
        run_plan(cx, index, out);
        if out.status == Status::Disagreed {
            return;
        }
        // Per-target contents expectations (vcopy_to_multiple) compare here.
        if let Some(targets) = field(op, &["targets"]).and_then(Value::as_array) {
            let mut fails: Vec<(String, String)> = Vec::new();
            for t in targets {
                let (Some(id), Some(exp)) = (
                    t.get("docid").and_then(Value::as_str),
                    t.get("contents").and_then(expect_strings),
                ) else {
                    continue;
                };
                match cx.read_content(id) {
                    Ok(items) => {
                        if let Err((e, a)) = compare_content(&exp, &items, cx.alpha) {
                            fails.push((format!("{id}: {e}"), format!("{id}: {a}")));
                        }
                    }
                    Err(code) => fails.push((format!("{id}: contents"), format!("{id}: {code}"))),
                }
            }
            if !fails.is_empty() {
                out.status = Status::Disagreed;
                out.comparator = Some("content".into());
                out.expected =
                    Some(fails.iter().map(|f| f.0.clone()).collect::<Vec<_>>().join(" | "));
                out.actual =
                    Some(fails.iter().map(|f| f.1.clone()).collect::<Vec<_>>().join(" | "));
            } else if targets.iter().any(|t| t.get("contents").is_some()) {
                out.status = Status::Agreed;
                out.comparator = Some("content".into());
            }
        }
        return;
    }

    // Source spec(s): explicit vspec dicts, span dicts, located texts. The
    // corpus extension records a SINGLE vspec dict (`source: {docid, span}`,
    // fanout/depth recordings) — normalized to a one-item list here.
    let mut specs: Vec<VSpec> = Vec::new();
    let mut copied: Vec<u8> = Vec::new();
    let mut src_doc: Option<String> = None;
    let spec_items: Option<Vec<&Value>> =
        match field(op, &["specs", "specset", "source", "sources"]) {
            Some(Value::Array(a)) => Some(a.iter().collect()),
            Some(v @ Value::Object(_)) if vspec_dict(v).is_some() => Some(vec![v]),
            _ => None,
        };
    if let Some(arr) = spec_items {
        for v in arr {
            if let Some((docid, spans)) = vspec_dict(v) {
                let Some(sd) = cx.alpha.translate(&docid) else {
                    out.status = Status::Disagreed;
                    out.comparator = Some("alpha".into());
                    out.note = Some(format!("vcopy source doc {docid} unresolvable"));
                    return;
                };
                src_doc.get_or_insert(docid.clone());
                for (sub, ord, w) in spans {
                    if let Some(span) = vspan(sub, ord, w) {
                        if sub == 1 {
                            copied.extend(cx.shadow.slice(&docid, ord, w));
                        }
                        specs.push(VSpec { source: sd.clone(), span });
                    }
                }
            } else if let Some(t) = v.as_str() {
                match locate(cx.shadow, None, t) {
                    Some(l) => {
                        if !vcopy_push_located(cx, out, l, &mut specs, &mut copied, &mut src_doc) {
                            return;
                        }
                    }
                    None => {
                        inexpressible(out, format!("vcopy span {t:?} not groundable"));
                        return;
                    }
                }
            } else {
                inexpressible(out, "vcopy spec list holds an unrecognized entry".into());
                return;
            }
        }
    } else if let Some(arr) = field(op, &["spans"]).and_then(Value::as_array) {
        for v in arr {
            if let Some((sub, ord, w)) = span_dict(v) {
                let hint = str_field(op, &["from", "source_doc"])
                    .and_then(|s| cx.shadow.resolve_doc(s))
                    .or_else(|| cx.shadow.scoped());
                let Some(docid) = hint else { continue };
                let Some(sd) = cx.alpha.translate(&docid) else { continue };
                if let Some(span) = vspan(sub, ord, w) {
                    if sub == 1 {
                        copied.extend(cx.shadow.slice(&docid, ord, w));
                    }
                    src_doc.get_or_insert(docid.clone());
                    specs.push(VSpec { source: sd, span });
                }
            } else if let Some(t) = v.as_str() {
                match locate(cx.shadow, None, t) {
                    Some(l) => {
                        if !vcopy_push_located(cx, out, l, &mut specs, &mut copied, &mut src_doc) {
                            return;
                        }
                    }
                    None => {
                        inexpressible(out, format!("vcopy span {t:?} not groundable"));
                        return;
                    }
                }
            }
        }
    } else if let Some((1, ord, w)) = field(op, &["source_span", "span"]).and_then(span_dict) {
        let src = str_field(op, &["from", "source_doc"])
            .and_then(|s| cx.shadow.resolve_doc(s))
            .or_else(|| {
                let dest_hint = str_field(op, &["to", "dest", "target", "target_doc"])
                    .and_then(|s| cx.shadow.resolve_doc(s))
                    .unwrap_or_default();
                cx.shadow.content_docs_except(&dest_hint).first().cloned()
            });
        let Some(src) = src else {
            inexpressible(out, "vcopy source_span with no source document".into());
            return;
        };
        let Some(sd) = cx.alpha.translate(&src) else {
            out.status = Status::Disagreed;
            out.comparator = Some("alpha".into());
            out.note = Some(format!("vcopy source doc {src} unresolvable"));
            return;
        };
        if let Some(span) = vspan(1, ord, w) {
            copied.extend(cx.shadow.slice(&src, ord, w));
            src_doc = Some(src);
            specs.push(VSpec { source: sd, span });
        }
    } else if let Some(t) = str_field(op, &["text", "span"]) {
        let from = str_field(op, &["from", "source_doc"]).and_then(|s| cx.shadow.resolve_doc(s));
        match locate(cx.shadow, from.as_deref(), t) {
            Some(l) => {
                if !vcopy_push_located(cx, out, l, &mut specs, &mut copied, &mut src_doc) {
                    return;
                }
            }
            None => {
                inexpressible(out, format!("vcopy text {t:?} not groundable"));
                return;
            }
        }
    } else if let Some(s) = str_field(op, &["from", "source"]) {
        if let Some(from) = cx.shadow.resolve_doc(s) {
            // `from: <doc>` with no span: the whole current extent.
            let n = cx.shadow.text_len(&from);
            if let (Some(sd), Some(span)) = (cx.alpha.translate(&from), vspan(1, 1, n)) {
                out.adaptations.push("whole-extent".into());
                copied.extend(cx.shadow.slice(&from, 1, n));
                src_doc = Some(from);
                specs.push(VSpec { source: sd, span });
            } else {
                inexpressible(out, "vcopy from an empty document".into());
                return;
            }
        } else if let Some(l) = locate(cx.shadow, None, s) {
            // A described region, not a doc ("positions 1-4 (Orig)" —
            // edgecases/vcopy_to_same_document). A grounding that lands
            // OUTSIDE its doc's live extent grounded against the wrong doc —
            // typically the register pointing at the just-created empty
            // destination — and the script's copy can only have read a doc
            // that holds the span: re-ground against the content-holding
            // docs excluding the dest reference (policy
            // `vcopy-source-reaimed`; internal/ispan_partial_overlap's
            // `from: "positions 3-7 (CDEFG)"` with `to: "dest"`, confirmed
            // by the recorded post-state "CDEFG in both"). No valid re-aim
            // keeps the original grounding and its loud divergence.
            let l = if l.ord + l.width > cx.shadow.text_len(&l.doc) + 1 {
                let dest_ref = str_field(op, &["to", "dest", "target", "target_doc"])
                    .filter(|t| !is_position_marker(t))
                    .and_then(|t| cx.shadow.resolve_doc(t))
                    .unwrap_or_default();
                match cx.shadow.content_docs_except(&dest_ref).iter().find_map(|d| {
                    locate(cx.shadow, Some(d.as_str()), s)
                        .filter(|c| c.ord + c.width <= cx.shadow.text_len(&c.doc) + 1)
                }) {
                    Some(re) => {
                        out.adaptations.push("vcopy-source-reaimed".into());
                        re
                    }
                    None => l,
                }
            } else {
                l
            };
            if !vcopy_push_located(cx, out, l, &mut specs, &mut copied, &mut src_doc) {
                return;
            }
        } else {
            inexpressible(out, format!("vcopy from {s:?}: neither a doc nor a groundable region"));
            return;
        }
    } else {
        inexpressible(out, "vcopy without specs, span or text".into());
        return;
    }
    if specs.is_empty() {
        inexpressible(out, "vcopy resolved to no source spans".into());
        return;
    }

    // Destination doc + position. `to` may be a doc reference or the
    // position markers "end"/"start" (destination = the source doc then).
    // A dest-less vcopy aims at the doc whose later probe shows the copied
    // bytes embedded (endsets/endsets_transcluded_source: the script's
    // second doc, which the register never pointed at), preferring a doc
    // other than the source; the register serves only evidence-less ops.
    let to_raw = str_field(op, &["to", "dest", "target", "target_doc"]);
    let dest: Option<String> = match to_raw {
        // "end"/"start"/"end of doc" are position markers over the source
        // doc itself (vcopy_to_same_document's self-transclusion).
        Some(s) if is_position_marker(s) => src_doc.clone(),
        Some(s) => cx.shadow.resolve_doc(s),
        None => str_field(op, &["doc", "docid"])
            .and_then(|s| cx.shadow.resolve_doc(s))
            .or_else(|| {
                let copied_s = String::from_utf8_lossy(&copied).into_owned();
                let evidenced: Vec<String> = cx
                    .shadow
                    .all_docs()
                    .into_iter()
                    .filter(|d| {
                        next_content_probe(cx.ops, index, d, cx.shadow)
                            .is_some_and(|p| p.contains(&copied_s))
                    })
                    .collect();
                let pick = evidenced
                    .iter()
                    .find(|d| Some(d.as_str()) != src_doc.as_deref())
                    .or_else(|| evidenced.first())
                    .cloned();
                if pick.is_some() {
                    out.adaptations.push("vcopy-dest-from-evidence".into());
                }
                pick
            })
            .or_else(|| cx.doc_arg(op, out, &["doc", "docid"])),
    };
    let Some(dest) = dest else {
        inexpressible(out, "vcopy without a resolvable destination".into());
        return;
    };
    let ord = match str_field(op, &["address", "at", "position"]) {
        Some(p) => match resolve_position(cx.shadow, &dest, p) {
            Some((1, o, _)) => o,
            _ => {
                inexpressible(out, format!("vcopy position `{p}` is not groundable"));
                return;
            }
        },
        None => {
            if to_raw.is_some_and(|s| s.trim().to_ascii_lowercase().starts_with("start")) {
                1
            } else {
                out.adaptations.push("position-end".into());
                cx.shadow.text_len(&dest) + 1
            }
        }
    };
    let Some(d) = cx.skep_doc(&dest) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("vcopy destination {dest} unresolvable"));
        return;
    };
    let xf = expected_failure(op);
    let r = cx.rig.exec(Op::Copy { doc: d, at: vpos(1, ord), specs });
    cx.shadow.insert(&dest, ord, &copied);
    if !settle_ack(out, xf, rejection_code(&r)) {
        return;
    }
    probe_state(cx, op, out, grants, &dest, Probe::PostWrite);
}

/// Push one located vcopy source region: resolve its doc, record the copied
/// bytes and the V-spec. `false` = unresolvable doc (outcome written).
fn vcopy_push_located(
    cx: &mut Cx,
    out: &mut OpOutcome,
    l: fields::Located,
    specs: &mut Vec<VSpec>,
    copied: &mut Vec<u8>,
    src_doc: &mut Option<String>,
) -> bool {
    let Some(sd) = cx.alpha.translate(&l.doc) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("vcopy source doc {} unresolvable", l.doc));
        return false;
    };
    out.adaptations.push(l.how.into());
    if let Some(span) = vspan(1, l.ord, l.width) {
        copied.extend(cx.shadow.slice(&l.doc, l.ord, l.width));
        src_doc.get_or_insert(l.doc.clone());
        specs.push(VSpec { source: sd, span });
    }
    true
}

pub(super) fn h_pivot_swap(cx: &mut Cx, op: &Value, out: &mut OpOutcome, pivot: bool) {
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        inexpressible(out, "rearrange with no document in scope".into());
        return;
    };
    let mut cuts = cuts_of(op);
    if cuts.is_empty() && !pivot {
        // Two texts to exchange, located in the shadow.
        if let Some(regions) = field(op, &["regions"]).and_then(Value::as_array) {
            let texts: Vec<&str> = regions.iter().filter_map(Value::as_str).collect();
            if texts.len() == 2 {
                let a = cx.shadow.find_text(Some(&doc), texts[0]);
                let b = cx.shadow.find_text(Some(&doc), texts[1]);
                if let (Some((_, s1)), Some((_, s2))) = (a, b) {
                    out.adaptations.push("text-located:regions".into());
                    let (w1, w2) = (texts[0].len() as u64, texts[1].len() as u64);
                    let (s1, e1, s2, e2) = if s1 <= s2 {
                        (s1, s1 + w1, s2, s2 + w2)
                    } else {
                        (s2, s2 + w2, s1, s1 + w1)
                    };
                    cuts = vec![s1, e1, s2, e2];
                }
            }
        }
    }
    let want = if pivot { 3 } else { 4 };
    if cuts.len() != want {
        inexpressible(out, format!("rearrange needs {want} cuts, could derive {}", cuts.len()));
        return;
    }
    let Some(d) = cx.skep_doc(&doc) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("rearrange in unresolvable doc {doc}"));
        return;
    };
    let xf = expected_failure(op);
    let r = cx
        .rig
        .exec(Op::Rearrange { doc: d, cuts: cuts.iter().map(|&c| vpos(1, c)).collect() });
    if pivot {
        cx.shadow.pivot(&doc, cuts[0], cuts[1], cuts[2]);
    } else {
        cx.shadow.swap(&doc, cuts[0], cuts[1], cuts[2], cuts[3]);
    }
    if !settle_ack(out, xf, rejection_code(&r)) {
        return;
    }
    out.status = Status::NotCompared;
}
