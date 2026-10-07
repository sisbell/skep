//! Content writes: insert (with its distributed, looped and interior-typing
//! forms), delete, vcopy, and the rearranges (pivot, swap). Each is carried
//! out through the `Cx` world-change methods, so the shadow follows the
//! recorded reality, never skep's answer; the inserts, deletes and vcopys
//! then compare the post-write state the golden recorded, where it recorded
//! one. A write that issues several requests issues every one of them
//! whatever skep answers an earlier one; the first failure is the op's.
//! Insert answers its success with `AckAddr`; delete, copy and rearrange
//! with `Ack` — skep-febe's dispatch — and each write tests for exactly its
//! own.

use serde_json::Value;

use skep_febe::Response;

use super::{
    create_one, inexpressible, plan_failed, probe_state, refusal, run_plan, settle_accepted,
    settle_unaccepted, Cx, Probe, Tally,
};
use crate::allowlist::Adjustments;
use crate::compare::compare_content;
use crate::evidence::{
    delete_is_noop, next_content_probe, resolve_delete_span, resolve_insert, took_effect,
};
use crate::fields::{
    cuts_of, distributed_insert_texts, distribution_targets, expect_strings, expected_failure,
    field, is_position_marker, resolve_position, str_field, vcopy_sources, verb_of, Verb,
};
use crate::outcome::{OpOutcome, Status};
use crate::tum::parse_vpos;

pub(super) fn h_insert(
    cx: &mut Cx,
    index: usize,
    op: &Value,
    out: &mut OpOutcome,
    adjustments: &Adjustments,
) {
    let recorded = took_effect(op);
    // insert_all + texts: one text per created doc, creation order (policy
    // `insert-all:distributed`; the grounding pre-pass distributes through
    // the same `fields::distributed_insert_texts` and `distribution_targets`).
    if let Some(texts) = distributed_insert_texts(op) {
        out.adaptations.push("insert-all:distributed".into());
        let docs = distribution_targets(cx.shadow, texts.len());
        let mut failed = false;
        for (docid, t) in docs.iter().zip(&texts) {
            let at = cx.shadow.text_len(docid) + 1;
            let r = cx.insert(docid, 1, at, t.as_bytes(), recorded);
            match r {
                _ if failed => {}
                Err(_) => {
                    failed = true;
                    out.never_bound(format!("insert_all target {docid} never bound"));
                }
                Ok(Response::AckAddr { .. }) => {}
                Ok(r) => {
                    failed = true;
                    let expected = format!("insert_all into {docid} succeeds");
                    out.disagree("rejection", expected, refusal(&r));
                }
            }
        }
        if !failed {
            out.status = Status::NotCompared;
        }
        return;
    }
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        inexpressible(out, "insert with no document in scope".into());
        return;
    };
    // Where the insert lands — its text, any re-aim, its position, the
    // recorded-vspanset pad — is the one reading the grounding pre-pass
    // applies too (`evidence::resolve_insert`), each policy it uses tagged.
    let landing = match resolve_insert(cx.ops, index, cx.shadow, &doc, op, &mut out.adaptations) {
        Ok(landing) => landing,
        Err(reason) => {
            inexpressible(out, reason);
            return;
        }
    };
    if landing.doc != doc {
        cx.shadow.set_current(&landing.doc);
    }
    let xf = expected_failure(op);
    let Ok(r) = cx.insert(&landing.doc, landing.sub, landing.ord, &landing.bytes, recorded) else {
        out.never_bound(format!("insert into never-bound doc {}", landing.doc));
        return;
    };
    match r {
        Response::AckAddr { .. } => {
            if settle_accepted(out, xf) {
                probe_state(cx, op, out, adjustments, &landing.doc, Probe::PostWrite);
            }
        }
        r => settle_unaccepted(out, xf, &r),
    }
}

pub(super) fn h_insert_loop(
    cx: &mut Cx,
    op: &Value,
    out: &mut OpOutcome,
    adjustments: &Adjustments,
) {
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
    let recorded = took_effect(op);
    let mut failed = false;
    for k in 0..count {
        let b = b'A' + (k % 26) as u8;
        let at = cx.shadow.text_len(&doc) + 1;
        match cx.insert(&doc, 1, at, &[b], recorded) {
            Err(_) => {
                // No α-image: nothing further reaches skep or the shadow.
                out.never_bound(format!("insert_loop into never-bound doc {doc}"));
                return;
            }
            Ok(Response::AckAddr { .. }) => {}
            Ok(r) => {
                if !failed {
                    failed = true;
                    let expected = format!("insert {} of {count} succeeds", k + 1);
                    out.disagree("rejection", expected, refusal(&r));
                }
            }
        }
    }
    if failed {
        return;
    }
    probe_state(cx, op, out, adjustments, &doc, Probe::PostWrite);
}

pub(super) fn h_interior_typing(
    cx: &mut Cx,
    op: &Value,
    out: &mut OpOutcome,
    adjustments: &Adjustments,
) {
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        inexpressible(out, "interior_typing with no document in scope".into());
        return;
    };
    let Some(results) = field(op, &["results"]).and_then(Value::as_array) else {
        inexpressible(out, "interior_typing without a results list".into());
        return;
    };
    out.adaptations.push("expansion-plan:interior-typing".into());
    let recorded = took_effect(op);
    let mut tally = Tally::default();
    for r in results {
        let (Some(ch), Some(pos)) =
            (r.get("char").and_then(Value::as_str), r.get("position").and_then(Value::as_str))
        else {
            continue;
        };
        // A step whose position does not ground loses both its insert and
        // its check — the op cannot be expressed in full.
        let Some((1, ord, _)) = resolve_position(cx.shadow, &doc, pos) else {
            tally.unaimed(format!("step '{ch}' at position `{pos}` does not ground"));
            continue;
        };
        let resp = match cx.insert(&doc, 1, ord, ch.as_bytes(), recorded) {
            Ok(resp) => resp,
            Err(_) => {
                out.never_bound(format!("interior_typing into never-bound doc {doc}"));
                return;
            }
        };
        if !matches!(resp, Response::AckAddr { .. }) {
            tally.differ(format!("insert '{ch}' at {pos}"), refusal(&resp));
            continue;
        }
        // Per-step probes: vspanset + contents recorded per character.
        let mut step = OpOutcome::new(out.index, &out.op_name);
        probe_state(cx, r, &mut step, adjustments, &doc, Probe::Step);
        match step.status {
            Status::Disagreed => tally.differ(
                format!("step '{ch}': {}", step.expected.unwrap_or_default()),
                step.actual.unwrap_or_default(),
            ),
            Status::Agreed => tally.agree(),
            _ => {}
        }
    }
    tally.settle(out, "state-probe");
}

pub(super) fn h_delete(
    cx: &mut Cx,
    index: usize,
    op: &Value,
    out: &mut OpOutcome,
    adjustments: &Adjustments,
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
        // content no-op, and the later link-findability divergence stands as
        // recorded — ruled ruling-10-i-coverage-findability (decisions.md
        // ruling 10).
        let links_vanish = cx.shadow.link_count(&doc) > 0
            && cx.ops[index + 1..].iter().any(|later| {
                if verb_of(later) != Some(Verb::FindLinks) {
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
                 (decisions.md ruling 2), so the link-findability divergence downstream \
                 stands — ruled ruling-10-i-coverage-findability (decisions.md ruling 10)",
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
        out.adaptations.extend(how.tag().map(str::to_string));
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
            out.agree("expected-failure");
            out.add_note("delete region not groundable; golden also recorded failure".into());
            return;
        }
        inexpressible(out, "delete without a groundable region".into());
        return;
    };
    let Ok(r) = cx.delete(&doc, sub, ord, width, took_effect(op)) else {
        out.never_bound(format!("delete in never-bound doc {doc}"));
        return;
    };
    match r {
        Response::Ack { .. } => {
            if settle_accepted(out, xf) {
                probe_state(cx, op, out, adjustments, &doc, Probe::PostWrite);
            }
        }
        r => settle_unaccepted(out, xf, &r),
    }
}

pub(super) fn h_vcopy(
    cx: &mut Cx,
    index: usize,
    op: &Value,
    out: &mut OpOutcome,
    adjustments: &Adjustments,
) {
    let recorded = took_effect(op);
    // Pre-pass expansion plans cover the macro forms (vcopy_multiple /
    // vcopy_all / vcopy_from_both / vcopy_to_multiple / create_and_
    // transclude): fillers as inserts, shared regions as real copies.
    if cx.plans.contains_key(&index) {
        // vcopy_to_multiple / create_and_transclude bind their target ids;
        // the first creation skep refuses is the op's disagreement.
        let mut refused: Option<Box<Response>> = None;
        if let Some(targets) = field(op, &["targets"]).and_then(Value::as_array) {
            for t in targets {
                let id = t.as_str().or_else(|| t.get("docid").and_then(Value::as_str));
                if let Some(id) = id {
                    if let Err(r) = create_one(cx, id, None, recorded) {
                        refused.get_or_insert(r);
                    }
                }
            }
        }
        let failure = run_plan(cx, index, out);
        if let Some(r) = refused {
            out.disagree("rejection", "document creation".into(), refusal(&r));
            return;
        }
        if let Some(failure) = failure {
            plan_failed(out, failure);
            return;
        }
        out.status = Status::NotCompared;
        // Per-target contents expectations (vcopy_to_multiple) compare here.
        if let Some(targets) = field(op, &["targets"]).and_then(Value::as_array) {
            let mut tally = Tally::default();
            for t in targets {
                let (Some(id), Some(exp)) = (
                    t.get("docid").and_then(Value::as_str),
                    t.get("contents").and_then(expect_strings),
                ) else {
                    continue;
                };
                match cx.read_content(id) {
                    Ok(items) => {
                        let label = format!("{id}: ");
                        tally.judge(compare_content(&exp, &items, cx.alpha), &label, &label);
                    }
                    Err(code) => tally.differ(format!("{id}: contents"), format!("{id}: {code}")),
                }
            }
            if tally.compared > 0 {
                tally.settle(out, "content");
            }
        }
        return;
    }

    // Source regions: the one reading both passes share (policy tags such
    // as `vcopy-source-reaimed` and the located texts' grounding included).
    let sources = match vcopy_sources(op, cx.shadow, &mut out.adaptations) {
        Ok(s) => s,
        Err(reason) => {
            inexpressible(out, reason);
            return;
        }
    };
    let src_doc = sources.first().map(|s| s.doc.clone());
    let copied: Vec<u8> = sources
        .iter()
        .filter(|s| s.sub == 1)
        .flat_map(|s| cx.shadow.slice(&s.doc, s.ord, s.width))
        .collect();

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
    let xf = expected_failure(op);
    let r = match cx.copy(&dest, ord, &sources, recorded) {
        Ok(r) => r,
        Err(g) if g == dest && sources.iter().all(|s| s.doc != g) => {
            out.never_bound(format!("vcopy destination {dest} never bound"));
            return;
        }
        Err(g) => {
            out.never_bound(format!("vcopy source doc {g} never bound"));
            return;
        }
    };
    match r {
        Response::Ack { .. } => {
            if settle_accepted(out, xf) {
                probe_state(cx, op, out, adjustments, &dest, Probe::PostWrite);
            }
        }
        r => settle_unaccepted(out, xf, &r),
    }
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
    let xf = expected_failure(op);
    let Ok(r) = cx.rearrange(&doc, &cuts, took_effect(op)) else {
        out.never_bound(format!("rearrange in never-bound doc {doc}"));
        return;
    };
    match r {
        Response::Ack { .. } => {
            if settle_accepted(out, xf) {
                out.status = Status::NotCompared;
            }
        }
        r => settle_unaccepted(out, xf, &r),
    }
}
