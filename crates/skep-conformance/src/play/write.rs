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
//!
//! The pre-pass restates these handlers' effects on the shadow in
//! `ground/sim.rs`, in the `Sim::sim_<verb>` methods named for them: change
//! the two together.

use serde_json::Value;

use skep_febe::Response;

use super::{
    ensure_document, plan_failed, probe_state, refusal, run_plan, settle_accepted,
    settle_unaccepted, CopyNeverBound, Cx, NeverBound, Tally,
};
use crate::allowlist::Adjustments;
use crate::compare::{compare_content, REMOVE_SPLITS_SUBSPACES_ANALYSIS};
use crate::evidence::{
    delete_is_noop, resolve_delete_span, resolve_insert, vcopy_destination, vcopy_ordinal, Effect,
};
use crate::fields::{
    cuts_of, distributed_insert_texts, distribution_targets, expected_failure, field,
    recorded_count, resolve_position, str_field, swap_regions, target_replies, vcopy_form,
    vcopy_sources, verb_of, Probe, Rearrangement, VcopyForm, Verb,
};
use crate::outcome::{Disagreement, OpOutcome};
use crate::tum::{parse_vpos, VPoint};

pub(super) fn h_insert(
    cx: &mut Cx,
    index: usize,
    op: &Value,
    out: &mut OpOutcome,
    adjustments: &Adjustments,
) {
    let effect = Effect::of(op);
    // insert_all + texts: one text per created doc, creation order (policy
    // `insert-all:distributed`; the grounding pre-pass distributes through
    // the same `fields::distributed_insert_texts` and `distribution_targets`).
    if let Some(texts) = distributed_insert_texts(op) {
        out.adaptations.push("insert-all:distributed".into());
        let docs = distribution_targets(cx.shadow, texts.len());
        let mut failed = false;
        for (docid, t) in docs.iter().zip(&texts) {
            let at = VPoint::content(cx.shadow.text_len(docid) + 1);
            let r = cx.insert(docid, at, t.as_bytes(), effect);
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
                    out.disagree("rejection", Disagreement { expected, actual: refusal(&r) });
                }
            }
        }
        if !failed {
            out.not_compared();
        }
        return;
    }
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        out.inexpressible("insert with no document in scope".into());
        return;
    };
    // Where the insert lands — its text, any re-aim, its position, the
    // recorded-vspanset pad — is the one reading the grounding pre-pass
    // applies too (`evidence::resolve_insert`), each policy it uses tagged.
    let landing = match resolve_insert(cx.ops, index, cx.shadow, &doc, &mut out.adaptations) {
        Ok(landing) => landing,
        Err(reason) => {
            out.inexpressible(reason);
            return;
        }
    };
    if landing.doc != doc {
        cx.shadow.set_current(&landing.doc);
    }
    let recorded_failure = expected_failure(op);
    let Ok(r) = cx.insert(&landing.doc, landing.at, &landing.bytes, effect) else {
        out.never_bound(format!("insert into never-bound doc {}", landing.doc));
        return;
    };
    match r {
        Response::AckAddr { .. } => {
            if settle_accepted(out, recorded_failure) {
                probe_state(cx, op, out, adjustments, &landing.doc, Probe::PostWrite);
            }
        }
        r => settle_unaccepted(out, recorded_failure, &r),
    }
}

pub(super) fn h_insert_loop(
    cx: &mut Cx,
    op: &Value,
    out: &mut OpOutcome,
    adjustments: &Adjustments,
) {
    // The count is recognized before anything acts on the op — before it
    // aims, so its register stays where it stood; the walk restates this
    // refusal (`Sim::refused_before_aiming`). One past the build budget
    // orders work no comparison can read.
    let count = match recorded_count(op) {
        Ok(Some(count)) => count,
        Ok(None) => {
            out.inexpressible("insert_loop without a count".into());
            return;
        }
        Err(past_budget) => {
            out.inexpressible(past_budget);
            return;
        }
    };
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        out.inexpressible("insert_loop with no document in scope".into());
        return;
    };
    // The recorded sample (edgecases/many_small_inserts) shows A–Z cycling,
    // one insert per character, appended.
    out.adaptations.push("insert-loop:a-z-cycle".into());
    let effect = Effect::of(op);
    let mut failed = false;
    for k in 0..count {
        let b = b'A' + (k % 26) as u8;
        let at = VPoint::content(cx.shadow.text_len(&doc) + 1);
        match cx.insert(&doc, at, &[b], effect) {
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
                    out.disagree("rejection", Disagreement { expected, actual: refusal(&r) });
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
        out.inexpressible("interior_typing with no document in scope".into());
        return;
    };
    let Some(results) = field(op, &["results"]).and_then(Value::as_array) else {
        out.inexpressible("interior_typing without a results list".into());
        return;
    };
    out.adaptations.push("interior-typing:per-step".into());
    let effect = Effect::of(op);
    let mut tally = Tally::default();
    for r in results {
        let (Some(ch), Some(pos)) =
            (r.get("char").and_then(Value::as_str), r.get("position").and_then(Value::as_str))
        else {
            continue;
        };
        // A step whose position does not ground loses both its insert and
        // its check — the op cannot be expressed in full.
        let Some((at @ VPoint { sub: 1, .. }, how)) = resolve_position(cx.shadow, &doc, pos)
        else {
            tally.unaimed(format!("step '{ch}' at position `{pos}` does not ground"));
            continue;
        };
        out.adaptations.extend(how.map(|how| how.tag().to_string()));
        let resp = match cx.insert(&doc, at, ch.as_bytes(), effect) {
            Ok(resp) => resp,
            Err(_) => {
                out.never_bound(format!("interior_typing into never-bound doc {doc}"));
                return;
            }
        };
        if !matches!(resp, Response::AckAddr { .. }) {
            let expected = format!("insert '{ch}' at {pos}");
            tally.differ(Disagreement { expected, actual: refusal(&resp) });
            continue;
        }
        // Per-step probes: vspanset + contents recorded per character,
        // each step judged as an op of its own and folded in as one part.
        let mut step = OpOutcome::new(out.index, &out.op_name);
        probe_state(cx, r, &mut step, adjustments, &doc, Probe::Step);
        tally.absorb(out, step, &format!("step '{ch}': "));
    }
    tally.settle(out, "state-probe");
}

/// A delete — of a region, or of the whole document when `verb` is
/// [`Verb::DeleteAll`].
pub(super) fn h_delete(
    cx: &mut Cx,
    index: usize,
    op: &Value,
    out: &mut OpOutcome,
    adjustments: &Adjustments,
    verb: Verb,
) {
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        out.inexpressible("delete with no document in scope".into());
        return;
    };
    // Policy `delete-noop-from-post-state`: the recorded post-delete content
    // equals the pre-delete content — udanax removed nothing (client-crash
    // family), so the harness executes nothing and later probes compare
    // against the intact document honestly.
    if delete_is_noop(cx.ops, index, cx.shadow, &doc) {
        out.adaptations.push("delete-noop-from-post-state".into());
        out.not_compared();
        let mut note = String::from(
            "recorded post-delete content equals pre-delete content; udanax removed nothing \
             from the content subspace",
        );
        // The standing analysis of a remove that split the subspaces
        // (`REMOVE_SPLITS_SUBSPACES_ANALYSIS`): the SAME recording later
        // reports the doc's links unfindable (find_links count 0 / empty).
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
            note.push_str("; ANALYSIS: ");
            note.push_str(REMOVE_SPLITS_SUBSPACES_ANALYSIS);
        }
        out.note = Some(note);
        return;
    }
    let recorded_failure = expected_failure(op);
    let region = if verb == Verb::DeleteAll {
        let n = cx.shadow.text_len(&doc);
        if n == 0 {
            out.adaptations.push("delete_all:empty-noop".into());
            out.not_compared();
            out.note = Some("document already empty; nothing to delete".into());
            return;
        }
        VPoint::content(1).region(n)
    } else if let Some((region, how)) = resolve_delete_span(cx.ops, index, cx.shadow, &doc) {
        out.adaptations.extend(how.tag().map(str::to_string));
        region
    } else if let Some(start) = str_field(op, &["start", "address", "at"]) {
        // A link-subspace delete (delete_middle_link_check_gap_closure).
        match parse_vpos(start) {
            Some(at) if at.sub != 1 => {
                let w = str_field(op, &["width"]).and_then(crate::tum::parse_width).unwrap_or(1);
                at.region(w)
            }
            _ => {
                out.inexpressible(format!("delete start `{start}` is not groundable"));
                return;
            }
        }
    } else {
        // Skep is never asked, so a failure the golden recorded meets no
        // answer to agree with: the op stays inexpressible either way.
        let mut reason = String::from("delete without a groundable region");
        if recorded_failure.is_some() {
            reason.push_str("; the golden recorded a failure, but skep was never asked");
        }
        out.inexpressible(reason);
        return;
    };
    let Ok(r) = cx.delete(&doc, region, Effect::of(op)) else {
        out.never_bound(format!("delete in never-bound doc {doc}"));
        return;
    };
    match r {
        Response::Ack { .. } => {
            if settle_accepted(out, recorded_failure) {
                probe_state(cx, op, out, adjustments, &doc, Probe::PostWrite);
            }
        }
        r => settle_unaccepted(out, recorded_failure, &r),
    }
}

pub(super) fn h_vcopy(
    cx: &mut Cx,
    index: usize,
    op: &Value,
    out: &mut OpOutcome,
    adjustments: &Adjustments,
) {
    let effect = Effect::of(op);
    // Every form but `VcopyForm::Ordinary`, and an ordinary copy the
    // pre-pass reconstructed, runs as the pre-pass's expansion plan:
    // fillers as inserts, shared regions as real copies.
    if cx.plans.contains_key(&index) {
        // vcopy_to_multiple / create_and_transclude bind their target ids;
        // the first creation skep refuses is the op's disagreement.
        let mut refused: Option<Box<Response>> = None;
        if let Some(targets) = field(op, &["targets"]).and_then(Value::as_array) {
            for t in targets {
                let id = t.as_str().or_else(|| t.get("docid").and_then(Value::as_str));
                if let Some(id) = id {
                    if let Err(r) = ensure_document(cx, id, None, effect) {
                        refused.get_or_insert(r);
                    }
                }
            }
        }
        let failure = run_plan(cx, index, out);
        if let Some(r) = refused {
            let expected = "document creation".to_string();
            out.disagree("rejection", Disagreement { expected, actual: refusal(&r) });
            return;
        }
        if let Some(failure) = failure {
            plan_failed(out, failure);
            return;
        }
        out.not_compared();
        // Per-target contents expectations (vcopy_to_multiple) compare here,
        // read as every `targets` list is (`fields::target_replies`).
        let targets = target_replies(op, cx.shadow);
        if !targets.is_empty() {
            let mut tally = Tally::default();
            for (id, exp) in &targets {
                match cx.read_content(id) {
                    Ok(items) => {
                        let label = format!("{id}: ");
                        tally.judge(compare_content(exp, &items, cx.alpha), &label);
                    }
                    Err(code) => tally.differ(Disagreement {
                        expected: format!("{id}: contents"),
                        actual: format!("{id}: {code}"),
                    }),
                }
            }
            tally.settle(out, "content");
        }
        return;
    }
    // Any other form copies only as the plan the pre-pass builds for it: read
    // as one ordinary copy, it would copy what its recording never asked for.
    if vcopy_form(op) != VcopyForm::Ordinary {
        let reason = format!(
            "`{}` copies only as a pre-pass expansion plan, and none was derived",
            out.op_name
        );
        out.inexpressible(reason);
        return;
    }

    // Source regions: the one reading both passes share (policy tags such
    // as `vcopy-source-reaimed` and the located texts' grounding included).
    let sources = match vcopy_sources(op, cx.shadow, &mut out.adaptations) {
        Ok(s) => s,
        Err(reason) => {
            out.inexpressible(reason);
            return;
        }
    };
    // Where the copy lands — its destination, then its ordinal there — is
    // the one reading the grounding pre-pass applies too
    // (`evidence::vcopy_destination`, `evidence::vcopy_ordinal`); a copy
    // that names and evidences no document aims by `doc_arg`.
    let dest = match vcopy_destination(cx.ops, index, cx.shadow, &sources, &mut out.adaptations) {
        Ok(Some(dest)) => Some(dest),
        Ok(None) => cx.doc_arg(op, out, &["doc", "docid"]),
        Err(reason) => {
            out.inexpressible(reason);
            return;
        }
    };
    let Some(dest) = dest else {
        out.inexpressible("vcopy without a resolvable destination".into());
        return;
    };
    let ord = match vcopy_ordinal(op, cx.shadow, &dest, &mut out.adaptations) {
        Ok(Some(ord)) => ord,
        Ok(None) => cx.shadow.text_len(&dest) + 1,
        Err(reason) => {
            out.inexpressible(reason);
            return;
        }
    };
    let recorded_failure = expected_failure(op);
    let r = match cx.copy(&dest, ord, &sources, effect) {
        Ok(r) => r,
        Err(CopyNeverBound::Destination(_)) => {
            out.never_bound(format!("vcopy destination {dest} never bound"));
            return;
        }
        Err(CopyNeverBound::Source(NeverBound(g))) => {
            out.never_bound(format!("vcopy source doc {g} never bound"));
            return;
        }
    };
    match r {
        Response::Ack { .. } => {
            if settle_accepted(out, recorded_failure) {
                probe_state(cx, op, out, adjustments, &dest, Probe::PostWrite);
            }
        }
        r => settle_unaccepted(out, recorded_failure, &r),
    }
}

/// A rearrangement of the given `shape`.
pub(super) fn h_rearrange(cx: &mut Cx, op: &Value, out: &mut OpOutcome, shape: Rearrangement) {
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        out.inexpressible("rearrange with no document in scope".into());
        return;
    };
    let mut cuts = cuts_of(op);
    if cuts.is_empty() && shape == Rearrangement::Swap {
        // Two texts to exchange, located in the shadow — the one reading the
        // grounding pre-pass applies too (`fields::swap_regions`).
        cuts = swap_regions(op, cx.shadow, &doc, &mut out.adaptations).unwrap_or_default();
    }
    let want = shape.cuts();
    if cuts.len() != want {
        out.inexpressible(format!("rearrange needs {want} cuts, could derive {}", cuts.len()));
        return;
    }
    let recorded_failure = expected_failure(op);
    let Ok(r) = cx.rearrange(&doc, &cuts, Effect::of(op)) else {
        out.never_bound(format!("rearrange in never-bound doc {doc}"));
        return;
    };
    match r {
        Response::Ack { .. } => {
            if settle_accepted(out, recorded_failure) {
                out.not_compared();
            }
        }
        r => settle_unaccepted(out, recorded_failure, &r),
    }
}
