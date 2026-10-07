//! Creation: documents — one, several, or a chain — the pre-pass's `setup`
//! plans, `open_document` (the no-op, and the CONFLICT_COPY fork as a
//! version), versions, and the account ops: `account` selection and
//! `create_node` sub-account minting, both as M3 delegation.
//!
//! The pre-pass restates these handlers' effects on the shadow in
//! `ground/sim.rs`, in the `Sim::sim_<verb>` methods named for them: change
//! the two together.

use serde_json::Value;

use skep_febe::Response;

use super::{
    ensure_document, inexpressible, joint_absence, plan_failed, refusal, run_plan, settle_accepted,
    settle_rejected, settle_unaccepted, Cx,
};
use crate::evidence::Effect;
use crate::fields::{
    create_name_of, created_addresses, expected_failure, field, group_word, is_conflict_copy,
    recorded_count, roster, str_field, version_result, version_source,
};
use crate::outcome::{Disagreement, OpOutcome, Status};
use crate::tum::VPoint;

/// A creation's end, once skep made every document the op asked for and the
/// recording reports no failure; `recorded` documents were created at an
/// address the recording kept, `synthesized` under a golden id the harness
/// minted (`Shadow::synthesize_docid`, tagged `docid-synthesized:N`) because it
/// kept none. The op agrees on the address binding only when every document's
/// address was recorded — each now bound in α to skep's mint, where a
/// conflicting bind is an α double-bind finding. A synthesized id binds but
/// compares nothing, and an op that kept no address at all compares nothing
/// either: both end `NotCompared`.
fn settle_creation(out: &mut OpOutcome, recorded: usize, synthesized: usize) {
    if synthesized > 0 {
        out.adaptations.push(format!("docid-synthesized:{synthesized}"));
        out.status = Status::NotCompared;
        let created = recorded + synthesized;
        out.add_note(format!(
            "the recording kept no address for {synthesized} of the {created} documents \
             created; no recorded result to bind"
        ));
    } else if recorded == 0 {
        out.status = Status::NotCompared;
        out.add_note("no recorded result to bind".into());
    } else {
        out.agree("address-binding");
    }
}

pub(super) fn h_create_document(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    let name = create_name_of(op);
    let (goldens, synthesized) = match created_addresses(op) {
        Some(ids) => (ids, 0),
        None => (vec![cx.shadow.synthesize_docid()], 1),
    };
    let recorded_failure = expected_failure(op);
    let effect = Effect::of(op);
    for (i, golden) in goldens.iter().enumerate() {
        // The op's name names its first document; one an implied create
        // already made is named and made current.
        let name = if i == 0 { name.as_deref() } else { None };
        if let Err(r) = ensure_document(cx, golden, name, effect) {
            settle_unaccepted(out, recorded_failure, &r);
            return;
        }
    }
    if settle_accepted(out, recorded_failure) {
        settle_creation(out, goldens.len() - synthesized, synthesized);
    }
}

pub(super) fn h_create_documents(cx: &mut Cx, index: usize, op: &Value, out: &mut OpOutcome) {
    let recorded_failure = expected_failure(op);
    let effect = Effect::of(op);
    // Every creation the op records is asked for. The first one skep refuses
    // is then settled, once, against the failure the golden recorded —
    // unless the op already disagrees (a text insert or a plan step skep
    // refused): that disagreement stands, the refusal noted beside it.
    let mut refused: Option<Box<Response>> = None;
    // How many of the documents the op creates are minted under a
    // synthesized golden id, the recording having kept none.
    let mut synthesized = 0usize;
    let mut create = |cx: &mut Cx, id: &str, name: Option<&str>| {
        if let Err(r) = ensure_document(cx, id, name, effect) {
            refused.get_or_insert(r);
        }
    };
    // docs map {name: id} — created in id order.
    let mut by_id: Vec<(String, String)> = op
        .get("docs")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(n, id)| id.as_str().map(|i| (i.to_string(), n.clone())))
                .collect()
        })
        .unwrap_or_default();
    // A roster of `<name>: <docid>` fields (doc1/doc2, source1/source2, the
    // `docs` op's A/B/C) — created in name order.
    let named = roster(op);
    // How many documents the op creates.
    let created = if !by_id.is_empty() {
        by_id.sort();
        for (id, n) in &by_id {
            create(cx, id, Some(n));
        }
        by_id.len()
    } else if !named.is_empty() {
        for (n, id) in &named {
            create(cx, id, Some(n));
        }
        named.len()
    } else {
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
        // A count past the build budget orders documents no comparison
        // could read: the op is refused before any is created.
        let count = match recorded_count(op) {
            Ok(count) => count,
            Err(past_budget) => {
                inexpressible(out, past_budget);
                return;
            }
        };
        let count = count
            .map(|c| c as usize)
            .unwrap_or_else(|| results.len().max(names.len()).max(1))
            .max(results.len());
        for k in 0..count {
            let id = match results.get(k) {
                Some(id) => id.clone(),
                None => {
                    synthesized += 1;
                    cx.shadow.synthesize_docid()
                }
            };
            let name =
                names.get(k).cloned().or_else(|| group.as_ref().map(|t| format!("{t}{}", k + 1)));
            create(cx, &id, name.as_deref());
            if let Some(g) = &group {
                let singular = g.trim_end_matches('s');
                cx.name_document(&id, &format!("{singular}{}", k + 1));
                cx.name_document(&id, &format!("{singular}_{k}"));
            }
            // The recorded text goes in whatever skep answers; a refusal is
            // the op's disagreement unless an earlier one already is. A
            // document with no α-image was refused at creation, a refusal
            // settled below.
            if let Some(t) = texts.get(k) {
                if let Ok(r) = cx.insert(&id, VPoint::content(1), t.as_bytes(), effect) {
                    let first = out.status != Status::Disagreed;
                    if first && !matches!(r, Response::AckAddr { .. }) {
                        let expected = format!("text insert into {id} succeeds");
                        out.disagree("rejection", Disagreement { expected, actual: refusal(&r) });
                    }
                }
            }
        }
        // World-construction plans (create_multiple_targets): the pre-pass
        // covered each created-empty doc's probed content with real copies.
        // The plan runs whatever skep answered a text insert; the earlier
        // failure stays the op's.
        if cx.plans.contains_key(&index) {
            if let Some(failure) = run_plan(cx, index, out) {
                if out.status != Status::Disagreed {
                    plan_failed(out, failure);
                }
            }
        }
        count
    };
    if let Some(r) = refused {
        if out.status == Status::Disagreed {
            out.add_note(format!("document creation: {}", refusal(&r)));
        } else {
            settle_unaccepted(out, recorded_failure, &r);
        }
        return;
    }
    if out.status == Status::Disagreed {
        return;
    }
    if settle_accepted(out, recorded_failure) {
        settle_creation(out, created - synthesized, synthesized);
    }
}

pub(super) fn h_create_chain(cx: &mut Cx, index: usize, op: &Value, out: &mut OpOutcome) {
    let Some(map) = op.get("docs").and_then(Value::as_object) else {
        inexpressible(out, "create_chain without a docs map".into());
        return;
    };
    let mut by_id: Vec<(String, String)> = map
        .iter()
        .filter_map(|(n, id)| id.as_str().map(|i| (i.to_string(), n.clone())))
        .collect();
    by_id.sort();
    let mut refused: Option<Box<Response>> = None;
    for (id, n) in &by_id {
        if let Err(r) = ensure_document(cx, id, Some(n), Effect::of(op)) {
            refused.get_or_insert(r);
        }
    }
    if let Some(r) = refused {
        let expected = "document creation".to_string();
        out.disagree("rejection", Disagreement { expected, actual: refusal(&r) });
        return;
    }
    if !cx.plans.contains_key(&index) {
        out.status = Status::NotCompared;
        out.note = Some("no expansion plan derived; nothing executed".into());
        return;
    }
    match run_plan(cx, index, out) {
        Some(failure) => plan_failed(out, failure),
        None => out.status = Status::NotCompared,
    }
}

pub(super) fn h_setup(cx: &mut Cx, index: usize, out: &mut OpOutcome) {
    if !cx.plans.contains_key(&index) {
        out.status = Status::Meta;
        out.note = Some("setup description not parseable; treated as meta".into());
        return;
    }
    match run_plan(cx, index, out) {
        Some(failure) => plan_failed(out, failure),
        None => out.status = Status::NotCompared,
    }
}

pub(super) fn h_open_document(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid", "document"]) else {
        inexpressible(out, "open_document without a resolvable doc".into());
        return;
    };
    let result = str_field(op, &["result"]).map(str::to_string);
    let recorded_failure = expected_failure(op);
    if is_conflict_copy(op) {
        out.adaptations.push("open_document:conflict_copy→version".into());
        match cx.create_version(&doc, result.as_deref(), &[], Effect::of(op)) {
            Err(_) => {
                out.never_bound(format!("open_document(conflict=copy) of never-bound doc {doc}"))
            }
            Ok(Response::AckAddr { .. }) => {
                if settle_accepted(out, recorded_failure) {
                    settle_creation(out, usize::from(result.is_some()), 0);
                }
            }
            Ok(other) => settle_unaccepted(out, recorded_failure, &other),
        }
        return;
    }
    out.adaptations.push("open_document:noop".into());
    // Green REFUSED this open (bert enforcement / account gating — manifest
    // A1/A2, recorded only in the multisession/boundary corpus); skep has no
    // open layer to refuse with. The divergence is real and surfaces raw
    // (policy `open-noop-vs-recorded-failure`) — never absorbed into the
    // no-op.
    if let Some(err) = recorded_failure {
        out.adaptations.push("open-noop-vs-recorded-failure".into());
        let expected = format!("failure: {err:?}");
        let actual =
            "skep has no bert/open layer (access control descoped); nothing rejected".to_string();
        out.disagree("expected-failure", Disagreement { expected, actual });
        return;
    }
    // The open result names the document opened: bound to that document's
    // α-image, it repeats the binding when it is the same golden address,
    // and a second golden address for one skep document — which α never
    // holds — surfaces as a double-bind finding. Peek, not translate:
    // green's OPEN validates nothing (A7), so an open of a never-created doc
    // succeeds there and has no α-image here — that absence is noted, not an
    // α-finding (the later probe's recorded failure meets it as joint
    // absence).
    if let Some(g) = &result {
        match cx.alpha.peek_translate(&doc) {
            Some(a) => cx.alpha.bind(g, &a),
            None => {
                out.add_note(format!(
                    "open of `{doc}` (never created; green's OPEN validates nothing) — \
                     result not bindable"
                ));
            }
        }
    }
    cx.shadow.set_current(&doc);
    out.status = Status::NotCompared;
}

pub(super) fn h_create_version(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    // The source and the version address the recording kept are the one
    // reading the grounding pre-pass applies too (`fields::version_source`,
    // `fields::version_result`).
    let Some(src) = version_source(op, cx.shadow, &mut out.adaptations) else {
        inexpressible(out, "create_version with no source document".into());
        return;
    };
    let golden = version_result(op);
    let recorded_failure = expected_failure(op);
    if joint_absence(cx, out, recorded_failure.as_deref(), &src) {
        return; // green failed versioning a never-created doc (boundary A7)
    }
    // A non-address doc/name/label field names the NEW version.
    let names: Vec<&str> =
        ["doc", "name", "label"].iter().filter_map(|k| str_field(op, &[k])).collect();
    match cx.create_version(&src, golden.as_deref(), &names, Effect::of(op)) {
        Err(_) => out.never_bound(format!("version of never-bound doc {src}")),
        Ok(Response::AckAddr { .. }) => {
            if !settle_accepted(out, recorded_failure) {
                return;
            }
            if golden.is_some() {
                out.agree("address-binding");
            } else {
                out.status = Status::NotCompared;
                out.note = Some("create_version with no recorded result to bind".into());
            }
        }
        Ok(other) => settle_unaccepted(out, recorded_failure, &other),
    }
}

// ── accounts ────────────────────────────────────────────────────────────────

pub(super) fn h_account(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    out.adaptations.push("account_as_delegate".into());
    let Some(acct) = str_field(op, &["account", "acctid", "id"]) else {
        inexpressible(out, "account op without an account field".into());
        return;
    };
    // A golden account α already binds is made current again; one seen for
    // the first time is delegated fresh.
    let switched = match cx.alpha.peek_exact(acct) {
        Some(a) => cx.rig.switch_to(&a).map(|()| a),
        None => cx.rig.delegate_account(),
    };
    match switched {
        Ok(a) => {
            cx.alpha.bind(acct, &a);
            // Multisession: `account` ops carrying a session field bind (or
            // re-bind) the label to this account (ms_create_race re-binds B).
            if let Some(session_label) = str_field(op, &["session"]) {
                cx.rig.bind_session_label(session_label, &a);
                out.adaptations.push(format!("session-bind:{session_label}"));
            }
            out.status = Status::NotCompared;
        }
        Err(e) => {
            let expected = format!("account context {acct}");
            out.disagree("account", Disagreement { expected, actual: e });
        }
    }
}

pub(super) fn h_create_node(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    out.adaptations.push("create_node_as_delegate".into());
    let Some(parent_golden) = str_field(op, &["account", "acctid", "parent"]) else {
        inexpressible(out, "create_node without an account field".into());
        return;
    };
    let Some(parent) = cx.alpha.translate(parent_golden) else {
        out.never_bound(format!("create_node under never-bound account {parent_golden}"));
        return;
    };
    let recorded_failure = expected_failure(op);
    match cx.rig.delegate_under(&parent) {
        Ok(sub_account) => {
            if !settle_accepted(out, recorded_failure) {
                return;
            }
            if let Some(g) = str_field(op, &["result"]) {
                cx.alpha.bind(g, &sub_account);
                out.agree("address-binding");
            } else {
                out.status = Status::NotCompared;
            }
        }
        Err(e) => settle_rejected(out, recorded_failure, e),
    }
}
