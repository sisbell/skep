//! Creation: documents — one, several, or a chain — the pre-pass's `setup`
//! plans, `open_document` (the no-op, and the CONFLICT_COPY fork as a
//! version), versions, and the account ops: `account` selection and
//! `create_node` sub-account minting, both as M3 delegation.

use serde_json::Value;

use skep_febe::Response;

use super::{
    create_one, inexpressible, joint_absence, plan_failed, refusal, run_plan, settle_accepted,
    settle_unaccepted, settle_rejected, Cx,
};
use crate::evidence::Effect;
use crate::fields::{create_name_of, expected_failure, field, group_word, roster, str_field};
use crate::outcome::{Disagreement, OpOutcome, Status};
use crate::tum::VPoint;

pub(super) fn h_create_document(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    let name = create_name_of(op);
    let goldens: Vec<String> = match field(op, &["result", "results"]) {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        _ => vec![cx.shadow.synthesize_docid()],
    };
    let xf = expected_failure(op);
    let effect = Effect::of(op);
    for (i, golden) in goldens.iter().enumerate() {
        if cx.shadow.knows(golden) {
            // The pre-pass's implied create; bind name and move on.
            if let (0, Some(n)) = (i, &name) {
                cx.shadow.bind_name(n, golden);
            }
            cx.shadow.set_current(golden);
            continue;
        }
        let r = cx.create_document(golden, if i == 0 { name.as_deref() } else { None }, effect);
        if !matches!(r, Response::AckAddr { .. }) {
            settle_unaccepted(out, xf, &r);
            return;
        }
    }
    if settle_accepted(out, xf) {
        out.agree("address-binding");
    }
}

pub(super) fn h_create_documents(cx: &mut Cx, index: usize, op: &Value, out: &mut OpOutcome) {
    let xf = expected_failure(op);
    let effect = Effect::of(op);
    // The first creation skep refuses settles the op against the failure
    // the golden recorded, once, after every creation the op records was
    // asked for.
    let mut refused: Option<Box<Response>> = None;
    let mut create = |cx: &mut Cx, id: &str, name: Option<&str>| {
        if let Err(r) = create_one(cx, id, name, effect) {
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
    if !by_id.is_empty() {
        by_id.sort();
        for (id, n) in &by_id {
            create(cx, id, Some(n));
        }
    } else if !named.is_empty() {
        for (n, id) in &named {
            create(cx, id, Some(n));
        }
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
        let count = field(op, &["count"])
            .and_then(Value::as_u64)
            .map(|c| c as usize)
            .unwrap_or_else(|| results.len().max(names.len()).max(1))
            .max(results.len());
        for k in 0..count {
            let id = results.get(k).cloned().unwrap_or_else(|| cx.shadow.synthesize_docid());
            let name =
                names.get(k).cloned().or_else(|| group.as_ref().map(|t| format!("{t}{}", k + 1)));
            create(cx, &id, name.as_deref());
            if let Some(g) = &group {
                let singular = g.trim_end_matches('s');
                cx.shadow.bind_name(&format!("{singular}{}", k + 1), &id);
                cx.shadow.bind_name(&format!("{singular}_{k}"), &id);
            }
            // The recorded text goes in whatever skep answers; a refusal is
            // the op's disagreement unless an earlier one already is. A
            // document with no α-image was refused at creation, which
            // settles the op below.
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
    }
    if let Some(r) = refused {
        settle_unaccepted(out, xf, &r);
        return;
    }
    if out.status == Status::Disagreed {
        return;
    }
    if settle_accepted(out, xf) {
        out.agree("address-binding");
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
        if let Err(r) = create_one(cx, id, Some(n), Effect::of(op)) {
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
    let conflict_copy = str_field(op, &["conflict"]).is_some_and(|c| c == "copy")
        || str_field(op, &["copy", "copy_mode"]).is_some_and(|c| c == "conflict_copy");
    let result = str_field(op, &["result"]).map(str::to_string);
    let xf = expected_failure(op);
    if conflict_copy {
        out.adaptations.push("open_document:conflict_copy→version".into());
        match cx.create_version(&doc, result.as_deref(), &[], Effect::of(op)) {
            Err(_) => {
                out.never_bound(format!("open_document(conflict=copy) of never-bound doc {doc}"))
            }
            Ok(Response::AckAddr { .. }) => {
                if settle_accepted(out, xf) {
                    out.agree("address-binding");
                }
            }
            Ok(other) => settle_unaccepted(out, xf, &other),
        }
        return;
    }
    out.adaptations.push("open_document:noop".into());
    // Green REFUSED this open (bert enforcement / account gating — manifest
    // A1/A2, recorded only in the multisession/boundary corpus); skep has no
    // open layer to refuse with. The divergence is real and surfaces raw
    // (policy `open-noop-vs-recorded-failure`) — never absorbed into the
    // no-op.
    if let Some(err) = xf {
        out.adaptations.push("open-noop-vs-recorded-failure".into());
        let expected = format!("failure: {err:?}");
        let actual =
            "skep has no bert/open layer (access control descoped); nothing rejected".to_string();
        out.disagree("expected-failure", Disagreement { expected, actual });
        return;
    }
    // The open result names the same document — bind the alias so both
    // spellings translate. Peek, not translate: green's OPEN validates
    // nothing (A7), so an open of a never-created doc succeeds there and has
    // no α-image here — that absence is noted, not an α-finding (the later
    // probe's recorded failure meets it as joint absence).
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
    // Source: an explicit from/source/of that RESOLVES; a `doc` field only
    // when it resolves to an existing doc (identity_through_rearrange_pivot
    // uses `doc` for the NEW version's name); else the register.
    let explicit = str_field(op, &["from", "source", "of", "original"])
        .and_then(|s| cx.shadow.resolve_doc(s));
    let via_doc_field = str_field(op, &["doc"]).and_then(|s| cx.shadow.resolve_doc(s));
    let src = explicit.or(via_doc_field).or_else(|| {
        out.adaptations.push("doc-from-register".into());
        cx.shadow.current()
    });
    let Some(src) = src else {
        inexpressible(out, "create_version with no source document".into());
        return;
    };
    let golden = match field(op, &["result"]) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Object(o)) => o.get("version").and_then(Value::as_str).map(str::to_string),
        _ => None,
    };
    let xf = expected_failure(op);
    if joint_absence(cx, out, xf.as_deref(), &src) {
        return; // green failed versioning a never-created doc (boundary A7)
    }
    // A non-address doc/name/label field names the NEW version.
    let names: Vec<&str> =
        ["doc", "name", "label"].iter().filter_map(|k| str_field(op, &[k])).collect();
    match cx.create_version(&src, golden.as_deref(), &names, Effect::of(op)) {
        Err(_) => out.never_bound(format!("version of never-bound doc {src}")),
        Ok(Response::AckAddr { .. }) => {
            if !settle_accepted(out, xf) {
                return;
            }
            if golden.is_some() {
                out.agree("address-binding");
            } else {
                out.status = Status::NotCompared;
                out.note = Some("create_version with no recorded result to bind".into());
            }
        }
        Ok(other) => settle_unaccepted(out, xf, &other),
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
    let switched = match cx.alpha.peek(acct) {
        Some(a) => cx.rig.switch_to(&a).map(|()| a),
        None => cx.rig.delegate_account(),
    };
    match switched {
        Ok(a) => {
            cx.alpha.bind(acct, &a);
            // Multisession: `account` ops carrying a session field bind (or
            // re-bind) the label to this account (ms_create_race re-binds B).
            if let Some(sess) = str_field(op, &["session"]) {
                cx.rig.bind_session_label(sess, &a);
                out.adaptations.push(format!("session-bind:{sess}"));
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
    let xf = expected_failure(op);
    match cx.rig.delegate_under(&parent) {
        Ok(sub) => {
            if !settle_accepted(out, xf) {
                return;
            }
            if let Some(g) = str_field(op, &["result"]) {
                cx.alpha.bind(g, &sub);
                out.agree("address-binding");
            } else {
                out.status = Status::NotCompared;
            }
        }
        Err(e) => settle_rejected(out, xf, e),
    }
}
