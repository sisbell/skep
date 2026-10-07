//! Creation: documents — one, several, or a chain — the pre-pass's `setup`
//! plans, `open_document` (the no-op, and the CONFLICT_COPY fork as a
//! version), versions, and the account ops: `account` selection and
//! `create_node` sub-account minting, both as M3 delegation.

use serde_json::Value;

use skep_content::Val;
use skep_febe::{Deposit, Op, Response};

use super::{
    create_one, fail_response, inexpressible, joint_absence, rejection_code, run_plan, settle_ack,
    vpos, Cx,
};
use crate::fields::{create_name_of, expected_failure, field, group_word, keyed_role, str_field};
use crate::outcome::{OpOutcome, Status};
use crate::tum::parse_dotted;

pub(super) fn h_create_document(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    let name = create_name_of(op);
    let goldens: Vec<String> = match field(op, &["result", "results"]) {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        _ => vec![cx.shadow.synthesize_docid()],
    };
    let xf = expected_failure(op);
    for (i, golden) in goldens.iter().enumerate() {
        if cx.shadow.knows(golden) {
            // Implied-created earlier (grounding); bind name and move on.
            if let (0, Some(n)) = (i, &name) {
                cx.shadow.bind_name(n, golden);
            }
            cx.shadow.set_current(golden);
            continue;
        }
        let r = cx.rig.create_private_document();
        match r {
            Response::AckAddr { addr, .. } => {
                cx.alpha.bind(golden, &addr);
                cx.shadow.create_doc(golden, if i == 0 { name.as_deref() } else { None });
            }
            other => {
                if !settle_ack(out, xf.clone(), rejection_code(&other)) {
                    return;
                }
            }
        }
    }
    if !settle_ack(out, xf, None) {
        return;
    }
    out.status = Status::Agreed;
    out.comparator = Some("address-binding".into());
}

pub(super) fn h_create_documents(cx: &mut Cx, index: usize, op: &Value, out: &mut OpOutcome) {
    let xf = expected_failure(op);
    // docs map {name: id} — created in id order.
    if let Some(map) = op.get("docs").and_then(Value::as_object) {
        let mut by_id: Vec<(String, String)> = map
            .iter()
            .filter_map(|(n, id)| id.as_str().map(|i| (i.to_string(), n.clone())))
            .collect();
        if !by_id.is_empty() {
            by_id.sort();
            for (id, n) in by_id {
                create_one(cx, out, &id, Some(&n));
            }
            let _ = settle_ack(out, xf, None);
            if out.status == Status::NotCompared {
                out.status = Status::Agreed;
                out.comparator = Some("address-binding".into());
            }
            return;
        }
    }
    // Role-keyed fields: doc1/doc2, source1/source2, targetN — any
    // `<role><n>` key holding a dotted docid (identity_mixed_sources).
    let mut keyed: Vec<(String, String)> = op
        .as_object()
        .map(|o| {
            o.iter()
                .filter(|(k, _)| keyed_role(k))
                .filter_map(|(k, v)| {
                    let id = v.as_str()?;
                    parse_dotted(id)?;
                    Some((k.clone(), id.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    if !keyed.is_empty() {
        keyed.sort();
        for (k, id) in keyed {
            create_one(cx, out, &id, Some(&k));
        }
        let _ = settle_ack(out, xf, None);
        if out.status == Status::NotCompared {
            out.status = Status::Agreed;
            out.comparator = Some("address-binding".into());
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
    let count = field(op, &["count"])
        .and_then(Value::as_u64)
        .map(|c| c as usize)
        .unwrap_or_else(|| results.len().max(names.len()).max(1))
        .max(results.len());
    for k in 0..count {
        let id = results.get(k).cloned().unwrap_or_else(|| cx.shadow.synthesize_docid());
        let name =
            names.get(k).cloned().or_else(|| group.as_ref().map(|t| format!("{t}{}", k + 1)));
        create_one(cx, out, &id, name.as_deref());
        if let Some(g) = &group {
            let singular = g.trim_end_matches('s');
            cx.shadow.bind_name(&format!("{singular}{}", k + 1), &id);
            cx.shadow.bind_name(&format!("{singular}_{k}"), &id);
        }
        if let Some(t) = texts.get(k) {
            if let Some(d) = cx.skep_doc(&id) {
                let values: Vec<Val> = t.bytes().map(|b| Val::new(vec![b])).collect();
                if let Response::AckAddr { .. } =
                    cx.rig.exec(Op::Insert { doc: d, at: vpos(1, 1), values, deposit: Deposit::Undeclared })
                {
                    cx.shadow.insert(&id, 1, t.as_bytes());
                }
            }
        }
    }
    // World-construction plans (create_multiple_targets): the pre-pass
    // covered each created-empty doc's probed content with real copies.
    if cx.plans.contains_key(&index) {
        run_plan(cx, index, out);
        if out.status == Status::Disagreed {
            return;
        }
        out.status = Status::NotCompared;
    }
    let _ = settle_ack(out, xf, None);
    if out.status == Status::NotCompared {
        out.status = Status::Agreed;
        out.comparator = Some("address-binding".into());
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
    for (id, n) in &by_id {
        create_one(cx, out, id, Some(n));
    }
    if out.status == Status::Disagreed {
        return;
    }
    run_plan(cx, index, out);
}

pub(super) fn h_setup(cx: &mut Cx, index: usize, out: &mut OpOutcome) {
    if cx.plans.contains_key(&index) {
        run_plan(cx, index, out);
    } else {
        out.status = Status::Meta;
        out.note = Some("setup description not parseable; treated as meta".into());
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
    if conflict_copy {
        out.adaptations.push("open_document:conflict_copy→version".into());
        let Some(src) = cx.skep_doc(&doc) else {
            out.status = Status::Disagreed;
            out.comparator = Some("alpha".into());
            out.note = Some(format!("open_document(conflict=copy) of unresolvable doc {doc}"));
            return;
        };
        match cx.rig.exec(Op::Version { d_src: src, published: None }) {
            Response::AckAddr { addr, .. } => {
                if let Some(g) = &result {
                    cx.alpha.bind(g, &addr);
                    cx.shadow.version(&doc, g);
                }
                out.status = Status::Agreed;
                out.comparator = Some("address-binding".into());
            }
            other => fail_response(out, "rejection", "version address (CONFLICT_COPY)", &other),
        }
        return;
    }
    out.adaptations.push("open_document:noop".into());
    // Green REFUSED this open (bert enforcement / account gating — manifest
    // A1/A2, recorded only in the multisession/boundary corpus); skep has no
    // open layer to refuse with. The divergence is real and surfaces raw
    // (policy `open-noop-vs-recorded-failure`) — never absorbed into the
    // no-op.
    if let Some(err) = expected_failure(op) {
        out.adaptations.push("open-noop-vs-recorded-failure".into());
        out.status = Status::Disagreed;
        out.comparator = Some("expected-failure".into());
        out.expected = Some(format!("failure: {err:?}"));
        out.actual =
            Some("skep has no bert/open layer (access control descoped); nothing rejected".into());
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
                out.note = Some(format!(
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
        cx.shadow.scoped()
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
    if joint_absence(cx, out, &xf, &src) {
        return; // green failed versioning a never-created doc (boundary A7)
    }
    let Some(d_src) = cx.skep_doc(&src) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("version of unresolvable doc {src}"));
        return;
    };
    match cx.rig.exec(Op::Version { d_src, published: None }) {
        Response::AckAddr { addr, .. } => {
            if !settle_ack(out, xf, None) {
                return;
            }
            if let Some(g) = &golden {
                cx.alpha.bind(g, &addr);
                cx.shadow.version(&src, g);
                // A non-address doc/name/label field names the NEW version.
                for key in ["doc", "name", "label"] {
                    if let Some(n) = str_field(op, &[key]) {
                        if parse_dotted(n).is_none() && cx.shadow.resolve_doc(n).is_none() {
                            cx.shadow.bind_name(n, g);
                        }
                    }
                }
                out.status = Status::Agreed;
                out.comparator = Some("address-binding".into());
            } else {
                out.status = Status::NotCompared;
                out.note = Some("create_version with no recorded result to bind".into());
            }
        }
        other => {
            settle_ack(out, xf, rejection_code(&other));
        }
    }
}

// ── accounts ────────────────────────────────────────────────────────────────

pub(super) fn h_account(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    out.adaptations.push("account_as_delegate".into());
    let Some(acct) = str_field(op, &["account", "acctid", "id"]) else {
        inexpressible(out, "account op without an account field".into());
        return;
    };
    let existing = cx.alpha.peek(acct);
    match cx.rig.switch_account(existing) {
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
            out.status = Status::Disagreed;
            out.comparator = Some("account".into());
            out.expected = Some(format!("account context {acct}"));
            out.actual = Some(e);
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
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("create_node under unresolvable account {parent_golden}"));
        return;
    };
    let xf = expected_failure(op);
    match cx.rig.delegate_under(&parent, false) {
        Ok(sub) => {
            if !settle_ack(out, xf, None) {
                return;
            }
            if let Some(g) = str_field(op, &["result"]) {
                cx.alpha.bind(g, &sub);
                out.status = Status::Agreed;
                out.comparator = Some("address-binding".into());
            } else {
                out.status = Status::NotCompared;
            }
        }
        Err(e) => {
            settle_ack(out, xf, Some(e));
        }
    }
}
