//! `skep fingerprint` (`client.md` §2.2): the store's keys — every one, or
//! the one `--select` or `--key` names — each with the bindings that name
//! it, or the pending state where none does (AUTH-5.32); `--payload`
//! re-prints a key's enrollment record, `--json` answers one document.

use skep_client::halt::Halt;
use skep_client::sheet::{group_hex, render_inert};
use skep_client::store::{Binding, KeyFacts, KeySelector, Purpose, StoreError};
use skep_identity::{encode_enroll, Enrollment};

use super::{data, halt, store_of, usage};
use crate::args::Command;

pub fn fingerprint(c: &Command) -> i32 {
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    let bindings = store.all_bindings().unwrap_or_default();
    let keys: Vec<KeyFacts> = if let Some(path) = c.key() {
        match store.select(&KeySelector::Path(&path), Purpose::Read) {
            Ok(k) => vec![k],
            Err(e) => return halt(e.into()),
        }
    } else if let Some(select) = c.value("--select", None) {
        match store.select(&KeySelector::select(&select), Purpose::Read) {
            Ok(k) => vec![k],
            Err(StoreError::Ambiguous { keys }) => {
                let list: Vec<String> = keys.iter().map(|k| format!("{} {}", k.fingerprint, k.label.as_deref().map(render_inert).unwrap_or_default())).collect();
                return halt(Halt::face(format!("`{select}` matches more than one key"), format!("neither a fingerprint prefix nor a label is unique by rule (AUTH-5.3):\n  {}", list.join("\n  ")), "give a longer prefix; never a pick"));
            }
            Err(StoreError::NotFound { select }) => return halt(Halt::face(format!("no key in the store matches `{select}`"), "the store's keys are listed by `skep fingerprint --dir`", "check the selector")),
            Err(e) => return halt(e.into()),
        }
    } else {
        match store.list() {
            Ok(keys) => keys,
            Err(e) => return halt(e.into()),
        }
    };
    let any_binding = bindings.iter().any(|b| matches!(b, Binding::Enrollment { .. }));
    let mut json_rows = Vec::new();
    for key in &keys {
        let fp = key.fingerprint;
        let bound: Vec<String> = bindings
            .iter()
            .filter_map(|b| match b {
                Binding::Enrollment { origin, principal, account, fingerprint } if *fingerprint == fp => Some(format!("{origin} principal {principal} account {account}")),
                _ => None,
            })
            .collect();
        let unbound = bound.is_empty();
        if c.switch("--json") {
            json_rows.push(serde_json::json!({
                "alg": key.public.alg(),
                "fingerprint": fp.to_hex(),
                "label": key.label,
                "anchor": key.anchor,
                "path": key.path.display().to_string(),
                "bindings": bound,
                "unbound": unbound,
                "payload": c.switch("--payload").then(|| encode_enroll(&[Enrollment::new(key.public.clone(), key.anchor, key.label.clone()).expect("a stored label is in the domain")])),
            }));
            continue;
        }
        data(format!("{} {}", key.public.alg(), key.public.to_hex()));
        data(fp.to_hex());
        data(group_hex(&fp.to_hex()));
        data(format!("label {}", key.label.as_deref().map(render_inert).unwrap_or_else(|| "(none)".into())));
        if key.anchor {
            data("ANCHOR — a paper's file, never a device key");
        }
        for b in &bound {
            data(format!("bound {b}"));
        }
        if unbound {
            // THE PENDING STATE (AUTH-5.32), the durable half of `keygen
            // --payload`'s line, conditioned on the walk.
            data(if any_binding {
                "UNBOUND — this key is enrolled at no board this store knows: `skep fingerprint --select <fp> --payload` re-prints its payload; `skep enroll` on a device already signed in (or `skep rotate --payload` there where this key REPLACES a machine), then `skep bind` here; where this key was made at `skep accept`, the outstanding act is the giver's genesis and their reply, then `skep bind`"
            } else {
                "UNBOUND — no board has been claimed from this store: the act is `skep claim`; or, for a board another device is signed in on, `skep enroll` there with this key's payload and `skep bind` here"
            });
        }
        if c.switch("--payload") {
            data(encode_enroll(&[Enrollment::new(key.public.clone(), key.anchor, key.label.clone()).expect("a stored label is in the domain")]));
        }
    }
    if c.switch("--json") {
        data(serde_json::Value::Array(json_rows).to_string());
    }
    0
}
