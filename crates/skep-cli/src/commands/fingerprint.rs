//! `skep fingerprint` (`client.md` §2.2): the store's keys — every one, or
//! the one `--select` or `--key` names — each with the bindings that name
//! it, or the pending state where none does (AUTH-5.32); `--payload`
//! re-prints a key's enrollment record, `--json` answers one document.

use skep_client::halt::Halt;
use skep_client::sheet::{group_hex, render_inert};
use skep_client::store::{Binding, KeyFacts, KeySelector, Purpose, StoreError};
use skep_identity::{encode_enroll, Enrollment};

use super::{data, record_refused, store_of, Stop, OUTSTANDING_ACT};
use crate::args::CommandLine;

/// The handoff recipient's clause of the outstanding-act line, its fourth
/// (§2.2): the payload went to a GIVER who seeds an account with it, and the
/// three-key record needs the anchor files, which never enter the store
/// (§3.4) — so its re-offer is `accept --reprint`, never `--payload` here.
const ACCEPT_CLAUSE: &str = "Where this key was made at `skep accept`: the outstanding act is the giver's genesis and their reply, then `skep \
     bind`, and the re-offer is `skep accept --reprint`, never `--payload` here.";

pub fn fingerprint(c: &CommandLine) -> Result<(), Stop> {
    let store = store_of(c)?;
    let key_file = c.key_file()?;
    // An unreadable bindings file halts naming it: read as an empty one, it
    // would list every key UNBOUND and name the wrong act.
    let bindings = store.all_bindings()?;
    let keys: Vec<KeyFacts> = if let Some(path) = key_file {
        vec![store.select(&KeySelector::Path(&path), Purpose::Read)?]
    } else if let Some(select) = c.value("--select") {
        match store.select(&KeySelector::select(select), Purpose::Read) {
            Ok(k) => vec![k],
            Err(StoreError::Ambiguous { keys }) => {
                let list: Vec<String> = keys.iter().map(|k| format!("{} {}", k.fingerprint, k.label.as_deref().map(render_inert).unwrap_or_default())).collect();
                return Err(Halt::face(format!("`{select}` matches more than one key"), format!("neither a fingerprint prefix nor a label is unique by rule (AUTH-5.3):\n  {}", list.join("\n  ")), "give a longer prefix; never a pick").into());
            }
            Err(StoreError::NotFound { select }) => return Err(Halt::face(format!("no key in the store matches `{select}`"), "the store's keys are listed by `skep fingerprint --dir`", "check the selector").into()),
            Err(e) => return Err(e.into()),
        }
    } else {
        store.list()?
    };
    let any_binding = bindings.iter().any(|b| matches!(b, Binding::Enrollment { .. }));
    let mut json_rows = Vec::new();
    for key in &keys {
        let fp = key.fingerprint;
        // The key's enrollment record, where `--payload` asks for it.
        let record =
            c.switch("--payload").then(|| Enrollment::new(key.public.clone(), key.anchor, key.label.clone())).transpose().map_err(record_refused)?.map(|e| encode_enroll(&[e]));
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
                "payload": record,
            }));
            continue;
        }
        data(format!("{} {}", key.public.alg(), key.public.to_hex()))?;
        data(fp.to_hex())?;
        for line in group_hex(&fp.to_hex()).lines() {
            data(line)?;
        }
        data(format!("label {}", key.label.as_deref().map(render_inert).unwrap_or_else(|| "(none)".into())))?;
        if key.anchor {
            data("ANCHOR — a paper's file, never a device key")?;
        }
        for b in &bound {
            data(format!("bound {b}"))?;
        }
        if unbound {
            // THE PENDING STATE (AUTH-5.32), the durable half of `keygen
            // --payload`'s line: the state, the re-print, the hop's and the
            // rotation's acts, `skep claim` where this store binds nothing
            // (§3.5 arm 4's fork), and the handoff recipient's clause.
            let (state, claim_clause) = if any_binding {
                ("UNBOUND — this key is enrolled at no board this store knows", "")
            } else {
                ("UNBOUND — no board has been claimed from this store", " Where this store is to claim a board of its own: `skep claim`.")
            };
            data(format!("{state}: `skep fingerprint --select <fp> --payload` re-prints this key's payload. {OUTSTANDING_ACT}{claim_clause} {ACCEPT_CLAUSE}"))?;
        }
        if let Some(record) = &record {
            data(record)?;
        }
    }
    if c.switch("--json") {
        data(serde_json::Value::Array(json_rows).to_string())?;
    }
    Ok(())
}
