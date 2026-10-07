//! `skep verify` (`client.md` §2.2): AUTH-5.65's pre-check as a command —
//! the origin arm, the key arm, and with `--payload` or `--anchor` the
//! whole-set compare against the genesis record (AUTH-4.58's detection).
//! A pass is exit 0; whatever it finds is a halt, exit 3.

use skep_client::ceremony::handshake::{key_face, Site};
use skep_client::derive::records::{compare_whole_set, credential_records};
use skep_client::derive::{origin_arm, precheck};
use skep_client::halt::Halt;
use skep_client::store::{KeySelector, Purpose};

use super::{board_of, data, difference_lines, halt, held_set, later_line, principal_or_bound, select_key, store_of, talk, usage};
use crate::args::Command;

pub fn verify(c: &Command) -> i32 {
    let board = match board_of(c) {
        Ok(b) => b,
        Err(u) => return usage(u),
    };
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    let json = c.switch("--json");
    let mut checks: Vec<&str> = Vec::new();
    // (1) THE ORIGIN ARM.
    let health = match board.health() {
        Ok(h) => h,
        Err(h) => return halt(h),
    };
    if let Err(h) = origin_arm(board.signed(), &health) {
        return halt(h);
    }
    checks.push("origin");
    // (2) THE KEY ARM: `principal_prefix(n)`, then `key_set` at the set the
    // walk reaches, against the selected key.
    let principal = match principal_or_bound(c, &store, &board) {
        Ok(p) => p,
        Err(h) => return halt(h),
    };
    let key = match c.key() {
        Some(path) => match store.select(&KeySelector::Path(&path), Purpose::Read) {
            Ok(k) => k,
            Err(e) => return halt(e.into()),
        },
        None => match select_key(c, &store, &board, Some(principal)) {
            Ok(k) => k,
            Err(h) => return halt(h),
        },
    };
    let pre = match precheck(&board, principal, &key.fingerprint) {
        Ok(p) => p,
        Err(h) => return halt(h),
    };
    checks.push("key_set");
    let own = [(key.fingerprint, key.public.clone())];
    if let Err(h) = key_face(&board, &pre.walk, &key.fingerprint, &own, Site::Session) {
        return halt(h);
    }
    // THE WHOLE-SET COMPARE, where the person holds what this device
    // composed (AUTH-4.58's detection; P25).
    let mut later_lines = Vec::new();
    let held = match held_set(c, &store, Some(&key), true) {
        Ok(h) => h,
        Err(h) => return halt(h),
    };
    if let Some(held) = held {
        checks.push("payload");
        let records = match credential_records(&board, &pre.walk.set_account, &own) {
            Ok(r) => r,
            Err(h) => return halt(h),
        };
        match compare_whole_set(&records, &pre.walk.set, &held) {
            None => return halt(Halt::face("the account has no genesis record to compare against", "the admitted read found no enrollment record naming the account", "this is a board fault, or the account is not the one the facts name")),
            Some(whole) => {
                if !whole.differences.is_empty() {
                    let lines = difference_lines(&whole.differences);
                    return halt(Halt::face(
                        format!("this account is NOT yours to keep as it stands (AUTH-5.53): the genesis record of {} differs from what you hold", pre.walk.set_account),
                        lines.join("\n  "),
                        "the acts by cell: a planted DEVICE key is retired from this device's own session; a planted ANCHOR only under an anchor of your own that survived; the state is PERMANENT where the flags did not — or decline the account",
                    ));
                }
                later_lines.extend(whole.later.iter().map(later_line));
            }
        }
    } else {
        talk("the key arm is the one-key read — this key's membership and never the set's: pass --payload or --anchor to compare the genesis record whole");
    }
    for l in &later_lines {
        talk(l);
    }
    talk("a block is invisible to both reads: a verify that passes can still meet 403 prefix_blocked at the next handshake");
    if json {
        data(serde_json::json!({
            "checks": checks,
            "account": pre.account,
            "set_account": pre.walk.set_account,
            "fingerprint": key.fingerprint.to_hex(),
            "state": "enrolled",
            "mode": pre.mode.name(),
            "limit": "a block is invisible to these reads",
        })
        .to_string());
    } else {
        data(format!("account {}", pre.account));
        if pre.walk.by_reference() {
            data(format!("opens by reference against {}", pre.walk.set_account));
        }
    }
    0
}
