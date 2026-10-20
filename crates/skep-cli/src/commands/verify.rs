//! `skep verify` (`client.md` §2.2): AUTH-5.65's pre-check as a command.
//!
//! It runs the origin arm, the key arm, and with `--payload` or `--anchor`
//! the whole-set compare against the genesis record (AUTH-4.58's
//! detection). A pass is exit 0; whatever it finds is a halt, exit 3.

use skep_client::ceremony::handshake::{key_face, Site};
use skep_client::derive::{origin_arm, precheck};
use skep_client::store::Purpose;

use super::{board_of, compare_genesis, data, held_set, key_named, principal_or_bound, select_key, store_of, talk, Stop};
use crate::args::CommandLine;

pub fn verify(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    let store = store_of(c)?;
    let given = c.principal()?;
    let key_file = c.key_file()?;
    let json = c.switch("--json");
    let mut checks: Vec<&str> = Vec::new();
    // (1) The origin arm.
    let health = board.health()?;
    origin_arm(board.signed(), &health)?;
    checks.push("origin");
    // (2) The key arm: `principal_prefix(n)`, then `key_set` at the set the
    // walk reaches, against the selected key.
    let principal = principal_or_bound(given, &store, &board)?;
    // A read of the key's public facts: `verify` signs nothing.
    let key = select_key(key_file.as_deref(), &store, &board, principal, Purpose::Read)?;
    let pre = precheck(&board, principal, &key.fingerprint)?;
    checks.push("key_set");
    let own = [(key.fingerprint, key.public.clone())];
    key_face(&board, &pre.walk, &key.fingerprint, &own, Site::Session)?;
    // The whole-set compare, where the person holds what this device
    // composed (AUTH-4.58's detection; P25).
    match held_set(&store, c.value("--payload"), c.values("--anchor"), &key)? {
        Some(held) => {
            checks.push("payload");
            compare_genesis(&board, &pre.walk, &own, &held, "or decline the account")?;
        }
        None => talk("the key arm is the one-key read — this key's membership and never the set's: pass --payload or --anchor to compare the genesis record whole"),
    }
    // What passed, joined to the board's record: the key the lookup chose,
    // by the fingerprint its writes are testified by (AUTH-4.48), the
    // principal (given, or chosen by the one-binding test), and the board
    // read.
    talk(format!(
        "key {} passed {} for principal {principal} at {}; a block is invisible to both reads: a verify that passes can still meet 403 \
         prefix_blocked at the next handshake",
        key_named(&key),
        checks.join(", "),
        board.dialed()
    ));
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
        .to_string())?;
    } else {
        data(format!("account {}", pre.account))?;
        if pre.walk.by_reference() {
            data(format!("opens by reference against {}", pre.walk.set_account))?;
        }
    }
    Ok(())
}
