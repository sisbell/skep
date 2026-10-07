//! `skep bind` (`client.md` §2.2): the three facts of an enroll hop or a
//! handoff landed on this device — confirmed against the board, the set
//! compared whole where the person holds it, the account's first signed
//! session run where one is owed, the binding line written. The one command
//! that sequences the library's compositions itself rather than calling a
//! walk.

use skep_client::board::{Board, Scope};
use skep_client::ceremony::first_session::{first_session, FirstSessionReads};
use skep_client::ceremony::handshake::{handshake, key_face, Site};
use skep_client::derive::records::{compare_whole_set, credential_records};
use skep_client::derive::{origin_arm, principal_of, walk_to_set};
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::halt::Halt;
use skep_client::sheet::Facts;
use skep_client::store::{Binding, KeySelector, KeyStore};

use super::{board_of, data, difference_lines, facts, halt, held_set, later_line, read_payload, select_key, store_of, talk, usage};
use crate::args::Command;
use crate::terminal::prompt_line;

/// The three facts, from `--account`/`--principal`/`--board`, or `--payload`
/// — a reply in the lines `facts` prints (`account …`, `principal …`,
/// `origin …`), `enroll`'s or `handoff`'s — or, for an account neither
/// names, a line pasted at the prompt.
fn facts_of(c: &Command, board: &Board) -> Result<(String, u64), Halt> {
    let mut account = c.value("--account", None);
    let mut principal = c.principal().map_err(|u| Halt::face("the principal is malformed", u.0, "pass --principal <n>"))?;
    if let Some(arg) = c.value("--payload", None) {
        let bytes = read_payload(&arg)?;
        let text = String::from_utf8_lossy(&bytes).to_string();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some("account"), Some(a)) => account = Some(a.to_string()),
                (Some("principal"), Some(p)) => principal = p.parse().ok(),
                (Some("origin"), Some(o)) => {
                    if o != board.dialed().as_str() {
                        return Err(Halt::face(format!("the reply names origin {o} and this command dials {}", board.dialed()), "the reply came from another board", "dial the board the reply names"));
                    }
                }
                _ => {}
            }
        }
    }
    let account = match account {
        Some(a) => a,
        None => prompt_line("account address (from the enrolling device's reply): ")
            .map_err(|e| Halt::face("the account could not be read", e.to_string(), "pass --account"))?
            .trim()
            .to_string(),
    };
    let principal = principal.ok_or_else(|| Halt::face("no principal", "--principal (or SKEP_PRINCIPAL), or a `principal` line in the reply, is required", "pass --principal <n>"))?;
    if account.is_empty() || !skep_client::address::is_address_text(&account) {
        return Err(Halt::face(format!("`{account}` is not an account address"), "an address is dotted decimal", "pass --account <address>"));
    }
    Ok((account, principal))
}

pub fn bind(c: &Command) -> i32 {
    let board = match board_of(c) {
        Ok(b) => b,
        Err(u) => return usage(u),
    };
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    let (account, principal) = match facts_of(c, &board) {
        Ok(f) => f,
        Err(h) => return halt(h),
    };
    // The facts CONFIRMED against the board before anything is written:
    // the origin arm; the principal by the ADDRESS-KEYED read (AUTH-6.37);
    // `principal_prefix(n)` against the pasted account; the key-set compare.
    let health = match board.health() {
        Ok(h) => h,
        Err(h) => return halt(h),
    };
    if let Err(h) = origin_arm(board.signed(), &health) {
        return halt(h);
    }
    match principal_of(&board, &account) {
        Ok(Some(p)) if p == principal => {}
        Ok(other) => {
            return halt(Halt::face(
                format!("the pasted principal {principal} is not the principal seated at {account}"),
                format!("`effective_owner({account})` where `prefix == {account}` answers {} — the reply came from another board or another principal, which is exactly what an out-of-band channel gets wrong", other.map(|p| p.to_string()).unwrap_or_else(|| "no seat".into())),
                "re-take the three facts from the enrolling device",
            ))
        }
        Err(h) => return halt(h),
    }
    match board.principal_prefix(principal) {
        Ok(Some(a)) if a == account => {}
        Ok(other) => {
            return halt(Halt::face(
                format!("the pasted account {account} is not `principal_prefix({principal})`"),
                format!("the board answers {} for that principal", other.unwrap_or_else(|| "null".into())),
                "re-take the three facts from the enrolling device",
            ))
        }
        Err(h) => return halt(h),
    }
    let key = match select_key(c, &store, &board, Some(principal)) {
        Ok(k) => k,
        Err(h) => return halt(h),
    };
    let walk = match walk_to_set(&board, &account) {
        Ok(w) => w,
        Err(h) => return halt(h),
    };
    let own = [(key.fingerprint, key.public.clone())];
    if let Err(h) = key_face(&board, &walk, &key.fingerprint, &own, Site::Tail) {
        return halt(h);
    }
    // At a HANDOFF LANDING the set is compared WHOLE, ahead of
    // `first_session` and any session (AUTH-4.58's detection).
    let records_for_compare = match held_set(c, &store, Some(&key), false) {
        Ok(h) => h,
        Err(h) => return halt(h),
    };
    if let Some(held) = records_for_compare {
        let records = match credential_records(&board, &walk.set_account, &own) {
            Ok(r) => r,
            Err(h) => return halt(h),
        };
        match compare_whole_set(&records, &walk.set, &held) {
            Some(whole) if !whole.differences.is_empty() => {
                return halt(Halt::face(
                    format!("this account is NOT yours to keep as it stands (AUTH-5.53): the genesis record of {account} differs from what you hold"),
                    difference_lines(&whole.differences).join("\n  "),
                    "the extra key is one the giver's hand can act with, whatever was said at `skep accept`; a planted device key is retired from this device's own session, a planted anchor only under an anchor of your own that survived",
                ))
            }
            Some(whole) => {
                for l in &whole.later {
                    talk(later_line(l));
                }
            }
            None => return halt(Halt::face("the account has no genesis record to compare against", "the admitted read found none", "this is a board fault")),
        }
    }
    // THE TWO ARMS, selected by `first_session`'s own reads (§2.2).
    let reads = match FirstSessionReads::take(&board, &account, &key.fingerprint, Some(&store)) {
        Ok(r) => r,
        Err(h) => return halt(h),
    };
    let mut agent_space = None;
    if reads.anything_owed() {
        if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
            talk(w);
        }
        let signer = match store.signer(&KeySelector::Path(&key.path)) {
            Ok(s) => s,
            Err(e) => return halt(e.into()),
        };
        let session = match handshake(&board, Scope::Content, &*signer, principal, Site::Tail) {
            Ok(s) => s,
            Err(h) => return halt(h),
        };
        let done = first_session(&board, &reads, &session, &*signer, Some(&store));
        let _ = session.close();
        match done {
            Err(h) => return halt(h),
            Ok(done) => {
                for w in &done.warnings {
                    talk(w);
                }
                if done.minted_home {
                    talk(format!("the home {} is minted — the empty profile home, born published (AUTH-5.90 (iii); AUTH-5.52)", reads.home));
                }
                if done.setup_stopped_seeded {
                    talk(format!("{} already holds a set of its own: the setup act stops and no agents' home is created (AUTH-5.90 (iii)'s permanent fact)", reads.agent_space));
                } else if let Some(d) = done.setup_skipped {
                    talk(format!("the setup act was not sent: this key stands {d} in the set that opens {}", reads.agent_space));
                } else if done.agent_space_principal.is_some() {
                    agent_space = Some(reads.agent_space.clone());
                }
            }
        }
    } else {
        talk("nothing is owed at this account's first signed session: no session is opened and no record is written");
    }
    let line = Binding::Enrollment { origin: board.dialed().clone(), principal, account: account.clone(), fingerprint: key.fingerprint };
    if let Err(w) = store.bind(&line) {
        talk(w.to_string());
    }
    facts(&Facts { account, principal, origin: board.dialed().clone() });
    if let Some(s) = agent_space {
        data(format!("agent space {s}"));
    }
    0
}
