//! `skep bind` (`client.md` §2.2): the three facts of an enroll hop or a
//! handoff landed on this device — confirmed against the board, the set
//! compared whole where another hand wrote the account's first set, the
//! account's first signed session run where one is owed, the binding line
//! written. With `keygen`, one of the two commands that sequence the
//! library's compositions themselves rather than calling a walk.

use skep_client::board::{Board, Scope};
use skep_client::ceremony::first_session::{first_session, FirstSessionReads};
use skep_client::ceremony::handshake::{handshake, key_face, Site};
use skep_client::derive::records::{compare_whole_set, credential_records};
use skep_client::derive::{origin_arm, principal_of, walk_to_set};
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::halt::Halt;
use skep_client::sheet::Facts;
use skep_client::store::{Binding, KeySelector, KeyStore, Purpose};

use super::{board_of, data, difference_lines, facts, halt, held_device, held_set, later_line, read_payload, select_key, store_of, talk, usage};
use crate::args::Command;
use crate::terminal::prompt_line;

/// The three facts, from `--account`/`--principal`/`--board`, or `--payload`
/// — a reply in the lines `facts` prints (`account …`, `principal …`,
/// `origin …`), `enroll`'s or `handoff`'s — or, for an account neither
/// names, a line pasted at the prompt. `given` is `Command::principal`'s
/// answer; a reply's principal line that is no principal halts, never
/// standing as one not given.
fn facts_of(c: &Command, board: &Board, given: Option<u64>) -> Result<(String, u64), Halt> {
    let mut account = c.value("--account", None);
    let mut principal = given;
    if let Some(arg) = c.value("--payload", None) {
        let bytes = read_payload(&arg)?;
        let text = String::from_utf8_lossy(&bytes).to_string();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some("account"), Some(a)) => account = Some(a.to_string()),
                (Some("principal"), Some(p)) => {
                    let n = p.parse().map_err(|_| {
                        Halt::face(
                            format!("the reply's principal line `{p}` is not a principal"),
                            "a principal is a non-negative integer, as `enroll` prints it",
                            "re-take the three facts from the enrolling device",
                        )
                    })?;
                    principal = Some(n);
                }
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

/// Which landing this is, where no `--anchor` says (§2.2 `bind`): THE PERSON
/// ANSWERS WHAT NO READ CAN (P27). Where another hand wrote this account's
/// first set — a handoff's genesis, a hosted signup's — that record is the
/// very one in question and its writer can give it any shape, so nothing on
/// the board tells such a landing from the enroll hop; and a key `skep
/// accept` made is a key file like `keygen`'s, recording nothing of the door
/// that made it. The question states what each answer costs where it is
/// wrong, and proposes none.
enum Landing {
    /// The enroll hop, or a rotation's: another of the person's devices
    /// enrolled this key, the genesis is theirs, and nothing is compared.
    Hop,
    /// Another hand wrote the first set around this key alone — a handoff's
    /// DECLINE arm, or a hosted signup's one-key payload: the genesis is
    /// compared against this device's key alone.
    KeyAlone,
    /// The input ended before an answer: nobody is there to ask.
    Unanswered,
}

/// The landing question, each answer with its price where it is wrong.
const LANDING_QUESTION: &str = "\
which landing is this? Nothing on the board or in this store tells the three apart, so the answer is yours (P27):
  hop    another of your devices enrolled this key (`skep enroll`, or `skep rotate --payload`); answered where another
         hand wrote this account's first set, nothing is compared, and a key written beside yours stands unseen
  alone  another hand wrote the first set around this key alone (a handoff whose anchor pair you declined at
         `skep accept`, or a hosted signup's one-key payload); the genesis is compared against this key, and
         answered anywhere else it halts on the keys your other device or your pair holds
  pair   another hand wrote it around this key and your anchor pair; the genesis is compared against the pair's
         files, so this run stops for them
answer hop, alone or pair: ";

/// The question again, after an answer that is none of the three.
const LANDING_AGAIN: &str = "answer hop, alone or pair: ";

/// The landing, asked through the terminal's paste prompt — a pipe answers
/// it as a terminal does — and asked again until the answer is one of the
/// three; `pair` is the halt whose act is the files.
fn landing() -> Result<Landing, Halt> {
    let mut prompt = LANDING_QUESTION;
    loop {
        let line = prompt_line(prompt).map_err(|e| Halt::face("the landing could not be read", e.to_string(), "answer on stdin, or pass the pair as `--anchor`"))?;
        if line.is_empty() {
            return Ok(Landing::Unanswered);
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "hop" => return Ok(Landing::Hop),
            "alone" => return Ok(Landing::KeyAlone),
            "pair" => {
                return Err(Halt::face(
                    "the anchor pair's files were not given: nothing was compared and nothing written",
                    "where another hand wrote the first set around this key and an anchor pair, the genesis is compared against the pair's files and this device's key (AUTH-4.58's detection)",
                    "re-run with `--anchor <a> --anchor <b>`",
                ))
            }
            _ => prompt = LANDING_AGAIN,
        }
    }
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
    let given = match c.principal() {
        Ok(p) => p,
        Err(u) => return usage(u),
    };
    let (account, principal) = match facts_of(c, &board, given) {
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
    let key = match select_key(c, &store, &board, principal, Purpose::Sign) {
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
    // Where another hand wrote this account's first set — a HANDOFF LANDING,
    // a hosted signup's — the set is compared WHOLE, ahead of
    // `first_session` and any session (AUTH-4.58's detection): against the
    // anchor files and this device's key, or on the DECLINE arm this
    // device's key alone — the person asked which landing this is where no
    // `--anchor` says.
    let held = match held_set(&store, None, &c.all("--anchor"), &key) {
        Ok(Some(held)) => Some(held),
        Ok(None) => match landing() {
            Ok(Landing::KeyAlone) => Some(vec![held_device(&key)]),
            Ok(Landing::Hop) => None,
            Ok(Landing::Unanswered) => {
                talk(
                    "\nno landing was answered before the input ended, so the genesis is not compared whole: this binding confirms \
                     this key's membership alone. Where another hand wrote this account's first set, pass your pair as `--anchor`, \
                     or, with this key alone, pass the reply as a file and answer `alone` on stdin",
                );
                None
            }
            Err(h) => return halt(h),
        },
        Err(h) => return halt(h),
    };
    if let Some(held) = held {
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
