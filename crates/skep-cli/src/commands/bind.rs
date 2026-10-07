//! `skep bind` (`client.md` §2.2): the three facts of an enroll hop, a
//! handoff or a hosted signup landed on this device — confirmed against the
//! board, the set compared whole where another hand wrote the account's
//! first set, the account's first signed session run where one is owed,
//! the binding line written. With `keygen`, one of the two commands that
//! sequence the library's compositions themselves rather than calling a
//! walk.

use skep_client::board::{Board, Scope};
use skep_client::ceremony::first_session::{first_session, FirstSessionReads};
use skep_client::ceremony::handshake::{handshake, key_face, Site};
use skep_client::derive::{origin_arm, principal_of, walk_to_set};
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::halt::Halt;
use skep_client::sheet::Facts;
use skep_client::store::{Binding, KeySelector, KeyStore, Purpose};

use super::{board_of, compare_genesis, data, facts, held_device, held_set, read_payload, select_key, store_of, talk, Stop};
use crate::args::CommandLine;
use crate::terminal::answer;

/// Who printed the reply `bind` lands, and so the one party that can print
/// it again: the enrolling device at the hop (`skep enroll`, or `skep rotate
/// --payload`), the giver at a handoff (§4c.2 G6), the host after a hosted
/// signup (§4.5 H6). Nothing in the reply says which, so a face that sends
/// the person back for the facts names all three, and the person knows
/// theirs (P27).
const REPLY_SENDER: &str = "whoever printed the reply — the enrolling device, the giver at a handoff, or your host after a hosted signup";

/// The three facts, from `--account`/`--principal`/`--board`, or `--payload`
/// — a reply in the lines `facts` prints (`account …`, `principal …`,
/// `origin …`), as `enroll`, `rotate`, `handoff` and `claim --hosted` print
/// them — or, for an account neither names, a line pasted at the prompt;
/// the origin the one this command dials, a reply naming another halting.
/// `given` is `CommandLine::principal`'s answer; a reply's principal line
/// that is no principal halts, never standing as one not given.
fn facts_of(c: &CommandLine, board: &Board, given: Option<u64>) -> Result<Facts, Halt> {
    let mut account = c.value("--account");
    let mut principal = given;
    if let Some(arg) = c.value("--payload") {
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
                            "a principal is a non-negative integer, as the reply prints it",
                            format!("re-take the three facts from {REPLY_SENDER}"),
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
        None => answer("account address (from the reply — the enrolling device's, the giver's at a handoff, or your host's): ")
            .map_err(|e| Halt::face("the account could not be read", e.to_string(), "pass --account"))?
            .unwrap_or_default()
            .trim()
            .to_string(),
    };
    let principal = principal.ok_or_else(|| Halt::face("no principal", "--principal (or SKEP_PRINCIPAL), or a `principal` line in the reply, is required", "pass --principal <n>"))?;
    if account.is_empty() || !skep_client::address::is_address_text(&account) {
        return Err(Halt::face(format!("`{account}` is not an account address"), "an address is dotted decimal", "pass --account <address>"));
    }
    Ok(Facts { account, principal, origin: board.dialed().clone() })
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
    /// Another hand wrote the first set around this key and the person's
    /// anchor pair: the genesis is compared against the pair's files and this
    /// device's key, and the question is asked only where no `--anchor` gave
    /// the files.
    Pair,
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

/// The landing, asked through the terminal's reader — a pipe answers it as
/// a terminal does — and asked again until the answer is one of the three;
/// `None` where the input ends before an answer, nobody being there to ask.
fn landing() -> Result<Option<Landing>, Halt> {
    let mut prompt = LANDING_QUESTION;
    loop {
        let Some(line) = answer(prompt).map_err(|e| Halt::face("the landing could not be read", e.to_string(), "answer on stdin, or pass the pair as `--anchor`"))? else {
            return Ok(None);
        };
        match line.trim().to_ascii_lowercase().as_str() {
            "hop" => return Ok(Some(Landing::Hop)),
            "alone" => return Ok(Some(Landing::KeyAlone)),
            "pair" => return Ok(Some(Landing::Pair)),
            _ => prompt = LANDING_AGAIN,
        }
    }
}

pub fn bind(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    let store = store_of(c)?;
    let given = c.principal()?;
    let key_file = c.key_file()?;
    let Facts { account, principal, origin } = facts_of(c, &board, given)?;
    // The facts CONFIRMED against the board before anything is written:
    // the origin arm; the principal by the ADDRESS-KEYED read (AUTH-6.37);
    // `principal_prefix(n)` against the pasted account; the key-set compare.
    let health = board.health()?;
    origin_arm(board.signed(), &health)?;
    match principal_of(&board, &account)? {
        Some(p) if p == principal => {}
        other => {
            return Err(Halt::face(
                format!("the pasted principal {principal} is not the principal seated at {account}"),
                format!("`effective_owner({account})` where `prefix == {account}` answers {} — the reply came from another board or another principal, which is exactly what an out-of-band channel gets wrong", other.map(|p| p.to_string()).unwrap_or_else(|| "no seat".into())),
                format!("re-take the three facts from {REPLY_SENDER}"),
            )
            .into())
        }
    }
    match board.principal_prefix(principal)? {
        Some(a) if a == account => {}
        other => {
            return Err(Halt::face(
                format!("the pasted account {account} is not `principal_prefix({principal})`"),
                format!("the board answers {} for that principal", other.unwrap_or_else(|| "null".into())),
                format!("re-take the three facts from {REPLY_SENDER}"),
            )
            .into())
        }
    }
    let key = select_key(key_file.as_deref(), &store, &board, principal, Purpose::Sign)?;
    let walk = walk_to_set(&board, &account)?;
    let own = [(key.fingerprint, key.public.clone())];
    key_face(&board, &walk, &key.fingerprint, &own, Site::Tail)?;
    // Where another hand wrote this account's first set — a HANDOFF LANDING,
    // a hosted signup's — the set is compared WHOLE, ahead of
    // `first_session` and any session (AUTH-4.58's detection): against the
    // anchor files and this device's key, or on the DECLINE arm this
    // device's key alone — the person asked which landing this is where no
    // `--anchor` says.
    let held = match held_set(&store, None, &c.all("--anchor"), &key)? {
        Some(held) => Some(held),
        None => match landing()? {
            Some(Landing::Hop) => None,
            Some(Landing::KeyAlone) => Some(vec![held_device(&key)]),
            Some(Landing::Pair) => {
                return Err(Halt::face(
                    "the anchor pair's files were not given: nothing was compared and nothing written",
                    "where another hand wrote the first set around this key and an anchor pair, the genesis is compared against the pair's files and this device's key (AUTH-4.58's detection)",
                    "re-run with `--anchor <a> --anchor <b>`",
                )
                .into())
            }
            None => {
                talk(
                    "\nno landing was answered before the input ended, so the genesis is not compared whole: this binding confirms \
                     this key's membership alone. Where another hand wrote this account's first set, pass your pair as `--anchor`, \
                     or, with this key alone, pass the reply as a file and answer `alone` on stdin",
                );
                None
            }
        },
    };
    if let Some(held) = held {
        compare_genesis(&board, &walk, &own, &held, "the extra key is one the giver's hand can act with, whatever was said at `skep accept`")?;
    }
    // THE TWO ARMS, selected by `first_session`'s own reads (§2.2).
    let reads = FirstSessionReads::take(&board, &account, &key.fingerprint, Some(&store))?;
    let mut agent_space = None;
    if reads.anything_owed() {
        if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
            talk(w);
        }
        let signer = store.signer(&KeySelector::Path(&key.path))?;
        let session = handshake(&board, Scope::Content, &*signer, principal, Site::Tail)?;
        let done = first_session(&board, &reads, &session, &*signer, Some(&store));
        let _ = session.close();
        let done = done?;
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
    } else {
        talk("nothing is owed at this account's first signed session: no session is opened and no record is written");
    }
    let line = Binding::Enrollment { origin: origin.clone(), principal, account: account.clone(), fingerprint: key.fingerprint };
    if let Err(w) = store.bind(&line) {
        talk(w.to_string());
    }
    facts(&Facts { account, principal, origin });
    if let Some(s) = agent_space {
        data(format!("agent space {s}"));
    }
    Ok(())
}
