//! `skep bind` (`client.md` §2.2): the three facts of an enroll hop, a
//! handoff or a hosted signup landed on this device — confirmed against the
//! board, the set compared whole where another hand wrote the account's
//! first set, the account's first signed session run where one is owed,
//! the binding line written — naming a key this store holds, a key file
//! from outside it refused before anything is. With `keygen`, one of the
//! two commands that sequence the library's compositions themselves rather
//! than calling a walk.

use std::fmt;

use skep_client::board::{Board, Scope};
use skep_client::ceremony::first_session::{first_session, FirstSessionReads};
use skep_client::ceremony::handshake::{handshake, key_face, Site};
use skep_client::derive::{origin_arm, principal_of, walk_to_set};
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::halt::Halt;
use skep_client::sheet::{render_inert, Facts};
use skep_client::store::{Binding, KeySelector, KeyStore, Purpose};

use super::{board_of, compare_genesis, data, held_device, held_set, print_facts, read_payload, select_key, store_of, talk, Stop};
use crate::args::{parse_principal, CommandLine, MAX_PRINCIPAL};
use crate::terminal::answer;

/// Who printed the reply `bind` lands, and so the one party that can print
/// it again: the enrolling device at the hop (`skep enroll`, or `skep rotate
/// --payload`), the giver at a handoff (§4c.2 G6), the host after a hosted
/// signup (§4.5 H6). Nothing in the reply says which, so a face that sends
/// the person back for the facts names all three, and the person knows
/// theirs (P27).
const REPLY_SENDER: &str = "whoever printed the reply — the enrolling device, the giver at a handoff, or your host after a hosted signup";

/// The three facts, from `--account`/`--principal`/`--board`, or `--payload`
/// — a reply in the lines `print_facts` writes (`account …`, `principal …`,
/// `origin …`), as `enroll`, `rotate`, `handoff` and `claim --hosted` print
/// them — or, for an account neither names, a line pasted at the prompt;
/// the origin the one this command dials, a reply naming another halting.
/// The reply is recognized whole before a fact is taken from it: each line
/// shows as it reads ([`shows_as_it_reads`]), a line naming a fact is that
/// fact and one value ([`fact_line`]), and a fact named twice names one
/// value ([`agree`]) — so what `bind` lands is what the person's screen
/// showed, never a line it hid nor the last of two. `given` is
/// `CommandLine::principal`'s answer, and a fact the reply names against it,
/// or against `--account`, halts as a second line would; a reply's
/// principal line that is no principal halts, never standing as one not
/// given.
fn facts_of(c: &CommandLine, board: &Board, given: Option<u64>) -> Result<Facts, Halt> {
    let mut account = c.value("--account").map(str::to_owned);
    let mut principal = given;
    if let Some(arg) = c.value("--payload") {
        let bytes = read_payload(arg)?;
        for line in String::from_utf8_lossy(&bytes).lines() {
            let Some((fact, value)) = fact_line(line)? else { continue };
            match fact {
                Fact::Account => account = Some(agree("account", account.take(), value.to_string())?),
                Fact::Principal => {
                    let n = parse_principal(value).ok_or_else(|| {
                        Halt::face(
                            format!("the reply's principal line `{value}` is not a principal"),
                            format!("a principal is a non-negative integer no greater than {MAX_PRINCIPAL} (AUTH-6.36), as the reply prints it"),
                            format!("re-take the three facts from {REPLY_SENDER}"),
                        )
                    })?;
                    principal = Some(agree("principal", principal, n)?);
                }
                Fact::Origin => {
                    if value != board.dialed().as_str() {
                        return Err(Halt::face(format!("the reply names origin {value} and this command dials {}", board.dialed()), "the reply came from another board", "dial the board the reply names"));
                    }
                }
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

/// One of the three facts a reply names, by the word its line opens with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fact {
    Account,
    Principal,
    Origin,
}

impl Fact {
    /// The fact `word` names, if it names one.
    fn named(word: &str) -> Option<Fact> {
        match word {
            "account" => Some(Fact::Account),
            "principal" => Some(Fact::Principal),
            "origin" => Some(Fact::Origin),
            _ => None,
        }
    }
}

/// The fact a reply's line names, and its value: `None` for a line that
/// names none — the hosted reply's claimant and its two acts among them —
/// and a halt for a line that shows other than it reads, or that opens with
/// a fact's name and is not exactly that name and one value.
fn fact_line(line: &str) -> Result<Option<(Fact, &str)>, Halt> {
    if !shows_as_it_reads(line) {
        return Err(Halt::face(
            format!("the reply's line `{line}` holds a character a screen does not show as it reads"),
            "a control character or a bidi control moves the cursor, erases or reorders a line, so a screen can show a reply other than the one `bind` reads: the reply is refused whole",
            format!("re-take the three facts from {REPLY_SENDER}"),
        ));
    }
    let mut words = line.split_whitespace();
    let Some(fact) = words.next().and_then(Fact::named) else { return Ok(None) };
    match (words.next(), words.next()) {
        (Some(value), None) => Ok(Some((fact, value))),
        _ => Err(Halt::face(
            format!("the reply's line `{line}` is not one fact"),
            "a line that opens with a fact's name — `account`, `principal`, `origin` — names that fact and one value, as the reply prints it",
            format!("re-take the three facts from {REPLY_SENDER}"),
        )),
    }
}

/// Whether `line` shows as it reads: no control character (C0, DEL, C1)
/// and nothing AUTH-5.2's rendering disarms (a bidi control) — the screen's
/// reading of it and `bind`'s are one.
fn shows_as_it_reads(line: &str) -> bool {
    !line.contains(char::is_control) && render_inert(line) == line
}

/// A fact the reply names — `word`, as its line opens — beside one already
/// named, by its flag or an earlier line: the same value stands; another
/// halts naming both, never the last one read (the person reads one line;
/// `bind` lands one fact).
fn agree<T: PartialEq + fmt::Display>(word: &str, named: Option<T>, read: T) -> Result<T, Halt> {
    match named {
        Some(named) if named != read => Err(Halt::face(
            format!("the reply names {word} {read}, and {word} {named} is already named — by its flag or an earlier line"),
            "a fact is named once: two values for it are two replies, and `bind` lands neither",
            format!("re-take the three facts from {REPLY_SENDER}"),
        )),
        _ => Ok(read),
    }
}

/// Which landing this is, where no `--anchor` says (§2.2 `bind`): THE PERSON
/// ANSWERS WHAT NO READ CAN (P27). Where another hand wrote this account's
/// first set — a handoff's genesis, a hosted signup's — that record is the
/// very one in question and its writer can give it any shape, so nothing on
/// the board tells such a landing from the enroll hop; and a key `skep
/// accept` made is a key file like `keygen`'s, recording nothing of the door
/// that made it. The question states what each answer costs where it is
/// wrong, and proposes none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    // The binding line this command appends, and the first session's
    // persist-first line beside it, name a key this store holds (§3.5 arm
    // 2, which reads the line back to the file): a key file `--key` (or
    // `SKEP_KEY`) names outside the store binds nothing here, and nothing
    // is written.
    if !store.key_path(&key.fingerprint).is_file() {
        return Err(Halt::face(
            format!("the key file {} is not this store's: {} holds no file for {}", key.path.display(), store.root().display(), key.fingerprint),
            "a binding line names a key this store holds (client.md §3.5 arm 2); one naming another would answer every later lookup with a missing file",
            "run `skep bind` with `--dir` naming the store that holds this key",
        )
        .into());
    }
    let walk = walk_to_set(&board, &account)?;
    let own = [(key.fingerprint, key.public.clone())];
    key_face(&board, &walk, &key.fingerprint, &own, Site::Tail)?;
    // Where another hand wrote this account's first set — a HANDOFF LANDING,
    // a hosted signup's — the set is compared WHOLE, ahead of
    // `first_session` and any session (AUTH-4.58's detection): against the
    // anchor files and this device's key, or on the DECLINE arm this
    // device's key alone — the person asked which landing this is where no
    // `--anchor` says.
    let held = match held_set(&store, None, c.values("--anchor"), &key)? {
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
    print_facts(&Facts { account, principal, origin })?;
    if let Some(s) = agent_space {
        data(format!("agent space {s}"))?;
    }
    Ok(())
}
