//! `recover` (`client.md` §4a): the DEVICE arm R0–R6 as one walk with the
//! STOLEN order (R4 ahead of R3, `key_set` RE-READ after each retirement,
//! the loop while any unaccounted non-anchor fingerprint stands, completion
//! the read after R3's commit, TERMINATION NOT GUARANTEED said —
//! AUTH-5.60 step 2's own order; AUTH-5.64's residual), and, in its child
//! `loss`, the LOSS arm L0–L7 (`--anchor-lost`, AUTH-5.59's LOSS arm;
//! AUTH-5.47). R0's reads in their order and R0's halts (the KEYLESS face
//! naming `skep keygen` then `skep recover`; `claimant == null` ⇒ `skep
//! claim`; the by-reference halt; NO anchor flagged ⇒ AUTH-5.16's second
//! arm; this store's key `retired` ⇒ I4; `enrolled` ⇒ RESUME at R4); R1 =
//! the import (whose account first, every arm); R2 the anchor session
//! through `handshake` (the seed held per §4a.3); R3 — R1's CLASS ANSWER
//! FIRST: on "an agent's" the enrollment is REFUSED and the ANCHORED ARM's
//! containment act OFFERED from the session R2 holds (AUTH-5.64: retire the
//! non-anchor set, enroll nothing; `first_session`'s FIRST STATE ALONE —
//! RULED 2026-10-04), then on "my own" the ENROLLMENT PREVIEW with a typed
//! confirmation, then `DepositKind::Enroll` of the store's device key under
//! the imported anchor's hand (the anchor grade); `first_session(A, R2's
//! session, the imported anchor)` AHEAD OF THE WALK'S FIRST CREDENTIAL WRITE
//! — R3's enrollment on the LOST arm, R4's first retirement on the STOLEN
//! arm (§4a.2 R3, R4); R4 — `--lost` against `enrolled`'s NON-ANCHOR
//! entries, the DEFAULT the one enrolled non-anchor fingerprint this store
//! does not hold, a list picked by fingerprint WITH LABELS otherwise, each
//! `preview(removed)` + a typed answer + `DepositKind::Retire` under the
//! anchor's hand; the `closed` path's ONE ARM PER E2 TRIGGER (AUTH-5.27); R5
//! the mirror's close (AUTH-5.54 step 3); R6 the binding appended, the
//! three facts, and on the STOLEN arm AUTH-5.89's RECOVERY READ over the
//! closure and the cone (every returned genesis shown with its hand and
//! label, UNATTRIBUTABLE below the floor; the WITNESS question with its
//! bounds, RES-184; the SEIZED class; the REPORT per A4 cell, RES-174's
//! rider) and AUTH-5.28's expected end.

use std::path::PathBuf;

use skep_identity::{Enrollment, Fingerprint, PublicKey};
use skep_signature::HybridSigner;

use super::say;
use crate::address::{doc_1_of, first_child};
use crate::board::{Board, KeySet, KeySetAnswer, Scope};
use crate::ceremony::deposit::{deposit, Deposit, DepositHalt, DepositKind, DepositOutcome};
use crate::ceremony::enumerate::{by_reference_cone, enroll_links_homed, head_closure};
use crate::ceremony::first_session::{first_session, mint_home, FirstSessionReads};
use crate::ceremony::handshake::{handshake, Session, Site};
use crate::ceremony::import::{import_anchor, no_artifact_face, whose_account, ImportContext, ImportOutcome, ImportedAnchor, Whose};
use crate::ceremony::preview::{declined, preview, Preview, PreviewSite, Previewed, Row};
use crate::ceremony::reads::{r0, A4Cell, Act, Reads};
use crate::derive::records::{credential_records, Hand, Records};
use crate::halt::Halt;
use crate::person::{Confirmation, Consent, Person, Public, Question};
use crate::sheet::{group_hex, render_inert, Facts};
use crate::store::{Binding, FileStore, KeyFacts, KeyStore};

mod loss;

use loss::loss_arm;

/// The command's inputs.
#[derive(Debug, Clone)]
pub struct RecoverOptions {
    pub principal: u64,
    /// `--anchor <path>`: the kept file.
    pub anchor: Option<PathBuf>,
    /// `--lost <fp-prefix>`…
    pub lost: Vec<String>,
    /// `--stolen`; `None` asks LOST or STOLEN at the head.
    pub stolen: Option<bool>,
    /// `--anchor-lost`: the LOSS arm.
    pub anchor_lost: bool,
    /// `--anchor-out <dir>` (the loss arm), once per fresh anchor.
    pub anchor_out: Vec<PathBuf>,
    /// `--paper` (the loss arm).
    pub paper: bool,
    /// The machine's host name and the date, for the fresh anchors' boxes'
    /// per-run default (the loss arm; §4.2 step 2).
    pub host_name: String,
    pub date: String,
}

/// What the walk did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovered {
    pub facts: Facts,
    /// The device key enrolled (the device arm), or the fresh anchors (the
    /// loss arm).
    pub enrolled: Vec<Fingerprint>,
    pub retired: Vec<Fingerprint>,
    pub binding_line: Option<String>,
    /// The containment act ran (an agent's account): nothing enrolled.
    pub containment: bool,
    /// THE RECOVERY READ's lines (AUTH-5.89; §4a.2 R6), the stolen arm's —
    /// among them the REPORT per A4 cell, where the cell has one (AUTH-5.60
    /// step 4).
    pub recovery_read: Vec<String>,
    pub warnings: Vec<String>,
}

fn abandoned() -> Halt {
    Halt::face("the walk was abandoned", "the person left", "re-run when ready; every state resumes by reading (P4)")
}

/// The store's device keys for this walk (§2.2 `recover`: the STORE's,
/// never `--key`), their public facts — the walk enrolls one by its public
/// key and signs with none; the KEYLESS face where the store holds none.
fn device_key_for(store: &FileStore) -> Result<Vec<KeyFacts>, Halt> {
    let devices = store.device_keys()?;
    if devices.is_empty() {
        return Err(Halt::face(
            format!("the key store {} holds no device key for this walk", store.root().display()),
            "`skep recover` enrolls the store's device key from the anchor's session, and generates none (the door is two commands, as `claim`'s is)",
            format!("run `skep keygen --dir {}` here, then `skep recover` again", store.root().display()),
        ));
    }
    Ok(devices)
}

/// The one ENROLLED at the set (a resume), else the one FRESH device key.
fn pick_device(devices: Vec<KeyFacts>, set: &KeySet) -> Result<(KeyFacts, bool), Halt> {
    if let Some(enrolled) = devices.iter().position(|d| set.enrolled(&d.fingerprint).is_some()) {
        let mut devices = devices;
        return Ok((devices.swap_remove(enrolled), true));
    }
    let fresh: Vec<usize> = devices.iter().enumerate().filter(|(_, d)| set.retired(&d.fingerprint).is_none()).map(|(i, _)| i).collect();
    match fresh.as_slice() {
        [one] => {
            let mut devices = devices;
            Ok((devices.swap_remove(*one), false))
        }
        [] => {
            let d = &devices[0];
            Err(Halt::face(
                format!("the store's device key {} is RETIRED at this account — it is never accepted again", d.fingerprint),
                "I4 (AUTH-2.98): a retired fingerprint never re-enters the set",
                "the one act is a fresh keypair under a new byline: `skep keygen`, then `skep recover` again",
            ))
        }
        many => Err(Halt::face(
            "more than one fresh device key stands in this store",
            format!("the walk enrolls ONE: {}", many.iter().map(|i| devices[*i].fingerprint.to_string()).collect::<Vec<_>>().join(", ")),
            "keep one fresh device key in the store for this walk (or run it from a fresh store with `--dir`)",
        )),
    }
}

/// A fingerprint's row for a face: grouped, labelled.
fn row_text(fp: &Fingerprint, records: &Records) -> String {
    format!("{} ({})", fp, records.label_of(fp).map(|l| render_inert(&l)).unwrap_or_else(|| "no label recorded".into()))
}

/// The current set at `account`.
fn reread(board: &Board, account: &str) -> Result<KeySet, Halt> {
    match board.key_set(account)? {
        KeySetAnswer::Set(s) => Ok(s),
        KeySetAnswer::NotAnAccount => Err(Halt::face(format!("{account} is not an account"), "`key_set` answered `not_an_account`", "re-run")),
    }
}

/// R4's TARGETS: `--lost` prefixes resolved against `enrolled`'s NON-ANCHOR
/// entries (an anchor match refused ahead of any frame); with none named,
/// the DEFAULT — the one enrolled non-anchor fingerprint this store does not
/// hold — or a LIST the person picks from by fingerprint, with labels.
fn targets(person: &mut dyn Person, set: &KeySet, records: &Records, held: &[Fingerprint], lost: &[String]) -> Result<Vec<Fingerprint>, Halt> {
    let mut out = Vec::new();
    if !lost.is_empty() {
        for prefix in lost {
            let prefix = prefix.trim().to_ascii_lowercase();
            let matches: Vec<_> = set.enrolled.iter().filter(|e| e.fingerprint.to_hex().starts_with(&prefix)).collect();
            match matches.as_slice() {
                [] => return Err(Halt::face(format!("no enrolled key starts with `{prefix}`"), "`--lost` names an enrolled NON-ANCHOR fingerprint", "name an enrolled fingerprint's prefix")),
                [one] if one.anchor => {
                    return Err(Halt::face(
                        format!("{} is an ANCHOR — refused at the prefix, ahead of any frame", one.fingerprint),
                        "the device arm retires device keys; an anchor's retirement needs an anchor session and is a walk of its own",
                        "a lost paper is retired by `skep recover --anchor-lost`; a held one by the anchor REPLACEMENT rotation, LATER",
                    ))
                }
                [one] => out.push(one.fingerprint),
                many => {
                    return Err(Halt::face(
                        format!("`{prefix}` matches more than one enrolled key"),
                        many.iter().map(|e| row_text(&e.fingerprint, records)).collect::<Vec<_>>().join("\n  "),
                        "give a longer prefix; never a pick",
                    ))
                }
            }
        }
        return Ok(out);
    }
    let unheld: Vec<Fingerprint> = set.enrolled.iter().filter(|e| !e.anchor && !held.contains(&e.fingerprint)).map(|e| e.fingerprint).collect();
    match unheld.as_slice() {
        [] => {
            say(person, "AUTH-5.47", "no enrolled non-anchor fingerprint stands that this store does not hold: nothing is retired at R4");
            Ok(Vec::new())
        }
        [one] => {
            say(person, "AUTH-5.47", format!("the DEFAULT: the one enrolled non-anchor fingerprint this store does not hold — {}", row_text(one, records)));
            Ok(vec![*one])
        }
        many => {
            let list: Vec<String> = many.iter().map(|f| format!("{}\n      {}", row_text(f, records), group_hex(&f.to_hex()).replace('\n', "\n      "))).collect();
            let answer = person
                .ask(Public(Question {
                    text: format!(
                        "more than one enrolled non-anchor key is not held here — which were LOST or STOLEN? answer by fingerprint prefix (space-separated; empty for none):\n  {}\n> ",
                        list.join("\n  ")
                    ),
                }))
                .map_err(|_| abandoned())?;
            for token in answer.split(|c: char| c.is_whitespace() || c == ',').filter(|t| !t.is_empty()) {
                let prefix = token.to_ascii_lowercase();
                let matches: Vec<&Fingerprint> = many.iter().filter(|f| f.to_hex().starts_with(&prefix)).collect();
                match matches.as_slice() {
                    [one] => out.push(**one),
                    _ => return Err(Halt::face(format!("`{prefix}` names no single key of the list"), "pick by a prefix of at least one R42 group", "re-run with `--lost <fp-prefix>`")),
                }
            }
            Ok(out)
        }
    }
}

/// ONE retirement under the anchor session: `preview(removed)`, the typed
/// answer, `DepositKind::Retire` under the anchor's hand. A key R0's set did
/// not hold was ENROLLED SINCE the walk began, and its row says so — read
/// off the walk's own reads, never passed in.
#[allow(clippy::too_many_arguments)]
fn retire_one(board: &Board, person: &mut dyn Person, session: &Session<'_>, hand: &HybridSigner, reads: &Reads, set: &KeySet, records: &Records, fp: &Fingerprint, held: &[Fingerprint], site: PreviewSite) -> Result<(), Halt> {
    let closure = head_closure(board, person, &reads.walk.set_account, fp)?;
    let since = reads.walk.set.enrolled(fp).is_none();
    let rows = [Row::of(fp, set, Some(records), held, None, since)];
    match preview(person, &Preview { account: &reads.walk.set_account, set, rows: &rows, closure: &closure, held, site, own_board: reads.cell.own_board() })? {
        Previewed::Confirmed => {}
        Previewed::Declined => return Err(declined("retirement")),
        Previewed::Unwritable => return Err(Halt::face("the retirement would empty the set", "`would_empty` armed: unreachable under an anchor session, the anchor standing enrolled", "this is this client's frame")),
    }
    let id = format!("recover.retire.{}", &fp.to_hex()[..8]);
    match deposit(board, session.token(), &Deposit { home: &reads.home, subject: &reads.walk.set_account, kind: DepositKind::Retire(vec![*fp]), hand: Some(hand), id: &id }) {
        Ok(DepositOutcome::Deposited { .. }) => Ok(()),
        Ok(DepositOutcome::Committed { reason }) => {
            say(person, "AUTH-5.17", format!("reconciled: {reason}"));
            Ok(())
        }
        Err(DepositHalt::SessionClosed(_)) => Err(closed_arm(board, reads, &session.fingerprint())),
        Err(other) => Err(other.into()),
    }
}

/// The `closed` path's ONE ARM PER E2 TRIGGER (AUTH-5.27), taken where a
/// deposit under the anchor session met the death signal
/// ([`DepositHalt::SessionClosed`]). A retirement ends a session only where it
/// names the key that OPENED it (AUTH-4.63), so the one key this face reads is
/// `session_key`: retired, it was ANOTHER hand's act, the hand named from the
/// records (AUTH-5.77) — another anchor standing retired says nothing of this
/// session, and the loss arm retires the lost paper itself. Otherwise the
/// daemon's restart (AUTH-5.31; its re-open meeting a block is the block's
/// arm) — derived from `key_set` and the records, never a silent re-import.
/// The SEEDED trigger arises only by reference, and is no arm here: both of
/// this walk's arms run R0 as walks that enroll, which halts a by-reference
/// account, so the session acts as the account whose set it is.
fn closed_arm(board: &Board, reads: &Reads, session_key: &Fingerprint) -> Halt {
    if let Ok(KeySetAnswer::Set(now)) = board.key_set(&reads.walk.set_account) {
        if now.retired(session_key).is_some() {
            let hand = credential_records(board, &reads.walk.set_account, &[]).ok().and_then(|records| {
                let rec = records.retirement_of(session_key)?;
                match (&rec.hand, rec.position) {
                    (Hand::Key(h), Some(at)) => Some(format!("retired at position {at} by {h} ({})", records.label_of(h).map(|l| render_inert(&l)).unwrap_or_default())),
                    _ => None,
                }
            });
            return Halt::face(
                format!("the anchor session died under the walk: the anchor {session_key} was retired by ANOTHER hand"),
                hand.unwrap_or_else(|| "the hand and the position were not readable at this board — no hand is asserted (AUTH-5.77's no-hand form)".into()),
                "AUTH-5.77: no act on this key opens anything; import another anchor of this account where one stands enrolled",
            );
        }
    }
    Halt::face(
        "the anchor session died under the walk",
        "the daemon restarted (AUTH-5.31), or the account was listed under the walk — a re-open meeting `403 prefix_blocked` is the BLOCK's arm (RES-65)",
        "re-run `skep recover`: the walk resumes at the first undone state by reading `key_set`; a standing anchor-grade token on a hosted board dies only at the daemon's restart — the operator's reach, not yours",
    )
}

/// THE RECOVERY READ (AUTH-5.89; `client.md` §4a.2 R6), on the STOLEN arm:
/// the closure for the stolen fingerprint, the agent space, the cone — every
/// returned genesis shown, the witness question, the seized class, the
/// report per A4 cell.
fn recovery_read(board: &Board, person: &mut dyn Person, reads: &Reads, stolen: &[Fingerprint], own: &[(Fingerprint, PublicKey)]) -> Result<Vec<String>, Halt> {
    let a = reads.walk.set_account.clone();
    say(person, "AUTH-5.89 (cost)", "THE RECOVERY READ over every space the stolen key could open: one `next_account_prefix`, one `key_set` and one `effective_owner` per account, with the admitted record read beneath each — seconds at a notebook with a few topics, minutes at hundreds of subdivisions; the accounts walked are counted as it runs; an interruption re-runs the read");
    let mut walked: Vec<String> = vec![a.clone(), first_child(&a)];
    for fp in stolen {
        let closure = head_closure(board, person, &a, fp)?;
        for admitted in closure.accounts {
            if !walked.contains(&admitted.account) {
                walked.push(admitted.account);
            }
        }
    }
    let cone = by_reference_cone(board, person, &walked)?;
    for node in &cone.nodes {
        if !node.seeded && !walked.contains(&node.account) {
            walked.push(node.account.clone());
        }
    }
    say(person, "AUTH-5.89 (cost)", format!("{} account(s) walked, {} reads", walked.len(), cone.reads));
    // Every returned genesis: an enrollment homed in a walked doc 1 whose
    // subject is another account.
    let mut returned: Vec<(String, String, String)> = Vec::new(); // (subject, home, rendering)
    for w in &walked {
        for (link, subject) in enroll_links_homed(board, &doc_1_of(w))? {
            if subject == *w || returned.iter().any(|(s, _, _)| *s == subject) {
                continue;
            }
            let rec = credential_records(board, &subject, own).ok();
            let genesis = rec.as_ref().and_then(|r| r.genesis().cloned());
            let line = match genesis {
                Some(g) => match (&g.hand, g.position) {
                    (Hand::Key(hand), Some(at)) => {
                        let label = rec.as_ref().and_then(|r| r.label_of(hand)).or_else(|| reads.records.label_of(hand)).map(|l| render_inert(&l)).unwrap_or_else(|| "no label".into());
                        let marker = if stolen.contains(hand) { " — THE STOLEN KEY's" } else { "" };
                        format!("{subject}: genesis written by {hand} ({label}) at position {at}, homed in {}{marker}", g.home)
                    }
                    (Hand::Bare, Some(at)) => format!("{subject}: genesis written by a bare session at position {at}, homed in {}", g.home),
                    _ => format!("{subject}: genesis homed in {} — UNATTRIBUTABLE: the writing key and the position are not readable at this board's retention (AUTH-5.91's disposition)", g.home),
                },
                None => format!("{subject}: an enrollment link at {link} whose record could not be read — UNATTRIBUTABLE"),
            };
            returned.push((subject, w.clone(), line));
        }
    }
    let mut lines = Vec::new();
    if returned.is_empty() {
        say(person, "AUTH-5.89", "the read returned NO genesis beneath the spaces the stolen key could open: nothing was delegated and seeded there");
    } else {
        say(person, "AUTH-5.89", format!("GENESES RETURNED:\n  {}", returned.iter().map(|(_, _, l)| l.clone()).collect::<Vec<_>>().join("\n  ")));
    }
    // The boundary line (AUTH-5.89, pinned) and R4's residual.
    let boundary = "THE BOUNDARY LINE: accounts the thief DELEGATED remain live under the thief's keys — neither retirable nor removable — surfaced as permanent residue beside what this walk closed, never promised away; accounts of your own the thief SEIZED remain live under the thief's keys with everything you filed there, neither retirable nor re-seedable (I5), surfaced as SEIZED and never as a delegation of the thief's; and a hand enrolling at machine rate can survive R4's rounds — TERMINATION IS NOT GUARANTEED".to_string();
    say(person, "AUTH-5.89", boundary.clone());
    lines.push(boundary);
    let mut marked: Vec<String> = Vec::new();
    if !returned.is_empty() {
        let answer = person
            .ask(Public(Question {
                text: "WHICH OF THESE ARE ACTS OF YOUR OWN — a handoff (`skep handoff`), or beneath your agent space a hire? The key is the tell and you are the witness: your custody pile names your ANCHORED hires by address and label; an ANCHORLESS hire leaves no paper; a plant under a label you also use is told apart by the ADDRESS alone — and a plant you mark as your own is the class this read cannot close (AUTH RES-184). Answer the addresses, space-separated, or `none`:\n> ".into(),
            }))
            .map_err(|_| abandoned())?;
        for token in answer.split(|c: char| c.is_whitespace() || c == ',').filter(|t| !t.is_empty() && *t != "none") {
            if returned.iter().any(|(s, _, _)| s == token) {
                marked.push(token.to_string());
            } else {
                say(person, "AUTH-5.89", format!("`{token}` is none of the addresses returned; ignored"));
            }
        }
    }
    let unmarked: Vec<&(String, String, String)> = returned.iter().filter(|(s, _, _)| !marked.contains(s)).collect();
    for (subject, home, _) in &unmarked {
        let line = format!(
            "{subject} (genesis in {home}) is not yours: where you delegated it, THIS WAS YOUR SPACE and what was filed in it is theirs now — SEIZED, never a delegation of the thief's; where the thief delegated it, it remains live under the thief's keys; the report is the one instrument over it"
        );
        say(person, "AUTH-5.89 (seized)", line.clone());
        lines.push(line);
    }
    // THE REPORT PER A4 CELL (AUTH-5.60 step 4; AUTH RES-174).
    let prefixes: Vec<String> = unmarked.iter().map(|(s, _, _)| s.clone()).collect();
    let cell_line = match &reads.cell {
        A4Cell::Served => format!(
            "THE REPORT, to THIS BOARD'S OPERATOR, over the prefixes you did not mark ({}): one blocked-prefix entry per prefix the thief seeded, each covering that account and everything beneath it (AUTH-4.70) — the only mechanism on a served board that ends a live account's future writes; an entry over a handoff of your own would refuse its recipient and one over a hire of your own would end your own agent, which is why only the unmarked are reported; nothing is erased and no key is touched. The DISAVOWAL is a content act of your own, which this library does not perform",
            if prefixes.is_empty() { "none".to_string() } else { prefixes.join(", ") }
        ),
        A4Cell::LoopbackNotebook => format!(
            "NO REPORT at a loopback-bound notebook: local forever, host and owner one party — the retirement alone ends the thief's writes under the retired key (AUTH-4.63){}; the DISAVOWAL stands as your own content act",
            if prefixes.is_empty() { String::new() } else { format!(", SAVE at a SEIZED account ({}), whose set no retirement names: there the act is your own as this board's operator — the blocked-prefix entry, arriving with the takedown record and not before", prefixes.join(", ")) }
        ),
        A4Cell::BindOverrideNotebook => format!(
            "YOUR OWN ACTS at a bind-override notebook: WITHDRAWING THE OVERRIDE — the board bound and configured on loopback again and restarted — ends every remote party's reach and every session, your own remote devices' included (a total denial, not a targeted one); and your own blocked-prefix list, one entry per prefix the thief seeded ({}), arriving with the takedown record and not before",
            if prefixes.is_empty() { "none".to_string() } else { prefixes.join(", ") }
        ),
        A4Cell::HandoffRecipient { giver } => format!(
            "THE REPORT, to {giver} as this board's operator (AUTH RES-174): over the prefixes the read returned at your own account less your own acts ({}); the giver's act is the blocked-prefix entry of their own list, arriving with the record and not before, or the withdrawal of their override named with its cost — and what stands until that hand acts is stated, never reported closed",
            if prefixes.is_empty() { "none".to_string() } else { prefixes.join(", ") }
        ),
    };
    say(person, "AUTH-5.60 step 4", cell_line.clone());
    lines.push(cell_line);
    Ok(lines)
}

/// THE WALK.
pub fn recover(board: &Board, store: &FileStore, person: &mut dyn Person, opts: &RecoverOptions) -> Result<Recovered, Halt> {
    if opts.anchor_lost {
        return loss_arm(board, store, person, opts);
    }
    // The STORE holds a device key for this walk — ahead of every read.
    let devices = device_key_for(store)?;
    let own: Vec<(Fingerprint, PublicKey)> = devices.iter().map(|d| (d.fingerprint, d.public.clone())).collect();
    let held: Vec<Fingerprint> = own.iter().map(|(f, _)| *f).collect();
    // LOST or STOLEN, at the walk's head ahead of every read (§4a.1; §4a.2
    // R6: the stolen arm's recovery read is priced at the choice).
    let stolen = match opts.stolen {
        Some(s) => s,
        None => person.yes_no(Public(Question { text: "was the device STOLEN (yes), or LOST (no)? Only the stolen arm walks what the thief holds, and it costs the recovery read".into() })).map_err(|_| abandoned())?,
    };
    if stolen {
        say(person, "AUTH-5.60 step 1", "STOLEN: what the thief holds — the machine, the loopback board and the key store, so the enrolled device key and sessions as you on the thief's own copy, and every draft ever written at a venue whose only confidentiality is locality; a retirement written here reaches the thief's copy not at all; R4 runs AHEAD of R3 and repeats against a re-read `key_set`");
    }
    // R0.
    let reads = r0(board, person, opts.principal, Act::Enrollment, &own)?;
    let account = reads.account.clone();
    // NO anchor flagged ⇒ AUTH-5.16's second arm.
    if !reads.walk.set.has_anchor() {
        return Err(Halt::face(
            format!("no anchor is enrolled at {}: the act is impossible on this account permanently", reads.walk.set_account),
            "AUTH-5.16's second arm — a paper import needs an enrolled anchor, and none stands",
            "the acts that exist: AUTH-5.32's hop from a device still signed in (`skep keygen --payload` here, `skep enroll` there, `skep bind` here); where none is, nothing on this account — R46's succession, a fresh board (its residue per mode: draft-only forever in CLAIMED-PERMISSIVE, read-only forever in ENFORCING; everything shared stays shared)",
        ));
    }
    let (device, resumed) = pick_device(devices, &reads.walk.set)?;
    if resumed {
        say(person, "AUTH-5.56", format!("resumed: the device key {} is already enrolled at {} — R3 stands done, read off `key_set`; the walk continues at R4", device.fingerprint, reads.walk.set_account));
    }
    // R1: WHOSE ACCOUNT, then the import.
    let whose = whose_account(person, &account, opts.principal)?;
    let cx = ImportContext { board, store, account: &account, principal: opts.principal, set_account: &reads.walk.set_account, set: &reads.walk.set, records: &reads.records, own: &own, anchor_path: opts.anchor.as_deref(), whose, cell: &reads.cell };
    let anchor: ImportedAnchor = match import_anchor(person, &cx)? {
        ImportOutcome::Anchor(a) => *a,
        ImportOutcome::Neither => return Err(no_artifact_face(person, &cx)),
    };
    // R2: THE ANCHOR SESSION (FULL), the seed held for the records.
    let session = handshake(board, Scope::Full, &anchor.signer, opts.principal, Site::Recover)?;
    say(person, "§4a.3", "the anchor session is open; the seed is held for the records this walk signs with it and dropped at the last of them — inside AUTH-5.54 step 3's mirror; a crash before the close leaves this anchor-grade token standing until the daemon restarts (your act at a notebook; the operator's reach at a hosted board)");
    let mut retired: Vec<Fingerprint> = Vec::new();
    let mut warnings = Vec::new();
    let result = (|| -> Result<Recovered, Halt> {
        let fs_reads = FirstSessionReads::take(board, &account, &anchor.fingerprint, Some(store))?;
        // R3's CLASS ANSWER FIRST: an agent's ⇒ the containment act.
        if whose == Whose::Agent {
            say(
                person,
                "AUTH-5.64",
                format!(
                    "THE ENROLLMENT IS REFUSED: this is an AGENT's account and enrolling this store's device key ({}) into its set would be a half burn with the wrong key — permanent under I4, with the agent's working key retired and no fresh working pubkey fetched (no fetch channel ships). The ANCHORED ARM's act for this hour, offered from the session this walk holds: RETIRE THE NON-ANCHOR SET AND ENROLL NOTHING — the commit kills that party's sessions (AUTH-4.63) and leaves nothing it can open, the account inert-but-alive under papers the compromise never touched; then remediate or provision, then RETURN AND ENROLL over a host you have remediated. This is not the burn: no working pubkey is fetched, the host is not remediated by it, nothing already written is undone.",
                    device.fingerprint
                ),
            );
            let take = person.yes_no(Public(Question { text: "retire every enrolled non-anchor fingerprint of this account now, enrolling nothing?".into() })).map_err(|_| abandoned())?;
            if !take {
                return Err(Halt::face("the containment act was declined: nothing was written", "the account stands anchored, the act untaken — never the anchorless arm's", "re-run when ready"));
            }
            // `first_session`'s FIRST STATE ALONE (RULED 2026-10-04).
            if mint_home(board, &fs_reads, &session)? {
                say(person, "AUTH-5.90 (iii)", format!("the home {} was minted (the first state alone; the setup state never runs at an agent's account)", fs_reads.home));
            }
            let mut set = reads.walk.set.clone();
            let mut records = reads.records.clone();
            for _ in 0..8 {
                let Some(fp) = set.enrolled.iter().find(|e| !e.anchor && !retired.contains(&e.fingerprint)).map(|e| e.fingerprint) else { break };
                retire_one(board, person, &session, &anchor.signer, &reads, &set, &records, &fp, &held, PreviewSite::RecoverDevice)?;
                retired.push(fp);
                set = reread(board, &reads.walk.set_account)?;
                records = credential_records(board, &reads.walk.set_account, &own)?;
            }
            say(person, "AUTH-5.64", format!("contained: {} non-anchor key(s) retired, nothing enrolled; `inc(A, 1)` was not delegated", retired.len()));
            return Ok(Recovered { facts: Facts { account: account.clone(), principal: opts.principal, origin: board.dialed().clone() }, enrolled: Vec::new(), retired: retired.clone(), binding_line: None, containment: true, recovery_read: Vec::new(), warnings: Vec::new() });
        }
        // The R4 rounds (a closure over the shared state).
        let mut set = reads.walk.set.clone();
        let mut records = reads.records.clone();
        let picked = targets(person, &set, &records, &held, &opts.lost)?;
        let kept: Vec<Fingerprint> = set.enrolled.iter().filter(|e| !e.anchor && !picked.contains(&e.fingerprint)).map(|e| e.fingerprint).collect();
        let mut accounted: Vec<Fingerprint> = kept;
        accounted.push(device.fingerprint);
        let r4 = |person: &mut dyn Person, set: &mut KeySet, records: &mut Records, mut round_targets: Vec<Fingerprint>, retired: &mut Vec<Fingerprint>| -> Result<(), Halt> {
            let mut rounds = 0usize;
            loop {
                for fp in &round_targets {
                    retire_one(board, person, &session, &anchor.signer, &reads, set, records, fp, &held, if stolen { PreviewSite::RecoverStolen } else { PreviewSite::RecoverDevice })?;
                    retired.push(*fp);
                    *set = reread(board, &reads.walk.set_account)?;
                }
                if !stolen {
                    return Ok(());
                }
                // THE RE-READ after each round: a fingerprint appearing
                // between rounds is shown as what it is.
                *set = reread(board, &reads.walk.set_account)?;
                let unaccounted: Vec<Fingerprint> = set.enrolled.iter().filter(|e| !e.anchor && !accounted.contains(&e.fingerprint) && !retired.contains(&e.fingerprint)).map(|e| e.fingerprint).collect();
                if unaccounted.is_empty() {
                    return Ok(());
                }
                rounds += 1;
                if rounds > 8 {
                    say(person, "AUTH-5.64 (residual)", "eight rounds and a hand still enrolling: TERMINATION IS NOT GUARANTEED — the walk stops here with that stated, never reported closed");
                    return Ok(());
                }
                *records = credential_records(board, &reads.walk.set_account, &own)?;
                say(person, "AUTH-5.64", format!("round {rounds}: {} fingerprint(s) ENROLLED SINCE THIS WALK BEGAN — {}", unaccounted.len(), unaccounted.iter().map(|f| row_text(f, records)).collect::<Vec<_>>().join(", ")));
                round_targets = unaccounted;
            }
        };
        if stolen {
            // `first_session` AHEAD OF THE WALK'S FIRST CREDENTIAL WRITE, which
            // on this arm is R4's first retirement, homed in A's doc 1 (§4a.2
            // R4) — a doc 1 that may not stand at a handoff's recipient who
            // never ran `skep bind` (AUTH-5.90 (iii)).
            let done = first_session(board, &fs_reads, &session, &anchor.signer, Some(store))?;
            warnings.extend(done.warnings.clone());
            r4(person, &mut set, &mut records, picked.clone(), &mut retired)?;
        }
        // R3: THE ENROLLMENT PREVIEW and its typed confirmation, then — on the
        // LOST arm, whose first credential write it is — `first_session`, then
        // the enrollment under the anchor's hand.
        if !resumed {
            say(
                person,
                "AUTH-5.46 (enrollment)",
                format!(
                    "ENROLLMENT PREVIEW — this is the walk's one PERMANENT, uncorrectable credential write:\n  account {} (principal {})\n  under the anchor `{}` ({})\n  enrolling the device key {}\n    {}\n    label: {} (public, permanent, the byline on every write this key makes — AUTH-5.42)",
                    account,
                    opts.principal,
                    anchor.label.as_deref().map(render_inert).unwrap_or_else(|| "no label".into()),
                    anchor.fingerprint,
                    device.fingerprint,
                    group_hex(&device.fingerprint.to_hex()).replace('\n', "\n    "),
                    device.label.as_deref().map(render_inert).unwrap_or_else(|| "(none)".into())
                ),
            );
            let expected = device.fingerprint.to_hex()[..8].to_string();
            let typed = person.confirm_typed(Consent(Confirmation { text: "CONFIRM THE ENROLLMENT — type the first 8 hex of the device key's fingerprint, or `no`".into(), expected: expected.clone() })).map_err(|_| abandoned())?;
            if typed.trim().to_ascii_lowercase() != expected {
                return Err(Halt::face("the enrollment was declined at the preview: nothing was enrolled", "the typed answer was not the row", "re-run when ready; the walk resumes by reading"));
            }
            if !stolen {
                let done = first_session(board, &fs_reads, &session, &anchor.signer, Some(store))?;
                warnings.extend(done.warnings.clone());
            }
            let id = format!("recover.enroll.{}", &device.fingerprint.to_hex()[..8]);
            let entry = Enrollment::new(device.public.clone(), false, device.label.clone()).expect("a stored label");
            let outcome = deposit(board, session.token(), &Deposit { home: &fs_reads.home, subject: &account, kind: DepositKind::Enroll(vec![entry]), hand: Some(&anchor.signer), id: &id });
            match outcome {
                Ok(DepositOutcome::Deposited { .. }) => say(person, "AUTH-5.59 step 1", format!("the device key {} is enrolled from the anchor's session", device.fingerprint)),
                Ok(DepositOutcome::Committed { reason }) => say(person, "AUTH-5.17", format!("R3 stands: {reason}")),
                Err(DepositHalt::SetFull(_)) => {
                    // The PERSON-CLASS inversion: R4 first, then R3.
                    say(person, "AUTH-5.13", "the set is full: retire a key you no longer hold first, then this device is enrolled — R4 runs ahead of R3 under this same session");
                    r4(person, &mut set, &mut records, picked.clone(), &mut retired)?;
                    let outcome = deposit(board, session.token(), &Deposit { home: &fs_reads.home, subject: &account, kind: DepositKind::Enroll(vec![Enrollment::new(device.public.clone(), false, device.label.clone()).expect("a stored label")]), hand: Some(&anchor.signer), id: &id })?;
                    if let DepositOutcome::Committed { reason } = outcome {
                        say(person, "AUTH-5.17", format!("R3 stands: {reason}"));
                    }
                }
                Err(DepositHalt::SessionClosed(_)) => return Err(closed_arm(board, &reads, &session.fingerprint())),
                Err(other) => return Err(other.into()),
            }
        }
        if !stolen {
            // THE LOST ARM keeps R3 → R4.
            r4(person, &mut set, &mut records, picked.clone(), &mut retired)?;
        } else {
            // COMPLETION IS THE READ MADE AFTER R3's ENROLL COMMITS.
            r4(person, &mut set, &mut records, Vec::new(), &mut retired)?;
        }
        Ok(Recovered { facts: Facts { account: account.clone(), principal: opts.principal, origin: board.dialed().clone() }, enrolled: vec![device.fingerprint], retired: retired.clone(), binding_line: None, containment: false, recovery_read: Vec::new(), warnings: warnings.clone() })
    })();
    // R5: the mirror's close — the session, and the placed copy destroyed.
    let _ = session.close();
    anchor.dispose(person);
    say(person, "AUTH-5.54 step 3", "the anchor session is closed and the imported seed dropped (the Ed25519 half wiped; the ML-DSA half's wipe is open work)");
    let mut done = result?;
    if done.containment {
        return Ok(done);
    }
    // R6: the binding, the three facts, the stolen arm's recovery read.
    let line = Binding::Enrollment { origin: board.dialed().clone(), principal: opts.principal, account: account.clone(), fingerprint: device.fingerprint };
    if let Err(w) = store.bind(&line) {
        done.warnings.push(w.to_string());
    }
    done.binding_line = Some(line.to_string());
    if stolen {
        done.recovery_read = recovery_read(board, person, &reads, &done.retired, &own)?;
    }
    say(person, "AUTH-5.28", "THE EXPECTED END: sign in with the new key — `skep session` — never an anchor import");
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::EnrolledKey;
    use crate::sheet::{KeyFile, Label, Seed};

    fn set(fps: &[(u8, bool)]) -> KeySet {
        let mut s = KeySet::default();
        for (b, anchor) in fps {
            let signer = crate::sign::signer_from_seed(&[*b; 32]);
            let key = HybridSigner::public_key(&signer).clone();
            s.enrolled.push(EnrolledKey { fingerprint: Fingerprint::of(&key), key, anchor: *anchor });
        }
        s
    }

    /// A device key's public facts, as the store's lookup answers them.
    fn facts(seed: u8) -> KeyFacts {
        let file = KeyFile::new(Seed::new([seed; 32]), false, Label::new(&format!("device {seed}")).ok(), None);
        KeyFacts { path: format!("{seed}.key").into(), fingerprint: file.fingerprint, public: file.public.clone(), label: file.label.clone(), anchor: false }
    }

    /// The store's device key for the walk, picked off its public facts: the
    /// enrolled one resumes; one fresh key is the key; a retired-only store
    /// is I4's halt.
    #[test]
    fn the_device_key_is_picked_by_its_diagnosis() {
        let fresh = facts(1);
        let (picked, resumed) = pick_device(vec![fresh.clone()], &set(&[(9, true)])).unwrap();
        assert_eq!((picked.fingerprint, resumed), (fresh.fingerprint, false));
        let (picked, resumed) = pick_device(vec![fresh.clone(), facts(2)], &set(&[(9, true), (2, false)])).unwrap();
        assert_eq!((picked.fingerprint, resumed), (facts(2).fingerprint, true), "the enrolled key resumes");
        let mut retired = set(&[(9, true)]);
        retired.retired.push(crate::board::RetiredKey { fingerprint: fresh.fingerprint, anchor: false });
        let err = pick_device(vec![fresh], &retired).unwrap_err();
        assert!(err.to_string().contains("I4 (AUTH-2.98)"), "{err}");
    }
}
