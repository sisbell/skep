//! `handoff` — THE GIVER's walk (`client.md` §4c.2 G0–G6; AUTH-5.90's door),
//! TWO INVOCATIONS: without `--payload`, G0's payload-free reads then G2 =
//! beat (a) — `delegate(new_prefix = --account, new_id)` with `new_id`
//! PERSISTED before the frame as a binding line (§4.3's persist-first rule;
//! AUTH-5.20; AUTH-5.19's read-back) — and the ADDRESS printed; IDEMPOTENT.
//! With `--payload`: G0 whole — `--account` in the giver's subtree with its
//! set EMPTY (AUTH-6.19's signal); the set that opens it by AUTH-5.21's walk
//! and its GRADE (AUTH-3.21's exception: anchor-grade where that set holds
//! an anchor, the giver's anchor then IMPORTED); THE OWNERSHIP TEST = where
//! that walk TERMINATES, the giver's own account, and a terminus that is
//! another party's a HALT (containment is NOT the test); `effective_owner`
//! (the seat, or beat (a) owed); the GIVING account's doc 1 (or beat (b)
//! owed); `parse_enroll` with `enroll`'s own comparison beat (AUTH-4.59;
//! AUTH-5.39); THE LATCH's test client-side first (AUTH-2.71) with the
//! declined board-wide check's residue said; the precondition that the
//! recipient's client can dial this board (RES-187). G1 the strings
//! (i)–(iv), (viii)/(ix) by NUMBER and the ANCHORLESS line (AUTH-5.16's
//! second arm; AUTH-5.62 (ii)); a typed confirmation. G3 = beat (b) the
//! giving account's home mint, idempotent by reading (AUTH-2.109). G4 =
//! beat (c) THE GENESIS — `DepositKind::EnrollVerbatim` homed in THE DOC 1 OF
//! THE ACCOUNT THE SUBDIVISION HANGS FROM (AUTH-2.62; AUTH-2.127), the
//! session acting AS that account (by reference below depth 1, AUTH-4.30
//! (i)), the grade as G0 read it. G5 = beat (d) the retry (AUTH-5.17;
//! AUTH-5.18's containment; the LATCH's face scoped to the home). G6 the
//! three facts for string (vii), the mirror's close, the giver's own
//! sessions AS the given account dead from the commit (AUTH-4.63). A
//! top-level `--account` HALTS: no door at the bootstrap tier (AUTH-5.90's
//! last clause).

use std::fmt;
use std::path::PathBuf;

use skep_identity::{Fingerprint, PublicKey};

use super::say;
use crate::address::{doc_1_of, first_child, parent_account};
use crate::board::{acked_addr, frames, Answer, Board, KeySetAnswer, Rejection, Scope};
use crate::ceremony::deposit::{deposit, Deposit, DepositHalt, DepositKind, DepositOutcome};
use crate::ceremony::enumerate::by_reference_cone;
use crate::ceremony::first_session::{delegate_persisted, document_present, persisted, Delegated};
use crate::ceremony::handshake::{handshake, key_face, Session, Site};
use crate::ceremony::import::{import_anchor, ImportContext, ImportOutcome, ImportedAnchor, Whose};
use crate::ceremony::payload::{compare_payload, parse_payload, payload_text};
use crate::ceremony::reads::A4Cell;
use crate::derive::records::credential_records;
use crate::derive::{precheck, principal_of, walk_to_set, Mode};
use crate::halt::Halt;
use crate::person::{Confirmation, Consent, Person};
use crate::sheet::Facts;
use crate::sign::Signer;
use crate::store::{arm4_face, FileStore, KeyFacts, KeySelector, KeyStore, Purpose, StoreError};

/// The command's inputs.
#[derive(Debug, Clone)]
pub struct HandoffOptions {
    pub principal: u64,
    /// `--account <address>`: the subdivision.
    pub account: String,
    /// `--payload <file|->`: the recipient's record — the second invocation.
    pub payload: Option<Vec<u8>>,
    /// `--anchor <path>`: the giver's anchor file, where the act is
    /// anchor-grade.
    pub anchor: Option<PathBuf>,
}

/// The genesis's GRADE (AUTH-3.21's exception): ANCHOR-grade wherever the
/// set that opens the subdivision holds an anchor — the giver's paper
/// anchor imported to sign it — DEVICE-grade where that set holds none. G0
/// reads it off the set; the hand the deposit signs with carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grade {
    Device,
    Anchor,
}

/// The grade as a person reads it: `device` or `anchor`.
impl fmt::Display for Grade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Grade::Device => "device",
            Grade::Anchor => "anchor",
        })
    }
}

/// What the walk did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffOutcome {
    /// Beat (a): the subdivision delegated (or found delegated) — its
    /// address and the principal seated there.
    Delegated { account: String, principal: u64, already: bool },
    /// Beats (b)–(d): the genesis written; the three facts for the reply.
    Seeded { facts: Facts, grade: Grade, reconciled: bool, warnings: Vec<String> },
}

/// G0's payload-free reads.
struct G0 {
    giver_account: String,
    /// The giver's device key, its public facts — its signer is the store's.
    giver_key: KeyFacts,
    /// The account the subdivision hangs from.
    giving: String,
    /// The principal seated at `--account`, where beat (a) stands done.
    principal: Option<u64>,
    /// The set that opens `--account` (the walk's terminus) and its anchor
    /// grade.
    set: crate::board::KeySet,
    set_account: String,
    grade: Grade,
    cell: A4Cell,
    health: crate::board::Health,
}

fn g0(board: &Board, store: &FileStore, person: &mut dyn Person, opts: &HandoffOptions) -> Result<G0, Halt> {
    let account = opts.account.trim().to_string();
    let Some(giving) = parent_account(&account) else {
        return Err(Halt::face(
            format!("{account} is a top-level address: at the bootstrap tier there is no handoff and no door"),
            "a second top-level account is a sibling no by-reference resolution reaches, and v1 has no gesture that creates one (AUTH-5.90's last clause)",
            "hand off a SUBDIVISION of your own account (`<your account>.2` and beyond)",
        ));
    };
    let key = match store.select(&KeySelector::Board { origin: board.dialed(), principal: Some(opts.principal) }, Purpose::Sign) {
        Ok(key) => key,
        Err(StoreError::NoSelection { keys }) => {
            return Err(arm4_face(store, &keys, Mode::of(&board.health()?)));
        }
        Err(e) => return Err(e.into()),
    };
    let pre = precheck(board, opts.principal, &key.fingerprint)?;
    key_face(board, &pre.walk, &key.fingerprint, &[(key.fingerprint, key.public.clone())], Site::Giver)?;
    let giver_account = pre.account.clone();
    if !account.starts_with(&format!("{giver_account}.")) {
        return Err(Halt::face(format!("{account} is not in your subtree"), format!("your account is {giver_account}; a handoff gives away a subdivision beneath it"), "name an address beneath your account"));
    }
    // The set that opens `--account`: AUTH-5.21's walk from it (or from the
    // giving account where the seat is not yet allocated); THE OWNERSHIP
    // TEST is where it TERMINATES.
    let principal = principal_of(board, &account)?;
    let own_set = match board.key_set(&account)? {
        KeySetAnswer::Set(s) => s,
        KeySetAnswer::NotAnAccount => Default::default(),
    };
    if !own_set.enrolled.is_empty() {
        return Err(Halt::face(
            format!("{account} already holds a key set of its own: it is already another party's"),
            "a NON-EMPTY `key_set` is exactly the signal that the account has been handed away (AUTH-6.19); a second genesis meets the latch (AUTH-2.71; I5)",
            "nothing of yours re-opens it (AUTH-5.90 clause 1); hand off another subdivision",
        ));
    }
    let walk = walk_to_set(board, if principal.is_some() { &account } else { &giving })?;
    if walk.set_account != giver_account {
        return Err(Halt::face(
            format!("{account} is not yours to give: the set that opens it stands at {}, another party's", walk.set_account),
            "THE OWNERSHIP TEST is where AUTH-5.21's walk terminates, never prefix containment: a subdivision beneath an account you handed away is that party's to give (AUTH-5.90; AUTH-5.59's scope)",
            "hand off a subdivision that still opens against your own set",
        ));
    }
    let grade = if walk.set.has_anchor() { Grade::Anchor } else { Grade::Device };
    let health = board.health()?;
    let cell = A4Cell::of(board, &health, &giver_account, &walk)?;
    say(
        person,
        "AUTH RES-187",
        match cell {
            A4Cell::LoopbackNotebook => "THE PRECONDITION: the board must be one the recipient's client can dial. This is a LOOPBACK-BOUND notebook, which only a co-resident client dials — a handoff to any other party presupposes the bind-override standing FIRST (the operator's own act, AUTH-4.7, with the cost AUTH-5.35 (a) states); a door run to its last beat for a party who cannot dial the board has given the subdivision away all the same",
            _ => "THE PRECONDITION: the board must be one the recipient's client can dial — every beat of theirs (the sign-in, the doc-1 mint, the setup act, the reply's use) is a request to this board",
        },
    );
    Ok(G0 { giver_account, giver_key: key, giving, principal, set: walk.set, set_account: walk.set_account, grade, cell, health })
}

/// G2 = beat (a): the delegate under a persisted `new_id` — §4.3's
/// persist-first form, `first_session`'s own (§4c.2 G2: "the same rule, the
/// same form, not a second one") — idempotent by the seat's read; what is
/// the site's is the address said on a delegate sent, and the face where
/// the address is no delegable child. Answers the principal seated at the
/// address, and whether beat (a) already stood.
fn g2(board: &Board, store: &FileStore, person: &mut dyn Person, g: &G0, session: &Session<'_>, account: &str) -> Result<(u64, bool), Halt> {
    if let Some(principal) = g.principal {
        say(person, "AUTH-5.90 (a)", format!("beat (a) stands done: {account} is seated (principal {principal}) — found by reading, no second delegate is sent"));
        return Ok((principal, true));
    }
    let mut warnings = Vec::new();
    let cached = persisted(board, Some(store), account);
    let outcome = delegate_persisted(board, session, Some(store), cached, account, &g.giver_key.fingerprint, &format!("handoff.delegate.{account}"), &mut warnings);
    for w in warnings {
        say(person, "§4.3", w);
    }
    match outcome? {
        Delegated::Committed { principal, sent: true } => {
            say(person, "AUTH-5.90 (a)", format!("beat (a): {account} delegated (principal {principal}); hand this ADDRESS to the recipient over the out-of-band channel the keys come back on — they run `skep accept --board {} --account {account}`", board.dialed()));
            Ok((principal, false))
        }
        Delegated::Committed { principal, sent: false } => Ok((principal, true)),
        Delegated::Seated(principal) => Ok((principal, true)),
        Delegated::NotAuthorized => Err(Halt::face(
            format!("`delegate` of {account} was refused `not_authorized`"),
            "the address is not the next delegable child of its parent (children are contiguous: obtain the address from `next_account_prefix`), or the parent is not yours",
            format!("the next delegable address under {} is what `next_account_prefix` answers; name that", g.giving),
        )),
    }
}

/// THE WALK.
pub fn handoff(board: &Board, store: &FileStore, person: &mut dyn Person, opts: &HandoffOptions) -> Result<HandoffOutcome, Halt> {
    let account = opts.account.trim().to_string();
    let g = g0(board, store, person, opts)?;
    let device = store.signer(&KeySelector::Path(&g.giver_key.path))?;
    // The session acts AS the giving account: the giver's own at depth 1,
    // BY REFERENCE below it (AUTH-4.30 (i)) — for beat (a)'s delegate (only
    // the owner of the parent delegates under it) and for beat (c)'s
    // genesis (ω admits the write from no other, AUTH-3.32).
    let session_principal = if g.giving == g.giver_account { opts.principal } else { principal_of(board, &g.giving)?.ok_or_else(|| Halt::face(format!("{} has no seat", g.giving), "the giving account is unallocated: delegate it first (`skep handoff --account` at that address)", "hand off the giving account's own parent first"))? };
    // FIRST INVOCATION: beat (a) alone, the address printed.
    let Some(payload) = &opts.payload else {
        if let Some(principal) = g.principal {
            return Ok(HandoffOutcome::Delegated { account, principal, already: true });
        }
        let session = handshake(board, Scope::Full, &*device, session_principal, Site::Giver)?;
        let out = g2(board, store, person, &g, &session, &account);
        let _ = session.close();
        let (principal, already) = out?;
        return Ok(HandoffOutcome::Delegated { account, principal, already });
    };
    // SECOND INVOCATION: G0 whole.
    let Some(principal) = g.principal else {
        return Err(Halt::face(
            format!("{account} is not yet delegated: beat (a) is still owed"),
            "`effective_owner` answers the seat above, not this address (AUTH-6.37's allocation test)",
            format!("run `skep handoff --board {} --account {account}` without `--payload` first, and hand the recipient the address", board.dialed()),
        ));
    };
    let text = payload_text(payload)?;
    let entries = parse_payload(&text)?;
    let payload_fps: Vec<Fingerprint> = entries.iter().map(|e| Fingerprint::of(&e.key)).collect();
    // THE LATCH's test, client-side FIRST (AUTH-2.71), with the declined
    // board-wide check's residue said.
    if let Some(fp) = payload_fps.iter().find(|fp| g.set.enrolled(fp).is_some() || g.set.retired(fp).is_some()) {
        return Err(Halt::face(
            format!("the payload names a key that already stands in the set that opens {account}: {fp}"),
            "the fold's latch refuses a genesis naming any key of the set above (AUTH-2.71): a handoff gives an account to a party that could not already open it (AUTH-5.90)",
            "string (ii): use THEIR keys, not yours — ask the recipient for a NEW key made for this account",
        ));
    }
    say(person, "AUTH-5.90", "what the latch does NOT test, said: it reaches the set ABOVE and no other set on this board (a board-wide disjointness test is DECLINED), so a key that already opens ANOTHER account of the recipient's is refused by nothing here — string (vi) at their beat is the whole guard, and such an account is one no recovery of that other account reaches (AUTH-5.89)");
    // The comparison beat — `enroll`'s own, rendered here.
    if !compare_payload(person, &entries, "skep handoff")? {
        return Err(Halt::face("the comparison was declined: nothing was written", "the typed answer was `no`", "compare with the recipient over the channel the address went out on, and re-run"));
    }
    // G1: THE COPY, strings by number, before the write.
    let giving_home = doc_1_of(&g.giving);
    let home_present = document_present(board, &giving_home)?;
    let anchor_sentence = if g.grade == Grade::Anchor { " Handing this off is an anchor act: you will import your paper anchor to write it." } else { "" };
    say(person, "AUTH-5.90 (i)", format!("(i) Seeding this space gives it away. From the moment you write this, {account} opens for whoever holds these keys, and not for you.{anchor_sentence}"));
    say(person, "AUTH-5.90 (ii)", "(ii) Use THEIR keys, not yours. A key that already opens your account is refused here — and ask them for a NEW key made for this account, not one that already opens an account of theirs.");
    say(person, "AUTH-5.90 (iii)", "(iii) You cannot take it back. Nothing you do re-opens this account, and getting back in if they lose their keys is theirs to solve, not yours.");
    let cone = by_reference_cone(board, person, std::slice::from_ref(&account))?;
    let n = cone.nodes.len();
    let m = cone.nodes.iter().filter(|c| c.seeded).count();
    say(
        person,
        "AUTH-5.90 (iv)",
        format!(
            "(iv) Everything already filed under {account} goes with it, including {n} space(s) beneath it — and {m} of them were already given away and stay with whoever holds their keys, still reading everything filed here; whoever holds these keys reads everything written in those {m} from this write on, and nothing here tells their holders so. From this write, whoever holds these keys reads every draft you have written under {}, including what you removed, and publishes under your prefix. Your own session there ends with this write. Anything {account} has shared stays shared: whoever holds these keys can withdraw those shares and you cannot, and until they do, whoever you shared with — your own agents included — reads what is written there. Anything shared WITH {account} is theirs to read now.",
            g.giver_account
        ),
    );
    if g.health.claimant() != Some(g.giver_account.as_str()) {
        say(person, "AUTH-5.90 (i) block", "If your account is ever blocked on this board, theirs is blocked with it.");
    }
    if account == first_child(&g.giver_account) {
        say(person, "AUTH-5.90 (viii)", format!("(viii) Your agents' home is {account}; giving that account away gives your agents' home away."));
    }
    let first_space_taken = matches!(board.key_set(&first_child(&account))?, KeySetAnswer::Set(s) if !s.enrolled.is_empty());
    if first_space_taken {
        say(person, "AUTH-5.90 (ix)", "(ix) The account you are giving has no room for their agents: its first space is already taken.");
    }
    if !entries.iter().any(|e| e.anchor) {
        say(
            person,
            "AUTH-5.16",
            "THE ANCHORLESS LINE: the account you are creating has no paper tier and its holder can never gain one — a post-genesis anchor enrollment needs an anchor session (AUTH-3.20/3.22) and there will never be one; the loss of that one device key is AUTH-5.62 (ii)'s anchorless end at an account no party can act at, no retirement reaches and no report can end. Where that is not what they intended: ask them to re-run `skep accept` with an anchor pair.",
        );
    }
    if !home_present {
        say(person, "AUTH-5.90 (b)", format!("beat (b) is owed: {} has no doc 1 — the mint creates a permanent, guest-readable, mirror-carried page at an address about to stop being yours, and the genesis stands in it forever", g.giving));
    }
    let typed = person
        .confirm_typed(Consent(Confirmation { text: format!("CONFIRM THE HANDOFF of {account} — type the address to confirm, or `no`"), expected: account.clone() }))
        .map_err(|_| Halt::face("the confirmation was abandoned", "nothing was written", "re-run when ready"))?;
    if typed.trim() != account {
        return Err(Halt::face("the handoff was declined: nothing was written", "the typed answer was not the address", "re-run when ready"));
    }
    // The hand: the giver's ANCHOR where the act is anchor-grade.
    let own: Vec<(Fingerprint, PublicKey)> = store.device_keys()?.iter().map(|k| (k.fingerprint, k.public.clone())).collect();
    let anchor: Option<ImportedAnchor> = if g.grade == Grade::Anchor {
        say(person, "AUTH-3.21", "the set that opens this account holds an anchor, so the handoff is ANCHOR-GRADE: your paper anchor is imported for this act alone");
        let records = credential_records(board, &g.set_account, &own)?;
        let cx = ImportContext { board, store, account: &g.giver_account, principal: opts.principal, set_account: &g.set_account, set: &g.set, records: &records, own: &own, anchor_path: opts.anchor.as_deref(), whose: Whose::Own, cell: &g.cell };
        match import_anchor(person, &cx)? {
            ImportOutcome::Anchor(a) => Some(*a),
            ImportOutcome::Neither => return Err(Halt::face("no anchor was handed in, and this handoff is anchor-grade", "AUTH-3.21: wherever the set that opens the account holds an anchor, the genesis needs a session an anchor of that set established", "hand in a paper anchor of your account (`--anchor <path>`, or at the prompt)")),
        }
    } else {
        None
    };
    let hand: &dyn Signer = match &anchor {
        Some(a) => &a.signer,
        None => &*device,
    };
    let session = handshake(board, Scope::Full, hand, session_principal, Site::Giver)?;
    let result = (|| -> Result<HandoffOutcome, Halt> {
        // G3 = beat (b): the giving account's home mint, idempotent by reading.
        if !document_present(board, &giving_home)? {
            let v = match session.op(&frames::create_home(&g.giving, Some(&format!("handoff.mint.{}", g.giving))))? {
                Answer::Closed => return Err(Halt::face("the session ended at the home mint", "closed", "re-run; beat (b) resumes by reading")),
                Answer::Document(v) => v,
            };
            if acked_addr(&v).is_none() {
                let r = Rejection::of(&v).map(|r| r.token()).unwrap_or_else(|| v.to_string());
                return Err(Halt::face(format!("the home mint of {} was refused: {r}", g.giving), "beat (b)", "re-run"));
            }
            say(person, "AUTH-5.90 (b)", format!("beat (b): {giving_home} minted, born published"));
        }
        // G4 = beat (c): THE GENESIS, verbatim, homed in the giving account's
        // doc 1, at the grade G0 read.
        let id = format!("handoff.genesis.{account}");
        let outcome = deposit(board, session.token(), &Deposit { home: &giving_home, subject: &account, kind: DepositKind::EnrollVerbatim(text.clone()), hand: Some(hand), id: &id });
        let reconciled = match outcome {
            Ok(DepositOutcome::Deposited { .. }) => false,
            Ok(DepositOutcome::Committed { reason }) => {
                say(person, "AUTH-5.18", format!("beat (d): {reason}"));
                true
            }
            Err(DepositHalt::NotGenesisRegistry(_)) => {
                return Err(Halt::face(
                    format!("this IS where {account}'s first keys go — but not these"),
                    format!("`not_genesis_registry` at {giving_home}, the doc 1 of the account the subdivision hangs from, with none of the payload's keys contained in the set: a key of the payload already opens the account above (AUTH-2.71's latch; AUTH-3.56's split row)"),
                    "ask the recipient for a NEW key made for this account (string (ii)); where the home above is wrong, this is this client's frame",
                ))
            }
            Err(other) => return Err(other.into()),
        };
        Ok(HandoffOutcome::Seeded { facts: Facts { account: account.clone(), principal, origin: board.dialed().clone() }, grade: g.grade, reconciled, warnings: Vec::new() })
    })();
    // G6: the mirror's close.
    let _ = session.close();
    if let Some(a) = anchor {
        a.dispose(person);
    }
    let out = result?;
    say(
        person,
        "AUTH-5.90 (vii)",
        format!(
            "THE REPLY for the recipient's string (vii): account {account}, principal {principal}, origin {} — they land it with `skep bind`; your own sessions AS {account} and anything beneath it are dead from the genesis's commit (AUTH-4.63), and the act is complete only when the reply stands with them",
            board.dialed()
        ),
    );
    Ok(out)
}
