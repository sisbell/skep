//! `enroll` (`client.md` §2.2): the signed-in half of AUTH-5.32's hop.
//!
//! It writes from a full session this command opens with an enrolled device
//! key of the principal — never `session`'s content token, under which this
//! write answers `content_session`. At the paste door (`payload`), ahead of
//! any read: `parse_enroll` on the pasted bytes (the canonical record and
//! nothing else; a mangled payload caught at the paste, AUTH-5.57 step 3's
//! echo-back), and an anchor-flagged entry refused at the paste naming the
//! walks that exist (AUTH-3.20/3.22). Then the by-reference halt where the
//! walk's terminus is empty at the principal's own account (AUTH-6.37;
//! AUTH-3.56's twin); the comparison, a consent moment (§9 item 42) — each
//! fingerprint re-derived and shown R42-grouped beside its label rendered
//! inert (AUTH-5.2) with AUTH-5.42's permanence line and one line saying
//! what the parse proves (R48); `first_session(account, this session, this
//! key)` ahead of the insert (AUTH-5.87; AUTH-5.90 (iii)); then
//! `DepositKind::EnrollVerbatim` under the record grade, the pasted bytes
//! the sig-less body (AUTH-4.58); the return leg's three facts, no binding
//! line appended (every fact a read, §3.7); `--reply <fp-prefix>`
//! re-derives and re-prints with no write, confirming the fingerprint
//! enrolled first (AUTH-5.32: "the enrolling device offers the reply
//! again"). The refusals: `too_many_enrolled` pinned to the act
//! (`skep retire`, AUTH-5.13), `nothing_changed` two states read from
//! `key_set` (AUTH-5.17; `retired` ⇒ I4's bar, AUTH-2.98), `undecodable_key`
//! this door's own arrival, `malformed_payload:<sub>` re-take never edit —
//! all faced by `deposit`'s base armed set.

use skep_identity::Fingerprint;

use super::say;
use crate::board::{Board, Scope};
use crate::ceremony::deposit::{deposit, Deposit, DepositKind, DepositOutcome};
use crate::ceremony::first_session::{first_session, FirstSessionReads};
use crate::ceremony::handshake::{handshake, Site};
use crate::ceremony::payload::{compare_payload, parse_payload, payload_text, refuse_anchor_flagged};
use crate::derive::{precheck, principal_of, walk_to_set, Mode};
use crate::halt::Halt;
use crate::person::Person;
use crate::sheet::Facts;
use crate::store::{arm4_face, FileStore, KeySelector, KeyStore, Purpose, StoreError};

/// The command's inputs.
#[derive(Debug, Clone)]
pub struct EnrollOptions {
    /// The principal whose enrolled device key opens the session.
    pub principal: u64,
    /// The pasted bytes.
    pub payload: Vec<u8>,
}

/// The return leg's three facts, and what was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolled {
    /// The return leg's three facts.
    pub facts: Facts,
    /// The fingerprints enrolled — at `--reply`, the one confirmed.
    pub fingerprints: Vec<Fingerprint>,
    /// The act had already committed — reconciled from the records, exit 0.
    pub reconciled: bool,
    /// The warnings the walk raised.
    pub warnings: Vec<String>,
}

/// Runs the walk.
///
/// # Errors
///
/// In the walk's order: a paste that is not UTF-8, not a canonical record,
/// or anchor-flagged; arm 4's fork where the store selects no key, and the
/// store's other refusals; the pre-check; the by-reference halt; the key
/// face; the comparison abandoned or declined; the handshake; the first
/// session; and the deposit's halts.
///
/// # Panics
///
/// Panics where the payload names no entry, or a fingerprint's hex runs
/// under 8 digits; `parse_payload`'s entries are never none and the hex
/// runs to 64, so neither fires.
pub fn enroll(board: &Board, store: &FileStore, person: &mut dyn Person, opts: &EnrollOptions) -> Result<Enrolled, Halt> {
    // The paste, parsed at the door — ahead of any read (P13).
    let text = payload_text(&opts.payload)?;
    let entries = parse_payload(&text)?;
    refuse_anchor_flagged(&entries, "skep enroll")?;
    let fps: Vec<Fingerprint> = entries.iter().map(|e| Fingerprint::of(&e.key)).collect();
    // The store's device key for (board, n) — §3.5's lookup; the pre-check
    // judges its enrollment.
    let key = match store.select(&KeySelector::Board { origin: board.dialed(), principal: Some(opts.principal) }, Purpose::Sign) {
        Ok(key) => key,
        Err(StoreError::NoSelection { keys }) => {
            return Err(arm4_face(store, &keys, Mode::of(&board.health()?)));
        }
        Err(e) => return Err(e.into()),
    };
    let signer = store.signer(&KeySelector::Path(&key.path))?;
    // The reads: the pre-check (the origin arm, `principal_prefix`, the walk).
    let pre = precheck(board, opts.principal, &key.fingerprint)?;
    if pre.walk.by_reference() {
        let at = principal_of(board, &pre.walk.set_account)?.map(|p| p.to_string()).unwrap_or_else(|| "?".into());
        return Err(Halt::face(
            format!("{} opens by reference and holds no keys of its own, so no key is enrolled AT it", pre.account),
            format!("`key_set({})` is empty and the set that opens it stands at {} (AUTH-4.30 (i); AUTH-6.19)", pre.account, pre.walk.set_account),
            format!("make the act at {} — principal {at} — where the set that opens it stands (AUTH-6.37; the enrollment-side twin of `not_holder_retirement`'s redirect)", pre.walk.set_account),
        ));
    }
    crate::ceremony::handshake::key_face(board, &pre.walk, &key.fingerprint, &[(key.fingerprint, key.public.clone())], Site::Session)?;
    let account = pre.account.clone();
    // The comparison — a consent moment.
    if !compare_payload(person, &entries, "skep enroll")? {
        return Err(Halt::face("the comparison was declined: nothing was written", "the typed answer was `no`", "re-take the payload from the generating device and compare again"));
    }
    // The full session this command opens.
    let session = handshake(board, Scope::Full, &*signer, opts.principal, Site::Session)?;
    // `first_session` ahead of the insert.
    let reads = FirstSessionReads::take(board, &account, &key.fingerprint, Some(store))?;
    let done = first_session(board, &reads, &session, &*signer, Some(store))?;
    let mut warnings = done.warnings.clone();
    if done.minted_home {
        warnings.push(format!("the home {} was minted ahead of the enrollment (AUTH-5.90 (iii): the first signed session's first act)", reads.home));
    }
    // The deposit: the pasted bytes verbatim as the sig-less body.
    let id = format!("enroll.{}", &fps[0].to_hex()[..8]);
    let outcome = deposit(board, session.token(), &Deposit { home: &reads.home, subject: &account, kind: DepositKind::EnrollVerbatim(text.clone()), hand: Some(&*signer), id: &id });
    let _ = session.close();
    let outcome = outcome?;
    let reconciled = match &outcome {
        DepositOutcome::Deposited { .. } => false,
        DepositOutcome::Committed { reason } => {
            say(person, "AUTH-5.17", format!("reconciled from the records: {reason}"));
            true
        }
    };
    say(
        person,
        "AUTH-5.32",
        "THE RETURN LEG: hand the three facts below to the device that generated the key — `skep bind` lands them there; this device appends no binding line, every fact being a read, and offers the reply again with `skep enroll --reply <fp-prefix>`",
    );
    Ok(Enrolled { facts: Facts { account, principal: opts.principal, origin: board.dialed().clone() }, fingerprints: fps, reconciled, warnings })
}

/// Answers `--reply <fp-prefix>`: the three facts re-derived from reads.
///
/// The fingerprint is confirmed enrolled in the set the walk reaches first;
/// no write.
///
/// # Errors
///
/// An unregistered principal; no enrolled key matching the prefix, or more
/// than one; and the reads' errors.
pub fn reply(board: &Board, principal: u64, prefix: &str) -> Result<Enrolled, Halt> {
    let Some(account) = board.principal_prefix(principal)? else {
        return Err(Halt::face(format!("principal {principal} is not a registered account on this board"), "`principal_prefix` answered null", "check the principal number and the board"));
    };
    let walk = walk_to_set(board, &account)?;
    let prefix = prefix.trim().to_ascii_lowercase();
    let matches: Vec<Fingerprint> = walk.set.enrolled.iter().filter(|e| e.fingerprint.to_hex().starts_with(&prefix)).map(|e| e.fingerprint).collect();
    match matches.as_slice() {
        [] => Err(Halt::face(
            format!("no enrolled key of {} starts with `{prefix}`", walk.set_account),
            "the reply is offered again only for a fingerprint ENROLLED in the set the walk reaches (AUTH-5.32)",
            "run the hop first: `skep enroll --payload`",
        )),
        [_] => Ok(Enrolled { facts: Facts { account, principal, origin: board.dialed().clone() }, fingerprints: matches, reconciled: true, warnings: Vec::new() }),
        many => Err(Halt::face(
            format!("`{prefix}` matches more than one enrolled key"),
            many.iter().map(|f| f.to_string()).collect::<Vec<_>>().join("\n  "),
            "give a longer prefix; never a pick",
        )),
    }
}
