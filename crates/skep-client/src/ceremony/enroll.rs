//! `enroll` (`client.md` §2.2): the signed-in half of AUTH-5.32's hop, from
//! a FULL session this command opens with an ENROLLED device key of the
//! principal — never `session`'s content token, under which this write
//! answers `content_session`. At the paste door (`payload`): `parse_enroll`
//! on the pasted bytes (the canonical record and nothing else; a mangled
//! payload caught at the paste, AUTH-5.57 step 3's echo-back); each
//! fingerprint RE-DERIVED and shown R42-grouped beside its label rendered
//! inert (AUTH-5.2) with AUTH-5.42's permanence line and ONE line saying
//! what the parse PROVES (R48); the comparison a CONSENT moment (cs6-1; §9
//! item 42); an ANCHOR-FLAGGED entry REFUSED at the paste naming the walks
//! that exist (AUTH-3.20/3.22). Then the by-reference HALT where the walk's
//! terminus is empty at the principal's own account (AUTH-6.37;
//! AUTH-3.56's twin); `first_session(account, this session, this key)`
//! AHEAD of the insert (AUTH-5.87; AUTH-5.90 (iii)); then
//! `DepositKind::EnrollVerbatim` under the record grade, the pasted bytes
//! the sig-less body (AUTH-4.58); the RETURN LEG's three facts, NO binding
//! line appended (every fact a read, §3.7); `--reply <fp-prefix>`
//! re-derives and re-prints with no write, confirming the fingerprint
//! ENROLLED first (AUTH-5.32: "the ENROLLING device OFFERS THE REPLY AGAIN").
//! The refusals: `too_many_enrolled` pinned to THE ACT (`skep retire`,
//! AUTH-5.13), `nothing_changed` TWO STATES read from `key_set` (AUTH-5.17;
//! `retired` ⇒ I4's bar, AUTH-2.98), `undecodable_key` this door's own
//! arrival, `malformed_payload:<sub>` re-take never edit — all faced by
//! `deposit`'s base armed set.

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
use crate::store::{arm4_face, store_halt, FileStore, KeySelector, KeyStore, Purpose, StoreError};

/// The command's inputs.
#[derive(Debug, Clone)]
pub struct EnrollOptions {
    pub principal: u64,
    /// The pasted bytes.
    pub payload: Vec<u8>,
}

/// The return leg's three facts, and what was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolled {
    pub facts: Facts,
    pub fingerprints: Vec<Fingerprint>,
    /// The act had already committed — reconciled from the records, exit 0.
    pub reconciled: bool,
    pub warnings: Vec<String>,
}

/// THE WALK.
pub fn enroll(board: &Board, store: &FileStore, person: &mut dyn Person, opts: &EnrollOptions) -> Result<Enrolled, Halt> {
    // The paste, parsed at the door — ahead of any read (P13).
    let text = payload_text(&opts.payload)?;
    let entries = parse_payload(&text)?;
    refuse_anchor_flagged(&entries, "skep enroll")?;
    let fps: Vec<Fingerprint> = entries.iter().map(|e| Fingerprint::of(&e.key)).collect();
    // The store's ENROLLED device key for (board, n) — §3.5's lookup.
    let key = match store.select(&KeySelector::Board { origin: &board.dialed, principal: Some(opts.principal) }, Purpose::Sign) {
        Ok(key) => key,
        Err(StoreError::NoSelection { keys }) => {
            return Err(arm4_face(store, &keys, Mode::of(&board.health()?)));
        }
        Err(e) => return Err(store_halt(e)),
    };
    let signer = store.signer(&KeySelector::Path(&key.path)).map_err(store_halt)?;
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
    crate::ceremony::handshake::key_face(board, &pre, &key.fingerprint, &[(key.fingerprint, key.public.clone())], Site::Session)?;
    let account = pre.account.clone();
    // THE COMPARISON — a CONSENT moment.
    if !compare_payload(person, &entries, "skep enroll")? {
        return Err(Halt::face("the comparison was declined: nothing was written", "the typed answer was `no`", "re-take the payload from the generating device and compare again"));
    }
    // THE FULL SESSION this command opens.
    let session = handshake(board, Scope::Full, &*signer, opts.principal, Site::Session)?;
    // `first_session` AHEAD of the insert.
    let reads = FirstSessionReads::take(board, &account, &key.fingerprint, Some(store))?;
    let done = first_session(board, &reads, &session, &*signer, Some(store))?;
    let mut warnings = done.warnings.clone();
    if done.minted_home {
        warnings.push(format!("the home {} was minted ahead of the enrollment (AUTH-5.90 (iii): the first signed session's first act)", reads.home));
    }
    // THE DEPOSIT: the pasted bytes VERBATIM as the sig-less body.
    let id = format!("enroll.{}", &fps[0].to_hex()[..8]);
    let outcome = deposit(board, &session.token, &Deposit { home: &reads.home, subject: &account, kind: DepositKind::EnrollVerbatim(text.clone()), hand: Some(&*signer), id: &id });
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
    Ok(Enrolled { facts: Facts { account, principal: opts.principal, origin: board.dialed.clone() }, fingerprints: fps, reconciled, warnings })
}

/// `--reply <fp-prefix>`: the three facts re-derived from reads, the
/// fingerprint confirmed ENROLLED in the set the walk reaches first; no
/// write.
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
        [_] => Ok(Enrolled { facts: Facts { account, principal, origin: board.dialed.clone() }, fingerprints: matches, reconciled: true, warnings: Vec::new() }),
        many => Err(Halt::face(
            format!("`{prefix}` matches more than one enrolled key"),
            many.iter().map(|f| f.to_string()).collect::<Vec<_>>().join("\n  "),
            "give a longer prefix; never a pick",
        )),
    }
}
