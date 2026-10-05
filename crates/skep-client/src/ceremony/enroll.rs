//! `enroll` (`client.md` §2.2): the signed-in half of AUTH-5.32's hop, from
//! a FULL session this command opens with an ENROLLED device key of the
//! principal — never `session`'s content token, under which this write
//! answers `content_session`. `parse_enroll` on the pasted bytes (the
//! canonical record and nothing else; a mangled payload caught at the paste,
//! AUTH-5.57 step 3's echo-back); each fingerprint RE-DERIVED and shown
//! R42-grouped beside its label rendered inert (AUTH-5.2) with AUTH-5.42's
//! permanence line and ONE line saying what the parse PROVES (R48); the
//! comparison a CONSENT moment (cs6-1; §9 item 42); an ANCHOR-FLAGGED entry
//! REFUSED at the paste naming the walks that exist (AUTH-3.20/3.22); the
//! by-reference HALT where the walk's terminus is empty at the principal's
//! own account (AUTH-6.37; AUTH-3.56's twin); `first_session(account, this
//! session, this key)` AHEAD of the insert (AUTH-5.87; AUTH-5.90 (iii));
//! then `DepositKind::EnrollVerbatim` under the record grade, the pasted
//! bytes the sig-less body (AUTH-4.58); the RETURN LEG's three facts, NO
//! binding line appended (every fact a read, §3.7); `--reply <fp-prefix>`
//! re-derives and re-prints with no write, confirming the fingerprint
//! ENROLLED first (AUTH-5.32: "the ENROLLING device OFFERS THE REPLY AGAIN").
//! The refusals: `too_many_enrolled` pinned to THE ACT (`skep retire`,
//! AUTH-5.13), `nothing_changed` TWO STATES read from `key_set` (AUTH-5.17;
//! `retired` ⇒ I4's bar, AUTH-2.98), `undecodable_key` this door's own
//! arrival, `malformed_payload:<sub>` re-take never edit — all faced by
//! `deposit`'s base armed set.

use skep_identity::{parse_enroll, Enrollment, Fingerprint};

use crate::board::{Board, Scope};
use crate::ceremony::claim::{arm4_face, store_halt};
use crate::ceremony::deposit::{deposit, Deposit, DepositKind, DepositOutcome, Grade};
use crate::ceremony::first_session::{first_session, FirstSessionReads};
use crate::ceremony::handshake::{handshake, Site};
use crate::derive::{precheck, principal_of, walk_to_set, Mode};
use crate::halt::Halt;
use crate::person::{Confirmation, Consent, Person, Public, Statement};
use crate::sheet::{group_hex, render_inert, Facts, KeyFile};
use crate::store::{FileStore, KeySelector, Purpose, StoreError};

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

fn say(person: &mut dyn Person, rule: &'static str, text: impl Into<String>) {
    person.say(Public(Statement { rule, text: text.into() }));
}

/// The pasted bytes as the record's TEXT: UTF-8, the trailing newline
/// stripped (the canonical encoding has no `\n`, RES-98).
pub fn payload_text(payload: &[u8]) -> Result<String, Halt> {
    let text = std::str::from_utf8(payload).map_err(|_| Halt::face("the payload is not UTF-8", "a canonical record is UTF-8 text (AUTH-2.130)", "re-take the payload from the device that generated it; never edit it here"))?;
    Ok(text.trim_end_matches(['\n', '\r']).to_string())
}

/// `parse_enroll` on the paste, the malformed face naming where.
pub fn parse_payload(text: &str) -> Result<Vec<Enrollment>, Halt> {
    parse_enroll(text.as_bytes()).map_err(|e| {
        Halt::face(
            "the payload is not a canonical enrollment record",
            format!("`parse_enroll` refused it: {e} — malformed_payload (AUTH-2.130 admits the canonical encoding and nothing else)"),
            "re-take the payload from the device that generated it (`skep keygen --payload`); never edit it here (AUTH-5.57 step 3's echo-back)",
        )
    })
}

/// An ANCHOR-FLAGGED entry is REFUSED AT THE PASTE, naming the walks that
/// exist — never stripped and re-flagged (AUTH-1.26 fixes the flag for the
/// fingerprint's life).
pub fn refuse_anchor_flagged(entries: &[Enrollment], door: &str) -> Result<(), Halt> {
    if let Some(e) = entries.iter().find(|e| e.anchor) {
        return Err(Halt::face(
            format!("the payload carries an ANCHOR-flagged entry ({}) and `{door}` enrolls device keys alone", Fingerprint::of(&e.key)),
            "a post-genesis anchor enrollment needs a session an anchor established (AUTH-3.20/3.22) and is a walk of its own; the flag is fixed for the fingerprint's life (AUTH-1.26), so it is never stripped here",
            "the walks that exist: `skep recover --anchor-lost` where a paper was lost (the loss arm), and the anchor REPLACEMENT rotation, LATER with the attendant campaign; a device is added with `skep keygen --payload`'s one device-flagged key",
        ));
    }
    Ok(())
}

/// THE COMPARISON BEAT (AUTH-5.32; AUTH-4.59; R48): each fingerprint
/// re-derived from the bytes read and shown R42-grouped beside its label
/// rendered inert with AUTH-5.42's permanence line, ONE line saying what the
/// parse proves, then the CONSENT: the person compares against the
/// generating device's display and types the first group. `false` on `no`.
pub fn compare_payload(person: &mut dyn Person, entries: &[Enrollment], door: &str) -> Result<bool, Halt> {
    for e in entries {
        let fp = Fingerprint::of(&e.key);
        say(
            person,
            "AUTH-5.32",
            format!(
                "key to enroll — fingerprint re-derived from the bytes read:\n  {}\n  {}\n  label: {} — {}\n  anchor: {}",
                fp,
                group_hex(&fp.to_hex()).replace('\n', "\n  "),
                e.label().map(render_inert).unwrap_or_else(|| "(none)".into()),
                "this label is PUBLIC, PERMANENT and UNCORRECTABLE, the byline on every write this key makes; it was typed on the generating device and the hand that commits it here never typed it (AUTH-5.42)",
                e.anchor
            ),
        );
    }
    say(
        person,
        "R48",
        "what the parse PROVES: that these bytes parsed as a canonical record — and nothing about who composed them. Compare the fingerprint above against the one the generating device displays, over the channel the payload came by, BEFORE anything depends on it (AUTH-5.39's discipline over a pubkey): a substituted payload enrolled here is a permanent co-holder of this account, evictable only by `skep retire`.",
    );
    let expected = Fingerprint::of(&entries[0].key).to_hex()[..8].to_string();
    for _ in 0..3 {
        let typed = person
            .confirm_typed(Consent(Confirmation {
                text: format!("`{door}`: does the fingerprint match the generating device's display? type its first 8 hex to confirm, or `no`"),
                expected: expected.clone(),
            }))
            .map_err(|_| Halt::face("the comparison was abandoned", "nothing was written", "re-run when ready"))?;
        let typed = typed.trim().to_ascii_lowercase();
        if typed == expected {
            return Ok(true);
        }
        if typed.is_empty() || typed == "no" || typed == "n" {
            return Ok(false);
        }
        say(person, "AUTH-5.39", format!("`{typed}` is not the first group of the fingerprint shown ({expected}…); compare again and type that group, or `no`"));
    }
    Ok(false)
}

/// THE WALK.
pub fn enroll(board: &Board, store: &FileStore, person: &mut dyn Person, opts: &EnrollOptions) -> Result<Enrolled, Halt> {
    // The paste, parsed at the door — ahead of any read (P13).
    let text = payload_text(&opts.payload)?;
    let entries = parse_payload(&text)?;
    refuse_anchor_flagged(&entries, "skep enroll")?;
    let fps: Vec<Fingerprint> = entries.iter().map(|e| Fingerprint::of(&e.key)).collect();
    // The store's ENROLLED device key for (board, n) — §3.5's lookup.
    let key = match store.select(&KeySelector::Binding { origin: &board.dialed, principal: Some(opts.principal) }, Purpose::Sign) {
        Ok(sel) => sel.file,
        Err(StoreError::NoSelection { keys }) => {
            let health = board.health()?;
            return Err(arm4_face(store, &keys, Mode::of(&health), health.local_trust()));
        }
        Err(e) => return Err(store_halt(e)),
    };
    let signer = key.signer();
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
    let session = handshake(board, Scope::Full, &signer, opts.principal, Site::Session)?;
    // `first_session` AHEAD of the insert.
    let reads = FirstSessionReads::take(board, &account, &key.fingerprint, Some(store), &board.dialed)?;
    let done = first_session(board, &reads, &session, &signer, Some(store));
    let done = match done {
        Ok(d) => d,
        Err(h) => {
            let _ = session.close(board);
            return Err(h);
        }
    };
    let mut warnings = done.warnings.clone();
    if done.minted_home {
        warnings.push(format!("the home {} was minted ahead of the enrollment (AUTH-5.90 (iii): the first signed session's first act)", reads.home));
    }
    // THE DEPOSIT: the pasted bytes VERBATIM as the sig-less body.
    let id = format!("enroll.{}", &fps[0].to_hex()[..8]);
    let outcome = deposit(board, &session.token, &Deposit { home: &reads.home, subject: &account, kind: DepositKind::EnrollVerbatim(text.clone()), grade: Grade::Device, hand: Some(&signer), id: &id });
    let _ = session.close(board);
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

/// The store's device key file for `--reply`'s caller and others: a read of
/// its public facts, no anchor test.
pub fn store_key(store: &FileStore, fp: &Fingerprint) -> Result<KeyFile, Halt> {
    store.load(&store.key_path(fp)).map_err(store_halt)
}
