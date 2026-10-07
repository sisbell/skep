//! `rotate` (`client.md` §4a.8 T0–T5): AUTH-5.59's DEVICE arm as ONE
//! gesture (RULED, owner 2026-09-09) — the OLD key HELD and signing, the NEW
//! key made here or carried in as `--payload` and compared as `enroll`
//! compares it. T0 R0's reads, the admitted read (the OLD key's enroll LINK
//! address for T3 and every label) and THE HEAD INVARIANT'S ENUMERATION
//! (AUTH-5.59's head). T1 the device-name box PREFILLED from the retiring
//! key's label (AUTH-5.59 step 6; AUTH-5.42; on the payload arm the label
//! rides inside the record, shown uncorrectable beside the comparison),
//! then `preview(removed)` over T0's enumeration — NO enrollment preview
//! beside it, the asymmetry with R3 the walks' own (R3 writes into an
//! account an imported artifact chose). T2 `first_session(X, the OLD key's
//! FULL session, the OLD key)` (AUTH-5.87; AUTH-5.90 (iii)) then
//! `DepositKind::Enroll` (or `EnrollVerbatim`) under the old key's hand at
//! the record grade (AUTH-5.59 step 1). T3 THE TRAIL — `assert_sup` from the
//! OLD enroll link to the NEW, homed in `X`'s own doc 1, `old` the address
//! T0's admitted read returned (at the notebook the genesis link's), `new`
//! T2's ack, signed by the OLD key, RESUMED BY READING the trail's presence
//! so a re-run never writes a second trail (AUTH-5.59 step 2; §4a.5). T4
//! `DepositKind::Retire` of the old key — THE LAST WRITE its session can
//! make, no close sent (AUTH-4.63; AUTH-5.59 step 4), `would_empty` armed.
//! T5 the `closed` as rotation's EXPECTED END (AUTH-5.28), the binding
//! appended for the new key where it is THIS store's, NONE on the payload
//! arm (the three facts printed for `skep bind` on the new device,
//! AUTH-5.32's return leg), the retired key's file left in place (§9 item
//! 36). `too_many_enrolled` at T2 faced as the PERSON-CLASS inversion
//! (AUTH-5.13); a `closed` BEFORE T4 faced per AUTH-5.77 with the hand
//! named, the walk halting at the first undone state.

use skep_identity::{Enrollment, Fingerprint, PublicKey};

use super::say;
use crate::board::{Board, Scope};
use crate::ceremony::deposit::{deposit, Deposit, DepositHalt, DepositKind, DepositOutcome};
use crate::ceremony::enumerate::head_closure;
use crate::ceremony::first_session::{first_session, FirstSessionReads};
use crate::ceremony::handshake::{handshake, Site};
use crate::ceremony::payload::{compare_payload, parse_payload, payload_text, refuse_anchor_flagged};
use crate::ceremony::preview::{declined, preview, Preview, PreviewSite, Previewed, Row};
use crate::ceremony::reads::{r0, Reads};
use crate::ceremony::trail::{trail_present, write_trail};
use crate::derive::records::{credential_records, Hand, Kind, Records};
use crate::derive::Mode;
use crate::halt::Halt;
use crate::person::{LabelBox, Person, Public};
use crate::sheet::{render_inert, Facts, Label};
use crate::store::{arm4_face, store_halt, Binding, FileStore, KeyFacts, KeySelector, KeyStore, Purpose, StoreError};

/// The command's inputs.
#[derive(Debug, Clone)]
pub struct RotateOptions {
    pub principal: u64,
    /// `--label <l>`: the new device's name, else the box, prefilled.
    pub label: Option<String>,
    /// `--payload <file|->`: the new key carried in from the device that
    /// holds it.
    pub payload: Option<Vec<u8>>,
}

/// What the rotation did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotated {
    pub facts: Facts,
    pub old: Fingerprint,
    pub new: Fingerprint,
    /// The supersession claim's address.
    pub trail: String,
    /// The binding appended for the new key, where it is this store's.
    pub binding_line: Option<String>,
    pub warnings: Vec<String>,
}

/// The OLD key's enroll link — at the notebook the genesis link's — from
/// the admitted read.
fn enroll_link_of(records: &Records, fp: &Fingerprint) -> Option<String> {
    records.records.iter().find(|r| r.kind == Kind::Enroll && r.enrolled.iter().any(|e| Fingerprint::of(&e.key) == *fp)).map(|r| r.link.clone())
}

/// AUTH-5.77's face for a `closed` met BEFORE T4: the old key retired by
/// another hand under the walk, the hand named from the records.
fn closed_before_t4(board: &Board, reads: &Reads, old: &Fingerprint, own: &[(Fingerprint, PublicKey)], h: Halt) -> Halt {
    let Ok(records) = credential_records(board, &reads.walk.set_account, own) else { return h };
    let Some(rec) = records.retirement_of(old) else { return h };
    let hand = match (&rec.hand, rec.position) {
        (Hand::Key(hand), Some(at)) => format!("retired at position {at} by {hand} ({}) — ANOTHER hand (AUTH-5.77)", records.label_of(hand).map(|l| render_inert(&l)).unwrap_or_default()),
        _ => "retired; the hand and the position were not readable at this board — no hand is asserted (AUTH-5.77's no-hand form)".into(),
    };
    Halt::face(
        format!("the old key {old} was retired under this walk, before its own retire-old"),
        format!("{hand}; the session died at that commit (AUTH-4.63)"),
        "the walk halts at the first undone state and resumes by reading (T2 by `key_set`, T3 by the trail's presence); sign in with a key you still hold",
    )
}

/// THE WALK.
pub fn rotate(board: &Board, store: &FileStore, person: &mut dyn Person, opts: &RotateOptions) -> Result<Rotated, Halt> {
    // The OLD key: the store's binding for (board, n).
    let old_key: KeyFacts = match store.select(&KeySelector::Board { origin: &board.dialed, principal: Some(opts.principal) }, Purpose::Sign) {
        Ok(key) => key,
        Err(StoreError::NoSelection { keys }) => {
            return Err(arm4_face(store, &keys, Mode::of(&board.health()?)));
        }
        Err(e) => return Err(store_halt(e)),
    };
    let old = store.signer(&KeySelector::Path(&old_key.path)).map_err(store_halt)?;
    let old_fp = old_key.fingerprint;
    let devices = store.device_keys().map_err(store_halt)?;
    let own: Vec<(Fingerprint, PublicKey)> = devices.iter().map(|k| (k.fingerprint, k.public.clone())).collect();
    // The payload arm's parse, at the door.
    let payload = match &opts.payload {
        Some(bytes) => {
            let text = payload_text(bytes)?;
            let entries = parse_payload(&text)?;
            refuse_anchor_flagged(&entries, "skep rotate --payload")?;
            Some((text, entries))
        }
        None => None,
    };
    // T0: R0's reads (this walk ENROLLS), the old enroll link, the closure.
    let reads = r0(board, person, opts.principal, true, &own)?;
    let account = reads.account.clone();
    if reads.walk.set.retired(&old_fp).is_some() {
        return Err(Halt::face(format!("the old key {old_fp} is already retired at {account}"), "I4 (AUTH-2.98): a retired fingerprint never re-enters the set; this rotation already ended, or another hand ended it", "sign in with a key you still hold (`skep session`)"));
    }
    let Some(old_link) = enroll_link_of(&reads.records, &old_fp) else {
        return Err(Halt::face(
            format!("the enroll link of {old_fp} was not found at {account}"),
            "the trail's `old` is the address the admitted read returns (AUTH-5.59 step 2); the read found no enrollment naming this key",
            "this is a board fault, or the account is not the one the key was enrolled at",
        ));
    };
    let closure = head_closure(board, person, &account, &old_fp)?;
    // The NEW key's resume read (T2 by `key_set`): on the payload arm its
    // fingerprint enrolled (`payload_enrolled`); on the generate arm an
    // UNBOUND device key of this store enrolled beside the old one.
    let bound: Vec<Fingerprint> = store.all_bindings().map_err(store_halt)?.into_iter().filter_map(|b| match b {
        Binding::Enrollment { origin, fingerprint, .. } if origin == board.dialed => Some(fingerprint),
        _ => None,
    }).collect();
    let resumed_new: Option<KeyFacts> = match &payload {
        Some(_) => None,
        None => devices
            .iter()
            .find(|k| k.fingerprint != old_fp && !bound.contains(&k.fingerprint) && reads.walk.set.enrolled(&k.fingerprint).is_some())
            .cloned(),
    };
    let payload_enrolled = payload.as_ref().is_some_and(|(_, e)| reads.walk.set.enrolled(&Fingerprint::of(&e[0].key)).is_some());
    // T1: the box, PREFILLED from the retiring key's label — or the payload's
    // label shown uncorrectable beside the comparison.
    let old_label = reads.records.label_of(&old_fp).or_else(|| old_key.label.clone());
    let new_label: Option<Label> = match (&payload, &resumed_new) {
        (Some((_, entries)), _) => {
            say(person, "AUTH-5.42", format!("on the payload arm the label rides inside the record — `{}` — uncorrectable once enrolled", entries[0].label().map(render_inert).unwrap_or_else(|| "(none)".into())));
            if !payload_enrolled && !compare_payload(person, entries, "skep rotate --payload")? {
                return Err(Halt::face("the comparison was declined: nothing was written", "the typed answer was `no`", "re-take the payload from the new device and compare again"));
            }
            None
        }
        (None, Some(resumed)) => {
            say(person, "AUTH-5.59 step 1", format!("resumed: the new key {} ({}) is already enrolled — T2 stands done, read off `key_set`", resumed.fingerprint, resumed.label.as_deref().map(render_inert).unwrap_or_default()));
            None
        }
        (None, None) => {
            let label = match &opts.label {
                Some(text) => Label::new(text).map_err(|f| Halt::face(format!("the label is refused at the box: {f}"), "AUTH-1.24's domain: non-empty, no line break, at most 128 bytes of UTF-8", "pass a label inside the domain"))?,
                None => loop {
                    let text = person
                        .label(Public(LabelBox {
                            title: "name the NEW device".into(),
                            statements: vec![
                                "This name is permanent and cannot be edited: fixing a typo costs a keypair (AUTH-5.42).".into(),
                                "It is a byline: this name appears beside every write you make with the NEW key, forever — the byline moves from the retiring key's label to this one (AUTH-5.69).".into(),
                                "It holds the DEVICE's name — never your own and never your organisation's.".into(),
                                format!("prefilled from the retiring key's label{}", old_label.as_deref().map(|l| format!(" (`{}`)", render_inert(l))).unwrap_or_default()),
                            ],
                            default: old_label.clone(),
                        }))
                        .map_err(|_| Halt::face("no device name was given", "the box was abandoned", "re-run `skep rotate`; nothing was written"))?;
                    match Label::new(&text) {
                        Ok(l) => break l,
                        Err(fault) => say(person, "AUTH-1.24", format!("that name is refused at the box: {fault}; name the device again")),
                    }
                },
            };
            Some(label)
        }
    };
    // THE PREVIEW over T0's enumeration (no enrollment preview beside it).
    let held: Vec<Fingerprint> = own.iter().map(|(f, _)| *f).collect();
    let rows = [Row::of(&old_fp, &reads.walk.set, Some(&reads.records), &held, Some(&old_fp), false)];
    match preview(person, &Preview { account: &account, set: &reads.walk.set, rows: &rows, closure: &closure, held: &held, site: PreviewSite::Rotate, own_board: reads.cell.own_board() })? {
        Previewed::Confirmed => {}
        Previewed::Declined => return Err(declined("rotation")),
        Previewed::Unwritable => return Err(Halt::face("the rotation's retire-old would empty the set", "`would_empty` armed", "this is this client's frame")),
    }
    // T2: the OLD key's FULL session — closed on every halt below by its own
    // drop, ended at T4 by T4's commit; `first_session` first; the enrollment.
    let session = handshake(board, Scope::Full, &*old, opts.principal, Site::Session)?;
    let fs_reads = FirstSessionReads::take(board, &account, &old_fp, Some(store))?;
    if let Err(h) = first_session(board, &fs_reads, &session, &*old, Some(store)) {
        return Err(closed_before_t4(board, &reads, &old_fp, &own, h));
    }
    let home = fs_reads.home.clone();
    let mut warnings = Vec::new();
    let (new_fp, new_key, new_link): (Fingerprint, Option<KeyFacts>, String) = {
        let kind_and_key: (DepositKind, Option<KeyFacts>, Fingerprint) = match (&payload, &resumed_new, &new_label) {
            (Some((text, entries)), _, _) => (DepositKind::EnrollVerbatim(text.clone()), None, Fingerprint::of(&entries[0].key)),
            (None, Some(resumed), _) => (DepositKind::Enroll(vec![Enrollment::new(resumed.public.clone(), false, resumed.label.clone()).expect("a stored label")]), Some(resumed.clone()), resumed.fingerprint),
            (None, None, Some(label)) => {
                let key_id = store.generate(Some(label.clone())).map_err(store_halt)?;
                let key = store.select(&KeySelector::Path(&store.key_path(&key_id.0)), Purpose::Read).map_err(store_halt)?;
                say(person, "§3a", format!("key file written: {} — the seed rests in this file and the filesystem's modes are its whole protection", key.path.display()));
                (DepositKind::Enroll(vec![Enrollment::new(key.public.clone(), false, Some(label.as_str().to_string())).expect("a label the box admitted")]), Some(key), key_id.0)
            }
            (None, None, None) => unreachable!("a label stands where no payload and no resumed key do"),
        };
        let (kind, key, fp) = kind_and_key;
        let id = format!("rotate.enroll.{}", &fp.to_hex()[..8]);
        let outcome = deposit(board, &session.token, &Deposit { home: &home, subject: &account, kind, hand: Some(&*old), id: &id });
        let link = match outcome {
            Ok(DepositOutcome::Deposited { link, .. }) => link,
            Ok(DepositOutcome::Committed { reason }) => {
                say(person, "AUTH-5.17", format!("T2 stands: {reason}"));
                let records = credential_records(board, &account, &own)?;
                enroll_link_of(&records, &fp).ok_or_else(|| Halt::face("the new key's enroll link was not found", "the record read after a reconciled enrollment names no link for it", "re-run; the walk resumes by reading"))?
            }
            Err(DepositHalt::SetFull(_)) => {
                return Err(Halt::face(
                    format!("the set at {account} is full (`too_many_enrolled`), and this rotation enrolls before it retires"),
                    "AUTH-5.13: the face names the act, never the count — and retire-first of THIS key is not the act here, since T4's retirement of the old key follows in this same session",
                    "retire a key you no longer hold first (`skep retire --fingerprint <prefix>`), then re-run `skep rotate`",
                ));
            }
            Err(DepositHalt::SessionClosed(h)) => return Err(closed_before_t4(board, &reads, &old_fp, &own, h)),
            Err(other) => return Err(other.into()),
        };
        (fp, key, link)
    };
    // T3: THE TRAIL, resumed by reading its presence.
    let trail = match trail_present(board, &old_link, &new_link)? {
        Some(claim) => {
            say(person, "AUTH-5.59 step 3", format!("the trail already stands at {claim} (from {old_link} to {new_link}): resumed by reading, no second trail is written"));
            claim
        }
        None => match write_trail(board, &session, &*old, &home, &old_link, &new_link, "rotate.trail") {
            Ok(claim) => {
                say(person, "AUTH-5.59 step 2", format!("the supersession trail is written at {claim}: `assert_sup` from the old enroll link {old_link} to the new {new_link}, homed in {home}, attested by the old key"));
                claim
            }
            Err(h) => return Err(closed_before_t4(board, &reads, &old_fp, &own, h)),
        },
    };
    // T4: the retire-old — THE LAST WRITE; no close sent.
    let id = format!("rotate.retire.{}", &old_fp.to_hex()[..8]);
    match deposit(board, &session.token, &Deposit { home: &home, subject: &account, kind: DepositKind::Retire(vec![old_fp]), hand: Some(&*old), id: &id }) {
        Ok(DepositOutcome::Deposited { .. }) => {}
        Ok(DepositOutcome::Committed { reason }) => say(person, "AUTH-5.17", format!("T4 stands: {reason}")),
        Err(DepositHalt::SessionClosed(h)) => return Err(closed_before_t4(board, &reads, &old_fp, &own, h)),
        Err(other) => return Err(other.into()),
    }
    // AUTH-4.63: T4's commit ended the old key's session.
    session.ended_by_commit();
    say(person, "AUTH-5.28", "ROTATION'S EXPECTED END: the commit ended the old key's session (AUTH-4.63) and no close is sent; the `closed` any later request would meet is this end and never a death face — the last step is a sign-in with the new key");
    // T5: the binding for the new key where it is THIS store's.
    let binding_line = match &new_key {
        Some(key) => {
            let line = Binding::Enrollment { origin: board.dialed.clone(), principal: opts.principal, account: account.clone(), fingerprint: key.fingerprint };
            if let Err(w) = store.bind(&line) {
                warnings.push(w.to_string());
            }
            Some(line.line())
        }
        None => {
            say(person, "AUTH-5.32", "the `--payload` arm appends no binding: the three facts below are for `skep bind` on the new device; this device's own line meets `verify`'s I4 face at its next pre-check");
            None
        }
    };
    say(person, "§9 item 36", format!("the retired key's file {} is left in place; its deletion is your act", store.key_path(&old_fp).display()));
    Ok(Rotated { facts: Facts { account, principal: opts.principal, origin: board.dialed.clone() }, old: old_fp, new: new_fp, trail, binding_line, warnings })
}
