//! `retire` (`client.md` §4a.4; §2.2): a DEVICE key retired from a FULL
//! session this command opens with a key this store holds (AUTH-5.60 step
//! 1: "from any OTHER enrolled key — an ungated device act", AUTH-3.65's
//! device columns). R0's reads; a FULL session under the store's key for
//! (`--board`, n); `first_session` first (R4's insert homes in the
//! account's doc 1, which may not stand — AUTH-5.90 (iii)); the prefix
//! resolved against the enrolled list WITH LABELS from the admitted read
//! (AUTH-5.69) — more than one match a halt listing them, an ANCHOR match
//! refused ahead of any frame naming `recover --anchor-lost` and the LATER
//! replacement; `preview(removed)` over the head invariant's enumeration;
//! the typed answer; ONE `DepositKind::Retire`; the close — OR, where the
//! retired key IS this session's own (AUTH-5.59 step 4's device arm), NO
//! close sent: the commit ends the session atomically (AUTH-4.63) and the
//! `closed` any later request meets is AUTH-5.28's expected end in its FORK
//! (an enrolled key still held ⇒ `skep session`; none ⇒ the keyless face,
//! `skep recover` with a paper). At an account that opens by reference the
//! retirement is REDIRECTED to the set account, where the key stands as
//! that account's own (`not_holder_retirement`'s face, AUTH-3.56). The
//! store's change: NONE (§9 item 36). The NOTEBOOK-AT-LOSS face where the
//! store holds no key that opens a session at `--board` (§4a.1).

use skep_identity::Fingerprint;

use super::say;
use crate::board::{Board, KeySetAnswer, Scope};
use crate::ceremony::deposit::{deposit, Deposit, DepositKind, DepositOutcome};
use crate::ceremony::enumerate::head_closure;
use crate::ceremony::first_session::{first_session, FirstSessionReads};
use crate::ceremony::handshake::{handshake, Site};
use crate::ceremony::preview::{declined, preview, Preview, PreviewSite, Previewed, Row};
use crate::ceremony::reads::r0;
use crate::halt::Halt;
use crate::person::Person;
use crate::sheet::render_inert;
use crate::store::{store_halt, FileStore, KeySelector, KeyStore, Purpose, StoreError};

/// The command's inputs.
#[derive(Debug, Clone)]
pub struct RetireOptions {
    pub principal: u64,
    /// `--fingerprint <fp-prefix>`: a prefix of the fingerprint to retire,
    /// resolved against the enrolled list.
    pub fingerprint_prefix: String,
}

/// How the walk ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetireEnd {
    /// Another key's retirement: the walk sent the session's close
    /// (AUTH-4.47).
    CloseSent,
    /// The session's OWN key was retired: the commit ended the session
    /// (AUTH-4.63) and no close was sent; the expected end's fork
    /// (AUTH-5.28) — another enrolled key of this store stands, or none.
    EndedByCommit { another_held: bool },
}

/// What was retired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retired {
    /// The account the retirement is homed at (the set account).
    pub account: String,
    pub fingerprint: Fingerprint,
    pub label: Option<String>,
    pub end: RetireEnd,
    pub reconciled: bool,
}

/// THE WALK.
pub fn retire(board: &Board, store: &FileStore, person: &mut dyn Person, opts: &RetireOptions) -> Result<Retired, Halt> {
    // The store's key for (board, n); the NOTEBOOK-AT-LOSS face where none
    // opens a session here (§4a.1).
    let key = match store.select(&KeySelector::Board { origin: &board.dialed, principal: Some(opts.principal) }, Purpose::Sign) {
        Ok(key) => key,
        Err(StoreError::NoSelection { keys }) => {
            return Err(Halt::face(
                format!("this store holds no key that opens a session at {} ({} key(s) in it, none bound to principal {})", board.dialed, keys.len(), opts.principal),
                "on the notebook DEVICE LOSS IS BOARD LOSS: there is no session to retire from at the moment of a loss (AUTH-5.60 step 1)",
                "the acts at that moment are the VOLUME BACKUP already taken and `skep recover` on a restored board (a paper import); where another device of yours is signed in, retire from it",
            ))
        }
        Err(e) => return Err(store_halt(e)),
    };
    let signer = store.signer(&KeySelector::Path(&key.path)).map_err(store_halt)?;
    let own: Vec<(Fingerprint, skep_identity::PublicKey)> = store.device_keys().map_err(store_halt)?.iter().map(|k| (k.fingerprint, k.public.clone())).collect();
    // R0's reads; a retirement at a by-reference account is redirected.
    let reads = r0(board, person, opts.principal, false, &own)?;
    if reads.walk.by_reference() {
        say(
            person,
            "AUTH-3.56",
            format!("{} opens by reference and holds no set of its own: the retirement is made at {}, where the key stands as that account's own (`not_holder_retirement`'s redirect)", reads.account, reads.walk.set_account),
        );
    }
    let set_account = reads.walk.set_account.clone();
    // The prefix, resolved against the enrolled list WITH LABELS.
    let prefix = opts.fingerprint_prefix.trim().to_ascii_lowercase();
    let matches: Vec<_> = reads.walk.set.enrolled.iter().filter(|e| e.fingerprint.to_hex().starts_with(&prefix)).collect();
    let target = match matches.as_slice() {
        [] => {
            let listed: Vec<String> = reads.walk.set.enrolled.iter().map(|e| format!("{} {} {}", e.fingerprint, if e.anchor { "ANCHOR" } else { "device" }, reads.records.label_of(&e.fingerprint).map(|l| render_inert(&l)).unwrap_or_default())).collect();
            return Err(Halt::face(
                format!("no enrolled key of {set_account} starts with `{prefix}`"),
                format!("the enrolled list:\n  {}", listed.join("\n  ")),
                "name an enrolled fingerprint's prefix",
            ));
        }
        [one] => (*one).clone(),
        many => {
            let listed: Vec<String> = many.iter().map(|e| format!("{} {}", e.fingerprint, reads.records.label_of(&e.fingerprint).map(|l| render_inert(&l)).unwrap_or_default())).collect();
            return Err(Halt::face(
                format!("`{prefix}` matches more than one enrolled key"),
                format!("neither a prefix nor a label is unique by rule (AUTH-5.3):\n  {}", listed.join("\n  ")),
                "give a longer prefix; never a pick",
            ));
        }
    };
    if target.anchor {
        return Err(Halt::face(
            format!("{} is an ANCHOR, and `skep retire` retires device keys alone", target.fingerprint),
            "an anchor's retirement needs an anchor session (AUTH-3.20/3.22) and is a walk of its own — refused ahead of any frame",
            "its walks: `skep recover --anchor-lost` where the paper was lost (the lost paper retired under the surviving one), and the anchor REPLACEMENT rotation, LATER with the attendant campaign",
        ));
    }
    let label = reads.records.label_of(&target.fingerprint);
    // THE FULL SESSION, as the set account's principal — closed on every
    // halt below by its own drop.
    let session = handshake(board, Scope::Full, &*signer, reads.set_principal, Site::Session)?;
    // `first_session` FIRST.
    let fs_reads = FirstSessionReads::take(board, &set_account, &key.fingerprint, Some(store))?;
    first_session(board, &fs_reads, &session, &*signer, Some(store))?;
    // The enumeration and the preview.
    let closure = head_closure(board, person, &set_account, &target.fingerprint)?;
    let held: Vec<Fingerprint> = own.iter().map(|(f, _)| *f).collect();
    let rows = [Row::of(&target.fingerprint, &reads.walk.set, Some(&reads.records), &held, Some(&key.fingerprint), false)];
    let answer = preview(person, &Preview { account: &set_account, set: &reads.walk.set, rows: &rows, closure: &closure, held: &held, site: PreviewSite::Retire, own_board: reads.cell.own_board() })?;
    match answer {
        Previewed::Confirmed => {}
        Previewed::Declined => return Err(declined("retirement")),
        Previewed::Unwritable => {
            return Err(Halt::face(
                format!("the retirement of {} cannot be written: it would empty the set at {set_account}", target.fingerprint),
                "`would_empty`: no anchor stands and this is the account's only device key — the preview said so and took no confirmation (§4a.4)",
                "the acts that exist while this key still signs: the hop from this session (`skep keygen --payload` on the second device, `skep enroll` here, `skep bind` there), and the volume copy where the board is your own",
            ));
        }
    }
    // ONE retirement.
    let own_key = target.fingerprint == key.fingerprint;
    let id = format!("retire.{}", &target.fingerprint.to_hex()[..8]);
    // A retirement that did not commit leaves the session live, and its drop
    // closes it — the own key's included.
    let outcome = deposit(board, &session.token, &Deposit { home: &fs_reads.home, subject: &set_account, kind: DepositKind::Retire(vec![target.fingerprint]), hand: Some(&*signer), id: &id })?;
    let reconciled = matches!(outcome, DepositOutcome::Committed { .. });
    if let DepositOutcome::Committed { reason } = &outcome {
        say(person, "AUTH-5.17", format!("reconciled: {reason}"));
    }
    say(person, "§9 item 36", "the store is unchanged: the key file stays where it was, written once and never rewritten; the board's `retired` list is what the pre-check reads at the next `session` here, and the file's deletion is your act");
    let end = if own_key {
        // AUTH-4.63: the commit ended this session; no close is sent.
        session.ended_by_commit();
        let another_held = match board.key_set(&set_account)? {
            KeySetAnswer::Set(s) => own.iter().any(|(f, _)| *f != key.fingerprint && s.enrolled(f).is_some_and(|e| !e.anchor)),
            KeySetAnswer::NotAnAccount => false,
        };
        say(
            person,
            "AUTH-5.28",
            if another_held {
                "this session's own key was retired: the commit ended the session (AUTH-4.63), no close is sent, and the `closed` any later request meets is the EXPECTED END — the next act is a sign-in with the key you still hold: `skep session`"
            } else {
                "this session's own key was retired: the commit ended the session (AUTH-4.63), no close is sent, and the `closed` any later request meets is the EXPECTED END; no enrolled key is held here, so the next act is the keyless face's — `skep keygen`, then `skep recover` with a paper (AUTH-5.32)"
            },
        );
        RetireEnd::EndedByCommit { another_held }
    } else {
        let _ = session.close();
        RetireEnd::CloseSent
    };
    Ok(Retired { account: set_account, fingerprint: target.fingerprint, label, end, reconciled })
}
