//! THE ONE CREDENTIAL-WRITE COMPOSITION (`client.md` §5.3; P28), run at
//! every deposit site — §4.1 S4, §4.5 H4, and the later lane's R3, R4, L4,
//! L6, T2, T4, G4 and `enroll` — holding, ABOVE THE CLAIM, THE RECORD GRADE
//! in this order: the SIG-LESS canonical record composed (AUTH-4.58: that
//! body is the record's identity); the `record` frame composed over it by
//! `skep_identity::entry_frame` — `board` the head document `H.1`'s pair,
//! `account` the HOME's account, `doc` the home, the five rows wire.md states
//! — SIGNED by the HAND the caller passes, the `sig` appended canonically
//! LAST; then the insert declared under the record's class type (AUTH-5.4;
//! PUB-2.64), the re-read `from` (AUTH-5.5), the link carrying the same type
//! (PUB-2.63), AUTH-5.6's per-session `id` on both, AUTH-5.17's reconcile
//! from the records and the BASE ARMED SET. At or below the claim the record
//! carries no `sig` and the order is the insert and the link alone.
//!
//! THE HAND IS THE GRADE: a key of the set that opens the home's account —
//! an anchor where the act is anchor-grade (AUTH-3.20/3.22; AUTH-3.21's
//! exception), any enrolled key otherwise — chosen by the walk, which holds
//! the session the act needs, and JUDGED BY THE BOARD
//! (`anchor_session_required`; the `attestation_` family), both faced in
//! the base set below; this composition re-checks nothing the board judges.
//!
//! Every token the base set arms is faced with its CONTENT and never the
//! token alone; everything outside it is HALT AND SURFACE (AUTH-5.66's
//! residue). A deposit that stops answers WHICH ARM stopped it,
//! [`DepositHalt`], beside the face it composed, so a walk acts on the arm
//! and never on a face's words. Each site states only what it ADDS or rules
//! unreachable.

use std::borrow::Cow;
use std::fmt;

use serde_json::Value;
use skep_identity::{canonical_record, parse_enroll, Enrollment, Fingerprint};

use crate::board::{acked_addr, answers, frames, Answer, Board, KeySetAnswer, Rejection, Token, T_ENROLL, T_RETIRE};
use crate::halt::Halt;
use crate::sign::{sig_hex, RecordFrame, Signer};

/// What the deposit records.
#[derive(Debug, Clone)]
pub enum DepositKind {
    /// An enrollment of these entries, composed here (`encode_enroll`).
    Enroll(Vec<Enrollment>),
    /// An enrollment whose canonical bytes arrived from another device and
    /// are kept VERBATIM as the sig-less body (AUTH-4.58; §4.5 H2, `enroll`'s
    /// paste) — admitted by `parse_enroll` ahead of any frame.
    EnrollVerbatim(String),
    /// A retirement of these fingerprints (`encode_retire`).
    Retire(Vec<Fingerprint>),
}

/// One deposit.
pub struct Deposit<'a> {
    /// The home — the subject's own doc 1 for a holder act, the genesis
    /// registry's for a seeding (AUTH-2.127).
    pub home: &'a str,
    /// The subject account — the link's `to`.
    pub subject: &'a str,
    pub kind: DepositKind,
    /// The writing hand, ABOVE THE CLAIM — and with it the act's GRADE (the
    /// module's doc); `None` at or below the claim (S4, H4), where the
    /// record carries no `sig`.
    pub hand: Option<&'a dyn Signer>,
    /// AUTH-5.6's per-session id, one per credential act; the insert and the
    /// link take `<id>.insert` and `<id>.link`.
    pub id: &'a str,
}

/// The deposit's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositOutcome {
    /// Both writes acked: the atom, the link, the link's position.
    Deposited { atom: String, link: String, at: u64 },
    /// The act had ALREADY COMMITTED and its ack was lost — reconciled from
    /// the records (AUTH-5.17; AUTH-5.18's containment), never "failed".
    Committed { reason: String },
}

/// Why a deposit stopped: THE ARM of the base set that stopped it, each
/// carrying the face this composition composed for it. The arms a walk acts
/// on are named; every other halt is [`DepositHalt::Other`]. A walk that
/// only surfaces the face takes it with `?` (`From<DepositHalt> for Halt`).
/// Non-exhaustive: an arm a walk comes to act on is named here in its turn.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DepositHalt {
    /// The death signal met under the deposit's own token — at the ordinal
    /// read, the insert, the read-back or the link (wire.md §Sessions): the
    /// session died under the act, and the walk faces WHICH trigger
    /// (AUTH-5.27; AUTH-4.63).
    SessionClosed(Halt),
    /// `too_many_enrolled` — the set is full (AUTH-5.13: the act, never the
    /// count).
    SetFull(Halt),
    /// `not_genesis_registry` with the record's keys not contained in the
    /// set (AUTH-5.18): its neither arm, or an account whose set is empty.
    NotGenesisRegistry(Halt),
    /// Every other halt and refusal.
    Other(Halt),
}

impl DepositHalt {
    /// The face, whichever arm.
    pub fn face(&self) -> &Halt {
        match self {
            DepositHalt::SessionClosed(h) | DepositHalt::SetFull(h) | DepositHalt::NotGenesisRegistry(h) | DepositHalt::Other(h) => h,
        }
    }
}

impl From<DepositHalt> for Halt {
    fn from(d: DepositHalt) -> Halt {
        match d {
            DepositHalt::SessionClosed(h) | DepositHalt::SetFull(h) | DepositHalt::NotGenesisRegistry(h) | DepositHalt::Other(h) => h,
        }
    }
}

/// A read the deposit makes that halts on its own — a guest read, a
/// transport fault — is no armed arm.
impl From<Halt> for DepositHalt {
    fn from(h: Halt) -> DepositHalt {
        DepositHalt::Other(h)
    }
}

impl fmt::Display for DepositHalt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.face().fmt(f)
    }
}

impl std::error::Error for DepositHalt {}

/// What the deposit writes, decided ONCE from its [`DepositKind`]: an
/// enrollment's entries — composed by the walk, or parsed off a verbatim
/// paste — or a retirement's fingerprints. The record's class, its canonical
/// spelling and the fingerprints the reconcile reads are each answered by the
/// kind, so no later step re-derives which kind it is.
enum Written<'k> {
    Enrollment(Cow<'k, [Enrollment]>),
    Retirement(&'k [Fingerprint]),
}

impl Written<'_> {
    /// The record class's type address — the insert's declaration and the
    /// link's type alike (AUTH-5.4; PUB-2.63).
    fn ty(&self) -> &'static str {
        match self {
            Written::Enrollment(_) => T_ENROLL,
            Written::Retirement(_) => T_RETIRE,
        }
    }

    /// The canonical record (AUTH-2.130), its `sig` appended last where one
    /// is given.
    fn record(&self, sig: Option<&str>) -> String {
        match self {
            Written::Enrollment(entries) => canonical_record(&entries[..], sig),
            Written::Retirement(fps) => canonical_record(fps, sig),
        }
    }

    /// The fingerprints the record names.
    fn fingerprints(&self) -> Vec<Fingerprint> {
        match self {
            Written::Enrollment(entries) => entries.iter().map(|e| Fingerprint::of(&e.key)).collect(),
            Written::Retirement(fps) => fps.to_vec(),
        }
    }
}

/// THE NEXT FREE CONTENT ORDINAL of `doc` — one past its arranged content
/// extent, off `retrieve_doc_v_span_set` (PUB-2.59: where a declared deposit
/// into a published document must land).
pub fn next_content_ordinal(board: &Board, token: Option<&Token>, doc: &str) -> Result<u64, Halt> {
    ordinal_at(board, token, doc).map_err(Halt::from)
}

/// [`next_content_ordinal`], its death signal the deposit's own arm.
fn ordinal_at(board: &Board, token: Option<&Token>, doc: &str) -> Result<u64, DepositHalt> {
    match board.op(token, &frames::span_set(doc))? {
        Answer::Closed => Err(DepositHalt::SessionClosed(closed_face("reading the home's extent"))),
        Answer::Document(v) => {
            if let Some(r) = Rejection::of(&v) {
                return Err(r.refused(&v).into());
            }
            Ok(answers::content_extent(&v) + 1)
        }
    }
}

fn closed_face(during: &str) -> Halt {
    Halt::face(
        format!("the session ended while {during}"),
        "the board answered `Skepd-Session: closed` (wire.md §Sessions: a close, a restart, a retirement, a genesis at the \
         account acted as, a block, or the flip into ENFORCING on a bare session)",
        "re-run: every state of this walk resumes by reading the board (AUTH-5.56); a key still enrolled re-handshakes, \
         a retired one halts (AUTH-5.66)",
    )
}

/// AUTH-5.5's READ-BACK: the bytes at the atom's address are the record
/// written — the I→V inversion over `image`, then `retrieve_v` (AUTH-2.114);
/// an atom the arrangement does not hold, or an I-map that does not read
/// whole, does not read back (AUTH-2.115). The death signal on any of its
/// three reads is the session's end and never a mismatch.
fn read_back(board: &Board, token: Option<&Token>, home: &str, atom: &str, expected: &str) -> Result<bool, DepositHalt> {
    let closed = || DepositHalt::SessionClosed(closed_face("reading the record back"));
    let Answer::Document(set) = board.op(token, &frames::span_set(home))? else { return Err(closed()) };
    let extent = answers::content_extent(&set);
    if extent == 0 {
        return Ok(false);
    }
    let Answer::Document(image) = board.op(token, &frames::image(home, 1, extent))? else { return Err(closed()) };
    let held = answers::i_map(&image).and_then(|map| map.into_iter().find(|(a, _)| a == atom));
    let Some((_, ordinal)) = held else { return Ok(false) };
    let Answer::Document(v) = board.op(token, &frames::retrieve_v(home, ordinal, 1))? else { return Err(closed()) };
    Ok(answers::first_atom(&v).as_deref() == Some(expected.as_bytes()))
}

/// THE COMPOSITION.
pub fn deposit(board: &Board, token: &Token, d: &Deposit<'_>) -> Result<DepositOutcome, DepositHalt> {
    // The record: the sig-less canonical body — a verbatim paste's own
    // bytes, AUTH-4.58 — then, above the claim, the hand's `sig` at the
    // act's grade, appended canonically last.
    let (written, sigless) = match &d.kind {
        DepositKind::Enroll(entries) => {
            let written = Written::Enrollment(Cow::Borrowed(entries.as_slice()));
            let sigless = written.record(None);
            (written, sigless)
        }
        DepositKind::EnrollVerbatim(text) => {
            let entries = parse_enroll(text.as_bytes()).map_err(|e| {
                Halt::face(
                    "the payload is not a canonical enrollment record",
                    format!("`parse_enroll` refused it: {e} (AUTH-2.130 admits the canonical encoding and nothing else)"),
                    "re-take the payload from the device that generated it; never edit it here (AUTH-5.57 step 3's echo-back)",
                )
            })?;
            (Written::Enrollment(Cow::Owned(entries)), text.clone())
        }
        DepositKind::Retire(fps) => {
            let written = Written::Retirement(fps.as_slice());
            let sigless = written.record(None);
            (written, sigless)
        }
    };
    let ty = written.ty();
    let record_text = match d.hand {
        None => sigless.clone(),
        Some(hand) => {
            let Some(term) = board.board_term()? else {
                return Err(DepositHalt::Other(Halt::face(
                    "this board has no H.1 yet",
                    "a record above the claim carries its hand's `sig` over the record frame, whose `board` term is `H.1`'s \
                     pair; the board is claimed and answers no head (the one write after a refused head, or a journal \
                     damaged below H.1)",
                    "retry once the board has written its head; nothing was written",
                )));
            };
            let home_account = board
                .effective_owner(d.home)?
                .map(|o| o.prefix)
                .ok_or_else(|| Halt::face("the home has no owner", format!("`effective_owner({})` answered null", d.home), "this is this client's frame and never your act; nothing was written"))?;
            let frame = RecordFrame { alg: hand.public_key().alg(), board: term, home_account: &home_account, home: d.home, ty, to: &[d.subject], sigless: sigless.as_bytes() }
                .compose()
                .ok_or_else(|| Halt::face("the record frame could not be composed", "an address of the deposit did not parse", "this is this client's frame; nothing was written"))?;
            written.record(Some(&sig_hex(&hand.sign(&frame))))
        }
    };

    // The insert, declared under the record's class type, at the next free
    // content ordinal; `published_target` — this client's own position
    // arithmetic raced — re-reads the ordinal and re-sends ONCE under the
    // same id (§5.3).
    let insert_id = format!("{}.insert", d.id);
    let link_id = format!("{}.link", d.id);
    let mut atom = None;
    for attempt in 0..2 {
        let ordinal = ordinal_at(board, Some(token), d.home)?;
        let v = match board.op(Some(token), &frames::insert_atom(d.home, ordinal, &record_text, ty, Some(&insert_id)))? {
            Answer::Closed => return Err(DepositHalt::SessionClosed(closed_face("inserting the record"))),
            Answer::Document(v) => v,
        };
        if let Some(a) = acked_addr(&v) {
            atom = Some(a.to_string());
            break;
        }
        let Some(r) = Rejection::of(&v) else { return Err(shape_face(&v).into()) };
        match r.key() {
            "published_target" if attempt == 0 => continue,
            _ => return Err(insert_face(&r, &v).into()),
        }
    }
    let Some(atom) = atom else {
        return Err(DepositHalt::Other(Halt::face(
            "the record's insert was refused twice as an in-place edit",
            "`published_target` answered the re-sent insert: this client's position arithmetic is wrong at this home",
            "this is this client's frame and never your act; nothing was written",
        )));
    };

    // AUTH-5.5: the re-read `from` — the bytes at the minted address ARE the
    // record written; pre-claim nothing un-arranges the atom, post-claim doc
    // 1 is published, so a mismatch is this client's own fault.
    if !read_back(board, Some(token), d.home, &atom, &record_text)? {
        return Err(DepositHalt::Other(Halt::face(
            "the record read back from its address is not the record written",
            format!("the atom at {atom} in {} does not hold the bytes this client inserted (AUTH-5.5)", d.home),
            "this is this client's frame; the inserted atom is inert prose in the home, and the deposit was not linked",
        )));
    }

    // The link, carrying the SAME type (PUB-2.63).
    let v = match board.op(Some(token), &frames::make_link(d.home, &[&atom], &[d.subject], ty, Some(&link_id)))? {
        Answer::Closed => return Err(DepositHalt::SessionClosed(closed_face("linking the record"))),
        Answer::Document(v) => v,
    };
    if let (Some(link), Some(at)) = (acked_addr(&v), crate::board::acked_at(&v)) {
        return Ok(DepositOutcome::Deposited { atom, link: link.to_string(), at });
    }
    let Some(r) = Rejection::of(&v) else { return Err(shape_face(&v).into()) };
    reconcile_or_face(board, d, &r, &v, &written)
}

fn shape_face(v: &Value) -> Halt {
    Halt::face("the board answered a shape this client does not know", format!("{v}"), "this is a fault in this client or the board; nothing further was written")
}

/// The insert's own refusals: `record_sig_required`, the attestation
/// tokens and `not_owner` are this client's frame, never the person's act.
fn insert_face(r: &Rejection, v: &Value) -> Halt {
    let token = r.token();
    match r.key() {
        "record_sig_required" => Halt::face(
            "the record was composed without its `sig` above the claim",
            format!("{token}: a record-kind atom carrying no `sig` is refused at its own insert and lands nowhere"),
            "this is this client's frame and never your act: a record above the claim is composed WITH its hand's `sig`",
        ),
        k if k.starts_with("attestation_") => Halt::face(
            "the board judged the record grade and refused",
            format!("{token} at the insert — the frame this client composed did not verify, or the board had no head"),
            "this is this client's frame and never your act; `board_unavailable` is a reorder: retry once the head is written",
        ),
        "unauthenticated" => Halt::face(
            "the session is not live",
            "`unauthenticated`: the token presented is unknown or dead",
            "re-run; the walk resumes by reading (AUTH-5.56)",
        ),
        "not_owner" => Halt::face(
            "this session does not own the home",
            format!("{token}: the record's home is not this principal's own document"),
            "this is this client's frame (the home is the subject's own doc 1 for a holder act) and never your act",
        ),
        _ => r.refused(v),
    }
}

/// THE BASE ARMED SET at the link (§5.3), with AUTH-5.17's reconcile from
/// the records; everything outside it the residue, HALT AND SURFACE. The
/// arms a walk acts on answer by name — `SetFull`, `NotGenesisRegistry` —
/// and every other face rides [`DepositHalt::Other`].
fn reconcile_or_face(board: &Board, d: &Deposit<'_>, r: &Rejection, v: &Value, written: &Written<'_>) -> Result<DepositOutcome, DepositHalt> {
    let other = |h: Halt| -> Result<DepositOutcome, DepositHalt> { Err(DepositHalt::Other(h)) };
    let token = r.token();
    let record_fps = written.fingerprints();
    match r.key() {
        "nothing_changed" => {
            // AUTH-5.17: TWO STATES, read from the records (`key_set`).
            let set = match board.key_set(d.subject)? {
                KeySetAnswer::Set(s) => s,
                KeySetAnswer::NotAnAccount => return other(r.refused(v)),
            };
            match written {
                Written::Enrollment(_) => {
                    if record_fps.iter().all(|fp| set.enrolled(fp).is_some()) {
                        return Ok(DepositOutcome::Committed { reason: "nothing_changed: every key of the record stands enrolled — the act committed and its ack was lost".into() });
                    }
                    if let Some(fp) = record_fps.iter().find(|fp| set.retired(fp).is_some()) {
                        return other(Halt::face(
                            format!("key {fp} is RETIRED at {} and nothing was written", d.subject),
                            "nothing_changed over a retired fingerprint is PERMANENT: I4 (AUTH-2.98) bars its re-entry forever",
                            "the one act is a fresh keypair under a new byline (`skep keygen`), enrolled by a key still in the set",
                        ));
                    }
                }
                Written::Retirement(_) => {
                    if record_fps.iter().all(|fp| set.retired(fp).is_some()) {
                        return Ok(DepositOutcome::Committed { reason: "nothing_changed: the fingerprints stand retired — committed, or another hand's earlier retirement".into() });
                    }
                }
            }
            other(r.refused(v))
        }
        "not_genesis_registry" => {
            // AUTH-5.18: read `key_set(subject)` BEFORE facing anything; the
            // test is CONTAINMENT.
            let set = match board.key_set(d.subject)? {
                KeySetAnswer::Set(s) => s,
                KeySetAnswer::NotAnAccount => return other(r.refused(v)),
            };
            if !record_fps.is_empty() && record_fps.iter().all(|fp| set.enrolled(fp).is_some() || set.retired(fp).is_some()) {
                return Ok(DepositOutcome::Committed { reason: "not_genesis_registry: the record's keys are contained in enrolled ∪ retired — the genesis committed and this retry is the ack (AUTH-5.18)".into() });
            }
            if set.is_empty() {
                return Err(DepositHalt::NotGenesisRegistry(Halt::face(
                    format!("{} holds no set of its own, and nothing goes here", d.subject),
                    "not_genesis_registry at an account whose set is EMPTY: this account's keys are its holder's (AUTH-5.18; AUTH-4.30 (i)); or the record's home is not this account's genesis registry",
                    "no act is needed where the account opens by reference; where this walk meant to seed an account, its home is wrong — this client's frame",
                )));
            }
            let health = board.health()?;
            let claimant = health.claimant().unwrap_or("none");
            Err(DepositHalt::NotGenesisRegistry(Halt::face(
                format!("{} already holds a key set and it is not this record's", d.subject),
                format!(
                    "not_genesis_registry with a NON-EMPTY set holding none of this record's keys (AUTH-5.18's neither arm): this \
                     record's genesis never committed and no retry of it can ever seed the account (AUTH-2.100); the board's \
                     claimant is {claimant}"
                ),
                "where you hold THAT run's anchor sheets the act is AUTH-5.56 boundary 4's — the resume claim signed by an \
                 imported paper anchor — and NO COMMAND IN THIS VERSION PERFORMS IT; otherwise re-genesis the board (stop the \
                 daemon, remove its data directory, start it fresh) and run `skep claim` again — never a fresh `delegate`",
            )))
        }
        "no_holder" => {
            // THE CLAIMED-MID-SPAN CELL (AUTH-5.56 cell 6), forked as AUTH-5.15
            // forks it on `/health.auth.claimant` against this walk's account.
            let health = board.health()?;
            match health.claimant() {
                Some(c) if c == d.subject => other(Halt::face(
                    "another run of this walk won the claim for this very account mid-span",
                    "no_holder at the genesis with this account the board's claimant: the person's two tabs — the other run's genesis landed first",
                    "finish from the other session, which holds the claim; the pair this run exported opens nothing and is destroyed or kept plainly marked dead",
                )),
                Some(c) => other(Halt::face(
                    format!("another hand claimed this board ({c}) while the ceremony was open"),
                    "no_holder: the genesis registry moved to the claimant's doc 1 (AUTH-5.56 cell 6) and the claim is irreversible (I6)",
                    "this account and this board are gone and no act on this board recovers either; what exists is a FRESH board, claimed before it is exposed (AUTH-5.15)",
                )),
                None => other(r.refused(v)),
            }
        }
        "too_many_enrolled" => Err(DepositHalt::SetFull(Halt::face(
            format!("the set at {} is full", d.subject),
            "too_many_enrolled: the enrolled-set cap (16) binds this enrollment",
            "retire a key from this set first — `skep retire --fingerprint <prefix>` from this same signed session — then re-run the act (AUTH-5.13: the act, never the count)",
        ))),
        "content_session" => other(Halt::face(
            "this session was opened for content only",
            "content_session: a content-scoped session cannot deposit, retire or claim a credential (AUTH-3.56 slot (6))",
            "open a FULL session from the device that holds the key — the commands that write a credential open their own",
        )),
        "signed_session_required" => other(Halt::face(
            "a credential write needs a signed session on a claimed board",
            "signed_session_required: this session is bare",
            "sign in with a key this account has enrolled (`skep session` opens content sessions; the credential commands open their own full session)",
        )),
        "anchor_session_required" => {
            let has_anchor = matches!(board.key_set(d.subject)?, KeySetAnswer::Set(s) if s.has_anchor());
            other(Halt::face(
                "this act needs a session an ANCHOR of the account established",
                "anchor_session_required: an anchor retirement or a post-genesis anchor-flagged enrollment needs an anchor session (AUTH-3.20/3.22)",
                if has_anchor {
                    "import a paper anchor of this account and run the walk that takes one — `skep recover` (the loss arm, `--anchor-lost`, where a paper was lost)"
                } else {
                    "no anchor is enrolled on this account: the act is impossible on this account permanently (AUTH-5.16's second arm)"
                },
            ))
        }
        "claim_first" => other(Halt::face(
            "this board is unclaimed and admits only the claim ceremony's own shape",
            "claim_first (AUTH-3.82)",
            "run `skep claim` on this board first",
        )),
        "preview_key" => other(Halt::face(
            "this is a PREVIEW key, and this board enrolls no preview keys",
            "preview_key: the record names a key of the preview kind (`fndsa512-preview-ed25519`) on a daemon launched without `--allow-preview-keys`",
            "make a key with a released client — the production kind, `mldsa65-ed25519` — and enroll that",
        )),
        "not_doc_one" | "unpublished" | "published_target" | "record_sig_required" | "system_account_keyless" | "replaces_not_credential" | "resolved_from" | "emit_not_make_link" | "malformed_shape" => other(Halt::face(
            "the board refused this client's frame",
            format!("{token}: the home, the declaration or the slots this client composed are wrong (never your act)"),
            "this is a fault in this client, not in your keys; nothing was written",
        )),
        k if k.starts_with("malformed_payload") || k == "undecodable_key" => other(Halt::face(
            "the record did not parse at the board",
            format!("{token}: `malformed_payload` names where, `undecodable_key` a key no half of which decodes"),
            "where the record came from another device, re-take it there and never edit it here; where this client composed it, this is its own fault",
        )),
        k if k.starts_with("attestation_") => other(Halt::face(
            "the board judged the record grade and refused",
            format!("{token}: the record's `sig` did not verify under the set that opens the home at the act's grade, or the board had no head"),
            "this is this client's frame and never your act; `board_unavailable` is a reorder: retry once the head is written",
        )),
        "already_claimed" | "claimant_keyless" | "claimant_not_top_level" | "claim_residue" => other(r.refused(v)),
        _ => other(Halt::face(
            format!("the board refused the deposit: {token}"),
            "a refusal no state of this walk arms — AUTH-5.66's residue is HALT AND SURFACE, never a retry",
            "nothing further was written; the walk resumes by reading the board",
        )),
    }
}
