//! The ceremonies (`client.md` §1.1's `ceremony` row), in two layers.
//!
//! **The compositions.** Every walk runs over them (P28), each one in-crate
//! home holding its frames, its reads, its armed refusals and its order,
//! every site stating only what it adds:
//!
//! * [`handshake`] — the one session-open composition: AUTH-5.65's pre-check
//!   ahead of the `/challenge`, the challenge with its `ttl_ms` read off the
//!   body, the framing by scope, the one re-challenge on `session_rejected`,
//!   and the three answers with their faces.
//! * [`deposit`] — the one credential-write composition: above the claim
//!   the record grade (the sig-less record, its `record` frame, the hand's
//!   `sig` at the act's grade), then the insert, the re-read `from`, the
//!   link, AUTH-5.6's `id`, AUTH-5.17's reconcile and the base armed set.
//! * [`registry_record`] — the one registry-record composition (REG-1.86;
//!   REG-2.23): the canonical body, its `record` frame and the hand's
//!   `sig`, the cap, the declared insert and its re-read `from`, the link —
//!   and, for an endpoint, the read of the deposit a later one names
//!   (REG-1.10); for a binding, a home's history folded by the walk's rule
//!   and the next prefix read off it (REG-2.3; REG-2.8 to REG-2.10); the
//!   three answers on a request's thread (REG-4.79); the approval link, a
//!   link alone (REG-4.123 step 1); and the reads of a link, a record's
//!   atom and a home's links that a door's console is built from.
//! * [`registration`] — the one registration-request composition
//!   (REG-4.67; REG-1.86): an applicant's own side, with no board and no
//!   account — the door identifier's form, the device key named or
//!   generated, the backup moment's node arm, the enrolments, the frame and
//!   its one signature, and the check of what it made. It composes and never
//!   writes: the request is deposited by another hand.
//! * [`policy`] — the one composition of a door's admission policy
//!   (REG-4.131; REG-4.139): the policy document's version chain read, the
//!   version standing at a position, the three ways a door has none, a
//!   file's check ahead of any write, and the four acts that publish the
//!   next version.
//! * [`first_session`] — the one first-signed-session composition
//!   (AUTH-5.90 (iii); AUTH-5.87): two states, each resumed by reading, the
//!   doc-1 read the metadata read in its three arms (REG-1.52), the second
//!   state never run at an agent's account, which holds no agent space.
//! * [`backup`] — the backup moment in AUTH-5.54's order (§4.2), at its
//!   five sites (the claim, the door-side form, the handoff's recipient,
//!   the hire's custody pair, the registration's pairs) and the loss arm's
//!   cited steps 1–3.
//! * `payload` — the paste door: a canonical record carried in from the
//!   device that generated it, parsed and nothing else (AUTH-2.130), an
//!   anchor-flagged entry refused where the door enrolls device keys alone,
//!   and the comparison beat (AUTH-5.32; R48); and the hire's own tests of
//!   an agent's key record — the flag, exactly one device-flagged entry, a
//!   label that is not empty — with its comparison (AUTH-5.58 step 4).
//! * `preview` — `preview(removed)`, the one retirement preview (AUTH-5.46).
//! * `enumerate` — the head invariant's enumeration (AUTH-5.59's head) and
//!   the by-reference cone (AUTH-5.89).
//! * [`trail`] — the supersession trail, `assert_sup` with its attest
//!   (AUTH-5.59 step 2), resumed by reading.
//! * `import` — the anchor import step (§4a.2 R1), never a command.
//! * `reads` — R0's reads, shared by the recovery family, and the A4 cell.
//!
//! **The walks.** One gesture each, over the compositions:
//!
//! * [`claim`] — the claim as a state machine: the notebook walk (§4.1),
//!   and the hosted arm (§4.5) in its child `hosted`.
//! * [`enroll`] — AUTH-5.32's hop, the signed-in half (§2.2).
//! * [`recover`] — the device arm with its stolen order (§4a.2 R0–R6), and
//!   the loss arm (§4a.6 L0–L7) in its child `loss`.
//! * [`retire`] — the device-key retirement (§4a.4; §2.2).
//! * [`rotate`] — AUTH-5.59's device arm as one gesture, with its trail
//!   (§4a.8 T0–T5).
//! * [`handoff`] — the giver's walk, G0–G6 (§4c.2).
//! * [`accept`] — the recipient's beat (§4c.1).
//! * [`hire`] — the owner's side of the hire ceremony, AUTH-5.58's steps 2–7
//!   in the rule's own order: the agent's account delegated beneath the
//!   agent space, its first key record composed by the owner beside a
//!   custody pair, its home minted, and only then its principal.
//! * [`console`] — the registrar's console at a registry's door (REG-4.107;
//!   REG-4.123 steps 1 to 3): the queue read with the approval's check, the
//!   approval's ordered writes with their resume, the refused and the
//!   denied answers, and the unattended hand's pass over the queue.
//!
//! **The rule between the layers.** A walk names compositions and never
//! another walk — what two walks share is a composition — and a composition
//! names no walk; nothing outside this module names it in code, save the
//! crate root's `Send + Sync` check on `handshake::Session` and the unit
//! tests. `tests/it/tidy.rs` checks it.
//!
//! **The attest.** Every `attest` a composition or a walk attaches is
//! composed by [`attest_member`], the ceremony's one `entry_frame` call
//! (P28): the trail's `assert_sup`, the home mints from a signed session
//! (`first_session`'s two — the first of them `hire`'s step 5 too —
//! `handoff`'s beat (b)), publish-class above the claim (PUB-6.43), the
//! approval link `registry_record` writes into a published home, and the
//! `publish` of a policy version (`policy`).
//!
//! **The well-known creation.** One write stands at this module's root, no
//! composition's and no walk's: [`create_well_known_document`], an account's
//! document created at one of its well-known slots — the mailbox, the bio,
//! the link page or the policy document (wire.md §Namespace) — with
//! [`well_known_frame`], the signed frame a published slot's creation
//! sends, its `attest` composed by that same composer over the slot
//! document's own address. It is here so a ceremony that needs a slot's
//! document made calls one function, and so no second `entry_frame` call
//! enters the ceremonies.
//!
//! No journal: every walk resumes by reading the board (§4.4; P4).

use serde_json::{json, Value};
use skep_address::Address;
use skep_identity::{entry_body_empty, entry_frame, BoardTerm, ContentFreeOp, DocTerm, EntryBody};

use crate::address::{parse_address, well_known_of, MAILBOX_SLOT, WELL_KNOWN_SLOTS};
use crate::board::{acked_addr, acked_nothing, frames, Answer, Board, Rejection};
use crate::halt::Halt;
use crate::person::{Person, Public, Statement};
use crate::sign::{sig_hex, Signer};

use handshake::Session;

// The compositions.
pub mod backup;
pub mod deposit;
pub(crate) mod enumerate;
pub mod first_session;
pub mod handshake;
pub(crate) mod import;
pub(crate) mod payload;
pub mod policy;
pub(crate) mod preview;
pub(crate) mod reads;
pub mod registration;
pub mod registry_record;
pub mod trail;

// The walks.
pub mod accept;
pub mod claim;
pub mod console;
pub mod enroll;
pub mod handoff;
pub mod hire;
pub mod recover;
pub mod retire;
pub mod rotate;

/// Says a pinned statement — a public moment.
///
/// The statement renders its rule beside its text: the one way every walk
/// and composition speaks to the person.
fn say(person: &mut dyn Person, rule: &'static str, text: impl Into<String>) {
    person.say(Public(Statement { rule, text: text.into() }));
}

/// Returns the `attest` member of a publish-class write (signed ops).
///
/// It is `{"alg": …, "sig": <hex>}`: the entry signature by `signer` over
/// the frame `skep_identity::entry_frame` composes — `alg` the signing key's
/// token, `term` `H.1`'s pair, `account` the session's own, `doc` the
/// write's address term and `body` its grammar's rows. Reading the term and
/// parsing the addresses stay the caller's, with their faces.
fn attest_member(term: BoardTerm, account: &Address, doc: DocTerm<'_>, body: &EntryBody, signer: &dyn Signer) -> Value {
    let alg = signer.public_key().alg();
    let bytes = entry_frame(alg, term, account, doc, body);
    json!({"alg": alg, "sig": sig_hex(&signer.sign(&bytes))})
}

/// One well-known creation's answer: the slot's document, and whose act it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WellKnownDocument {
    /// The slot document's address, `<account>.0.<slot>`, as the board
    /// answered it.
    pub addr: String,
    /// Whether this call created the document.
    ///
    /// `false` where it already stood: the board answered the standing
    /// address and committed nothing (wire.md §The response envelope,
    /// `"committed": false`). A re-send under the creating call's own `id`
    /// on its session is that call again — the board answers its first
    /// acknowledgment whole (wire.md §Correlation and idempotency) — so it
    /// reads `true`.
    pub created: bool,
}

/// Returns a published slot's creation frame for `account`, attested.
///
/// It is `frames::create_well_known_document` at `slot` — the bio's, the
/// link page's or the policy document's — carrying the `attest` a published
/// creation owes on a claimed board (PUB-6.43; wire.md §Namespace): the
/// entry signature over the empty body under the op's own token, the
/// frame's `account` the session's own, `own`, and its `doc` the slot
/// document's own address, `<account>.0.<slot>`, signed by `signer`, the
/// session's key — as the daemon composes the frame it verifies, and as the
/// shell's composer does. The address is a function of the request, so the
/// frame is composed before the commit, and one signed for a slot verifies
/// at no other. `term` is `H.1`'s pair, the caller's read.
///
/// # Errors
///
/// A `slot` that is no published well-known slot — the mailbox's, whose
/// creation signs nothing (`frames::create_mailbox`), or a number no slot
/// has — and an address that does not parse: each this client's own frame,
/// nothing sent.
pub fn well_known_frame(term: BoardTerm, own: &str, account: &str, slot: u64, signer: &dyn Signer, id: Option<&str>) -> Result<Value, Halt> {
    if slot == MAILBOX_SLOT || !WELL_KNOWN_SLOTS.contains(&slot) {
        return Err(Halt::face(
            format!("document {slot} of {account} is no published well-known slot"),
            "a signed well-known creation is the bio's (3), the link page's (4) or the policy document's (5); the mailbox's (2) is private and signs nothing (wire.md §Namespace)",
            "this is this client's frame; nothing was written",
        ));
    }
    let frame_fault = || Halt::face("the well-known creation's frame could not be composed", "an address of the creation did not parse", "this is this client's frame; nothing was written");
    let own = parse_address(own).ok_or_else(frame_fault)?;
    let document = parse_address(&well_known_of(account, slot)).ok_or_else(frame_fault)?;
    let attest = attest_member(term, &own, DocTerm::One(&document), &entry_body_empty(ContentFreeOp::CreateWellKnownDocument), signer);
    Ok(frames::create_well_known_document(account, slot, Some(attest), id))
}

/// Creates `account`'s document at the well-known slot `slot`, once.
///
/// It sends `create_well_known_document` under `session` (wire.md
/// §Namespace): at the mailbox's slot the plain frame, which signs nothing
/// and a bare session may send; at the bio's, the link page's and the
/// policy document's the attested frame ([`well_known_frame`]), which a
/// claimed board takes from a signed session alone. The document is created
/// in the slot's own state — the mailbox private, the other three published
/// — and holds nothing: a published slot's first words arrive by an
/// ordinary `stage` from it and a `publish` naming it as `doc`. A slot is
/// created once, so the call is safe to repeat: where the document already
/// stands the board answers its address and commits nothing, and the answer
/// says so ([`WellKnownDocument::created`]). At the mailbox's slot that is
/// every account whose home the board minted: the board creates the mailbox
/// in the home's own commit (the mailbox design §3), so the call answers it
/// standing. `id` is the idempotency id the frame carries.
///
/// # Errors
///
/// A board with no `H.1` yet halts at a published slot, nothing sent;
/// [`well_known_frame`]'s halts; an `attestation_*` refusal is faced as
/// this client's own frame; the session closed, any other refusal — the
/// board's `mint_home_first`, `signed_session_required`, `not_owner`,
/// `system_account_no_well_known` among them, verbatim — an answer that is
/// no `ack_addr`, and the reads' errors halt.
pub fn create_well_known_document(board: &Board, session: &Session<'_>, account: &str, slot: u64, signer: &dyn Signer, id: &str) -> Result<WellKnownDocument, Halt> {
    let frame = if slot == MAILBOX_SLOT {
        frames::create_mailbox(account, Some(id))
    } else {
        let Some(term) = board.board_term()? else {
            return Err(Halt::face(
                format!("this board has no H.1 yet, so document {slot} of {account} cannot be created from this session"),
                "a published well-known creation carries an `attest` naming `H.1`'s pair as its board term, and the board answers no head",
                "retry once the board has written its head; nothing was written",
            ));
        };
        well_known_frame(term, session.account(), account, slot, signer, Some(id))?
    };
    let v = match session.op(&frame)? {
        Answer::Closed => {
            return Err(Halt::face(
                "the session ended at the well-known creation",
                "the board answered `Skepd-Session: closed`",
                "re-run: the creation is made once, and a second call is answered the standing document",
            ))
        }
        Answer::Document(v) => v,
    };
    match Rejection::of(&v) {
        None => match acked_addr(&v) {
            Some(addr) => Ok(WellKnownDocument { addr: addr.to_string(), created: !acked_nothing(&v) }),
            None => Err(Halt::face("the board answered the well-known creation with no address", v.to_string(), "this answer is not the wire's `ack_addr`; nothing is assumed written")),
        },
        Some(r) if r.key().starts_with("attestation_") => Err(Halt::face(
            "the board judged the well-known creation's attest and refused",
            format!("{}: the frame this client composed did not verify under the set that opens the account as of the base, or the board had no head", r.token()),
            "this is this client's frame and never your act; `board_unavailable` is a reorder — retry once the head is written",
        )),
        Some(r) => Err(r.refused(&v)),
    }
}
