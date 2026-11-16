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
//!   (REG-1.10).
//! * [`registration`] — the one registration-request composition
//!   (REG-4.67; REG-1.86): an applicant's own side, with no board and no
//!   account — the door identifier's form, the device key named or
//!   generated, the backup moment's node arm, the enrolments, the frame and
//!   its one signature, and the check of what it made. It composes and never
//!   writes: the request is deposited by another hand.
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
//!
//! **The rule between the layers.** A walk names compositions and never
//! another walk — what two walks share is a composition — and a composition
//! names no walk; nothing outside this module names it in code, save the
//! crate root's `Send + Sync` check on `handshake::Session` and the unit
//! tests. `tests/it/tidy.rs` checks it.
//!
//! **The attest.** Every `attest` a composition or a walk attaches is
//! composed by [`attest_member`], the ceremony's one `entry_frame` call
//! (P28): the trail's `assert_sup`, and the home mints from a signed session
//! (`first_session`'s two — the first of them `hire`'s step 5 too —
//! `handoff`'s beat (b)), publish-class above the claim (PUB-6.43).
//!
//! No journal: every walk resumes by reading the board (§4.4; P4).

use serde_json::{json, Value};
use skep_address::Address;
use skep_identity::{entry_frame, BoardTerm, DocTerm, EntryBody};

use crate::person::{Person, Public, Statement};
use crate::sign::{sig_hex, Signer};

// The compositions.
pub mod backup;
pub mod deposit;
pub(crate) mod enumerate;
pub mod first_session;
pub mod handshake;
pub(crate) mod import;
pub(crate) mod payload;
pub(crate) mod preview;
pub(crate) mod reads;
pub mod registration;
pub mod registry_record;
pub mod trail;

// The walks.
pub mod accept;
pub mod claim;
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
