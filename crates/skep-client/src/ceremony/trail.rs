//! The supersession trail (`client.md` §4a.5; AUTH-5.59 step 2).
//!
//! It is `assert_sup` from the old enroll link to the new enroll link —
//! links, never the record documents — homed in the subject account's own
//! doc 1, written by `rotate` (§4a.8 T3) and the loss arm (§4a.6, between
//! L5 and L6) and by `recover`'s device arm never (AUTH RES-62 §6). Above
//! the claim the trail is publish-class (homed in a published doc 1, sent
//! from a signed session), so it carries an `attest` over its own entry
//! frame — composed through the ceremony's one composer (`attest_member`;
//! P28) with `entry_body_assert_sup`'s body, and signed by the walk's own
//! key (the old key at `rotate`, the surviving anchor on the loss arm). At
//! an account's first rotation the old enroll link is its genesis, homed in
//! the genesis registry (AUTH-2.62, AUTH-2.127): the subject's own doc 1 at
//! the notebook's claimant, the delegating account's at a handoff's
//! recipient or a hired agent. The trail is resumed by reading its presence
//! over the residence-address discovery, so a re-run never writes a second
//! trail (AUTH-5.59 step 3's machine resume). That discovery reads the
//! active view, where a retracted trail reads as absent, so the resume
//! holds because the board refuses the trail's retraction from every
//! session as the subject, wherever its `old` is homed (PUB-6.64,
//! `nullify_audit_view`; skep #677).

use skep_identity::{entry_body_assert_sup, unit_span, DocTerm, EntrySlot, LinkSlots};

use super::attest_member;
use crate::address::parse_address;
use crate::board::{acked_addr, answers, frames, Answer, Board, Rejection, T_SUPERSEDES};
use crate::ceremony::enumerate::link_subject;
use crate::ceremony::handshake::Session;
use crate::halt::Halt;
use crate::sign::Signer;

/// One supersession trail, named by its three addresses.
///
/// `home` is the subject account's own doc 1 it is homed in, `old` the old
/// enroll link and `new` the new one. The addresses are named so `old` and
/// `new` cannot trade places in a call — a claim written backwards is
/// permanent and public, and the resume read, which looks from `old`, would
/// miss it and write a second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Trail<'a> {
    /// The subject account's own doc 1 the trail is homed in.
    pub home: &'a str,
    /// The old enroll link.
    pub old: &'a str,
    /// The new enroll link.
    pub new: &'a str,
}

impl Trail<'_> {
    /// Reads whether a supersession claim from `old` to `new` already stands.
    ///
    /// It is the resume read — `find_links_ftt` over the supersedes type and
    /// `old`'s unit span, each claim's `to` read off `read_link` — answering
    /// the claim's address, else `None`.
    ///
    /// # Errors
    ///
    /// [`Board::guest`]'s errors, the discovery's and each `read_link`'s.
    pub fn present(&self, board: &Board) -> Result<Option<String>, Halt> {
        let v = board.guest(&frames::find_links_ftt_from(T_SUPERSEDES, self.old))?;
        for claim in answers::addrs(&v) {
            if link_subject(board, claim)?.as_deref() == Some(self.new) {
                return Ok(Some(claim.to_string()));
            }
        }
        Ok(None)
    }

    /// Writes the trail: `assert_sup` homed in `home`, with its `attest`.
    ///
    /// The entry frame's `alg` is the signing key's token, `board` `H.1`'s
    /// pair, `account` the session's account, `doc` the home, the body
    /// `entry_body_assert_sup`'s four rows (the supersedes class's unit span,
    /// `old`'s, `new`'s, the `replaces` row empty) — signed by `signer`. It
    /// answers the claim's address.
    ///
    /// # Errors
    ///
    /// A board with no `H.1` yet halts, nothing written; an address of the
    /// trail that does not parse is this client's frame; the session closed,
    /// an answer of a shape this client does not know, an endpoint that is
    /// not a resident link, an `attestation_*` refusal and `not_owner` are
    /// each faced; any other refusal is the board's; and the reads' and the
    /// write's own errors.
    pub fn write(&self, board: &Board, session: &Session<'_>, signer: &dyn Signer, id: &str) -> Result<String, Halt> {
        let Trail { home, old, new } = *self;
        let Some(term) = board.board_term()? else {
            return Err(Halt::face("this board has no H.1 yet", "the trail's `attest` names `H.1`'s pair as its board term and the board answers no head", "retry once the board has written its head; nothing was written"));
        };
        let frame_fault = || Halt::face("the trail's frame could not be composed", "an address of the trail did not parse", "this is this client's frame; nothing was written");
        let account = parse_address(session.account()).ok_or_else(frame_fault)?;
        let home_addr = parse_address(home).ok_or_else(frame_fault)?;
        let old_addr = parse_address(old).ok_or_else(frame_fault)?;
        let new_addr = parse_address(new).ok_or_else(frame_fault)?;
        let ty_addr = parse_address(T_SUPERSEDES).ok_or_else(frame_fault)?;
        let (from, to, ty) = ([unit_span(&old_addr)], [unit_span(&new_addr)], [unit_span(&ty_addr)]);
        let body = entry_body_assert_sup(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) });
        let attest = attest_member(term, &account, DocTerm::One(&home_addr), &body, signer);
        let v = match session.op(&frames::assert_sup(home, old, new, Some(attest), Some(id)))? {
            Answer::Closed => {
                return Err(Halt::face(
                    "the session ended while writing the supersession trail",
                    "the board answered `Skepd-Session: closed`",
                    "re-run: the trail resumes by reading its presence (AUTH-5.59 step 3)",
                ))
            }
            Answer::Document(v) => v,
        };
        if let Some(claim) = acked_addr(&v) {
            return Ok(claim.to_string());
        }
        let Some(r) = Rejection::of(&v) else {
            return Err(Halt::face("the trail answered a shape this client does not know", v.to_string(), "this is a fault in this client or the board"));
        };
        Err(match r.key() {
            "endpoint_not_resident" | "original_not_resident" => Halt::face(
                "an endpoint of the trail is not a resident link",
                format!("{}: `old` {old} or `new` {new} is no link this session may read (wire.md §Links (writes))", r.token()),
                "this is this client's frame — the old enroll link is the admitted read's and the new one T2's ack; re-run, the walk resumes by reading",
            ),
            k if k.starts_with("attestation_") => Halt::face(
                "the board judged the trail's attest and refused",
                format!("{}: the frame this client composed did not verify under the set that opens the account as of the base, or the board had no head", r.token()),
                "this is this client's frame and never your act; `board_unavailable` is a reorder — retry once the head is written",
            ),
            "not_owner" => Halt::face(
                "this session does not own the trail's home",
                format!("{}: the trail is homed in the subject account's own doc 1 and ω admits the write from that account's session alone", r.token()),
                "this is this client's frame and never your act",
            ),
            _ => r.refused(&v),
        })
    }
}
