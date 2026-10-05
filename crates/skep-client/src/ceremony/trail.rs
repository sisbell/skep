//! THE SUPERSESSION TRAIL (`client.md` §4a.5; AUTH-5.59 step 2): `assert_sup`
//! from the OLD enroll LINK to the NEW enroll LINK — links, never the record
//! documents — homed in the SUBJECT ACCOUNT'S OWN DOC 1, written by `rotate`
//! (§4a.8 T3) and the LOSS arm (§4a.6, between L5 and L6) and by `recover`'s
//! device arm NEVER (AUTH RES-62 §6). Above the claim the trail is
//! publish-class (homed in a published doc 1, sent from a signed session),
//! so it carries an `attest` over its own entry frame — composed through
//! `skep_identity::entry_frame` with `entry_body_assert_sup`'s body, the one
//! composer (P28; no second `entry_frame`), and signed by the walk's own key
//! (the OLD key at `rotate`, the surviving anchor on the LOSS arm). RESUMED
//! BY READING the trail's presence over the residence-address discovery, so
//! a re-run never writes a second trail (AUTH-5.59 step 3's machine resume).

use serde_json::json;
use skep_identity::{entry_body_assert_sup, entry_frame, unit_span, DocTerm, EntrySlot, LinkSlots};

use crate::board::{acked_addr, frames, Answer, Board, Rejection, T_SUPERSEDES};
use crate::ceremony::enumerate::link_subject;
use crate::ceremony::handshake::Session;
use crate::derive::records::parse_address;
use crate::halt::Halt;
use crate::sign::{sig_hex, Signer};

/// THE RESUME READ: a supersession claim FROM `old` already stands —
/// `find_links_ftt` over the supersedes type and `old`'s unit span — its
/// address, else `None`. Where `new` is given the claim must name it as its
/// `to`.
pub fn trail_present(board: &Board, old: &str, new: Option<&str>) -> Result<Option<String>, Halt> {
    let Answer::Document(v) = board.op(None, &frames::find_links_ftt_from(T_SUPERSEDES, old))? else { return Ok(None) };
    for claim in v["addrs"].as_array().into_iter().flatten().filter_map(|a| a.as_str()) {
        match new {
            None => return Ok(Some(claim.to_string())),
            Some(n) => {
                if link_subject(board, claim)?.as_deref() == Some(n) {
                    return Ok(Some(claim.to_string()));
                }
            }
        }
    }
    Ok(None)
}

/// THE WRITE: `assert_sup` homed in `home`, with its `attest` — the entry
/// frame's `alg` the signing key's token, `board` `H.1`'s pair, `account`
/// the session's account, `doc` the home, the body `entry_body_assert_sup`'s
/// four rows (the supersedes class's unit span, `old`'s, `new`'s, the
/// `replaces` row empty) — signed by `signer`. Answers the claim's address.
pub fn write_trail(board: &Board, session: &Session, signer: &dyn Signer, home: &str, old: &str, new: &str, id: &str) -> Result<String, Halt> {
    let Some(term) = board.board_term()? else {
        return Err(Halt::face("this board has no H.1 yet", "the trail's `attest` names `H.1`'s pair as its board term and the board answers no head", "retry once the board has written its head; nothing was written"));
    };
    let frame_fault = || Halt::face("the trail's frame could not be composed", "an address of the trail did not parse", "this is this client's frame; nothing was written");
    let account = parse_address(&session.account).ok_or_else(frame_fault)?;
    let home_addr = parse_address(home).ok_or_else(frame_fault)?;
    let old_addr = parse_address(old).ok_or_else(frame_fault)?;
    let new_addr = parse_address(new).ok_or_else(frame_fault)?;
    let ty_addr = parse_address(T_SUPERSEDES).ok_or_else(frame_fault)?;
    let (from, to, ty) = ([unit_span(&old_addr)], [unit_span(&new_addr)], [unit_span(&ty_addr)]);
    let body = entry_body_assert_sup(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) });
    let alg = signer.public_key().alg().to_string();
    let bytes = entry_frame(&alg, term, &account, DocTerm::One(&home_addr), &body);
    let attest = json!({"alg": alg, "sig": sig_hex(&signer.sign(&bytes))});
    let v = match session.op(board, &frames::assert_sup(home, old, new, Some(attest), Some(id)))? {
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
    Err(match r.token().as_str() {
        "endpoint_not_resident" | "original_not_resident" => Halt::face(
            "an endpoint of the trail is not a resident link",
            format!("{}: `old` {old} or `new` {new} is no link this session may read (wire.md §Links (writes))", r.token()),
            "this is this client's frame — the old enroll link is the admitted read's and the new one T2's ack; re-run, the walk resumes by reading",
        ),
        t if t.starts_with("attestation_") => Halt::face(
            "the board judged the trail's attest and refused",
            format!("{t}: the frame this client composed did not verify under the set that opens the account as of the base, or the board had no head"),
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
