//! THE ONE SESSION-OPEN COMPOSITION (`client.md` §1.1's `handshake`; P28):
//! AUTH-5.65's pre-check ahead of the `/challenge` — the origin arm first
//! (AUTH-5.24), then the key-set compare at the set AUTH-5.21's walk reaches
//! — the challenge with its `ttl_ms` read off the body and never assumed,
//! the framing under `SESSION_TAG` or `SESSION_TAG_V2` as `scope` says
//! (AUTH-6.4), the signature, the body (AUTH-6.2), the ONE re-challenge on
//! `session_rejected` (AUTH-5.25), and the three answers with their faces:
//! AUTH-5.25's TERMINAL BUSY arm in the rule's own words; `403
//! prefix_blocked`'s HALT AND SURFACE with the ground read as a guest
//! (AUTH-5.66; RES-73), never a retry and never "busy"; and `400
//! malformed_session_request`, this client's own framing, surfaced verbatim.
//! The one re-challenge completes before the composition returns, so a
//! caller holding key material may drop it on return where nothing after
//! signs with it. The SCOPE is the walk's, passed once. The [`Session`] it
//! answers owns its own END.

use skep_identity::Fingerprint;

use crate::board::{answers, frames, Answer, Board, CloseAnswer, Opened, Scope, SessionBody, Token};
use crate::derive::records::{credential_records, Hand};
use crate::derive::{precheck, KeyDiagnosis, PreCheck};
use crate::halt::{Blocked, Halt};
use crate::sign::{session_payload, sig_hex, Signer};

/// One open signed session: the token, what it was opened as and the board
/// it stands at — and THE OWNER OF ITS OWN END. Exactly one of three acts
/// ends it, each consuming it: [`Session::close`], `POST /session/close`
/// (AUTH-4.47; AUTH-5.54 step 3's mirror takes "the SESSION and not the
/// material alone"); [`Session::ended_by_commit`], where the act's own
/// commit ended it — the session's own key retired (AUTH-4.63) — and no
/// close is owed; and [`Session::into_token`], the token handed out live. A
/// session dropped by none of them — every halt a walk takes after its
/// handshake — sends the close on the drop, best effort, so no exit leaves
/// a session standing at the daemon until its restart (§4a.3's residue).
#[derive(Debug)]
pub struct Session<'b> {
    board: &'b Board,
    /// One of the three ends ran: the drop sends nothing.
    ended: bool,
    pub token: Token,
    pub principal: u64,
    pub scope: Scope,
    /// `principal_prefix(principal)` — the account the session acts as.
    pub account: String,
    /// The key that opened it.
    pub fingerprint: Fingerprint,
}

impl Session<'_> {
    /// One frame under this session's token, at the board it stands at.
    pub fn op(&self, frame: &serde_json::Value) -> Result<Answer, Halt> {
        self.board.op(Some(&self.token), frame)
    }

    /// `POST /session/close` (AUTH-4.47) — the session's ordinary end.
    pub fn close(mut self) -> Result<CloseAnswer, Halt> {
        self.ended = true;
        self.board.session_close(&self.token)
    }

    /// The end where the act's own commit ended the session (AUTH-4.63: a
    /// retirement of the key that opened it kills its sessions at the
    /// commit): nothing is sent — the `closed` any later request would meet
    /// is the act's EXPECTED END (AUTH-5.28). Called only after that commit
    /// answered; a retirement that did not commit leaves the session live,
    /// and its drop closes it.
    pub fn ended_by_commit(mut self) {
        self.ended = true;
    }

    /// The end where the session outlives this process: its token handed
    /// out LIVE — `skep session`'s one datum (§2.2), which the holder closes.
    pub fn into_token(mut self) -> Token {
        self.ended = true;
        self.token.clone()
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        if !self.ended {
            let _ = self.board.session_close(&self.token);
        }
    }
}

/// THE SITE a handshake runs at — what the key arm's third-state face names
/// as its act (`client.md` §2.2 `verify`: the act is site-specific, so the
/// face names the site rather than a retry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Site {
    /// `skep session` — a board this store claimed, or is keyless for.
    Session,
    /// The claim's own signed session (S5): the genesis recorded a pubkey
    /// this key does not match (AUTH-5.25 (iii)).
    Claim,
    /// The claim's tail on the OURS arm, and `bind`'s setup arm.
    Tail,
    /// `first_session`'s op (3), a session AS `inc(account, 1)` by reference.
    Setup,
    /// The hosted customer's first signed session, the detection H6 names.
    Hosted,
    /// The recovery's anchor session (§4a.2 R2) and the loss arm's: the key
    /// is an IMPORTED anchor, so neither list is the WRONG SHEET (AUTH-5.25
    /// (iii)) — another account's or another board's paper.
    Recover,
    /// The giver's session at the handoff door (§4c.2), the one it opens
    /// BY REFERENCE as the giving account included.
    Giver,
}

/// THE THREE-STATE KEY FACE (`client.md` §2.2 `verify`), ONE diagnosis shared
/// by `verify`, `session`'s pre-check and `enroll`: `retired` ⇒ I4's
/// permanent bar (AUTH-2.98), the hand named from the records where it can be
/// read (AUTH-5.28's chrome where this store's own, AUTH-5.77's where
/// another's), neither asserted below the floor (§9 item 50); in NEITHER list
/// ⇒ AUTH-5.25 (iii) with the act by site.
pub fn key_face(board: &Board, pre: &PreCheck, fp: &Fingerprint, own: &[(Fingerprint, skep_identity::PublicKey)], site: Site) -> Result<(), Halt> {
    match pre.diagnosis {
        KeyDiagnosis::Enrolled { .. } => Ok(()),
        KeyDiagnosis::Retired { .. } => {
            // The hand and the position, from the admitted read (RULED, owner
            // 2026-09-22 "i"); the read made only on this failing path.
            let records = credential_records(board, &pre.walk.set_account, own).ok();
            let label = records.as_ref().and_then(|r| r.label_of(fp));
            let named = match &label {
                Some(l) => format!("{fp} ({})", crate::sheet::render_inert(l)),
                None => fp.to_string(),
            };
            let retirement = records.as_ref().and_then(|r| r.retirement_of(fp).map(|rec| (rec.hand.clone(), rec.position, r.label_of_hand(&rec.hand))));
            let cause = match retirement {
                Some((Hand::Key(hand), Some(at), hand_label)) => {
                    let whose = if own.iter().any(|(f, _)| *f == hand) { "this store's own key — the person did this (AUTH-5.28)" } else { "ANOTHER hand (AUTH-5.77)" };
                    let hand_text = match hand_label {
                        Some(l) => format!("{hand} ({})", crate::sheet::render_inert(&l)),
                        None => hand.to_string(),
                    };
                    format!("retired at position {at} by {hand_text}: {whose}")
                }
                Some((Hand::Bare, Some(at), _)) => format!("retired at position {at} by a bare session"),
                Some((_, _, _)) | None => "this fingerprint stands RETIRED; who wrote the retirement, and when, was not readable at this board (below its retention floor, or the record unfetchable) — no hand is asserted".to_string(),
            };
            Err(Halt::face(
                format!("key {named} is retired at account {} — it is never accepted again", pre.walk.set_account),
                format!("{cause}; I4 (AUTH-2.98): a retired fingerprint never re-enters the set, and no act on this key changes it"),
                "the one act is a fresh keypair under a new byline (`skep keygen`), enrolled by a key still in the set — never 'check your key path'",
            ))
        }
        KeyDiagnosis::Neither => {
            let act = match site {
                Site::Session | Site::Tail => format!(
                    "at a board this store claimed, the key on your paper is not the key in the set (the wrong sheet, \
                     AUTH-5.25 (i)/(iii)); at a board this store is keyless for, either enroll this key from a device of yours \
                     still signed in (`skep keygen --payload` here, `skep enroll` there, `skep bind` back here) or recover \
                     from a paper anchor (`skep keygen` here, then `skep recover`); the set the walk reached is {}'s",
                    pre.walk.set_account
                ),
                Site::Recover => format!(
                    "THE WRONG SHEET (AUTH-5.25 (iii)): the key on this paper is not a key of the set at {} — another account's \
                     or another board's paper; check the three facts it carries against the board and the principal you named",
                    pre.walk.set_account
                ),
                Site::Giver => format!(
                    "the giver's key stands in neither list of the set that opens the giving account ({}); a handoff is made \
                     by a key of the set that opens the account above the subdivision (AUTH-5.90)",
                    pre.walk.set_account
                ),
                Site::Claim => "the genesis recorded a pubkey this key does not match; AUTH-5.25 (iii)'s act is a pinned order — \
                     import a paper anchor and sign the claim with it, the device key enrolled as the resume's next act — and NO \
                     COMMAND IN THIS VERSION PERFORMS IT"
                    .to_string(),
                Site::Setup => "the key that would open the agents' home stands in neither list of the set that opens it; the \
                     setup act is sent not at all (P13)"
                    .to_string(),
                Site::Hosted => "this is exactly the arrival the hosted reply's first act exists to produce: this account is not \
                     yours to keep (AUTH-5.53) — never a re-run"
                    .to_string(),
            };
            Err(Halt::face(
                format!("this account's records do not list this key: {fp} is in neither list of the set at {}", pre.walk.set_account),
                format!(
                    "AUTH-5.25 cell (iii): `key_set` at {} (reached by AUTH-5.21's walk from {}) holds the key neither enrolled nor retired",
                    pre.walk.set_account, pre.account
                ),
                act,
            ))
        }
    }
}

/// THE COMPOSITION: the pre-check, then the handshake.
pub fn handshake<'b>(board: &'b Board, scope: Scope, signer: &dyn Signer, principal: u64, site: Site) -> Result<Session<'b>, Halt> {
    let fp = signer.fingerprint();
    let pre = precheck(board, principal, &fp)?;
    handshake_prechecked(board, scope, signer, principal, &pre, site)
}

/// The handshake over reads the caller already made (the claim's S5, whose
/// `principal_prefix` and `key_set` reads are live).
pub fn handshake_prechecked<'b>(board: &'b Board, scope: Scope, signer: &dyn Signer, principal: u64, pre: &PreCheck, site: Site) -> Result<Session<'b>, Halt> {
    let fp = signer.fingerprint();
    let own = [(fp, signer.public_key())];
    key_face(board, pre, &fp, &own, site)?;
    let mut rejected_once = false;
    loop {
        let challenge = board.challenge(principal)?;
        if challenge.ttl_ms == 0 {
            return Err(Halt::face(
                "the challenge carried no ttl_ms",
                "`GET /challenge` answered a body without the TTL the wire pins (wire.md §Sessions)",
                "this board is not speaking the wire this client expects; nothing was written",
            ));
        }
        let payload = session_payload(&board.signed, &challenge.nonce, principal, scope);
        let sig = sig_hex(&signer.sign(&payload));
        match board.session_open(SessionBody::Signed { principal, nonce: &challenge.nonce, sig_hex: &sig, scope })? {
            Opened::Token(token) => {
                return Ok(Session { board, ended: false, token, principal, scope, account: pre.account.clone(), fingerprint: fp });
            }
            Opened::Rejected => {
                if rejected_once {
                    // AUTH-5.25's TERMINAL BUSY ARM, in the rule's own words:
                    // the pre-check found this key enrolled and this origin
                    // answered for, so the cause is transient, never a
                    // mis-signing.
                    return Err(Halt::face(
                        "the board did not accept the sign-in",
                        "two `401 session_rejected` in a row after a pre-check that passed — this key is enrolled and this \
                         origin is answered for — so the cause is transient: the board may be busy, or a third party is \
                         evicting nonces (AUTH-5.26, indistinguishable from load)",
                        "try again",
                    ));
                }
                rejected_once = true;
                continue;
            }
            Opened::Blocked { record } => {
                let ground = read_ground(board, &record);
                return Err(Halt::Blocked(Blocked { record, named_by: board.dialed.as_str().to_string(), ground }));
            }
        }
    }
}

/// The takedown record's text, read AS A GUEST at the board that named it
/// (RES-73's reading): the record value at the version address's first
/// position, off `retrieve_v` — `None` where it does not answer one. Best
/// effort: whether its ω prefix covers this account and its home is that
/// board's doc 1 are stated in the face as what was and was not read.
fn read_ground(board: &Board, record: &str) -> Option<String> {
    let v = board.guest(&frames::retrieve_v(record, 1, 1)).ok()?;
    answers::first_atom(&v).and_then(|bytes| String::from_utf8(bytes).ok())
}
