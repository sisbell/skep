//! The session endpoints.
//!
//! They are `GET /challenge`, `POST /session` and `POST /session/close`.

use std::time::Instant;

use serde_json::Value;
use skep_namespace::PrincipalId;
use skep_util::json::obj;
use skep_util::permits::edge_clock_now;

use super::actor::Resolved;
use super::reply::{refuse, refuse_handshake, Reply, TransportError};
use super::request::{sole_param, HttpRequest};
use super::Daemon;
use skep_core::auth::session::{
    handshake, parse_session_body, Actor, Opened, SessionBinding, Token, CHALLENGE_TTL_MS,
};
use skep_core::auth::OsEntropy;

impl Daemon {
    /// Answers `GET /challenge?principal=N` with a nonce (AUTH-6.1).
    ///
    /// It issues a nonce for any principal — nothing is secret; the burn is
    /// the credential.
    ///
    /// The mint's clock is the edge clock
    /// (`skep_util::permits::edge_clock_now`): the monotonic clock plus the
    /// test seam's offset, which is nothing in a shipped daemon — so the
    /// store judges a nonce's time to live and its edge pair's hold-down
    /// (`operations.md` §1.1 m12) by one reading, and a suite drives both
    /// through the daemon's one clock seam. The pair is judged at the mint
    /// and said by the daemon at the end of this routing
    /// (`Daemon::say_the_edges_crossed`); it changes nothing of the answer.
    pub(super) fn get_challenge(&self, query: Option<&str>) -> Reply {
        let principal = match challenge_principal(query) {
            Ok(p) => p,
            Err(detail) => return refuse(TransportError::MalformedChallenge, Some(&detail)),
        };
        let nonce =
            self.auth.challenges.issue(PrincipalId(principal), edge_clock_now(), &mut OsEntropy);
        Reply::json(
            200,
            obj(vec![
                ("nonce", Value::String(nonce.to_hex())),
                ("principal", Value::Number(principal.into())),
                ("ttl_ms", Value::Number(CHALLENGE_TTL_MS.into())),
            ]),
        )
    }

    /// Opens a session from `POST /session`'s three-form body (AUTH-6.2).
    ///
    /// The forms are bare (honored per `bare_bind_allowed`), signed (the
    /// challenge/response handshake, verified in every mode), or scoped
    /// signed — the signed form carrying `"scope": "content"`, verified under
    /// the v2 bytes and opening a binding that deposits no credential
    /// (AUTH-4.39). A syntax fault — a scope fault included — is the 400 and
    /// spends no credential; every handshake failure *of the credential* is
    /// the one 401, `session_rejected`, byte-identical across causes
    /// (AUTH-6.5). The one exception, by status: a signed body naming a
    /// principal under a listed prefix is `403 prefix_blocked` carrying the
    /// record's address (AUTH-4.36 step 4b) — [`refuse_handshake`] builds
    /// both.
    pub(super) fn post_session(&self, req: &HttpRequest) -> Reply {
        let body = match parse_session_body(&req.body) {
            Ok(b) => b,
            Err(detail) => {
                return refuse(TransportError::MalformedSessionRequest, Some(&detail))
            }
        };
        // One head snapshot: the world and the key table it carries, so the
        // handshake's account registry and its key set are one committed
        // state.
        let snap = self.engine.kernel().snapshot();
        let outcome = handshake(
            &self.auth.cfg,
            &self.auth.challenges,
            snap.world(),
            body,
            req.peer,
            req.origin.as_deref(),
            Instant::now(),
        );
        match outcome {
            Ok(Opened { principal, signer, scope }) => {
                // Every POST /session mints a distinct SessionId, principal
                // 0 included (AUTH-4.40; M10's bootstrap_session mints
                // fresh per call, as built, AUTH-6.35).
                let sid = if principal == skep_namespace::BOOTSTRAP_PRINCIPAL {
                    self.febe.bootstrap_session()
                } else {
                    self.febe.open_session(principal)
                };
                // The scope is set once, here, from the verified body — the
                // handshake's answer — and the 200 below says nothing of it
                // (AUTH-4.39): a client knows the scope it asked for.
                let token = self
                    .auth
                    .sessions
                    .open(SessionBinding { sid, principal, signer, scope }, &mut OsEntropy);
                Reply::json(
                    200,
                    obj(vec![
                        ("principal", Value::Number(principal.0.into())),
                        ("session", Value::String(token.to_wire())),
                    ]),
                )
            }
            Err(refusal) => refuse_handshake(&refusal),
        }
    }

    /// Answers `POST /session/close` (AUTH-4.47): an idempotent 204.
    ///
    /// Through [`Daemon::token_route`], the header falls out with no special
    /// case — a live token's 204 carries no header (the close is the
    /// person's own act); an unknown or already-dead one resolved `Guest`,
    /// so the route closed it already and its 204 carries
    /// `Skepd-Session: closed`.
    ///
    /// **The third case closes nothing**, and the uniform answer is the
    /// point. A live bare binding whose request
    /// `skep_core::auth::session::bare_bind_allowed` refuses resolves
    /// `Guest(GuestReason::RequestRefused)`, which [`Actor`] states "lives
    /// untouched", so this arm does not fire, nothing is retired, `closed`
    /// is false, and the 204 is byte-identical to a successful close. On the
    /// default loopback bind the one reachable cell is a foreign `Origin` —
    /// the cross-site case the bare arm's origin fence exists for, since
    /// every peer there is loopback and the signed arm consults neither peer
    /// nor origin; a bind beyond loopback (`--bind`) reaches the peer's cell
    /// too. A page that may not write as a binding must not retire it, nor
    /// learn from the answer whether it is live. Every honest client is at an
    /// admitted origin or sends no `Origin` at all.
    pub(super) fn post_session_close(&self, resolved: &Resolved, req: &HttpRequest) -> Reply {
        if let Actor::Principal(_) = &resolved.actor {
            if let Some(t) = req.session_token.as_deref().and_then(Token::parse) {
                self.close_binding(&t);
            }
        }
        Reply { status: 204, body: None, headers: Vec::new() }
    }
}

/// Parses the `/challenge` query: exactly `principal=<non-negative integer>`.
///
/// It reads the query through [`sole_param`].
///
/// # Errors
///
/// [`sole_param`]'s refusals, an absent `principal`, and a value that is
/// not a non-negative integer.
fn challenge_principal(query: Option<&str>) -> Result<u64, String> {
    let v = sole_param(query, "principal")?.ok_or("the required parameter is principal=<id>")?;
    v.parse().map_err(|_| format!("principal: '{v}' is not a non-negative integer"))
}
