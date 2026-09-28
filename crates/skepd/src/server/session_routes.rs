//! The session endpoints (`GET /challenge`, `POST /session`, `POST /session/close`).

use std::time::Instant;

use serde_json::Value;
use skep_namespace::PrincipalId;

use super::actor::Resolved;
use super::reply::{
    at_most_once, query_pairs, refuse, refuse_handshake, HttpRequest, Reply, TransportError,
};
use super::Daemon;
use crate::auth::session::{
    handshake, parse_session_body, Actor, Opened, SessionBinding, Token, CHALLENGE_TTL_MS,
};
use crate::auth::OsEntropy;
use crate::codec::obj;

impl Daemon {
    /// `GET /challenge?principal=N` (AUTH-6.1): issue a nonce for ANY
    /// principal — nothing is secret; the burn is the credential.
    pub(super) fn get_challenge(&self, query: Option<&str>) -> Reply {
        let principal = match challenge_principal(query) {
            Ok(p) => p,
            Err(detail) => return refuse(TransportError::MalformedChallenge, Some(&detail)),
        };
        let nonce =
            self.auth.challenges.issue(PrincipalId(principal), Instant::now(), &mut OsEntropy);
        Reply::json(
            200,
            obj(vec![
                ("nonce", Value::String(nonce.to_hex())),
                ("principal", Value::Number(principal.into())),
                ("ttl_ms", Value::Number(CHALLENGE_TTL_MS.into())),
            ]),
        )
    }

    /// `POST /session` — the three-form body (AUTH-6.2): bare (honored per
    /// `bare_bind_allowed`), signed (the challenge/response handshake,
    /// verified in EVERY mode), or SCOPED signed — the signed form carrying
    /// `"scope": "content"`, verified under the v2 bytes and opening a
    /// binding that deposits no credential (AUTH-4.39). A syntax fault — a
    /// scope fault included — is the 400 and spends no credential; every
    /// handshake failure OF THE CREDENTIAL is the ONE 401,
    /// `session_rejected`, byte-identical across causes (AUTH-6.5).
    /// THE ONE EXCEPTION, BY STATUS: a signed body naming a principal under
    /// a listed prefix is `403 prefix_blocked` carrying the record's
    /// address (AUTH-4.36 step 4b) — [`refuse_handshake`] builds both.
    pub(super) fn post_session(&self, req: &HttpRequest) -> Reply {
        let body = match parse_session_body(&req.body) {
            Ok(b) => b,
            Err(detail) => {
                return refuse(TransportError::MalformedSessionRequest, Some(&detail))
            }
        };
        let snap = self.engine.kernel().snapshot();
        let identity = self.auth.fold.snapshot();
        let outcome = handshake(
            &self.auth.cfg,
            &self.auth.challenges,
            snap.world(),
            &identity,
            body,
            req.peer,
            req.origin.as_deref(),
            Instant::now(),
        );
        match outcome {
            Ok(Opened { principal, signer, scope }) => {
                // Every POST /session mints a DISTINCT SessionId, principal
                // 0 included (AUTH-4.40; M10's bootstrap_session mints
                // fresh per call — confirmed as-built, AUTH-6.35).
                let sid = if principal == skep_namespace::BOOTSTRAP_PRINCIPAL {
                    self.febe.bootstrap_session()
                } else {
                    self.febe.open_session(principal)
                };
                // The scope is set ONCE, here, from the VERIFIED body — the
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

    /// `POST /session/close` (AUTH-4.47): idempotent 204. Through
    /// [`Daemon::token_route`], the header falls out with no special case —
    /// a LIVE token's 204 carries no header (the close is the person's own
    /// act); an unknown or already-dead one resolved Guest, so the route
    /// closed it already and its 204 carries `Skepd-Session: closed`.
    ///
    /// THE THIRD CASE CLOSES NOTHING, and the uniform answer is the point: a
    /// LIVE BARE binding whose request
    /// [`crate::auth::session::bare_bind_allowed`] refuses resolves
    /// `Guest(GuestReason::RequestRefused)`, which [`Actor`] rules "lives
    /// untouched", so this arm does not fire, nothing is retired, `closed`
    /// is false, and the 204 is byte-identical to a successful close. The
    /// one reachable cell is a foreign `Origin` — the cross-site case the
    /// bare arm's origin fence exists for, since this daemon binds loopback
    /// and the signed arm consults neither peer nor origin — and a page that
    /// may not WRITE as a binding must not retire it, nor learn from the
    /// answer whether it is live. Every honest client is at an admitted
    /// origin or sends no `Origin` at all.
    pub(super) fn post_session_close(&self, resolved: &Resolved, req: &HttpRequest) -> Reply {
        if let Actor::Principal(_) = &resolved.actor {
            if let Some(t) = req.session_token.as_deref().and_then(Token::parse) {
                self.close_binding(&t);
            }
        }
        Reply { status: 204, body: None, headers: Vec::new() }
    }
}

/// The `/challenge` query: exactly `principal=<non-negative integer>`.
fn challenge_principal(query: Option<&str>) -> Result<u64, String> {
    let query = match query {
        None | Some("") => return Err("the required parameter is principal=<id>".into()),
        Some(query) => query,
    };
    let mut principal: Option<u64> = None;
    for (k, v) in query_pairs(query)? {
        match k {
            "principal" => {
                at_most_once(&principal, "parameter", "principal")?;
                principal = Some(
                    v.parse()
                        .map_err(|_| format!("principal: '{v}' is not a non-negative integer"))?,
                );
            }
            other => return Err(format!("unknown parameter '{other}'")),
        }
    }
    principal.ok_or_else(|| String::from("the required parameter is principal=<id>"))
}
