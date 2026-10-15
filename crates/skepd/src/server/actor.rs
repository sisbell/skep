//! How a request's session resolves.
//!
//! The items are `Resolved`, `resolve_actor` and `close_binding`.

use skep_engine::World;
use skep_febe::SessionId;
use skep_namespace::PrincipalId;

use super::request::HttpRequest;
use super::Daemon;
use skep_core::auth::session::{resolve, Actor, GuestReason, Token};

impl Daemon {
    /// Closes one token's binding in both stores, and the credential memo.
    ///
    /// The stores are the sessions map and M10. [`Daemon::resolve_actor`]'s
    /// eviction arm and `/session/close` share it.
    pub(super) fn close_binding(&self, token: &Token) {
        if let Some(binding) = self.auth.sessions.close(token) {
            self.febe.close_session(binding.sid);
            self.auth.memo.purge(binding.sid);
        }
    }

    /// Resolves the actor, the death sequence's one home (AUTH-4.42).
    ///
    /// The sequence has four parts: the site's own token parse and lookup,
    /// `resolve` against the world the *caller* supplies, the
    /// close-both-stores arm on `Unknown | BindingDead`, and whether this
    /// response owes `Skepd-Session: closed`.
    ///
    /// The world is the caller's because that is the only thing the sites
    /// differ by: the route level resolves against the head
    /// ([`Daemon::resolve_at_head`]; AUTH-4.29 — historical routes included),
    /// the write sequences against the snapshot their gates stand on
    /// (`locked_state`; AUTH-4.28's which-lookup pin), and the blob finish
    /// against the head under the credential lock. The key table is that
    /// world's own slice, so no caller can hand one from another snapshot.
    /// Every `Guest` at a write sequence then answers `unauthenticated` by
    /// executing under M10's guest session — M10's own code, with the op kind
    /// named.
    ///
    /// The answer is a [`Resolved`], whose two fields are the actor this
    /// request acts as and whether the fourth step above fired — so the
    /// death signal a response owes is named at this signature rather than
    /// reassembled from a bare `bool` at each call.
    pub(super) fn resolve_actor(&self, req: &HttpRequest, world: &World) -> Resolved {
        // A present-but-unparseable token is no token (AUTH-4.18):
        // `Guest(NoToken)`, nothing to close, no header.
        let token = req.session_token.as_deref().and_then(Token::parse);
        let lookup = self.auth.sessions.lookup(token.as_ref());
        let actor = resolve(&self.auth.cfg, lookup, req.peer, req.origin.as_deref(), world);
        let closed =
            matches!(actor, Actor::Guest(GuestReason::Unknown | GuestReason::BindingDead));
        if closed {
            if let Some(t) = &token {
                self.close_binding(t);
            }
        }
        Resolved { actor, closed }
    }
}

/// How one request's session resolved.
///
/// It holds the actor the request acts as, and whether this response owes
/// the `Skepd-Session: closed` header.
pub(super) struct Resolved {
    pub(super) actor: Actor,
    pub(super) closed: bool,
}

impl Resolved {
    /// Returns the principal the request's reads run at.
    ///
    /// It is the bound principal, or `None` for the guest (an absent,
    /// unparseable, unknown or dead token, or a bare bind this request's
    /// peer or origin refuses).
    pub(super) fn principal(&self) -> Option<PrincipalId> {
        match &self.actor {
            Actor::Principal(binding) => Some(binding.principal),
            Actor::Guest(_) => None,
        }
    }

    /// Returns the session the request's dispatch runs under.
    ///
    /// It is the bound one, or M10's guest, [`SessionId::GUEST`] (M10 serves
    /// reads and refuses writes `Unauthenticated` under it).
    pub(super) fn sid(&self) -> SessionId {
        match &self.actor {
            Actor::Principal(binding) => binding.sid,
            Actor::Guest(_) => SessionId::GUEST,
        }
    }
}
