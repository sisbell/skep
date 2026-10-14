//! THE STATUS MAP (Q5 (a); the provisioning record §5.2), the book's, in
//! memory: each post this process admitted, by its STATUS TOKEN — 128 bits
//! of OS entropy as lowercase hex (`names::unguessable`), shown only to the
//! poster and in the mail, NEVER LOGGED — with its name, its state
//! ([`PostState`]) and what the reply needs that a name does not say, the
//! record's anchorless fact; and THE NAMES ROUTED AT START, REBUILT from the
//! snippet directory as Q5 (a) rules — every `<name>.caddy` file
//! `caddy::routed` reads — which the serving line counts as `live`. A post
//! this process makes live is live by its own state, and no name is added to
//! them: whether a board is live now is what stands under its name
//! (`names::taken`), never a list kept here. The reply's three facts are kept
//! nowhere here: they are the constants and the public origin, and the reply
//! renders them (`reply`). The map holds NAMES across a restart and no token:
//! a token is never written anywhere, so a status URL minted before a restart
//! answers 404 after it, though the board it named stands, live, and its mail
//! — if it was sent — carries the reply.
//!
//! ITS ONE CLIENT is the book, `flow`'s `Book`: the map keeps each post's
//! state and which states hold a name, and the book's rules alone move a
//! post — so the map is a module of `flow`'s own, which no module but
//! `flow` can name.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::io;
use std::path::Path;

use crate::caddy;
use crate::name::Name;

/// A post's state, from its admission to its end: IN FLIGHT while queued or
/// running — its name held, its page D-7 — then ENDED, live or failed, its
/// state final.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostState {
    /// Admitted, waiting for the worker: D-7.
    Queued,
    /// The worker runs its steps: D-7.
    Running,
    /// The route stands: the live reply.
    Live,
    /// A step failed and the cleanup ran: D-8 — what the post made removed,
    /// or, where a removal itself failed, what it left standing under the
    /// name, logged (the provisioning record §5.2's named gap).
    Failed,
}

impl PostState {
    /// Whether the post has ENDED — live or failed: its state final, its
    /// name held no more. A post that has not is in flight.
    fn ended(self) -> bool {
        matches!(self, PostState::Live | PostState::Failed)
    }
}

/// One post this process admitted, as its status page reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedPost {
    /// The board's name.
    pub name: Name,
    /// Its state.
    pub state: PostState,
    /// Whether its record carried no anchor-flagged entry — the reply's
    /// anchorless sentence.
    pub anchorless: bool,
}

/// THE STATUS MAP: this process's posts by token, and the names routed at
/// start.
#[derive(Clone, Default)]
pub struct StatusMap {
    posts: HashMap<String, AdmittedPost>,
    routed_at_start: BTreeSet<Name>,
}

/// The posts' count and the names routed at start: the map's keys are
/// status tokens, never a log line's.
impl fmt::Debug for StatusMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatusMap").field("posts", &self.posts.len()).field("routed_at_start", &self.routed_at_start).finish()
    }
}

impl StatusMap {
    /// THE REBUILD AT START (Q5 (a)): each name [`caddy::routed`] reads,
    /// routed at start; no post, no token.
    pub fn rebuild(boards_dir: &Path) -> io::Result<StatusMap> {
        Ok(StatusMap { posts: HashMap::new(), routed_at_start: caddy::routed(boards_dir)?.into_iter().collect() })
    }

    /// A post admitted under `token`: queued. PRECONDITION, the caller's:
    /// `token` is one this process never admitted — a token is its post's
    /// identity, and an ended post's state is final — so a token admitted
    /// twice is the caller's bug, and panics naming it before the map
    /// changes.
    pub fn admit(&mut self, token: String, name: Name, anchorless: bool) {
        assert!(!self.posts.contains_key(&token), "`admit` takes a token this process never admitted: a token is its post's identity");
        self.posts.insert(token, AdmittedPost { name, state: PostState::Queued, anchorless });
    }

    /// `token`'s post moved to `state`. PRECONDITION, the caller's: `token`
    /// is one this process admitted, and its post has not ended — a live or
    /// a failed post's state is final, for its page says how it ended and an
    /// ended post holds no name — as the book's rules alone move a post.
    /// Either broken is the caller's bug, and panics naming it.
    pub fn set(&mut self, token: &str, state: PostState) {
        let post = self.posts.get_mut(token).expect("`set` names a token this process admitted: the book moves only its own jobs' posts");
        assert!(!post.state.ended(), "`set` moves a post that has not ended — an ended post's state is final — and this one is {:?}", post.state);
        post.state = state;
    }

    /// `token`'s post, where this process admitted one.
    pub fn post(&self, token: &str) -> Option<&AdmittedPost> {
        self.posts.get(token)
    }

    /// Whether a post this process admitted that has not ended — in flight,
    /// queued or running — names `name`: the name is HELD by it — the owner's
    /// lock per name — though nothing stands under it yet.
    pub fn holds(&self, name: &Name) -> bool {
        self.posts.values().any(|p| &p.name == name && !p.state.ended())
    }

    /// The names routed at start, as the rebuild found them: what the
    /// serving line counts as `live`.
    pub fn routed_at_start(&self) -> &BTreeSet<Name> {
        &self.routed_at_start
    }
}

#[cfg(test)]
mod tests;
