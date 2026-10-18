//! The status map (Q5 (a); the provisioning record §5.2): the book's.
//!
//! It is kept in memory, and holds each post this process admitted, by its
//! status token — 128 bits of OS entropy as lowercase hex
//! (`names::unguessable`), shown only to the poster and in the mail, never
//! logged — with its name, its state ([`PostState`]) and what the reply needs
//! that a name does not say, the record's anchorless fact; and the names
//! routed at start, rebuilt from the snippet directory as Q5 (a) has it —
//! every `<name>.caddy` file `caddy::routed` reads — which the serving line
//! counts as `live`. A post this process makes live is live by its own state,
//! and no name is added to them: whether a board is live now is what stands
//! under its name (`names::taken`), never a list kept here. The reply's three
//! facts are kept nowhere here: they are the constants and the public origin,
//! and the reply renders them (`reply`). The map holds names across a restart
//! and no token: a token is never written to a file the service keeps, so a
//! status URL minted before a restart answers 404 after it, though the board
//! it named may stand, live, and its mail — if it was sent — carries the
//! reply.
//!
//! Its one holder is the book, `flow`'s `Book`, and its one client `flow`:
//! the map keeps each post's state and which states hold a name, and the
//! book's rules alone move a post — so the map is a module of `flow`'s own,
//! which no module but `flow` can name.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::io;
use std::path::Path;

use crate::caddy;
use crate::name::Name;

/// A post's state, from its admission to its end.
///
/// It is in flight while queued or running — its name held, its page D-7 —
/// then ended, live or failed, its state final.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostState {
    /// Admitted, waiting for the worker: D-7.
    Queued,
    /// The worker runs its steps: D-7.
    Running,
    /// The route stands: the live reply.
    Live,
    /// A step failed and the cleanup ran: D-8.
    ///
    /// What the post made is removed, or, where a removal itself failed, what
    /// it left standing under the name is logged (the provisioning record
    /// §5.2's named gap).
    Failed,
}

impl PostState {
    /// Returns whether the post has ended, live or failed.
    ///
    /// Its state is then final, its name held no more. A post that has not
    /// ended is in flight.
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
    /// Whether its record carried no anchor-flagged entry.
    ///
    /// It is the fact the reply's anchorless sentence says.
    pub anchorless: bool,
}

/// The status map.
///
/// It holds this process's posts by token, and the names routed at start.
#[derive(Clone, Default)]
pub struct StatusMap {
    posts: HashMap<String, AdmittedPost>,
    routed_at_start: BTreeSet<Name>,
}

/// The posts' count and the names routed at start.
///
/// The map's keys are status tokens, never a log line's.
impl fmt::Debug for StatusMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatusMap").field("posts", &self.posts.len()).field("routed_at_start", &self.routed_at_start).finish()
    }
}

impl StatusMap {
    /// Rebuilds the map at start (Q5 (a)): each name [`caddy::routed`] reads.
    ///
    /// Each such name is routed at start; there is no post, no token.
    ///
    /// # Errors
    ///
    /// The snippet directory's, as [`caddy::routed`] meets it.
    pub fn rebuild(boards_dir: &Path) -> io::Result<StatusMap> {
        Ok(StatusMap { posts: HashMap::new(), routed_at_start: caddy::routed(boards_dir)?.into_iter().collect() })
    }

    /// Admits a post under `token`: queued.
    ///
    /// # Panics
    ///
    /// Panics where `token` is one this process already admitted, before the
    /// map changes: a token is its post's identity, and an ended post's state
    /// is final, so a token admitted twice is the caller's bug, and the panic
    /// names it.
    pub fn admit(&mut self, token: String, name: Name, anchorless: bool) {
        assert!(!self.posts.contains_key(&token), "`admit` takes a token this process never admitted: a token is its post's identity");
        self.posts.insert(token, AdmittedPost { name, state: PostState::Queued, anchorless });
    }

    /// Moves `token`'s post to `state`.
    ///
    /// # Panics
    ///
    /// Panics, naming the caller's bug, where `token` is not one this process
    /// admitted, or where its post has ended — a live or a failed post's state
    /// is final, for its page says how it ended and an ended post holds no
    /// name — as the book's rules alone move a post.
    pub fn set(&mut self, token: &str, state: PostState) {
        let post = self.posts.get_mut(token).expect("`set` names a token this process admitted: the book moves only its own jobs' posts");
        assert!(!post.state.ended(), "`set` moves a post that has not ended — an ended post's state is final — and this one is {:?}", post.state);
        post.state = state;
    }

    /// Returns `token`'s post, where this process admitted one.
    pub fn post(&self, token: &str) -> Option<&AdmittedPost> {
        self.posts.get(token)
    }

    /// Returns whether a post in flight names `name`, holding it.
    ///
    /// A post this process admitted that has not ended — in flight, queued or
    /// running — and names `name` holds the name — the lock per name — though
    /// nothing may stand under it yet.
    pub fn holds(&self, name: &Name) -> bool {
        self.posts.values().any(|p| &p.name == name && !p.state.ended())
    }

    /// Returns the names routed at start, as the rebuild found them.
    ///
    /// They are what the serving line counts as `live`.
    pub fn routed_at_start(&self) -> &BTreeSet<Name> {
        &self.routed_at_start
    }
}

#[cfg(test)]
mod tests;
