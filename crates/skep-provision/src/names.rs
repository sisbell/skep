//! THE TRUTH ABOUT NAMES and THE STATUS MAP (Q5 (a); the provisioning
//! record §5.2).
//!
//! TAKEN is what STANDS, read from Docker's own state and the snippet
//! directory — the three things a provisioning leaves — and kept in no
//! ledger: a name is taken iff its snippet `<boards-dir>/<name>.caddy`
//! exists, OR `docker volume inspect <name>` exits 0, OR `docker container
//! inspect <name>` exits 0 ([`taken`]; the order fixed here: the snippet, a
//! file read with no call, then the volume, then the container, the first
//! that stands answering). D-4's "taken" and D-8's "Nothing stands under
//! your name" are statements about exactly these, made true — and checked
//! — by the same reads: the flow makes them at the post, under no lock of
//! its own, again before step 3 on the worker that owns the name, and once
//! more after a failed post's cleanup and after each of the sweep's
//! removals, whose verdict they are; the log carries the history.
//!
//! THE LABELLED VOLUMES ([`labelled`]), read at start: every volume this
//! service made carries one label (`docker.rs`'s `LABEL_KEY`), as any other
//! service's on the host would — one service per Docker host is the
//! sweep's precondition — and the listing by it, sorted here against the
//! snippet directory, tells a HALF-MADE board — a volume under a name in
//! the grammar with no snippet, what a stop mid-board leaves — from a
//! routed one and from a volume under no name of this grammar; the flow's
//! sweep removes the first and leaves the rest.
//!
//! THE STATUS MAP ([`StatusMap`]), in memory: each post this process
//! admitted, by its STATUS TOKEN — 128 bits of OS entropy as lowercase hex
//! ([`unguessable`]), shown only to the poster and in the mail, NEVER
//! LOGGED — with its name, its state ([`PostState`]) and what the reply needs
//! that a name does not say, the record's anchorless fact; and every LIVE
//! name. REBUILT AT START from the snippet directory: every `<name>.caddy` is
//! a live name. The reply's three facts are kept nowhere here: they are the
//! constants and the public origin, and the reply renders them (`reply`). The
//! map holds NAMES across a restart and no token: a token is never written
//! anywhere, so a status URL minted before a restart answers 404 after it,
//! though the board it named stands, live, and its mail — if it was sent —
//! carries the reply.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::io;
use std::path::Path;

use crate::caddy;
use crate::docker::Docker;
use crate::name::Name;

/// What a name is TAKEN by (Q5 (a)): the first of the three things a
/// provisioning leaves that [`taken`] finds standing under it. A name a post
/// in flight holds ([`StatusMap::holds`]) has nothing standing under it yet;
/// both meet D-4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TakenBy {
    /// `<boards-dir>/<name>.caddy` exists.
    Snippet,
    /// `docker volume inspect <name>` exited 0.
    Volume,
    /// `docker container inspect <name>` exited 0.
    Container,
}

/// What took the name, as the log says it.
impl fmt::Display for TakenBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TakenBy::Snippet => "its snippet stands",
            TakenBy::Volume => "a volume stands under it",
            TakenBy::Container => "a container stands under it",
        })
    }
}

/// THE TRUTH ABOUT `name`: what stands under it, the first of the snippet,
/// the volume and the container — `None` where none does. An inspect's
/// non-zero exit is "not standing" whatever its reason, an Engine that
/// cannot be reached among them: at a post the volume's own creation then
/// fails, and nothing is made; after a cleanup's or the sweep's removals the
/// verdict reads done, and what the Engine left the next start's sweep
/// finds. A `docker` that cannot be run at all is the error.
pub fn taken(docker: &dyn Docker, boards_dir: &Path, name: &Name) -> io::Result<Option<TakenBy>> {
    if caddy::stands(boards_dir, name)? {
        return Ok(Some(TakenBy::Snippet));
    }
    if docker.volume_inspect(name)?.ok() {
        return Ok(Some(TakenBy::Volume));
    }
    if docker.container_inspect(name)?.ok() {
        return Ok(Some(TakenBy::Container));
    }
    Ok(None)
}

/// What the labelled volumes stand for, sorted at start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Labelled {
    /// Under a name in the grammar with NO snippet: a stop mid-board left
    /// it, and the sweep removes it.
    pub half_made: Vec<Name>,
    /// Under a name whose snippet stands: a board routed — live, or stopped
    /// and Docker's `--restart` to bring back — and left.
    pub routed: Vec<Name>,
    /// Under no name [`Name::exact`] reads, as listed; logged and left.
    pub unnamed: Vec<String>,
}

/// THE LABELLED VOLUMES SORTED: `listing` is the stdout of the volumes
/// call, one name per line (a blank line no name); each is a name
/// [`Name::exact`] reads, and then half-made or routed by whether
/// `<boards-dir>/<name>.caddy` stands, or unnamed. The error is the snippet
/// directory's.
pub fn labelled(listing: &[u8], boards_dir: &Path) -> io::Result<Labelled> {
    let mut sorted = Labelled::default();
    for listed in String::from_utf8_lossy(listing).lines().map(str::trim).filter(|l| !l.is_empty()) {
        match Name::exact(listed) {
            Some(name) => {
                if caddy::stands(boards_dir, &name)? {
                    sorted.routed.push(name);
                } else {
                    sorted.half_made.push(name);
                }
            }
            None => sorted.unnamed.push(listed.to_owned()),
        }
    }
    Ok(sorted)
}

/// AN UNGUESSABLE VALUE: 128 bits of OS entropy as 32 lowercase hex digits
/// — a status token, minted at the post so that the status URL is the
/// poster's and not guessable (the provisioning record §5.2), and the invite
/// code `invite` mints where none is given.
pub fn unguessable() -> io::Result<String> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|e| io::Error::other(format!("OS entropy: {e}")))?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

/// A post's state, from its admission to its end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostState {
    /// Admitted, waiting for the worker: D-7.
    Queued,
    /// The worker runs its steps: D-7.
    Running,
    /// The route stands: the live reply.
    Live,
    /// A step failed and the cleanup ran: D-8 — what the post made removed,
    /// or, where a removal itself failed, the name left standing and logged
    /// (the provisioning record §5.2's named gap).
    Failed,
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

/// THE STATUS MAP: this process's posts by token, and every live name.
#[derive(Clone, Default)]
pub struct StatusMap {
    posts: HashMap<String, AdmittedPost>,
    live: BTreeSet<Name>,
}

/// The posts' count and the live names: the map's keys are status tokens,
/// never a log line's.
impl fmt::Debug for StatusMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatusMap").field("posts", &self.posts.len()).field("live", &self.live).finish()
    }
}

impl StatusMap {
    /// THE REBUILD AT START: every routed name live — each name whose
    /// snippet stands; no post, no token.
    pub fn rebuild(boards_dir: &Path) -> io::Result<StatusMap> {
        Ok(StatusMap { posts: HashMap::new(), live: caddy::routed(boards_dir)?.into_iter().collect() })
    }

    /// A post admitted under `token`: queued.
    pub fn admit(&mut self, token: String, name: Name, anchorless: bool) {
        self.posts.insert(token, AdmittedPost { name, state: PostState::Queued, anchorless });
    }

    /// `token`'s post moved to `state`; a post gone live joins the live
    /// names. PRECONDITION, the caller's: `token` is one this process
    /// admitted, and its post has not ended — a live or a failed post's
    /// state is final, for the live names never shrink and an ended post
    /// holds no name — as the book's rules alone move a post. Either broken
    /// is the caller's bug, and panics naming it.
    pub fn set(&mut self, token: &str, state: PostState) {
        let post = self.posts.get_mut(token).expect("`set` names a token this process admitted: the book moves only its own jobs' posts");
        assert!(matches!(post.state, PostState::Queued | PostState::Running), "`set` moves a post that has not ended — an ended post's state is final — and this one is {:?}", post.state);
        post.state = state;
        if state == PostState::Live {
            self.live.insert(post.name.clone());
        }
    }

    /// `token`'s post, where this process admitted one.
    pub fn post(&self, token: &str) -> Option<&AdmittedPost> {
        self.posts.get(token)
    }

    /// Whether a post this process admitted, not yet finished — queued or
    /// running — names `name`: the name is HELD by it — the owner's lock per
    /// name — though nothing stands under it yet.
    pub fn holds(&self, name: &Name) -> bool {
        self.posts.values().any(|p| &p.name == name && matches!(p.state, PostState::Queued | PostState::Running))
    }

    /// The live names.
    pub fn live(&self) -> &BTreeSet<Name> {
        &self.live
    }
}

#[cfg(test)]
mod tests;
