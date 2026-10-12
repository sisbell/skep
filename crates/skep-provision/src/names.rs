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
//! your name" are statements about exactly these, made true by the same
//! reads the cleanup answers to. The flow makes the three reads at the post,
//! under no lock of its own, and again before step 3 on the worker that
//! owns the name; the log carries the history.
//!
//! THE LABELLED VOLUMES ([`labelled`]), read at start: every volume this
//! service made carries one label (`docker.rs`'s `LABEL_KEY`), and the
//! listing by it, sorted here against the snippet directory, tells a
//! HALF-MADE board — a volume under a name in the grammar with no snippet,
//! what a stop mid-board leaves — from a routed one and from a volume under
//! no name of this grammar; the flow's sweep removes the first and leaves
//! the rest.
//!
//! THE STATUS MAP ([`StatusMap`]), in memory: each post of this run by its
//! STATUS TOKEN — 128 bits of OS entropy as lowercase hex ([`fresh_token`]),
//! shown only to the poster and in the mail, NEVER LOGGED — with its name,
//! its state ([`State`]) and what the reply needs; and every LIVE name with
//! its facts. REBUILT AT START from the snippet directory: every
//! `<name>.caddy` is a live name whose facts are the constants — the
//! account `1.0.1`, the principal `1`, the origin `https://<name>.<suffix>`.
//! The map holds NAMES across a restart and no token: a token is never
//! written anywhere, so a status address minted before a restart answers
//! 404 after it, though the board it named stands, live, and its mail — if
//! it was sent — carries the reply.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::Path;

use crate::caddy;
use crate::docker::Docker;
use crate::record::Name;
use crate::sidecar::{ACCOUNT, PRINCIPAL};

/// Which of the three things standing makes a name taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holder {
    /// `<boards-dir>/<name>.caddy` exists.
    Snippet,
    /// `docker volume inspect <name>` exited 0.
    Volume,
    /// `docker container inspect <name>` exited 0.
    Container,
}

impl Holder {
    /// The holder as the log names it.
    pub fn said(self) -> &'static str {
        match self {
            Holder::Snippet => "its snippet stands",
            Holder::Volume => "a volume stands under it",
            Holder::Container => "a container stands under it",
        }
    }
}

/// THE TRUTH ABOUT `name`: what stands under it, the first of the snippet,
/// the volume and the container — `None` where none does. An inspect's
/// non-zero exit is "not standing" whatever its reason (an Engine that
/// cannot be reached among them — the volume's own creation then fails, and
/// nothing is made); a `docker` that cannot be run at all is the error.
pub fn taken(docker: &dyn Docker, boards_dir: &Path, name: &Name) -> io::Result<Option<Holder>> {
    if caddy::path(boards_dir, name).try_exists()? {
        return Ok(Some(Holder::Snippet));
    }
    if docker.volume_inspect(name)?.ok() {
        return Ok(Some(Holder::Volume));
    }
    if docker.container_inspect(name)?.ok() {
        return Ok(Some(Holder::Container));
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
    /// Under no name in the grammar — or one that does not spell itself
    /// back, as a snippet's stem must — as listed; logged and left.
    pub unnamed: Vec<String>,
}

/// THE LABELLED VOLUMES SORTED: `listing` is the stdout of the volumes
/// call, one name per line (a blank line no name); each is a name in the
/// grammar that spells itself back, and then half-made or routed by whether
/// `<boards-dir>/<name>.caddy` stands, or unnamed. The error is the snippet
/// directory's.
pub fn labelled(listing: &[u8], boards_dir: &Path) -> io::Result<Labelled> {
    let mut sorted = Labelled::default();
    for listed in String::from_utf8_lossy(listing).lines().map(str::trim).filter(|l| !l.is_empty()) {
        match Name::parse(listed.as_bytes()) {
            Ok(name) if name.as_str() == listed => {
                if caddy::path(boards_dir, &name).try_exists()? {
                    sorted.routed.push(name);
                } else {
                    sorted.half_made.push(name);
                }
            }
            _ => sorted.unnamed.push(listed.to_owned()),
        }
    }
    Ok(sorted)
}

/// A FRESH TOKEN: 128 bits of OS entropy as 32 lowercase hex digits — the
/// status token, and the invite code `invite` mints where none is given.
pub fn fresh_token() -> io::Result<String> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|e| io::Error::other(format!("OS entropy: {e}")))?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

/// A live board's three facts (AUTH-5.76's channel; the reply carries
/// them): the account, the principal and the PUBLIC origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// The account the claim founded: [`ACCOUNT`].
    pub account: &'static str,
    /// Its principal: [`PRINCIPAL`].
    pub principal: u64,
    /// `https://<name>.<suffix>`.
    pub origin: String,
}

/// The facts of `name` under `suffix`: the constants, and the public
/// origin.
pub fn facts(name: &Name, suffix: &str) -> Facts {
    Facts { account: ACCOUNT, principal: PRINCIPAL, origin: name.origin(suffix) }
}

/// Where a post stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Admitted, waiting for the worker: D-7.
    Queued,
    /// The worker runs its steps: D-7.
    Running,
    /// The route stands: the live reply.
    Live,
    /// A step failed and what it made was removed: D-8.
    Failed,
}

/// One post of this run, as its status page reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Post {
    /// The board's name.
    pub name: Name,
    /// Where it stands.
    pub state: State,
    /// Whether its record carried no anchor-flagged entry — the reply's
    /// anchorless sentence.
    pub anchorless: bool,
}

/// THE STATUS MAP: this run's posts by token, and every live name with its
/// facts.
#[derive(Debug, Clone, Default)]
pub struct StatusMap {
    posts: HashMap<String, Post>,
    live: BTreeMap<Name, Facts>,
}

impl StatusMap {
    /// THE REBUILD AT START: every name the snippet directory stands for,
    /// live, with the constant facts; no post, no token.
    pub fn rebuild(boards_dir: &Path, suffix: &str) -> io::Result<StatusMap> {
        let live = caddy::names(boards_dir)?.into_iter().map(|name| (name.clone(), facts(&name, suffix))).collect();
        Ok(StatusMap { posts: HashMap::new(), live })
    }

    /// A post admitted under `token`: queued.
    pub fn admit(&mut self, token: String, name: Name, anchorless: bool) {
        self.posts.insert(token, Post { name, state: State::Queued, anchorless });
    }

    /// `token`'s post moved to `state`; a post gone live joins the live
    /// names with `facts`.
    pub fn set(&mut self, token: &str, state: State, facts: Option<Facts>) {
        if let Some(post) = self.posts.get_mut(token) {
            post.state = state;
            if let (State::Live, Some(facts)) = (state, facts) {
                self.live.insert(post.name.clone(), facts);
            }
        }
    }

    /// `token`'s post, where this run admitted one.
    pub fn post(&self, token: &str) -> Option<&Post> {
        self.posts.get(token)
    }

    /// Whether a post of this run that is not yet finished — queued or
    /// running — names `name`: the name is held by it, though nothing stands
    /// under it yet.
    pub fn holds(&self, name: &Name) -> bool {
        self.posts.values().any(|p| &p.name == name && matches!(p.state, State::Queued | State::Running))
    }

    /// The live names and their facts.
    pub fn live(&self) -> &BTreeMap<Name, Facts> {
        &self.live
    }
}

#[cfg(test)]
mod tests;
