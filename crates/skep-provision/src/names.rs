//! THE TRUTH ABOUT NAMES (Q5 (a); the provisioning record §5.2).
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
//! AN UNGUESSABLE VALUE ([`unguessable`]): 128 bits of OS entropy as
//! lowercase hex — the status token the flow mints at a post, the key the
//! book's status map holds the post by, NEVER LOGGED; and the invite code
//! `invite` mints where none is given. Its one failure is its own,
//! [`NoEntropy`]: the OS giving none.

use std::fmt;
use std::io;
use std::path::Path;

use crate::caddy;
use crate::docker::Docker;
use crate::name::Name;

/// What a name is TAKEN by (Q5 (a)): the first of the three things a
/// provisioning leaves that [`taken`] finds standing under it. A name a post
/// in flight holds — `flow`'s book, through its status map — has nothing
/// standing under it yet; both meet D-4.
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
/// fails while the Engine stays unreachable, and nothing is made; after a
/// cleanup's or the sweep's removals the verdict reads done, and what the
/// Engine left the next start's sweep finds. The error is a snippet
/// directory that cannot be searched ([`caddy::stands`]'s), its words
/// opening `the snippet directory <path>: `, or a `docker` that cannot be
/// run at all, its words opening `docker could not run: ` — each the OS's
/// own error after them, its kind kept ([`sourced`]), so a line that says a
/// look could not be made names which of the two failed.
pub fn taken(docker: &dyn Docker, boards_dir: &Path, name: &Name) -> io::Result<Option<TakenBy>> {
    if caddy::stands(boards_dir, name).map_err(|e| sourced(e, format!("the snippet directory {}", boards_dir.display())))? {
        return Ok(Some(TakenBy::Snippet));
    }
    if docker.volume_inspect(name).map_err(|e| sourced(e, "docker could not run"))?.success() {
        return Ok(Some(TakenBy::Volume));
    }
    if docker.container_inspect(name).map_err(|e| sourced(e, "docker could not run"))?.success() {
        return Ok(Some(TakenBy::Container));
    }
    Ok(None)
}

/// A READ's ERROR WITH ITS SOURCE, its kind kept — the snippet directory's
/// search or `docker`'s run — so a line that says a look could not be made
/// names which, where the OS's own words name neither: `No such file or
/// directory` is as much a `docker` missing from `PATH` as a snippet
/// directory gone.
fn sourced(e: io::Error, source: impl fmt::Display) -> io::Error {
    io::Error::new(e.kind(), format!("{source}: {e}"))
}

/// What the labelled volumes stand for, sorted at start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Labelled {
    /// Under a name in the grammar with NO snippet: a stop mid-board left
    /// it, and the sweep removes it.
    pub half_made: Vec<Name>,
    /// Under a name whose snippet stands: a board routed — live, or its run
    /// stopped (RUNBOOK §10 step 12) — and left; and what the sweep holds the
    /// names routed at start against, a snippet with no volume here a route
    /// to no board, and the invite file's spent lines against, a board here
    /// with none spent under it one whose invite may still say issued.
    pub routed: Vec<Name>,
    /// Under no name of the grammar — none [`Name::exact`] reads — as
    /// listed; logged and left.
    pub ungrammatical: Vec<String>,
}

/// THE LABELLED VOLUMES SORTED: `listing` is [`Docker::labelled_volumes`]'s
/// stdout, one name per line (a blank line no name); each is a name
/// [`Name::exact`] reads, and then half-made or routed by whether
/// `<boards-dir>/<name>.caddy` stands, or ungrammatical. The error is the
/// snippet directory's.
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
            None => sorted.ungrammatical.push(listed.to_owned()),
        }
    }
    Ok(sorted)
}

/// NO ENTROPY: the OS would not give the 128 bits an unguessable value is
/// drawn from — a failure of its own, never a file's, so a caller answers it
/// as its own refusal: `invites`' `MintRefused::Entropy`, which `?` reaches,
/// and a post's D-8.
#[derive(Debug, Clone, Copy)]
pub struct NoEntropy(pub getrandom::Error);

/// The failure as the log and a refusal say it: `OS entropy: ` and the OS's
/// own words.
impl fmt::Display for NoEntropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OS entropy: {}", self.0)
    }
}

impl std::error::Error for NoEntropy {}

/// AN UNGUESSABLE VALUE: 128 bits of OS entropy as 32 lowercase hex digits
/// — a status token, minted at the post so that the status URL is the
/// poster's and not guessable (the provisioning record §5.2), and the invite
/// code `invite` mints where none is given. The error is [`NoEntropy`].
pub fn unguessable() -> Result<String, NoEntropy> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(NoEntropy)?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests;
