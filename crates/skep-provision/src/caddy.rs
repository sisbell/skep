//! The proxy's snippet: one file per board, `<boards-dir>/<name>.caddy`.
//!
//! It is step 5's (the deployment notes §4a, "One board's snippet"), and the
//! Caddyfile's `*.<suffix>` site imports it
//! (`import /etc/caddy/boards/*.caddy`) — one hostname per board and never a
//! path (AUTH-4.57 (c)) — routing the board's host to its serving run on the
//! bridge with the active health check whose condition is the pair
//! (AUTH-4.57 (d)): the route stands only while `/health` answers `claimant`
//! `1.0.1` and `local_trust` `false`, on the first start and at every
//! restart. The text is the notes' block, tabs and comments included, with
//! `alice` and `skep.host` replaced by the name and the suffix ([`snippet`]);
//! every directive in it is as the notes know Caddy 2 (unverified here, the
//! provisioning record §8 item 2).
//!
//! The write ([`write()`]) is `whole`'s replacement at [`SNIPPET_MODE`]: the
//! text written whole to the sibling `<name>.caddy.tmp` — a name the
//! import's `*.caddy` glob never matches — and renamed over `<name>.caddy`,
//! so a reload sees the whole snippet or none. The mode is `0644`, readable
//! by all whatever this process's umask — a unit's `UMask=0077` would
//! otherwise leave it `0600` — because Caddy reads it as its own container's
//! user, which is the VM's configuration (unverified here); it holds no
//! secret. The removal ([`remove`]) is `whole`'s. Whether it stands
//! ([`stands`]) is the first of the truth about names' three reads, and the
//! sweep's sort. The reload ([`reload`]) is the runner's `docker exec
//! <caddy> caddy reload`, after the write and after a removal. The probe
//! ([`probe`]) is a write and a removal tried at start, so a snippet
//! directory the service's user cannot write is a start refused — never
//! every board's failure at its snippet's write, after its claim.
//!
//! **The directory is the list of boards.** The status map is rebuilt from
//! it at start ([`routed`]), and the sweep at start spares the labelled
//! volumes whose snippet stands here and removes every other under a name of
//! the grammar — so a start over a directory emptier than the Engine's
//! volumes removes every board it lacks.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::docker::{Docker, BOARD_PORT};
use crate::domain::Domain;
use crate::name::Name;
use crate::process::Exit;
use crate::whole;

/// The snippet's mode: `0644`, readable by all.
///
/// Caddy reads the file as its own container's user (unverified here); the
/// mode is set exactly, whatever this process's umask; it holds no secret.
const SNIPPET_MODE: u32 = 0o644;

/// The probe's name in the snippet directory.
///
/// It is one no `<name>.caddy` glob matches — Caddy's import, [`routed`] —
/// and no [`Name`] spells, so a probe a stop left behind is read as no
/// board's, and the next probe replaces it.
const PROBE: &str = ".skep-provision.probe";

/// Returns the snippet's text for `name` under `suffix`.
///
/// It is the deployment notes' block for `alice` under `skep.host`, byte for
/// byte, every occurrence of either replaced — the matcher, the host, the
/// upstream. `suffix` is a [`Domain`], so no character the Caddyfile reads as
/// its own reaches the text.
pub fn snippet(name: &Name, suffix: &Domain) -> String {
    format!(
        "@{name} host {host}\n\
         handle @{name} {{\n\
         \treverse_proxy {name}:{BOARD_PORT} {{\n\
         \t\t# AUTH-4.57 (d): the route stands only while /health answers\n\
         \t\t# the pair — claimant not null AND local_trust false\n\
         \t\thealth_uri /health\n\
         \t\thealth_interval 10s\n\
         \t\thealth_timeout 5s\n\
         \t\thealth_status 200\n\
         \t\thealth_body `\"claimant\":\"1\\.0\\.1\",\"local_trust\":false`\n\
         \t\t# GET /events: no response buffering (media setting 2)\n\
         \t\tflush_interval -1\n\
         \t}}\n\
         }}\n",
        host = name.host(suffix)
    )
}

/// Returns where `name`'s snippet lives: `<boards-dir>/<name>.caddy`.
///
/// It is the path a line about a write or a removal that failed names it by.
pub fn snippet_path(boards_dir: &Path, name: &Name) -> PathBuf {
    boards_dir.join(format!("{name}.caddy"))
}

/// Returns whether `name`'s snippet stands.
///
/// Anything at its path stands, a link followed to what it names — the
/// snippet file Q5 (a) names, or anything else there, a directory the write
/// could not replace among them; a link to nothing does not stand. It is the
/// first of the truth about names' three reads, made with no call, and the
/// sweep's sort of the labelled volumes.
///
/// # Errors
///
/// The directory's, where whether anything stands at the path cannot be
/// read.
pub fn stands(boards_dir: &Path, name: &Name) -> io::Result<bool> {
    snippet_path(boards_dir, name).try_exists()
}

/// Writes `name`'s snippet whole, then renames it into place.
///
/// The snippet lands at [`SNIPPET_MODE`]. The flow reads every error as a
/// snippet that may stand, and an error is a failed step for the flow.
///
/// **Precondition.** No other write or removal of `name`'s snippet runs at
/// once. It is the caller's to keep — the route lock, under which the flow
/// makes both, keeps it — and nothing here checks it.
///
/// # Errors
///
/// An error before the rename comes with the directory as it was and no temp
/// file of this call's left; one from the directory's sync after it comes
/// with the snippet standing.
pub fn write(boards_dir: &Path, name: &Name, suffix: &Domain) -> io::Result<()> {
    whole::replace(&snippet_path(boards_dir, name), snippet(name, suffix).as_bytes(), SNIPPET_MODE, &|| Ok(()))
}

/// Removes `name`'s snippet, answering whether one stood.
///
/// It answers `true` where one stood, the directory then synced, and `false`
/// where none did.
///
/// **Precondition.** No other write or removal of `name`'s snippet runs at
/// once. It is the caller's to keep — the route lock, under which the flow
/// makes both, keeps it — and nothing here checks it.
///
/// # Errors
///
/// An error leaves the snippet standing where the unlink failed, and arrives
/// with it gone where the sync after it failed — so the flow reads every
/// error as a snippet that may stand.
pub fn remove(boards_dir: &Path, name: &Name) -> io::Result<bool> {
    whole::remove(&snippet_path(boards_dir, name))
}

/// Reloads Caddy through the runner.
///
/// Caddy re-reads its configuration, the boards' snippets with it.
///
/// # Errors
///
/// The runner's error, where the call could not be run; a reload that ran
/// answers its exit, whatever it is.
pub fn reload(docker: &dyn Docker) -> io::Result<Exit> {
    docker.caddy_reload()
}

/// Tries the snippet directory's write, at start.
///
/// [`PROBE`] is written through `whole` at [`SNIPPET_MODE`], as a snippet is,
/// and removed — so a directory the service's user cannot write is a start
/// refused, said with its directory and its owner's act, never every board's
/// failure at its snippet's write after its claim and its `/health` wait.
///
/// # Errors
///
/// The write's or the removal's.
pub fn probe(boards_dir: &Path) -> io::Result<()> {
    let probe = boards_dir.join(PROBE);
    whole::replace(&probe, b"", SNIPPET_MODE, &|| Ok(()))?;
    whole::remove(&probe).map(|_| ())
}

/// Returns the routed names: what the status map is rebuilt from at start.
///
/// Each is a name whose snippet is a regular file — a `<name>.caddy` entry,
/// read as it is in the directory and never through a link, whose stem
/// [`Name::exact`] reads. An entry of another shape — a directory, a link —
/// is passed over here, though [`stands`] finds a directory standing, and a
/// link to anything that stands.
///
/// # Errors
///
/// The directory's, where it or an entry's type cannot be read.
pub fn routed(boards_dir: &Path) -> io::Result<Vec<Name>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(boards_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(stem) = file_name.to_str().and_then(|n| n.strip_suffix(".caddy")) else { continue };
        if !entry.file_type()?.is_file() {
            continue;
        }
        if let Some(name) = Name::exact(stem) {
            found.push(name);
        }
    }
    found.sort();
    Ok(found)
}

#[cfg(test)]
mod tests;
