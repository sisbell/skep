//! THE PROXY's SNIPPET (step 5; the deployment notes §4a, "One board's
//! snippet"): ONE file per board, `<boards-dir>/<name>.caddy`, which the
//! Caddyfile's `*.<suffix>` site imports (`import /etc/caddy/boards/*.caddy`)
//! — one hostname per board and never a path (AUTH-4.57 (c)) — routing the
//! board's host to its serving run on the bridge with the active health
//! check whose condition is the pair (AUTH-4.57 (d)): the route stands only
//! while `/health` answers `claimant` `1.0.1` and `local_trust` `false`, on
//! the first start and at every restart. THE TEXT IS THE NOTES' BLOCK, tabs
//! and comments included, with `alice` and `skep.host` replaced by the name
//! and the suffix ([`snippet`]); every directive in it is as the notes know
//! Caddy 2 (UNVERIFIED HERE, the provisioning record §8 item 2).
//!
//! THE WRITE ([`write()`]) is `whole`'s replacement at [`SNIPPET_MODE`]: the
//! text written whole to the sibling `<name>.caddy.tmp` — a name the
//! import's `*.caddy` glob never matches — and renamed over `<name>.caddy`,
//! so a reload sees the whole snippet or none. The mode is `0644`, readable
//! by all whatever this process's umask — a unit's `UMask=0077` would
//! otherwise leave it `0600` — because Caddy reads it as its own container's
//! user, which is the VM's configuration (UNVERIFIED HERE); it holds no
//! secret. THE REMOVAL ([`remove`]) is `whole`'s. WHETHER IT STANDS
//! ([`stands`]) is the first of the truth about names' three reads, and the
//! sweep's sort. THE RELOAD ([`reload`]) is the runner's `docker exec
//! <caddy> caddy reload`, after the write and after a removal.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::docker::{Docker, BOARD_PORT};
use crate::domain::Domain;
use crate::name::Name;
use crate::process::Exit;
use crate::whole;

/// THE SNIPPET's MODE: `0644`, readable by all — Caddy reads the file as
/// its own container's user (UNVERIFIED HERE) — and set exactly, whatever
/// this process's umask; it holds no secret.
const SNIPPET_MODE: u32 = 0o644;

/// THE SNIPPET's TEXT for `name` under `suffix`: the deployment notes' block
/// for `alice` under `skep.host`, byte for byte, every occurrence of either
/// replaced — the matcher, the host, the upstream. `suffix` a [`Domain`],
/// so no character the Caddyfile reads as its own reaches the text.
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

/// Where `name`'s snippet lives: `<boards-dir>/<name>.caddy`.
fn snippet_path(boards_dir: &Path, name: &Name) -> PathBuf {
    boards_dir.join(format!("{name}.caddy"))
}

/// WHETHER `name`'s SNIPPET STANDS: anything at its path, a link followed to
/// what it names — the snippet file Q5 (a) names, or anything else there, a
/// directory the write could not replace among them; a link to nothing does
/// not stand. The first of the truth about names' three reads, made with no
/// call, and the sweep's sort of the labelled volumes. The error is the
/// directory's.
pub fn stands(boards_dir: &Path, name: &Name) -> io::Result<bool> {
    snippet_path(boards_dir, name).try_exists()
}

/// THE WRITE, WHOLE-THEN-RENAME: the snippet in place at [`SNIPPET_MODE`], or
/// an error — before the rename with the directory as it was and no temp file
/// left, from the directory's sync after it with the snippet STANDING: the
/// flow reads every error as a snippet that may stand. An error is a failed
/// step for the flow. PRECONDITION, the caller's: no other write or removal
/// of `name`'s snippet runs at once — the route lock, under which the flow
/// makes both, keeps it; nothing here checks it.
pub fn write(boards_dir: &Path, name: &Name, suffix: &Domain) -> io::Result<()> {
    whole::replace(&snippet_path(boards_dir, name), snippet(name, suffix).as_bytes(), SNIPPET_MODE, &|| Ok(()))
}

/// THE REMOVAL: `name`'s snippet gone — `true` where one stood, `false` where
/// none did — and the directory synced; an error leaves the snippet standing
/// where the unlink failed, and arrives with it gone where the sync after it
/// failed — so the flow reads every error as a snippet that may stand.
/// PRECONDITION, the caller's: no other write or removal of `name`'s snippet
/// runs at once — the route lock, under which the flow makes both, keeps it;
/// nothing here checks it.
pub fn remove(boards_dir: &Path, name: &Name) -> io::Result<bool> {
    whole::remove(&snippet_path(boards_dir, name))
}

/// THE RELOAD: Caddy re-reads its configuration, the boards' snippets with
/// it, through the runner.
pub fn reload(docker: &dyn Docker) -> io::Result<Exit> {
    docker.caddy_reload()
}

/// THE ROUTED NAMES: each name whose snippet is a regular file — a
/// `<name>.caddy` entry, read as it is in the directory and never through a
/// link, whose stem [`Name::exact`] reads — what the status map is rebuilt
/// from at start. An entry of another shape — a directory, a link — is
/// passed over here, though [`stands`] finds a directory standing, and a
/// link to anything that stands.
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
