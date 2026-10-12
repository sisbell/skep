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
//! THE WRITE ([`write()`]) is WHOLE-THEN-RENAME, as the workspace writes a file
//! it replaces: the text written to the sibling `<name>.caddy.tmp` — a name
//! the import's `*.caddy` glob never matches — synced, then renamed over
//! `<name>.caddy` (`std::fs::rename` is atomic within one filesystem, as
//! this crate knows POSIX — UNVERIFIED HERE), and the directory synced: a
//! reload sees the whole snippet or none. The file is made readable by all
//! (`0644`) whatever this process's umask — a unit's `UMask=0077` would
//! otherwise leave it `0600` — because Caddy reads it as its own container's
//! user, which is the VM's configuration (UNVERIFIED HERE); it holds no
//! secret. THE RELOAD ([`reload`]) is the runner's `docker exec <caddy> caddy
//! reload`, after the write and after a removal.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::docker::{Docker, Exit, BOARD_PORT};
use crate::record::Name;

/// THE SNIPPET's TEXT for `name` under `suffix`: the deployment notes' block
/// for `alice` under `skep.host`, byte for byte, every occurrence of either
/// replaced — the matcher, the host, the upstream.
pub fn snippet(name: &Name, suffix: &str) -> String {
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
pub fn path(boards_dir: &Path, name: &Name) -> PathBuf {
    boards_dir.join(format!("{name}.caddy"))
}

/// The sibling the write goes through: `<name>.caddy.tmp`, outside the
/// import's glob.
fn temp_path(boards_dir: &Path, name: &Name) -> PathBuf {
    boards_dir.join(format!("{name}.caddy.tmp"))
}

/// THE WRITE, WHOLE-THEN-RENAME: the snippet in place, or an error with the
/// directory as it was — the temp file removed on the way out. An error is
/// a failed step for the flow.
pub fn write(boards_dir: &Path, name: &Name, suffix: &str) -> io::Result<()> {
    let tmp = temp_path(boards_dir, name);
    let written = (|| {
        let mut file = OpenOptions::new().write(true).create(true).truncate(true).open(&tmp)?;
        file.write_all(snippet(name, suffix).as_bytes())?;
        set_readable(&tmp)?;
        file.sync_all()?;
        fs::rename(&tmp, path(boards_dir, name))?;
        sync_dir(boards_dir)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

/// THE REMOVAL: `name`'s snippet gone — `true` where one stood, `false`
/// where none did — and the directory synced.
pub fn remove(boards_dir: &Path, name: &Name) -> io::Result<bool> {
    match fs::remove_file(path(boards_dir, name)) {
        Ok(()) => sync_dir(boards_dir).map(|()| true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// THE RELOAD: Caddy re-reads its configuration, the boards' snippets with
/// it, through the runner.
pub fn reload(docker: &dyn Docker) -> io::Result<Exit> {
    docker.caddy_reload()
}

/// Every name a snippet stands for: each `<name>.caddy` file in the
/// directory whose stem is a name in the grammar — what the status map is
/// rebuilt from at start. A file of another shape is no board's and is
/// passed over.
pub fn names(boards_dir: &Path) -> io::Result<Vec<Name>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(boards_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(stem) = file_name.to_str().and_then(|n| n.strip_suffix(".caddy")) else { continue };
        if !entry.file_type()?.is_file() {
            continue;
        }
        if let Ok(name) = Name::parse(stem.as_bytes()) {
            if name.as_str() == stem {
                found.push(name);
            }
        }
    }
    found.sort();
    Ok(found)
}

/// The snippet's mode set to `0644` on unix, the umask notwithstanding.
fn set_readable(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The directory's entry list made durable after a rename or a removal, on
/// unix; elsewhere there is nothing to open a directory with.
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests;
