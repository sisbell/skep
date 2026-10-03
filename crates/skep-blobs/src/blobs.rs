//! THE FILES, `<root>/<designation>/<hex>`, and the directory discipline
//! every store under the root shares: the install order (a temp file
//! fsynced, renamed onto its name, the directory fsynced, the root where
//! the directory is new), the JSON-lines log's tail check and compaction,
//! and the steps of a finish the hazard seam can hold or fail.
//!
//! THE ORDER (`media.md` Op inventory 1, "THE PUT's DISPOSITION ON A HASH
//! ALREADY PRESENT IS REPLACE, NOT NO-OP"; the register M-I5 (a)): a rename
//! is atomic in the namespace and is lost with its directory entry at a
//! power loss, so a file is durable only at its directory's fsync, and a
//! new directory's entry only at ITS parent's — which is why the finish
//! syncs the designation directory after the rename and the root after the
//! first finish into a designation directory this process created. The
//! temp file lives in the target's own designation directory, so the rename
//! never crosses a filesystem. REPLACE is `rename(2)`'s own disposition
//! over an existing name: the file holding the wrong bytes under the right
//! name is the one case a repair exists for, and a no-op would defeat it.
//!
//! THE REPLACED INSTANCE IS RETIRED AFTER THE ANSWER (`media.md` Op
//! inventory 1, "NO ANSWER OF THE UPLOAD SAYS WHETHER THE FILE WAS ALREADY
//! HERE" — the TIME an answer takes is part of what it says). A rename over
//! a name whose inode holds its last link frees that inode's blocks inside
//! the rename, which at the per-file cap costs the replace arm hundreds of
//! milliseconds a create never pays. So where the name exists the finish
//! first gives the old inode a SECOND NAME — a hard link at an ASIDE name no
//! hex spells, `.retired-<hex>-<n>` in the same directory — then renames the
//! partial onto the hash: the old inode keeps a link, the rename frees
//! nothing, and the aside is unlinked AFTER the answer has been written
//! ([`Store::retire_asides`](crate::Store::retire_asides)), where the
//! freeing's cost lands off the request's path. A link rather than a rename aside, so the hash is never
//! without a file: a failure at the rename leaves the old bytes at the hash
//! and the aside beside them, never an absent name. Nothing names an aside
//! — no lease, no cell — so every reader of the directory ignores it, the
//! pruner's pass removes one the deferred step did not, and open removes
//! every one it finds (a crash between the answer and the unlink).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde_json::Value;

/// The steps of a finish, in order — the points the hazard seam names
/// (`test-hooks`): a hold or an injected failure is placed BEFORE the step
/// it names, after every step before it has completed. Two are the
/// REPLACE's own and are met only where the name already exists:
/// [`Step::LinkAside`] inside the finish, [`Step::UnlinkAside`] in the
/// deferred step after the answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Step {
    /// The partial's final fsync.
    TempSync,
    /// The hard link of the old file at `<designation>/<hex>` to its aside
    /// name — taken only where the name exists.
    LinkAside,
    /// The rename of the partial onto `<designation>/<hex>`.
    Rename,
    /// The designation directory's fsync — the rename's durability.
    DirSync,
    /// The root's fsync — a new designation directory's durability. Taken
    /// only where this process created the directory; a hold or a failure
    /// named here is met only on such a finish.
    RootSync,
    /// The lease's append and sync.
    LeaseSync,
    /// The upload record's retirement — the last act before the answer.
    RecordRetire,
    /// The unlink of a replaced file's aside name — the deferred step, run
    /// after the answer ([`Store::retire_asides`](crate::Store::retire_asides))
    /// and never inside a finish; met only on a finish that replaced a
    /// present name.
    UnlinkAside,
}

/// The prefix of an aside name: `.retired-<hex>-<n>`, the second name a
/// replaced file carries from the finish's link until the deferred unlink.
/// The leading dot keeps it apart from any hex name, as the partial's is.
pub(crate) const ASIDE_PREFIX: &str = ".retired-";

/// The aside name of the `n`th replace of `hex` this process makes.
pub(crate) fn aside_name(hex: &str, n: u64) -> String {
    format!("{ASIDE_PREFIX}{hex}-{n}")
}

/// Whether a directory entry's name is an aside's.
pub(crate) fn is_aside_name(name: &str) -> bool {
    name.starts_with(ASIDE_PREFIX)
}

/// A finished upload's answer: the file's designation, its hash as
/// lowercase hex, and its length. One shape whether or not the file was
/// already here (the record's "NO ANSWER OF THE UPLOAD SAYS WHETHER THE
/// FILE WAS ALREADY HERE").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finished {
    pub designation: String,
    pub hex: String,
    pub size: u64,
}

/// The hazard seam's state (`test-hooks`): at most one failure point and
/// one hold.
#[cfg(feature = "test-hooks")]
#[derive(Default)]
pub(crate) struct Hooks {
    pub fail_at: Option<Step>,
    pub hold: Option<(Step, Box<dyn Fn() + Send + Sync>)>,
}

/// A designation's spelling: lowercase letters, digits and `-`, nonempty,
/// never a name a hex could be mistaken for or a path could escape by.
pub(crate) fn designation_ok(designation: &str) -> bool {
    !designation.is_empty()
        && designation.len() <= 32
        && designation.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A hex name's spelling: lowercase hex, an even length between 2 and 128.
pub(crate) fn hex_ok(hex: &str) -> bool {
    hex.len() >= 2
        && hex.len() <= 128
        && hex.len() % 2 == 0
        && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Fsync a directory, so entry creations, removals and renames inside it
/// are durable (the kernel's own discipline, `journal/segment.rs`). On a
/// non-unix target this is a no-op; v1 targets unix.
pub(crate) fn fsync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// The volume's free space at `path`, in bytes — what the floor reads: the
/// blocks available to an unprivileged writer times the fragment size.
pub(crate) fn free_space(path: &Path) -> io::Result<u64> {
    let v = rustix::fs::statvfs(path).map_err(io::Error::from)?;
    Ok(v.f_bavail.saturating_mul(v.f_frsize))
}

// ── the JSON-lines logs ──────────────────────────────────────────────────

/// Read a log whole, as the JSON values of its lines in order — trust ending
/// at the first line that is no JSON object or that lacks its newline (a
/// torn tail), which is TRUNCATED off the file there and never read past
/// (the honest-null arm's tail check). Answers the values and whether the
/// file was cut.
pub(crate) fn read_log(path: &Path) -> io::Result<(Vec<Value>, bool)> {
    let mut bytes = Vec::new();
    match File::open(path) {
        Ok(mut f) => {
            f.read_to_end(&mut bytes)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), false)),
        Err(e) => return Err(e),
    }
    let mut values = Vec::new();
    let mut good = 0usize;
    let mut cut = false;
    let mut at = 0usize;
    while at < bytes.len() {
        let Some(nl) = bytes[at..].iter().position(|&b| b == b'\n') else {
            cut = true; // no newline: a line being written when the process died
            break;
        };
        let line = &bytes[at..at + nl];
        match serde_json::from_slice::<Value>(line) {
            Ok(v) if v.is_object() => {
                values.push(v);
                at += nl + 1;
                good = at;
            }
            _ => {
                cut = true;
                break;
            }
        }
    }
    if cut {
        OpenOptions::new().write(true).open(path)?.set_len(good as u64)?;
    }
    Ok((values, cut))
}

/// Open a log for appending, creating it under `dir` where absent.
pub(crate) fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// Rewrite a log to exactly `lines` — the compaction: written to a
/// `.compact` twin beside it, fsynced, renamed over the log, the directory
/// fsynced — the same install order a blob takes, so a crash mid-compaction
/// leaves the old log whole or the new one, never a mix. Answers the fresh
/// append handle.
pub(crate) fn rewrite_log(path: &Path, lines: &[String]) -> io::Result<File> {
    let dir = path.parent().expect("a log sits in a directory");
    let twin = path.with_extension("compact");
    {
        let mut f = File::create(&twin)?;
        for line in lines {
            f.write_all(line.as_bytes())?;
            f.write_all(b"\n")?;
        }
        f.sync_all()?;
    }
    fs::rename(&twin, path)?;
    fsync_dir(dir)?;
    open_append(path)
}

/// One JSON object as its line, members in sorted order (serde_json's map
/// is a sorted map), no newline.
pub(crate) fn line_of(v: &Value) -> String {
    serde_json::to_string(v).expect("a JSON value renders")
}

/// Install `bytes` at `path` by the blob's own order — the operator's pull
/// and the tests take this door; the PUT's finish takes the step-by-step
/// one in `lib.rs`, where the hazard seam sits. A temp file beside the
/// target, fsynced, renamed over it, the directory fsynced.
pub(crate) fn install_whole(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().expect("a blob sits in its designation directory");
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".install-{}", std::process::id()));
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    fsync_dir(dir)?;
    Ok(())
}

/// The path of a blob under `root`.
pub(crate) fn blob_path(root: &Path, designation: &str, hex: &str) -> PathBuf {
    root.join(designation).join(hex)
}
