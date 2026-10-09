//! (a) THE BLOB STORE's FILES ARE OWNER-ONLY (`Store::open`, the partial's
//! creation, the finish's install, the pull's `Store::install_file`, the
//! two logs and their compaction twins, and the seam's `Store::install`):
//! a fresh store under a `blobs/` that does not exist creates it `0700`;
//! after a partial is created, a blob installed by the finish's path, one
//! by the pull's and one by the seam's, and a record logged, every
//! directory under the root is `0700` and every file `0600` — the
//! designation directory, the partial, the three blobs, `uploads.log` and
//! `leases.log` — and the logs again once a reopen's compaction has
//! rewritten one through its twin, the log then being the twin's own file.
//!
//! The claim asserts the EXACT bits and reports the umask it ran under: at
//! `022`, the machine's default, the modes removed would leave `0755`
//! directories and `0644` files; at a umask that already masks group and
//! other the claim cannot tell the modes from the umask, and says so. The
//! umask is read, never set.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use skep_blobs::{HashFunction, Store};

use crate::{hex_of, open, put_whole, standing};

/// The permission bits of `path` — `mode & 0o7777`.
#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    meta.permissions().mode() & 0o7777
}

/// The inode of `path` — whether a file is the one that stood before.
#[cfg(unix)]
fn inode_of(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).unwrap_or_else(|e| panic!("{}: {e}", path.display())).ino()
}

/// The umask this process runs under, read through the shell and REPORTED
/// — never set.
fn umask() -> u32 {
    let out = Command::new("sh").args(["-c", "umask"]).output().expect("sh -c umask");
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    u32::from_str_radix(&text, 8).unwrap_or_else(|_| panic!("the shell's umask is octal: {text:?}"))
}

/// Every directory and file under `root`, recursively — the root itself
/// first — each with whether it is a directory and its mode.
#[cfg(unix)]
fn tree_modes(root: &Path) -> Vec<(PathBuf, bool, u32)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, bool, u32)>) {
        for entry in fs::read_dir(dir).expect("a directory") {
            let path = entry.expect("an entry").path();
            let is_dir = path.is_dir();
            out.push((path.clone(), is_dir, mode_of(&path)));
            if is_dir {
                walk(&path, out);
            }
        }
    }
    let mut out = vec![(root.to_path_buf(), true, mode_of(root))];
    walk(root, &mut out);
    out
}

/// (a) THE BLOB STORE's FILES ARE OWNER-ONLY: `blobs/` born `0700`; the
/// designation directory `0700`; the partial, the finish's blob, the
/// seam's planted blob and both logs `0600`; the pull's path over a root
/// that does not yet exist making every component `0700` and the file
/// `0600`; and after a reopen's compaction the rewritten log — the twin's
/// own file, by inode — `0600` too. Every entry under each root, exactly.
#[cfg(unix)]
#[test]
fn the_stores_directories_and_files_are_owner_only_whatever_the_umask() {
    let umask = umask();
    println!(
        "ran under umask {umask:03o}: a {} claim — the modes removed would leave {:o} and {:o} here",
        if umask & 0o077 == 0o077 { "NON-DISCRIMINATING" } else { "discriminating" },
        0o777 & !umask,
        0o666 & !umask
    );
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("blobs");
    assert!(!root.exists(), "the root does not exist before the open");
    let planted_hex = hex_of(b"planted by the seam");

    let (partial, finished) = {
        let store = open(&root, 0);
        assert_eq!(mode_of(&root), 0o700, "blobs/ is born 0700");
        // The partial: the designation directory made with it.
        let partial = standing(&store, "p", 10, b"hello", 0);
        // The finish's install: the partial renamed onto its hex.
        let finished = put_whole(&store, "q", b"a whole deposit", 0);
        // The seam's install: a temp file beside the target, renamed over it.
        store.install("blake3", &planted_hex, b"planted by the seam").expect("the seam installs");
        (partial, finished)
    };
    let designation = root.join("blake3");
    let partial_path = designation.join(format!(".upload-{}", partial.id));
    assert!(partial_path.is_file(), "the partial stands at {}", partial_path.display());
    assert_eq!(mode_of(&designation), 0o700, "the designation directory is 0700");
    assert_eq!(mode_of(&partial_path), 0o600, "the partial is 0600");
    assert_eq!(mode_of(&designation.join(&finished.hex)), 0o600, "the finish's blob is 0600");
    assert_eq!(mode_of(&designation.join(&planted_hex)), 0o600, "the seam's blob is 0600");
    for log in ["uploads.log", "leases.log"] {
        assert_eq!(mode_of(&root.join(log)), 0o600, "{log} is 0600");
    }

    // THE PULL's PATH over a root that does not yet exist: every component
    // it makes is 0700, the installed file 0600.
    let pulled_root = tmp.path().join("pulled").join("blobs");
    let source = tmp.path().join("picture");
    fs::write(&source, b"the picture's bytes").expect("a source file");
    let pulled = Store::install_file(&pulled_root, HashFunction::Blake3, &source, None).expect("the pull installs");
    for dir in [tmp.path().join("pulled"), pulled_root.clone(), pulled_root.join("blake3")] {
        assert_eq!(mode_of(&dir), 0o700, "the pull made {} 0700", dir.display());
    }
    assert_eq!(mode_of(&pulled_root.join("blake3").join(&pulled.hex)), 0o600, "the pulled file is 0600");

    // A REOPEN's COMPACTION: `uploads.log` holds more lines than its one
    // standing record, so the open rewrites it through its twin, and the
    // file at the name is the twin's — a fresh inode, born 0600.
    let before = inode_of(&root.join("uploads.log"));
    drop(open(&root, 0));
    assert_ne!(inode_of(&root.join("uploads.log")), before, "the open rewrote uploads.log through its twin");
    assert!(!root.join("uploads.compact").exists(), "the twin is renamed over the log");
    for log in ["uploads.log", "leases.log"] {
        assert_eq!(mode_of(&root.join(log)), 0o600, "{log} is 0600 after the compaction");
    }

    // EVERY ENTRY under both roots, directory or file, nothing else.
    for root in [root, pulled_root] {
        for (path, is_dir, mode) in tree_modes(&root) {
            let wanted = if is_dir { 0o700 } else { 0o600 };
            assert_eq!(mode, wanted, "{} is {wanted:o} exactly", path.display());
        }
    }
}
