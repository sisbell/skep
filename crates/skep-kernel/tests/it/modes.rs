//! (a) THE KERNEL's FILES ARE OWNER-ONLY — the caller contract on
//! `Durability::Fsync`'s `journal_path` (`config.rs`): "On unix the
//! directory and every file the kernel creates in it are OWNER-ONLY — the
//! directory `0700` (every component `open()` makes), each file `0600` —
//! the mode set at creation, the process umask irrelevant". A kernel opened
//! on a path that does not exist creates every missing component `0700`,
//! and after one commit and one checkpoint `kernel.lock`, `seg-1.wal` and
//! `checkpoint.<n>` — the checkpoint written through `checkpoint.tmp`, whose
//! mode the rename carries — are `0600` exactly, no other bit set.
//!
//! The claim asserts the EXACT bits and reports the umask it ran under: at
//! `022`, the machine's default, the modes removed would leave a `0755`
//! directory and `0644` files, which is what the claim fails on; at a umask
//! that already masks group and other the claim cannot tell the modes from
//! the umask, and says so beside the figure it prints. The umask is read,
//! never set — a test sets no process umask.

use std::fs;
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};
use skep_kernel::{
    BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelConfig, SaltSource, WorldState,
};

/// The smallest world the kernel opens: a count of the records applied.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Count(u64);

#[derive(Debug, Serialize, Deserialize)]
struct Tick;

impl WorldState for Count {
    type Record = Tick;

    fn apply(&self, _: &Tick) -> Self {
        Count(self.0 + 1)
    }
}

/// The permission bits of `path` — `mode & 0o7777`, so a set-id or sticky
/// bit shows rather than hides.
#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    meta.permissions().mode() & 0o7777
}

/// The umask this process runs under, read through the shell and REPORTED
/// — never set: a test sets no process umask.
fn umask() -> u32 {
    let out = Command::new("sh").args(["-c", "umask"]).output().expect("sh -c umask");
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    u32::from_str_radix(&text, 8).unwrap_or_else(|_| panic!("the shell's umask is octal: {text:?}"))
}

/// A journaled configuration over `dir`, checkpoints by hand.
fn cfg(dir: &Path) -> KernelConfig {
    KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 2,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0x4D),
    }
}

/// (a) THE KERNEL's FILES ARE OWNER-ONLY: the directory `0700` — the
/// missing parent `open()` made with it too — and, after one commit and
/// one checkpoint, `kernel.lock`, `seg-1.wal` and `checkpoint.<n>` `0600`
/// exactly; every entry of the directory, named or not, the same. The umask
/// the claim ran under is printed with the verdict.
#[cfg(unix)]
#[test]
fn the_kernels_directory_and_files_are_owner_only_whatever_the_umask() {
    let umask = umask();
    let tmp = tempfile::tempdir().expect("tempdir");
    let parent = tmp.path().join("nested");
    let dir = parent.join("board");
    assert!(!parent.exists(), "the path does not exist before the open");

    let kernel = Kernel::open(cfg(&dir), Count::default()).expect("a fresh kernel opens");
    kernel
        .transact(&[], |staging| {
            staging.push(Tick);
            Ok::<(), ()>(())
        })
        .expect("one commit");
    let landed = kernel.checkpoint().expect("one checkpoint");
    drop(kernel);

    println!(
        "ran under umask {umask:03o}: a {} claim — the modes removed would leave {:o} and {:o} here",
        if umask & 0o077 == 0o077 { "NON-DISCRIMINATING" } else { "discriminating" },
        0o777 & !umask,
        0o666 & !umask
    );
    assert_eq!(mode_of(&parent), 0o700, "every component open() made is 0700: {}", parent.display());
    assert_eq!(mode_of(&dir), 0o700, "the data directory is 0700: {}", dir.display());
    for name in ["kernel.lock", "seg-1.wal", &format!("checkpoint.{}", landed.0)] {
        let path = dir.join(name);
        assert!(path.is_file(), "{name} stands");
        assert_eq!(mode_of(&path), 0o600, "{name} is 0600 exactly");
    }
    let mut entries = 0;
    for entry in fs::read_dir(&dir).expect("list the directory") {
        let path = entry.expect("an entry").path();
        assert!(path.is_file(), "the kernel makes no directory inside its own: {}", path.display());
        assert_eq!(mode_of(&path), 0o600, "{} is 0600 exactly", path.display());
        entries += 1;
    }
    assert_eq!(entries, 3, "the lock, the segment and the checkpoint, nothing else");
}
