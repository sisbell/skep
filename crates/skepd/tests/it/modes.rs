//! THE BOARD IS BORN OWNER-ONLY, AND A LOOSE ONE IS REFUSED (the local-board
//! record's two daemon changes, (a) and (b), both RULED in; `ARCHITECTURE.md`
//! "The daemon writes only its own files"; the usage's `--data-dir`
//! sentence), judged on the REAL BINARY in `open.rs`'s harness — spawned
//! with its two streams piped and read on threads, killed and reaped by the
//! [`Spawned`] guard on a passing claim's return and a failing one's unwind
//! alike:
//!
//! * (a) THE DAEMON's FILES ARE OWNER-ONLY, UNDER A LOOSE UMASK: the binary
//!   started through `sh -c 'umask 022; exec …'` on a data directory that
//!   does not exist, one commit over the wire, then killed — the directory
//!   is `0700`, `blobs/` is `0700`, and `kernel.lock`, `seg-1.wal`,
//!   `commits.log`, the four feed files, `feed-attest.log`, `uploads.log`
//!   and `leases.log` are `0600`; every directory and file under it, exactly.
//!   The umask is the shell's and never the suite's, so the claim fails
//!   deterministically with the modes removed (`0644` files appear).
//! * (b) A LOOSE DIRECTORY IS REFUSED, A TIGHT ONE ADMITTED: a directory the
//!   test made `0755` — the start exits 1 with ONE stderr line, the record's
//!   words naming the path, the mode `755` and `chmod 700`, nothing created
//!   inside it and nothing repaired; `0750` the same, at its mode; the same
//!   directory set `0700` is admitted; one that does not exist is created
//!   `0700` and admitted. THE ARM: the refusal is the binary's own door
//!   before the open ((b-B)), so the line is stderr's FIRST and no `open:
//!   data-dir` line precedes it — where the directory is admitted, that
//!   open line is the first.
//! * (b) THE TOOLS' AND THE LIBRARY's STANDING under (b-B): `skepd
//!   inventory` over a `0755` copy of a board ANSWERS, and `Daemon::open`
//!   on a `0755` directory SERVES — neither is held to the mode; the binary
//!   refuses that same copy. The arm's consequence, written down.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::common::{get, json, spawn_unclaimed};
use crate::open::{after_the_head, delegate_a_home, serving_port, skepd, Spawned, Stderr, PATIENCE};

/// The permission bits of `path` — `mode & 0o7777`.
#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    meta.permissions().mode() & 0o7777
}

/// `mode` as a `Permissions`, for the test's own `chmod`.
#[cfg(unix)]
fn perms(mode: u32) -> fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    fs::Permissions::from_mode(mode)
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

/// `src`'s tree copied into `dst`, which the caller has made — the copy a
/// backup tool makes at the process umask.
fn copy_tree(src: &Path, dst: &Path) {
    for entry in fs::read_dir(src).expect("read the board") {
        let entry = entry.expect("an entry");
        let to = dst.join(entry.file_name());
        if entry.file_type().expect("a file type").is_dir() {
            fs::create_dir_all(&to).expect("a copied directory");
            copy_tree(&entry.path(), &to);
        } else {
            fs::copy(entry.path(), &to).expect("copy a file");
        }
    }
}

/// The binary over `dir` on `--port 0` with the floor's workers
/// (`skepd::MIN_WORKERS`, the count the parse admits), started through
/// `sh` under `umask 022` — the loose default a login shell gives — with
/// `exec`, so the child IS the binary and the guard's kill reaches it; both
/// streams piped.
fn skepd_under_umask_022(dir: &Path) -> Command {
    let workers = skepd::MIN_WORKERS.to_string();
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg("umask 022; exec \"$0\" \"$@\"")
        .arg(env!("CARGO_BIN_EXE_skepd"))
        .arg("--data-dir")
        .arg(dir)
        .args(["--port", "0", "--workers", workers.as_str()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// The record's refusal line for `dir` at `mode`, as `skepd: {e}` prints it.
fn refusal_line(dir: &Path, mode: u32) -> String {
    format!(
        "skepd: the data directory {} is mode {mode:o}: other users of this machine can read the \
         board; chmod 700 {} and start again",
        dir.display(),
        dir.display()
    )
}

/// A child run to its exit: the code, stderr whole and stdout whole.
fn run_to_exit(cmd: &mut Command) -> (Option<i32>, String, String) {
    let mut child = Spawned::launch(cmd);
    let status = child.wait_within(PATIENCE);
    let mut stderr = String::new();
    child.child.stderr.take().expect("piped").read_to_string(&mut stderr).expect("read stderr");
    let mut stdout = String::new();
    child.child.stdout.take().expect("piped").read_to_string(&mut stdout).expect("read stdout");
    (status.code(), stderr, stdout)
}

/// A child served over `dir` through `cmd`: the open's first line is the
/// directory's, `/health` answers, and the child is killed — its stderr
/// whole answered for the caller's reading.
fn serve_then_kill(cmd: &mut Command) -> Vec<String> {
    let mut child = Spawned::launch(cmd);
    let stderr = Stderr::of(&mut child.child);
    let port = serving_port(&mut child.child, PATIENCE);
    let (st, body) = get(port, "/health");
    assert_eq!((st, json(&body)["ok"].as_bool()), (200, Some(true)), "{}", String::from_utf8_lossy(&body));
    child.kill();
    let whole = stderr.whole();
    let first = whole.first().expect("the open said its directory");
    assert!(
        after_the_head(first, "open").is_some_and(|said| said.starts_with("data-dir ")),
        "an admitted start's first line is the open's directory line: {first:?}"
    );
    whole
}

/// (a) THE DAEMON's FILES ARE OWNER-ONLY, UNDER A LOOSE UMASK: the binary
/// under `umask 022` on a directory that does not exist, two commits over
/// the wire (the delegate and a home's mint), then killed — the directory
/// and `blobs/` `0700`, every named file `0600`, and every entry under the
/// directory, exactly.
#[cfg(unix)]
#[test]
fn every_directory_and_file_the_board_creates_is_owner_only_under_a_loose_umask() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    assert!(!dir.exists());
    let mut child = Spawned::launch(&mut skepd_under_umask_022(&dir));
    let stderr = Stderr::of(&mut child.child);
    let port = serving_port(&mut child.child, PATIENCE);
    let (_home, _session) = delegate_a_home(port);
    child.kill();
    let _ = stderr.whole();
    println!("the child ran under umask 022 by construction (the shell's, never the suite's)");

    assert_eq!(mode_of(&dir), 0o700, "the data directory is 0700");
    assert_eq!(mode_of(&dir.join("blobs")), 0o700, "blobs/ is 0700");
    for name in [
        "kernel.lock",
        "seg-1.wal",
        "commits.log",
        "feed-index.log",
        "feed-offsets.log",
        "feed-masked.log",
        "feed-streams.log",
        "feed-attest.log",
        "blobs/uploads.log",
        "blobs/leases.log",
    ] {
        let path = dir.join(name);
        assert!(path.is_file(), "{name} stands");
        assert_eq!(mode_of(&path), 0o600, "FINDING ((a), the modes): {name} is not 0600");
    }
    for (path, is_dir, mode) in tree_modes(&dir) {
        let wanted = if is_dir { 0o700 } else { 0o600 };
        assert_eq!(mode, wanted, "FINDING ((a), the modes): {} is {mode:o}, not {wanted:o}", path.display());
    }
}

/// (b) A LOOSE DIRECTORY IS REFUSED, A TIGHT ONE ADMITTED — and the arm is
/// the binary's door before the open ((b-B)): the refusal is stderr's one
/// line, nothing on stdout, nothing created inside the directory, nothing
/// repaired; at `0750` the same, at its mode; at `0700` admitted, the open's
/// directory line then first; a directory that does not exist created
/// `0700` and admitted.
#[cfg(unix)]
#[test]
fn a_loose_data_directory_is_refused_before_the_open_and_a_tight_one_admitted() {
    use std::os::unix::fs::DirBuilderExt;
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    fs::DirBuilder::new().mode(0o755).create(&dir).expect("a loose directory");
    assert_eq!(mode_of(&dir), 0o755, "the test's directory is 0755 (the umask took no bit of it)");

    // REFUSED at 0755.
    let (code, stderr, stdout) = run_to_exit(&mut skepd(&dir, &["--port", "0"]));
    assert_eq!(code, Some(1), "exit 1; stderr: {stderr:?}");
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(lines, vec![refusal_line(&dir, 0o755).as_str()], "FINDING ((b), the refusal): stderr is not the record's one line");
    assert!(stdout.is_empty(), "no serving line: {stdout:?}");
    assert!(
        fs::read_dir(&dir).expect("list").next().is_none(),
        "FINDING ((b), the refusal): something was created inside the refused directory"
    );
    assert_eq!(mode_of(&dir), 0o755, "nothing repaired: the mode stands");

    // REFUSED at 0750 — a group bit alone is loose, and the line says 750.
    fs::set_permissions(&dir, perms(0o750)).expect("chmod 750");
    let (code, stderr, _) = run_to_exit(&mut skepd(&dir, &["--port", "0"]));
    assert_eq!(code, Some(1), "exit 1; stderr: {stderr:?}");
    assert_eq!(stderr.lines().collect::<Vec<_>>(), vec![refusal_line(&dir, 0o750).as_str()]);
    assert!(!dir.join("kernel.lock").exists(), "no lock taken");

    // ADMITTED at 0700: the open's directory line is stderr's first, the
    // board serves, the lock stands.
    fs::set_permissions(&dir, perms(0o700)).expect("chmod 700");
    let workers = skepd::MIN_WORKERS.to_string();
    serve_then_kill(&mut skepd(&dir, &["--port", "0", "--workers", &workers]));
    assert!(dir.join("kernel.lock").is_file(), "admitted: the open took its lock");
    assert_eq!(mode_of(&dir), 0o700);

    // A DIRECTORY THAT DOES NOT EXIST: created 0700 and admitted.
    let fresh = tmp.path().join("fresh");
    assert!(!fresh.exists());
    serve_then_kill(&mut skepd(&fresh, &["--port", "0", "--workers", &workers]));
    assert_eq!(mode_of(&fresh), 0o700, "the kernel created it owner-only");
}

/// (b) THE TOOLS' AND THE LIBRARY's STANDING under arm (b-B): a board built
/// in-process and closed, copied whole into a `0755` directory — `skepd
/// inventory` over the copy ANSWERS its object and exits 0; the library's
/// open on a `0755` directory SERVES; and the binary's served start refuses
/// that same copy with the record's line.
#[cfg(unix)]
#[test]
fn the_inventory_and_the_librarys_open_are_not_held_to_the_directorys_mode() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let built = tmp.path().join("built");
    {
        let sd = spawn_unclaimed(&built);
        delegate_a_home(sd.port());
        sd.shutdown();
    }
    let copy = tmp.path().join("copy");
    fs::create_dir_all(&copy).expect("the copy's directory");
    fs::set_permissions(&copy, perms(0o755)).expect("chmod 755");
    copy_tree(&built, &copy);
    assert_eq!(mode_of(&copy), 0o755);

    // THE INVENTORY over the loose copy answers.
    let out = Command::new(env!("CARGO_BIN_EXE_skepd"))
        .args(["inventory", "--data-dir"])
        .arg(&copy)
        .output()
        .expect("run the inventory");
    assert!(
        out.status.success(),
        "the inventory is not held to the mode (arm (b-B)): exit {:?}, stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let v = json(&out.stdout);
    assert!(v.is_object() && !v["holes"].is_null(), "the inventory's one object: {v}");

    // THE LIBRARY's OPEN on a loose directory serves.
    let loose = tmp.path().join("loose");
    fs::create_dir_all(&loose).expect("a loose directory");
    fs::set_permissions(&loose, perms(0o755)).expect("chmod 755");
    {
        let sd = spawn_unclaimed(&loose);
        let (st, body) = get(sd.port(), "/health");
        assert_eq!((st, json(&body)["ok"].as_bool()), (200, Some(true)), "the library is not held to the mode (arm (b-B))");
        sd.shutdown();
    }

    // THE BINARY's served start refuses the same copy.
    let (code, stderr, _) = run_to_exit(&mut skepd(&copy, &["--port", "0"]));
    assert_eq!(code, Some(1), "stderr: {stderr:?}");
    assert_eq!(stderr.lines().collect::<Vec<_>>(), vec![refusal_line(&copy, 0o755).as_str()]);
}
