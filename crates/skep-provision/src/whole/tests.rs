//! A KEPT FILE CHANGED DURABLY: the replacement lands whole at exactly the
//! mode its owner names — a temp file a stop left behind at a wider mode
//! never carried into the file — and replaces the bytes whole; a link
//! planted at the temp file's name is never written through; a failure
//! between the write and the rename leaves the old file whole and no temp
//! file, and an error from the directory's sync comes after the act — the
//! new file in place, the removed one gone; the removal answers whether a
//! file stood. (The owners' own modes are their suites': the snippet's
//! `0644` in `caddy`'s, the sign-up file's `0600` in `signups`'.)

use std::fs;

use super::*;
use crate::scratch::Scratch;

/// THE REPLACEMENT AT ITS OWNER's MODE: `0600` and `0644` alike, the file
/// holds the bytes whole at exactly that mode and no temp file is left; a
/// second replacement over a temp file a stop left at `0666` holds the new
/// bytes at the owner's mode, not the leftover's.
#[cfg(unix)]
#[test]
fn a_replacement_lands_whole_at_the_mode_its_owner_names() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new();
    let mode = |path: &Path| fs::metadata(path).expect("its mode").permissions().mode() & 0o777;
    for owner_mode in [0o600, 0o644] {
        let path = dir.path().join(format!("file-{owner_mode:o}"));
        replace(&path, b"old\n", owner_mode, &|| Ok(())).expect("replaced");
        assert_eq!((fs::read(&path).expect("the file"), mode(&path)), (b"old\n".to_vec(), owner_mode));
        assert!(!temp_of(&path).exists(), "no temp file left");
        fs::write(temp_of(&path), b"a stop's leftover").expect("a leftover temp file");
        fs::set_permissions(temp_of(&path), fs::Permissions::from_mode(0o666)).expect("widened");
        replace(&path, b"new\n", owner_mode, &|| Ok(())).expect("replaced again");
        assert_eq!((fs::read(&path).expect("the file"), mode(&path)), (b"new\n".to_vec(), owner_mode), "{owner_mode:o} over a leftover at 666");
        assert!(!temp_of(&path).exists(), "no temp file left");
    }
}

/// A LINK PLANTED AT THE TEMP FILE's NAME is never written through: the
/// file it points at keeps its bytes and its mode, and the replacement
/// lands as a regular file of its own; a link that dangles makes no file
/// where it points.
#[cfg(unix)]
#[test]
fn a_link_planted_at_the_temp_name_is_never_written_through() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = Scratch::new();
    let victim = dir.path().join("invites");
    fs::write(&victim, b"the invite file\n").expect("a victim");
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).expect("owner-only");
    let path = dir.path().join("alice.caddy");
    symlink(&victim, temp_of(&path)).expect("a planted link");
    replace(&path, b"a snippet\n", 0o644, &|| Ok(())).expect("replaced");
    assert_eq!(fs::read(&victim).expect("the victim"), b"the invite file\n");
    assert_eq!(fs::metadata(&victim).expect("its mode").permissions().mode() & 0o777, 0o600);
    assert!(fs::symlink_metadata(&path).expect("the file").file_type().is_file(), "the replacement is a link");
    assert_eq!(fs::read(&path).expect("the file"), b"a snippet\n");
    let elsewhere = dir.path().join("elsewhere");
    symlink(&elsewhere, temp_of(&path)).expect("a dangling link");
    replace(&path, b"another\n", 0o644, &|| Ok(())).expect("replaced");
    assert!(!elsewhere.exists(), "a file made where the dangling link points");
    assert_eq!(fs::read(&path).expect("the file"), b"another\n");
}

/// A FAILURE between the write and the rename leaves the old file whole and
/// no temp file behind.
#[test]
fn a_failure_before_the_rename_leaves_the_old_file_whole() {
    let dir = Scratch::new();
    let path = dir.path().join("file");
    replace(&path, b"old\n", 0o600, &|| Ok(())).expect("replaced");
    let failed = replace(&path, b"new\n", 0o600, &|| Err(io::Error::other("a failure between the write and the rename")));
    assert!(failed.is_err());
    assert_eq!(fs::read(&path).expect("the file"), b"old\n");
    assert!(!temp_of(&path).exists(), "no temp file left");
}

/// AN ERROR FROM THE DIRECTORY's SYNC COMES AFTER THE ACT: in a directory
/// its owner may write and search but not read — the rename lands, and the
/// directory's open for its sync is refused — the replacement answers an
/// error with the new file in place and no temp file, and the removal an
/// error with the file gone: an error is never "the old file".
#[cfg(unix)]
#[test]
fn an_error_from_the_directorys_sync_comes_after_the_act() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new();
    let boards = dir.path().join("boards");
    fs::create_dir(&boards).expect("a directory");
    let path = boards.join("file");
    replace(&path, b"old\n", 0o600, &|| Ok(())).expect("replaced");
    fs::set_permissions(&boards, fs::Permissions::from_mode(0o300)).expect("writable and searchable, not readable");
    assert!(replace(&path, b"new\n", 0o600, &|| Ok(())).is_err(), "the directory's sync was refused");
    assert_eq!(fs::read(&path).expect("the file"), b"new\n", "the new file in place");
    assert!(!temp_of(&path).exists(), "no temp file left");
    assert!(remove(&path).is_err(), "the directory's sync was refused");
    assert!(!path.exists(), "the file gone");
}

/// THE REMOVAL answers whether a file stood: `true` once, then `false`.
#[test]
fn a_removal_answers_whether_a_file_stood() {
    let dir = Scratch::new();
    let path = dir.path().join("file");
    replace(&path, b"x", 0o644, &|| Ok(())).expect("replaced");
    assert!(remove(&path).expect("removed"));
    assert!(!path.exists());
    assert!(!remove(&path).expect("nothing to remove"));
}

/// A file's temp sibling is its name and `.tmp` — the snippet's
/// `<name>.caddy.tmp`, outside the proxy's `*.caddy` glob.
#[test]
fn the_temp_sibling_is_the_name_and_dot_tmp() {
    assert_eq!(temp_of(Path::new("/etc/caddy/boards/alice.caddy")), PathBuf::from("/etc/caddy/boards/alice.caddy.tmp"));
}
