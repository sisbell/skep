//! A KEPT FILE CHANGED DURABLY: the replacement lands whole at exactly the
//! mode its owner names — a temp file a stop left behind at a wider mode
//! brought to it, never carried into the file — and replaces the bytes
//! whole; a failure between the write and the rename leaves the old file
//! whole and no temp file; the removal answers whether a file stood. (The
//! owners' own modes are their suites': the snippet's `0644` in `caddy`'s,
//! the sign-up file's `0600` in `signups`'.)

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
    for owners in [0o600, 0o644] {
        let path = dir.path().join(format!("file-{owners:o}"));
        replace(&path, b"old\n", owners, &|| Ok(())).expect("replaced");
        assert_eq!((fs::read(&path).expect("the file"), mode(&path)), (b"old\n".to_vec(), owners));
        assert!(!temp_of(&path).exists(), "no temp file left");
        fs::write(temp_of(&path), b"a stop's leftover").expect("a leftover temp file");
        fs::set_permissions(temp_of(&path), fs::Permissions::from_mode(0o666)).expect("widened");
        replace(&path, b"new\n", owners, &|| Ok(())).expect("replaced again");
        assert_eq!((fs::read(&path).expect("the file"), mode(&path)), (b"new\n".to_vec(), owners), "{owners:o} over a leftover at 666");
        assert!(!temp_of(&path).exists(), "no temp file left");
    }
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
