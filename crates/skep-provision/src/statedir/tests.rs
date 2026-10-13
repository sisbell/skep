//! T10 — THE STATE DIRECTORY beneath the sign-up file and the invite file:
//! the address rule and its value; THE DOOR, made `0700` and refused loose
//! in the daemon's words — any group or other bit, each one alone; THE
//! WRITER, its files owner-only, whose failure between the write and the
//! rename leaves the old file whole and no temp file; and the date a line
//! carries.

use std::fs;

use super::*;
use crate::scratch::Scratch;
use crate::whole::temp_of;

/// The address rule: one `@` with a side each way, at most 254 bytes, no
/// control character and no whitespace — and [`MailAddress::parse`], its one
/// door, admits exactly the addresses the rule does, keeping each as given,
/// its `Debug` showing none of it.
#[test]
fn an_address_is_one_at_with_a_side_each_way_no_space_and_no_control() {
    for ok in ["a@b", "person@example.com", "first.last+tag@sub.example.org"] {
        assert!(address_ok(ok), "{ok}");
        assert_eq!(MailAddress::parse(ok).as_ref().map(MailAddress::as_str), Some(ok));
    }
    let long = format!("{}@b", "a".repeat(MAX_ADDRESS_BYTES - 2));
    assert!(address_ok(&long));
    assert!(MailAddress::parse(&long).is_some());
    for bad in ["", "ab", "@b", "a@", "a@b@c", "a b@c", "a@b\n", "a\t@b", "a@b\r", "\u{a0}a@b"] {
        assert!(!address_ok(bad), "{bad:?}");
        assert!(MailAddress::parse(bad).is_none(), "{bad:?}");
    }
    assert!(!address_ok(&format!("{long}c")), "255 bytes");
    assert!(MailAddress::parse(&format!("{long}c")).is_none(), "255 bytes");
    assert_eq!(format!("{:?}", MailAddress::parse("person@example.com").expect("an address")), "MailAddress(…)");
}

/// THE STATE DIRECTORY's DOOR: made `0700` where absent; refused where it
/// stands with a group or other bit set, in `skepd`'s `LooseDataDir`
/// words; admitted at `0700`; refused where a file stands at the path.
#[cfg(unix)]
#[test]
fn the_state_directory_is_owner_only_or_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new();
    let made = dir.path().join("made");
    StateDir::open(&made).expect("made");
    assert_eq!(fs::metadata(&made).expect("its mode").permissions().mode() & 0o777, 0o700);
    let loose = dir.path().join("loose");
    fs::create_dir(&loose).expect("a directory");
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).expect("loosened");
    let refused: &dyn std::error::Error = &StateDir::open(&loose).expect_err("loose");
    assert_eq!(
        refused.to_string(),
        format!("the state directory {0} is mode 755: other users of this machine can read the sign-up addresses and the invite codes; chmod 700 {0} and start again", loose.display())
    );
    assert_eq!(fs::read_dir(&loose).expect("listed").count(), 0, "nothing created, nothing repaired");
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o700)).expect("tightened");
    StateDir::open(&loose).expect("admitted at 0700");
    let file = dir.path().join("file");
    fs::write(&file, b"").expect("a file");
    assert!(matches!(StateDir::open(&file), Err(StateDirRefused::Io { .. })));
}

/// THE DOOR REFUSES ANY GROUP OR OTHER BIT, each one alone — a group that
/// can write the directory, and so swap the invite file for its own, as
/// surely as one that can read it — and names the mode it found.
#[cfg(unix)]
#[test]
fn any_group_or_other_bit_alone_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new();
    for bit in [0o040, 0o020, 0o010, 0o004, 0o002, 0o001] {
        let path = dir.path().join(format!("loose-{bit:o}"));
        fs::create_dir(&path).expect("a directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700 | bit)).expect("loosened");
        match StateDir::open(&path) {
            Err(StateDirRefused::Loose { mode, .. }) => assert_eq!(mode, 0o700 | bit),
            other => panic!("{:o}: {other:?}", 0o700 | bit),
        }
    }
}

/// THE WRITER: its file owner-only, `0600`; a failure between the write and
/// the rename leaves the old file whole and no temp file behind; a write
/// that completes replaces it.
#[test]
fn a_failure_before_the_rename_leaves_the_old_file_whole() {
    let dir = Scratch::new();
    let path = dir.path().join("file");
    write_whole(&path, b"old\n").expect("written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&path).expect("its mode").permissions().mode() & 0o777, 0o600);
    }
    let failed = write_whole_with(&path, b"new\n", &|| Err(io::Error::other("a failure between the write and the rename")));
    assert!(failed.is_err());
    assert_eq!(fs::read(&path).expect("the file"), b"old\n");
    assert!(!temp_of(&path).exists(), "no temp file left");
    write_whole(&path, b"new\n").expect("written");
    assert_eq!(fs::read(&path).expect("the file"), b"new\n");
    assert!(!temp_of(&path).exists());
}

/// The date: `yyyy-mm-dd` in UTC, from unix seconds.
#[test]
fn the_date_is_yyyy_mm_dd_in_utc() {
    assert_eq!(civil_date(0), "1970-01-01");
    assert_eq!(civil_date(86_399), "1970-01-01");
    assert_eq!(civil_date(86_400), "1970-01-02");
    assert_eq!(civil_date(951_782_400), "2000-02-29");
    assert_eq!(civil_date(1_791_763_200), "2026-10-12");
}
