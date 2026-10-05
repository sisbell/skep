//! THE FILES (`media.md` §The media stores; M-I5 (c)): the size check's
//! read, a size that cannot be read answered as a failure and never as an
//! absence; the name check at every entry point, and the one designation a
//! creation may name; the directory listings, each naming its own class in
//! name order; and the floor's read of the space available on the volume.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::{hex_of, open, put_whole, standing, INTERVAL};

/// THE DIRECTORY LISTINGS NAME EACH CLASS ALONE, IN NAME ORDER
/// (`Store::blobs_of`: "the files at HEX NAMES …, in name order — … a
/// partial or an aside excluded by its name"; `Store::asides_of`,
/// `Store::designations`: "in name order"): beside eight files at hex names
/// stand eight asides, eight partials, a directory at a hex name and eight
/// more designation directories; each listing names its own class alone,
/// sorted — eight names in a random order fall sorted once in 40,320.
#[test]
fn the_directory_listings_name_each_class_alone_in_name_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    let designation_dir = root.join("blake3");
    fs::create_dir(&designation_dir).unwrap();
    let mut hexes: Vec<String> = (0u8..8).map(|i| hex_of(&[i])).collect();
    for (i, hex) in hexes.iter().enumerate() {
        fs::write(designation_dir.join(hex), b"a file").unwrap();
        fs::write(designation_dir.join(format!(".retired-{hex}-{i}")), b"an aside").unwrap();
        fs::write(designation_dir.join(format!(".upload-{}", &hex[..32])), b"a partial").unwrap();
        fs::create_dir(root.join(format!("d{i}"))).unwrap();
    }
    fs::create_dir(designation_dir.join(hex_of(b"a directory"))).unwrap();
    hexes.sort();
    assert_eq!(store.blobs_of("blake3").unwrap(), hexes, "the files at hex names alone, sorted");
    let asides = store.asides_of("blake3").unwrap();
    assert_eq!(asides.len(), 8, "the asides alone: {asides:?}");
    assert!(asides.windows(2).all(|w| w[0] < w[1]), "sorted: {asides:?}");
    let mut dirs: Vec<String> = (0..8).map(|i| format!("d{i}")).chain(["blake3".to_string()]).collect();
    dirs.sort();
    assert_eq!(store.designations().unwrap(), dirs, "every directory under the root, sorted");
}

/// The size check's read: present with its size, absent as `None`, and a
/// name that is no hex — a partial's, a path's — as absent too. And the
/// name check it reads through: a path is answered for well-formed names
/// alone, so no name a caller hands in reaches past its designation
/// directory.
#[test]
fn blob_size_answers_the_files_size_and_nothing_for_a_name_that_is_no_hex() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    let fin = put_whole(&store, "k", b"12345", 1);
    assert_eq!(store.blob_size("blake3", &fin.hex).unwrap(), Some(5));
    assert_eq!(store.blob_size("blake3", &hex_of(b"other")).unwrap(), None);
    assert_eq!(store.blob_size("blake3", "../leases.log").unwrap(), None);
    assert_eq!(store.blob_size("blake3", "ABCDEF").unwrap(), None, "uppercase is no hex here");
    assert_eq!(store.blob_size("BLAKE3", &fin.hex).unwrap(), None, "a designation is lowercase");
    assert_eq!(store.blob_size("blake3", ".upload-00000000000000000000000000000000").unwrap(), None);
    assert_eq!(store.blob_path("blake3", &fin.hex), Some(root.join("blake3").join(&fin.hex)));
    assert_eq!(store.blob_path("blake3", "../leases.log"), None, "no path out of the directory");
    assert_eq!(store.blob_path("BLAKE3", &fin.hex), None);
    assert_eq!(store.blob_path("..", &fin.hex), None);
}

/// AN UNREADABLE SIZE IS A FAILURE, NEVER AN ABSENCE (`Store::blob_size`:
/// "An I/O failure is no absence"; M-I5 (c), the deposit record exact of
/// what is on disk): a file whose name cannot be read — its designation
/// directory listed but not searched — answers the failure, where an
/// absence would tell the binding and the deposit read the deposit is gone;
/// readable again, the same file answers its size.
#[cfg(unix)]
#[test]
fn an_unreadable_size_is_a_failure_never_an_absence() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    let fin = put_whole(&store, "k", b"12345", 1);
    let designation_dir = root.join("blake3");
    let mode = fs::metadata(&designation_dir).unwrap().permissions();
    // Read and written, never searched: no name in it can be stat'ed.
    fs::set_permissions(&designation_dir, fs::Permissions::from_mode(0o600)).unwrap();
    let unreadable = store.blob_size("blake3", &fin.hex).map_err(|e| e.kind());
    fs::set_permissions(&designation_dir, mode).unwrap();
    if unreadable == Ok(Some(5)) {
        return; // a privileged process searches any directory: nothing to inject
    }
    assert_eq!(unreadable, Err(io::ErrorKind::PermissionDenied), "the failure answered, never an absence");
    assert_eq!(store.blob_size("blake3", &fin.hex).unwrap(), Some(5), "readable again, the file answers its size");
}

/// Every entry under `at` by its path relative to `at` — a directory as
/// `None`, a file as its bytes — sorted: what "touches nothing" compares.
fn tree(at: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    let mut out = Vec::new();
    let mut dirs = vec![at.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).expect("read_dir") {
            let path = entry.expect("entry").path();
            let rel = path.strip_prefix(at).expect("under at").to_path_buf();
            if path.is_dir() {
                out.push((rel, None));
                dirs.push(path);
            } else {
                out.push((rel, Some(fs::read(&path).expect("read"))));
            }
        }
    }
    out.sort();
    out
}

/// THE STORE CHECKS EVERY NAME IT IS HANDED (`Store`: "a malformed one is
/// answered as absent by every read and act … and refused as
/// `InvalidInput` by `create_upload`"): over families of malformed names —
/// escapes that reach a file that stands, the wrong case, each length just
/// past its bound, a partial's, a blob's and near-aside spellings where an
/// aside's belongs — every entry point answers absent and nothing under the
/// root or beside it is touched; the names AT each bound are well-formed.
#[test]
fn every_entry_point_answers_a_malformed_name_as_absent_and_touches_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    let blob = put_whole(&store, "k", b"a blob an escape could reach", 1).hex;
    let replaced = hex_of(b"a replaced blob");
    store.install("blake3", &replaced, b"its wrong bytes").unwrap();
    put_whole(&store, "k", b"a replaced blob", 2);
    let aside = store.asides_of("blake3").unwrap().pop().expect("the replace's aside, queued");
    let partial = format!(".upload-{}", standing(&store, "k", 100, b"part", 3).id.to_hex());
    let long_count = format!(".retired-{replaced}-{}", "9".repeat(21));
    fs::write(root.join("blake3").join(&long_count), b"no aside's").unwrap();
    let before = tree(dir.path());
    let designations = ["", ".", "..", "../blobs/blake3", "blake3/.", "BLAKE3", "blake_3", "blåke3"]
        .map(String::from)
        .into_iter()
        .chain(["a".repeat(33)]);
    for d in designations {
        assert_eq!(store.blob_path(&d, &blob), None, "{d:?}");
        assert!(matches!(store.blob_size(&d, &blob), Ok(None)), "{d:?}");
        assert!(matches!(store.blobs_of(&d).as_deref(), Ok([])), "{d:?}: listed");
        assert!(matches!(store.asides_of(&d).as_deref(), Ok([])), "{d:?}: listed");
        assert!(matches!(store.unlink_blob(&d, &blob), Ok(false)), "{d:?}: unlinked");
        assert!(matches!(store.remove_aside(&d, &aside), Ok(false)), "{d:?}: removed");
        let created = store.create_upload("k", &d, 1, INTERVAL, 4).map(|r| r.id).map_err(|e| e.kind());
        assert_eq!(created, Err(io::ErrorKind::InvalidInput), "{d:?}: created");
    }
    let hexes = ["", "a", "abc", "gg", "..", "../leases.log", "../uploads.log"].map(String::from).into_iter().chain([
        blob.to_uppercase(),
        blob[..63].to_string(),
        format!("{blob}/"),
        "a".repeat(129),
        "a".repeat(130),
        partial.clone(),
        aside.clone(),
    ]);
    for h in hexes {
        assert_eq!(store.blob_path("blake3", &h), None, "{h:?}");
        assert!(matches!(store.blob_size("blake3", &h), Ok(None)), "{h:?}");
        assert!(matches!(store.unlink_blob("blake3", &h), Ok(false)), "{h:?}: unlinked");
    }
    let near_asides = [
        ".retired-x".to_string(),
        format!("{aside}/../{aside}"),
        long_count,
        blob.clone(),
        partial,
        format!(".retired-{}-0", replaced.to_uppercase()),
    ];
    for name in near_asides {
        assert!(matches!(store.remove_aside("blake3", &name), Ok(false)), "{name:?}: removed");
    }
    assert_eq!(tree(dir.path()), before, "no malformed name touched a file, under the root or beside it");
    for (d, h) in [("a".repeat(32), "ab".to_string()), ("-".to_string(), "a".repeat(128))] {
        assert_eq!(store.blob_path(&d, &h), Some(root.join(&d).join(&h)), "{d:?}/{h:?}: well-formed at its bound");
    }
}

/// A KEY NAMES THE FUNCTION THAT MADE IT (`media.md` §The design, item 4,
/// "EVERY SIDECAR KEY NAMES ITS FUNCTION"; `Store::create_upload`): the
/// store computes one hash, BLAKE3's, under one designation, `blake3`, so a
/// creation under any other — however well spelled — is refused as
/// `InvalidInput` before anything is minted, nothing under the root touched;
/// the one it computes is admitted.
#[test]
fn a_creation_under_another_hashs_designation_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let before = tree(dir.path());
    for d in ["sha256-tree", "sha256", "blake3-xof"] {
        let created = store.create_upload("k", d, 1, INTERVAL, 1).map(|r| r.id).map_err(|e| e.kind());
        assert_eq!(created, Err(io::ErrorKind::InvalidInput), "{d}");
    }
    assert_eq!(tree(dir.path()), before, "no directory, partial or record line made");
    assert!(store.create_upload("k", "blake3", 1, INTERVAL, 1).is_ok());
}

/// THE FLOOR's ONE READ OF THE HOST: the space available on the volume at
/// the root, in whole fragments — more than nothing, and short of the
/// volume's size, part of which the files this test made already use.
#[test]
fn free_space_reads_the_space_available_never_the_volumes_size() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    let free = store.free_space().expect("statvfs");
    let volume = rustix::fs::statvfs(&root).expect("statvfs");
    let size = volume.f_blocks.saturating_mul(volume.f_frsize);
    assert!(0 < free && free < size, "{free} bytes free of a {size}-byte volume, which this test's files already use");
    assert_eq!(free % volume.f_frsize, 0, "{free}: whole {}-byte fragments", volume.f_frsize);
}
