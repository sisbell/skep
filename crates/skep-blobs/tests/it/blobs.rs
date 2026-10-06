//! THE FILES (`media.md` §The media stores; M-I5 (c)): the size check's
//! read, a size that cannot be read answered as a failure and never as an
//! absence; the name check at every entry point, and the designation a
//! creation's function files under; a well-formed name with nothing behind
//! it — no directory yet, an aside another remover took, an entry that is
//! no file — absent to every read and act; the directory listings, each
//! naming its own class in name order; and the floor's read of the space
//! available on the volume.

use std::fs;
use std::path::{Path, PathBuf};

use skep_blobs::HashFunction;

use crate::{hex_of, open, put_whole, standing, INTERVAL};

/// THE DIRECTORY LISTINGS NAME EACH CLASS ALONE, IN NAME ORDER
/// (`Store::blobs_of`: "the files at HEX NAMES …, in name order — … a
/// partial or an aside excluded by its name"; `Store::asides_of`: "in name
/// order"; `Store::designation_dirs`: "every directory there, whatever its
/// name, by name, in name order"): beside eight files at hex names stand
/// eight asides, eight partials and a directory at a hex name, and beside
/// `blake3` nine more designation directories, one under a name no
/// designation spells; each listing names its own class alone, sorted — the
/// designation directories every directory under the root, whatever its
/// name — and eight names in a random order fall sorted once in 40,320.
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
    let foreign = "not_a_designation";
    fs::create_dir(root.join(foreign)).unwrap();
    hexes.sort();
    assert_eq!(store.blobs_of("blake3").unwrap(), hexes, "the files at hex names alone, sorted");
    let asides = store.asides_of("blake3").unwrap();
    assert_eq!(asides.len(), 8, "the asides alone: {asides:?}");
    assert!(asides.windows(2).all(|w| w[0] < w[1]), "sorted: {asides:?}");
    let mut dirs: Vec<String> = (0..8).map(|i| format!("d{i}")).chain(["blake3", foreign].map(String::from)).collect();
    dirs.sort();
    assert_eq!(store.designation_dirs().unwrap(), dirs, "every directory under the root, whatever its name, sorted");
}

/// THE PRUNER's RENAME ASIDE (M-I5 (b), (f); `Store::rename_aside`: "the
/// file renamed to an aside name of its own, the REPLACE's own name and
/// serial"): a leased file renamed aside stands under `.retired-<hex>-<n>`
/// and no longer at its hex — absent to the size check, listed among the
/// asides — and is removed after by the pass's own act; a second rename
/// aside of the absent name is `None`, as is one of a malformed name; the
/// renames and a replace's link draw on one rising serial — a rename of an
/// absent name spends one too — so no two asides ever share a name.
#[test]
fn rename_aside_takes_the_name_under_the_replaces_serial_and_the_aside_is_removed_after() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    let first = put_whole(&store, "k", b"the first file", 1);
    let second = put_whole(&store, "k", b"the second file", 1);
    let aside = store.rename_aside("blake3", &first.hex).unwrap().expect("a file went aside");
    assert!(aside.starts_with(&format!(".retired-{}-", first.hex)), "{aside}");
    assert_eq!(store.blob_size("blake3", &first.hex).unwrap(), None, "absent at its hex");
    assert!(root.join("blake3").join(&aside).is_file(), "standing at the aside name");
    assert_eq!(store.asides_of("blake3").unwrap(), vec![aside.clone()]);
    assert_eq!(store.rename_aside("blake3", &first.hex).unwrap(), None, "nothing stands: none");
    assert_eq!(store.rename_aside("blake3", "../leases.log").unwrap(), None, "a malformed name: none");
    assert_eq!(store.rename_aside("BLAKE3", &second.hex).unwrap(), None);
    let other = store.rename_aside("blake3", &second.hex).unwrap().expect("the second file went aside");
    assert_ne!(aside, other, "two serials");
    assert_eq!(store.blobs_of("blake3").unwrap(), Vec::<String>::new(), "both gone from their names");
    // The unlink after, under no arm: the pass's own act.
    assert!(store.remove_aside("blake3", &aside).unwrap());
    assert!(store.remove_aside("blake3", &other).unwrap());
    assert!(store.asides_of("blake3").unwrap().is_empty());
    // A replace's aside draws on the same serial, past every rename's.
    let third = put_whole(&store, "k", b"the third file", 2);
    put_whole(&store, "k", b"the third file", 3);
    let replaced = store.asides_of("blake3").unwrap();
    assert_eq!(replaced.len(), 1, "{replaced:?}");
    assert!(replaced[0].starts_with(&format!(".retired-{}-", third.hex)));
    let serial = |name: &str| name.rsplit('-').next().unwrap().parse::<u64>().unwrap();
    assert_eq!(serial(&aside), 0, "the first rename's serial");
    assert!(serial(&aside) < serial(&other) && serial(&other) < serial(&replaced[0]), "one rising serial: {aside} {other} {}", replaced[0]);
}

/// THE CAPACITY READ (the daemon's default per-account limit's source;
/// `Store::capacity`): the volume's capacity off the same `statvfs` as the
/// floor's free space — a figure, and never below the free space.
#[test]
fn the_capacity_is_the_volumes_and_never_below_its_free_space() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let capacity = store.capacity().expect("statvfs answers");
    let free = store.free_space().expect("statvfs answers");
    assert!(capacity > 0);
    assert!(capacity >= free, "capacity {capacity} below free {free}");
}

/// THE PULL's INSTALL (M-I5 (d); `Store::install_file`: "the bytes of
/// `source` streamed into a temp file … hashed as they are copied … renamed
/// onto `<designation>/<hex>` — REPLACE where a file stands"): a file is
/// installed under its own hash with no record and no lease, the store
/// opened beside answering it as a plain file; a file whose bytes are not
/// the expected hash's is refused, nothing installed and no temp file
/// left; a corrupt file at the name is REPLACED by the install of the
/// right bytes; and an absent source is the file's own error.
#[test]
fn install_file_installs_by_the_puts_order_replaces_and_refuses_another_hash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let bytes = b"the picture's bytes, restored".to_vec();
    let hex = hex_of(&bytes);
    let source = dir.path().join("source");
    fs::write(&source, &bytes).unwrap();
    let partials = |root: &Path| -> usize {
        fs::read_dir(root.join("blake3")).map(|d| d.filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with(".upload-")).count()).unwrap_or(0)
    };
    let fin = skep_blobs::Store::install_file(&root, HashFunction::Blake3, &source, None).unwrap();
    assert_eq!((fin.designation.as_str(), fin.hex.as_str(), fin.size), ("blake3", hex.as_str(), bytes.len() as u64));
    assert_eq!(fs::read(root.join("blake3").join(&hex)).unwrap(), bytes);
    assert_eq!(partials(&root), 0, "no temp file left");
    let wrong = hex_of(b"other bytes");
    let err = skep_blobs::Store::install_file(&root, HashFunction::Blake3, &source, Some(&wrong)).expect_err("refused");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
    assert!(err.to_string().contains(&wrong) && err.to_string().contains(&hex), "{err}");
    assert_eq!(partials(&root), 0, "nothing left behind");
    assert!(skep_blobs::Store::install_file(&root, HashFunction::Blake3, dir.path().join("absent"), None).is_err());
    let store = open(&root, 0);
    assert_eq!(store.blob_size("blake3", &hex).unwrap(), Some(bytes.len() as u64), "a plain file to the store");
    assert_eq!(store.lease_state("k", "blake3", &hex, 0), skep_blobs::LeaseState::None, "no lease");
    assert!(store.uploads_of("k", 0).is_empty(), "no record");
    store.install("blake3", &hex, b"corrupt bytes under the right name").unwrap();
    let fin = skep_blobs::Store::install_file(&root, HashFunction::Blake3, &source, Some(&hex)).unwrap();
    assert_eq!(fin.hex, hex);
    assert_eq!(fs::read(root.join("blake3").join(&hex)).unwrap(), bytes, "replaced");
    assert_eq!(partials(&root), 0);
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
    assert_eq!(unreadable, Err(std::io::ErrorKind::PermissionDenied), "the failure answered, never an absence");
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
/// answered as absent by every read and act" — `create_upload` takes no
/// name): over families of malformed names — escapes that reach a file that
/// stands, the wrong case, each length just past its bound, a partial's, a
/// blob's and near-aside spellings where an aside's belongs — every entry
/// point answers absent and nothing under the root or beside it is touched;
/// the names AT each bound are well-formed.
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

/// A WELL-FORMED NAME WITH NOTHING BEHIND IT IS ABSENT TO EVERY READ AND ACT
/// (`Store::blobs_of`: "An absent directory holds none"; `Store::remove_aside`:
/// "`Ok(false)` where none stood"; `Store::blob_size`: `Ok(None)` for "no
/// entry, an entry that is no file"; `blobs::remove_if_present`: "a name
/// another remover took first … leaves nothing to do"): on a fresh store,
/// whose designation directory no upload has made — the pruner's pass reads
/// the pinned designation all the same — every listing is empty and every
/// act finds nothing; once the deferred unlink has taken a replace's aside,
/// the pass's own removal of it finds none and says so; and a directory
/// standing at a hex name is no file to the size check.
#[test]
fn a_well_formed_name_with_nothing_behind_it_is_absent_to_every_read_and_act() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    let bytes = b"the picture's bytes";
    let hex = hex_of(bytes);
    assert!(!root.join("blake3").exists(), "no upload has made the designation directory");
    assert_eq!(store.blobs_of("blake3").unwrap(), Vec::<String>::new(), "no directory: no blob");
    assert_eq!(store.asides_of("blake3").unwrap(), Vec::<String>::new(), "no directory: no aside");
    assert_eq!(store.blob_size("blake3", &hex).unwrap(), None, "no directory: no size");
    assert!(!store.unlink_blob("blake3", &hex).unwrap(), "no directory: nothing to unlink");
    assert!(!store.remove_aside("blake3", &format!(".retired-{hex}-0")).unwrap(), "no directory: no aside");
    store.install("blake3", &hex, b"garbage under the right name").unwrap();
    put_whole(&store, "k", bytes, 1);
    let aside = store.asides_of("blake3").unwrap().pop().expect("the replace's aside");
    assert_eq!(store.unlink_asides().unwrap(), 1, "the deferred unlink takes it first");
    assert!(!store.remove_aside("blake3", &aside).unwrap(), "the pass's removal finds none, and says so");
    let not_a_file = hex_of(b"a directory at a hex name");
    fs::create_dir(root.join("blake3").join(&not_a_file)).unwrap();
    assert_eq!(store.blob_size("blake3", &not_a_file).unwrap(), None, "an entry that is no file is no blob");
}

/// A KEY NAMES THE FUNCTION THAT MADE IT (`media.md` §The design, item 4,
/// "EVERY SIDECAR KEY NAMES ITS FUNCTION"; `Store::create_upload`): a
/// creation names a function the store computes — a `HashFunction`, so no
/// other can be spelled — and is filed under its designation, `blake3`: the
/// record, the partial's directory and the finish's answer all name it.
#[test]
fn a_creation_is_filed_under_its_functions_designation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    let rec = store.create_upload("k", HashFunction::Blake3, 5, INTERVAL, 1).unwrap();
    assert_eq!(rec.designation, HashFunction::Blake3.designation());
    assert_eq!(rec.designation, "blake3", "the cell schema's own");
    assert!(root.join("blake3").join(format!(".upload-{}", rec.id)).is_file(), "its partial in that directory");
    let mut stream = store.resume("k", &rec.id, 0, 1).unwrap();
    stream.append(b"bytes", 1).unwrap();
    assert_eq!(stream.finish(INTERVAL, 1).unwrap().designation, "blake3", "and the finish answers it");
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
