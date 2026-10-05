//! THE LEASE LOG on the honest-null arm (M-I5 (c); `media.md` Op inventory
//! 1, "EACH KEY's CURRENT RECORD IS ITS LATEST, AND OPEN COMPACTS BOTH
//! STORES"): the three states and the horizon, read off the record alone,
//! a principal's live leases in hex order, the latest-wins re-PUT, the
//! compaction at open, the pending bytes — an upload expired and not yet
//! removed counted by nothing — the pruner's read of whether any principal
//! holds a file live, the torn tail, and a line naming a malformed
//! designation or hex, or lacking any member, read as no lease. "A LIVE
//! LEASE OVER A FILE THAT IS NOT THERE READS AS LAPSED" is the daemon's
//! rule, built on this store's `lease_state` and `blob_size`; the store's
//! lease state answers the record and nothing of the file.

use std::fs;
use std::time::Duration;

use skep_blobs::{HashFunction, LeaseState};

use crate::{every_deposit_unplaced, hex_of, open, put_whole, HORIZON_MS, INTERVAL, INTERVAL_MS};

/// LIVE within the interval, LAPSED past it within the HORIZON (its expiry
/// named), NONE past the horizon — and NONE for another principal at every
/// moment, whatever the directory holds. Each answer is the record's: a
/// live lease whose file is gone still answers LIVE.
#[test]
fn a_lease_is_live_then_lapsed_within_the_horizon_then_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let fin = put_whole(&store, "k", b"bytes", 100);
    let expires = 100 + INTERVAL_MS;
    assert_eq!(store.lease_state("k", "blake3", &fin.hex, 100), LeaseState::Live { size: 5, expires });
    assert_eq!(store.lease_state("k", "blake3", &fin.hex, expires - 1), LeaseState::Live { size: 5, expires });
    assert_eq!(store.lease_state("k", "blake3", &fin.hex, expires), LeaseState::Lapsed { expires });
    assert_eq!(store.lease_state("k", "blake3", &fin.hex, expires + HORIZON_MS - 1), LeaseState::Lapsed { expires });
    assert_eq!(store.lease_state("k", "blake3", &fin.hex, expires + HORIZON_MS), LeaseState::None);
    for now in [100, expires, expires + HORIZON_MS] {
        assert_eq!(store.lease_state("other", "blake3", &fin.hex, now), LeaseState::None);
        assert_eq!(store.lease_state("k", "sha256-tree", &fin.hex, now), LeaseState::None, "the designation is part of the lease's key");
    }
    let live = store.live_leases_of("k", 100);
    assert_eq!(live.len(), 1);
    let l = &live[0];
    assert_eq!(
        (l.principal.as_str(), l.designation.as_str(), l.hex.as_str(), l.size, l.expires),
        ("k", "blake3", fin.hex.as_str(), 5, expires)
    );
    assert_eq!(store.live_leases_of("k", expires), vec![], "the deposit read lists live leases alone");
    fs::remove_file(store.blob_path("blake3", &fin.hex).unwrap()).unwrap();
    assert_eq!(
        store.lease_state("k", "blake3", &fin.hex, 100),
        LeaseState::Live { size: 5, expires },
        "read off the record alone"
    );
}

/// A PRINCIPAL's LIVE LEASES LIST IN HEX ORDER (`Store::live_leases_of`, the
/// deposit read's list): eight deposits come back sorted by hex — eight in
/// a random order fall sorted once in 40,320.
#[test]
fn a_principals_live_leases_list_in_hex_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let mut hexes: Vec<String> = (0u8..8).map(|i| put_whole(&store, "k", &[i; 3], 1).hex).collect();
    hexes.sort();
    let listed: Vec<String> = store.live_leases_of("k", 2).into_iter().map(|l| l.hex).collect();
    assert_eq!(listed, hexes);
}

/// A re-PUT's lease REPLACES the one before whatever either's expiry: the
/// principal's current lease on a hash is its LATEST line there — a
/// shortened interval after a longer one answers the shorter; and open
/// compacts the log to the latest line of each, dropping every lease past
/// the horizon.
#[test]
fn the_latest_lease_wins_and_open_compacts_to_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let hex = hex_of(b"same bytes");
    {
        let store = open(&root, 0);
        let fin = put_whole(&store, "k", b"same bytes", 1_000);
        assert_eq!(fin.hex, hex);
        // The same bytes again with an EARLIER expiry — an interval of
        // nothing: the later line wins.
        let rec = store.create_upload("k", HashFunction::Blake3, 10, INTERVAL, 2_000).unwrap();
        let mut stream = store.resume("k", &rec.id, 0, 2_000).unwrap();
        stream.append(b"same bytes", 2_000).unwrap();
        stream.finish(Duration::ZERO, 2_000).unwrap();
        assert_eq!(store.lease_state("k", "blake3", &hex, 2_001), LeaseState::Lapsed { expires: 2_000 });
        // And a third time, the latest line again: live once more.
        put_whole(&store, "k", b"same bytes", 3_000);
        assert_eq!(store.lease_state("k", "blake3", &hex, 3_001), LeaseState::Live { size: 10, expires: 3_000 + INTERVAL_MS });
        // Another principal's lease on other bytes, long gone by the reopen
        // below.
        put_whole(&store, "j", b"old", 10);
        let lines = fs::read_to_string(root.join("leases.log")).unwrap().lines().count();
        assert_eq!(lines, 4, "four appends, one per finish");
    }
    // Reopened past `j`'s horizon but inside `k`'s latest: compacted to one
    // line, k's, which answers LAPSED off that line.
    let now = 10 + INTERVAL_MS + HORIZON_MS;
    let store = open(&root, now);
    let lines = fs::read_to_string(root.join("leases.log")).unwrap().lines().count();
    assert_eq!(lines, 1, "compacted: k's latest line alone");
    assert_eq!(store.lease_state("j", "blake3", &hex_of(b"old"), now), LeaseState::None);
    assert_eq!(store.lease_state("k", "blake3", &hex, now), LeaseState::Lapsed { expires: 3_000 + INTERVAL_MS });
}

/// THE PENDING BYTES (M-I6 (b)): a principal's unplaced deposits' sizes
/// plus its standing uploads' durable offsets, falling to nothing as its
/// leases lapse and its upload expires — an expired upload counted by
/// nothing, though no pass has removed it yet; the venue total the sum over
/// every principal, never the directory's bytes — one file two principals
/// both leased counts twice there and once in each principal's own. And a
/// placed deposit — a lease on a hash its principal's own cells name, which
/// its base counts — is no pending byte; the partials count whole either
/// way.
#[test]
fn pending_bytes_are_record_derived_per_principal_and_in_total() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    put_whole(&store, "a", b"shared", 10);
    put_whole(&store, "b", b"shared", 10);
    put_whole(&store, "a", b"a's own", 10);
    crate::standing(&store, "b", 100, b"partial", 10);
    assert_eq!(store.pending_bytes("a", 11, every_deposit_unplaced), 6 + 7);
    assert_eq!(store.pending_bytes("b", 11, every_deposit_unplaced), 6 + 7);
    assert_eq!(
        store.pending_total(11, every_deposit_unplaced),
        6 + 7 + 6 + 7,
        "the sum of own scopes, the shared file counted in each"
    );
    assert_eq!(store.pending_bytes("c", 11, every_deposit_unplaced), 0);
    let shared = hex_of(b"shared");
    // Both principals' cells name the shared file: placed, in their bases.
    let unplaced = |l: &skep_blobs::Lease| l.hex != shared;
    assert_eq!(store.pending_bytes("a", 11, &unplaced), 7, "a's own lease alone");
    assert_eq!(store.pending_bytes("b", 11, &unplaced), 7, "b's partial alone, counted whole");
    assert_eq!(store.pending_total(11, &unplaced), 7 + 7);
    let lapsed = 10 + INTERVAL_MS;
    assert_eq!(store.pending_bytes("a", lapsed, every_deposit_unplaced), 0, "lapsed leases count nothing");
    assert_eq!(
        store.pending_bytes("b", lapsed, every_deposit_unplaced),
        0,
        "b's lapsed lease nothing, nor its upload, expired and not yet removed"
    );
    assert_eq!(store.pending_total(lapsed, every_deposit_unplaced), 0, "and an expired upload neither");
}

/// THE ANY-PRINCIPAL READ (the pruner's; M-I5 (b) at its strictest): a
/// file is held while ANY principal's lease on it is live — whoever
/// deposited it — and not once every lease has lapsed; a lapsed lease
/// within the horizon holds nothing here, though it answers LAPSED to its
/// own principal; the designation is part of the lease's key.
#[test]
fn any_live_lease_answers_for_every_principal_together() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let fin = put_whole(&store, "a", b"shared", 100);
    put_whole(&store, "b", b"shared", 200);
    assert!(store.any_live_lease("blake3", &fin.hex, 150));
    let a_lapsed = 100 + INTERVAL_MS;
    assert!(store.any_live_lease("blake3", &fin.hex, a_lapsed), "b's lease still holds it");
    assert_eq!(store.lease_state("a", "blake3", &fin.hex, a_lapsed), LeaseState::Lapsed { expires: a_lapsed });
    let both_lapsed = 200 + INTERVAL_MS;
    assert!(!store.any_live_lease("blake3", &fin.hex, both_lapsed), "every lease lapsed: held by no principal");
    assert!(!store.any_live_lease("sha256-tree", &fin.hex, 150), "the designation is part of the lease's key");
    assert!(!store.any_live_lease("blake3", &hex_of(b"never"), 150));
}

/// A torn tail of the lease log is truncated at open — a half-written
/// lease line reads as NO lease, the cure a re-PUT — and the lines before
/// it stand.
#[test]
fn a_torn_lease_tail_reads_as_no_lease() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let hex = {
        let store = open(&root, 0);
        put_whole(&store, "k", b"whole", 1).hex
    };
    let log = root.join("leases.log");
    let whole = fs::read_to_string(&log).unwrap();
    fs::write(&log, format!("{whole}{{\"designation\":\"blake3\",\"expires\":9999,\"hex\":\"{}\",\"key\":\"k\",\"si", hex_of(b"torn"))).unwrap();
    let store = open(&root, 2);
    assert_eq!(store.lease_state("k", "blake3", &hex_of(b"torn"), 2), LeaseState::None);
    assert!(matches!(store.lease_state("k", "blake3", &hex, 2), LeaseState::Live { size: 5, .. }));
    assert!(fs::read_to_string(&log).unwrap().ends_with('\n'));
}

/// A LEASE LINE NAMING A MALFORMED NAME IS NO LEASE (`Store`: "THE STORE
/// CHECKS EVERY NAME IT IS HANDED", a log's names at open as a caller's): a
/// log restored from elsewhere is read through the name check a caller's
/// names meet, so a line whose designation or hex the check refuses — an
/// escape above the root or to an absolute path, the wrong case, a name that
/// is no hex — reads as a lost lease does: NONE to its principal, live for no
/// principal, among no deposits, in no pending byte. The same line naming a
/// well-formed designation and hex stands, and the compaction keeps it alone.
#[test]
fn a_lease_line_naming_a_malformed_name_is_no_lease() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    fs::create_dir_all(&root).unwrap();
    let hex = hex_of(b"a deposit");
    let malformed = [
        ("blake3".to_string(), "../../x".to_string()),
        ("blake3".to_string(), hex.to_uppercase()),
        ("blake3".to_string(), format!("{hex}/")),
        ("blake3".to_string(), format!(".retired-{hex}-0")),
        ("..".to_string(), hex.clone()),
        ("BLAKE3".to_string(), hex.clone()),
        ("blake3/..".to_string(), hex.clone()),
        (dir.path().to_str().expect("a UTF-8 tempdir").to_string(), hex.clone()),
    ];
    let line = |designation: &str, hex: &str| {
        let v = serde_json::json!({"designation": designation, "expires": 9_999, "hex": hex, "key": "k", "size": 7});
        format!("{v}\n")
    };
    let log: String = malformed.iter().map(|(d, h)| line(d, h)).chain([line("blake3", &hex)]).collect();
    fs::write(root.join("leases.log"), log).unwrap();
    let store = open(&root, 1);
    for (d, h) in &malformed {
        assert_eq!(store.lease_state("k", d, h, 1), LeaseState::None, "{d:?}/{h:?}");
        assert!(!store.any_live_lease(d, h, 1), "{d:?}/{h:?}: live for no principal");
    }
    let listed: Vec<(String, String)> =
        store.live_leases_of("k", 1).into_iter().map(|l| (l.designation, l.hex)).collect();
    assert_eq!(listed, vec![("blake3".to_string(), hex.clone())], "the well-formed line's lease alone");
    assert_eq!(store.pending_bytes("k", 1, every_deposit_unplaced), 7, "its size alone");
    assert_eq!(fs::read_to_string(root.join("leases.log")).unwrap().lines().count(), 1, "compacted to it");
}

/// A LEASE LINE LACKING ANY MEMBER IS NO LEASE (`Lease::parse`: `None` "for a
/// value of no shape this build reads: a member missing"): the store holds
/// no value of its own for a member a line lacks, so for each member in
/// turn, a line lacking it — a log restored from elsewhere — reads as a lost
/// lease does: live for no principal and kept by no compaction, while the
/// whole line stands alone.
#[test]
fn a_lease_line_lacking_any_member_is_no_lease() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    fs::create_dir_all(&root).unwrap();
    let members = ["designation", "expires", "hex", "key", "size"];
    let hex_n = |n: usize| hex_of(&[n as u8]);
    let line = |hex: &str, lacking: Option<&str>| {
        let mut v = serde_json::json!({"designation": "blake3", "expires": 9_999, "hex": hex, "key": "k", "size": 7});
        if let Some(member) = lacking {
            v.as_object_mut().expect("a lease line is an object").remove(member);
        }
        format!("{v}\n")
    };
    let whole = hex_n(members.len());
    let log: String =
        members.iter().enumerate().map(|(n, &m)| line(&hex_n(n), Some(m))).chain([line(&whole, None)]).collect();
    fs::write(root.join("leases.log"), log).unwrap();
    let store = open(&root, 1);
    for (n, member) in members.iter().enumerate() {
        assert!(!store.any_live_lease("blake3", &hex_n(n), 1), "lacking {member}: live for no principal");
    }
    let listed: Vec<String> = store.live_leases_of("k", 1).into_iter().map(|l| l.hex).collect();
    assert_eq!(listed, vec![whole], "the whole line's lease alone");
    assert_eq!(fs::read_to_string(root.join("leases.log")).unwrap().lines().count(), 1, "compacted to it");
}
