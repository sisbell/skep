//! THE LEASE LOG on the honest-null arm (M-I5 (c); `media.md` Op inventory
//! 1, "EACH KEY's CURRENT RECORD IS ITS LATEST, AND OPEN COMPACTS BOTH
//! STORES"; "A LIVE LEASE OVER A FILE THAT IS NOT THERE READS AS LAPSED"):
//! the three states and the horizon, the latest-wins re-PUT, the compaction
//! at open, the pending bytes, and the torn tail.

use std::fs;

use skep_blobs::LeaseState;

use crate::{hex_of, open, put_whole, HORIZON, INTERVAL};

/// LIVE within the interval, LAPSED past it within the HORIZON (its expiry
/// named), NONE past the horizon — and NONE for another key at every
/// moment, whatever the directory holds.
#[test]
fn a_lease_is_live_then_lapsed_within_the_horizon_then_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let fin = put_whole(&store, "k", b"bytes", 100);
    let expires = 100 + INTERVAL;
    assert_eq!(store.lease("k", "blake3", &fin.hex, 100), LeaseState::Live { size: 5, expires });
    assert_eq!(store.lease("k", "blake3", &fin.hex, expires - 1), LeaseState::Live { size: 5, expires });
    assert_eq!(store.lease("k", "blake3", &fin.hex, expires), LeaseState::Lapsed { expires });
    assert_eq!(store.lease("k", "blake3", &fin.hex, expires + HORIZON - 1), LeaseState::Lapsed { expires });
    assert_eq!(store.lease("k", "blake3", &fin.hex, expires + HORIZON), LeaseState::None);
    for now in [100, expires, expires + HORIZON] {
        assert_eq!(store.lease("other", "blake3", &fin.hex, now), LeaseState::None);
        assert_eq!(store.lease("k", "sha256-tree", &fin.hex, now), LeaseState::None, "the designation is part of the key");
    }
    assert_eq!(store.leases_of("k", 100), vec![skep_blobs::Lease { key: "k".into(), designation: "blake3".into(), hex: fin.hex.clone(), size: 5, expires }]);
    assert_eq!(store.leases_of("k", expires), vec![], "the deposit read lists live leases alone");
}

/// A re-PUT's lease REPLACES the one before whatever either's expiry: the
/// key's current lease is its LATEST line — a shortened interval after a
/// longer one answers the shorter; and open compacts the log to each key's
/// latest line, dropping every lease past the horizon.
#[test]
fn the_latest_lease_wins_and_open_compacts_to_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let hex = hex_of(b"same bytes");
    {
        let store = open(&root, 0);
        let fin = put_whole(&store, "k", b"same bytes", 1_000);
        assert_eq!(fin.hex, hex);
        // The same bytes again with an EARLIER expiry: the later line wins.
        let rec = store.create_upload("k", "blake3", 10, 2_000 + INTERVAL, None).unwrap();
        store.resume("k", &rec.id, 0, 2_000).unwrap();
        store.append("k", &rec.id, b"same bytes", 2_000, INTERVAL).unwrap();
        store.settle("k", &rec.id, 2_000, INTERVAL).unwrap();
        store.finish("k", &rec.id, 2_000, 500).unwrap();
        assert_eq!(store.lease("k", "blake3", &hex, 2_001), LeaseState::Lapsed { expires: 500 });
        // And a third time, the latest line again: live once more.
        put_whole(&store, "k", b"same bytes", 3_000);
        assert_eq!(store.lease("k", "blake3", &hex, 3_001), LeaseState::Live { size: 10, expires: 3_000 + INTERVAL });
        // Another key's lease on other bytes, long gone by the reopen below.
        put_whole(&store, "j", b"old", 10);
        let lines = fs::read_to_string(root.join("leases.log")).unwrap().lines().count();
        assert_eq!(lines, 4, "four appends, one per finish");
    }
    // Reopened past `j`'s horizon but inside `k`'s latest: compacted to one
    // line, k's, which answers LAPSED off that line.
    let now = 10 + INTERVAL + HORIZON;
    let store = open(&root, now);
    let lines = fs::read_to_string(root.join("leases.log")).unwrap().lines().count();
    assert_eq!(lines, 1, "compacted: k's latest line alone");
    assert_eq!(store.lease("j", "blake3", &hex_of(b"old"), now), LeaseState::None);
    assert_eq!(store.lease("k", "blake3", &hex, now), LeaseState::Lapsed { expires: 3_000 + INTERVAL });
}

/// THE PENDING BYTES (M-I6 (b)): a key's live leases' sizes plus its
/// standing uploads' durable offsets, falling as a lease lapses; the venue
/// total the sum over every key, never the directory's bytes — one file two
/// keys both leased counts twice there and once in each key's own.
#[test]
fn pending_bytes_are_record_derived_per_key_and_in_total() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    put_whole(&store, "a", b"shared", 10);
    put_whole(&store, "b", b"shared", 10);
    put_whole(&store, "a", b"a's own", 10);
    crate::standing(&store, "b", 100, b"partial", 10);
    assert_eq!(store.pending_bytes("a", 11), 6 + 7);
    assert_eq!(store.pending_bytes("b", 11), 6 + 7);
    assert_eq!(store.pending_total(11), 6 + 7 + 6 + 7, "the sum of own scopes, the shared file counted in each");
    assert_eq!(store.pending_bytes("c", 11), 0);
    let lapsed = 10 + INTERVAL;
    assert_eq!(store.pending_bytes("a", lapsed), 0, "lapsed leases count nothing");
    assert_eq!(store.pending_total(lapsed), 0, "and an expired upload neither");
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
    assert_eq!(store.lease("k", "blake3", &hex_of(b"torn"), 2), LeaseState::None);
    assert!(matches!(store.lease("k", "blake3", &hex, 2), LeaseState::Live { size: 5, .. }));
    assert!(fs::read_to_string(&log).unwrap().ends_with('\n'));
}
