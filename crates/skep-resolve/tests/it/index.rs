//! THE INDEX from the fixture (REG-3.21 to REG-3.26; REG-2.8 to REG-2.11,
//! REG-2.24; REG-1.10, REG-1.11; rm-2): the verified bindings and endpoints
//! the fixture board holds, the two tampered records suppressed by cause,
//! the rebuild from the copy with no wire read, the realm checked at the
//! base (REG-3.42), and the hint's one line (REG-3.2).

use skep_identity::Fingerprint;
use skep_resolve::{Cause, Mirror, MirrorError, Opened, Refusal, RootHint, Verdict};

use crate::{addr, fixture, open_fixture_mirror, replay_dial};

/// Every binding and endpoint the board committed is in the index SIGNED,
/// but the two the seam tampered: 1.4's (UNSIGNED, its `sig` zeroed) and
/// 1.14's (MALFORMED, its body spaced), each counted by its cause and
/// consulted at no resolve.
#[test]
fn the_index_holds_the_verified_records_and_suppresses_the_tampered() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, mirror) = open_fixture_mirror(dir.path());
    let index = mirror.index();
    let counts = index.counts();
    assert_eq!(counts.prefixes, 12, "fourteen orgs less the two suppressed: {counts:?}");
    assert_eq!(counts.bindings, 16, "twelve allocations, 1.5's retirement, 1.6's three later bindings: {counts:?}");
    assert_eq!(counts.honored_bindings, 14, "the allocations, the retirement and the restoration: {counts:?}");
    assert_eq!(counts.endpoints, 16, "{counts:?}");
    assert_eq!(counts.honored_endpoints, 15, "1.2's third deposit names a stale state: {counts:?}");
    assert!(index.bindings().all(|b| matches!(b.verdict, Verdict::Signed(_))));
    assert!(index.all_endpoints().all(|e| matches!(e.verdict, Verdict::Signed(_))));
    assert_eq!(index.suppressed.len(), 2, "{:?}", index.suppressed);
    assert!(index.suppressed.iter().any(|s| s.cause == Cause::Unsigned), "{:?}", index.suppressed);
    assert!(
        index.suppressed.iter().any(|s| matches!(s.cause, Cause::Malformed(skep_registry::Refusal::NotCanonical))),
        "{:?}",
        index.suppressed
    );
    assert!(index.standing(&addr(&fixture.tampered_unsigned)).is_none());
    assert!(index.standing(&addr(&fixture.tampered_malformed)).is_none());
    let stats = mirror.stats();
    assert!(stats.rows > 0 && stats.pages > 0 && stats.reads.total() > 0);
    assert_eq!(stats.records, 34, "eighteen binding bodies and sixteen endpoint bodies read, the two tampered among them: {stats:?}");
}

/// THE REBUILD (REG-3.25; R5 (h)): the index rebuilt from the copy alone —
/// no board dialed, every fetch served from the cache — equals the live
/// one, standing for standing and deposit for deposit; and the copy re-opened
/// against the source is checked and RESUMED (REG-3.18).
#[test]
fn the_rebuild_from_the_copy_reads_no_wire_and_equals_the_live_index() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, live) = open_fixture_mirror(dir.path());
    let rows = live.stats().rows;
    let offline = Mirror::rebuild_offline(&fixture.hint, dir.path()).expect("rebuilt from the copy");
    assert_eq!(offline.stats().reads.total(), 0, "no wire read");
    assert_eq!(offline.head(), live.head());
    for prefix in live.index().prefixes() {
        assert_eq!(offline.index().standing(prefix), live.index().standing(prefix), "{prefix}");
    }
    assert_eq!(offline.index().counts(), live.index().counts());
    assert_eq!(offline.index().suppressed, live.index().suppressed);
    drop(live);
    let dial = replay_dial(fixture.clone());
    let resumed = Mirror::open(&fixture.hint, dir.path(), &dial).expect("resumed");
    assert_eq!(*resumed.opened(), Opened::Resumed { checked_rows: rows });
    assert_eq!(resumed.index().counts(), offline.index().counts());
}

/// REG-3.42, REG-3.19: a hint naming another realm than the root's genesis
/// set is refused at the base, the two realms named, and no copy is written.
#[test]
fn a_hint_naming_another_realm_is_refused_at_the_base() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = fixture();
    let other = Fingerprint::parse_hex(&"11".repeat(32)).unwrap();
    let hint = RootHint::new(fixture.hint.origins.clone(), other, None).unwrap();
    let dial = replay_dial(fixture.clone());
    let refused = Mirror::open(&hint, dir.path(), &dial).err();
    assert_eq!(
        refused,
        Some(MirrorError::Refused(Refusal::RealmMismatch { expected: other, found: fixture.hint.realm }))
    );
    assert!(!dir.path().join(skep_resolve::FEED_COPY).exists());
    assert!(!dir.path().join(skep_resolve::FETCH_CACHE).exists());
}

/// THE REPLAY MATRIX at the resolver (REG-2.9, REG-2.10, REG-2.24; REG-1.10,
/// REG-1.11), over the board's own records: at 1.6 the allocation stands, the
/// double allocation and the stale-state binding are inert, the restoration
/// naming the current state is honored and wins; at 1.5 the retirement is
/// honored; at 1.2 the second deposit is current and the third, naming the
/// first again, is inert; at 1.7 the nullified second deposit leaves the view
/// and the first stands.
#[test]
fn the_replay_matrix_at_the_resolver() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_, mirror) = open_fixture_mirror(dir.path());
    let index = mirror.index();
    let six = index.standing(&addr("1.6")).expect("bound");
    let honored: Vec<bool> = six.history.iter().map(|b| b.record.honored).collect();
    assert_eq!(honored, [true, false, false, true]);
    assert_eq!(six.current, six.history[3], "the later honored binding wins");
    assert_eq!(six.history[1].record.replaces, None, "the double allocation named the empty state");
    assert_eq!(six.history[2].record.replaces, Some(six.history[1].link.clone()), "the stale state named is the inert one's link");
    assert_eq!(six.history[3].record.replaces, Some(six.history[0].link.clone()));
    assert!(six.history.windows(2).all(|w| w[0].position < w[1].position), "journal order");
    let five = index.standing(&addr("1.5")).expect("retired");
    assert_eq!(five.history.len(), 2);
    assert!(five.history.iter().all(|b| b.record.honored));
    assert_eq!(five.current.record.account, None);
    let two = index.endpoints(&skep_identity::doc_1_of(&index.standing(&addr("1.2")).unwrap().current.record.account.clone().unwrap()));
    assert_eq!(two.iter().map(|d| d.record.honored).collect::<Vec<_>>(), [true, true, false]);
    assert_eq!(two[2].record.replaces, Some(two[0].link.clone()), "the third names the first, no longer current");
    let home = two[0].home.clone();
    assert_eq!(index.current_endpoint(&home).map(|d| d.link.clone()), Some(two[1].link.clone()));
    let seven_home = skep_identity::doc_1_of(&index.standing(&addr("1.7")).unwrap().current.record.account.clone().unwrap());
    let seven = index.endpoints(&seven_home);
    assert_eq!(seven.iter().map(|d| (d.record.honored, d.record.nullified)).collect::<Vec<_>>(), [(true, false), (true, true)]);
    assert_eq!(index.current_endpoint(&seven_home).map(|d| d.link.clone()), Some(seven[0].link.clone()), "the one before it stands");
}

/// REG-3.2: the hint the recording was made under reads back from its one
/// line as itself.
#[test]
fn the_hint_line_in_the_fixture_parses_back_to_itself() {
    let fixture = fixture();
    let line = fixture.hint.to_string();
    assert_eq!(RootHint::parse(&line).expect("parses"), fixture.hint);
    assert!(line.contains(" realm:"), "{line}");
    assert_eq!(fixture.hint.fork_point, None, "an unforked lineage");
}
