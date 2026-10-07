//! THE INDEX from the fixture (REG-3.21 to REG-3.26; REG-2.8 to REG-2.11,
//! REG-2.24; REG-1.10, REG-1.11; rm-2): the verified bindings and endpoints
//! the fixture board holds, the two tampered records suppressed by cause,
//! and every record UNDETERMINABLE HERE, never unsigned, where the reader
//! lacks an input; and the replay matrix over the board's own records.

use std::fs;

use skep_resolve::{Cause, Mirror, Verdict, FETCH_CACHE};

use crate::{addr, open_fixture_mirror};

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
    assert_eq!(index.suppressed().len(), 2, "{:?}", index.suppressed());
    assert!(index.suppressed().iter().any(|s| s.cause == Cause::Verdict(Verdict::Unsigned)), "{:?}", index.suppressed());
    assert!(
        index
            .suppressed()
            .iter()
            .any(|s| matches!(s.cause, Cause::Malformed(skep_registry::ParseRefusal::NotCanonical))),
        "{:?}",
        index.suppressed()
    );
    assert!(index.standing(&addr(&fixture.tampered_unsigned)).is_none());
    assert!(index.standing(&addr(&fixture.tampered_malformed)).is_none());
    let stats = mirror.stats();
    assert!(stats.rows > 0 && stats.pages > 0 && stats.reads.total() > 0);
    assert_eq!(stats.records, 34, "eighteen binding bodies and sixteen endpoint bodies read, the two tampered among them: {stats:?}");
}

/// A READER MISSING AN INPUT judges no record UNSIGNED (REG-1.86 (e): the
/// verdict is manufactured from no missing input): rebuilt from a copy whose
/// cache lacks every key table, or the board term, or every record's bytes,
/// each record the fold reaches is UNDETERMINABLE HERE — 1.4's zeroed `sig`
/// among them, a signature this reader cannot check — and none UNSIGNED;
/// 1.14's spaced body, where its bytes are held, is no record at all and
/// MALFORMED, as it is to every reader; and nothing enters the index.
#[test]
fn a_reader_missing_an_input_judges_undeterminable_here_never_unsigned() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, mirror) = open_fixture_mirror(dir.path());
    drop(mirror);
    let cache = fs::read_to_string(dir.path().join(FETCH_CACHE)).expect("the fetch cache");
    for (missing, malformed, undeterminable) in [(r#"{"keys":"#, 1, 33), (r#"{"board":"#, 1, 33), (r#"{"atom":"#, 0, 34)] {
        let without: String = cache.lines().filter(|l| !l.starts_with(missing)).map(|l| format!("{l}\n")).collect();
        assert_ne!(without, cache, "the cache holds {missing}");
        fs::write(dir.path().join(FETCH_CACHE), &without).expect("the cache without them");
        let offline = Mirror::rebuild_offline(&fixture.hint, dir.path()).expect("rebuilt");
        let c = offline.index().counts();
        let suppressed = (c.suppressed_unsigned, c.suppressed_malformed, c.suppressed_undeterminable);
        assert_eq!(suppressed, (0, malformed, undeterminable), "without {missing}: {c:?}");
        assert_eq!((c.bindings, c.endpoints), (0, 0), "without {missing}");
    }
}

/// THE REPLAY MATRIX at the resolver (REG-2.9, REG-2.10, REG-2.24; REG-1.10,
/// REG-1.11), over the board's own records: at 1.6 the allocation stands, the
/// double allocation and the stale-state binding are inert, the restoration
/// naming the current state is honored and wins; at 1.5 the retirement is
/// honored; at 1.2 the second deposit is current and the third, naming the
/// first again, is inert; at 1.7 the nullified second deposit leaves the view
/// and the first stands.
#[test]
fn the_replay_matrix_holds_over_the_boards_own_records() {
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
