//! THE INDEX from the fixture (REG-3.21 to REG-3.26; REG-2.8 to REG-2.11,
//! REG-2.24; REG-1.10, REG-1.11; rm-2): the verified bindings and endpoints
//! the fixture board holds, the two tampered records suppressed by cause,
//! the rebuild from the copy with no wire read, the realm checked at the
//! base under a fresh base and a held copy alike (REG-3.42), the copy's two
//! files — begun together, read back by their format, written once per
//! value — and the hint's one line (REG-3.2).

use std::fs;

use serde_json::json;
use skep_identity::Fingerprint;
use skep_resolve::{Cause, Mirror, MirrorError, Opened, RealmId, Refusal, RootHint, Verdict, FEED_COPY, FETCH_CACHE};
use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

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
    assert_eq!(index.suppressed().len(), 2, "{:?}", index.suppressed());
    assert!(index.suppressed().iter().any(|s| s.cause == Cause::Verdict(Verdict::Unsigned)), "{:?}", index.suppressed());
    assert!(
        index.suppressed().iter().any(|s| matches!(s.cause, Cause::Malformed(skep_registry::Refusal::NotCanonical))),
        "{:?}",
        index.suppressed()
    );
    assert!(index.standing(&addr(&fixture.tampered_unsigned)).is_none());
    assert!(index.standing(&addr(&fixture.tampered_malformed)).is_none());
    let stats = mirror.stats();
    assert!(stats.rows > 0 && stats.pages > 0 && stats.reads.total() > 0);
    assert_eq!(stats.records, 34, "eighteen binding bodies and sixteen endpoint bodies read, the two tampered among them: {stats:?}");
}

/// THE REBUILD (REG-3.25; R5 (h)): the index rebuilt from the copy alone —
/// no board dialed, every fetch served from the cache — equals the live
/// one, standing for standing and deposit for deposit, and names itself a
/// rebuild, nothing checked against a source; a table the cache never held
/// — the registrar's own, rotated after every binding — is one it could not
/// read, never an empty set; and the copy re-opened against the source is
/// checked and RESUMED (REG-3.18).
#[test]
fn the_rebuild_from_the_copy_reads_no_wire_and_equals_the_live_index() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, live) = open_fixture_mirror(dir.path());
    let rows = live.stats().rows;
    let mut offline = Mirror::rebuild_offline(&fixture.hint, dir.path()).expect("rebuilt from the copy");
    assert_eq!(*offline.opened(), Opened::Rebuilt);
    assert_eq!(offline.head(), live.head());
    for prefix in live.index().prefixes() {
        assert_eq!(offline.index().standing(prefix), live.index().standing(prefix), "{prefix}");
    }
    assert_eq!(offline.index().counts(), live.index().counts());
    assert_eq!(offline.index().suppressed(), live.index().suppressed());
    assert_eq!(offline.index(), live.index(), "every deposit and its verdict, not their counts alone");
    let claimant = offline.claim().map(|(_, c)| c.clone()).expect("the claim, from the cache");
    assert_eq!(offline.current_keys(&claimant), Ok(None), "the table at the head was never fetched");
    assert_eq!(offline.stats().reads.total(), 0, "no wire read");
    drop(live);
    let dial = replay_dial(fixture.clone());
    let resumed = Mirror::open(&fixture.hint, dir.path(), &dial).expect("resumed");
    assert_eq!(*resumed.opened(), Opened::Resumed { checked_rows: rows });
    assert_eq!(resumed.index().counts(), offline.index().counts());
}

/// REG-3.42, REG-3.19: a hint whose realm id names another genesis
/// fingerprint than the root's genesis set's is refused at the base, the two
/// genesis fingerprints named, and no copy is written.
#[test]
fn a_hint_naming_another_realm_is_refused_at_the_base() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = fixture();
    let other = Fingerprint::parse_hex(&"11".repeat(32)).unwrap();
    let hint = RootHint::new(fixture.hint.origins().to_vec(), other, None).unwrap();
    let dial = replay_dial(fixture.clone());
    let refused = Mirror::open(&hint, dir.path(), &dial).unwrap_err();
    assert_eq!(
        refused,
        MirrorError::Refused(Refusal::RealmMismatch { expected: other, found: fixture.hint.realm().genesis })
    );
    assert!(!dir.path().join(FEED_COPY).exists());
    assert!(!dir.path().join(FETCH_CACHE).exists());
}

/// REG-3.42 UNDER A HELD COPY: what the copy says of its genesis is the
/// copy's word, never the root's. A courier's feed copy of this root's
/// journal, its header rewritten to another genesis fingerprint and shipped
/// with a fetch cache whose genesis table for the claimant agrees with that
/// fingerprint, matches the source row for row and head pair for pair — and
/// is refused at the claim's row all the same, the realm compared against
/// the genesis set the source answers and never the cache's; the two genesis
/// fingerprints named, and nothing written: the feed copy and the cache as
/// they were shipped.
#[test]
fn a_held_copy_naming_another_realm_is_refused_at_the_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, mirror) = open_fixture_mirror(dir.path());
    let claimant = mirror.claim().map(|(_, c)| c.to_string()).expect("the claim");
    drop(mirror);
    let forged = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[9; 32]).expect("tag 1").public_key().clone();
    let other = RealmId::genesis_fingerprint(&[Fingerprint::of(&forged)]);
    let feed = fs::read_to_string(dir.path().join(FEED_COPY)).expect("the feed copy");
    let shipped_feed = feed.replacen(&fixture.hint.realm().genesis.to_hex(), &other.to_hex(), 1);
    assert_ne!(shipped_feed, feed, "the header names the genesis fingerprint");
    fs::write(dir.path().join(FEED_COPY), &shipped_feed).expect("the courier's header");
    let genesis = json!({ "keys": {
        "account": claimant, "epoch": 0, "at": 0,
        "enrolled": [{ "alg": forged.alg(), "key": forged.to_hex(), "anchor": true }],
    }});
    let cache = fs::read_to_string(dir.path().join(FETCH_CACHE)).expect("the fetch cache");
    let shipped_cache = format!("{cache}{genesis}\n");
    fs::write(dir.path().join(FETCH_CACHE), &shipped_cache).expect("the courier's cache");
    let hint = RootHint::new(fixture.hint.origins().to_vec(), other, None).unwrap();
    let dial = replay_dial(fixture.clone());
    let refused = Mirror::open(&hint, dir.path(), &dial).unwrap_err();
    assert_eq!(
        refused,
        MirrorError::Refused(Refusal::RealmMismatch { expected: other, found: fixture.hint.realm().genesis })
    );
    assert_eq!(fs::read_to_string(dir.path().join(FEED_COPY)).expect("the feed copy"), shipped_feed, "no line of the copy");
    assert_eq!(fs::read_to_string(dir.path().join(FETCH_CACHE)).expect("the fetch cache"), shipped_cache, "nor of the cache");
}

/// A NEW BASE BEGINS BOTH FILES: a fetch cache left in the directory with no
/// feed copy beside it — another base's, or what a reset left — holds no
/// line of the base the bootstrap writes, so no resume ever reads it as this
/// mirror's own.
#[test]
fn a_bootstrap_begins_the_cache_afresh() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stray = json!({ "link": { "at": 1, "address": "1.0.1.0.1.0.2.1", "home": "1.0.1.0.1", "ty": null, "from": [], "to": [], "of": "another base" } });
    fs::write(dir.path().join(FETCH_CACHE), format!("{stray}\n")).expect("a cache with no feed copy");
    let (_, mirror) = open_fixture_mirror(dir.path());
    assert_eq!(*mirror.opened(), Opened::Bootstrapped);
    let cache = fs::read_to_string(dir.path().join(FETCH_CACHE)).expect("the fetch cache");
    assert!(!cache.contains("another base"), "the stray line survived the bootstrap");
    assert!(cache.lines().any(|l| l.starts_with(r#"{"claim":"#)), "the base's own lines");
}

/// THE COPY IS READ BY ITS FORMAT: a feed copy whose header carries no
/// format stamp is no copy this build writes, and is refused offline as it
/// is at the open — never rebuilt from.
#[test]
fn a_copy_with_no_format_stamp_is_refused_offline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, mirror) = open_fixture_mirror(dir.path());
    drop(mirror);
    let feed = fs::read_to_string(dir.path().join(FEED_COPY)).expect("the feed copy");
    let (header, rows) = feed.split_once('\n').expect("a header and rows");
    let mut unstamped: serde_json::Value = serde_json::from_str(header).expect("the header is JSON");
    unstamped.as_object_mut().expect("an object").remove("skep-resolve");
    fs::write(dir.path().join(FEED_COPY), format!("{unstamped}\n{rows}")).expect("the copy unstamped");
    assert!(
        matches!(Mirror::rebuild_offline(&fixture.hint, dir.path()).unwrap_err(), MirrorError::Copy(e) if e.contains("not a feed copy")),
        "an unstamped copy is refused"
    );
    let dial = replay_dial(fixture.clone());
    assert!(matches!(Mirror::open(&fixture.hint, dir.path(), &dial).unwrap_err(), MirrorError::Copy(_)), "offline as at the open");
}

/// A VALUE IS WRITTEN ONCE: the copy resumed twice against the source reads
/// every link, atom, table and the claim it holds back through its own
/// cache, so each re-open writes no line — the cache holds one claim line,
/// never one per open, and both files come back as they were.
#[test]
fn a_resumed_copy_writes_no_line_its_cache_holds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, mirror) = open_fixture_mirror(dir.path());
    drop(mirror);
    let read = |name: &str| fs::read_to_string(dir.path().join(name)).expect("a file of the copy");
    let (feed, cache) = (read(FEED_COPY), read(FETCH_CACHE));
    let dial = replay_dial(fixture.clone());
    for _ in 0..2 {
        let resumed = Mirror::open(&fixture.hint, dir.path(), &dial).expect("resumed");
        assert!(matches!(resumed.opened(), Opened::Resumed { .. }));
    }
    assert_eq!(read(FETCH_CACHE).lines().filter(|l| l.starts_with(r#"{"claim":"#)).count(), 1);
    assert_eq!(read(FETCH_CACHE), cache, "no line of the cache");
    assert_eq!(read(FEED_COPY), feed, "nor of the feed copy");
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
    assert_eq!(fixture.hint.realm().fork_point, None, "an unforked lineage");
}
