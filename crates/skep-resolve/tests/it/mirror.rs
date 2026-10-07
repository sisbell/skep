//! THE MIRROR from the fixture: the rebuild from the copy with no wire read
//! (REG-3.25), and the offline mirror's scope; the base — the realm checked
//! under a fresh base and a held copy alike (REG-3.42), the held head pairs
//! checked (REG-3.18), a re-ordered copy refused online by provenance and
//! offline by its order, a copy of another genesis retired (REG-3.17), the
//! root the first origin that answers; the copy's two files — begun
//! together, read back by their format, a cache line cut short holding
//! nothing, written once per value — and the hint's one line (REG-3.2).

use std::cell::RefCell;
use std::fs;
use std::io::Write;

use serde_json::{json, Value};
use skep_identity::Fingerprint;
use skep_resolve::{
    Method, Mirror, MirrorError, Opened, Origin, RealmId, Refusal, RootHint, Transport, TransportError, FEED_COPY,
    FETCH_CACHE,
};
use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

use crate::{fixture, open_fixture_mirror, replay_dial, Replay};

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

/// AN OFFLINE MIRROR SERVES ITS OWN COPY ALONE (REG-3.25): the copy is
/// rebuilt only under a hint whose genesis fingerprint its header names —
/// offline, that comparison is the only realm check there is — and the
/// mirror it answers never syncs: a sync is a wire read, refused with no
/// board held, and it writes nothing.
#[test]
fn an_offline_mirror_serves_its_own_copy_alone_and_never_syncs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, mirror) = open_fixture_mirror(dir.path());
    drop(mirror);
    let read = |name: &str| fs::read_to_string(dir.path().join(name)).expect("a file of the copy");
    let (feed, cache) = (read(FEED_COPY), read(FETCH_CACHE));
    let other = Fingerprint::parse_hex(&"11".repeat(32)).unwrap();
    let elsewhere = RootHint::new(fixture.hint.origins().to_vec(), other, None).unwrap();
    assert!(matches!(Mirror::rebuild_offline(&elsewhere, dir.path()), Err(MirrorError::Copy(_))), "another realm's hint");
    let mut offline = Mirror::rebuild_offline(&fixture.hint, dir.path()).expect("rebuilt");
    assert_eq!(offline.sync(), Err(MirrorError::Offline));
    assert_eq!(read(FEED_COPY), feed, "no line of the copy");
    assert_eq!(read(FETCH_CACHE), cache, "nor of the cache");
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
/// with a fetch cache whose every table for the claimant — at the epoch the
/// mirror keeps its genesis set under, and at 0 — agrees with that
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
    let forge = |epoch: &Value, at: &Value| {
        json!({ "keys": {
            "account": claimant, "epoch": epoch, "at": at,
            "enrolled": [{ "alg": forged.alg(), "key": forged.to_hex(), "anchor": true }],
        }})
    };
    let cache = fs::read_to_string(dir.path().join(FETCH_CACHE)).expect("the fetch cache");
    let mut forgeries: Vec<Value> = cache
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("a cache line is JSON"))
        .filter(|line| line["keys"]["account"] == claimant.as_str())
        .map(|line| forge(&line["keys"]["epoch"], &line["keys"]["at"]))
        .collect();
    assert!(!forgeries.is_empty(), "the cache holds the claimant's genesis table");
    forgeries.push(forge(&json!(0), &json!(0)));
    let shipped_cache = format!("{cache}{}", forgeries.iter().map(|f| format!("{f}\n")).collect::<String>());
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

/// A CACHE LINE CUT SHORT HOLDS NOTHING: a fetch cache a crash left
/// mid-line — its last line unterminated, no JSON — is read for every line
/// that reads, the cut one passed over and never refusing the cache; the
/// copy resumes against the source, its index the live one's.
#[test]
fn a_cache_line_cut_short_holds_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, live) = open_fixture_mirror(dir.path());
    let index = live.index().clone();
    drop(live);
    let mut cache = fs::OpenOptions::new().append(true).open(dir.path().join(FETCH_CACHE)).expect("the fetch cache");
    cache.write_all(br#"{"atom":{"addr"#).expect("a line cut short");
    drop(cache);
    let dial = replay_dial(fixture.clone());
    let resumed = Mirror::open(&fixture.hint, dir.path(), &dial).expect("resumed");
    assert!(matches!(resumed.opened(), Opened::Resumed { .. }), "{:?}", resumed.opened());
    assert_eq!(*resumed.index(), index, "the index the live one's");
}

/// THE FEED'S ORDER, HELD ON EACH PATH BY ITS OWNER: a copy two of whose
/// rows are swapped is refused online by provenance — `Refusal::Diverged` at
/// the first held position that parts from the source, the later of the
/// two (REG-3.13, the courier vector) — and offline, where no source
/// answers, by its own order, never folded.
#[test]
fn a_reordered_copy_is_refused_by_provenance_online_and_by_its_order_offline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, mirror) = open_fixture_mirror(dir.path());
    drop(mirror);
    let feed = fs::read_to_string(dir.path().join(FEED_COPY)).expect("the feed copy");
    let mut lines: Vec<&str> = feed.lines().collect();
    let rows: Vec<usize> = lines.iter().enumerate().filter(|(_, l)| l.starts_with(r#"{"row":"#)).map(|(i, _)| i).collect();
    let mid = rows[rows.len() / 2];
    assert!(rows.contains(&(mid + 1)), "two rows side by side");
    lines.swap(mid, mid + 1);
    let later = serde_json::from_str::<Value>(lines[mid]).expect("a row")["row"]["at"].as_u64().expect("its position");
    fs::write(dir.path().join(FEED_COPY), lines.join("\n") + "\n").expect("the copy, two rows swapped");
    let dial = replay_dial(fixture.clone());
    assert_eq!(Mirror::open(&fixture.hint, dir.path(), &dial).unwrap_err(), MirrorError::Refused(Refusal::Diverged { at: later }));
    let offline = Mirror::rebuild_offline(&fixture.hint, dir.path()).unwrap_err();
    assert!(matches!(&offline, MirrorError::Copy(e) if e.contains("do not rise")), "{offline:?}");
}

/// THE HEAD PAIRS ARE CHECKED (REG-3.18; `Refusal::ChainDiverged`): a copy
/// whose every row the source answers identically, but whose held head pair
/// the source's own recomputation of its chain contradicts — two journals
/// that serve one feed and differ beneath it — is refused at that pair's
/// position, and nothing is written.
#[test]
fn a_head_pair_the_source_contradicts_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, mirror) = open_fixture_mirror(dir.path());
    drop(mirror);
    let read = |name: &str| fs::read_to_string(dir.path().join(name)).expect("a file of the copy");
    let (feed, cache) = (read(FEED_COPY), read(FETCH_CACHE));
    let mut held_at = None;
    let forged: String = feed
        .lines()
        .map(|line| {
            if !line.starts_with(r#"{"head":"#) {
                return format!("{line}\n");
            }
            let mut pair: Value = serde_json::from_str(line).expect("a head pair is JSON");
            held_at = pair["head"]["at"].as_u64();
            pair["head"]["chain"] = json!("00".repeat(32));
            format!("{pair}\n")
        })
        .collect();
    let at = held_at.expect("the bootstrap held a head pair");
    fs::write(dir.path().join(FEED_COPY), &forged).expect("the copy, its head pair contradicted");
    let dial = replay_dial(fixture.clone());
    let refused = Mirror::open(&fixture.hint, dir.path(), &dial).unwrap_err();
    assert_eq!(refused, MirrorError::Refused(Refusal::ChainDiverged { at }));
    assert_eq!(read(FEED_COPY), forged, "no line of the copy");
    assert_eq!(read(FETCH_CACHE), cache, "nor of the cache");
}

/// A HINT RE-POINTED TO ANOTHER GENESIS (REG-3.17): a copy whose header
/// names another genesis fingerprint than the hint's is no base of this
/// realm — it is RETIRED beside the new, both its files kept under that
/// genesis fingerprint's name, and the base is established afresh from the
/// root's genesis, resuming nothing: the new copy is the one a cold mirror
/// writes.
#[test]
fn a_copy_of_another_genesis_is_retired_and_the_base_established_afresh() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, mirror) = open_fixture_mirror(dir.path());
    drop(mirror);
    let read = |name: &str| fs::read_to_string(dir.path().join(name)).expect("a file of the directory");
    let (feed, cache) = (read(FEED_COPY), read(FETCH_CACHE));
    let other = Fingerprint::parse_hex(&"11".repeat(32)).unwrap();
    let held = feed.replacen(&fixture.hint.realm().genesis.to_hex(), &other.to_hex(), 1);
    fs::write(dir.path().join(FEED_COPY), &held).expect("a copy of another genesis");
    let dial = replay_dial(fixture.clone());
    let mirror = Mirror::open(&fixture.hint, dir.path(), &dial).expect("re-bootstrapped");
    let suffix = format!("retired-{}", &other.to_hex()[..16]);
    let retired = format!("{FEED_COPY}.{suffix}");
    assert_eq!(*mirror.opened(), Opened::Rebootstrapped { retired: dir.path().join(&retired) });
    assert_eq!(read(&retired), held, "the copy retired under its own genesis fingerprint");
    assert_eq!(read(&format!("{FETCH_CACHE}.{suffix}")), cache, "its cache retired beside it");
    assert_eq!(read(FEED_COPY), feed, "the new copy is the one a cold mirror writes");
    assert_eq!(read(FETCH_CACHE), cache, "and so is its cache");
}

/// A board that is down: every exchange is refused `503`.
struct Down;

impl Transport for Down {
    fn exchange(&self, _: Method, _: &str, _: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        Ok((503, b"down".to_vec()))
    }
}

/// THE ROOT IS THE FIRST ORIGIN THAT ANSWERS (REG-3.2): the hint's origins
/// are dialed in its order, an origin whose board does not answer `/health`
/// is passed over, the first that answers is the root the base is read
/// from — named in the copy's header — and no origin after it is dialed.
#[test]
fn the_first_origin_that_answers_is_the_root_and_none_after_it_is_dialed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = fixture();
    let origins: Vec<Origin> = (1..=3).map(|port| Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap()).collect();
    let hint = RootHint::new(origins.clone(), fixture.hint.realm().genesis, None).unwrap();
    let dialed = RefCell::new(Vec::new());
    let dial = |o: &Origin| -> Result<Box<dyn Transport>, TransportError> {
        dialed.borrow_mut().push(o.clone());
        if *o == origins[0] {
            Ok(Box::new(Down))
        } else {
            Ok(Box::new(Replay(fixture.clone())))
        }
    };
    let mirror = Mirror::open(&hint, dir.path(), &dial).expect("opened at the second origin");
    assert_eq!(mirror.root(), Some(&origins[1]));
    assert_eq!(*dialed.borrow(), origins[..2], "none dialed after the root");
    let feed = fs::read_to_string(dir.path().join(FEED_COPY)).expect("the feed copy");
    let header: Value = serde_json::from_str(feed.lines().next().expect("a header")).expect("the header is JSON");
    assert_eq!(header["root"], "http://127.0.0.1:2", "the root named in the copy's header");
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
/// never one per open, and both files come back as they were; and the
/// copy's bytes each resumed mirror reports are the two files' as held.
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
        assert_eq!(resumed.stats().copy_bytes, (feed.len() + cache.len()) as u64, "the copy's bytes, the files' as held");
    }
    assert_eq!(read(FETCH_CACHE).lines().filter(|l| l.starts_with(r#"{"claim":"#)).count(), 1);
    assert_eq!(read(FETCH_CACHE), cache, "no line of the cache");
    assert_eq!(read(FEED_COPY), feed, "nor of the feed copy");
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
