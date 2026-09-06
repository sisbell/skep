//! The exception set (PUB round 1, delta 2 — owner ruling D1, 2026-09-05):
//! the engine's derived membership index over M3's publication bit takes
//! both halves of the hint discipline (PUB-7.7) — SEEDED at load, FOLDED on
//! every document-minting record — and the load check that guards its
//! fail-open polarity (PUB-7.8, PUB-7.9) holds through the assembled engine:
//! a checkpoint the World cannot decode replays from an older start point or
//! refuses to open, and never serves an empty set. Store semantics are not
//! re-tested here (M3 owns the bit and its record); what is tested is the
//! assembly.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::*;
use skep_address::{validate, Address, Tumbler};
use skep_arrangement::VersionError;
use skep_content::Val;
use skep_engine::{Engine, EngineError, OpenError, World};
use skep_kernel::TxnError;
use skep_namespace::HasM3;
use tempfile::tempdir;

/// The set as `(draft, owner)` pairs in address order — the hash-keyed map
/// has no order of its own.
fn drafts_of(world: &World) -> Vec<(Address, Address)> {
    let mut pairs: Vec<(Address, Address)> =
        world.drafts().map(|(doc, owner)| (doc.clone(), owner.clone())).collect();
    pairs.sort();
    pairs
}

/// Three drafts and two published documents in one account: the home (the
/// account's first mint, born published — PUB-1.17), two flagless mints and
/// one explicit `false` (drafts), one explicit `true` (an edition).
struct Docs {
    acct: Address,
    home: Address,
    drafts: [Address; 3],
    edition: Address,
}

impl Docs {
    /// What these documents put in the exception set, in address order.
    fn expected_set(&self) -> Vec<(Address, Address)> {
        let mut pairs: Vec<(Address, Address)> =
            self.drafts.iter().map(|d| (d.clone(), self.acct.clone())).collect();
        pairs.sort();
        pairs
    }
}

fn mint_docs(engine: &Engine) -> Docs {
    let (acct, home) = setup_home(engine);
    let ns = engine.namespace();
    let mint = |flag: Option<bool>| {
        ns.create_new_document(USER, &acct, flag).expect("the owner mints a document").0
    };
    let d1 = mint(None);
    let d2 = mint(None);
    let edition = mint(Some(true));
    let d3 = mint(Some(false));
    Docs { acct, home, drafts: [d1, d2, d3], edition }
}

/// The one checkpoint in `dir` — every test here takes exactly one.
fn checkpoint_file(dir: &Path) -> PathBuf {
    let mut found: Vec<PathBuf> = fs::read_dir(dir)
        .expect("read the journal directory")
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("checkpoint.") && name != "checkpoint.tmp")
        })
        .collect();
    assert_eq!(found.len(), 1, "exactly one checkpoint expected: {found:?}");
    found.pop().expect("one checkpoint")
}

fn remove_checkpoints(dir: &Path) {
    fs::remove_file(checkpoint_file(dir)).expect("remove the checkpoint");
}

/// Replace the checkpoint's BODY under a VALID header, so the DECODE is what
/// refuses it and never the checksum. M2's layout, kept as written for the
/// first two fields: `[magic 4][seq u64 LE][crc32c(body) u32 LE]
/// [body_len u64 LE][body]`. Should M2 ever move its header, this rewrite
/// degrades to a checksum failure — which M2's chain refuses the same way, so
/// the tests below still pass but stop exercising the decode route; the
/// coupling is stated here so that a header change knows to look.
fn rewrite_checkpoint_body(dir: &Path, body: &[u8]) {
    let path = checkpoint_file(dir);
    let data = fs::read(&path).expect("read the checkpoint");
    let mut out = data[..12].to_vec();
    out.extend_from_slice(&crc32c::crc32c(body).to_le_bytes());
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(body);
    fs::write(&path, out).expect("rewrite the checkpoint");
}

/// A checkpoint body in the PRE-STAMP World layout — the slices of genesis
/// with no leading format stamp, what a build from before the stamp wrote —
/// which this build must refuse to decode (PUB-7.8: fail to DECODE, never
/// default). The World's own unit test pins that the stamp is the leading
/// eight bytes; the assert here re-states the one fact this fixture rests on.
fn pre_stamp_body() -> Vec<u8> {
    let whole = bincode::serialize(&World::genesis()).expect("a world serializes");
    let pre = whole[8..].to_vec();
    assert!(
        bincode::deserialize::<World>(&pre).is_err(),
        "the pre-stamp layout must not decode as this build's World"
    );
    pre
}

/// Test 1 — the SEED: a checkpoint holding three drafts and two published
/// documents, reopened, yields exactly the three. The checkpoint sits at the
/// head, so the reopened base IS the checkpoint and nothing replays onto it:
/// the set below is the seed's alone.
#[test]
fn the_seed_holds_exactly_the_drafts_of_a_checkpoint() {
    let dir = tempdir().expect("tempdir");
    let (docs, live) = {
        let engine = Engine::open(fsync_cfg(dir.path())).expect("fsync open");
        let docs = mint_docs(&engine);
        engine.kernel().checkpoint().expect("checkpoint at head");
        let live = drafts_of(engine.kernel().snapshot().world());
        (docs, live)
    };

    let engine = Engine::open(fsync_cfg(dir.path())).expect("reopen over the checkpoint");
    let snap = engine.kernel().snapshot();
    let world = snap.world();
    assert_eq!(drafts_of(world), docs.expected_set(), "the seed holds exactly the three drafts");
    assert_eq!(drafts_of(world), live, "…and equals the live fold it stands in for");
    for draft in &docs.drafts {
        assert!(!world.published(draft), "{draft} is a draft");
        assert_eq!(world.owner_account(draft), Some(&docs.acct), "the owner fixed at mint");
    }
    for published in [&docs.home, &docs.edition] {
        assert!(world.published(published), "{published} is published — a membership miss");
        assert_eq!(world.owner_account(published), None, "the memo exists for drafts alone");
    }
    engine.check_hints().expect("the seed equals a from-authoritative rebuild");
}

/// Test 2 — the FOLD: a draft minted after the checkpoint joins the set in
/// the commit that registers it, so ONE head snapshot holds both or neither
/// (PUB-7.7 as RES-209 states it); a published mint registers and joins
/// nothing; and the replayed tail carries the membership across a reopen.
#[test]
fn a_draft_joins_the_set_in_the_commit_that_registers_it() {
    let dir = tempdir().expect("tempdir");
    let (draft, live) = {
        let engine = Engine::open(fsync_cfg(dir.path())).expect("fsync open");
        let docs = mint_docs(&engine);
        engine.kernel().checkpoint().expect("checkpoint below the tail");

        let before = engine.kernel().snapshot();
        let (draft, at) =
            engine.namespace().create_new_document(USER, &docs.acct, None).expect("a draft mints");
        let after = engine.kernel().snapshot();
        assert_eq!(after.seq(), at, "the head is the mint's own commit");
        // One head snapshot holds the registration AND the membership…
        assert!(after.world().m3().is_registered_document(&draft));
        assert!(!after.world().published(&draft));
        assert_eq!(after.world().owner_account(&draft), Some(&docs.acct));
        // …and the snapshot before it holds neither: the registration is
        // never visible ahead of the fold.
        assert!(!before.world().m3().is_registered_document(&draft));
        assert!(before.world().owner_account(&draft).is_none());
        assert_eq!(drafts_of(after.world()).len(), 4);

        // A published mint after the checkpoint registers and joins nothing.
        let (edition, _) = engine
            .namespace()
            .create_new_document(USER, &docs.acct, Some(true))
            .expect("an edition mints");
        let head = engine.kernel().snapshot();
        assert!(head.world().m3().is_registered_document(&edition));
        assert!(head.world().published(&edition));
        assert_eq!(drafts_of(head.world()).len(), 4);
        engine.check_hints().expect("the fold equals a from-authoritative rebuild");
        (draft, drafts_of(head.world()))
    };

    // The reopen is checkpoint + replay: the seed covers the three, the
    // replayed tail folds the fourth.
    let engine = Engine::open(fsync_cfg(dir.path())).expect("reopen");
    let snap = engine.kernel().snapshot();
    assert!(!snap.world().published(&draft), "the replayed draft is in the recovered set");
    assert_eq!(drafts_of(snap.world()), live);
}

/// Test 3 — replay equivalence: the live fold, checkpoint + replay, and a
/// full replay from genesis (the checkpoint removed) yield one set. The tail
/// includes a version of an edition, which inherits published and is not a
/// member of the set. A version of a DRAFT is no longer a member the tail
/// can hold: private documents are versionless (PUB-2.9, the write path's
/// own refusal since lane 3.1), so the attempt is refused and joins nothing.
#[test]
fn checkpoint_plus_replay_and_full_replay_yield_the_live_set() {
    let dir = tempdir().expect("tempdir");
    let (head, live) = {
        let engine = Engine::open(fsync_cfg(dir.path())).expect("fsync open");
        let docs = mint_docs(&engine);
        engine.kernel().checkpoint().expect("checkpoint mid-history");
        engine.namespace().create_new_document(USER, &docs.acct, None).expect("a draft");
        engine.namespace().create_new_document(USER, &docs.acct, Some(true)).expect("an edition");
        assert!(
            matches!(
                engine.vstream().version(USER, &docs.drafts[0], None),
                Err(TxnError::Rejected(VersionError::PrivateSourceVersionless))
            ),
            "a private owned source is versionless (PUB-2.9)"
        );
        engine.vstream().version(USER, &docs.edition, None).expect("a version of the edition");
        engine.check_hints().expect("the live fold equals a from-authoritative rebuild");
        let live = drafts_of(engine.kernel().snapshot().world());
        assert_eq!(live.len(), 4, "three drafts and one more; the refused version joined nothing");
        (engine.kernel().current_seq(), live)
    };

    // Checkpoint + replay.
    {
        let engine = Engine::open(fsync_cfg(dir.path())).expect("reopen over the checkpoint");
        assert_eq!(engine.kernel().current_seq(), head);
        assert_eq!(drafts_of(engine.kernel().snapshot().world()), live);
        engine.check_hints().expect("the recovered set equals a from-authoritative rebuild");
    }

    // Full replay: with the checkpoint gone, genesis carries the base and
    // every record folds.
    remove_checkpoints(dir.path());
    {
        let engine = Engine::open(fsync_cfg(dir.path())).expect("reopen from genesis");
        assert_eq!(engine.kernel().current_seq(), head);
        assert_eq!(drafts_of(engine.kernel().snapshot().world()), live);
        engine.check_hints().expect("the replayed set equals a from-authoritative rebuild");
    }
}

/// Test 4 — miss = published: a published document is absent from the set,
/// and so is an address never registered — the fail-open polarity PUB-7.5
/// names, which is why the API's contract puts the caller's registration
/// check AHEAD of the read (PUB-6.37; the daemon's publish gate does).
#[test]
fn an_unregistered_address_is_absent_so_registration_guards_the_read() {
    let engine = mem_engine();
    let docs = mint_docs(&engine);
    let snap = engine.kernel().snapshot();
    let world = snap.world();

    assert!(world.published(&docs.home));
    assert!(world.published(&docs.edition));

    // A never-minted slot of the account's own document chain.
    let never: Address = {
        let comps = docs.acct.tumbler().iter().cloned().chain([nat(0), nat(99)]);
        validate(Tumbler::new(comps).expect("nonempty")).expect("T4-valid")
    };
    assert!(!world.m3().is_registered_document(&never));
    assert!(
        world.published(&never),
        "absent from the set exactly as a published document is — the registration check stands ahead"
    );
    assert_eq!(world.owner_account(&never), None);
    assert!(
        !world.m3().published(&never),
        "M3's own read answers the fail-private direction there: the two agree on every \
         registered document — the contract's domain — and only there"
    );
}

/// Test 7 — the load check, fallback half (PUB-7.8, PUB-7.9): a checkpoint
/// whose body is the pre-stamp World layout validates its header and fails to
/// DECODE; M2's chain falls back to genesis — the journal still reaches
/// Seq(1) — and replays the whole history onto it. The recovered set is the
/// live one, never the empty set a decoded base would have carried.
#[test]
fn an_undecodable_checkpoint_replays_from_genesis_and_never_serves_an_empty_set() {
    let dir = tempdir().expect("tempdir");
    let (head, live) = {
        let engine = Engine::open(fsync_cfg(dir.path())).expect("fsync open");
        let docs = mint_docs(&engine);
        engine.kernel().checkpoint().expect("checkpoint at head");
        let live = drafts_of(engine.kernel().snapshot().world());
        assert_eq!(live, docs.expected_set());
        (engine.kernel().current_seq(), live)
    };

    rewrite_checkpoint_body(dir.path(), &pre_stamp_body());

    let engine = Engine::open(fsync_cfg(dir.path())).expect("the fallback chain carries the open");
    assert_eq!(engine.kernel().current_seq(), head, "the whole history replayed onto genesis");
    assert_eq!(
        drafts_of(engine.kernel().snapshot().world()),
        live,
        "the set is the live one — never the empty set of a decoded pre-bit base"
    );
    engine.check_hints().expect("the replayed set equals a from-authoritative rebuild");
}

/// Test 7 — the load check, refusal half (PUB-7.9): where the decode fails
/// and no older start point exists, the open REFUSES — `BadCheckpoint` — and
/// never serves the empty set. Genesis is made unreachable the way M2's own
/// suite does it: the journal rotates into a second segment and the
/// checkpoint's reclamation drops the first.
#[test]
fn an_undecodable_checkpoint_with_no_older_start_point_refuses_to_open() {
    let dir = tempdir().expect("tempdir");
    {
        let engine = Engine::open(fsync_cfg(dir.path())).expect("fsync open");
        let docs = mint_docs(&engine);
        // One content value past M2's segment rotation size (1 MiB), then one
        // more commit, which rotates the writer into a second segment and
        // closes the first.
        engine
            .vstream()
            .insert(OWNER, &docs.drafts[0], vp(1, 1), vec![Val::new(vec![b'x'; (1 << 20) + (1 << 16)])], false)
            .expect("a large insert commits");
        engine.namespace().create_new_document(USER, &docs.acct, None).expect("the rotating commit");
        // The checkpoint at head reclaims the closed first segment below it.
        engine.kernel().checkpoint().expect("checkpoint at head");
    }
    assert!(
        !dir.path().join("seg-1.wal").exists(),
        "the fixture must reclaim the first segment — otherwise genesis still stands in and \
         this test proves nothing"
    );

    rewrite_checkpoint_body(dir.path(), &pre_stamp_body());

    match Engine::open(fsync_cfg(dir.path())) {
        Err(EngineError::Open(OpenError::BadCheckpoint)) => {}
        Err(other) => panic!("the exhausted chain must refuse BadCheckpoint, got: {other}"),
        Ok(engine) => panic!(
            "opened at head {} over an undecodable sole base with genesis unreachable — from what?",
            engine.kernel().current_seq()
        ),
    }
}

/// The dump renders the set as a hint — draft → owner, address-ordered — so
/// the crash and conformance harnesses' byte comparison covers it, and the
/// hint-faithfulness check compares the fold against the seed through it.
#[cfg(feature = "dump")]
#[test]
fn the_dump_renders_the_exception_set_as_a_hint() {
    let engine = mem_engine();
    let docs = mint_docs(&engine);
    let text = engine.world_dump().into_string();
    assert!(text.starts_with("skep-world-dump v4\n"), "unexpected banner: {text:.32}");

    let mut pairs: Vec<(String, String)> = docs
        .drafts
        .iter()
        .map(|d| (format!("{:?}", d.to_string()), format!("{:?}", docs.acct.to_string())))
        .collect();
    pairs.sort();
    let entries: Vec<String> = pairs.iter().map(|(k, v)| format!("{k}: {v}")).collect();
    let expected = format!("\"publication.drafts\": {{{}}}", entries.join(", "));
    assert!(text.contains(&expected), "expected {expected} in the dump:\n{text}");
    engine.check_hints().expect("the set's fold equals its seed");
}
