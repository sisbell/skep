//! The world-dump surface and the recovery-order contract, together:
//! dump determinism (two dumps of equal worlds are byte-equal), recovery
//! equivalence (a world folded live from genesis dumps byte-equal to the
//! world restored from checkpoint + rebuild_derived + replay), and hint
//! faithfulness (live incrementally-maintained hints equal a
//! from-authoritative rebuild). The scenario deliberately crosses a
//! checkpoint mid-history and populates every dump-observable hint family:
//! typed slices (shipped and app classes), the nullified set, supersession
//! edges, and content/arrangement state.

#![cfg(feature = "dump")]

use std::collections::BTreeSet;

mod common;

use common::*;
use skep_content::Val;
use skep_engine::{Engine, GenesisConfig, TypeDecl};
use skep_links::{enc, Behavior, Registration, Shape, SlotArg};
use tempfile::tempdir;

/// The standard reserved addresses plus one app-declared Binary idem⊤ type,
/// so genesis decls (and their dump section) are non-trivial.
fn rich_genesis() -> GenesisConfig {
    let mut cfg = GenesisConfig::standard();
    cfg.types.decls = vec![TypeDecl {
        key: enc(&[a(&[9, 0, 9, 0, 9, 0, 8, 1])]),
        reg: Registration {
            shape: Shape::Binary,
            idem: true,
            behaviors: BTreeSet::<Behavior>::new(),
        },
    }];
    cfg
}

#[test]
fn dumps_are_deterministic_and_recovery_is_equivalent() {
    let dir = tempdir().expect("tempdir");
    let genesis = rich_genesis();

    let dump_live;
    {
        let engine = Engine::open(fsync_cfg(dir.path()), genesis.clone()).expect("fsync open");
        let (_acct, doc) = setup_doc(&engine);

        // History batch A (below the checkpoint): content.
        let (start, _) = engine
            .vstream()
            .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'p']), Val::new(vec![b'q'])])
            .expect("insert succeeds");

        // Checkpoint mid-history, so recovery is checkpoint + replay, not a
        // pure journal fold.
        engine.kernel().checkpoint().expect("checkpoint succeeds");

        // History batch B (the replay tail): links, a supersession claim, a
        // retraction, and an app-typed emission — populating every
        // dump-observable hint family past the checkpoint.
        let (l1, _) = engine
            .linkstore()
            .makelink(
                OWNER,
                &doc,
                SlotArg::Resolve(vec![vspec(&doc, 1, 1)]),
                SlotArg::Resolve(vec![vspec(&doc, 2, 1)]),
                SlotArg::Resolve(vec![vspec(&doc, 1, 2)]),
            )
            .expect("makelink l1");
        let (l2, _) = engine
            .linkstore()
            .makelink(
                OWNER,
                &doc,
                SlotArg::Resolve(vec![vspec(&doc, 2, 1)]),
                SlotArg::Resolve(vec![vspec(&doc, 1, 1)]),
                SlotArg::Resolve(vec![vspec(&doc, 1, 2)]),
            )
            .expect("makelink l2");
        engine.linkstore().assert_sup(OWNER, &doc, &l1, &l2).expect("assert_sup");
        engine.linkstore().nullify(OWNER, &doc, &l1).expect("nullify");
        let rel = genesis.types.decls[0].key.clone();
        engine
            .linkstore()
            .emit(OWNER, &doc, &rel, &start, std::slice::from_ref(&doc))
            .expect("app-typed emit");

        // Dump determinism: two dumps of one world are byte-equal.
        let d1 = engine.world_dump();
        let d2 = engine.world_dump();
        assert_eq!(d1, d2, "two dumps of one world must be byte-equal");

        // Hint faithfulness on the live world.
        engine.check_hints().expect("live hints match a from-scratch rebuild");

        dump_live = d1;
        // Engine drops: journal lock released.
    }

    {
        let engine = Engine::open(fsync_cfg(dir.path()), genesis.clone()).expect("reopen");

        // Recovery equivalence: live fold == checkpoint + rebuild + replay.
        let dump_recovered = engine.world_dump();
        assert_eq!(
            dump_live, dump_recovered,
            "a world folded live and a world restored from checkpoint+replay must dump byte-equal"
        );

        // Hint faithfulness again, now over the recovered hints.
        engine.check_hints().expect("recovered hints match a from-scratch rebuild");
    }
}

/// A world the caller pinned itself — a snapshot rather than the engine's
/// own committed read — dumps deterministically and its hints are faithful,
/// with the genesis configuration supplied by the engine that produced it
/// (the harness shape: any world this engine made, rendered against the one
/// config it was sealed under).
#[test]
fn a_caller_pinned_world_dumps_deterministically() {
    let engine = Engine::open(mem_cfg(), rich_genesis()).expect("in-memory open");
    let (_acct, doc) = setup_doc(&engine);
    engine
        .vstream()
        .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'v'])])
        .expect("insert succeeds");

    let snap = engine.kernel().snapshot();
    let d1 = engine.dump_of(snap.world());
    let d2 = engine.dump_of(snap.world());
    assert_eq!(d1, d2);
    engine.check_hints_of(snap.world()).expect("hints are faithful");
}

/// The dump's vocabulary is part of its format, so it is pinned here rather
/// than left to whatever the assembler happens to call its fields: each
/// authoritative section is named for the store whose slice it renders, and
/// the banner names the version those keys belong to.
#[test]
fn the_dump_names_each_section_for_its_store() {
    let engine = Engine::open(mem_cfg(), rich_genesis()).expect("in-memory open");
    let text = engine.world_dump().into_string();

    assert!(text.starts_with("skep-world-dump v2\n"), "unexpected banner: {text:.32}");
    for section in [r#""namespace""#, r#""content""#, r#""arrangement""#, r#""links""#] {
        assert!(
            text.contains(section),
            "the authoritative section {section} must be named: {text:.200}"
        );
    }
}

/// A dump is its text, and every way of reading it out gives the same text —
/// so a caller showing one reaches for `{}` rather than an accessor, and
/// equal dumps hash alike for a harness collecting the distinct ones across a
/// sweep of crash points.
#[test]
fn a_dump_reads_out_as_its_text_by_every_route() {
    use std::collections::HashSet;

    let engine = Engine::open(mem_cfg(), rich_genesis()).expect("in-memory open");
    let dump = engine.world_dump();

    assert_eq!(format!("{dump}"), dump.as_str());
    assert_eq!(AsRef::<str>::as_ref(&dump), dump.as_str());
    assert_eq!(dump.as_bytes(), dump.as_str().as_bytes());

    let distinct: HashSet<_> = [engine.world_dump(), engine.world_dump()].into_iter().collect();
    assert_eq!(distinct.len(), 1, "two dumps of one world are one dump");
    assert_eq!(dump.clone().into_string(), dump.as_str());
}
