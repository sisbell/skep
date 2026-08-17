//! The observation surface and the recovery-order contract, together:
//! dump determinism (two dumps of equal worlds are byte-equal), recovery
//! equivalence (a world folded live from genesis dumps byte-equal to the
//! world restored from checkpoint + rebuild_derived + replay), and hint
//! faithfulness (live incrementally-maintained hints equal a
//! from-authoritative rebuild). The scenario deliberately crosses a
//! checkpoint mid-history and populates every dump-observable hint family:
//! typed slices (shipped and app classes), the nullified set, supersession
//! edges, and content/arrangement state.

#![cfg(feature = "observe")]

mod common;

use common::*;
use skep_content::Val;
use skep_engine::observe::{dump, hints_faithful};
use skep_engine::{Engine, GenesisConfig, ReservedAddrs, TypeDecl};
use skep_links::{enc, Behavior, Registration, Shape, SlotArg};
use tempfile::tempdir;

/// The standard reserved addresses plus one app-declared Binary idem⊤ type,
/// so genesis decls (and their dump section) are non-trivial.
fn rich_genesis() -> GenesisConfig {
    let reserved: ReservedAddrs = GenesisConfig::standard().reserved;
    let rel_key = enc(&[a(&[9, 0, 9, 0, 9, 0, 8, 1])]);
    let decls = vec![TypeDecl {
        key: rel_key,
        reg: Registration {
            shape: Shape::Binary,
            idem: true,
            behaviors: im::OrdSet::<Behavior>::new(),
        },
    }];
    GenesisConfig { reserved, decls }
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
            .insert(&doc, vp(1, 1), vec![Val::new(vec![b'p']), Val::new(vec![b'q'])])
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
                &doc,
                SlotArg::Resolve(vec![vspec(&doc, 1, 1)]),
                SlotArg::Resolve(vec![vspec(&doc, 2, 1)]),
                SlotArg::Resolve(vec![vspec(&doc, 1, 2)]),
            )
            .expect("makelink l1");
        let (l2, _) = engine
            .linkstore()
            .makelink(
                &doc,
                SlotArg::Resolve(vec![vspec(&doc, 2, 1)]),
                SlotArg::Resolve(vec![vspec(&doc, 1, 1)]),
                SlotArg::Resolve(vec![vspec(&doc, 1, 2)]),
            )
            .expect("makelink l2");
        engine.linkstore().assert_sup(&doc, &l1, &l2).expect("assert_sup");
        engine.linkstore().nullify(&doc, &l1).expect("nullify");
        let rel = genesis.decls[0].key.clone();
        engine
            .linkstore()
            .emit(&doc, &rel, &start, std::slice::from_ref(&doc))
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

/// The free-function surface works off a caller-pinned snapshot too (the
/// harness shape: no `Engine`, just a world and the genesis config).
#[test]
fn dump_free_functions_off_a_snapshot() {
    let genesis = rich_genesis();
    let engine = Engine::open(mem_cfg(), genesis.clone()).expect("in-memory open");
    let (_acct, doc) = setup_doc(&engine);
    engine
        .vstream()
        .insert(&doc, vp(1, 1), vec![Val::new(vec![b'v'])])
        .expect("insert succeeds");

    let snap = engine.kernel().snapshot();
    let d1 = dump(snap.world(), &genesis);
    let d2 = dump(snap.world(), &genesis);
    assert_eq!(d1, d2);
    hints_faithful(snap.world(), &genesis).expect("hints are faithful");
}
