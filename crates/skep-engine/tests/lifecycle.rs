//! One cross-store lifecycle through the real kernel under `Fsync`:
//! create document → insert → retrieve → makelink → findlinks → version —
//! every seam the engine closes, exercised once end-to-end, then reopened
//! from the journal to show the observable state survives recovery. Store
//! semantics are NOT re-tested here (the stores' own suites own that); what
//! is tested is the assembly: that the drivers, folds, lifts, and accessors
//! compose over one world.

mod common;

use std::collections::BTreeSet;

use common::*;
use skep_address::Address;
use skep_content::Val;
use skep_discovery::LinkQuery;
use skep_engine::{Engine, EngineError, GenesisConfig, ReservedAddrs, TypeDecl};
use skep_links::{enc, Behavior, HasLinks, Registration, Shape, ShippedType, SlotArg};
use skep_retrieval::{Query, Spec};
use tempfile::tempdir;

#[test]
fn cross_store_lifecycle_under_fsync() {
    let dir = tempdir().expect("tempdir");
    let expected = vec![b"x".to_vec(), b"y".to_vec(), b"z".to_vec()];

    let (doc, version_doc, link, last_seq);
    {
        let engine =
            Engine::open(fsync_cfg(dir.path()), GenesisConfig::standard()).expect("fsync open");

        // M3: bootstrap → delegate → create (the account/document prologue).
        let (_acct, d) = setup_doc(&engine);
        doc = d;

        // M5+M4+M3 composite: insert three values at the head.
        let (_start, insert_seq) = engine
            .vstream()
            .insert(
                OWNER,
                &doc,
                vp(1, 1),
                vec![Val::new(vec![b'x']), Val::new(vec![b'y']), Val::new(vec![b'z'])],
            )
            .expect("insert succeeds");

        // M6 read off one pinned snapshot: the bytes come back verbatim.
        {
            let snap = engine.kernel().snapshot();
            let q = Query::new(&snap);
            // M6's RetrieveError implements Display but not Debug (a store
            // decision the engine may not edit), so no `.expect` here.
            let delivery = q
                .retrieve_v(&[Spec { doc: doc.clone(), span: vspan(1, 1, 3) }])
                .unwrap_or_else(|e| panic!("retrieve failed: {e}"));
            assert_eq!(delivered_bytes(&delivery), expected);
        }

        // M7+M3+M5 composite: an open content link over the inserted content.
        let (l, link_seq) = engine
            .linkstore()
            .makelink(
                OWNER,
                &doc,
                SlotArg::Resolve(vec![vspec(&doc, 1, 1)]),
                SlotArg::Resolve(vec![vspec(&doc, 2, 1)]),
                SlotArg::Resolve(vec![vspec(&doc, 3, 1)]),
            )
            .expect("makelink succeeds");
        link = l;
        assert!(link_seq > insert_seq, "commit order is monotone across stores");

        // M8: the link is discoverable from the home document's region…
        let found_in_home = LinkQuery::new(engine.kernel())
            .findlinks_v(&doc, &[vspan(1, 1, 3)])
            .expect("findlinks succeeds");
        assert!(found_in_home.contains(&link), "the fresh link is discoverable from its home");

        // …and M7's raw read returns it verbatim.
        {
            let snap = engine.kernel().snapshot();
            assert!(snap.world().links().readlink(&link).is_some());
        }

        // M5+M3: version — a copy-on-write fork sharing the content.
        let (vd, _version_seq) = engine.vstream().version(USER, &doc).expect("version succeeds");
        version_doc = vd;
        {
            let snap = engine.kernel().snapshot();
            let q = Query::new(&snap);
            let delivery = q
                .retrieve_v(&[Spec { doc: version_doc.clone(), span: vspan(1, 1, 3) }])
                .unwrap_or_else(|e| panic!("retrieve of the version failed: {e}"));
            assert_eq!(delivered_bytes(&delivery), expected, "the version shares the content");
        }

        // The same I-addresses arranged in the version make the link
        // discoverable from it too — cross-store transclusion discovery.
        let found_in_version = LinkQuery::new(engine.kernel())
            .findlinks_v(&version_doc, &[vspan(1, 1, 3)])
            .expect("findlinks over the version succeeds");
        assert!(
            found_in_version.contains(&link),
            "the link is discoverable through the transclusion"
        );

        last_seq = engine.kernel().current_seq();
        // The engine (and with it every Arc<Kernel> clone) drops here,
        // releasing the journal's exclusion lock.
    }

    // Reopen from the journal: replay reproduces the same observable state.
    {
        let engine =
            Engine::open(fsync_cfg(dir.path()), GenesisConfig::standard()).expect("reopen");
        assert_eq!(engine.kernel().current_seq(), last_seq, "the log position survives recovery");

        let snap = engine.kernel().snapshot();
        let q = Query::new(&snap);
        for d in [&doc, &version_doc] {
            let delivery = q
                .retrieve_v(&[Spec { doc: (*d).clone(), span: vspan(1, 1, 3) }])
                .unwrap_or_else(|e| panic!("retrieve after recovery failed: {e}"));
            assert_eq!(delivered_bytes(&delivery), expected);
        }
        assert!(snap.world().links().readlink(&link).is_some());

        let found_in_home = LinkQuery::new(engine.kernel())
            .findlinks_v(&doc, &[vspan(1, 1, 3)])
            .expect("findlinks after recovery succeeds");
        assert!(found_in_home.contains(&link));
    }
}

/// Reopening a checkpointed journal under an edited genesis config trips
/// `check_genesis_drift` (M2's byte-identical-genesis contract, checked at
/// assembly) instead of silently running under a configuration the journal was
/// never sealed with — for EVERY shipped class, and the refusal names the one
/// that disagrees. A check that covered four classes out of five would refuse
/// nothing on the fifth, and a refusal that named the wrong class would send
/// the operator to the wrong line of their config.
#[test]
fn a_drifted_reopen_is_refused_and_names_the_shipped_class_that_drifted() {
    /// One edit to the reserved half: the shipped class it moves, and the
    /// setter that moves it.
    type ReservedEdit = (ShippedType, fn(&mut ReservedAddrs, Address));

    let edits: [ReservedEdit; 5] = [
        (ShippedType::PredDef, |r, addr| r.pred_def = addr),
        (ShippedType::PredStable, |r, addr| r.pred_stable = addr),
        (ShippedType::Retired, |r, addr| r.retired = addr),
        (ShippedType::Supersedes, |r, addr| r.supersedes = addr),
        (ShippedType::Retraction, |r, addr| r.retraction = addr),
    ];

    for (class, edit) in edits {
        let dir = tempdir().expect("tempdir");
        {
            let engine = Engine::open(fsync_cfg(dir.path()), GenesisConfig::standard())
                .expect("fsync open");
            setup_doc(&engine);
            // LOAD-BEARING, not scenario dressing: the check compares the
            // passed config against the one a CHECKPOINT carries. With no
            // checkpoint the reopen replays onto the passed genesis and there
            // is nothing left to disagree with.
            engine.kernel().checkpoint().expect("checkpoint succeeds");
        }

        // Valid on its own — an unused ordinal in the same reserved family —
        // but not the config this journal was sealed under.
        let mut drifted = GenesisConfig::standard();
        edit(&mut drifted.types.reserved, addr(&[9, 0, 9, 0, 9, 0, 9, 6]));

        match Engine::open(fsync_cfg(dir.path()), drifted) {
            Err(EngineError::GenesisReservedDrift(named)) => {
                assert_eq!(named, class, "the refusal must name the class that drifted");
            }
            Err(other) => panic!("expected GenesisReservedDrift({class:?}), got {other:?}"),
            Ok(_) => panic!("a drifted genesis reopen must be refused ({class:?})"),
        }
    }
}

/// The decl side of the same check: a journal sealed with one app-declared
/// type, reopened under a config declaring that same key with a DIFFERENT
/// registration, is refused at assembly. Nothing downstream would have caught
/// it — a daemon assembles no `Coordinator`, and the world dump would go on
/// enumerating that class from a registration the store never validated.
#[test]
fn drifted_app_decl_reopen_is_refused() {
    let dir = tempdir().expect("tempdir");
    let app_key = || enc(&[addr(&[9, 0, 9, 0, 9, 0, 8, 1])]);
    let declared = |idem: bool| TypeDecl {
        key: app_key(),
        reg: Registration { shape: Shape::Binary, idem, behaviors: BTreeSet::<Behavior>::new() },
    };

    let mut sealed = GenesisConfig::standard();
    sealed.types.decls = vec![declared(true)];
    {
        let engine = Engine::open(fsync_cfg(dir.path()), sealed).expect("fsync open");
        setup_doc(&engine);
        // As above: the checkpoint is what carries the sealed config forward.
        engine.kernel().checkpoint().expect("checkpoint succeeds");
    }

    // Valid on its own — an app may declare a Binary idem⊥ type — but not the
    // registration this journal sealed for that key.
    let mut drifted = GenesisConfig::standard();
    drifted.types.decls = vec![declared(false)];

    match Engine::open(fsync_cfg(dir.path()), drifted) {
        Err(EngineError::GenesisDeclDrift(d)) => {
            assert_eq!(d.key, app_key(), "the refusal names the decl the caller passed");
            assert!(!d.reg.idem, "…with the registration it passed, not the sealed one");
        }
        Err(other) => panic!("expected GenesisDeclDrift, got {other:?}"),
        Ok(_) => panic!("a drifted app decl must be refused"),
    }
}
