//! One cross-store lifecycle through the real kernel under `Fsync`:
//! create document → insert → retrieve → makelink → findlinks → version —
//! every seam the engine closes, exercised once end-to-end, then reopened
//! from the journal to show the observable state survives recovery. Store
//! semantics are NOT re-tested here (the stores' own suites own that); what
//! is tested is the assembly: that the drivers, folds, lifts, and accessors
//! compose over one world.

mod common;

use common::*;
use skep_content::Val;
use skep_discovery::LinkQuery;
use skep_engine::{Engine, EngineError, GenesisConfig};
use skep_links::HasLinks;
use skep_retrieval::{Query, Spec};
use tempfile::tempdir;

#[test]
fn cross_store_lifecycle_under_fsync() {
    let dir = tempdir().expect("tempdir");
    let expected = vec![b"x".to_vec(), b"y".to_vec(), b"z".to_vec()];

    let (doc, doc2, link, last_seq);
    {
        let engine =
            Engine::open(fsync_cfg(dir.path()), GenesisConfig::standard()).expect("fsync open");

        // M3: bootstrap → delegate → create (the account/document prologue).
        let (_acct, d) = setup_doc(&engine);
        doc = d;

        // M5+M4+M3 composite: insert three values at the head.
        let (_start, s_insert) = engine
            .vstream()
            .insert(
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
        let (l, s_link) = engine
            .linkstore()
            .makelink(
                &doc,
                vec![vspec(&doc, 1, 1)],
                vec![vspec(&doc, 2, 1)],
                vec![vspec(&doc, 3, 1)],
            )
            .expect("makelink succeeds");
        link = l;
        assert!(s_link > s_insert, "commit order is monotone across stores");

        // M8: the link is discoverable from the home document's region…
        let found = LinkQuery::new(engine.kernel())
            .findlinks_v(&doc, &[vspan(1, 1, 3)])
            .expect("findlinks succeeds");
        assert!(found.contains(&link), "the fresh link is discoverable from its home");

        // …and M7's raw read returns it verbatim.
        {
            let snap = engine.kernel().snapshot();
            assert!(snap.world().links().readlink(&link).is_some());
        }

        // M5+M3: version — a copy-on-write fork sharing the content.
        let (d2, _s_version) = engine.vstream().version(USER, &doc).expect("version succeeds");
        doc2 = d2;
        {
            let snap = engine.kernel().snapshot();
            let q = Query::new(&snap);
            let delivery = q
                .retrieve_v(&[Spec { doc: doc2.clone(), span: vspan(1, 1, 3) }])
                .unwrap_or_else(|e| panic!("retrieve of the version failed: {e}"));
            assert_eq!(delivered_bytes(&delivery), expected, "the version shares the content");
        }

        // The same I-addresses arranged in the version make the link
        // discoverable from it too — cross-store transclusion discovery.
        let found2 = LinkQuery::new(engine.kernel())
            .findlinks_v(&doc2, &[vspan(1, 1, 3)])
            .expect("findlinks over the version succeeds");
        assert!(found2.contains(&link), "the link is discoverable through the transclusion");

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
        for d in [&doc, &doc2] {
            let delivery = q
                .retrieve_v(&[Spec { doc: (*d).clone(), span: vspan(1, 1, 3) }])
                .unwrap_or_else(|e| panic!("retrieve after recovery failed: {e}"));
            assert_eq!(delivered_bytes(&delivery), expected);
        }
        assert!(snap.world().links().readlink(&link).is_some());

        let found = LinkQuery::new(engine.kernel())
            .findlinks_v(&doc, &[vspan(1, 1, 3)])
            .expect("findlinks after recovery succeeds");
        assert!(found.contains(&link));
    }
}

/// Reopening a checkpointed journal under an edited genesis config trips the
/// engine's drift wire (M2's byte-identical-genesis contract, checked at
/// assembly) instead of silently splitting the two registry consumers.
#[test]
fn drifted_genesis_reopen_is_refused() {
    let dir = tempdir().expect("tempdir");
    {
        let engine =
            Engine::open(fsync_cfg(dir.path()), GenesisConfig::standard()).expect("fsync open");
        setup_doc(&engine);
        engine.kernel().checkpoint().expect("checkpoint succeeds");
    }

    // Valid on its own, but not the config this journal was sealed under.
    let mut reserved = GenesisConfig::standard().reserved;
    reserved.retired = a(&[9, 0, 9, 0, 9, 0, 9, 6]);
    let drifted = GenesisConfig { reserved, decls: Vec::new() };

    match Engine::open(fsync_cfg(dir.path()), drifted) {
        Err(EngineError::GenesisDrift(_)) => {}
        Err(other) => panic!("expected GenesisDrift, got {other:?}"),
        Ok(_) => panic!("a drifted genesis reopen must be refused"),
    }
}
