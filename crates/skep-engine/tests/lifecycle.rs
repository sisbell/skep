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
use skep_engine::Engine;
use skep_links::{HasLinks, SlotArg};
use skep_retrieval::{Query, Spec};
use tempfile::tempdir;

#[test]
fn cross_store_lifecycle_under_fsync() {
    let dir = tempdir().expect("tempdir");
    let expected = vec![b"x".to_vec(), b"y".to_vec(), b"z".to_vec()];

    let (doc, version_doc, link, last_seq);
    {
        let engine = Engine::open(fsync_cfg(dir.path())).expect("fsync open");

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
        let (vd, _version_seq) = engine.vstream().version(USER, &doc, None).expect("version succeeds");
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
        let engine = Engine::open(fsync_cfg(dir.path())).expect("reopen");
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
