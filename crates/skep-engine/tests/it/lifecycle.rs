//! One cross-store lifecycle through the real kernel under `Fsync`:
//! create document → insert → retrieve → makelink → findlinks → version —
//! every seam the engine closes, exercised once end-to-end, then reopened
//! from the journal to show the observable state survives recovery. Store
//! semantics are NOT re-tested here (the stores' own suites own that); what
//! is tested is the assembly: that the drivers, folds, lifts, and accessors
//! compose over one world.

use crate::common;

use common::*;
use skep_address::{Address, Nat};
use skep_arrangement::AsOf;
use skep_arrangement::{deposit_class_types, Deposit, VPos};
use skep_content::Val;
use skep_discovery::findlinks_v_on;
use skep_engine::{Engine, World};
use skep_links::{HasLinks, SlotArg};
use skep_retrieval::{Flagged, LineNumbers, Query, Spec};
use tempfile::tempdir;

/// The TOTAL predicate, admitting every home: this lifecycle is a harness,
/// answering for no reader class, and says so where it reads.
fn every_home(_: &Address) -> bool {
    true
}

/// Returns the line read's request over `text`, and the answer owed it.
///
/// The request lists every position up to one past the end and every line
/// up to one past the count. The answer is a count over the bytes a reader
/// of everything is delivered: a position lies on the line one more than the
/// line breaks below it, a line starts at the first position lying on it,
/// and text after the last line break is a line.
fn lines_counted(text: &[u8]) -> (Vec<VPos>, Vec<Nat>, LineNumbers) {
    let line_of = |at: usize| 1 + text[..at - 1].iter().filter(|&&b| b == b'\n').count();
    let count = line_of(text.len() + 1) - usize::from(text.last().is_none_or(|&b| b == b'\n'));
    let flagged = |number: usize| Flagged { number: Nat::from(number), masked: false };
    let positions: Vec<usize> = (1..=text.len() + 1).collect();
    let lines: Vec<usize> = (0..=count + 1).collect();
    let answer = LineNumbers {
        positions: positions.iter().map(|&at| flagged(line_of(at))).collect(),
        lines: lines
            .iter()
            .map(|&line| (1..=text.len()).find(|&at| line_of(at) == line))
            .map(|start| {
                start.map(|at| Flagged { number: VPos::content(Nat::from(at)), masked: false })
            })
            .collect(),
        count: flagged(count),
    };
    let positions = positions.into_iter().map(|at| VPos::content(Nat::from(at))).collect();
    (positions, lines.into_iter().map(Nat::from).collect(), answer)
}

/// The drivers, folds, lifts and accessors compose over ONE world, and the
/// observable state that composition produced comes back after the journal is
/// reopened: the same content, the same line numbers, the same version, the
/// same link, and the same log position, replayed rather than remembered.
/// The line numbers are M4's line-break counts read through M6, which no
/// dump shows: before the reopen and after it they are a count over the
/// delivered text.
#[test]
fn a_cross_store_lifecycle_survives_a_journal_reopen() {
    let dir = tempdir().expect("tempdir");
    // Three per-byte values, one insert: one stretch in M4, delivered as one
    // byte-run item. The middle one is a line break, so the document is two
    // lines.
    let expected = vec![b"x\nz".to_vec()];
    let (positions, lines, numbered) = lines_counted(&expected.concat());

    let (doc, version_member, link, last_seq);
    {
        let engine = Engine::open(fsync_cfg(dir.path())).expect("fsync open");

        // M3: bootstrap → delegate → create (the account/document prologue).
        // The document is the account's PUBLISHED home: it is the one owned
        // source the version step below may fork (PUB-2.9), and content
        // enters it by a DECLARED deposit at its fresh positions (PUB-2.59).
        let (_acct, d) = setup_home(&engine);
        doc = d;

        // M5+M4+M3 composite: deposit three values at the head, declared
        // under ENROLL's type — the first member of M5's set (PUB-2.11,
        // RES-261); the bytes are prose, PUB-2.60's residue, which the door
        // admits on the type alone.
        let (_start, insert_seq) = engine
            .vstream()
            .insert(
                OWNER,
                &doc,
                vp(1, 1),
                vec![Val::new(vec![b'x']), Val::new(vec![b'\n']), Val::new(vec![b'z'])],
                Deposit::Declared(deposit_class_types()[0].clone()),
                AsOf::Typed(engine.kernel().current_seq()),
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
            // The line read, off the same snapshot: a count over that text.
            assert_eq!(q.line_numbers(&doc, &positions, &lines), Ok(numbered.clone()));
        }

        // M7+M3+M5 composite: an open content link over the inserted content.
        let (l, link_seq) = engine
            .linkstore(&World::visible_to(OWNER))
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
        let found_in_home =
            findlinks_v_on(&engine.kernel().snapshot(), &doc, &[vspan(1, 1, 3)], &every_home)
                .expect("findlinks succeeds");
        assert!(found_in_home.contains(&link), "the fresh link is discoverable from its home");

        // …and M7's raw read returns it verbatim.
        {
            let snap = engine.kernel().snapshot();
            assert!(snap.world().links().readlink(&link).is_some());
        }

        // M5+M3: version — a copy-on-write fork sharing the content.
        let (vm, _version_seq) =
            engine.vstream().version(USER, &doc, None).expect("version succeeds");
        version_member = vm;
        {
            let snap = engine.kernel().snapshot();
            let q = Query::new(&snap);
            let delivery = q
                .retrieve_v(&[Spec { doc: version_member.clone(), span: vspan(1, 1, 3) }])
                .unwrap_or_else(|e| panic!("retrieve of the version failed: {e}"));
            assert_eq!(delivered_bytes(&delivery), expected, "the version shares the content");
            assert_eq!(
                q.line_numbers(&version_member, &positions, &lines),
                Ok(numbered.clone()),
                "and so its line numbers"
            );
        }

        // The same I-addresses arranged in the version make the link
        // discoverable from it too — cross-store transclusion discovery.
        let found_in_version = findlinks_v_on(
            &engine.kernel().snapshot(),
            &version_member,
            &[vspan(1, 1, 3)],
            &every_home,
        )
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
        for d in [&doc, &version_member] {
            let delivery = q
                .retrieve_v(&[Spec { doc: (*d).clone(), span: vspan(1, 1, 3) }])
                .unwrap_or_else(|e| panic!("retrieve after recovery failed: {e}"));
            assert_eq!(delivered_bytes(&delivery), expected);
            assert_eq!(
                q.line_numbers(d, &positions, &lines),
                Ok(numbered.clone()),
                "a reopened world numbers its lines as the one that wrote them did"
            );
        }
        assert!(snap.world().links().readlink(&link).is_some());

        let found_in_home = findlinks_v_on(&snap, &doc, &[vspan(1, 1, 3)], &every_home)
            .expect("findlinks after recovery succeeds");
        assert!(found_in_home.contains(&link));
    }
}
