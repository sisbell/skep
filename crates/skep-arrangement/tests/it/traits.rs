//! The public values' standard traits, which a foreign crate cannot add:
//! `Hash` agreeing with `Eq`, the V-span reading, the lent run walk, the
//! `Copy` handle, and the `Send + Sync` the request values and every refusal
//! carry.

use skep_address::{Address, Span};
use skep_arrangement::{
    as_ordinal_vspan, is_ordinal_vspan, seat_link, Base, Caller, CopyError, DeleteError, Deposit,
    HasM5, InsertError, PublishError, RearrangeError, Run, RunError, Runs, SeatError, SegmentRun,
    Shot, ShotRun, ShotTerms, VPos, VSpec, VersionError, Vstream,
};

use crate::common::*;

#[test]
fn the_public_values_key_a_hash_set_by_the_equality_they_compare_on() {
    // A foreign crate cannot add `Hash` to M5's types (the orphan rule), so
    // the promise is witnessed from one: each public value keys a set, and a
    // repeat collapses there exactly as `==` says it should — the agreement
    // between `Hash` and `Eq` every set and map rests on.
    fn one_and_another<T: std::hash::Hash + Eq + Clone + std::fmt::Debug>(one: T, another: T) {
        assert_ne!(one, another);
        let set: std::collections::HashSet<T> = [one.clone(), another, one].into_iter().collect();
        assert_eq!(set.len(), 2, "{set:?}");
    }
    let run = |start: &Address, width: u32| Run::new(start.clone(), n(width)).expect("a run");
    // Two runs sharing a start are two runs: a run is its start AND width.
    one_and_another(run(&ca(1), 2), run(&ca(1), 3));
    one_and_another(RunError::ZeroWidth, RunError::NotAnElementPosition);
    one_and_another(vp(1, 2), vp(2, 1));
    one_and_another(
        VSpec { source: doc1(), span: vspan(1, 1, 2) },
        VSpec { source: doc2(), span: vspan(1, 1, 2) },
    );
    one_and_another(P1, Caller::System);
    one_and_another(declared(), Deposit::Undeclared);
    // A declaration is the type it names: two classes are two declarations.
    one_and_another(Deposit::Declared(enroll_ty()), Deposit::Declared(retire_ty()));
    one_and_another(shot_run(&pdoc(), &pca(1), 1), shot_run(&pdoc(), &pca(1), 2));
    one_and_another(base(&pdoc(), 1), base(&pdoc(), 2));
    one_and_another(
        Shot { base: None, draft: None, runs: vec![] },
        Shot { base: Some(base(&pdoc(), 0)), draft: None, runs: vec![] },
    );
    // The birth bit is part of the terms: a base extent of zero and no base
    // at all are two terms, and they key two entries.
    one_and_another(
        ShotTerms {
            placed: n(2),
            base_extent: None,
        },
        ShotTerms {
            placed: n(2),
            base_extent: Some(n(0)),
        },
    );
    // A segment run is its class AND its run: one run in two classes keys
    // two entries.
    one_and_another(
        SegmentRun::Value(run(&ca(1), 1)),
        SegmentRun::Window(run(&ca(1), 1)),
    );
}

#[test]
fn the_v_span_reading_hands_a_foreign_caller_the_parts_it_would_otherwise_index() {
    // The reader is public so no neighbour re-extracts a V-span's parts by
    // position: the three quantities come back named, and the content clause
    // the neighbours add is answered by the reading itself. The reading is a
    // VIEW into the span it read, so the span outlives it.
    let content = vspan(1, 7, 4);
    let reading = as_ordinal_vspan(&content).expect("an ordinal V-span reads");
    assert_eq!((reading.subspace, reading.ordinal, reading.count), (&n(1), &n(7), &n(4)));
    assert!(reading.is_content());
    assert!(!as_ordinal_vspan(&vspan(2, 1, 1)).expect("a link V-span reads").is_content());
    // What the verdict refuses, the reading refuses: one shape, two forms.
    let action_point_1 = Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12-legal");
    assert!(as_ordinal_vspan(&action_point_1).is_none());
    assert!(!is_ordinal_vspan(&action_point_1));
}

#[test]
fn the_run_reads_lend_a_walk_that_knows_its_length_and_both_ends() {
    // `content_runs`/`link_runs` lend the stored runs as `Runs`, whose
    // backing is hidden and to which a foreign crate can add no trait — so
    // what the loan promises is witnessed from one: a nameable type, the
    // exact length, the reverse walk and fusing, `Debug`, and `Send + Sync`,
    // which the type has because of what it borrows and which a caller
    // handing a walk to another thread depends on without any signature
    // saying so.
    fn lends<'a, I>(walk: I) -> usize
    where
        I: ExactSizeIterator<Item = &'a Run>
            + DoubleEndedIterator
            + std::iter::FusedIterator
            + std::fmt::Debug
            + Send
            + Sync,
    {
        walk.len()
    }
    let k = mem_kernel();
    insert_abc(&k);
    seat_link(&k, &doc1(), &a(&[1, 0, 1, 0, 1, 0, 2, 1])).expect("seat commits");
    let s = k.snapshot();
    let m5 = s.world().m5();
    let content: Runs<'_> = m5.content_runs(&doc1());
    assert_eq!(format!("{content:?}"), "Runs { .. }", "the cursor, not the runs");
    assert_eq!(lends(content), m5.content_run_count(&doc1()));
    assert_eq!(lends(m5.link_runs(&doc1())), m5.link_run_count(&doc1()));
}

#[test]
fn the_op_handle_copies_as_the_reference_it_is() {
    // Two borrows — the kernel and, on an attested handle, the attestation:
    // a foreign caller holding the handle may hold it twice without asking
    // the kernel again, and the promise is a trait only this crate can
    // supply. Using `vs` after it has been copied out
    // is the compile-time proof; the insert makes the test earn its name.
    fn copies<T: Copy>(_: T) {}
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    copies(vs);
    vs.insert(P1, &doc1(), vp(1, 1), vec![val(b"a")], Deposit::Undeclared)
        .expect("the handle is still usable after being copied out");
}

#[test]
fn the_request_values_and_every_refusal_cross_threads() {
    // A caller moves M5's request values and refusals across threads — a
    // refusal boxed into `Box<dyn Error + Send + Sync>`, a shot handed to a
    // worker — and no signature says they may: each is `Send` and `Sync`
    // because of what it holds, and the refusals hold M3's `MintError` and
    // M4's `ContentError`, so a change in either crate could revoke the
    // promise with no M5 signature moving. Witnessed from a foreign crate,
    // so the build that breaks it is this one. `M5State` and `M5Rec` — and
    // `Run` and `ShotTerms` inside them — are witnessed already by every
    // test world, `WorldState` asking `Send + Sync + 'static` of the slice
    // and its record.
    fn crosses<T: Send + Sync + 'static>() {}
    fn refusal<E: std::error::Error + Send + Sync + 'static>() {}
    crosses::<VPos>();
    crosses::<VSpec>();
    crosses::<Caller>();
    crosses::<Deposit>();
    crosses::<ShotRun>();
    crosses::<Base>();
    crosses::<Shot>();
    crosses::<SegmentRun>();
    refusal::<RunError>();
    refusal::<InsertError>();
    refusal::<CopyError>();
    refusal::<DeleteError>();
    refusal::<RearrangeError>();
    refusal::<VersionError>();
    refusal::<PublishError>();
    refusal::<SeatError>();
}
