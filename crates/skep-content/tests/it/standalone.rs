//! The standalone `write` and `write_stretch` — M2 contract 3's
//! transact-wrapped forms, `test-hooks` builds only — and the composite shape
//! production uses instead: a write commits and reads back through a
//! snapshot, a stretch commits and every address inside it reads back, a
//! second write at one address or inside a stretch is refused verbatim with
//! the first bytes kept, an overlapping stretch is refused verbatim, and the
//! stage doors compose into one transaction off the working slice. And the
//! routing assertion at both doors: a debug build panics on a non-content
//! address before key derivation, a release build writes one that has a
//! document as given, and either door's panic is located at the line that
//! passed the address in.

use skep_address::Nat;
use skep_content::{
    stage_stretch, stage_write, write, write_stretch, ContentError, ContentStore, HasContent,
};
use skep_namespace::M3State;

use crate::common::*;

// ---- §C the standalone ops over M2 ----

#[test]
fn write_commits_and_reads_back_through_a_snapshot() {
    let k = mem_kernel();
    let a1 = ca(1);
    let (stored, seq) = write(&k, &a1, val(b"alpha")).expect("fresh write commits");
    assert_eq!(stored, *a1.tumbler());
    assert_eq!(k.current_seq(), seq);
    // Bind the snapshot first; the piece borrows THROUGH it (§B).
    let s = k.snapshot();
    assert_eq!(s.seq(), seq);
    let c = s.world().content();
    assert!(c.contains(a1.tumbler()));
    assert_eq!(read(c, a1.tumbler()), Some(b"alpha".to_vec()));
    assert_eq!(c.len(), 1);
}

#[test]
fn write_stretch_commits_a_run_and_every_address_inside_it_reads_back() {
    // ops.rs (`write_stretch`): the twin of `write` for a stretch — one
    // transaction under the same lock key, through `stage_stretch`'s door —
    // commits one record and one entry, and every address of the run reads
    // back its byte as a one-byte piece, the run read covering the whole.
    let k = mem_kernel();
    let first = ca(3);
    let (stored, seq) = write_stretch(&k, &first, bytes(b"hello")).expect("fresh stretch commits");
    assert_eq!(stored, *first.tumbler());
    assert_eq!(k.current_seq(), seq);
    let s = k.snapshot();
    assert_eq!(s.seq(), seq);
    let c = s.world().content();
    assert_eq!(c.len(), 1, "one entry for the run");
    for (ordinal, byte) in (3..).zip(b"hello") {
        assert!(c.contains(ca(ordinal).tumbler()));
        assert_eq!(read_arm(c, ca(ordinal).tumbler()), Some((true, vec![*byte])));
    }
    assert!(!c.contains(ca(8).tumbler()), "the reach holds nothing");
    assert_eq!(
        pieces_of(c, first.tumbler(), 5),
        (vec![(true, b"hello".to_vec())], true),
        "the run read lends the stretch whole"
    );
}

#[test]
fn write_rejects_a_second_write_at_one_address_and_preserves_the_first_value() {
    // S0(b) through `write`'s own transaction: the second write is a clean
    // typed rejection (surfaced verbatim per M2), nothing committed, the
    // stored value untouched.
    let k = mem_kernel();
    let a1 = ca(1);
    write(&k, &a1, val(b"first")).expect("fresh write commits");
    let seq_before = k.current_seq();
    let err = rejected(write(&k, &a1, val(b"second")));
    assert_eq!(err, ContentError::AlreadyStored(a1.tumbler().clone()));
    assert_eq!(k.current_seq(), seq_before);
    let s = k.snapshot();
    let c = s.world().content();
    assert_eq!(c.len(), 1);
    assert_eq!(read(c, a1.tumbler()), Some(b"first".to_vec()));
}

#[test]
fn write_stretch_rejects_a_covered_first_address_an_overlap_and_an_empty_run_verbatim() {
    // S0(b) through `write_stretch`'s own transaction, in `stage_stretch`'s
    // order: a stretch of no bytes is `EmptyStretch`; a first address inside
    // a committed stretch, or at a committed value, is `AlreadyStored`; a run
    // reaching over a committed entry is `Overlap`; and `write` at an address
    // inside a committed stretch is `AlreadyStored` too. Each a typed
    // rejection surfaced verbatim, nothing committed, the stored bytes
    // untouched.
    let k = mem_kernel();
    write_stretch(&k, &ca(1), bytes(b"abc")).expect("1..=3 commits");
    write(&k, &ca(10), val(b"atom")).expect("10 commits");
    let seq_before = k.current_seq();
    assert_eq!(rejected(write_stretch(&k, &ca(20), bytes(b""))), ContentError::EmptyStretch);
    assert_eq!(
        rejected(write_stretch(&k, &ca(2), bytes(b"xy"))),
        ContentError::AlreadyStored(ca(2).tumbler().clone()),
        "inside the committed stretch"
    );
    assert_eq!(
        rejected(write_stretch(&k, &ca(10), bytes(b"xy"))),
        ContentError::AlreadyStored(ca(10).tumbler().clone()),
        "at the committed value"
    );
    assert_eq!(
        rejected(write_stretch(&k, &ca(8), bytes(b"xyz"))),
        ContentError::Overlap { first: ca(8).tumbler().clone(), reach: ca(11).tumbler().clone() },
        "8..=10 reaches over the value at 10"
    );
    assert_eq!(
        rejected(write(&k, &ca(3), val(b"x"))),
        ContentError::AlreadyStored(ca(3).tumbler().clone()),
        "a write inside the committed stretch"
    );
    assert_eq!(k.current_seq(), seq_before, "nothing committed");
    let s = k.snapshot();
    let c = s.world().content();
    assert_eq!(c.len(), 2);
    assert_eq!(read(c, ca(2).tumbler()), Some(b"b".to_vec()));
    assert_eq!(read(c, ca(10).tumbler()), Some(b"atom".to_vec()));
    // A run ending exactly at the value commits: the reach is not held.
    drop(s);
    assert!(write_stretch(&k, &ca(4), bytes(b"defghi")).is_ok(), "4..=9 touches 10 and no more");
}

#[test]
fn stage_write_composes_into_one_transaction_off_the_working_slice() {
    // The M5-shape composite (§Dependencies & seams): m records staged via
    // the stage doors against stg.working().content() in ONE transact,
    // committed under one marker; the working slice reflects each push, so a
    // second stage of one address within the composite is rejected — a write
    // at a staged stretch's interior included.
    let k = mem_kernel();
    let home = a(&[1, 0, 1, 0, 1]);
    let a1 = ca(1);
    let a2 = ca(2);
    let s3 = ca(3);
    let (_, seq) = k
        .transact(&[M3State::content_lock_key(&home)], |stg| {
            let r1 = stage_write(stg.working().content(), a1.clone(), val(b"one"))?;
            stg.push(r1.into());
            // working() reflects the push: re-staging a1 here is rejected.
            assert!(matches!(
                stage_write(stg.working().content(), a1.clone(), val(b"again")),
                Err(ContentError::AlreadyStored(t)) if t == *a1.tumbler()
            ));
            let r2 = stage_write(stg.working().content(), a2.clone(), val(b"two"))?;
            stg.push(r2.into());
            let r3 = stage_stretch(stg.working().content(), s3.clone(), bytes(b"xyz"))?;
            stg.push(r3.into());
            // working() reflects the stretch: its interior is covered.
            assert!(matches!(
                stage_write(stg.working().content(), ca(4), val(b"inside")),
                Err(ContentError::AlreadyStored(t)) if t == *ca(4).tumbler()
            ));
            // Pins the closure's error parameter: `?` on the doors only
            // constrains `E: From<ContentError>`, which infers nothing.
            Ok::<(), ContentError>(())
        })
        .expect("composite commits");
    let s = k.snapshot();
    assert_eq!(s.seq(), seq);
    let c = s.world().content();
    assert_eq!(c.len(), 3);
    assert_eq!(read(c, a1.tumbler()), Some(b"one".to_vec()));
    assert_eq!(read(c, a2.tumbler()), Some(b"two".to_vec()));
    assert!(c.pieces(s3.tumbler(), &Nat::from(3u32)).covered());
    assert_eq!(read(c, ca(5).tumbler()), Some(b"z".to_vec()));
}

// ---- Open build decision #4: the routing assertion at the doors ----

#[test]
#[cfg_attr(debug_assertions, should_panic(expected = "content routing: write"))]
#[cfg_attr(not(debug_assertions), should_panic(expected = "content address ⇒ zeros = 3"))]
fn write_panics_on_an_address_with_no_document_routing_first_in_debug() {
    // §C: a zeros = 1 input is an internal invariant violation, never a
    // domain rejection. A debug build's routing assertion fires BEFORE key
    // derivation (its message, not the `.expect`'s); in release it is
    // compiled out and the `document_of` `.expect` — the trusted-address
    // contract — fires.
    let k = mem_kernel();
    let account = a(&[1, 0, 1]);
    let _ = write(&k, &account, val(b"x"));
}

#[test]
#[cfg_attr(debug_assertions, should_panic(expected = "content routing: write_stretch"))]
#[cfg_attr(not(debug_assertions), should_panic(expected = "content address ⇒ zeros = 3"))]
fn write_stretch_panics_on_an_address_with_no_document_routing_first_in_debug() {
    // ops.rs (`write_stretch`'s `# Panics`): as `write` does, under its own
    // door's name.
    let k = mem_kernel();
    let account = a(&[1, 0, 1]);
    let _ = write_stretch(&k, &account, bytes(b"x"));
}

#[test]
#[cfg_attr(debug_assertions, should_panic(expected = "content routing: write"))]
fn write_trusts_a_document_level_address_in_release_and_panics_on_it_in_debug() {
    // §C: `write`'s `.expect` catches only an address with no document
    // (zeros < 2). A document-level address has one — itself — so it passes
    // the `.expect`: a debug build's routing assertion is what stops it, and
    // a release build, that assertion compiled out, writes it as given. The
    // trusted-address contract is the caller's, checked whole in debug builds
    // only.
    let k = mem_kernel();
    let doc = a(&[1, 0, 1, 0, 1]);
    let (stored, _) = write(&k, &doc, val(b"x")).expect("release trusts the caller's address");
    assert_eq!(stored, *doc.tumbler());
    let s = k.snapshot();
    assert!(s.world().content().contains(doc.tumbler()), "release writes the address as given");
}

/// The source file a panic inside `f` is located at, read by a hook set for
/// this call alone, the previous hook put back after it. `#[track_caller]`,
/// so a call that did not panic is reported at the test's line.
#[track_caller]
fn panic_file(f: impl FnOnce()) -> String {
    use std::cell::Cell;
    use std::panic::{self, AssertUnwindSafe};
    thread_local! {
        static FILE: Cell<Option<String>> = const { Cell::new(None) };
    }
    let previous = panic::take_hook();
    panic::set_hook(Box::new(|info| FILE.set(info.location().map(|l| l.file().to_owned()))));
    let outcome = panic::catch_unwind(AssertUnwindSafe(f));
    panic::set_hook(previous);
    assert!(outcome.is_err(), "the call was expected to panic");
    FILE.take().expect("a panic has a location")
}

#[test]
fn a_panic_at_either_door_is_located_at_the_line_that_passed_the_address_in() {
    // §C: every door is `#[track_caller]`, so a mis-routed address panics
    // at the caller's line — in this file — and not inside M4. A debug
    // build's routing assertion fires through each door; in release it is
    // compiled out, the stage doors admit the address, and the standalone
    // ops' `.expect` fires at the caller's line instead.
    let k = mem_kernel();
    let account = a(&[1, 0, 1]);
    let through_write = panic_file(|| {
        let _ = write(&k, &account, val(b"x"));
    });
    assert_eq!(through_write, file!());
    let through_write_stretch = panic_file(|| {
        let _ = write_stretch(&k, &account, bytes(b"x"));
    });
    assert_eq!(through_write_stretch, file!());
    if cfg!(debug_assertions) {
        let through_stage = panic_file(|| {
            let _ = stage_write(&ContentStore::default(), account.clone(), val(b"x"));
        });
        assert_eq!(through_stage, file!());
        let through_stage_stretch = panic_file(|| {
            let _ = stage_stretch(&ContentStore::default(), account, bytes(b"x"));
        });
        assert_eq!(through_stage_stretch, file!());
    }
}
