//! The standalone `write` — M2 contract 3's transact-wrapped form,
//! `test-hooks` builds only — and the composite shape production uses
//! instead: a write commits and reads back through a snapshot, a double
//! write is refused verbatim with the first value kept, and `stage_write`
//! composes into one transaction off the working slice. And the routing
//! assertion at `write`'s door: a debug build panics on a non-content
//! address before key derivation, a release build writes one that has a
//! document as given, and either door's panic is located at the line that
//! passed the address in.

use skep_content::{stage_write, write, ContentError, ContentStore, HasContent, Val};
use skep_namespace::M3State;

use crate::common::*;

// ---- §C the standalone op over M2 ----

#[test]
fn standalone_write_commits_and_reads_back_through_a_snapshot() {
    let k = mem_kernel();
    let a1 = ca(1);
    let (stored, seq) = write(&k, &a1, val(b"alpha")).expect("fresh write commits");
    assert_eq!(stored, *a1.tumbler());
    assert_eq!(k.current_seq(), seq);
    // Bind the snapshot first; the &Val borrows THROUGH it (§B).
    let s = k.snapshot();
    assert_eq!(s.seq(), seq);
    let c = s.world().content();
    assert!(c.contains(a1.tumbler()));
    assert_eq!(c.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"alpha"[..]));
    assert_eq!(c.len(), 1);
}

#[test]
fn standalone_write_rejects_a_double_write_and_preserves_the_first_value() {
    // S0(b) through the composite: the second write is a clean typed
    // rejection (surfaced verbatim per M2), nothing committed, the stored
    // value untouched.
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
    assert_eq!(c.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"first"[..]));
}

#[test]
fn stage_write_composes_into_one_transaction_off_the_working_slice() {
    // The M5-shape composite (§Dependencies & seams): m records staged via
    // stage_write against stg.working().content() in ONE transact, committed
    // under one marker; the working slice reflects each push, so an
    // intra-composite double-stage is rejected.
    let k = mem_kernel();
    let d = a(&[1, 0, 1, 0, 1]);
    let a1 = ca(1);
    let a2 = ca(2);
    let (_, seq) = k
        .transact(&[M3State::content_lock_key(&d)], |stg| {
            let r1 = stage_write(stg.working().content(), &a1, val(b"one"))?;
            stg.push(r1.into());
            // working() reflects the push: re-staging a1 here is rejected.
            assert!(matches!(
                stage_write(stg.working().content(), &a1, val(b"dup")),
                Err(ContentError::AlreadyStored(t)) if t == *a1.tumbler()
            ));
            let r2 = stage_write(stg.working().content(), &a2, val(b"two"))?;
            stg.push(r2.into());
            // Pins the closure's error parameter: `?` on stage_write only
            // constrains `E: From<ContentError>`, which infers nothing.
            Ok::<(), ContentError>(())
        })
        .expect("composite commits");
    let s = k.snapshot();
    assert_eq!(s.seq(), seq);
    let c = s.world().content();
    assert_eq!(c.len(), 2);
    assert_eq!(c.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"one"[..]));
    assert_eq!(c.value_at(a2.tumbler()).map(Val::as_bytes), Some(&b"two"[..]));
}

// ---- Open build decision #4: the routing assertion at write's door ----

#[test]
#[cfg_attr(debug_assertions, should_panic(expected = "content routing: write"))]
#[cfg_attr(not(debug_assertions), should_panic(expected = "content address ⇒ zeros = 3"))]
fn write_panics_on_a_non_content_address_routing_first() {
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
/// this call alone, the previous hook put back after it.
fn panic_file(f: impl FnOnce()) -> String {
    use std::cell::RefCell;
    use std::panic::{self, AssertUnwindSafe};
    thread_local! {
        static FILE: RefCell<Option<String>> = const { RefCell::new(None) };
    }
    let previous = panic::take_hook();
    panic::set_hook(Box::new(|info| {
        let file = info.location().map(|l| l.file().to_owned());
        FILE.with(|slot| *slot.borrow_mut() = file);
    }));
    let outcome = panic::catch_unwind(AssertUnwindSafe(f));
    panic::set_hook(previous);
    assert!(outcome.is_err(), "the call was expected to panic");
    FILE.with(|slot| slot.borrow_mut().take()).expect("a panic has a location")
}

#[test]
fn a_routing_panic_is_located_at_the_line_that_passed_the_address_in() {
    // §C: both doors are `#[track_caller]`, so a mis-routed address panics
    // at the caller's line — in this file — and not inside M4. A debug
    // build's routing assertion fires through either door; in release it is
    // compiled out, `stage_write` admits the address, and `write`'s
    // `.expect` fires at the caller's line instead.
    let k = mem_kernel();
    let account = a(&[1, 0, 1]);
    let through_write = panic_file(|| {
        let _ = write(&k, &account, val(b"x"));
    });
    assert_eq!(through_write, file!());
    if cfg!(debug_assertions) {
        let through_stage = panic_file(|| {
            let _ = stage_write(&ContentStore::default(), &account, val(b"x"));
        });
        assert_eq!(through_stage, file!());
    }
}
