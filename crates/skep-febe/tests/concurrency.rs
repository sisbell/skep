//! Reentrancy under the concurrency the transport is invited to use (§8):
//! the handle is shared, `execute` is called from several threads at once,
//! and each call is still one operation with one linearization point.
//!
//! The interleaving is nondeterministic; the assertions are not. M2's applier
//! lock serializes commits and mints disjoint `Seq` ranges, and M3 mints
//! append-only addresses, so distinctness holds however the threads land —
//! no sleeps, no timing, no shared fixture between tests.

mod common;

use common::*;
use skep_address::Address;
use skep_content::Val;
use skep_febe::Op;
use skep_kernel::Seq;

const WRITERS: u8 = 8;

/// §8/A1: concurrent writes through one handle each get their own commit —
/// a distinct address and a distinct coordinate. Two callers handed the same
/// `Seq` would be two operations sharing one linearization point, which is
/// the property the whole surface is built to deliver.
#[test]
fn concurrent_writes_each_get_their_own_linearization_point() {
    let fx = setup();
    let doc = create_doc(&fx);
    let before = fx.op.log_position();

    // Each thread extracts its own `(Address, Seq)` before joining, so
    // nothing but plain data crosses back.
    let acks: Vec<(Address, Seq)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..WRITERS)
            .map(|i| {
                let doc = doc.clone();
                let op = &fx.op;
                let s = fx.s;
                scope.spawn(move || {
                    ack_addr(ex(
                        op,
                        s,
                        Op::Insert {
                            doc,
                            at: vp(1, 1),
                            values: vec![Val::new(vec![b'a' + i])],
                        },
                    ))
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("no writer panics")).collect()
    });

    assert_eq!(acks.len(), usize::from(WRITERS));
    for (i, (addr_a, at_a)) in acks.iter().enumerate() {
        for (addr_b, at_b) in &acks[i + 1..] {
            assert_ne!(addr_a, addr_b, "two concurrent inserts placed content at one address");
            assert_ne!(at_a, at_b, "two concurrent writes share one linearization point");
        }
    }
    assert!(
        fx.op.log_position() > before,
        "every concurrent write committed, so the log advanced past where they started"
    );
    for (_, at) in &acks {
        assert!(*at <= fx.op.log_position(), "no write acknowledges past the log head");
    }
}
