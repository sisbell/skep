//! Reentrancy under the concurrency the transport is invited to use (§8):
//! the handle is shared, `execute` is called from several threads at once,
//! and each call is still one operation with one linearization point.
//!
//! The interleaving is nondeterministic; the assertions are not. M2's applier
//! lock serializes commits and mints disjoint `Seq` ranges, and M3 mints
//! append-only addresses, so distinctness holds however the threads land —
//! no sleeps, no timing, no shared fixture between tests.
//!
//! ONE assertion is about the interleaving itself: the first-mint race asserts
//! that BOTH commit orders occurred, and runs its rounds on, to a cap, until
//! they have. Every per-round assertion there holds whichever thread wins.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::common;

use common::*;
use skep_address::Address;
use skep_arrangement::published_target;
use skep_content::Val;
use skep_febe::{Deposit, Op, OpKind, OperationSurface, SessionId};
use skep_kernel::{Kernel, Seq};
use skep_namespace::{HasM3, PrincipalId};

const WRITERS: u8 = 8;

/// §8/A1: concurrent writes through one handle each get their own commit —
/// a distinct address and a distinct coordinate. Two callers handed the same
/// `Seq` would be two operations sharing one linearization point, which is
/// the property the whole surface is built to deliver.
#[test]
fn concurrent_writes_each_get_their_own_linearization_point() {
    let fx = setup();
    let doc = create_doc(&fx);
    let before = fx.febe.log_position();

    // Each thread extracts its own `(Address, Seq)` before joining, so
    // nothing but plain data crosses back.
    let acks: Vec<(Address, Seq)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..WRITERS)
            .map(|i| {
                let doc = doc.clone();
                let febe = &fx.febe;
                let user = fx.user;
                scope.spawn(move || {
                    ack_addr(ex(
                        febe,
                        user,
                        Op::Insert {
                            doc,
                            at: vp(1, 1),
                            values: vec![Val::new(vec![b'a' + i])],
                            deposit: Deposit::Undeclared,
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
        fx.febe.log_position() > before,
        "every concurrent write committed, so the log advanced past where they started"
    );
    for (_, at) in &acks {
        assert!(*at <= fx.febe.log_position(), "no write acknowledges past the log head");
    }
}

/// One fresh EMPTY account under the genesis node, seated as `setup` seats
/// USER's — the peeked next-form prefix, delegated under the bootstrap
/// session — and nothing minted in it.
fn seat_empty_account(febe: &OperationSurface<World>, boot: SessionId, id: PrincipalId) -> Address {
    let (prefix, _) = maybe_addr(ex(febe, boot, Op::NextAccountPrefix { parent: node1() }));
    let prefix = prefix.expect("the genesis node has a delegable next-form prefix");
    ack_addr(ex(febe, boot, Op::Delegate { new_prefix: prefix.tumbler().clone(), new_id: id })).0
}

/// The engine's read predicate in miniature, for a door whose world derives
/// none (`common`'s `World` admits every read until a test seeds a refusal):
/// published ∨ the owner's own, off the kernel's head. Under it the guest
/// reads the published documents alone, so what it is served and what it is
/// withheld is a read of the bit the mint journaled. Total, and READABLE for
/// an address M3 never registered, as `with_read_predicate` demands.
fn published_or_own(
    kernel: Arc<Kernel<World>>,
) -> impl Fn(Option<PrincipalId>, &Address) -> bool + Send + Sync + 'static {
    move |principal, doc| {
        let head = kernel.snapshot();
        let m3 = head.world().m3();
        !m3.is_registered_document(doc)
            || published_target(m3, doc)
            || principal.is_some_and(|id| m3.is_effective_owner(id, doc))
    }
}

/// PUB-8.21 BELOW THE DAEMON (the conformance pack's §2.13 row 3): TWO
/// CONCURRENT flagless FIRST MINTS into ONE empty account — both ACKED,
/// EXACTLY ONE born published, and it is doc 1. The mirror of skepd's
/// `two_concurrent_first_mints_bear_exactly_one_published_home`, one level
/// down, and the half that vector cannot see: the daemon holds its own
/// serialization lock across its gates and the execute they gate
/// (`plain_sequence`), so at the wire a build that breaks THIS layer alone
/// stays green. Here no daemon is in the path — two threads, one
/// `OperationSurface`, one kernel — so what serializes the two mints is what
/// is pinned: M2's `transact` takes the single applier lock BEFORE it loads
/// the base root, and M3 resolves the flagless default INSIDE that
/// transaction, off the working state the mint itself reads
/// (`Namespace::create_new_document`). The second mint's base therefore
/// already holds the first's document, and it is born a PRIVATE draft — never
/// a second home, and never refused. A default read hoisted out of the
/// transaction, off a head snapshot, hands both mints `true`, and only a real
/// race shows it.
///
/// The race is REAL: per round one fresh EMPTY account, TWO live sessions of
/// its principal, two threads, each sending the flagless
/// `create_new_document`. They are released off one START LINE both are
/// already spinning on, and not off a `std::sync::Barrier`, which parks its
/// early arriver and lets its last straight through: in-process that head
/// start can outlast a whole mint. Measured under this suite's own parallel
/// load, a `Barrier` ran about half of the first sixteen rounds as a
/// sequential pair — which a hoisted read survives — and one thread committed
/// first in nearly every round. Which thread's mint commits first is the
/// scheduler's to say, so the rounds run until BOTH orders have occurred, and
/// never fewer than `MIN_ROUNDS`: the pin holds whichever wins.
///
/// "Born published" is read off the surface's own reads — `doc_metadata` as
/// the owner, and the GUEST's: served the home, `withheld` the draft, through
/// [`published_or_own`].
#[test]
fn two_concurrent_first_mints_below_the_daemon_bear_exactly_one_published_home() {
    const MIN_ROUNDS: usize = 16;
    const MAX_ROUNDS: usize = 256;

    // Built here rather than by `surface`, which keeps its kernel to itself:
    // the supplied predicate reads this one.
    let kernel = kernel();
    let febe = OperationSurface::new(Box::new(KernelStores { kernel: Arc::clone(&kernel) }))
        .with_read_predicate(published_or_own(kernel));
    let boot = febe.bootstrap_session();
    // The GUEST: the one id no `open` mints, bound to no principal (§6).
    let guest = SessionId::GUEST;

    // `won[i]`: the rounds in which thread `i`'s mint committed FIRST.
    let mut won = [0usize; 2];
    let mut rounds = 0;
    while rounds < MAX_ROUNDS && (rounds < MIN_ROUNDS || won.contains(&0)) {
        let id = PrincipalId(1_000 + rounds as u64);
        let account = seat_empty_account(&febe, boot, id);
        let sessions = [febe.open_session(id), febe.open_session(id)];
        assert_ne!(sessions[0], sessions[1], "two live sessions of the one principal");
        // The chain's first two slots — ghosts until this round's mints land.
        let (home, draft) = (ghost_doc(&account, 1), ghost_doc(&account, 2));

        // The start line: each thread counts itself in and spins on `go`,
        // which rises once both are there — neither parked, neither ahead.
        // This thread spins beside them and does not yield: measured, a
        // yielding wait handed the first-spawned thread four rounds in five.
        let (ready, go) = (AtomicUsize::new(0), AtomicBool::new(false));
        // Both ACKED — neither is refused, neither is lost: each thread opens
        // its own `AckAddr`, as the writers above do.
        let minted: Vec<(Address, Seq)> = std::thread::scope(|scope| {
            let handles: Vec<_> = sessions
                .iter()
                .map(|&session| {
                    let (febe, ready, go, account) = (&febe, &ready, &go, account.clone());
                    scope.spawn(move || {
                        ready.fetch_add(1, Ordering::Release);
                        while !go.load(Ordering::Acquire) {
                            std::hint::spin_loop();
                        }
                        ack_addr(ex(febe, session, Op::CreateNewDocument { account, published: None }))
                    })
                })
                .collect();
            while ready.load(Ordering::Acquire) < sessions.len() {
                std::hint::spin_loop();
            }
            go.store(true, Ordering::Release);
            handles.into_iter().map(|h| h.join().expect("no mint panics")).collect()
        });

        // One slot each, and the account's doc 1 went to the mint that
        // committed first: the chain's order is the log's.
        let winner = minted.iter().position(|(doc, _)| *doc == home).unwrap_or_else(|| {
            panic!("round {rounds}: neither mint is {home}: {minted:?}")
        });
        let ((_, home_at), (second, draft_at)) = (&minted[winner], &minted[1 - winner]);
        assert_eq!(*second, draft, "round {rounds}: two distinct addresses: {minted:?}");
        assert!(home_at < draft_at, "round {rounds}: doc 1 is the mint that committed first");

        // EXACTLY ONE born published — and it is the home.
        let published = |session: SessionId, doc: &Address| {
            doc_metadata(ex(&febe, session, Op::DocMetadata { doc: doc.clone() })).1
        };
        assert!(
            published(sessions[0], &home),
            "round {rounds}: the first committed mint is born published"
        );
        assert!(
            !published(sessions[0], &draft),
            "round {rounds}: the second is born PRIVATE, never a second home"
        );
        // The guest is served the one and withheld the other.
        assert!(published(guest, &home), "round {rounds}: the guest reads the published home");
        assert_withheld(
            ex(&febe, guest, Op::DocMetadata { doc: draft.clone() }),
            OpKind::DocMetadata,
            &draft,
        );

        won[winner] += 1;
        rounds += 1;
    }
    eprintln!(
        "concurrent first mints below the daemon: {rounds} rounds; committed first — thread 0: {}, thread 1: {}",
        won[0], won[1]
    );
    assert!(
        !won.contains(&0),
        "both orders must occur — {rounds} rounds, committed first {won:?}"
    );
}
