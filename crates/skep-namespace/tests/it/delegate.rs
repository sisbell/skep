//! §B delegate: the account mint and its principal seat in one transaction,
//! and so an account's seat as its allocation; the peek that is not a
//! reservation, the pinned rejection order, the depth refusal and the peek's
//! bound, and ordinal one under every node.

use crate::common::*;

use skep_address::Level;
use skep_namespace::{
    system_account, DelegateError, HasM3, M3Rec, M3State, Namespace, BOOTSTRAP_PRINCIPAL,
    MAX_PRINCIPAL_COMPONENTS,
};

#[test]
fn delegate_mints_the_account_and_registers_its_principal_atomically() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);

    // The peek names the exact next-form value delegate demands (O17c) —
    // no guess-and-retry.
    let peek = k
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(&a(&[1]))
        .expect("node peek");
    assert_eq!(peek, a(&[1, 0, 1]));

    let before = k.current_seq();
    let (acct, seq) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, peek.tumbler().clone(), ID1)
        .expect("delegate");
    assert_eq!(acct, peek);
    assert!(seq > before);
    assert_eq!(k.current_seq(), seq); // the committed last_seq

    // Both halves landed in ONE transaction (O17b): the allocation and the
    // principal.
    let snap = k.snapshot();
    let m3 = snap.world().m3();
    assert!(m3.is_allocated(&acct));
    assert_eq!(m3.entity_level(&acct), Some(Level::Account));
    assert_eq!(m3.principal_prefix(ID1), Some(&acct));
    // Effective ownership moved to the new principal (O7).
    assert_eq!(m3.effective_owner(&acct), Some(ID1));
    // The node's account chain peeks the next slot now.
    assert_eq!(m3.next_account_prefix(&a(&[1])), Some(a(&[1, 0, 2])));

    // Sub-account delegation on the account's own (A, 1) chain — the sixth
    // chain family (Conflicts §8).
    let sub_peek = m3.next_account_prefix(&acct).expect("account peek");
    assert_eq!(sub_peek, a(&[1, 0, 1, 1]));
    let (sub_acct, _) = ns
        .delegate(ID1, sub_peek.tumbler().clone(), ID2)
        .expect("sub-delegate");
    assert_eq!(sub_acct, sub_peek);
    let snap = k.snapshot();
    let m3 = snap.world().m3();
    assert_eq!(m3.effective_owner(&sub_acct), Some(ID2));
    // ω still refines by longest match beside the sub-account.
    assert_eq!(m3.effective_owner(&a(&[1, 0, 1, 2])), Some(ID1));
    // The `(A, 1)` chain under an account is the sub-account chain, not a
    // version chain: the version read answers nothing there, however many
    // sub-accounts the chain holds.
    assert_eq!(m3.latest_version(&acct), None);

    // next_account_prefix: None unless the parent is a REGISTERED node or
    // account.
    assert!(m3.next_account_prefix(&a(&[1, 0, 9])).is_none());
    let (doc, _) = ns.create_new_document(ID1, &acct, None).expect("create");
    assert!(k
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(&doc)
        .is_none());
}

/// An account's seat is its allocation (§6, O17b): `delegate` seats every
/// prefix it mints in the transaction that mints it, and genesis seeds its one
/// account seated, so on any state M3's ops produce an account-tier address is
/// registered iff a principal is seated exactly at it — the equality the
/// owner-of-address read (AUTH-6.37) answers as its allocation test
/// (AUTH-5.87). Probed at every account-tier shape the ops produce, seated
/// and free alike.
#[test]
fn an_account_is_allocated_iff_a_principal_is_seated_at_it() {
    let (k, acct, _doc) = kernel_with_account_and_doc();
    let (sub, _) = Namespace::new(&k)
        .delegate(ID1, t(&[1, 0, 1, 1]), ID2)
        .expect("sub-delegate");
    let m3 = k.snapshot().world().m3().clone();
    for probe in [
        acct.clone(),
        sub.clone(),
        system_account(),
        a(&[1, 0, 2]),       // the bootstrap node's next slot
        a(&[1, 0, 1, 2]),    // the account's next sub-account slot
        a(&[1, 0, 1, 1, 1]), // the sub-account's first slot
        a(&[1, 1, 0, 2]),    // the system node's next slot
    ] {
        assert_eq!(
            m3.is_registered_account(&probe),
            m3.effective_owner_prefix(&probe) == Some(&probe),
            "allocation and seat disagree at {probe:?}"
        );
    }
    // Both answers occur, so the equality is not vacuous.
    assert!(m3.is_registered_account(&sub));
    assert!(!m3.is_registered_account(&a(&[1, 0, 2])));
}

#[test]
fn a_stale_peek_loses_and_never_re_seats_a_live_prefix() {
    // §6 / O17c: `next_account_prefix` is a peek, NOT a reservation — "two
    // racing peeks of the same value leave exactly one winner". The loser's
    // retry is refused by (i) or (ii), which is exactly what discharges
    // `has_principal_strictly_under`'s `p ∉ Π` precondition: once `p` IS a
    // principal the (iv) probe answers false, so the two gates PINNED ahead of
    // it are the ones doing the work here. (The probe's own contract, that
    // blind spot included, is pinned in `state.rs`'s unit tests; what this
    // test holds is the workflow and the state it leaves.)
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let peek = k
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(&a(&[1]))
        .expect("node peek");
    // Two callers hold the same peeked value; the first delegation wins.
    ns.delegate(BOOTSTRAP_PRINCIPAL, peek.tumbler().clone(), ID1)
        .expect("the first delegation of a peeked prefix wins");
    let before = k.current_seq();

    // The ancestor's stale retry: ω moved to ID1 (O7), so (ii) refuses — NOT
    // (iv), which sees `p` itself as the first key ≥ p and answers false.
    assert_eq!(
        rejected(ns.delegate(BOOTSTRAP_PRINCIPAL, peek.tumbler().clone(), ID2)),
        DelegateError::NotAuthorized
    );
    // The seated principal's own retry: (i) refuses — a prefix is not a
    // STRICT ancestor of itself.
    assert_eq!(
        rejected(ns.delegate(ID1, peek.tumbler().clone(), ID2)),
        DelegateError::NotAncestor
    );
    // The VERBATIM retry a caller sends when its acknowledgement was lost:
    // same delegator, same prefix, same id. It answers `NotAuthorized` too, so
    // the code alone cannot tell a retry from a lost race.
    assert_eq!(
        rejected(ns.delegate(BOOTSTRAP_PRINCIPAL, peek.tumbler().clone(), ID1)),
        DelegateError::NotAuthorized
    );

    // Neither retry moved anything: one seat, one id, one commit.
    assert_eq!(k.current_seq(), before);
    let m3 = k.snapshot().world().m3().clone();
    assert_eq!(m3.effective_owner(&peek), Some(ID1));
    // The disambiguator `delegate`'s contract publishes: the retried id IS
    // seated at the prefix it asked for, and the racing loser's names no
    // principal — which is how a caller tells the two `NotAuthorized`s apart.
    assert_eq!(m3.principal_prefix(ID1), Some(&peek));
    assert!(m3.principal_prefix(ID2).is_none());
    // …and the chain moved on, so a fresh peek names a different prefix.
    assert_eq!(m3.next_account_prefix(&a(&[1])), Some(a(&[1, 0, 2])));
}

#[test]
fn delegate_rejection_order_is_pinned() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);

    // Pre-work rejections (§6, no transaction opened) win over every
    // in-closure condition — here the delegator is ALSO unknown:
    // NotValid (validate-lift; [1,0] has a trailing zero)…
    assert_eq!(
        rejected(ns.delegate(UNKNOWN_ID, t(&[1, 0]), ID1)),
        DelegateError::NotValid
    );
    // …then NotAccountTier (hoisted (iii)): a bare node prefix is T4-VALID
    // but parentless — the hoist must reject it typed, before any
    // namespace_of/lock-key construction (no panic), and a document-tier
    // prefix is equally out (zeros == 1, narrowed from O15's ≤ 1).
    assert_eq!(
        rejected(ns.delegate(UNKNOWN_ID, t(&[2]), ID1)),
        DelegateError::NotAccountTier
    );
    assert_eq!(
        rejected(ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1, 0, 1]), ID1)),
        DelegateError::NotAccountTier
    );
    // NotAccountTier precedes TooDeep: an over-cap NODE-tier prefix is refused
    // for its tier, since depth bounds the principal registry alone — the
    // mirror of `register_node`'s NotNode-before-TooDeep.
    let node_over: Vec<u32> = std::iter::repeat_n(1u32, MAX_PRINCIPAL_COMPONENTS + 1).collect();
    assert_eq!(
        rejected(ns.delegate(UNKNOWN_ID, t(&node_over), ID1)),
        DelegateError::NotAccountTier
    );
    // …then TooDeep, the last pre-work guard, which precedes DelegatorUnknown:
    // an over-cap account-tier prefix from a caller who names no principal is
    // refused on depth, before any registry read.
    let mut acct_over = vec![1u32, 0];
    acct_over.extend(std::iter::repeat_n(1u32, MAX_PRINCIPAL_COMPONENTS));
    assert_eq!(
        rejected(ns.delegate(UNKNOWN_ID, t(&acct_over), ID1)),
        DelegateError::TooDeep
    );
    // DelegatorUnknown: the first in-closure gate.
    assert_eq!(
        rejected(ns.delegate(UNKNOWN_ID, t(&[1, 0, 1]), ID1)),
        DelegateError::DelegatorUnknown
    );

    ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("delegate [1,0,1] → ID1");

    // NotAncestor (i): ID1's prefix [1,0,1] does not contain [1,0,2] — and
    // (ii) would also fail (ω([1,0,2]) = π₀), so this pins (i) before (ii).
    assert_eq!(
        rejected(ns.delegate(ID1, t(&[1, 0, 2]), ID2)),
        DelegateError::NotAncestor
    );
    // NotAuthorized (ii): π₀ is an ancestor of [1,0,1,1], but ω resolves
    // the delegate ID1 (longest match), not the ancestor.
    assert_eq!(
        rejected(ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1, 1]), ID2)),
        DelegateError::NotAuthorized
    );
    // (ii) precedes (iv): with ID1 above [1,0,1,1] and ID2 strictly under
    // it, a non-ω delegator earns NotAuthorized though top-down also
    // fails… ([1,0,1,1] is deliberately NOT itself a principal, since the
    // §6 (iv) single probe answers false when it is.)
    let seeded = World {
        m3: M3State::genesis()
            .apply_m3(&alloc(&[1, 0, 1]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 1]),
                id: ID1,
            })
            .apply_m3(&alloc(&[1, 0, 1, 1]))
            .apply_m3(&alloc(&[1, 0, 1, 1, 1]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 1, 1, 1]),
                id: ID2,
            }),
    };
    let flanked_k = mem_kernel(seeded);
    let flanked_ns = Namespace::new(&flanked_k);
    assert_eq!(
        rejected(flanked_ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1, 1]), UNKNOWN_ID)),
        DelegateError::NotAuthorized
    );
    // …while ω itself reaches (iv) — so delegation can never seat a
    // principal ABOVE an existing one (top-down nesting, O15 iv).
    assert_eq!(
        rejected(flanked_ns.delegate(ID1, t(&[1, 0, 1, 1]), UNKNOWN_ID)),
        DelegateError::NotTopDown
    );
    // DuplicateId: a reused id rejects even though [1,0,3] is fresh AND not
    // next-form — DuplicateId precedes NotNextForm.
    assert_eq!(
        rejected(ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 3]), ID1)),
        DelegateError::DuplicateId
    );
    // NotNextForm (O17c): fresh prefix, fresh id, registered parent — but
    // the (N, 2) frontier's next is [1,0,2].
    assert_eq!(
        rejected(ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 3]), ID2)),
        DelegateError::NotNextForm
    );
    // A rejected delegation commits NEITHER half (clean typed rejection).
    let snap = k.snapshot();
    assert!(!snap.world().m3().is_allocated(&a(&[1, 0, 3])));
    assert!(snap.world().m3().principal_prefix(ID2).is_none());

    // ParentNotRegistered (P8, Conflicts §5) — on a FRESH kernel π₀ is ω of
    // [1,0,1,1] and that chain's next-form is satisfied, so the unregistered
    // parent is the only failing gate; with [1,0,1,2] it also precedes
    // NotNextForm.
    let fresh_k = mem_kernel(genesis_world());
    let fresh_ns = Namespace::new(&fresh_k);
    assert_eq!(
        rejected(fresh_ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1, 1]), ID2)),
        DelegateError::ParentNotRegistered
    );
    assert_eq!(
        rejected(fresh_ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1, 2]), ID2)),
        DelegateError::ParentNotRegistered
    );
    // id-freshness guards the bootstrap id too: no later principal may
    // re-claim id 0 (§7).
    assert_eq!(
        rejected(fresh_ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), BOOTSTRAP_PRINCIPAL)),
        DelegateError::DuplicateId
    );
    // DuplicateId precedes ParentNotRegistered: the id is taken AND [1,0,1]
    // — the parent of [1,0,1,1] — was never registered.
    assert_eq!(
        rejected(fresh_ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1, 1]), BOOTSTRAP_PRINCIPAL)),
        DelegateError::DuplicateId
    );

    // NotFresh and NotTopDown need an allocated-but-principal-less account;
    // the fold admits exactly the record shapes delegate itself stages
    // (apply_m3 totality domain), so seed one directly.
    let seeded = World {
        m3: M3State::genesis().apply_m3(&alloc(&[1, 0, 1])),
    };
    let allocated_k = mem_kernel(seeded);
    let allocated_ns = Namespace::new(&allocated_k);
    // (v) freshness: [1,0,1] is allocated (ω = π₀, so (ii) passes).
    assert_eq!(
        rejected(allocated_ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID2)),
        DelegateError::NotFresh
    );
    // NotFresh precedes DuplicateId: [1,0,1] is allocated AND id 0 is taken.
    assert_eq!(
        rejected(allocated_ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), BOOTSTRAP_PRINCIPAL)),
        DelegateError::NotFresh
    );
    // (iv) top-down: with a principal strictly under [1,0,1] the same call
    // rejects NotTopDown — which precedes NotFresh (the input violates
    // both).
    let seeded = World {
        m3: M3State::genesis()
            .apply_m3(&alloc(&[1, 0, 1]))
            .apply_m3(&alloc(&[1, 0, 1, 1]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 1, 1]),
                id: ID2,
            }),
    };
    let nested_k = mem_kernel(seeded);
    let nested_ns = Namespace::new(&nested_k);
    assert_eq!(
        rejected(nested_ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), UNKNOWN_ID)),
        DelegateError::NotTopDown
    );
}

// ---- the depth refusal and the peek's bound ----

#[test]
fn delegate_refuses_a_wire_deep_prefix_structurally() {
    // §6: `delegate` takes an UNVALIDATED `Tumbler` straight off the wire, and
    // T4 bounds an address's zero pattern, not its component count — so ~100 KB
    // of dotted decimal is a 50_000-component account-tier prefix. Each of the
    // three wire-deep shapes is refused as PRE-WORK — on depth if account-tier,
    // on tier if not — before the full-depth `parent` clone, the
    // nine-bytes-per-component lock key and the transaction that takes both
    // keys; the fourth case is the deepest ADMISSIBLE prefix, which traverses
    // the whole gate chain and must still refuse structurally. No assertion
    // pins a constant — a wall-clock bound is a flake; the depth is chosen so
    // a regression to superlinear work stops the suite instead of reddening a
    // line. Corpus seeds for the fuzzing tier.
    let (k, acct, _doc) = kernel_with_account_and_doc(); // Π = { [1]→π₀, [1,0,1]→ID1 }
    let ns = Namespace::new(&k);
    let before = k.current_seq();

    // Inside the caller's OWN subtree, and outside it: both over-cap, so
    // neither reaches (i)'s containment fence, let alone the registry reads.
    let mut deep = vec![1u32, 0, 1];
    deep.extend(std::iter::repeat_n(1u32, 49_997));
    assert_eq!(
        rejected(ns.delegate(ID1, t(&deep), ID2)),
        DelegateError::TooDeep
    );
    let mut foreign = vec![1u32, 0, 2];
    foreign.extend(std::iter::repeat_n(1u32, 49_997));
    assert_eq!(
        rejected(ns.delegate(ID1, t(&foreign), ID2)),
        DelegateError::TooDeep
    );

    // A node-tier prefix of the same length is refused for its TIER, which the
    // pinned order puts first — depth bounds the principal registry alone.
    let node_deep: Vec<u32> = std::iter::repeat_n(1u32, 50_000).collect();
    assert_eq!(
        rejected(ns.delegate(ID1, t(&node_deep), ID2)),
        DelegateError::NotAccountTier
    );

    // At the cap the prefix is admissible and traverses the WHOLE gate chain
    // under both held keys — `parent`, `account_lock_key`'s encoding,
    // `has_principal_strictly_under`'s range probe, `is_allocated`'s
    // decomposition and `mint_account`'s frontier read all take it whole. That
    // is the case the cap does not close, and it must still refuse
    // structurally, without reaching an `expect`.
    let mut at_cap = vec![1u32, 0, 1];
    at_cap.extend(std::iter::repeat_n(1u32, MAX_PRINCIPAL_COMPONENTS - 3));
    assert_eq!(t(&at_cap).len(), MAX_PRINCIPAL_COMPONENTS);
    assert_eq!(
        rejected(ns.delegate(ID1, t(&at_cap), ID2)),
        DelegateError::ParentNotRegistered
    );

    // Nothing committed, and the account's own chain stands where it stood.
    assert_eq!(k.current_seq(), before);
    assert_eq!(
        k.snapshot().world().m3().next_account_prefix(&acct),
        Some(a(&[1, 0, 1, 1]))
    );
}

#[test]
fn the_peek_and_the_delegate_gate_stop_at_the_same_nesting_depth() {
    // §6: `MAX_PRINCIPAL_COMPONENTS` is a resource refusal on the second
    // uncompressed registry, and the peek and the gate must read ONE bound or
    // a caller is handed a prefix `delegate` refuses. Seeded through the fold,
    // because reaching the cap through the op is sixty durable delegations of
    // no additional interest — each `Allocate` here is `c₁` of a fresh chain,
    // so the contiguity domain holds.
    let mut deep = vec![1u32, 0];
    deep.extend(std::iter::repeat_n(1u32, MAX_PRINCIPAL_COMPONENTS - 2));
    let under = deep[..MAX_PRINCIPAL_COMPONENTS - 1].to_vec();
    let m3 = M3State::genesis()
        .apply_m3(&alloc(&under))
        .apply_m3(&alloc(&deep));
    assert_eq!(a(&deep).tumbler().len(), MAX_PRINCIPAL_COMPONENTS);

    // One below the cap the chain still has a delegable slot…
    assert!(m3.next_account_prefix(&a(&under)).is_some());
    // …at the cap it has none, because the slot would be over-cap — and the
    // parent is a registered account either way, so this `None` is the depth
    // refusal and not the ineligible-parent one.
    assert_eq!(m3.entity_level(&a(&deep)), Some(Level::Account));
    assert!(m3.next_account_prefix(&a(&deep)).is_none());

    // …and the gate refuses that very prefix, as pre-work: neither id below
    // names a principal here, so only a pre-work guard can be answering.
    let mut over = deep.clone();
    over.push(1);
    let k = mem_kernel(World { m3 });
    assert_eq!(
        rejected(Namespace::new(&k).delegate(ID1, t(&over), UNKNOWN_ID)),
        DelegateError::TooDeep
    );
}

// ---- the first account under a node ----

/// The first account under a node is its first delegate's by standing
/// convention (ruling clause 2), and M3 already enforces the half a format
/// can: the first delegate under ANY node receives account ordinal 1 — the
/// frontier's `c₁ = N·0·1`, which `delegate`'s next-form gate demands
/// verbatim — and once seated it is never re-delegated, because prefix
/// freshness refuses the seat a second time. Pinned at the bootstrap node and
/// at the host node 1.2 (the numbering ruling's other named node); at the
/// registry node 1.1 the seat is genesis's own — PUB-6.65 seeds the system
/// account at 1.1.0.1 — so there the test pins the seed holding ordinal 1 and
/// the next arrival landing at 2.
#[test]
fn the_first_delegate_under_a_node_receives_account_ordinal_one() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);

    // Under the abstract root [1], the peek and the gate agree on 1.0.1…
    let snap = k.snapshot();
    assert_eq!(
        snap.world().m3().next_account_prefix(&a(&[1])),
        Some(a(&[1, 0, 1]))
    );
    drop(snap);
    // …an off-by-one guess is refused as not next-form…
    assert!(matches!(
        rejected(ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 2]), ID1)),
        DelegateError::NotNextForm
    ));
    // …and the first delegation is exactly account 1.
    let (first, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("the first delegate under [1]");
    assert_eq!(first, a(&[1, 0, 1]));

    // The registry node 1.1 is seeded, and ordinal 1 under it is the system
    // account's seat (PUB-6.65): the seed took the first ordinal the way a
    // first delegate does, so the peek there already answers ordinal 2.
    let snap = k.snapshot();
    assert_eq!(
        snap.world().m3().next_account_prefix(&a(&[1, 1])),
        Some(a(&[1, 1, 0, 2])),
        "the seeded system account holds ordinal 1 under the registry node"
    );
    drop(snap);

    // The host node 1.2, registered here: the operator's prefix is 1.2.0.1,
    // and once seated it cannot be delegated to anyone else — π₀ is no longer
    // its ω (the gate order reaches NotAuthorized before freshness), and the
    // operator itself is refused at ancestry (a prefix is never its own strict
    // ancestor). The next arrival lands at ordinal 2.
    ns.register_node(t(&[1, 2])).expect("register 1.2");
    let snap = k.snapshot();
    assert_eq!(
        snap.world().m3().next_account_prefix(&a(&[1, 2])),
        Some(a(&[1, 2, 0, 1])),
        "the first delegate under the host node lands at account 1"
    );
    drop(snap);
    let (operator, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 2, 0, 1]), ID2)
        .expect("the operator's delegation");
    assert_eq!(operator, a(&[1, 2, 0, 1]));
    assert!(matches!(
        rejected(ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 2, 0, 1]), UNKNOWN_ID)),
        DelegateError::NotAuthorized
    ));
    assert!(matches!(
        rejected(ns.delegate(ID2, t(&[1, 2, 0, 1]), UNKNOWN_ID)),
        DelegateError::NotAncestor
    ));
    let snap = k.snapshot();
    assert_eq!(
        snap.world().m3().next_account_prefix(&a(&[1, 2])),
        Some(a(&[1, 2, 0, 2])),
        "the operator's prefix is never delegated to anyone else"
    );
}
