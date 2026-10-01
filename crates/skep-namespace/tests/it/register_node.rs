//! §B register_node: validate-not-mint admission in its pinned guard order,
//! the pre-work refusals that open no transaction, the transaction every op
//! opens past them, and the handle itself — one kernel borrow, which copies
//! and prints like one.

use crate::common::*;

use skep_address::Level;
use skep_namespace::{
    CreateDocumentError, DelegateError, HasM3, M3Rec, M3State, Namespace, NodeError,
    BOOTSTRAP_PRINCIPAL, MAX_NODE_COMPONENTS, MAX_PRINCIPAL_COMPONENTS,
};

#[test]
fn register_node_validates_and_admits_supplied_addresses() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);

    // Ordinary admission (ASN-0047): the address is SUPPLIED, validated,
    // registered.
    let (node, seq) = ns.register_node(t(&[1, 7])).expect("register");
    assert_eq!(node, a(&[1, 7]));
    assert_eq!(k.current_seq(), seq);
    let snap = k.snapshot();
    let m3 = snap.world().m3();
    assert_eq!(m3.entity_level(&node), Some(Level::Node));
    assert!(m3.is_allocated(&node));
    // A provisioned node stays bootstrap-owned via ω until an account is
    // delegated beneath it (Conflicts §7)…
    assert_eq!(m3.effective_owner(&node), Some(BOOTSTRAP_PRINCIPAL));
    // …and delegation beneath it works through the ordinary gate.
    let peek = m3.next_account_prefix(&node).expect("peek under new node");
    assert_eq!(peek, a(&[1, 7, 0, 1]));
    ns.delegate(BOOTSTRAP_PRINCIPAL, peek.into(), ID1)
        .expect("delegate under the new node");

    // Admission asks nothing of the address's ANCESTORS: a node address names
    // a provisioning path originated OUTSIDE the docuverse, so `nodes` is
    // deliberately non-contiguous and P8 is not a gate here — [1,5,7] is
    // admitted while [1,5] is registered nowhere.
    assert_eq!(
        ns.register_node(t(&[1, 5, 7]))
            .expect("a node whose parent is unregistered")
            .0,
        a(&[1, 5, 7])
    );
    assert_eq!(
        k.snapshot().world().m3().entity_level(&a(&[1, 5, 7])),
        Some(Level::Node)
    );
    assert_eq!(k.snapshot().world().m3().entity_level(&a(&[1, 5])), None);

    // Rejections, in the documented guard order. The first three are pure
    // pre-work (validity, level and depth read the address alone); `NotFresh`
    // reads the registry under the held key, and `NotDescendantOfBootstrap`
    // reads none, following it because the order is the contract.
    let before = k.current_seq();
    // NotValid — not T4 ([1,0] has a trailing zero).
    assert_eq!(rejected(ns.register_node(t(&[1, 0]))), NodeError::NotValid);
    // NotNode — account-level input; checked before lineage ([2,0,1] is
    // also not bootstrap-descended).
    assert_eq!(
        rejected(ns.register_node(t(&[2, 0, 1]))),
        NodeError::NotNode
    );
    // NotNode precedes NotFresh: [1,7,0,1] is account-level AND registered
    // (the delegation above allocated it).
    assert_eq!(
        rejected(ns.register_node(t(&[1, 7, 0, 1]))),
        NodeError::NotNode
    );
    // TooDeep — `nodes` is the one registry M3 cannot keep in frontier form,
    // so an entry's component COUNT is refused rather than stored (magnitude
    // is M1-unbounded — see `MAX_NODE_COMPONENTS`). The probe is otherwise
    // impeccable — node-level, fresh, bootstrap-descended — so depth is the
    // only guard that can be refusing it.
    let too_deep: Vec<u32> = std::iter::repeat_n(1u32, MAX_NODE_COMPONENTS + 1).collect();
    assert_eq!(a(&too_deep).level(), Level::Node);
    assert_eq!(rejected(ns.register_node(t(&too_deep))), NodeError::TooDeep);
    // NotNode precedes TooDeep: an equally over-long ACCOUNT-tier address is
    // refused for its tier, since depth bounds the node registry alone.
    let mut deep_acct = vec![1u32, 0];
    deep_acct.extend(std::iter::repeat_n(1u32, MAX_NODE_COMPONENTS + 1));
    assert_eq!(
        rejected(ns.register_node(t(&deep_acct))),
        NodeError::NotNode
    );
    // NotFresh — duplicates surface typed, never a silent coalesce; the
    // seeded [1] and the just-registered [1,7] alike.
    assert_eq!(rejected(ns.register_node(t(&[1]))), NodeError::NotFresh);
    assert_eq!(rejected(ns.register_node(t(&[1, 7]))), NodeError::NotFresh);
    // NotDescendantOfBootstrap — [1] ≼ addr fails.
    assert_eq!(
        rejected(ns.register_node(t(&[2]))),
        NodeError::NotDescendantOfBootstrap
    );
    // A rejected admission commits nothing, whichever guard refused it.
    assert_eq!(k.current_seq(), before);

    // The cap is exactly where it says it is: one component shorter than the
    // refusal above is admitted, so `TooDeep` bounds the registry rather than
    // narrowing what provisioning may name.
    let at_cap: Vec<u32> = std::iter::repeat_n(1u32, MAX_NODE_COMPONENTS).collect();
    assert_eq!(
        ns.register_node(t(&at_cap)).expect("at the cap").0,
        a(&at_cap)
    );
    assert_eq!(
        k.snapshot().world().m3().entity_level(&a(&at_cap)),
        Some(Level::Node)
    );

    // TooDeep precedes NotFresh: an over-cap address that is ALSO registered.
    // `register_node` cannot reach that state — the cap refuses admission —
    // and `apply_m3` documents it as representable, since the record door
    // deliberately does not carry the cap (an over-cap entry is a permanent
    // resource charge, and nothing more).
    let seeded = World {
        m3: M3State::genesis().apply_m3(&M3Rec::RegisterNode { addr: a(&too_deep) }),
    };
    let over_cap_k = mem_kernel(seeded);
    assert_eq!(
        rejected(Namespace::new(&over_cap_k).register_node(t(&too_deep))),
        NodeError::TooDeep
    );

    // NotFresh precedes NotDescendantOfBootstrap: [2] is registered AND off
    // the bootstrap lineage — a state `register_node` itself cannot reach,
    // so seed it through the fold.
    let seeded = World {
        m3: M3State::genesis().apply_m3(&M3Rec::RegisterNode { addr: a(&[2]) }),
    };
    let off_lineage_k = mem_kernel(seeded);
    assert_eq!(
        rejected(Namespace::new(&off_lineage_k).register_node(t(&[2]))),
        NodeError::NotFresh
    );
}

#[test]
fn pre_work_rejections_open_no_transaction() {
    // §6/§7: `delegate`'s NotValid/NotAccountTier/TooDeep, `register_node`'s
    // NotValid/NotNode/TooDeep and `fork`'s unknown id are decided from the
    // argument alone and reject with NO transaction opened. M2 answers a
    // nested `transact` with a panic naming the broken obligation and permits
    // `snapshot()` inside a closure (kernel §3), so calling them from inside
    // a transaction is what separates "rejected before opening one" from
    // "rejected inside one" — `current_seq` cannot, since a rejected closure
    // draws no Seq either. Both `TooDeep`s are here for the reason they exist:
    // an oversized request must cost nothing, not a lock and a transaction.
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let too_deep: Vec<u32> = std::iter::repeat_n(1u32, MAX_NODE_COMPONENTS + 1).collect();
    let mut deep_prefix = vec![1u32, 0];
    deep_prefix.extend(std::iter::repeat_n(1u32, MAX_PRINCIPAL_COMPONENTS));
    k.transact::<_, ()>(&[], |_stg| {
        assert_eq!(
            rejected(ns.delegate(ID1, t(&[1, 0]), ID2)),
            DelegateError::NotValid
        );
        assert_eq!(
            rejected(ns.delegate(ID1, t(&[2]), ID2)),
            DelegateError::NotAccountTier
        );
        assert_eq!(
            rejected(ns.delegate(ID1, t(&deep_prefix), ID2)),
            DelegateError::TooDeep
        );
        assert_eq!(rejected(ns.register_node(t(&[1, 0]))), NodeError::NotValid);
        assert_eq!(
            rejected(ns.register_node(t(&[2, 0, 1]))),
            NodeError::NotNode
        );
        assert_eq!(rejected(ns.register_node(t(&too_deep))), NodeError::TooDeep);
        assert_eq!(
            rejected(ns.fork(UNKNOWN_ID, None)),
            CreateDocumentError::NotOwner
        );
        Ok(())
    })
    .expect("the outer transaction is a zero-step commit");
}

/// The other half of `Namespace`'s inherited PRECONDITION: past its pre-work an
/// op opens a transaction of its own, so a call from inside a `transact`
/// closure on the same kernel is a caller's bug, and M2 answers it as one —
/// a panic naming the broken obligation, never a refusal the caller could
/// mistake for the op's own. `[1, 7]` passes all three of `register_node`'s
/// pre-work guards — T4, node level, depth — so nothing stops the call before
/// it opens its transaction.
#[test]
#[should_panic(expected = "transact is not reentrant")]
fn an_op_past_its_pre_work_opens_a_transaction_of_its_own() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let _ = k.transact::<_, ()>(&[], |_stg| {
        let _ = ns.register_node(t(&[1, 7]));
        Ok(())
    });
}

/// `fork` under the same PRECONDITION: its one refusal before a transaction
/// is the unknown id, and past it the op is `create_new_document`'s
/// transaction. So a composite that forks WITH content cannot call `fork`
/// inside its own closure — it builds the fork from M3's pure parts, as
/// `fork`'s doc says. `ID1` is seated in the fixture, so the call is past
/// that refusal.
#[test]
#[should_panic(expected = "transact is not reentrant")]
fn a_fork_past_its_unknown_id_opens_a_transaction_of_its_own() {
    let (k, _acct, _doc) = kernel_with_account_and_doc();
    let ns = Namespace::new(&k);
    let _ = k.transact::<_, ()>(&[], |_stg| {
        let _ = ns.fork(ID1, None);
        Ok(())
    });
}

/// The handle is one kernel borrow, so it copies like one, and it prints as
/// that borrow — the kernel's own rendering, nothing of the world. The world
/// here is not `Debug`, which is the case a derived impl could not serve. A
/// copy drives the same kernel: a node admitted through it is no longer fresh
/// to the original.
#[test]
fn the_handle_is_a_kernel_borrow_that_copies_and_prints() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let copy = ns;
    assert_eq!(
        format!("{copy:?}"),
        format!("Namespace {{ kernel: {k:?} }}")
    );
    copy.register_node(t(&[1, 7]))
        .expect("admitted through the copy");
    assert_eq!(rejected(ns.register_node(t(&[1, 7]))), NodeError::NotFresh);
}
