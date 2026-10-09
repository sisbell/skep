//! §B the `Namespace` handle, across its four ops: what the type's own doc
//! and impls promise rather than any one op's — the transaction each op
//! opens, the refusals it decides before opening it and those it decides
//! inside, the nested call its caller must never make, and which of those
//! transactions an attestation it carries signs — and the handle itself,
//! borrows and nothing else, which copies as they do and prints as the
//! kernel it borrows and the arm it commits under.

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::common::*;

use skep_kernel::{Attestation, Kernel};
use skep_namespace::{
    CreateDocumentError, DelegateError, M3Rec, M3State, MintError, Namespace, PrincipalId,
    RegisterNodeError, BOOTSTRAP_PRINCIPAL, MAX_NODE_COMPONENTS, MAX_PRINCIPAL_COMPONENTS,
};
use tempfile::tempdir;

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
        assert_eq!(
            rejected(ns.register_node(t(&[1, 0]))),
            RegisterNodeError::NotValid
        );
        assert_eq!(
            rejected(ns.register_node(t(&[2, 0, 1]))),
            RegisterNodeError::NotNode
        );
        assert_eq!(
            rejected(ns.register_node(t(&too_deep))),
            RegisterNodeError::TooDeep
        );
        assert_eq!(
            rejected(ns.fork(UNKNOWN_ID, None)),
            CreateDocumentError::NotOwner
        );
        Ok(())
    })
    .expect("the outer transaction is a zero-step commit");
}

/// What `call` panicked with when made from inside a transaction on `k`, or
/// `None` if it returned. The panic is caught inside the outer closure, which
/// M2's reentrancy refusal permits: `ApplierLock::acquire` makes it before the
/// lock is taken or any state is touched, so the outer transaction then
/// commits its zero steps.
fn panic_of_a_nested_call<T>(k: &Kernel<World>, call: impl FnOnce() -> T) -> Option<String> {
    let mut raised = None;
    k.transact::<_, ()>(&[], |_stg| {
        if let Err(payload) = catch_unwind(AssertUnwindSafe(call)) {
            raised = Some(
                payload
                    .downcast_ref::<&str>()
                    .map(|message| (*message).to_owned())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_default(),
            );
        }
        Ok(())
    })
    .expect("the outer transaction is a zero-step commit");
    raised
}

/// The other side of the pre-work split: every refusal an op's doc places
/// INSIDE its transaction is decided only after that transaction opens. Most
/// are race-prone — ω, the top-down probe, freshness, id-freshness, P8 and
/// next-form, node freshness — and must read the committed state under the
/// op's own held keys, never a snapshot taken before it; the rest — the
/// delegator's resolution, its ancestry, node lineage — are monotone or read
/// no state, and sit inside to hold the pinned order. Hoisted onto a snapshot
/// they keep every sequential test green while a racing commit decides them
/// on stale state — π₀ mints into an account delegated a moment before, two
/// delegators seat one fresh id twice, two admissions of one node both answer
/// `Ok` — and each refusal moves ahead of M2's `Poisoned`, against
/// `Namespace`'s PRECEDENCE. Each case first earns its refusal outside any
/// transaction, then is made from inside one: an op that opens its own before
/// deciding panics on M2's reentrancy obligation, and one that decided early
/// hands its refusal back instead.
#[test]
fn in_closure_rejections_open_the_ops_own_transaction() {
    // One state with an input for every in-closure refusal: ID1 seated at
    // [1,0,1] as `delegate` stages it; [1,0,2] allocated with no one seated;
    // [1,0,3] unseated with a principal beneath it — the last two shapes no
    // op produces, seeded through the fold as the rejection-order test does.
    let seeded = World {
        m3: M3State::genesis()
            .apply_m3(&alloc(&[1, 0, 1]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 1]),
                id: ID1,
            })
            .apply_m3(&alloc(&[1, 0, 2]))
            .apply_m3(&alloc(&[1, 0, 3]))
            .apply_m3(&alloc(&[1, 0, 3, 1]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 3, 1]),
                id: PrincipalId(3),
            }),
    };
    let k = mem_kernel(seeded);
    let ns = Namespace::new(&k);
    let before = k.current_seq();
    let decided_inside = |case: &str, raised: Option<String>| {
        assert!(
            raised
                .as_deref()
                .is_some_and(|message| message.contains("transact is not reentrant")),
            "{case}: not decided inside the op's own transaction (nested call raised {raised:?})"
        );
    };

    // `delegate`: every gate past the pre-work, in its pinned order.
    for (case, delegator, prefix, new_id, refusal) in [
        (
            "an unknown delegator",
            UNKNOWN_ID,
            vec![1u32, 0, 4],
            ID2,
            DelegateError::DelegatorUnknown,
        ),
        (
            "a delegator that is no ancestor",
            ID1,
            vec![1, 0, 4],
            ID2,
            DelegateError::NotAncestor,
        ),
        (
            "an ancestor that is not ω",
            BOOTSTRAP_PRINCIPAL,
            vec![1, 0, 1, 1],
            ID2,
            DelegateError::NotAuthorized,
        ),
        (
            "a principal seated beneath",
            BOOTSTRAP_PRINCIPAL,
            vec![1, 0, 3],
            ID2,
            DelegateError::NotTopDown,
        ),
        (
            "an allocated prefix",
            BOOTSTRAP_PRINCIPAL,
            vec![1, 0, 2],
            ID2,
            DelegateError::NotFresh,
        ),
        (
            "an id already carried",
            BOOTSTRAP_PRINCIPAL,
            vec![1, 0, 4],
            ID1,
            DelegateError::DuplicateId,
        ),
        (
            "an unregistered parent",
            BOOTSTRAP_PRINCIPAL,
            vec![1, 0, 9, 1],
            ID2,
            DelegateError::ParentNotRegistered,
        ),
        (
            "a prefix past the next",
            BOOTSTRAP_PRINCIPAL,
            vec![1, 0, 5],
            ID2,
            DelegateError::NotNextForm,
        ),
    ] {
        assert_eq!(
            rejected(ns.delegate(delegator, t(&prefix), new_id)),
            refusal,
            "{case}: the premise"
        );
        decided_inside(
            case,
            panic_of_a_nested_call(&k, || ns.delegate(delegator, t(&prefix), new_id)),
        );
    }

    // `create_new_document`: ω, then the mint's structural gate.
    for (case, account, refusal) in [
        (
            "an account π₀ is not ω of",
            a(&[1, 0, 1]),
            CreateDocumentError::NotOwner,
        ),
        (
            "an unregistered account",
            a(&[1, 0, 9]),
            CreateDocumentError::Mint(MintError::NotAnAccount),
        ),
    ] {
        assert_eq!(
            rejected(ns.create_new_document(BOOTSTRAP_PRINCIPAL, &account, None)),
            refusal,
            "{case}: the premise"
        );
        decided_inside(
            case,
            panic_of_a_nested_call(&k, || {
                ns.create_new_document(BOOTSTRAP_PRINCIPAL, &account, None)
            }),
        );
    }

    // `fork` past its unknown-id refusal: π₀'s own prefix is a node.
    assert_eq!(
        rejected(ns.fork(BOOTSTRAP_PRINCIPAL, None)),
        CreateDocumentError::Mint(MintError::NotAnAccount),
        "a node-tier fork: the premise"
    );
    decided_inside(
        "a node-tier fork",
        panic_of_a_nested_call(&k, || ns.fork(BOOTSTRAP_PRINCIPAL, None)),
    );

    // `register_node`: freshness, then the lineage guard its doc keeps inside.
    for (case, addr, refusal) in [
        (
            "a node already admitted",
            vec![1u32],
            RegisterNodeError::NotFresh,
        ),
        (
            "a node off the bootstrap lineage",
            vec![2],
            RegisterNodeError::NotDescendantOfBootstrap,
        ),
    ] {
        assert_eq!(
            rejected(ns.register_node(t(&addr))),
            refusal,
            "{case}: the premise"
        );
        decided_inside(
            case,
            panic_of_a_nested_call(&k, || ns.register_node(t(&addr))),
        );
    }

    // Refusals all, outside and in: nothing committed.
    assert_eq!(k.current_seq(), before);
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

/// The handle is borrows and nothing else — the plain one built here borrows
/// the kernel alone — so it copies as a reference does, and it prints as the
/// kernel it borrows and its arm, plain here: the kernel's own rendering,
/// nothing of the world. The world here is not `Debug`, which is the case a
/// derived impl could not serve. A copy drives the same kernel: a node
/// admitted through it is no longer fresh to the original.
#[test]
fn the_handle_is_a_kernel_borrow_that_copies_and_prints() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let copy = ns;
    assert_eq!(
        format!("{copy:?}"),
        format!("Namespace {{ kernel: {k:?}, attested: false }}")
    );
    copy.register_node(t(&[1, 7]))
        .expect("admitted through the copy");
    assert_eq!(
        rejected(ns.register_node(t(&[1, 7]))),
        RegisterNodeError::NotFresh
    );
}

/// THE ATTESTED ARM (signed ops): which of M3's transactions an attestation
/// fills is M3's alone, stated on the handle's `attest` field — M10's
/// dispatch holds no copy of it — so this suite is the one place M3's half is
/// observed. An attested handle's `create_new_document` and `fork` commit
/// under the value it carries; its `delegate` and `register_node`, outside
/// the checked set, leave their signature slots empty whatever it carries; a
/// plain handle's mint leaves its signature slot empty too; and the handle
/// prints the arm it commits under, never the value. Over a journaled
/// kernel, since an in-memory one keeps no marker. One attested handle serves
/// four calls here to pin what the type does; a producer builds one per call
/// (`Namespace::attested`'s obligation).
#[test]
fn an_attested_handle_signs_its_two_document_mints_alone() {
    let dir = tempdir().expect("tempdir");
    let k = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("open");
    let attestation =
        Attestation::new(1, vec![0xA5; 64]).expect("a non-zero tag over a non-empty blob");
    let signed = Namespace::attested(&k, Some(&attestation));
    assert_eq!(
        format!("{signed:?}"),
        format!("Namespace {{ kernel: {k:?}, attested: true }}")
    );

    let (acct, delegated) = signed
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("the delegation commits");
    let (_, admitted) = signed
        .register_node(t(&[1, 7]))
        .expect("the admission commits");
    let (_, created) = signed
        .create_new_document(ID1, &acct, None)
        .expect("the create commits");
    let (_, forked) = signed.fork(ID1, None).expect("the fork commits");
    let (_, plain) = Namespace::new(&k)
        .create_new_document(ID1, &acct, None)
        .expect("a plain handle's create commits");

    for (at, commit, signature_slot) in [
        (delegated, "delegate", None),
        (admitted, "register_node", None),
        (created, "create_new_document", Some(attestation.clone())),
        (forked, "fork", Some(attestation.clone())),
        (plain, "a plain handle's create_new_document", None),
    ] {
        assert_eq!(
            k.attestation_at(at)
                .expect("a journaled kernel reads its own markers"),
            signature_slot,
            "{commit}: its marker's signature slot"
        );
    }
}
