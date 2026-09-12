//! The demand side (M10): the assembled `World` satisfies `Operation<W>`'s
//! bounds as written, and the engine's `Stores<World>` factory drives the
//! real request lifecycle. A short bootstrap→delegate→create→insert→retrieve
//! round-trip is enough — M10's own suite owns the lifecycle semantics; this
//! proves the assembly plugs in.

use crate::common;

use std::sync::Arc;

use common::*;
use skep_address::Address;
use skep_arrangement::Deposit;
use skep_content::Val;
use skep_engine::{Engine, EngineStores};
use skep_febe::{Disposition, Op, Operation, RejectCode, Request, Response};
use skep_kernel::Kernel;
use skep_namespace::PrincipalId;
use skep_retrieval::Spec;
use tempfile::tempdir;

fn ack_addr(r: Response) -> skep_address::Address {
    match r {
        Response::AckAddr { addr, .. } => addr,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected AckAddr"),
    }
}

#[test]
fn engine_world_satisfies_the_febe_demand() {
    let engine = mem_engine();
    let op: Operation<skep_engine::World> = Operation::new(Box::new(engine.stores()));

    let boot_session = op.bootstrap_session();
    let prefix = match op.execute(
        boot_session,
        Request { id: None, op: Op::NextAccountPrefix { parent: node1() } },
    ) {
        Response::MaybeAddr { addr: Some(a), .. } => a,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected MaybeAddr"),
    };

    let acct = ack_addr(op.execute(
        boot_session,
        Request {
            id: None,
            op: Op::Delegate { new_prefix: prefix.tumbler().clone(), new_id: USER },
        },
    ));

    let session = op.open_session(USER);
    // A DRAFT (explicit `false`): the account's flagless first mint would
    // be its published home, which takes no in-place edit (PUB-2.11).
    let doc = ack_addr(op.execute(
        session,
        Request {
            id: None,
            op: Op::CreateNewDocument { account: acct.clone(), published: Some(false) },
        },
    ));

    ack_addr(op.execute(
        session,
        Request {
            id: None,
            op: Op::Insert {
                doc: doc.clone(),
                at: vp(1, 1),
                values: vec![Val::new(vec![b'w'])],
                deposit: Deposit::Undeclared,
            },
        },
    ));

    match op.execute(
        session,
        Request {
            id: None,
            op: Op::RetrieveV { specs: vec![Spec { doc: doc.clone(), span: vspan(1, 1, 1) }] },
        },
    ) {
        Response::Delivery { items, .. } => {
            assert_eq!(delivered_bytes(&items), vec![b"w".to_vec()]);
        }
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected Delivery"),
    }
}

/// The read surface through the demand side (PUB round 2, lane 3.3): M10 builds
/// its per-request predicate off `ReadableWorld`, which the assembled `World`
/// implements with the engine's own `readable` (published ∨ subtree ∨ grant,
/// PUB-1.31). So over this engine a private draft is delivered to its owner and
/// answers WITHHELD — `reorder`, `site.addr` the document, no `detail`
/// (PUB-8.4, PUB-8.5) — to a retired (guest) session and to a principal outside
/// the owner's subtree, while the account's published home answers every
/// class. The predicate's clauses are `tests/grants.rs`'s; what this pins is
/// that `Operation<World>` reaches them at all.
#[test]
fn m10_s_read_surface_answers_through_the_engine_s_predicate() {
    let engine = mem_engine();
    let op: Operation<skep_engine::World> = Operation::new(Box::new(engine.stores()));

    let boot = op.bootstrap_session();
    let prefix = match op.execute(
        boot,
        Request { id: None, op: Op::NextAccountPrefix { parent: node1() } },
    ) {
        Response::MaybeAddr { addr: Some(a), .. } => a,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected MaybeAddr"),
    };
    let acct = ack_addr(op.execute(
        boot,
        Request {
            id: None,
            op: Op::Delegate { new_prefix: prefix.tumbler().clone(), new_id: USER },
        },
    ));
    let owner = op.open_session(USER);
    // The flagless first mint is the account's HOME, born published
    // (PUB-8.21); the second is a private draft.
    let home = ack_addr(op.execute(
        owner,
        Request { id: None, op: Op::CreateNewDocument { account: acct.clone(), published: None } },
    ));
    let draft = ack_addr(op.execute(
        owner,
        Request { id: None, op: Op::CreateNewDocument { account: acct.clone(), published: None } },
    ));
    ack_addr(op.execute(
        owner,
        Request {
            id: None,
            op: Op::Insert {
                doc: draft.clone(),
                at: vp(1, 1),
                values: vec![Val::new(vec![b'w'])],
                deposit: Deposit::Undeclared,
            },
        },
    ));

    let read = |session, doc: &Address| {
        op.execute(
            session,
            Request {
                id: None,
                op: Op::RetrieveV { specs: vec![Spec { doc: doc.clone(), span: vspan(1, 1, 1) }] },
            },
        )
    };
    let withheld = |resp: Response, doc: &Address| match resp {
        Response::Rejected(rej) => {
            assert_eq!(rej.code, RejectCode::Withheld, "{rej:?}");
            assert_eq!(rej.disposition, Disposition::Reorder, "{rej:?}");
            assert_eq!(rej.site.as_ref().and_then(|s| s.addr.as_ref()), Some(doc), "{rej:?}");
            assert!(rej.detail.is_none(), "withheld carries no detail: {rej:?}");
        }
        _ => panic!("expected the withheld rejection for {doc}"),
    };

    // SUBTREE — the owner reads its own draft.
    match read(owner, &draft) {
        Response::Delivery { items, .. } => {
            assert_eq!(delivered_bytes(&items), vec![b"w".to_vec()]);
        }
        Response::Rejected(rej) => panic!("the owner was refused its own draft: {rej:?}"),
        _ => panic!("expected Delivery"),
    }
    // GUEST — a retired session carries no principal (the daemon's guest
    // pattern): the guest predicate is published alone.
    let guest = op.open_session(PrincipalId(4242));
    op.close_session(guest);
    withheld(read(guest, &draft), &draft);
    // NON-ENTITLED — a bound principal outside the owner's subtree, no grant.
    let stranger = op.open_session(PrincipalId(77));
    withheld(read(stranger, &draft), &draft);
    // The published home answers both classes — a span set (empty, nothing
    // deposited), never a withheld answer: a published document never
    // answers withheld (PUB-6.3).
    for session in [guest, stranger] {
        match op.execute(session, Request { id: None, op: Op::RetrieveDocVSpanSet { doc: home.clone() } })
        {
            Response::SpanSet { .. } => {}
            Response::Rejected(rej) => panic!("the published home was refused: {rej:?}"),
            _ => panic!("expected SpanSet"),
        }
    }
}

/// The other kernel `EngineStores` serves: a throwaway one rooted at a world
/// `Engine::world_at` reconstructed, which is how a daemon answers a
/// historical read. Assembled here out of the engine's own parts, since the
/// engine is where knowing which driver constructor fills which slot lives.
#[test]
fn engine_stores_serves_a_kernel_rooted_at_a_reconstructed_world() {
    let dir = tempdir().expect("tempdir");
    let engine = Engine::open(fsync_cfg(dir.path())).expect("fsync open");
    let (_acct, doc) = setup_doc(&engine);
    engine
        .vstream()
        .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'x'])], Deposit::Undeclared)
        .expect("insert succeeds");

    let past = engine.kernel().current_seq();
    engine
        .vstream()
        .insert(OWNER, &doc, vp(1, 2), vec![Val::new(vec![b'y'])], Deposit::Undeclared)
        .expect("insert succeeds");

    let world = engine.world_at(past).expect("a committed boundary answers");
    let kernel = Kernel::open(mem_cfg(), world).expect("an in-memory open runs no recovery");
    let op: Operation<skep_engine::World> =
        Operation::new(Box::new(EngineStores::new(Arc::new(kernel))));
    let session = op.open_session(USER);

    match op.execute(
        session,
        Request {
            id: None,
            op: Op::RetrieveV { specs: vec![Spec { doc: doc.clone(), span: vspan(1, 1, 1) }] },
        },
    ) {
        Response::Delivery { items, .. } => {
            assert_eq!(delivered_bytes(&items), vec![b"x".to_vec()]);
        }
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected Delivery"),
    }

    // …and it is the PAST: the value committed after `past` is not in it. A
    // reconstruction that came back holding it would read as the head.
    if let Response::Delivery { items, .. } = op.execute(
        session,
        Request {
            id: None,
            op: Op::RetrieveV { specs: vec![Spec { doc: doc.clone(), span: vspan(1, 1, 2) }] },
        },
    ) {
        assert_ne!(
            delivered_bytes(&items).len(),
            2,
            "the reconstructed world must not hold the head's second value"
        );
    }
}
