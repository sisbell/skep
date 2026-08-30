//! The demand side (M10): the assembled `World` satisfies `Operation<W>`'s
//! bounds as written, and the engine's `Stores<World>` factory drives the
//! real request lifecycle. A short bootstrap→delegate→create→insert→retrieve
//! round-trip is enough — M10's own suite owns the lifecycle semantics; this
//! proves the assembly plugs in.

mod common;

use std::sync::Arc;

use common::*;
use skep_content::Val;
use skep_engine::{Engine, EngineStores, GenesisConfig};
use skep_febe::{Op, Operation, Request, Response};
use skep_kernel::Kernel;
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
    let doc = ack_addr(op.execute(
        session,
        Request { id: None, op: Op::CreateNewDocument { account: acct.clone() } },
    ));

    ack_addr(op.execute(
        session,
        Request {
            id: None,
            op: Op::Insert { doc: doc.clone(), at: vp(1, 1), values: vec![Val::new(vec![b'w'])] },
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

/// The other kernel `EngineStores` serves: a throwaway one rooted at a world
/// `Engine::world_at` reconstructed, which is how a daemon answers a
/// historical read. Assembled here out of the engine's own parts, since the
/// engine is where knowing which driver constructor fills which slot lives.
#[test]
fn engine_stores_serves_a_kernel_rooted_at_a_reconstructed_world() {
    let dir = tempdir().expect("tempdir");
    let engine = Engine::open(fsync_cfg(dir.path()), GenesisConfig::standard()).expect("fsync open");
    let (_acct, doc) = setup_doc(&engine);
    engine
        .vstream()
        .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'x'])])
        .expect("insert succeeds");

    let past = engine.kernel().current_seq();
    engine
        .vstream()
        .insert(OWNER, &doc, vp(1, 2), vec![Val::new(vec![b'y'])])
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
