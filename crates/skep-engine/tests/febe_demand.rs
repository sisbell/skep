//! The demand side (M10): the assembled `World` satisfies `Operation<W>`'s
//! bounds as written, and the engine's `Stores<World>` factory drives the
//! real request lifecycle. A short bootstrap→delegate→create→insert→retrieve
//! round-trip is enough — M10's own suite owns the lifecycle semantics; this
//! proves the assembly plugs in.

mod common;

use common::*;
use skep_content::Val;
use skep_febe::{Op, Operation, Request, Response};
use skep_retrieval::Spec;

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

    let boot = op.bootstrap_session();
    let prefix = match op.execute(boot, Request { id: None, op: Op::NextAccountPrefix { parent: node1() } })
    {
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

    let s = op.open_session(USER);
    let doc = ack_addr(
        op.execute(s, Request { id: None, op: Op::CreateNewDocument { account: acct.clone() } }),
    );

    ack_addr(op.execute(
        s,
        Request {
            id: None,
            op: Op::Insert { doc: doc.clone(), at: vp(1, 1), values: vec![Val::new(vec![b'w'])] },
        },
    ));

    match op.execute(
        s,
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
