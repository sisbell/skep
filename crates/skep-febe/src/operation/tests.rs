use std::sync::Arc;

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Tumbler};
use skep_arrangement::{Deposit, HasM5, InsertError, M5Rec, M5State, VPos};
use skep_content::{ContentStore, ContentWrite, HasContent, Val};
use skep_kernel::{
    CheckpointPolicy, Durability, Kernel, KernelConfig, SaltSource, Seq, TxnError, WorldState,
};
use skep_links::{HasLinks, LinkRec, LinkState};
use skep_namespace::{HasM3, M3Rec, M3State, PrincipalId};

use super::*;
use crate::op::{Op, ReqId};
use crate::reject::Disposition;
use crate::response::CommittedAck;

// ── a minimal assembled world (the composition contract in miniature) ──

#[derive(Clone, Serialize, Deserialize)]
struct World {
    m3: M3State,
    content: ContentStore,
    m5: M5State,
    links: LinkState,
}

#[derive(Clone, Serialize, Deserialize)]
enum Record {
    M3(M3Rec),
    Content(ContentWrite),
    M5(M5Rec),
    Links(LinkRec),
}

impl WorldState for World {
    type Record = Record;
    fn apply(&self, r: &Record) -> World {
        match r {
            Record::M3(x) => World { m3: self.m3.apply_m3(x), ..self.clone() },
            Record::Content(x) => World { content: self.content.apply_write(x), ..self.clone() },
            Record::M5(x) => World { m5: self.m5.apply_m5(x), ..self.clone() },
            Record::Links(x) => World { links: self.links.apply_link(x), ..self.clone() },
        }
    }
    fn rebuild_derived(self) -> Self {
        let World { m3, content, m5, links } = self;
        World { m3, content, m5: m5.rebuild_derived(), links: links.rebuild_derived() }
    }
}

impl HasM3 for World {
    fn m3(&self) -> &M3State {
        &self.m3
    }
}
impl HasContent for World {
    fn content(&self) -> &ContentStore {
        &self.content
    }
}
impl HasM5 for World {
    fn m5(&self) -> &M5State {
        &self.m5
    }
}
impl HasLinks for World {
    fn links(&self) -> &LinkState {
        &self.links
    }
}
impl crate::ReadableWorld for World {
    // The test world admits every read: masking (published ∨ subtree ∨
    // grant) is the engine's predicate, exercised by skepd's suite and the
    // engine's own; M10's lifecycle tests are principal-partition and
    // dispatch tests, orthogonal to it.
    fn readable(&self, _principal: Option<PrincipalId>, _doc: &Address) -> bool {
        true
    }
}
impl crate::PublicationWorld for World {
    // The edition-claim class is the engine's composition (the pinned
    // type address lives there); this world carries none, so the lookup
    // answers the empty class and the arm's shape is what is exercised.
    fn edition_claims(&self, _target: &Address) -> Vec<crate::EditionClaim> {
        Vec::new()
    }
    // The grant fold is the engine's too; this world carries none, so the
    // live universal index is empty and the arm's shape is what is
    // exercised (the narrowing has its own vectors in `tests/it`).
    fn universal_grant_index(&self) -> Vec<crate::UniversalIndexRow> {
        Vec::new()
    }
}
impl From<M3Rec> for Record {
    fn from(r: M3Rec) -> Record {
        Record::M3(r)
    }
}
impl From<ContentWrite> for Record {
    fn from(r: ContentWrite) -> Record {
        Record::Content(r)
    }
}
impl From<M5Rec> for Record {
    fn from(r: M5Rec) -> Record {
        Record::M5(r)
    }
}
impl From<LinkRec> for Record {
    fn from(r: LinkRec) -> Record {
        Record::Links(r)
    }
}

fn tum(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")
}
fn addr(comps: &[u32]) -> Address {
    validate(tum(comps)).unwrap_or_else(|_| panic!("T4-valid test address"))
}
fn genesis_world() -> World {
    World {
        m3: M3State::genesis(),
        content: ContentStore::default(),
        m5: M5State::genesis(),
        links: LinkState::genesis(),
    }
}

fn kernel() -> Arc<Kernel<World>> {
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    };
    Arc::new(Kernel::open(cfg, genesis_world()).expect("in-memory open cannot fail"))
}

struct KernelStores {
    kernel: Arc<Kernel<World>>,
}

/// The whole of what an implementer owes: one kernel, answered the same
/// way every time. All three drivers follow from it.
impl crate::Stores<World> for KernelStores {
    fn kernel(&self) -> &Kernel<World> {
        &self.kernel
    }
}

fn surface() -> OperationSurface<World> {
    OperationSurface::new(Box::new(KernelStores { kernel: kernel() }))
}

fn insert_op() -> Op {
    Op::Insert {
        doc: addr(&[1, 0, 1, 0, 1]),
        at: VPos { subspace: Nat::from(1u32), ordinal: Nat::from(1u32) },
        values: vec![Val::new(vec![1u8])],
        deposit: Deposit::Undeclared,
    }
}

fn rejected(r: Response) -> Rejection {
    match r {
        Response::Rejected(rej) => rej,
        _ => panic!("expected Rejected"),
    }
}

/// §8: `execute` is reentrant & Sync — the handle is shareable across the
/// transport's pipelined callers.
#[test]
fn the_operation_surface_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<OperationSurface<World>>();
}

/// C-SEND-SYNC: the request a transport hands a worker and the answer it
/// hands back. Both are `Send + Sync` today by inheritance alone — from M6's
/// and M8's query results and M5's and M8's request values, none of which a
/// `WorldState` bound constrains — so the promise is pinned where it is
/// made, and a payload that revokes it fails this build, not a transport's.
#[test]
fn a_request_and_its_answer_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Request>();
    assert_send_sync::<Response>();
}

/// C-DEBUG over a world that has none: this module's `World` derives no
/// `Debug`, so the impl asks nothing of `W`. The surface renders through
/// M2's lock-free rendering of its kernel and says whether a supplied
/// predicate answers.
#[test]
fn the_operation_surface_is_debug_over_a_world_that_is_not() {
    let live = format!("{:?}", surface());
    assert!(live.starts_with("OperationSurface { kernel: Kernel {"), "{live}");
    assert!(live.ends_with("read_predicate: None, .. }"), "{live}");
    let historical = format!("{:?}", surface().with_read_predicate(|_, _| true));
    assert!(historical.contains(r#"read_predicate: Some("supplied")"#), "{historical}");
}

/// §6: ids are unique within an uptime; a closed session is unbound, so a
/// later write on it is rejected `Unauthenticated` (Permanent) before any
/// transaction — no store is touched.
#[test]
fn closed_session_write_is_unauthenticated() {
    let febe = surface();
    let s1 = febe.open_session(PrincipalId(1));
    let s2 = febe.open_session(PrincipalId(2));
    assert_ne!(s1, s2);
    febe.close_session(s1);
    let rej = rejected(febe.execute(s1, Request { id: None, op: insert_op(), attest: None }));
    assert_eq!(rej.op, OpKind::Insert);
    assert_eq!(rej.code, RejectCode::Unauthenticated);
    assert_eq!(rej.disposition, Disposition::Permanent);
}

/// §6/§Invariants: the step-(b) gate is ONE uniform rule — a write
/// requires a bound session, full stop — so it holds for every write,
/// `RegisterNode` (whose principal M3 ignores) included, and for every
/// unbound id alike: one retired by `close_session`, and
/// [`SessionId::GUEST`], which no `open` mints. The second is what makes
/// the constant safe to hand to every unauthenticated request. And it
/// holds BEFORE any transaction, which is what the unmoved log position
/// witnesses: no store is reached on the way to the refusal.
#[test]
fn every_write_on_an_unbound_session_is_unauthenticated_before_any_transaction() {
    let febe = surface();
    let retired = febe.open_session(PrincipalId(1));
    febe.close_session(retired);
    let before = febe.log_position();
    for session in [retired, SessionId::GUEST] {
        for (op, is_read) in crate::op::tests::all_ops() {
            if is_read {
                continue;
            }
            let kind = op.kind();
            match febe.execute(session, Request { id: None, op, attest: None }) {
                Response::Rejected(rej) => {
                    assert_eq!(rej.op, kind, "the rejection names the op it refused");
                    assert_eq!(rej.code, RejectCode::Unauthenticated, "{kind:?} under {session:?}");
                    assert_eq!(rej.disposition, Disposition::Permanent, "{kind:?}");
                }
                _ => panic!("{kind:?} was answered on the unbound session {session:?}"),
            }
        }
    }
    assert_eq!(
        febe.log_position(),
        before,
        "no write on an unbound session may reach a transaction"
    );
}

/// §1/§2, the complement of the gate above: a read tolerates an unbound
/// session — it is ANSWERED, as the guest. Every read arm is driven
/// through `execute` on an id that was never opened; each may reject for
/// its own reasons against a genesis world, but never for authentication.
/// Driving all 27 also exercises `execute`'s Total contract on the read
/// half: an arm that panics fails here.
#[test]
fn no_read_is_ever_rejected_for_an_unbound_session() {
    let febe = surface();
    let never_opened = SessionId::unminted(9999);
    for (op, is_read) in crate::op::tests::all_ops() {
        if !is_read {
            continue;
        }
        let kind = op.kind();
        if let Response::Rejected(rej) = febe.execute(never_opened, Request { id: None, op, attest: None }) {
            assert_ne!(
                rej.code,
                RejectCode::Unauthenticated,
                "{kind:?} is a read: the session gate is not its to fail"
            );
        }
    }
}

/// §5/§9: the first `TxnError::Poisoned` latches the flag inside
/// `lower_write`; thereafter writes fail fast with Halt at step (c) while
/// reads keep being served off the last root.
#[test]
fn poison_latch_halts_writes_but_reads_continue() {
    let febe = surface();
    let s = febe.open_session(PrincipalId(1));
    let rej = febe.lower_write(OpKind::Insert, TxnError::<InsertError>::Poisoned);
    assert_eq!(rej.code, RejectCode::Poisoned);
    assert_eq!(rej.disposition, Disposition::Halt);
    assert!(febe.poisoned.load(Ordering::Relaxed));
    // Write: fails fast pre-dispatch.
    let rej = rejected(febe.execute(s, Request { id: None, op: insert_op(), attest: None }));
    assert_eq!(rej.code, RejectCode::Poisoned);
    assert_eq!(rej.disposition, Disposition::Halt);
    // Read: still served (M2 snapshots survive a poisoned kernel).
    let resp = febe.execute(s, Request { id: None, op: Op::NextAccountPrefix { parent: addr(&[1]) }, attest: None });
    match resp {
        Response::MaybeAddr { addr, .. } => assert!(addr.is_some()),
        _ => panic!("read must still be served on a poisoned kernel"),
    }
}

/// §1: the precedence when both write gates would refuse. Gate (c) is
/// consulted before gate (b), so a write on a CLOSED session against a
/// latched kernel answers `Poisoned`/`Halt` — the client is told the
/// engine stopped, not that it must re-authenticate. Without the order
/// this request has two defensible answers and nothing choosing between
/// them.
#[test]
fn a_halted_kernel_outranks_an_unbound_session() {
    let febe = surface();
    let s = febe.open_session(PrincipalId(1));
    febe.close_session(s);
    // Raised for the latch alone; the rejection itself answers no request.
    let _ = febe.lower_write(OpKind::Insert, TxnError::<InsertError>::Poisoned);
    let rej = rejected(febe.execute(s, Request { id: None, op: insert_op(), attest: None }));
    assert_eq!(
        rej.code,
        RejectCode::Poisoned,
        "the poison gate speaks first, so an unbound session is not what this refusal names"
    );
    assert_eq!(rej.disposition, Disposition::Halt);
}

/// §7/§1(d): the memo admits a committed-write acknowledgment and
/// nothing else. `to_ack` is what refuses the other two shapes, so
/// neither a rejection surfaced through `execute` (a Reorder/Retry
/// reissue MUST re-execute) nor a read answer (whose snapshot goes
/// stale) can be memoized even when the request carried an id.
#[test]
fn only_committed_writes_are_cached() {
    let febe = surface();
    let s = febe.open_session(PrincipalId(1));
    assert!(Response::Count { n: 3, as_of: Seq(1) }.to_ack().is_none());
    assert!(Response::Rejected(rejection(OpKind::Insert, RejectCode::Unauthenticated))
        .to_ack()
        .is_none());
    // A rejected write carrying an id leaves no entry behind.
    let id = ReqId(b"req-2".to_vec());
    let retired = febe.open_session(PrincipalId(3));
    febe.close_session(retired);
    let r = febe.execute(retired, Request { id: Some(id.clone()), op: insert_op(), attest: None });
    assert!(matches!(r, Response::Rejected(_)));
    assert!(febe.idem.get(retired, &id, OpKind::Insert).is_none());
    // Nor does a read carrying one.
    let rid = ReqId(b"req-3".to_vec());
    let resp = febe.execute(
        s,
        Request { id: Some(rid.clone()), op: Op::NextAccountPrefix { parent: addr(&[1]) }, attest: None },
    );
    assert!(matches!(resp, Response::MaybeAddr { .. }));
    assert!(febe.idem.get(s, &rid, OpKind::NextAccountPrefix).is_none());
}

/// §1: step (a) runs AHEAD of the step-(c) poison gate, and that order is
/// what a client retrying a write it already committed depends on — it
/// receives the acknowledgment it lost, not the news that the kernel has
/// since halted. A write it has NOT committed is halted, which is what
/// makes the replay above a statement about the order rather than about
/// the latch being unset.
#[test]
fn a_memoized_ack_is_replayed_on_a_poisoned_kernel() {
    let febe = surface();
    let s = febe.bootstrap_session();
    let id = ReqId(b"node-5".to_vec());
    let node = || Op::RegisterNode { addr: tum(&[1, 5]) };
    let (addr, at) = match febe.execute(s, Request { id: Some(id.clone()), op: node(), attest: None }) {
        Response::AckAddr { addr, at } => (addr, at),
        _ => panic!("RegisterNode under the bootstrap session commits"),
    };

    // The kernel halts AFTER that write committed — the latch is what this
    // call is for, so the rejection it builds answers nothing.
    let _ = febe.lower_write(OpKind::Insert, TxnError::<InsertError>::Poisoned);
    assert!(febe.poisoned.load(Ordering::Relaxed));

    // A fresh keyed write is halted at step (c) — the gate is live.
    let rej = rejected(febe.execute(
        s,
        Request { id: Some(ReqId(b"node-6".to_vec())), op: Op::RegisterNode { addr: tum(&[1, 6]) }, attest: None },
    ));
    assert_eq!(rej.code, RejectCode::Poisoned);
    assert_eq!(rej.disposition, Disposition::Halt);

    // The retry of the committed one is answered from the memo instead.
    match febe.execute(s, Request { id: Some(id), op: node(), attest: None }) {
        Response::AckAddr { addr: replayed, at: replayed_at } => {
            assert_eq!(replayed, addr, "the replayed ack is the committed one");
            assert_eq!(replayed_at, at, "…at the coordinate it committed");
        }
        _ => panic!("a memoized ack is served ahead of the poison gate"),
    }
}

/// §1/§6/§7: step (a) precedes the SESSION gate, and the documented
/// outcome of the close/purge race. An `execute` already past its
/// step-(a) lookup may deposit its ack after `close_session` has swept,
/// and that entry then lives until eviction — so presenting the retired
/// id replays one acknowledgment of a write that session itself
/// committed, rather than answering `Unauthenticated`. It authorizes
/// nothing and commits nothing.
#[test]
fn a_memoized_ack_outliving_its_binding_is_replayed_not_refused() {
    let febe = surface();
    let s = febe.open_session(PrincipalId(1));
    let id = ReqId(b"in-flight".to_vec());
    // The deposit a request already past step (a) makes after the sweep.
    febe.close_session(s);
    febe.idem.put(
        s,
        id.clone(),
        OpKind::Insert,
        CommittedAck::Addr { addr: addr(&[1, 0, 1, 0, 1]), at: Seq(3) },
    );
    let before = febe.log_position();

    match febe.execute(s, Request { id: Some(id), op: insert_op(), attest: None }) {
        Response::AckAddr { addr: replayed, at } => {
            assert_eq!(replayed, addr(&[1, 0, 1, 0, 1]), "the memo answers ahead of the gate");
            assert_eq!(at, Seq(3), "…at the coordinate it committed");
        }
        _ => panic!("a memoized ack is served ahead of the session gate"),
    }
    assert_eq!(febe.log_position(), before, "a replayed ack commits nothing");

    // The binding really is gone: an unkeyed write on the same id is
    // refused, so the replay above says something about the ORDER of the
    // two steps and not about the session still being bound.
    let rej = rejected(febe.execute(s, Request { id: None, op: insert_op(), attest: None }));
    assert_eq!(rej.code, RejectCode::Unauthenticated);
}

/// §1: the partition is written in three places — `is_read`, and each
/// dispatch table's complement `|`-list — and they must agree. Adding a
/// variant is caught by the compiler at all three; MOVING one across the
/// partition is not, because every match stays exhaustive: `is_read`
/// alone picks the table, so an op moved in that one list would route to
/// the table whose complement arm holds it and answer `Malformed`
/// forever. Feeding every op to the WRONG table pins the agreement — each
/// complement arm must hold exactly the ops `is_read` sends elsewhere.
#[test]
fn each_dispatch_table_rejects_exactly_the_other_half() {
    let febe = surface();
    for (op, is_read) in crate::op::tests::all_ops() {
        let kind = op.kind();
        let wrong_table = if is_read {
            febe.dispatch_write(WriteCtx { principal: PrincipalId(1) }, op, None)
        } else {
            febe.dispatch_read(op, Some(PrincipalId(1)))
        };
        match wrong_table {
            Err(rej) => {
                assert_eq!(rej.op, kind);
                assert_eq!(rej.code, RejectCode::Malformed, "{kind:?}");
            }
            Ok(_) => panic!("{kind:?} was answered by the table for the other half"),
        }
    }
}
