use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Span, Tumbler};
use skep_arrangement::{
    deposit_class_types, Deposit, HasM5, InsertError, M5Rec, M5State, VPos, VSpec, Vstream,
};
use skep_content::{ContentStore, ContentWrite, HasContent, Val};
use skep_kernel::{
    Attestation, CheckpointPolicy, Durability, Kernel, KernelConfig, SaltSource, Seq, TxnError,
    WorldState,
};
use skep_links::{
    EditLinkError, HasLinks, LinkRec, LinkState, LinkWriter, SlotArg, Visibility, FROM,
    MAX_SLOT_RESOLVE_STEPS, MAX_SLOT_SPANS,
};
use skep_namespace::{HasM3, M3Rec, M3State, PrincipalId};

use super::*;
use crate::op::{Op, ReqId, SuccessorSpec};
use crate::publication::birth_version;
use crate::reject::Disposition;
use crate::response::{BirthVersion, CommittedAck};
use crate::successor::successor_link;

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

/// A `Stores` recording every attestation a driver acquisition carries — the
/// whole of what this surface can put in a commit marker's slot — and
/// otherwise the three drivers over one kernel, as `KernelStores` builds
/// them.
struct RecordingStores {
    kernel: Arc<Kernel<World>>,
    carried: Arc<Mutex<Vec<Attestation>>>,
}

impl crate::Stores<World> for RecordingStores {
    fn kernel(&self) -> &Kernel<World> {
        &self.kernel
    }
    fn vstream_attested<'a>(&'a self, attest: Option<&'a Attestation>) -> Vstream<'a, World> {
        self.carried.lock().extend(attest.cloned());
        Vstream::attested(self.kernel(), attest)
    }
    fn linkstore_attested<'a>(
        &'a self,
        visibility: &'a Visibility<'a, World>,
        attest: Option<&'a Attestation>,
    ) -> LinkWriter<'a, World> {
        self.carried.lock().extend(attest.cloned());
        LinkWriter::attested(self.kernel(), visibility, attest)
    }
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
/// its own reasons against a genesis world, but never for authentication,
/// and a refusal names the op it refused. Driving every read also
/// exercises `execute`'s Total contract on the read half: an arm that
/// panics fails here.
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
            assert_eq!(rej.op, kind, "a refusal names the op it refused");
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
fn only_committed_writes_are_memoized() {
    let febe = surface();
    let s = febe.open_session(PrincipalId(1));
    assert!(Response::Count { n: 3, as_of: Seq(1) }.to_ack().is_none());
    assert!(Response::Rejected(rejection(OpKind::Insert, RejectCode::Unauthenticated))
        .to_ack()
        .is_none());
    // A rejected write carrying an id leaves no entry behind.
    let write_id = ReqId(b"req-2".to_vec());
    let retired = febe.open_session(PrincipalId(3));
    febe.close_session(retired);
    let r = febe.execute(
        retired,
        Request { id: Some(write_id.clone()), op: insert_op(), attest: None },
    );
    assert!(matches!(r, Response::Rejected(_)));
    assert!(febe.idem.get(retired, &write_id, OpKind::Insert).is_none());
    // Nor does a read carrying one.
    let read_id = ReqId(b"req-3".to_vec());
    let resp = febe.execute(
        s,
        Request {
            id: Some(read_id.clone()),
            op: Op::NextAccountPrefix { parent: addr(&[1]) },
            attest: None,
        },
    );
    assert!(matches!(resp, Response::MaybeAddr { .. }));
    assert!(febe.idem.get(s, &read_id, OpKind::NextAccountPrefix).is_none());
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
    let (committed, committed_at) =
        match febe.execute(s, Request { id: Some(id.clone()), op: node(), attest: None }) {
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
            assert_eq!(replayed, committed, "the replayed ack is the committed one");
            assert_eq!(replayed_at, committed_at, "…at the coordinate it committed");
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

/// §1's Total contract on the WRITE half: every write, under a BOUND session
/// so each clears step (b) and reaches its arm, is answered and none
/// unwinds; and every refusal names the op it refused. A genesis world sends
/// most of them down their store's refusal path — where an arm that
/// unwrapped would panic, and one that lowered under another op's kind would
/// mislabel the frame.
#[test]
fn every_write_under_a_bound_session_is_answered_and_its_refusals_name_it() {
    let febe = surface();
    let s = febe.bootstrap_session();
    for (op, is_read) in crate::op::tests::all_ops() {
        if is_read {
            continue;
        }
        let kind = op.kind();
        if let Response::Rejected(rej) = febe.execute(s, Request { id: None, op, attest: None }) {
            assert_eq!(rej.op, kind, "a refusal names the op it refused");
            assert_ne!(rej.code, RejectCode::Unauthenticated, "{kind:?}: the session is bound");
        }
    }
}

/// THE ATTESTATION'S PRODUCER SET (`Request::attest`): the value a request
/// carries reaches a store driver on exactly three writes — `insert`,
/// `publish`, `make_link` — once each, and is dropped on every other write.
/// EDITLINK goes a second time with an empty successor: the partition's
/// fixture is refused by M10's own successor guard before any driver is
/// acquired, which would leave its row vacuous.
#[test]
fn an_attestation_reaches_a_store_driver_on_insert_publish_and_make_link_alone() {
    let carried = Arc::new(Mutex::new(Vec::new()));
    let febe = OperationSurface::new(Box::new(RecordingStores {
        kernel: kernel(),
        carried: Arc::clone(&carried),
    }));
    let s = febe.bootstrap_session();
    let attestation =
        Attestation::new(1, vec![0xA5]).expect("a non-zero tag over a non-empty blob");
    let doc = addr(&[1, 0, 1, 0, 1]);
    let buildable_edit = Op::EditLink {
        original: doc.clone(),
        successor: SuccessorSpec {
            from: vec![],
            to: vec![],
            ty: SlotArg::Addrs(vec![doc.clone()]),
        },
        d_s: doc.clone(),
        d_a: doc,
    };
    let writes = crate::op::tests::all_ops()
        .into_iter()
        .filter_map(|(op, is_read)| (!is_read).then_some(op))
        .chain([buildable_edit]);
    for op in writes {
        let kind = op.kind();
        let _ = febe.execute(s, Request { id: None, op, attest: Some(attestation.clone()) });
        let reached = std::mem::take(&mut *carried.lock());
        let in_the_slice = matches!(kind, OpKind::Insert | OpKind::Publish | OpKind::MakeLink);
        let expected = if in_the_slice { vec![attestation.clone()] } else { Vec::new() };
        assert_eq!(reached, expected, "{kind:?}");
    }
}

// ── the store-backed tests of `successor` and `publication` ──
//
// They sit here rather than beside the code they test: each builds its
// fixture through `OperationSurface::execute`, which the module order lets
// only `operation`, the last module, name, and each reads the surface's
// private `stores` for the snapshot it hands the function under test.

/// The principal [`fragmented_draft`]'s account is delegated to.
const DRAFT_OWNER: PrincipalId = PrincipalId(7);

/// A draft in a delegated account, driven through `execute`: three elements
/// with the middle one deleted, so one spec over its first two positions
/// resolves to TWO spans — and then its whole extent copied onto its own tail
/// `doublings` times. Each copy doubles the runs, the seam between one copy
/// and the next joining two I-addresses no run coalesces across, so the draft
/// ends at `2^(doublings + 1)` runs of one position each.
fn fragmented_draft(febe: &OperationSurface<World>, doublings: u32) -> Address {
    let issue = |session: SessionId, op: Op| {
        match febe.execute(session, Request { id: None, op, attest: None }) {
            Response::Rejected(rej) => panic!("the fixture's requests are answered: {rej}"),
            answered => answered,
        }
    };
    let boot = febe.bootstrap_session();
    let Response::MaybeAddr { addr: Some(prefix), .. } =
        issue(boot, Op::NextAccountPrefix { parent: addr(&[1]) })
    else {
        panic!("the genesis node has a delegable next-form prefix");
    };
    let Response::AckAddr { addr: account, .. } =
        issue(boot, Op::Delegate { new_prefix: prefix.tumbler().clone(), new_id: DRAFT_OWNER })
    else {
        panic!("the bootstrap session delegates the prefix");
    };
    let session = febe.open_session(DRAFT_OWNER);
    let Response::AckAddr { addr: doc, .. } =
        issue(session, Op::CreateNewDocument { account, published: Some(false) })
    else {
        panic!("the owner mints a draft");
    };
    let insert = Op::Insert {
        doc: doc.clone(),
        at: VPos::content(Nat::from(1u32)),
        values: [b'a', b'b', b'c'].map(|b| Val::new(vec![b])).to_vec(),
        deposit: Deposit::Undeclared,
    };
    assert!(matches!(issue(session, insert), Response::AckAddr { .. }), "the owner fills its draft");
    let p = VPos::content(Nat::from(2u32));
    let deleted = issue(session, Op::Delete { doc: doc.clone(), p, width: Nat::from(1u32) });
    assert!(matches!(deleted, Response::Ack { .. }), "the owner deletes the middle element");
    for k in 0..doublings {
        let extent = 2u32 << k;
        let whole = Span::new(tum(&[1, 1]), tum(&[0, extent]))
            .unwrap_or_else(|_| panic!("well-formed test span"));
        let copy = Op::Copy {
            doc: doc.clone(),
            at: VPos::content(Nat::from(extent + 1)),
            specs: vec![VSpec { source: doc.clone(), span: whole }],
        };
        assert!(matches!(issue(session, copy), Response::Ack { .. }), "the owner doubles its draft");
    }
    doc
}

/// §4, the build a DEFERRED write gets: where the door did not judge the
/// write, EDITLINK's successor slot is never refused for its span budget —
/// that verdict is M7's, after its home gate — and stops ONE span past it, so
/// M7 is certain to refuse it and the build's own peak stays one slot's
/// worth however many specs follow. Where the door judged, the same slot is
/// refused as it crosses, naming the slot. A slot exactly at the budget is
/// an ordinary slot under both.
#[test]
fn an_unjudged_successor_slot_stops_one_span_past_the_budget() {
    let febe = surface();
    let doc = fragmented_draft(&febe, 0);
    let snap = febe.stores.kernel().snapshot();
    let (m3, m5) = (snap.world().m3(), snap.world().m5());
    let two_spans = || VSpec {
        source: doc.clone(),
        span: Span::new(tum(&[1, 1]), tum(&[0, 2]))
            .unwrap_or_else(|_| panic!("well-formed test span")),
    };
    assert_eq!(m5.resolve(&doc, &two_spans().span).len(), 2, "premise: two spans per spec");
    let successor = |specs: usize| SuccessorSpec {
        from: vec![two_spans(); specs],
        to: vec![],
        ty: SlotArg::Addrs(vec![doc.clone()]),
    };

    // Twice the budget's worth of specs: the slot crosses at the halfway
    // spec, and every spec after it resolves nothing more.
    let over = successor(MAX_SLOT_SPANS);
    let unjudged = successor_link(m3, m5, &over, false)
        .expect("an unjudged build leaves the budget to the store");
    assert_eq!(unjudged.from_slot().len(), MAX_SLOT_SPANS + 1, "one span past, and no further");
    let refused = successor_link(m3, m5, &over, true)
        .expect_err("a judged build refuses as the slot crosses");
    assert_eq!(refused.code, RejectCode::SlotTooLarge);
    assert_eq!(refused.site.and_then(|s| s.slot), Some(FROM), "the slot is named");

    // Exactly at the budget: an ordinary slot, whoever answers the budget.
    let at_cap = successor(MAX_SLOT_SPANS / 2);
    for judged in [true, false] {
        let link = successor_link(m3, m5, &at_cap, judged).expect("a slot at the budget");
        assert_eq!(link.from_slot().len(), MAX_SLOT_SPANS, "judged: {judged}");
    }
}

/// §4, the successor slot's WORK budget, and what an unjudged slot over it is
/// built to be. A spec opening past its source's arranged end keeps no span
/// while walking every run, so no span count sees the slot; only the charge
/// taken before each walk bounds it. Where the door judged, the slot is
/// refused as the charge crosses, naming the slot. Where it deferred, nothing
/// here refuses it and the slot is left one span past the span budget — so
/// where the store's own gate passes after all, in the window the deferral
/// leaves between the door's snapshot and the commit, M7 refuses the slot
/// rather than deposit a successor short of what was asked. One walk fewer is
/// the budget exactly, an ordinary slot under both.
#[test]
fn an_unjudged_successor_slot_over_the_work_budget_is_built_for_the_store_to_refuse() {
    let febe = surface();
    let doc = fragmented_draft(&febe, 10);
    let owner = febe.open_session(DRAFT_OWNER);
    let link_op = Op::MakeLink {
        home: doc.clone(),
        from: SlotArg::Addrs(vec![]),
        to: SlotArg::Addrs(vec![]),
        ty: SlotArg::Addrs(vec![doc.clone()]),
        replaces: None,
    };
    let original = match febe.execute(owner, Request { id: None, op: link_op, attest: None }) {
        Response::AckAddr { addr, .. } => addr,
        other => panic!("the owner links its draft: {other:?}"),
    };
    let snap = febe.stores.kernel().snapshot();
    let (m3, m5) = (snap.world().m3(), snap.world().m5());
    let run_count = m5.content_run_count(&doc);
    assert_eq!(run_count, 2048, "premise: one walk over this source passes 2048 runs");
    let past_the_end = || VSpec {
        source: doc.clone(),
        span: Span::new(tum(&[1, 2049]), tum(&[0, 1]))
            .unwrap_or_else(|_| panic!("well-formed test span")),
    };
    assert!(m5.resolve(&doc, &past_the_end().span).is_empty(), "premise: each spec keeps nothing");
    let at_budget = MAX_SLOT_RESOLVE_STEPS / run_count;
    assert_eq!(at_budget * run_count, MAX_SLOT_RESOLVE_STEPS, "premise: the budget is whole walks");
    let successor = |specs: usize| SuccessorSpec {
        from: vec![past_the_end(); specs],
        to: vec![],
        ty: SlotArg::Addrs(vec![doc.clone()]),
    };

    // One walk past the budget.
    let over = successor(at_budget + 1);
    let refused = successor_link(m3, m5, &over, true)
        .expect_err("a judged build refuses as the charge crosses");
    assert_eq!(refused.code, RejectCode::SlotTooLarge);
    let site = refused.site.expect("the slot is named");
    assert_eq!(site.slot, Some(FROM));
    assert!(site.index.is_none(), "the slot is at fault, not one spec in it");
    let built_to_fail = successor_link(m3, m5, &over, false)
        .expect("an unjudged build refuses nothing a source decides");
    assert_eq!(built_to_fail.from_slot().len(), MAX_SLOT_SPANS + 1, "one span past the span budget");

    // The window the deferral leaves: the store's own gate passes after all.
    // M7 refuses the slot there, and nothing is deposited.
    let before = febe.log_position();
    let visibility = |_: &World, _: &Address| true;
    let attempt = febe.stores.linkstore(&visibility).editlink(
        Caller::Principal(DRAFT_OWNER),
        &original,
        built_to_fail,
        &doc,
        &doc,
    );
    assert!(
        matches!(attempt, Err(TxnError::Rejected(EditLinkError::SlotTooLarge))),
        "{attempt:?}"
    );
    assert_eq!(febe.log_position(), before, "a successor short of what was asked is never deposited");

    // The budget exactly: an ordinary slot, whoever answers the budget.
    for judged in [true, false] {
        let link = successor_link(m3, m5, &successor(at_budget), judged).expect("a walk at the budget");
        assert!(link.from_slot().is_empty(), "judged: {judged}");
    }
}

/// PUB-8.12 / PUB-2.15, at `publication::birth_version`: the birth version is
/// the DOCUMENT's, whatever address of it is asked. A version member answers
/// its trunk's — the address the first `version` minted, with the content it
/// was born with — and never the opening slot of its own namespace, which no
/// mint produced. A document whose chain has no member answers none, and so
/// does an address of another tier, which anchors no chain.
#[test]
fn a_version_member_answers_its_trunks_birth_version() {
    let febe = surface();
    let issue = |session: SessionId, op: Op| {
        match febe.execute(session, Request { id: None, op, attest: None }) {
            Response::Rejected(rej) => panic!("the fixture's requests are answered: {rej}"),
            answered => answered,
        }
    };
    let boot = febe.bootstrap_session();
    let Response::MaybeAddr { addr: Some(prefix), .. } =
        issue(boot, Op::NextAccountPrefix { parent: addr(&[1]) })
    else {
        panic!("the genesis node has a delegable next-form prefix");
    };
    let Response::AckAddr { addr: account, .. } =
        issue(boot, Op::Delegate { new_prefix: prefix.tumbler().clone(), new_id: DRAFT_OWNER })
    else {
        panic!("the bootstrap session delegates the prefix");
    };
    let owner = febe.open_session(DRAFT_OWNER);
    let mint = |published: bool| {
        let op = Op::CreateNewDocument { account: account.clone(), published: Some(published) };
        match issue(owner, op) {
            Response::AckAddr { addr, .. } => addr,
            other => panic!("the owner mints a document: {other:?}"),
        }
    };
    let edition = mint(true);
    let draft = mint(false);
    let deposit = Op::Insert {
        doc: edition.clone(),
        at: VPos::content(Nat::from(1u32)),
        values: [b'a', b'b', b'c'].map(|b| Val::new(vec![b])).to_vec(),
        deposit: Deposit::Declared(deposit_class_types()[0].clone()),
    };
    assert!(matches!(issue(owner, deposit), Response::AckAddr { .. }), "the owner deposits");
    let Response::AckAddr { addr: member, .. } =
        issue(owner, Op::Version { d_src: edition.clone(), published: None })
    else {
        panic!("the owner versions its edition");
    };

    let snap = febe.stores.kernel().snapshot();
    let (m3, m5) = (snap.world().m3(), snap.world().m5());
    let born = Some(BirthVersion { addr: member.clone(), extent: Nat::from(3u32) });
    assert_eq!(birth_version(m3, m5, &edition), born, "the trunk answers its chain's opening");
    assert_eq!(
        birth_version(m3, m5, &member),
        born,
        "a member answers its trunk's birth version, never its own namespace's opening slot"
    );
    assert_eq!(birth_version(m3, m5, &draft), None, "a chain with no member has no birth version");
    assert_eq!(birth_version(m3, m5, &account), None, "no tier but a document's anchors a chain");
}
