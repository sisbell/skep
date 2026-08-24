//! Shared test scaffolding: a minimal engine-side world (the composition
//! contract's assembler role, in miniature) over M3 + M4 + M5 + M7, an
//! in-memory kernel, the `Stores` factory the binary would build, and
//! response extractors. Everything past genesis is driven through the FEBE
//! surface itself (bootstrap → delegate → create → …), exercising the real
//! request lifecycle end-to-end.

#![allow(dead_code)] // each integration test binary uses a subset

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Span, SpanSet, Tumbler};
use skep_arrangement::{HasM5, M5Rec, M5State, Run, VPos, VSpec, Vstream};
use skep_content::{ContentStore, ContentWrite, HasContent, Val};
use skep_discovery::{OrphanReport, SupClaim, Window};
use skep_febe::{Op, Operation, Rejection, ReqId, Request, Response, SessionId, Stores};
use skep_kernel::{CheckpointPolicy, Durability, Kernel, KernelConfig, Seq, WorldState};
use skep_links::{
    enc, Endset, HasLinks, Invalid, Link, LinkRec, LinkState, LinkWriter, ReservedAddrs,
};
use skep_namespace::{HasM3, M3Rec, M3State, Namespace, PrincipalId};
use skep_retrieval::{CompareReport, Deletions, Delivery};

// ───────────────────────── the assembled test world ─────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct World {
    pub m3: M3State,
    pub content: ContentStore,
    pub m5: M5State,
    pub links: LinkState,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Record {
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

// ───────────────────────────── address fixtures ─────────────────────────────

pub fn t(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
}

pub fn a(comps: &[u32]) -> Address {
    validate(t(comps)).unwrap_or_else(|_| panic!("test addresses are T4-valid"))
}

pub fn n(x: u32) -> Nat {
    Nat::from(x)
}

/// The genesis bootstrap node `[1]`.
pub fn node1() -> Address {
    a(&[1])
}

/// Reserved type address `k` — element-level in subspace 9 (outside
/// {s_C, s_L}: reserved-isolation).
pub fn ra(k: u32) -> Address {
    a(&[9, 0, 9, 0, 9, 0, 9, k])
}

pub fn reserved() -> ReservedAddrs {
    ReservedAddrs {
        pred_def: ra(1),
        pred_stable: ra(2),
        retired: ra(3),
        supersedes: ra(4),
        retraction: ra(5),
    }
}

/// The shipped Supersedes class as an address-denoting type endset.
pub fn supersedes_ty() -> Endset {
    enc(&[ra(4)])
}

/// The shipped PredDef class (Unary, idem⊤) — the one emitable shipped type.
pub fn pred_def_ty() -> Endset {
    enc(&[ra(1)])
}

pub fn vp(subspace: u32, ordinal: u32) -> VPos {
    VPos { subspace: n(subspace), ordinal: n(ordinal) }
}

/// An ordinal-level depth-2 V-span `[subspace, ord] w [0, width]`.
pub fn vspan(subspace: u32, ord: u32, width: u32) -> Span {
    Span::new(t(&[subspace, ord]), t(&[0, width]))
        .unwrap_or_else(|_| panic!("well-formed test span"))
}

/// A content V-spec over `doc`.
pub fn vspec(doc: &Address, ord: u32, width: u32) -> VSpec {
    VSpec { source: doc.clone(), span: vspan(1, ord, width) }
}

// ─────────────────────────────── world assembly ─────────────────────────────

pub fn genesis_world() -> World {
    World {
        m3: M3State::genesis(),
        content: ContentStore::default(),
        m5: M5State::genesis(),
        links: LinkState::genesis(reserved(), vec![]).expect("test genesis type config is valid"),
    }
}

pub fn kernel() -> Arc<Kernel<World>> {
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
    };
    Arc::new(Kernel::open(cfg, genesis_world()).expect("in-memory open cannot fail"))
}

/// The production-shaped `Stores` factory the binary would build (the
/// as-built store-driver constructors of the design's Conflicts #6).
pub struct KernelStores {
    pub kernel: Arc<Kernel<World>>,
}

impl Stores<World> for KernelStores {
    fn kernel(&self) -> &Kernel<World> {
        &self.kernel
    }
    fn namespace(&self) -> Namespace<'_, World> {
        Namespace::new(&self.kernel)
    }
    fn vstream(&self) -> Vstream<'_, World> {
        Vstream::new(&self.kernel)
    }
    fn linkstore(&self) -> LinkWriter<'_, World> {
        LinkWriter::new(&self.kernel)
    }
}

pub fn operation() -> Operation<World> {
    Operation::new(Box::new(KernelStores { kernel: kernel() }))
}

// ───────────────────────────── request helpers ──────────────────────────────

pub fn ex(op: &Operation<World>, s: SessionId, o: Op) -> Response {
    op.execute(s, Request { id: None, op: o })
}

pub fn ex_id(op: &Operation<World>, s: SessionId, id: &[u8], o: Op) -> Response {
    op.execute(s, Request { id: Some(ReqId(id.to_vec())), op: o })
}

// ─────────────────────────── response extractors ────────────────────────────

pub fn rejected(r: Response) -> Rejection {
    match r {
        Response::Rejected(rej) => rej,
        _ => panic!("expected Rejected, got a success response"),
    }
}

pub fn ack(r: Response) -> Seq {
    match r {
        Response::Ack { at } => at,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected Ack"),
    }
}

pub fn ack_addr(r: Response) -> (Address, Seq) {
    match r {
        Response::AckAddr { addr, at } => (addr, at),
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected AckAddr"),
    }
}

pub fn ack_edit(r: Response) -> (Address, Address, Seq) {
    match r {
        Response::AckEdit { successor, claim, at } => (successor, claim, at),
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected AckEdit"),
    }
}

pub fn maybe_addr(r: Response) -> (Option<Address>, Seq) {
    match r {
        Response::MaybeAddr { addr, as_of } => (addr, as_of),
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected MaybeAddr"),
    }
}

pub fn delivery(r: Response) -> (Delivery, Seq) {
    match r {
        Response::Delivery { items, as_of } => (items, as_of),
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected Delivery"),
    }
}

pub fn spanset(r: Response) -> (SpanSet, Seq) {
    match r {
        Response::SpanSet { set, as_of } => (set, as_of),
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected SpanSet"),
    }
}

pub fn addrs(r: Response) -> Vec<Address> {
    match r {
        Response::Addrs { addrs, .. } => addrs,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected Addrs"),
    }
}

pub fn count(r: Response) -> usize {
    match r {
        Response::Count { n, .. } => n,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected Count"),
    }
}

pub fn page(r: Response) -> Window {
    match r {
        Response::Page { window, .. } => window,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected Page"),
    }
}

pub fn endsets(r: Response) -> Vec<(usize, Endset)> {
    match r {
        Response::Endsets { pairs, .. } => pairs,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected Endsets"),
    }
}

pub fn runs(r: Response) -> Vec<Run> {
    match r {
        Response::Runs { runs, .. } => runs,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected Runs"),
    }
}

pub fn boolv(r: Response) -> bool {
    match r {
        Response::Bool { val, .. } => val,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected Bool"),
    }
}

pub fn link_value(r: Response) -> Option<Link> {
    match r {
        Response::LinkValue { link, .. } => link,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected LinkValue"),
    }
}

pub fn follow(r: Response) -> Result<SpanSet, Invalid> {
    match r {
        Response::Follow { result, .. } => result,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected Follow"),
    }
}

pub fn deletions_rep(r: Response) -> Deletions {
    match r {
        Response::Deletions { rep, .. } => rep,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected Deletions"),
    }
}

pub fn compare_rep(r: Response) -> CompareReport {
    match r {
        Response::Compare { rep, .. } => rep,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected Compare"),
    }
}

pub fn orphans(r: Response) -> OrphanReport {
    match r {
        Response::Orphans { report, .. } => report,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected Orphans"),
    }
}

pub fn claims(r: Response) -> Vec<SupClaim> {
    match r {
        Response::Claims { claims, .. } => claims,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected Claims"),
    }
}

// ───────────────────────────── standard fixture ─────────────────────────────

pub const USER: PrincipalId = PrincipalId(7);

/// An `Operation` plus a bootstrap session, one delegated account under the
/// genesis node, and an open session for its principal — all driven through
/// the FEBE surface itself.
pub struct Fx {
    pub op: Operation<World>,
    pub boot: SessionId,
    pub s: SessionId,
    pub acct: Address,
}

pub fn setup() -> Fx {
    let op = operation();
    let boot = op.bootstrap_session();
    let (prefix, _) = maybe_addr(ex(&op, boot, Op::NextAccountPrefix { parent: node1() }));
    let prefix = prefix.expect("the genesis node has a delegable next-form prefix");
    let (acct, _) = ack_addr(ex(
        &op,
        boot,
        Op::Delegate { new_prefix: prefix.tumbler().clone(), new_id: USER },
    ));
    let s = op.open_session(USER);
    Fx { op, boot, s, acct }
}

pub fn create_doc(fx: &Fx) -> Address {
    ack_addr(ex(&fx.op, fx.s, Op::CreateNewDocument { account: fx.acct.clone() })).0
}

/// Insert three one-byte values at the head of `doc`'s content subspace;
/// returns the placed run's start address and the commit `Seq`.
pub fn insert3(fx: &Fx, doc: &Address) -> (Address, Seq) {
    ack_addr(ex(
        &fx.op,
        fx.s,
        Op::Insert {
            doc: doc.clone(),
            at: vp(1, 1),
            values: vec![Val::new(vec![b'a']), Val::new(vec![b'b']), Val::new(vec![b'c'])],
        },
    ))
}
