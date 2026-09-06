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
use skep_arrangement::{HasM5, M5Rec, M5State, Run, VPos, VSpec};
use skep_content::{ContentStore, ContentWrite, HasContent, Val};
use skep_discovery::{OrphanReport, SupClaim, Window};
use skep_febe::{Op, Operation, Rejection, ReqId, Request, Response, SessionId, Stores};
use skep_kernel::{CheckpointPolicy, Durability, Kernel, KernelConfig, Seq, WorldState};
use skep_links::{
    enc, Endset, HasLinks, Invalid, Link, LinkRec, LinkState, LinkWriter,
};
use skep_namespace::{HasM3, M3Rec, M3State, PrincipalId};
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

pub fn tum(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
}

pub fn addr(comps: &[u32]) -> Address {
    validate(tum(comps)).unwrap_or_else(|_| panic!("test addresses are T4-valid"))
}

pub fn nat(x: u32) -> Nat {
    Nat::from(x)
}

/// The genesis bootstrap node `[1]`.
pub fn node1() -> Address {
    addr(&[1])
}

/// Reserved type address `k` — ghost tumbler `[1,1,0,1,0,1,0,1,k]` (the
/// compiled format constants for k = 1..=5).
pub fn ra(k: u32) -> Address {
    addr(&[1, 1, 0, 1, 0, 1, 0, 1, k])
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
    VPos { subspace: nat(subspace), ordinal: nat(ordinal) }
}

/// An ordinal-level depth-2 V-span `[subspace, ord] w [0, width]`.
pub fn vspan(subspace: u32, ord: u32, width: u32) -> Span {
    Span::new(tum(&[subspace, ord]), tum(&[0, width]))
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
        links: LinkState::genesis(),
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
    fn linkstore(&self) -> LinkWriter<'_, World> {
        LinkWriter::new(&self.kernel)
    }
}

pub fn operation() -> Operation<World> {
    Operation::new(Box::new(KernelStores { kernel: kernel() }))
}

// ───────────────────────────── request helpers ──────────────────────────────

pub fn ex(febe: &Operation<World>, session: SessionId, op: Op) -> Response {
    febe.execute(session, Request { id: None, op })
}

pub fn ex_id(febe: &Operation<World>, session: SessionId, id: &[u8], op: Op) -> Response {
    febe.execute(session, Request { id: Some(ReqId(id.to_vec())), op })
}

// ─────────────────────────── response extractors ────────────────────────────
//
// One per `Response` variant, each named for the variant it opens, so an
// assertion reads as the shape it expects and a wrong shape panics with the
// name. `bool_val` is the one departure: the bare variant name is a primitive
// type's, legal in the value namespace and unreadable.

pub fn rejected(r: Response) -> Rejection {
    match r {
        Response::Rejected(rej) => rej,
        _ => panic!("expected Rejected, got a success response"),
    }
}

/// The snapshot coordinate a read answer reports (A2/V1) — the one field
/// every read shape carries and every extractor below drops.
///
/// EXHAUSTIVE with no `_` arm, for the reason `Response::as_ack` is: a new
/// response shape must be classified as a read answer or not before this
/// file compiles. The three acknowledging shapes carry a *committed*
/// coordinate, not a snapshot one, so asking here is the question's own
/// mistake and says so.
pub fn as_of(r: &Response) -> Seq {
    match r {
        Response::Delivery { as_of, .. }
        | Response::SpanSet { as_of, .. }
        | Response::Addrs { as_of, .. }
        | Response::MaybeAddr { as_of, .. }
        | Response::Count { as_of, .. }
        | Response::Page { as_of, .. }
        | Response::Endsets { as_of, .. }
        | Response::Runs { as_of, .. }
        | Response::Bool { as_of, .. }
        | Response::LinkValue { as_of, .. }
        | Response::Follow { as_of, .. }
        | Response::Deletions { as_of, .. }
        | Response::Compare { as_of, .. }
        | Response::Orphans { as_of, .. }
        | Response::Claims { as_of, .. } => *as_of,
        Response::Rejected(rej) => panic!("expected a read answer, got a rejection: {rej}"),
        Response::Ack { .. } | Response::AckAddr { .. } | Response::AckEdit { .. } => {
            panic!("a committed write reports `at`, not `as_of`")
        }
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

pub fn bool_val(r: Response) -> bool {
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

pub fn deletions(r: Response) -> Deletions {
    match r {
        Response::Deletions { rep, .. } => rep,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        _ => panic!("expected Deletions"),
    }
}

pub fn compare(r: Response) -> CompareReport {
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
pub struct Fixture {
    pub febe: Operation<World>,
    pub boot: SessionId,
    pub user: SessionId,
    pub account: Address,
}

pub fn setup() -> Fixture {
    let febe = operation();
    let boot = febe.bootstrap_session();
    let (prefix, _) = maybe_addr(ex(&febe, boot, Op::NextAccountPrefix { parent: node1() }));
    let prefix = prefix.expect("the genesis node has a delegable next-form prefix");
    let (account, _) = ack_addr(ex(
        &febe,
        boot,
        Op::Delegate { new_prefix: prefix.tumbler().clone(), new_id: USER },
    ));
    let user = febe.open_session(USER);
    Fixture { febe, boot, user, account }
}

pub fn create_doc(fx: &Fixture) -> Address {
    ack_addr(ex(&fx.febe, fx.user, Op::CreateNewDocument { account: fx.account.clone(), published: None })).0
}

/// Insert three one-byte values at the head of `doc`'s content subspace;
/// returns the placed run's start address and the commit `Seq`.
pub fn insert3(fx: &Fixture, doc: &Address) -> (Address, Seq) {
    ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::Insert {
            doc: doc.clone(),
            at: vp(1, 1),
            values: vec![Val::new(vec![b'a']), Val::new(vec![b'b']), Val::new(vec![b'c'])],
        },
    ))
}
