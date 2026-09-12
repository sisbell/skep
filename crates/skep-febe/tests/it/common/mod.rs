//! Shared test scaffolding: a minimal engine-side world (the composition
//! contract's assembler role, in miniature) over M3 + M4 + M5 + M7, an
//! in-memory kernel, the `Stores` factory the binary would build, and
//! response extractors. Everything past genesis is driven through the FEBE
//! surface itself (bootstrap → delegate → create → …), exercising the real
//! request lifecycle end-to-end.

use std::cell::RefCell;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Span, SpanSet, Tumbler};
use skep_arrangement::{HasM5, M5Rec, M5State, Run, VPos, VSpec};
use skep_content::{ContentStore, ContentWrite, HasContent, Val};
use skep_discovery::{OrphanReport, SupClaim, Window};
use skep_febe::{
    BirthVersion, Deposit, Disposition, EditionClaim, Op, OpKind, Operation, RejectCode, Rejection,
    ReqId, Request, Response, SessionId, Stores,
};
use skep_kernel::{CheckpointPolicy, Durability, Kernel, KernelConfig, Seq, WorldState};
use skep_links::{enc, Endset, HasLinks, Invalid, Link, LinkRec, LinkState};
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
impl skep_febe::ReadableWorld for World {
    // Masking (published ∨ subtree ∨ grant) is the engine's predicate; this
    // miniature world carries no exception set or grant fold, and the suites
    // built on [`setup`] (lifecycle, coordinates, concurrency) are orthogonal
    // to it — so every read is admitted. A suite that is ABOUT the door takes
    // [`setup_with_unreadable`], which supplies its own `ReadPredicate`.
    fn readable(&self, _principal: Option<PrincipalId>, _doc: &Address) -> bool {
        true
    }
}
thread_local! {
    /// The rows this world's [`skep_febe::PublicationWorld`] answers with, for
    /// ANY target. The CLASS is the engine's composition — its pinned type
    /// address lives there, beside the grant type — so this miniature world
    /// carries none of its own and answers the empty class unless a test
    /// seeds it through [`seed_edition_claims`].
    ///
    /// Cleared by [`operation`], which every fixture below goes through, so
    /// the table a test sees is its own whether the harness gives each test a
    /// thread, a process, or neither: no test depends on the order the suite
    /// runs in.
    static EDITION_CLAIMS: RefCell<Vec<EditionClaim>> = const { RefCell::new(Vec::new()) };
}

/// Seed the rows `Op::EditionClaims` is answered with, UNFILTERED — M10's own
/// home rule (PUB-6.13) is what a test using this is about.
pub fn seed_edition_claims(rows: Vec<EditionClaim>) {
    EDITION_CLAIMS.with(|c| *c.borrow_mut() = rows);
}

impl skep_febe::PublicationWorld for World {
    fn edition_claims(&self, _target: &Address) -> Vec<EditionClaim> {
        EDITION_CLAIMS.with(|c| c.borrow().clone())
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

/// A document-tier address under `account` that no mint ever produced — the
/// account's document chain at an ordinal its frontier has not reached.
pub fn ghost_doc(account: &Address, ordinal: u32) -> Address {
    let comps = account.tumbler().iter().cloned().chain([nat(0), nat(ordinal)]);
    validate(Tumbler::new(comps).expect("nonempty"))
        .unwrap_or_else(|_| panic!("a document under a T4-valid account is T4-valid"))
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
}

pub fn operation() -> Operation<World> {
    seed_edition_claims(Vec::new()); // the empty class, until a test seeds it
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
        other => panic!("expected Rejected, got {other:?}"),
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
        | Response::Claims { as_of, .. }
        | Response::DocMetadata { as_of, .. }
        | Response::EditionClaims { as_of, .. } => *as_of,
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
        other => panic!("expected Ack, got {other:?}"),
    }
}

pub fn ack_addr(r: Response) -> (Address, Seq) {
    match r {
        Response::AckAddr { addr, at } => (addr, at),
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected AckAddr, got {other:?}"),
    }
}

pub fn ack_edit(r: Response) -> (Address, Address, Seq) {
    match r {
        Response::AckEdit { successor, claim, at } => (successor, claim, at),
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected AckEdit, got {other:?}"),
    }
}

pub fn maybe_addr(r: Response) -> (Option<Address>, Seq) {
    match r {
        Response::MaybeAddr { addr, as_of } => (addr, as_of),
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected MaybeAddr, got {other:?}"),
    }
}

pub fn delivery(r: Response) -> (Delivery, Seq) {
    match r {
        Response::Delivery { items, as_of } => (items, as_of),
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected Delivery, got {other:?}"),
    }
}

pub fn spanset(r: Response) -> (SpanSet, Seq) {
    match r {
        Response::SpanSet { set, as_of } => (set, as_of),
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected SpanSet, got {other:?}"),
    }
}

pub fn addrs(r: Response) -> Vec<Address> {
    match r {
        Response::Addrs { addrs, .. } => addrs,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected Addrs, got {other:?}"),
    }
}

pub fn count(r: Response) -> usize {
    match r {
        Response::Count { n, .. } => n,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected Count, got {other:?}"),
    }
}

pub fn page(r: Response) -> Window {
    match r {
        Response::Page { window, .. } => window,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected Page, got {other:?}"),
    }
}

pub fn endsets(r: Response) -> Vec<(usize, Endset)> {
    match r {
        Response::Endsets { pairs, .. } => pairs,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected Endsets, got {other:?}"),
    }
}

pub fn runs(r: Response) -> Vec<Run> {
    match r {
        Response::Runs { runs, .. } => runs,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected Runs, got {other:?}"),
    }
}

pub fn bool_val(r: Response) -> bool {
    match r {
        Response::Bool { val, .. } => val,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected Bool, got {other:?}"),
    }
}

pub fn link_value(r: Response) -> Option<Link> {
    match r {
        Response::LinkValue { link, .. } => link,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected LinkValue, got {other:?}"),
    }
}

pub fn follow(r: Response) -> Result<SpanSet, Invalid> {
    match r {
        Response::Follow { result, .. } => result,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected Follow, got {other:?}"),
    }
}

pub fn deletions(r: Response) -> Deletions {
    match r {
        Response::Deletions { rep, .. } => rep,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected Deletions, got {other:?}"),
    }
}

pub fn compare(r: Response) -> CompareReport {
    match r {
        Response::Compare { rep, .. } => rep,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected Compare, got {other:?}"),
    }
}

pub fn orphans(r: Response) -> OrphanReport {
    match r {
        Response::Orphans { report, .. } => report,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected Orphans, got {other:?}"),
    }
}

pub fn claims(r: Response) -> Vec<SupClaim> {
    match r {
        Response::Claims { claims, .. } => claims,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected Claims, got {other:?}"),
    }
}

/// The doc-metadata answer as `(doc, published, owner, birth)`.
pub fn doc_metadata(r: Response) -> (Address, bool, Option<Address>, Option<BirthVersion>) {
    match r {
        Response::DocMetadata { doc, published, owner, birth, .. } => {
            (doc, published, owner, birth)
        }
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected DocMetadata, got {other:?}"),
    }
}

pub fn edition_claims(r: Response) -> Vec<EditionClaim> {
    match r {
        Response::EditionClaims { claims, .. } => claims,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected EditionClaims, got {other:?}"),
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

/// A DRAFT in the fixture's account — an explicit `false`, since the
/// account's flagless first mint is its born-published home (PUB-8.21) and a
/// published document takes no in-place edit (PUB-2.11): the documents these
/// tests write are drafts. (The explicit-`false` FIRST mint is refused at the
/// daemon's door alone, PUB-8.20; M10 and M3 mint it.)
pub fn create_doc(fx: &Fixture) -> Address {
    ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::CreateNewDocument { account: fx.account.clone(), published: Some(false) },
    ))
    .0
}

/// A PUBLISHED edition in the fixture's account — the one owned source
/// `version` admits (PUB-2.9), and the target the in-place refusal keys on.
pub fn create_edition(fx: &Fixture) -> Address {
    ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::CreateNewDocument { account: fx.account.clone(), published: Some(true) },
    ))
    .0
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
            deposit: Deposit::Undeclared,
        },
    ))
}

/// [`insert3`] as a DECLARED deposit — the one way content enters a
/// PUBLISHED document on this surface (PUB-2.59, PUB-9.13): three values at
/// the empty edition's fresh positions.
pub fn deposit3(fx: &Fixture, doc: &Address) -> (Address, Seq) {
    ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::Insert {
            doc: doc.clone(),
            at: vp(1, 1),
            values: vec![Val::new(vec![b'a']), Val::new(vec![b'b']), Val::new(vec![b'c'])],
            deposit: Deposit::Declared,
        },
    ))
}

// ───────────────── the readability fixture (the door's two sides) ───────────
//
// The front door answers ONE predicate, so a supplied `ReadPredicate` under
// which a document is unreadable to everyone but its owner is what a private
// draft looks like to this suite — the miniature world carries no exception
// set or grant fold, and the engine's own predicate is the daemon suites' to
// exercise (`skepd/tests/source_gate.rs`). What the suites built on this
// fixture pin is the DOOR's own contract, independent of how the predicate is
// derived.
//
// Three words, three concepts, each the corpus's: a DOCUMENT is unreadable
// (PUB-6.1), a REQUEST is refused, an ANSWER is withheld.

/// A second principal, delegated under the genesis node beside [`USER`]:
/// the NON-ENTITLED stranger of every cell below.
pub const OTHER: PrincipalId = PrincipalId(8);

/// The documents that are UNREADABLE under the supplied predicate to every
/// principal but [`USER`] — a draft of USER's, as far as the door can tell.
/// Readability is relational, so this is not a property the documents carry:
/// the same document is readable to USER and unreadable to the stranger,
/// which is the whole of what the fixture arranges. Shared with the predicate
/// closure and filled once the documents exist.
pub type Unreadable = Arc<Mutex<Vec<Address>>>;

/// The standard fixture under a predicate that admits USER everywhere and
/// leaves `unreadable` unreadable to every other principal — the shape the
/// engine's own predicate takes on a private draft (the owner reads by the
/// subtree clause, a stranger does not), and the GUEST's too, since a session
/// resolving to no principal is not `Some(USER)` either.
pub fn setup_with_unreadable() -> (Fixture, Unreadable) {
    let unreadable: Unreadable = Arc::new(Mutex::new(Vec::new()));
    let predicate = {
        let unreadable = Arc::clone(&unreadable);
        move |principal: Option<PrincipalId>, doc: &Address| {
            principal == Some(USER) || !unreadable.lock().expect("no poisoning").contains(doc)
        }
    };
    let febe = operation().with_read_predicate(predicate);
    let boot = febe.bootstrap_session();
    let (prefix, _) = maybe_addr(ex(&febe, boot, Op::NextAccountPrefix { parent: node1() }));
    let prefix = prefix.expect("the genesis node has a delegable next-form prefix");
    let (account, _) = ack_addr(ex(
        &febe,
        boot,
        Op::Delegate { new_prefix: prefix.tumbler().clone(), new_id: USER },
    ));
    let user = febe.open_session(USER);
    (Fixture { febe, boot, user, account }, unreadable)
}

/// PUB-8.4/8.5 at the door: `withheld`, `reorder`, `site.addr` the document,
/// no `detail`.
pub fn assert_withheld(r: Response, kind: OpKind, doc: &Address) {
    let rej = rejected(r);
    assert_eq!(rej.op, kind);
    assert_eq!(rej.code, RejectCode::Withheld, "{rej}");
    assert_eq!(rej.disposition, Disposition::Reorder);
    assert_eq!(rej.site.expect("the withheld document rides the site").addr.as_ref(), Some(doc));
    assert!(rej.detail.is_none(), "PUB-8.5: no detail on this code, ever");
}
