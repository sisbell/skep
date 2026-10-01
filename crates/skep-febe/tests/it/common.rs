//! Shared test scaffolding: a minimal engine-side world (the composition
//! contract's assembler role, in miniature) over M3 + M4 + M5 + M7, an
//! in-memory kernel (and a journaled one, for a test that reads history
//! back), the `Stores` factory the binary would build, response extractors,
//! and the chain that commits every write once. Everything past genesis is
//! driven through the FEBE surface itself (bootstrap → delegate → create →
//! …), exercising the real request lifecycle end-to-end.

use std::cell::{Cell, RefCell};
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Span, SpanSet, Tumbler};
use skep_arrangement::{deposit_class_types, HasM5, M5Rec, M5State, Run, VPos, VSpec};
use skep_content::{ContentStore, ContentWrite, HasContent, Val};
use skep_discovery::{OrphanReport, SupClaim, Window};
use skep_febe::{
    Base, BirthVersion, Deposit, Disposition, EditionClaim, Op, OpKind, OperationSurface,
    RejectCode, Rejection, ReqId, Request, Response, SessionId, Shot, ShotRun, SlotArg, Stores,
    SuccessorSpec, UniversalGrant, UniversalIndexRow,
};
use skep_kernel::{
    Attestation, BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelConfig, SaltSource,
    Seq, WorldState,
};
use skep_links::{enc, Endset, HasLinks, Invalid, Link, LinkRec, LinkState};
use skep_namespace::{HasM3, M3Rec, M3State, PrincipalId};
use skep_retrieval::{CompareReport, Deletions, Delivery, DeliveryItem, Spec};

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
thread_local! {
    /// The documents this world's OWN [`skep_febe::ReadableWorld`] refuses to
    /// every principal but [`USER`] — the arm a front door built by
    /// `OperationSurface::new` ALONE answers through, which is the live
    /// daemon's configuration. EMPTY by default, so every read is admitted
    /// and every suite that is not about this arm is unaffected.
    ///
    /// Cleared by [`surface_over`], as [`EDITION_CLAIMS`] is, so the table a
    /// test sees is its own whether the harness gives each test a thread, a
    /// process, or neither: no test depends on the order the suite runs in.
    static UNREADABLE_WORLD: RefCell<Vec<Address>> = const { RefCell::new(Vec::new()) };
}

/// Seed the documents the WORLD's own predicate refuses. A test that is about
/// the SUPPLIED predicate takes [`setup_with_unreadable`] instead; the two
/// spell the same rule, so which predicate answers is the whole of what a
/// test using one and not the other exercises.
pub fn seed_unreadable_world(docs: Vec<Address>) {
    UNREADABLE_WORLD.with(|u| *u.borrow_mut() = docs);
}

impl skep_febe::ReadableWorld for World {
    /// Deriving the engine's real predicate — published ∨ subtree ∨ grant — is
    /// the engine's, and its suite's; this miniature world carries no
    /// exception set and no grant fold. What it carries is the ability to
    /// REFUSE, so the fork in `OperationSurface::readable` has both arms
    /// reachable from here: seeded through [`seed_unreadable_world`], this
    /// answers for a front door that supplies no predicate of its own.
    fn readable(&self, principal: Option<PrincipalId>, doc: &Address) -> bool {
        principal == Some(USER) || UNREADABLE_WORLD.with(|u| !u.borrow().contains(doc))
    }
}
thread_local! {
    /// The rows this world's [`skep_febe::PublicationWorld`] answers with, for
    /// ANY target. The CLASS is the engine's composition — its pinned type
    /// address lives there, beside the grant type — so this miniature world
    /// carries none of its own and answers the empty class unless a test
    /// seeds it through [`seed_edition_claims`].
    ///
    /// Cleared by [`surface_over`], which every fixture below goes through,
    /// so the table a test sees is its own whether the harness gives each
    /// test a thread, a process, or neither: no test depends on the order the
    /// suite runs in.
    static EDITION_CLAIMS: RefCell<Vec<EditionClaim>> = const { RefCell::new(Vec::new()) };
}

/// Seed the rows `Op::EditionClaims` is answered with, UNFILTERED — M10's own
/// home rule (PUB-6.13) is what a test using this is about.
pub fn seed_edition_claims(rows: Vec<EditionClaim>) {
    EDITION_CLAIMS.with(|c| *c.borrow_mut() = rows);
}

thread_local! {
    /// The STORED rows this world's [`skep_febe::PublicationWorld`] hands the
    /// any-principal discovery read (PUB-8.47) — the live universal INDEX as
    /// the engine would enumerate it, content prefix and issuers per row. The
    /// fold is the engine's composition, so this miniature world carries none
    /// of its own and answers the empty index unless a test seeds it through
    /// [`seed_universal_grant_index`]; the FOLD-FILTER that narrows each row
    /// into a served one (RES-231/264/273/298) is M10's own and is what a test
    /// seeding this is about. Cleared by [`surface_over`], as
    /// [`EDITION_CLAIMS`] is.
    static UNIVERSAL_GRANT_INDEX: RefCell<Vec<UniversalIndexRow>> =
        const { RefCell::new(Vec::new()) };
}

/// Seed the index rows `Op::UniversalGrants` is answered from, RAW — the
/// index, never the answer set: M10's own narrowing is what a test using
/// this is about.
pub fn seed_universal_grant_index(rows: Vec<UniversalIndexRow>) {
    UNIVERSAL_GRANT_INDEX.with(|g| *g.borrow_mut() = rows);
}

thread_local! {
    /// How many times this world's universal index has been ENUMERATED — the
    /// unit the any-principal read's cost is paid in (PUB-8.47: "enumerated
    /// once per request", and never for the guest). Reset by
    /// [`surface_over`], as [`UNIVERSAL_GRANT_INDEX`] is.
    static UNIVERSAL_GRANT_INDEX_READS: Cell<usize> = const { Cell::new(0) };
}

/// How many times M10 has enumerated the universal index since the surface
/// was built.
pub fn universal_grant_index_reads() -> usize {
    UNIVERSAL_GRANT_INDEX_READS.with(Cell::get)
}

impl skep_febe::PublicationWorld for World {
    /// The seeded rows, for ANY target — once the one precondition the seam
    /// states holds: `target` is a REGISTERED DOCUMENT, which M10 owes the
    /// lookup and discharges with its own registration refusal ahead of it
    /// (`PublicationWorld::edition_claims`). The engine's lookup ranges over
    /// `target`'s whole subtree, so asked about an account or a node it walks
    /// every claim beneath; a double that answered anyway would let a front
    /// door that asked first and refused after pass every test.
    fn edition_claims(&self, target: &Address) -> Vec<EditionClaim> {
        assert!(
            self.m3.is_registered_document(target),
            "M10 asked the edition-claim lookup about {target}, which is not a registered \
             document: the seam's precondition was not discharged"
        );
        EDITION_CLAIMS.with(|c| c.borrow().clone())
    }
    /// The seeded index, each call counted as one ENUMERATION
    /// ([`universal_grant_index_reads`]).
    fn universal_grant_index(&self) -> Vec<UniversalIndexRow> {
        UNIVERSAL_GRANT_INDEX_READS.with(|n| n.set(n.get() + 1));
        UNIVERSAL_GRANT_INDEX.with(|g| g.borrow().clone())
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
pub fn reserved_type_addr(k: u32) -> Address {
    addr(&[1, 1, 0, 1, 0, 1, 0, 1, k])
}

/// The shipped Supersedes class as an address-denoting type endset.
pub fn supersedes_ty() -> Endset {
    enc(&[reserved_type_addr(4)])
}

/// The shipped PredDef class (Unary, idem⊤) — the one emitable shipped type.
pub fn pred_def_ty() -> Endset {
    enc(&[reserved_type_addr(1)])
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
        salt: SaltSource::Seeded(0),
    };
    Arc::new(Kernel::open(cfg, genesis_world()).expect("in-memory open cannot fail"))
}

/// A kernel journaled under `dir`, for a test that reads its history back —
/// the commit markers, of which an in-memory kernel keeps none.
pub fn journaled_kernel(dir: &Path) -> Arc<Kernel<World>> {
    let cfg = KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 1,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    };
    Arc::new(Kernel::open(cfg, genesis_world()).expect("a journaled open over a fresh directory"))
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

/// A front door over `kernel`, the miniature world's seeded tables and its
/// enumeration count cleared first, so a test sees only what it seeds itself
/// and counts only what it asks.
pub fn surface_over(kernel: Arc<Kernel<World>>) -> OperationSurface<World> {
    seed_edition_claims(Vec::new()); // the empty class, until a test seeds it
    seed_universal_grant_index(Vec::new()); // …the empty universal index, likewise
    UNIVERSAL_GRANT_INDEX_READS.with(|n| n.set(0)); // …no enumeration of it counted yet
    seed_unreadable_world(Vec::new()); // …and a world that admits every read
    OperationSurface::new(Box::new(KernelStores { kernel }))
}

/// [`surface_over`] a fresh in-memory kernel.
pub fn surface() -> OperationSurface<World> {
    surface_over(kernel())
}

// ───────────────────────────── request helpers ──────────────────────────────

pub fn ex(febe: &OperationSurface<World>, session: SessionId, op: Op) -> Response {
    febe.execute(session, Request::from(op))
}

pub fn ex_id(febe: &OperationSurface<World>, session: SessionId, id: &[u8], op: Op) -> Response {
    febe.execute(session, Request { id: Some(ReqId(id.to_vec())), ..Request::from(op) })
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
/// every read shape carries and every extractor below drops. It asks M10's
/// own [`Response::as_of`], whose match is the classification, and requires
/// a read answer: an acknowledgment carries a *committed* coordinate and a
/// rejection none, so asking here is the question's own mistake and says so.
pub fn as_of(r: &Response) -> Seq {
    r.as_of().unwrap_or_else(|| panic!("expected a read answer, got {r:?}"))
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

/// ω's pair off the owner-of-address read (AUTH-6.37): `(prefix, principal)`,
/// or `None` where no registered principal's prefix contains the address.
pub fn effective_owner(r: Response) -> Option<(Address, PrincipalId)> {
    match r {
        Response::EffectiveOwner { owner, .. } => owner,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected EffectiveOwner, got {other:?}"),
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

/// The SERVED rows of the any-principal discovery read (PUB-8.47), in the
/// order they came back — covered prefix and issuers per row.
pub fn universal_grants(r: Response) -> Vec<UniversalGrant> {
    match r {
        Response::UniversalGrants { rows, .. } => rows,
        Response::Rejected(rej) => panic!("rejected: {rej:?}"),
        other => panic!("expected UniversalGrants, got {other:?}"),
    }
}

// ───────────────────────────── standard fixture ─────────────────────────────

pub const USER: PrincipalId = PrincipalId(7);

/// An `OperationSurface` plus a bootstrap session, one delegated account
/// under the genesis node, and an open session for its principal — all driven
/// through the FEBE surface itself.
pub struct Fixture {
    pub febe: OperationSurface<World>,
    pub boot: SessionId,
    pub user: SessionId,
    pub account: Address,
}

/// The standard fixture over [`surface`].
pub fn setup() -> Fixture {
    fixture_on(surface())
}

/// The standard fixture over `febe`, whichever kernel and predicate it was
/// built with.
pub fn fixture_on(febe: OperationSurface<World>) -> Fixture {
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

/// The deposit declaration this suite's declared fixtures carry: ENROLL's
/// type, the first member of M5's set (PUB-2.11, RES-261). What they deposit
/// is prose — PUB-2.60's residue, bytes of the depositor's choosing under a
/// declared class type — which M5 admits on the type alone.
pub fn declared() -> Deposit {
    Deposit::Declared(deposit_class_types()[0].clone())
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
            deposit: declared(),
        },
    ))
}

/// A three-element document and one link over it — the starting point every
/// EDITLINK case needs, the successor suite's and the retry memo's alike.
pub fn linked_doc(fx: &Fixture) -> (Address, Address) {
    let d = create_doc(fx);
    insert3(fx, &d);
    let (l, _) = ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::MakeLink {
            home: d.clone(),
            from: SlotArg::Resolve(vec![vspec(&d, 1, 1)]),
            to: SlotArg::Resolve(vec![vspec(&d, 2, 1)]),
            ty: SlotArg::Resolve(vec![vspec(&d, 3, 1)]),
            replaces: None,
        },
    ));
    (d, l)
}

/// A draft of `run_count` content runs of one position each, `run_count` a
/// power of two from 2: three elements with the middle one deleted — `a` and
/// `c`, at I-addresses no run joins — and then its whole extent copied onto
/// its own tail until it holds `run_count` positions, each copy doubling the
/// runs. Checked rather than trusted: the image is `a`'s and `c`'s two
/// one-position I-runs and the delivery alternates them, so no two
/// neighbouring positions are I-adjacent and every position is its own run.
pub fn fragmented_doc(fx: &Fixture, run_count: u32) -> Address {
    assert!(run_count >= 2 && run_count.is_power_of_two(), "a power of two from 2: {run_count}");
    let d = create_doc(fx);
    insert3(fx, &d);
    ack(ex(&fx.febe, fx.user, Op::Delete { doc: d.clone(), p: vp(1, 2), width: nat(1) }));
    let mut extent = 2;
    while extent < run_count {
        ack(ex(
            &fx.febe,
            fx.user,
            Op::Copy { doc: d.clone(), at: vp(1, extent + 1), specs: vec![vspec(&d, 1, extent)] },
        ));
        extent *= 2;
    }
    let whole = || vspan(1, 1, extent);
    let image = runs(ex(&fx.febe, fx.user, Op::Image { d: d.clone(), region: vec![whole()] }));
    assert!(image.len() == 2 && image.iter().all(|r| *r.width() == nat(1)), "{image:?}");
    let retrieve = Op::RetrieveV { specs: vec![Spec { doc: d.clone(), span: whole() }] };
    let (items, _) = delivery(ex(&fx.febe, fx.user, retrieve));
    let text: Vec<u8> = items
        .iter()
        .flat_map(|item| match item {
            DeliveryItem::Content(v) => v.as_bytes().to_vec(),
            other => panic!("every position is arranged content: {other:?}"),
        })
        .collect();
    assert_eq!(text, b"ac".repeat(run_count as usize / 2), "the delivery alternates a and c");
    d
}

// ──────────────────────────────── every write ───────────────────────────────

/// The committed coordinate an acknowledgment carries, whichever of the
/// three acknowledging shapes it is.
pub fn at_of(kind: OpKind, r: &Response) -> Seq {
    match r {
        Response::Ack { at } | Response::AckAddr { at, .. } | Response::AckEdit { at, .. } => *at,
        Response::Rejected(rej) => panic!("{kind:?} was rejected: {rej}"),
        _ => panic!("{kind:?} did not acknowledge a committed write"),
    }
}

/// All fifteen writes, once each, as one sequential chain over `fx`, every
/// one of the fifteen carrying `attest`; the fixtures the chain needs in
/// between are built through the plain helpers, which carry none. `each` is
/// handed each of the fifteen as it returns: its kind, the committed head
/// just before it was sent, and its answer.
pub fn commit_every_write(
    fx: &Fixture,
    attest: Option<&Attestation>,
    mut each: impl FnMut(OpKind, Seq, &Response),
) {
    let mut write = |session: SessionId, op: Op| {
        let kind = op.kind();
        let before = fx.febe.log_position();
        let r = fx.febe.execute(session, Request { attest: attest.cloned(), ..Request::from(op) });
        each(kind, before, &r);
        r
    };

    // ── the document family — the working document is a DRAFT (an explicit
    //    `false`: the account's flagless first mint would be its published
    //    home, which takes no in-place edit, PUB-2.11) ──
    let (draft, _) = ack_addr(write(
        fx.user,
        Op::CreateNewDocument { account: fx.account.clone(), published: Some(false) },
    ));
    ack_addr(write(
        fx.user,
        Op::Insert {
            doc: draft.clone(),
            at: vp(1, 1),
            values: vec![Val::new(vec![b'a']), Val::new(vec![b'b']), Val::new(vec![b'c'])],
            deposit: Deposit::Undeclared,
        },
    ));
    let (fork, _) = ack_addr(write(fx.user, Op::Fork { published: None }));

    // A version needs a PUBLISHED owned source (PUB-2.9): the edition.
    let edition = create_edition(fx);
    let (edition_start, _) = deposit3(fx, &edition);
    let (member, _) =
        ack_addr(write(fx.user, Op::Version { d_src: edition.clone(), published: None }));

    // The shot (lane 3.2): the next member off the head just minted, the
    // edition's own three positions supplied by reference.
    let shot = Shot {
        base: Some(Base { member, extent: nat(3) }),
        draft: None,
        runs: vec![ShotRun {
            origin: edition.clone(),
            run: Run::new(edition_start, nat(3)).expect("a content run"),
        }],
    };
    ack_addr(write(fx.user, Op::Publish { doc: edition, shot }));

    ack(write(fx.user, Op::Copy { doc: fork, at: vp(1, 1), specs: vec![vspec(&draft, 1, 1)] }));
    ack(write(fx.user, Op::Delete { doc: draft.clone(), p: vp(1, 3), width: nat(1) }));
    ack(write(fx.user, Op::Rearrange { doc: draft, cuts: vec![vp(1, 1), vp(1, 2), vp(1, 3)] }));

    // ── the link family, on a document whose three ordinals are intact ──
    let home = create_doc(fx);
    let (home_start, _) = insert3(fx, &home);
    let make = || Op::MakeLink {
        home: home.clone(),
        from: SlotArg::Resolve(vec![vspec(&home, 1, 1)]),
        to: SlotArg::Resolve(vec![vspec(&home, 2, 1)]),
        ty: SlotArg::Resolve(vec![vspec(&home, 3, 1)]),
        replaces: None,
    };
    let (l1, _) = ack_addr(write(fx.user, make()));
    let (l2, _) = ack_addr(ex(&fx.febe, fx.user, make()));
    ack_edit(write(
        fx.user,
        Op::EditLink {
            original: l1.clone(),
            successor: SuccessorSpec {
                from: vec![vspec(&home, 1, 1)],
                to: vec![vspec(&home, 2, 1)],
                ty: SlotArg::Resolve(vec![vspec(&home, 3, 1)]),
            },
            d_s: home.clone(),
            d_a: home.clone(),
        },
    ));
    ack_addr(write(fx.user, Op::AssertSup { home: home.clone(), old: l1, new: l2.clone() }));
    ack_addr(write(
        fx.user,
        Op::Emit { home: home.clone(), ty: pred_def_ty(), from: home_start, to: vec![] },
    ));
    ack_addr(write(fx.user, Op::Nullify { home, target: l2 }));

    // ── provisioning, under the bootstrap session ──
    let (prefix, _) = maybe_addr(ex(&fx.febe, fx.boot, Op::NextAccountPrefix { parent: node1() }));
    let prefix = prefix.expect("the genesis node is still delegable");
    ack_addr(write(
        fx.boot,
        Op::Delegate { new_prefix: prefix.tumbler().clone(), new_id: PrincipalId(11) },
    ));
    ack_addr(write(fx.boot, Op::RegisterNode { addr: tum(&[1, 4]) }));
}

// ───────────────── the readability fixture (the door's two sides) ───────────
//
// The front door answers ONE predicate, so a supplied `ReadPredicate` under
// which a document is unreadable to everyone but its owner is what a private
// draft looks like to this suite — the miniature world carries no exception
// set or grant fold, and the engine's own predicate is the daemon suites' to
// exercise (`skepd/tests/it/source_gate.rs`). What the suites built on this
// fixture pin is the DOOR's own contract, independent of how the predicate is
// derived.
//
// [`setup_with_unreadable`] supplies that predicate; the WORLD spells the same
// rule through [`seed_unreadable_world`], for the arm a front door that
// supplies none answers through. Which of the two a test takes is which arm
// it exercises.
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
    (fixture_on(surface().with_read_predicate(predicate)), unreadable)
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
