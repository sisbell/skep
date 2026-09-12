//! The parsed request model: [`Request`]/[`ReqId`], the [`Op`] enum (one
//! variant per FEBE operation), the [`OpKind`] fieldless echo, and the
//! read/write partition the lifecycle gates on (§1).

use skep_address::{Address, Nat, Span, Tumbler};
use skep_arrangement::{Deposit, Shot, VPos, VSpec};
use skep_content::Val;
use skep_discovery::{Cursor, FourSet};
use skep_links::{Endset, SlotArg, View};
use skep_namespace::PrincipalId;
use skep_retrieval::{RegionSpec, Spec};

/// One parsed FEBE request: an optional idempotency key plus the operation.
/// `id` is used ONLY to key the retry memo (§1(a)/§7); it is never echoed on
/// the response path (§8).
///
/// A value, with [`Op`]'s derives and for [`Op`]'s reason: `execute` consumes
/// a request, so a transport that records, reorders or reissues what it
/// dispatched keeps a clone of one.
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    /// The client's idempotency key (optional): a token the CLIENT chooses,
    /// unique only within its own session.
    pub id: Option<ReqId>,
    /// The parsed operation.
    pub op: Op,
}

/// The client's idempotency key — chosen by the client, unique only within
/// its session (§7), and half of the memo's key, which pairs it with the
/// session that committed under it.
///
/// What the key buys is the answer to a retry sent AFTER the original's
/// acknowledgment was lost. Two requests carrying one id concurrently are two
/// operations, since the memo is consulted before dispatch and written after
/// it, and a restart empties it — so this is a hint that saves a duplicate
/// commit, never a guarantee against one.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ReqId(pub Vec<u8>);

/// The most bytes one idempotency key may carry into the memo.
///
/// The bill this bounds is M10's, so the number is M10's. A committed write's
/// key stays RESIDENT for the life of its cache entry — until eviction, or
/// until [`Operation::close_session`] purges the session — so the memo's
/// retention is (cache capacity) × (this cap), and both factors have to be
/// finite for the product to be. With this one uncapped the other factor
/// would be whatever body size the transport admits: one session's worth of
/// committed writes retaining gigabytes that do not clear when the caller
/// stops, unlike every CPU cost on this surface.
///
/// 256 bytes is far above any key a client needs — a UUID is 36 characters, a
/// hex-encoded 256-bit value 64 — and puts the retained bill at a quarter
/// megabyte against the memo's 1024 entries.
///
/// A transport refuses an over-long id at parse, which is the first door and
/// the one that tells the client. [`crate::Operation`] holds the second: a key
/// past this bound is simply not memoized, so a hand-assembled [`Request`]
/// cannot enlarge the bill by skipping the parser.
///
/// [`Operation::close_session`]: crate::Operation::close_session
pub const MAX_REQ_ID_BYTES: usize = 256;

/// The parsed request — one variant per FEBE operation (args in M1/M5/M7/M8
/// types; the principal comes from the session, never the wire).
///
/// A value, because [`Operation::execute`] consumes one: a transport that
/// wants to hold what it dispatched — to log it, to buffer it for reorder, to
/// reissue it under [`Request::id`] — keeps a clone, and one that classifies a
/// request through [`Op::is_read`] before dispatching it can then still
/// dispatch it. Comparison for the same callers: a harness pins the request it
/// built against the one a parser produced.
///
/// [`Operation::execute`]: crate::Operation::execute
///
/// NOT `Debug`, on one leaf: M4's `Val`, which withholds it so that content
/// bytes never render into a log. NOT `Hash`, on that leaf and M1's `Address`.
/// Deliberately not `#[non_exhaustive]` either: a consumer's exhaustive match
/// over this enum is what forces a new operation to be given a wire name and a
/// marshaling, where a `_` arm would silently drop it.
#[derive(Clone, PartialEq, Eq)]
pub enum Op {
    // ── namespace writes (→ M3) ──
    /// CREATENEWDOCUMENT (ASN-0103): baptize a fresh empty document.
    ///
    /// `published` is the three-valued publication flag (PUB-8.16:
    /// `absent | true | false`, `None` being absent). The wire default is
    /// PRIVATE (PUB-1.1); the ABSENT arm resolves at M3's create path — the
    /// account's FIRST document born published, every later flagless one
    /// private (PUB-8.21). M10 passes it through verbatim; the explicit-false
    /// FIRST-mint refusal is the DAEMON's door alone (PUB-8.20, owner ruling
    /// D2c), never this type's.
    CreateNewDocument { account: Address, published: Option<bool> },
    /// Delegation (ASN-0042 O15): baptize an account prefix + register its
    /// principal atomically.
    Delegate { new_prefix: Tumbler, new_id: PrincipalId },
    /// NodeBaptism admission (ASN-0047): the address is supplied by
    /// provisioning, not minted.
    ///
    /// A bound session is the ONLY gate on this path, and no module holds a
    /// stronger one. Step (b) proves that some session is bound and nothing
    /// further; `Namespace::register_node` takes no principal, so this arm
    /// passes none, and `NodeError` carries no authority variant, so M3 makes
    /// no ownership or tier check either. Any bound session, speaking for any
    /// principal, may therefore register a node-tier entity — confining this
    /// to provisioning is policy nobody enforces.
    RegisterNode { addr: Tumbler },
    /// Denial-as-fork (O10, account tier): a fresh EMPTY document in the
    /// caller's own account — shares NO content (the content-sharing fork is
    /// [`Op::Version`]; §3).
    ///
    /// `published` is the three-valued flag (PUB-8.16), handed through
    /// verbatim to `Namespace::fork`, which resolves it at M3's create path
    /// exactly as [`Op::CreateNewDocument`]'s is (fork reduces to a create in
    /// the caller's own account — one rule, one place, owner 2026-09-05). A
    /// first fork into an empty account is refused `mint_home_first` at the
    /// daemon (PUB-8.22) before the flag is consulted.
    Fork { published: Option<bool> },
    // ── namespace reads (→ M3) ──
    /// M3's next-form delegable prefix — what [`Op::Delegate`] demands (§2).
    NextAccountPrefix { parent: Address },
    /// Any principal's (public, immutable) account Address — what
    /// [`Op::CreateNewDocument`] demands. Deliberately an explicit wire id,
    /// not the session principal (§2).
    PrincipalPrefix { id: PrincipalId },
    /// The doc-metadata read (PUB-8.12; PUB round 2, lane 3.4 §1): a
    /// document's publication state, its owner account, and its birth
    /// version with that version's base extent — what a client's own
    /// PUB-3.19 admission test needs, and nothing else. `doc` is a
    /// DOC-ARGUMENT (PUB-6.1): unreadable ⟹ `withheld`; unregistered ⟹
    /// the store's `doc_not_registered` (fail-open at the consult, PUB-6.12).
    /// A version member answers its DOCUMENT's state (PUB-2.15).
    DocMetadata { doc: Address },
    // ── arrangement writes (→ M5) ──
    /// INSERT (ASN-0116). `Val` is M4's, carried in the payload verbatim —
    /// M10 names M4's types and calls no M4 function.
    ///
    /// `deposit` is the DEPOSIT DECLARATION (PUB-9.13's DECLARED horn, owner
    /// ruling 2026-09-05; PUB-2.59, PUB-2.63): the deposit-class record
    /// atom's untyped first `insert` says so, and M5 admits a
    /// [`Deposit::Declared`] insert into a PUBLISHED document iff it is
    /// deposit-shaped — fresh positions past the arranged extent — where an
    /// [`Deposit::Undeclared`] one, or a declared one touching an arranged
    /// position, refuses `published_target` (PUB-2.11). Absent on the wire is
    /// `Undeclared`; into a draft the declaration is inert. It is M5's own
    /// two-state type, carried verbatim: M10 decides nothing about it.
    Insert { doc: Address, at: VPos, values: Vec<Val>, deposit: Deposit },
    /// DELETE (ASN-0117).
    Delete { doc: Address, p: VPos, width: Nat },
    /// COPY / transclusion (ASN-0118).
    Copy { doc: Address, at: VPos, specs: Vec<VSpec> },
    /// REARRANGE (pivot/swap).
    Rearrange { doc: Address, cuts: Vec<VPos> },
    /// CREATENEWVERSION (ASN-0123) — the content-sharing, copy-on-write fork.
    ///
    /// `published` is the three-valued flag with `None` ⇒ INHERIT
    /// `published(d_src)` (PUB-8.17). M5's `version` composite resolves the
    /// inheritance off its own working state and passes the resolved bit
    /// down (PUB-8.18); M10 hands the flag through unresolved.
    Version { d_src: Address, published: Option<bool> },
    /// PUBLISH — the SHOT (PUB-2.33, PUB-8.1; PUB round 2, lane 3.2): append
    /// the next member of `doc`'s chain, born published, in one commit, from
    /// the CLIENT-SUPPLIED runs of `shot`. M5's composite decides the
    /// destination at commit (the trunk's next member, or the base's
    /// daughter — PUB-2.39), places the runs by their origin (PUB-2.40) and
    /// runs the source gate (PUB-6.23) through the read predicate the daemon
    /// supplies ([`Operation::with_read_predicate`]); M10 hands the shot
    /// through verbatim and names no policy of its own.
    ///
    /// [`Operation::with_read_predicate`]: crate::Operation::with_read_predicate
    Publish { doc: Address, shot: Shot },
    // ── link writes (→ M7) ──
    /// MAKELINK (ASN-0120, as amended 2026-08-16): open link from three
    /// two-form slots — each content V-specs (resolved by M7 inside its
    /// transact) or address NAMES deposited verbatim (`SlotArg` is M7's).
    MakeLink { home: Address, from: SlotArg, to: SlotArg, ty: SlotArg },
    /// Emit_K: gated typed-relation emission (ASN-0126).
    Emit { home: Address, ty: Endset, from: Address, to: Vec<Address> },
    /// Nullify_Binary — the sole retraction path.
    Nullify { home: Address, target: Address },
    /// assert_sup: "old is superseded by new".
    AssertSup { home: Address, old: Address, new: Address },
    /// editlink: successor + supersession claim, one composite (§4).
    EditLink { original: Address, successor: SuccessorSpec, d_s: Address, d_a: Address },
    // ── raw link reads (→ M7) ──
    /// Σ.L(a) verbatim.
    ReadLink { a: Address },
    /// Slot coverage; carries its own in-band `Result` (⟨⟩ ≠ ⊥ — §2).
    FollowLink { a: Address, slot: usize },
    // ── content/provenance reads (→ M6) ──
    /// RETRIEVEV (ASN-0115).
    RetrieveV { specs: Vec<Spec> },
    /// RETRIEVEDOCVSPAN (ASN-0112).
    RetrieveDocVSpan { doc: Address },
    /// RETRIEVEDOCVSPANSET (ASN-0113).
    RetrieveDocVSpanSet { doc: Address },
    /// SHOWORIGIN, V-arity (ASN-0077).
    ShowOrigin { doc: Address, span: Span },
    /// SHOWDELETIONS (ASN-0075).
    ShowDeletions { d_a: Address, d_b: Address },
    /// COMPARE / SHOWRELATIONOF2VERSIONS (ASN-0122).
    Compare { rho1: Vec<RegionSpec>, rho2: Vec<RegionSpec> },
    /// FINDDOCSCONTAINING (ASN-0124).
    FindDocsContaining { regions: Vec<RegionSpec> },
    // ── link discovery reads (→ M8) ──
    /// V→I image of a region (ASN-0098 companion).
    Image { d: Address, region: Vec<Span> },
    /// Content-region link discovery (foundation ∩ active).
    FindLinksV { d: Address, region: Vec<Span> },
    /// Four-set descriptor query (ASN-0121).
    FindLinksFtt { q: FourSet },
    /// Present-tense census over a region.
    CountV { d: Address, region: Vec<Span> },
    /// Descriptor census (ASN-0132).
    CountFtt { q: FourSet },
    /// Windowed region enumeration (ASN-0108).
    WindowV { d: Address, region: Vec<Span>, cur: Cursor, n: usize },
    /// Windowed descriptor enumeration (ASN-0108, FTT reading).
    WindowFtt { q: FourSet, cur: Cursor, n: usize },
    /// RETRIEVEENDSETS (ASN-0131).
    RetrieveEndsets { d: Address, region: Vec<Span> },
    /// I→V projection of a link slot into a document (ASN-0098).
    Project { a: Address, slot: usize, d: Address },
    /// Compound "arrangement-reachable AND active".
    DiscoverableFrom { a: Address, d: Address },
    /// Pre-edit link-survival what-if (ASN-0117 preview).
    DeleteOrphans { d: Address, p: VPos, width: Nat },
    /// Archival supersession lineage: claims with `old = y`.
    InClaims { y: Address, view: View },
    /// Archival supersession lineage: claims with `new = x`.
    OutClaims { x: Address, view: View },
    // ── publication reads (→ the world's composition of M7, lane 3.4) ──
    /// The audit-view edition-claim lookup (PUB-8.46): every ADMITTED,
    /// UNSUPERSEDED claim of the edition-claim class whose `to` slot denotes
    /// `target` — the whole document or a version of it — WHETHER OR NOT
    /// RETRACTED, each with its home (the edition) and its retraction stated.
    /// `target` is a DOC-ARGUMENT (unreadable ⟹ `withheld`); each row is
    /// then kept only where the caller can read its HOME (PUB-6.13), so a
    /// draft edition's claim is invisible to a stranger. The client's
    /// PUB-3.19 admission test over each home is its own, through
    /// [`Op::DocMetadata`].
    EditionClaims { target: Address },
}

/// EditLink's successor, assembled by M10 from content V-specs (§4).
/// `from`/`to` are content-resolved ONLY — a deliberate narrowing: an
/// address-denoting successor is not constructible here; supersession of
/// managed tuples goes via [`Op::Emit`] + [`Op::AssertSup`]. The type slot
/// is the two-form [`SlotArg`] (formerly this crate's own `TypeArg`; the
/// 2026-08-16 amendment unified it with M7's, which [`Op::MakeLink`]'s
/// three slots now share).
///
/// REFUSAL PRECEDENCE, since a successor may be wrong in several places at
/// once and exactly one answer comes back: the slots are built `from`, then
/// `to`, then `ty`, and the first that refuses speaks. Within a slot the first
/// offending spec speaks, `IllFormedSpec` ahead of `SourceNotRegistered` on
/// it. [`crate::FaultSite`] carries both halves of the coordinate: `slot`
/// names which of the three refused, in M7's numbering ([`FROM`]/[`TO`]/
/// [`TYPE`], the numbering [`Op::FollowLink`]'s `slot` is already in), and
/// `index` the offending spec's position within it.
///
/// [`FROM`]: crate::FROM
/// [`TO`]: crate::TO
/// [`TYPE`]: crate::TYPE
#[derive(Clone, PartialEq, Eq)]
pub struct SuccessorSpec {
    pub from: Vec<VSpec>,
    pub to: Vec<VSpec>,
    pub ty: SlotArg,
}

/// Whether the write door consults an op, and what its consult stands behind
/// — PUB-6.36's slot 1 ahead of slot 6, as a value ([`Op::write_consult`]).
/// The two answers instruct the door differently, so they are two variants
/// rather than an `Option` whose emptiness a reader must interpret.
///
/// `pub(crate)` with its producer: nothing outside M10 re-runs the deferral.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WriteConsult<'a> {
    /// The door consults NOTHING for this op: it returns before
    /// [`Op::source_arguments`] is ever read. A write that reads a source
    /// must never answer this — its sources would reach the store with no
    /// readability gate.
    NotTaken,
    /// Consulted, and DEFERRED: the consult runs only where these
    /// destinations' own ownership gate would pass, so a session that may not
    /// write here is never told whether it may read there. EMPTY for
    /// `version`, which is consulted with no destination to defer on.
    AfterOwnershipOf(Vec<&'a Address>),
}

/// Fieldless echo of [`Op`] (one unit variant per operation) PLUS
/// [`OpKind::Unparseable`]. `execute` only ever sees an already-parsed
/// [`Request`], so a `Codec::parse` failure has produced no `Op`; the
/// TRANSPORT builds that one `Response::Rejected` itself, stamping it
/// `OpKind::Unparseable` (§Public interface/Codec). [`Op::kind`] produces
/// every variant EXCEPT `Unparseable`. `Copy + PartialEq` so `execute`
/// captures it once and threads it to both idempotency steps and every
/// rejection, and `idem_get` can match it (§7); `Hash` so a caller may key
/// by it — per-operation counters and sets are what a transport instruments
/// this surface with, and only this crate can supply the impl.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum OpKind {
    CreateNewDocument,
    Delegate,
    RegisterNode,
    Fork,
    NextAccountPrefix,
    PrincipalPrefix,
    DocMetadata,
    Insert,
    Delete,
    Copy,
    Rearrange,
    Version,
    Publish,
    MakeLink,
    Emit,
    Nullify,
    AssertSup,
    EditLink,
    ReadLink,
    FollowLink,
    RetrieveV,
    RetrieveDocVSpan,
    RetrieveDocVSpanSet,
    ShowOrigin,
    ShowDeletions,
    Compare,
    FindDocsContaining,
    Image,
    FindLinksV,
    FindLinksFtt,
    CountV,
    CountFtt,
    WindowV,
    WindowFtt,
    RetrieveEndsets,
    Project,
    DiscoverableFrom,
    DeleteOrphans,
    InClaims,
    OutClaims,
    EditionClaims,
    /// A frame that never parsed into an `Op` — stamped by the TRANSPORT,
    /// never by [`Op::kind`].
    Unparseable,
}

impl Op {
    /// Reads vs writes PARTITION `Op` exhaustively (`is_write == !is_read`),
    /// keyed to the grouping in `Op`'s definition (§1). `execute` gates on
    /// this split (writes get a proven-bound principal; reads don't), and it
    /// selects the dispatch function. EXHAUSTIVE match with NO `_` arm — a
    /// new `Op` variant fails to compile here (and at both dispatch
    /// functions) until classified, never silently defaulting into either
    /// half.
    ///
    /// Public because the partition is a fact about the request, not an
    /// implementation detail of the lifecycle: a transport that serializes
    /// or records writes must know which side an `Op` falls on BEFORE
    /// [`Operation::execute`] takes it, and this is the one answer.
    ///
    /// [`Operation::execute`]: crate::Operation::execute
    //
    // The two-arm shape is load-bearing (compile-time non-exhaustiveness on a
    // new variant), so the `matches!` rewrite clippy suggests is refused.
    #[allow(clippy::match_like_matches_macro)]
    pub fn is_read(&self) -> bool {
        match self {
            Op::NextAccountPrefix { .. }
            | Op::PrincipalPrefix { .. }
            | Op::DocMetadata { .. }
            | Op::ReadLink { .. }
            | Op::FollowLink { .. }
            | Op::RetrieveV { .. }
            | Op::RetrieveDocVSpan { .. }
            | Op::RetrieveDocVSpanSet { .. }
            | Op::ShowOrigin { .. }
            | Op::ShowDeletions { .. }
            | Op::Compare { .. }
            | Op::FindDocsContaining { .. }
            | Op::Image { .. }
            | Op::FindLinksV { .. }
            | Op::FindLinksFtt { .. }
            | Op::CountV { .. }
            | Op::CountFtt { .. }
            | Op::WindowV { .. }
            | Op::WindowFtt { .. }
            | Op::RetrieveEndsets { .. }
            | Op::Project { .. }
            | Op::DiscoverableFrom { .. }
            | Op::DeleteOrphans { .. }
            | Op::InClaims { .. }
            | Op::OutClaims { .. }
            | Op::EditionClaims { .. } => true,
            Op::CreateNewDocument { .. }
            | Op::Delegate { .. }
            | Op::RegisterNode { .. }
            | Op::Fork { .. }
            | Op::Insert { .. }
            | Op::Delete { .. }
            | Op::Copy { .. }
            | Op::Rearrange { .. }
            | Op::Version { .. }
            | Op::Publish { .. }
            | Op::MakeLink { .. }
            | Op::Emit { .. }
            | Op::Nullify { .. }
            | Op::AssertSup { .. }
            | Op::EditLink { .. } => false,
        }
    }

    /// The other side of [`Op::is_read`], and defined as its absence so the
    /// two cannot disagree about a variant.
    pub fn is_write(&self) -> bool {
        !self.is_read()
    }

    /// The fieldless echo — never yields [`OpKind::Unparseable`].
    pub fn kind(&self) -> OpKind {
        match self {
            Op::CreateNewDocument { .. } => OpKind::CreateNewDocument,
            Op::Delegate { .. } => OpKind::Delegate,
            Op::RegisterNode { .. } => OpKind::RegisterNode,
            Op::Fork { .. } => OpKind::Fork,
            Op::NextAccountPrefix { .. } => OpKind::NextAccountPrefix,
            Op::PrincipalPrefix { .. } => OpKind::PrincipalPrefix,
            Op::DocMetadata { .. } => OpKind::DocMetadata,
            Op::Insert { .. } => OpKind::Insert,
            Op::Delete { .. } => OpKind::Delete,
            Op::Copy { .. } => OpKind::Copy,
            Op::Rearrange { .. } => OpKind::Rearrange,
            Op::Version { .. } => OpKind::Version,
            Op::Publish { .. } => OpKind::Publish,
            Op::MakeLink { .. } => OpKind::MakeLink,
            Op::Emit { .. } => OpKind::Emit,
            Op::Nullify { .. } => OpKind::Nullify,
            Op::AssertSup { .. } => OpKind::AssertSup,
            Op::EditLink { .. } => OpKind::EditLink,
            Op::ReadLink { .. } => OpKind::ReadLink,
            Op::FollowLink { .. } => OpKind::FollowLink,
            Op::RetrieveV { .. } => OpKind::RetrieveV,
            Op::RetrieveDocVSpan { .. } => OpKind::RetrieveDocVSpan,
            Op::RetrieveDocVSpanSet { .. } => OpKind::RetrieveDocVSpanSet,
            Op::ShowOrigin { .. } => OpKind::ShowOrigin,
            Op::ShowDeletions { .. } => OpKind::ShowDeletions,
            Op::Compare { .. } => OpKind::Compare,
            Op::FindDocsContaining { .. } => OpKind::FindDocsContaining,
            Op::Image { .. } => OpKind::Image,
            Op::FindLinksV { .. } => OpKind::FindLinksV,
            Op::FindLinksFtt { .. } => OpKind::FindLinksFtt,
            Op::CountV { .. } => OpKind::CountV,
            Op::CountFtt { .. } => OpKind::CountFtt,
            Op::WindowV { .. } => OpKind::WindowV,
            Op::WindowFtt { .. } => OpKind::WindowFtt,
            Op::RetrieveEndsets { .. } => OpKind::RetrieveEndsets,
            Op::Project { .. } => OpKind::Project,
            Op::DiscoverableFrom { .. } => OpKind::DiscoverableFrom,
            Op::DeleteOrphans { .. } => OpKind::DeleteOrphans,
            Op::InClaims { .. } => OpKind::InClaims,
            Op::OutClaims { .. } => OpKind::OutClaims,
            Op::EditionClaims { .. } => OpKind::EditionClaims,
        }
    }

    /// The DOC-ARGUMENT list of a read op, in DECLARATION ORDER (PUB-6.1,
    /// PUB-6.4; PUB round 2, lane 3.3 §2): the named documents the
    /// doc-argument consult tests, so the first unreadable one is the
    /// `site.addr` a WITHHELD rejection carries. Within a list, in index
    /// order; across an op's lists, in declaration order (a spec-set's docs,
    /// then ρ₁'s regions before ρ₂'s, `d_a` before `d_b`, and
    /// `project`/`discoverable_from`'s `d` — the dual row's FIRST, PUB-6.8).
    /// Every other read — the FTT descriptor family (its `home` is a coverage
    /// constraint, not a named document), the raw link reads (link-address
    /// ABSENCE, PUB-6.6, never withheld), the lineage probes (`y`/`x` are
    /// probe keys, PUB-6.12), the namespace reads — names no document to
    /// withhold and answers the empty list; and every write answers it too,
    /// its source consult being the write door's own list,
    /// [`Op::source_arguments`] (PUB-6.23).
    ///
    /// Public because the consult has TWO sites that must agree on the list:
    /// [`Operation::execute`] runs it over the snapshot it pins, and a
    /// transport answering a HISTORICAL read runs it over the HEAD before
    /// any reconstruction (PUB-6.49: the head-set check precedes the
    /// N-world's registration check and the history refusals), reading the
    /// same list rather than restating it.
    ///
    /// [`Operation::execute`]: crate::Operation::execute
    pub fn doc_arguments(&self) -> Vec<&Address> {
        match self {
            Op::RetrieveV { specs } => specs.iter().map(|s| &s.doc).collect(),
            Op::RetrieveDocVSpan { doc } | Op::RetrieveDocVSpanSet { doc } => vec![doc],
            Op::ShowOrigin { doc, .. } => vec![doc],
            Op::ShowDeletions { d_a, d_b } => vec![d_a, d_b],
            Op::Compare { rho1, rho2 } => rho1.iter().chain(rho2).map(|r| &r.doc).collect(),
            Op::FindDocsContaining { regions } => regions.iter().map(|r| &r.doc).collect(),
            Op::Image { d, .. }
            | Op::FindLinksV { d, .. }
            | Op::CountV { d, .. }
            | Op::WindowV { d, .. }
            | Op::RetrieveEndsets { d, .. }
            | Op::DeleteOrphans { d, .. }
            | Op::Project { d, .. }
            | Op::DiscoverableFrom { d, .. } => vec![d],
            // The two publication reads (lane 3.4): each names ONE document,
            // and it is the consulted one — `doc_metadata` answers nothing
            // about a document the caller cannot read (PUB-8.12), and the
            // edition lookup's `target` is a named document, not a probe key
            // (PUB-8.46; the H1 row: unreadable ⟹ withheld).
            Op::DocMetadata { doc } => vec![doc],
            Op::EditionClaims { target } => vec![target],
            // No named document to withhold (see above); written out rather
            // than wildcarded so a new read variant is classified here on
            // purpose, never defaulted to "consults nothing".
            Op::NextAccountPrefix { .. }
            | Op::PrincipalPrefix { .. }
            | Op::ReadLink { .. }
            | Op::FollowLink { .. }
            | Op::FindLinksFtt { .. }
            | Op::CountFtt { .. }
            | Op::WindowFtt { .. }
            | Op::InClaims { .. }
            | Op::OutClaims { .. }
            | Op::CreateNewDocument { .. }
            | Op::Delegate { .. }
            | Op::RegisterNode { .. }
            | Op::Fork { .. }
            | Op::Insert { .. }
            | Op::Delete { .. }
            | Op::Copy { .. }
            | Op::Rearrange { .. }
            | Op::Version { .. }
            | Op::Publish { .. }
            | Op::MakeLink { .. }
            | Op::Emit { .. }
            | Op::Nullify { .. }
            | Op::AssertSup { .. }
            | Op::EditLink { .. } => Vec::new(),
        }
    }

    /// The SOURCE-ARGUMENT list of a write op, in DECLARATION ORDER (PUB-6.23,
    /// PUB-6.24, PUB-6.4; PUB round 2, lane 3.3c §1): the documents whose
    /// ARRANGEMENT the write READS before it writes, so the first unreadable
    /// one is the `site.addr` the write door's WITHHELD rejection carries.
    /// `copy` names each `specs[].source` by index; `version` its `d_src`;
    /// `make_link` and `edit_link` the document of every RESOLVE-form slot's
    /// V-spec — slots in the wire's declared order `from`, `to`, `ty`, specs
    /// by index within a slot. An ADDRESS-FORM slot names no source: an
    /// address is not secret and needs no read to write (PUB-1.13,
    /// PUB-6.24), so it is ungated and contributes nothing here.
    ///
    /// `fork` reads no source (PUB-6.23) and answers the empty list, as does
    /// every other write — `publish`'s source gate is the composite's own,
    /// threaded per ORIGIN through the predicate M10 hands M5 (PUB-8.1), and
    /// `emit`'s endpoints are address-form (PUB-6.11) — and every read, whose
    /// consult is [`Op::doc_arguments`]. Written out, no wildcard, so a new
    /// variant is classified here on purpose.
    ///
    /// Public for the reason [`Op::doc_arguments`] is: the list is a fact
    /// about the request, and a transport that wants to know which documents
    /// a write will read before it dispatches it reads the same list.
    pub fn source_arguments(&self) -> Vec<&Address> {
        fn resolve_sources<'a>(slot: &'a SlotArg, out: &mut Vec<&'a Address>) {
            if let SlotArg::Resolve(specs) = slot {
                out.extend(specs.iter().map(|s| &s.source));
            }
        }
        match self {
            Op::Copy { specs, .. } => specs.iter().map(|s| &s.source).collect(),
            Op::Version { d_src, .. } => vec![d_src],
            Op::MakeLink { from, to, ty, .. } => {
                let mut out = Vec::new();
                resolve_sources(from, &mut out);
                resolve_sources(to, &mut out);
                resolve_sources(ty, &mut out);
                out
            }
            // The successor's `from`/`to` are content-resolved by their type
            // ([`SuccessorSpec`]); only its `ty` has the address form.
            Op::EditLink { successor, .. } => {
                let mut out: Vec<&Address> =
                    successor.from.iter().chain(&successor.to).map(|s| &s.source).collect();
                resolve_sources(&successor.ty, &mut out);
                out
            }
            // No source to consult (see above); written out rather than
            // wildcarded so a new write variant decides whether it reads one.
            Op::CreateNewDocument { .. }
            | Op::Delegate { .. }
            | Op::RegisterNode { .. }
            | Op::Fork { .. }
            | Op::Insert { .. }
            | Op::Delete { .. }
            | Op::Rearrange { .. }
            | Op::Publish { .. }
            | Op::Emit { .. }
            | Op::Nullify { .. }
            | Op::AssertSup { .. }
            | Op::NextAccountPrefix { .. }
            | Op::PrincipalPrefix { .. }
            | Op::ReadLink { .. }
            | Op::FollowLink { .. }
            | Op::RetrieveV { .. }
            | Op::RetrieveDocVSpan { .. }
            | Op::RetrieveDocVSpanSet { .. }
            | Op::ShowOrigin { .. }
            | Op::ShowDeletions { .. }
            | Op::Compare { .. }
            | Op::FindDocsContaining { .. }
            | Op::Image { .. }
            | Op::FindLinksV { .. }
            | Op::FindLinksFtt { .. }
            | Op::CountV { .. }
            | Op::CountFtt { .. }
            | Op::WindowV { .. }
            | Op::WindowFtt { .. }
            | Op::RetrieveEndsets { .. }
            | Op::Project { .. }
            | Op::DiscoverableFrom { .. }
            | Op::DeleteOrphans { .. }
            | Op::InClaims { .. }
            | Op::OutClaims { .. }
            | Op::DocMetadata { .. }
            | Op::EditionClaims { .. } => Vec::new(),
        }
    }

    /// Whether the write door consults this op at all and — PUB-6.36 slot 1
    /// ahead of slot 6, PUB-6.38 — whose ownership gate it stands behind (see
    /// [`Operation::consult_write`]). [`WriteConsult::AfterOwnershipOf`] for
    /// exactly the writes the consult reaches — a source-reading write or one
    /// validating a link by address — listing the documents the store's own
    /// `not_owner` is judged on, EMPTY for `version`, whose mint lands in the
    /// caller's own account and which no destination gate precedes
    /// (MINT-FIRST is the daemon's, slot 2).
    /// [`WriteConsult::NotTaken`] for a write with nothing to consult and for
    /// every read. `nullify` is `NotTaken` on purpose: its target takes
    /// PUB-6.9's ω-first order and the slot-5 nullify-class refusals (lane
    /// 3.5), not this consult. `emit`'s endpoints are address-form (PUB-6.11)
    /// and `publish`'s source gate is the composite's own, threaded per origin
    /// (PUB-8.1). EXHAUSTIVE with no `_` arm: a new `Op` decides its row here.
    ///
    /// A write that reads a source must never answer `NotTaken` — that
    /// pairing would hand the source to the store with no readability gate,
    /// PUB-6.23 silently unapplied — and the two lists are pinned against each
    /// other over the whole `Op` domain in this module's tests rather than
    /// left to agree by hand.
    ///
    /// `pub(crate)`, where its two siblings are public, and deliberately: a
    /// historical door re-runs [`Op::doc_arguments`] over the head (PUB-6.49)
    /// and a transport may read [`Op::source_arguments`] before dispatch, but
    /// nothing outside M10 re-runs the DEFERRAL, which exists to decide when
    /// M10's own door stays silent so the store speaks first. Publishing it
    /// would invite a transport to rebuild the slot-1-before-slot-6 ordering
    /// M10 holds.
    ///
    /// [`Operation::consult_write`]: crate::Operation
    pub(crate) fn write_consult(&self) -> WriteConsult<'_> {
        match self {
            Op::Copy { doc, .. } => WriteConsult::AfterOwnershipOf(vec![doc]),
            Op::Version { .. } => WriteConsult::AfterOwnershipOf(Vec::new()),
            Op::MakeLink { home, .. } => WriteConsult::AfterOwnershipOf(vec![home]),
            Op::AssertSup { home, .. } => WriteConsult::AfterOwnershipOf(vec![home]),
            Op::EditLink { d_s, d_a, .. } => WriteConsult::AfterOwnershipOf(vec![d_s, d_a]),
            Op::CreateNewDocument { .. }
            | Op::Delegate { .. }
            | Op::RegisterNode { .. }
            | Op::Fork { .. }
            | Op::Insert { .. }
            | Op::Delete { .. }
            | Op::Rearrange { .. }
            | Op::Publish { .. }
            | Op::Emit { .. }
            | Op::Nullify { .. }
            | Op::NextAccountPrefix { .. }
            | Op::PrincipalPrefix { .. }
            | Op::ReadLink { .. }
            | Op::FollowLink { .. }
            | Op::RetrieveV { .. }
            | Op::RetrieveDocVSpan { .. }
            | Op::RetrieveDocVSpanSet { .. }
            | Op::ShowOrigin { .. }
            | Op::ShowDeletions { .. }
            | Op::Compare { .. }
            | Op::FindDocsContaining { .. }
            | Op::Image { .. }
            | Op::FindLinksV { .. }
            | Op::FindLinksFtt { .. }
            | Op::CountV { .. }
            | Op::CountFtt { .. }
            | Op::WindowV { .. }
            | Op::WindowFtt { .. }
            | Op::RetrieveEndsets { .. }
            | Op::Project { .. }
            | Op::DiscoverableFrom { .. }
            | Op::DeleteOrphans { .. }
            | Op::InClaims { .. }
            | Op::OutClaims { .. }
            | Op::DocMetadata { .. }
            | Op::EditionClaims { .. } => WriteConsult::NotTaken,
        }
    }

    /// The destination whose arrangement this write EDITS IN PLACE, if it is
    /// one of that class (PUB-2.11): `insert`, `delete`, `copy`-into and
    /// `rearrange`, the four writes that advance an existing document's
    /// arrangement. `None` for everything else, and each exclusion is the
    /// rule's own: the link writes are outside it (PUB-2.12), `version` and
    /// `create`/`fork` MINT a document rather than advancing one,
    /// `publish` appends a chain member whose destination M5's composite
    /// decides (PUB-2.39), and no read edits anything. EXHAUSTIVE with no
    /// `_` arm: a new `Op` decides its row here.
    ///
    /// This names the CLASS; what restricts the door's pre-evaluation to
    /// `copy` is the ORDER in which the door asks. [`Operation::consult_write`]
    /// asks only after the deferral, so only CONSULTED writes reach it —
    /// `insert`, `delete` and `rearrange` read no source, answer
    /// [`WriteConsult::NotTaken`] from [`Op::write_consult`], and meet the
    /// store's own `published_target` unchanged, one layer later. The two
    /// lists are therefore read together, and the pairing is pinned in this
    /// module's tests rather than left to agree by hand.
    ///
    /// `pub(crate)` for [`Op::write_consult`]'s reason: nothing
    /// outside M10 re-runs the door's pre-evaluation, which exists to order
    /// one refusal ahead of another inside this surface.
    ///
    /// [`Operation::consult_write`]: crate::Operation
    pub(crate) fn in_place_destination(&self) -> Option<&Address> {
        match self {
            Op::Insert { doc, .. }
            | Op::Delete { doc, .. }
            | Op::Copy { doc, .. }
            | Op::Rearrange { doc, .. } => Some(doc),
            Op::CreateNewDocument { .. }
            | Op::Delegate { .. }
            | Op::RegisterNode { .. }
            | Op::Fork { .. }
            | Op::Version { .. }
            | Op::Publish { .. }
            | Op::MakeLink { .. }
            | Op::Emit { .. }
            | Op::Nullify { .. }
            | Op::AssertSup { .. }
            | Op::EditLink { .. }
            | Op::NextAccountPrefix { .. }
            | Op::PrincipalPrefix { .. }
            | Op::ReadLink { .. }
            | Op::FollowLink { .. }
            | Op::RetrieveV { .. }
            | Op::RetrieveDocVSpan { .. }
            | Op::RetrieveDocVSpanSet { .. }
            | Op::ShowOrigin { .. }
            | Op::ShowDeletions { .. }
            | Op::Compare { .. }
            | Op::FindDocsContaining { .. }
            | Op::Image { .. }
            | Op::FindLinksV { .. }
            | Op::FindLinksFtt { .. }
            | Op::CountV { .. }
            | Op::CountFtt { .. }
            | Op::WindowV { .. }
            | Op::WindowFtt { .. }
            | Op::RetrieveEndsets { .. }
            | Op::Project { .. }
            | Op::DiscoverableFrom { .. }
            | Op::DeleteOrphans { .. }
            | Op::InClaims { .. }
            | Op::OutClaims { .. }
            | Op::DocMetadata { .. }
            | Op::EditionClaims { .. } => None,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use skep_address::{validate, Nat, Span, Tumbler};
    use skep_discovery::SlotSpec;

    fn tum(comps: &[u32]) -> Tumbler {
        Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")
    }
    fn addr(comps: &[u32]) -> Address {
        validate(tum(comps)).unwrap_or_else(|_| panic!("T4-valid test address"))
    }
    fn sp() -> Span {
        Span::new(tum(&[1, 1]), tum(&[0, 1])).unwrap_or_else(|_| panic!("well-formed test span"))
    }
    fn vpos() -> VPos {
        VPos { subspace: Nat::from(1u32), ordinal: Nat::from(1u32) }
    }
    fn vs() -> VSpec {
        VSpec { source: addr(&[1, 0, 1, 0, 1]), span: sp() }
    }
    fn q() -> FourSet {
        FourSet { home: SlotSpec::Any, from: SlotSpec::Any, to: SlotSpec::Any, ty: SlotSpec::Any }
    }
    fn doc() -> Address {
        addr(&[1, 0, 1, 0, 1])
    }

    /// Every variant, paired with its documented partition side (§1's
    /// `is_read` grouping): `(op, is_read)`. Crate-visible: the dispatch
    /// tables' agreement with this partition is checked against the same
    /// fixture, in `operation.rs`.
    pub(crate) fn all_ops() -> Vec<(Op, bool)> {
        vec![
            (Op::CreateNewDocument { account: addr(&[1, 0, 1]), published: None }, false),
            (Op::Delegate { new_prefix: tum(&[1, 0, 1]), new_id: PrincipalId(1) }, false),
            (Op::RegisterNode { addr: tum(&[1, 1]) }, false),
            (Op::Fork { published: None }, false),
            (Op::NextAccountPrefix { parent: addr(&[1]) }, true),
            (Op::PrincipalPrefix { id: PrincipalId(1) }, true),
            (Op::DocMetadata { doc: doc() }, true),
            (
                Op::Insert {
                    doc: doc(),
                    at: vpos(),
                    values: vec![Val::new(vec![1u8])],
                    deposit: Deposit::Undeclared,
                },
                false,
            ),
            (Op::Delete { doc: doc(), p: vpos(), width: Nat::from(1u32) }, false),
            (Op::Copy { doc: doc(), at: vpos(), specs: vec![vs()] }, false),
            (Op::Rearrange { doc: doc(), cuts: vec![vpos()] }, false),
            (Op::Version { d_src: doc(), published: None }, false),
            (
                Op::Publish { doc: doc(), shot: Shot { base: None, draft: None, runs: vec![] } },
                false,
            ),
            (
                Op::MakeLink {
                    home: doc(),
                    from: SlotArg::Resolve(vec![vs()]),
                    to: SlotArg::Addrs(vec![doc()]),
                    ty: SlotArg::Resolve(vec![vs()]),
                },
                false,
            ),
            (Op::Emit { home: doc(), ty: Endset::empty(), from: doc(), to: vec![] }, false),
            (Op::Nullify { home: doc(), target: doc() }, false),
            (Op::AssertSup { home: doc(), old: doc(), new: doc() }, false),
            (
                Op::EditLink {
                    original: doc(),
                    successor: SuccessorSpec { from: vec![vs()], to: vec![vs()], ty: SlotArg::Addrs(vec![doc()]) },
                    d_s: doc(),
                    d_a: doc(),
                },
                false,
            ),
            (Op::ReadLink { a: doc() }, true),
            (Op::FollowLink { a: doc(), slot: 1 }, true),
            (Op::RetrieveV { specs: vec![Spec { doc: doc(), span: sp() }] }, true),
            (Op::RetrieveDocVSpan { doc: doc() }, true),
            (Op::RetrieveDocVSpanSet { doc: doc() }, true),
            (Op::ShowOrigin { doc: doc(), span: sp() }, true),
            (Op::ShowDeletions { d_a: doc(), d_b: doc() }, true),
            (
                Op::Compare {
                    rho1: vec![RegionSpec { doc: doc(), spans: vec![sp()] }],
                    rho2: vec![],
                },
                true,
            ),
            (Op::FindDocsContaining { regions: vec![RegionSpec { doc: doc(), spans: vec![sp()] }] }, true),
            (Op::Image { d: doc(), region: vec![sp()] }, true),
            (Op::FindLinksV { d: doc(), region: vec![sp()] }, true),
            (Op::FindLinksFtt { q: q() }, true),
            (Op::CountV { d: doc(), region: vec![sp()] }, true),
            (Op::CountFtt { q: q() }, true),
            (Op::WindowV { d: doc(), region: vec![sp()], cur: None, n: 1 }, true),
            (Op::WindowFtt { q: q(), cur: None, n: 1 }, true),
            (Op::RetrieveEndsets { d: doc(), region: vec![sp()] }, true),
            (Op::Project { a: doc(), slot: 1, d: doc() }, true),
            (Op::DiscoverableFrom { a: doc(), d: doc() }, true),
            (Op::DeleteOrphans { d: doc(), p: vpos(), width: Nat::from(1u32) }, true),
            (Op::InClaims { y: doc(), view: View::Active }, true),
            (Op::OutClaims { x: doc(), view: View::Active }, true),
            (Op::EditionClaims { target: doc() }, true),
        ]
    }

    /// §1: the read/write partition is exhaustive and two-sided
    /// (`is_write == !is_read`), with 26 reads and 15 writes (the publish
    /// shot joining the fourteen of the design, lane 3.2; the doc-metadata
    /// read and the edition-claim lookup joining the twenty-four reads,
    /// lane 3.4).
    #[test]
    fn partition_matches_the_design_grouping() {
        let ops = all_ops();
        assert_eq!(ops.len(), 41);
        let reads = ops.iter().filter(|(_, r)| *r).count();
        assert_eq!(reads, 26);
        for (op, expect_read) in &ops {
            assert_eq!(op.is_read(), *expect_read);
            assert_eq!(op.is_write(), !*expect_read);
        }
    }

    /// `Op::kind` is injective over the variants and never yields
    /// `Unparseable`. Injectivity is read off a [`HashSet`], which is the
    /// same shape a transport keying per-operation counters uses, so the
    /// `Hash` a caller depends on is exercised here rather than merely
    /// derived.
    ///
    /// [`HashSet`]: std::collections::HashSet
    #[test]
    fn kind_is_injective_and_never_unparseable() {
        let mut seen = std::collections::HashSet::new();
        for (op, _) in all_ops() {
            let kind = op.kind();
            assert_ne!(kind, OpKind::Unparseable);
            assert!(seen.insert(kind), "{kind:?} is produced by two variants");
        }
        assert_eq!(seen.len(), 41);
    }

    /// PUB-6.4: the doc-argument list runs in DECLARATION order across an
    /// op's lists and by index within each — `d_a` before `d_b`, ρ₁'s regions
    /// before ρ₂'s, the dual row's `d` alone (PUB-6.8) — and a read that
    /// names no document to withhold (the FTT family, the raw link reads,
    /// the lineage probes, the namespace reads) answers the empty list, as
    /// every write does.
    #[test]
    fn doc_arguments_run_in_declaration_order() {
        let a = addr(&[1, 0, 1, 0, 1]);
        let b = addr(&[1, 0, 1, 0, 2]);
        let c = addr(&[1, 0, 1, 0, 3]);
        let op = Op::ShowDeletions { d_a: a.clone(), d_b: b.clone() };
        assert_eq!(op.doc_arguments(), vec![&a, &b]);
        let op = Op::Compare {
            rho1: vec![RegionSpec { doc: b.clone(), spans: vec![sp()] }],
            rho2: vec![
                RegionSpec { doc: c.clone(), spans: vec![] },
                RegionSpec { doc: a.clone(), spans: vec![] },
            ],
        };
        assert_eq!(op.doc_arguments(), vec![&b, &c, &a]);
        let op = Op::Project { a: a.clone(), slot: 1, d: c.clone() };
        assert_eq!(op.doc_arguments(), vec![&c], "the dual row consults `d`, never the link");
        // Lane 3.4: the two publication reads each consult their one named
        // document — the H1 row's "target unreadable ⟹ withheld".
        let op = Op::DocMetadata { doc: b.clone() };
        assert_eq!(op.doc_arguments(), vec![&b]);
        let op = Op::EditionClaims { target: c.clone() };
        assert_eq!(op.doc_arguments(), vec![&c], "the target is a named document, not a probe key");
        for (op, is_read) in all_ops() {
            let named = !op.doc_arguments().is_empty();
            let expects_consult = is_read
                && !matches!(
                    op,
                    Op::NextAccountPrefix { .. }
                        | Op::PrincipalPrefix { .. }
                        | Op::ReadLink { .. }
                        | Op::FollowLink { .. }
                        | Op::FindLinksFtt { .. }
                        | Op::CountFtt { .. }
                        | Op::WindowFtt { .. }
                        | Op::InClaims { .. }
                        | Op::OutClaims { .. }
                );
            assert_eq!(named, expects_consult, "{:?}: the doc-argument row", op.kind());
        }
    }

    /// PUB-6.23 / PUB-6.24 / PUB-6.4, lane 3.3c: the source-argument list
    /// runs in DECLARATION order — `copy`'s specs by index, `version`'s
    /// `d_src`, and the two link writes' RESOLVE-form slots in the wire's
    /// declared order `from`, `to`, `ty` with specs by index inside a slot —
    /// while an ADDRESS-FORM slot is ungated and names nothing. Exactly the
    /// four source-reading writes answer a non-empty list; `fork`, every other
    /// write and every read answer the empty one.
    #[test]
    fn source_arguments_run_in_declaration_order_and_skip_address_form_slots() {
        let a = addr(&[1, 0, 1, 0, 1]);
        let b = addr(&[1, 0, 1, 0, 2]);
        let c = addr(&[1, 0, 1, 0, 3]);
        let spec = |d: &Address| VSpec { source: d.clone(), span: sp() };

        let op = Op::Copy { doc: a.clone(), at: vpos(), specs: vec![spec(&b), spec(&c)] };
        assert_eq!(op.source_arguments(), vec![&b, &c], "copy: each spec's source, by index");
        let op = Op::Version { d_src: b.clone(), published: None };
        assert_eq!(op.source_arguments(), vec![&b]);
        let op = Op::MakeLink {
            home: a.clone(),
            from: SlotArg::Resolve(vec![spec(&c)]),
            to: SlotArg::Addrs(vec![b.clone()]),
            ty: SlotArg::Resolve(vec![spec(&b), spec(&a)]),
        };
        assert_eq!(
            op.source_arguments(),
            vec![&c, &b, &a],
            "make_link: from, then ty — the address-form `to` names no source"
        );
        let op = Op::EditLink {
            original: a.clone(),
            successor: SuccessorSpec {
                from: vec![spec(&c)],
                to: vec![spec(&b)],
                ty: SlotArg::Addrs(vec![a.clone()]),
            },
            d_s: a.clone(),
            d_a: a.clone(),
        };
        assert_eq!(op.source_arguments(), vec![&c, &b], "edit_link: the successor's slots in order");

        for (op, is_read) in all_ops() {
            let reads_a_source = !op.source_arguments().is_empty();
            let expects = !is_read
                && matches!(
                    op,
                    Op::Copy { .. } | Op::Version { .. } | Op::MakeLink { .. } | Op::EditLink { .. }
                );
            assert_eq!(reads_a_source, expects, "{:?}: the source-reading-writes row", op.kind());
        }
    }

    /// PUB-6.23 at the pairing of the two lists, which is where it can
    /// silently fail. The door reads `write_consult` FIRST and returns on
    /// [`WriteConsult::NotTaken`] without ever reading `source_arguments`, so
    /// the two are jointly load-bearing: a write that declares a source and
    /// answers `NotTaken` hands that source to its store with no readability
    /// gate, and both matches being exhaustive means the compiler forces two
    /// independent decisions and accepts the wrong pairing. The law is that
    /// pairing — a declared source implies a consult — plus the two arms of
    /// [`WriteConsult`] itself, which differ in what they let the door do and
    /// are likewise both well-typed.
    #[test]
    fn a_write_that_reads_a_source_is_always_consulted() {
        for (op, is_read) in all_ops() {
            let declares_a_source = !op.source_arguments().is_empty();
            let consulted = matches!(op.write_consult(), WriteConsult::AfterOwnershipOf(_));
            assert!(
                !declares_a_source || consulted,
                "{:?} declares a source and is NotTaken: its sources reach the store ungated",
                op.kind()
            );
            assert!(
                !is_read || !consulted,
                "{:?} is a read: the write door's consult is not its",
                op.kind()
            );
        }

        // Consulted with an EMPTY destination list: no destination to defer
        // on — the mint lands in the caller's own account (MINT-FIRST is the
        // daemon's).
        let version = Op::Version { d_src: doc(), published: None };
        match version.write_consult() {
            WriteConsult::AfterOwnershipOf(d) => assert!(
                d.is_empty(),
                "an empty destination list is not the same answer as `NotTaken`"
            ),
            WriteConsult::NotTaken => panic!("version is consulted"),
        }
        // Consulted with destinations: the documents the store's own
        // `not_owner` is judged on, which is what the door defers to.
        let a = addr(&[1, 0, 1, 0, 1]);
        let b = addr(&[1, 0, 1, 0, 2]);
        let edit = Op::EditLink {
            original: a.clone(),
            successor: SuccessorSpec { from: vec![], to: vec![], ty: SlotArg::Addrs(vec![a.clone()]) },
            d_s: a.clone(),
            d_a: b.clone(),
        };
        assert_eq!(
            edit.write_consult(),
            WriteConsult::AfterOwnershipOf(vec![&a, &b]),
            "both written homes"
        );
        // NotTaken: a write with nothing to consult — no source, no
        // link-address argument.
        let insert = Op::Insert {
            doc: doc(),
            at: vpos(),
            values: vec![Val::new(vec![1u8])],
            deposit: Deposit::Undeclared,
        };
        assert_eq!(insert.write_consult(), WriteConsult::NotTaken);
    }

    /// PUB-2.11 / PUB-6.36 slot 5, at the OTHER pairing the door depends on
    /// (`Operation::consult_write`). `in_place_destination` names the class
    /// — the four writes that advance an existing document's arrangement —
    /// and the door's ORDER is what narrows the pre-evaluation to `copy`:
    /// the check runs past the deferral, so only a CONSULTED member reaches
    /// it, and the three that are not consulted meet the store's own
    /// `published_target` unchanged. Both halves are stated here, because a
    /// member that quietly stopped being consulted, or a consulted write that
    /// quietly left the class, would reorder a refusal with nothing to say so.
    #[test]
    fn the_in_place_class_is_the_four_arrangement_edits_and_only_copy_is_consulted() {
        for (op, is_read) in all_ops() {
            let in_place = op.in_place_destination().is_some();
            let expects = !is_read
                && matches!(
                    op,
                    Op::Insert { .. } | Op::Delete { .. } | Op::Copy { .. } | Op::Rearrange { .. }
                );
            assert_eq!(in_place, expects, "{:?}: the in-place arrangement-edit row", op.kind());
            assert!(
                !in_place || !is_read,
                "{:?} is a read: no read edits an arrangement",
                op.kind()
            );
            // The door's reach: a member the deferral admits is one whose
            // refusal the door orders ahead of the source consult.
            let pre_evaluated =
                in_place && matches!(op.write_consult(), WriteConsult::AfterOwnershipOf(_));
            assert_eq!(
                pre_evaluated,
                matches!(op, Op::Copy { .. }),
                "{:?}: `copy` is the one member the door's pre-evaluation reaches",
                op.kind()
            );
        }

        // The destination named is the document EDITED, not a source read.
        let d = addr(&[1, 0, 1, 0, 1]);
        let src = addr(&[1, 0, 1, 0, 2]);
        let copy = Op::Copy {
            doc: d.clone(),
            at: vpos(),
            specs: vec![VSpec { source: src, span: sp() }],
        };
        assert_eq!(copy.in_place_destination(), Some(&d));
    }
}
