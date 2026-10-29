//! The parsed request model, from the request down to its operation's kind.
//!
//! It holds [`Request`]/[`ReqId`], the [`Op`] enum (one variant per FEBE
//! operation), the [`OpKind`] fieldless echo, and the read/write partition
//! the lifecycle gates on (§1).

use skep_address::{document_of, Address, Level, Nat, Span, Tumbler};
use skep_arrangement::{trunk_of, Deposit, Shot, ShotRun, VPos, VSpec};
use skep_content::Val;
use skep_discovery::{Cursor, FourSet};
use skep_kernel::Attestation;
use skep_links::{Endset, PublishDeposits, PublishTarget, SlotArg, View};
use skep_namespace::PrincipalId;
use skep_retrieval::{RegionSpec, Spec};

/// One parsed FEBE request: its operation, idempotency key and attestation.
///
/// The key and the attestation are optional, and the attestation (signed
/// ops) is what the write's store writes into the commit marker of each
/// transaction it signs. `id` is used only to key the retry memo
/// (§1(a)/§7); it is never echoed on the response path (§8).
///
/// A value, with [`Op`]'s traits and for [`Op`]'s reason: `execute` consumes
/// a request, so a transport that records, reorders or reissues what it
/// dispatched keeps a clone of one.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Request {
    /// The client's idempotency key, optional.
    ///
    /// A token the client chooses, naming one request within its own session
    /// — reused, after a write committed under it, for a different write of
    /// the same kind, it is answered from the memo and that write does not
    /// run ([`ReqId`]).
    pub id: Option<ReqId>,
    /// The parsed operation.
    pub op: Op,
    /// The attestation (signed ops).
    ///
    /// The design record §7.3 (ii) places it: "the value rides `Request`
    /// beside `id`". It is the entry signature the daemon's write-path check
    /// admitted for this write, lifted from the op frame's top-level `attest`
    /// member by the codec and carried here, one field on the object
    /// `execute` already takes, so no `Op` variant and neither exhaustive
    /// classifier is asked about it. M10 hands it to every M5 and M7 driver
    /// the write acquires, and to the namespace driver of the two document
    /// mints; the store fills the commit marker's signature slot on the
    /// transactions it signs — each store states which on its handle — and
    /// on every other write, `delegate`'s and `register_node`'s included, the
    /// value is dropped, unwritten.
    ///
    /// **Who sets it.** It is set by the dispatched write path alone, after
    /// its check: a transport that lifts the member sets it only where the
    /// check admitted the signature, which is what bounds the signature
    /// slot's producer set (the design record §5.5) — M10 classifies nothing
    /// about it and verifies nothing, the kernel writes it opaquely.
    pub attest: Option<Attestation>,
}

/// Converts `op` into a request with no idempotency key and no attestation.
///
/// It is what an in-process caller with neither builds, and the base a
/// caller with one writes over
/// (`Request { id: Some(id), ..Request::from(op) }`).
impl From<Op> for Request {
    fn from(op: Op) -> Request {
        Request { id: None, op, attest: None }
    }
}

/// The client's idempotency key, scoped to its own session (§7).
///
/// The client chooses it, and it is half of the memo's key, which pairs it
/// with the session that committed under it.
///
/// What the key buys is the answer to a retry sent *after* the original's
/// acknowledgment was lost. Two requests carrying one id concurrently are two
/// operations, since the memo is read before dispatch and written after
/// it, and a restart empties it — so this is a hint that saves a duplicate
/// commit, never a guarantee against one.
///
/// **The caller's two obligations.** An id names one request: a retry
/// re-presents the request it was first sent with. The memo compares the op's
/// kind and nothing else of it — not its arguments, not its `attest` — so a
/// write reusing an id under which this session already committed a write of
/// the same kind is answered with that write's acknowledgment — its `at` and
/// whatever addresses it names — and is not executed, for as long as the
/// entry lives (until eviction, the session's close, or a restart). Nothing
/// reports the reuse, so the obligation is the caller's alone. And a key
/// longer than [`MAX_REQ_ID_BYTES`] is accepted and simply not memoized, so a
/// retry under it re-executes and is never told; a caller choosing a
/// structured key — a URL, a serialized blob — should measure it against
/// that bound.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ReqId(pub Vec<u8>);

/// The most bytes one idempotency key may carry into the memo.
///
/// The bill this bounds is M10's, so the number is M10's. A committed write's
/// key stays resident for the life of its memo entry — until eviction, or
/// until [`OperationSurface::close_session`] purges the session — so the
/// memo's key retention is (memo capacity) × (this cap), and both factors
/// have to be finite for the product to be. With this one uncapped the other
/// factor would be whatever body size the transport admits: one session's
/// worth of committed writes retaining gigabytes that do not clear when the
/// caller stops, unlike every CPU cost on this surface.
///
/// 256 bytes is far above any key a client needs — a UUID is 36 characters,
/// a hex-encoded 256-bit value 64 — and puts the retained key bill at a
/// quarter megabyte against the daemon's 1024-entry memo; the acknowledgment
/// beside each key is the store's, sized by the addresses it carries, and no
/// part of this cap's bill.
///
/// A transport may refuse an over-long id at parse, as skepd's does: that is
/// the first check, and the one that tells the client.
/// [`crate::OperationSurface`] holds the second: a key past this bound is
/// simply not memoized, so a hand-assembled [`Request`] cannot enlarge the
/// bill by skipping the parser.
///
/// [`OperationSurface::close_session`]: crate::OperationSurface::close_session
pub const MAX_REQ_ID_BYTES: usize = 256;

/// The parsed request, one variant per FEBE operation.
///
/// Its args are in M1/M5/M7/M8 types, in the namespace's, the content
/// store's and the retrieval queries' (`PrincipalId`, `Val`, `Spec`,
/// `RegionSpec`), and in this crate's own [`SuccessorSpec`] and [`ISpan`];
/// the principal comes from the session, never the wire.
///
/// A value, because [`OperationSurface::execute`] consumes one: a transport
/// that wants to hold what it dispatched — to log it, to buffer it for
/// reorder, to reissue it under [`Request::id`] — keeps a clone, and one that
/// classifies a request through [`Op::is_read`] before dispatching it can
/// then still dispatch it. Comparison for the same callers: a harness pins
/// the request it built against the one a parser produced.
///
/// [`OperationSurface::execute`]: crate::OperationSurface::execute
///
/// `Debug` by hand, in `request/debug.rs`, so an `Insert`'s values render as
/// their count — one short field however many values the insert carries,
/// where a derive would list one byte length per value — and never a byte
/// (M4's `Val`, M6's `DeliveryItem` and M2's `Attestation` redact theirs the
/// same way), and every other field by its own `Debug`. Not `Hash`: M4's
/// `Val` has none.
///
/// Deliberately not `#[non_exhaustive]`, and nor are [`OpKind`],
/// [`RejectCode`] and [`Response`]: a consumer's exhaustive match over each is
/// what forces a new variant to be given a wire name and a marshaling, where
/// the `_` arm `#[non_exhaustive]` demands of an outside crate would silently
/// absorb it. Every variant of the four is therefore semver surface, and adding
/// one breaks such a match on purpose.
///
/// [`RejectCode`]: crate::RejectCode
/// [`Response`]: crate::Response
#[derive(Clone, PartialEq, Eq)]
pub enum Op {
    // ── namespace writes (→ M3) ──
    /// CREATENEWDOCUMENT (ASN-0103), which baptizes a fresh empty document.
    ///
    /// `published` is the three-valued publication flag (PUB-8.16:
    /// `absent | true | false`, `None` being absent). The wire default is
    /// private (PUB-1.1); the `absent` arm resolves at M3's create path — the
    /// account's first document born published, every later flagless one
    /// private (PUB-8.21). M10 passes it through verbatim; the explicit-false
    /// first-mint refusal is the daemon's door alone (PUB-8.20, PUB-kickoff
    /// D2c), never this type's.
    CreateNewDocument { account: Address, published: Option<bool> },
    /// Delegation (ASN-0042 O15) of an account prefix and its principal.
    ///
    /// It baptizes the prefix and registers its principal atomically.
    Delegate { new_prefix: Tumbler, new_id: PrincipalId },
    /// NodeBaptism admission (ASN-0047).
    ///
    /// The address is supplied by provisioning, not minted. A bound session
    /// is the only authority gate on this path, and no module holds a
    /// stronger one. Step (b) proves that some session is bound and nothing
    /// further; `Namespace::register_node` takes no principal, so this arm
    /// passes none, and `RegisterNodeError` carries no authority variant, so
    /// M3 makes no ownership check and no check of the caller's tier either
    /// — its one tier check is the address's own (`NotNode`). Any bound
    /// session, speaking for any principal, may therefore register a
    /// node-tier entity — confining this to provisioning is policy nobody
    /// enforces.
    RegisterNode { addr: Tumbler },
    /// Denial-as-fork (O10, account tier): a fresh empty document.
    ///
    /// It lands in the caller's own account and shares no content (the
    /// content-sharing fork is [`Op::Version`]; §3).
    ///
    /// `published` is the three-valued flag (PUB-8.16), handed through
    /// verbatim to `Namespace::fork`, which resolves it at M3's create path
    /// exactly as [`Op::CreateNewDocument`]'s is (fork reduces to a create in
    /// the caller's own account — one rule, one place). A first fork into an
    /// empty account is refused `mint_home_first` at the daemon (PUB-8.22)
    /// before the flag is read.
    Fork { published: Option<bool> },
    // ── namespace reads (→ M3) ──
    /// M3's next-form delegable prefix — what [`Op::Delegate`] demands (§2).
    NextAccountPrefix { parent: Address },
    /// Any principal's seat — what [`Op::CreateNewDocument`] demands.
    ///
    /// It is public, immutable registry data, and an account address for
    /// every principal but the bootstrap principal, whose seat is the node
    /// `[1]`. Deliberately an explicit wire id, not the session principal
    /// (§2).
    PrincipalPrefix { id: PrincipalId },
    /// The owner-of-address read (AUTH-6.37): ω unprojected.
    ///
    /// It answers the longest registered prefix containing `addr` and the
    /// principal seated at it, from one walk of M3's principal registry
    /// (`M3State::effective_owner_pair`). `addr` rides in the serving board's
    /// own local form — the form [`Op::Delegate`] takes and
    /// [`Op::PrincipalPrefix`] answers — and need not be allocated: ω is a
    /// pure prefix query. There is no document argument, so nothing is
    /// consulted and nothing withheld: like its two siblings above this is
    /// public, append-only registry data, the same answer for every caller
    /// and for none (no session is needed).
    ///
    /// An account is allocated — a seat of its own — iff the answer's prefix
    /// equals the address asked, the one test every caller makes. Any other
    /// prefix names the nearest seat *above* `addr`, so an unallocated
    /// `inc(X, 1)` answers `X`'s own principal and never none under the
    /// node; `Some` alone is therefore not the allocation test (AUTH-5.87 op
    /// (1)'s resume reads the equality and nothing else). Both halves are
    /// absent, together, only where no registered principal's prefix contains
    /// `addr`. Total — no fault path, as the two reads above have none.
    EffectiveOwner { addr: Address },
    // ── arrangement writes (→ M5) ──
    /// INSERT (ASN-0116).
    ///
    /// `Val` is M4's, carried in the payload verbatim — M10 names M4's types,
    /// and calls M4 only at the read by identity's arm ([`Op::RetrieveI`]).
    ///
    /// `deposit` is the deposit declaration (PUB-9.13's declared horn;
    /// PUB-2.59, PUB-2.63): the deposit-class record atom's first `insert`
    /// names its class — the declaration carries the class's type address,
    /// the one the pair's `make_link` then carries (PUB-2.11, PUB-2.64;
    /// RES-249) — and M5 clears a [`Deposit::Declared`] insert into a
    /// published document of the `published_target` refusal iff that type is
    /// one its deposit class holds and the insert is deposit-shaped — fresh
    /// positions past the arranged extent — where an [`Deposit::Undeclared`]
    /// one, a declared one naming any other type, or a declared one touching
    /// an arranged position, refuses `published_target` (PUB-2.11). Absent on
    /// the wire is `Undeclared`; into a draft the declaration is inert. It is
    /// M5's own two-variant type, carried verbatim: M10 decides nothing about
    /// it, the class test included.
    Insert { doc: Address, at: VPos, values: Vec<Val>, deposit: Deposit },
    /// DELETE (ASN-0117).
    Delete { doc: Address, p: VPos, width: Nat },
    /// COPY / transclusion (ASN-0118).
    Copy { doc: Address, at: VPos, specs: Vec<VSpec> },
    /// REINSTATE, the write by identity (the replacement act's record).
    ///
    /// `runs` are content I-runs the client names beside the document each
    /// states minted it — the publish shot's run form — placed into `doc` at
    /// `at` by identity, whether or not any arrangement holds them now, so a
    /// run a `delete` un-arranged comes back at its own addresses and every
    /// link on them returns; `retrieve_i`'s twin as `copy` is `retrieve_v`'s.
    /// A draft's write, owner-gated on `doc`.
    ///
    /// **The reach is wide.** A run's origin may be any document the session
    /// principal may read, consulted at the write door per distinct origin in
    /// run order ([`Op::source_arguments`]), the destination's own I-space
    /// excepted, as the shot's gate excepts it. M5's gates are the shot's on a
    /// client-named run — every address probed — and M10 hands the runs
    /// through verbatim.
    Reinstate { doc: Address, at: VPos, runs: Vec<ShotRun> },
    /// REARRANGE (pivot/swap).
    Rearrange { doc: Address, cuts: Vec<VPos> },
    /// CREATENEWVERSION (ASN-0123) — the content-sharing, copy-on-write fork.
    ///
    /// `published` is the three-valued flag with `None` ⇒ inherit
    /// `published(d_src)` (PUB-8.17). M5's `version` composite resolves the
    /// inheritance off its own working state and passes the resolved bit
    /// down (PUB-8.18); M10 hands the flag through unresolved.
    Version { d_src: Address, published: Option<bool> },
    /// PUBLISH, the shot (PUB-2.33, PUB-8.1).
    ///
    /// It appends the next member of `doc`'s chain, born published, in one
    /// commit, from the client-supplied runs of `shot`. M5's composite
    /// decides the destination at commit (the trunk's next member, or the
    /// base's daughter — PUB-2.39), places the runs by their origin
    /// (PUB-2.40) and runs the source gate (PUB-6.23) under the session's
    /// visibility class, which M10 lends it for this one write — the value
    /// the five link writes lend M7; M10 hands the shot through verbatim and
    /// names no policy of its own.
    ///
    /// **The kept places** (the link-sets design §5.7). `places` is parallel
    /// to `shot.runs` by index: for a draft-native run, the V-position it
    /// held in the staging draft when the client composed the request, read
    /// off the draft's image — or, for a STRAY run, one of the document's
    /// own identity the client re-composed by reference to a correspondence
    /// record's published words where the draft still arranges the record's
    /// draft words, the place those words hold — or `None`; empty where the
    /// request carries none, which is today's shot, writing nothing of the
    /// draft. The composite checks, in the shot's one commit, that the
    /// draft still arranges each such run's draft words at its place and
    /// replaces them there by the published identity, refusing the whole
    /// publication where it does not (`KeptPlaceMoved`, `site.index` the
    /// entry) or where no record of the draft names a stray run's identity
    /// whole (`StrayPlaceUnrecorded`, the same site). They ride BESIDE the
    /// shot and not in it: the shot is the member's arrangement, what the
    /// entry signature is composed over, and a place is a fact about the
    /// draft, outside the signed preimage as `draft` is — so the composer
    /// reads `shot` and `doc` alone, and every builder of a `Shot` stands.
    /// The wire's codec holds the list to `runs`' length, each place to a
    /// run of the draft or of `doc`'s own trunk and to the content subspace,
    /// padded with `None` to `runs`' length where any place is present; M10
    /// hands it through verbatim.
    ///
    /// **The target and the deposits** (the link-sets design §5.7; lane
    /// S3). `target` is where the publication lands: a published document
    /// of the caller's — today's `doc` — or, at the mint form, the parent
    /// account the commit mints an edition under (`mint: true` with
    /// `account`, `doc` absent) — M7's [`PublishTarget`], an enum over the
    /// two forms so a request names exactly one. `deposits` is the edition
    /// claim's flag (`claim: true`, at either form: the claim homed in the
    /// edition the commit mints or the one `doc` names, which must hold no
    /// member yet — skep #692) and the request's three optional lists
    /// beside the shot — `links`, `retract`, `read_with` (M7's
    /// [`PublishDeposits`]) — every public deposit the one commit stages
    /// after the records and before the re-window; empty where the request
    /// sends none, which with the document form is today's shot. The deposits lie INSIDE the signed preimage: the body
    /// is the shot's rows then each public deposit's, in the one order M7's
    /// plan gives them. M10 hands both through verbatim; the shape of each
    /// member is the codec's, and what each deposit is refused is M7's plan's,
    /// lowered here with its entry's index.
    ///
    /// **Size.** Its work is not bounded by its request's size;
    /// [`Codec::parse`] says why and what a route owes.
    ///
    /// [`Codec::parse`]: crate::Codec::parse
    Publish { target: PublishTarget, shot: Shot, places: Vec<Option<VPos>>, deposits: PublishDeposits },
    // ── link writes (→ M7) ──
    /// MAKELINK (ASN-0120): an open link from three three-form slots.
    ///
    /// Each slot is content V-specs (resolved by M7 inside its transact),
    /// address names deposited verbatim, or content I-spans deposited
    /// verbatim (`SlotArg` is M7's). The two name forms name no source: the
    /// door consults nothing for them and M7 reads nothing of the document
    /// they name — an I-span's shape is held by request arithmetic alone,
    /// `not_content_subspace` by slot and index (M7's content clause).
    ///
    /// `replaces` is the op's optional member naming the state the record
    /// replaces (PUB-5.15 (iii), (iv); RES-308): `None` — the member absent —
    /// is the empty state, and the record deposits alone; `Some` deposits the
    /// record and its `replaces` link in one transaction (M7's
    /// `LinkWriter::makelink_replacing`), the link's `to` this address. At
    /// the grant it names the revocation a re-share follows, and the grant
    /// fold honors the grant only where that is its key's current state. A
    /// name, as an address-form slot is: M10 consults nothing for it and
    /// checks nothing of it — whether it is current is the fold's question.
    /// Inside the entry frame's signed body (`skep_identity`'s `make_link`
    /// row), so the member a signature covers is the one that is deposited.
    MakeLink { home: Address, from: SlotArg, to: SlotArg, ty: SlotArg, replaces: Option<Address> },
    /// Emit_K: gated typed-relation emission (ASN-0126).
    Emit { home: Address, ty: Endset, from: Address, to: Vec<Address> },
    /// Nullify_Binary — the sole retraction path.
    Nullify { home: Address, target: Address },
    /// assert_sup: "old is superseded by new".
    AssertSup { home: Address, old: Address, new: Address },
    /// editlink: successor + supersession claim, one composite (§4).
    ///
    /// **Refusal order across the three layers that may answer it.** Where
    /// both `d_s` and `d_a` are registered documents the caller owns, the door
    /// speaks first — `original` homed where the caller cannot read answers
    /// `OriginalNotResident`, exactly as a never-deposited link, and an
    /// unreadable successor source `Withheld` — then the successor's own
    /// refusals ([`SuccessorSpec`]), then M7's. Where they are not, the door
    /// judges nothing: the successor's request-shape and registration
    /// refusals still speak, ahead of M7's home gate, which then answers
    /// `HomeNotRegistered`, or `NotOwner` naming the home that failed — at
    /// the commit base, so a home registered after the door's snapshot passes
    /// it ([`OperationSurface::execute`]).
    ///
    /// [`OperationSurface::execute`]: crate::OperationSurface::execute
    EditLink { original: Address, successor: SuccessorSpec, d_s: Address, d_a: Address },
    // ── raw link reads (→ M7) ──
    /// Σ.L(a) verbatim.
    ///
    /// A link whose home document this caller may not read answers absent —
    /// `None`, exactly as an address no link occupies (PUB-6.6) — never a
    /// rejection, which would confirm the link is there. So `None` does not
    /// distinguish "no link" from "not yours to see", and a client must not
    /// read it as the former.
    ReadLink { a: Address },
    /// Slot coverage, carrying its own in-band `Result` (⟨⟩ ≠ ⊥ — §2).
    ///
    /// A link whose home document this caller may not read answers absent,
    /// on the `⊥` side of that very distinction: `Err(Invalid)`, exactly as
    /// an address no link occupies (PUB-6.6), never `Ok(⟨⟩)`, which stays a
    /// present link's empty slot.
    ///
    /// `slot` is M7's 1-based numbering — [`FROM`], [`TO`], [`TYPE`] on a
    /// triple — and a slot outside the link's arity, `0` and `usize::MAX`
    /// among them, is `⊥` too: `Err(Invalid)`, an answer and never a fault.
    ///
    /// [`FROM`]: crate::FROM
    /// [`TO`]: crate::TO
    /// [`TYPE`]: crate::TYPE
    FollowLink { a: Address, slot: usize },
    // ── content/provenance reads (→ M6; the read by identity and the
    //    frontier read ask the world directly) ──
    /// RETRIEVEV (ASN-0115).
    ///
    /// Each spec's named `doc` is consulted, so an unreadable one answers
    /// `Withheld`; but a run whose origin the caller may not read comes back
    /// as the withheld `DeliveryItem` at its own position (PUB-6.41) —
    /// neither dropped from the delivery nor raised as a rejection — so
    /// positions are preserved and a caller handles that arm.
    ///
    /// **Size.** Its work is not bounded by its request's size;
    /// [`Codec::parse`] says why and what a route owes.
    ///
    /// [`Codec::parse`]: crate::Codec::parse
    RetrieveV { specs: Vec<Spec> },
    /// RETRIEVEI, the read by identity (AUTH-6.38–6.40).
    ///
    /// It answers the values at I-addresses (the media record's "the read by
    /// identity"; the register M-I2 (a), (h)), one item per position of each
    /// [`ISpan`] in span order, as M4 holds them — `None` where the position
    /// was never minted, and `None` at a link position too, M4 holding
    /// content-subspace elements alone. Its reach is every value the document
    /// minted, arranged or not, under no floor: `value_at` is keyed by
    /// I-address and blind to arrangement, so a value deleted from a draft is
    /// read here by a reader the draft admits, however late admitted.
    ///
    /// **Its argument is derived (PUB-6.38).** No span names a document —
    /// each derives one, `document_of` of its start, by address arithmetic on
    /// the op's own fields — so the consult walks [`Op::derived_doc_arguments`]
    /// after the named list, and the first unreadable derived document
    /// answers `Withheld` naming it, before dispatch (PUB-6.5's order,
    /// PUB-8.4's shape) — never a per-address withheld item, whose count
    /// would be the extent PUB-6.5 withholds. A span whose start has no
    /// derived document — a node's, an account's or a document's own address
    /// — or whose width is zero is refused at the op's shape, by that same
    /// arithmetic and before any consult, so the derived list is bounded by
    /// the span count the parser caps (PATTERNS P29). Each span is confined
    /// to one derived document by construction: a span advances its start's
    /// last component alone, and the document prefix never moves.
    ///
    /// **Size.** The delivery is the widths summed, request arithmetic, held
    /// to `skep_retrieval::MAX_DELIVERY_ITEMS` as RETRIEVEV's is and refused
    /// whole past it (`TooManyItems`), before the first address is expanded.
    /// The grammar is interim; AUTH's docket pins the final.
    RetrieveI { spans: Vec<ISpan> },
    /// The content-frontier read (AUTH-6.38): `doc`'s content mint frontier.
    ///
    /// It is the next unminted content ordinal — a draft's mint count plus
    /// one — read off M3's content chain for the document (the media record's
    /// "the frontier read is a doc-argument op of its own"). `doc` is a
    /// doc-argument (PUB-6.1, by PUB-6.12's rule): unreadable ⟹ `withheld`
    /// before dispatch, so a draft's mint count is never told to a reader
    /// the draft does not admit; unregistered ⟹ `DocNotRegistered`, M10's
    /// own refusal, as the doc-metadata read answers it. Served on `/op-at`
    /// for "as of N" as every read is.
    ContentFrontier { doc: Address },
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
    /// The count by home that lifts no link (the link-sets design §7,
    /// W10 (a)): per readable home holding a link that touches the region,
    /// in address order, the number of its distinct links there, counted
    /// and never lifted, stopping at the budget `n` with `exhausted`
    /// answering whether the walk ended under it; `except` names the homes
    /// passed unstabbed and uncounted — the applied sets', which the page
    /// reads by home. `d` is the doc-argument, as `count_v`'s is: unreadable
    /// ⟹ `withheld` before dispatch (PUB-6.12); a home in `except` is
    /// never consulted and never answers anything.
    CountVByHome { d: Address, region: Vec<Span>, n: usize, except: Vec<Address> },
    /// The retracted-links read (the link-sets design §7, lane 7; the
    /// owner's rulings of 2026-10-28): every link ever made whose endsets
    /// touch the region, active or RETRACTED — the AUDIT view, where every
    /// other region read answers the active one — windowed over homes as
    /// `window_v` is, each row the link with the position of the commit that
    /// minted it and, where retracted, its earliest retraction's position;
    /// positions only, no time. `d` is the doc-argument, as `window_v`'s is:
    /// unreadable ⟹ `withheld` before dispatch (PUB-6.12); the rows are
    /// filtered at each LINK's home, and a retraction homed where the caller
    /// may not read crosses as its position alone, never its address
    /// (PUB-6.47).
    FindLinksVHistory { d: Address, region: Vec<Span>, cur: Cursor, n: usize },
    /// RETRIEVEENDSETS (ASN-0131).
    RetrieveEndsets { d: Address, region: Vec<Span> },
    /// I→V projection of a link slot into a document (ASN-0098).
    ///
    /// The dual row (PUB-6.8): `d` is the doc-argument, so an unreadable `d`
    /// answers `Withheld` naming `d`; the link `a` is not one, so a link homed
    /// where the caller cannot read takes the reader's own absence answer
    /// instead. A `Withheld` here is therefore always about `d`, and never a
    /// statement about `a`.
    ///
    /// `slot` is numbered as [`Op::FollowLink`]'s, and a slot outside the
    /// link's arity answers `NotALink`, as an absent link does — M8 answers
    /// the two alike.
    Project { a: Address, slot: usize, d: Address },
    /// Compound "arrangement-reachable and active".
    ///
    /// The dual row, as [`Op::Project`]'s: `d` is the doc-argument and an
    /// unreadable one answers `Withheld` naming `d`, while the link `a` is not
    /// one and so never answers `Withheld` (PUB-6.8).
    ///
    /// **What `a` answers instead.** It is the absence its three siblings
    /// answer, each in its own shape: a link homed where the caller cannot
    /// read is absent and answers `NotALink` — exactly what an address no link
    /// occupies answers — so, as at [`Op::ReadLink`], [`Op::FollowLink`] and
    /// [`Op::Project`], the answer never distinguishes an occupied address from
    /// an unoccupied one (PUB-6.6's table: `not_a_link` here). Never `false`,
    /// which is the retracted link's answer and would tell the caller that a
    /// link occupies the address. A retracted link in a home the caller *may*
    /// read is present to them, and still answers `false`.
    DiscoverableFrom { a: Address, d: Address },
    /// Pre-edit link-survival what-if (ASN-0117 preview).
    DeleteOrphans { d: Address, p: VPos, width: Nat },
    /// Archival supersession lineage: claims with `old = y`.
    InClaims { y: Address, view: View },
    /// Archival supersession lineage: claims with `new = x`.
    OutClaims { x: Address, view: View },
    // ── publication reads (PUB-8.47): answers M10 composes rather than
    //    forwards to one store — what they need that no store computes is
    //    the `publication` card's ──
    /// The doc-metadata read (PUB-8.12).
    ///
    /// It answers a document's publication state, its owner account, and its
    /// birth version with that version's birth extent — what a client's own
    /// PUB-3.19 admission test needs — and, of the address named, its shot
    /// terms and its fork source (below). `doc` is a doc-argument (PUB-6.1):
    /// unreadable ⟹ `withheld` (fail-open at the consult, PUB-6.12). It must
    /// also be a registered document: unregistered, or any other tier, ⟹
    /// `DocNotRegistered` — M10's own refusal, like [`Op::EditionClaims`]'s,
    /// since this read composes its answer from more than one store and so
    /// reaches none that could raise one. A version member answers its
    /// document's state (PUB-2.15) — and, beside it, its own shot terms where
    /// the shot minted it (signed-ops D25: the count the client placed and
    /// the base extent its copy took, what a verifier of the member's entry
    /// signature reads off the member), and its own fork source where a
    /// `version` minted it (the fork-source design record).
    DocMetadata { doc: Address },
    /// The audit-view edition-claim lookup (PUB-8.46).
    ///
    /// It answers every unsuperseded claim of the edition-claim class whose
    /// `to` slot overlaps `target`'s subtree, whether or not retracted, each
    /// with its home (the edition) and its retraction stated. Overlap is
    /// wider than denotation, and that width is the containment the lookup is
    /// for: asking about a document yields the claims on it and on its
    /// versions, and a `to` slot spanning the subtree without denoting an
    /// address in it is still a row. Class membership is the other way — by
    /// denotation over the type slot — so the two slots are read by different
    /// regimes.
    ///
    /// `target` is a doc-argument (unreadable ⟹ `withheld`) and must be a
    /// registered document: unregistered, or any other tier, ⟹
    /// `DocNotRegistered` — M10's own refusal, since this read composes a
    /// world capability rather than calling one store operation, and the
    /// check is what confines the lookup to one document's claims. Each
    /// surviving row is then kept only where the caller can read its home
    /// (PUB-6.13), so a draft edition's claim is invisible to a stranger.
    /// The client's PUB-3.19 admission test over each home is its own,
    /// through [`Op::DocMetadata`].
    ///
    /// **Order.** The rows come back in link-address order — the order the
    /// world answers the class in, preserved through the home filter — so
    /// dropping a row never reorders its neighbours and a client may page or
    /// diff the answer without sorting it first.
    EditionClaims { target: Address },
    /// The any-principal discovery read (PUB-8.47; RES-224).
    ///
    /// It is the grant fold's live universal set, exposed to a bound
    /// principal as one wire read — one row per content prefix with the
    /// issuers who granted it to every principal, in prefix order — and empty
    /// for the guest (PUB-5.109): an answer, never a refusal, since grants
    /// reach principals alone. No argument: the set is a board population,
    /// and the answer does not depend on which principal asks, only on guest
    /// against bound. It names no document, so nothing is consulted and
    /// nothing withheld.
    ///
    /// The served row is fold-filtered, never raw (RES-231, RES-264,
    /// RES-273, RES-298): each stored row is narrowed to the prefix its issuer
    /// ω-owns, so a client is handed the set the fold *answers* from and
    /// never the index it keys on (RES-258). The compare is ω's (RES-298) —
    /// the registry's `effective_owner_prefix` of the stored prefix against
    /// each issuer of the row — in three arms:
    ///
    /// * where ω of the stored prefix *is* the issuer's account, the stored
    ///   prefix, unchanged: that account, a document of it, or a sub-prefix
    ///   of it no delegation has seated (RES-298's named residue — ω answers
    ///   the issuer there until a delegation seats the sub-prefix, and the row
    ///   drops at the next read after);
    /// * where the stored prefix contains the issuer's account and is not it —
    ///   wider, an agent's share over its hirer's prefix (RES-264) — the
    ///   issuer's own account, which is every document the issuer owns under
    ///   the stored prefix and exactly what the fold's probe answers `true`
    ///   for;
    /// * otherwise no row: a stranger's record over a stranger's document
    ///   (RES-231's cell), and a hirer's grant beneath its registered
    ///   sub-account — inside the hirer's account by address, the
    ///   sub-account's by ω, so the issuer is not the owner and the fold
    ///   honors the grant for no document.
    ///
    /// The compare is M3's own walk, one per stored row off the read's
    /// snapshot: no read class and no index is added (PUB-3.48), the fold's
    /// own universal index is what is read, and the bound is that index's own
    /// size (PUB-7.45) times that walk.
    ///
    /// What it serves is the client's — the arrival face, the any-principal
    /// arm, the back-fill — and never what the daemon *serves*: the feed
    /// applies the same live set itself at serve, so this read changes what a
    /// client may display and nothing about what it can read (PUB-8.42's
    /// list, not PUB-8.43's bound). Total, like every read that neither names
    /// nor derives a document.
    UniversalGrants,
}

/// EditLink's successor, assembled by M10 from content V-specs or I-spans
/// (§4).
///
/// `from`/`to` take two of M7's three slot forms: content V-specs, resolved
/// here off the snapshot, or content I-spans, deposited verbatim (W6 (a) —
/// the re-made end of an accepted link is the original's own I-spans, cut
/// in I-space, and names no source). The address form is refused on them —
/// a deliberate narrowing, kept: an address-denoting successor endpoint is
/// `ill_formed_successor` at the build, naming the slot, and the wire's
/// parse admits no `addrs` object there; supersession of managed tuples goes
/// via [`Op::Emit`] + [`Op::AssertSup`]. The type slot is M7's three-form
/// [`SlotArg`], which [`Op::MakeLink`]'s three slots share.
///
/// **Refusal precedence.** A successor may be wrong in several places at once
/// and exactly one answer comes back, so the order decides it: the slots are
/// built `from`, then `to`, then `ty`, and the first that refuses speaks.
/// Within a slot the first offending spec speaks, `IllFormedSpec` ahead of
/// `SourceNotRegistered` on it; within an I-span slot the first span that is
/// no content I-span, `NotContentSubspace`. [`crate::FaultSite`] localizes
/// the refusal in two fields: `slot` names which of the three refused, in
/// M7's numbering ([`FROM`]/[`TO`]/[`TYPE`], the numbering
/// [`Op::FollowLink`]'s `slot` is already in), and `index` the offending
/// spec's or span's position within it.
///
/// A slot is also held to M7's two per-slot budgets — the spans it keeps
/// ([`MAX_SLOT_SPANS`]) and the run-list steps its resolution walks — and
/// over either answers `SlotTooLarge`, naming the slot and no index, the slot
/// rather than one spec being at fault. Where both homes are registered
/// documents the caller owns — the write the door judges — the refusal is
/// M10's, raised as the slot crosses, once every spec reached so far has
/// passed its two checks, so a spec after the crossing is never reached.
/// Where they are not, the budget is M7's, answered after M7's home gate, so
/// the store's `HomeNotRegistered`/`NotOwner` speaks first and the answer
/// never turns on what a source the caller may not read holds; should that
/// gate pass after all — a home registered in the window between M10's
/// snapshot and the commit — it is M7 that answers `SlotTooLarge`, with no
/// site, and a successor under both budgets commits as built, its sources
/// never consulted ([`OperationSurface::execute`] states that window). The
/// two name forms are the exception: an address-form type slot's count and
/// an I-span slot's count are the request's own, so each is held to the span
/// budget whoever asks.
///
/// [`FROM`]: crate::FROM
/// [`TO`]: crate::TO
/// [`TYPE`]: crate::TYPE
/// [`MAX_SLOT_SPANS`]: crate::MAX_SLOT_SPANS
/// [`OperationSurface::execute`]: crate::OperationSurface::execute
///
/// `Debug` by derive, where the [`Op`] that carries it writes its own: no
/// `Val` reaches this payload. So a client that meets an [`IllFormedSpec`] at
/// some `slot`/`index` can render the successor it sent, and a harness
/// comparing a built successor against a parsed one can write the
/// `assert_eq!` its [`PartialEq`] is for.
///
/// [`IllFormedSpec`]: crate::RejectCode::IllFormedSpec
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessorSpec {
    /// The successor's `from` slot: content V-specs, or content I-spans.
    ///
    /// A `Vec<VSpec>` converts into the first form (`SlotArg`'s `From`); the
    /// address form is refused at the build.
    pub from: SlotArg,
    /// The successor's `to` slot: content V-specs, or content I-spans.
    pub to: SlotArg,
    /// The successor's type slot, in any of [`SlotArg`]'s three forms.
    pub ty: SlotArg,
}

/// One I-span of [`Op::RetrieveI`]: `width` consecutive positions from `start`.
///
/// `start` is an I-address, and the positions are I-positions — element
/// positions of one document, which the op's shape holds to no subspace; in
/// the content subspace they are the positions a document's mint issues in
/// order, so a span over them is the chain's own run. A value, with [`Op`]'s
/// derives and for its reason; `Hash` because its two fields carry one, so a
/// caller may key a cache by the span it asked.
///
/// Its document is derived, never named: `document_of(start)` (PUB-6.38),
/// which [`Op::derived_doc_arguments`] computes and the consult walks. A
/// start that is no element position derives none, and the op's shape
/// refuses it ([`ISpanFault::NoElementPosition`]) ahead of any consult.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ISpan {
    /// The first I-address of the span — an element position.
    pub start: Address,
    /// How many consecutive positions from it, at least one.
    pub width: Nat,
}

/// How an [`ISpan`] fails the op's shape.
///
/// These are the two faults [`Op::derived_doc_arguments`] refuses, by
/// address arithmetic on the span's own fields and before any consult. Named
/// here, beside the list it refuses, and lowered to its rejection by the
/// consult that walks the list: the first to `NotContentSubspace`, the second
/// to `EmptyWidth`, each naming the span's index as its site, as a malformed
/// RETRIEVEV spec names its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ISpanFault {
    /// The start names no element position, so no document derives from it.
    ///
    /// It is a node's, an account's or a document's own address.
    NoElementPosition,
    /// The width is zero: a span over no position.
    EmptyWidth,
}

/// The fieldless echo of [`Op`], plus [`OpKind::Unparseable`].
///
/// It has one unit variant per operation. `execute` only ever sees an
/// already-parsed [`Request`], so a `Codec::parse` failure has produced no
/// `Op`; the transport builds that one `Response::Rejected` itself, around
/// [`Rejection::unparseable`], which stamps it `OpKind::Unparseable`
/// (§Public interface/Codec). [`Op::kind`] produces every variant except
/// `Unparseable`. `Copy + PartialEq` so `execute` captures it before dispatch
/// moves the op and threads it to both idempotency steps and its own two
/// gates' rejections — every other rejection takes its own copy off the op,
/// save the successor build's, which names `OpKind::EditLink` itself — and
/// the retry memo's lookup can match it (§7); `Hash` so a caller may key by
/// it — per-operation counters and sets are what a transport instruments
/// this surface with, and only this crate can supply the impl. Not
/// `#[non_exhaustive]`, for [`Op`]'s reason.
///
/// [`Rejection::unparseable`]: crate::Rejection::unparseable
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum OpKind {
    /// The kind of [`Op::CreateNewDocument`].
    CreateNewDocument,
    /// The kind of [`Op::Delegate`].
    Delegate,
    /// The kind of [`Op::RegisterNode`].
    RegisterNode,
    /// The kind of [`Op::Fork`].
    Fork,
    /// The kind of [`Op::NextAccountPrefix`].
    NextAccountPrefix,
    /// The kind of [`Op::PrincipalPrefix`].
    PrincipalPrefix,
    /// The kind of [`Op::EffectiveOwner`].
    EffectiveOwner,
    /// The kind of [`Op::Insert`].
    Insert,
    /// The kind of [`Op::Delete`].
    Delete,
    /// The kind of [`Op::Copy`].
    Copy,
    /// The kind of [`Op::Reinstate`].
    Reinstate,
    /// The kind of [`Op::Rearrange`].
    Rearrange,
    /// The kind of [`Op::Version`].
    Version,
    /// The kind of [`Op::Publish`].
    Publish,
    /// The kind of [`Op::MakeLink`].
    MakeLink,
    /// The kind of [`Op::Emit`].
    Emit,
    /// The kind of [`Op::Nullify`].
    Nullify,
    /// The kind of [`Op::AssertSup`].
    AssertSup,
    /// The kind of [`Op::EditLink`].
    EditLink,
    /// The kind of [`Op::ReadLink`].
    ReadLink,
    /// The kind of [`Op::FollowLink`].
    FollowLink,
    /// The kind of [`Op::RetrieveV`].
    RetrieveV,
    /// The kind of [`Op::RetrieveI`].
    RetrieveI,
    /// The kind of [`Op::ContentFrontier`].
    ContentFrontier,
    /// The kind of [`Op::RetrieveDocVSpan`].
    RetrieveDocVSpan,
    /// The kind of [`Op::RetrieveDocVSpanSet`].
    RetrieveDocVSpanSet,
    /// The kind of [`Op::ShowOrigin`].
    ShowOrigin,
    /// The kind of [`Op::ShowDeletions`].
    ShowDeletions,
    /// The kind of [`Op::Compare`].
    Compare,
    /// The kind of [`Op::FindDocsContaining`].
    FindDocsContaining,
    /// The kind of [`Op::Image`].
    Image,
    /// The kind of [`Op::FindLinksV`].
    FindLinksV,
    /// The kind of [`Op::FindLinksFtt`].
    FindLinksFtt,
    /// The kind of [`Op::CountV`].
    CountV,
    /// The kind of [`Op::CountFtt`].
    CountFtt,
    /// The kind of [`Op::WindowV`].
    WindowV,
    /// The kind of [`Op::WindowFtt`].
    WindowFtt,
    /// The kind of [`Op::CountVByHome`].
    CountVByHome,
    /// The kind of [`Op::FindLinksVHistory`].
    FindLinksVHistory,
    /// The kind of [`Op::RetrieveEndsets`].
    RetrieveEndsets,
    /// The kind of [`Op::Project`].
    Project,
    /// The kind of [`Op::DiscoverableFrom`].
    DiscoverableFrom,
    /// The kind of [`Op::DeleteOrphans`].
    DeleteOrphans,
    /// The kind of [`Op::InClaims`].
    InClaims,
    /// The kind of [`Op::OutClaims`].
    OutClaims,
    /// The kind of [`Op::DocMetadata`].
    DocMetadata,
    /// The kind of [`Op::EditionClaims`].
    EditionClaims,
    /// The kind of [`Op::UniversalGrants`].
    UniversalGrants,
    /// A frame that never parsed into an `Op`.
    ///
    /// [`Rejection::unparseable`] stamps it, on the transport's parse
    /// failure, and [`Op::kind`] never does.
    ///
    /// [`Rejection::unparseable`]: crate::Rejection::unparseable
    Unparseable,
}

impl Op {
    /// Returns whether this op is a read: one half of `Op`'s partition (§1).
    ///
    /// Reads and writes partition `Op` exhaustively (`is_write == !is_read`),
    /// keyed to the grouping in `Op`'s definition. `execute` gates on this
    /// split (writes get a proven-bound principal; reads don't), and it
    /// selects the dispatch function. Exhaustive match with no `_` arm — a
    /// new `Op` variant fails to compile here (and at both dispatch
    /// functions) until classified, never silently defaulting into either
    /// half.
    ///
    /// Public because the partition is a fact about the request, not an
    /// implementation detail of the lifecycle: a transport that serializes
    /// or records writes must know which side an `Op` falls on *before*
    /// [`OperationSurface::execute`] takes it, and this is the one answer.
    ///
    /// [`OperationSurface::execute`]: crate::OperationSurface::execute
    //
    // The two-arm shape is load-bearing (compile-time non-exhaustiveness on a
    // new variant), so the `matches!` rewrite clippy suggests is refused.
    #[allow(clippy::match_like_matches_macro)]
    pub fn is_read(&self) -> bool {
        match self {
            Op::NextAccountPrefix { .. }
            | Op::PrincipalPrefix { .. }
            | Op::EffectiveOwner { .. }
            | Op::DocMetadata { .. }
            | Op::ReadLink { .. }
            | Op::FollowLink { .. }
            | Op::RetrieveV { .. }
            | Op::RetrieveI { .. }
            | Op::ContentFrontier { .. }
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
            | Op::CountVByHome { .. }
            | Op::FindLinksVHistory { .. }
            | Op::RetrieveEndsets { .. }
            | Op::Project { .. }
            | Op::DiscoverableFrom { .. }
            | Op::DeleteOrphans { .. }
            | Op::InClaims { .. }
            | Op::OutClaims { .. }
            | Op::EditionClaims { .. }
            | Op::UniversalGrants => true,
            Op::CreateNewDocument { .. }
            | Op::Delegate { .. }
            | Op::RegisterNode { .. }
            | Op::Fork { .. }
            | Op::Insert { .. }
            | Op::Delete { .. }
            | Op::Copy { .. }
            | Op::Reinstate { .. }
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

    /// Returns whether this op is a write: the other side of [`Op::is_read`].
    ///
    /// It is defined as that answer's absence, so the two cannot disagree
    /// about a variant.
    pub fn is_write(&self) -> bool {
        !self.is_read()
    }

    /// Returns the op's fieldless echo, never [`OpKind::Unparseable`].
    pub fn kind(&self) -> OpKind {
        match self {
            Op::CreateNewDocument { .. } => OpKind::CreateNewDocument,
            Op::Delegate { .. } => OpKind::Delegate,
            Op::RegisterNode { .. } => OpKind::RegisterNode,
            Op::Fork { .. } => OpKind::Fork,
            Op::NextAccountPrefix { .. } => OpKind::NextAccountPrefix,
            Op::PrincipalPrefix { .. } => OpKind::PrincipalPrefix,
            Op::EffectiveOwner { .. } => OpKind::EffectiveOwner,
            Op::DocMetadata { .. } => OpKind::DocMetadata,
            Op::Insert { .. } => OpKind::Insert,
            Op::Delete { .. } => OpKind::Delete,
            Op::Copy { .. } => OpKind::Copy,
            Op::Reinstate { .. } => OpKind::Reinstate,
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
            Op::RetrieveI { .. } => OpKind::RetrieveI,
            Op::ContentFrontier { .. } => OpKind::ContentFrontier,
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
            Op::CountVByHome { .. } => OpKind::CountVByHome,
            Op::FindLinksVHistory { .. } => OpKind::FindLinksVHistory,
            Op::RetrieveEndsets { .. } => OpKind::RetrieveEndsets,
            Op::Project { .. } => OpKind::Project,
            Op::DiscoverableFrom { .. } => OpKind::DiscoverableFrom,
            Op::DeleteOrphans { .. } => OpKind::DeleteOrphans,
            Op::InClaims { .. } => OpKind::InClaims,
            Op::OutClaims { .. } => OpKind::OutClaims,
            Op::EditionClaims { .. } => OpKind::EditionClaims,
            Op::UniversalGrants => OpKind::UniversalGrants,
        }
    }

    /// Returns a read's doc-argument list, in declaration order.
    ///
    /// They are the named documents the doc-argument consult tests (PUB-6.1,
    /// PUB-6.4), so the first unreadable one is the `site.addr` a `Withheld`
    /// rejection carries. Within a list, in index order; across an op's
    /// lists, in declaration order (a spec-set's docs, then ρ₁'s regions
    /// before ρ₂'s, `d_a` before `d_b`, and `project`/`discoverable_from`'s
    /// `d` — the dual row's first, PUB-6.8). Every other read — the FTT
    /// descriptor family (its `home` is a coverage constraint, not a named
    /// document), the raw link reads (link-address absence, PUB-6.6, never
    /// withheld), the lineage probes (`y`/`x` are probe keys, PUB-6.12), the
    /// namespace reads (the owner-of-address read among them: its `addr` is a
    /// registry probe, never a document argument, AUTH-6.37), the any-principal
    /// discovery read (no argument at all, its rows fold-filtered at its own
    /// arm, PUB-8.47), the read by identity (each span derives its document
    /// rather than naming one, [`Op::derived_doc_arguments`]) — names no
    /// document to withhold and answers the empty list; and every write
    /// answers it too, its source consult being the write door's own list,
    /// [`Op::source_arguments`] (PUB-6.23).
    ///
    /// Public as a fact about the request: it is what a caller reads, with
    /// [`Op::derived_doc_arguments`], to know which documents a read's
    /// `Withheld` may name. The consult over it is [`consult_read`], shared by
    /// both front doors that run it — [`OperationSurface::execute`] over the
    /// snapshot it pins, and a transport answering a historical read over the
    /// head before any reconstruction (PUB-6.49) — so the list, its order and
    /// the verdict have one spelling.
    ///
    /// [`consult_read`]: crate::consult_read
    /// [`OperationSurface::execute`]: crate::OperationSurface::execute
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
            | Op::CountVByHome { d, .. }
            | Op::FindLinksVHistory { d, .. }
            | Op::RetrieveEndsets { d, .. }
            | Op::DeleteOrphans { d, .. }
            | Op::Project { d, .. }
            | Op::DiscoverableFrom { d, .. } => vec![d],
            // The two publication reads that take a document: each names one,
            // and it is the consulted one — `doc_metadata` answers nothing
            // about a document the caller cannot read (PUB-8.12), and the
            // edition lookup's `target` is a named document, not a probe key
            // (PUB-8.46; the H1 row: unreadable ⟹ withheld).
            Op::DocMetadata { doc } => vec![doc],
            Op::EditionClaims { target } => vec![target],
            // The frontier read names its document (the media record: "a
            // doc-argument op of its own"), and on a draft its answer is the
            // draft's mint count plus one, so it takes PUB-6.1's row by
            // PUB-6.12's rule.
            Op::ContentFrontier { doc } => vec![doc],
            // No named document to withhold (see above); written out rather
            // than wildcarded so a new read variant is classified here on
            // purpose, never defaulted to "consults nothing". The read by
            // identity is among them by design: it names no document — each
            // span derives one, and the derived list is
            // [`Op::derived_doc_arguments`], walked by the same consult.
            Op::RetrieveI { .. }
            | Op::NextAccountPrefix { .. }
            | Op::PrincipalPrefix { .. }
            | Op::EffectiveOwner { .. }
            | Op::ReadLink { .. }
            | Op::FollowLink { .. }
            | Op::FindLinksFtt { .. }
            | Op::CountFtt { .. }
            | Op::WindowFtt { .. }
            | Op::InClaims { .. }
            | Op::OutClaims { .. }
            | Op::UniversalGrants
            | Op::CreateNewDocument { .. }
            | Op::Delegate { .. }
            | Op::RegisterNode { .. }
            | Op::Fork { .. }
            | Op::Insert { .. }
            | Op::Delete { .. }
            | Op::Copy { .. }
            | Op::Reinstate { .. }
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

    /// Returns the documents a read derives rather than names (PUB-6.38).
    ///
    /// This derived-argument list is the documents a read consults that it
    /// does not name but derives by address arithmetic on its own fields (the
    /// media record's "each I-span confined to one derived document";
    /// PATTERNS P29) — [`Op::RetrieveI`]'s, `document_of` of each span's
    /// start, in span order — which [`consult_read`] walks *after*
    /// [`Op::doc_arguments`]'s named ones, so the first unreadable derived
    /// document answers `Withheld` naming it before dispatch, and the
    /// historical door walks it the same way (PUB-6.49). Owned, where the
    /// named list lends borrows: a derived document is no field of the op.
    ///
    /// A span never crosses a document: it advances its start's last
    /// component alone, and the document prefix is invariant under that, so
    /// confinement holds by construction and no check is needed for it.
    ///
    /// Every other op answers the empty list, written out with no wildcard
    /// for [`Op::doc_arguments`]'s reason: a new read decides here whether
    /// its argument is derived.
    ///
    /// # Errors
    ///
    /// The shape refusal rides the derivation, by the span's index: a span of
    /// zero width spans nothing ([`ISpanFault::EmptyWidth`]), and one whose
    /// start names no element position — a node's, an account's or a
    /// document's own address — derives nothing
    /// ([`ISpanFault::NoElementPosition`]). The first such span answers, its
    /// width judged ahead of its start. Either is refused here, *before* any
    /// document is consulted and before any store is asked, so the list is
    /// bounded by the span count the parser caps and a prober learns nothing a
    /// span's shape did not already say.
    ///
    /// [`consult_read`]: crate::consult_read
    pub fn derived_doc_arguments(&self) -> Result<Vec<Address>, (usize, ISpanFault)> {
        match self {
            Op::RetrieveI { spans } => spans
                .iter()
                .enumerate()
                .map(|(index, span)| {
                    if span.width == Nat::from(0u32) {
                        return Err((index, ISpanFault::EmptyWidth));
                    }
                    if span.start.level() != Level::Element {
                        return Err((index, ISpanFault::NoElementPosition));
                    }
                    document_of(&span.start).ok_or((index, ISpanFault::NoElementPosition))
                })
                .collect(),
            Op::ContentFrontier { .. }
            | Op::NextAccountPrefix { .. }
            | Op::PrincipalPrefix { .. }
            | Op::EffectiveOwner { .. }
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
            | Op::CountVByHome { .. }
            | Op::FindLinksVHistory { .. }
            | Op::RetrieveEndsets { .. }
            | Op::Project { .. }
            | Op::DiscoverableFrom { .. }
            | Op::DeleteOrphans { .. }
            | Op::InClaims { .. }
            | Op::OutClaims { .. }
            | Op::DocMetadata { .. }
            | Op::EditionClaims { .. }
            | Op::UniversalGrants
            | Op::CreateNewDocument { .. }
            | Op::Delegate { .. }
            | Op::RegisterNode { .. }
            | Op::Fork { .. }
            | Op::Insert { .. }
            | Op::Delete { .. }
            | Op::Copy { .. }
            | Op::Reinstate { .. }
            | Op::Rearrange { .. }
            | Op::Version { .. }
            | Op::Publish { .. }
            | Op::MakeLink { .. }
            | Op::Emit { .. }
            | Op::Nullify { .. }
            | Op::AssertSup { .. }
            | Op::EditLink { .. } => Ok(Vec::new()),
        }
    }

    /// Returns a write's source-argument list, in declaration order.
    ///
    /// They are the documents whose arrangement — or, for `reinstate`, whose
    /// minted content — the write reads before it writes (PUB-6.23, PUB-6.24,
    /// PUB-6.4), so the first unreadable one is the `site.addr` the write
    /// door's `Withheld` rejection carries. `copy` names each
    /// `specs[].source` by index; `reinstate` each distinct `runs[].origin`
    /// in run order, the destination's own I-space excepted (the shot's rule:
    /// the document's own needs no consult — address arithmetic on the stated
    /// origin, PUB-2.15); `version` its `d_src`; `make_link` and `edit_link`
    /// the document of every `Resolve`-form slot's V-spec — slots in the
    /// wire's declared order `from`, `to`, `ty`, specs by index within a slot.
    /// An address-form or I-span slot names no source: an address is not
    /// secret and needs no read to write (PUB-1.13, PUB-6.24), and an I-span
    /// is an address with a width, so both are ungated and contribute nothing
    /// here — which is the read check's door channel (W6 (a)).
    ///
    /// `fork` reads no source (PUB-6.23) and answers the empty list, as does
    /// every other write — `publish`'s source gate is the composite's own,
    /// threaded per origin through the predicate M10 hands M5 (PUB-8.1), and
    /// `emit`'s endpoints are address-form (PUB-6.11) — and every read, whose
    /// consult is [`Op::doc_arguments`] (and, for the read by identity,
    /// [`Op::derived_doc_arguments`]). Written out, no wildcard, so a new
    /// variant is classified here on purpose.
    ///
    /// Public for the reason [`Op::doc_arguments`] is: the list is a fact
    /// about the request, and a transport that wants to know which documents
    /// a write will read before it dispatches it reads the same list.
    pub fn source_arguments(&self) -> Vec<&Address> {
        /// Appends a `Resolve`-form slot's source documents to `out`.
        ///
        /// It reads no arrangement: a `Resolve` slot names its sources, and
        /// resolving them is M5's act, on the far side of the consult this
        /// list feeds. The two name forms have none (`SlotArg::specs`).
        fn push_resolve_sources<'a>(slot: &'a SlotArg, out: &mut Vec<&'a Address>) {
            out.extend(slot.specs().iter().map(|s| &s.source));
        }
        match self {
            Op::Copy { specs, .. } => specs.iter().map(|s| &s.source).collect(),
            // The distinct origins the runs state, in run order, as the
            // client states them — the address a `withheld` names — the
            // destination's own I-space excepted: a stated origin projecting
            // to `doc`'s trunk (PUB-2.15) is the writer's own, which the
            // deferral has just found it owns.
            Op::Reinstate { doc, runs, .. } => {
                let own = trunk_of(doc);
                let mut out: Vec<&Address> = Vec::new();
                for ShotRun { origin, .. } in runs {
                    if trunk_of(origin) != own && !out.contains(&origin) {
                        out.push(origin);
                    }
                }
                out
            }
            Op::Version { d_src, .. } => vec![d_src],
            Op::MakeLink { from, to, ty, .. } => {
                let mut out = Vec::new();
                push_resolve_sources(from, &mut out);
                push_resolve_sources(to, &mut out);
                push_resolve_sources(ty, &mut out);
                out
            }
            // The successor's three slots in declared order, each
            // contributing its `Resolve` sources and nothing in the two name
            // forms ([`SuccessorSpec`]).
            Op::EditLink { successor, .. } => {
                let mut out = Vec::new();
                push_resolve_sources(&successor.from, &mut out);
                push_resolve_sources(&successor.to, &mut out);
                push_resolve_sources(&successor.ty, &mut out);
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
            | Op::EffectiveOwner { .. }
            | Op::ReadLink { .. }
            | Op::FollowLink { .. }
            | Op::RetrieveV { .. }
            | Op::RetrieveI { .. }
            | Op::ContentFrontier { .. }
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
            | Op::CountVByHome { .. }
            | Op::FindLinksVHistory { .. }
            | Op::RetrieveEndsets { .. }
            | Op::Project { .. }
            | Op::DiscoverableFrom { .. }
            | Op::DeleteOrphans { .. }
            | Op::InClaims { .. }
            | Op::OutClaims { .. }
            | Op::DocMetadata { .. }
            | Op::EditionClaims { .. }
            | Op::UniversalGrants => Vec::new(),
        }
    }
}

// `Op`'s hand-written `Debug`, which renders an `Insert`'s values by count.
mod debug;

#[cfg(test)]
pub(crate) mod tests;
