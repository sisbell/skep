//! The parsed request model: [`Request`]/[`ReqId`], the [`Op`] enum (one
//! variant per FEBE operation), the [`OpKind`] fieldless echo, and the
//! read/write partition the lifecycle gates on (§1).

use skep_address::{Address, Nat, Span, Tumbler};
use skep_arrangement::{VPos, VSpec};
use skep_content::Val;
use skep_discovery::{Cursor, FourSet};
use skep_links::{Endset, SlotArg, View};
use skep_namespace::PrincipalId;
use skep_retrieval::{Region, Spec};

/// One parsed FEBE request: an optional idempotency key plus the operation.
/// `id` is used ONLY to key the retry memo (§1(a)/§7); it is never echoed on
/// the response path (§8).
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
pub enum Op {
    // ── namespace writes (→ M3) ──
    /// CREATENEWDOCUMENT (ASN-0103): baptize a fresh empty document.
    CreateNewDocument { account: Address },
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
    Fork,
    // ── namespace reads (→ M3) ──
    /// M3's next-form delegable prefix — what [`Op::Delegate`] demands (§2).
    NextAccountPrefix { parent: Address },
    /// Any principal's (public, immutable) account Address — what
    /// [`Op::CreateNewDocument`] demands. Deliberately an explicit wire id,
    /// not the session principal (§2).
    PrincipalPrefix { id: PrincipalId },
    // ── arrangement writes (→ M5) ──
    /// INSERT (ASN-0116). `Val` is M4's, carried in the payload verbatim —
    /// M10 names M4's types and calls no M4 function.
    Insert { doc: Address, at: VPos, values: Vec<Val> },
    /// DELETE (ASN-0117).
    Delete { doc: Address, p: VPos, width: Nat },
    /// COPY / transclusion (ASN-0118).
    Copy { doc: Address, at: VPos, specs: Vec<VSpec> },
    /// REARRANGE (pivot/swap).
    Rearrange { doc: Address, cuts: Vec<VPos> },
    /// CREATENEWVERSION (ASN-0123) — the content-sharing, copy-on-write fork.
    Version { d_src: Address },
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
    Compare { rho1: Vec<Region>, rho2: Vec<Region> },
    /// FINDDOCSCONTAINING (ASN-0124).
    FindDocsContaining { regions: Vec<Region> },
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
pub struct SuccessorSpec {
    pub from: Vec<VSpec>,
    pub to: Vec<VSpec>,
    pub ty: SlotArg,
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
    Insert,
    Delete,
    Copy,
    Rearrange,
    Version,
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
            | Op::OutClaims { .. } => true,
            Op::CreateNewDocument { .. }
            | Op::Delegate { .. }
            | Op::RegisterNode { .. }
            | Op::Fork
            | Op::Insert { .. }
            | Op::Delete { .. }
            | Op::Copy { .. }
            | Op::Rearrange { .. }
            | Op::Version { .. }
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
            Op::Fork => OpKind::Fork,
            Op::NextAccountPrefix { .. } => OpKind::NextAccountPrefix,
            Op::PrincipalPrefix { .. } => OpKind::PrincipalPrefix,
            Op::Insert { .. } => OpKind::Insert,
            Op::Delete { .. } => OpKind::Delete,
            Op::Copy { .. } => OpKind::Copy,
            Op::Rearrange { .. } => OpKind::Rearrange,
            Op::Version { .. } => OpKind::Version,
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
            (Op::CreateNewDocument { account: addr(&[1, 0, 1]) }, false),
            (Op::Delegate { new_prefix: tum(&[1, 0, 1]), new_id: PrincipalId(1) }, false),
            (Op::RegisterNode { addr: tum(&[1, 1]) }, false),
            (Op::Fork, false),
            (Op::NextAccountPrefix { parent: addr(&[1]) }, true),
            (Op::PrincipalPrefix { id: PrincipalId(1) }, true),
            (Op::Insert { doc: doc(), at: vpos(), values: vec![Val::new(vec![1u8])] }, false),
            (Op::Delete { doc: doc(), p: vpos(), width: Nat::from(1u32) }, false),
            (Op::Copy { doc: doc(), at: vpos(), specs: vec![vs()] }, false),
            (Op::Rearrange { doc: doc(), cuts: vec![vpos()] }, false),
            (Op::Version { d_src: doc() }, false),
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
            (Op::Compare { rho1: vec![], rho2: vec![] }, true),
            (Op::FindDocsContaining { regions: vec![Region { doc: doc(), spans: vec![sp()] }] }, true),
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
        ]
    }

    /// §1: the read/write partition is exhaustive and two-sided
    /// (`is_write == !is_read`), with 24 reads and 14 writes.
    #[test]
    fn partition_matches_the_design_grouping() {
        let ops = all_ops();
        assert_eq!(ops.len(), 38);
        let reads = ops.iter().filter(|(_, r)| *r).count();
        assert_eq!(reads, 24);
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
        assert_eq!(seen.len(), 38);
    }
}
