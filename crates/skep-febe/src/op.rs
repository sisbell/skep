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

/// One parsed FEBE request: an optional client idempotency key plus the
/// operation. `id` is used ONLY as the per-session idempotency key
/// (§1(a)/§7); it is never echoed on the response path (§8).
pub struct Request {
    /// Client idempotency key (optional; client-unique within its session).
    pub id: Option<ReqId>,
    /// The parsed operation.
    pub op: Op,
}

/// The client-supplied idempotency key — client-unique within its session
/// (§7). Half of the `(SessionId, ReqId)` cache key.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ReqId(pub Vec<u8>);

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
    /// provisioning, not minted; still requires a bound session (§6).
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
    /// INSERT (ASN-0116). `Val` is M4's — the type-only M10→M4 edge.
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
/// rejection, and `idem_get` can match it (§7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
    //
    // The two-arm shape is load-bearing (compile-time non-exhaustiveness on a
    // new variant), so the `matches!` rewrite clippy suggests is refused.
    #[allow(clippy::match_like_matches_macro)]
    pub(crate) fn is_read(&self) -> bool {
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

    pub(crate) fn is_write(&self) -> bool {
        !self.is_read()
    }

    /// The fieldless echo — never yields [`OpKind::Unparseable`].
    pub(crate) fn kind(&self) -> OpKind {
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
mod tests {
    use super::*;
    use skep_address::{validate, Nat, Span, Tumbler};
    use skep_discovery::SlotSpec;

    fn t(comps: &[u32]) -> Tumbler {
        Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")
    }
    fn a(comps: &[u32]) -> Address {
        validate(t(comps)).unwrap_or_else(|_| panic!("T4-valid test address"))
    }
    fn sp() -> Span {
        Span::new(t(&[1, 1]), t(&[0, 1])).unwrap_or_else(|_| panic!("well-formed test span"))
    }
    fn vp() -> VPos {
        VPos { subspace: Nat::from(1u32), ordinal: Nat::from(1u32) }
    }
    fn vs() -> VSpec {
        VSpec { source: a(&[1, 0, 1, 0, 1]), span: sp() }
    }
    fn q() -> FourSet {
        FourSet { home: SlotSpec::Any, from: SlotSpec::Any, to: SlotSpec::Any, ty: SlotSpec::Any }
    }
    fn d() -> Address {
        a(&[1, 0, 1, 0, 1])
    }

    /// Every variant, paired with its documented partition side (§1's
    /// `is_read` grouping): `(op, is_read)`.
    fn all_ops() -> Vec<(Op, bool)> {
        vec![
            (Op::CreateNewDocument { account: a(&[1, 0, 1]) }, false),
            (Op::Delegate { new_prefix: t(&[1, 0, 1]), new_id: PrincipalId(1) }, false),
            (Op::RegisterNode { addr: t(&[1, 1]) }, false),
            (Op::Fork, false),
            (Op::NextAccountPrefix { parent: a(&[1]) }, true),
            (Op::PrincipalPrefix { id: PrincipalId(1) }, true),
            (Op::Insert { doc: d(), at: vp(), values: vec![Val::new(vec![1u8])] }, false),
            (Op::Delete { doc: d(), p: vp(), width: Nat::from(1u32) }, false),
            (Op::Copy { doc: d(), at: vp(), specs: vec![vs()] }, false),
            (Op::Rearrange { doc: d(), cuts: vec![vp()] }, false),
            (Op::Version { d_src: d() }, false),
            (
                Op::MakeLink {
                    home: d(),
                    from: SlotArg::Resolve(vec![vs()]),
                    to: SlotArg::Addrs(vec![d()]),
                    ty: SlotArg::Resolve(vec![vs()]),
                },
                false,
            ),
            (Op::Emit { home: d(), ty: Endset::empty(), from: d(), to: vec![] }, false),
            (Op::Nullify { home: d(), target: d() }, false),
            (Op::AssertSup { home: d(), old: d(), new: d() }, false),
            (
                Op::EditLink {
                    original: d(),
                    successor: SuccessorSpec { from: vec![vs()], to: vec![vs()], ty: SlotArg::Addrs(vec![d()]) },
                    d_s: d(),
                    d_a: d(),
                },
                false,
            ),
            (Op::ReadLink { a: d() }, true),
            (Op::FollowLink { a: d(), slot: 1 }, true),
            (Op::RetrieveV { specs: vec![Spec { doc: d(), span: sp() }] }, true),
            (Op::RetrieveDocVSpan { doc: d() }, true),
            (Op::RetrieveDocVSpanSet { doc: d() }, true),
            (Op::ShowOrigin { doc: d(), span: sp() }, true),
            (Op::ShowDeletions { d_a: d(), d_b: d() }, true),
            (Op::Compare { rho1: vec![], rho2: vec![] }, true),
            (Op::FindDocsContaining { regions: vec![Region { doc: d(), spans: vec![sp()] }] }, true),
            (Op::Image { d: d(), region: vec![sp()] }, true),
            (Op::FindLinksV { d: d(), region: vec![sp()] }, true),
            (Op::FindLinksFtt { q: q() }, true),
            (Op::CountV { d: d(), region: vec![sp()] }, true),
            (Op::CountFtt { q: q() }, true),
            (Op::WindowV { d: d(), region: vec![sp()], cur: None, n: 1 }, true),
            (Op::WindowFtt { q: q(), cur: None, n: 1 }, true),
            (Op::RetrieveEndsets { d: d(), region: vec![sp()] }, true),
            (Op::Project { a: d(), slot: 1, d: d() }, true),
            (Op::DiscoverableFrom { a: d(), d: d() }, true),
            (Op::DeleteOrphans { d: d(), p: vp(), width: Nat::from(1u32) }, true),
            (Op::InClaims { y: d(), view: View::Active }, true),
            (Op::OutClaims { x: d(), view: View::Active }, true),
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
    /// `Unparseable`.
    #[test]
    fn kind_is_injective_and_never_unparseable() {
        let kinds: Vec<OpKind> = all_ops().iter().map(|(op, _)| op.kind()).collect();
        for k in &kinds {
            assert_ne!(*k, OpKind::Unparseable);
        }
        for (i, ka) in kinds.iter().enumerate() {
            for kb in &kinds[i + 1..] {
                assert_ne!(*ka, *kb);
            }
        }
    }
}
