//! What M10 requires of the engine that assembles it: the world it reads —
//! [`FebeWorld`] and its two capabilities, [`ReadableWorld`] and
//! [`PublicationWorld`] — and the factory it writes through, [`Stores`].
//! The engine implements the two capabilities and the four store accessors
//! for its `World`, which the blanket impl below then makes a `FebeWorld`;
//! the binary supplies the one `Stores`.

use skep_address::Address;
use skep_arrangement::{HasM5, Vstream};
use skep_content::HasContent;
use skep_kernel::{Attestation, Kernel, WorldState};
use skep_links::{HasLinks, LinkWriter, Visibility};
use skep_namespace::{HasM3, Namespace, PrincipalId};

use crate::response::EditionClaim;

/// THE read predicate as a capability of the world M10 reads (PUB round 2,
/// lane 3.3, §1; PUB-1.31, PUB-6.39). M10 is generic over `W` and names no
/// concrete `World`, so it reaches the engine's derived predicate — published ∨
/// subtree ∨ grant — through this one accessor, off M10's OWN read snapshot, so
/// the answer and the `as_of` it is stamped with stand on one committed state.
///
/// `principal` is `None` for the GUEST (published alone). Implemented by the
/// engine's `World` (the exception set beside the grant fold). A write
/// reaches this same predicate as the VISIBILITY CLASS M10 lends a store for
/// one write; a front door that supplies a [`ReadPredicate`] — the historical
/// door — answers through that instead, on both paths.
/// The STRUCK second form — handing readers the principal's account and grant
/// set — is deliberately absent: what threads down is this opaque `bool`, never
/// the sets behind it.
///
/// [`ReadPredicate`]: crate::ReadPredicate
pub trait ReadableWorld {
    /// `readable(doc, principal)` — the one predicate every read surface
    /// answers through. `None` ⟹ the guest (published documents only).
    ///
    /// TOTAL, over addresses of any tier and whether or not the store has
    /// registered them: M10's doc-argument consult walks a request's NAMED
    /// documents before any registration check, and the link-address rule
    /// asks about a home DERIVED by address arithmetic (PUB-6.38), which no
    /// store need have registered. An UNREGISTERED address must answer
    /// READABLE — PUB-7.5's fail-open sign, the exception set holding the
    /// unpublished side so a membership miss is the published fast path — so
    /// that each read arm's own `*NotRegistered` speaks and a WITHHELD answer
    /// is only ever a registered private document (PUB-6.12). A predicate
    /// that refuses defensively for an address it cannot resolve inverts
    /// that guarantee and tells a prober that a nonexistent address
    /// exists-but-is-hidden.
    fn readable(&self, principal: Option<PrincipalId>, doc: &Address) -> bool;
}

/// The publication VOCABULARY as a capability of the world M10 reads (PUB
/// round 2, lane 3.4 §2): classes whose membership is decided by a pinned
/// type address, which is the engine's knowledge and not this module's. Its
/// own seam, beside [`ReadableWorld`] rather than inside it, because the two
/// answer unrelated questions — one is a predicate consulted by the whole
/// operation surface, these are class lookups each consulted by one
/// operation — and each should be nameable by a consumer that wants only it.
/// Two lookups: the edition-claim class over a target, [`Op::EditionClaims`]'s
/// input, and the grant fold's live ANY-PRINCIPAL index (PUB-8.47),
/// [`Op::UniversalGrants`]'s.
///
/// [`Op::EditionClaims`]: crate::Op::EditionClaims
/// [`Op::UniversalGrants`]: crate::Op::UniversalGrants
pub trait PublicationWorld {
    /// The audit-view edition-claim lookup (PUB-8.46; PUB round 2, lane 3.4
    /// §2): every link of the edition-claim class whose `to` slot OVERLAPS
    /// `target`'s subtree, UNSUPERSEDED (no operative ⟦supersedes⟧
    /// successor, PUB-6.32), WHETHER OR NOT RETRACTED, in link-address
    /// order.
    ///
    /// THE TWO SLOTS ARE JUDGED BY DIFFERENT REGIMES, which is why one word
    /// cannot serve for both. The `to` slot matches by OVERLAP against the
    /// subtree, which is WIDER than denotation: asking about a document
    /// yields the claims on it AND on its versions, and a `to` slot spanning
    /// the subtree without denoting an address in it is still a row. That
    /// width is the containment the lookup is for. Class MEMBERSHIP is the
    /// other way, by DENOTATION: the type slot is address-denoting and every
    /// address it denotes lies under the pinned edition type by prefix, so a
    /// slot that merely overlaps the class range is no member. A caller
    /// sizing this answer therefore reads the overlap and not a denotation
    /// count.
    ///
    /// PRECONDITION: `target` is a REGISTERED DOCUMENT. M10 checks it and
    /// answers `DocNotRegistered` otherwise, so an implementer may assume
    /// document tier — and needs to, since the `to` range is `target`'s whole
    /// subtree and nothing narrows it by level: an account-tier target would
    /// range over every document under it, and a node-tier one over the
    /// store.
    ///
    /// UNFILTERED by principal: M10 applies the home rule (PUB-6.13) per row
    /// off the same snapshot, so the world answers the class and the front
    /// door the class the caller reads. The engine composes M7's own audit
    /// reads for it (`match_links`, `succs`, `is_active`) and names no
    /// type-vocabulary semantics of its own beyond the pinned address.
    fn edition_claims(&self, target: &Address) -> Vec<EditionClaim>;

    /// THE LIVE ANY-PRINCIPAL INDEX (PUB-8.47, PUB-7.22): the grant fold's
    /// universal index as [`UniversalIndexRow`]s — every content prefix an
    /// admitted, unrevoked ANY-PRINCIPAL grant names, with the issuers who
    /// granted it — in prefix order, each issuer list in address order. The
    /// engine's `World::universal_grants`, cloned out of its borrow.
    ///
    /// The INDEX, and never the answer set (RES-258): the world hands over the
    /// STORED rows, and the front door serves the COVERED ones, narrowing
    /// every row to the prefix its issuer ω-owns, by ω over the row's prefix
    /// off the same snapshot ([`Op::UniversalGrants`] states the compare;
    /// RES-231, RES-264, RES-273, RES-298). So this seam answers in its own
    /// row type and a client is served another ([`UniversalGrant`]): the
    /// edition-claim lookup's rows are answer rows the front door DROPS per
    /// caller and never rewrites, while these are index rows it TRANSFORMS,
    /// alike for every caller. Each row keeps the one obligation
    /// [`UniversalIndexRow`] states. No index is added and no read class:
    /// this is the fold's own slot, enumerated once per request, and its
    /// bound is that index's own size (PUB-7.45). Principal-blind — the
    /// guest's empty answer is the front door's.
    ///
    /// [`Op::UniversalGrants`]: crate::Op::UniversalGrants
    /// [`UniversalGrant`]: crate::UniversalGrant
    fn universal_grant_index(&self) -> Vec<UniversalIndexRow>;
}

/// One STORED row of the grant fold's live ANY-PRINCIPAL index, as
/// [`PublicationWorld::universal_grant_index`] hands it over (PUB-8.47,
/// PUB-7.22): a content prefix as the index keys it, and the issuers whose
/// index entries name it. OWNED, so the seam carries no lifetime of the world
/// behind it: the narrowing takes the rows by value and moves each issuer
/// into the served row it lands in.
///
/// A row of the INDEX, never of an answer (RES-258). Coverage is containment
/// ∩ the issuer's own documents (PUB-5.9), and the fold applies the ownership
/// half at its probe (`grant_exists`'s issuer compare, PUB-7.3) and never at
/// indexing, so a row is a SUPERSET of entitlement: it may list several
/// issuers, and an issuer may own nothing under the prefix. Handed to a
/// client as it stands, a stranger's record over a stranger's document would
/// render as a board-wide face (PUB-5.21's MUST NEVER). The front door
/// narrows every row before a client sees one ([`Op::UniversalGrants`]
/// states the compare), and what it serves is the other row type,
/// [`UniversalGrant`] — so a row of this type has no way into a response.
///
/// WHAT AN IMPLEMENTER OWES. The engine hands rows over in prefix order, each
/// issuer list in address order without a repeat — the fold's own shape —
/// and the narrowing relies on neither, grouping and ordering what it serves
/// for itself. It relies on ONE fact, and the served guarantee — every issuer
/// listed ω-owns the prefix beside it — rests on it: **every issuer is a
/// registered seat**, a prefix M3's principal registry holds, so ω answers
/// the issuer at its own address. The fold takes each issuer as ω of a
/// grant's home and the registry only grows, so the engine meets it by
/// construction; nothing on this side of the seam checks it. An issuer that
/// is no seat would be served at its own account wherever a stored prefix is
/// wider than it, as though it owned what ω gives to another seat.
///
/// [`Op::UniversalGrants`]: crate::Op::UniversalGrants
/// [`UniversalGrant`]: crate::UniversalGrant
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UniversalIndexRow {
    /// The content prefix as the index keys it — a document or an account
    /// address.
    pub content_prefix: Address,
    /// The issuers whose index entries name it, in address order, each a
    /// registered seat.
    pub issuers: Vec<Address>,
}

/// The world the front door dispatches over: M2's fold contract plus every
/// upstream accessor, since M10 reaches all four store slices — the widest
/// bound set in the engine, and M10's own slice count is zero (Engine
/// Composition Contract — no state, no record variant, no fold). The two
/// publication seams join the set for PUB round 2: [`ReadableWorld`], off
/// which every read builds its per-request `Fn(&Address) -> bool` (lane
/// 3.3), and [`PublicationWorld`], which the edition-claim and any-principal
/// reads ask (lane 3.4, PUB-8.47).
///
/// Named for the reason M6 names `RetrievalWorld` and M7 `LinkWorld`: one word for
/// the seam, so a consumer generic over the same world writes one bound
/// rather than six. Blanket-implemented, so an engine that implements the
/// accessors gets this for free; the record lift each write path needs
/// (`W::Record: From<M3Rec>` and its three siblings) stays on the impl that
/// requires it.
pub trait FebeWorld:
    WorldState + HasM3 + HasM5 + HasLinks + HasContent + ReadableWorld + PublicationWorld
{
}
impl<
        W: WorldState + HasM3 + HasM5 + HasLinks + HasContent + ReadableWorld + PublicationWorld,
    > FebeWorld for W
{
}

/// The injected acquisition path for the three transact-driving store-driver
/// handles (§Public interface). The binary/engine builds the one production
/// impl; M10 names only this trait and the published handle *types*, acquiring
/// a driver per-op. Reads, snapshots, `current_seq`, and the latent composite
/// go through [`Stores::kernel`].
///
/// **An implementer supplies the kernel, and nothing else.** All three
/// drivers follow from it: `Namespace::new`, `Vstream::new` and
/// `LinkWriter::new` are each bound by `W: WorldState` alone — exactly this
/// trait's bound — and each handle holds the borrows it is handed and no
/// state, M7's taking the caller's VISIBILITY class beside the kernel, which
/// is already this method's parameter. So all three are given here rather
/// than transcribed identically into every impl.
///
/// PRECONDITION on the implementer: **[`Stores::kernel`] answers with the
/// same `Kernel<W>` on every call.** The signature does not force it — it is
/// consulted afresh per request, so an impl that opened a kernel per call
/// would compile — and every coordinate M10 reports rests on it:
/// `OperationSurface::log_position` and every read's `as_of` come from
/// `kernel()`, while the link writes commit through `linkstore()`. Two kernels
/// leave those coordinates describing different logs, each store still
/// committing before it acknowledges and the reported positions no longer
/// meaning what this module promises. The three provided bodies are each
/// built over `kernel()`, so an implementer that supplies only the kernel
/// cannot violate that half — which is why the precondition is stated on the
/// one method such an implementer writes. An implementer that OVERRIDES one
/// of the three takes the obligation back on, and owes the same single-kernel
/// guarantee for whatever driver it returns.
///
/// The design flagged the engine-facing store-driver constructors as a
/// required upstream interface amendment (Conflicts resolved #6); the as-built
/// crates already publish them — `Namespace::new(&Kernel<W>)`,
/// `Vstream::new(&Kernel<W>)`, and `LinkWriter::new(&Kernel<W>,
/// &Visibility<W>)` — which is what lets the three bodies live here. What the
/// binary supplies is the kernel it recovered through M2; M10 takes that
/// INJECTED for decoupling/testability (an in-memory-kernel-backed `Stores`
/// exercises the whole lifecycle with no disk/recovery), not because the
/// constructors are unreachable.
pub trait Stores<W: WorldState>: Send + Sync {
    /// M2 — reads/snapshots/`current_seq`/the latent composite `transact`.
    fn kernel(&self) -> &Kernel<W>;
    /// M3 driver — borrows the held kernel for the call.
    fn namespace(&self) -> Namespace<'_, W> {
        Namespace::new(self.kernel())
    }
    /// M5 driver — borrows the held kernel for the call.
    fn vstream(&self) -> Vstream<'_, W> {
        Vstream::new(self.kernel())
    }
    /// M7 driver — borrows the held kernel for the call, at the caller's
    /// VISIBILITY class (lane 3.3b, PUB-6.25): M10 builds `visibility` per
    /// link write from the session's principal — `readable(doc, principal)`
    /// — and M7 applies it INSIDE the write transaction, to the working
    /// world, at link-home identity, so its idempotency and dedup lookups see
    /// only the incumbents this principal could read.
    fn linkstore<'a>(&'a self, visibility: &'a Visibility<'a, W>) -> LinkWriter<'a, W> {
        LinkWriter::new(self.kernel(), visibility)
    }
    /// THE ATTESTED M5 DRIVER (signed ops; the placement the owner confirmed
    /// 2026-09-25: the attestation rides the DRIVER HANDLE): a `Vstream` that
    /// hands `attest` to the kernel's `transact_attested` arm at the one
    /// transaction its publish-class-capable calls of this slice open —
    /// `insert`, `publish` — filling that transaction's commit marker slot and
    /// no other's. A handle serves exactly one call, which is exactly one
    /// transaction, so the value can neither outlive the arm (a borrow) nor
    /// reach a second commit. `None` is [`Stores::vstream`] exactly. WHO CALLS
    /// THIS is the slot's producer set (the design record §5.5): M10's
    /// `dispatch_write`, with a value the daemon's check admitted, and no
    /// other writer — the head writer, M9 and every plain handle build
    /// through `vstream`, and pass `None` by construction.
    fn vstream_attested<'a>(&'a self, attest: Option<&'a Attestation>) -> Vstream<'a, W> {
        Vstream::attested(self.kernel(), attest)
    }
    /// THE ATTESTED M7 DRIVER — [`Stores::linkstore`] with the attestation
    /// beside the visibility class, handed to `transact_attested` at
    /// `makelink`'s one transaction (the slice's link write); the same
    /// producer-set discipline as [`Stores::vstream_attested`].
    fn linkstore_attested<'a>(
        &'a self,
        visibility: &'a Visibility<'a, W>,
        attest: Option<&'a Attestation>,
    ) -> LinkWriter<'a, W> {
        LinkWriter::attested(self.kernel(), visibility, attest)
    }
}
