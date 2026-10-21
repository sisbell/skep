//! What M10 requires of the engine that assembles it.
//!
//! That is the world it reads — [`FebeWorld`] and its two capabilities,
//! [`ReadableWorld`] and [`PublicationWorld`] — and the factory it writes
//! through, [`Stores`]. The engine implements the two capabilities and the
//! four store accessors for its `World`, which the blanket impl below then
//! makes a `FebeWorld`; the binary supplies the one `Stores`.

use skep_address::Address;
use skep_arrangement::{HasM5, Vstream};
use skep_content::HasContent;
use skep_kernel::{Attestation, Kernel, WorldState};
use skep_links::{HasLinks, LinkWriter, Visibility};
use skep_namespace::{HasM3, Namespace, PrincipalId};

use crate::response::EditionClaim;

/// *The* read predicate as a capability of M10's world (PUB-1.31, PUB-6.39).
///
/// M10 is generic over `W` and names no concrete `World`, so it reaches the
/// engine's derived predicate — published ∨ subtree ∨ grant — through this
/// one accessor.
///
/// `principal` is `None` for the guest (published alone). Implemented by the
/// engine's `World` (the exception set beside the grant fold). The struck
/// second form — handing readers the principal's account and grant set — is
/// deliberately absent: what threads down is this opaque `bool`, never the
/// sets behind it.
pub trait ReadableWorld {
    /// Returns whether `principal` may read `doc`, off this world.
    ///
    /// It is the world's own [`ReadPredicate`]: `readable(doc, principal)`
    /// off the world it is handed — the snapshot a read or the write door
    /// pins, or the working world a write's store hands its gate. `None` ⟹
    /// the guest (published documents only). Its whole contract — who asks it
    /// and how often, what it owes for an address no store has registered,
    /// the one departure the engine's `World` records, and where it is
    /// evaluated — is stated once, on [`ReadPredicate`].
    ///
    /// [`ReadPredicate`]: crate::ReadPredicate
    fn readable(&self, principal: Option<PrincipalId>, doc: &Address) -> bool;
}

/// The publication vocabulary as a capability of the world M10 reads.
///
/// It is classes whose membership is decided by a pinned type address, which
/// is the engine's knowledge and not this module's. Its own seam, beside
/// [`ReadableWorld`] rather than inside it, because the two answer unrelated
/// questions — one is the predicate the whole operation surface answers
/// through, these are class lookups each asked by one operation — and each
/// should be nameable by a consumer that wants only it. Two lookups: the
/// edition-claim class over a target, [`Op::EditionClaims`]'s input, and the
/// grant fold's live any-principal index (PUB-8.47),
/// [`Op::UniversalGrants`]'s.
///
/// [`Op::EditionClaims`]: crate::Op::EditionClaims
/// [`Op::UniversalGrants`]: crate::Op::UniversalGrants
pub trait PublicationWorld {
    /// Returns the audit-view edition-claim lookup over `target` (PUB-8.46).
    ///
    /// It is every link of the edition-claim class whose `to` slot overlaps
    /// `target`'s subtree, unsuperseded (no operative ⟦supersedes⟧ successor,
    /// PUB-6.32), whether or not retracted, in link-address order.
    ///
    /// The two slots are judged by different regimes, which is why one word
    /// cannot serve for both. The `to` slot matches by overlap against the
    /// subtree, which is wider than denotation: asking about a document
    /// yields the claims on it and on its versions, and a `to` slot spanning
    /// the subtree without denoting an address in it is still a row. That
    /// width is the containment the lookup is for. Class membership is the
    /// other way, by denotation: the type slot is address-denoting and every
    /// address it denotes lies under the pinned edition type by prefix, so a
    /// slot that merely overlaps the class range is no member. A caller
    /// sizing this answer therefore reads the overlap and not a denotation
    /// count.
    ///
    /// **Precondition.** `target` is a registered document. M10 checks it and
    /// answers `DocNotRegistered` otherwise, so an implementer may assume
    /// document tier — and needs to, since the `to` range is `target`'s whole
    /// subtree and nothing narrows it by level: an account-tier target would
    /// range over every document under it, and a node-tier one over the
    /// store.
    ///
    /// Unfiltered by principal: M10 applies the home rule (PUB-6.13) per row,
    /// through the request's read predicate — off the same snapshot, unless a
    /// supplied [`ReadPredicate`] answers in the world's place — so the world
    /// answers the class and the front door the class the caller reads. The
    /// engine composes M7's own audit reads for it (`match_links`, `succs`,
    /// `is_active`) and names no type-vocabulary semantics of its own beyond
    /// the pinned address.
    ///
    /// [`ReadPredicate`]: crate::ReadPredicate
    fn edition_claims(&self, target: &Address) -> Vec<EditionClaim>;

    /// Returns the live any-principal index (PUB-8.47, PUB-7.22).
    ///
    /// It is the grant fold's universal index as [`UniversalIndexRow`]s —
    /// every content prefix an admitted, unrevoked any-principal grant names,
    /// with the issuers who granted it — in prefix order, each issuer list in
    /// address order. The engine's `World::universal_grants`, cloned out of
    /// its borrow.
    ///
    /// The index, and never the answer set (RES-258): the world hands over the
    /// stored rows, and the front door serves the covered ones, narrowing
    /// every row to the prefix its issuer ω-owns, by ω over the row's prefix
    /// off the same snapshot ([`Op::UniversalGrants`] states the compare;
    /// RES-231, RES-264, RES-273, RES-298). So this seam answers in its own
    /// row type and a client is served another ([`UniversalGrant`]): the
    /// edition-claim lookup's rows are answer rows the front door *drops* per
    /// caller and never rewrites, while these are index rows it *transforms*,
    /// alike for every caller. Each row keeps the one obligation
    /// [`UniversalIndexRow`] states. No index is added and no read class:
    /// this is the fold's own index, enumerated once per bound principal's
    /// request and never for the guest's, and its bound is that index's own
    /// size (PUB-7.45). Principal-blind — the guest's empty answer is the
    /// front door's.
    ///
    /// [`Op::UniversalGrants`]: crate::Op::UniversalGrants
    /// [`UniversalGrant`]: crate::UniversalGrant
    fn universal_grant_index(&self) -> Vec<UniversalIndexRow>;
}

/// One stored row of the grant fold's live any-principal index (PUB-8.47).
///
/// It is a row as [`PublicationWorld::universal_grant_index`] hands it over
/// (PUB-7.22): a content prefix as the index keys it, and the issuers whose
/// index entries name it. Owned, so the seam carries no lifetime of the world
/// behind it: the narrowing takes the rows by value and moves each issuer
/// into the served row it lands in.
///
/// A row of the index, never of an answer (RES-258). Coverage is containment
/// ∩ the issuer's own documents (PUB-5.9), and the fold applies the ownership
/// half at its probe (`grant_exists`'s issuer compare, PUB-7.3) and never at
/// indexing, so a row is a superset of entitlement: it may list several
/// issuers, and an issuer may own nothing under the prefix. Handed to a
/// client as it stands, a stranger's record over a stranger's document would
/// render as a board-wide face (PUB-5.21's "must never"). The front door
/// narrows every row before a client sees one ([`Op::UniversalGrants`]
/// states the compare), and what it serves is the other row type,
/// [`UniversalGrant`] — so a row of this type has no way into a response.
///
/// **What an implementer owes.** The engine hands rows over in prefix order,
/// each issuer list in address order without a repeat — the fold's own shape
/// — and the narrowing relies on neither, grouping and ordering what it
/// serves for itself. It relies on one fact, and the served guarantee —
/// every issuer listed ω-owns the prefix beside it — rests on it: **every
/// issuer is a registered seat**, a prefix M3's principal registry holds, so
/// ω answers the issuer at its own address. The fold takes each issuer as ω
/// of a grant's home and the registry only grows, so the engine meets it by
/// construction; nothing on this side of the seam checks it. An issuer that
/// is no seat would be served at its own account wherever a stored prefix is
/// wider than it, as though it owned what ω gives to another seat.
///
/// [`Op::UniversalGrants`]: crate::Op::UniversalGrants
/// [`UniversalGrant`]: crate::UniversalGrant
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UniversalIndexRow {
    /// The content prefix as the index keys it.
    ///
    /// It is a document or an account address.
    pub content_prefix: Address,
    /// The issuers whose index entries name it.
    ///
    /// They come in address order, each a registered seat.
    pub issuers: Vec<Address>,
}

/// The world the front door dispatches over.
///
/// It is M2's fold contract plus every upstream accessor, since M10 reaches
/// all four store slices — the widest bound set in the engine, and M10's own
/// slice count is zero (Engine Composition Contract — no state, no record
/// variant, no fold). The two publication seams join the set:
/// [`ReadableWorld`], off which every read builds its per-request
/// `Fn(&Address) -> bool` unless a [`ReadPredicate`] is supplied, and
/// [`PublicationWorld`], which the edition-claim and any-principal reads ask
/// (PUB-8.47).
///
/// Named for the reason M6 names `RetrievalWorld` and M7 `LinkWorld`: one
/// word for the seam, so a consumer generic over the same world writes one
/// bound rather than every trait beneath it. Blanket-implemented, so an
/// engine that implements the accessors gets this for free; the record lift
/// each write path needs (`W::Record: From<M3Rec>` and its four siblings)
/// stays on the impl that requires it.
///
/// [`ReadPredicate`]: crate::ReadPredicate
pub trait FebeWorld:
    WorldState + HasM3 + HasM5 + HasLinks + HasContent + ReadableWorld + PublicationWorld
{
}
impl<
        W: WorldState + HasM3 + HasM5 + HasLinks + HasContent + ReadableWorld + PublicationWorld,
    > FebeWorld for W
{
}

/// The injected acquisition path for the three transact-driving store drivers.
///
/// Each is a store-driver handle (§Public interface). The binary/engine
/// builds the one production impl; M10 names only this trait and the
/// published handle *types*, acquiring a driver per-op. Reads, snapshots,
/// `current_seq`, and the latent composite go through [`Stores::kernel`]. The
/// one question a write asks of the factory before it acquires a driver —
/// whether the kernel still accepts writes — is [`Stores::is_poisoned`].
///
/// **An implementer supplies the kernel, and nothing else.** All three
/// drivers follow from it: `Namespace::new`, `Vstream::new` and
/// `LinkWriter::new` are each bound by `W: WorldState` alone — exactly this
/// trait's bound — and each handle holds the borrows it is handed and no
/// state, M7's taking the caller's visibility class beside the kernel, which
/// is already this method's parameter. So all three are given here rather
/// than transcribed identically into every impl, and so is the poison report,
/// which is the kernel's own answer.
///
/// **Precondition.** It is on the implementer: **[`Stores::kernel`] answers
/// with the same `Kernel<W>` on every call.** The signature does not force it
/// — it is called afresh per request, so an impl that opened a kernel per
/// call would compile — and every coordinate M10 reports rests on it:
/// `OperationSurface::log_position` and every read's `as_of` come from
/// `kernel()`, while the writes commit through the drivers this trait hands
/// out. Two kernels leave those coordinates describing different logs, each
/// store still committing before it acknowledges and the reported positions
/// not meaning what this module promises. The provided bodies, the drivers
/// and the poison report alike, are each built over `kernel()`, so an
/// implementer that supplies only the kernel cannot violate that half — which
/// is why the precondition is stated on the one method such an implementer
/// writes. An implementer that *overrides* one of them takes the obligation
/// back on, and owes the same single-kernel guarantee for whatever it
/// returns.
///
/// The design names the engine-facing store-driver constructors a required
/// upstream interface amendment (Conflicts resolved #6), and the crates
/// publish them — `Namespace::new(&Kernel<W>)`, `Vstream::new(&Kernel<W>)`,
/// and `LinkWriter::new(&Kernel<W>, &Visibility<W>)` — which is what lets the
/// three bodies live here. What the binary supplies is the kernel it
/// recovered through M2; M10 takes that injected for decoupling/testability
/// (an in-memory-kernel-backed `Stores` exercises the whole lifecycle with no
/// disk/recovery), not because the constructors are unreachable.
pub trait Stores<W: WorldState>: Send + Sync {
    /// Returns the kernel (M2).
    ///
    /// It serves reads, snapshots, `current_seq` and the latent composite
    /// `transact`.
    fn kernel(&self) -> &Kernel<W>;
    /// Returns whether this factory's kernel has halted its write paths.
    ///
    /// It is M2's [`Kernel::is_poisoned`] for the kernel behind these
    /// drivers. `OperationSurface::execute` asks this at step (c), before any
    /// write reaches a driver. M2's word for the answer holds here: a `true`
    /// is actionable without a race, and a `false` may age, the refusal
    /// `transact` returns staying authoritative. The answer being the
    /// kernel's, the poison gate it serves holds whichever writer poisoned
    /// the kernel — M10's own, M9's rule fires, or a transport's writer of
    /// its own.
    ///
    /// Provided over `kernel()`, as the drivers are, and an implementer that
    /// overrides it owes M2's answer for that same kernel. The one exception
    /// is a test's: M2 offers no way to poison an in-memory kernel, so a test
    /// overrides this to stand a write in front of a poisoned one.
    fn is_poisoned(&self) -> bool {
        self.kernel().is_poisoned()
    }
    /// Returns the M3 driver, which borrows the held kernel for the call.
    fn namespace(&self) -> Namespace<'_, W> {
        Namespace::new(self.kernel())
    }
    /// Returns the attested M3 driver (signed ops).
    ///
    /// It is [`Stores::namespace`] with the attestation beside the kernel,
    /// built by `Namespace::attested`, whose signed transactions M3 states
    /// there: the two document mints, a mint born published being a
    /// publish-class act. The same producer-set discipline as
    /// [`Stores::vstream_attested`]; `None` is [`Stores::namespace`] exactly.
    fn namespace_attested<'a>(&'a self, attest: Option<&'a Attestation>) -> Namespace<'a, W> {
        Namespace::attested(self.kernel(), attest)
    }
    /// Returns the M5 driver, which borrows the held kernel for the call.
    fn vstream(&self) -> Vstream<'_, W> {
        Vstream::new(self.kernel())
    }
    /// Returns the M7 driver at the caller's visibility class (PUB-6.25).
    ///
    /// It borrows the held kernel for the call. M10 builds `visibility` per
    /// link write from the session's principal — `readable(doc, principal)`
    /// — and M7 applies it inside the write transaction, to the working
    /// world, at link-home identity, so its idempotency and dedup lookups see
    /// only the incumbents this principal could read.
    fn linkstore<'a>(&'a self, visibility: &'a Visibility<'a, W>) -> LinkWriter<'a, W> {
        LinkWriter::new(self.kernel(), visibility)
    }
    /// Returns the attested M5 driver (signed ops).
    ///
    /// The attestation rides the driver handle: a `Vstream` built by
    /// `Vstream::attested` — the transactions it signs are M5's to state
    /// there, and it fills no signature slot outside them. A handle serves
    /// exactly one call, which is exactly one transaction, so the value can
    /// neither outlive the arm (a borrow) nor reach a second commit. `None` is
    /// [`Stores::vstream`] exactly.
    ///
    /// **Who calls this.** Its callers are the signature slot's producer set
    /// (the design record §5.5): M10's `dispatch_write`, with a value the
    /// daemon's check admitted, and no other writer — the head writer builds
    /// through `vstream` and M9 through `Vstream::new`, and every plain handle
    /// passes `None` by construction.
    fn vstream_attested<'a>(&'a self, attest: Option<&'a Attestation>) -> Vstream<'a, W> {
        Vstream::attested(self.kernel(), attest)
    }
    /// Returns the attested M7 driver.
    ///
    /// It is [`Stores::linkstore`] with the attestation beside the visibility
    /// class, built by `LinkWriter::attested`, whose signed transactions M7
    /// states there; the same producer-set discipline as
    /// [`Stores::vstream_attested`].
    fn linkstore_attested<'a>(
        &'a self,
        visibility: &'a Visibility<'a, W>,
        attest: Option<&'a Attestation>,
    ) -> LinkWriter<'a, W> {
        LinkWriter::attested(self.kernel(), visibility, attest)
    }
}
