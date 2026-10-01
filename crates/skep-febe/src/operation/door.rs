//! The READABILITY DOOR: the one read predicate a front door answers through
//! — its world's own or a supplied [`ReadPredicate`], bound once per request
//! by [`OperationSurface::readable_by`] — the two consults it drives
//! ([`consult_read`], [`OperationSurface::consult_write`]), the link-address
//! absence rule ([`home_readable`]), the visibility class lent to a store for
//! one write ([`OperationSurface::visible_to`]), and the three per-variant
//! tables only the write consult asks, [`Op::write_consult`],
//! [`Op::in_place_destination`] and [`Op::link_address_arguments`], defined
//! here so nothing else can ask them.
//!
//! `OperationSurface::readable`, where a supplied predicate overrides the
//! world's own, is private to this module, so the compiler keeps every other
//! file from calling it by name. Everything else — the two dispatch tables,
//! and through them every masking reader in M6 and M8 — reaches the
//! predicate through `readable_by` or `visible_to`. The world's own predicate
//! cannot be fenced the same way: `ReadableWorld::readable` is a supertrait
//! method of `FebeWorld`, callable on any `W` with no import, so a read arm
//! that asked it would compile and answer through the world where a supplied
//! predicate should have answered. `tests/it/tidy.rs` checks that no file but
//! this one asks it.
//!
//! The door is a child of the lifecycle rather than a card beside it because
//! the two share the proven-bound principal: `consult_write` rides the
//! lifecycle's [`WriteCtx`], which a child sees without widening, and binds
//! its predicate from that principal and from nothing else.

use skep_address::{document_of, Address};
use skep_arrangement::published_target;
use skep_namespace::PrincipalId;

use super::{OperationSurface, WriteCtx};
use crate::op::Op;
use crate::reject::{rejection, FaultSite, RejectCode, Rejection};
use crate::successor::Judgment;
use crate::world::FebeWorld;

/// THE READ PREDICATE (PUB-1.31; PUB-6.39's one-per-request shape; PUB round
/// 2, lane 3.3): may `principal` (`None` = the GUEST) read the document `doc`?
/// A front door answers the world's own, [`ReadableWorld::readable`], unless
/// the transport supplies this closure in its place
/// ([`OperationSurface::with_read_predicate`]). Whichever answers owes
/// everything below, and this is the one place it is stated.
///
/// WHO ASKS IT, AND HOW OFTEN. The door's two consults and its link-address
/// rule ask once per NAMED argument of the request, a count the transport's
/// parser caps. The readers that mask below the door — M6's per-run withheld
/// arm and container filter, M8's result-set filters, the edition-claim home
/// rule — ask once per RESULT ROW: a count set by stored state, capped by
/// nothing, and reached by an unauthenticated guest through the FTT descriptor
/// family, which names no document at all and whose unconstrained form matches
/// every active link in the store. M10 creates that second class, by threading
/// this one predicate down into the readers, so a supplier sizing its own work
/// against a per-argument figure has priced only the first. And lent as a
/// write's VISIBILITY CLASS it is asked by every gate a store runs inside its
/// own transaction: M5's per-origin source gate on the shot (PUB-6.23,
/// PUB-8.1's second constraint) and M7's value-keyed gates on the five link
/// writes (PUB-6.25).
///
/// OBLIGATIONS ON THE ANSWER. It is asked about addresses of any tier,
/// REGISTERED OR NOT: the doc-argument consult walks the request's NAMED
/// documents before any registration check, and the link-address rule asks
/// it of a home DERIVED by address arithmetic (PUB-6.38), which no store
/// need have registered. So it must be TOTAL, and it must answer READABLE
/// for an address the store has not registered — PUB-7.5's fail-open sign,
/// the exception set holding the unpublished side so a membership miss is
/// the published fast path. That is what leaves each arm's own
/// `*NotRegistered` to speak, and what makes a WITHHELD answer only ever a
/// REGISTERED PRIVATE document (PUB-6.12). A predicate that refuses
/// defensively for an address it cannot resolve inverts that guarantee and
/// tells a prober that a nonexistent address exists-but-is-hidden. M6's
/// per-run arm and M5's publish gate check registration before asking, as
/// their own behaviour and not as a guarantee from here.
///
/// ONE DEPARTURE IS ON RECORD. The engine's predicate meets those obligations
/// for every unregistered address but one shape, and so does any supplied
/// closure built over the engine's world, the daemon's historical door's among
/// them: an address shaped as a VERSION MEMBER of a registered draft reads as
/// that draft (PUB-2.15) and is withheld wherever the draft is, though no mint
/// produced it. The engine records it on its impl of [`ReadableWorld`]. Which
/// of PUB-2.15 and PUB-6.12 governs that shape is PUB's to rule; until it
/// does, a `Withheld` naming such an address names one no store registered.
///
/// ABSENT ([`OperationSurface::new`] alone), the world's own answers, which is
/// the live daemon's case: off the ONE snapshot a read pins, so the answer and
/// the `as_of` it is stamped with stand on one committed state, and, as a
/// write's visibility class, off the working world of that write's own
/// transaction, which its store — M5 on the shot, M7 on the link writes —
/// hands it. SUPPLIED, this closure OVERRIDES the world it would be evaluated
/// over — what a HISTORICAL read needs: `/op-at N` answers the N-world's
/// content through the HEAD's exception set and grant set (PUB-6.48), so the
/// daemon's throwaway front door over the reconstructed world answers through
/// a predicate closed over one head snapshot. `Send + Sync + 'static`, since
/// the front door is shared across a transport's worker pool.
///
/// WHERE IT IS EVALUATED, and what that position costs the supplier. On a
/// READ it answers off the snapshot the request pinned, and the caller waits
/// alone. On a WRITE it is lent to the store as the caller's VISIBILITY CLASS
/// ([`OperationSurface::visible_to`]) and evaluated INSIDE that store's
/// transaction — M5's publish source gate, M7's value-keyed gates on the five
/// link writes — under M2's applier lock. So it inherits `transact`'s
/// precondition, which M5 states for the parameter M10 fills here and which
/// M10 can no more check than M5 can: it MUST NOT call `transact` on that
/// kernel (M2 answers a nested write with its reentrancy panic, the
/// supplier's bug), and every other writer in the engine waits while it
/// answers. A predicate that resolves its grants by asking the engine is the
/// shape that trips both; one closed over a snapshot it already holds, as the
/// daemon's historical door is, trips neither.
///
/// This is the PREDICATE a door consults, never the act of consulting it:
/// `consult_read` and `consult_write` are the two consults, in the corpus's
/// sense, and both answer through the per-request binding
/// [`OperationSurface::readable_by`] makes of this.
///
/// [`ReadableWorld`]: crate::ReadableWorld
/// [`ReadableWorld::readable`]: crate::ReadableWorld::readable
/// [`OperationSurface::readable_by`]: crate::OperationSurface
/// [`OperationSurface::visible_to`]: crate::OperationSurface
pub type ReadPredicate = dyn Fn(Option<PrincipalId>, &Address) -> bool + Send + Sync;

impl<W: FebeWorld> OperationSurface<W> {
    /// `readable(doc, principal)` for this front door: the supplied
    /// [`ReadPredicate`] where one was given, else the world's own
    /// [`ReadableWorld::readable`] off `world` — the snapshot a read arm
    /// pinned, or the working world a store hands the predicate of a write.
    /// `None` is the guest. Every consult of the predicate, read path and
    /// visibility class alike, goes through here, so a front door answers ONE
    /// predicate.
    ///
    /// [`ReadableWorld::readable`]: crate::ReadableWorld::readable
    fn readable(&self, world: &W, principal: Option<PrincipalId>, doc: &Address) -> bool {
        match &self.read_predicate {
            Some(predicate) => predicate(principal, doc),
            None => world.readable(principal, doc),
        }
    }

    /// THE ONE READ PREDICATE OF ONE REQUEST (PUB-6.39): `readable(doc)` for
    /// this request's principal, bound ONCE off the ONE world the request
    /// answers from — the snapshot a read pinned, or the snapshot the write
    /// door pinned — and threaded to every asker [`ReadPredicate`] lists.
    /// Each receives an opaque `Fn(&Address) -> bool` and never the principal
    /// behind it (the STRUCK second form), so the answer and the `as_of` it is
    /// stamped with stand on one committed state and no consumer can ask a
    /// second question.
    ///
    /// `None` is the GUEST — a session that resolves to no principal, which
    /// on the read path is a mask and never a refusal.
    ///
    /// The write path's [`OperationSurface::visible_to`] is the sibling
    /// shape and not this one: a visibility class is lent to a STORE, which
    /// supplies its own working world per call, so it stays `Fn(&W,
    /// &Address)` and is closed over the front door rather than over a
    /// world.
    ///
    /// No auto traits are named. A return-position `impl Trait` leaks its
    /// closure's `Send`/`Sync` to callers whether or not it states them, and
    /// no consumer needs them: each takes a bare `&dyn Fn(&Address) -> bool`
    /// and asks it on the request's own thread.
    /// [`OperationSurface::visible_to`] names them because the one thing it
    /// is lent to does.
    pub(super) fn readable_by<'a>(
        &'a self,
        world: &'a W,
        principal: Option<PrincipalId>,
    ) -> impl Fn(&Address) -> bool + 'a {
        move |doc: &Address| self.readable(world, principal, doc)
    }

    /// THE VISIBILITY CLASS OF A WRITE (PUB round 2, lane 3.3b; PUB-6.25,
    /// PUB-6.28): the predicate a store runs a write's in-transaction gates
    /// under for this session — `readable(doc, principal)` for the session's
    /// PRINCIPAL, closed here and lent to the store driver for the one write:
    /// the one closure every in-transaction asker [`ReadPredicate`] lists is
    /// handed. Each evaluates it INSIDE the write transaction, over the
    /// WORKING world it hands the closure — never over the snapshot a read
    /// pins. Where this front door carries a supplied [`ReadPredicate`] (the
    /// historical door), that is what answers here too — one front door, one
    /// predicate — and the world the store hands in is then not read, the head
    /// snapshot the predicate closed over being the world it reads; such a
    /// door dispatches no write today, and the case is the round's escalated
    /// one.
    ///
    /// `Send + Sync` are stated because M7's `Visibility` names them, which
    /// moves an error to this definition rather than the store's call.
    pub(super) fn visible_to(
        &self,
        principal: PrincipalId,
    ) -> impl Fn(&W, &Address) -> bool + Send + Sync + '_ {
        move |world: &W, doc: &Address| self.readable(world, Some(principal), doc)
    }
}

/// PUB-6.6's link-address rule, shared by the read door and the write door:
/// is the document a link ADDRESS is homed in one this caller may read? An
/// address with no home — anything that is not an element — has none to
/// judge and is left to the store. One spelling, because the two doors must
/// agree about whether a link exists: a rule whose point is non-disclosure
/// cannot be written twice and changed once. `document_of` is address
/// arithmetic, so this reads nothing (PUB-6.38).
pub(super) fn home_readable(a: &Address, readable: &dyn Fn(&Address) -> bool) -> bool {
    document_of(a).is_none_or(|home| readable(&home))
}

/// THE READ SIDE'S CONSULT — the DOC-ARGUMENT consult (§2, PUB-6.12; PUB
/// round 2, lane 3.3): the FIRST unreadable NAMED document of the read, in
/// declaration order ([`Op::doc_arguments`], PUB-6.4), answers WITHHELD
/// naming itself — `reorder`, `site.addr` the document, no `detail`
/// (PUB-8.5). Consulted through `readable`, the one predicate the request
/// answers through, so the verdict and the answer it guards stand on one
/// committed state.
///
/// PRECONDITION on `readable`: it is the predicate the request is answered
/// through — the one `execute` binds off the snapshot it pins, or the HEAD's
/// for a historical read — and so owes [`ReadPredicate`]'s contract. This
/// consult checks no registration of its own: that contract is what sends an
/// unregistered document past it to its store's own `*NotRegistered`
/// (PUB-6.37, PUB-7.5), and nothing here can tell a predicate that breaks it.
///
/// It runs BEFORE any other validation, so a published document never
/// answers withheld and a private one never reaches a refusal that would
/// describe it. The complementary rules of the read door live with the
/// answers they shape rather than here: the link-ADDRESS absence rule at the
/// two arms it governs, and the result-set filter inside each reader that
/// applies it.
///
/// PUBLIC, because two callers must give one request one verdict.
/// [`OperationSurface::execute`] runs it ahead of every read arm, over the
/// predicate it binds off the snapshot it pins; a transport answering a
/// HISTORICAL read runs it over the HEAD's predicate BEFORE it reconstructs
/// the N-world (PUB-6.49: the head-set check precedes the N-world's
/// registration check and the history refusals). The list, its order and
/// the verdict all live here, so the two answers cannot come apart.
///
/// Its sibling is the write side's consult, `consult_write`: one obligation
/// split by path, the two deciding who may read what, so a reader looking
/// for either should find both. This one is a function OVER the predicate
/// because two front doors run it and the historical one builds its
/// predicate itself; the write side has one front door, so `consult_write`
/// binds its own and cannot be handed another.
///
/// [`OperationSurface::execute`]: crate::OperationSurface::execute
pub fn consult_read(op: &Op, readable: &dyn Fn(&Address) -> bool) -> Result<(), Rejection> {
    for arg in op.doc_arguments() {
        if !readable(arg) {
            return Err(Rejection::classified(
                op.kind(),
                RejectCode::Withheld,
                Some(FaultSite { addr: Some(arg.clone()), ..FaultSite::default() }),
            ));
        }
    }
    Ok(())
}

/// Whether the write door consults an op, and what its consult stands behind
/// — PUB-6.36's slot 1 ahead of slot 6, as a value ([`Op::write_consult`]).
/// The two answers instruct the door differently, so they are two variants
/// rather than an `Option` whose emptiness a reader must interpret.
///
/// Private to the door, with its producer: nothing outside it re-runs the
/// deferral.
#[derive(Debug, PartialEq, Eq)]
enum WriteConsult<'a> {
    /// The door consults NOTHING for this op: it returns before
    /// [`Op::source_arguments`] or [`Op::link_address_arguments`] is ever
    /// read. Neither a write that reads a source nor one that validates a link
    /// by address may answer this — its sources would reach the store with no
    /// readability gate, or its store's own answer would confirm a link homed
    /// where the caller cannot read.
    NotTaken,
    /// Consulted BEHIND THE DEFERRAL: the consult runs only where these
    /// destinations' own ownership gate would pass — where it would not, the
    /// door defers and judges nothing — so a session that may not write here
    /// is never told whether it may read there. EMPTY for `version`, which is
    /// consulted with no destination to defer on.
    AfterOwnershipOf(Vec<&'a Address>),
}

impl Op {
    /// Whether the write door consults this op at all and — PUB-6.36 slot 1
    /// ahead of slot 6, PUB-6.38 — whose ownership gate it stands behind (see
    /// `consult_write`). [`WriteConsult::AfterOwnershipOf`] for exactly the
    /// writes the consult reaches — a source-reading write or one validating
    /// a link by address ([`Op::link_address_arguments`]) — listing the
    /// documents the store's own `not_owner` is judged on, EMPTY for
    /// `version`, whose mint lands in the caller's own account and which no
    /// destination gate precedes (MINT-FIRST is the daemon's, PUB-6.36's
    /// slot 2). [`WriteConsult::NotTaken`] for a write with nothing to consult
    /// and for every read. `nullify` is `NotTaken` on purpose: its target
    /// takes PUB-6.9's ω-first order and PUB-6.36's slot-5 nullify-class
    /// refusals (lane 3.5), not this consult. `emit`'s endpoints are
    /// address-form (PUB-6.11) and `publish`'s source gate is the composite's
    /// own, threaded per origin (PUB-8.1). EXHAUSTIVE with no `_` arm: a new
    /// `Op` decides its row here.
    ///
    /// A write that reads a source must never answer `NotTaken` — that
    /// pairing would hand the source to the store with no readability gate,
    /// PUB-6.23 silently unapplied — nor may one that validates a link by
    /// address, whose PUB-6.6 rule would then never run. Each pairing is
    /// pinned over the whole `Op` domain in this module's tests rather than
    /// left to agree by hand.
    ///
    /// Defined here, private to the door, where its two siblings in `op` are
    /// public, and deliberately: a historical door re-runs
    /// [`Op::doc_arguments`] over the head (PUB-6.49) and a transport may read
    /// [`Op::source_arguments`] before dispatch, but nothing outside this door
    /// re-runs the DEFERRAL, which exists to decide when M10's own door stays
    /// silent so the store speaks first. Publishing it would invite a
    /// transport to rebuild PUB-6.36's slot-1-before-slot-6 ordering M10
    /// holds.
    fn write_consult(&self) -> WriteConsult<'_> {
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
            | Op::RetrieveEndsets { .. }
            | Op::Project { .. }
            | Op::DiscoverableFrom { .. }
            | Op::DeleteOrphans { .. }
            | Op::InClaims { .. }
            | Op::OutClaims { .. }
            | Op::DocMetadata { .. }
            | Op::EditionClaims { .. }
            | Op::UniversalGrants => WriteConsult::NotTaken,
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
    /// `copy` is the ORDER in which the door asks. `consult_write` asks only
    /// after the deferral, so only CONSULTED writes reach it —
    /// `insert`, `delete` and `rearrange` read no source, answer
    /// [`WriteConsult::NotTaken`] from [`Op::write_consult`], and meet the
    /// store's own `published_target` unchanged, one layer later. The two
    /// lists are therefore read together, and the pairing is pinned in this
    /// module's tests rather than left to agree by hand.
    ///
    /// Private to the door for [`Op::write_consult`]'s reason: nothing outside
    /// it re-runs the door's pre-evaluation, which exists to order one refusal
    /// ahead of another inside this surface.
    fn in_place_destination(&self) -> Option<&Address> {
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
            | Op::RetrieveEndsets { .. }
            | Op::Project { .. }
            | Op::DiscoverableFrom { .. }
            | Op::DeleteOrphans { .. }
            | Op::InClaims { .. }
            | Op::OutClaims { .. }
            | Op::DocMetadata { .. }
            | Op::EditionClaims { .. }
            | Op::UniversalGrants => None,
        }
    }

    /// The link ADDRESSES this write validates for existence (PUB-6.6), in
    /// declaration order, with the op's own code for an address no link
    /// occupies — the code a link homed where the caller cannot read answers
    /// too, so the answer never confirms a link the caller may not see:
    /// `edit_link`'s `original` answers `OriginalNotResident`, and
    /// `assert_sup`'s `old` and `new` answer `EndpointNotResident`. `None`
    /// for everything else. `nullify` is `None` on purpose: its target takes
    /// PUB-6.9's ω-first order and PUB-6.36's slot-5 nullify-class refusals
    /// (lane 3.5), not this rule. No read is in the table: a read applies
    /// PUB-6.6 at its own arm, where absence is the shape of an answer rather
    /// than a code. EXHAUSTIVE with no `_` arm: a new `Op` decides its row
    /// here.
    ///
    /// The rule runs past the deferral, so a write in this table must also be
    /// consulted ([`Op::write_consult`]): one answering `NotTaken` would
    /// never meet the rule, and its store's own answer would confirm a link
    /// homed where the caller cannot read. The pairing is pinned in this
    /// module's tests rather than left to agree by hand.
    ///
    /// Private to the door for [`Op::write_consult`]'s reason: nothing outside
    /// it re-runs the door's ordering of one refusal ahead of another.
    fn link_address_arguments(&self) -> Option<(Vec<&Address>, RejectCode)> {
        match self {
            Op::EditLink { original, .. } => {
                Some((vec![original], RejectCode::OriginalNotResident))
            }
            Op::AssertSup { old, new, .. } => {
                Some((vec![old, new], RejectCode::EndpointNotResident))
            }
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
            | Op::RetrieveEndsets { .. }
            | Op::Project { .. }
            | Op::DiscoverableFrom { .. }
            | Op::DeleteOrphans { .. }
            | Op::InClaims { .. }
            | Op::OutClaims { .. }
            | Op::DocMetadata { .. }
            | Op::EditionClaims { .. }
            | Op::UniversalGrants => None,
        }
    }
}

impl<W: FebeWorld> OperationSurface<W> {
    /// THE WRITE SIDE'S CONSULT (PUB round 2, lane 3.3c; PUB-6.23, PUB-6.24,
    /// PUB-6.36 slot 6, PUB-6.38): the door's pre-dispatch check on a write
    /// that READS a document before it writes — `copy`'s sources, `version`'s
    /// `d_src`, the RESOLVE-form slots of `make_link` and `edit_link` — and the
    /// LINK-ADDRESS rule on the links a write validates by address (PUB-6.6:
    /// `edit_link.original`, `assert_sup.old`/`new`, the table
    /// [`Op::link_address_arguments`] keeps). It binds its own predicate —
    /// [`OperationSurface::readable_by`] for `wc`'s PROVEN-bound principal, off
    /// the `world` it reads the registry from — so the predicate and the
    /// registry stand on one snapshot and no caller can hand it another; and
    /// wherever the door judges the write at all, it runs BEFORE the store call
    /// (or the EDITLINK successor build) that would read the source's
    /// arrangement.
    ///
    /// RETURNS whether the door JUDGED the write: [`Judgment::Judged`] where it
    /// ran past the deferral below and every rule it owns passed;
    /// [`Judgment::Unjudged`] where it judged nothing — an op it does not
    /// consult ([`WriteConsult::NotTaken`]), or one whose destination's own
    /// gate would refuse, so the store speaks first. An `Unjudged` binds the
    /// dispatch that follows: the write's sources went unconsulted, so nothing
    /// built from their arrangements before the store call may speak — no
    /// verdict whose answer a source the caller may not read could decide.
    /// That is why the EDITLINK successor build takes it (`successor_link`'s
    /// `judgment`).
    ///
    /// ORDER, as PUB-6.36 pins it and PUB-6.38 places it: slot 1, the
    /// DESTINATION's `not_owner`, stands AHEAD of this consult. The store words
    /// that verdict inside its own transaction, so the door realizes the order
    /// by DEFERRING: the consult runs only where the destination's own gate
    /// would pass — registered, and ω-owned by the caller, asked through the
    /// store's one spelling of ω (`Caller::is_owner`, M5's, which is M3's
    /// `is_effective_owner`) — and where it would not, nothing here speaks, nor
    /// anything built from the sources it left unconsulted (the `Unjudged` it
    /// returns), and the store answers its own `doc_not_registered` /
    /// `home_not_registered` / `not_owner`. A session that may not write here
    /// is never told whether it may read there (PUB-6.43's ground). M10 words
    /// no ownership verdict of its own; it only declines to judge a source
    /// ahead of one. Registration of the SOURCE stands ahead too (PUB-6.37), by
    /// [`ReadPredicate`]'s contract: an unregistered source passes here and
    /// takes the store's `source_not_registered`.
    ///
    /// PUB-6.36'S SLOT 5 AHEAD OF ITS SLOT 6, and how this door reaches it
    /// (PUB round 2, lane 4.2, F3; PUB-2.11, PUB-6.38): the model's refusals
    /// are evaluated INSIDE the store transaction (owner ruling D2b), which
    /// once left one cell the door could not order — a source the caller may
    /// not read, copied into a PUBLISHED destination the caller owns —
    /// answered `withheld` where PUB-6.36 has slot 5 speak first. The door now
    /// PRE-EVALUATES the in-place advance refusal itself, between the deferral
    /// and the consult, over the class [`Op::in_place_destination`] names, by
    /// ASKING M5's own rule, [`published_target`], on a destination the
    /// deferral has just found registered (PUB-6.37): M5 publishes that read so
    /// a door pre-evaluating the refusal runs the predicate the store enforces
    /// instead of restating it, and only the ORDERING is M10's. So the answer
    /// is `published_target` byte-identically to the store's (same code,
    /// disposition, no site, no detail), and it stays so through any later
    /// revision of the rule. A session refused the write is never told whether
    /// it may read the source (PUB-6.43's ground), the store's own refusal is
    /// simply unreached on that cell, and every other cell answers as before:
    /// where the destination is a draft the check is silent, and where the
    /// store would have refused `published_target` it still does, one layer
    /// earlier and in the same bytes. The versionless sibling never meets the
    /// consult: `private_source_versionless` fires only on a source the caller
    /// OWNS, which the subtree clause makes readable, so no source is both
    /// unreadable and versionless. M5's own refusal stands untouched.
    ///
    /// The two verdicts this consult can speak are the read side's own,
    /// wire-identical to what the store would say of the same address in a
    /// world without the draft: `withheld` — `reorder`, `site.addr` the FIRST
    /// unreadable source in declaration order (PUB-6.4,
    /// [`Op::source_arguments`]), no `detail` (PUB-8.5) — and, for a link homed
    /// in a document the caller may not read, the op's OWN never-deposited
    /// answer (`original_not_resident`, `endpoint_not_resident`, the code
    /// [`Op::link_address_arguments`] pairs with each link), never a withheld
    /// that confirms a draft-homed link exists (PUB-6.6). `document_of(a)` is
    /// address arithmetic — no read (PUB-6.38). Within `edit_link` the
    /// link-address argument speaks first: `original` is declared ahead of
    /// `successor`, and the store's own residence check precedes its slot
    /// checks. `nullify.target` takes no rule here — PUB-6.9's ω-first order
    /// and PUB-6.36's slot-5 nullify-class refusals govern it (lane 3.5).
    ///
    /// STALENESS, since the predicate and the registry are read off `world` — a
    /// PRIOR snapshot, not the base the write commits on. For four of the five
    /// source-reading writes — `copy`, `version`, `make_link`, `edit_link` —
    /// this door is the SOLE enforcement of PUB-6.23: their stores carry no
    /// `withheld` verdict, so what is decided here is what is enforced, and it
    /// is decided at that snapshot rather than at the operation's linearization
    /// point. Most of what the door reads survives the gap because its state is
    /// MONOTONE, and can therefore only produce a false REFUSAL and never a
    /// wrong admission: the registry only grows (every `M3Rec` variant is an
    /// insert), publication never transitions (PUB-1.9), so `published_target`
    /// cannot go stale at all, and ω is stable because a fresh delegation
    /// cannot reassign an allocated prefix. A GRANT is the clause that is not
    /// monotone — it is revocable — so a source readable here may be unreadable
    /// when the write commits, and the gap is REQUEST-SIZED: the consult
    /// itself, up to three full slots of specs, and for `edit_link` the whole
    /// successor build besides. What bounds the consequence is not this door:
    /// the arrangement a late `copy` or `version` produces reads back masked
    /// per run by origin (PUB-6.41), and the I-extents a late `make_link`
    /// deposits are not secret (PUB-6.24). Closing the gap means the shape
    /// `publish` already has — the visibility class evaluated inside the
    /// store's own transaction (`Vstream::publish`) — which is those four
    /// stores' signatures to change, not this door's.
    ///
    /// [`OperationSurface::readable_by`]: OperationSurface::readable_by
    pub(super) fn consult_write(
        &self,
        wc: &WriteCtx,
        op: &Op,
        world: &W,
    ) -> Result<Judgment, Rejection> {
        let kind = op.kind();
        let m3 = world.m3();
        let readable = self.readable_by(world, Some(wc.principal));
        let WriteConsult::AfterOwnershipOf(destinations) = op.write_consult() else {
            // No source and no link-address argument (see the table).
            return Ok(Judgment::Unjudged);
        };
        // PUB-6.36's slot 1 ahead of its slot 6: defer to the store wherever
        // the destination's own gate would refuse.
        let caller = wc.caller();
        if !destinations.iter().all(|d| m3.is_registered_document(d) && caller.is_owner(m3, d)) {
            return Ok(Judgment::Unjudged);
        }
        // PUB-6.36's slot 5 ahead of its slot 6 (lane 4.2, F3): the model's
        // in-place advance refusal on this write's destination — PUB-2.11,
        // asked of M5's own `published_target` on a destination the deferral
        // has just found registered (PUB-6.37), so the door runs the rule the
        // store enforces rather than a copy of it — BEFORE any source is
        // consulted, so the one cell where both apply answers
        // `published_target`, never `withheld`. `copy` is the only member of
        // the class that is also consulted; the others never reach here
        // (`in_place_destination`).
        if let Some(in_place) = op.in_place_destination() {
            if published_target(m3, in_place) {
                return Err(rejection(kind, RejectCode::PublishedTarget));
            }
        }
        // §2 — the link-address rule on writes (PUB-6.6): a link homed where
        // the caller cannot read answers the op's own never-deposited code,
        // exactly as an address no link occupies
        // (`Op::link_address_arguments`).
        if let Some((links, absent)) = op.link_address_arguments() {
            if !links.iter().all(|link| home_readable(link, &readable)) {
                return Err(rejection(kind, absent));
            }
        }
        // §1 — the source consult: the first unreadable source, in
        // declaration order, answers WITHHELD naming itself.
        for source in op.source_arguments() {
            if !readable(source) {
                return Err(Rejection::classified(
                    kind,
                    RejectCode::Withheld,
                    Some(FaultSite { addr: Some(source.clone()), ..FaultSite::default() }),
                ));
            }
        }
        Ok(Judgment::Judged)
    }
}

#[cfg(test)]
mod tests {
    use skep_address::{validate, Nat, Span, Tumbler};
    use skep_arrangement::{Deposit, VPos, VSpec};
    use skep_content::Val;
    use skep_links::SlotArg;

    use super::*;
    use crate::op::tests::all_ops;
    use crate::op::SuccessorSpec;

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
    fn doc() -> Address {
        addr(&[1, 0, 1, 0, 1])
    }

    /// PUB-6.23 at the pairing of the two lists, which is where it can
    /// silently fail. The door reads `write_consult` FIRST and returns on
    /// [`WriteConsult::NotTaken`] without ever reading `source_arguments`, so
    /// the two are jointly load-bearing: a write that reads a source and
    /// answers `NotTaken` hands that source to its store with no readability
    /// gate, and both matches being exhaustive means the compiler forces two
    /// independent decisions and accepts the wrong pairing. The law is that
    /// pairing — reading a source implies a consult — plus the two arms of
    /// [`WriteConsult`] itself, which differ in what they let the door do and
    /// are likewise both well-typed.
    #[test]
    fn a_write_that_reads_a_source_is_always_consulted() {
        for (op, is_read) in all_ops() {
            let reads_a_source = !op.source_arguments().is_empty();
            let consulted = matches!(op.write_consult(), WriteConsult::AfterOwnershipOf(_));
            assert!(
                !reads_a_source || consulted,
                "{:?} reads a source and is NotTaken: its sources reach the store ungated",
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
            WriteConsult::AfterOwnershipOf(destinations) => assert!(
                destinations.is_empty(),
                "an empty destination list is not the same answer as `NotTaken`"
            ),
            WriteConsult::NotTaken => panic!("version is consulted"),
        }
        // Consulted with destinations: the documents the store's own
        // `not_owner` is judged on, which is what the door defers to.
        let d1 = addr(&[1, 0, 1, 0, 1]);
        let d2 = addr(&[1, 0, 1, 0, 2]);
        let edit = Op::EditLink {
            original: d1.clone(),
            successor: SuccessorSpec {
                from: vec![],
                to: vec![],
                ty: SlotArg::Addrs(vec![d1.clone()]),
            },
            d_s: d1.clone(),
            d_a: d2.clone(),
        };
        assert_eq!(
            edit.write_consult(),
            WriteConsult::AfterOwnershipOf(vec![&d1, &d2]),
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
    /// (`consult_write`). `in_place_destination` names the class
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

    /// PUB-6.6 at the THIRD pairing the door depends on (`consult_write`).
    /// The link-address rule runs past the deferral, so a write that
    /// validates a link by address and answers `NotTaken` never meets it, and
    /// its store's own answer confirms a link homed where the caller cannot
    /// read. The class is `edit_link` and `assert_sup`, each with its own
    /// never-deposited code, and no read is in it.
    #[test]
    fn a_write_that_validates_a_link_by_address_is_always_consulted() {
        for (op, is_read) in all_ops() {
            let validates = op.link_address_arguments().is_some();
            let expects = matches!(op, Op::EditLink { .. } | Op::AssertSup { .. });
            assert_eq!(validates, expects, "{:?}: the link-address row", op.kind());
            assert!(
                !validates || matches!(op.write_consult(), WriteConsult::AfterOwnershipOf(_)),
                "{:?} validates a link by address and is NotTaken: the rule never runs",
                op.kind()
            );
            assert!(
                !is_read || !validates,
                "{:?} is a read: it answers absence at its own arm",
                op.kind()
            );
        }

        // The links named, in declaration order, each op with its own code.
        let (old, new) = (addr(&[1, 0, 1, 0, 2]), addr(&[1, 0, 1, 0, 3]));
        let sup = Op::AssertSup { home: doc(), old: old.clone(), new: new.clone() };
        assert_eq!(
            sup.link_address_arguments(),
            Some((vec![&old, &new], RejectCode::EndpointNotResident))
        );
        let edit = Op::EditLink {
            original: old.clone(),
            successor: SuccessorSpec { from: vec![], to: vec![], ty: SlotArg::Addrs(vec![]) },
            d_s: doc(),
            d_a: doc(),
        };
        assert_eq!(
            edit.link_address_arguments(),
            Some((vec![&old], RejectCode::OriginalNotResident))
        );
    }
}
