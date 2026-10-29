//! The readability door: the one read predicate a front door answers through.
//!
//! That predicate is its world's own or a supplied [`ReadPredicate`], bound
//! once per request by [`OperationSurface::readable_by`]. Here too are the
//! two consults it drives ([`consult_read`],
//! [`OperationSurface::consult_write`]), the link-address absence rule
//! ([`home_readable`]), the visibility class lent to a store for one write
//! ([`OperationSurface::visible_to`]), and the three per-variant tables only
//! the write consult asks, [`Op::write_consult`],
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
use crate::reject::{rejection, FaultSite, RejectCode, Rejection};
use crate::request::{ISpanFault, Op};
use crate::successor::Judgment;
use crate::world::FebeWorld;

/// The read predicate (PUB-1.31): whether `principal` may read `doc`.
///
/// It takes PUB-6.39's one-per-request shape, and `None` is the guest. A
/// front door answers the world's own, [`ReadableWorld::readable`], unless
/// the transport supplies this closure in its place
/// ([`OperationSurface::with_read_predicate`]). Whichever answers owes
/// everything below, and this is the one place it is stated.
///
/// **Who asks it, and how often.** The door's two consults and its
/// link-address rule ask once per argument the request names or derives, a
/// count the transport's parser caps. The readers that mask below the door —
/// M6's per-run withheld arm and container filter, M8's result-set filters, the
/// edition-claim home rule — ask once per result row: a count set by stored
/// state, capped by nothing, and reached by an unauthenticated guest through
/// the FTT descriptor family, which names no document at all and whose
/// unconstrained form matches every active link in the store. M10 creates
/// that second class, by threading this one predicate down into the readers,
/// so a supplier sizing its own work against a per-argument figure has priced
/// only the first. And lent as a write's visibility class it is asked by
/// every gate a store runs inside its own transaction: M5's per-origin source
/// gate on the shot (PUB-6.23, PUB-8.1's second constraint) and M7's
/// value-keyed gates on the five link writes (PUB-6.25).
///
/// **Obligations on the answer.** It is asked about addresses of any tier,
/// registered or not: the doc-argument consult walks the request's named
/// documents before any registration check, and the link-address rule asks
/// it of a home derived by address arithmetic (PUB-6.38), which no store
/// need have registered. So it must be total, and it must answer readable
/// for an address the store has not registered — PUB-7.5's fail-open sign,
/// the exception set holding the unpublished side so a membership miss is
/// the published fast path. That is what leaves each arm's own
/// `*NotRegistered` to speak, and what makes a withheld answer only ever a
/// registered private document (PUB-6.12). A predicate that refuses
/// defensively for an address it cannot resolve inverts that guarantee and
/// tells a prober that a nonexistent address exists-but-is-hidden. M6's
/// per-run arm and M5's publish gate check registration before asking, as
/// their own behaviour and not as a guarantee from here.
///
/// **One departure is on record.** The engine's predicate meets those
/// obligations for every unregistered address but one shape, and so does any
/// supplied closure built over the engine's world, the daemon's historical
/// door's among them: an address shaped as a version member of a registered
/// draft reads as that draft (PUB-2.15) and is withheld wherever the draft
/// is, though no mint produced it. The engine records it on its impl of
/// [`ReadableWorld`]. Which of PUB-2.15 and PUB-6.12 governs that shape is
/// PUB's to rule; until it does, a `Withheld` naming such an address names
/// one no store registered.
///
/// Absent ([`OperationSurface::new`] alone), the world's own answers, which
/// is the live daemon's case: off the one snapshot a read pins, so the answer
/// and the `as_of` it is stamped with stand on one committed state; off the
/// snapshot the write door pins, for a write's consult; and, as a write's
/// visibility class, off the working world of that write's own transaction,
/// which its store — M5 on the shot, M7 on the link writes — hands it.
/// Supplied, this closure overrides the world it would be
/// evaluated over — what a historical read needs: `/op-at N` answers the
/// N-world's content through the head's exception set and grant set
/// (PUB-6.48), so the daemon's throwaway front door over the reconstructed
/// world answers through a predicate closed over one head snapshot.
/// `Send + Sync + 'static`, since the front door is shared across a
/// transport's worker pool.
///
/// **Where it is evaluated, and what that position costs the supplier.** On
/// a read it answers off the snapshot the request pinned, and the caller
/// waits alone. On a write the door's consult asks it off the snapshot the
/// door pinned, ahead of the write's transaction; and where a store gates
/// the write itself — M5's publish source gate, M7's value-keyed gates on
/// the five link writes — it is lent to that store as the caller's
/// visibility class (`OperationSurface::visible_to`) and evaluated inside
/// the store's transaction, under M2's applier lock. So it inherits
/// `transact`'s precondition, which M5 states for the parameter M10 fills
/// here and which M10 can no more check than M5 can: it must not call
/// `transact` on that kernel (M2 answers a nested write with its reentrancy
/// panic, the supplier's bug), and every other writer in the engine waits
/// while it answers. A predicate that resolves its grants by asking the
/// engine is the shape that trips both; one closed over a snapshot it
/// already holds, as the daemon's historical door is, trips neither.
///
/// This is the predicate a door consults, never the act of consulting it:
/// `consult_read` and `consult_write` are the two consults, in the corpus's
/// sense, and both answer through the per-request binding
/// `OperationSurface::readable_by` makes of this.
///
/// [`ReadableWorld`]: crate::ReadableWorld
/// [`ReadableWorld::readable`]: crate::ReadableWorld::readable
pub type ReadPredicate = dyn Fn(Option<PrincipalId>, &Address) -> bool + Send + Sync;

impl<W: FebeWorld> OperationSurface<W> {
    /// Returns `readable(doc, principal)` for this front door.
    ///
    /// It is the supplied [`ReadPredicate`] where one was given, else the
    /// world's own [`ReadableWorld::readable`] off `world` — the snapshot a
    /// request pinned, a read's or the write door's, or the working world a
    /// store hands the predicate of a write. `None` is the guest. Every
    /// consult of the predicate, read path and visibility class alike, goes
    /// through here, so a front door answers one predicate.
    ///
    /// [`ReadableWorld::readable`]: crate::ReadableWorld::readable
    fn readable(&self, world: &W, principal: Option<PrincipalId>, doc: &Address) -> bool {
        match &self.read_predicate {
            Some(predicate) => predicate(principal, doc),
            None => world.readable(principal, doc),
        }
    }

    /// Returns the one read predicate of one request (PUB-6.39).
    ///
    /// It is `readable(doc)` for this request's principal, bound once off the
    /// one world the request answers from — the snapshot a read pinned, or the
    /// snapshot the write door pinned — and threaded to every asker
    /// [`ReadPredicate`] lists outside a store's transaction. Each receives an
    /// opaque `Fn(&Address) -> bool` and never the principal behind it (the
    /// struck second form), so the answer and the `as_of` it is stamped with
    /// stand on one committed state and no consumer can ask a second question.
    ///
    /// `None` is the guest — a session that resolves to no principal, which
    /// on the read path is a mask and never a refusal.
    ///
    /// The write path's [`OperationSurface::visible_to`] is the sibling
    /// shape and not this one: a visibility class is lent to a store, which
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

    /// Returns the visibility class of a write (PUB-6.25, PUB-6.28).
    ///
    /// It is the predicate a store runs a write's in-transaction gates under
    /// for this session — `readable(doc, principal)` for the session's
    /// principal, closed here and lent to the store driver for the one write:
    /// the one closure every in-transaction asker [`ReadPredicate`] lists is
    /// handed. Each evaluates it inside the write transaction, over the
    /// working world it hands the closure — never over the snapshot a read
    /// pins. Where this front door carries a supplied [`ReadPredicate`] (the
    /// historical door), that is what answers here too — one front door, one
    /// predicate — and the world the store hands in is then not read, the head
    /// snapshot the predicate closed over being the world it reads; such a
    /// door dispatches no write.
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

/// Answers PUB-6.6's link-address rule, shared by the read and write doors.
///
/// It asks whether the document a link address is homed in is one this
/// caller may read. An address with no document — a node's or an account's —
/// has none to judge and is left to the store, and a document's own address
/// is its own home. One spelling, because the two doors must agree about
/// whether a link exists: a rule whose point is non-disclosure cannot be
/// written twice and changed once. `document_of` is address arithmetic, so
/// deriving the home reads nothing (PUB-6.38).
pub(super) fn home_readable(a: &Address, readable: &dyn Fn(&Address) -> bool) -> bool {
    document_of(a).is_none_or(|home| readable(&home))
}

/// Runs the read side's consult, the doc-argument consult (PUB-6.12).
///
/// Consulted through `readable`, the one predicate the request answers
/// through, so the verdict and the answer it guards stand on one committed
/// state.
///
/// **Precondition.** `readable` is the predicate the request is answered
/// through — the one `execute` binds off the snapshot it pins, or the head's
/// for a historical read — and so owes [`ReadPredicate`]'s contract. This
/// consult checks no registration of its own: that contract
/// is what sends an unregistered document past it to its store's own
/// `*NotRegistered` (PUB-6.37, PUB-7.5), and nothing here can tell a
/// predicate that breaks it.
///
/// It runs before any other validation, so a published document never
/// answers withheld and a private one never reaches a refusal that would
/// describe it. The complementary rules of the read door live with the
/// answers they shape rather than here: the link-address absence rule at the
/// arms that apply it — two in the read dispatch, two in the discovery
/// readers — and the result-set filter inside each reader that applies it.
///
/// Public, because two callers must give one request one verdict.
/// [`OperationSurface::execute`] runs it ahead of every read arm, over the
/// predicate it binds off the snapshot it pins; a transport answering a
/// historical read runs it over the head's predicate before it reconstructs
/// the N-world (PUB-6.49: the head-set check precedes the N-world's
/// registration check and the history refusals). The list, its order and
/// the verdict all live here, so the two answers cannot come apart — the
/// derived list and its shape refusal included, so the historical door reads
/// a derived home exactly as the live one does.
///
/// Its sibling is the write side's consult, `consult_write`: one obligation
/// split by path, the two deciding who may read what, so a reader looking
/// for either should find both. This one is a function over the predicate
/// because two front doors run it and the historical one builds its
/// predicate itself; the write side has one front door, so `consult_write`
/// binds its own and cannot be handed another.
///
/// # Errors
///
/// The first of these that holds answers:
///
/// 1. The first unreadable named document of the read, in declaration order
///    ([`Op::doc_arguments`], PUB-6.4), answers `Withheld` naming itself —
///    `reorder`, `site.addr` the document, no `detail` (PUB-8.5).
/// 2. Then the derived list (the media record's "each I-span confined to one
///    derived document"; PUB-6.38; M-I2 (a)): the documents the read derives
///    rather than names — [`Op::derived_doc_arguments`], the read by
///    identity's. The derivation refuses the op's shape on its way — a span
///    with no element position at its start, or of zero width, the first
///    such span answering, its width checked ahead of its start — which is
///    the one refusal this consult raises that is not `Withheld`: by address
///    arithmetic on the request alone, before any document is consulted, so
///    a prober learns nothing a span's shape did not already say
///    (`NotContentSubspace` for the one, `EmptyWidth` for the other, each
///    with the span's index as its site, as a malformed RETRIEVEV spec names
///    its own).
/// 3. The derived documents are walked after the named ones under the same
///    predicate, the first unreadable one answering the same `Withheld`
///    naming it, before dispatch and never as a per-address item.
///
/// [`OperationSurface::execute`]: crate::OperationSurface::execute
pub fn consult_read(op: &Op, readable: &dyn Fn(&Address) -> bool) -> Result<(), Rejection> {
    let withheld = |doc: &Address| {
        Rejection::classified(
            op.kind(),
            RejectCode::Withheld,
            Some(FaultSite { addr: Some(doc.clone()), ..FaultSite::default() }),
        )
    };
    for doc in op.doc_arguments() {
        if !readable(doc) {
            return Err(withheld(doc));
        }
    }
    let derived = op.derived_doc_arguments().map_err(|(index, fault)| {
        let code = match fault {
            ISpanFault::NoElementPosition => RejectCode::NotContentSubspace,
            ISpanFault::EmptyWidth => RejectCode::EmptyWidth,
        };
        Rejection::classified(
            op.kind(),
            code,
            Some(FaultSite { index: Some(index), ..FaultSite::default() }),
        )
    })?;
    for doc in &derived {
        if !readable(doc) {
            return Err(withheld(doc));
        }
    }
    Ok(())
}

/// Whether the write door consults an op, and what its consult stands behind.
///
/// It is PUB-6.36's slot 1 ahead of slot 6, as a value
/// ([`Op::write_consult`]). The two answers instruct the door differently, so
/// they are two variants rather than an `Option` whose emptiness a reader
/// must interpret.
///
/// Private to the door, with its producer: nothing outside it re-runs the
/// deferral.
#[derive(Debug, PartialEq, Eq)]
enum WriteConsult<'a> {
    /// The door consults nothing for this op.
    ///
    /// It returns before [`Op::source_arguments`] or
    /// [`Op::link_address_arguments`] is ever read. Neither a write that reads
    /// a source nor one that validates a link by address may answer this —
    /// its sources would reach the store with no readability gate, or its
    /// store's own answer would confirm a link homed where the caller cannot
    /// read.
    NotTaken,
    /// Consulted behind the deferral on these destinations' ownership gate.
    ///
    /// The consult runs only where these destinations' own ownership gate
    /// would pass — where it would not, the door defers and judges nothing —
    /// so a session that may not write here is never told whether it may read
    /// there. Empty for `version`, which is consulted with no destination to
    /// defer on.
    AfterOwnershipOf(Vec<&'a Address>),
}

impl Op {
    /// Returns whether the write door consults this op, and behind whose gate.
    ///
    /// It orders PUB-6.36 slot 1 ahead of slot 6 (PUB-6.38; see
    /// `consult_write`). [`WriteConsult::AfterOwnershipOf`] for exactly the
    /// writes the consult reaches — a source-reading write or one validating a
    /// link by address ([`Op::link_address_arguments`]) — listing the
    /// documents the store's own `not_owner` is judged on, empty for
    /// `version`, whose mint lands in the caller's own account and which no
    /// destination gate precedes (mint-first is the daemon's, PUB-6.36's slot
    /// 2). [`WriteConsult::NotTaken`] for a write with nothing to consult and
    /// for every read. `nullify` is `NotTaken` on purpose: its target takes
    /// PUB-6.9's ω-first order and PUB-6.36's slot-5 nullify-class refusals,
    /// not this consult. `emit`'s endpoints are address-form (PUB-6.11) and
    /// `publish`'s source gate is the composite's own, threaded per origin
    /// (PUB-8.1). Exhaustive with no `_` arm: a new `Op` decides its row here.
    ///
    /// A write that reads a source must never answer `NotTaken` — that
    /// pairing would hand the source to the store with no readability gate,
    /// PUB-6.23 silently unapplied — nor may one that validates a link by
    /// address, whose PUB-6.6 rule would then never run. Each pairing is
    /// pinned over the whole `Op` domain in this module's tests rather than
    /// left to agree by hand.
    ///
    /// Defined here, private to the door, where its two siblings in `request`
    /// are public, and deliberately: a historical door re-runs
    /// [`Op::doc_arguments`] over the head (PUB-6.49) and a transport may read
    /// [`Op::source_arguments`] before dispatch, but nothing outside this door
    /// re-runs the deferral, which exists to decide when M10's own door stays
    /// silent so the store speaks first. Publishing it would invite a
    /// transport to rebuild PUB-6.36's slot-1-before-slot-6 ordering M10
    /// holds.
    fn write_consult(&self) -> WriteConsult<'_> {
        match self {
            Op::Copy { doc, .. } => WriteConsult::AfterOwnershipOf(vec![doc]),
            // The write by identity reads its origins' bytes as `copy` reads
            // its sources' arrangements — under the wide reach, any readable
            // document's (the replacement act's record, Q2) — so it is
            // consulted exactly as `copy` is, behind the destination's gate.
            Op::Reinstate { doc, .. } => WriteConsult::AfterOwnershipOf(vec![doc]),
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
            | Op::UniversalGrants => WriteConsult::NotTaken,
        }
    }

    /// Returns the destination this write edits in place, if any (PUB-2.11).
    ///
    /// The class is `insert`, `delete`, `copy`-into, `reinstate` and
    /// `rearrange`, the five writes that advance an existing document's
    /// arrangement. `None` for everything else, and each exclusion is the
    /// rule's own: the link writes are outside it (PUB-2.12), `version` and
    /// `create`/`fork` mint a document rather than advancing one, `publish`
    /// appends a chain member whose destination M5's composite decides
    /// (PUB-2.39), and no read edits anything. Exhaustive with no `_` arm: a
    /// new `Op` decides its row here.
    ///
    /// This names the class; what restricts the door's pre-evaluation to
    /// `copy` and `reinstate` is the order in which the door asks.
    /// `consult_write` asks only after the deferral, so only consulted writes
    /// reach it — `insert`, `delete` and `rearrange` read no source, answer
    /// [`WriteConsult::NotTaken`] from [`Op::write_consult`], and meet the
    /// store's own `published_target` as the store words it, one layer later.
    /// The two lists are therefore read together, and the pairing is pinned
    /// in this module's tests rather than left to agree by hand.
    ///
    /// Private to the door for [`Op::write_consult`]'s reason: nothing outside
    /// it re-runs the door's pre-evaluation, which exists to order one refusal
    /// ahead of another inside this surface.
    fn in_place_destination(&self) -> Option<&Address> {
        match self {
            Op::Insert { doc, .. }
            | Op::Delete { doc, .. }
            | Op::Copy { doc, .. }
            | Op::Reinstate { doc, .. }
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
            | Op::UniversalGrants => None,
        }
    }

    /// Returns the link addresses this write validates for existence (PUB-6.6).
    ///
    /// They come in declaration order, with the op's own code for an address
    /// no link occupies — the code a link homed where the caller cannot read
    /// answers too, so the answer never confirms a link the caller may not
    /// see: `edit_link`'s `original` answers `OriginalNotResident`, and
    /// `assert_sup`'s `old` and `new` answer `EndpointNotResident`. `None` for
    /// everything else. `nullify` is `None` on purpose: its target takes
    /// PUB-6.9's ω-first order and PUB-6.36's slot-5 nullify-class refusals,
    /// not this rule. No read is in the table: a read applies PUB-6.6 at its
    /// own arm or in its reader, answering absence as it answers an address
    /// no link occupies. Exhaustive with no `_` arm: a new `Op` decides its
    /// row here.
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
            | Op::Reinstate { .. }
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
            | Op::UniversalGrants => None,
        }
    }
}

impl<W: FebeWorld> OperationSurface<W> {
    /// Runs the write side's consult: the door's pre-dispatch check on a write.
    ///
    /// It realizes PUB-6.23, PUB-6.24, PUB-6.36 slot 6 and PUB-6.38 on a write
    /// that reads a document before it writes — `copy`'s sources,
    /// `reinstate`'s run origins, `version`'s `d_src`, the resolve-form slots
    /// of `make_link` and `edit_link` — and runs the link-address rule on the
    /// links a write validates by address (PUB-6.6: `edit_link.original`,
    /// `assert_sup.old`/`new`, the table [`Op::link_address_arguments`]
    /// keeps). It binds its own predicate — [`OperationSurface::readable_by`]
    /// for `wc`'s proven-bound principal, off the `world` it reads the registry
    /// from — so the predicate and the registry stand on one snapshot and no
    /// caller can hand it another; and wherever the door judges the write at
    /// all, it runs before the store call (or the EDITLINK successor build)
    /// that would read the source's arrangement.
    ///
    /// It returns whether the door judged the write: [`Judgment::Judged`]
    /// where it ran past the deferral below and every rule it owns passed;
    /// [`Judgment::Unjudged`] where it judged nothing — an op it does not
    /// consult ([`WriteConsult::NotTaken`]), or one whose destination's own
    /// gate would refuse, so the store speaks first. An `Unjudged` binds the
    /// dispatch that follows: the write's sources went unconsulted, so nothing
    /// built from their arrangements before the store call may speak — no
    /// verdict whose answer a source the caller may not read could decide.
    /// That is why the EDITLINK successor build takes it (`successor_link`'s
    /// `judgment`).
    ///
    /// **Staleness.** The predicate and the registry are read off `world` — a
    /// prior snapshot, not the base the write commits on. For five of the six
    /// source-reading writes — `copy`, `reinstate`, `version`,
    /// `make_link`, `edit_link` — this door is the sole enforcement of
    /// PUB-6.23: their stores carry no `withheld` verdict (M5 states the gate
    /// as COPY's, REINSTATE's and VERSION's precondition, which this consult
    /// discharges), so what is decided here is what is enforced, and it is
    /// decided at that snapshot rather than at the operation's linearization
    /// point. The gap opens only where a write commits between the two —
    /// another `execute` in flight, which §8 invites, or a writer outside the
    /// surface — and three of the door's readings can then admit what the
    /// commit base would refuse. Registration grows, and the door reads it
    /// permissively twice: the deferral judges nothing where a destination is
    /// not yet registered, so a destination registered in the window — the
    /// caller's own pipelined `create` is enough — turns a write the door left
    /// to the store's gate into one that store admits with its sources never
    /// consulted and its link-address arguments never judged, COPY's
    /// precondition undischarged; and the predicate's fail-open reads a
    /// document not yet registered as readable, though a write in the window
    /// may register it private and fill it. A grant is revocable, so a source
    /// readable here may be unreadable when the write commits. What cannot go
    /// stale: publication never transitions (PUB-1.9), so `published_target`
    /// cannot, and ω over a registered document is stable, no delegation
    /// seating a prefix between an account and its documents. The window spans
    /// the consult itself — up to three full slots of specs, and for
    /// `edit_link` the whole successor build, which the caller sizes — and the
    /// write's wait for M2's applier lock, where any other write may commit.
    /// What bounds the consequence is not this door: the arrangement a late
    /// `copy`, `reinstate` or `version` produces reads back masked per run by
    /// origin (PUB-6.41), and the I-extents a late `make_link` or `edit_link`
    /// deposits are not secret (PUB-6.24); a late link-address argument is
    /// bounded by nothing, the store's residence check then confirming a link
    /// homed where the caller cannot read (PUB-6.6). Closing the gap means the
    /// shape `publish` already has — the visibility class evaluated inside the
    /// store's own transaction (`Vstream::publish`), over the sources these
    /// writes read and the links `edit_link` and `assert_sup` name — which is
    /// M5's and M7's to change, not this door's; until then the door holds
    /// exactly only where nothing commits in the window, which
    /// [`OperationSurface::execute`] states as concurrency's price.
    ///
    /// # Errors
    ///
    /// **Order.** As PUB-6.36 pins it and PUB-6.38 places it, slot 1, the
    /// destination's `not_owner`, stands ahead of this consult. The store
    /// words that verdict inside its own transaction, so the door realizes the
    /// order by deferring: the consult runs only where the destination's own
    /// gate would pass — registered, and ω-owned by the caller, asked as the
    /// store's own ownership-gate question (`Caller::passes_ownership_gate`,
    /// M5's: registration, then ω through `Caller::is_owner`, which is M3's
    /// `is_effective_owner`) — and where it would not, nothing here speaks,
    /// nor anything built from the sources it left unconsulted (the `Unjudged`
    /// it returns), and the store answers its own `doc_not_registered` /
    /// `home_not_registered` / `not_owner`. A session that may not write here
    /// is never told whether it may read there (PUB-6.43's ground). M10 words
    /// no ownership verdict of its own; it only declines to judge a source
    /// ahead of one. Registration of the source stands ahead too (PUB-6.37),
    /// by [`ReadPredicate`]'s contract: an unregistered source passes here and
    /// takes the refusal its write gives one — the store's
    /// `source_not_registered` for `copy`, `reinstate` and `version`, the
    /// successor build's for `edit_link`, the link store's `ill_formed_spec`
    /// for a `make_link` slot. Each store answer named here is its commit
    /// base's, which a write landing after this door's snapshot can change
    /// (the staleness paragraph, above).
    ///
    /// **PUB-6.36's slot 5 ahead of its slot 6, and how this door reaches it
    /// (PUB-2.11, PUB-6.38).** The model's refusals are evaluated inside the
    /// store transaction (PUB-kickoff D2b), which leaves one cell the door
    /// could not order on its own — a source the caller may not read, copied
    /// into a published destination the caller owns — where `withheld` would
    /// answer though PUB-6.36 has slot 5 speak first. So the door
    /// pre-evaluates the in-place advance refusal itself, between the deferral
    /// and the consult, over the class [`Op::in_place_destination`] names, by
    /// asking M5's own rule, [`published_target`], on a destination the
    /// deferral has just found registered (PUB-6.37): M5 publishes that read so
    /// a door pre-evaluating the refusal runs the predicate the store enforces
    /// instead of restating it, and only the ordering is M10's. So the answer
    /// is `published_target` byte-identically to the store's (same code,
    /// disposition, no site, no detail), and it stays so through any revision
    /// of the rule. A session refused the write is never told whether it may
    /// read the source (PUB-6.43's ground), the store's own refusal is
    /// unreached on that cell, and every other cell answers as the store would:
    /// where the destination is a draft the check is silent, and where the
    /// store would refuse `published_target` the refusal comes one layer
    /// earlier and in the same bytes. The versionless sibling never meets the
    /// consult: `private_source_versionless` fires only on a source the caller
    /// owns, which the subtree clause makes readable, so no source is both
    /// unreadable and versionless. M5's own refusal stands.
    ///
    /// Besides `published_target`, the two verdicts this consult can speak are
    /// the read side's own: `withheld` — `reorder`, `site.addr` the first
    /// unreadable source in declaration order (PUB-6.4,
    /// [`Op::source_arguments`]), no `detail` (PUB-8.5) — and, for a link homed
    /// in a document the caller may not read, the op's own never-deposited
    /// answer (`original_not_resident`, `endpoint_not_resident`, the code
    /// [`Op::link_address_arguments`] pairs with each link), wire-identical to
    /// what the store would say of the same address in a world without the
    /// draft and never a withheld that confirms a draft-homed link exists
    /// (PUB-6.6). `document_of(a)` is address arithmetic — no read (PUB-6.38).
    /// Within `edit_link` the link-address argument speaks first: `original`
    /// is declared ahead of `successor`, and the store's own residence check
    /// precedes its slot checks. `nullify.target` takes no rule here —
    /// PUB-6.9's ω-first order and PUB-6.36's slot-5 nullify-class refusals
    /// govern it.
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
        if !destinations
            .iter()
            .all(|d| caller.passes_ownership_gate(m3, d))
        {
            return Ok(Judgment::Unjudged);
        }
        // PUB-6.36's slot 5 ahead of its slot 6: the model's in-place advance
        // refusal on this write's destination — PUB-2.11, asked of M5's own
        // `published_target` on a destination the deferral has just found
        // registered (PUB-6.37), so the door runs the rule the store enforces
        // rather than a copy of it — before any source is consulted, so the
        // one cell where both apply answers `published_target`, never
        // `withheld`. `copy` and `reinstate` are the members of the class that
        // are also consulted; the others never reach here
        // (`in_place_destination`).
        if let Some(in_place) = op.in_place_destination() {
            if published_target(m3, in_place) {
                return Err(rejection(kind, RejectCode::PublishedTarget));
            }
        }
        // The link-address rule on writes (PUB-6.6): a link homed where the
        // caller cannot read answers the op's own never-deposited code,
        // exactly as an address no link occupies
        // (`Op::link_address_arguments`).
        if let Some((links, absent)) = op.link_address_arguments() {
            if !links.iter().all(|link| home_readable(link, &readable)) {
                return Err(rejection(kind, absent));
            }
        }
        // The source consult: the first unreadable source, in declaration
        // order, answers withheld naming itself.
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
    use skep_arrangement::{Deposit, Run, ShotRun, VPos, VSpec};
    use skep_content::Val;
    use skep_links::SlotArg;

    use super::*;
    use crate::request::tests::all_ops;
    use crate::request::SuccessorSpec;

    fn tum(comps: &[u32]) -> Tumbler {
        Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")
    }
    fn addr(comps: &[u32]) -> Address {
        validate(tum(comps)).unwrap_or_else(|_| panic!("T4-valid test address"))
    }
    fn vspan() -> Span {
        Span::new(tum(&[1, 1]), tum(&[0, 1])).unwrap_or_else(|_| panic!("well-formed test span"))
    }
    fn vpos() -> VPos {
        VPos { subspace: Nat::from(1u32), ordinal: Nat::from(1u32) }
    }
    fn doc() -> Address {
        addr(&[1, 0, 1, 0, 1])
    }

    /// PUB-6.23 at the pairing of the two lists, where it can silently fail.
    ///
    /// The door reads `write_consult` first and returns on
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

        // Consulted with an empty destination list: no destination to defer
        // on — the mint lands in the caller's own account (mint-first is the
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
                from: vec![].into(),
                to: vec![].into(),
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

    /// PUB-2.11 / PUB-6.36 slot 5: the other pairing `consult_write` needs.
    ///
    /// `in_place_destination` names the class — the five writes that advance
    /// an existing document's arrangement — and the door's order is what
    /// narrows the pre-evaluation to `copy` and `reinstate`: the check runs
    /// past the deferral, so only a consulted member reaches it, and the three
    /// that are not consulted meet the store's own `published_target` as the
    /// store words it. Both halves are stated here, because a member that
    /// quietly stopped being consulted, or a consulted write that quietly left
    /// the class, would reorder a refusal with nothing to say so.
    #[test]
    fn the_in_place_class_is_the_five_arrangement_edits_and_copy_and_reinstate_are_consulted() {
        for (op, is_read) in all_ops() {
            let in_place = op.in_place_destination().is_some();
            let expects = !is_read
                && matches!(
                    op,
                    Op::Insert { .. }
                        | Op::Delete { .. }
                        | Op::Copy { .. }
                        | Op::Reinstate { .. }
                        | Op::Rearrange { .. }
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
                matches!(op, Op::Copy { .. } | Op::Reinstate { .. }),
                "{:?}: `copy` and `reinstate` are the members the door's pre-evaluation reaches",
                op.kind()
            );
        }

        // The destination named is the document edited, not a source read —
        // for the transclusion by position and for the one by identity.
        let d = addr(&[1, 0, 1, 0, 1]);
        let src = addr(&[1, 0, 1, 0, 2]);
        let copy = Op::Copy {
            doc: d.clone(),
            at: vpos(),
            specs: vec![VSpec { source: src.clone(), span: vspan() }],
        };
        assert_eq!(copy.in_place_destination(), Some(&d));
        let reinstate = Op::Reinstate {
            doc: d.clone(),
            at: vpos(),
            runs: vec![ShotRun {
                origin: src.clone(),
                run: Run::new(addr(&[1, 0, 1, 0, 2, 0, 1, 1]), Nat::from(1u32))
                    .expect("a content run"),
            }],
        };
        assert_eq!(reinstate.in_place_destination(), Some(&d));
        assert_eq!(reinstate.write_consult(), WriteConsult::AfterOwnershipOf(vec![&d]));
        assert_eq!(reinstate.source_arguments(), vec![&src], "the origin it is consulted on");
    }

    /// PUB-6.6: the third pairing `consult_write` depends on.
    ///
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
            successor: SuccessorSpec { from: vec![].into(), to: vec![].into(), ty: SlotArg::Addrs(vec![]) },
            d_s: doc(),
            d_a: doc(),
        };
        assert_eq!(
            edit.link_address_arguments(),
            Some((vec![&old], RejectCode::OriginalNotResident))
        );
    }
}
