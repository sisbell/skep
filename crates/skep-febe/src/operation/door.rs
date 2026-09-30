//! The READABILITY DOOR: the one read predicate a front door answers through
//! — its world's own or a supplied [`ReadPredicate`], bound once per request
//! by [`OperationSurface::readable_by`] — the two consults it drives
//! ([`consult_read`], [`consult_write`]), the link-address absence rule
//! ([`home_readable`]), and the visibility class lent to a store for one
//! write ([`OperationSurface::visible_to`]).
//!
//! `OperationSurface::readable`, where a supplied predicate and the world's
//! own meet, is private to this module. Everything else — the two dispatch
//! tables, and through them every masking reader in M6 and M8 — reaches the
//! predicate through `readable_by` or `visible_to`, so a front door answers
//! ONE predicate by construction rather than by review.
//!
//! The door is a child of the lifecycle rather than a card beside it because
//! the two share the proven-bound principal: `consult_write` rides the
//! lifecycle's [`WriteCtx`], which a child sees without widening, and its
//! precondition — the predicate built from that principal and from nothing
//! else — is stated against it.

use skep_address::{document_of, Address};
use skep_arrangement::published_target;
use skep_namespace::{M3State, PrincipalId};

use super::{OperationSurface, WriteCtx};
use crate::op::{Op, WriteConsult};
use crate::reject::{rejection, FaultSite, RejectCode, Rejection};
use crate::world::FebeWorld;

/// THE read predicate, as the transport may SUPPLY it (PUB-1.31; PUB-6.39's
/// one-per-request shape; PUB round 2, lane 3.3 — the predicate widened from
/// the publish shot's source gate to the whole read surface): may `principal`
/// (`None` = the GUEST) read the document `doc`? Consulted by every read arm
/// — the doc-argument consult, the per-run withheld arm, the result-set
/// filter — and by the publish composite's source gate (PUB-6.23, PUB-8.1's
/// second constraint).
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
/// Absent ([`OperationSurface::new`] alone), M10 answers the world's own
/// [`ReadableWorld::readable`], which is the live daemon's case: a read arm
/// off the ONE snapshot it pins per request, so the answer and the `as_of` it
/// is stamped with stand on one committed state, and the publish composite's
/// source gate over the working world of the shot's own transaction, which M5
/// hands it. Supplied ([`OperationSurface::with_read_predicate`]), it
/// OVERRIDES the world the predicate is evaluated over — what a HISTORICAL
/// read needs: `/op-at N` answers the N-world's content through the HEAD's
/// exception set and grant set (PUB-6.48), so the daemon's throwaway front
/// door over the reconstructed world answers through a predicate closed over
/// one head snapshot. `Send + Sync + 'static`, since the front door is shared
/// across a transport's worker pool.
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
    /// publish shot alike, goes through here, so a front door answers ONE
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
    /// door pinned — and threaded to everything that asks.
    ///
    /// Its consumers are the whole of the door and of the masking below it:
    /// the two consults ([`consult_read`], [`consult_write`]), the
    /// link-ADDRESS absence rule ([`home_readable`]), M6's per-run withheld
    /// arm and container filter, M8's result-set filters, and the
    /// edition-claim home rule. Each receives an opaque
    /// `Fn(&Address) -> bool` and never the principal behind it (the STRUCK
    /// second form), so the answer and the `as_of` it is stamped with stand
    /// on one committed state and no consumer can ask a second question.
    ///
    /// `None` is the GUEST — a session that resolves to no principal, which
    /// on the read path is a mask and never a refusal.
    ///
    /// HOW OFTEN IT IS ASKED falls into two classes, and only one of them is
    /// request-sized. The two consults and the link-address rule ask once per
    /// NAMED argument of the request, a count the transport's parser caps.
    /// M6's per-run mask and M8's result-set filters ask once per RESULT ROW
    /// — a count set by stored state, capped by nothing, and reached by an
    /// unauthenticated guest through the FTT descriptor family, which names
    /// no document at all and whose unconstrained form matches every active
    /// link in the store. Each call projects its address to the document
    /// that owns it, one allocation per component. M10 is what creates the
    /// second class, by threading this one predicate down into the readers,
    /// so it is where the class is named: a supplier sizing its own work
    /// against a per-argument figure has priced only the first.
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
    /// PRINCIPAL, closed here and lent to the store driver for the one write.
    /// The ONE closure every such gate is handed: M7's value-keyed dedup and
    /// idempotency gates on the five link writes, and M5's per-ORIGIN source
    /// gate on the publish shot (PUB-6.23). Each evaluates it INSIDE the
    /// write transaction, over the WORKING world it hands the closure —
    /// never over the snapshot a read pins. Where this front door carries a
    /// supplied
    /// [`ReadPredicate`] (the historical door), that is what answers here too
    /// — one front door, one predicate — and the world M7 hands in is then not
    /// read, the head snapshot the predicate closed over being the world it
    /// reads; such a door dispatches no write today, and the case is the
    /// round's escalated one.
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
/// It runs AFTER registration — an unregistered document is fail-open
/// readable (PUB-7.5) and defers to its store's own `*NotRegistered` —
/// and BEFORE any other validation, so a published document never answers
/// withheld and a private one never reaches a refusal that would describe
/// it. The complementary rules of the read door live with the answers
/// they shape rather than here: the link-ADDRESS absence rule at the two
/// arms it governs, and the result-set filter inside each reader that
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
/// for either should find both. Both are functions OVER the predicate rather
/// than methods that fetch it, so a door's policy cannot come to answer a
/// predicate other than the one its request was built with.
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

/// THE WRITE SIDE'S CONSULT (PUB round 2, lane 3.3c; PUB-6.23, PUB-6.24,
/// PUB-6.36 slot 6, PUB-6.38): the door's pre-dispatch check on a write
/// that READS a document before it writes — `copy`'s sources, `version`'s
/// `d_src`, the RESOLVE-form slots of `make_link` and `edit_link` — and
/// the LINK-ADDRESS rule on the links a write validates by address
/// (PUB-6.6: `edit_link.original`, `assert_sup.old`/`new`). Consulted
/// through `readable`, the ONE predicate this request was built with
/// ([`OperationSurface::readable_by`]) — the same binding every read arm
/// answers, so one front door answers one predicate — and, wherever the door
/// judges the write at all, BEFORE the store call (or the EDITLINK successor
/// build) that would read the source's arrangement.
///
/// RETURNS whether the door JUDGED the write: `true` where it ran past the
/// deferral below and every rule it owns passed; `false` where it judged
/// nothing — an op it does not consult ([`WriteConsult::NotTaken`]), or one
/// whose destination's own gate would refuse, so the store speaks first. A
/// `false` binds the dispatch that follows: the write's sources went
/// unconsulted, so nothing built from their arrangements before the store
/// call may speak — no verdict whose answer a source the caller may not read
/// could decide. That is why the EDITLINK successor build takes it
/// (`successor_link`'s `judged`).
///
/// PRECONDITION: `readable` is built from `wc.principal`, off the same
/// snapshot `m3` is read from, and from nothing else. The door DERIVES no
/// principal of its own — `wc` is the proven-bound one — so a predicate
/// built from some other principal would judge this write's sources for a
/// caller who is not making it. The one call site builds it on the line
/// above, which is why the two travel together.
///
/// ORDER, as PUB-6.36 pins it and PUB-6.38 places it: slot 1, the
/// DESTINATION's `not_owner`, stands AHEAD of this consult. The store
/// words that verdict inside its own transaction, so the door realizes
/// the order by DEFERRING: the consult runs only where the destination's
/// own gate would pass — registered, and ω-owned by the caller, asked
/// through the store's one spelling of ω (`Caller::is_owner`, M5's, which
/// is M3's `is_effective_owner`) — and where it would not, nothing here
/// speaks, nor anything built from the sources it left unconsulted (the
/// `false` it returns), and the store answers its own `doc_not_registered` /
/// `home_not_registered` / `not_owner`. A session that may not write here
/// is never told whether it may read there (PUB-6.43's ground). M10 words
/// no ownership verdict of its own; it only declines to judge a source
/// ahead of one. Registration of the SOURCE stands ahead too (PUB-6.37),
/// by the predicate's own construction: an unregistered address is
/// fail-open readable (PUB-7.5), so it passes here and takes the store's
/// `source_not_registered` — a withheld answer is only ever a REGISTERED
/// private document.
///
/// SLOT 5 AHEAD OF SLOT 6, and how this door reaches it (PUB round 2,
/// lane 4.2, F3; PUB-6.36, PUB-2.11, PUB-6.38): the model's refusals are
/// evaluated INSIDE the store transaction (owner ruling D2b), which once
/// left one cell the door could not order — a source the caller may not
/// read, copied into a PUBLISHED destination the caller owns — answered
/// `withheld` where PUB-6.36 has slot 5 speak first. The door now
/// PRE-EVALUATES the in-place advance refusal itself, between the
/// deferral and the consult, over the class [`Op::in_place_destination`]
/// names, by ASKING M5's own rule, [`published_target`], on a destination
/// the deferral has just found registered (PUB-6.37): M5 publishes that
/// read so a door pre-evaluating the refusal runs the predicate the store
/// enforces instead of restating it, and only the ORDERING is M10's. So
/// the answer is `published_target` byte-identically to the store's (same
/// code, disposition, no site, no detail), and it stays so through any
/// later revision of the rule. A session refused the write is never told
/// whether it may
/// read the source (PUB-6.43's ground), the store's own refusal is
/// simply unreached on that cell, and every other cell answers as before:
/// where the destination is a draft the check is silent, and where the
/// store would have refused `published_target` it still does, one layer
/// earlier and in the same bytes. The versionless sibling never meets the
/// consult: `private_source_versionless` fires only on a source the
/// caller OWNS, which the subtree clause makes readable, so no source is
/// both unreadable and versionless. M5's own refusal stands untouched.
///
/// The two verdicts this consult can speak are the read side's own,
/// wire-identical to what the store would say of the same address in a
/// world without the draft: `withheld` — `reorder`, `site.addr` the
/// FIRST unreadable source in declaration order (PUB-6.4,
/// [`Op::source_arguments`]), no `detail` (PUB-8.5) — and, for a link
/// homed in a document the caller may not read, the op's OWN
/// never-deposited answer (`original_not_resident`,
/// `endpoint_not_resident`), never a withheld that confirms a
/// draft-homed link exists (PUB-6.6). `document_of(a)` is address
/// arithmetic — no read (PUB-6.38). Within `edit_link` the link-address
/// argument speaks first: `original` is declared ahead of `successor`,
/// and the store's own residence check precedes its slot checks.
/// `nullify.target` takes no rule here — PUB-6.9's ω-first order and the
/// slot-5 nullify-class refusals govern it (lane 3.5).
///
/// STALENESS, since `readable` and `m3` are read off a PRIOR snapshot and
/// not the base the write commits on. For four of the five source-reading
/// writes — `copy`, `version`, `make_link`, `edit_link` — this door is the
/// SOLE enforcement of PUB-6.23: their stores carry no `withheld` verdict,
/// so what is decided here is what is enforced, and it is decided at that
/// snapshot rather than at the operation's linearization point. Most of
/// what the door reads survives the gap because its state is MONOTONE, and
/// can therefore only produce a false REFUSAL and never a wrong admission:
/// the registry only grows (every `M3Rec` variant is an insert),
/// publication never transitions (PUB-1.9), so `published_target` cannot go
/// stale at all, and ω is stable because a fresh delegation cannot reassign
/// an allocated prefix. A GRANT is the clause that is not monotone — it is
/// revocable — so a source readable here may be unreadable when the write
/// commits, and the gap is REQUEST-SIZED: the consult itself, up to three
/// full slots of specs, and for `edit_link` the whole successor build
/// besides. What bounds the consequence is not this door: the arrangement
/// a late `copy` or `version` produces reads back masked per run by origin
/// (PUB-6.41), and the I-extents a late `make_link` deposits are not
/// secret (PUB-6.24). Closing the gap means the shape `publish` already
/// has — the visibility class evaluated inside the store's own transaction
/// (`Vstream::publish`) — which is those four stores' signatures to
/// change, not this door's.
///
/// [`OperationSurface::readable_by`]: OperationSurface::readable_by
pub(super) fn consult_write(
    wc: &WriteCtx,
    op: &Op,
    m3: &M3State,
    readable: &dyn Fn(&Address) -> bool,
) -> Result<bool, Rejection> {
    let kind = op.kind();
    let WriteConsult::AfterOwnershipOf(destinations) = op.write_consult() else {
        return Ok(false); // no source and no link-address argument (see the table)
    };
    // Slot 1 ahead of slot 6: defer to the store wherever the
    // destination's own gate would refuse.
    let caller = wc.caller();
    if !destinations.iter().all(|d| m3.is_registered_document(d) && caller.is_owner(m3, d)) {
        return Ok(false);
    }
    // Slot 5 ahead of slot 6 (lane 4.2, F3): the model's in-place advance
    // refusal on this write's destination — PUB-2.11, asked of M5's own
    // `published_target` on a destination the deferral has just found
    // registered (PUB-6.37), so the door runs the rule the store enforces
    // rather than a copy of it — BEFORE any source is consulted, so the
    // one cell where both apply answers `published_target`, never
    // `withheld`. `copy` is the only member of the class that is also
    // consulted; the others never reach here (`in_place_destination`).
    if let Some(in_place) = op.in_place_destination() {
        if published_target(m3, in_place) {
            return Err(rejection(kind, RejectCode::PublishedTarget));
        }
    }
    // §2 — the link-address rule on writes (PUB-6.6): the op's own absence
    // answer, exactly as for an address no link occupies. Two arms, and
    // they stay HERE rather than joining the request-shape lists on `Op`:
    // what they decide is not an address list but WHICH never-deposited
    // code answers, which is this door's lifecycle vocabulary.
    match op {
        Op::EditLink { original, .. } if !home_readable(original, readable) => {
            return Err(rejection(kind, RejectCode::OriginalNotResident));
        }
        Op::AssertSup { old, new, .. }
            if !home_readable(old, readable) || !home_readable(new, readable) =>
        {
            return Err(rejection(kind, RejectCode::EndpointNotResident));
        }
        _ => {}
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
    Ok(true)
}
