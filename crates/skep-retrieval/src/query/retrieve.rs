//! §A The two operations that open M4, in the one impl block bounded by
//! `HasContent`: RETRIEVEV (ASN-0115), which resolves and then dereferences
//! and is the one operation that delivers bytes, and the line read, which
//! asks M4 its line-break counts and reads no value.

use std::sync::Arc;

use num_traits::{One, ToPrimitive, Zero};
use skep_address::{ordinal, Address, Nat};
use skep_arrangement::{ordinal_vspan, reading_surface, Run, VPos};
use skep_content::{ContentStore, HasContent, Piece};
use skep_namespace::M3State;

use super::{run_origin, Query, RetrievalWorld};
use crate::budget::{Count, OverBudget, MAX_DELIVERY_ITEMS, MAX_WALK_STEPS};
use crate::error::{LinesError, RetrieveError};
use crate::types::{Delivery, DeliveryItem, Flagged, LineNumbers, Spec};
use crate::vspan::{gate_vspan, walk_price, Subspace};

/// Returns whether a run of `origin` is withheld from the reader.
///
/// The one masking test both operations here apply to a run (PUB-6.41): its
/// origin is no registered document, or `readable` refuses it. The registry
/// is asked first, since `readable` is contracted to registered documents
/// (PUB-6.37), so an unregistered origin is withheld with the predicate
/// unconsulted.
fn withheld(m3: &M3State, origin: &Address, readable: &dyn Fn(&Address) -> bool) -> bool {
    !m3.is_registered_document(origin) || !readable(origin)
}

/// Returns the line breaks among `run`'s first `k` positions.
///
/// `below` is M4's count below the run's first address. The first `k`
/// positions of a run are a run, whose reach is the address `k` positions
/// in, so the count is one read of M4 and the address arithmetic stays M5's.
///
/// **Precondition.** `k` is at most the run's width.
///
/// # Panics
///
/// Panics if M5 refuses a positive-width run at a start a run already
/// stands at, which no input reaches.
fn breaks_within(content: &ContentStore, run: &Run, below: u64, k: &Nat) -> u64 {
    if k.is_zero() {
        return 0;
    }
    let first_k = Run::new(run.i_start().clone(), k.clone())
        .expect("a run's start opens a run of any positive width");
    content.line_breaks_before(&first_k.reach()) - below
}

/// RETRIEVEV and the line read alone open M4, so they alone name it:
/// `HasContent` is this impl block's bound and nowhere else's, which is what
/// makes the other six operations' value-blindness structural rather than a
/// rule their cards ask a maintainer to keep — and `tests/it/tidy.rs` holds
/// it, failing on any other file under `src/` that names the content store.
impl<W: RetrievalWorld + HasContent> Query<'_, W> {
    /// RETRIEVEV (ASN-0115) — resolve, then dereference, in order (the
    /// load-bearing two-phase factoring): resolve V-spans to I-addresses
    /// (M5), then fetch values (M4, content) or pass the address through
    /// (links — never reads M4).
    ///
    /// The arrangement resolved is each named document's READING SURFACE
    /// (crate doc, *Which arrangement an operation answers from*): the gate
    /// runs on the address named, the surface answers, and the delivery is
    /// reported under the name given.
    ///
    /// Rejects the WHOLE request on any malformed spec (well-formedness
    /// precondition); gaps / depth-incompatible (`#start ≥ 3`) / foreign or
    /// empty subspaces degrade to silent empty contributions and are never
    /// refused for what they name (R6 — M5's defensive resolution yields
    /// fewer-or-zero runs), and a spec-set of them is answered whatever its
    /// size, a spec that yields nothing reading no run.
    /// Empty spec-set ⇒ `Ok(empty)`. Delivery is one `Content` item per
    /// atom position and one `Bytes` item per maximal run of single-byte
    /// positions of every DELIVERED run (R3 exactness position for position,
    /// R8 no-dedup; [`DeliveryItem`] says how the wire keeps it) — and one
    /// [`DeliveryItem::Withheld`] per run whose origin is not a registered
    /// document, occupying that run's `width` positions (PUB-1.57): the one
    /// masking the identity predicate leaves, since the predicate is
    /// contracted to registered documents (PUB-6.37) and RES-162's unheld
    /// origin — a mirror that never held the draft a published window names —
    /// is a run this form can meet. Per-spec concatenation in submitted order
    /// (R5), ascending-V within, no merge, no global sort.
    ///
    /// WHICH REFUSAL SPEAKS. The gate checks the spec-set in SUBMITTED ORDER
    /// and reports the FIRST faulty spec, whatever the kind of its fault;
    /// within one spec the registry check precedes the span gate. So
    /// `MalformedSpec { index: i }` and `DocNotRegistered` both carry a
    /// promise about the specs before the offending one: a caller may rely on
    /// specs `0..i` being registered documents with well-formed spans, and
    /// repair a batch from the offending spec onward rather than re-checking
    /// it whole.
    /// And it completes over the whole spec-set before any spec is
    /// walked, so a gate fault always outranks `TooManyItems`.
    ///
    /// COST IS THE ANSWER'S SIZE, AND THE ANSWER'S SIZE IS SET BY STORED STATE
    /// THE REQUEST DOES NOT SEE. The delivery is at most `Σᵢ |σᵢ ∩ [1, n_Sᵢ]|`
    /// items, a withheld run being one item for its `width` positions; each
    /// content item is one `Arc` clone, never a byte copy, but one item
    /// nonetheless — and `n_S` is VIRTUAL: M5 caps the runs a placing request
    /// stores and no position count, so a few COPYs transcluding a document
    /// onto itself make one spec name more positions than the store holds
    /// values. So the delivery is held to the delivery budget,
    /// [`MAX_DELIVERY_ITEMS`] (`TooManyItems`, refused AS THE DELIVERY IS
    /// PRODUCED: a withheld run as one item, a delivered run's positions as one
    /// batch before the first is expanded). That is the whole of what the
    /// spec-set's resolution reads: each spec reaches its span by a descent of
    /// the run-list and reads from there the runs it yields, every one an
    /// item or more of the delivery (crate doc, *What M6 refuses for size*).
    /// It is a REFUSAL, never a truncation: R3
    /// forbids delivering fewer, R5 reordering into something cheaper and R8
    /// collapsing the repeats, and a refused request gets no delivery at all,
    /// so all three hold verbatim for every delivery answered. A caller
    /// wanting more splits the spec-set or narrows its spans.
    pub fn retrieve_v(&self, specs: &[Spec]) -> Result<Delivery, RetrieveError> {
        // The masked form under the all-true predicate: its only `Withheld`
        // items are unregistered-origin runs (PUB-6.37; RES-162). M10's
        // dispatch calls [`Query::retrieve_v_masked`] with the predicate it
        // threads in per request; this delegate serves the callers that read
        // for no principal — this crate's suite and skep-engine's cross-store
        // lifecycle suite — unchanged.
        self.retrieve_v_masked(specs, &|_| true)
    }

    /// RETRIEVEV with the per-origin consult (PUB-6.41; PUB round 2, lane 3.3,
    /// §2/§4): the same delivery, but each RUN is tested against its origin
    /// DOCUMENT (M1's `document_of` of the run's I-start, which block
    /// uniformity makes the origin of every position in it) through
    /// `readable`, and a masked run — its origin unreadable to the reading
    /// principal, OR unregistered — is emitted as [`DeliveryItem::Withheld`]
    /// AT ITS OWN POSITION rather than delivered (PUB-6.58: one item per run,
    /// never coalesced). The NAMED document's own readability is the caller's
    /// doc-argument consult (PUB-6.12), run pre-dispatch; this masks only the
    /// ORIGINS its runs window. M6 decides no readability here — it applies
    /// the predicate M10 threads in, at the run, which is the granularity the
    /// delivery has.
    ///
    /// THE PREDICATE'S OWN PRECONDITION IS DISCHARGED HERE. `readable` is
    /// contracted to REGISTERED documents (PUB-6.37, the rule
    /// `reading_surface` is under too), and the gate established that of the
    /// documents NAMED, not of the origins their runs window; so each origin
    /// is checked against the registry before the predicate is asked, and one
    /// that is not a registered document — reachable as RES-162's unheld
    /// origin, the mirror that never held the draft a published window names
    /// — takes the withheld arm directly, the predicate unconsulted. The
    /// predicate is consulted only after the gate has
    /// passed the whole request — a request refused at it consults it of
    /// nothing, and one refused for the size of its delivery has consulted it
    /// of every run resolved up to AND INCLUDING the one that crossed the
    /// budget, each asked before it is counted — once per resolved run with a
    /// registered origin, of that run's origin document alone, which may be a
    /// version address. The document NAMED is asked about only where it is
    /// itself some run's origin — as its own content is, PUB-6.41 testing
    /// every run against its origin — and never on its own account, its
    /// readability being M10's doc-argument consult (PUB-6.12).
    pub fn retrieve_v_masked(
        &self,
        specs: &[Spec],
        readable: &dyn Fn(&Address) -> bool,
    ) -> Result<Delivery, RetrieveError> {
        let w = self.0.world();
        let (m3, m5, content) = (w.m3(), w.m5(), w.content());
        // Gate the whole request first — VSpec WELL-FORMEDNESS is the only
        // in-model failure (ASN-0115). A well-formed but depth-incompatible
        // (#start ≥ 3) spec is NOT rejected here (R6).
        for (index, spec) in specs.iter().enumerate() {
            if !m3.is_registered_document(&spec.doc) {
                return Err(RetrieveError::DocNotRegistered(spec.doc.clone()));
            }
            gate_vspan(&spec.span)
                .map_err(|fault| RetrieveError::MalformedSpec { index, fault })?;
        }
        let over = |OverBudget| RetrieveError::TooManyItems;
        let mut out = Vec::new();
        // The delivery budget, counted as the delivery is produced
        // (MAX_DELIVERY_ITEMS' card).
        let mut items_produced = Count::against(MAX_DELIVERY_ITEMS);
        for spec in specs {
            // Concatenate per spec, IN ORDER (R5) — no global sort. Classify
            // ONCE per spec, because the answer is constant over the spec's
            // positions. Gated on the address named above; the surface
            // answers.
            let sub = Subspace::of_span(&spec.span);
            let surface = reading_surface(m3, &spec.doc);
            for run in m5.iter_resolve(&surface, &spec.span) {
                // The per-origin consult (PUB-6.41), asked once per run: the
                // run's origin DOCUMENT, tested BEFORE the run is expanded.
                // The registry check first is the predicate's precondition
                // (PUB-6.37: registered documents only), M6's to discharge at
                // this site because the gate saw the named document and not
                // the origin; an unregistered origin (RES-162) is withheld
                // without the predicate being asked. Either way the WHOLE run
                // is masked as one withheld item at its own position — never
                // coalesced with a neighbour (PUB-6.58).
                let origin = run_origin(&run);
                if withheld(m3, &origin, readable) {
                    items_produced.admit(1).map_err(over)?;
                    out.push(DeliveryItem::Withheld { origin, width: run.width().clone() });
                    continue;
                }
                // The run's positions as ONE batch, admitted before the first
                // is expanded, so a run wider than what the budget has left is
                // refused whole; a width past `usize` is past any budget. The
                // budget counts POSITIONS, as it did when every position was
                // an item: a byte-run item below stands for its run's width.
                items_produced
                    .admit(run.width().to_usize().unwrap_or(usize::MAX))
                    .map_err(over)?;
                match sub {
                    // Per maximal PIECE of the run's I-extent, ascending V
                    // (R3) — no dedup (R8): M4's one run read, one predecessor
                    // lookup and a forward walk, lends each piece borrowed —
                    // a run of single-byte values inside one stretch as ONE
                    // `Bytes` item (one allocation per piece), a value as
                    // `Content` (an `Arc` clone). S3★ — an arranged content
                    // position has an M4 value — is M5's to keep, on its
                    // WRITE path, at every operation that places a content
                    // run; `covered`, asked of the walk after `by_ref()`, is
                    // where a regression in any of them would surface.
                    Some(Subspace::Content) => {
                        let mut pieces = content.pieces(run.i_start().tumbler(), run.width());
                        for piece in pieces.by_ref() {
                            out.push(match piece {
                                Piece::Bytes(bytes) => DeliveryItem::Bytes(Arc::from(bytes)),
                                Piece::Value(v) => DeliveryItem::Content(v.clone()),
                            });
                        }
                        assert!(
                            pieces.covered(),
                            "S3★: an arranged content position has a stored value"
                        );
                    }
                    // Per active position: the link reference IS the address
                    // — never reads M4; the run answers for its own positions,
                    // in the owned form, since the resolution hands the run
                    // over and it outlives only this walk.
                    Some(Subspace::Link) => {
                        for a in run.into_addrs() {
                            out.push(DeliveryItem::Ref(a));
                        }
                    }
                    // UNREACHABLE for an ACTIVE position: S3★-aux confines
                    // every bound V-position to subspace ∈ {s_C, s_L}, and the
                    // resolution yields NO runs for any other start subspace,
                    // so executing here means upstream corruption. PANIC IN
                    // ALL PROFILES — one read-path policy with the S3★
                    // assertion above: silently dropping an active position
                    // would violate exactness (R3).
                    None => {
                        unreachable!("active V-position must be content or link subspace (S3★-aux)")
                    }
                }
            }
        }
        Ok(Delivery(out)) // empty spec-set ⇒ Ok(Delivery(vec![]))
    }

    /// Returns the line read's numbers, as a reader of everything counts.
    ///
    /// It is [`Query::line_numbers_masked`] under the all-true predicate, so
    /// the one run it withholds is a run whose origin is no registered
    /// document. It serves the callers that read for no principal.
    ///
    /// # Errors
    ///
    /// As [`Query::line_numbers_masked`].
    pub fn line_numbers(
        &self,
        doc: &Address,
        positions: &[VPos],
        lines: &[Nat],
    ) -> Result<LineNumbers, LinesError> {
        self.line_numbers_masked(doc, positions, lines, &|_| true)
    }

    /// Returns the line of each position, each line's start and the count.
    ///
    /// The line read answers three questions of one document's content, in
    /// numbers alone: which line each of `positions` lies on, where each of
    /// `lines` starts, and how many lines the document holds.
    /// [`LineNumbers`] states the rule that counts a line.
    ///
    /// The arrangement numbered is `doc`'s reading surface (crate doc, *Which
    /// arrangement an operation answers from*): the gate runs on the address
    /// named, the surface answers, and a position is a position of the
    /// surface.
    ///
    /// **Masking** (PUB-6.41). Each run is tested as RETRIEVEV tests it,
    /// against its origin document, and a withheld run counts no line break.
    /// Its width is no secret, a delivery showing it, but where its line
    /// breaks fall would be, so the numbers are the ones the reader counts in
    /// the delivery it is served, and each carries the flag [`Flagged`]
    /// states. The named document's own readability is M10's doc-argument
    /// consult (PUB-6.12). The predicate is consulted only after the gate and
    /// the walk budget have passed the request, once per run of a registered
    /// origin.
    ///
    /// **Cost** (SP-23). The gate reads the surface's content count, which
    /// M5 reads off its run-list's root. The walk then pulls each content run once from
    /// M5's lazy resolution, whatever the lists hold, and asks M4 two counts
    /// of each run it may read, one more for each listed position and each
    /// listed line, and one for the document's last position. The lists are
    /// each sorted once, by what they ask, and the read holds them, the
    /// answers and the run in hand. It bounds neither list: capping them is
    /// the transport's.
    ///
    /// # Errors
    ///
    /// In this order, the first that holds answering:
    ///
    /// 1. [`LinesError::DocNotRegistered`] where `doc` is no registered
    ///    document.
    /// 2. For each position in request order,
    ///    [`LinesError::NotContentSubspace`] where it names any subspace but
    ///    the content one, then [`LinesError::RangeNotPresent`] where its
    ///    ordinal is zero or past the content count plus one.
    /// 3. [`LinesError::TooManyItems`] where the surface's content runs are
    ///    priced past the walk budget, before the first is pulled.
    ///
    /// # Panics
    ///
    /// Panics if M4's two line reads disagree about a run's line breaks, if
    /// M5 refuses a run of the first positions of one it resolved, or if the
    /// walk passes a position the gate admitted: states no input reaches.
    pub fn line_numbers_masked(
        &self,
        doc: &Address,
        positions: &[VPos],
        lines: &[Nat],
        readable: &dyn Fn(&Address) -> bool,
    ) -> Result<LineNumbers, LinesError> {
        let w = self.0.world();
        let (m3, m5, content) = (w.m3(), w.m5(), w.content());
        if !m3.is_registered_document(doc) {
            return Err(LinesError::DocNotRegistered);
        }
        // Gated on the address named; every arrangement read below is the
        // surface's.
        let surface = reading_surface(m3, doc);
        let one = Nat::one();
        let count = Subspace::Content.count(m5, &surface);
        let past_end = &count + &one;
        for (index, at) in positions.iter().enumerate() {
            if !at.is_content() {
                return Err(LinesError::NotContentSubspace { index });
            }
            if at.ordinal.is_zero() || at.ordinal > past_end {
                return Err(LinesError::RangeNotPresent { index });
            }
        }
        // The surface's whole content extent, the one span the read walks:
        // `None` where the surface holds no content, which walks nothing.
        let extent = ordinal_vspan(Subspace::Content.anchor(), count);
        // One walk, priced before its first run is pulled: the extent
        // holds every content run, so its price is the surface's run count
        // (MAX_WALK_STEPS' card).
        let mut runs_priced = Count::against(MAX_WALK_STEPS);
        runs_priced.admit(walk_price(m5, &surface)).map_err(|OverBudget| LinesError::TooManyItems)?;

        // Each list in the order the walk meets what it asks, answered into
        // its request-order slot as the walk passes it.
        let mut by_ordinal: Vec<usize> = (0..positions.len()).collect();
        by_ordinal.sort_by(|&a, &b| positions[a].ordinal.cmp(&positions[b].ordinal));
        let mut by_line: Vec<usize> = (0..lines.len()).collect();
        by_line.sort_by(|&a, &b| lines[a].cmp(&lines[b]));
        let mut asked_positions = by_ordinal.into_iter().peekable();
        let mut asked_lines = by_line.into_iter().peekable();
        let mut position_lines: Vec<Option<Flagged<Nat>>> = vec![None; positions.len()];
        let mut line_starts: Vec<Option<Flagged<VPos>>> = vec![None; lines.len()];

        // Line 0 names no line and is answered none. Line 1 opens at the
        // first run's first position, as every later line opens one position
        // past a line break: `opening` holds the asked lines whose line break
        // the walk has passed and whose first position it has yet to reach.
        while asked_lines.next_if(|&i| lines[i].is_zero()).is_some() {}
        let mut opening: Vec<usize> = Vec::new();
        while let Some(i) = asked_lines.next_if(|&i| lines[i] == one) {
            opening.push(i);
        }
        // The V-ordinal the run in hand opens at, the line breaks counted
        // below it, and whether a withheld run lies at or below it.
        let mut opens_at = Nat::one();
        let mut breaks = Nat::zero();
        let mut masked = false;
        // The run the walk last pulled, where it may be read and holds a line
        // break, with M4's count below its start and its own count: what the
        // end rule asks once the walk is over.
        let mut last: Option<(Run, u64, u64)> = None;
        for run in extent
            .iter()
            .flat_map(|extent| m5.iter_resolve(&surface, extent))
        {
            let reach = &opens_at + run.width();
            // A withheld run lies at its own first position, so the flag
            // moves before anything at or past that position is answered.
            let hidden = withheld(m3, &run_origin(&run), readable);
            masked |= hidden;
            for i in opening.drain(..) {
                let number = VPos::content(opens_at.clone());
                line_starts[i] = Some(Flagged { number, masked });
            }
            // M4's count below the run's start, and the run's own line
            // breaks: none of either where the run is withheld.
            let below = (!hidden).then(|| content.line_breaks_before(run.i_start().tumbler()));
            let own = below.map_or(0, |below| content.line_breaks_before(&run.reach()) - below);
            while let Some(i) = asked_positions.next_if(|&i| positions[i].ordinal < reach) {
                // A position inside a withheld run is on the line the run
                // starts on.
                let within = below.map_or(0, |below| {
                    breaks_within(content, &run, below, &(&positions[i].ordinal - &opens_at))
                });
                let number = &breaks + Nat::from(within) + &one;
                position_lines[i] = Some(Flagged { number, masked });
            }
            let counted = &breaks + Nat::from(own);
            // Line `N` opens one position past line break `N − 1`. Every
            // asked line still waiting has its line break past `breaks`, so
            // the ones at or below `counted` have theirs in this run, at the
            // zero-based place `N − 2 − breaks` of the run's own.
            while let Some(i) = asked_lines.next_if(|&i| lines[i] <= &counted + &one) {
                let nth = u64::try_from(&lines[i] - &one - &one - &breaks)
                    .expect("a place below one run's u64 count of line breaks");
                let at = content
                    .nth_line_break_from(run.i_start().tumbler(), nth)
                    .expect("a run holds each line break M4 counts between its ends");
                let start = &opens_at + (ordinal(&at) - ordinal(run.i_start().tumbler())) + &one;
                if start < reach {
                    let number = VPos::content(start);
                    line_starts[i] = Some(Flagged { number, masked });
                } else {
                    // The line break is the run's last position: the line
                    // opens at the next run's first, and takes its flag there.
                    opening.push(i);
                }
            }
            breaks = counted;
            opens_at = reach;
            last = below.filter(|_| own > 0).map(|below| (run, below, own));
        }

        // The end. A position still asked is the one past the last, where an
        // insert would land. A line still asked names none: its line break is
        // the document's last position, or the document holds too few.
        for i in asked_positions {
            let number = &breaks + &one;
            position_lines[i] = Some(Flagged { number, masked });
        }
        let ends_in_a_line_break = last.is_some_and(|(run, below, own)| {
            own - breaks_within(content, &run, below, &(run.width() - &one)) == 1
        });
        let unbroken_tail = opens_at > one && !ends_in_a_line_break;
        let number = if unbroken_tail {
            &breaks + &one
        } else {
            breaks
        };
        Ok(LineNumbers {
            positions: position_lines
                .into_iter()
                .map(|line| line.expect("the gate admits only positions the walk answers"))
                .collect(),
            lines: line_starts,
            count: Flagged { number, masked },
        })
    }
}
