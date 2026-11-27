//! §The publish shot's values (PUB-2.33, PUB-8.1).
//!
//! They are its request — the client-supplied I-address runs with the origin
//! each windows, the base the staged draft was taken from, the stretches of
//! that base the runs replace where the shot names its change and not its
//! whole arrangement ([`ShotStretch`], judged by request arithmetic alone,
//! [`Shot::stretch_fault`]), the drafts whose
//! identity the shot re-mints (the rendering `draft` and the family's other
//! drafts `also` names — THE NAMED DRAFTS, [`Shot::named_drafts`], the family
//! rule's one spelling with [`Shot::is_draft_native`]), and the whole shot,
//! the composite's arrangement input, taken from the client and never read
//! off any draft's arrangement at commit — the runs it re-inserts, the
//! count of their distinct positions and their grouping by named draft
//! ([`Shot::reinserted_runs`], [`Shot::reinserted_values`],
//! [`Shot::reinserted_runs_by_draft`]; the count of the units those
//! positions are staged as reads the content store and sits with the
//! staging it splits like, `ops/publish.rs`'s `Shot::reinserted_units`), and
//! its address form on both sides of the commit: [`Shot::address_form`] for
//! the
//! request, [`M5State::address_form_of`] for the member it minted, and
//! [`run_origin_document`], the classifier each of them asks. The two sides
//! of the address form must agree as the signed body spells them — window for
//! window, and value for value between — so they are stated in one file.
//!
//! Three values rather than loose arguments, for the reason [`crate::VPos`]
//! and [`crate::VSpec`] are values: the pieces of a shot travel together, and
//! a `base` handed over without the extent its copy took would be a base the
//! composite cannot compose against (PUB-2.42).

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use num_traits::One;
use skep_address::{content_subspace, document_of, Address, Nat};

use crate::chain::trunk_of;
use crate::run::Run;
use crate::run_list::extend_or_push_run;
use crate::run_union::RunUnion;
use crate::state::{M5State, Stretch};

/// Returns a supplied run's origin document.
///
/// It is the trunk (PUB-2.15) of the document the run's addresses were
/// minted under, `document_of` of its start and then `trunk_of` — provided
/// the start is a content element; `None` for a link element or an address
/// with no document. What the source gate asks about and `Withheld` names
/// (PUB-8.4's `site.addr`), what a stated `origin` must project to — a shot
/// run's and a REINSTATE run's alike — and what classes a run, in the
/// address form on both of its sides ([`Shot::address_form`],
/// [`M5State::address_form_of`]) and among the runs a shot re-inserts
/// ([`Shot::reinserted_runs`]). Pure address arithmetic: it reads nothing.
pub(crate) fn run_origin_document(run: &Run) -> Option<Address> {
    if run.i_start().subspace() != Some(&content_subspace()) {
        return None;
    }
    document_of(run.i_start()).map(|d| trunk_of(&d))
}

/// One client-supplied run of a publish shot (PUB-2.33 as amended, PUB-8.1).
///
/// The runs together are the arrangement the shooting client rendered and
/// the person confirmed, one I-run at a time, in arrangement order.
///
/// `origin` is the document the run windows — the document its I-addresses
/// were minted under, as the client states it. Its projection to the trunk
/// (PUB-2.15), the run's origin document, is what the source gate is asked
/// about (PUB-6.23) and what decides the run's family in the member
/// (PUB-2.40): the shot document's own I-space stays by reference, a NAMED
/// draft's — the rendering `draft`'s, or one `also` names — is re-inserted
/// as fresh identity, any other document's stays a window — three families,
/// disjoint under [`Shot`]'s precondition on the named drafts. The composite
/// checks the statement against the run's start —
/// a run whose stated origin does not project to the origin document its
/// start settles is refused `BadRun` (`PublishError`) — so the field is the
/// client's statement of intent, and a mistaken one is told rather than
/// silently re-derived.
///
/// `run` is the I-run: a content element start, which the composite checks
/// (`BadRun` otherwise), and a width ≥ 1, built through [`Run::new`], the one
/// foreign constructor — so a shot cannot name a zero-width run or a start
/// that is not a full element position.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ShotRun {
    /// The document the run windows, as the client states it.
    ///
    /// It is a member or the document it projects to; the composite compares
    /// it projected (PUB-2.15).
    pub origin: Address,
    /// The I-run itself.
    pub run: Run,
}

/// The base a staged draft was taken from (PUB-2.37), with the extent taken.
///
/// The base is the member the stager's `copy` named as its source — the
/// trunk head for the ordinary shot, a pinned member for the daughter shot —
/// or the document itself while it has no member yet (a published document
/// between its mint and its birth version, PUB-2.66's memberless reading),
/// together with how many of its content positions the copy took.
///
/// `extent` is what lets the composite honor PUB-2.42's deposit cell against
/// a whole-arrangement supply: a published member's content arrangement
/// changes only by exempt deposits appended at fresh positions (PUB-2.43),
/// so the positions of `member` past `extent` are exactly the deposits the
/// render post-dates, and the composite carries them into the new member
/// unchanged (PUB-2.45). A pinned base's content never grows, so for a
/// daughter shot the extent equals the base's current count and nothing is
/// appended. An extent past the base's current count is a request defect
/// (`BaseExtentTooLarge`).
///
/// **Precondition.** `extent` is exactly the count of `member`'s leading
/// positions the staged copy took: the client's statement about its own
/// render, which M5 cannot see. M5 refutes only an extent past the base's
/// current count; an understated one carries positions the client's runs
/// already hold a second time, and an overstated one within the count drops
/// the deposits that lie between — both silently.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Base {
    /// The member (or memberless document) the draft was copied from.
    pub member: Address,
    /// How many content positions of `member` the copy took.
    ///
    /// It is the extent the staged arrangement accounts for.
    pub extent: Nat,
}

/// One stretch of a shot's stretch list (the wire's `stretches` entry).
///
/// The member is its base with stretches replaced: `width` positions of the
/// base from `start` on are replaced by the next `count` entries of the
/// shot's `runs`. A stretch of no width places its runs before `start`, the
/// boundary past the base's extent among them; one of no count only
/// removes. The stretches of one shot are in the base's own coordinates,
/// ascending and apart, and their counts partition `runs` in order
/// ([`Shot::stretch_fault`] judges all of it).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ShotStretch {
    /// The first position of the base the stretch replaces, 1-based.
    pub start: Nat,
    /// How many positions of the base it replaces.
    pub width: Nat,
    /// How many entries of the shot's `runs`, the next in order, replace
    /// them.
    pub count: usize,
}

/// Why a shot's stretch list is no list of stretches of its base.
///
/// It is request arithmetic alone — the list, the base's stated extent and
/// the count of `runs` — judged in this order, the first fault deciding:
/// the list as a whole, then each entry in turn, then the counts' sum.
/// [`Shot::stretch_fault`] answers it; a door ahead of the store refuses
/// the frame with the entry it names, and the store refuses the shot
/// ([`PublishError::BadStretches`](crate::PublishError::BadStretches)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StretchFault {
    /// The shot carries a list and names no base for it to replace
    /// stretches of.
    NoBase,
    /// The entry at `index` starts at position 0, or below the reach of the
    /// entry before it: the stretches are ascending and apart.
    NotApart {
        /// The entry's position in the list.
        index: usize,
    },
    /// The entry at `index` starts past `base.extent + 1`, the last
    /// boundary of the positions the staged copy took.
    StartPastExtent {
        /// The entry's position in the list.
        index: usize,
    },
    /// The entry at `index` replaces positions past `base.extent`.
    ReachPastExtent {
        /// The entry's position in the list.
        index: usize,
    },
    /// The counts do not sum to `runs`' length: `index` is the entry whose
    /// count first carries the sum past it, or the last entry where the
    /// sum falls short.
    CountMismatch {
        /// The entry's position in the list.
        index: usize,
    },
}

/// One publish shot (PUB-2.33): the next member of the document's chain.
///
/// The member is born published, in one commit.
///
/// `base` absent is the birth shape (PUB-2.34), which mints the birth version
/// — the chain's first member — and is admitted only while the chain is
/// empty. With `stretches` empty — THE WHOLE FORM — `runs` is the whole
/// arrangement the client rendered (PUB-2.33 as
/// amended); the composite appends the base's post-render deposits after it
/// (PUB-2.42, PUB-2.45) — with a base; absent, nothing is appended. With
/// `stretches` named, `runs` is THE CHANGE: the member is the base with each
/// stretch replaced by its share of `runs` ([`ShotStretch`]), every position
/// of the base no stretch names standing where the base holds it, its
/// post-render deposits past `base.extent` among them. The whole form is the
/// change of one stretch over the base's positions `[1, base.extent]`, so
/// the two forms mint one member from one request's facts, and every index
/// into `runs` — a kept place's, a pairing's, a refusal's site — counts the
/// runs the request carries under either.
///
/// `draft` names the RENDERING draft — the draft whose arrangement the runs
/// render, the home of the kept places and of the records for its own
/// identity — and `also` THE FAMILY's OTHER DRAFTS (the Nelson way, B3-S10;
/// the link-sets design §5.7, THE REQUEST): the other private drafts of the
/// caller's own whose identity this shot re-mints beside the rendering
/// draft's, in the request's order. Together they are THE NAMED DRAFTS
/// ([`Shot::named_drafts`]), each judged as the document it projects to
/// (PUB-2.15): every one must be registered
/// ([`SourceNotRegistered`](crate::PublishError::SourceNotRegistered)) and
/// the caller's own ([`NotOwner`](crate::PublishError::NotOwner) carrying the
/// draft at fault, in the request's order), and a run is draft-native —
/// re-inserted as fresh identity under the document's own I-space (PUB-2.40,
/// PUB-2.41) — exactly when its origin document is one of them
/// ([`Shot::is_draft_native`]). `draft` absent, no run is draft-native and
/// `also` is empty (the codec refuses `also` without `draft`); `also` empty
/// is the one-draft shot.
///
/// The shot moves one recorded base at most, the rendering draft's, and
/// only where it is that draft's own publication ([`Shot::moves_base_of`]):
/// its placing record names the draft, and the fold moves the draft's base
/// to the member minted and clears its merge marker (BASE★ on
/// [`M5State`]). A shot that sets `keep_base` publishes the draft's words
/// without being its publication — the merge's shot from the head, whose
/// member holds words the draft never had (skep #944) — and leaves the
/// rendering draft's base and marker standing, as every `also` draft's
/// stand, so the draft stands behind the member it published.
///
/// **Precondition.** Every named draft lies outside the chain of the document
/// the shot appends to ([`Vstream::publish`](crate::Vstream::publish)'s
/// `doc`): each is a document the change was staged in, never that document,
/// the base, or any other member of its chain. The composite does not check
/// this. It takes the statement at its word, and the statement decides each
/// run's family. A named draft inside the chain makes the document's own runs
/// draft-native: they are re-inserted as fresh identity and counted against
/// [`MAX_REINSERTED_VALUES`](crate::MAX_REINSERTED_VALUES) and
/// [`MAX_REINSERTED_UNITS`](crate::MAX_REINSERTED_UNITS), where they would
/// otherwise be placed by reference. The member then holds, at those
/// positions, fresh addresses that no earlier member of the chain arranges,
/// and a link made on the edition's text does not reach them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Shot {
    /// The member the draft was staged from, with the extent the copy took.
    ///
    /// It is absent in the birth shape.
    pub base: Option<Base>,
    /// The rendering draft, whose native runs are re-inserted as fresh
    /// identity and whose kept places the request may carry.
    ///
    /// It is a document outside the shot's own chain, as the type's
    /// precondition states.
    pub draft: Option<Address>,
    /// The family's other drafts whose identity this shot re-mints beside
    /// the rendering draft's (the wire's `also`), in the request's order.
    ///
    /// Each is a document outside the shot's own chain, as the type's
    /// precondition states; each keeps its own correspondence records, is
    /// re-windowed at the kept places the link store's composite carries for
    /// it (skep #739), and keeps its recorded base. Empty is the one-draft
    /// shot.
    pub also: Vec<Address>,
    /// Whether the rendering draft's recorded base stands (wire: `keep_base`).
    ///
    /// `false` is a publication of the draft itself, which moves the draft's
    /// base to the member minted ([`moves_base_of`](Shot::moves_base_of)).
    /// `true` publishes the draft's words without being its publication and
    /// changes nothing else: the draft's native runs are re-inserted, its
    /// records homed in it and its kept places re-windowed as at its own.
    /// Inert without a `draft`, which the codec refuses, and outside the
    /// signed body, as `draft` is.
    pub keep_base: bool,
    /// The client-rendered runs, in order: the whole arrangement, or with
    /// `stretches` the runs of the change, stretch after stretch.
    pub runs: Vec<ShotRun>,
    /// The stretches of the base `runs` replace, ascending and apart; empty
    /// for the whole form.
    ///
    /// **Precondition.** [`stretch_fault`](Shot::stretch_fault) answers
    /// `None`: the list rides a base, lies inside its extent and partitions
    /// `runs`. The store refuses a shot that breaks it
    /// (`PublishError::BadStretches`); the pure reads here —
    /// [`address_form`](Shot::address_form),
    /// [`stretch_terms`](Shot::stretch_terms) — are total over one that
    /// does, a count past the runs left taking what is left.
    pub stretches: Vec<ShotStretch>,
}

impl Shot {
    /// Returns why `stretches` is no list of stretches of the shot's base,
    /// or `None` where it is one — and for the whole form, which names none.
    ///
    /// Request arithmetic, reading nothing: a list with no base
    /// ([`StretchFault::NoBase`]); then each entry in order — a start at
    /// position 0 or below the reach (`start + width`) of the entry before
    /// it ([`StretchFault::NotApart`]; two stretches may touch, and two
    /// that replace nothing may name one position, the earlier's runs then
    /// standing before the later's), a start past `base.extent + 1`
    /// ([`StretchFault::StartPastExtent`]), a reach past it
    /// ([`StretchFault::ReachPastExtent`]), a count carrying the counts'
    /// sum past `runs`' length ([`StretchFault::CountMismatch`]) — then a
    /// sum short of it, named at the last entry. The one spelling of the
    /// rule: the wire's door refuses a frame by it before any read, and the
    /// store a shot handed to it another way.
    pub fn stretch_fault(&self) -> Option<StretchFault> {
        if self.stretches.is_empty() {
            return None;
        }
        let Some(base) = &self.base else { return Some(StretchFault::NoBase) };
        let boundary = &base.extent + Nat::one();
        let mut reach = Nat::one();
        let mut counted = 0usize;
        for (index, stretch) in self.stretches.iter().enumerate() {
            if stretch.start < reach {
                return Some(StretchFault::NotApart { index });
            }
            if stretch.start > boundary {
                return Some(StretchFault::StartPastExtent { index });
            }
            reach = &stretch.start + &stretch.width;
            if reach > boundary {
                return Some(StretchFault::ReachPastExtent { index });
            }
            counted = counted.saturating_add(stretch.count);
            if counted > self.runs.len() {
                return Some(StretchFault::CountMismatch { index });
            }
        }
        (counted != self.runs.len()).then_some(StretchFault::CountMismatch { index: self.stretches.len() - 1 })
    }

    /// Returns `runs` stretch by stretch: each stretch's share, in order.
    ///
    /// The whole form is one share, every run. With a list each stretch
    /// takes its `count` of the runs left — what is left where the count
    /// passes it, and the last stretch nothing past its own count, so runs
    /// no count reaches are in no share: a list
    /// [`stretch_fault`](Shot::stretch_fault) refuses, which the store
    /// never places.
    pub(crate) fn runs_by_stretch(&self) -> impl Iterator<Item = &[ShotRun]> + '_ {
        let whole = self.stretches.is_empty().then_some(self.runs.as_slice());
        let mut rest = self.runs.as_slice();
        let shares = self.stretches.iter().map(move |stretch| {
            let (share, left) = rest.split_at(stretch.count.min(rest.len()));
            rest = left;
            share
        });
        whole.into_iter().chain(shares)
    }

    /// Returns the stretch list in the member's terms: each stretch with
    /// its count read as the positions its runs hold.
    ///
    /// One [`Stretch`] an entry of `stretches`, `placed` the widths of its
    /// share of `runs` summed; empty for the whole form. It is what the
    /// shot's placing record keeps ([`ShotTerms`](crate::ShotTerms)), what
    /// its signed body's stretch row spells, and so what a signer composes
    /// from the request and a verifier from the member's terms alike.
    /// Request arithmetic, reading nothing.
    pub fn stretch_terms(&self) -> Vec<Stretch> {
        if self.stretches.is_empty() {
            return Vec::new();
        }
        self.stretches
            .iter()
            .zip(self.runs_by_stretch())
            .map(|(stretch, share)| Stretch {
                start: stretch.start.clone(),
                width: stretch.width.clone(),
                placed: share.iter().map(|stated| stated.run.width()).sum(),
            })
            .collect()
    }

    /// Returns the address form of the runs as the commit will place them.
    ///
    /// The commit is [`Vstream::publish`](crate::Vstream::publish) asked with
    /// `doc`, placing into the next member of the document `doc` projects to
    /// (PUB-2.15), a member of its chain naming the shot as the document
    /// itself does: the runs the shot's entry signature spells, each classed
    /// by the family the commit gives it — a run the commit copies in (the
    /// corpus's verb) is a [`Value`](SegmentRun::Value) run, signed by value:
    /// the shot document's own I-space (its origin document, that
    /// projection), placed by reference, and a named draft's text (its
    /// origin document one of [`named_drafts`](Shot::named_drafts)),
    /// re-inserted as fresh identity under the document's own I-space — at
    /// the member, both are the trunk's own; every other run is a
    /// [`Window`](SegmentRun::Window), a reference the commit keeps to
    /// another document's I-space, signed by address.
    /// Consecutive windows that are I-adjacent become one, through the
    /// placement's own accumulator, exactly as the member's run-list will hold
    /// them; the value runs keep their boundaries, which the body never spells
    /// — its segments are each window and each stretch of consecutive value
    /// runs, as [`SegmentRun`] states.
    ///
    /// **A stretch boundary closes a segment.** Where the shot names
    /// `stretches`, the runs of one stretch are classed and joined as above
    /// and no window is joined across two: the accumulator restarts at each
    /// stretch's first run, as the placement's does, so two I-adjacent
    /// windows of two stretches stay two here — and two in the member's
    /// form, which is read image by image. The runs come back in one list,
    /// stretch after stretch; where each stretch's runs end is
    /// [`stretch_terms`](Shot::stretch_terms)' to say, by positions, and a
    /// composer of the signed body closes its value stretch there too.
    ///
    /// So it answers for the request what [`M5State::address_form_of`]
    /// answers for the member it mints, read back at the images of the
    /// shot's stretches — as the signed body spells it: the same windows, run for run
    /// and in the same V-places, and between them the same positions spelled
    /// by value, value for value. The value runs themselves need not match —
    /// the member holds as one run what the request may name as several, and
    /// a draft-native run's addresses are the draft's here and fresh there —
    /// which is why the body spells a stretch by its values and never by its
    /// runs.
    ///
    /// Pure address arithmetic over the request, as the family test at the
    /// commit is: the origin document is derived from each run's own start
    /// (`document_of`, then `trunk_of`, PUB-2.15) and never from the stated
    /// `origin`, so a run the commit will refuse `BadRun` — a start that is
    /// no content element — classes as a window here, spelled and never
    /// read; the store's refusal answers it. Reads no world.
    pub fn address_form(&self, doc: &Address) -> Vec<SegmentRun> {
        let trunk = trunk_of(doc);
        let mut out: Vec<SegmentRun> = Vec::new();
        for share in self.runs_by_stretch() {
            // The consecutive windows in hand, accumulated through the one
            // run accumulator (`extend_or_push_run`), so the merge condition
            // is the placement's own; a value run closes the group, and so
            // does the stretch's end.
            let mut windows: Vec<Run> = Vec::new();
            for ShotRun { run, .. } in share {
                let by_value = run_origin_document(run)
                    .is_some_and(|origin_doc| origin_doc == trunk || self.is_draft_native(&origin_doc));
                if by_value {
                    out.extend(windows.drain(..).map(SegmentRun::Window));
                    out.push(SegmentRun::Value(run.clone()));
                } else {
                    extend_or_push_run(&mut windows, run.clone());
                }
            }
            out.extend(windows.into_iter().map(SegmentRun::Window));
        }
        out
    }

    /// Returns the runs this shot re-inserts: its draft-native runs (PUB-2.40).
    ///
    /// They come in the order given: those whose origin document — derived
    /// from the run's own start, as [`address_form`](Shot::address_form)
    /// derives it, and never from the stated `origin` — is one of the
    /// [`named_drafts`](Shot::named_drafts), the rendering draft's or an
    /// `also` draft's alike ([`is_draft_native`](Shot::is_draft_native));
    /// none with no draft, and a run named twice yielded twice. Their values
    /// are the ones the commit re-inserts as fresh identity under the
    /// document's own I-space, in this order
    /// ([`Vstream::publish`](crate::Vstream::publish) states where that
    /// identity lands); the address form spells them by value beside the
    /// document's own runs and does not tell the two apart. Request arithmetic
    /// over the runs and the drafts as the client stated them, reading nothing
    /// — so a caller judging the values a shot re-inserts asks this rather
    /// than re-deriving each run's family; one judging them per draft asks
    /// [`reinserted_runs_of`](Shot::reinserted_runs_of).
    pub fn reinserted_runs(&self) -> impl Iterator<Item = &Run> + '_ {
        self.runs
            .iter()
            .map(|stated| &stated.run)
            .filter(move |run| run_origin_document(run).is_some_and(|d| self.is_draft_native(&d)))
    }

    /// Returns the runs this shot re-inserts whose identity is `draft_doc`'s.
    ///
    /// They are [`reinserted_runs`](Shot::reinserted_runs) narrowed to one
    /// named draft — `draft_doc` as [`named_drafts`](Shot::named_drafts)
    /// yields it, the document the draft projects to — in the order given;
    /// none for a document that is no named draft, since the shot re-inserts
    /// no run of it. Request arithmetic, reading nothing: the named drafts
    /// are tested once per call and each run's origin once, so a caller
    /// asking of one draft pays `O(k + n)`; a caller asking of every named
    /// draft asks [`reinserted_runs_by_draft`](Shot::reinserted_runs_by_draft)
    /// instead, which pays one pass for all of them.
    pub fn reinserted_runs_of<'s>(&'s self, draft_doc: &'s Address) -> impl Iterator<Item = &'s Run> + 's {
        let named = self.is_draft_native(draft_doc);
        self.runs
            .iter()
            .map(|stated| &stated.run)
            .filter(move |run| named && run_origin_document(run).as_ref() == Some(draft_doc))
    }

    /// Returns THE NAMED DRAFTS, each once, with the runs this shot
    /// re-inserts of its identity.
    ///
    /// The drafts come as [`named_drafts`](Shot::named_drafts) yields them —
    /// the rendering draft first, then each `also` draft in the request's
    /// order — each as the document it projects to and kept at its first
    /// occurrence, so two entries projecting to one document are one draft
    /// here; each draft's runs are [`reinserted_runs_of`](Shot::reinserted_runs_of)
    /// of it, in the order given, a named draft no run is of holding none.
    /// So the groups partition [`reinserted_runs`](Shot::reinserted_runs):
    /// every re-inserted run lies in exactly one. The per-home spelling the
    /// twin fence reads each named draft's own records by, the lock set
    /// takes each named draft's link key by, the price counts the fence's
    /// stabs by and the feed row names each named draft by. Request
    /// arithmetic, reading nothing, in one pass: the drafts indexed once,
    /// then each run's origin looked up in the index — `O((k + n) log k)`
    /// over `k` named drafts and `n` runs, where asking
    /// [`reinserted_runs_of`](Shot::reinserted_runs_of) per draft would pay
    /// `O(k · (k + n))`.
    pub fn reinserted_runs_by_draft(&self) -> Vec<(Address, Vec<&Run>)> {
        let mut groups: Vec<(Address, Vec<&Run>)> = Vec::new();
        let mut index: BTreeMap<Address, usize> = BTreeMap::new();
        for draft in self.named_drafts() {
            if let Entry::Vacant(slot) = index.entry(draft.clone()) {
                slot.insert(groups.len());
                groups.push((draft, Vec::new()));
            }
        }
        for ShotRun { run, .. } in &self.runs {
            if let Some(&k) = run_origin_document(run).as_ref().and_then(|origin| index.get(origin)) {
                groups[k].1.push(run);
            }
        }
        groups
    }

    /// Returns how many values this shot re-inserts: its positions.
    ///
    /// It is the DISTINCT positions [`reinserted_runs`](Shot::reinserted_runs)
    /// name — the runs' I-extents merged (the run union, the carried-run
    /// test's own merge) and their widths
    /// summed, a position two runs name counted once, since the commit mints
    /// each draft identity once per shot and places every later occurrence
    /// by reference (the link-sets design §5.7;
    /// [`Vstream::publish`](crate::Vstream::publish) states where the fresh
    /// identity lands); zero with no draft. Over every named draft: the
    /// positions of two drafts are distinct addresses, so each counts. It is
    /// the count [`Vstream::publish`](crate::Vstream::publish) holds to
    /// [`MAX_REINSERTED_VALUES`](crate::MAX_REINSERTED_VALUES)
    /// (`TooManyValues`), and its one spelling: request arithmetic, reading
    /// nothing — so a caller judging a shot's positions ahead of its
    /// transaction asks this, and its refusal and the store's cannot part.
    /// It does not tell the records the shot stages — two for an atom, and
    /// two for a whole run of single-byte values however many positions it
    /// holds: those are the units, counted off the stored pieces by
    /// [`reinserted_units`](Shot::reinserted_units), which asks this first.
    /// `O(n log n)` in the draft-native runs, the merge's sort.
    pub fn reinserted_values(&self) -> Nat {
        RunUnion::of(self.reinserted_runs()).runs().map(|run| run.width().clone()).sum()
    }

    /// Returns the document `draft` projects to (PUB-2.15), if one is named:
    /// THE RENDERING DRAFT.
    ///
    /// It is the home of the kept places in the request's `places` — the
    /// draft the shot's one commit re-windows first, each `also` draft after
    /// it at its own (the link-sets design §5.7; skep #739) — the origin the
    /// edition claim names, and the draft whose recorded base a publication
    /// of it moves ([`moves_base_of`](Shot::moves_base_of)). The family rule
    /// [`Shot`] states is wider than it:
    /// [`named_drafts`](Shot::named_drafts) yields it first and the `also`
    /// drafts after it, and [`is_draft_native`](Shot::is_draft_native) is the
    /// test [`address_form`](Shot::address_form),
    /// [`reinserted_runs`](Shot::reinserted_runs) and `publish`'s placement
    /// ask; a caller that means the rendering draft — the re-window, the
    /// claim's origin, the kept-place test — asks this.
    pub fn draft_document(&self) -> Option<Address> {
        self.draft.as_ref().map(trunk_of)
    }

    /// Returns the draft whose recorded base this shot moves, if any.
    ///
    /// It is the document the rendering draft projects to (PUB-2.15), as
    /// [`draft_document`](Shot::draft_document) answers it, where the shot
    /// is that draft's own publication; `None` where the shot names no
    /// draft or sets [`keep_base`](Shot::keep_base). It is the draft the
    /// shot's placing record names
    /// ([`M5Rec::ShotPlace`](crate::M5Rec::ShotPlace)'s `draft`), at which
    /// the fold moves the draft's base to the member minted and clears
    /// its merge marker (BASE★ on [`M5State`]), so a draft named by a member
    /// of its chain moves its own document's base, and no `also` draft's
    /// base moves at all. Request arithmetic, reading nothing.
    pub fn moves_base_of(&self) -> Option<Address> {
        self.draft_document().filter(|_| !self.keep_base)
    }

    /// Returns THE NAMED DRAFTS, each as the document it projects to
    /// (PUB-2.15): the rendering draft first, then each draft `also` names,
    /// in the request's order.
    ///
    /// The family rule [`Shot`] states, spelled once: the documents whose
    /// registration and ownership the shot checks in this order
    /// (`SourceNotRegistered`, then `NotOwner` carrying the draft at fault,
    /// each ahead of the runs), whose identity the shot re-mints
    /// ([`is_draft_native`](Shot::is_draft_native)), in which it homes its
    /// correspondence records (each piece's in the draft its identity was),
    /// and which the feed row names after the member — the rendering draft
    /// always, each `also` draft where the commit wrote it. Empty with no
    /// `draft` — `also` rides only beside one. Request
    /// arithmetic, reading nothing.
    pub fn named_drafts(&self) -> impl Iterator<Item = Address> + '_ {
        self.draft.iter().chain(&self.also).map(trunk_of)
    }

    /// Returns whether `origin_doc`, a run's origin document, is a named
    /// draft's: whether a run of that identity is DRAFT-NATIVE, re-inserted
    /// as fresh identity (PUB-2.40) rather than placed by reference or kept
    /// as a window.
    ///
    /// The one test the family rule [`Shot`] states is decided by, asked by
    /// [`address_form`](Shot::address_form),
    /// [`reinserted_runs`](Shot::reinserted_runs) and `publish`'s placement
    /// alike, so the values a shot says it re-inserts are the values its
    /// commit writes over every named draft. `origin_doc` is a document
    /// (`run_origin_document`'s projection); `O(k)` in the named drafts.
    pub fn is_draft_native(&self, origin_doc: &Address) -> bool {
        self.named_drafts().any(|draft| draft == *origin_doc)
    }
}

/// One run of a shot's address form, named for the body segment it lies in.
///
/// It is a run of the member the shot mints, classed by the family the
/// commit gives it, the two classes the signed body spells apart. A run, and
/// not a segment: the body's segments (wire.md's `publish` body, which
/// skep-identity's `PublishBody` builds) are each window and each stretch of
/// consecutive value runs, so two value runs side by side here lie in one
/// value stretch there, and a window is a segment of its own. Answered for
/// the request by [`Shot::address_form`] and for the committed member by
/// [`M5State::address_form_of`], which agree as the signed body spells them
/// (stated on [`Shot::address_form`]): that agreement is what lets a verifier
/// holding the member, and no request, compose the body the client signed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SegmentRun {
    /// A run of a value stretch: one the commit copies in (the corpus's verb).
    ///
    /// It is the shot document's own I-space by reference, or a named
    /// draft's text re-inserted as fresh identity under it — signed by value,
    /// each position's value in V-order. The verb is not COPY's act: a value
    /// run may carry fresh identity, which COPY never mints, and a run the
    /// draft took by COPY from a third document is a
    /// [`Window`](SegmentRun::Window) here. At the member every such run
    /// is of the member's own trunk; the request's run boundaries within a
    /// stretch of them are not the member's and are spelled by nothing.
    Value(Run),
    /// A window onto another document's I-space, kept as a reference.
    ///
    /// The commit keeps it so, and it is signed by address, its I-start and
    /// its width — as the member's arrangement holds the run, maximally
    /// merged, and clipped to the client's placed positions.
    Window(Run),
}

impl SegmentRun {
    /// Returns the run itself, whichever class it is.
    ///
    /// That is a value run's positions or a window's I-extent. The class is
    /// the variant; a caller after the run alone asks this rather than
    /// matching both arms.
    pub fn run(&self) -> &Run {
        match self {
            SegmentRun::Value(run) | SegmentRun::Window(run) => run,
        }
    }
}

impl M5State {
    /// Returns the address form read at the positions `member`'s shot placed.
    ///
    /// Those positions are the runs the client placed, which its entry
    /// signature covers — the member's leading positions for a shot with no
    /// stretch list, ahead of the base's carried tail, and for a shot with
    /// one the images of its stretches, each stretch's share of the runs
    /// where the stretches before it left its start
    /// ([`ShotTerms::images`](crate::ShotTerms::images)) — answered as
    /// [`SegmentRun`]s in V-order, image after image, each run classed by its
    /// origin document as
    /// the commit left it: a run of the member's own trunk is a
    /// [`Value`](SegmentRun::Value) run — the shot document's own I-space
    /// placed by reference, and the named drafts' text the commit
    /// re-inserted under that trunk, told apart by nothing here and signed
    /// alike, by value — and a run of any other document is a
    /// [`Window`](SegmentRun::Window), signed by address. The runs are the
    /// arrangement's own, maximally merged within an image and clipped at
    /// its two ends by the run-list's own clip — the range walk
    /// every resolution takes — so a run the member holds across two images,
    /// or across an image and the base's positions beside it, is answered
    /// in each image's part alone, never joined across; and what this
    /// answers for a committed member is
    /// what [`Shot::address_form`] answered for the request that minted it, as
    /// the body spells them (stated there), and a verifier holding the member
    /// composes the shot's signed body with no request in hand. The terms are
    /// the member's own ([`shot_terms`](M5State::shot_terms)): a member no
    /// shot minted answers nothing. A member with fewer positions than an
    /// image names answers what it has; an absent arrangement answers
    /// nothing.
    pub fn address_form_of(&self, member: &Address) -> Vec<SegmentRun> {
        let Some(terms) = self.shot_terms(member) else { return Vec::new() };
        let trunk = trunk_of(member);
        let list = self.content_list(member);
        let mut out: Vec<SegmentRun> = Vec::new();
        for (at, placed) in terms.images() {
            out.extend(list.iter_resolve_range(&at, &placed).map(|run| {
                if run_origin_document(&run).as_ref() == Some(&trunk) {
                    SegmentRun::Value(run)
                } else {
                    SegmentRun::Window(run)
                }
            }));
        }
        out
    }
}
