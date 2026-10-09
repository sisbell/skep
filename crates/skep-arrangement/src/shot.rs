//! §The PUBLISH SHOT's values (PUB-2.33, PUB-8.1): its request — the
//! client-supplied I-address runs with the origin each windows, the base the
//! staged draft was taken from, and the whole shot, the composite's
//! arrangement input, taken FROM THE CLIENT and never read off any draft's
//! arrangement at commit — the runs it re-inserts and their count
//! ([`Shot::reinserted_runs`], [`Shot::reinserted_values`]), and its ADDRESS
//! FORM on both sides of the commit: [`Shot::address_form`] for the request,
//! [`M5State::address_form_of`] for the member it minted, and
//! [`run_origin_document`], the classifier each of them asks. The two sides
//! of the address form must agree as the signed body spells them — window for
//! window, and value for value between — so they are stated in one file.
//!
//! Three values rather than loose arguments, for the reason [`crate::VPos`]
//! and [`crate::VSpec`] are values: the pieces of a shot travel together, and
//! a `base` handed over without the extent its copy took would be a base the
//! composite cannot compose against (PUB-2.42).

use num_traits::One;
use skep_address::{content_subspace, document_of, Address, Nat};

use crate::chain::trunk_of;
use crate::run::Run;
use crate::runlist::extend_or_push_run;
use crate::state::M5State;

/// A supplied run's ORIGIN DOCUMENT — the trunk (PUB-2.15) of the document
/// its addresses were minted under, `document_of` of its start and then
/// `trunk_of` — provided the start is a CONTENT element; `None` for a link
/// element or an address with no document. What the source gate asks about
/// and `Withheld` names (PUB-8.4's `site.addr`), what a shot's stated
/// `origin` must project to, and what classes a run in the ADDRESS FORM on
/// both of its sides ([`Shot::address_form`], [`M5State::address_form_of`]).
/// Pure address arithmetic: it reads nothing.
pub(crate) fn run_origin_document(run: &Run) -> Option<Address> {
    if run.i_start().subspace() != Some(&content_subspace()) {
        return None;
    }
    document_of(run.i_start()).map(|d| trunk_of(&d))
}

/// One client-supplied run of a publish shot (PUB-2.33 as amended,
/// PUB-8.1): the arrangement the shooting client rendered and the person
/// confirmed, one I-run at a time, in arrangement order.
///
/// `origin` is the DOCUMENT the run windows — the document its I-addresses
/// were minted under, as the client states it. Its projection to the trunk
/// (PUB-2.15), the run's ORIGIN DOCUMENT, is what the source gate is asked
/// about (PUB-6.23) and what decides the run's family in the member
/// (PUB-2.40): the shot document's own I-space stays by reference, the
/// staging draft's is re-inserted as fresh identity, any other document's
/// stays a window — three families, disjoint under [`Shot`]'s REQUIRES on
/// `draft`. The composite CHECKS the statement against the run's
/// start — a run whose stated origin does not project to the origin document
/// its start settles is refused `BadRun` (`PublishError`) — so the field is
/// the client's statement of intent, and a mistaken one is told rather than
/// silently re-derived.
///
/// `run` is the I-run: a content element start and a width ≥ 1, built
/// through [`Run::new`], the one foreign constructor — so a shot cannot name
/// a zero-width run or a start that is not a full element position.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ShotRun {
    /// The document the run windows, as the client states it — a member or
    /// the document it projects to; the composite compares it projected
    /// (PUB-2.15).
    pub origin: Address,
    /// The I-run itself.
    pub run: Run,
}

/// The base a staged draft was taken from (PUB-2.37): the MEMBER the
/// stager's `copy` named as its source — the trunk head for the ordinary
/// shot, a pinned member for the daughter shot — or the document itself
/// while it has no member yet (a published document between its mint and
/// its birth version, PUB-2.66's memberless reading), together with how many
/// of its content positions the copy TOOK.
///
/// `extent` is what lets the composite honor PUB-2.42's deposit cell against
/// a whole-arrangement supply: a published member's arrangement changes only
/// by exempt deposits appended at fresh positions (PUB-2.43), so the
/// positions of `member` past `extent` are exactly the deposits the render
/// post-dates, and the composite carries them into the new member unchanged
/// (PUB-2.45). A pinned base never grows, so for a daughter shot the extent
/// equals the base's current count and nothing is appended. An extent past
/// the base's current count is a request defect (`BaseExtentTooLarge`).
///
/// REQUIRES — `extent` is EXACTLY the count of `member`'s leading positions
/// the staged copy took: the client's statement about its own render, which
/// M5 cannot see. M5 refutes only an extent past the base's current count;
/// an understated one carries positions the client's runs already hold a
/// second time, and an overstated one within the count drops the deposits
/// that lie between — both silently.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Base {
    /// The member (or memberless document) the draft was copied from.
    pub member: Address,
    /// The content positions of `member` the copy took — the extent the
    /// staged arrangement accounts for.
    pub extent: Nat,
}

/// One publish shot (PUB-2.33): the next member of the document's chain,
/// born published, in one commit.
///
/// `base` absent is the BIRTH SHAPE (PUB-2.34), which mints the BIRTH VERSION
/// — the chain's first member — and is admitted only while the chain is
/// empty. `runs` is the WHOLE arrangement the client rendered (PUB-2.33 as
/// amended); the composite appends the base's post-render deposits after it
/// (PUB-2.42, PUB-2.45) — with a base; absent, nothing is appended.
///
/// `draft` names the staging draft whose native runs are re-inserted as
/// fresh identity under the document's own I-space (PUB-2.40, PUB-2.41);
/// absent, no run is draft-native. It is judged as the document it projects
/// to (PUB-2.15): that document must be registered
/// ([`SourceNotRegistered`](crate::PublishError::SourceNotRegistered)), and a
/// run is draft-native exactly when its origin document is that document.
///
/// REQUIRES — the draft lies OUTSIDE the chain of the document the shot
/// appends to ([`Vstream::publish`](crate::Vstream::publish)'s `doc`): it is
/// the document the change was staged in, never that document, the base, or
/// any other member of its chain. The composite does not check this. It takes
/// the statement at its word, and the statement decides each run's family. A
/// `draft` inside the chain makes the document's OWN runs draft-native: they
/// are re-inserted as fresh identity and counted against
/// [`MAX_REINSERTED_VALUES`](crate::MAX_REINSERTED_VALUES), where they would
/// otherwise be placed by reference. The member then holds, at those
/// positions, fresh addresses that no earlier member of the chain arranges,
/// and a link made on the edition's text does not reach them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Shot {
    /// The member the draft was staged from, with the extent the copy took;
    /// absent in the birth shape.
    pub base: Option<Base>,
    /// The staging draft, whose runs are re-inserted as fresh identity — a
    /// document outside the shot's own chain, as the type's REQUIRES states.
    pub draft: Option<Address>,
    /// The client-rendered arrangement, in order.
    pub runs: Vec<ShotRun>,
}

impl Shot {
    /// THE ADDRESS FORM of this shot's runs AS THE COMMIT WILL PLACE THEM
    /// when [`Vstream::publish`](crate::Vstream::publish) is asked with `doc`
    /// — into the next member of the document `doc` projects to (PUB-2.15), a
    /// member of its chain naming the shot as the document itself does (l6-A4
    /// = r6-4, owner-ruled 2026-09-29; fam2-Q's arm A): the runs the shot's
    /// entry signature spells, each CLASSED by the family the commit gives
    /// it — a run the commit COPIES IN (the corpus's verb) is a
    /// [`Value`](SegmentRun::Value) run, signed BY VALUE: the shot document's
    /// own I-space (its origin document, that projection), placed by
    /// reference, and the staging draft's text (its origin document the
    /// draft's trunk), re-inserted as fresh identity under the document's own
    /// I-space — at the member, both are the trunk's own; every other run is
    /// a [`Window`](SegmentRun::Window), a reference the commit keeps to
    /// another document's I-space, signed BY ADDRESS. Consecutive windows
    /// that are I-adjacent become ONE, through the placement's own
    /// accumulator, exactly as the member's run-list will hold them; the
    /// value runs keep their boundaries, which the body never spells — its
    /// SEGMENTS are each window and each stretch of consecutive value runs,
    /// as [`SegmentRun`] states.
    ///
    /// So it answers for the request what [`M5State::address_form_of`]
    /// answers for the member it mints, read back with the shot's `placed`
    /// count — AS THE SIGNED BODY SPELLS IT: the same windows, run for run
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
        let draft_doc = self.draft_document();
        let mut out: Vec<SegmentRun> = Vec::new();
        // The consecutive windows in hand, accumulated through the ONE run
        // accumulator (`extend_or_push_run`), so the merge condition is the
        // placement's own; a value run closes the group.
        let mut windows: Vec<Run> = Vec::new();
        for ShotRun { run, .. } in &self.runs {
            let by_value = run_origin_document(run).is_some_and(|origin_doc| {
                origin_doc == trunk || draft_doc.as_ref() == Some(&origin_doc)
            });
            if by_value {
                out.extend(windows.drain(..).map(SegmentRun::Window));
                out.push(SegmentRun::Value(run.clone()));
            } else {
                extend_or_push_run(&mut windows, run.clone());
            }
        }
        out.extend(windows.into_iter().map(SegmentRun::Window));
        out
    }

    /// THE RUNS THIS SHOT RE-INSERTS — its DRAFT-NATIVE runs (PUB-2.40), in
    /// the order given: those whose ORIGIN DOCUMENT — derived from the run's
    /// own start, as [`address_form`](Shot::address_form) derives it, and
    /// never from the stated `origin` — is [`draft_document`](Shot::draft_document);
    /// none with no draft, and a run named twice yielded twice. Their values
    /// are the ones the commit re-inserts as fresh identity under the
    /// document's own I-space, in this order
    /// ([`Vstream::publish`](crate::Vstream::publish) states where that
    /// identity lands); the address form spells them by value beside the
    /// document's own runs and does not tell the two apart. Request
    /// arithmetic over the runs and the draft as the client stated them,
    /// reading nothing — so a caller judging the values a shot re-inserts
    /// asks this rather than re-deriving each run's family.
    pub fn reinserted_runs(&self) -> impl Iterator<Item = &Run> + '_ {
        let draft_doc = self.draft_document();
        self.runs
            .iter()
            .map(|stated| &stated.run)
            .filter(move |run| draft_doc.is_some() && run_origin_document(run) == draft_doc)
    }

    /// THE VALUES THIS SHOT RE-INSERTS, counted —
    /// [`reinserted_runs`](Shot::reinserted_runs)' widths summed, two staged
    /// records apiece; zero with no draft. THE count
    /// [`Vstream::publish`](crate::Vstream::publish) holds to
    /// [`MAX_REINSERTED_VALUES`](crate::MAX_REINSERTED_VALUES)
    /// (`TooManyValues`), and its one spelling: request arithmetic, reading
    /// nothing — so a caller pricing a shot ahead of its transaction asks
    /// this, and its refusal and the store's cannot part.
    pub fn reinserted_values(&self) -> Nat {
        self.reinserted_runs().map(Run::width).sum()
    }

    /// The document `draft` projects to (PUB-2.15), or `None` with no draft
    /// named: the one a run's ORIGIN DOCUMENT must be for the run to be
    /// DRAFT-NATIVE, re-inserted as fresh identity (PUB-2.40) — the document
    /// whose registration the shot checks, and whose owner and readability a
    /// door judging the re-inserted values asks about. The draft half of the
    /// family rule [`Shot`] states, spelled once and asked by
    /// [`address_form`](Shot::address_form),
    /// [`reinserted_runs`](Shot::reinserted_runs) and `publish`'s
    /// registration check and placement alike; the run half, its origin
    /// document, is derived from each run's own start, as [`ShotRun`] states.
    pub fn draft_document(&self) -> Option<Address> {
        self.draft.as_ref().map(trunk_of)
    }
}

/// One RUN of a shot's ADDRESS FORM (l6-A4) — a run of the member the shot
/// mints, classed by the family the commit gives it, the two classes the
/// signed body spells apart — named for the SEGMENT of that body it lies in.
/// A run, and not a segment: the body's SEGMENTS (wire.md's `publish` body,
/// which skep-identity's `PublishBody` builds) are each window and each
/// stretch of consecutive value runs, so two value runs side by side here lie
/// in ONE value stretch there, and a window is a segment of its own.
/// Answered for the REQUEST by [`Shot::address_form`] and for the committed
/// MEMBER by [`M5State::address_form_of`], which agree as the signed body
/// spells them (stated on [`Shot::address_form`]): that agreement is what
/// lets a verifier holding the member, and no request, compose the body the
/// client signed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SegmentRun {
    /// A run of a VALUE STRETCH — a run the commit copies in (the corpus's
    /// verb): the shot document's own I-space by reference, or the staging
    /// draft's text re-inserted as fresh identity under it — signed BY VALUE,
    /// each position's value in V-order. The verb is not COPY's act: a value
    /// run may carry fresh identity, which COPY never mints, and a run the
    /// draft took by COPY from a third document is a
    /// [`Window`](SegmentRun::Window) here. At the member every such run
    /// is of the member's own trunk; the request's run boundaries within a
    /// stretch of them are not the member's and are spelled by nothing.
    Value(Run),
    /// A WINDOW onto another document's I-space, which the commit keeps as a
    /// reference: signed BY ADDRESS, its I-start and its width — as the
    /// member's arrangement holds the run, maximally merged, and clipped to
    /// the client's placed positions.
    Window(Run),
}

impl SegmentRun {
    /// The run itself, whichever class it is — a value run's positions or a
    /// window's I-extent. The class is the variant; a caller after the run
    /// alone asks this rather than matching both arms.
    pub fn run(&self) -> &Run {
        match self {
            SegmentRun::Value(run) | SegmentRun::Window(run) => run,
        }
    }
}

impl M5State {
    /// THE ADDRESS FORM READ AT THE MEMBER (l6-A4 = r6-4, owner-ruled
    /// 2026-09-29): `member`'s first `placed` content positions — the runs
    /// the client placed, which its entry signature covers, ahead of the
    /// base's carried tail — as [`SegmentRun`]s in V-order, each run
    /// classed by its ORIGIN DOCUMENT as the commit left it: a run of the
    /// member's own trunk is a [`Value`](SegmentRun::Value) run — the shot
    /// document's own I-space placed by reference, and the staging draft's
    /// text the commit re-inserted under that trunk, told apart by nothing
    /// here and signed alike, BY VALUE — and a run of any other document is a
    /// [`Window`](SegmentRun::Window), signed BY ADDRESS. The runs are the
    /// arrangement's own, maximally merged, the last one CLIPPED where the
    /// client's positions end, by the run-list's own clip — the range walk
    /// every resolution takes; so what this answers for a committed member is
    /// what [`Shot::address_form`] answered for the request that minted it, as
    /// the body spells them (stated there), and a verifier holding the member
    /// composes the shot's signed body with no request in hand. `placed` is
    /// the caller's — the member's own [`shot_terms`](M5State::shot_terms),
    /// or a count a checker chooses. A member with fewer positions than
    /// `placed` answers what it has; an absent arrangement answers nothing.
    pub fn address_form_of(&self, member: &Address, placed: &Nat) -> Vec<SegmentRun> {
        let trunk = trunk_of(member);
        self.content_list(member)
            .iter_resolve_range(&Nat::one(), placed)
            .map(|run| {
                if run_origin_document(&run).as_ref() == Some(&trunk) {
                    SegmentRun::Value(run)
                } else {
                    SegmentRun::Window(run)
                }
            })
            .collect()
    }
}
