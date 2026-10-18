//! PUBLISH, the shot (PUB-2.33): a published document's next member.
//!
//! The member is born published in one commit from the runs the client
//! supplied. Here too are its admission ([`shot_admission`]), its checks
//! through the source gate, offered to a door as a query — and `SettledRun`,
//! the one value its source gate, existence check and placement each walk.

use std::collections::BTreeSet;
use std::sync::Arc;

use skep_address::{Address, Nat};
use skep_content::{ContentStretch, ContentWrite, HasContent, Piece, Val};
use skep_kernel::{Seq, TxnError, WorldState};
use skep_namespace::{HasM3, M3Rec, M3State};

use super::{
    allocate_for_placement, allocate_stretch_for_placement, head_lock_key, Vstream,
    MAX_PLACED_RUNS, MAX_REINSERTED_VALUES,
};
use crate::chain::{published_target, trunk_head, trunk_of};
use crate::error::PublishError;
use crate::ownership::{gate_write, Caller};
use crate::run::Run;
use crate::run_list::extend_or_push_run;
use crate::run_union::RunUnion;
use crate::shot::{run_origin_document, Shot};
use crate::state::{M5Rec, ShotTerms};
use crate::HasM5;

/// One part of a draft-native run's re-insert.
///
/// It is copied out of the working slice before the run's first stage: a
/// maximal run of single-byte values — consecutive `Piece::Bytes`, and every
/// one-byte `Piece::Value` among them (the length test: the wire canonicalizes
/// a one-byte atom to its per-byte form, so the member's bytes and positions
/// are unchanged) — or any other value, an atom of two bytes or more or an
/// empty value, its `Val` cloned (a refcount bump). The walk completes into
/// an ordered list of these before anything is staged, because the pieces
/// borrow `stg.working().content()` and every stage takes `&mut Staging` and
/// must read the working slice after each push; bounded by the run's width
/// in bytes plus one `Val` handle per other value, under
/// `MAX_REINSERTED_VALUES`.
enum Part {
    Run(Vec<u8>),
    Atom(Val),
}

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3 + HasContent, // reads M3 (registration, mints) + M4 (writes, and the shot's byte reads) + M5
    W::Record: From<M5Rec> + From<M3Rec> + From<ContentWrite> + From<ContentStretch>, // stages M3Rec + ContentWrite/ContentStretch + M5Rec
{
    /// Appends the next member of `doc`'s chain, born published, in one commit.
    ///
    /// PUBLISH, the shot (PUB-2.33), takes the member's arrangement from the
    /// client-supplied runs of `shot` (PUB-8.1) and from nothing any draft
    /// holds at commit. Returns the member's address and the commit `Seq`.
    /// The birth version (PUB-2.34) is minted by this same composite — in the
    /// birth shape, `shot.base` absent, or off the memberless document named
    /// as its own base (the destination, below).
    ///
    /// **Destination** (PUB-2.37, PUB-2.39, PUB-2.55): the next member of the
    /// chain anchored at the base, decided at commit — the trunk's next member
    /// (`mint_version(trunk_of(doc))`, `D.4`) when the base is still the trunk
    /// head ([`trunk_head`], the head every floating reader answers from, read
    /// before the member is minted), the base's own daughter
    /// (`mint_version(base)`, `D.3.1`) when it is not. Two shots racing off
    /// one head both commit, the first on the trunk and the second as the
    /// head's daughter (PUB-2.44); nothing is positionally applied to an
    /// advanced head and nothing is refused for want of a base (PUB-2.38). A
    /// memberless document is its own base, and the base absent is the birth
    /// shape (PUB-2.34); either way the shot mints the birth version, the
    /// chain's first member `D.1`, and either form is admitted only while the
    /// chain is empty — once a member exists the document's own pre-chain
    /// arrangement is no base, and the shot must name the member it was staged
    /// from (`BaseSuperseded`). The two are one destination and not one
    /// arrangement: with no base there is no extent and so no carried tail,
    /// and a deposit that landed in the memberless document after the render
    /// stays in the pre-chain arrangement the member supersedes. A client
    /// wanting the deposit cell honored at birth names the document itself as
    /// its base, with the extent its render took.
    ///
    /// **The member's arrangement** (PUB-2.40, PUB-2.41, PUB-2.42): each
    /// supplied run by its origin document — the trunk (PUB-2.15) of the
    /// document that minted its addresses, which the run's own start settles
    /// (`document_of` then `trunk_of`) and the client's stated `origin` must
    /// project to. The document's own I-space (its own content chain or any
    /// member's) is placed by reference; the staging draft's is re-inserted as
    /// fresh identity under the document's own I-space, each maximal run of
    /// single-byte values as one stretch and each atom as its own value
    /// through INSERT's own allocation steps (`allocate_stretch_for_placement`,
    /// `allocate_for_placement`), the bytes read at the draft's addresses by
    /// M4's run read — a byte read, never an arrangement read — so the
    /// committed member references no address of the draft; any other
    /// document's stays a window, answering its origin. The three families are
    /// disjoint under [`Shot`]'s precondition on `draft`; a draft inside
    /// `doc`'s chain moves the document's own runs into the draft's family, as
    /// `Shot` states. The runs are placed in the order given, then the base's
    /// post-render deposits after them: a published member changes only by
    /// exempt deposits appended at fresh positions (PUB-2.43 — the
    /// append-only edition these operations keep, as [`Vstream`] states), so
    /// its positions past `base.extent` — the extent the staged copy took,
    /// which the client states and M5 refutes only when it exceeds the base's
    /// count ([`Base`](crate::Base) states the obligation) — are exactly the
    /// deposits the render post-dates, asked of the base's arrangement, which
    /// knows its own extent, and carried unchanged (PUB-2.45, PUB-2.67). What
    /// the shot un-arranges is what the stager un-arranged and nothing else.
    /// One [`M5Rec::ShotPlace`] journals the whole arrangement at ordinal 1 —
    /// the fold appends every placed run's I-extent to R (J1★), the
    /// by-reference runs as COPY's are and the fresh ones as INSERT's — and
    /// the shot's terms ([`ShotTerms`]; signed-ops D25): where the client's
    /// runs end — Σ width of its runs, the boundary the run-list erases
    /// whenever the last of them and the carried tail are I-adjacent — and the
    /// base's extent, absent in the birth shape. The record is pushed for
    /// every member the shot mints, an empty placement included, since the
    /// terms exist whatever the placement holds; an empty one leaves the
    /// member reading as the lazy empty arrangement — and a birth version so
    /// minted with its birth extent noted at zero. The member's link subspace
    /// starts empty either way: the shot places content alone, and a link
    /// seated in the base stays the base's — a link is arranged only in its
    /// home document (CL-OWN, PUB-2.12), and the member is a home no link has
    /// yet.
    ///
    /// **Where the fresh identity lands** (PUB-2.40), stated because a reader
    /// the ack does not tell reads it back. The values
    /// [`Shot::reinserted_runs`](crate::Shot::reinserted_runs) names —
    /// [`Shot::reinserted_values`](crate::Shot::reinserted_values) of them, a
    /// run named twice minted twice — are minted in that order, one after
    /// another, under the content chain of the document `doc` projects to
    /// (the member's own trunk), and the commit mints nothing else under that
    /// content chain: the member itself is minted on a version chain. Each
    /// content mint takes the content chain's next ordinal
    /// (`M3State::mint_content`, `M3State::mint_content_range`), the fact
    /// INSERT's one run rests on too, so in the world the commit leaves they
    /// are that content chain's last `reinserted_values()` addresses, just
    /// below its frontier (`M3State::next_content_address`) — where
    /// skep-media's cell index reads them, off the commit's own world, to
    /// enter any reference cell among them. A later content mint under that
    /// content chain moves its frontier past them.
    /// `the_values_a_shot_says_it_reinserts_are_the_values_its_commit_writes`
    /// pins the order, the content chain and the "nothing else", and
    /// `a_shot_judges_every_address_it_names_as_the_document_it_projects_to`
    /// the content chain of a shot a member names.
    ///
    /// `readable(world, origin_doc)` answers whether the shooter may read
    /// `origin_doc`; `true` admits it. M5 hands it the transaction's working
    /// world — the world in which `publish` has just found `origin_doc`
    /// registered — and asks only about an origin document (PUB-2.15): once
    /// per distinct origin document, in run order, skipping the document's
    /// own and every run the base already arranges. Because it is never asked
    /// of a world that has not registered what it is asked about, a predicate
    /// that is fail-open on an unregistered address (PUB-7.5), and that reads
    /// the world it is handed, cannot decide the gate.
    ///
    /// **Precondition** on `readable`, two clauses the composite cannot check.
    /// First, it answers off the world it is handed, as a function of that
    /// world and the origin document it is asked about — the same pair always
    /// answered alike. The guarantee above holds only for a predicate that
    /// reads that world: one that answers from a world captured before this
    /// transaction — an M2 snapshot, or a consult that ignores its argument —
    /// may be asked about an origin its world never registered, where a
    /// fail-open predicate admits it. And [`shot_admission`]'s one answer
    /// holds only for a predicate that answers each pair alike. Second, it
    /// runs inside this op's transaction, under M2's applier lock, so it
    /// inherits `transact`'s precondition: it must not call `transact` on this
    /// kernel (see Panics, below), and every other writer waits while it
    /// answers.
    ///
    /// **Locks.** The chain's head key (`head_lock_key(doc)`, the trunk's
    /// `version_lock_key`), `content_lock_key(trunk_of(doc))` (the
    /// fresh-identity mints), and the base's own version key when the base is
    /// a member — the daughter chain's frontier, taken since which chain the
    /// member joins is decided inside. Every origin is read off the
    /// transaction's working world; no origin is locked (a window is a
    /// reference).
    ///
    /// A member address given as `doc` is gated as named — its registration
    /// and ω — and then projected to its document (PUB-2.15): the shot is
    /// the document's, whichever member names it, and its publication, chain
    /// and base are judged on that document.
    ///
    /// `shot` is borrowed, as [`shot_admission`] borrows it: the composite
    /// reads the request — its admission, the re-insert's count, the
    /// existence walk — and clones each by-reference run into the member's
    /// placement, so taking it whole would cost a caller that keeps its
    /// request (to report it, or to ask its address form after the commit) a
    /// clone of every run, for nothing the composite moves.
    ///
    /// **Cost, and who owns it.** The re-insert pushes a mint and a content
    /// record per maximal run of single-byte values and per atom of each
    /// draft-native run — two records per run or atom, INSERT's own steps, so
    /// an unscattered draft of `n` typed bytes is two records and a draft of
    /// `n` atoms `2n` — and `n`, the values, is capped at
    /// [`MAX_REINSERTED_VALUES`], counted off the request before any address
    /// is probed. Beside them sit the member's mint and one placement, whose
    /// run count (the client's runs, coalesced, plus the base's deposit runs)
    /// is capped at [`MAX_PLACED_RUNS`], measured as each run is accumulated.
    /// Both are ceilings a shot cannot be split to meet, since the member it
    /// produces is born whole. Two terms are set by stored state rather than
    /// by the request's size. The carried-run test merges the base's runs into
    /// their union once per admission — `O(n log n)` in
    /// [`content_run_count`](crate::M5State::content_run_count) of the base,
    /// and pointers alone, one per run to sort them and room for two per run
    /// once built — and answers each supplied run by one binary search of it,
    /// whatever the run's width. The existence check
    /// probes every distinct address the supplied runs name, once — their
    /// I-extents merged first — stopping at the first one M4 does not hold.
    /// Over the draft-native runs that walk is bounded by the re-insert's cap;
    /// over the by-reference runs it is the union they name — for a shot that
    /// commits, every distinct position — which is the stored content the
    /// request points at and not its repetition of it: a run list naming one
    /// I-extent many times walks it once, and a short run list still walks as
    /// far as the stored content it names. The wire caps the run count and not
    /// that union. Those two — the base's run count, which the arrangement
    /// answers without reading a run, and the size of the union the
    /// by-reference runs name — are the numbers a route that carries this op
    /// owes.
    ///
    /// # Errors
    ///
    /// Each refusal comes as `TxnError::Rejected`, in this order (which error
    /// wins), PUB-6.36's slots: `DocNotRegistered` → `NotOwner` (slot 1, ω on
    /// the address named — the only question the shot asks of its caller, and
    /// one [`Caller::System`] passes) → registration (slot 3):
    /// `SourceNotRegistered` for the base, then the document the draft
    /// projects to (PUB-2.15), then each run's origin document in run order,
    /// each run's shape (`BadRun`) settled as its origin document is derived →
    /// `PrivateSourceVersionless` (slot 5: a private document has no chain,
    /// PUB-2.9's `true` face) → the base's shape: `BaseNotInChain` →
    /// `BaseSuperseded` → `BaseExtentTooLarge` → the source gate (slot 6,
    /// PUB-6.23; PUB-8.1's second constraint): `readable` consulted per
    /// distinct origin document, in run order, skipping the document's own
    /// I-space and every run the base already arranges (PUB-6.24's carried
    /// cell), the first unreadable origin document answering `Withheld` with
    /// it — before any existence answer, so a run onto an unreadable origin
    /// is refused whether or not its addresses exist; every verdict to here is
    /// [`shot_admission`]'s, which this composite opens with on its working
    /// world → `TooManyValues`
    /// ([`Shot::reinserted_values`](crate::Shot::reinserted_values) against
    /// [`MAX_REINSERTED_VALUES`] — request arithmetic, so it answers before
    /// any address is probed) → existence, `DanglingSource` where an address
    /// some run names holds no value, each run of the union of the runs'
    /// I-extents read once by M4's run read → then the placement, run by run
    /// in the order given: a draft-native run's maximal byte-runs and atoms
    /// `Mint` → `Content` apiece, and after each run `TooManyRuns` once the
    /// accumulator passes the budget; then `TooManyRuns` as the base's tail is
    /// carried; last the member's own `Mint`. The mints and writes are
    /// defensive (M3's frontier gate, M4's write-once guard), so on a correct
    /// store no honest request sees them contend with `TooManyRuns`. The
    /// kernel's own failures — `OverBudget`, `Unencodable`, `Durability`,
    /// `Poisoned` — come back as `transact_attested` returns them.
    ///
    /// # Panics
    ///
    /// Panics where `readable` calls `transact` on this kernel: M2 answers
    /// that nested write with its reentrancy panic, the caller's bug.
    pub fn publish(
        &self,
        caller: Caller,
        doc: &Address,
        shot: &Shot,
        readable: &dyn Fn(&W, &Address) -> bool,
    ) -> Result<(Address, Seq), TxnError<PublishError>> {
        let trunk = trunk_of(doc);
        // The values the shot re-inserts: request arithmetic, reading no
        // world, so taken before the transaction opens —
        // `Shot::reinserted_values`, the count's one spelling, which a caller
        // pricing the shot ahead of this op asks too. Refused at its own
        // slot, inside.
        let reinserted = shot.reinserted_values();
        let mut keys = vec![head_lock_key(doc), M3State::content_lock_key(&trunk)];
        if let Some(base) = &shot.base {
            if base.member != trunk {
                keys.push(M3State::version_lock_key(&base.member));
            }
        }
        // The attested arm (signed ops): `transact` itself where this handle
        // carries no attestation, else the same commit with its marker's
        // signature slot filled.
        self.kernel.transact_attested(&keys, self.attest, |stg| {
            // Slots 1 through 6 — the shot's admission, asked of this
            // transaction's working world: its verdicts are `shot_admission`'s,
            // and what the rest of the composite needs of it is the anchor
            // the member is minted under and the runs settled beside their
            // origin documents.
            let Admission { anchor, supplied } =
                admit(stg.working(), caller, doc, shot, readable)?;
            // Which runs are the staging draft's, re-inserted as fresh
            // identity rather than placed by reference (PUB-2.40) — the
            // family rule `Shot` states, by which `Shot::reinserted_runs`
            // names the runs this placement re-inserts: both compare the
            // run's origin document with `Shot::draft_document`, and
            // `the_values_a_shot_says_it_reinserts_are_the_values_its_commit_writes`
            // holds them to one answer, value for value and in the order they
            // land.
            let draft_doc = shot.draft_document();
            let draft_native = |origin_doc: &Address| draft_doc.as_ref() == Some(origin_doc);
            // The re-insert's size, refused before any address is probed:
            // every address of every draft-native run is re-inserted below,
            // two staged records per maximal byte-run or atom — two per value
            // at the worst case, every value an atom — and nothing M2 measures
            // stops the staging before it is whole. Request arithmetic
            // (`reinserted`, counted before the transaction opened), so it
            // discloses nothing — and refused here, it bounds the existence
            // walk over those runs too.
            if reinserted > Nat::from(MAX_REINSERTED_VALUES) {
                return Err(PublishError::TooManyValues);
            }
            // Existence (S3★): every address a run names holds a value. Each
            // address is asked, not only the start: a by-reference run is the
            // client's I-extent rather than one an arrangement resolved. Each
            // is asked once, over the union of the supplied runs' I-extents
            // (`RunUnion`), which holds every address any run names, each in
            // one of its runs: a value found there is found for every run
            // naming it, and a request naming one stored extent many times
            // walks it once. And each is asked through `pieces`, M4's run
            // read — one predecessor lookup per run of the union, then a walk
            // piece by piece, `covered` saying whether every address answered
            // — the accessor the re-insert below reads the draft-native bytes
            // with. COPY places by reference and reads no value back, so
            // presence is the whole of its question; the shot does read them,
            // and asking with the read's own accessor makes the answer found
            // here the answer the re-insert gets — M4's fold only ever adds
            // (S0), so no write staged in between can take a value away.
            let content = stg.working().content();
            for run in RunUnion::of(supplied.iter().map(|settled| settled.run)).runs() {
                if !content.pieces(run.i_start().tumbler(), run.width()).covered() {
                    return Err(PublishError::DanglingSource);
                }
            }
            // The shot's first term (signed-ops D25), `placed`: the positions
            // the client placed — Σ width of its runs, whatever family each
            // is — read off the request before the placement below erases
            // the boundary between the last of them and the carried tail,
            // which `placed` never counts.
            let placed = supplied.iter().map(|settled| settled.run.width()).sum::<Nat>();
            // The member's placement: the client's runs in order — the
            // draft-native ones re-inserted as fresh identity under the
            // document's own I-space — then the base's post-render deposits.
            let mut placement: Vec<Run> = Vec::new();
            for SettledRun { run, origin_doc } in supplied {
                if draft_native(&origin_doc) {
                    // The walk completes before the first stage ([`Part`]):
                    // the run's pieces, read by M4's run read off the working
                    // slice, are copied into an owned, ordered list — every
                    // `Bytes` piece and every one-byte `Value` extending the
                    // pending byte-run, every other `Value` (an atom of two
                    // bytes or more, or an empty one) closing it and taking
                    // its `Val` by clone — `covered` is asked, the borrow of
                    // the working slice ends, and only then is each part
                    // staged in the list's order: a maximal byte-run as one
                    // stretch under the trunk's chain, each other value as
                    // its own mint and write. So a draft typed in bursts and
                    // published unscattered is one stretch in the member, and
                    // one whose edits scattered its arrangement into K runs
                    // costs K.
                    let parts = {
                        let content = stg.working().content();
                        let mut pieces = content.pieces(run.i_start().tumbler(), run.width());
                        let mut parts: Vec<Part> = Vec::new();
                        let mut pending: Vec<u8> = Vec::new();
                        for piece in pieces.by_ref() {
                            match piece {
                                Piece::Bytes(bytes) => pending.extend_from_slice(bytes),
                                // The length test: a one-byte value is a
                                // per-byte value, and joins the run.
                                Piece::Value(v) if v.len() == 1 => {
                                    pending.extend_from_slice(v.as_bytes());
                                }
                                Piece::Value(v) => {
                                    if !pending.is_empty() {
                                        parts.push(Part::Run(std::mem::take(&mut pending)));
                                    }
                                    parts.push(Part::Atom(v.clone()));
                                }
                            }
                        }
                        assert!(
                            pieces.covered(),
                            "the existence check found a value at every address of every run, and M4's fold only adds"
                        );
                        if !pending.is_empty() {
                            parts.push(Part::Run(pending));
                        }
                        parts
                    };
                    for part in parts {
                        match part {
                            Part::Run(bytes) => allocate_stretch_for_placement::<_, PublishError>(
                                stg,
                                &trunk,
                                Arc::from(bytes),
                                &mut placement,
                            )?,
                            Part::Atom(value) => allocate_for_placement::<_, PublishError>(
                                stg,
                                &trunk,
                                value,
                                &mut placement,
                            )?,
                        }
                    }
                } else {
                    extend_or_push_run(&mut placement, run.clone());
                }
                if placement.len() > MAX_PLACED_RUNS {
                    return Err(PublishError::TooManyRuns);
                }
            }
            // The base's positions past the extent its staged copy took are
            // the deposits the render post-dates (PUB-2.43, PUB-2.45) — asked
            // of the arrangement, which knows its own extent, and measured as
            // each is accumulated, the walk stopping at the cap.
            if let Some(base) = &shot.base {
                for run in stg.working().m5().content_runs_past(&base.member, &base.extent) {
                    extend_or_push_run(&mut placement, run);
                    if placement.len() > MAX_PLACED_RUNS {
                        return Err(PublishError::TooManyRuns);
                    }
                }
            }
            // The member: born published (PUB-2.5, PUB-2.10), under the
            // anchor its admission decided.
            let (member, m3rec) = stg.working().m3().mint_version(&anchor, true)?;
            stg.push(m3rec.into());
            // Its placing record, pushed whatever the placement holds: the
            // whole arrangement and the shot's terms, the base's extent absent
            // in the birth shape (signed-ops D25).
            stg.push(
                M5Rec::ShotPlace {
                    doc: member.clone(),
                    runs: placement,
                    terms: ShotTerms {
                        placed,
                        base_extent: shot.base.as_ref().map(|base| base.extent.clone()),
                    },
                }
                .into(),
            );
            Ok(member)
        })
    }
}

/// Returns the shot's admission: `publish`'s checks through its source gate.
///
/// They are the checks [`Vstream::publish`] makes through its source gate,
/// before it probes an address, stages a record or mints: registration and ω
/// of the address named, the registration and shape of every argument, the
/// document's publication, the base's shape, and the source gate — PUB-6.36's
/// slots 1 through 6, in the order `publish` states — asked of `world` and
/// nothing else. `Ok` is a shot `publish` carries past its source gate in
/// `world`; whatever it answers after that — `TooManyValues` onward — is the
/// composite's alone.
///
/// **One answer, not two**: `publish` opens with this check on its working
/// world, so a door asking it of the world the transaction will open on,
/// with the predicate `publish` will be handed, is told what `publish` will
/// answer through its gate, with nothing simulated or staged to learn it.
/// `readable` is asked as `publish` asks it — once per distinct origin
/// document, in run order, of `world` — and is held to the first clause of
/// `publish`'s precondition on it: a function of the world it is handed and
/// the origin it is asked about. The one answer rests on that premise, which
/// nothing here can check: a predicate that answers one pair two ways — off a
/// budget, a clock or a count of its calls — can tell this query one thing
/// and `publish` another.
///
/// **Cost**: `publish`'s own through its gate — the carried-run test (the
/// base's runs merged into their union once, each supplied run one search of
/// it), one consult per distinct origin document — and nothing of the
/// existence walk or the placement. It reads no content store, so a world of
/// M3 and M5 alone answers it.
///
/// # Errors
///
/// `Err` is the refusal `publish` answers there, and only a verdict of those
/// slots: `DocNotRegistered`, `NotOwner`, `SourceNotRegistered`, `BadRun`,
/// `PrivateSourceVersionless`, `BaseNotInChain`, `BaseSuperseded`,
/// `BaseExtentTooLarge`, `Withheld` — the first in the order `publish`
/// states.
pub fn shot_admission<W: HasM3 + HasM5>(
    world: &W,
    caller: Caller,
    doc: &Address,
    shot: &Shot,
    readable: &dyn Fn(&W, &Address) -> bool,
) -> Result<(), PublishError> {
    admit(world, caller, doc, shot, readable).map(|_| ())
}

/// Runs `publish`'s checks through its source gate, asked of `world` alone.
///
/// They are PUB-6.36's slots 1 to 6, in the order `publish` states:
/// [`shot_admission`]'s verdict, with what the rest of the composite needs of
/// it.
///
/// # Errors
///
/// Returns [`shot_admission`]'s refusal, the first in the order `publish`
/// states.
fn admit<'s, W: HasM3 + HasM5>(
    world: &W,
    caller: Caller,
    doc: &Address,
    shot: &'s Shot,
    readable: &dyn Fn(&W, &Address) -> bool,
) -> Result<Admission<'s>, PublishError> {
    let trunk = trunk_of(doc);
    // Slot 1: registration and ω, on the address named.
    gate_write(
        world.m3(),
        caller,
        doc,
        PublishError::DocNotRegistered,
        PublishError::NotOwner,
    )?;
    let (m3, m5) = (world.m3(), world.m5());
    // Slot 3: registration — the base, the document the draft projects to,
    // every origin document (PUB-6.37: an unregistered argument answers
    // registration and nothing later).
    if let Some(base) = &shot.base {
        if !m3.is_registered_document(&base.member) {
            return Err(PublishError::SourceNotRegistered);
        }
    }
    if let Some(draft_doc) = shot.draft_document() {
        if !m3.is_registered_document(&draft_doc) {
            return Err(PublishError::SourceNotRegistered);
        }
    }
    // Each run settled beside its origin document (`SettledRun`): derived
    // from the run's own start, required to be the document the client's
    // stated `origin` projects to, then registered — the first defective run
    // in order deciding.
    let supplied: Vec<SettledRun<'s>> = shot
        .runs
        .iter()
        .map(|stated| -> Result<SettledRun<'s>, PublishError> {
            let origin_doc = run_origin_document(&stated.run).ok_or(PublishError::BadRun)?;
            if origin_doc != trunk_of(&stated.origin) {
                return Err(PublishError::BadRun);
            }
            if !m3.is_registered_document(&origin_doc) {
                return Err(PublishError::SourceNotRegistered);
            }
            Ok(SettledRun {
                run: &stated.run,
                origin_doc,
            })
        })
        .collect::<Result<_, _>>()?;
    // Slot 5: the model's refusal — a private document has no chain to
    // append to (PUB-2.9).
    if !published_target(m3, doc) {
        return Err(PublishError::PrivateSourceVersionless);
    }
    // The base's shape, and the anchor the member is minted under — judged
    // against the head every floating reader answers from, read before the
    // member is minted.
    let head = trunk_head(m3, doc);
    let anchor = match &shot.base {
        None => {
            if head.is_some() {
                return Err(PublishError::BaseSuperseded);
            }
            trunk.clone()
        }
        Some(base) => {
            if base.member == trunk {
                if head.is_some() {
                    return Err(PublishError::BaseSuperseded);
                }
            } else if trunk_of(&base.member) != trunk {
                return Err(PublishError::BaseNotInChain);
            }
            if base.extent > m5.content_count(&base.member) {
                return Err(PublishError::BaseExtentTooLarge);
            }
            // The head/pinned distinction is the commit's own (PUB-2.39's
            // head/older): the memberless document, or a base that is still
            // the head ⇒ the trunk's next member; else the base's daughter.
            if base.member == trunk || head.as_ref() == Some(&base.member) {
                trunk.clone()
            } else {
                base.member.clone()
            }
        }
    };
    // Slot 6: the source gate, per distinct origin document, in run order —
    // the document's own I-space needs no consult, a run the base already
    // arranges takes none (PUB-6.24), and the first unreadable origin
    // document speaks before any existence answer. An origin document joins
    // `admitted` only once the consult admits it: a carried run adds nothing
    // to it, so a later run from the same origin that the base does not
    // arrange is still asked about. The base's runs are merged into their
    // union once, at the first run the gate must ask about, and every run is
    // then one search of it: a carried run admits no origin, so a request of
    // carried runs asks this of every one.
    let mut base_union: Option<RunUnion<'_>> = None;
    let mut admitted: BTreeSet<&Address> = BTreeSet::new();
    for SettledRun { run, origin_doc } in &supplied {
        if *origin_doc == trunk || admitted.contains(origin_doc) {
            continue;
        }
        let carried = shot.base.as_ref().is_some_and(|base| {
            base_union
                .get_or_insert_with(|| RunUnion::of(m5.content_runs(&base.member)))
                .covers(run)
        });
        if carried {
            continue;
        }
        if !readable(world, origin_doc) {
            return Err(PublishError::Withheld(origin_doc.clone()));
        }
        admitted.insert(origin_doc);
    }
    Ok(Admission { anchor, supplied })
}

/// What the shot's admission ([`admit`]) hands the rest of the composite.
///
/// It is the anchor its member is minted under — decided with the base's
/// shape — and the runs settled beside their origin documents.
struct Admission<'s> {
    anchor: Address,
    supplied: Vec<SettledRun<'s>>,
}

/// A supplied run beside the origin document its own start settles.
///
/// The document is [`run_origin_document`]'s, checked against the client's
/// stated `origin` and found registered: the one value the shot's source
/// gate, existence check and placement each walk, so every question about a
/// run is asked of that run's own origin document and no second list has to
/// stay in step with the runs for the gate to judge the run it is looking at.
/// [`ShotRun`](crate::ShotRun) is the client's statement; this is the
/// statement checked, beside the run it checked.
struct SettledRun<'s> {
    run: &'s Run,
    origin_doc: Address,
}

#[cfg(test)]
mod tests;
