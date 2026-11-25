//! The pure core of the merge — the merge record's §7 `compose_runs`.
//!
//! A base and its sides come in as run lists, as `image` delivers them,
//! with the document the merge lands on; the merged list, the gap report
//! and the run counts go out; every value read is made through a closure
//! the caller supplies, so a test needs no board. `compose_asking` takes the
//! line rule's reads through a closure of their own, told beside each run
//! which pair of changes it decides (`LinePair`), so a caller whose read is
//! refused can say which; that closure answers only where a run's line
//! breaks fall (`LineRead`), so no byte the line rule reads outlives its
//! read.
//! The record's §1.4 states the composition in seven steps, and the seven
//! private functions `removals`, `spine_of`, `additions`, `placement`,
//! `gaps`, `splice` and `report` are those steps in that order, with
//! `collision_regions` and `lone_removals` feeding `gaps` and `resolve`
//! applying step 7's resolutions ahead of the splice. Before them
//! `claim_identities` finds each fresh identity several sides hold: at one
//! spot it is kept once, by the holder whose keeping breaks no holder's own
//! order (`Kept::of`), whichever side is listed first — a holder that
//! orders it otherwise, or sets words of its own beside it, keeping its
//! copy at a gap that asks, where the splice lays it once — and at two or
//! more it is a `moves` gap with spots (CM-I33), the merger's choice of
//! holder applied before the walk. §2's rules decide each gap's kind and
//! its default — the sides' reorders folded into the spine in the order
//! listed (`fold`), and two sides' neighbouring changes met at a line's
//! edge — two additions, R2's `anchor` among them, or an addition and a
//! removal one side alone made with no words of its own in its place
//! (`lone_removals`), each a change the other side did not also make, a
//! word kept once counted as each holder's that placed it (`Placers`) —
//! which `line_edges` decides inside `gaps`, whatever the switches, off as
//! much of the base text between them as the answer needs, never a run of
//! it past that (skep #1173, #1174, #1176); §5's value rule reads bytes at a
//! shared gap (the dedup) and, switched on, before the walk (the retype),
//! logging each run either takes out of M.
//! Beside the core stand the two other pure functions §7 names: [`base_of`],
//! the nearest common ancestor of two members by §1.2's address forms —
//! the record on the trunk, where every member was minted against the one
//! before it; below the trunk the reads walk the bases the board recorded
//! instead (the `reads` module) — and [`script`], the in-place edit script
//! that turns a draft's list into a target — a preview; the draft landing
//! sends one `set_arrangement`.
//!
//! The vocabulary is the record's. A run is `(origin, i_start, width)`. The
//! base is the state every side descends from: a member, or the document's
//! own arrangement from before its first version. The spine is the surviving
//! base material in the order M keeps it. A side's run is fresh when its
//! positions are not the base's. A stretch is a side's maximal run of fresh
//! material at one place, with its two anchors: the base positions
//! immediately before and after it in that side's own sequence, the ends of
//! the document standing in where there is none. A spot is the pair of
//! anchors a stretch sits between. A gap is a place in M between two
//! surviving base positions, or at either end, where some side placed
//! material or where two sides removed the same material — save a `moves`
//! gap, which is no place but a side's reorder the spine did not take, or
//! one fresh identity two sides placed at two spots, each spot read by the
//! base positions both keep.
//!
//! The lists are never expanded to positions. The walk is made over the
//! fragments of the lists' common refinement — every run cut at every
//! other run's edges, so a fragment lies wholly inside or wholly outside each
//! list — and a fragment stands for its positions in every rule below. A
//! run a list places twice is two placements, each its own position in
//! every rule (skep #763): the second placement of a fragment is a fragment
//! of its own, the same across the lists, so a copy every list holds is
//! shared material and a copy one list adds is its addition. The cost is in
//! runs, not in width.
//!
//! Nothing here dials, reads or writes. The one crate this file links is
//! `skep-address`, for the address form the anchors are reported in.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};

use skep_address::{content_subspace, elem_addr, validate, Address, ElemPos, Level, Nat, Tumbler};

// ── the public types ──────────────────────────────────────────────────────

/// A run as a side's `image` delivers it (merge record, vocabulary).
///
/// `width` content positions of the document `origin`, the first at ordinal
/// `i_start`: the position `origin·0·1·i_start` and the `width − 1` after
/// it. The origin is a document address — the chain that minted the
/// positions, which for a member's own text is its trunk and for a window
/// is the other document. The crate's `image` answer carries a prefix string
/// and a V-ordinal instead; the merge's reads convert it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Run {
    /// The document whose chain minted the positions.
    pub origin: Address,
    /// The first position's ordinal in the origin's content subspace.
    pub i_start: u64,
    /// How many positions the run holds; a run of width 0 is malformed.
    pub width: u64,
}

impl Run {
    /// Returns a run over `width` positions of `origin` from `i_start`.
    pub fn new(origin: Address, i_start: u64, width: u64) -> Run {
        Run { origin, i_start, width }
    }

    /// Returns the ordinal one past the run's last position, its exclusive end.
    ///
    /// It is the daemon's own notion of a run's reach, which two runs are
    /// I-adjacent at. It saturates at the top of the range rather than wrap.
    pub fn reach(&self) -> u64 {
        self.i_start.saturating_add(self.width)
    }

    /// Returns the address of the run's position at offset `k`.
    ///
    /// `None` for `k` at or past the width, for an origin that is no
    /// document address, and for an ordinal past the range or one the
    /// address grammar refuses.
    pub fn address_at(&self, k: u64) -> Option<Address> {
        if k >= self.width {
            return None;
        }
        element_address(&self.origin, self.i_start.checked_add(k)?)
    }

    /// Returns the stretches of the run's positions no run of `others` holds.
    ///
    /// They come in the run's order, each as a run of the same origin: the
    /// run whole where nothing of `others` overlaps it, nothing where
    /// `others` cover it, and a run of another origin holds none of it. A
    /// gap lists a word two sides placed alike under each side that keeps it
    /// (`Gap::runs`), and M lays it once: this reads a side's runs less
    /// those another side already lays.
    pub fn without<'a>(&self, others: impl IntoIterator<Item = &'a Run>) -> Vec<Run> {
        let mut covered: Vec<(u64, u64)> = others
            .into_iter()
            .filter(|o| o.origin == self.origin)
            .map(|o| (o.i_start.max(self.i_start), o.reach().min(self.reach())))
            .filter(|(lo, hi)| lo < hi)
            .collect();
        covered.sort_unstable();
        let mut out = Vec::new();
        let mut cursor = self.i_start;
        for (lo, hi) in covered {
            if lo > cursor {
                out.push(Run::new(self.origin.clone(), cursor, lo - cursor));
            }
            cursor = cursor.max(hi);
        }
        if cursor < self.reach() {
            out.push(Run::new(self.origin.clone(), cursor, self.reach() - cursor));
        }
        out
    }
}

/// The index of a side among the sides given to [`compose_runs`].
///
/// The record's `side` in a gap's runs: `0` the first side listed, which is
/// the head in every shape the record draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SideIx(pub u8);

/// A gap's number in the report, counted from 1, the `moves` gaps first.
///
/// The `moves` gaps with spots come first, each one fresh identity two or
/// more sides placed at different spots (CM-I33), then the spine's. The
/// other gaps are numbered in the order of their default places in M. No
/// resolution renumbers a gap — not one that moves it, not one that moves a
/// gap with spots' words, not the order chosen at a spine's `moves` gap
/// (skep #1155) — so every resolution in one list names a gap by its number
/// in the report composed with no resolution, and a gap only a resolution
/// makes is numbered after that report's last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GapId(pub u32);

/// One delivery item of a run's value, as `retrieve_v` delivers it.
///
/// It is the bytes of one position, or of one atom. The crate holds no
/// public delivery-item type of its own, so the item is its bytes; two runs
/// are equal under the value rule when their items are.
pub type Item = Vec<u8>;

/// The composition's switches (merge record §5 and §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// The value rule's dedup (§5, case (g)), on by default.
    ///
    /// At an `order` gap where two sides placed equal bytes, one identity is
    /// kept, the earlier side's.
    pub dedup: bool,
    /// The value rule's retype normalization (§5, case (f)), off by default.
    ///
    /// A side that removed base bytes and placed equal fresh bytes in their
    /// place keeps the base's identity instead, where another side still
    /// holds those base bytes to read them through.
    pub retype: bool,
    /// The merger's choices at gaps the rules left unsettled (§1.4 step 7).
    pub resolutions: Vec<Resolution>,
    /// How many times this merge's publish landed as a daughter.
    ///
    /// Each time, the merger composed again (merge record decision 17). It
    /// is carried for the record the landing writes; the composition does
    /// not read it.
    pub retries: u32,
}

impl Default for Options {
    fn default() -> Options {
        Options { dedup: true, retype: false, resolutions: Vec::new(), retries: 0 }
    }
}

/// The merger's choice at one gap, overriding its default.
///
/// The merge record draws it at §1.4 step 7 and §2, "what unsettled means".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// The gap resolved, by its number in the report.
    pub gap: GapId,
    /// What the merger chose.
    pub choice: Choice,
    /// Who chose.
    pub by: ResolvedBy,
}

/// What a merger can choose at a gap (merge record §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    /// The sides' groups in this order; a side left out is not placed.
    ///
    /// At a `moves` gap, the one side whose order the spine takes — the
    /// side whose order it took, confirmed, or the other, whose reorder is
    /// then applied first and every other side's folded after it; at one
    /// with spots, the one side whose placement of the words M takes.
    Order(Vec<SideIx>),
    /// The gap's material placed after this surviving base position.
    ///
    /// It lands at the first place after the position where some list's run
    /// starts or ends — right after it where one does. Where the base places
    /// the position's run twice (skep #763) the address names each
    /// placement: the gap goes to the place every move naming it names,
    /// else the last move's, the nearest its composed place among them.
    After(Address),
    /// The gap's material placed before this surviving base position.
    ///
    /// It lands at the last place at or before the position where some
    /// list's run starts or ends — right before it where one does. Where the
    /// base places the position's run twice, as `After`.
    Before(Address),
    /// Only this side's material placed; the other sides' is left out.
    ///
    /// Every word the side placed at the gap is its material, a word another
    /// side placed alike among them (`Gap::runs`). At a `moves` gap with
    /// spots, as `Order` of this one side.
    KeepOnly(SideIx),
    /// Every group placed as composed, confirmed.
    ///
    /// It confirms the gap's placement as the composition left it — an
    /// order the value rule's dedup thinned included, never putting a
    /// dropped copy back (§5, case (g)); a gap of fewer than two groups
    /// takes none.
    KeepBoth,
    /// Nothing placed: the gap's material left out of M.
    ///
    /// Its bytes stand where the side holds them.
    Omit,
}

/// Who settled a gap (merge record §4, `resolved_by`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedBy {
    /// The rules of §2, or the value rule's dedup (§5), with no choice asked.
    Rule,
    /// A person, with judgment.
    Person,
    /// An agent, with judgment.
    Agent,
    /// An answer record at this address, read by an agent under its brief.
    Answer(Address),
}

/// The seven kinds of gap (merge record §2, §4; skep #1173).
///
/// The rules settle one of them, `Anchor`; the other six are the merger's,
/// save an `order` gap the value rule's dedup settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GapKind {
    /// Two or more sides added at one spot: unsettled (R1).
    ///
    /// The default is the commit order. Words several sides placed alike
    /// there make one where the sides order them otherwise, or each set words
    /// of their own beside them (`compose_runs`).
    Order,
    /// An addition beside a removal, one of its anchors surviving (R2).
    ///
    /// The adding side's own removal overlaps nothing another side removed:
    /// settled, placed beside the survivor, save where another side's change
    /// meets it at a line's edge, a `line` gap with that place its default.
    Anchor,
    /// An addition whose anchors are both gone: unsettled (R3).
    ///
    /// The default is after the nearest surviving base position to its left.
    Corner,
    /// An addition whose anchors both survive but no longer stand together.
    ///
    /// The spine's order parts them — another side's move, or the base's
    /// where the adding side's own move is not applied: unsettled, the
    /// default after the left anchor (R4 i).
    Cut,
    /// Two or more sides removed overlapping base material: unsettled (R4 ii).
    ///
    /// It holds whether all, some or none of them put something in its
    /// place; the default is what was put there, kept in the commit order
    /// after the left survivor.
    Collision,
    /// A side's reorder the spine did not take: unsettled (R4 iii).
    ///
    /// With no `spine_hint` the sides' reorders fold in the order listed,
    /// each applied where it composes with those applied before it, and it
    /// arises for each that does not, as where two sides reordered
    /// overlapping material: the default is the order the fold gave, the
    /// side's reorder not applied, the gap naming the earliest applied side
    /// its reorder overlaps as the one whose order the spine took. Under a
    /// `spine_hint` the default is the hinted side's order, and each other
    /// side whose reorder differs from it is a `moves` gap.
    ///
    /// It is also one fresh identity two or more sides placed at different
    /// spots (CM-I33): unsettled, the default the earliest holding side's
    /// placement, every other holder's copy left out, its [`Gap::spots`]
    /// naming each holder's spot. The same identity at one spot is no gap.
    Moves,
    /// One side's addition next in M to another side's change at a line's
    /// edge: unsettled, the default its own place (skep #1173, #1176).
    ///
    /// The change is another side's addition, or a stretch of base material
    /// one other side alone removed with no words of its own in its place,
    /// which stands in M as a point where its bytes were. The two stand at
    /// different places with only surviving base text between them, one
    /// inside a line and the other right after that line's break, or one at
    /// a line's start — the document's start among them — and the other
    /// inside that line; a line break is the byte `\n`. Each addition of the
    /// two held by one side alone is a `line` gap, a removal beside it named
    /// in its [`Gap::removed`], and words two or more sides added at one spot
    /// stay an `order` gap. An addition beside a removal is one too, R2's
    /// place beside its surviving anchor its default. Each of the two is a
    /// change the other's side did not also make: a word several sides placed
    /// alike is each one's, whichever keeps the copy M lays, so a side whose
    /// every change the other side made too asks nothing. Two changes inside
    /// one line ask nothing, nor do two a whole line or more apart — a
    /// removal from a line's start beside an addition right after that
    /// line's break among them — nor two the reads of whose base text
    /// between them `values` does not answer one item a position, nor a pair
    /// one of which is a cut, a corner or a collision, which asks already. A
    /// removal stands whatever the merger chooses: the gap's choices place
    /// the addition.
    Line,
}

/// How a gap's material was laid in M (merge record §4, `placed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    /// The sides whose material was placed, in that order.
    ///
    /// At a `moves` gap, the one side whose order the spine took; at one
    /// with spots, the one side whose placement of the words M took.
    Order(Vec<SideIx>),
    /// Placed immediately after the surviving base position before the gap.
    After,
    /// Placed immediately before the surviving base position after the gap.
    Before,
    /// Nothing placed: the merger's `Omit`.
    Omitted,
}

/// One gap of the report (merge record §1.4 step 7, §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    /// The gap's number, counted from 1, the `moves` gaps first.
    ///
    /// Those with spots come before the spine's; the other gaps are
    /// numbered in the order of their default places in M ([`GapId`]).
    pub id: GapId,
    /// Its kind.
    pub kind: GapKind,
    /// The surviving base position M holds immediately before the gap.
    ///
    /// `None` at the start of M, and at a `moves` gap.
    pub after: Option<Address>,
    /// The surviving base position M holds immediately after the gap.
    ///
    /// `None` at the end of M, and at a `moves` gap.
    pub before: Option<Address>,
    /// The contested runs with the side each came from, in the default order.
    ///
    /// Each side's runs come in its own order. A word several sides placed
    /// alike at the gap is listed under each side that keeps it there, and M
    /// lays it once, where the first side laid takes it ([`Run::without`]).
    /// At a `moves` gap, the material each side moved; at one with spots,
    /// each holding side's runs of the one identity, in the side's order.
    pub runs: Vec<(SideIx, Run)>,
    /// How the runs were laid in M.
    pub placed: Placement,
    /// Whether the placement asks no choice.
    pub settled: bool,
    /// Who settled it: the rule, a merger, or no one yet.
    pub resolved_by: Option<ResolvedBy>,
    /// Each holding side's spot, at a `moves` gap of one fresh identity
    /// two or more sides placed apart (CM-I33), in side order.
    ///
    /// Empty at every other gap.
    pub spots: Vec<Spot>,
    /// Each removal that meets a `line` gap's words at a line's edge, in
    /// M's order (skep #1176).
    ///
    /// Each is a stretch of base material another side alone removed with no
    /// words of its own in its place. It stands whatever the merger chooses,
    /// since the gap's choices place its words alone. Empty at every other
    /// gap, and at a `line` gap that only another side's addition meets.
    pub removed: Vec<Removed>,
}

/// Where one side placed the words a `moves` gap with spots contests.
///
/// The spot is read off the side's own sequence by the base positions
/// every holding side keeps (CM-I33), so a neighbour one side removed moves
/// nothing: the nearest such position before the words and after them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spot {
    /// The side.
    pub side: SideIx,
    /// The base position the side's placement follows, `None` at the start.
    pub after: Option<Address>,
    /// The base position the side's placement precedes, `None` at the end.
    pub before: Option<Address>,
}

/// A removal a `line` gap names: base material one side alone removed.
///
/// It is read as a gap's place is, by the surviving base positions M holds
/// either side of where its bytes were (skep #1176).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removed {
    /// The side that removed it.
    pub side: SideIx,
    /// The surviving base position M holds just before it, `None` at M's
    /// start.
    pub after: Option<Address>,
    /// The surviving base position M holds just after it, `None` at M's end.
    pub before: Option<Address>,
}

/// One run of M with the side that placed it (merge record §1.5, `Merged`).
///
/// The record's `family` member — own, window or draft-native — needs the
/// reads to tell a window from an own run, so the merge's reads add it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacedRun {
    /// The run, coalesced as the member will hold it.
    pub run: Run,
    /// The side whose fresh material begins the run.
    ///
    /// `None` for a run that begins with the base's material. A run two
    /// sides' adjacent fresh runs coalesced into carries the first's.
    pub side: Option<SideIx>,
}

/// The run counts the record keeps (merge record §8, decision 17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunCounts {
    /// The first side's runs as given.
    pub a: usize,
    /// The other sides' runs as given, together.
    ///
    /// The record keeps two numbers, and every side after the first is an
    /// alternative.
    pub b: usize,
    /// M's runs, coalesced.
    ///
    /// It is the count the shot carries and the cap is checked against.
    pub m: usize,
}

/// The value rule's switches and where it fired (merge record §4, `values`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueLog {
    /// The dedup switch as composed.
    pub dedup: bool,
    /// The retype switch as composed.
    pub retype: bool,
    /// The gaps where the dedup dropped a side's copy.
    pub applied: Vec<GapId>,
    /// Each fresh run the retype normalization took out of M, with the side
    /// that placed it (§5, case (f)).
    ///
    /// Its bytes equal the base material the side removed in its place, so M
    /// holds that material by the base's identity instead, and any link on
    /// the run stays in its side. Empty with the retype off.
    pub retyped: Vec<(SideIx, Run)>,
}

/// What [`compose_runs`] returns.
///
/// It holds M, the gap report, the counts, the value log, and the
/// resolutions it could not apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Composed {
    /// The merged list, coalesced by I-adjacency as the member will hold it.
    pub runs: Vec<PlacedRun>,
    /// Every gap by number ([`GapId`]): the `moves` gaps, then the others.
    ///
    /// The `moves` gaps with spots come before the spine's, and the others
    /// in the order of their default places in M — at the default order,
    /// where a side's order is chosen at a spine's `moves` gap — then every
    /// gap only a resolution makes. A one-sided addition between two
    /// surviving anchors that stand together asks nothing and is not listed,
    /// save one next to another side's addition or lone removal at a line's
    /// edge ([`GapKind::Line`]), nor is a fresh identity several sides placed
    /// at one spot in one order, one side's words there an in-order part of
    /// another's.
    pub gaps: Vec<Gap>,
    /// The run counts.
    pub counts: RunCounts,
    /// The value rule's log.
    pub values: ValueLog,
    /// The resolutions not applied.
    ///
    /// Each named no gap of this report, a gap the rules had settled, a
    /// choice the gap cannot take, or a gap the order chosen at a spine's
    /// `moves` gap removes (skep #1155); each stands here untouched, so the
    /// caller sees what was not applied.
    pub ignored: Vec<Resolution>,
}

/// One in-place edit of a draft, as [`script`] spells it.
///
/// The edits take the form of the wire's `delete` and `reinstate`, positions
/// in the draft's content ordinals, counted from 1. They are a preview of
/// what turning the draft into its target would take as in-place edits; the
/// draft landing sends none of them — it is one `set_arrangement` — so no
/// frame is built from one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InPlaceOp {
    /// Removes `width` positions from position `p` of the draft.
    ///
    /// The position is the draft's as it stands when the op is applied.
    Delete {
        /// The first position removed.
        p: u64,
        /// How many positions.
        width: u64,
    },
    /// Places `runs` by identity before position `at` of the draft.
    ///
    /// The position is the draft's as it stands when the op is applied; `at`
    /// one past the content appends.
    Reinstate {
        /// The position the first placed run takes.
        at: u64,
        /// The runs placed, in order.
        runs: Vec<Run>,
    },
}

// ── the core ──────────────────────────────────────────────────────────────

/// Composes the sides over the base: M, the gap report and the counts.
///
/// `base` is the base's run list — a member's, or the document's own
/// arrangement from before its first version, empty on most documents — and
/// each side its own, every list as `image` delivers it, the sides in
/// commit order. `doc` is the trunk the merge lands on, the bare document
/// named as the origin of every run of its own text (`origin_of`). The
/// document's chain is that text and every origin the base holds, whatever
/// the base holds — an empty base included — and the order rule puts a
/// group whose first run is in the chain before every group whose first run
/// is not: a window onto a document the base holds nothing of, a draft's
/// fresh text, a fork's (merge record §2 R1; skep #1115); groups whose first
/// runs are one are ordered by their next. `spine_hint` names
/// the side whose order the spine takes where the sides disagree about the
/// order of the surviving base material; `None` computes it — the base's
/// order, or the one side's that reordered, or the reorders of two or more
/// sides folded in the order listed, each composed with those applied
/// before it where they touch different material, and each that does not a
/// `moves` gap, its reorder not applied, so one overlapping pair voids
/// neither the other sides' reorders nor its earlier side's. `values`
/// answers a side's run with its items: the value rule compares them, and
/// the line rule reads through the first side listed as much of the
/// surviving base text between two sides' neighbouring changes — two
/// additions, or an addition and a removal one side alone made with no
/// words of its own in its place — as its answer needs
/// ([`GapKind::Line`]) — the position before the first, the text's last
/// byte and its first 4,096 positions, read on from them only where a
/// longer line leaves the answer open, and of the removals beside one
/// addition the nearest first, a farther one weighed only where the nearer
/// one's reads showed no break that parts it from the addition, a run whose
/// every position an earlier read answered not asked again — whatever the
/// value rule's switches; a run asked may be a part of a run the side
/// holds; `None` leaves the rule that asked unfired there. The line rule
/// keeps no item it reads: each answer is taken down to where its line
/// breaks fall as it arrives (`LineRead`). The composition writes nothing
/// and dials nothing (merge record §1.4, §7).
///
/// Before the walk, a fresh identity two or more sides hold is kept by one
/// of them. Where every holder placed it at one spot — the nearest base
/// position before it and after it that every holder keeps — it is kept
/// once, where it breaks no holder's own order and asks the least: in a
/// holder's own stretch, or at that common spot, read off each list's
/// anchors and never off the order the sides are listed in but where two
/// places rank alike (`Kept::of`). A holder whose words there are an
/// in-order part of the keeper's gives up its copy, and no gap is asked;
/// a holder that orders the words it shares with the keeper otherwise, or
/// sets words of its own beside them, keeps its copy at the keeper's gap,
/// which asks, its group listing every word it placed, and M lays each word
/// once, where the first group laid takes it. Where every place breaks some
/// holder's order, the words that would come out of it join the keeper's
/// gap. Where the spots differ it is a `moves` gap with spots (CM-I33),
/// numbered first, by its earliest holder and its place there: unsettled,
/// the earliest holder's placement its default, every other holder's copy
/// left out; `Choice::Order` or `Choice::KeepOnly` of one holder keeps that
/// holder's placement instead, the later of two standing, and any other
/// choice there is `ignored`.
///
/// The walk, in the record's seven steps: the removals, the spine, each
/// side's additions with their anchors, the placement of each by its
/// kind, the gaps with the line rule, the order rule and the value rule,
/// the splice and the coalesce, the report with the resolutions applied —
/// applied ahead of the splice, so M holds them. A holder chosen at a gap
/// with spots moves the words to its spot, which can raise a gap there or
/// leave none at the default spot; every other gap that stands keeps the
/// number it has at the default, the first gap of the walk at the defaults
/// with its kind, its place in the spine and the same runs besides the
/// moved words; a gap the moved words make is numbered after that walk's
/// last, and one they unmake — a `line` gap whose partner they were among
/// them — leaves its number unused, a choice naming it standing in
/// `ignored`. A spine's `moves` gap resolved by `Choice::Order` of the side
/// whose order the spine took is settled, nothing walked again. With no
/// `spine_hint`, one resolved by `Choice::Order` of the other side walks the
/// whole composition again, that side's reorder applied first and every
/// other side's folded after it, and every gap keeps the number the walk at
/// the default order gave it (skep #1155): a `moves` gap the number of the
/// one between the same two sides, else the one holding the same side's
/// reorder, and every other gap the number of the gap with its kind and the
/// same runs — a collision no side filled, of the one over the same base
/// positions — never by its place, which the order moves. A gap that walk
/// did not have is numbered after its last, so a resolution naming one the
/// chosen order removes stands in `ignored`, and every resolution in one
/// list names the report's numbers. Under a `spine_hint` that resolution is
/// not applied and stands in `ignored`.
///
/// **Precondition.** Every run has a width above 0. A release build skips a
/// run of width 0 and composes the rest. A list that places one run twice
/// is admitted: each placement is its own position (skep #763), so both
/// placements survive where every side keeps them and a side that removes
/// one removes that one alone.
///
/// # Panics
///
/// Panics in a debug build on a run of width 0.
pub fn compose_runs(
    base: &[Run],
    doc: &Address,
    sides: &[(SideIx, Vec<Run>)],
    spine_hint: Option<SideIx>,
    options: &Options,
    values: &dyn Fn(SideIx, &Run) -> Option<Vec<Item>>,
) -> Composed {
    let lines = |side: SideIx, run: &Run, _: &LinePair| {
        values(side, run).map(|items| LineRead::of(&items, run.width))
    };
    compose_asking(base, doc, sides, spine_hint, options, values, &lines)
}

/// The pair of changes a line read decides, named by its two anchors.
///
/// [`compose_asking`]'s line closure is told it beside each run, so its
/// caller can say which pair a read it could not answer was for: two sides'
/// neighbouring changes — two additions, or an addition and a removal one
/// side alone made — whose meeting at a line's edge the read decides, named
/// as the report names a gap's or a removal's (`anchors_at`; skep #1174,
/// #1176).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::merge) struct LinePair {
    /// The surviving base position M holds just before the first of the
    /// two, as that addition's gap names it ([`Gap::after`]), or that
    /// removal's ([`Removed::after`]); `None` at M's start.
    pub(in crate::merge) after: Option<Address>,
    /// The surviving base position M holds just after the second, as that
    /// addition's gap names it ([`Gap::before`]), or that removal's
    /// ([`Removed::before`]); `None` at M's end.
    pub(in crate::merge) before: Option<Address>,
}

/// What a line read answered: where the run's line breaks fall.
///
/// The line rule looks at nothing in an item but whether it is the byte
/// `\n`, and at nothing in an answer but whether it holds one item a
/// position (skep #1173), so a read is kept as those facts alone and no
/// item outlives its read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::merge) enum LineRead {
    /// One item a position: the offsets into the run, from 0, of the items
    /// that are the byte `\n`, rising.
    Breaks(Vec<u64>),
    /// Another count of items than the run's positions, which decides
    /// nothing.
    Unfit,
}

impl LineRead {
    /// Returns what `items`, a read of a run of `width` positions, tells the
    /// line rule.
    pub(in crate::merge) fn of(items: &[Item], width: u64) -> LineRead {
        if items.len() as u64 != width {
            return LineRead::Unfit;
        }
        let breaks = (0u64..).zip(items).filter(|(_, item)| item.as_slice() == b"\n");
        LineRead::Breaks(breaks.map(|(k, _)| k).collect())
    }
}

/// What answers a side's run with its items, for the value rule.
///
/// It is [`compose_asking`]'s `values`: `None` leaves the rule unfired
/// there.
pub(in crate::merge) type AskedValues<'a> = dyn Fn(SideIx, &Run) -> Option<Vec<Item>> + 'a;

/// What answers a side's run with where its line breaks fall, for the line
/// rule, told the pair of changes the read decides.
///
/// It is [`compose_asking`]'s `lines`: `None` leaves the rule unfired
/// there.
pub(in crate::merge) type AskedLines<'a> =
    dyn Fn(SideIx, &Run, &LinePair) -> Option<LineRead> + 'a;

/// Composes as [`compose_runs`] does, the line rule reading through a
/// closure of its own.
///
/// `values` answers the value rule's reads with a run's items, and `lines`
/// the line rule's with where a run's line breaks fall ([`LineRead`]), told
/// the pair of changes the read decides ([`LinePair`]); [`compose_runs`] is
/// this with a `lines` that takes `values`' items down to their breaks.
///
/// # Panics
///
/// Panics in a debug build on a run of width 0, as [`compose_runs`] does.
pub(in crate::merge) fn compose_asking(
    base: &[Run],
    doc: &Address,
    sides: &[(SideIx, Vec<Run>)],
    spine_hint: Option<SideIx>,
    options: &Options,
    values: &AskedValues<'_>,
    lines: &AskedLines<'_>,
) -> Composed {
    let r = Refinement::of(base, sides);
    let chain = r.chain(doc);
    let mut seqs = r.sides.clone();
    let retyped = if options.retype { undo_retypes(&r, &mut seqs, values) } else { Vec::new() };
    let claimed = Claimed::of(&r, &seqs, &options.resolutions);
    let hint = spine_hint.and_then(|h| r.side_ix.iter().position(|s| *s == h));
    let walked = Walking {
        r: &r,
        chain: &chain,
        claimed: &claimed,
        options,
        values,
        lines,
        retyped: &retyped,
    };
    let (first, numbering) = walk(&walked, SpineOrder::Given(hint));
    if hint.is_none() {
        if let Some(side) = moves_choice(&r, &numbering, &options.resolutions) {
            return walk(&walked, SpineOrder::Chosen { side, numbering: &numbering }).0;
        }
    }
    first
}

/// The order a walk's spine takes, and what its gaps are numbered by.
enum SpineOrder<'a> {
    /// The order `spine_of` computes, or the side a `spine_hint` names.
    ///
    /// The gaps are numbered by this walk.
    Given(Option<usize>),
    /// The order a merger chose at a spine's `moves` gap: that side's
    /// reorder applied first, every other folded after it.
    ///
    /// Every gap is numbered by `numbering`, the walk's at the order given
    /// (skep #1155).
    Chosen { side: usize, numbering: &'a Numbering },
}

/// What every walk of one composition reads.
struct Walking<'a> {
    r: &'a Refinement,
    /// The document's chain, as `Refinement::chain` reads it.
    chain: &'a HashSet<usize>,
    /// The sequences once each fresh identity several sides hold is kept by
    /// one, with the gaps with spots that decided it.
    claimed: &'a Claimed,
    options: &'a Options,
    /// The value rule's reads.
    values: &'a AskedValues<'a>,
    /// The line rule's reads, each told the pair it decides.
    lines: &'a AskedLines<'a>,
    /// The runs the retype normalization took out of M (`undo_retypes`).
    retyped: &'a [(SideIx, Run)],
}

/// Runs the seven steps over the normalized sequences under one spine order.
///
/// `order` is the spine's order and what the gaps are numbered by. Beside
/// the composition it returns the numbering its gaps took, which a walk
/// under a chosen order numbers its own by.
fn walk(walking: &Walking<'_>, order: SpineOrder<'_>) -> (Composed, Numbering) {
    let Walking { r, chain, claimed, options, values, lines, retyped } = *walking;
    let in_base = r.in_base();
    let seqs = &claimed.kept.seqs;
    let in_side: Vec<Vec<Option<usize>>> = seqs.iter().map(|seq| r.presence(seq)).collect();
    let (removed_by, removed) = removals(r, &in_side);
    let after_claims = claimed.claims.len() as u32 + 1;
    let (hint, chosen) = match &order {
        SpineOrder::Given(hint) => (*hint, None),
        SpineOrder::Chosen { side, .. } => (None, Some(*side)),
    };
    let (spine, spine_pos, mut moves) =
        spine_of(r, seqs, &in_base, &removed, hint, chosen, after_claims);
    let layout = Layout {
        r,
        in_base: &in_base,
        removed_by: &removed_by,
        removed: &removed,
        spine: &spine,
        spine_pos: &spine_pos,
    };
    let laid = layout.place(&claimed.kept);
    let regions = collision_regions(r, &removed_by, &removed, &spine_pos);
    let lone =
        |laid: &Laid<'_>| lone_removals(r, &removed_by, &removed, &spine_pos, &laid.stretches);
    let first = after_claims + moves.len() as u32;
    let (mut entries, mut applied) =
        gaps(r, chain, &spine, &laid, &regions, &lone(&laid), first, options, lines, values);
    if let SpineOrder::Chosen { numbering, .. } = order {
        // A side's order chosen at a spine's `moves` gap: every gap numbered
        // as the walk at the order given numbered it, which a holder's
        // choice had already numbered as at the claims' defaults.
        numbering.number(&mut entries, &mut moves, &mut applied);
    } else if let Some(defaults) = &claimed.defaults {
        // A holder chosen at a gap with spots: the gaps numbered as the walk
        // at the claims' defaults numbers its own. Only the moved words'
        // stretches differ between the two, so the removals, the spine and
        // the collision regions are this walk's, and the lone removals are
        // those that walk's stretches leave. That walk's line rule reads the
        // base text as this one's does, so a `line` gap there that still
        // stands here keeps its number, and one the moved words partnered
        // stands here no more, its number left unused; the dedup changes no
        // kind, run or place, so that walk's dedup reads no value.
        let at_defaults = layout.place(defaults);
        let none = |_: SideIx, _: &Run| -> Option<Vec<Item>> { None };
        let (at_defaults, _) = gaps(
            r,
            chain,
            &spine,
            &at_defaults,
            &regions,
            &lone(&at_defaults),
            first,
            options,
            lines,
            &none,
        );
        number_as(&mut entries, &mut applied, &at_defaults, &claimed.moved(), first);
    }
    let ignored = resolve(r, &mut entries, &mut moves, &claimed.claims, &options.resolutions, &in_base, &spine_pos);
    let runs = splice(r, &entries, &spine);
    let gaps = report(r, &entries, &moves, &claimed.claims, &spine);
    let counts = RunCounts {
        a: r.side_runs.first().copied().unwrap_or(0),
        b: r.side_runs.iter().skip(1).sum(),
        m: runs.len(),
    };
    let composed = Composed {
        runs,
        gaps,
        counts,
        values: ValueLog {
            dedup: options.dedup,
            retype: options.retype,
            applied,
            retyped: retyped.to_vec(),
        },
        ignored,
    };
    (composed, Numbering::of(entries, moves, &claimed.claims))
}

/// Returns the side a merger chose at a spine's `moves` gap, where one
/// chose the side whose reorder the spine did not take.
///
/// A gap's choice is the last resolution naming it that takes one of its two
/// sides' orders, as at every other gap the later of two standing: a choice
/// of the side whose order the spine took confirms it and walks nothing
/// again (`resolve`), so it stands over an earlier choice of the other. Of
/// the gaps whose choice is the other side, the one whose choice comes first
/// in the list is the one the composition walks again under. A `moves` gap
/// with spots moves no base material: its choice was applied before the
/// walk.
fn moves_choice(
    r: &Refinement,
    numbering: &Numbering,
    resolutions: &[Resolution],
) -> Option<usize> {
    let takes = |res: &Resolution, side: usize| matches!(&res.choice, Choice::Order(sides) if sides.as_slice() == [r.side_ix[side]]);
    numbering
        .moves
        .iter()
        .filter_map(|gap| {
            let (at, res) = resolutions.iter().enumerate().rev().find(|(_, res)| {
                res.gap == gap.id && (takes(res, gap.winner) || takes(res, gap.loser))
            })?;
            takes(res, gap.loser).then_some((at, gap.loser))
        })
        .min_by_key(|&(at, _)| at)
        .map(|(_, loser)| loser)
}

// ── the refinement ────────────────────────────────────────────────────────

/// One fragment of the common refinement.
///
/// It is `width` positions of the origin `origin` names from ordinal
/// `start`, lying wholly inside or wholly outside every list given.
#[derive(Debug, Clone, Copy)]
struct Frag {
    origin: usize,
    start: u64,
    width: u64,
}

/// The lists given as sequences of fragment ids over one fragment table.
struct Refinement {
    /// The origins named, interned.
    origins: Vec<Address>,
    /// The fragments, by id.
    frags: Vec<Frag>,
    /// The base's sequence.
    base: Vec<usize>,
    /// Each side's sequence.
    sides: Vec<Vec<usize>>,
    /// Each side's index as the caller named it.
    side_ix: Vec<SideIx>,
    /// Each side's run count as given.
    side_runs: Vec<usize>,
}

impl Refinement {
    /// Returns the refinement of the base and the sides.
    ///
    /// Every run is cut at every other run's edges, each list then a
    /// sequence of fragment ids. A position a list places twice is two
    /// placements (skep #763): the `k`-th placement of a fragment in one
    /// list is the fragment's `k`-th copy, a fragment id of its own with the
    /// same origin, start and width, and the same id for the `k`-th
    /// placement in every list — so a copy every list holds is one shared
    /// position and a copy one list adds is that list's addition — and no
    /// id stands twice in one sequence.
    ///
    /// # Panics
    ///
    /// Panics in a debug build on a run of width 0.
    fn of(base: &[Run], sides: &[(SideIx, Vec<Run>)]) -> Refinement {
        let mut origins: Vec<Address> = Vec::new();
        let mut points: Vec<Vec<u64>> = Vec::new();
        let all = base.iter().chain(sides.iter().flat_map(|(_, runs)| runs.iter()));
        for run in all {
            debug_assert!(run.width > 0, "a run of width 0 is malformed: {run:?}");
            if run.width == 0 {
                continue;
            }
            let o = match origins.iter().position(|x| *x == run.origin) {
                Some(o) => o,
                None => {
                    origins.push(run.origin.clone());
                    points.push(Vec::new());
                    origins.len() - 1
                }
            };
            points[o].push(run.i_start);
            points[o].push(run.reach());
        }
        let mut frags = Vec::new();
        let mut first = Vec::with_capacity(points.len());
        for (o, pts) in points.iter_mut().enumerate() {
            pts.sort_unstable();
            pts.dedup();
            first.push(frags.len());
            for pair in pts.windows(2) {
                frags.push(Frag { origin: o, start: pair[0], width: pair[1] - pair[0] });
            }
        }
        // The copies: `(fragment, k)` → the id of its `k`-th repeat, shared
        // by every list, minted as a list first places the fragment again.
        let mut copies: HashMap<(usize, usize), usize> = HashMap::new();
        let mut sequence = |runs: &[Run]| -> Vec<usize> {
            let mut placed: HashMap<usize, usize> = HashMap::new();
            let mut out = Vec::new();
            for run in runs.iter().filter(|run| run.width > 0) {
                let Some(o) = origins.iter().position(|x| *x == run.origin) else { continue };
                let (Ok(i), Ok(j)) = (points[o].binary_search(&run.i_start), points[o].binary_search(&run.reach()))
                else {
                    continue;
                };
                for id in first[o] + i..first[o] + j {
                    let k = placed.entry(id).or_insert(0);
                    let placement = if *k == 0 {
                        id
                    } else {
                        *copies.entry((id, *k)).or_insert_with(|| {
                            frags.push(frags[id]);
                            frags.len() - 1
                        })
                    };
                    *k += 1;
                    out.push(placement);
                }
            }
            out
        };
        let base_seq = sequence(base);
        let side_seqs: Vec<Vec<usize>> = sides.iter().map(|(_, runs)| sequence(runs)).collect();
        Refinement {
            base: base_seq,
            sides: side_seqs,
            side_ix: sides.iter().map(|(ix, _)| *ix).collect(),
            side_runs: sides.iter().map(|(_, runs)| runs.len()).collect(),
            origins,
            frags,
        }
    }

    /// Returns the interned origins of the document's chain.
    ///
    /// They are `doc`, the trunk whose own text names it as its origin, and
    /// every origin the base holds, whatever the base holds — so an empty
    /// base still leaves the document's own text in the chain (merge record
    /// §2 R1; skep #1115).
    fn chain(&self, doc: &Address) -> HashSet<usize> {
        let mut chain: HashSet<usize> = self.base.iter().map(|&f| self.frags[f].origin).collect();
        chain.extend(self.origins.iter().position(|o| o == doc));
        chain
    }

    /// Returns each fragment's index in the base, where it is the base's.
    fn in_base(&self) -> Vec<Option<usize>> {
        self.presence(&self.base)
    }

    /// Returns each fragment's index in `seq`, where it is there.
    fn presence(&self, seq: &[usize]) -> Vec<Option<usize>> {
        let mut out = vec![None; self.frags.len()];
        for (i, &f) in seq.iter().enumerate() {
            out[f] = Some(i);
        }
        out
    }

    /// Returns the fragments as runs.
    ///
    /// I-adjacent fragments of one origin are widened into one: the daemon's
    /// own accumulator, never coalescing on value.
    fn coalesce(&self, frags: impl IntoIterator<Item = usize>) -> Vec<Run> {
        let mut out: Vec<Run> = Vec::new();
        for f in frags {
            let frag = self.frags[f];
            if let Some(last) = out.last_mut() {
                if last.origin == self.origins[frag.origin] && last.reach() == frag.start {
                    if let Some(width) = last.width.checked_add(frag.width) {
                        last.width = width;
                        continue;
                    }
                }
            }
            out.push(Run::new(self.origins[frag.origin].clone(), frag.start, frag.width));
        }
        out
    }

    /// Returns the address of a fragment's first position.
    fn first_address(&self, f: usize) -> Option<Address> {
        let frag = self.frags[f];
        element_address(&self.origins[frag.origin], frag.start)
    }

    /// Returns the address of a fragment's last position.
    fn last_address(&self, f: usize) -> Option<Address> {
        let frag = self.frags[f];
        element_address(&self.origins[frag.origin], frag.start.checked_add(frag.width)?.checked_sub(1)?)
    }

    /// Returns a fragment's last position, as a run of width 1.
    fn last_position(&self, f: usize) -> Run {
        let frag = self.frags[f];
        Run::new(self.origins[frag.origin].clone(), frag.start + (frag.width - 1), 1)
    }

    /// Returns the items of a side's fragments, read through the closure.
    ///
    /// They are read as the runs the side holds them in; `None` where any
    /// read answers none.
    fn bytes(
        &self,
        side: usize,
        frags: impl IntoIterator<Item = usize>,
        values: &dyn Fn(SideIx, &Run) -> Option<Vec<Item>>,
    ) -> Option<Vec<Item>> {
        let mut out = Vec::new();
        for run in self.coalesce(frags) {
            out.extend(values(self.side_ix[side], &run)?);
        }
        Some(out)
    }

    /// Returns each base fragment holding `addr`, by its index in the base.
    ///
    /// A run the base places twice holds `addr` once per placement (skep
    /// #763), so there may be more than one; none for an address no base
    /// run holds.
    fn locate(&self, addr: &Address, in_base: &[Option<usize>]) -> Vec<usize> {
        let held = || -> Option<(usize, u64)> {
            let doc = skep_address::document_of(addr)?;
            let o = self.origins.iter().position(|x| *x == doc)?;
            let field = addr.element_field()?;
            if field.len() != 2 || field[0] != content_subspace() {
                return None;
            }
            Some((o, u64::try_from(&field[1]).ok()?))
        };
        let Some((o, n)) = held() else { return Vec::new() };
        let holding = |fr: &Frag| fr.origin == o && fr.start <= n && n - fr.start < fr.width;
        self.frags
            .iter()
            .enumerate()
            .filter(|(_, fr)| holding(fr))
            .filter_map(|(f, _)| in_base[f])
            .collect()
    }

    /// Returns the spine gaps a move names: after each surviving placement
    /// of the position an `After` names, before each of the one a `Before`
    /// names; `None` for a choice that is no move.
    fn places(
        &self,
        choice: &Choice,
        in_base: &[Option<usize>],
        spine_pos: &[Option<usize>],
    ) -> Option<Vec<usize>> {
        let (addr, shift) = match choice {
            Choice::After(addr) => (addr, 1),
            Choice::Before(addr) => (addr, 0),
            Choice::Order(_) | Choice::KeepOnly(_) | Choice::KeepBoth | Choice::Omit => {
                return None
            }
        };
        Some(
            self.locate(addr, in_base)
                .into_iter()
                .filter_map(|bi| spine_pos[bi])
                .map(|p| p + shift)
                .collect(),
        )
    }
}

/// Returns the address `origin·0·1·ordinal`.
///
/// `None` for an origin that is no document address or an ordinal of 0.
fn element_address(origin: &Address, ordinal: u64) -> Option<Address> {
    elem_addr(ElemPos { doc: origin.clone(), subspace: content_subspace(), ordinal: Nat::from(ordinal) }).ok()
}

// ── before the walk: the value rule's retype, and shared identities ───────

/// Applies the retype normalization (merge record §5, case (f)).
///
/// A side's stretch standing in place of base material the side removed
/// whole, whose bytes equal that material's, is replaced by the material's
/// own fragments, so the base's identity is kept. The removed bytes are
/// read from another side that still holds them — a base run's value is
/// never read. Returned is each stretch so replaced, as runs with its side,
/// in side order: the value log's `retyped`.
fn undo_retypes(
    r: &Refinement,
    seqs: &mut [Vec<usize>],
    values: &dyn Fn(SideIx, &Run) -> Option<Vec<Item>>,
) -> Vec<(SideIx, Run)> {
    let in_base = r.in_base();
    let mut retyped = Vec::new();
    for s in 0..seqs.len() {
        let presence: Vec<Vec<Option<usize>>> = seqs.iter().map(|seq| r.presence(seq)).collect();
        let mut replacements: Vec<(usize, usize, Vec<usize>)> = Vec::new();
        for st in additions(seqs, &in_base).into_iter().filter(|st| st.side == s) {
            let lo = st.x.map_or(0, |x| x + 1);
            let hi = st.y.unwrap_or(r.base.len());
            if lo >= hi || !(lo..hi).all(|bi| presence[s][r.base[bi]].is_none()) {
                continue;
            }
            let holder = (0..seqs.len()).find(|&t| t != s && (lo..hi).all(|bi| presence[t][r.base[bi]].is_some()));
            let Some(t) = holder else { continue };
            let removed = r.bytes(t, (lo..hi).map(|bi| r.base[bi]), values);
            let fresh = r.bytes(s, st.frags.iter().copied(), values);
            if removed.is_some() && removed == fresh {
                retyped.extend(
                    r.coalesce(st.frags.iter().copied()).into_iter().map(|run| (r.side_ix[s], run)),
                );
                replacements.push((st.at, st.frags.len(), (lo..hi).map(|bi| r.base[bi]).collect()));
            }
        }
        for (at, len, base_frags) in replacements.into_iter().rev() {
            seqs[s].splice(at..at + len, base_frags);
        }
    }
    retyped
}

/// The base indices of the nearest base positions before a place in a
/// side's sequence and after it, `None` at an end.
type Anchors = (Option<usize>, Option<usize>);

/// One holding side's placement of the words a gap with spots contests.
struct Holder {
    /// The side, by its index among the sides given.
    side: usize,
    /// The gap's fragments, in the side's own order.
    frags: Vec<usize>,
    /// Its spot: the anchors before the words and after them that every
    /// holder keeps.
    spot: Anchors,
}

/// A `moves` gap with spots as the walk holds it (CM-I33).
///
/// It is one fresh identity two or more sides hold at different spots: its
/// holders in side order, the earliest first, and the one M takes.
struct Claim {
    id: GapId,
    holders: Vec<Holder>,
    /// The holder whose placement M takes, by its index in `holders`: 0,
    /// the earliest, by default.
    chosen: usize,
    settled: bool,
    resolved_by: Option<ResolvedBy>,
}

impl Claim {
    /// Returns the holder a choice names, by its index in `holders`.
    ///
    /// It is `Order` of one holding side or `KeepOnly` of one; every other
    /// choice names none.
    fn holder_named(&self, r: &Refinement, choice: &Choice) -> Option<usize> {
        let side = match choice {
            Choice::Order(sides) => match sides.as_slice() {
                [one] => *one,
                _ => return None,
            },
            Choice::KeepOnly(side) => *side,
            Choice::After(_) | Choice::Before(_) | Choice::KeepBoth | Choice::Omit => return None,
        };
        self.holders.iter().position(|h| r.side_ix[h.side] == side)
    }
}

/// The sides' sequences once each fresh identity several of them hold is
/// kept by one, with the gaps with spots that decided where (CM-I33).
struct Claimed {
    /// The gaps with spots, numbered from 1.
    claims: Vec<Claim>,
    /// The sequences under the gaps' choices.
    kept: Kept,
    /// The sequences at every gap's default, where a choice moved one.
    defaults: Option<Kept>,
}

impl Claimed {
    /// Returns the claimed sequences, the merger's choices at the gaps with
    /// spots applied.
    ///
    /// Of two resolutions naming one gap the later stands; one naming no
    /// holder changes nothing, and `resolve` lists it as not applied. Each
    /// identity several sides hold at one spot is then kept by one of them
    /// (`Kept::of`), under the choices and at the defaults alike.
    fn of(r: &Refinement, seqs: &[Vec<usize>], resolutions: &[Resolution]) -> Claimed {
        let (mut claims, shares) = claim_identities(r, seqs);
        for res in resolutions {
            let Some(claim) = claims.iter_mut().find(|c| c.id == res.gap) else { continue };
            if let Some(holder) = claim.holder_named(r, &res.choice) {
                claim.chosen = holder;
                claim.settled = true;
                claim.resolved_by = Some(res.by.clone());
            }
        }
        let moved = claims.iter().any(|c| c.chosen != 0);
        Claimed {
            kept: Kept::of(r, &claimed(seqs, &claims, |c| c.chosen), &shares),
            defaults: moved.then(|| Kept::of(r, &claimed(seqs, &claims, |_| 0), &shares)),
            claims,
        }
    }

    /// Returns the fragments of every gap whose chosen holder is not its
    /// default.
    fn moved(&self) -> HashSet<usize> {
        self.claims.iter().filter(|c| c.chosen != 0).flat_map(|c| c.holders[0].frags.iter().copied()).collect()
    }
}

/// A fresh fragment two or more sides hold at one spot (merge record §2,
/// the one rule: an identical addition is not a difference).
///
/// The spot is read by the base positions every holder keeps, as a gap
/// with spots reads its holders' (CM-I33); here every holder's is the same.
struct Share {
    frag: usize,
    /// The sides that hold it, in side order.
    holders: Vec<usize>,
    /// The spot every holder places it at.
    spot: Anchors,
}

/// Returns the gaps with spots and the identities held at one spot.
///
/// The gaps with spots are each fresh identity two or more sides hold at
/// different spots (merge record §2, the one rule; CM-I33). A holder's spot
/// is the nearest base position before the identity and after it in the
/// holder's own sequence that every holder keeps, so a neighbour one holder
/// removed moves nothing. An identity every holder placed at one spot is no
/// gap: an identical addition is not a difference, and it is a `Share`, one
/// per fragment. Contested fragments that stand together in their earliest
/// holder's sequence, held by the same sides at the same spots, are one
/// gap, numbered from 1 by the earliest holder, then by place there.
fn claim_identities(r: &Refinement, seqs: &[Vec<usize>]) -> (Vec<Claim>, Vec<Share>) {
    let in_base = r.in_base();
    let presence: Vec<Vec<Option<usize>>> = seqs.iter().map(|seq| r.presence(seq)).collect();
    // Each holder's common anchors at each place of its sequence, once per
    // set of holders.
    let mut anchors: HashMap<Vec<usize>, Vec<Vec<Anchors>>> = HashMap::new();
    let mut claims: Vec<Claim> = Vec::new();
    let mut shares: Vec<Share> = Vec::new();
    for (s, seq) in seqs.iter().enumerate() {
        // The gap the fragment before this one in `seq` joined.
        let mut open: Option<usize> = None;
        for &f in seq {
            let places: Vec<(usize, usize)> = match in_base[f] {
                Some(_) => Vec::new(),
                None => (0..seqs.len()).filter_map(|t| presence[t][f].map(|i| (t, i))).collect(),
            };
            if places.len() < 2 || places[0].0 != s {
                open = None;
                continue;
            }
            let sides: Vec<usize> = places.iter().map(|&(t, _)| t).collect();
            if !anchors.contains_key(&sides) {
                let per = sides.iter().map(|&t| common_anchors(&seqs[t], &in_base, &presence, &sides)).collect();
                anchors.insert(sides.clone(), per);
            }
            let spots: Vec<Anchors> =
                places.iter().zip(&anchors[&sides]).map(|(&(_, i), at)| at[i]).collect();
            if spots.iter().all(|spot| *spot == spots[0]) {
                shares.push(Share { frag: f, holders: sides, spot: spots[0] });
                open = None;
                continue;
            }
            let joined = open.filter(|&c| {
                claims[c].holders.iter().map(|h| (h.side, h.spot)).eq(sides.iter().copied().zip(spots.iter().copied()))
            });
            match joined {
                Some(c) => claims[c].holders.iter_mut().for_each(|h| h.frags.push(f)),
                None => {
                    claims.push(Claim {
                        id: GapId(claims.len() as u32 + 1),
                        holders: sides.iter().zip(&spots).map(|(&side, &spot)| Holder { side, frags: vec![f], spot }).collect(),
                        chosen: 0,
                        settled: false,
                        resolved_by: None,
                    });
                    open = Some(claims.len() - 1);
                }
            }
        }
    }
    for claim in &mut claims {
        for holder in &mut claim.holders {
            holder.frags.sort_by_key(|&f| presence[holder.side][f]);
        }
    }
    (claims, shares)
}

/// Returns, at each place of `seq`, the nearest base position before it and
/// after it that every side of `holders` keeps, as base indices.
fn common_anchors(
    seq: &[usize],
    in_base: &[Option<usize>],
    presence: &[Vec<Option<usize>>],
    holders: &[usize],
) -> Vec<Anchors> {
    let common = |f: usize| in_base[f].filter(|_| holders.iter().all(|&t| presence[t][f].is_some()));
    let mut out = vec![(None, None); seq.len()];
    let mut last = None;
    for (i, &f) in seq.iter().enumerate() {
        out[i].0 = last;
        last = common(f).or(last);
    }
    let mut next = None;
    for (i, &f) in seq.iter().enumerate().rev() {
        out[i].1 = next;
        next = common(f).or(next);
    }
    out
}

/// Returns the sequences with each gap with spots' fragments kept by one
/// holder, the one `holder` names: every other holder's copy taken out.
fn claimed(
    seqs: &[Vec<usize>],
    claims: &[Claim],
    holder: impl Fn(&Claim) -> usize,
) -> Vec<Vec<usize>> {
    let mut out = seqs.to_vec();
    for claim in claims {
        let chosen = holder(claim);
        for (_, held) in claim.holders.iter().enumerate().filter(|(k, _)| *k != chosen) {
            out[held.side].retain(|f| !held.frags.contains(f));
        }
    }
    out
}

/// A side's stretch by its side and its two anchors, as base indices.
///
/// A side places each base position at most once, so its stretches stand
/// between distinct pairs of anchors, and taking fresh fragments out of a
/// sequence leaves every stretch's anchors as they were.
type StretchAt = (usize, Option<usize>, Option<usize>);

/// The sequences once each identity several sides hold at one spot is kept
/// by one of them (merge record §2, the one rule; §1.4 step 5).
///
/// Beside them stand the stretches placed elsewhere than their own anchors:
/// a keeper's stretch placed at its fragments' common spot, and a stretch
/// that joins another's gap (`Kept::of`).
struct Kept {
    /// The sequences, each shared fragment in its keeper's and in each
    /// holder's that asks or breaks beside it.
    seqs: Vec<Vec<usize>>,
    /// Each stretch placed at a common spot instead of its own anchors.
    spots: HashMap<StretchAt, Anchors>,
    /// Each stretch placed in another stretch's gap.
    joins: HashMap<StretchAt, StretchAt>,
    /// Each stretch's fragments before any shared one was taken out of it.
    whole: HashMap<StretchAt, Vec<usize>>,
    /// Each side's shared fragments it gave up to another holder's copy.
    ///
    /// A holder that gives its copy up placed those words all the same:
    /// the line rule counts them as its words wherever the keeper's copy is
    /// laid (`Placers`), so which holder keeps a word decides nothing it
    /// asks.
    given_up: Vec<HashSet<usize>>,
}

/// Where a shared fragment is kept, and what that asks.
///
/// It is ranked by `Keeping::rank`: a placement that keeps every holder's
/// order before one that does not, then the fewest gaps it asks, a holder's
/// own stretch before the common spot, the earliest place, the earliest
/// side.
struct Keeping {
    /// The side whose sequence keeps the fragment.
    side: usize,
    /// Its stretch holding the fragment.
    at: StretchAt,
    /// Where the stretch is placed: its own anchors, or the common spot.
    anchors: Anchors,
    /// Whether the stretch is placed at the common spot.
    at_spot: bool,
    /// The holders whose order this placement breaks.
    breaks: Vec<usize>,
    /// The holders whose stretch stands at the same place and asks there:
    /// it holds words the keeper lacks, or orders the words it shares with
    /// the keeper otherwise.
    asking: Vec<usize>,
    /// The gaps this placement asks: each holder of `asking`, and a corner
    /// or a collision at the keeper's anchors.
    asks: usize,
}

impl Keeping {
    fn rank(&self) -> (bool, usize, bool, (i64, i64), usize) {
        (
            !self.breaks.is_empty(),
            self.asks,
            self.at_spot,
            stretch_key(self.anchors.0, self.anchors.1),
            self.side,
        )
    }
}

impl Kept {
    /// Returns `seqs` with each identity of `shares` kept by one holder.
    ///
    /// An identical addition is kept once (§2), and which holder keeps it
    /// decides where M places it: in that holder's stretch, by that
    /// stretch's anchors. So the copy is kept where it breaks no holder's
    /// own order: placed at another stretch's place, a holder's words beside
    /// it would come out on the wrong side of it, and its words placed
    /// between the two places too (§2 R1, a side's runs in its own order);
    /// and a holder that orders the spot's shared words it holds with the
    /// keeper otherwise than the keeper, in one stretch or across several, is
    /// broken wherever the keeper's stretch is laid (`crosses`). Each
    /// holder's stretch is a candidate, and — where every holder's stretch
    /// holds only fragments every holder holds, in one order — the
    /// fragment's common spot, read by the base positions every holder
    /// keeps, carried by the earliest holder, whose stretch is then any
    /// holder's. Of the candidates that break no order, the one
    /// asking the fewest gaps is taken — a holder at the same place with
    /// words the keeper lacks, or with the shared words in another order,
    /// makes an `order` gap, anchors both gone a `corner`, the keeper's
    /// removal there overlapping another's a `collision` — then a holder's
    /// own stretch before the common spot, then the earliest place, then the
    /// earliest side. A holder that asks, or is broken, keeps its copy, so its
    /// group at the gap lists every word it placed there and a choice of that
    /// side lays them all; so does a holder placed elsewhere than the keeper
    /// where a side holding none of the words set words of its own at the
    /// holder's place, which the copy is asked against there (R1). Every
    /// other holder gives up its copy, which laid at the keeper's place keeps
    /// that holder's order; the splice lays each fragment once, and
    /// `given_up` keeps it as that holder's word, a change it made all the
    /// same. Where every candidate breaks an order, the
    /// holders' words around the fragment cannot be laid in every holder's
    /// order, and the stretches that would come out of order, each broken
    /// holder's copy in them, join the keeper's gap, which asks: an `order`
    /// gap of the sides' groups. The choice reads each list's anchors and
    /// order alone, never the order the sides are listed in, but where two
    /// candidates rank alike.
    fn of(r: &Refinement, seqs: &[Vec<usize>], shares: &[Share]) -> Kept {
        let in_base = r.in_base();
        let presence: Vec<Vec<Option<usize>>> = seqs.iter().map(|seq| r.presence(seq)).collect();
        let (removed_by, removed) = removals(r, &presence);
        let stretches = additions(seqs, &in_base);
        let mut holding: HashMap<(usize, usize), usize> = HashMap::new();
        for (i, st) in stretches.iter().enumerate() {
            for &f in &st.frags {
                holding.insert((st.side, f), i);
            }
        }
        let mut strip: Vec<HashSet<usize>> = vec![HashSet::new(); seqs.len()];
        let mut spots = HashMap::new();
        let mut joins = HashMap::new();
        // The shared words of each common spot, all laid in that spot's gap.
        let mut by_spot: HashMap<Anchors, Vec<usize>> = HashMap::new();
        for share in shares {
            by_spot.entry(share.spot).or_default().push(share.frag);
        }
        // What a share's keeping reads that depends on its stretches, its
        // spot or its candidate alone, each read once whatever the shares:
        // a stretch's first and last fragment a side does not hold, by
        // (stretch, side); whether one holder orders a spot's shared words
        // otherwise than another, by (spot, holder, keeper); whether a
        // keeper's removal between a candidate's anchors overlaps another's,
        // by (keeper, anchors).
        let mut unheld_in: HashMap<(usize, usize), Option<(usize, usize)>> = HashMap::new();
        let mut crossed_at: HashMap<(Anchors, usize, usize), bool> = HashMap::new();
        let mut collides: HashMap<(usize, Anchors), bool> = HashMap::new();
        for share in shares {
            let stretch_of = |t: usize| holding[&(t, share.frag)];
            let words = &by_spot[&share.spot];
            let mut unheld = |s: usize, k: usize| -> Option<(usize, usize)> {
                *unheld_in.entry((s, k)).or_insert_with(|| {
                    let frags = &stretches[s].frags;
                    let first = frags.iter().position(|&g| presence[k][g].is_none())?;
                    let last = frags.iter().rposition(|&g| presence[k][g].is_none())?;
                    Some((first, last))
                })
            };
            let mut crossing = |t: usize, k: usize| -> bool {
                *crossed_at
                    .entry((share.spot, t, k))
                    .or_insert_with(|| crosses(words, t, k, &presence))
            };
            // Every holder's stretch the same words in one order: the earliest
            // holder's, carried to the common spot, is any holder's.
            let mut pure = true;
            for &t in &share.holders {
                let s = stretch_of(t);
                pure = pure
                    && share.holders.iter().all(|&h| unheld(s, h).is_none())
                    && !crossing(t, share.holders[0]);
            }
            let mut candidates: Vec<(usize, Anchors, bool)> = share
                .holders
                .iter()
                .map(|&k| {
                    let own = &stretches[stretch_of(k)];
                    (k, (own.x, own.y), false)
                })
                .collect();
            if pure {
                candidates.push((share.holders[0], share.spot, true));
            }
            // The first candidate of the least rank.
            let mut keeping: Option<Keeping> = None;
            for (k, anchors, at_spot) in candidates {
                let key = stretch_key(anchors.0, anchors.1);
                let (mut breaks, mut asking) = (Vec::new(), Vec::new());
                for &t in share.holders.iter().filter(|&&t| at_spot || t != k) {
                    let s = stretch_of(t);
                    let own = &stretches[s];
                    let own_key = stretch_key(own.x, own.y);
                    // The fragment's place in its stretch, which is the run
                    // of its side's sequence from `own.at`.
                    let at = presence[t][share.frag].expect("a holder holds its fragment") - own.at;
                    let (before, after) = unheld(s, k)
                        .map_or((false, false), |(first, last)| (first < at, last > at));
                    let crossed = crossing(t, k);
                    if own_key == key {
                        if crossed || (!at_spot && (before || after)) {
                            asking.push(t);
                        }
                        continue;
                    }
                    let (lo, hi) = (own_key.min(key), own_key.max(key));
                    let between = stretches.iter().any(|s| {
                        s.side == t && lo < stretch_key(s.x, s.y) && stretch_key(s.x, s.y) < hi
                    });
                    let apart = (own_key < key && after) || (own_key > key && before);
                    if crossed || between || apart {
                        breaks.push(t);
                    }
                }
                let collision = *collides.entry((k, anchors)).or_insert_with(|| {
                    let (lo, hi) =
                        (anchors.0.map_or(0, |x| x + 1), anchors.1.unwrap_or(r.base.len()));
                    (lo..hi).any(|bi| {
                        removed_by[k][bi]
                            && (0..removed_by.len()).any(|t| t != k && removed_by[t][bi])
                    })
                });
                let gone = |bi: Option<usize>| bi.is_some_and(|bi| removed[bi]);
                let asks =
                    asking.len() + usize::from((gone(anchors.0) && gone(anchors.1)) || collision);
                let own = &stretches[stretch_of(k)];
                let candidate = Keeping {
                    side: k,
                    at: (k, own.x, own.y),
                    anchors,
                    at_spot,
                    breaks,
                    asking,
                    asks,
                };
                if keeping.as_ref().is_none_or(|best| candidate.rank() < best.rank()) {
                    keeping = Some(candidate);
                }
            }
            let keeping = keeping.expect("a share has holders");
            // A holder that asks, or is broken, keeps its copy at the gap; so
            // does one placed elsewhere than the keeper where a side holding
            // none of the words placed words of its own beside it, which its
            // copy is asked against there (R1).
            let place = stretch_key(keeping.anchors.0, keeping.anchors.1);
            let contested = |t: usize| {
                let own = &stretches[stretch_of(t)];
                let at = stretch_key(own.x, own.y);
                at != place
                    && stretches
                        .iter()
                        .any(|s| !share.holders.contains(&s.side) && stretch_key(s.x, s.y) == at)
            };
            let keeps = |t: usize| {
                keeping.asking.contains(&t) || keeping.breaks.contains(&t) || contested(t)
            };
            for &t in share.holders.iter().filter(|&&t| t != keeping.side && !keeps(t)) {
                strip[t].insert(share.frag);
            }
            if keeping.at_spot {
                spots.insert(keeping.at, keeping.anchors);
            }
            // Where the holders' words cannot be laid in every holder's
            // order, those that would come out of order join the keeper's
            // gap: of several keepers' gaps, the one placed first, whatever
            // order the shares are met in.
            for &t in &keeping.breaks {
                let own = &stretches[stretch_of(t)];
                let own_key = stretch_key(own.x, own.y);
                let (lo, hi) = (own_key.min(place), own_key.max(place));
                for s in
                    stretches.iter().filter(|s| s.side == t && (s.side, s.x, s.y) != keeping.at)
                {
                    let at = stretch_key(s.x, s.y);
                    let first = joins.get(&(t, s.x, s.y)).is_none_or(|&(_, k)| place < k);
                    if (at == own_key || (lo < at && at < hi)) && first {
                        joins.insert((t, s.x, s.y), (keeping.at, place));
                    }
                }
            }
        }
        let seqs = seqs
            .iter()
            .enumerate()
            .map(|(s, seq)| seq.iter().copied().filter(|f| !strip[s].contains(f)).collect())
            .collect();
        let whole = stretches.into_iter().map(|st| ((st.side, st.x, st.y), st.frags)).collect();
        let joins = joins.into_iter().map(|(from, (to, _))| (from, to)).collect();
        Kept { seqs, spots, joins, whole, given_up: strip }
    }
}

/// Returns a stretch's sort key at a spine gap: its anchors as base indices,
/// the start before every index and the end after every index.
fn stretch_key(x: Option<usize>, y: Option<usize>) -> (i64, i64) {
    (x.map_or(-1, |x| x as i64), y.map_or(i64::MAX, |y| y as i64))
}

/// Returns whether side `t` holds two of `words` that side `k` holds too in
/// the other order: `presence` is each side's index of each fragment.
///
/// `words` are the shared words of one common spot, which the walk lays in
/// that spot's gap whichever holder keeps each: a holder that orders them
/// otherwise than the keeper is broken by the keeper's laying (§2 R1).
fn crosses(words: &[usize], t: usize, k: usize, presence: &[Vec<Option<usize>>]) -> bool {
    let mut both: Vec<(usize, usize)> =
        words.iter().filter_map(|&f| Some((presence[t][f]?, presence[k][f]?))).collect();
    both.sort_unstable();
    both.windows(2).any(|w| w[0].1 > w[1].1)
}

// ── step 1: the removals ──────────────────────────────────────────────────

/// Returns step 1's removals (merge record §1.4).
///
/// They are, per side, the base positions absent from it; and their union,
/// absent from M whatever the other sides did.
fn removals(r: &Refinement, in_side: &[Vec<Option<usize>>]) -> (Vec<Vec<bool>>, Vec<bool>) {
    let removed_by: Vec<Vec<bool>> =
        in_side.iter().map(|side| r.base.iter().map(|&f| side[f].is_none()).collect()).collect();
    let removed = (0..r.base.len()).map(|bi| removed_by.iter().any(|side| side[bi])).collect();
    (removed_by, removed)
}

// ── step 2: the spine ─────────────────────────────────────────────────────

/// A `moves` gap as the walk holds it.
///
/// It names the side whose order the spine took, the side whose reorder was
/// not applied, and the material each moved.
struct Moves {
    id: GapId,
    winner: usize,
    loser: usize,
    runs: Vec<(SideIx, Run)>,
    settled: bool,
    resolved_by: Option<ResolvedBy>,
}

/// Returns step 2's spine and its `moves` gaps (merge record §1.4).
///
/// The spine is the surviving base material in the order M keeps it — the
/// base's, unless sides reordered it: their reorders folded in the order
/// the sides are listed (`fold`), each that composes with those applied
/// before it applied, and each that does not a `moves` gap, its reorder not
/// applied (§2 R4 iii). `hint` names the side whose order wins outright,
/// every other side's reorder that differs from it a `moves` gap; `chosen`
/// names the side a merger chose, its reorder applied first and every other
/// folded after it. No `moves` gap is settled here: a merger settles one by
/// confirming its winner (`resolve`). The gaps are numbered from `first`,
/// after the gaps with spots, in the order of the sides whose reorders they
/// hold, and a walk under a chosen order numbers them again
/// (`Numbering::number`).
fn spine_of(
    r: &Refinement,
    seqs: &[Vec<usize>],
    in_base: &[Option<usize>],
    removed: &[bool],
    hint: Option<usize>,
    chosen: Option<usize>,
    first: u32,
) -> (Vec<usize>, Vec<Option<usize>>, Vec<Moves>) {
    let surv: Vec<usize> = (0..r.base.len()).filter(|&bi| !removed[bi]).collect();
    let orders: Vec<Vec<usize>> = seqs
        .iter()
        .map(|seq| seq.iter().filter_map(|&f| in_base[f]).filter(|&bi| !removed[bi]).collect())
        .collect();
    let reordered: Vec<usize> = (0..seqs.len()).filter(|&s| orders[s] != surv).collect();
    let (spine, lost) = match hint {
        Some(h) => {
            let lost = reordered
                .iter()
                .filter(|&&s| s != h && orders[s] != orders[h])
                .map(|&s| (h, s))
                .collect();
            (orders[h].clone(), lost)
        }
        None => fold(&surv, &orders, &reordered, chosen),
    };
    let mut spine_pos = vec![None; r.base.len()];
    for (p, &bi) in spine.iter().enumerate() {
        spine_pos[bi] = Some(p);
    }
    let moves = lost
        .into_iter()
        .enumerate()
        .map(|(k, (winner, loser))| {
            let mut runs = moved_runs(r, &surv, winner, &orders[winner]);
            runs.extend(moved_runs(r, &surv, loser, &orders[loser]));
            Moves {
                id: GapId(first + k as u32),
                winner,
                loser,
                runs,
                settled: false,
                resolved_by: None,
            }
        })
        .collect();
    (spine, spine_pos, moves)
}

/// Folds the sides' reorders into one order of the survivors (§2 R4 iii).
///
/// `reordered` lists the sides whose order differs from the base's, in the
/// order the sides are listed, and `first`, where a merger chose it, comes
/// before them all. Each in turn is applied where it composes with every
/// reorder applied before it (`compose_reorders`); a side whose order is
/// the spine's already adds nothing; and each other side is lost to the
/// earliest applied side its own reorder overlaps — else to the first
/// applied, where it overlaps none alone but all together. Returned are the
/// spine and each lost side with the side it lost to, `(winner, loser)`.
/// The fold of two sides is their composition where they compose and the
/// first's order where they do not, so every pair of sides is judged as a
/// merge of two, and a side's reorder that touches material no earlier side
/// moved is never voided by an overlap between two others.
fn fold(
    surv: &[usize],
    orders: &[Vec<usize>],
    reordered: &[usize],
    first: Option<usize>,
) -> (Vec<usize>, Vec<(usize, usize)>) {
    let mut applied: Vec<usize> = first.into_iter().collect();
    let mut spine = first.map_or_else(|| surv.to_vec(), |f| orders[f].clone());
    let mut lost = Vec::new();
    let composed = |sides: &[usize]| -> Option<Vec<usize>> {
        let given: Vec<(usize, &[usize])> =
            sides.iter().map(|&s| (s, orders[s].as_slice())).collect();
        compose_reorders(surv, &given)
    };
    for &s in reordered.iter().filter(|&&s| Some(s) != first) {
        if orders[s] == spine {
            continue;
        }
        if applied.is_empty() {
            applied.push(s);
            spine = orders[s].clone();
            continue;
        }
        let with: Vec<usize> = applied.iter().copied().chain([s]).collect();
        match composed(&with) {
            Some(both) => {
                applied = with;
                spine = both;
            }
            None => {
                let winner = applied
                    .iter()
                    .copied()
                    .find(|&a| composed(&[a, s]).is_none())
                    .unwrap_or(applied[0]);
                lost.push((winner, s));
            }
        }
    }
    (spine, lost)
}

/// Returns the base material a side moved, as runs with the side.
///
/// It is the survivors outside the longest part of the side's order that
/// keeps the base's.
fn moved_runs(r: &Refinement, surv: &[usize], side: usize, order: &[usize]) -> Vec<(SideIx, Run)> {
    let moved = moved_set(surv, order);
    let mut bis: Vec<usize> = moved.into_iter().collect();
    bis.sort_unstable();
    r.coalesce(bis.into_iter().map(|bi| r.base[bi])).into_iter().map(|run| (r.side_ix[side], run)).collect()
}

/// Returns the base indices a side's order moved.
///
/// They are relative to the base's order of the survivors.
fn moved_set(surv: &[usize], order: &[usize]) -> HashSet<usize> {
    let mut rank = vec![None; surv.iter().copied().max().map_or(0, |m| m + 1)];
    for (p, &bi) in surv.iter().enumerate() {
        rank[bi] = Some(p);
    }
    let keys: Vec<Option<usize>> = order.iter().map(|&bi| rank.get(bi).copied().flatten()).collect();
    let kept: HashSet<usize> = longest_increasing(&keys).into_iter().collect();
    order.iter().enumerate().filter(|(i, _)| !kept.contains(i)).map(|(_, &bi)| bi).collect()
}

/// Composes two or more sides' reorders into one order of the survivors.
///
/// `None` where they overlap: a survivor two of them moved, or a pair of
/// survivors whose order the sides' moves and the base's order between them
/// cannot all keep. The material no side moved keeps the base's order; each
/// moved survivor keeps its place among that material as its side put it;
/// two moved survivors stand in the order the side that changed their order
/// gave, else the base's.
///
/// The cost is quadratic in the moved survivors: the slots are filled in one
/// pass, and the survivors of one slot are ordered by their scores — how
/// many of the slot's others each comes before. The pair order is a
/// tournament, so one order keeps every pair of a slot exactly where its
/// scores are all distinct, and it is the scores' order, highest first;
/// equal scores are a cycle no order keeps.
fn compose_reorders(surv: &[usize], orders: &[(usize, &[usize])]) -> Option<Vec<usize>> {
    let top = surv.iter().copied().max().map_or(0, |m| m + 1);
    let mut base_pos = vec![usize::MAX; top];
    for (p, &bi) in surv.iter().enumerate() {
        base_pos[bi] = p;
    }
    // Each survivor's position in each order, and the one side that moved
    // it; a survivor two sides moved is an overlap.
    let mut pos: Vec<Vec<usize>> = Vec::new();
    let mut moved_by = vec![None; top];
    for (k, (_, order)) in orders.iter().enumerate() {
        let mut p = vec![usize::MAX; top];
        for (i, &bi) in order.iter().enumerate() {
            p[bi] = i;
        }
        pos.push(p);
        for bi in moved_set(surv, order) {
            if moved_by[bi].is_some() {
                return None;
            }
            moved_by[bi] = Some(k);
        }
    }
    // The unmoved material in the base's order, and each moved survivor's
    // slot among it as its own side placed it.
    let kept: Vec<usize> = surv.iter().copied().filter(|&bi| moved_by[bi].is_none()).collect();
    let mut slot = vec![usize::MAX; top];
    for (k, (_, order)) in orders.iter().enumerate() {
        let mut seen = 0;
        for &bi in order.iter() {
            match moved_by[bi] {
                None => seen += 1,
                Some(side) if side == k => slot[bi] = seen,
                Some(_) => {}
            }
        }
    }
    let moved: Vec<usize> = surv.iter().copied().filter(|&bi| moved_by[bi].is_some()).collect();
    // Two moved survivors: before, by the side that changed their order,
    // else by the base. Across slots the slots must agree; inside one slot
    // the pairs order the slot.
    let before = |x: usize, y: usize| -> bool {
        let base = base_pos[x] < base_pos[y];
        for &side in [moved_by[x], moved_by[y]].iter().flatten() {
            let own = pos[side][x] < pos[side][y];
            if own != base {
                return own;
            }
        }
        base
    };
    for (i, &x) in moved.iter().enumerate() {
        for &y in &moved[i + 1..] {
            if slot[x] != slot[y] && (slot[x] < slot[y]) != before(x, y) {
                return None;
            }
        }
    }
    let mut slots: Vec<Vec<usize>> = vec![Vec::new(); kept.len() + 1];
    for &bi in &moved {
        slots[slot[bi]].push(bi);
    }
    let mut spine = Vec::with_capacity(surv.len());
    for (s, here) in slots.iter().enumerate() {
        let mut scored: Vec<(usize, usize)> = here
            .iter()
            .map(|&x| (here.iter().filter(|&&y| y != x && before(x, y)).count(), x))
            .collect();
        scored.sort_unstable_by_key(|&(score, _)| std::cmp::Reverse(score));
        if scored.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return None;
        }
        spine.extend(scored.into_iter().map(|(_, x)| x));
        if s < kept.len() {
            spine.push(kept[s]);
        }
    }
    Some(spine)
}

/// Returns the positions of one longest strictly increasing subsequence.
///
/// The subsequence is of `keys`, a `None` never kept — patience sorting
/// with back links; deterministic.
fn longest_increasing(keys: &[Option<usize>]) -> Vec<usize> {
    let mut tails: Vec<usize> = Vec::new();
    let mut back: Vec<Option<usize>> = vec![None; keys.len()];
    for (i, key) in keys.iter().enumerate() {
        let Some(k) = key else { continue };
        let at = tails.partition_point(|&t| keys[t].is_some_and(|tk| tk < *k));
        back[i] = at.checked_sub(1).map(|p| tails[p]);
        if at == tails.len() {
            tails.push(i);
        } else {
            tails[at] = i;
        }
    }
    let mut out = Vec::new();
    let mut cursor = tails.last().copied();
    while let Some(i) = cursor {
        out.push(i);
        cursor = back[i];
    }
    out.reverse();
    out
}

// ── step 3: the additions ─────────────────────────────────────────────────

/// A side's stretch.
///
/// It holds its side, its fragments, where it begins in the side's
/// sequence, and its two anchors as base indices — `None` at the document's
/// ends — and beside its fragments the ones it held before each identity
/// several sides hold was kept by one of them (`Kept::of`), every shared
/// fragment among them.
struct Stretch {
    side: usize,
    at: usize,
    frags: Vec<usize>,
    whole: Vec<usize>,
    x: Option<usize>,
    y: Option<usize>,
}

/// Returns step 3's additions (merge record §1.4).
///
/// They are each side's maximal stretches of its sequence whose positions
/// are not the base's, each with the base positions immediately before and
/// after it there.
fn additions(seqs: &[Vec<usize>], in_base: &[Option<usize>]) -> Vec<Stretch> {
    let mut out = Vec::new();
    for (side, seq) in seqs.iter().enumerate() {
        let mut i = 0;
        let mut x = None;
        while i < seq.len() {
            if let Some(bi) = in_base[seq[i]] {
                x = Some(bi);
                i += 1;
                continue;
            }
            let at = i;
            let mut frags = Vec::new();
            while i < seq.len() && in_base[seq[i]].is_none() {
                frags.push(seq[i]);
                i += 1;
            }
            let y = seq.get(i).and_then(|&f| in_base[f]);
            let whole = frags.clone();
            out.push(Stretch { side, at, frags, whole, x, y });
        }
    }
    out
}

// ── step 4: the placement ─────────────────────────────────────────────────

/// Where a stretch goes and what kind of gap it makes.
///
/// `home` is the gap of the spine it lands in (gap `g` lies before the
/// spine's `g`-th survivor, `0` the start), `kind` `None` for an addition
/// between two anchors that stand together, which asks nothing where it is
/// one-sided and meets no other side's addition or lone removal at a line's
/// edge (`line_edges`), and `key` the spot it sorts by there, its anchors'
/// (`stretch_key`).
#[derive(Clone, Copy)]
struct Placed {
    kind: Option<GapKind>,
    home: usize,
    before: bool,
    key: (i64, i64),
}

/// The spine and the removals one walk places stretches by.
struct Layout<'a> {
    r: &'a Refinement,
    in_base: &'a [Option<usize>],
    removed_by: &'a [Vec<bool>],
    removed: &'a [bool],
    spine: &'a [usize],
    spine_pos: &'a [Option<usize>],
}

/// One walk's additions as `Layout::place` lays them out over one `Kept`.
///
/// It holds the stretches, the placement of each, and the shared words each
/// side of that same `Kept` gave up to another holder's copy, which the line
/// rule counts as that side's (`Placers`).
struct Laid<'k> {
    stretches: Vec<Stretch>,
    /// Each stretch's placement, parallel to `stretches`.
    placed: Vec<Placed>,
    given_up: &'k [HashSet<usize>],
}

impl Layout<'_> {
    /// Returns step 3's additions over `kept` with step 4's placements.
    ///
    /// A keeper's stretch `kept` places at a common spot is placed by that
    /// spot's anchors, and a stretch that joins another's gap takes that
    /// stretch's placement (`Kept::of`), so the two group as one gap.
    fn place<'k>(&self, kept: &'k Kept) -> Laid<'k> {
        let mut stretches = additions(&kept.seqs, self.in_base);
        let ids: Vec<StretchAt> = stretches.iter().map(|st| (st.side, st.x, st.y)).collect();
        for (st, id) in stretches.iter_mut().zip(&ids) {
            if let Some(&(x, y)) = kept.spots.get(id) {
                (st.x, st.y) = (x, y);
            }
            if let Some(whole) = kept.whole.get(id) {
                st.whole.clone_from(whole);
            }
        }
        let mut placed = placement(
            self.r,
            &stretches,
            self.removed_by,
            self.removed,
            self.spine,
            self.spine_pos,
        );
        let index: HashMap<StretchAt, usize> =
            ids.iter().enumerate().map(|(i, id)| (*id, i)).collect();
        let joined: Vec<(usize, usize)> = ids
            .iter()
            .enumerate()
            .filter_map(|(i, id)| Some((i, *index.get(&joined_to(&kept.joins, *id)?)?)))
            .collect();
        let at_own = placed.clone();
        for (i, j) in joined {
            placed[i] = at_own[j];
        }
        Laid { stretches, placed, given_up: &kept.given_up }
    }
}

/// Returns the stretch whose gap `from` joins, following joins in turn.
///
/// `None` where `from` joins none. The joins are finite, so a chain of them
/// ends, or returns to a stretch it passed, where it stops.
fn joined_to(joins: &HashMap<StretchAt, StretchAt>, from: StretchAt) -> Option<StretchAt> {
    let mut at = *joins.get(&from)?;
    let mut passed = vec![from];
    while let Some(&next) = joins.get(&at) {
        if passed.contains(&next) {
            break;
        }
        passed.push(at);
        at = next;
    }
    Some(at)
}

/// Returns step 4's placements (merge record §1.4, §2).
///
/// Each stretch is placed by its anchors. Its own side's removal between
/// its anchors overlapping another side's removal is a `collision`,
/// whatever stands in the place. Else both anchors surviving and standing
/// together in the spine is the gap between them; both surviving apart is a
/// `cut`, after the left; one surviving is an `anchor`, beside the
/// survivor; neither is a `corner`, after the nearest survivor to the left
/// in the base's order.
fn placement(
    r: &Refinement,
    stretches: &[Stretch],
    removed_by: &[Vec<bool>],
    removed: &[bool],
    spine: &[usize],
    spine_pos: &[Option<usize>],
) -> Vec<Placed> {
    let after = |bi: Option<usize>| bi.and_then(|bi| spine_pos[bi]).map_or(0, |p| p + 1);
    let left = |from: Option<usize>| after_left_survivor(from, removed, spine_pos);
    stretches
        .iter()
        .map(|st| {
            let key = stretch_key(st.x, st.y);
            let lo = st.x.map_or(0, |x| x + 1);
            let hi = st.y.unwrap_or(r.base.len());
            let collision = (lo..hi).any(|bi| {
                removed_by[st.side][bi] && (0..removed_by.len()).any(|t| t != st.side && removed_by[t][bi])
            });
            if collision {
                return Placed {
                    kind: Some(GapKind::Collision),
                    home: left(st.x),
                    before: false,
                    key,
                };
            }
            let x_survives = st.x.is_none_or(|x| !removed[x]);
            let y_survives = st.y.is_none_or(|y| !removed[y]);
            match (x_survives, y_survives) {
                (true, true) => {
                    let px = st.x.and_then(|x| spine_pos[x]);
                    let py = st.y.and_then(|y| spine_pos[y]);
                    let together = match (px, py) {
                        (None, None) => spine.is_empty(),
                        (None, Some(q)) => q == 0,
                        (Some(p), None) => p + 1 == spine.len(),
                        (Some(p), Some(q)) => p + 1 == q,
                    };
                    let kind = if together { None } else { Some(GapKind::Cut) };
                    Placed { kind, home: after(st.x), before: false, key }
                }
                (true, false) => {
                    Placed { kind: Some(GapKind::Anchor), home: after(st.x), before: false, key }
                }
                (false, true) => {
                    // The right anchor survives: before it in the spine —
                    // and where it is `⊤`, the end of the document, before
                    // the spine's end.
                    let home = st.y.and_then(|y| spine_pos[y]).unwrap_or(spine.len());
                    Placed { kind: Some(GapKind::Anchor), home, before: true, key }
                }
                (false, false) => {
                    Placed { kind: Some(GapKind::Corner), home: left(st.x), before: false, key }
                }
            }
        })
        .collect()
}

/// Returns the spine gap immediately after a survivor to the left.
///
/// The survivor is the nearest surviving base position at or left of base
/// index `from`, in the base's order; the gap is the start where there is
/// none.
fn after_left_survivor(from: Option<usize>, removed: &[bool], spine_pos: &[Option<usize>]) -> usize {
    let mut cursor = from;
    while let Some(bi) = cursor {
        if !removed[bi] {
            return spine_pos[bi].map_or(0, |p| p + 1);
        }
        cursor = bi.checked_sub(1);
    }
    0
}

/// A stretch of base material two sides both removed.
///
/// It is held as a spine gap and the base indices it covers (merge record
/// decision 3: a collision with nothing put in its place is still listed).
struct Region {
    home: usize,
    first: usize,
    last: usize,
}

/// Returns the maximal stretches of the base that two sides both removed.
///
/// They come in the base's order.
fn collision_regions(
    r: &Refinement,
    removed_by: &[Vec<bool>],
    removed: &[bool],
    spine_pos: &[Option<usize>],
) -> Vec<Region> {
    let twice = |bi: usize| removed_by.iter().filter(|side| side[bi]).count() >= 2;
    let mut out = Vec::new();
    let mut bi = 0;
    while bi < r.base.len() {
        if !twice(bi) {
            bi += 1;
            continue;
        }
        let first = bi;
        while bi < r.base.len() && twice(bi) {
            bi += 1;
        }
        let home = after_left_survivor(first.checked_sub(1), removed, spine_pos);
        out.push(Region { home, first, last: bi - 1 });
    }
    out
}

/// A stretch of base material one side alone removed with no words of its
/// own in its place, as the line rule weighs it (skep #1176).
///
/// It stands in M as a point where its bytes were: `home` the spine gap
/// after the nearest surviving base position to its left, as a collision's
/// region stands, and `key` its first and last base indices, which order it
/// among the gaps there.
#[derive(Clone, Copy)]
struct LoneRemoval {
    side: usize,
    home: usize,
    key: (i64, i64),
}

/// Returns the stretches of the base one side alone removed and set no
/// words of its own in place of, in M's order (skep #1176).
///
/// Each is a maximal run of base indices `removed_by` marks removed by one
/// side and by no other. One the side set words in place of — a stretch of
/// its own whose anchors stand either side of the run — is no lone
/// removal: the line rule weighs those words, an addition, instead.
fn lone_removals(
    r: &Refinement,
    removed_by: &[Vec<bool>],
    removed: &[bool],
    spine_pos: &[Option<usize>],
    stretches: &[Stretch],
) -> Vec<LoneRemoval> {
    let by_one = |bi: usize| -> Option<usize> {
        let mut by = (0..removed_by.len()).filter(|&side| removed_by[side][bi]);
        let side = by.next()?;
        by.next().is_none().then_some(side)
    };
    let mut out = Vec::new();
    let mut bi = 0;
    while bi < r.base.len() {
        let Some(side) = by_one(bi) else {
            bi += 1;
            continue;
        };
        let first = bi;
        while bi < r.base.len() && by_one(bi) == Some(side) {
            bi += 1;
        }
        let last = bi - 1;
        let typed_over = stretches.iter().any(|st| {
            st.side == side && st.x.is_none_or(|x| x < first) && st.y.is_none_or(|y| y > last)
        });
        if !typed_over {
            let home = after_left_survivor(first.checked_sub(1), removed, spine_pos);
            out.push(LoneRemoval { side, home, key: (first as i64, last as i64) });
        }
    }
    out.sort_by_key(|lone| (lone.home, lone.key));
    out
}

// ── step 5: the gaps ──────────────────────────────────────────────────────

/// One side's material at a gap.
///
/// It is its stretches' fragments, in the side's own order, and beside them
/// the fragments those stretches held before a shared one was kept by
/// another holder (`Stretch`).
#[derive(PartialEq, Eq)]
struct Group {
    side: usize,
    frags: Vec<usize>,
    whole: Vec<usize>,
}

/// A gap as the walk holds it before the report.
///
/// It holds its number and its kind, the spine gap it lands in, the spot it
/// sorts by there, the groups by side in the default order, how they are
/// placed, whether and by whom it is settled, and the lone removals that
/// meet its words at a line's edge (`line_edges`).
struct Entry {
    id: Option<GapId>,
    kind: Option<GapKind>,
    home: usize,
    key: (i64, i64),
    groups: Vec<Group>,
    placed: Placement,
    settled: bool,
    resolved_by: Option<ResolvedBy>,
    removed: Vec<LoneRemoval>,
}

/// Returns step 5's gaps (merge record §1.4, §2 R1, §5; skep #1173,
/// #1176).
///
/// The stretches `laid` holds that landed at one spot are grouped by side,
/// each group in its side's own order; the collisions at one spine gap are
/// one `collision` gap, a region no side filled listed too; the gaps are put
/// in M's order, the order `splice` lays them in, and an addition met at a
/// line's edge by another side's neighbouring addition, or by one of
/// `lone`, the removals one side alone made with no words of its own in
/// their place (`lone_removals`), is a `line` gap (`line_edges`, its reads
/// through `lines`, a side's words there counting the shared ones `laid`
/// says it gave up); then the groups go in the order rule's order — a spot
/// two sides added at is an `order` gap, unsettled, where it would otherwise
/// be no gap or an `anchor` — and the dedup reads through `values` where it
/// is on, each line read told the pair it decides (`LinePair`). The gaps
/// are numbered here from `first`, in M's order after the
/// `moves` gaps, so the dedup can name the gap it fired at; a walk with a
/// holder chosen, or under a chosen order, numbers them again (`number_as`,
/// `Numbering::number`), the dedup's ids following them. `chain` is the
/// document's chain the order rule reads, and `spine` the walk's.
#[allow(clippy::too_many_arguments)]
fn gaps(
    r: &Refinement,
    chain: &HashSet<usize>,
    spine: &[usize],
    laid: &Laid<'_>,
    regions: &[Region],
    lone: &[LoneRemoval],
    first: u32,
    options: &Options,
    lines: &AskedLines<'_>,
    values: &AskedValues<'_>,
) -> (Vec<Entry>, Vec<GapId>) {
    let mut entries: Vec<Entry> = Vec::new();
    for (st, p) in laid.stretches.iter().zip(&laid.placed) {
        let key = p.key;
        let found = entries.iter().position(|e| {
            e.home == p.home
                && e.kind == p.kind
                && (p.kind == Some(GapKind::Collision) || e.key == key)
        });
        let at = match found {
            Some(at) => at,
            None => {
                entries.push(Entry {
                    id: None,
                    kind: p.kind,
                    home: p.home,
                    key,
                    groups: Vec::new(),
                    placed: if p.before { Placement::Before } else { Placement::After },
                    settled: false,
                    resolved_by: None,
                    removed: Vec::new(),
                });
                entries.len() - 1
            }
        };
        let entry = &mut entries[at];
        entry.key = entry.key.min(key);
        match entry.groups.iter_mut().find(|g| g.side == st.side) {
            Some(group) => {
                group.frags.extend(st.frags.iter().copied());
                group.whole.extend(st.whole.iter().copied());
            }
            None => entry.groups.push(Group {
                side: st.side,
                frags: st.frags.clone(),
                whole: st.whole.clone(),
            }),
        }
    }
    // A shared word a side gave up to a keeper whose copy the same gap lays
    // is that side's word at the gap too: each group lists every word its
    // stretches held that the gap lays, in the side's own order, so a choice
    // of the side lays all it placed there.
    for entry in entries.iter_mut() {
        let laid: HashSet<usize> =
            entry.groups.iter().flat_map(|g| g.frags.iter().copied()).collect();
        for group in entry.groups.iter_mut() {
            group.frags = group.whole.iter().copied().filter(|f| laid.contains(f)).collect();
        }
    }
    for region in regions {
        if !entries.iter().any(|e| e.kind == Some(GapKind::Collision) && e.home == region.home) {
            entries.push(Entry {
                id: None,
                kind: Some(GapKind::Collision),
                home: region.home,
                key: (region.first as i64, region.last as i64),
                groups: Vec::new(),
                placed: Placement::After,
                settled: false,
                resolved_by: None,
                removed: Vec::new(),
            });
        }
    }
    entries.sort_by_key(|e| (e.home, e.key));
    line_edges(r, spine, &mut entries, lone, laid.given_up, lines);
    // The order rule: a spot two sides added at is an `order` gap where it
    // would otherwise be no gap or an `anchor`, the groups by the commit of
    // their first run — inside the document's chain the address order, a
    // group whose first run lies outside it last. The chain is the
    // document's own text and every origin the base holds, so over an empty
    // base the document's text still comes before a window onto a document
    // addressed below it (skep #1115). Two groups whose first runs are one —
    // a word both sides placed alike, kept by each (`Kept::of`) — are
    // ordered by the commit of their next.
    let commit = |f: &usize| {
        let frag = r.frags[*f];
        (!chain.contains(&frag.origin), &r.origins[frag.origin], frag.start)
    };
    for entry in entries.iter_mut() {
        entry.groups.sort_by(|a, b| a.frags.iter().map(commit).cmp(b.frags.iter().map(commit)));
        if entry.groups.len() >= 2 {
            if matches!(entry.kind, None | Some(GapKind::Anchor)) {
                entry.kind = Some(GapKind::Order);
            }
            entry.placed = Placement::Order(entry.groups.iter().map(|g| r.side_ix[g.side]).collect());
        }
        if entry.kind == Some(GapKind::Anchor) {
            entry.settled = true;
            entry.resolved_by = Some(ResolvedBy::Rule);
        }
    }
    let mut next = first;
    for entry in entries.iter_mut().filter(|e| e.kind.is_some()) {
        entry.id = Some(GapId(next));
        next += 1;
    }
    // The value rule's dedup: at an `order` gap, a later group whose bytes
    // equal an earlier kept group's is not placed; a gap it empties of
    // difference is settled by it.
    let mut applied = Vec::new();
    if options.dedup {
        for entry in entries.iter_mut().filter(|e| e.kind == Some(GapKind::Order)) {
            let bytes: Vec<Option<Vec<Item>>> =
                entry.groups.iter().map(|g| r.bytes(g.side, g.frags.iter().copied(), values)).collect();
            let mut kept: Vec<usize> = Vec::new();
            for j in 0..entry.groups.len() {
                let twice = bytes[j].is_some() && kept.iter().any(|&i| bytes[i] == bytes[j]);
                if !twice {
                    kept.push(j);
                }
            }
            if kept.len() < entry.groups.len() {
                applied.extend(entry.id);
                entry.placed = Placement::Order(kept.iter().map(|&i| r.side_ix[entry.groups[i].side]).collect());
                if kept.len() == 1 {
                    entry.settled = true;
                    entry.resolved_by = Some(ResolvedBy::Rule);
                }
            }
        }
    }
    (entries, applied)
}

/// How far into the text between a pair's two changes the line rule first
/// reads.
///
/// A read of this many positions finds the break of any line shorter than
/// it. The rule's first reads over a pair ask at most this many positions
/// of the text between them and two more, whatever the text's length; it
/// reads on only where a line longer than this leaves its answer open
/// (`meet_at_a_line_edge`).
pub(super) const LINE_READ: u64 = 4096;

/// Marks each addition another side's change meets at a line's edge a
/// `line` gap (skep #1173, #1176).
///
/// `entries` are in M's order. The rule weighs an entry that has no kind or
/// is R2's `anchor`, an addition beside a removal, whose place R2 settles
/// and whose line's edge it leaves to this rule; never a cut, a corner or a
/// collision, which asks already. Two neighbours among those that lay
/// words are a pair where they lie in different spine gaps, so that only
/// surviving base text stands between them in M, both are weighed, one at
/// least is held by one side alone — two held by several sides are `order`
/// gaps whatever the text — and they hold the changes of two sides, each
/// one the other did not also make: some side placed at one of the two a
/// word another side did not place there, and that other placed at the
/// other a word the first did not. A side's words at an entry count the
/// shared ones it gave up to the keeper's copy laid there (`given_up`;
/// `Placers`), so which holder keeps a word decides no pair, and a side
/// whose every change another side made too meets no line's edge. A removal
/// of `lone`, in M's order too, is a pair with its nearest neighbour before
/// it and its nearest after it among the entries that lay words, where that
/// neighbour lies in another spine gap, is weighed, and is held by one
/// other side alone, which placed there a word the remover did not;
/// removals stand beside each other in M as points, so another removal
/// between them parts nothing. The first of a
/// pair stands at a line's start where the base position just before it is
/// a line break, or where it lies at the document's start. The pair meets
/// at a line's edge where the base text M lays between the two holds one
/// line break, its last byte, and the first does not stand at a line's
/// start — one inside a line, the other right after its break — or where
/// that text holds none and the first does — one at a line's start, the
/// other inside that line. Each addition of the two held by one side alone
/// is then a `line` gap, and the removal of a pair is named in its gap
/// ([`Gap::removed`]), in M's order. `lines` reads what decides it through
/// the first side listed, which holds every surviving base position
/// (`meet_at_a_line_edge`), each read told the pair it decides: the first
/// change's `after` anchor and the second's `before`, as the report names
/// each gap's and each removal's (`anchors_at`). The pairs of two additions
/// are weighed first, in M's order.
///
/// The removals that pair with one addition are weighed walking outward
/// from it, the nearest first on each side, those at one spot weighed as
/// one, since a pair's answer is its two spots'. The texts of one walk nest:
/// each farther one holds the nearer one's, so a break the nearer one's
/// reads showed before its text's last byte — or anywhere in it, walking
/// after the addition, where each text ends at its own removal — parts
/// every farther removal too, and the walk ends there, unread. It ends as
/// well at a pair whose reads did not answer one item a position. Every
/// range a read answered is kept for the rest of the rule, as where its
/// breaks fall and never as its bytes (`LineReads`), so a farther pair asks
/// only the text the nearer ones' reads did not reach and the position
/// before its removal: a walk reads the text out from its addition to the
/// break that ends it, a line's worth or two, however many removals share
/// one addition (skep #1176).
///
/// Which runs a pair's first reads ask is the entries' and the removals'
/// alone, never the values', save a walk's past its nearest removal: every
/// pair is found on the kinds `placement` gave, the marks made once every
/// pair is weighed, and every first read of a pair asked before any is
/// weighed, or answered from the ranges kept. A pair reads on past
/// them, and a walk goes on past its pair, only where they answered one
/// item a position and left it undecided, so a reader answering no run, or
/// every run with no items, marks no gap and is asked no further read.
fn line_edges(
    r: &Refinement,
    spine: &[usize],
    entries: &mut [Entry],
    lone: &[LoneRemoval],
    given_up: &[HashSet<usize>],
    lines: &AskedLines<'_>,
) {
    let reads = LineReads::new(lines);
    let alone = |e: &Entry| e.groups.len() == 1;
    let weighable = |e: &Entry| matches!(e.kind, None | Some(GapKind::Anchor));
    let placers = Placers::of(entries, given_up);
    let laying: Vec<usize> =
        (0..entries.len()).filter(|&i| !entries[i].groups.is_empty()).collect();
    let mut marked: Vec<usize> = Vec::new();
    for pair in laying.windows(2) {
        let (p, q) = (&entries[pair[0]], &entries[pair[1]]);
        let apart = p.home < q.home && weighable(p) && weighable(q);
        if !apart || !(alone(p) || alone(q)) || !placers.two_sides_changed(pair[0], pair[1]) {
            continue;
        }
        if meet_between(r, spine, p.home, q.home, &reads).meets {
            marked.extend(pair.iter().copied().filter(|&i| alone(&entries[i])));
        }
    }
    // A removal lies before every entry at its spot or past it, so it is
    // walked to from the first entry that lays words at or past its spot
    // and from the last before it; `past(i)` is the first removal past
    // entry `i`.
    let place = |i: usize| (entries[i].home, entries[i].key);
    let past = |i: usize| lone.partition_point(|l| (l.home, l.key) <= place(i));
    let mut answered: Vec<(usize, LoneRemoval)> = Vec::new();
    for (k, &i) in laying.iter().enumerate() {
        let e = &entries[i];
        if !weighable(e) || !alone(e) {
            continue;
        }
        let (side, home) = (e.groups[0].side, e.home);
        // A removal whose side placed here not every word the addition
        // lays: never the adding side's own, which placed them all.
        let other = |l: &&LoneRemoval| placers.beyond(i, side, l.side);
        let from = k.checked_sub(1).map_or(0, |j| past(laying[j]));
        let to = laying.get(k + 1).map_or(lone.len(), |&j| past(j));
        let at = past(i);
        // Before the addition, each removal the first of its pair: the
        // texts share their last byte.
        let mut weighed: Option<(usize, Edge)> = None;
        for removal in lone[from..at].iter().rev().filter(|l| other(l) && l.home < home) {
            let edge = match weighed {
                Some((spot, edge)) if spot == removal.home => edge,
                Some((_, edge)) if !edge.answered || edge.broken => break,
                _ => meet_between(r, spine, removal.home, home, &reads),
            };
            weighed = Some((removal.home, edge));
            if edge.meets {
                answered.push((i, *removal));
            }
        }
        // After it, the addition the first: each text ends at its removal.
        let mut weighed: Option<(usize, Edge)> = None;
        for removal in lone[at..to].iter().filter(|l| other(l) && l.home > home) {
            let edge = match weighed {
                Some((spot, edge)) if spot == removal.home => edge,
                Some((_, edge)) if !edge.answered || edge.broken || edge.ends_in_break => break,
                _ => meet_between(r, spine, home, removal.home, &reads),
            };
            weighed = Some((removal.home, edge));
            if edge.meets {
                answered.push((i, *removal));
            }
        }
    }
    answered.sort_by_key(|(i, removal)| (*i, removal.home, removal.key));
    for i in marked {
        entries[i].kind = Some(GapKind::Line);
    }
    for (i, removal) in answered {
        entries[i].kind = Some(GapKind::Line);
        entries[i].removed.push(removal);
    }
}

/// Each side's words at each entry, as the line rule reads them (skep
/// #1173, #1176).
///
/// A side's words at an entry are its group's, and every word the entry
/// lays that the side gave up to another holder's copy (`Kept::given_up`):
/// a holder that gave its copy up placed those words all the same, so
/// which holder keeps a word decides nothing the rule asks.
struct Placers(Vec<Vec<(usize, HashSet<usize>)>>);

impl Placers {
    /// Returns each side's words at each of `entries`, `given_up` each
    /// side's shared words given up to another holder's copy.
    fn of(entries: &[Entry], given_up: &[HashSet<usize>]) -> Placers {
        let mut givers: HashMap<usize, Vec<usize>> = HashMap::new();
        for (side, gave) in given_up.iter().enumerate() {
            for &f in gave {
                givers.entry(f).or_default().push(side);
            }
        }
        let at = |e: &Entry| {
            let mut words: Vec<(usize, HashSet<usize>)> =
                e.groups.iter().map(|g| (g.side, g.frags.iter().copied().collect())).collect();
            for f in e.groups.iter().flat_map(|g| g.frags.iter().copied()) {
                for &side in givers.get(&f).into_iter().flatten() {
                    match words.iter_mut().find(|(s, _)| *s == side) {
                        Some((_, held)) => {
                            held.insert(f);
                        }
                        None => words.push((side, HashSet::from([f]))),
                    }
                }
            }
            words
        };
        Placers(entries.iter().map(at).collect())
    }

    /// Returns whether side `x` placed at entry `i` a word side `z` did not
    /// place there.
    fn beyond(&self, i: usize, x: usize, z: usize) -> bool {
        let words = |side: usize| self.0[i].iter().find(|(s, _)| *s == side).map(|(_, w)| w);
        match (words(x), words(z)) {
            (None, _) => false,
            (Some(xs), None) => !xs.is_empty(),
            (Some(xs), Some(zs)) => xs.iter().any(|f| !zs.contains(f)),
        }
    }

    /// Returns whether entries `p` and `q` hold the changes of two sides,
    /// each one the other did not also make.
    ///
    /// Some side placed at `p` a word another did not place there, and that
    /// other placed at `q` a word the first did not.
    fn two_sides_changed(&self, p: usize, q: usize) -> bool {
        let sides: Vec<usize> = self.0[p].iter().chain(&self.0[q]).map(|(s, _)| *s).collect();
        sides.iter().any(|&x| {
            sides.iter().any(|&z| x != z && self.beyond(p, x, z) && self.beyond(q, z, x))
        })
    }
}

/// Returns what the reads showed of the changes in the spine gaps `first`
/// and `second` at a line's edge, `first` the earlier (`line_edges`).
///
/// The text between them is the surviving base text M lays from the spine
/// gap `first` to `second`, and the position before is the last of the
/// survivor just before `first`, none at the document's start; each read
/// is told the pair by the first's `after` anchor and the second's `before`
/// (`LinePair`).
fn meet_between(r: &Refinement, spine: &[usize], first: usize, second: usize, lines: &LineReads<'_>) -> Edge {
    let before = first.checked_sub(1).map(|at| r.last_position(r.base[spine[at]]));
    let text = r.coalesce(spine[first..second].iter().map(|&bi| r.base[bi]));
    let pair = LinePair {
        after: anchors_at(r, spine, first).0,
        before: anchors_at(r, spine, second).1,
    };
    let read = |side: SideIx, run: &Run| lines.read(side, run, &pair);
    meet_at_a_line_edge(r.side_ix[0], before, &text, &read)
}

/// The line rule's reads of the base text, each kept as the range it read
/// and the line breaks in it (`line_edges`; skep #1176).
///
/// A run wholly inside the ranges kept for its origin is answered from them
/// and asked nothing; any other is asked whole, as the pair spells it, so
/// the runs asked are among those the rule asks keeping nothing, never a run
/// cut otherwise, and a read answering anything but one item a position
/// keeps nothing. The rule reads through the first side listed alone, and an
/// item at an I-address is the same at every read, so a range kept answers
/// as a read asked again would. No item is kept: the rule looks at nothing
/// in one but whether it is the byte `\n` (`LineRead`).
struct LineReads<'a> {
    /// The reads, as [`compose_asking`]'s `lines`.
    lines: &'a AskedLines<'a>,
    /// Each origin's ranges read, and the breaks in them.
    kept: RefCell<HashMap<Address, ReadRanges>>,
}

impl<'a> LineReads<'a> {
    /// Returns the reads through `lines`, nothing kept yet.
    fn new(lines: &'a AskedLines<'a>) -> LineReads<'a> {
        LineReads { lines, kept: RefCell::new(HashMap::new()) }
    }

    /// Returns where `run`'s line breaks fall, from the ranges kept or read
    /// now as `pair` tells; `None` where the read answers none.
    fn read(&self, side: SideIx, run: &Run, pair: &LinePair) -> Option<LineRead> {
        let kept = self.kept.borrow().get(&run.origin).and_then(|at| at.breaks_over(run));
        if let Some(breaks) = kept {
            return Some(LineRead::Breaks(breaks));
        }
        let read = (self.lines)(side, run, pair)?;
        if let LineRead::Breaks(breaks) = &read {
            self.kept.borrow_mut().entry(run.origin.clone()).or_default().keep(run, breaks);
        }
        Some(read)
    }
}

/// One origin's ranges of I-ordinals the line rule has read, and the line
/// breaks in them (`LineReads`).
#[derive(Default)]
struct ReadRanges {
    /// The ranges read, each `(first, reach)`, rising and apart: two that
    /// touch or overlap are kept as one.
    ranges: Vec<(u64, u64)>,
    /// The I-ordinals of the breaks in them.
    breaks: BTreeSet<u64>,
}

impl ReadRanges {
    /// Returns where `run`'s line breaks fall, as offsets into it from 0,
    /// where every position of it was read; `None` where one was not.
    fn breaks_over(&self, run: &Run) -> Option<Vec<u64>> {
        let below = self.ranges.partition_point(|&(first, _)| first <= run.i_start);
        let (_, reach) = *self.ranges.get(below.checked_sub(1)?)?;
        let breaks = self.breaks.range(run.i_start..run.reach());
        (reach >= run.reach()).then(|| breaks.map(|at| at - run.i_start).collect())
    }

    /// Keeps `run`'s positions as read, its line breaks at the offsets
    /// `breaks`, from 0.
    fn keep(&mut self, run: &Run, breaks: &[u64]) {
        // The ranges touching or overlapping the run's, which every range
        // before `lo` ends short of and every range from `hi` starts past.
        let lo = self.ranges.partition_point(|&(_, reach)| reach < run.i_start);
        let hi = self.ranges.partition_point(|&(first, _)| first <= run.reach());
        let joined = self.ranges[lo..hi]
            .iter()
            .fold((run.i_start, run.reach()), |(a, b), &(first, reach)| (a.min(first), b.max(reach)));
        self.ranges.splice(lo..hi, [joined]);
        self.breaks.extend(breaks.iter().map(|at| run.i_start + at));
    }
}

/// What the line rule's reads showed of the text between two changes
/// (`meet_at_a_line_edge`).
///
/// A fact the reads did not show is `false`, and a read that answered
/// anything but one item a position shows nothing at all.
#[derive(Clone, Copy, Default)]
struct Edge {
    /// The two meet at a line's edge.
    meets: bool,
    /// Every read answered one item a position.
    answered: bool,
    /// A line break stands in the text before its last byte.
    broken: bool,
    /// The text's last byte is a line break.
    ends_in_break: bool,
}

/// Returns whether two changes meet at a line's edge, with what the reads
/// showed of the text between them (`line_edges`).
///
/// The two are additions, or an addition and a lone removal, which stands
/// where its bytes were. `text` is the base text M lays between them, as
/// runs, and `before` the base position just before the first, none at the
/// document's start; `lines` reads where their line breaks fall through
/// `head`. The answer is decided by three facts: whether the first stands
/// at a line's start —
/// `before` a line break, or none — whether the text's last byte is a
/// break, and whether a break stands before that last byte; the two meet
/// where the first two facts differ and no such break stands, so the text
/// is read whole only where they meet. The first reads, asked together, are
/// `before`, the text's first `LINE_READ` positions and its last byte;
/// where those leave the answer open, the text is read on from them, each
/// read twice as long as the one before, until a break or the last byte.
/// So every position read is one the answer turns on, the same for every
/// reader, and a run of the text past them is never read (skep #1174). A
/// read answering anything but one item a position, or none, decides
/// nothing: they do not meet, and the reads show nothing.
fn meet_at_a_line_edge(
    head: SideIx,
    before: Option<Run>,
    text: &[Run],
    lines: &dyn Fn(SideIx, &Run) -> Option<LineRead>,
) -> Edge {
    // Every run asked, stopping at a read that answers none; whether they
    // hold a line break, or none where a run answers another count of items
    // than its width.
    let read = |runs: &[Run]| -> Option<bool> {
        let (mut fits, mut broken) = (true, false);
        for run in runs {
            match lines(head, run)? {
                LineRead::Breaks(at) => broken |= !at.is_empty(),
                LineRead::Unfit => fits = false,
            }
        }
        fits.then_some(broken)
    };
    let width = text.iter().map(|run| run.width).fold(0, u64::saturating_add);
    let Some(last) = width.checked_sub(1) else { return Edge::default() };
    let opening = last.min(LINE_READ);
    // The first reads, in the text's order, every one asked before any is
    // weighed; `before` and the last byte are one position each.
    let start = before.map(|run| read(&[run]));
    let opened = read(&runs_over(text, 0, opening));
    let ending = read(&runs_over(text, last, width));
    let start = match start {
        None => true,
        Some(Some(broken)) => broken,
        Some(None) => return Edge::default(),
    };
    let (Some(broken), Some(ends_in_break)) = (opened, ending) else {
        return Edge::default();
    };
    let shown = Edge { meets: false, answered: true, broken, ends_in_break };
    if shown.ends_in_break == start || shown.broken {
        return shown;
    }
    let (mut read_to, mut asked) = (opening, LINE_READ);
    while read_to < last {
        asked = asked.saturating_mul(2);
        let to = read_to.saturating_add(asked).min(last);
        match read(&runs_over(text, read_to, to)) {
            Some(false) => read_to = to,
            Some(true) => return Edge { broken: true, ..shown },
            None => return Edge::default(),
        }
    }
    Edge { meets: true, ..shown }
}

/// Returns the runs holding positions `from..to` of `text`, counted from 0.
fn runs_over(text: &[Run], from: u64, to: u64) -> Vec<Run> {
    let mut out = Vec::new();
    let mut at = 0u64;
    for run in text {
        let (lo, hi) = (from.max(at), to.min(at.saturating_add(run.width)));
        if lo < hi {
            out.push(Run::new(run.origin.clone(), run.i_start + (lo - at), hi - lo));
        }
        at = at.saturating_add(run.width);
    }
    out
}

/// A gap's groups by side, each its fragments in the side's order, the
/// moved words taken out: what `number_as` matches two walks' gaps by.
type Unmoved = Vec<(usize, Vec<usize>)>;

/// A numbered gap of the walk at the claims' defaults, as `number_as`
/// matches it: its kind, its spine gap and its groups besides the moved
/// words.
struct AtDefault {
    id: GapId,
    kind: Option<GapKind>,
    home: usize,
    unmoved: Unmoved,
}

/// Numbers a walk's gaps as the walk at the claims' defaults numbers its own.
///
/// The walk is at the order given, and `defaults` is that walk's gaps at the
/// claims' defaults (CM-I33); a walk under a chosen order is numbered by
/// `Numbering::number` instead. A chosen holder moves the words `moved`
/// names, and every other part of the two walks is the same. So a gap takes
/// the number of the first gap of `defaults` not yet taken with its kind,
/// its place in the spine and the same groups once the moved words are taken
/// out of both — a gap whose only runs are the moved words, which stand at
/// one spot in the one walk and at another in the other, matching none, save
/// a collision, which its region names — and every other gap is numbered
/// after the last of `defaults`, which were numbered from `first`, in M's
/// order. The value log's ids follow their gaps.
fn number_as(entries: &mut [Entry], applied: &mut [GapId], defaults: &[Entry], moved: &HashSet<usize>, first: u32) {
    let unmoved = |e: &Entry| -> Unmoved {
        let mut groups: Unmoved = e
            .groups
            .iter()
            .map(|g| (g.side, g.frags.iter().copied().filter(|f| !moved.contains(f)).collect::<Vec<usize>>()))
            .filter(|(_, frags)| !frags.is_empty())
            .collect();
        groups.sort();
        groups
    };
    let mut candidates: Vec<AtDefault> = defaults
        .iter()
        .filter_map(|e| Some(AtDefault { id: e.id?, kind: e.kind, home: e.home, unmoved: unmoved(e) }))
        .filter(|d| !d.unmoved.is_empty() || d.kind == Some(GapKind::Collision))
        .collect();
    let mut next = first + defaults.iter().filter(|e| e.id.is_some()).count() as u32;
    let mut renumbered: HashMap<GapId, GapId> = HashMap::new();
    for entry in entries.iter_mut() {
        let Some(id) = entry.id else { continue };
        let groups = unmoved(entry);
        let at = candidates.iter().position(|d| d.kind == entry.kind && d.home == entry.home && d.unmoved == groups);
        let found = at.map(|at| candidates.remove(at).id);
        let number = found.unwrap_or_else(|| {
            next += 1;
            GapId(next - 1)
        });
        entry.id = Some(number);
        renumbered.insert(id, number);
    }
    for id in applied.iter_mut() {
        if let Some(number) = renumbered.get(id) {
            *id = *number;
        }
    }
}

/// The numbers a walk at the order given gave its gaps, by what each holds.
///
/// It is what the walk under the order a merger chose at a spine's `moves`
/// gap numbers its own gaps by (skep #1155). Both walks stand on one set of
/// claimed sequences, so their stretches are the same and group alike under
/// any spine — a collision by the survivor left of it, every other gap by
/// its two anchors — and only the spine differs: a gap is known in both by
/// what it holds, never by its place, which the order moves.
struct Numbering {
    /// The gaps of the spine's places, numbered or not.
    entries: Vec<Entry>,
    /// The spine's `moves` gaps.
    moves: Vec<Moves>,
    /// The highest number given, the gaps with spots' included.
    last: u32,
}

impl Numbering {
    /// Returns the numbering of a walk's gaps, the claims' among them.
    fn of(entries: Vec<Entry>, moves: Vec<Moves>, claims: &[Claim]) -> Numbering {
        let ids = claims.iter().map(|c| c.id).chain(moves.iter().map(|m| m.id));
        let last = ids.chain(entries.iter().filter_map(|e| e.id)).max().map_or(0, |id| id.0);
        Numbering { entries, moves, last }
    }

    /// Numbers the gaps of a walk under a chosen order as these were.
    ///
    /// A `moves` gap takes the number of the one here between the same two
    /// sides, whichever won — so the gap the merger chose at keeps its
    /// number, its winner now the chosen side — else of the one here whose
    /// reorder lost as its own did, each number taken once. Every other gap
    /// takes the number of the first gap here not yet taken with its kind
    /// and the same groups, fragment for fragment — a collision no side
    /// filled, of the one over the same base positions. A gap matching none,
    /// one the chosen order makes, is numbered after the last here, the
    /// `moves` gaps first, then the others in M's order; a gap here matching
    /// none, one the chosen order removes, leaves its number unused. The
    /// value log's ids follow their gaps.
    fn number(&self, entries: &mut [Entry], moves: &mut [Moves], applied: &mut [GapId]) {
        let mut next = self.last;
        let pair = |m: &Moves| (m.winner.min(m.loser), m.winner.max(m.loser));
        let mut open: Vec<&Moves> = self.moves.iter().collect();
        let mut ids: Vec<Option<GapId>> = vec![None; moves.len()];
        for (id, gap) in ids.iter_mut().zip(moves.iter()) {
            if let Some(at) = open.iter().position(|m| pair(m) == pair(gap)) {
                *id = Some(open.remove(at).id);
            }
        }
        for (id, gap) in ids.iter_mut().zip(moves.iter()).filter(|(id, _)| id.is_none()) {
            if let Some(at) = open.iter().position(|m| m.loser == gap.loser) {
                *id = Some(open.remove(at).id);
            }
        }
        for (gap, id) in moves.iter_mut().zip(ids) {
            gap.id = id.unwrap_or_else(|| {
                next += 1;
                GapId(next)
            });
        }
        let mut open: Vec<(GapId, &Entry)> = self.entries.iter().filter_map(|e| Some((e.id?, e))).collect();
        let mut renumbered: HashMap<GapId, GapId> = HashMap::new();
        for entry in entries.iter_mut() {
            let Some(id) = entry.id else { continue };
            let at = open.iter().position(|(_, e)| {
                e.kind == entry.kind && e.groups == entry.groups && (!e.groups.is_empty() || e.key == entry.key)
            });
            let number = match at {
                Some(at) => open.remove(at).0,
                None => {
                    next += 1;
                    GapId(next)
                }
            };
            entry.id = Some(number);
            renumbered.insert(id, number);
        }
        for id in applied.iter_mut() {
            if let Some(number) = renumbered.get(id) {
                *id = *number;
            }
        }
    }
}

// ── step 7's resolutions, applied before the splice ───────────────────────

/// Applies the merger's resolutions to the gaps they name.
///
/// Each overrides the gap's default and sets who resolved it (merge record
/// §1.4 step 7). Returned are the ones not applied, in the order given:
/// naming no gap, a gap the rules settled, or a choice the gap cannot take.
/// At a gap with spots the choice of one holder was applied before the
/// walk (`Claimed::of`), and every other choice there is not applied. At a
/// spine's `moves` gap the order the spine took applies, settling it — the
/// other side's order chosen re-walks the spine (`moves_choice`) — and
/// every other choice there is not applied. A gap the rules settled takes
/// no choice, so a move there moves nothing. At any other gap, every
/// `After` and `Before` naming it moves it together: an address names a
/// position of each placement of a run the base places twice (skep #763),
/// so each names the places beside each surviving placement, and the gap
/// goes to the one every move names, else the one the last move names —
/// of those, the nearest its composed place, the earlier on a tie. A move
/// at a gap of one group places it by its anchor too. Every other choice
/// sets what is placed, `KeepBoth` the placement as composed; of two that
/// set the same, the later stands.
fn resolve(
    r: &Refinement,
    entries: &mut [Entry],
    moves: &mut [Moves],
    claims: &[Claim],
    resolutions: &[Resolution],
    in_base: &[Option<usize>],
    spine_pos: &[Option<usize>],
) -> Vec<Resolution> {
    let composed: Vec<(usize, Placement)> =
        entries.iter().map(|e| (e.home, e.placed.clone())).collect();
    for (entry, (home, _)) in entries.iter_mut().zip(&composed) {
        // A gap the rules settled takes no choice: a move there moves nothing.
        let Some(id) = entry.id.filter(|_| entry.resolved_by != Some(ResolvedBy::Rule)) else {
            continue;
        };
        let named: Vec<Vec<usize>> = resolutions
            .iter()
            .filter(|res| res.gap == id)
            .filter_map(|res| r.places(&res.choice, in_base, spine_pos))
            .filter(|places| !places.is_empty())
            .collect();
        let Some(last) = named.last() else { continue };
        let every: Vec<usize> =
            last.iter().copied().filter(|p| named.iter().all(|n| n.contains(p))).collect();
        let pool = if every.is_empty() { last } else { &every };
        entry.home = pool
            .iter()
            .copied()
            .min_by_key(|p| (p.abs_diff(*home), *p))
            .expect("a move names a place");
    }
    let mut ignored = Vec::new();
    for res in resolutions {
        if let Some(claim) = claims.iter().find(|c| c.id == res.gap) {
            if claim.holder_named(r, &res.choice).is_none() {
                ignored.push(res.clone());
            }
            continue;
        }
        if let Some(gap) = moves.iter_mut().find(|m| m.id == res.gap) {
            if matches!(&res.choice, Choice::Order(sides) if sides.as_slice() == [r.side_ix[gap.winner]])
            {
                gap.settled = true;
                gap.resolved_by = Some(res.by.clone());
            } else {
                ignored.push(res.clone());
            }
            continue;
        }
        let Some(i) = entries.iter().position(|e| e.id == Some(res.gap)) else {
            ignored.push(res.clone());
            continue;
        };
        let entry = &mut entries[i];
        if entry.resolved_by == Some(ResolvedBy::Rule) {
            ignored.push(res.clone());
            continue;
        }
        let sides: Vec<SideIx> = entry.groups.iter().map(|g| r.side_ix[g.side]).collect();
        let applied = match &res.choice {
            Choice::Order(order) => {
                let fits = !order.is_empty()
                    && order.iter().all(|s| sides.contains(s))
                    && order.iter().collect::<HashSet<_>>().len() == order.len();
                if fits {
                    entry.placed = Placement::Order(order.clone());
                }
                fits
            }
            Choice::After(_) | Choice::Before(_) => {
                let fits = r
                    .places(&res.choice, in_base, spine_pos)
                    .is_some_and(|places| !places.is_empty());
                if fits && entry.groups.len() == 1 {
                    entry.placed = if matches!(res.choice, Choice::Before(_)) {
                        Placement::Before
                    } else {
                        Placement::After
                    };
                }
                fits
            }
            Choice::KeepOnly(side) => {
                let fits = sides.contains(side);
                if fits {
                    entry.placed = Placement::Order(vec![*side]);
                }
                fits
            }
            Choice::KeepBoth => {
                let fits = sides.len() >= 2;
                if fits {
                    entry.placed = composed[i].1.clone();
                }
                fits
            }
            Choice::Omit => {
                entry.placed = Placement::Omitted;
                true
            }
        };
        if applied {
            entry.settled = true;
            entry.resolved_by = Some(res.by.clone());
        } else {
            ignored.push(res.clone());
        }
    }
    ignored
}

// ── step 6: the splice and the coalesce ───────────────────────────────────

/// Returns M, step 6 of the merge record's §1.4.
///
/// M is the spine with every gap's material spliced in — at one spine gap
/// the spots in the base's order of their anchors, at one spot the groups
/// as placed — then coalesced by I-adjacency with the daemon's own rule, so
/// `runs(M)` is what the member will hold. A fragment two groups list, a
/// word two sides placed alike (`Kept::of`), is laid once, where the first
/// group laid takes it.
fn splice(r: &Refinement, entries: &[Entry], spine: &[usize]) -> Vec<PlacedRun> {
    let mut by_home: Vec<Vec<usize>> = vec![Vec::new(); spine.len() + 1];
    for (i, e) in entries.iter().enumerate() {
        by_home[e.home.min(spine.len())].push(i);
    }
    for bucket in by_home.iter_mut() {
        bucket.sort_by_key(|&i| (entries[i].key, i));
    }
    let mut laid: Vec<(usize, Option<usize>)> = Vec::new();
    let mut once: HashSet<usize> = HashSet::new();
    for (g, bucket) in by_home.iter().enumerate() {
        for &i in bucket {
            let entry = &entries[i];
            let mut lay = |group: &Group| {
                let fresh = group.frags.iter().filter(|&&f| once.insert(f));
                laid.extend(fresh.map(|&f| (f, Some(group.side))));
            };
            match &entry.placed {
                Placement::Omitted => {}
                Placement::Order(sides) => {
                    for side in sides {
                        if let Some(group) = entry.groups.iter().find(|g| r.side_ix[g.side] == *side) {
                            lay(group);
                        }
                    }
                }
                Placement::After | Placement::Before => entry.groups.iter().for_each(&mut lay),
            }
        }
        if g < spine.len() {
            laid.push((r.base[spine[g]], None));
        }
    }
    let mut out: Vec<PlacedRun> = Vec::new();
    for (f, side) in laid {
        let frag = r.frags[f];
        if let Some(last) = out.last_mut() {
            if last.run.origin == r.origins[frag.origin] && last.run.reach() == frag.start {
                if let Some(width) = last.run.width.checked_add(frag.width) {
                    last.run.width = width;
                    continue;
                }
            }
        }
        out.push(PlacedRun {
            run: Run::new(r.origins[frag.origin].clone(), frag.start, frag.width),
            side: side.map(|s| r.side_ix[s]),
        });
    }
    out
}

// ── step 7: the report ────────────────────────────────────────────────────

/// Returns step 7's report (merge record §1.4).
///
/// It lists every gap with its kind, its anchors as M holds them, the runs
/// contested with their sides, whether it is settled and by whom — by
/// number, the `moves` gaps first, those with spots naming each holder's,
/// then the others in the order of their default places in M, a `line` gap
/// naming each lone removal that meets its words by that removal's own
/// anchors, wherever a move puts the gap.
fn report(r: &Refinement, entries: &[Entry], moves: &[Moves], claims: &[Claim], spine: &[usize]) -> Vec<Gap> {
    let mut out: Vec<Gap> = claims
        .iter()
        .map(|c| Gap {
            id: c.id,
            kind: GapKind::Moves,
            after: None,
            before: None,
            runs: c
                .holders
                .iter()
                .flat_map(|h| r.coalesce(h.frags.iter().copied()).into_iter().map(move |run| (r.side_ix[h.side], run)))
                .collect(),
            placed: Placement::Order(vec![r.side_ix[c.holders[c.chosen].side]]),
            settled: c.settled,
            resolved_by: c.resolved_by.clone(),
            spots: c
                .holders
                .iter()
                .map(|h| Spot {
                    side: r.side_ix[h.side],
                    after: h.spot.0.and_then(|bi| r.last_address(r.base[bi])),
                    before: h.spot.1.and_then(|bi| r.first_address(r.base[bi])),
                })
                .collect(),
            removed: Vec::new(),
        })
        .collect();
    out.extend(moves.iter().map(|m| Gap {
        id: m.id,
        kind: GapKind::Moves,
        after: None,
        before: None,
        runs: m.runs.clone(),
        placed: Placement::Order(vec![r.side_ix[m.winner]]),
        settled: m.settled,
        resolved_by: m.resolved_by.clone(),
        spots: Vec::new(),
        removed: Vec::new(),
    }));
    for entry in entries {
        let (Some(id), Some(kind)) = (entry.id, entry.kind) else { continue };
        let (after, before) = anchors_at(r, spine, entry.home);
        out.push(Gap {
            id,
            kind,
            after,
            before,
            runs: entry
                .groups
                .iter()
                .flat_map(|g| r.coalesce(g.frags.iter().copied()).into_iter().map(move |run| (r.side_ix[g.side], run)))
                .collect(),
            placed: entry.placed.clone(),
            settled: entry.settled,
            resolved_by: entry.resolved_by.clone(),
            spots: Vec::new(),
            removed: entry
                .removed
                .iter()
                .map(|lone| {
                    let (after, before) = anchors_at(r, spine, lone.home);
                    Removed { side: r.side_ix[lone.side], after, before }
                })
                .collect(),
        });
    }
    out.sort_by_key(|g| g.id);
    out
}

/// Returns the anchors M holds either side of the spine gap `home`.
///
/// They are the address of the last position of the surviving base
/// material just before it and of the first just after it, `None` at M's
/// start and at its end: the anchors a gap there is reported with
/// ([`Gap::after`], [`Gap::before`]), a lone removal there is named with
/// ([`Removed`]), and a line read's pair is told (`LinePair`).
fn anchors_at(r: &Refinement, spine: &[usize], home: usize) -> (Option<Address>, Option<Address>) {
    let home = home.min(spine.len());
    (
        home.checked_sub(1).and_then(|p| r.last_address(r.base[spine[p]])),
        spine.get(home).and_then(|&bi| r.first_address(r.base[bi])),
    )
}

// ── the base of two members ───────────────────────────────────────────────

/// Returns the base of two members of one chain by their addresses (merge
/// record §1.2).
///
/// It is their nearest common ancestor along the chains their addresses
/// spell: a trunk member `D.k` under `D.k−1`, a daughter `X.m` under `X`,
/// `D.1` under nothing. So for `D.k+1` against `D.k.m` it is `D.k`; for
/// `D.k.1` against `D.k.2`, `D.k`; for `D.k.1.1` against the head, `D.k`;
/// for `D.k.1` against `D.j.1` with `j < k`, `D.j`. `None` for two members
/// of different documents, and for an address that is no member: a bare
/// document, a draft, an element.
///
/// On the trunk the address is the record: a trunk member `D.k` was minted
/// against `D.k−1`, so for two trunk members this is the base. Below the
/// trunk an address need not name the member a daughter was published
/// against — a draft begun from `D` before its first version and published
/// once `D.1` stood lands as `D.1.k`, recorded against `D` — and the merge's
/// reads walk the bases the board recorded instead (the `reads` module),
/// never this.
pub fn base_of(a: &Address, b: &Address) -> Option<Address> {
    let (head_a, versions_a) = member_parts(a)?;
    let (head_b, versions_b) = member_parts(b)?;
    if head_a != head_b {
        return None;
    }
    let chain_b = ancestry(versions_b);
    let shared = ancestry(versions_a).into_iter().find(|v| chain_b.contains(v))?;
    validate(Tumbler::new(head_a.into_iter().chain(shared)).ok()?).ok()
}

/// Splits a member at its document number into head and version components.
///
/// The head runs through the document number, the version components after
/// it; `None` unless a document address with at least one version
/// component.
fn member_parts(a: &Address) -> Option<(Vec<Nat>, Vec<Nat>)> {
    if a.level() != Level::Document {
        return None;
    }
    let field = a.document_field()?;
    if field.len() < 2 {
        return None;
    }
    let comps: Vec<Nat> = a.tumbler().iter().cloned().collect();
    let head = comps.len() - field.len() + 1;
    Some((comps[..head].to_vec(), comps[head..].to_vec()))
}

/// Returns a member's version components and each ancestor's, nearest first.
fn ancestry(mut versions: Vec<Nat>) -> Vec<Vec<Nat>> {
    let one = Nat::from(1u32);
    let mut out = Vec::new();
    loop {
        out.push(versions.clone());
        if versions.len() >= 2 {
            versions.pop();
        } else if versions[0] > one {
            versions[0] = &versions[0] - &one;
        } else {
            return out;
        }
    }
}

// ── the in-place script ───────────────────────────────────────────────────

/// Returns the edit script from a draft arranged as `current` to `target`.
///
/// The script turns the draft into `target` by identity, edit by edit. The
/// longest part of `current` that stands in `target`'s order is kept; every
/// other stretch of `current` is one `delete`, the deletes listed
/// last-to-first so each position holds when the one before it has been
/// applied; then every stretch of `target` not kept is one `reinstate`,
/// first-to-last, at the position it takes once the ones before it are
/// applied. A run that moved is deleted before it is placed again. It is a
/// PREVIEW of the change, a pure function the suite's `apply` reads back:
/// the draft landing sends none of its ops — it sets the draft's whole
/// arrangement in one `set_arrangement` (merge record §1.5 as the landing
/// lane ruled it), so no edit is one commit on the draft.
///
/// **Precondition.** As [`compose_runs`]'s: no run of width 0. A draft or a
/// target that places one run twice is admitted, each placement its own
/// position (skep #763).
///
/// # Panics
///
/// Panics in a debug build on a run of width 0, as [`compose_runs`] does.
pub fn script(current: &[Run], target: &[Run]) -> Vec<InPlaceOp> {
    let r = Refinement::of(current, &[(SideIx(0), target.to_vec())]);
    let (cur, tgt) = (&r.base, &r.sides[0]);
    let in_target = r.presence(tgt);
    let keys: Vec<Option<usize>> = cur.iter().map(|&f| in_target[f]).collect();
    let kept: HashSet<usize> = longest_increasing(&keys).into_iter().map(|i| cur[i]).collect();
    let width = |f: usize| r.frags[f].width;
    let mut ops = Vec::new();
    let (mut p, mut i) = (1u64, 0);
    while i < cur.len() {
        if kept.contains(&cur[i]) {
            p = p.saturating_add(width(cur[i]));
            i += 1;
            continue;
        }
        let (start, mut gone) = (p, 0u64);
        while i < cur.len() && !kept.contains(&cur[i]) {
            gone = gone.saturating_add(width(cur[i]));
            p = p.saturating_add(width(cur[i]));
            i += 1;
        }
        ops.push(InPlaceOp::Delete { p: start, width: gone });
    }
    ops.reverse();
    let (mut at, mut j) = (1u64, 0);
    while j < tgt.len() {
        if kept.contains(&tgt[j]) {
            at = at.saturating_add(width(tgt[j]));
            j += 1;
            continue;
        }
        let (start, mut frags) = (at, Vec::new());
        while j < tgt.len() && !kept.contains(&tgt[j]) {
            frags.push(tgt[j]);
            at = at.saturating_add(width(tgt[j]));
            j += 1;
        }
        ops.push(InPlaceOp::Reinstate { at: start, runs: r.coalesce(frags) });
    }
    ops
}
