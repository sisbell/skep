//! The pure core of the merge — the merge record's §7 `compose_runs`.
//!
//! A base and its sides come in as run lists, as `image` delivers them; the
//! merged list, the gap report and the run counts go out; every value read
//! is made through a closure the caller supplies, so a test needs no board.
//! The record's §1.4 states the composition in seven steps, and the seven
//! private functions `removals`, `spine_of`, `additions`, `placement`,
//! `gaps`, `splice` and `report` are those steps in that order, with
//! `collision_regions` feeding `gaps` and `resolve` applying step 7's
//! resolutions ahead of the splice. §2's rules
//! decide each gap's kind and its default; §5's value rule reads bytes at a
//! shared gap (the dedup) and, switched on, before the walk (the retype).
//! Beside the core stand the two other pure functions §7 names: [`base_of`],
//! the nearest common ancestor of two members by §1.2's address forms, and
//! [`script`], the in-place edit script §1.5's draft landing applies.
//!
//! The vocabulary is the record's. A run is `(origin, i_start, width)`. The
//! base is the member every side descends from. The spine is the surviving
//! base material in the order M keeps it. A side's run is fresh when its
//! positions are not the base's. A stretch is a side's maximal run of fresh
//! material at one place, with its two anchors: the base positions
//! immediately before and after it in that side's own sequence, the ends of
//! the document standing in where there is none. A spot is the pair of
//! anchors a stretch sits between. A gap is a place in M between two
//! surviving base positions, or at either end, where some side placed
//! material or where two sides removed the same material — save a `moves`
//! gap, which is no place but a side's reorder the spine did not take.
//!
//! The lists are never expanded to positions. The walk is made over the
//! fragments of the lists' common refinement — every run cut at every
//! other run's edges, so a fragment lies wholly inside or wholly outside each
//! list — and a fragment stands for its positions in every rule below. The
//! cost is in runs, not in width.
//!
//! Nothing here dials, reads or writes. The one crate this file links is
//! `skep-address`, for the address form the anchors are reported in.

use std::collections::HashSet;

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
}

/// The index of a side among the sides given to [`compose_runs`].
///
/// The record's `side` in a gap's runs: `0` the first side listed, which is
/// the head in every shape the record draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SideIx(pub u8);

/// A gap's number in the report, counted from 1, the `moves` gaps first.
///
/// The other gaps are numbered in the order of their default places in M;
/// a resolution that moves one keeps its number.
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
    /// At a `moves` gap, the one side whose order the spine takes.
    Order(Vec<SideIx>),
    /// The gap's material placed after this surviving base position.
    ///
    /// It lands at the first place after the position where some list's run
    /// starts or ends — right after it where one does.
    After(Address),
    /// The gap's material placed before this surviving base position.
    ///
    /// It lands at the last place at or before the position where some
    /// list's run starts or ends — right before it where one does.
    Before(Address),
    /// Only this side's material placed; the other sides' is left out.
    KeepOnly(SideIx),
    /// Every side's material placed in the default order, confirmed.
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

/// The six kinds of gap (merge record §2, §4).
///
/// The rules settle one of them, `Anchor`; the other five are the merger's,
/// save an `order` gap the value rule's dedup settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GapKind {
    /// Two or more sides added at one spot: unsettled (R1).
    ///
    /// The default is the commit order.
    Order,
    /// An addition beside a removal, one of its anchors surviving (R2).
    ///
    /// The adding side's own removal overlaps nothing another side removed:
    /// settled, placed beside the survivor.
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
    /// With no `spine_hint` it arises where the sides' reorders do not
    /// compose, as where two sides reordered overlapping material, and the
    /// default is the earliest reordering side's order, each later side
    /// whose order differs from it a `moves` gap, its reorder not applied.
    /// Under a `spine_hint` the default is the hinted side's order, and each
    /// other side whose reorder differs from it is a `moves` gap.
    Moves,
}

/// How a gap's material was laid in M (merge record §4, `placed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    /// The sides whose material was placed, in that order.
    ///
    /// At a `moves` gap, the one side whose order the spine took.
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
    /// The other gaps are numbered in the order of their default places in M.
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
    /// At a `moves` gap, the material each side moved.
    pub runs: Vec<(SideIx, Run)>,
    /// How the runs were laid in M.
    pub placed: Placement,
    /// Whether the placement asks no choice.
    pub settled: bool,
    /// Who settled it: the rule, a merger, or no one yet.
    pub resolved_by: Option<ResolvedBy>,
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
}

/// What [`compose_runs`] returns.
///
/// It holds M, the gap report, the counts, the value log, and the
/// resolutions it could not apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Composed {
    /// The merged list, coalesced by I-adjacency as the member will hold it.
    pub runs: Vec<PlacedRun>,
    /// Every gap by number: the `moves` gaps, then the others.
    ///
    /// The others come in the order of their default places in M. A
    /// one-sided addition between two surviving anchors that stand
    /// together asks nothing and is not listed.
    pub gaps: Vec<Gap>,
    /// The run counts.
    pub counts: RunCounts,
    /// The value rule's log.
    pub values: ValueLog,
    /// The resolutions not applied.
    ///
    /// Each named no gap of this report, a gap the rules had settled, or a
    /// choice the gap cannot take; each stands here untouched, so the caller
    /// sees what was not applied.
    pub ignored: Vec<Resolution>,
}

/// One in-place edit of a draft (merge record §1.5, the draft landing).
///
/// The edits are the wire's `delete` and `reinstate`, positions in the
/// draft's content ordinals, counted from 1.
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
/// `base` is the base member's run list and each side its own, every list
/// as `image` delivers it, the sides in commit order. `spine_hint` names
/// the side whose order the spine takes where the sides disagree about the
/// order of the surviving base material; `None` computes it — the base's
/// order, or the one side's that reordered, or the reorders of two or more
/// sides composed where they touch different material, else the earliest
/// reordering side's, with a `moves` gap for each later side whose order
/// differs from it. `values` answers a side's run with its items, which
/// the value rule compares; a run asked may be a part of a run the side
/// holds; `None` leaves the rule unfired there. The composition writes
/// nothing and dials nothing (merge record §1.4, §7).
///
/// The walk, in the record's seven steps: the removals, the spine, each
/// side's additions with their anchors, the placement of each by its
/// kind, the gaps with the order rule and the value rule, the splice and
/// the coalesce, the report with the resolutions applied — applied ahead
/// of the splice, so M holds them. With no
/// `spine_hint`, a `moves` gap resolved by `Choice::Order` of one side
/// re-walks the whole composition under that side's order, so the report's
/// other gaps may be numbered afresh: a caller resolves a `moves` gap first
/// and reads the report again. Under a `spine_hint` that resolution is not
/// applied and stands in `ignored`.
///
/// **Precondition.** Every run has a width above 0, and no position stands
/// twice in one list. A release build skips a run of width 0 and the later
/// of two placements of one position, and composes the rest.
///
/// # Panics
///
/// Panics in a debug build on a run of width 0 and on a position placed
/// twice in one list.
pub fn compose_runs(
    base: &[Run],
    sides: &[(SideIx, Vec<Run>)],
    spine_hint: Option<SideIx>,
    options: &Options,
    values: &dyn Fn(SideIx, &Run) -> Option<Vec<Item>>,
) -> Composed {
    let r = Refinement::of(base, sides);
    let mut seqs = r.sides.clone();
    if options.retype {
        undo_retypes(&r, &mut seqs, values);
    }
    claim_identities(&r, &mut seqs);
    let hint = spine_hint.and_then(|h| r.side_ix.iter().position(|s| *s == h));
    let first = walk(&r, &seqs, hint, None, options, values);
    if hint.is_none() {
        if let Some((side, by)) = moves_choice(&r, &first, &options.resolutions) {
            return walk(&r, &seqs, Some(side), Some(by), options, values);
        }
    }
    first
}

/// Runs the seven steps over the normalized sequences under one spine choice.
fn walk(
    r: &Refinement,
    seqs: &[Vec<usize>],
    hint: Option<usize>,
    forced: Option<ResolvedBy>,
    options: &Options,
    values: &dyn Fn(SideIx, &Run) -> Option<Vec<Item>>,
) -> Composed {
    let in_base = r.in_base();
    let in_side: Vec<Vec<Option<usize>>> = seqs.iter().map(|seq| r.presence(seq)).collect();
    let (removed_by, removed) = removals(r, &in_side);
    let (spine, spine_pos, mut moves) = spine_of(r, seqs, &in_base, &removed, hint, forced);
    let stretches = additions(seqs, &in_base);
    let placed = placement(r, &stretches, &removed_by, &removed, &spine, &spine_pos);
    let regions = collision_regions(r, &removed_by, &removed, &spine_pos);
    let (mut entries, applied) = gaps(r, &stretches, &placed, &regions, moves.len(), options, values);
    let ignored = resolve(r, &mut entries, &mut moves, &options.resolutions, &in_base, &spine_pos);
    let runs = splice(r, &entries, &spine);
    let gaps = report(r, &entries, &moves, &spine);
    let counts = RunCounts {
        a: r.side_runs.first().copied().unwrap_or(0),
        b: r.side_runs.iter().skip(1).sum(),
        m: runs.len(),
    };
    Composed {
        runs,
        gaps,
        counts,
        values: ValueLog { dedup: options.dedup, retype: options.retype, applied },
        ignored,
    }
}

/// Returns the resolution of a `moves` gap, if one is given.
///
/// It is the side whose order the merger chose, and who chose.
fn moves_choice(r: &Refinement, composed: &Composed, resolutions: &[Resolution]) -> Option<(usize, ResolvedBy)> {
    for res in resolutions {
        let Some(gap) = composed.gaps.iter().find(|g| g.id == res.gap && g.kind == GapKind::Moves) else {
            continue;
        };
        if let Choice::Order(sides) = &res.choice {
            if let [side] = sides.as_slice() {
                if gap.runs.iter().any(|(s, _)| s == side) {
                    if let Some(ix) = r.side_ix.iter().position(|s| s == side) {
                        return Some((ix, res.by.clone()));
                    }
                }
            }
        }
    }
    None
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
    /// sequence of fragment ids.
    ///
    /// # Panics
    ///
    /// Panics in a debug build on a run of width 0 and on a position placed
    /// twice in one list.
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
        let sequence = |runs: &[Run]| -> Vec<usize> {
            let mut seen = HashSet::new();
            let mut out = Vec::new();
            for run in runs.iter().filter(|run| run.width > 0) {
                let Some(o) = origins.iter().position(|x| *x == run.origin) else { continue };
                let (Ok(i), Ok(j)) = (points[o].binary_search(&run.i_start), points[o].binary_search(&run.reach()))
                else {
                    continue;
                };
                for id in first[o] + i..first[o] + j {
                    let fresh = seen.insert(id);
                    debug_assert!(fresh, "a position placed twice in one list: {run:?}");
                    if fresh {
                        out.push(id);
                    }
                }
            }
            out
        };
        Refinement {
            base: sequence(base),
            sides: sides.iter().map(|(_, runs)| sequence(runs)).collect(),
            side_ix: sides.iter().map(|(ix, _)| *ix).collect(),
            side_runs: sides.iter().map(|(_, runs)| runs.len()).collect(),
            origins,
            frags,
        }
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

    /// Returns the base fragment holding `addr`, by its index in the base.
    fn locate(&self, addr: &Address, in_base: &[Option<usize>]) -> Option<usize> {
        let doc = skep_address::document_of(addr)?;
        let o = self.origins.iter().position(|x| *x == doc)?;
        let field = addr.element_field()?;
        if field.len() != 2 || field[0] != content_subspace() {
            return None;
        }
        let n = u64::try_from(&field[1]).ok()?;
        let f = self.frags.iter().position(|fr| fr.origin == o && fr.start <= n && n - fr.start < fr.width)?;
        in_base[f]
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
/// never read.
fn undo_retypes(r: &Refinement, seqs: &mut [Vec<usize>], values: &dyn Fn(SideIx, &Run) -> Option<Vec<Item>>) {
    let in_base = r.in_base();
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
                replacements.push((st.at, st.frags.len(), (lo..hi).map(|bi| r.base[bi]).collect()));
            }
        }
        for (at, len, base_frags) in replacements.into_iter().rev() {
            seqs[s].splice(at..at + len, base_frags);
        }
    }
}

/// Places a fresh identity several sides hold once.
///
/// It is placed where the earliest side holds it: an identical addition is
/// not a difference (merge record §2, the one rule).
fn claim_identities(r: &Refinement, seqs: &mut [Vec<usize>]) {
    let in_base = r.in_base();
    let mut claimed = HashSet::new();
    for seq in seqs.iter_mut() {
        seq.retain(|&f| in_base[f].is_some() || claimed.insert(f));
    }
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
    runs: Vec<(SideIx, Run)>,
    settled: bool,
    resolved_by: Option<ResolvedBy>,
}

/// Returns step 2's spine and its `moves` gaps (merge record §1.4).
///
/// The spine is the surviving base material in the order M keeps it — the
/// base's, unless a side reordered it: then that side's; the reorders of
/// two or more sides composed where they touch different material, else the
/// earliest reordering side's order with a `moves` gap for each later side
/// whose order differs from it (§2 R4 iii). `hint`
/// names the side whose order wins outright; `forced` marks every `moves`
/// gap settled by the merger who named it.
fn spine_of(
    r: &Refinement,
    seqs: &[Vec<usize>],
    in_base: &[Option<usize>],
    removed: &[bool],
    hint: Option<usize>,
    forced: Option<ResolvedBy>,
) -> (Vec<usize>, Vec<Option<usize>>, Vec<Moves>) {
    let surv: Vec<usize> = (0..r.base.len()).filter(|&bi| !removed[bi]).collect();
    let orders: Vec<Vec<usize>> = seqs
        .iter()
        .map(|seq| seq.iter().filter_map(|&f| in_base[f]).filter(|&bi| !removed[bi]).collect())
        .collect();
    let reordered: Vec<usize> = (0..seqs.len()).filter(|&s| orders[s] != surv).collect();
    let (spine, winner) = match hint {
        Some(h) => (orders[h].clone(), Some(h)),
        None => match reordered.as_slice() {
            [] => (surv.clone(), None),
            [one] => (orders[*one].clone(), Some(*one)),
            many => {
                let given: Vec<(usize, &[usize])> = many.iter().map(|&s| (s, orders[s].as_slice())).collect();
                match compose_reorders(&surv, &given) {
                    Some(spine) => (spine, None),
                    None => (orders[many[0]].clone(), Some(many[0])),
                }
            }
        },
    };
    let mut spine_pos = vec![None; r.base.len()];
    for (p, &bi) in spine.iter().enumerate() {
        spine_pos[bi] = Some(p);
    }
    let mut moves = Vec::new();
    if let Some(winner) = winner {
        for &loser in reordered.iter().filter(|&&s| s != winner && orders[s] != spine) {
            let mut runs = moved_runs(r, &surv, winner, &orders[winner]);
            runs.extend(moved_runs(r, &surv, loser, &orders[loser]));
            moves.push(Moves {
                id: GapId(moves.len() as u32 + 1),
                winner,
                runs,
                settled: forced.is_some(),
                resolved_by: forced.clone(),
            });
        }
    }
    (spine, spine_pos, moves)
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
    let mut spine = Vec::with_capacity(surv.len());
    for s in 0..=kept.len() {
        let mut here: Vec<usize> = moved.iter().copied().filter(|&bi| slot[bi] == s).collect();
        while !here.is_empty() {
            let first = here.iter().position(|&x| here.iter().all(|&y| x == y || before(x, y)))?;
            spine.push(here.remove(first));
        }
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
/// ends.
struct Stretch {
    side: usize,
    at: usize,
    frags: Vec<usize>,
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
            out.push(Stretch { side, at, frags, x, y });
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
/// one-sided.
struct Placed {
    kind: Option<GapKind>,
    home: usize,
    before: bool,
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
            let lo = st.x.map_or(0, |x| x + 1);
            let hi = st.y.unwrap_or(r.base.len());
            let collision = (lo..hi).any(|bi| {
                removed_by[st.side][bi] && (0..removed_by.len()).any(|t| t != st.side && removed_by[t][bi])
            });
            if collision {
                return Placed { kind: Some(GapKind::Collision), home: left(st.x), before: false };
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
                    Placed { kind, home: after(st.x), before: false }
                }
                (true, false) => Placed { kind: Some(GapKind::Anchor), home: after(st.x), before: false },
                (false, true) => {
                    // The right anchor survives: before it in the spine —
                    // and where it is `⊤`, the end of the document, before
                    // the spine's end.
                    Placed { kind: Some(GapKind::Anchor), home: st.y.and_then(|y| spine_pos[y]).unwrap_or(spine.len()), before: true }
                }
                (false, false) => Placed { kind: Some(GapKind::Corner), home: left(st.x), before: false },
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

// ── step 5: the gaps ──────────────────────────────────────────────────────

/// One side's material at a gap.
///
/// It is its stretches' fragments, in the side's own order.
struct Group {
    side: usize,
    frags: Vec<usize>,
}

/// A gap as the walk holds it before the report.
///
/// It holds its number and its kind, the spine gap it lands in, the spot it
/// sorts by there, the groups by side in the default order, how they are
/// placed, and whether and by whom it is settled.
struct Entry {
    id: Option<GapId>,
    kind: Option<GapKind>,
    home: usize,
    key: (i64, i64),
    groups: Vec<Group>,
    placed: Placement,
    settled: bool,
    resolved_by: Option<ResolvedBy>,
}

/// Returns step 5's gaps (merge record §1.4, §2 R1, §5).
///
/// The stretches that landed at one spot are grouped by side, each group in
/// its side's own order, the groups in the order rule's order — a spot two
/// sides added at is an `order` gap, unsettled, where it would otherwise be
/// no gap or an `anchor`; the collisions at one spine gap are one
/// `collision` gap, a region no side filled listed too; then the dedup
/// where it is on. The gaps are numbered here, in M's order after the
/// `moves` gaps, so the dedup can name the gap it fired at.
fn gaps(
    r: &Refinement,
    stretches: &[Stretch],
    placed: &[Placed],
    regions: &[Region],
    moves: usize,
    options: &Options,
    values: &dyn Fn(SideIx, &Run) -> Option<Vec<Item>>,
) -> (Vec<Entry>, Vec<GapId>) {
    let mut entries: Vec<Entry> = Vec::new();
    for (st, p) in stretches.iter().zip(placed) {
        let key = (st.x.map_or(-1, |x| x as i64), st.y.map_or(i64::MAX, |y| y as i64));
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
                });
                entries.len() - 1
            }
        };
        let entry = &mut entries[at];
        entry.key = entry.key.min(key);
        match entry.groups.iter_mut().find(|g| g.side == st.side) {
            Some(group) => group.frags.extend(st.frags.iter().copied()),
            None => entry.groups.push(Group { side: st.side, frags: st.frags.clone() }),
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
            });
        }
    }
    // The order rule: a spot two sides added at is an `order` gap where it
    // would otherwise be no gap or an `anchor`, the groups by the commit of
    // their first run — inside one chain the address order, a side whose
    // material is not the base's chain last.
    let chain: HashSet<usize> = r.base.iter().map(|&f| r.frags[f].origin).collect();
    for entry in entries.iter_mut() {
        entry.groups.sort_by_key(|g| {
            let first = r.frags[g.frags[0]];
            (!chain.contains(&first.origin), r.origins[first.origin].clone(), first.start)
        });
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
    entries.sort_by(|a, b| (a.home, a.key).cmp(&(b.home, b.key)));
    let mut next = moves as u32 + 1;
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

// ── step 7's resolutions, applied before the splice ───────────────────────

/// Applies the merger's resolutions to the gaps they name.
///
/// Each overrides the gap's default and sets who resolved it (merge record
/// §1.4 step 7). Returned are the ones not applied: naming no gap, a gap the
/// rules settled, or a choice the gap cannot take. At a `moves` gap only the
/// order the spine took applies. At any other gap, two naming it apply in
/// turn and combine: an `After` or a `Before` moves the gap, and at a gap of
/// one group places it by that anchor too; every other choice sets what is
/// placed; where two set the same, the later stands.
fn resolve(
    r: &Refinement,
    entries: &mut [Entry],
    moves: &mut [Moves],
    resolutions: &[Resolution],
    in_base: &[Option<usize>],
    spine_pos: &[Option<usize>],
) -> Vec<Resolution> {
    let mut ignored = Vec::new();
    for res in resolutions {
        if let Some(gap) = moves.iter_mut().find(|m| m.id == res.gap) {
            let chosen = matches!(&res.choice, Choice::Order(sides) if sides.as_slice() == [r.side_ix[gap.winner]]);
            if gap.settled && chosen {
                gap.resolved_by = Some(res.by.clone());
            } else {
                ignored.push(res.clone());
            }
            continue;
        }
        let Some(entry) = entries.iter_mut().find(|e| e.id == Some(res.gap)) else {
            ignored.push(res.clone());
            continue;
        };
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
            Choice::After(addr) | Choice::Before(addr) => {
                let before = matches!(res.choice, Choice::Before(_));
                match r.locate(addr, in_base).and_then(|bi| spine_pos[bi]) {
                    Some(p) => {
                        entry.home = if before { p } else { p + 1 };
                        if entry.groups.len() == 1 {
                            entry.placed = if before { Placement::Before } else { Placement::After };
                        }
                        true
                    }
                    None => false,
                }
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
                    entry.placed = Placement::Order(sides.clone());
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
/// `runs(M)` is what the member will hold.
fn splice(r: &Refinement, entries: &[Entry], spine: &[usize]) -> Vec<PlacedRun> {
    let mut by_home: Vec<Vec<usize>> = vec![Vec::new(); spine.len() + 1];
    for (i, e) in entries.iter().enumerate() {
        by_home[e.home.min(spine.len())].push(i);
    }
    for bucket in by_home.iter_mut() {
        bucket.sort_by_key(|&i| (entries[i].key, i));
    }
    let mut laid: Vec<(usize, Option<usize>)> = Vec::new();
    for (g, bucket) in by_home.iter().enumerate() {
        for &i in bucket {
            let entry = &entries[i];
            let mut lay = |group: &Group| laid.extend(group.frags.iter().map(|&f| (f, Some(group.side))));
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
/// number, the `moves` gaps first, then the others in the order of their
/// default places in M.
fn report(r: &Refinement, entries: &[Entry], moves: &[Moves], spine: &[usize]) -> Vec<Gap> {
    let mut out: Vec<Gap> = moves
        .iter()
        .map(|m| Gap {
            id: m.id,
            kind: GapKind::Moves,
            after: None,
            before: None,
            runs: m.runs.clone(),
            placed: Placement::Order(vec![r.side_ix[m.winner]]),
            settled: m.settled,
            resolved_by: m.resolved_by.clone(),
        })
        .collect();
    for entry in entries {
        let (Some(id), Some(kind)) = (entry.id, entry.kind) else { continue };
        let home = entry.home.min(spine.len());
        out.push(Gap {
            id,
            kind,
            after: home.checked_sub(1).and_then(|p| r.last_address(r.base[spine[p]])),
            before: spine.get(home).and_then(|&bi| r.first_address(r.base[bi])),
            runs: entry
                .groups
                .iter()
                .flat_map(|g| r.coalesce(g.frags.iter().copied()).into_iter().map(move |run| (r.side_ix[g.side], run)))
                .collect(),
            placed: entry.placed.clone(),
            settled: entry.settled,
            resolved_by: entry.resolved_by.clone(),
        });
    }
    out.sort_by_key(|g| g.id);
    out
}

// ── the base of two members ───────────────────────────────────────────────

/// Returns the base of two members of one chain (merge record §1.2).
///
/// It is their nearest common ancestor along the chains of members each was
/// minted against. A trunk member `D.k` was minted against `D.k−1`, a
/// daughter `X.m` against `X`; `D.1` against nothing. So for `D.k+1` against
/// `D.k.m` the base is `D.k`; for `D.k.1` against `D.k.2`, `D.k`; for
/// `D.k.1.1` against the head, `D.k`; for `D.k.1` against `D.j.1` with
/// `j < k`, `D.j`. `None` for two members of different documents, and for
/// an address that is no member: a bare document, a draft, an element.
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
/// The script turns the draft into `target` by identity (merge record §1.5,
/// the draft landing). The longest part of `current` that stands in
/// `target`'s order is kept; every other stretch of `current` is one
/// `delete`, the deletes listed last-to-first so each position holds when
/// the one before it has been applied; then every stretch of `target` not
/// kept is one `reinstate`, first-to-last, at the position it takes once
/// the ones before it are applied. A run that moved is deleted before it is
/// placed again, so a draft never holds it twice. Each op is one commit on
/// the draft.
///
/// **Precondition.** As [`compose_runs`]'s: no run of width 0, no position
/// twice in one list.
///
/// # Panics
///
/// Panics in a debug build on a run of width 0 and on a position placed
/// twice in one list, as [`compose_runs`] does.
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
