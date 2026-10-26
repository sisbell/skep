//! The spanfilade (§6): the per-slot coverage index `stab` answers from,
//! grouped by home, with a directory of the homes a query could meet.
//!
//! [`Spanfilade`] holds one [`SlotIndex`] per slot position a stored link has,
//! and the hint fold files every span of every slot there under the link that
//! holds it and the link's home. A stab asks the index which links' slot
//! overlaps a query instead of testing every link in the store, and it asks
//! home by home: the directory names the homes some filing of which could
//! meet the query, without visiting a link, and the stab of one home is the
//! stab of today's two halves within that home's keys alone. So a read costs
//! the directory entries it steps, one lift per candidate home, and the hits
//! of the homes it stabs; a home it leaves unstabbed — one its reader may not
//! read — costs it one directory step and nothing of that home's links, and
//! the store's size enters only as the logarithm inside each ordered-set
//! range (PUB-7.18, at every slot).
//!
//! Overlap is [`overlaps`], which comes to `max start < min reach`. For a
//! stored span `[s, r)` and a query span `[q, e)` that is `s < e ∧ q < r`, and
//! splitting on the stored start gives two halves that never meet and together
//! hold every match: a span with `s ≥ q` overlaps exactly when it starts inside
//! the query span, and one with `s < q` exactly when it contains `q`.
//!
//! The index answers both halves for the spans the write paths store, the
//! sibling runs: a level-uniform span whose width is zero in every component
//! but its last, `[p·x, p·y)` — the subtrees of the siblings `p·x … p·(y−1)`
//! of its axis `p`, the start less its last component. `enc` builds them, as
//! `subtree_of`'s width is `δ(1, #p)`, and so does M5's `Run::iextent`. A
//! sibling run contains a tumbler `t` exactly when `p` is a proper prefix of
//! `t` and `x ≤ t[#p] < y`, so "contains `q`" is a one-coordinate stabbing
//! question asked on each prefix of `q` that is an axis. Any other span is
//! residue, tested whole against every query span; no deposit path the wire
//! reaches stores one.
//!
//! **The home-first keys.** Every part of a slot's index carries the link's
//! home as the leading key component — `starts` is `(home, start, link)`, the
//! axis parts `(home, axis, level, coordinate, link)`, the residue keyed by
//! `(home, link)` — the home an interned `Arc` every filing of that home
//! shares. One ordered set per part still, never a set per home: `im`
//! allocates a whole B-tree node for every set, however few keys it holds.
//! The stab of one home prefixes the home to every range bound, so it is
//! today's two halves over that home's keys, `O(log n + the home's hits)`.
//!
//! **The directory.** Two more ordered sets per slot answer which homes have
//! a filing a query could meet, without visiting a link. For the half that
//! starts inside the query, `starting_homes` holds `(axis, block, home)` once
//! for every home with a run starting in that block of its axis, a block
//! being `2^BLOCK_BITS` coordinates on a content axis ([`BLOCK_BITS`]) and
//! one coordinate on any other; for the half that contains the query start,
//! `containing_homes` holds `(axis, level, node, home)` once for every home
//! with a run filed at that node of the axis index. Each entry is written at a home's first filing in its key, a
//! `contains` then an insert, as `levels` is kept. The enumeration for a
//! query span `[s, r)` is one range per block its coordinates cross on each
//! axis holding starts inside it — the axes that are prefixes of `s`, over
//! the coordinates between `s` and `r`, and every axis between `s` and `r`
//! in T1 order, whole — and one range per `(axis, level, node)` of the
//! containing probe set, which is today's; every home holding residue is a
//! candidate for every query. A directory range names a home with a run in
//! the block or at the node, which may yet miss the span: the candidate set
//! over-includes at block grain, and the per-home stab is exact.
//!
//! **The axis index.** Each sibling run on an axis is filed at one node of
//! its coordinates' binary partition: its level `ℓ = bits(x ⊕ (y − 1))`,
//! which is 0 for a width-1 run, and its block `m = x >> ℓ`. A level-0 node
//! holds only `[m, m + 1)`; a node at level `ℓ ≥ 1` holds only runs inside its
//! block `[m·2^ℓ, (m + 1)·2^ℓ)` that contain both `M − 1` and its midpoint
//! `M = m·2^ℓ + 2^(ℓ−1)`, and files each twice, by `x` and by `y`. A point `c`
//! meets one node per level, `(ℓ, c >> ℓ)`. At level 0 everything there
//! contains it; above, a point below the midpoint (bit `ℓ − 1` of `c` clear) is
//! contained by the runs with `x ≤ c`, and one at or past it by the runs with
//! `y > c`. On the query start's own axis a run with `x = c` starts at the
//! query start, which the first half holds, so there the second half takes
//! `x < c` and skips level 0, and each hit is visited once.
//!
//! **The candidates, lazily and in address order.** [`Touching`] merges every
//! directory range a query opens — and, for the type slot, the typed slices'
//! homes the read surface seeks — into one walk yielding each candidate home
//! once, ascending, as the index holds it, with the query spans whose ranges
//! named it: each range yields its homes ascending, a heap of the ranges
//! yields the least next home across them, and the ranges naming one home are
//! drained together. Each range stands for one part of the stab ([`Parts`]) —
//! a block range for the starting half, a node range for the containing half,
//! the residue range for the residue test — and a span carries the parts of
//! the ranges that named it. A caller stabs a home over the spans that named
//! it, at those parts, and no other, so the probes a read runs are the
//! directory entries it stepped, not the product of its homes, its spans and
//! the parts of a stab; and a caller that stops early — a window past its `n`
//! — steps no entry past the homes it passed.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::iter::Peekable;
use std::ops::Bound::{Excluded, Included, Unbounded};
use std::sync::{Arc, LazyLock};

use im::{OrdMap, OrdSet};
use skep_address::{
    classify_spans, content_subspace, validate, Address, Nat, Span, SpanRel, Tumbler,
};

use crate::endset::Link;

/// Returns whether two spans overlap, as the spanfilade counts it (§6).
///
/// Overlap is `ProperOverlap | Containment | Equal` — not `Adjacent`
/// (abutting spans share no tumbler; matching them would false-positive every
/// link whose slot coverage merely abuts the query) and never M1's
/// `intersect` (which faults on the mixed-length endpoints M5's resolve runs
/// routinely produce). [`SlotIndex::stab_in`] answers by it — its two halves
/// split it on the stored start, and it tests the residue directly — and so
/// does every later conjunct of `match_links`.
pub(super) fn overlaps(a: &Span, b: &Span) -> bool {
    matches!(
        classify_spans(a, b),
        SpanRel::ProperOverlap | SpanRel::Containment | SpanRel::Equal
    )
}

/// A home: a link's home document, as the hint fold computes it.
///
/// A [`Spanfilade`] holds each one once, and every filing of a link homed
/// there shares that allocation.
pub(super) type Home = Arc<Tumbler>;

/// An axis: a sibling run's start less its last component.
///
/// A [`SlotIndex`] holds each one once, and every filing on it shares that
/// allocation.
type Axis = Arc<[Nat]>;

/// One filing of a sibling run under its home: `(home, axis, level,
/// coordinate, link)`.
type Filing = (Home, Axis, u64, Nat, Arc<Tumbler>);

/// The width of a directory block on a content axis, as a power of two:
/// `2^BLOCK_BITS` positions share one `(axis, block, home)` entry per home.
///
/// Chosen by a counted measurement over two boards. At a document of 10⁴
/// linking homes, each with one link at its own position, a short passage
/// of ten positions steps as many directory entries as the block holds homes
/// — ten at a block of one, about sixty-four here, over a thousand at 2^10 —
/// against the ten links it answers, so a wider block costs a popular
/// document's short reads homes they never stab. At an ordinary passage —
/// a hundred homes with ten links apiece, at distinct positions inside a
/// passage of a hundred — the read steps one entry per home and position at
/// a block of one, a thousand, and one or two per home here, so a narrower
/// block prices an unreadable home's whole passage by its links again, the
/// cost this index exists to close. Sixty-four positions is the grain at
/// which a passage's links in one home collapse to one or two entries while
/// a ten-position read over-includes at most the block's other homes.
pub(super) const BLOCK_BITS: u64 = 6;

/// `[0]`, the least tumbler and so below every link address.
///
/// It closes the ranges over keys that end in a link.
static BELOW_EVERY_LINK: LazyLock<Arc<Tumbler>> =
    LazyLock::new(|| Arc::new(Tumbler::new([Nat::from(0u32)]).expect("one component")));

/// Returns [`BELOW_EVERY_LINK`], shared rather than built per range.
fn below_every_link() -> Arc<Tumbler> {
    Arc::clone(&BELOW_EVERY_LINK)
}

/// Returns the directory block of coordinate `c` on `axis`.
///
/// A content axis — one whose last two components are `0 · s_C`, the
/// content subspace of a document or a member — is where passages lie and
/// where a home's links cluster, so its coordinates share blocks of
/// `2^BLOCK_BITS`. Every other axis files at the coordinate itself: a link
/// ordinal is a name a claim gives one link and never a position a query
/// ranges over, a document or account number likewise, and grouping them
/// would name a home for the claims on a key's sixty-three neighbours — a
/// probe at an address no claim names would then cost what its block holds,
/// and tell a reader that claims lie nearby.
fn block_of(axis: &[Nat], c: &Nat) -> Nat {
    match axis {
        [.., separator, subspace] if separator.bits() == 0 && *subspace == content_subspace() => {
            c >> BLOCK_BITS
        }
        _ => c.clone(),
    }
}

/// Lifts a home from the index's tumbler to an `Address`.
///
/// A home here is `document_of` a link key, computed by the hint fold, so it
/// is T4-valid; the `expect` restates that where it leaves the index.
fn lift_home(home: &Home) -> Address {
    validate((**home).clone()).expect("a filed home is document_of a T4-valid link key")
}

/// The spanfilade: one [`SlotIndex`] per slot position a stored link has.
///
/// The hint fold files every span of a deposit here ([`Spanfilade::file`]),
/// so the index covers the audit slice; a read applies its view to the
/// answer.
#[derive(Debug, Clone, Default)]
pub(super) struct Spanfilade {
    /// Slot `i + 1`'s index at position `i`, for the widest arity filed.
    slots: Vec<SlotIndex>,
    /// Every home a filed link has, held once.
    homes: OrdMap<Home, ()>,
}

impl Spanfilade {
    /// Files every span of `value`'s slots under the link at `addr`, homed
    /// at `home`.
    ///
    /// It costs a few ordered-set inserts per span, `O(log n)` each, and a
    /// directory lookup per span — an insert too at a home's first filing in
    /// a block or at a node.
    pub(super) fn file(&mut self, addr: &Tumbler, home: &Tumbler, value: &Link) {
        let home = self.intern(home);
        let link = Arc::new(addr.clone());
        for (position, endset) in value.slots().enumerate() {
            if position == self.slots.len() {
                self.slots.push(SlotIndex::default());
            }
            for (index, span) in endset.spans().enumerate() {
                self.slots[position].file(&home, &link, index, span);
            }
        }
    }

    /// Returns the held home equal to `home`, holding it first if it is new.
    fn intern(&mut self, home: &Tumbler) -> Home {
        if let Some((held, ())) = self.homes.get_key_value(home) {
            return Arc::clone(held);
        }
        let held: Home = Arc::new(home.clone());
        self.homes.insert(Arc::clone(&held), ());
        held
    }

    /// Returns the held home equal to `home`, or `None` where no link homed
    /// there is filed — and so no range keyed by it holds anything.
    pub(super) fn home(&self, home: &Tumbler) -> Option<&Home> {
        self.homes.get_key_value(home).map(|(held, ())| held)
    }

    /// Returns slot `slot`'s index, or `None` for a slot no filed link has —
    /// `0`, below the 1-based floor, or one past every arity filed.
    pub(super) fn slot(&self, slot: usize) -> Option<&SlotIndex> {
        slot.checked_sub(1)
            .and_then(|position| self.slots.get(position))
    }
}

/// One slot position's index.
///
/// Its sibling runs are held twice — by start, for the half of a stab that
/// starts inside the query span, and on their axis, for the half that
/// contains the query start — and every other span once, as residue, each
/// part keyed by the link's home first. Beside them the directory's two
/// parts name the homes with a filing in a block or at a node. Each part is
/// one ordered set keyed by a tuple, never a set per home, per start or per
/// axis: `im` allocates a whole B-tree node for every set, however few keys
/// it holds. Homes, starts and links are shared `Arc`s, so the path copies a
/// persistent insert makes copy pointers rather than tumblers.
#[derive(Debug, Clone, Default)]
pub(super) struct SlotIndex {
    /// Every sibling run's start beside its link, under its home.
    starts: OrdSet<(Home, Arc<Tumbler>, Arc<Tumbler>)>,
    /// Every axis a run here sits on, held once.
    axes: OrdMap<Axis, ()>,
    /// Every level an axis files a run at, as `(axis, level)`.
    levels: OrdSet<(Axis, u64)>,
    /// Every sibling run by its first coordinate `x`, under its home.
    by_first: OrdSet<Filing>,
    /// Every sibling run at level 1 or more by its end coordinate `y`, under
    /// its home.
    by_end: OrdSet<Filing>,
    /// Every span that is no sibling run, under its home and link, keyed by
    /// its position in the slot.
    residue: OrdMap<(Home, Arc<Tumbler>, usize), Span>,
    /// The directory's starting half: `(axis, block, home)` once per home
    /// with a run starting in the block.
    starting_homes: OrdSet<(Axis, Nat, Home)>,
    /// The directory's containing half: `(axis, level, node, home)` once per
    /// home with a run filed at the node.
    containing_homes: OrdSet<(Axis, u64, Nat, Home)>,
}

impl SlotIndex {
    /// Files the `index`-th span of `link`'s slot, homed at `home`.
    fn file(&mut self, home: &Home, link: &Arc<Tumbler>, index: usize, span: &Span) {
        let Some(SiblingRun { axis, first, end }) = SiblingRun::of(span) else {
            self.residue
                .insert((Arc::clone(home), Arc::clone(link), index), span.clone());
            return;
        };
        let level = (&first ^ &(&end - 1u32)).bits();
        let axis = self.intern(axis);
        self.starts.insert((
            Arc::clone(home),
            Arc::new(span.start().clone()),
            Arc::clone(link),
        ));
        // Asked first because an insert copies its path even when the key is
        // there, and nearly every filing meets its axis's level, its home's
        // block and its home's node already held.
        let axis_level = (Arc::clone(&axis), level);
        if !self.levels.contains(&axis_level) {
            self.levels.insert(axis_level);
        }
        let in_block = (Arc::clone(&axis), block_of(&axis, &first), Arc::clone(home));
        if !self.starting_homes.contains(&in_block) {
            self.starting_homes.insert(in_block);
        }
        let at_node = (Arc::clone(&axis), level, &first >> level, Arc::clone(home));
        if !self.containing_homes.contains(&at_node) {
            self.containing_homes.insert(at_node);
        }
        if level > 0 {
            self.by_end.insert((
                Arc::clone(home),
                Arc::clone(&axis),
                level,
                end,
                Arc::clone(link),
            ));
        }
        self.by_first
            .insert((Arc::clone(home), axis, level, first, Arc::clone(link)));
    }

    /// Returns the held axis equal to `comps`, holding it first if it is new.
    fn intern(&mut self, comps: Vec<Nat>) -> Axis {
        if let Some((axis, ())) = self.axes.get_key_value(comps.as_slice()) {
            return Arc::clone(axis);
        }
        let axis: Axis = Arc::from(comps);
        self.axes.insert(Arc::clone(&axis), ());
        axis
    }

    /// Hands `hit` every link homed at `home` one of whose spans here
    /// overlaps `q` — once per span and half that finds it, so a caller
    /// wanting each link once deduplicates what it is handed.
    pub(super) fn stab_in<'a>(&'a self, home: &Home, q: &Span, hit: &mut impl FnMut(&'a Tumbler)) {
        self.stab_in_parts(home, q, Parts::ALL, hit);
    }

    /// Hands `hit` every link homed at `home` one of whose spans here
    /// overlaps `q` and that one of `parts` finds.
    ///
    /// It is [`SlotIndex::stab_in`] at the parts named, every other part
    /// skipped. A part no range of which named the home finds no link of it
    /// ([`Parts`]), so at the parts the walk named a home and span at, this
    /// answers what `stab_in` answers for that span.
    pub(super) fn stab_in_parts<'a>(
        &'a self,
        home: &Home,
        q: &Span,
        parts: Parts,
        hit: &mut impl FnMut(&'a Tumbler),
    ) {
        if parts.has(Parts::STARTING) {
            self.starting_inside(home, q, hit);
        }
        if parts.has(Parts::CONTAINING) {
            self.containing(home, q.start(), hit);
        }
        if parts.has(Parts::RESIDUE) {
            let from = (Arc::clone(home), below_every_link(), 0);
            for ((at, link, _), span) in self.residue.range((Included(from), Unbounded)) {
                if at != home {
                    break; // the home's residue is one key range
                }
                if overlaps(q, span) {
                    hit(link);
                }
            }
        }
    }

    /// Hands `hit` the link of every sibling run homed at `home` starting
    /// inside `q`.
    fn starting_inside<'a>(&'a self, home: &Home, q: &Span, hit: &mut impl FnMut(&'a Tumbler)) {
        let from = (Arc::clone(home), Arc::new(q.start().clone()), below_every_link());
        let to = (Arc::clone(home), Arc::new(q.reach()), below_every_link());
        for (_, _, link) in self.starts.range((Included(from), Excluded(to))) {
            hit(link);
        }
    }

    /// Hands `hit` the link of every sibling run homed at `home` that
    /// contains `start`.
    ///
    /// A run starting at `start` itself is left to
    /// [`SlotIndex::starting_inside`].
    fn containing<'a>(&'a self, home: &Home, start: &Tumbler, hit: &mut impl FnMut(&'a Tumbler)) {
        let comps: Vec<Nat> = start.iter().cloned().collect();
        for (depth, c) in comps.iter().enumerate() {
            let Some((axis, ())) = self.axes.get_key_value(&comps[..depth]) else {
                continue;
            };
            let own_axis = depth + 1 == comps.len();
            for level in self.levels_of(axis) {
                if level == 0 {
                    if !own_axis {
                        collect(&self.by_first, home, axis, 0, c.clone(), c + 1u32, hit);
                    }
                } else if c.bit(level - 1) {
                    let block_end = ((c >> level) + 1u32) << level;
                    collect(&self.by_end, home, axis, level, c + 1u32, block_end + 1u32, hit);
                } else {
                    let block_start = (c >> level) << level;
                    let past = if own_axis { c.clone() } else { c + 1u32 };
                    collect(&self.by_first, home, axis, level, block_start, past, hit);
                }
            }
        }
    }

    /// Returns the levels `axis` files runs at, ascending.
    fn levels_of(&self, axis: &Axis) -> impl Iterator<Item = u64> + '_ {
        let levels = (
            Included((Arc::clone(axis), 0)),
            Included((Arc::clone(axis), u64::MAX)),
        );
        self.levels.range(levels).map(|&(_, level)| level)
    }

    /// Opens the directory ranges that name the homes with a filing that
    /// could meet `q`, as streams tagged `(pair, Some(span))`, onto `out`.
    ///
    /// For the starting half, one stream per block of each axis that holds
    /// a start inside `[s, r)` — the axes that are proper prefixes of `s`,
    /// over the coordinates that keep `a·c` inside the span, and the axes
    /// between `s` and `r` in T1 order, whole — found by seeking the blocks
    /// the axis actually holds, each standing for [`Parts::STARTING`]. For
    /// the containing half, one stream per `(axis, level, node)` of the
    /// probe set [`SlotIndex::containing`] walks, each standing for
    /// [`Parts::CONTAINING`]. Residue is the slot's, not the span's:
    /// [`SlotIndex::residue_stream`] opens it once per query.
    pub(super) fn streams<'a>(
        &'a self,
        q: &Span,
        pair: usize,
        span: usize,
        out: &mut Vec<Stream<'a>>,
    ) {
        let s: Vec<Nat> = q.start().iter().cloned().collect();
        let r: Vec<Nat> = q.reach().iter().cloned().collect();
        // The starting half: the axes that are proper prefixes of `s`, each
        // over the coordinates `c` with `s ≤ a·c < r`.
        for depth in 0..s.len() {
            let Some((axis, ())) = self.axes.get_key_value(&s[..depth]) else {
                continue;
            };
            // `a·c` is `s` itself at the last depth and a proper prefix of
            // `s` — below it — at any other, so the first coordinate at or
            // past `s` is one more there.
            let lowest = if depth + 1 == s.len() {
                s[depth].clone()
            } else {
                &s[depth] + 1u32
            };
            if let Some(past) = coordinates_below(&s[..depth], &r) {
                self.block_streams(axis, lowest, past, pair, span, out);
            }
        }
        // …and every axis between `s` and `r`: on each, every coordinate is
        // past `s`, and the ones short of `r` are kept.
        let between: (std::ops::Bound<&[Nat]>, std::ops::Bound<&[Nat]>) =
            (Included(&s[..]), Excluded(&r[..]));
        for (axis, ()) in self.axes.range::<_, [Nat]>(between) {
            if let Some(past) = coordinates_below(axis, &r) {
                self.block_streams(axis, Nat::from(0u32), past, pair, span, out);
            }
        }
        // The containing half: the nodes the probe set visits.
        for (depth, c) in s.iter().enumerate() {
            let Some((axis, ())) = self.axes.get_key_value(&s[..depth]) else {
                continue;
            };
            let own_axis = depth + 1 == s.len();
            for level in self.levels_of(axis) {
                if level == 0 && own_axis {
                    continue; // a run starting at `s` is the starting half's
                }
                let node = c >> level;
                let from = (Arc::clone(axis), level, node.clone(), below_every_link());
                let to = (Arc::clone(axis), level, node + 1u32, below_every_link());
                let homes = self
                    .containing_homes
                    .range((Included(from), Excluded(to)))
                    .map(|(_, _, _, home)| Arc::clone(home));
                out.push(Stream::new(pair, Some(span), Parts::CONTAINING, homes));
            }
        }
    }

    /// Opens one stream per block of `axis` holding a start, from the block
    /// of `lowest` to the block of the coordinate before `past`, onto `out`.
    fn block_streams<'a>(
        &'a self,
        axis: &Axis,
        lowest: Nat,
        past: Past,
        pair: usize,
        span: usize,
        out: &mut Vec<Stream<'a>>,
    ) {
        let last_block = match &past {
            Past::Every => None,
            Past::At(past) if *past <= lowest => return,
            Past::At(past) => Some(block_of(axis, &(past - 1u32))),
        };
        let mut block = block_of(axis, &lowest);
        loop {
            // Seek the first held block at or past `block`: a block no home
            // starts in opens no stream and costs one seek.
            let from = (Arc::clone(axis), block.clone(), below_every_link());
            let Some((at, held, _)) = self
                .starting_homes
                .range((Included(from), Unbounded))
                .next()
            else {
                return;
            };
            if at != axis || last_block.as_ref().is_some_and(|last| held > last) {
                return;
            }
            let from = (Arc::clone(axis), held.clone(), below_every_link());
            let to = (Arc::clone(axis), held + 1u32, below_every_link());
            let homes = self
                .starting_homes
                .range((Included(from), Excluded(to)))
                .map(|(_, _, home)| Arc::clone(home));
            out.push(Stream::new(pair, Some(span), Parts::STARTING, homes));
            block = held + 1u32;
        }
    }

    /// Returns a stream of every home holding residue here, tagged
    /// `(pair, None)` and standing for [`Parts::RESIDUE`] — a candidate for
    /// every query, the residue being tested whole — or `None` where there is
    /// no residue.
    pub(super) fn residue_stream(&self, pair: usize) -> Option<Stream<'_>> {
        if self.residue.is_empty() {
            return None;
        }
        let homes = self.residue.keys().map(|(home, _, _)| Arc::clone(home));
        Some(Stream::new(pair, None, Parts::RESIDUE, homes))
    }
}

/// Hands `hit` every filing's link homed at `home` on `axis` at `level` in
/// `[from, to)`.
fn collect<'a>(
    filings: &'a OrdSet<Filing>,
    home: &Home,
    axis: &Axis,
    level: u64,
    from: Nat,
    to: Nat,
    hit: &mut impl FnMut(&'a Tumbler),
) {
    let from = (Arc::clone(home), Arc::clone(axis), level, from, below_every_link());
    let to = (Arc::clone(home), Arc::clone(axis), level, to, below_every_link());
    for (_, _, _, _, link) in filings.range((Included(from), Excluded(to))) {
        hit(link);
    }
}

/// The exclusive upper bound on the coordinates `c` of an axis keeping `a·c`
/// below a reach `r`.
enum Past {
    /// Every coordinate keeps `a·c < r`.
    Every,
    /// The coordinates below this one do.
    At(Nat),
}

/// Returns the coordinates `c` with `a·c < r` in T1 order, or `None` where
/// no coordinate does.
///
/// T1 order is lexicographic and prefix-smaller. Where `a` is a proper
/// prefix of `r`, `a·c` is below `r` for `c` below `r`'s component there,
/// and at it too when `a·c` is still a proper prefix of `r`; where `a` is `r`
/// or past it, no `a·c` is below `r`; and where `a` is below `r` without
/// being its prefix, every `a·c` is.
fn coordinates_below(a: &[Nat], r: &[Nat]) -> Option<Past> {
    if a.len() < r.len() && r.starts_with(a) {
        let at = &r[a.len()];
        return Some(Past::At(if r.len() == a.len() + 1 {
            at.clone()
        } else {
            at + 1u32
        }));
    }
    (a < r).then_some(Past::Every)
}

/// Which parts of a home's stab a directory range stands for.
///
/// The parts are the starting half ([`SlotIndex::starting_inside`]), the
/// containing half ([`SlotIndex::containing`]) and the residue test. The
/// ranges of each part name every home that part could hit for a span
/// `[s, r)`: a run starting inside the span starts on an axis that is a
/// proper prefix of `s` or lies between `s` and `r` in T1 order, in a block
/// [`SlotIndex::streams`] opens; a run containing `s` and not starting at it
/// is filed, on an axis that is a proper prefix of `s`, at the node of `s`'s
/// coordinate there at one of the levels the axis files at — the node the
/// containing probe set visits; and the residue range names every home
/// holding residue. So a home no range of a part named for a span holds no
/// link that part finds for it, and a stab of the home at the parts that
/// named it answers what a stab at every part answers. A typed slice's
/// homes, named by class and not by a range of the index, stand for every
/// part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Parts(u8);

impl Parts {
    /// No part: what a span no range named stands for.
    const NONE: Parts = Parts(0);
    /// The starting half: the runs starting inside the span.
    const STARTING: Parts = Parts(1);
    /// The containing half: the runs containing the span's start.
    const CONTAINING: Parts = Parts(1 << 1);
    /// The residue test: every span that is no sibling run, tested whole.
    const RESIDUE: Parts = Parts(1 << 2);
    /// Every part: a whole stab.
    pub(super) const ALL: Parts = Parts(0b111);

    /// Returns the parts of `self` and of `other` together.
    fn with(self, other: Parts) -> Parts {
        Parts(self.0 | other.0)
    }

    /// Returns whether `self` holds `part`.
    fn has(self, part: Parts) -> bool {
        self.0 & part.0 != 0
    }
}

/// One directory range, or one typed slice's homes: the homes it names,
/// ascending, which query it was opened for — `span` the index of the span
/// within the query's endset, or `None` where it names a home for the whole
/// query — and the parts of a stab it stands for.
pub(super) struct Stream<'a> {
    pair: usize,
    span: Option<usize>,
    parts: Parts,
    homes: Box<dyn Iterator<Item = Home> + 'a>,
}

impl<'a> Stream<'a> {
    /// Wraps `homes`, which yields its homes ascending, under its tag.
    pub(super) fn new(
        pair: usize,
        span: Option<usize>,
        parts: Parts,
        homes: impl Iterator<Item = Home> + 'a,
    ) -> Stream<'a> {
        Stream {
            pair,
            span,
            parts,
            homes: Box::new(homes),
        }
    }
}

/// One candidate home a stab could meet, with the query spans whose
/// directory ranges named it.
///
/// Yielded by the walk `LinkState::homes_touching` answers (`Touching`): the
/// home in address order among its siblings, and, per query the walk was
/// opened for, the spans some filing of the home could overlap — the spans
/// the per-home stab need probe, every other span being one no filing of
/// this home meets — each with the parts of the stab whose ranges named the
/// home for it, the parts `LinkState::stab_in_slots` probes the span at. The
/// touch holds the home as the index holds it, so that stab looks the home
/// up nowhere.
#[derive(Debug)]
pub struct Touch<'q> {
    /// The candidate home.
    home: Address,
    /// The candidate home as the index holds it.
    held: Home,
    /// Per span named: its query's index in the walk, the parts of the stab
    /// whose ranges named the home for it, and the span — grouped by query,
    /// each query's spans in its order.
    named: Vec<(usize, Parts, &'q Span)>,
}

impl<'q> Touch<'q> {
    /// Returns the candidate home.
    pub fn home(&self) -> &Address {
        &self.home
    }

    /// Returns the candidate home, consuming the touch.
    pub fn into_home(self) -> Address {
        self.home
    }

    /// Returns the spans of query `query` — its index in the list the walk
    /// was opened over — whose ranges named this home, in the query's order.
    pub fn spans(&self, query: usize) -> impl Iterator<Item = &'q Span> + '_ {
        self.named_at(query).map(|(span, _)| span)
    }

    /// Returns the spans of query `query` whose ranges named this home, each
    /// with the parts of the stab those ranges stand for, in the query's
    /// order.
    pub(super) fn named_at(&self, query: usize) -> impl Iterator<Item = (&'q Span, Parts)> + '_ {
        self.named
            .iter()
            .filter(move |(pair, _, _)| *pair == query)
            .map(|&(_, parts, span)| (span, parts))
    }

    /// Returns the candidate home as the index holds it.
    pub(super) fn held(&self) -> &Home {
        &self.held
    }
}

/// The walk of candidate homes over a list of `(slot, query)` pairs.
///
/// A heap of the streams every pair opened — the directory ranges, and the
/// typed slices' homes for a type query — ordered by each stream's next home,
/// so the least home across them comes first; every stream that names it is
/// drained together and advanced, and the spans those streams were opened for
/// are the touch's, each with the parts of the streams that named it. Lazy: a
/// stream is stepped only as far as the homes yielded, so a caller that stops
/// steps no entry past them.
pub(super) struct Touching<'q> {
    /// Per pair, the query's spans by index, for the touches to name.
    spans: Vec<Vec<&'q Span>>,
    streams: Vec<Stream<'q>>,
    heap: BinaryHeap<Reverse<(Home, usize)>>,
    /// The streams that named the home last yielded, kept from yield to
    /// yield so a touch allocates its named spans and nothing more.
    naming: Vec<usize>,
}

impl<'q> Touching<'q> {
    /// Opens the walk over `streams`, each tagged with a pair of `spans`.
    pub(super) fn open(spans: Vec<Vec<&'q Span>>, mut streams: Vec<Stream<'q>>) -> Touching<'q> {
        let mut heap = BinaryHeap::with_capacity(streams.len());
        for (i, stream) in streams.iter_mut().enumerate() {
            if let Some(home) = stream.homes.next() {
                heap.push(Reverse((home, i)));
            }
        }
        Touching {
            spans,
            streams,
            heap,
            naming: Vec::new(),
        }
    }

    /// Pushes stream `i`'s next home, if it has one.
    fn advance(&mut self, i: usize) {
        if let Some(home) = self.streams[i].homes.next() {
            self.heap.push(Reverse((home, i)));
        }
    }
}

impl<'q> Iterator for Touching<'q> {
    type Item = Touch<'q>;

    fn next(&mut self) -> Option<Touch<'q>> {
        let Reverse((home, first)) = self.heap.pop()?;
        let mut naming = std::mem::take(&mut self.naming);
        naming.clear();
        naming.push(first);
        self.advance(first);
        while let Some(Reverse((next, _))) = self.heap.peek() {
            if *next != home {
                break;
            }
            let Reverse((_, i)) = self.heap.pop().expect("peeked");
            naming.push(i);
            self.advance(i);
        }
        // Grouped by pair, and within a pair by span, the whole-query streams
        // — `None` — ahead of the per-span ones.
        let streams = &self.streams;
        naming.sort_unstable_by_key(|&i| (streams[i].pair, streams[i].span));
        let mut named = Vec::new();
        let mut at = naming.iter().map(|&i| &streams[i]).peekable();
        while let Some(&&Stream { pair, .. }) = at.peek() {
            let whole = join_parts(&mut at, pair, None, Parts::NONE);
            if whole == Parts::NONE {
                // Named by its spans alone: each span a range named, once,
                // at the parts its ranges stand for.
                while let Some(&&Stream {
                    pair: next,
                    span: Some(span),
                    ..
                }) = at.peek()
                {
                    if next != pair {
                        break;
                    }
                    let parts = join_parts(&mut at, pair, Some(span), Parts::NONE);
                    named.push((pair, parts, self.spans[pair][span]));
                }
            } else {
                // Named for the whole query: every span of it, at the whole
                // query's parts and its own ranges'.
                for (span, &q) in self.spans[pair].iter().enumerate() {
                    named.push((pair, join_parts(&mut at, pair, Some(span), whole), q));
                }
            }
        }
        self.naming = naming;
        Some(Touch {
            home: lift_home(&home),
            held: home,
            named,
        })
    }
}

/// Returns `parts` joined with the parts of the streams heading `at` that
/// were opened for span `span` of pair `pair`, consuming those streams.
fn join_parts<'s, 'q: 's>(
    at: &mut Peekable<impl Iterator<Item = &'s Stream<'q>>>,
    pair: usize,
    span: Option<usize>,
    mut parts: Parts,
) -> Parts {
    while let Some(stream) = at.next_if(|s| s.pair == pair && s.span == span) {
        parts = parts.with(stream.parts);
    }
    parts
}

/// A sibling run `[p·x, p·y)`, as its axis `p` and its coordinates.
struct SiblingRun {
    axis: Vec<Nat>,
    first: Nat,
    end: Nat,
}

impl SiblingRun {
    /// Returns `span`'s parts if it is a sibling run, else `None`.
    ///
    /// A sibling run is level-uniform with a width zero in every component
    /// but its last. T12 makes that last component nonzero, so `y > x`.
    fn of(span: &Span) -> Option<SiblingRun> {
        let (start, width) = (span.start(), span.width());
        if start.len() != width.len() {
            return None;
        }
        let mut widths = width.iter();
        let step = widths.next_back().expect("a tumbler is nonempty");
        if widths.any(|w| w.bits() != 0) {
            return None;
        }
        let mut axis: Vec<Nat> = start.iter().cloned().collect();
        let first = axis.pop().expect("a tumbler is nonempty");
        let end = &first + step;
        Some(SiblingRun { axis, first, end })
    }
}

#[cfg(test)]
mod tests;
