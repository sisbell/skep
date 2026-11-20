//! A text's change by identity: two images planned as lines (skep #1091).
//!
//! A board knows which positions of a text as it stood are, by identity,
//! positions of the text as it stands: a block moved by a `rearrange` is the
//! same I-addresses at another place, and a block deleted and typed again is
//! other addresses that read the same. This module turns that knowledge into
//! the plan of a diff, so a caller shows a move as a move and a re-typed
//! block as re-typed, where a diff of the two texts shows the first as a
//! removal and an addition and shows nothing of the second. It is a function
//! of two images and two line tables: it reads no board and compares no text
//! but the lines' keys its caller hands it, and stands in every build.
//!
//! The two texts are *before*, a document holding the text as it stood — a
//! mark, the version a draft was staged from, a document it copied from —
//! and *now*, the draft. Positions count from 1 in each.
//!
//! A publication between the two re-mints a draft's words: its shot leaves
//! the draft arranging the member's I-addresses where it arranged its own,
//! and homes a correspondence record naming each pair in the draft. A
//! caller comparing across one hands both images mapped through the
//! records every publication left — each draft's records read in its
//! owner's account, the person's drafts and another account's alike — by
//! the restore's mapping, read after both images; mapped on one side alone,
//! or not at all, re-minted words pair with nothing and read as gone and
//! new.
//!
//! **Identity** ([`Identity::of`]). Each image is cut, chain by chain, at
//! every I-address where a run of either begins or ends, so two pieces hold
//! the same I-addresses or share none; a piece of *before* and a piece of
//! *now* of one range are a *pair*. A range either text places more than
//! once makes a pair for each two of its places, and the rest of the plan
//! takes each piece in one pair at most:
//!
//! * the pairs that *stay* are the set heaviest in positions whose order in
//!   *now* keeps its order in *before* — of several such sets, the one a walk
//!   of *before* reaches first;
//! * of the pieces no staying pair takes, those of one range are matched in
//!   order, a piece of *before* with a piece of *now*: a match *moved*;
//! * a piece of *now* left over stands *again*: its range has more places
//!   now than before, and it is paired with the range's first place before;
//! * a piece of *before* left over is *gone* — its positions hold nothing
//!   now, though the range stands elsewhere, where its values are read — and
//!   so is every piece of a range *now* holds nowhere, whose values only a
//!   read by identity gives ([`Gone`]);
//! * a piece of *now* whose range *before* holds nowhere is *new*.
//!
//! Pairs that go on along one diagonal — the next position of each text —
//! are one pair, whatever their I-addresses, so a line two runs make up is
//! held by one pair. The counts follow ([`Bytes`]): *new* and *gone* as
//! above, *moved* the positions of *now* that moved or stand again.
//!
//! **The source map** ([`Identity::sources`]). *Before* is told stretch by
//! stretch as positions of *now* or as a gone span, so a caller that holds
//! the text of *now* builds the text of *before* from it and reads only the
//! gone spans.
//!
//! **The lines** ([`Identity::lines`]). Over the two texts' lines:
//!
//! * a line is *held* where one staying pair holds it whole, its line break
//!   too, at a whole line of *now*;
//! * a line *moved* where a moved pair, or one standing again, holds it so;
//! * between two held lines, the lines neither held nor moved that are equal
//!   as text are matched in order, as the edit's finder matches lines (the
//!   parent's `unmatched`, under
//!   [`MAX_MATCH_PRODUCT`](super::MAX_MATCH_PRODUCT): a stretch past the
//!   bound is matched nowhere, its lines gone and new);
//! * every other line of *before* is gone and every other line of *now* new.
//!
//! A new line whose every position is new and which equals a gone line as
//! text, and a line matched as text whose every position is new, is
//! *re-typed*: said only for a block of such lines holding at least
//! [`MIN_KEPT_BETWEEN`] characters that are no whitespace, so a blank line
//! or a lone brace an edit wrote again with its neighbours says nothing —
//! what an edit writes again and what a diff calls re-typed agree. The
//! changed lines are grouped in hunks, the caller's count of unchanged lines
//! either side, two hunks that touch being one.
//!
//! **The bound** ([`MAX_PAIRS`]). The pieces of each image and the pairs
//! they make are counted before any is built, and a plan past the bound is
//! refused ([`Unplanned`]): two images that each place one range thousands
//! of times would make millions of pairs.
//!
//! **The cost** (SP-23). With `r` the runs of the two images, `p` the pieces
//! and pairs, at most [`MAX_PAIRS`] each, and `l` the lines: the cut is a
//! sort of `r` boundaries and a search for each run; the staying set is a
//! heaviest increasing subsequence over the pairs, `O(p log p)` by a Fenwick
//! tree over the pieces of *now*; the held and moved lines are a search for
//! each pair and each line it holds; the match by text walks, between two
//! held lines, what the edit's finder walks there; and the ops, the hunks
//! and the notes are each one walk of the lines. Memory is the pieces, the
//! pairs and a few words a line.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::ops::Range;

use super::{unmatched, MIN_KEPT_BETWEEN};
use crate::board::{IRun, Image};

/// The most pieces of one image, and the most pairs, a plan is made over.
///
/// It is sixteen times the board's run budget for an image: two images at
/// that budget cut each other into twice their runs at most where no range
/// repeats, and the rest is room for ranges that do. Past it the plan is
/// refused before a piece or a pair is built ([`Unplanned`]).
pub const MAX_PAIRS: usize = 1 << 16;

/// A plan refused: the two images make more than [`MAX_PAIRS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unplanned {
    /// How many pieces of one image, or pairs, the images make.
    pub pairs: u64,
}

/// A stretch the two texts share by identity.
///
/// The `width` positions from `before` of the one text hold the very
/// I-addresses the `width` positions from `now` of the other hold, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pair {
    /// The first position of the stretch in *before*.
    pub before: u64,
    /// The first position of the stretch in *now*.
    pub now: u64,
    /// How many positions the stretch is.
    pub width: u64,
}

/// A stretch of *before* whose I-addresses *now* arranges nowhere.
///
/// Its values are read by identity: `width` content positions from the
/// I-address [`Gone::start`], all of one chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gone {
    /// The first position of the stretch in *before*.
    pub before: u64,
    /// The I-addresses' components before their last.
    pub prefix: String,
    /// The first I-address's last component.
    pub first: u64,
    /// How many positions the stretch is.
    pub width: u64,
}

impl Gone {
    /// Returns the stretch's first I-address.
    pub fn start(&self) -> String {
        format!("{}.{}", self.prefix, self.first)
    }
}

/// Where the values of a stretch of *before* are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// In *now*, from this position on: the stretch stands there by identity.
    Now(u64),
    /// By identity: the gone span of this index ([`Identity::gone`]), whole.
    Gone(usize),
}

/// A stretch of *before*, and where its values are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stretch {
    /// The first position of the stretch in *before*.
    pub before: u64,
    /// How many positions the stretch is.
    pub width: u64,
    /// Where its values are read.
    pub source: Source,
}

/// A change's size by identity, in positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bytes {
    /// The positions of *now* whose I-addresses *before* arranges nowhere.
    pub new: u64,
    /// The positions of *before* that neither stay nor moved.
    pub gone: u64,
    /// The positions of *now* that moved, or stand again.
    pub moved: u64,
}

/// What a piece of *before* is in the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Was {
    /// In a staying pair, with the piece of *now* of this index.
    Stays(usize),
    /// In a moved pair, with the piece of *now* of this index.
    Moved(usize),
    /// Gone, its range standing in *now* at the piece of this index.
    Copied(usize),
    /// Gone, its range standing nowhere in *now*.
    ///
    /// Until the plan classes it, any piece.
    Gone,
}

/// What a piece of *now* is in the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Is {
    /// In a staying pair.
    Stays,
    /// In a moved pair.
    Moved,
    /// Standing again, paired with the piece of *before* of this index.
    Again(usize),
    /// New: its range stands nowhere in *before*.
    ///
    /// Until the plan classes it, any piece.
    New,
}

/// One piece of an image: a stretch of one range.
#[derive(Debug, Clone, Copy)]
struct Piece {
    /// The range it is of, by index.
    range: usize,
    /// The chain its I-addresses lie in, by index.
    chain: usize,
    /// Its first I-address's last component.
    first: u64,
    /// Its first position in its text.
    at: u64,
    /// How many positions it is.
    width: u64,
}

/// What identity says of a text's change, before any of its text is read.
///
/// Its invariant, kept by [`Identity::of`], the one way one is made: no two
/// of the staying, the moved and the standing-again pairs share a position
/// of *now*, and no two of the staying and the moved a position of *before*;
/// the staying pairs ascend in both texts; the positions of *now* are those
/// of the three kinds of pair and the new ones, and the positions of
/// *before* those of the staying and the moved pairs and the gone ones; and
/// the source map tiles *before*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The pairs that stay, ascending in both texts.
    stays: Vec<Pair>,
    /// The pairs that moved, ascending in *before*.
    moved: Vec<Pair>,
    /// The pairs standing again, ascending in *now*.
    again: Vec<Pair>,
    /// The gone spans read by identity, ascending in *before*.
    gone: Vec<Gone>,
    /// *Before*, stretch by stretch.
    sources: Vec<Stretch>,
    /// The stretches of *now* that are new, ascending.
    new: Vec<Range<u64>>,
    /// How many positions *before* holds.
    before: u64,
    /// How many positions *now* holds.
    now: u64,
    /// The change's size.
    bytes: Bytes,
}

/// Pushes `pair` onto `pairs`, joined to the last where it goes on.
///
/// It goes on where it starts at the last's next position in both texts.
fn push_pair(pairs: &mut Vec<Pair>, pair: Pair) {
    match pairs.last_mut() {
        Some(last) if last.before + last.width == pair.before && last.now + last.width == pair.now => last.width += pair.width,
        _ => pairs.push(pair),
    }
}

/// An image cut into pieces, and the ranges they are of.
struct Cut {
    /// The pieces of *before*, in its order.
    before: Vec<Piece>,
    /// The pieces of *now*, in its order.
    now: Vec<Piece>,
    /// Each range's pieces of *before*, by index, ascending.
    in_before: Vec<Vec<usize>>,
    /// Each range's pieces of *now*, by index, ascending.
    in_now: Vec<Vec<usize>>,
    /// The chains' prefixes, by index.
    chains: Vec<String>,
}

/// Returns the edges that lie strictly inside `run`, ascending.
///
/// `edges` are its chain's, ascending: each inside it begins a piece of it.
fn inside<'e>(edges: &'e [u128], run: &IRun) -> &'e [u128] {
    let (first, end) = (u128::from(run.first), u128::from(run.first) + u128::from(run.width));
    &edges[edges.partition_point(|edge| *edge <= first)..edges.partition_point(|edge| *edge < end)]
}

impl Cut {
    /// Cuts the two images at every I-address a run of either begins or ends.
    ///
    /// # Errors
    ///
    /// [`Unplanned`] where either image makes more than [`MAX_PAIRS`]
    /// pieces, counted before any is built.
    fn of(before: &Image, now: &Image) -> Result<Cut, Unplanned> {
        let mut chain_of: HashMap<&str, usize> = HashMap::new();
        let mut chains: Vec<String> = Vec::new();
        let mut edges: Vec<Vec<u128>> = Vec::new();
        for run in before.runs().iter().chain(now.runs()) {
            let chain = *chain_of.entry(run.prefix.as_str()).or_insert_with(|| {
                chains.push(run.prefix.clone());
                edges.push(Vec::new());
                chains.len() - 1
            });
            edges[chain].extend([u128::from(run.first), u128::from(run.first) + u128::from(run.width)]);
        }
        for chain in &mut edges {
            chain.sort_unstable();
            chain.dedup();
        }
        for image in [before, now] {
            let pieces: u64 = image.runs().iter().map(|run| inside(&edges[chain_of[run.prefix.as_str()]], run).len() as u64 + 1).sum();
            if pieces > MAX_PAIRS as u64 {
                return Err(Unplanned { pairs: pieces });
            }
        }
        let mut range_of: HashMap<(usize, u64), usize> = HashMap::new();
        let mut pieces = [Vec::new(), Vec::new()];
        for (image, pieces) in [before, now].into_iter().zip(&mut pieces) {
            for run in image.runs() {
                let chain = chain_of[run.prefix.as_str()];
                // Each piece from its start in the run up to the next one's.
                let starts = std::iter::once(0).chain(inside(&edges[chain], run).iter().map(|edge| (*edge - u128::from(run.first)) as u64));
                let mut starts = starts.peekable();
                while let Some(into) = starts.next() {
                    let past = starts.peek().copied().unwrap_or(run.width);
                    let next = range_of.len();
                    let range = *range_of.entry((chain, run.first + into)).or_insert(next);
                    pieces.push(Piece { range, chain, first: run.first + into, at: run.ordinal + into, width: past - into });
                }
            }
        }
        let [before, now] = pieces;
        let by_range = |pieces: &[Piece]| {
            let mut of = vec![Vec::new(); range_of.len()];
            for (k, piece) in pieces.iter().enumerate() {
                of[piece.range].push(k);
            }
            of
        };
        let (in_before, in_now) = (by_range(&before), by_range(&now));
        Ok(Cut { before, now, in_before, in_now, chains })
    }

    /// Returns how many pairs the pieces make: each two places of a range.
    fn pairs(&self) -> u64 {
        self.in_before.iter().zip(&self.in_now).map(|(before, now)| (before.len() as u64).saturating_mul(now.len() as u64)).fold(0, u64::saturating_add)
    }

    /// Returns the pairs that stay, each as its two pieces' indexes.
    ///
    /// The first is the piece of *before*, the second the piece of *now* it
    /// stays with. They are the set heaviest in positions that ascends in
    /// both texts: a
    /// heaviest increasing subsequence over the pairs, walked in the order
    /// of *before* — a piece's pairs from its last place in *now* to its
    /// first, so no two of them chain — each taking the heaviest set that
    /// ends before its place in *now*, kept in a Fenwick tree over the
    /// pieces of *now*. Of two sets of one weight the one found first is
    /// kept.
    fn stays(&self) -> Vec<(usize, usize)> {
        /// The heavier of two sets, and of two of one weight the earlier.
        fn better(a: (u64, usize), b: (u64, usize)) -> (u64, usize) {
            if b.0 > a.0 || (b.0 == a.0 && b.1 < a.1) {
                b
            } else {
                a
            }
        }
        const NONE: usize = usize::MAX;
        let pairs: Vec<(usize, usize)> = self.before.iter().enumerate().flat_map(|(b, piece)| self.in_now[piece.range].iter().rev().map(move |n| (b, *n))).collect();
        // `tree[k]`: the best set ending at a piece of *now* the node covers.
        let mut tree = vec![(0u64, NONE); self.now.len() + 1];
        let (mut total, mut back) = (vec![0u64; pairs.len()], vec![NONE; pairs.len()]);
        for (k, &(b, n)) in pairs.iter().enumerate() {
            let (mut found, mut at) = ((0, NONE), n);
            while at > 0 {
                found = better(found, tree[at]);
                at &= at - 1;
            }
            (total[k], back[k]) = (found.0 + self.before[b].width, found.1);
            let mut at = n + 1;
            while at < tree.len() {
                tree[at] = better(tree[at], (total[k], k));
                at += at.isolate_lowest_one();
            }
        }
        let mut last = (0..pairs.len()).fold((0, NONE), |best, k| better(best, (total[k], k))).1;
        let mut stays = Vec::new();
        while last != NONE {
            stays.push(pairs[last]);
            last = back[last];
        }
        stays.reverse();
        stays
    }
}

impl Identity {
    /// Plans what the image `now` shares by identity with the image `before`.
    ///
    /// The plan is the module doc's *Identity*: the pairs that stay, moved
    /// and stand again, the gone spans, the new stretches, the counts and
    /// the source map.
    ///
    /// # Errors
    ///
    /// [`Unplanned`] where either image is cut into more than [`MAX_PAIRS`]
    /// pieces, or the pieces make more pairs than that: nothing of the plan
    /// is built.
    pub fn of(before: &Image, now: &Image) -> Result<Identity, Unplanned> {
        let cut = Cut::of(before, now)?;
        let pairs = cut.pairs();
        if pairs > MAX_PAIRS as u64 {
            return Err(Unplanned { pairs });
        }
        let (mut was, mut is) = (vec![Was::Gone; cut.before.len()], vec![Is::New; cut.now.len()]);
        for (b, n) in cut.stays() {
            (was[b], is[n]) = (Was::Stays(n), Is::Stays);
        }
        for (before, now) in cut.in_before.iter().zip(&cut.in_now) {
            // The pieces of one range no staying pair takes, matched in order.
            let left_before: Vec<usize> = before.iter().copied().filter(|b| was[*b] == Was::Gone).collect();
            let left_now: Vec<usize> = now.iter().copied().filter(|n| is[*n] == Is::New).collect();
            for (b, n) in left_before.iter().zip(&left_now) {
                (was[*b], is[*n]) = (Was::Moved(*n), Is::Moved);
            }
            let matched = left_before.len().min(left_now.len());
            if let Some(stands) = now.first() {
                for b in &left_before[matched..] {
                    was[*b] = Was::Copied(*stands);
                }
            }
            if let Some(stood) = before.first() {
                for n in &left_now[matched..] {
                    is[*n] = Is::Again(*stood);
                }
            }
        }
        let mut plan = Identity {
            stays: Vec::new(),
            moved: Vec::new(),
            again: Vec::new(),
            gone: Vec::new(),
            sources: Vec::new(),
            new: Vec::new(),
            before: before.extent(),
            now: now.extent(),
            bytes: Bytes::default(),
        };
        for (piece, was) in cut.before.iter().zip(&was) {
            let source = match *was {
                Was::Stays(n) | Was::Moved(n) => {
                    let pair = Pair { before: piece.at, now: cut.now[n].at, width: piece.width };
                    push_pair(if matches!(was, Was::Stays(_)) { &mut plan.stays } else { &mut plan.moved }, pair);
                    Source::Now(pair.now)
                }
                Was::Copied(n) => {
                    plan.bytes.gone += piece.width;
                    Source::Now(cut.now[n].at)
                }
                Was::Gone => {
                    plan.bytes.gone += piece.width;
                    plan.read(piece, &cut.chains[piece.chain])
                }
            };
            plan.told(piece, source);
        }
        for (piece, is) in cut.now.iter().zip(&is) {
            match *is {
                Is::Stays => {}
                Is::Moved => plan.bytes.moved += piece.width,
                Is::Again(b) => {
                    plan.bytes.moved += piece.width;
                    push_pair(&mut plan.again, Pair { before: cut.before[b].at, now: piece.at, width: piece.width });
                }
                Is::New => {
                    plan.bytes.new += piece.width;
                    match plan.new.last_mut() {
                        Some(last) if last.end == piece.at => last.end += piece.width,
                        _ => plan.new.push(piece.at..piece.at + piece.width),
                    }
                }
            }
        }
        Ok(plan)
    }

    /// Returns the source of a gone piece read by identity.
    ///
    /// The piece joins the gone span before it where it goes on in both
    /// *before* and its chain; else it is a span of its own.
    fn read(&mut self, piece: &Piece, prefix: &str) -> Source {
        match self.gone.last_mut() {
            Some(last) if last.before + last.width == piece.at && last.prefix == prefix && last.first.checked_add(last.width) == Some(piece.first) => last.width += piece.width,
            _ => self.gone.push(Gone { before: piece.at, prefix: prefix.to_string(), first: piece.first, width: piece.width }),
        }
        Source::Gone(self.gone.len() - 1)
    }

    /// Adds `piece` of *before* to the source map, read at `source`.
    ///
    /// It joins the stretch before it where the two are read side by side:
    /// in *now*, or as one gone span.
    fn told(&mut self, piece: &Piece, source: Source) {
        if let Some(last) = self.sources.last_mut() {
            let goes_on = match (last.source, source) {
                (Source::Now(from), Source::Now(next)) => from + last.width == next,
                (Source::Gone(span), Source::Gone(next)) => span == next,
                _ => false,
            };
            if goes_on {
                last.width += piece.width;
                return;
            }
        }
        self.sources.push(Stretch { before: piece.at, width: piece.width, source });
    }

    /// Returns the pairs that stay, ascending in both texts.
    pub fn stays(&self) -> &[Pair] {
        &self.stays
    }

    /// Returns the pairs that moved, ascending in *before*.
    pub fn moved(&self) -> &[Pair] {
        &self.moved
    }

    /// Returns the pairs standing again, ascending in *now*.
    ///
    /// Each is a stretch of *now* whose range has more places now than
    /// before, with the range's first place in *before*.
    pub fn again(&self) -> &[Pair] {
        &self.again
    }

    /// Returns the gone spans a read by identity gives.
    ///
    /// They ascend in *before*.
    pub fn gone(&self) -> &[Gone] {
        &self.gone
    }

    /// Returns *before* stretch by stretch, each with where it is read.
    ///
    /// The stretches tile the positions of *before* in order.
    pub fn sources(&self) -> &[Stretch] {
        &self.sources
    }

    /// Returns the change's size by identity.
    pub fn bytes(&self) -> Bytes {
        self.bytes
    }

    /// Returns how many positions *before* holds.
    pub fn before_extent(&self) -> u64 {
        self.before
    }

    /// Returns how many positions *now* holds.
    pub fn now_extent(&self) -> u64 {
        self.now
    }

    /// Returns how many positions of *now* hold I-addresses *before* holds.
    pub fn shared(&self) -> u64 {
        self.now - self.bytes.new
    }

    /// Returns whether nothing changed: every position of both texts stays.
    pub fn unchanged(&self) -> bool {
        let stays: u64 = self.stays.iter().map(|pair| pair.width).sum();
        stays == self.before && stays == self.now
    }

    /// Returns whether every position of the line `line` of *now* is new.
    fn all_new<K>(&self, line: &Line<K>) -> bool {
        let k = self.new.partition_point(|stretch| stretch.start <= line.start);
        k.checked_sub(1).and_then(|k| self.new.get(k)).is_some_and(|stretch| line.start.saturating_add(line.len) <= stretch.end)
    }

    /// Plans the change as lines: the ops, their hunks, the notes, the counts.
    ///
    /// `before` and `now` are the two texts' lines, and `context` how many
    /// unchanged lines a hunk shows either side of a change. The plan is the
    /// module doc's *The lines*.
    ///
    /// **Precondition.** Each table holds its text's lines in order, none
    /// overlapping another: a table that does not is planned as it stands,
    /// its lines found by their starts.
    pub fn lines<K: Eq + Hash>(&self, before: &[Line<K>], now: &[Line<K>], context: usize) -> Lines {
        let held = whole_lines(&self.stays, before, now);
        let mut taken = vec![false; now.len()];
        let mut same: Vec<Option<usize>> = vec![None; before.len()];
        for (i, j) in held {
            if !std::mem::replace(&mut taken[j], true) {
                same[i] = Some(j);
            }
        }
        // The lines that moved: where each line of *now* came from, and where
        // each line of *before* went.
        let mut moved_in: Vec<Option<(usize, bool)>> = vec![None; now.len()];
        let mut moved_out: Vec<Option<usize>> = vec![None; before.len()];
        for (pairs, again) in [(&self.moved, false), (&self.again, true)] {
            for (i, j) in whole_lines(pairs, before, now) {
                if taken[j] || moved_in[j].is_some() {
                    continue;
                }
                moved_in[j] = Some((i, again));
                if !again && same[i].is_none() {
                    moved_out[i].get_or_insert(j);
                }
            }
        }
        // Between two held lines, the lines equal as text, in order.
        let mut by_text = vec![false; before.len()];
        let held: Vec<(usize, usize)> = same.iter().enumerate().filter_map(|(i, j)| j.map(|j| (i, j))).collect();
        let (mut i0, mut j0) = (0, 0);
        for (i1, j1) in held.into_iter().chain([(before.len(), now.len())]) {
            let a: Vec<usize> = (i0..i1).filter(|i| moved_out[*i].is_none()).collect();
            let b: Vec<usize> = (j0..j1).filter(|j| moved_in[*j].is_none()).collect();
            let a_keys: Vec<(&K, bool)> = a.iter().map(|i| (&before[*i].key, before[*i].closed)).collect();
            let b_keys: Vec<(&K, bool)> = b.iter().map(|j| (&now[*j].key, now[*j].closed)).collect();
            let (mut pi, mut pj) = (0, 0);
            for (gone, new) in unmatched(&a_keys, &b_keys).into_iter().chain([(a.len()..a.len(), b.len()..b.len())]) {
                for (i, j) in a[pi..gone.start].iter().zip(&b[pj..new.start]) {
                    (same[*i], by_text[*i]) = (Some(*j), true);
                }
                (pi, pj) = (gone.end, new.end);
            }
            (i0, j0) = (i1 + 1, j1 + 1);
        }
        // The edit script: each line of either text once, in order.
        let op_of_before = |i: usize| match moved_out[i] {
            Some(j) => Op::MovedOut { before: number(i), now: number(j) },
            None => Op::Gone { before: number(i) },
        };
        let op_of_now = |j: usize| match moved_in[j] {
            Some((i, _)) => Op::MovedIn { now: number(j), before: number(i) },
            None => Op::New { now: number(j) },
        };
        let mut ops = Vec::with_capacity(before.len().max(now.len()));
        let (mut i, mut j) = (0, 0);
        for (mi, mj) in same.iter().enumerate().filter_map(|(mi, mj)| mj.map(|mj| (mi, mj))) {
            if mj < j {
                continue;
            }
            ops.extend((i..mi).map(op_of_before));
            ops.extend((j..mj).map(op_of_now));
            ops.push(Op::Same { before: number(mi), now: number(mj) });
            (i, j) = (mi + 1, mj + 1);
        }
        ops.extend((i..before.len()).map(op_of_before));
        ops.extend((j..now.len()).map(op_of_now));
        // The lines typed again: a new line equal to a gone one as text, and
        // a line matched as text, every position of either new.
        let mut went: HashMap<&K, VecDeque<usize>> = HashMap::new();
        for op in &ops {
            if let Op::Gone { before: i } = op {
                let i = index(*i);
                went.entry(&before[i].key).or_default().push_back(i);
            }
        }
        let mut retyped: Vec<Option<usize>> = vec![None; now.len()];
        let mut last: Option<usize> = None;
        for op in &ops {
            match *op {
                Op::New { now: j } => {
                    let j = index(j);
                    let pool = went.get_mut(&now[j].key).filter(|pool| !pool.is_empty() && self.all_new(&now[j]));
                    last = pool.and_then(|pool| {
                        // A block goes on with the line after the one before it.
                        let at = last.and_then(|last| pool.iter().position(|i| *i == last + 1)).unwrap_or(0);
                        pool.remove(at)
                    });
                    retyped[j] = last;
                }
                Op::Same { before: i, now: j } if by_text[index(i)] && self.all_new(&now[index(j)]) => retyped[index(j)] = Some(index(i)),
                _ => {}
            }
        }
        let mut notes = Vec::new();
        let mut whole = 0u64;
        for (j, i, count) in blocks(moved_in.iter().copied()) {
            whole += now[j..j + count].iter().map(|line| line.len).sum::<u64>();
            let (before, now) = (span(i.0, count), span(j, count));
            notes.push(if i.1 { Note::PlacedTwice { before, now } } else { Note::Moved { before, now } });
        }
        if self.bytes.moved > whole {
            notes.push(Note::MovedWithinLines { bytes: self.bytes.moved - whole });
        }
        for (j, i, count) in blocks(retyped.iter().map(|from| from.map(|i| (i, false)))) {
            if now[j..j + count].iter().map(|line| line.solid).sum::<u64>() >= MIN_KEPT_BETWEEN as u64 {
                notes.push(Note::Retyped { before: span(i.0, count), now: span(j, count) });
            }
        }
        let count = |of: fn(&Op) -> bool| ops.iter().filter(|op| of(op)).count() as u64;
        let counts = LineCounts { added: count(|op| matches!(op, Op::New { .. })), removed: count(|op| matches!(op, Op::Gone { .. })), moved: count(|op| matches!(op, Op::MovedIn { .. })) };
        let hunks = hunks(&ops, context);
        Lines { ops, hunks, notes, counts }
    }
}

/// Returns the line number of the line of index `index`: from 1.
fn number(index: usize) -> u64 {
    index as u64 + 1
}

/// Returns the index of the line numbered `number`.
fn index(number: u64) -> usize {
    (number - 1) as usize
}

/// Returns `count` lines from the index `first` as two line numbers.
///
/// They are the first line's and the last's.
fn span(first: usize, count: usize) -> (u64, u64) {
    (number(first), number(first + count - 1))
}

/// Returns the lines of `before` the pairs hold whole, by index.
///
/// Each is given with the line of `now` it stands at. A line is held
/// whole where one pair holds every position of it, its line
/// break too, and the positions of `now` the pair sets them at are exactly
/// one line of `now`.
fn whole_lines<K>(pairs: &[Pair], before: &[Line<K>], now: &[Line<K>]) -> Vec<(usize, usize)> {
    let mut lines = Vec::new();
    for pair in pairs {
        let end = pair.before.saturating_add(pair.width);
        let first = before.partition_point(|line| line.start < pair.before);
        for (i, line) in before.iter().enumerate().skip(first).take_while(|(_, line)| line.start.saturating_add(line.len) <= end) {
            let at = line.start - pair.before + pair.now;
            if let Ok(j) = now.binary_search_by_key(&at, |line| line.start) {
                if now[j].len == line.len {
                    lines.push((i, j));
                }
            }
        }
    }
    lines
}

/// Returns the blocks of a map from lines of *now* to lines of *before*.
///
/// `from` holds, for each line of *now* in order, the line of *before* it
/// is mapped from and a mark, or none. A block is a run of lines one after
/// another mapped from lines one after another under one mark: its first
/// line of *now*, its first line of *before* with the mark, and its count.
fn blocks(from: impl Iterator<Item = Option<(usize, bool)>>) -> Vec<(usize, (usize, bool), usize)> {
    let mut all: Vec<(usize, (usize, bool), usize)> = Vec::new();
    for (j, from) in from.enumerate() {
        let Some((i, mark)) = from else { continue };
        match all.last_mut() {
            Some((first, (start, same), count)) if *first + *count == j && *start + *count == i && *same == mark => *count += 1,
            _ => all.push((j, (i, mark), 1)),
        }
    }
    all
}

/// Returns the hunks of `ops`.
///
/// Each is a run of changed lines with `context` unchanged lines either
/// side, two that touch being one.
fn hunks(ops: &[Op], context: usize) -> Vec<Hunk> {
    let mut ranges: Vec<Range<usize>> = Vec::new();
    for (k, _) in ops.iter().enumerate().filter(|(_, op)| !matches!(op, Op::Same { .. })) {
        let (low, high) = (k.saturating_sub(context), ops.len().min(k.saturating_add(context).saturating_add(1)));
        match ranges.last_mut() {
            Some(last) if low <= last.end => last.end = high,
            _ => ranges.push(low..high),
        }
    }
    // The lines of each text before each hunk, and in it, by one walk.
    let (mut hunks, mut seen) = (Vec::with_capacity(ranges.len()), (0u64, 0u64));
    let mut at = 0;
    for range in ranges {
        let count = |ops: &[Op]| ops.iter().fold((0u64, 0u64), |(before, now), op| (before + u64::from(op.in_before()), now + u64::from(op.in_now())));
        let skipped = count(&ops[at..range.start]);
        seen = (seen.0 + skipped.0, seen.1 + skipped.1);
        let held = count(&ops[range.clone()]);
        hunks.push(Hunk { before: (seen.0 + u64::from(held.0 > 0), held.0), now: (seen.1 + u64::from(held.1 > 0), held.1), ops: range.clone() });
        seen = (seen.0 + held.0, seen.1 + held.1);
        at = range.end;
    }
    hunks
}

/// One line of a text, as the plan reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line<K> {
    /// The position of the line's first value in its text, from 1.
    pub start: u64,
    /// How many positions the line is, its line break among them.
    pub len: u64,
    /// The line's text, its line break left out.
    ///
    /// Two lines are equal as text where their keys are equal: a line
    /// holding a value that is no text is equal to no other, so its caller
    /// hands it a key no other line carries.
    pub key: K,
    /// Whether a line break ends the line; a text's last line may have none.
    pub closed: bool,
    /// How many characters of the line are no whitespace.
    pub solid: u64,
}

/// One line of the edit script, by line numbers from 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// A line unchanged: held by identity, or equal as text.
    Same {
        /// Its number in *before*.
        before: u64,
        /// Its number in *now*.
        now: u64,
    },
    /// A line of *before* that is gone.
    Gone {
        /// Its number in *before*.
        before: u64,
    },
    /// A line of *before* that moved, its identity kept.
    MovedOut {
        /// Its number in *before*.
        before: u64,
        /// Its number in *now*.
        now: u64,
    },
    /// A line of *now* that is new.
    New {
        /// Its number in *now*.
        now: u64,
    },
    /// A line of *now* that moved here, or stands here again, by identity.
    MovedIn {
        /// Its number in *now*.
        now: u64,
        /// The number in *before* of the line it is.
        before: u64,
    },
}

impl Op {
    /// Returns whether the op is a line of *before*.
    fn in_before(&self) -> bool {
        matches!(self, Op::Same { .. } | Op::Gone { .. } | Op::MovedOut { .. })
    }

    /// Returns whether the op is a line of *now*.
    fn in_now(&self) -> bool {
        matches!(self, Op::Same { .. } | Op::New { .. } | Op::MovedIn { .. })
    }
}

/// A run of the edit script shown together: changed lines and their context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hunk {
    /// The ops it holds, by index into [`Lines::ops`].
    pub ops: Range<usize>,
    /// Its lines of *before*: the first's number, and how many.
    ///
    /// Where it holds none, the number is the line it follows, 0 at the
    /// text's start.
    pub before: (u64, u64),
    /// Its lines of *now*, told as [`Hunk::before`] is.
    pub now: (u64, u64),
}

/// What identity shows and a diff of two texts cannot.
///
/// Each span of lines is its first and last number, from 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Note {
    /// Lines that moved, their identity kept.
    Moved {
        /// The lines in *before*.
        before: (u64, u64),
        /// The lines in *now*.
        now: (u64, u64),
    },
    /// Lines that stand here by identity and at another place of *now* too.
    PlacedTwice {
        /// The lines in *before* they are.
        before: (u64, u64),
        /// The lines in *now*.
        now: (u64, u64),
    },
    /// Lines typed again: equal as text, every position new.
    Retyped {
        /// The lines in *before* they equal.
        before: (u64, u64),
        /// The lines in *now*.
        now: (u64, u64),
    },
    /// Positions that moved, or stand again, which no whole line holds.
    MovedWithinLines {
        /// How many positions.
        bytes: u64,
    },
}

/// A change's size in lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LineCounts {
    /// The lines of *now* that are new.
    pub added: u64,
    /// The lines of *before* that are gone.
    pub removed: u64,
    /// The lines of *now* that moved here, or stand here again.
    pub moved: u64,
}

/// A change planned as lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lines {
    /// The edit script: each line of either text once, in order.
    pub ops: Vec<Op>,
    /// The hunks, ascending, none touching another.
    pub hunks: Vec<Hunk>,
    /// The notes.
    ///
    /// The moved blocks and those standing again come in the order of
    /// *now*, then the positions moved within lines, then the re-typed
    /// blocks.
    pub notes: Vec<Note>,
    /// The change's size in lines.
    pub counts: LineCounts,
}

#[cfg(test)]
mod tests;
