//! §Internal design — the pieces every link-set read shares, as M7's link
//! sets are built and walked here: the v1 slot list a per-slot read is exact
//! over, the lift of arrangement runs to the query endset M7's homes-first
//! reads take, one candidate home's probes at every v1 slot and the
//! disjunction over slots that is ASN-0127's `findlinks`, and the two
//! windowing combinators — the window over homes that pages a family's
//! candidate homes in address order, paying for `n` and the homes it passes,
//! and the key-cut within one home's share. All pure over borrowed state;
//! nothing here snapshots (callers thread ONE snapshot per operation).
//!
//! A home's share of a selection index comes back from M7 in one of two
//! shapes, and a read walks either by reference, cloning only the addresses
//! it hands back. The descriptor family's per-home answers are M7's
//! `OrdSet`s, walked with `iter`, `range` and `contains`: `im` 15's consuming
//! iterator is not a move — it copies every node it passes and clones every
//! value it yields, so `into_iter` over a set a read only looks at copies the
//! set, and `im`'s `intersection` and `relative_complement` walk their
//! ARGUMENT that way, so a large set belongs on the `contains` side of a
//! filter, never on the walked side. The region family's per-home answers
//! are M7's `(link, slot)` pairs in a `Vec`, read once through
//! [`distinct`], which moves each address out, and cut by [`Share`] where a
//! window pages them; no set is built per slot or per home, so a home that
//! holds no hit on the query costs the parts of the stab that named it and
//! nothing else.

use std::ops::Bound::{Excluded, Unbounded};

use im::OrdSet;
use skep_address::Address;
use skep_arrangement::Run;
use skep_links::{Endset, FROM, TO, TYPE};

use crate::home::{home_admitted, home_behind};
use crate::types::{Cursor, Window};

/// The slots a v1 link has: every v1 link-creation path deposits an arity-3
/// link, so a disjunction over these three is exact over ALL slots and a
/// per-home read of the three misses nothing. Nothing in M8 can check that —
/// M7's per-home stabs are per-slot and M8 owns no index — so it is stated
/// once, here, and every homes-first region read reaches the store through
/// this list.
pub(crate) const V1_SLOTS: [usize; 3] = [FROM, TO, TYPE];

/// Lifts arrangement runs to M7's query endset: each run's I-extent, whose
/// coverage holds the run's addresses and every address extending one of
/// them (the crate header's one shape).
///
/// Every homes-first region-shaped query reaches the spanfilade through
/// this reading of its I-extents. The query aggregates iextents across
/// origin documents and is therefore MIXED-LENGTH by construction; no
/// partition by level class is owed because its only consumer is M7's
/// `classify_spans` overlap, which is gate-free. Empty `runs` lift to the
/// empty endset, for which M7 names no candidate home, so an empty image
/// costs no probe.
///
/// The runs are taken as a SEQUENCE rather than a slice, because that is all
/// the lift reads: a caller whose runs are already contiguous passes the
/// `&Vec<Run>` it holds, and one whose runs come from two arrangements —
/// the preview's surviving content beside `d`'s link runs — chains M5's loan
/// on rather than copying it into a vector to be read once.
pub(crate) fn extents<'r>(runs: impl IntoIterator<Item = &'r Run>) -> Endset {
    Endset::from_spans(runs.into_iter().map(Run::iextent))
}

/// One candidate home's probes at every v1 slot: `(slot, query)` pairs, slot
/// `i` of [`V1_SLOTS`] at pair `first + i` of the walk the home's touch came
/// from — what M7's `stab_in_slots` takes, which stabs the home at each slot
/// over the spans whose directory ranges named it there, at the parts of the
/// stab those ranges stand for. A slot whose query named the home by no span
/// costs the home's stab nothing.
pub(crate) fn probes(first: usize) -> impl Iterator<Item = (usize, usize)> {
    V1_SLOTS
        .into_iter()
        .enumerate()
        .map(move |(i, slot)| (slot, first + i))
}

/// The disjunctive ASN-0127 `findlinks(I)` core: OR across a v1 link's slots
/// (M7 has no slot-collapsed primitive), over one home's `(link, slot)`
/// pairs as M7's `stab_in_slots` answers them — in address order, a link
/// once per slot it touches at — read out as the distinct links in that
/// order. A link touching at two slots follows itself, so the repeat is the
/// adjacent one; each address then moves out of the pairs once, cloned by
/// nothing.
pub(crate) fn distinct(mut pairs: Vec<(Address, usize)>) -> impl Iterator<Item = Address> {
    pairs.dedup_by(|later, earlier| later.0 == earlier.0);
    pairs.into_iter().map(|(address, _)| address)
}

/// One home's share of a selection index, in address order, as a window cuts
/// it: M7's `OrdSet` where the descriptor family answers a home, and the
/// region family's `Vec` of distinct links.
pub(crate) trait Share {
    /// The share strictly past `cursor`, in address order — a key-cut, never
    /// a lookup of the cursor — or the whole share with no cursor.
    fn past<'s>(&'s self, cursor: Option<&'s Address>) -> impl Iterator<Item = &'s Address> + 's;
}

impl Share for OrdSet<Address> {
    /// `range(Excluded(cursor)..)`: the cut BORROWS the cursor — `range`
    /// accepts any `RangeBounds`, std's borrowed `(Bound<&T>, Bound<&T>)`
    /// included, as std's ordered maps do — so the cursor is never copied to
    /// be cut at.
    fn past<'s>(&'s self, cursor: Option<&'s Address>) -> impl Iterator<Item = &'s Address> + 's {
        self.range((cursor.map_or(Unbounded, Excluded), Unbounded))
    }
}

impl Share for Vec<Address> {
    /// The suffix past the cursor, found by one binary search over the
    /// sorted share.
    fn past<'s>(&'s self, cursor: Option<&'s Address>) -> impl Iterator<Item = &'s Address> + 's {
        let from = cursor.map_or(0, |c| self.partition_point(|a| a <= c));
        self[from..].iter()
    }
}

/// THE WINDOW OVER HOMES (ASN-0108), driving both `window_v` and
/// `window_ftt`: a stateless key-cut over admitted homes in address order,
/// paying for `n` links and the homes it passes.
///
/// `homes` yields the candidate homes in address order — a `Touch`, or a
/// home the home slot or the store names — `home` reads the address off one
/// and `links` reads a home's own answer, in address order, which the walk
/// asks of the homes it admits alone and no further than it pages. A home
/// behind the cursor ([`home_behind`]) is passed unasked and unread; the
/// cursor's own home is cut strictly past the cursor by [`window_over`], and
/// every later home is taken whole, until `n` links are in hand — so resume
/// is a key-cut and never a lookup of the cursor (W8), no
/// continuously-matching link is duplicated or skipped (W4/W5), `n` is
/// clamped to ≥ 1 (W9), `exhausted = batch.len() < n` and `next` is the
/// ≺-max of the batch, else the cursor unchanged. A home the reader refuses
/// is passed before the slice and never counted against `n` (PUB-6.14).
pub(crate) fn window_homes<H, S: Share>(
    homes: impl Iterator<Item = H>,
    home: impl Fn(&H) -> &Address,
    links: impl Fn(H) -> S,
    readable: &dyn Fn(&Address) -> bool,
    cur: Cursor,
    n: usize,
) -> Window {
    let n = n.max(1);
    let mut batch: Vec<Address> = Vec::new();
    for candidate in homes {
        if cur.as_ref().is_some_and(|c| home_behind(home(&candidate), c)) {
            continue; // every link of it sorts at or before the cursor
        }
        if !home_admitted(readable, home(&candidate)) {
            continue;
        }
        let page = window_over(&links(candidate), cur.clone(), n - batch.len(), |_| true);
        batch.extend(page.batch);
        if batch.len() == n {
            break;
        }
    }
    let exhausted = batch.len() < n;
    let next = batch.last().cloned().or(cur);
    Window {
        batch,
        next,
        exhausted,
    }
}

/// THE KEY-CUT WITHIN ONE HOME (ASN-0108): a stateless cut over
/// `candidates` — one home's share of a selection index — in address order,
/// admitting those `keep` accepts, which [`window_homes`] applies to each
/// home it admits.
///
/// * Resume is [`Share::past`] the cursor — a key-cut, never an exact-match
///   scan, so the cursor survives orphaning by construction (W8), and no
///   continuously-matching link is duplicated or skipped (W4/W5).
/// * `n` is clamped to ≥ 1 (W9 totality): an unclamped `n = 0` would yield
///   `exhausted = (0 < 0) = false` with an empty batch and an unchanged
///   cursor — a silent non-terminating signal.
/// * `keep` is a post-filter over the candidate set, applied LAZILY during
///   the cut walk: a link it refuses is skipped BEFORE the slice and never
///   counted against `n`, and a narrow filter never materializes the
///   filtered set. The window over homes passes the total filter: the home
///   rule is asked of a home ahead of its links (PUB-6.14), so within an
///   admitted home nothing is refused.
/// * `exhausted = batch.len() < n` (a short window, zero included, W9);
///   `next` = the ≺-max of the batch, else the cursor unchanged.
pub(crate) fn window_over(
    candidates: &impl Share,
    cur: Cursor,
    n: usize,
    keep: impl Fn(&Address) -> bool,
) -> Window {
    let n = n.max(1);
    // The cut borrows the cursor, so it is moved into `next` when the batch
    // is empty and dropped otherwise, never copied to be cut at.
    let batch: Vec<Address> = candidates
        .past(cur.as_ref())
        .filter(|&a| keep(a))
        .take(n)
        .cloned()
        .collect();
    let exhausted = batch.len() < n;
    let next = batch.last().cloned().or(cur);
    Window {
        batch,
        next,
        exhausted,
    }
}
