//! RANKING (`search.md` §3.3): BM25 over the UNIT with k₁ = 1.2 and b = 0.75
//! — "the standard parameters, FTS5's own pins" — its idf PINNED in the one
//! form §3.3 writes ([`idf`]), its term score as written ([`term_score`]), a
//! HIGHER score the better match, the list descending. ONE SCORE PER QUERY
//! FORM, each INTERIM as the forms are: a WORD as BM25's one term; a PHRASE
//! (an implicit one included, §3.2) as ONE COMBINED TERM, its tf the
//! phrase's occurrences in the unit and its idf the sum of its words' idf; a
//! PREFIX's expansion and a FUZZY word's candidates each as ONE COMBINED TERM
//! over the UNION of their postings — tf the occurrences summed, df the
//! units in the union, "so no unit gains by holding many completions"; a
//! CONJUNCTION as the sum of its words' scores, summed in query-word order,
//! "so floating-point summation is deterministic too". The forms' tf and df
//! are the evaluator's (`query`); this module holds the formula, the
//! statistics and the order.
//!
//! THE PAIR SCORES AS ONE CORPUS over its MERGED STATISTICS
//! ([`Statistics`]): N the units of both indexes, df(t) the sum, the average
//! length over both, "so a draft's score and an edition's are comparable and
//! the two lists merge into one ranking by score" — EXACT, since "no
//! document is two units in the pair, the published shadow unit CUT (ITEM 4)":
//! each index's live units are counted ONCE, by its own count, and never
//! again through the other member. DETERMINISTIC: the same pair and query
//! give the same scores, and TIES are broken by the one order [`order`]
//! states — document address, then member, then span start, each ascending —
//! "so one board's answer is one order on every run and behind every engine".
//! NO OTHER INPUT in v1: no recency term, no boost, no proximity term (§3.3).

use std::cmp::Ordering;

use crate::hit::Hit;
use crate::index::Index;

/// BM25's `k₁` (§3.3): 1.2, FTS5's pin.
pub const K1: f64 = 1.2;

/// BM25's `b` (§3.3): 0.75, FTS5's pin, PROPOSED against §7.1's long-unit
/// row, which measures it and BM25+ over this idf.
pub const B: f64 = 0.75;

/// THE PINNED idf (§3.3, as written): "idf(t) = ln(1 + (N − df(t) +
/// 0.5)/(df(t) + 0.5)) — positive at every df, Lucene's form, so a term or a
/// prefix's union held by most units weighs near zero (about 0.5/N at df =
/// N) and never below it". `units` is N over the pair and `df` the units of
/// the pair holding the term — or the union, for an expansion. NO FLOOR is
/// applied: the form is positive wherever df ≤ N, which the merged
/// statistics hold by construction; FTS5's floor of a non-positive idf at
/// 10⁻⁶ belongs to the Robertson–Spärck Jones form this pin declines, and
/// §3.3 names FTS5's negation and Lucene's dropped `(k₁ + 1)` as the
/// departures that change no order.
pub fn idf(units: usize, df: usize) -> f64 {
    debug_assert!(df <= units, "a df counts live units of the pair, never more than it holds");
    let n = units as f64;
    let d = df as f64;
    (1.0 + (n - d + 0.5) / (d + 0.5)).ln()
}

/// A term's score (§3.3, as written): `idf(t) · tf · (k₁ + 1) / (tf + k₁ ·
/// (1 − b + b · dl/avgdl))`, `dl` the unit's token count and `avgdl` the
/// pair's ([`Statistics::avgdl`]). Zero at `tf = 0`. Every query form is
/// scored by this one formula with its own idf and tf (the module doc).
pub fn term_score(idf: f64, tf: usize, dl: usize, avgdl: f64) -> f64 {
    if tf == 0 {
        return 0.0;
    }
    let tf = tf as f64;
    let length = if avgdl > 0.0 { dl as f64 / avgdl } else { 1.0 };
    idf * tf * (K1 + 1.0) / (tf + K1 * (1.0 - B + B * length))
}

/// THE PAIR's MERGED STATISTICS (§3.3): "N the units of both, df(t) the sum,
/// the average length over both". Each index contributes its own live counts
/// once — the published member's units are never counted again through the
/// supplement — which is exact under ITEM 4's cut: no document is two units
/// in the pair.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Statistics {
    /// N: the live units over the pair.
    pub units: usize,
    /// The live tokens over the pair — every live posting entry, one per
    /// token.
    pub tokens: usize,
    /// avgdl: the tokens per unit over the pair; zero over an empty pair.
    pub avgdl: f64,
}

impl Statistics {
    /// The statistics merged over `indexes` — the pair's members by role, or
    /// one index alone for the guest form — each counted once.
    pub fn merged<'a>(indexes: impl IntoIterator<Item = &'a Index>) -> Statistics {
        let (mut units, mut tokens) = (0usize, 0usize);
        for index in indexes {
            let stats = index.stats();
            units += stats.units;
            tokens += stats.postings;
        }
        let avgdl = if units == 0 { 0.0 } else { tokens as f64 / units as f64 };
        Statistics { units, tokens, avgdl }
    }
}

/// THE ORDER (§3.3): the score descending — a HIGHER score the better match
/// — and TIES "broken by document address, then member, then span start,
/// each ascending, so one board's answer is one order on every run and
/// behind every engine". A total order over finite scores: `f64::total_cmp`,
/// and a std `HashMap`'s per-process seed reorders nothing, since no map
/// decides it.
pub fn order(a: &Hit, b: &Hit) -> Ordering {
    b.score
        .total_cmp(&a.score)
        .then_with(|| a.doc.cmp(&b.doc))
        .then_with(|| a.member.cmp(&b.member))
        .then_with(|| a.span.start.cmp(&b.span.start))
}

#[cfg(test)]
mod tests;
