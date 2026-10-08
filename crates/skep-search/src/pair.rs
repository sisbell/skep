//! THE PAIR (`search.md` §1.4, §5.2): "the two indexes passed BY ROLE —
//! `Pair { published: &Index, supplement: Option<&Index> }` — each member
//! named for what it is, §5.2's separation visible at the call": a query runs
//! over THE PAIR THE SESSION NAMES — the board's published index and this
//! principal's supplement — or over the published index alone where no
//! session stands, the guest form (fact 4; §4's invariant (iii)). The pair is
//! a value of references the embedder composes per query; it holds no lock
//! and opens no file, so another principal's supplement is another file
//! (§5.2) and can stand in no pair but its own session's.
//!
//! Beside the two indexes the pair carries THE STANDING's INPUTS (§3.1):
//! `ranges`, the supplement header's per-range records, and `honored`, the
//! prefixes the shell's poll currently honors (R90 (b)'s discovery reads).
//! WHY HERE: a `RangeRecord` is the SHELL's fact — the `Header` it composes
//! and `load` hands back (§5.1) — and the honored set is live poll state no
//! file holds; the index records nothing of ranges, `merge` sees no range,
//! and recording a unit's range at `merge` would write the shell's fact into
//! the crate's body and change the file's layout (§5.1). The pair is where
//! the shell already names what it searches, so it names the ranges there,
//! and `Pair::standing` composes `Held` by the prefix arithmetic §3.1
//! states: a hit is `Held` where its document lies under a header range and
//! under NO prefix the honored set or the subtree admits — the subtree's own
//! and ancestors' ranges carry no grant and admit — "where several departed
//! grants cover the span, the narrowest prefix's". For the guest form both
//! are empty.
//!
//! [`QueryOpts`] bounds the list (§3.2: "`QueryOpts { limit (default 50),
//! offset }` — the embedder passes `limit` as the rows the box shows, so
//! spans and snippets are cut for the displayed hits alone"), and nothing
//! the design does not name: the three INTERIM pins are constants of
//! `query`, not options. [`Index::query`] is the one call, signed as §1.4
//! signs it.

use skep_address::is_prefix;

use crate::header::RangeRecord;
use crate::hit::{Answer, Rung, Standing};
use crate::index::{Index, Prefix};
use crate::query::{self, Bounds, Query};
use crate::unit::{Kind, Unit};

/// `limit`'s default (§3.2): 50 rows.
pub const DEFAULT_LIMIT: usize = 50;

/// The list's bounds (§3.2): the hits from `offset`, at most `limit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryOpts {
    /// The hits skipped before the first listed, in §3.3's order.
    pub offset: usize,
    /// The hits listed at most — the rows the box shows.
    pub limit: usize,
}

impl Default for QueryOpts {
    /// No offset, [`DEFAULT_LIMIT`] rows.
    fn default() -> QueryOpts {
        QueryOpts { offset: 0, limit: DEFAULT_LIMIT }
    }
}

/// THE PAIR BY ROLE (§1.4), with the standing's inputs (§3.1).
#[derive(Debug, Clone, Copy)]
pub struct Pair<'a> {
    /// The board's published index, `Guest` class.
    pub published: &'a Index,
    /// The session's principal's supplement, or none for the guest form.
    pub supplement: Option<&'a Index>,
    /// The supplement header's per-range records (`Header::ranges`): the
    /// widened ranges, each with its `under` prefix and, for a granted range,
    /// its grant's kind and issuer; the subtree's own and ancestors' ranges
    /// carry none. Empty for the guest form.
    pub ranges: &'a [RangeRecord],
    /// The prefixes the shell's poll currently honors — the honored set's
    /// granted prefixes. A document under one is never `Held`. Empty for the
    /// guest form.
    pub honored: &'a [Prefix],
}

/// Which member of the pair a unit came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Published,
    Supplement,
}

impl<'a> Pair<'a> {
    /// The guest form: the published index alone, no supplement, no ranges
    /// (§5.2; fact 4: "the guest face searches the published index alone,
    /// always, in every matcher").
    pub fn guest(published: &'a Index) -> Pair<'a> {
        Pair { published, supplement: None, ranges: &[], honored: &[] }
    }

    /// A session's pair: the published index and this principal's
    /// supplement, with the supplement's header ranges and the honored set's
    /// prefixes.
    pub fn session(
        published: &'a Index,
        supplement: &'a Index,
        ranges: &'a [RangeRecord],
        honored: &'a [Prefix],
    ) -> Pair<'a> {
        Pair { published, supplement: Some(supplement), ranges, honored }
    }

    /// The pair's members in role order: the published index, then the
    /// supplement where one stands.
    pub fn indexes(&self) -> impl Iterator<Item = &'a Index> {
        std::iter::once(self.published).chain(self.supplement)
    }

    /// THE STANDING of a unit's hit (§3.1), from the member it came from and
    /// the pair's inputs: a published member's edition is `Public`; a draft
    /// is never `Public`; a supplement's unit is `YoursToRead` where a range
    /// with no grant — the subtree's own or an ancestor's — covers its
    /// document, or an honored prefix does, else `Held` with the narrowest
    /// covering granted range's cell and issuer, the rung its shape; a unit
    /// no range covers is `YoursToRead`. No read is made.
    pub(crate) fn standing(&self, role: Role, unit: &Unit) -> Standing {
        match role {
            Role::Published => {
                if unit.kind() == Kind::Draft {
                    Standing::YoursToRead
                } else {
                    Standing::Public
                }
            }
            Role::Supplement => {
                let doc = unit.key().doc();
                let mut departed: Option<&RangeRecord> = None;
                for range in self.ranges {
                    let covers = range
                        .under
                        .as_ref()
                        .map_or(true, |under| is_prefix(under.tumbler(), doc.tumbler()));
                    if !covers {
                        continue;
                    }
                    if range.grant.is_none() {
                        return Standing::YoursToRead;
                    }
                    let narrower = departed.map_or(true, |held| width(range) > width(held));
                    if narrower {
                        departed = Some(range);
                    }
                }
                if self.honored.iter().any(|prefix| prefix.admits(doc)) {
                    return Standing::YoursToRead;
                }
                match departed.and_then(|range| range.grant.as_ref().map(|grant| (range, grant))) {
                    Some((range, grant)) => Standing::Held {
                        kind: grant.kind,
                        rung: range.under.as_ref().map_or(Rung::Account, Rung::of),
                        issuer: grant.issuer.clone(),
                    },
                    None => Standing::YoursToRead,
                }
            }
        }
    }
}

/// A range's width for the narrowest-prefix rule: its prefix's component
/// count, the board's whole feed the widest.
fn width(range: &RangeRecord) -> usize {
    range.under.as_ref().map_or(0, |under| under.tumbler().len())
}

impl Index {
    /// ONE QUERY OVER THE PAIR, BY ROLE (§1.4): "the published index and the
    /// session's supplement (§5.2), or the published index alone — ranked
    /// over their MERGED statistics (§3.3); `opts` bounds the list". The
    /// query is §3.2's one grammar parsed by `Query::parse`; the answer
    /// §3.1's, every bound a flag on it. Evaluated FROM SCRATCH at every
    /// keystroke: this call takes no earlier answer. A read of the indexes,
    /// under the embedder's read side beside `save` (§5.6).
    pub fn query(pair: Pair<'_>, q: &Query, opts: &QueryOpts) -> Answer {
        query::evaluate(&pair, q, opts, Bounds::PINNED)
    }
}

#[cfg(test)]
mod tests;
