//! THE BRIDGE CALL (`client.md` §4e.5; §4b.1's `search` row): `search(session
//! | guest, board, query, opts) → {hits, places, state}` as a library call on
//! the consumer. THE QUERY IS UNTRUSTED INPUT: its length is bounded at
//! [`QUERY_BOUND`] bytes (INTERIM) BEFORE the crate's `Query::parse` sees it,
//! the refusal [`QueryTooLong`] echoing nothing of it. THE PAIR is composed
//! by role (`search.md` §1.4, §5.2): `Pair::session` from the published
//! index, the principal's supplement, the supplement header's ranges and
//! the HONORED SET the discovery reads hold — the standing's three inputs
//! (§3.1), so the crate composes `Held` by prefix arithmetic and no read is
//! made — or `Pair::guest` from the published index alone; `limit` and
//! `offset` forwarded. THE TWO MATCHERS IN ONE CALL: `places`, the document
//! index's exact address and label matches, DRAWN AT THE CALL's CLASS — the
//! published part and the principal's part for a session, the published part
//! alone for the guest — each with a standing at the DOCUMENT grain: `Public`
//! from the published part, `YoursToRead` from the principal's, `Held` by
//! the same arithmetic over the header ranges, the honored set and the
//! subtree. The crate's flags — `truncated`, `more_terms`, `fuzzy_bounded`,
//! `positions_bounded` — are forwarded; `state` is THE PAIR's. PURE LOCAL: no
//! board read on the call's path (fact 10), and NO RECORD OF A SEARCH: no log
//! line, refusal detail or panic payload of this module carries the query or
//! a hit. Nothing in the answer names a file, a path or a principal's
//! directory.

use std::fmt;

use skep_address::{is_prefix, Address};
use skep_search::{Hit, Index, Kind, Pair, Prefix, Query, QueryOpts, RangeRecord, Rung, Standing, DEFAULT_LIMIT};

use crate::board::Token;

use super::consumer::{Consumer, Mount, Slot};
use super::state::State;

/// A SIGNED SESSION as the search half takes it: the token the handshake
/// answered, the principal it was opened as and the account it acts as —
/// the three facts `ceremony::handshake::Session` lends through its getters
/// (`token()`, `principal()`, `account()`), which the embedder hands in
/// here, so this module stands BESIDE the ceremonies and names none
/// (`ARCHITECTURE.md` §The client: "Nothing outside `ceremony/` names it";
/// `tests/it/tidy.rs` checks it). The token never leaves the consumer: it
/// rides the supplement's reads in `Skepd-Session` and nothing else.
#[derive(Debug, Clone, Copy)]
pub struct SessionRef<'a> {
    /// The session's token.
    pub token: &'a Token,
    /// The principal the session was opened as.
    pub principal: u64,
    /// `principal_prefix(principal)` — the account the session acts as.
    pub account: &'a str,
}

/// THE QUERY's LENGTH BOUND in bytes (`client.md` §4e.5: "an INTERIM 1,024
/// bytes").
pub const QUERY_BOUND: usize = 1024;

/// `query_too_long` — the shell's own refusal, never a wire token: the
/// query's byte length passed [`QUERY_BOUND`]. Its text names the bound and
/// the length and nothing of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryTooLong {
    /// The bound, in bytes.
    pub bound: usize,
    /// The query's length, in bytes.
    pub length: usize,
}

impl fmt::Display for QueryTooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the query is longer than the search admits ({} bytes against a bound of {})", self.length, self.bound)
    }
}

impl std::error::Error for QueryTooLong {}

/// Who searches (`client.md` §4b.1): the guest form, or a session — the
/// pair its principal names.
#[derive(Debug, Clone, Copy)]
pub enum Who<'a> {
    /// The guest form: the published index alone.
    Guest,
    /// A session: the published index and this principal's supplement.
    Session(SessionRef<'a>),
}

impl Who<'_> {
    /// The principal a session searches as; none for the guest.
    pub fn principal(&self) -> Option<u64> {
        match self {
            Who::Guest => None,
            Who::Session(s) => Some(s.principal),
        }
    }
}

/// The list's bounds (`search.md` §3.2): `limit` the rows the box shows,
/// `offset` the rows skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchOpts {
    /// The hits listed at most.
    pub limit: usize,
    /// The hits skipped before the first listed.
    pub offset: usize,
}

impl Default for SearchOpts {
    /// No offset, the crate's `DEFAULT_LIMIT` rows.
    fn default() -> SearchOpts {
        SearchOpts { limit: DEFAULT_LIMIT, offset: 0 }
    }
}

/// One of the document index's exact matches (§4e.5), with a standing at
/// the document grain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    /// The document.
    pub doc: Address,
    /// Edition or draft.
    pub kind: Kind,
    /// The document's first line, where it holds text.
    pub label: Option<String>,
    /// Who reads the document.
    pub standing: Standing,
}

/// The bridge call's answer: the crate's hits with its five facts forwarded,
/// the shell's places, and the pair's state.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchAnswer {
    /// The hits, `search.md` §3.1's contract.
    pub hits: Vec<Hit>,
    /// The matching units — exact, or a lower bound where a bound was met.
    pub total: usize,
    /// Whether more units match than the list holds.
    pub truncated: bool,
    /// Whether an expansion met its bound.
    pub more_terms: bool,
    /// Whether the fuzzy bound left a word unexpanded.
    pub fuzzy_bounded: bool,
    /// Whether the evaluation stopped at its positions bound.
    pub positions_bounded: bool,
    /// The document index's exact address and label matches at the call's
    /// class.
    pub places: Vec<Place>,
    /// The state of the pair this call searched.
    pub state: State,
}

impl Consumer<'_> {
    /// THE BRIDGE CALL (the module doc). A board the consumer holds no index
    /// for answers `State::None` and no hit; a held lock `State::Busy` and no
    /// hit; a faced file `State::NewerSkep` and no hit.
    pub fn search(&self, who: Who<'_>, query: &str, opts: &SearchOpts) -> Result<SearchAnswer, QueryTooLong> {
        if query.len() > QUERY_BOUND {
            return Err(QueryTooLong { bound: QUERY_BOUND, length: query.len() });
        }
        let state = self.state(who);
        let empty = |state: State| SearchAnswer {
            hits: Vec::new(),
            total: 0,
            truncated: false,
            more_terms: false,
            fuzzy_bounded: false,
            positions_bounded: false,
            places: Vec::new(),
            state,
        };
        if matches!(state, State::None | State::Busy | State::NewerSkep { .. }) {
            return Ok(empty(state));
        }
        let guard = self.mount.read().expect("the engines' lock");
        let Mount::Live(live) = &*guard else { return Ok(empty(state)) };
        let Slot::Engine(published) = &live.published else { return Ok(empty(state)) };
        let supplement = who.principal().and_then(|n| live.supplements.get(&n));
        let parsed = Query::parse(query);
        let query_opts = QueryOpts { offset: opts.offset, limit: opts.limit };
        let mut places: Vec<Place> = published
            .places
            .matching(query)
            .into_iter()
            .filter_map(|doc| {
                let record = published.places.get(doc)?;
                let standing = if record.kind == Kind::Draft { Standing::YoursToRead } else { Standing::Public };
                Some(Place { doc: doc.clone(), kind: record.kind, label: record.label.clone(), standing })
            })
            .collect();
        let answer = match supplement {
            Some(s) => match &s.slot {
                Slot::Engine(engine) => {
                    let honored: Vec<Prefix> = s.honored.iter().map(|h| Prefix::new(h.prefix.clone())).collect();
                    let pair = Pair::session(&published.index, &engine.index, &engine.header.ranges, &honored);
                    for doc in engine.places.matching(query) {
                        let Some(record) = engine.places.get(doc) else { continue };
                        let standing = standing_of(doc, &engine.header.ranges, &honored);
                        places.push(Place { doc: doc.clone(), kind: record.kind, label: record.label.clone(), standing });
                    }
                    Index::query(pair, &parsed, &query_opts)
                }
                _ => Index::query(Pair::guest(&published.index), &parsed, &query_opts),
            },
            None => Index::query(Pair::guest(&published.index), &parsed, &query_opts),
        };
        places.sort_by(|a, b| a.doc.cmp(&b.doc));
        places.dedup_by(|a, b| a.doc == b.doc);
        Ok(SearchAnswer {
            hits: answer.hits,
            total: answer.total,
            truncated: answer.truncated,
            more_terms: answer.more_terms,
            fuzzy_bounded: answer.fuzzy_bounded,
            positions_bounded: answer.positions_bounded,
            places,
            state,
        })
    }
}

/// THE STANDING AT THE DOCUMENT GRAIN (`client.md` §4e.5; `search.md`
/// §3.1), the shell's own arithmetic over the three inputs it holds: a
/// document of the principal's part is `YoursToRead` where a range with no
/// grant — the subtree's own or an ancestor's — covers it, or an honored
/// prefix does; else `Held` with the narrowest covering granted range's cell
/// and issuer, the rung the range's own shape; a document no range covers is
/// `YoursToRead`. No read is made.
pub(super) fn standing_of(doc: &Address, ranges: &[RangeRecord], honored: &[Prefix]) -> Standing {
    let mut departed: Option<&RangeRecord> = None;
    for range in ranges {
        let covers = range.under.as_ref().map_or(true, |under| is_prefix(under.tumbler(), doc.tumbler()));
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
    if honored.iter().any(|prefix| prefix.admits(doc)) {
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

/// A range's width for the narrowest-prefix rule: its prefix's component
/// count, the board's whole feed the widest.
fn width(range: &RangeRecord) -> usize {
    range.under.as_ref().map_or(0, |under| under.tumbler().len())
}
