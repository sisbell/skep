//! The bridge's two calls over the index (`client.md` §4e.5; A-255).
//!
//! They are `search(session | guest, board, query, opts) → {hits, places,
//! state}` (§4b.1's `search` row) and the document index's listing,
//! `places(session | guest, board, under) → {docs, counts, state}`, each a
//! library call on the consumer.
//!
//! **The query is untrusted input.** Its length is bounded at
//! [`QUERY_BOUND`] bytes (interim) before the crate's `Query::parse` sees
//! it, the refusal [`QueryTooLong`] echoing nothing of it.
//!
//! **The pair** is composed by role (`search.md` §1.4, §5.2):
//! `Pair::session` from the published index, the principal's supplement,
//! the supplement header's ranges and the honored set the discovery reads
//! hold — the standing's three inputs (§3.1), so the crate composes `Held`
//! by prefix arithmetic and no read is made — or `Pair::guest` from the
//! published index alone, for the guest and for a session whose supplement
//! is not mounted; `limit` and `offset` forwarded.
//!
//! **The two matchers in one call.** `places`, the document index's exact
//! address and label matches, is drawn at the call's class — the published
//! part and the principal's part for a session, the published part alone
//! for the guest and where no supplement is mounted — each with a standing
//! at the document grain: `Public` from the published part, save a draft
//! there, which is `YoursToRead`; `YoursToRead` from the principal's, `Held`
//! by the same arithmetic over the header ranges, the honored set and the
//! subtree. The crate's flags — `truncated`, `more_terms`, `fuzzy_bounded`,
//! `positions_bounded` — are forwarded; `state` is the pair's.
//!
//! **The listing** is the document index read whole at the call's class,
//! as `places` is drawn (foundations §2: the far scale is "drawn from the
//! client's index read whole", its counts per account "masked at the
//! reader's class", A-260): every document of the published part, and of
//! the principal's part for a session whose supplement is mounted, each
//! with the standing a match carries, narrowed to those under a prefix
//! where the call names one. The counts per account are tallied over the
//! documents listed, so the two never disagree.
//!
//! **Pure local.** No board read on either call's path (fact 10), and no
//! record of a search: no log line, refusal detail or panic payload of this
//! module carries the query or a hit. Nothing in an answer names a file, a
//! path or a principal's directory.

use std::collections::BTreeMap;
use std::fmt;

use skep_address::{is_prefix, Address};
use skep_search::{Hit, Index, Kind, Pair, Prefix, Query, QueryOpts, RangeRecord, Rung, Standing, DEFAULT_LIMIT};

use crate::board::Token;

use super::consumer::{Consumer, Mount, Slot};
use super::places::{account_of, PlaceRecord};
use super::state::State;

/// A signed session as the search half takes it.
///
/// It is the token the handshake answered, the principal it was opened as
/// and the account it acts as — the three facts `ceremony::handshake::Session`
/// lends through its getters (`token()`, `principal()`, `account()`), which
/// the embedder hands in here, so this module stands beside the ceremonies
/// and names none (`ARCHITECTURE.md` §The client: "Nothing outside
/// `ceremony/` names it"; `tests/it/tidy.rs` checks it). The token never
/// leaves the consumer: it rides the supplement's reads in `Skepd-Session`
/// and nothing else.
#[derive(Debug, Clone, Copy)]
pub struct SessionRef<'a> {
    /// The session's token.
    pub token: &'a Token,
    /// The principal the session was opened as.
    pub principal: u64,
    /// `principal_prefix(principal)` — the account the session acts as.
    pub account: &'a str,
}

/// The query's length bound in bytes.
///
/// `client.md` §4e.5: "an interim 1,024 bytes".
pub const QUERY_BOUND: usize = 1024;

/// `query_too_long` — the shell's own refusal, never a wire token.
///
/// The query's byte length passed [`QUERY_BOUND`]. Its text names the bound
/// and the length and nothing of the input.
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

/// Who searches (`client.md` §4b.1).
///
/// It is the guest form, or a session — the pair its principal names.
#[derive(Debug, Clone, Copy)]
pub enum Who<'a> {
    /// The guest form: the published index alone.
    Guest,
    /// A session: the published index and this principal's supplement.
    Session(SessionRef<'a>),
}

impl Who<'_> {
    /// Returns the principal a session searches as; none for the guest.
    pub fn principal(&self) -> Option<u64> {
        match self {
            Who::Guest => None,
            Who::Session(s) => Some(s.principal),
        }
    }
}

/// The list's bounds (`search.md` §3.2).
///
/// `limit` is the rows the box shows, `offset` the rows skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchOpts {
    /// The hits listed at most.
    pub limit: usize,
    /// The hits skipped before the first listed.
    pub offset: usize,
}

impl Default for SearchOpts {
    /// Returns no offset and the crate's `DEFAULT_LIMIT` rows.
    fn default() -> SearchOpts {
        SearchOpts { limit: DEFAULT_LIMIT, offset: 0 }
    }
}

/// One document of the document index, as a call answers it (§4e.5).
///
/// It is an exact match of [`Consumer::search`] or a document of
/// [`Consumer::places`]' listing, with a standing at the document grain.
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

/// The search call's answer.
///
/// It holds the crate's hits with its five facts forwarded, the shell's
/// places, and the pair's state.
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
    /// The document index's exact address and label matches.
    ///
    /// They are drawn at the call's class.
    pub places: Vec<Place>,
    /// The state of the pair this call searched.
    pub state: State,
}

/// The listing's answer (the module doc).
///
/// It holds every document of the document index at the call's class, the
/// counts per account over them, and the pair's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacesAnswer {
    /// The documents, in address order, each once.
    pub docs: Vec<Place>,
    /// How many of the documents listed lie under each account (A-255).
    ///
    /// The accounts are in address order.
    pub counts: BTreeMap<Address, usize>,
    /// The state of the pair this call read.
    pub state: State,
}

impl Consumer<'_> {
    /// Makes the search call (the module doc).
    ///
    /// A board the consumer holds no index for answers `State::None` and no
    /// hit; a held lock, or a resume left pending, `State::Busy` and no hit;
    /// a faced file `State::NewerSkep` and no hit.
    ///
    /// # Errors
    ///
    /// [`QueryTooLong`] where the query's byte length passes [`QUERY_BOUND`].
    ///
    /// # Panics
    ///
    /// Panics where the engines' lock is poisoned.
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
        let mut places: Vec<Place> = published.places.matching(query).into_iter().filter_map(|doc| Some(published_place(doc, published.places.get(doc)?))).collect();
        let answer = match supplement {
            Some(s) => match &s.slot {
                Slot::Engine(engine) => {
                    let honored: Vec<Prefix> = s.honored.iter().map(|h| Prefix::new(h.prefix.clone())).collect();
                    let pair = Pair::session(&published.index, &engine.index, &engine.header.ranges, &honored);
                    for doc in engine.places.matching(query) {
                        let Some(record) = engine.places.get(doc) else { continue };
                        places.push(principal_place(doc, record, &engine.header.ranges, &honored));
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

    /// Lists the document index at the call's class (the module doc).
    ///
    /// `under`, where given, keeps the documents under that prefix alone — an
    /// account's, or a document's own. A board the consumer holds no index
    /// for answers `State::None` and no document; a held lock, or a resume
    /// left pending, `State::Busy` and none; a faced file `State::NewerSkep`
    /// and none.
    ///
    /// # Panics
    ///
    /// Panics where the engines' lock is poisoned.
    pub fn places(&self, who: Who<'_>, under: Option<&Address>) -> PlacesAnswer {
        let state = self.state(who);
        let empty = |state: State| PlacesAnswer { docs: Vec::new(), counts: BTreeMap::new(), state };
        if matches!(state, State::None | State::Busy | State::NewerSkep { .. }) {
            return empty(state);
        }
        let guard = self.mount.read().expect("the engines' lock");
        let Mount::Live(live) = &*guard else { return empty(state) };
        let Slot::Engine(published) = &live.published else { return empty(state) };
        let listed = |doc: &Address| under.is_none_or(|under| is_prefix(under.tumbler(), doc.tumbler()));
        let mut docs: Vec<Place> = published.places.docs().filter(|(doc, _)| listed(doc)).map(|(doc, record)| published_place(doc, record)).collect();
        if let Some(s) = who.principal().and_then(|n| live.supplements.get(&n)) {
            if let Slot::Engine(engine) = &s.slot {
                let honored: Vec<Prefix> = s.honored.iter().map(|h| Prefix::new(h.prefix.clone())).collect();
                let ranges = &engine.header.ranges;
                docs.extend(engine.places.docs().filter(|(doc, _)| listed(doc)).map(|(doc, record)| principal_place(doc, record, ranges, &honored)));
            }
        }
        docs.sort_by(|a, b| a.doc.cmp(&b.doc));
        docs.dedup_by(|a, b| a.doc == b.doc);
        let mut counts = BTreeMap::new();
        for place in &docs {
            if let Some(account) = account_of(&place.doc) {
                *counts.entry(account).or_insert(0) += 1;
            }
        }
        PlacesAnswer { docs, counts, state }
    }
}

/// Returns a document of the published part as a [`Place`].
///
/// Its standing is `Public`, save a draft's, which is `YoursToRead`.
fn published_place(doc: &Address, record: &PlaceRecord) -> Place {
    let standing = if record.kind == Kind::Draft { Standing::YoursToRead } else { Standing::Public };
    Place { doc: doc.clone(), kind: record.kind, label: record.label.clone(), standing }
}

/// Returns a document of a principal's part as a [`Place`].
///
/// Its standing is `standing_of`'s, over the supplement's header ranges and
/// its honored set.
fn principal_place(doc: &Address, record: &PlaceRecord, ranges: &[RangeRecord], honored: &[Prefix]) -> Place {
    Place { doc: doc.clone(), kind: record.kind, label: record.label.clone(), standing: standing_of(doc, ranges, honored) }
}

/// Returns a document's standing at the document grain.
///
/// It is the shell's own arithmetic over the three inputs it holds
/// (`client.md` §4e.5; `search.md` §3.1): a document of the principal's
/// part is `YoursToRead` where a range with no grant — the subtree's own or
/// an ancestor's — covers it, or an honored prefix does; else `Held` with
/// the narrowest covering granted range's cell and issuer, the rung the
/// range's own shape; a document no range covers is `YoursToRead`. No read
/// is made.
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

/// Returns a range's width for the narrowest-prefix rule.
///
/// It is its prefix's component count, the board's whole feed the widest.
fn width(range: &RangeRecord) -> usize {
    range.under.as_ref().map_or(0, |under| under.tumbler().len())
}
