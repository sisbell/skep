//! The change feed's publication half, which answers `GET /changes`.
//!
//! It is `commits.log` composed with its four derived sidecars, the
//! per-class mask, the supplement merge, the universal term, and the two
//! narrowings — with the attest store (`attest.rs`) beside them, whose slots
//! a page renders. The wire surface is `GET /changes` (wire.md §The change
//! feed); what this module owes it is one answer — the feed-class oracle
//! (PUB-6.59): for any class, every page equals the position walk over
//! `(since, head]` with `readable()` applied per entry and `docs` reduced,
//! masked entries omitted, `limit`/`last`/`more` over the visible stream
//! (PUB-6.44). Every structure below is a way of finding the candidates for
//! that walk at a cost the spec pins (PUB-7.19–7.35); none of them decides
//! the answer, which is the read predicate's per entry (PUB-7.20).
//!
//! # The mask (PUB-6.44–6.46)
//!
//! An entry classifies over its `docs` — the target for arrangement writes,
//! the home for link writes, the minted document for mints, and for
//! `nullify` the record's home and the target link's home as a set — never
//! over sources read. It is masked iff `docs` is non-empty and none is
//! readable to the requester; otherwise it is shown with `docs` reduced to
//! the readable ones. `[]`-docs entries (`delegate`, `register_node`) are
//! never masked. A masked entry is omitted — never present with nulled
//! fields, which is the reserved rendering of lost testimony. A bare entry
//! classifies from the journal (`classify::derived_docs`, computed by the
//! walk that reconstructs it, at the open where the index lost its
//! classification, or at the record step of a write that panicked past its
//! commit): its class is the journal's, its rendering stays the nulls.
//!
//! # The structures (PUB-7.19–7.21)
//!
//! `commits.log` (`sidecar.rs`) is the authority for what an entry says.
//! Beside it, four derived sidecars (`derived.rs`), each appended at commit
//! and held resident as its twin; and, in their line shape under a class of
//! its own, the attest store ([`AttestStore`], `attest.rs`, which states the
//! class), whose slot for a position the page renders as the entry's
//! `attest` member (`CommitMeta::entry`). The five files, `commits.log` and
//! the four derived, are compacted to the journal's reclaim floor — at open,
//! and after each checkpoint the daemon's checkpoint thread lands, the floor
//! moving at a checkpoint and at no other moment (one rewrite for both
//! moments, the second [`Feed::compact_below_reclaim_floor`]'s, under this
//! feed's lock); the attest store never (its class). The four twins:
//!
//! * the per-document position index (`index`: document → positions, keyed
//!   by tumbler, so an account's documents and any content-prefix are one
//!   contiguous key range) — the `under=` narrowing's and the universal
//!   term's source, with the per-position classification map (`docs`) as
//!   its inverse;
//! * the position → offset array (`CommitsLog::offsets`) — position-keyed
//!   access into `commits.log`; this build's reader is resident, so
//!   `CommitsLog::entries` is what answers a position and this array
//!   answers nothing. The file is what a non-resident reader would seek
//!   by, and the array is what keeps that file right;
//! * the masked-position bitmap (`masked`: positions whose docs are
//!   non-empty and all drafts at commit) and its complement, the
//!   materialized published stream (`published`), which a guest page walks
//!   in O(page). For a position the bitmap does not hold it is a skip
//!   accelerator and never the authority: the position is walked and the
//!   mask decides. For one it holds, it decides candidacy — the field's own
//!   card states that direction and the invariant it rests on;
//! * the per-owner-account draft-position streams (`streams`: owner →
//!   positions naming one of that owner's drafts — every fully-masked
//!   position plus the straddles).
//!
//! # The walk behind the listener (`operations.md` §3.3 step 2; §4 row 16)
//!
//! Two losses leave the walk work, and the open serves ahead of both. Where
//! `commits.log` was lost or torn, its open records the uncovered region
//! `(low, head]` as pending ([`FeedPending::region`]). Where `feed-index.log`
//! was lost or cut, the bare positions it no longer classifies — those the
//! log holds bare above the index's coverage, a set at or below the log's
//! coverage and no contiguous region — are recorded as pending too
//! ([`FeedPending::unsorted`]; [`Inner::unsorted`]), each owing a world
//! reconstruction the open does not pay. The four derived files are rebuilt
//! for what is classified and rewritten fenced short of every pending
//! position — the region's lower edge, the first unsorted position less one,
//! whichever is lower — and the write path then runs the walk on a thread of
//! its own ([`Feed::walk_and_land`]) while the board serves — at the open
//! instead, where the OS refuses the thread. Meanwhile a page whose rows
//! would reach a pending position is refused [`ChangesAnswer::Rebuilding`]
//! (`503 feed_rebuilding`, retry-class), pages below and above serving —
//! served, such a page would skip the set's positions in silence or, read
//! off the files that stand, carry rows a class may not see: an issuer
//! stream taken whole past [`MAX_FILTERED_PREFIXES`], a straddle's `attest`
//! — so the refusal is the one answer; a write's record enters the twins
//! and, the region pending, none of the five files, the set pending, the
//! log alone ([`Inner::fold_position`]); a checkpoint's compaction moves the
//! fence in memory and writes nothing. The walk sorts the set first, in one
//! pass with the region's walk where both pend: each position classified
//! from the journal off the world below it and its own, carried forward
//! along a run ([`BareClassifier`]), and landed as it is sorted
//! ([`Feed::land_sorted`]) — folded into the twins, the index file appended
//! up to it, so a kill mid-sort keeps the progress and the next open pends
//! the rest. Then the landing under this feed's lock ([`Feed::land`]): the
//! region's classifications folded into the twins as the record step folds
//! a position; the index, the bitmap and the streams rewritten whole from
//! the twins, the same rewrite the open and the checkpoint thread run; then
//! one rewrite of `commits.log` — the walked boundaries bare among the held
//! positions, in position order, every offset assigned — where a region
//! pended, or where a compaction deferred its rewrite to this landing; and
//! last the offset array that names its lines. So a kill between two of
//! them leaves the region to a walk behind the listener again, never to a
//! classification before the board serves; and a derived file whose
//! landing rewrite fails before its rename, short of what the walk landed,
//! takes no further line. The attest store's file is untouched, its served
//! window trimmed with the twins, its lines appended all the same and its
//! open having made the region's slots resident from its own lines and,
//! above its coverage, from the kernel's markers.
//!
//! # The supplement (PUB-7.22–7.28)
//!
//! A principal's page is the K-way merge, deduplicated by position, of: the
//! published walk; its own account's, its ancestor accounts' and its
//! descendant owner accounts' streams (the subtree clause runs both ways,
//! PUB-1.32 — its own and ancestor accounts, the subtrees that enclose it,
//! by key; the owner accounts beneath it as one key range of `streams`
//! under its account — PUB-7.24's subtree term, the price of the ancestor
//! read; a node-tier principal opens neither); its grant-selected issuer
//! streams, each under a per-entry containment test against the union of
//! that issuer's covered prefixes for this principal (an account-depth
//! grant, or a union of more than [`MAX_FILTERED_PREFIXES`], is the stream
//! whole); and the universal term, derived at serve — the position index's
//! lists under each live any-principal prefix, enumerated once per request
//! off the same head snapshot as the rest of the class. The class is
//! resolved off one head snapshot per request (PUB-6.40) — the route pins
//! it and calls [`FeedClass::of`] — and arrives at the page as
//! [`FeedClass`]; the page resolves nothing itself. Guests never merge the
//! universal term (PUB-5.109).
//!
//! # The narrowings (PUB-7.31–7.35)
//!
//! `under=<address-or-prefix>` serves off the position index with
//! doc-granular skipping — an unreadable document's whole list is skipped on
//! one test — under the merge-or-walk rule: merge the lists under the
//! prefix iff the prefix holds no more documents than the range holds
//! positions, else walk the visible stream testing the prefix per entry.
//! `drafts=true` keeps the entries whose reduced docs name a draft. On its
//! own it is served off the streams and the universal term alone — no
//! published walk, so a guest's page is empty by construction. Beside an
//! `under=` the merge rule takes, the candidates are that prefix's index
//! lists instead, published documents included, and the flag is applied by
//! the mask's own per-entry test rather than by the source set — the same
//! answer by a second route, since an entry naming no readable draft is
//! dropped either way.

mod attest;
mod derived;

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::io;
use std::num::NonZeroUsize;
use std::ops::Bound;
use std::path::Path;
use std::time::Instant;

use parking_lot::Mutex;
use serde_json::Value;
use skep_address::{is_prefix, parent, Address, Tumbler};
use skep_engine::{Engine, IssuerGrantIndexRow, ReaderClass, World};
use skep_kernel::{Attestation, HistoryError, Kernel, Seq, Snapshot};
use skep_namespace::{HasM3, PrincipalId};
use skep_util::notice::Class;

use self::attest::AttestStore;
use self::derived::{
    LineFile, OwedSync, SyncHandle, INDEX_DOCS, INDEX_FILE, MASKED_FILE, OFFSETS_FILE,
    OFFSETS_OFFSET, STREAMS_FILE, STREAMS_OWNERS,
};
#[cfg(any(test, feature = "test-hooks"))]
use super::sidecar::{fire_the_feed_walks_fault, FEED_WALK_HOLD};
use super::sidecar::{
    list_boundaries, reclaim_floor, reclaim_floor_of, reconstruct, Carrier, CommitMeta, CommitsLog,
    Cut, CutHead, FeedPending, IoCause, JournalTerms, MalformedCase, MalformedNamesLine, OpTerms,
    ProgressCadence, Recorded, RewriteFail, Unsorted, WalkControl, WalkLandingLine, WalkOpenLine,
    WalkOutcome, WalkRefusedLine,
};
use super::classify::{classify, derived_docs, parse_dotted, Doc};
use super::{Lines, Signed};
use crate::codec::append_bytes;
use crate::limits::MAX_CHANGES_PAGE_BYTES;
use crate::serial::SerialGuard;

/// The most granted prefixes [`Inner::names_under`] scans per candidate.
///
/// Past it, [`Inner::sources`] stands the filter aside and lets the mask
/// decide.
///
/// The filter is a candidate optimization and never the answer: it only
/// removes candidates from one source, the merge deduplicates, and
/// [`Inner::visible`] decides every candidate that survives — so standing it
/// aside can only widen a candidate set the mask then judges, and the page
/// does not move. That is what makes a cap here answer-preserving rather
/// than a narrowing, and it is weaker than "it drops only what the mask
/// drops", which [`Inner::names_under`] records as false.
///
/// The budget is the cost of the probe this filter precedes. `World::readable`
/// answers the grant clause by testing a document's O(depth) ancestor prefixes
/// against a prefix-keyed set; this filter walks the issuer's whole granted
/// union linearly, per candidate. Past the depth bound the linear walk costs
/// more per candidate than the indexed probe that follows it, so the filter
/// stops being an optimization and becomes a tax — and the union is a quantity
/// the issuer writes, one prefix per grant, uncapped by the fold, so a holder
/// of thousands of narrow grants would otherwise buy an O(union) scan per
/// candidate on every page, under the lock [`crate::commits::Commits`]
/// takes to record a commit. The number is M3's `MAX_PRINCIPAL_COMPONENTS`,
/// which is that depth bound, taken from M3 so the two cannot part.
const MAX_FILTERED_PREFIXES: usize = skep_namespace::MAX_PRINCIPAL_COMPONENTS;

/// The requester's feed class, resolved off one head snapshot (PUB-6.40).
///
/// The route resolves it and threads it down: the read predicate at the
/// requester's class, the stream keys its class opens, and the universal
/// term's live set. The feed evaluates it and resolves nothing of its own.
pub struct FeedClass<'a> {
    /// The requester's reader class (`None` is the guest) over the head world.
    ///
    /// Every field below stands on that world — the one snapshot the route
    /// pinned for this request — with the requester's seat looked up at most
    /// once for the whole request.
    ///
    /// [`FeedClass::of`] builds it from the request's `(world, principal)`
    /// pair and derives the stream keys below from its seat, and
    /// [`FeedClass::readable`] answers the mask off it, so a class whose mask
    /// and whose stream keys belong to different principals is not
    /// constructible — the keys would open a principal's drafts while the
    /// mask refused all of them, which fails into an emptier page with
    /// nothing to report it.
    reader: ReaderClass<'a>,
    /// The requester's enclosing subtrees: its own and its ancestor accounts.
    ///
    /// They are every account whose subtree holds the requester: the subtree
    /// clause's first compare (the requester at or beneath the owner,
    /// PUB-1.32) and PUB-7.24's "its own account's, its ancestor accounts'"
    /// streams, each a draft-stream key, O(depth). Empty for the guest and
    /// for a node-tier principal. Not PUB-7.24's subtree term, which is the
    /// requester's own subtree beneath it — the descendants',
    /// [`FeedClass::descendants_under`].
    enclosing_subtrees: Vec<Address>,
    /// The requester's own account, as the prefix of its descendants' streams.
    ///
    /// Its descendant owner accounts' streams lie under it (the subtree
    /// clause's second compare — the requester at or above the owner,
    /// PUB-1.32; PUB-7.24's subtree term, the price of the ancestor read, as
    /// RES-220 names it). A prefix and never a key list, as the universal
    /// term's are: the streams are keyed per owner account in tumbler order,
    /// so every owner account beneath this one is one contiguous key range,
    /// which [`streams_beneath`] enumerates at serve — O(descendant owner
    /// accounts), and an account beneath it that owns no draft stream costs
    /// nothing.
    ///
    /// `None` for the guest and for a node-tier principal, and the second is
    /// the read predicate's principal-0 exclusion, kept here as its twin:
    /// principal 0 is seated at a node, whose prefix contains every owner
    /// account on the board, and it is no account's ancestor for the subtree
    /// clause (PUB-1.32: excluded by name) — so it opens no descendant range.
    /// The mask would admit no entry such a range put forward that the
    /// published walk, an issuer stream or the universal term does not put
    /// forward already — a straddle, shown by its published half, or a draft
    /// a grant opens to principal 0 — so what the `None` keeps off
    /// principal 0's page is the cost, a merge of every draft stream there
    /// is, and never an answer.
    descendants_under: Option<Address>,
    /// The grant-selected issuers (`World::issuers_for`, PUB-7.25).
    ///
    /// Each is an issuing account with the union of the content prefixes it
    /// granted this principal, the issuer being the draft-stream key this
    /// clause opens.
    issuers: Vec<IssuerGrantIndexRow<'a>>,
    /// The live any-principal prefixes (`World::universal_grants`, PUB-7.22).
    ///
    /// Each is a key range over the position index, never a stream key.
    /// Empty for the guest (grants reach principals alone, PUB-5.109).
    ///
    /// The prefix alone, where the engine's row carries the issuing accounts
    /// beside it: this term needs no issuer, because the mask's own grant
    /// clause admits exactly the entries the issuing owner covers, so
    /// [`Inner::visible`] decides every candidate the prefix's index lists
    /// put forward.
    universal_prefixes: Vec<&'a Address>,
}

impl<'a> FeedClass<'a> {
    /// Returns the whole class one `(world, principal)` pair opens.
    ///
    /// It is resolved off one head snapshot (PUB-6.40): the route pins the
    /// snapshot and hands the world in, and every field's own rule is stated
    /// on the field above — which is why the resolution lives here rather
    /// than at the route, where it would restate them.
    pub fn of(world: &'a World, principal: Option<PrincipalId>) -> FeedClass<'a> {
        let reader = world.reader_class(principal);
        // The seat the mask resolves, handed out: the stream keys below and
        // the mask stand on one lookup in M3's principal registry.
        let account = reader.seat().cloned();
        let enclosing_subtrees: Vec<Address> = std::iter::successors(account.clone(), parent)
            .filter(|a| world.m3().is_registered_account(a))
            .collect();
        // The grants borrow the world rather than the account they select on,
        // so this term runs ahead of the one that consumes it.
        let issuers = account.as_ref().map(|pa| world.issuers_for(pa)).unwrap_or_default();
        // An account alone opens the descendant range — the tier test the
        // read predicate makes ahead of its second compare, so principal 0's
        // node seat opens none.
        let descendants_under = account.filter(|a| world.m3().is_registered_account(a));
        // The issuing accounts the engine hands back beside each prefix are
        // dropped at this seam, for the reason the field states.
        let universal_prefixes = match principal {
            Some(_) => world.universal_grants().into_iter().map(|g| g.content_prefix).collect(),
            None => Vec::new(),
        };
        FeedClass {
            reader,
            enclosing_subtrees,
            descendants_under,
            issuers,
            universal_prefixes,
        }
    }

    /// Returns `readable(principal, ·)` at the head: the mask (PUB-7.20).
    ///
    /// [`Inner::visible`] applies it per entry and [`Inner::sources`] applies
    /// it per document in the merge arm's skip.
    ///
    /// A method over the stored reader class rather than a closure the route
    /// hands in: the answer is a pure function of the `(world, principal)`
    /// pair the class was built from, so it costs no box and no indirect call
    /// per candidate, the requester's seat is looked up once per request
    /// rather than once per draft-homed candidate, and there is no separately
    /// supplied mask to disagree with the keys.
    fn readable(&self, doc: &Address) -> bool {
        self.reader.readable(doc)
    }
}

/// What one compaction of the feed's files did.
///
/// It is the answer of `Feed::compact_below_reclaim_floor`, read by the
/// checkpoint thread for its landing line: the fence compacted to, or `None`
/// where nothing lay below the reclaim floor and nothing was written; and,
/// beside the fence, the files that stood — each whose rewrite failed before
/// its rename, the old file whole and the next compaction trying again — by
/// name, so the line is truthful of each file. A file whose rewrite failed
/// past its rename was compacted (the new file is in place) and has said its
/// own stop; it is none of these. Empty with no fence: nothing was attempted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeedCompaction {
    /// The last position dropped, or `None` where nothing lay below the floor.
    ///
    /// The files are compacted below the position after it.
    pub fence: Option<u64>,
    /// The files whose rewrite failed before its rename, standing as they were.
    ///
    /// They are in the order the compaction attempted them.
    pub standing: Vec<&'static str>,
    /// What the walk has yet to land, whose landing the rewrite waits on.
    ///
    /// The walk behind the listener has yet to land the region, the bare
    /// positions the index lost, or both, so the fence moved in memory alone
    /// — the resident entries and the twins trimmed — and no file was
    /// written. `None` where the files were rewritten, or nothing lay below
    /// the floor.
    pub deferred: Option<FeedPending>,
}

/// What `feed-attest.log` holds, as one read of it answers.
///
/// The file is never compacted — below the reclaim floor its lines are an
/// entry signature's only copy — so it grows by one line per attested
/// commit, ~6.9 KB under tag 1, for the life of the board; the slots
/// resident are one per attested position the feed serves (~3.4 KB each),
/// trimmed with the feed's other twins at every compaction, so the journal's
/// retained window bounds them. Read by the checkpoint thread at each
/// landing, for its line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestStoreFigures {
    /// The file's size in bytes, or `None` where its metadata did not answer.
    pub bytes: Option<u64>,
    /// The marker slots held resident for the positions the feed serves.
    pub slots: usize,
}

/// One `/changes` question: the parsed query string.
///
/// Its answer is [`ChangesAnswer`].
#[derive(Clone, Debug)]
pub struct ChangesQuery {
    /// The fence: positions strictly above it.
    pub since: u64,
    /// The page cap, over the visible stream — at least one, by type.
    ///
    /// A zero cap is not a smaller page: `Feed::page` would break on the first
    /// visible candidate and answer `more: true` with `last` echoing `since`,
    /// a client told to poll again at a fence that never advances. The wire's
    /// parser refuses it (`limit: must be 1..=4096`) rather than clamping, and
    /// the type is what makes that the only answer: no constructor, the
    /// parser or a second one, can build a zero cap.
    pub limit: NonZeroUsize,
    /// `under=`: the narrowing under one tumbler (PUB-7.31).
    ///
    /// It keeps only the entries whose reduced docs name a document under
    /// this tumbler.
    pub under: Option<Tumbler>,
    /// `drafts=true`: only entries whose reduced docs name a draft (PUB-7.35).
    pub drafts_only: bool,
}

/// The answer `GET /changes` marshals.
#[derive(Debug)]
pub enum ChangesAnswer {
    /// `since` reaches below what the feed can enumerate.
    ///
    /// The test is `CommitsLog::admits_since`; `floor` is the wire's sense of
    /// the word (wire.md §Reading history: the oldest position still
    /// answerable), which is not the fence that predicate tests — the
    /// distinction, and the step between the two numbers, are
    /// `CommitsLog::floor`'s, which is what this field is filled from.
    /// Class-invariant, like every position (PUB-6.52's residue).
    Reclaimed {
        /// The oldest position still answerable, or `None` where none is.
        floor: Option<u64>,
    },
    /// The visible entries in `(since, head]`, oldest first, marshaled.
    ///
    /// The page is capped at `limit` and carried as the wire carries it
    /// (PUB-6.44): `{"changes":[…],"last":N,"more":B}`, its keys in the order
    /// [`obj`](skep_util::json::obj) sorts them — `last` the final entry's
    /// position (or `since` echoed when the page is empty), `more` whether a
    /// visible entry remains past it, and true too while the walk's pending
    /// region lies past it.
    Page {
        /// The page object's bytes, each row marshaled into them once.
        body: Vec<u8>,
    },
    /// The page byte budget (SO-I9; P29): the page asked for would pass it.
    ///
    /// Marshaled, the page the query asks for would pass
    /// [`MAX_CHANGES_PAGE_BYTES`] — so it is refused whole, never shortened
    /// (PUB-6.44: a page is never short of `limit` before the head), with the
    /// budget and `fits`, the largest `limit` whose rows from this `since`
    /// stay within it, the page object's envelope aside: the rows measured
    /// before the one that crossed. A `fits` of zero says the first row alone
    /// passes the budget — no `limit` serves this fence.
    OverBudget {
        /// The page byte budget.
        budget: usize,
        /// The largest `limit` whose rows from this `since` fit the budget.
        fits: usize,
    },
    /// The walk pending (`operations.md` §3.3 step 2; §4 row 16).
    ///
    /// The page would reach a position the walk behind the listener has yet
    /// to land: one of `(low, head]`, the positions a lost or torn
    /// `commits.log` left uncovered, or a bare position `feed-index.log`
    /// lost, unsorted — refused `503 feed_rebuilding`, retry-class as
    /// `index_rebuilding` is, under its own token. What pends rides as
    /// figures ([`FeedPending`]); the route words them and carries no member
    /// for them. `Feed::page` states the test: not only a `since` at a
    /// pending position — a page starting below one whose `limit` rows are
    /// not all below it would otherwise skip positions in silence.
    Rebuilding {
        /// What the walk has yet to land, as the open read it less what has
        /// landed since.
        pending: FeedPending,
    },
}

/// The feed: `commits.log`, the four derived twins and the attest store.
///
/// They sit under one lock.
pub(super) struct Feed {
    inner: Mutex<Inner>,
    /// The attest store's second handle, its lines' syncs made through it.
    ///
    /// The record step makes each attest line durable through it once the
    /// feed's lock is released ([`Feed::sync_the_attest_line`]).
    attest_sync: SyncHandle,
    /// The test seam's hold on the attest line's sync ([`SyncHold`]).
    #[cfg(test)]
    pub(super) attest_sync_hold: SyncHold,
}

/// A feed file stopped this uptime, with the position its stop was set at.
///
/// The file is `commits.log` or one of the four derived files, taking no
/// further line, by name; the position is the failed append's; the fence a
/// derived file's rewrite failed past its rename at, or the last entry a
/// `commits.log` rewrite failed past its rename wrote; or the region's lower
/// edge, where a landing's failed rewrite left the file short of the region
/// (each file's `stopped` field says which). It is what the standing line
/// re-says a stopped file by, once an hour while it stands (`operations.md`
/// §1 the rates, `{file} stopped since position {p}`); the attest store is
/// never among them — its stop halts the write path, which the halt's own
/// clause carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoppedFile {
    /// The file's name, as its own lines name it.
    pub name: &'static str,
    /// The position the stop was set at, which the file's own stop line names.
    ///
    /// It is an ordering (`operations.md` §1, the joins).
    pub since: u64,
}

/// The attest store's failure (SO-I5 (d)): a line it could not make durable.
///
/// The line is [`AttestStore::record`]'s — its write failed, said once on
/// the operator stream there, or its sync, said by
/// [`AttestStore::sync_failed`] — and the failure is answered through
/// [`Feed::record`] or [`Feed::record_bare`] to the write path, which refuses
/// every later write for the uptime on it. The attest store's alone: a
/// derived file's failed append is reported and fails no op (P22), so it is
/// never answered as this.
#[derive(Debug)]
pub(super) struct AttestStoreFailed;

struct Inner {
    log: CommitsLog,
    /// Position → its classified docs (positions with docs only).
    ///
    /// It is the index's inverse, and what the mask reads per entry.
    docs: BTreeMap<u64, Vec<Doc>>,
    /// The position index: document → the address as named, and its positions.
    ///
    /// A document is keyed by tumbler, so a prefix is a range; its positions
    /// are ascending, which is what makes [`at_or_above`]'s `partition_point`
    /// meaningful over a list of them.
    ///
    /// Three construction paths establish it. At [`Feed::open`] the lists
    /// are built by iterating [`Inner::docs`], a `BTreeMap`, so the
    /// container supplies the order. At [`Inner::fold_position`] they are
    /// pushed, and the order comes from the write path: positions are
    /// recorded under the serialization guard
    /// ([`crate::commits::Commits::commit_recorded`], which both of the
    /// write path's doors run, executes and records as one operation under
    /// it), so each push is strictly above every prior one. At the walk's
    /// landings ([`Feed::land_sorted`], [`Feed::land`]) a position lands
    /// below the ones recorded above the head while the walk ran, and
    /// [`push_in_order`] places it ahead of them, each list holding a
    /// position once.
    index: BTreeMap<Tumbler, (Address, Vec<u64>)>,
    /// The bitmap: positions masked at commit (docs non-empty, all drafts).
    ///
    /// The invariant its use rests on: every member has a non-empty entry in
    /// [`Inner::docs`]. [`Inner::fold_position`] establishes it, one
    /// classification deciding both. The replay does not: this set is seeded
    /// from `feed-masked.log` and `docs` from `feed-index.log`,
    /// independently.
    ///
    /// Where the two disagree this set decides the guest's page, because
    /// [`Inner::published`] is exactly its complement and a guest has no
    /// other source: a member the classification has nothing for is excluded
    /// from the published walk and absent from the index (which `docs`
    /// builds), so a guest never sees it — where [`Inner::visible`], reading
    /// it as a `[]`-docs entry, would show it to every class. A principal
    /// may still reach it, since the streams are seeded from
    /// `feed-streams.log` rather than from `docs`.
    ///
    /// No live commit produces that disagreement, and the two shapes that
    /// could are edge: a `commits.log` line demoted for malformed names,
    /// whose entry is then bare and discloses its position alone either way,
    /// and an edited file. Not filtered against `docs` at open on purpose —
    /// the filter is a change to which entries a class sees, taken off a
    /// file this daemon did not write.
    masked: BTreeSet<u64>,
    /// The materialized published stream: every entry not in `masked`.
    published: BTreeSet<u64>,
    /// Owner account → the positions naming one of its drafts, ascending.
    ///
    /// It is the one position collection built from a file's own sequence:
    /// `masked` and `published` are `BTreeSet`s and [`Inner::index`] takes
    /// its replay order from `docs`, a `BTreeMap`, while this is pushed — in
    /// file order at replay, in position order at the record
    /// ([`Inner::index`]'s second path, and the same guard), and below the
    /// window's positions at the walk's landings (its third, through
    /// [`push_in_order`]). [`Feed::open`] sorts the replayed half, which is
    /// what establishes the invariant [`at_or_above`]'s `partition_point`
    /// reads.
    streams: BTreeMap<Address, Vec<u64>>,
    /// The bare positions `feed-index.log` lost that the walk has yet to sort.
    ///
    /// They are the positions the log holds bare above the index file's
    /// coverage that no surviving index record classifies — each at or below
    /// the log's coverage, a set and no region, read at [`Feed::open`] and
    /// never classified there — the module doc's second pending state. While
    /// a position stands here it is in no twin: not in [`Inner::docs`],
    /// [`Inner::masked`], [`Inner::published`] or [`Inner::streams`], and
    /// [`Inner::visible`] shows it to no class; a page that would reach it
    /// is refused ([`Inner::first_pending_above`]); the four files take no
    /// line ([`Inner::fold_position`]), fenced below its first member. The
    /// walk sorts them ascending and each leaves as it lands
    /// ([`Feed::land_sorted`]); a compaction drops the ones the journal
    /// reclaimed ([`Inner::drop_at_or_below`]).
    unsorted: BTreeSet<u64>,
    /// Whether the walk has yet to land what the open left pending.
    ///
    /// Set at [`Feed::open`] where a region or a set pends, cleared at the
    /// end of [`Feed::land`], once the four files are rewritten whole. It
    /// outlasts the set: the last position sorted leaves the set before the
    /// landing's rewrite, and a line a file took in that window — the four
    /// standing fenced below the set — would raise its claim over the
    /// positions sorted since, so the record step appends to no file while
    /// this stands ([`Inner::fold_position`]), a compaction writes nothing
    /// ([`Inner::pends`]), and a suite that waits on the landing waits on
    /// this (`Feed::walk_pending`).
    landing_owed: bool,
    /// The attest store, on its own card ([`AttestStore`]).
    ///
    /// Its class keeps it out of `files` and out of every rewrite here; its
    /// served window is trimmed beside the twins ([`Inner::drop_at_or_below`]),
    /// its file never. Read per rendered entry by [`Feed::page`], the one
    /// consumer.
    attest: AttestStore,
    files: Files,
}

/// The four derived sidecars' files.
///
/// They are the ones [`Feed::open`]'s compaction rewrites; the attest store
/// keeps its own.
struct Files {
    index: LineFile,
    offsets: LineFile,
    masked: LineFile,
    streams: LineFile,
}

impl Feed {
    /// Opens the feed over `dir`, replaying its files and closing their tails.
    ///
    /// It replays `commits.log` (recording its uncovered tail as the region
    /// pending, below), replays the four derived sidecars, re-derives each
    /// one's missing tail from `commits.log` — a recorded position's
    /// contribution from its own record; a bare position the index no longer
    /// classifies is the walk's, recorded as pending (below), never
    /// classified here — and fences each at the head, or short of the first
    /// pending position where any pends; then opens the attest store
    /// ([`AttestStore::open`]). Runs after M2's load-and-replay and before
    /// the first page (PUB-6.40): every classification here reads the
    /// recovered head's exception set, and the grant fold it stands beside
    /// is seeded by the same load.
    ///
    /// **Cost.** The `commits.log` replay, whose cost `CommitsLog::open`
    /// states — the walk is not the open's, nor is any world reconstruction:
    /// a bare position the index lost is sorted behind the listener — plus
    /// O(each derived file) to replay it and O(its missing tail) to close
    /// it, a whole-file loss being one O(the log) rebuild of what the log's
    /// records classify, and the attest store's own open, whose cost
    /// [`AttestStore::open`] states. Never a rewrite per restart: a derived
    /// file is rewritten only when the log compacted under it, when it
    /// carries another journal's lines, while the walk has a region or a set
    /// pending (below), or (the offset array) when its offsets no longer
    /// match the log's.
    ///
    /// **The lines** (`operations.md` §1.1 rows 9, 11, 2), through `lines`,
    /// the classed door the write path made ahead of this open: a derived
    /// file's cut, answered by its replay, is said here with the last trusted
    /// position and that the cut part is re-derived ([`DerivedCutLine`]);
    /// the index file's malformed names are counted and said once with the
    /// first position and how many of them are bare, which no testimony
    /// rescues ([`MalformedNamesLine`]); what the compaction dropped below
    /// the reclaim floor is said once the derived files follow the log
    /// ([`OpenCompactionLine`]); and the open ends on how far back `/changes`
    /// answers, what waits on the walk, and how long the open took
    /// ([`FeedOpenLine`]). The bare positions the index lost are the walk
    /// thread's to say (`operations.md` §1.1 m15; [`Feed::walk_and_land`]).
    ///
    /// **What pends** (the module doc's walk): where the log's open found
    /// positions it does not cover, or the index's replay left bare positions
    /// of the log's unclassified, the four derived files are rebuilt for
    /// what is classified and rewritten fenced short of the first pending
    /// position — the region's lower edge or the first unsorted position
    /// less one, whichever is lower: an honest coverage claim, so a crash
    /// before the landing, or a derived rewrite the landing cannot make,
    /// leaves no file claiming over positions it never processed (the
    /// derived card's gap rule), the next open re-deriving from that fence —
    /// the set's positions enter no twin ([`Inner::unsorted`]), and the
    /// open's snapshot of the head's world is answered beside the feed, for
    /// the walk to diff from and the landings to classify against (PUB-7.7's
    /// one-snapshot clause: the head's exception set as the open read it);
    /// `None` where the log covers the head and the index every bare
    /// position it holds.
    ///
    /// # Errors
    ///
    /// Every failure of the open, which names its file, the kind kept — the
    /// replays' and the attest store's at their own opens, this open's
    /// appends, fences and rewrites through one closure per file here. A
    /// rewrite is fatal either side of its rename, and the first file whose
    /// rewrite failed is the one answered.
    pub(super) fn open(
        dir: &Path,
        engine: &Engine,
        lines: &Lines,
    ) -> io::Result<(Feed, Option<Snapshot<World>>)> {
        let started = Instant::now();
        let log = CommitsLog::open(dir, engine, lines)?;
        let head = log.open_head();
        let pending = log.pending_region();
        let snap = engine.kernel().snapshot();
        let world = snap.world();

        // Every line of the four is held: each is bounded by the journal's
        // retention, compacted below when the log was, and the offset array's
        // agreement test reads every entry, the ones the log no longer holds
        // included. A cut is each file's own to say: re-derived, below.
        // A derived file's lines past the head are re-derived too, so the
        // replay's report of them is not said.
        let (mut f_index, index_entries, replayed) =
            LineFile::open(dir, INDEX_FILE, head, |_| true, lines)?;
        say_derived_cut(lines, INDEX_FILE, replayed.cut);
        let (mut f_offsets, offset_entries, replayed) =
            LineFile::open(dir, OFFSETS_FILE, head, |_| true, lines)?;
        say_derived_cut(lines, OFFSETS_FILE, replayed.cut);
        let (mut f_masked, masked_entries, replayed) =
            LineFile::open(dir, MASKED_FILE, head, |_| true, lines)?;
        say_derived_cut(lines, MASKED_FILE, replayed.cut);
        let (mut f_streams, stream_entries, replayed) =
            LineFile::open(dir, STREAMS_FILE, head, |_| true, lines)?;
        say_derived_cut(lines, STREAMS_FILE, replayed.cut);

        // ── the classification map: the index file's entries for positions
        //    the log holds, then the index's tail, a recorded position from
        //    its record and a bare one from the journal ──
        let mut docs: BTreeMap<u64, Vec<Doc>> = BTreeMap::new();
        // The index file's malformed names, counted for one line after the
        // read: the positions met, the bare ones among them, and the first.
        let mut malformed: Option<(usize, usize, u64)> = None;
        for (at, m) in &index_entries {
            let Some(meta) = log.entries().get(at) else { continue };
            // Counted against what the file claimed, not against what could
            // be read out of it: an element that is not a string is one
            // malformed name like any other, and dropping it ahead of this
            // count is what would let a short list pass the test below.
            let named = elements_of(m.get(INDEX_DOCS));
            let addrs: Vec<Address> =
                named.iter().filter_map(Value::as_str).filter_map(parse_dotted).collect();
            let addrs = if addrs.len() == named.len() {
                addrs
            } else {
                // A derived record this daemon cannot parse. Never trusted
                // over the authority file — that is the derived layer's
                // whole standing — so a recorded position answers from its
                // own testimony instead, which `CommitsLog` stands behind
                // (its entries are checked at its own open); a bare one has
                // none, and stays unclassified, which is the residue it
                // already carries. Accepting the short list would mask the
                // position by a smaller set than the write touched, and
                // accepting an empty one would make it a `[]`-docs entry,
                // which is never masked.
                let (count, bare, first) = malformed.unwrap_or((0, 0, *at));
                let (addrs, is_bare) = match meta {
                    CommitMeta::Recorded { docs: authority, .. } => {
                        (authority.iter().filter_map(|s| parse_dotted(s)).collect(), false)
                    }
                    CommitMeta::Bare { .. } => (Vec::new(), true),
                };
                malformed = Some((count + 1, bare + usize::from(is_bare), first.min(*at)));
                addrs
            };
            if !addrs.is_empty() {
                docs.insert(*at, classify(world, addrs));
            }
        }
        if let Some((positions, bare, first)) = malformed {
            let case = MalformedCase::Index { bare };
            let line = MalformedNamesLine { file: INDEX_FILE, positions, first, case };
            lines.say(Class::Failure, line);
        }
        // The index's tail: a recorded position is classified from its own
        // record here — every name reads, `CommitsLog` having demoted the
        // recorded positions whose did not — and a bare one the index lost
        // is the walk's, the set it sorts behind the listener (the module
        // doc), a world reconstruction each that the open does not pay.
        let mut unsorted: BTreeSet<u64> = BTreeSet::new();
        for (&at, meta) in log.entries().range(f_index.first_uncovered()..) {
            if docs.contains_key(&at) {
                continue;
            }
            match meta {
                CommitMeta::Recorded { docs: strings, .. } => {
                    let addrs: Vec<Address> =
                        strings.iter().filter_map(|s| parse_dotted(s)).collect();
                    if !addrs.is_empty() {
                        docs.insert(at, classify(world, addrs));
                    }
                }
                CommitMeta::Bare { .. } => {
                    unsorted.insert(at);
                }
            }
        }
        // The coverage the open closes the four files at: the head; the
        // region's lower edge where the walk has the rest to land; and
        // short of the first unsorted position where the set pends,
        // whichever is lower — no file claims over a position the walk has
        // yet to land.
        let covered = pending.map_or(head, |(low, _)| low);
        let covered =
            unsorted.first().map_or(covered, |&first| covered.min(first.saturating_sub(1)));
        // The four files are rewritten whole below where the log compacted
        // under them or anything pends; else each takes its tail's lines and
        // its fence here.
        let rewriting = log.rewritten() || pending.is_some() || !unsorted.is_empty();
        if !rewriting {
            for (&at, ds) in docs.range(f_index.first_uncovered()..) {
                f_index
                    .append(at, vec![(INDEX_DOCS, doc_strings(ds))])
                    .map_err(with_file(INDEX_FILE))?;
            }
            f_index.fence(covered).map_err(with_file(INDEX_FILE))?;
        }

        // ── the position index twin, from the classification map ──
        let mut index: BTreeMap<Tumbler, (Address, Vec<u64>)> = BTreeMap::new();
        for (at, ds) in &docs {
            for d in ds {
                let list = index
                    .entry(d.addr.tumbler().clone())
                    .or_insert_with(|| (d.addr.clone(), Vec::new()));
                if list.1.last() != Some(at) {
                    list.1.push(*at);
                }
            }
        }

        // ── the bitmap, and its complement ──
        //
        // An unsorted position enters neither: it is in no twin until the
        // walk lands it ([`Inner::unsorted`]), whatever a file that stood
        // claimed of it.
        let mut masked: BTreeSet<u64> = masked_entries
            .iter()
            .map(|(at, _)| *at)
            .filter(|at| log.entries().contains_key(at) && !unsorted.contains(at))
            .collect();
        for (&at, _) in log.entries().range(f_masked.first_uncovered()..) {
            if unsorted.contains(&at) {
                continue;
            }
            if masked_at_commit(docs.get(&at).map(Vec::as_slice).unwrap_or(&[])) {
                masked.insert(at);
                if !rewriting {
                    f_masked.append(at, vec![]).map_err(with_file(MASKED_FILE))?;
                }
            }
        }
        if !rewriting {
            f_masked.fence(covered).map_err(with_file(MASKED_FILE))?;
        }
        let published: BTreeSet<u64> = log
            .entries()
            .keys()
            .copied()
            .filter(|at| !masked.contains(at) && !unsorted.contains(at))
            .collect();

        // ── the per-owner draft streams ──
        //
        // An owner name this daemon cannot parse is dropped here, and that is
        // the safe direction: the position leaves that owner's stream, so
        // their supplement is short by it and nothing is unmasked. The index
        // above cannot be lossy in the same way — a dropped document shortens
        // the class the mask is computed over — which is why that read
        // refuses a half-record and this one does not.
        let mut streams: BTreeMap<Address, Vec<u64>> = BTreeMap::new();
        for (at, m) in &stream_entries {
            if !log.entries().contains_key(at) || unsorted.contains(at) {
                continue;
            }
            for owner in elements_of(m.get(STREAMS_OWNERS))
                .iter()
                .filter_map(Value::as_str)
                .filter_map(parse_dotted)
            {
                let stream = streams.entry(owner).or_default();
                if stream.last() != Some(at) {
                    stream.push(*at);
                }
            }
        }
        // The replay above pushed in file order, which establishes nothing:
        // this map's lists are ascending by invariant, which is what makes
        // [`at_or_above`]'s `partition_point` meaningful and what the
        // consecutive-repeat dedup above rests on. `index` takes its order
        // from `docs`, a `BTreeMap`, and `masked` and `published` are
        // `BTreeSet`s, so this is the one collection built from a file's own
        // sequence and this is where its gate is closed rather than
        // inherited. The tail below appends strictly above every replayed
        // entry (coverage is at least every replayed position), in ascending
        // order, so it preserves what this establishes.
        for positions in streams.values_mut() {
            positions.sort_unstable();
            positions.dedup();
        }
        for (&at, _) in log.entries().range(f_streams.first_uncovered()..) {
            if unsorted.contains(&at) {
                continue;
            }
            let owners = owners_of(docs.get(&at).map(Vec::as_slice).unwrap_or(&[]));
            if !owners.is_empty() {
                for owner in &owners {
                    streams.entry(owner.clone()).or_default().push(at);
                }
                if !rewriting {
                    f_streams
                        .append(at, vec![(STREAMS_OWNERS, addr_strings(&owners))])
                        .map_err(with_file(STREAMS_FILE))?;
                }
            }
        }
        if !rewriting {
            f_streams.fence(covered).map_err(with_file(STREAMS_FILE))?;
        }

        // ── the offset array, checked against the log's own replay ──
        //
        // `!log.rewritten()` is this file's half of compaction as well as its
        // agreement test: a compacted log moved every offset, so the file is
        // rewritten below — with the other three where the log compacted or
        // anything pends, alone where the log stands, nothing pends, and its
        // offsets merely disagree.
        let offsets_agree = !log.rewritten()
            && offset_entries.iter().all(|(at, m)| {
                m.get(OFFSETS_OFFSET).and_then(Value::as_u64)
                    == log.offsets().get(at).map(|o| o.0)
            });
        if offsets_agree && !rewriting {
            for (&at, &offset) in log.offsets().range(f_offsets.first_uncovered()..) {
                f_offsets
                    .append(at, vec![(OFFSETS_OFFSET, Value::Number(offset.0.into()))])
                    .map_err(with_file(OFFSETS_FILE))?;
            }
            f_offsets.fence(covered).map_err(with_file(OFFSETS_FILE))?;
        }

        // ── the attest store, on its own card, and the handle its lines are
        //    made durable through ──
        let (attest, attest_sync) = AttestStore::open(dir, engine, &log, lines)?;

        // ── compaction: the log dropped what the journal reclaimed, so the
        //    derived files drop it too, rewritten from the twins — the same
        //    rewrite the checkpoint thread runs after each checkpoint lands
        //    (`Feed::compact_below_reclaim_floor`), through the same method,
        //    the four files at once; or the offset array alone, where the
        //    log stands and its offsets disagree; or, anything pending, the
        //    four fenced short of the first pending position whatever they
        //    claimed, each record above that fence left out — a file fenced
        //    over positions it never processed would read them as
        //    contributing nothing at the next open, a draft write unmasked,
        //    where the walk's landing then cannot rewrite it. A fifth derived
        //    file belongs in one of that method's two halves, which the
        //    walk's landing calls apart; the attest store is not one, and
        //    `Files` does not hold it. Fatal here, either side of a rename:
        //    nothing is served yet — the bare I/O error wrapped with the
        //    file's name, which `RewriteFail::into_io` does not carry. ──
        let landing_owed = pending.is_some() || !unsorted.is_empty();
        let mut inner = Inner {
            log,
            docs,
            index,
            masked,
            published,
            streams,
            unsorted,
            landing_owed,
            attest,
            files: Files {
                index: f_index,
                offsets: f_offsets,
                masked: f_masked,
                streams: f_streams,
            },
        };
        let failures = if rewriting {
            inner.rewrite_derived_files(covered)
        } else if !offsets_agree {
            inner.rewrite_offsets_file(covered, false)
        } else {
            Vec::new()
        };
        if let Some(unwritten) = failures.into_iter().next() {
            return Err(with_file(unwritten.name)(unwritten.failed.into_io()));
        }
        if let Some((floor, dropped)) = inner.log.compacted_at_open() {
            lines.say(Class::Open, OpenCompactionLine { floor, dropped });
        }
        let pending = inner.pending();
        let entries = inner.log.entries();
        let reach = FeedOpenLine {
            floor: inner.log.floor(),
            head,
            entries: entries.len(),
            bare: entries.values().filter(|m| matches!(m, CommitMeta::Bare { .. })).count(),
            pending,
            elapsed_ms: started.elapsed().as_millis(),
        };
        lines.say(Class::Open, reach);
        let feed = Feed {
            inner: Mutex::new(inner),
            attest_sync,
            #[cfg(test)]
            attest_sync_hold: SyncHold::new(),
        };
        Ok((feed, (!pending.is_empty()).then_some(snap)))
    }

    /// Returns what the attest store holds ([`AttestStoreFigures`]).
    ///
    /// Read under the feed's lock and no guard.
    pub(super) fn attest_store_figures(&self) -> AttestStoreFigures {
        self.inner.lock().attest.figures()
    }

    /// Returns the region pending, as a read under the feed's lock.
    ///
    /// It is `CommitsLog::pending_region`: `(low, head]`, or `None` where the
    /// log covered the head at open, or once the walk has landed.
    pub(super) fn pending_region(&self) -> Option<(u64, u64)> {
        self.inner.lock().log.pending_region()
    }

    /// Returns what the walk has yet to land, as figures, under the feed's lock.
    ///
    /// It is the region and the bare positions the index lost that stand
    /// unsorted ([`FeedPending`]), as they stand now: the set shrinks as the
    /// walk lands each position ([`Feed::land_sorted`]), and a compaction
    /// drops what the journal reclaimed. Empty once everything has landed.
    pub(super) fn pending(&self) -> FeedPending {
        self.inner.lock().pending()
    }

    /// The test seam behind `skepd::Daemon::feed_pending_set`.
    ///
    /// It answers the bare positions the index lost that the walk has yet to
    /// sort, ascending — the feed's own read, under its lock and no guard.
    /// Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn pending_set(&self) -> Vec<u64> {
        self.inner.lock().unsorted.iter().copied().collect()
    }

    /// The test seam behind `skepd::Daemon::feed_walk_pending`.
    ///
    /// It answers whether the walk has yet to land what the open left
    /// pending — the region, the set, or the landing's own rewrite of the
    /// files once every position is sorted ([`Inner::landing_owed`]) — the
    /// feed's own read, under its lock and no guard: what a suite waits on
    /// before it reads the landed files. Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn walk_pending(&self) -> bool {
        self.inner.lock().pends()
    }

    /// Walks what pends and lands it: the walk behind the listener.
    ///
    /// It is the thread's body, less the catch, which the write path puts
    /// around it (`operations.md` §3.3 step 2; §1.1 m15). What pends is read
    /// once under the lock — the region, and the set with the entry below
    /// each of its positions ([`ToSort`]). Then the `open:` lines: the
    /// region's with the count of the kernel's one scan ([`list_boundaries`];
    /// [`WalkOpenLine`]) and the journal's refusal of the list where it met
    /// one ([`WalkRefusedLine`]); the set's with its count and the world
    /// reconstructions it will pay ([`BareClassificationLine`]). Then the
    /// hold and the fault (test seams), after the lines and before the first
    /// position or boundary. Then the sort of the set ([`Feed::sort`]), each
    /// position landed as it is sorted, and the walk over the region
    /// ([`reconstruct`]: the `progress:` lines) off `kernel` and the open's
    /// `snapshot` of the head's world — one pass where both pend — and the
    /// landing ([`Feed::land`]). Returns with nothing further written where
    /// the stop was asked before the landing, or where nothing pends.
    ///
    /// # Panics
    ///
    /// Panics where the walk's fault is armed (a test seam): after the hold
    /// and before the first position or boundary, so a suite drives the
    /// thread's catch.
    pub(super) fn walk_and_land(
        &self,
        kernel: &Kernel<World>,
        snapshot: &Snapshot<World>,
        control: &WalkControl,
        lines: &Lines,
    ) {
        let started = Instant::now();
        let (region, to_sort, index_coverage) = {
            let inner = self.inner.lock();
            let to_sort: Vec<ToSort> = inner
                .unsorted
                .iter()
                .map(|&at| ToSort {
                    at,
                    below: inner.log.entries().range(..at).next_back().map_or(0, |(k, _)| *k),
                })
                .collect();
            (inner.log.pending_region(), to_sort, inner.files.index.coverage())
        };
        if region.is_none() && to_sort.is_empty() {
            // Nothing left to walk — a compaction dropped the set before the
            // walk read it — and the landing still owed: the files rewritten
            // whole, the record step freed.
            self.land(None, None, kernel, snapshot.world(), control, lines);
            return;
        }
        // The region's list, one scan, said ahead of the hold with the
        // journal's refusal of the list where it met one.
        let listing = region.map(|(low, head)| {
            let listing = list_boundaries(kernel, low, head);
            let boundaries = listing.boundaries.len();
            lines.say(Class::Open, WalkOpenLine { covered: low, boundaries, head });
            if let Some(refusal) = &listing.refusal {
                let fence = listing.min_since.unwrap_or(low);
                lines.say(Class::Failure, WalkRefusedLine { refusal, fence });
            }
            listing
        });
        // The set's count, said ahead of its cost: a world reconstruction a
        // position, one more below each run of them, none at the head
        // ([`BareClassifier`] carries a run's worlds forward).
        if !to_sort.is_empty() {
            let head = snapshot.seq().0;
            let mut planned = 0usize;
            let mut sorted_before: Option<u64> = None;
            for item in &to_sort {
                let follows_a_run = sorted_before == Some(item.below);
                planned += usize::from(!follows_a_run) + usize::from(item.at != head);
                sorted_before = Some(item.at);
            }
            let line = BareClassificationLine {
                coverage: index_coverage,
                positions: to_sort.len(),
                reconstructions: planned,
            };
            lines.say(Class::Open, line);
        }
        #[cfg(any(test, feature = "test-hooks"))]
        {
            FEED_WALK_HOLD.wait_at(0, control);
            if control.stopped() {
                return;
            }
            fire_the_feed_walks_fault();
        }
        let sorted = if to_sort.is_empty() {
            None
        } else {
            match self.sort(kernel, snapshot, &to_sort, control, lines) {
                Some(figures) => Some(figures),
                None => return,
            }
        };
        let outcome = match listing {
            Some(listing) => {
                match reconstruct(kernel, snapshot.world(), listing, started, lines, control) {
                    Some(outcome) => Some(outcome),
                    None => return,
                }
            }
            None => None,
        };
        self.land(outcome, sorted, kernel, snapshot.world(), control, lines);
    }

    /// Sorts the bare positions the index lost, landing each as it is sorted.
    ///
    /// Each position is classified from the journal off the world at the
    /// entry below it and its own ([`BareClassifier`]: a run of them shares
    /// its worlds, so the run costs one reconstruction a position and one
    /// below its first, and the head's world is the open's `snapshot`), and
    /// landed at once under the feed's lock ([`Feed::land_sorted`]) — the
    /// twins take it, the index file is appended up to it — so a kill
    /// mid-sort keeps every position sorted so far and the next open pends
    /// the rest. The `progress:` line comes at the cadence
    /// ([`BareClassifyingLine`]: every so many positions or so long,
    /// whichever first, the figures `control` holds); the journal's refusals
    /// are counted and said once after the pass, the first in the kernel's
    /// words ([`ClassificationRefusedLine`]), each refused position landed
    /// unclassified — served to every class, its position alone, the module
    /// doc's residue. A position a compaction dropped from the set meanwhile
    /// — the journal reclaimed it — is passed over, neither classified nor
    /// counted. Answers the figures the landing line says ([`SortFigures`]);
    /// `None` where the stop was asked, the positions landed so far
    /// standing. The hold (a test seam) parks the walk after the k-th
    /// position where armed for it.
    fn sort(
        &self,
        kernel: &Kernel<World>,
        snapshot: &Snapshot<World>,
        to_sort: &[ToSort],
        control: &WalkControl,
        lines: &Lines,
    ) -> Option<SortFigures> {
        let started = Instant::now();
        let mut classifier = BareClassifier::new(kernel, snapshot);
        let mut cadence = ProgressCadence::new();
        let mut refused: Option<(usize, u64, String)> = None;
        let mut attempted = 0usize;
        let mut items = to_sort.iter().peekable();
        while let Some(item) = items.next() {
            if control.stopped() {
                return None;
            }
            if !self.inner.lock().unsorted.contains(&item.at) {
                continue;
            }
            attempted += 1;
            let docs = match classifier.classify(item.at, item.below) {
                Ok(addrs) => Some(addrs),
                Err(e) => {
                    refused = Some(match refused {
                        None => (1, item.at, e.to_string()),
                        Some((n, first, account)) => (n + 1, first, account),
                    });
                    None
                }
            };
            self.land_sorted(item.at, docs, snapshot.world());
            let (every, interval) = control.cadence();
            if cadence.due(attempted, every, interval) {
                let progress = BareClassifyingLine {
                    position: item.at,
                    done: attempted,
                    of: to_sort.len(),
                    elapsed_ms: started.elapsed().as_millis(),
                };
                lines.say(Class::Progress, progress);
            }
            // The hold after the k-th position, where a next one stands.
            #[cfg(any(test, feature = "test-hooks"))]
            if items.peek().is_some() {
                FEED_WALK_HOLD.wait_at(attempted as u64, control);
                if control.stopped() {
                    return None;
                }
            }
        }
        let refusals = refused.as_ref().map_or(0, |(n, ..)| *n);
        if let Some((positions, first, account)) = refused {
            lines.say(Class::Failure, ClassificationRefusedLine { positions, first, account });
        }
        Some(SortFigures {
            of: attempted,
            refused: refusals,
            reconstructions: classifier.finish(),
            elapsed_ms: started.elapsed().as_millis(),
        })
    }

    /// Lands one sorted position: into the twins, and the index file up to it.
    ///
    /// Under the feed's lock: the position leaves the set; its classification
    /// against `world` — the open's head, PUB-7.7's one snapshot — enters the
    /// twins as the record step folds a position ([`Inner::fold_into_maps`];
    /// a position the journal refused enters with no document, the published
    /// walk's, its position alone); and the index file takes every classified
    /// position from its coverage up to this one
    /// ([`Inner::append_the_index_through`]), which is the progress a kill
    /// keeps: the set is sorted ascending, so the file's claim never passes an
    /// unsorted position, and the next open pends what lies above its
    /// coverage. The other three files wait on the landing, fenced below the
    /// set. A position a compaction dropped meanwhile lands nothing.
    fn land_sorted(&self, at: u64, docs: Option<Vec<Address>>, world: &World) {
        let mut inner = self.inner.lock();
        if !inner.unsorted.remove(&at) {
            return;
        }
        let docs = docs.map(|addrs| classify(world, addrs)).unwrap_or_default();
        inner.fold_into_maps(at, docs);
        inner.append_the_index_through(at);
    }

    /// Lands the walk under this feed's lock, the five files written in order.
    ///
    /// The lock is the record step's and the page's, so a write's record and
    /// a page wait on it for the rewrites' length and never see a half-landed
    /// feed. The region's classifications are folded into the twins as the
    /// record step folds a position ([`Inner::fold_into_maps`]), classified
    /// against `world` — the open's head, PUB-7.7's one snapshot — and into
    /// `commits.log`'s resident entries behind the fence as the floor stands
    /// at the landing ([`CommitsLog::fold_the_walk`]: a checkpoint that
    /// landed during the walk moved it, its compaction deferred to this
    /// landing), the twins trimmed to the same fence; the set's positions
    /// landed as they were sorted ([`Feed::land_sorted`]). Then the files,
    /// each whole, in the order that keeps a kill between any two inside the
    /// walk behind the listener (`operations.md` §3.3 step 2): the index,
    /// the bitmap and the streams from the twins, fenced at the last position
    /// the log holds ([`Inner::rewrite_classified_files`]); then
    /// `commits.log` — the region's landing
    /// ([`CommitsLog::write_the_landing`]) where one pended, else the
    /// compaction a landing owed where one deferred its rewrite while the set
    /// pended ([`CommitsLog::rewrite_the_owed`]), the file otherwise standing
    /// complete, every line appended as it was recorded; then the offset
    /// array, which names the lines that rewrite placed. Killed before
    /// `commits.log`'s rewrite, the file stands as the open found it, so the
    /// next open's region pends again and the three are fenced back at its
    /// lower edge; killed after it, the three cover the region, so that open
    /// classifies nothing from the journal before it serves. The attest
    /// store's file is untouched; the `landing:` lines are said last — the
    /// region's ([`WalkLandingLine`]), then the set's
    /// ([`BareClassifiedLine`]).
    ///
    /// A rewrite that fails is said and fails no op. Before its rename a
    /// derived file stands whole and fenced where it was — the region's lower
    /// edge, the first unsorted position less one, or, the index's, the last
    /// position the sort appended — short of what the walk landed and of
    /// every write recorded while it pended, so it is stopped there
    /// ([`LineFile::stop_at`]): a later append would raise its coverage claim
    /// over the gap, and a position at or below a claim with no record is a
    /// `[]`-docs entry, which no mask withholds. The next open re-derives
    /// that file above its fence, sorting the region's bare positions behind
    /// the listener. `commits.log` stops at the region's lower edge
    /// ([`CommitsLog::write_the_landing`] says why); the compaction a landing
    /// owed is left owed. Past its rename a file is in place and has said its
    /// own stop. A stop asked while the walk ran writes nothing.
    fn land(
        &self,
        outcome: Option<WalkOutcome>,
        sorted: Option<SortFigures>,
        kernel: &Kernel<World>,
        world: &World,
        control: &WalkControl,
        lines: &Lines,
    ) {
        // The floor as it stands now, off the lock: one probe, free.
        let floor_fence = reclaim_floor_of(kernel).map(|floor| floor.saturating_sub(1));
        let mut inner = self.inner.lock();
        let held = Instant::now();
        if control.stop.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        // The region's half: its boundaries into the twins, each placed
        // below the positions recorded during the walk, and into the log's
        // resident entries behind the fence as it stands at the landing.
        let region = outcome.as_ref().and_then(|outcome| {
            for w in &outcome.boundaries {
                let docs =
                    w.docs.as_ref().map(|addrs| classify(world, addrs.clone())).unwrap_or_default();
                inner.fold_into_maps(w.at, docs);
            }
            inner.log.fold_the_walk(&outcome.boundaries, outcome.min_since, floor_fence)
        });
        if let Some((_, fence)) = region {
            inner.drop_at_or_below(fence);
        }
        let covered = inner
            .log
            .entries()
            .keys()
            .next_back()
            .copied()
            .or(region.map(|(_, fence)| fence))
            .unwrap_or_else(|| inner.files.index.coverage());
        let classified = inner.rewrite_classified_files(covered, true);
        say_the_landings_refusals(lines, classified);
        #[cfg(test)]
        if CUT_THE_NEXT_LANDING.swap(false, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        // The log: the region's landing, said at the log — before its rename
        // as the landing's own refusal, past it as the file's stop — or, no
        // region pending, the rewrite a compaction left to this landing where
        // one did. The resident entries are complete either way.
        let in_memory_alone = match region {
            Some(((low, _), _)) => {
                matches!(inner.log.write_the_landing(low), Err(RewriteFail::BeforeRename(_)))
            }
            None => {
                if let Err(RewriteFail::BeforeRename(e)) = inner.log.rewrite_the_owed() {
                    lines.say(
                        Class::Failure,
                        format_args!(
                            "commits.log: the compaction the walk's landing owed failed before its \
                             rename: {}; the file stands as it was, holding lines below the fence, \
                             and the next checkpoint's compaction tries again",
                            IoCause(&e)
                        ),
                    );
                }
                false
            }
        };
        let offsets = inner.rewrite_offsets_file(covered, true);
        say_the_landings_refusals(lines, offsets);
        inner.landing_owed = false;
        if let (Some(outcome), Some(((low, head), fence))) = (&outcome, region) {
            lines.say(
                Class::Landing,
                WalkLandingLine {
                    low,
                    head,
                    walked: outcome.boundaries.len(),
                    unclassified: outcome.unclassified(),
                    elapsed_ms: outcome.started.elapsed().as_millis(),
                    held_ms: held.elapsed().as_millis(),
                    fence: (fence > low).then_some(fence),
                    in_memory_alone,
                },
            );
        }
        if let Some(sort) = sorted {
            lines.say(
                Class::Landing,
                BareClassifiedLine {
                    classified: sort.classified(),
                    of: sort.of,
                    reconstructions: sort.reconstructions,
                    elapsed_ms: sort.elapsed_ms,
                    held_ms: held.elapsed().as_millis(),
                },
            );
        }
    }

    /// Compacts the five files to the journal's reclaim floor, while serving.
    ///
    /// It is what the daemon's checkpoint thread runs after each checkpoint
    /// lands, under this feed's lock, which is the one lock the record step and
    /// the page take: the same rewrite [`Feed::open`] runs, the fence found by
    /// the same probe ([`reclaim_floor`]). `commits.log` drops every entry at
    /// or below the fence just under the floor and rewrites itself around the
    /// survivors ([`CommitsLog::compact_to`]); the four twins and the attest
    /// store's served window drop the same positions and the four derived files
    /// are rewritten from the twins whole, fenced at the last recorded
    /// position; the attest store's file is untouched (its class: below the
    /// floor its lines are primary). Answers what it did ([`FeedCompaction`]):
    /// the fence compacted to, or none where the floor has not moved past the
    /// oldest entry — the ordinary answer between reclaiming checkpoints — and
    /// nothing is written; and beside the fence, by name, each file that stood.
    ///
    /// **The disposition** while serving is the record step's own (the rule
    /// [`Feed::record`] states): reported on the operator stream, never
    /// failing an op. A rewrite that fails before its rename leaves that file
    /// whole and standing and is said here, the next checkpoint's compaction
    /// trying again — and that file is named in the answer, so the checkpoint
    /// thread's landing line is truthful of it; one that fails past its rename
    /// stops its file for the uptime and is said by the file itself, once —
    /// the new file is in place, so it is not one that stood — the resident
    /// twins are trimmed either way and serve this uptime, and the next open
    /// re-derives (P22).
    ///
    /// **While the walk has anything pending** — the region, the bare
    /// positions the index lost, or both — the rewrite is deferred: the fence
    /// moves in memory — the log's entries and the twins trimmed, the
    /// unsorted positions the journal reclaimed dropped with them, so a page
    /// below it answers 410 at once, as `/op-at` does — and no file is
    /// written, the twins lacking what the files must carry; the landing's
    /// rewrite writes the fence, which it reads from the floor again then
    /// ([`Feed::land`]), `commits.log`'s among them
    /// ([`CommitsLog::compact_in_memory`]). The deferral's record is that
    /// fence: `commits.log`'s `min_since` ahead of the line its file holds
    /// until the landing. The answer names the fence and what the files'
    /// rewrite waits on (`deferred`), and no file standing, so the checkpoint
    /// thread's line says the files were not written.
    ///
    /// **The lines** (`operations.md` §1.1 rows 27 and 28) go through `lines`,
    /// the write path's classed door, handed at the call as the walk's landing
    /// is handed it: a rewrite that failed before its rename, with the reclaim
    /// floor's position it compacted to, said per attempt — each landing while
    /// the cause stands is a fresh act whose failure is news, the rule's named
    /// exception — under `Class::Failure`.
    pub(super) fn compact_below_reclaim_floor(
        &self,
        engine: &Engine,
        lines: &Lines,
    ) -> FeedCompaction {
        let Some(floor) = reclaim_floor(engine) else {
            return FeedCompaction::default();
        };
        let fence = floor.saturating_sub(1);
        let mut inner = self.inner.lock();
        let mut standing = Vec::new();
        let pends = inner.pends();
        let pending = inner.pending();
        let dropped = if !pends {
            match inner.log.compact_to(fence) {
                Ok(dropped) => dropped,
                // The file said its own stop; the entries are trimmed all the
                // same, and the twins follow them below.
                Err(RewriteFail::PastRename(_)) => true,
                Err(before) => {
                    lines.say(
                        Class::Failure,
                        format_args!(
                            "commits.log compaction below the reclaim floor at position {floor} \
                             failed {before}; the file stands as it was, and the next \
                             checkpoint's compaction tries again"
                        ),
                    );
                    standing.push("commits.log");
                    true
                }
            }
        } else {
            // The walk pending: the fence moves in memory alone, the log's
            // rewrite owed to the landing with the derived files' (the
            // deferral above).
            inner.log.compact_in_memory(fence)
        };
        if !dropped {
            return FeedCompaction::default();
        }
        inner.drop_at_or_below(fence);
        if pends {
            return FeedCompaction { fence: Some(fence), standing, deferred: Some(pending) };
        }
        let covered = inner.log.entries().keys().next_back().copied().unwrap_or(fence);
        for unwritten in inner.rewrite_derived_files(covered) {
            if let RewriteFail::BeforeRename(e) = unwritten.failed {
                lines.say(
                    Class::Failure,
                    format_args!(
                        "{} compaction below the reclaim floor at position {floor} failed \
                         before its rename: {}; the file stands as it was, and the next \
                         checkpoint's compaction tries again",
                        unwritten.name,
                        IoCause(&e)
                    ),
                );
                standing.push(unwritten.name);
            }
        }
        FeedCompaction { fence: Some(fence), standing, deferred: None }
    }

    /// The test seam that fails the next rewrite past its rename.
    ///
    /// It is behind `skepd::Daemon::fail_the_feeds_next_rewrite_past_rename`:
    /// the next rewrite of each of the five files fails past its rename.
    /// Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn fail_next_rewrite_past_rename(&self) {
        let mut inner = self.inner.lock();
        inner.log.fail_next_rewrite_past_rename();
        inner.files.index.fail_next_rewrite_past_rename();
        inner.files.offsets.fail_next_rewrite_past_rename();
        inner.files.masked.fail_next_rewrite_past_rename();
        inner.files.streams.fail_next_rewrite_past_rename();
    }

    /// Returns the stopped files, with the position each stop was set at.
    ///
    /// They are, of `commits.log` and the four derived files, those that take
    /// no further line this uptime ([`StoppedFile`]) — `commits.log` first,
    /// then the four in their table's order — read under the feed's lock and
    /// no guard. The standing line's read (once an hour while any stands) and
    /// the test seam `skepd::Daemon::stopped_feed_files`'s.
    pub(super) fn stopped_files(&self) -> Vec<StoppedFile> {
        let inner = self.inner.lock();
        let mut stopped = Vec::new();
        if let Some(since) = inner.log.stopped_since() {
            stopped.push(StoppedFile { name: "commits.log", since });
        }
        for (name, file) in [
            (INDEX_FILE, &inner.files.index),
            (OFFSETS_FILE, &inner.files.offsets),
            (MASKED_FILE, &inner.files.masked),
            (STREAMS_FILE, &inner.files.streams),
        ] {
            if let Some(since) = file.stopped_since() {
                stopped.push(StoppedFile { name, since });
            }
        }
        stopped
    }

    /// Records one committed write at ack time, and classifies it.
    ///
    /// It runs under the write-serialization guard, between a commit and its
    /// ack, which is [`CommitsLog::record`]'s contract and this method's; the
    /// guard argument is that contract's cheap half. The write is classified
    /// against `world` — the post-commit head, so the minted document's
    /// registration and bit are in it — into the four derived structures: the
    /// offset array, the index (docs non-empty), the bitmap or the published
    /// stream, and each named draft's owner stream — and, where the write's
    /// marker slot was filled, into the attest store ([`AttestStore::record`]),
    /// the admitted value itself. Declined exactly when the log declines (an
    /// old commit's re-ack).
    ///
    /// The derived appends are testimony too: a failed one is reported and the
    /// resident twin stays right, so this uptime answers correctly and the next
    /// open's tail check re-derives what the file missed. The attest store's
    /// line is the exception (SO-I5 (d)): synced before this returns, off the
    /// feed's lock ([`Feed::sync_the_attest_line`]), and where its write or its
    /// sync fails the slot is still served this uptime, the line rebuilt from
    /// the journal by the restart's open.
    ///
    /// `docs` arrives as addresses and is rendered once, here, for the
    /// authority file alone: the classification reads them as addresses, so
    /// text handed down from the write path would be parsed straight back — and
    /// a parse that could not read a name would have nowhere to report it,
    /// leaving the position classified short and, where every name dropped,
    /// served to every class as a `[]`-docs entry.
    ///
    /// # Errors
    ///
    /// [`AttestStoreFailed`] where the attest store's line could not be written
    /// or synced, on which the write path halts.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn record(
        &self,
        serial: &SerialGuard<'_>,
        at: u64,
        op: &'static str,
        docs: Vec<Address>,
        testimony: String,
        signed: Option<Signed>,
        terms: Option<OpTerms>,
        world: &World,
    ) -> Result<(), AttestStoreFailed> {
        let owed = {
            let mut inner = self.inner.lock();
            let rendered: Vec<String> = docs.iter().map(|a| a.tumbler().to_string()).collect();
            let (carrier, attest) = match signed {
                Some(Signed::Marker(a)) => (Some(Carrier::Marker), Some(a)),
                Some(Signed::RecordSig) => (Some(Carrier::RecordSig), None),
                None => (None, None),
            };
            let Some(recorded) =
                inner.log.record(serial, at, op, rendered, testimony, carrier, terms)
            else {
                return Ok(());
            };
            inner.fold_position(at, recorded, classify(world, docs), attest)?
        };
        self.sync_the_attest_line(serial, owed)
    }

    /// Records the bare entry of a write that panicked past its commit.
    ///
    /// It is the record of the panic past the commit (`operations.md` §4 row
    /// 34): one bare entry at `at` — the position a write committed before it
    /// panicked, which the write path's door caught — under the same guard
    /// and contract as [`Feed::record`], between the commit and the re-raise.
    /// What the recorded row would have carried is lost with the answer, so
    /// the entry is the walk's own form ([`CommitMeta::Bare`] with the
    /// journal's answer, `null` for the rest), and its classification the
    /// walk's: `docs` and `journal` as `classify::derived_journal` read them
    /// off the two worlds the door held, `docs` classified here against
    /// `world` — the post-commit head — as a recorded position's are, so the
    /// mask, the index, the bitmap and the streams take the position as the
    /// walk's landing would, at the commit rather than at the next open.
    /// `attest` is the marker slot the write filled, where it filled one —
    /// the value the plain sequence admitted and handed the kernel — mirrored
    /// into the attest store and synced as every admitted marker is
    /// (SO-I5 (d)). Declined exactly when the log declines.
    ///
    /// # Errors
    ///
    /// The store's refusal, answered as [`Feed::record`] answers it:
    /// [`AttestStoreFailed`] where the attest store's line could not be
    /// written or synced.
    pub(super) fn record_bare(
        &self,
        serial: &SerialGuard<'_>,
        at: u64,
        docs: Vec<Address>,
        journal: JournalTerms,
        attest: Option<Attestation>,
        world: &World,
    ) -> Result<(), AttestStoreFailed> {
        let owed = {
            let mut inner = self.inner.lock();
            let Some(recorded) = inner.log.record_bare(serial, at, journal) else {
                return Ok(());
            };
            inner.fold_position(at, recorded, classify(world, docs), attest)?
        };
        self.sync_the_attest_line(serial, owed)
    }

    /// Makes the attest line the record step appended durable, off the lock.
    ///
    /// The line was written under the feed's lock ([`AttestStore::record`]),
    /// its sync owed; it is synced here through the store's second handle
    /// ([`SyncHandle`]) with that lock released, so a page, a `/health` probe
    /// or a compaction that comes meanwhile waits on no fsync. The guard
    /// argument is what keeps the line durable before the next commit
    /// (SO-I5 (d)): the record step's caller holds the serialization guard
    /// across this, and every commit — the one whose crossing calls for the
    /// checkpoint that reclaims the line's journal copy among them — opens
    /// under it.
    ///
    /// # Errors
    ///
    /// [`AttestStoreFailed`] where the sync failed: the failure is said and the
    /// file stopped, under the lock again ([`AttestStore::sync_failed`]).
    fn sync_the_attest_line(
        &self,
        _serial: &SerialGuard<'_>,
        owed: Option<OwedSync>,
    ) -> Result<(), AttestStoreFailed> {
        let Some(owed) = owed else { return Ok(()) };
        #[cfg(test)]
        self.attest_sync_hold.park();
        match self.attest_sync.sync() {
            Ok(()) => {
                #[cfg(any(test, feature = "test-hooks"))]
                self.inner.lock().attest.settle(owed);
                Ok(())
            }
            Err(e) => {
                self.inner.lock().attest.sync_failed(owed, &e);
                Err(AttestStoreFailed)
            }
        }
    }

    /// The test seam behind `skepd::Daemon::attest_store_synced_through`.
    ///
    /// It answers the coverage the attest store's last successful sync made
    /// durable. Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn attest_store_synced_through(&self) -> u64 {
        self.inner.lock().attest.synced_through()
    }

    /// The test seam behind `skepd::Daemon::fail_the_attest_stores_next_write`.
    ///
    /// The attest store's next write fails at the OS. Not a stable API.
    ///
    /// # Panics
    ///
    /// Panics where [`AttestStore::fail_next_write`] does: the read-only
    /// handle on the file could not be opened.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn fail_the_attest_stores_next_write(&self) {
        self.inner.lock().attest.fail_next_write();
    }

    /// Returns the data behind `GET /changes` at `class`.
    ///
    /// The rows are collected under the feed's lock and rendered after it is
    /// released: [`Feed::record`], the write path's step under the
    /// serialization lock, waits on that lock, and an attested row's render —
    /// its `attest` member, 6,746 hex characters under tag 1 — is the dearest
    /// part of a page. Under the lock: the merge, the mask, and a clone per
    /// row, the slot an `Arc`.
    ///
    /// **The page's bytes.** Each row is rendered and marshaled straight into
    /// the page object's body, once, and its tree dropped — so a page costs one
    /// marshal per row and holds the body and one row's tree at a time, and the
    /// route sends the body as it stands.
    ///
    /// **The page byte budget** (SO-I9): the rows are measured as they are
    /// marshaled — each entry's bytes and the comma between entries, the
    /// page object's own envelope (`changes`, `last`, `more`: at most 55
    /// bytes) aside — and where the sum passes [`MAX_CHANGES_PAGE_BYTES`] the
    /// whole request is refused ([`ChangesAnswer::OverBudget`]), naming the
    /// budget and the rows that fit, never a page shorter than `limit`
    /// (PUB-6.44). The budget is paid at the layer that produces the page
    /// (P29), so a guest asking the maximum `limit` over attested rows costs
    /// the daemon the render of at most the budget's worth of rows and one
    /// more.
    ///
    /// **The walk pending** (`operations.md` §3.3 step 2: "for any page whose
    /// range reaches into the uncovered region, not only a `since` inside it —
    /// a page starting below the region would otherwise silently skip its
    /// positions"): after the reclaimed check and before the merge serves a
    /// row, where a position above `since` waits on the walk — the first of
    /// the region's above it, or the first unsorted position above it,
    /// whichever is lower ([`Inner::first_pending_above`]) — the page is
    /// refused [`ChangesAnswer::Rebuilding`] unless its `limit` rows all lie
    /// below that position — the merge walked up to it and no further, since
    /// the twins hold nothing of the region or the set and the next candidate
    /// past it would be a position above, the pending one skipped between.
    /// The arithmetic, pinned by the walk suite: the region's `low` is
    /// covered (a page's last row may be it), `head` uncovered (the last of
    /// the region); a page refused by the position test `since + limit > low`
    /// is refused here too, since fewer than `limit` positions, hence rows,
    /// lie in `(since, low]`, and a page that test would serve over sparse
    /// positions — fewer than `limit` rows below `low`, the merge then
    /// reaching past the region — is refused as well; an unsorted position is
    /// its own fence, the sorted positions on either side of it serving. A
    /// page served below a pending position answers `more: true`: the walk
    /// holds positions this class may see, which the next page meets as the
    /// refusal or, landed, as rows. A page with `since` at or above the last
    /// pending position serves from the twins — every position recorded since
    /// the open is in them.
    ///
    /// # Panics
    ///
    /// Panics if a rendered entry is not a JSON object; [`CommitMeta::entry`]
    /// renders every entry as one, so the `expect` never fires.
    pub(crate) fn page(&self, class: &FeedClass<'_>, query: &ChangesQuery) -> ChangesAnswer {
        let (rows, more) = {
            let inner = self.inner.lock();
            if !inner.log.admits_since(query.since) {
                return ChangesAnswer::Reclaimed { floor: inner.log.floor() };
            }
            let Some(start) = query.since.checked_add(1) else {
                let body = page_body(PAGE_HEAD.to_vec(), query.since, false);
                return ChangesAnswer::Page { body };
            };
            let reach = inner.first_pending_above(query.since);
            let mut rows = Vec::new();
            let mut more = false;
            for at in Merge::new(inner.sources(class, query, start)) {
                if reach.is_some_and(|pending| at >= pending) {
                    break;
                }
                let Some(Visible { meta, reduced, whole }) = inner.visible(class, query, at) else {
                    continue;
                };
                if rows.len() == query.limit.get() {
                    more = true;
                    break;
                }
                let reduced: Vec<String> = reduced.iter().map(|d| d.addr.to_string()).collect();
                rows.push((at, meta.clone(), reduced, whole, inner.attest.slot(at)));
            }
            if reach.is_some() {
                if rows.len() < query.limit.get() {
                    return ChangesAnswer::Rebuilding { pending: inner.pending() };
                }
                more = true;
            }
            (rows, more)
        };
        let last = rows.last().map_or(query.since, |(at, ..)| *at);
        let mut body = PAGE_HEAD.to_vec();
        for (before, (at, meta, reduced, whole, slot)) in rows.into_iter().enumerate() {
            let mut entry = meta.entry(at, reduced, slot.as_deref());
            // The third absence (SO-I5 (e)): a row whose `docs` this class
            // reduces — a straddle, a draft-homed `nullify` of a public link
            // or an `edit_link` with one home a draft (PUB-6.47) — carries no
            // `attest`, absent and never `null`: the signature is a function
            // of the home the row withholds, and served it would confirm a
            // guess at that home, the confirmation the chain's salt exists to
            // deny. The verdict there is undeterminable from this feed; the
            // owner's own page carries the member whole.
            if !whole {
                entry.as_object_mut().expect("an entry is an object").remove("attest");
            }
            // The comma that joins the entry to the one before, then its
            // bytes, measured as they land: past the budget, the rows before
            // this one are the ones that fit.
            if before > 0 {
                body.push(b',');
            }
            append_bytes(&mut body, &entry);
            if body.len() - PAGE_HEAD.len() > MAX_CHANGES_PAGE_BYTES {
                return ChangesAnswer::OverBudget { budget: MAX_CHANGES_PAGE_BYTES, fits: before };
            }
        }
        ChangesAnswer::Page { body: page_body(body, last, more) }
    }

    /// Returns how many candidate sources `class`'s page merges for `query`.
    ///
    /// It is the width [`Inner::sources`] hands [`Merge`], the term PUB-7.28
    /// prices a page by: the published walk (absent under `drafts=true`) and
    /// one stream per owner account the class opens — never one list per
    /// visible draft document (PUB-7.24) — and one index list per document
    /// under each universal prefix; an `under=` the merge rule takes is one
    /// index list per readable document under it instead.
    #[cfg(test)]
    pub(super) fn merge_width(&self, class: &FeedClass<'_>, query: &ChangesQuery) -> usize {
        let start = query.since.saturating_add(1);
        self.inner.lock().sources(class, query, start).len()
    }

    /// Returns the head position's recorded wall-clock time.
    ///
    /// It is `CommitsLog::head_time`.
    pub(crate) fn head_time(&self) -> Option<u64> {
        self.inner.lock().log.head_time()
    }

    /// Returns every recorded entry above `position`.
    ///
    /// It is `CommitsLog::entries_above`, for the head writer's resume.
    pub(crate) fn entries_above(&self, position: u64) -> Vec<(u64, CommitMeta)> {
        self.inner.lock().log.entries_above(position)
    }
}

/// The page object's head, `{"changes":[`, ahead of its rows' bytes.
///
/// The keys are `obj`'s order, `changes` < `last` < `more`, so the head and
/// [`page_body`]'s tail spell the object `obj` would build.
const PAGE_HEAD: &[u8] = br#"{"changes":["#;

/// Returns the page object's body: its head and rows in `body`, closed.
///
/// `body` is [`PAGE_HEAD`] and the rows marshaled after it, joined by
/// commas; `last` and `more` close the object.
fn page_body(mut body: Vec<u8>, last: u64, more: bool) -> Vec<u8> {
    body.extend_from_slice(format!(r#"],"last":{last},"more":{more}}}"#).as_bytes());
    body
}

/// Returns the closure that names a derived file in an open-time failure.
///
/// It wraps as `BlockedSupply::read`'s closure wraps its path, one per file:
/// the kind kept, the name before the OS's text, so the daemon's
/// `change-feed sidecar: {e}` reads
/// `change-feed sidecar: feed-index.log: {e}` (`operations.md` §1.1 row 2).
fn with_file(name: &'static str) -> impl Fn(io::Error) -> io::Error {
    move |e| io::Error::new(e.kind(), format!("{name}: {e}"))
}

/// Says each derived file the walk's landing left unrewritten.
///
/// Each failed before its rename and stands fenced where it was, short of
/// what the walk landed, stopped there (`Feed::land`); a failure past the
/// rename the file has said itself. The line says the stop, what serves and
/// the act owed before the restart whose open re-derives the file: `{file}:
/// the walk's landing rewrite failed before its rename: {cause}; the file
/// stands fenced at position {fence}, short of what the walk landed, and
/// takes no further line, so the next open re-derives above it — the board
/// serves from memory, and nothing is lost`, then
/// [`IoCause::before_the_restart`]'s clause.
fn say_the_landings_refusals(lines: &Lines, failures: Vec<Unwritten>) {
    for Unwritten { name, failed, fence } in failures {
        if let RewriteFail::BeforeRename(e) = failed {
            let cause = IoCause(&e);
            lines.say(
                Class::Failure,
                format_args!(
                    "{name}: the walk's landing rewrite failed before its rename: {cause}; the \
                     file stands fenced at position {fence}, short of what the walk landed, and \
                     takes no further line, so the next open re-derives above it — the board \
                     serves from memory, and nothing is lost{}",
                    cause.before_the_restart()
                ),
            );
        }
    }
}

/// A derived file whose rewrite failed, as the rewrites answer it.
///
/// It is the file by name, how its rewrite failed ([`RewriteFail`]: on which
/// side of its rename) and the fence it stands at — its coverage after the
/// failure, which the walk's landing stops it at and names.
struct Unwritten {
    name: &'static str,
    failed: RewriteFail,
    fence: u64,
}

/// Rewrites one derived file whole, stopping it where a landing left it short.
///
/// The rewrite is [`LineFile::rewrite`]'s, fenced at `covered`. Where `stop`
/// — the walk's landing's — and the rewrite failed before its rename, the
/// file stands fenced where it was, short of what the walk landed, and is
/// stopped there ([`LineFile::stop_at`]); a compaction's rewrite stops
/// nothing, the next compaction trying again. Answers the failure, with the
/// fence the file stands at ([`Unwritten`]).
fn rewrite_or_stop(
    file: &mut LineFile,
    name: &'static str,
    records: Vec<Value>,
    covered: u64,
    stop: bool,
) -> Option<Unwritten> {
    let failed = file.rewrite(records, covered).err()?;
    if stop && matches!(failed, RewriteFail::BeforeRename(_)) {
        file.stop_at(file.coverage());
    }
    Some(Unwritten { name, failed, fence: file.coverage() })
}

/// The test seam: the next walk's landing ends between its rewrites, once.
///
/// Armed, the landing ends after the index, the bitmap and the streams are
/// rewritten and before `commits.log` is — the data directory a kill between
/// the two leaves — and disarms. It writes no further file and says no
/// `landing:` line, so the suite drops the write path and opens over what
/// the cut left.
#[cfg(test)]
pub(super) static CUT_THE_NEXT_LANDING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// The test seam: a hold on the attest line's sync, one per feed.
///
/// Armed, a record step that owes an attest line its sync parks between the
/// feed's lock and the sync ([`Feed::sync_the_attest_line`]), so a suite
/// reads the feed while it stands there; [`SyncHold::parked`] answers once
/// one does.
#[cfg(test)]
pub(super) struct SyncHold {
    held: Mutex<bool>,
    released: parking_lot::Condvar,
    parked: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl SyncHold {
    fn new() -> SyncHold {
        SyncHold {
            held: Mutex::new(false),
            released: parking_lot::Condvar::new(),
            parked: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Arms the hold: the next record step that owes a sync parks.
    pub(super) fn hold(&self) {
        *self.held.lock() = true;
    }

    /// Releases the hold: a parked record step makes its sync.
    pub(super) fn release(&self) {
        *self.held.lock() = false;
        self.released.notify_all();
    }

    /// Returns whether a record step stands parked at the hold.
    pub(super) fn parked(&self) -> bool {
        self.parked.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Parks the record step while the hold is armed.
    fn park(&self) {
        let mut held = self.held.lock();
        while *held {
            self.parked.store(true, std::sync::atomic::Ordering::Release);
            self.released.wait(&mut held);
        }
        self.parked.store(false, std::sync::atomic::Ordering::Release);
    }
}

/// Says row 9 for a derived file where its replay answered a cut.
///
/// The line is the head, then this file's case — the cut part is
/// re-derived, by the tail derivation [`Feed::open`] runs from the last
/// trusted position.
fn say_derived_cut(lines: &Lines, name: &'static str, cut: Option<Cut>) {
    if let Some(cut) = cut {
        lines.say(Class::Failure, DerivedCutLine { name, cut });
    }
}

/// Row 9's words for one of the four derived files.
///
/// They are `operations.md` §1.1 row 9's: `{file}: trust ends at position
/// {c} (byte {n} of {len}); the {k} bytes after it are cut; the cut part is
/// re-derived`. A pure value, pinned by `to_string()` in the unit suite;
/// emitted under `Class::Failure` by [`say_derived_cut`].
struct DerivedCutLine {
    name: &'static str,
    cut: Cut,
}

impl std::fmt::Display for DerivedCutLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; the cut part is re-derived", CutHead { name: self.name, cut: self.cut })
    }
}

/// The walk's `open:` line for the bare positions the index lost (m15).
///
/// The positions are classified from the journal behind the listener, the
/// board serving. The words: `feed-index.log covers to position {c}: {n}
/// bare positions are classified from the journal behind the listener, {r}
/// world reconstructions in all` — `{c}` the index file's coverage as the
/// open left it, below the first of them; the cost said ahead of paying it:
/// one reconstruction a position, one more below each run of them and none
/// at the head ([`BareClassifier`] carries a run's worlds), exact where the
/// journal answers and an upper bound where it refuses. A pure value, pinned
/// by `to_string()` in the unit suite; emitted under `Class::Open` by
/// [`Feed::walk_and_land`] at the walk's start, ahead of the hold.
struct BareClassificationLine {
    coverage: u64,
    positions: usize,
    /// The world reconstructions the classification will pay.
    reconstructions: usize,
}

impl std::fmt::Display for BareClassificationLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{INDEX_FILE} covers to position {}: {} bare positions are classified from the \
             journal behind the listener, {} world reconstructions in all",
            self.coverage, self.positions, self.reconstructions
        )
    }
}

/// The walk's `progress:` line while it sorts the set (m15).
///
/// The words: `feed-index.log: the bare classification at position {p},
/// {i} of {n}, {d} ms in` — `{p}` the position last sorted, `{i}` how many
/// are done of the `{n}` the `open:` line named, `{d}` since the sort began.
/// Said as a position lands, once the cadence's count of positions is done
/// since the last line or its interval has passed, whichever comes first —
/// the shipped figures `FEED_WALK_PROGRESS_BOUNDARIES` and
/// `FEED_WALK_PROGRESS_INTERVAL`, or the test seam's
/// ([`WalkControl`]) — the walk's tell from a hang: a world reconstruction a
/// position can run for seconds at a large world. A pure value, pinned by
/// `to_string()` in the unit suite; emitted under `Class::Progress` by
/// [`Feed::sort`].
struct BareClassifyingLine {
    position: u64,
    done: usize,
    of: usize,
    elapsed_ms: u128,
}

impl std::fmt::Display for BareClassifyingLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{INDEX_FILE}: the bare classification at position {}, {} of {}, {} ms in",
            self.position, self.done, self.of, self.elapsed_ms
        )
    }
}

/// The walk's `landing:` line for the set it sorted (m15).
///
/// The words: `feed-index.log: {c} of {n} bare positions classified from the
/// journal, {k} world reconstructions, in {d} ms; the landing held the
/// change feed's lock {r} ms` — `{k}` the reconstructions the journal
/// answered, so `{d}` over `{k}` bounds what one costs on this board, the
/// figure to size the next such sort by; `{r}` the landing's own span under
/// the lock every write's record and every page waits on; the positions the
/// journal refused said beside it ([`ClassificationRefusedLine`]). A pure
/// value, pinned by `to_string()` in the unit suite; emitted under
/// `Class::Landing` by [`Feed::land`].
struct BareClassifiedLine {
    classified: usize,
    of: usize,
    /// The world reconstructions the journal answered.
    reconstructions: usize,
    elapsed_ms: u128,
    held_ms: u128,
}

impl std::fmt::Display for BareClassifiedLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{INDEX_FILE}: {} of {} bare positions classified from the journal, {} world \
             reconstructions, in {} ms; the landing held the change feed's lock {} ms",
            self.classified, self.of, self.reconstructions, self.elapsed_ms, self.held_ms
        )
    }
}

/// What the sort of the bare positions the index lost came to.
///
/// It is what the set's `landing:` line says ([`BareClassifiedLine`]): the
/// positions attempted — the set as the walk started — how many the journal
/// refused, the world reconstructions it answered, and the sort's span.
struct SortFigures {
    of: usize,
    refused: usize,
    reconstructions: usize,
    elapsed_ms: u128,
}

impl SortFigures {
    /// Returns how many positions the journal classified.
    fn classified(&self) -> usize {
        self.of - self.refused
    }
}

/// One bare position the index lost, as the walk sorts it.
///
/// `below` is the entry below it in the log — the position whose world the
/// classification diffs from, genesis where none stands — read off the log
/// under the feed's lock as the walk starts, and stable while it runs: no
/// entry enters the log below the head but the region's own, which lie
/// above every position here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ToSort {
    at: u64,
    below: u64,
}

/// The feed's open, done: how far back `/changes` answers, and the cost.
///
/// The words: `the change feed answers from position {f} to position {h}:
/// commits.log {n} entries, {b} of them bare[; {what} wait on the walk], in
/// {d} ms` — `{f}` the oldest position still answerable, the `floor` a `410
/// history_reclaimed` names; the bare entries those whose testimony is lost;
/// what the walk behind the listener has yet to land, where anything pends
/// ([`FeedPending`]'s words: `positions ({low}, {head}]`, `{n} bare
/// positions the index lost`, or the two joined by `and`); and the open's
/// whole span. A feed that answers no position — no entry, nothing pending
/// — says `the change feed answers no position yet, the head at position
/// {h}, in {d} ms`. A pure value, pinned by `to_string()` in the unit suite;
/// emitted under `Class::Open` by [`Feed::open`], last.
struct FeedOpenLine {
    floor: Option<u64>,
    head: u64,
    entries: usize,
    bare: usize,
    pending: FeedPending,
    elapsed_ms: u128,
}

impl std::fmt::Display for FeedOpenLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(floor) = self.floor else {
            return write!(
                f,
                "the change feed answers no position yet, the head at position {}, in {} ms",
                self.head, self.elapsed_ms
            );
        };
        write!(
            f,
            "the change feed answers from position {floor} to position {}: commits.log {} \
             entries, {} of them bare",
            self.head, self.entries, self.bare
        )?;
        if !self.pending.is_empty() {
            write!(f, "; {} wait on the walk", self.pending)?;
        }
        write!(f, ", in {} ms", self.elapsed_ms)
    }
}

/// The journal's refusals of the walk's bare classification, said once.
///
/// The words: `feed-index.log: the journal refused to classify {n} bare
/// positions, the first at position {p} ({account}): each is served to
/// every class, its position alone` — `{account}` the first refusal's, in
/// the kernel's words. A pure value, pinned by `to_string()` in the unit
/// suite; emitted under `Class::Failure` by [`Feed::sort`], once after the
/// pass.
struct ClassificationRefusedLine {
    positions: usize,
    first: u64,
    account: String,
}

impl std::fmt::Display for ClassificationRefusedLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{INDEX_FILE}: the journal refused to classify {} bare positions, the first at \
             position {} ({}): each is served to every class, its position alone",
            self.positions, self.first, self.account
        )
    }
}

/// The open's line for what its compaction dropped below the reclaim floor.
///
/// The words: `the change feed's files compacted below the reclaim floor at
/// position {f}: {k} entries dropped`. A pure value, pinned by
/// `to_string()` in the unit suite; emitted under `Class::Open` by
/// [`Feed::open`] once the derived files follow the log.
struct OpenCompactionLine {
    floor: u64,
    dropped: usize,
}

impl std::fmt::Display for OpenCompactionLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the change feed's files compacted below the reclaim floor at position {}: {} \
             entries dropped",
            self.floor, self.dropped
        )
    }
}

/// What a position's fold into the twins would put on the files' lines.
///
/// It is [`Inner::fold_into_maps`]'s answer, for three of the four files: the
/// index record's documents where it named any, whether the bitmap takes it,
/// the owner streams it enters.
struct Folded {
    docs: Option<Value>,
    masked: bool,
    owners: Option<Value>,
}

/// One entry as a class sees it ([`Inner::visible`]).
///
/// It is its meta, its docs reduced to the ones the class may read, and
/// whether that reduction dropped none of them — `false` where it dropped
/// any, as on a straddle row at a class that cannot read its drafts, whose
/// `attest` the page then withholds (the third absence, which [`Feed::page`]
/// states).
struct Visible<'a> {
    meta: &'a CommitMeta,
    reduced: Vec<&'a Doc>,
    whole: bool,
}

impl Inner {
    /// Returns what the walk has yet to land, as figures ([`FeedPending`]).
    ///
    /// It is the log's region and the set as it stands: how many positions,
    /// the lowest and the highest.
    fn pending(&self) -> FeedPending {
        let unsorted = match (self.unsorted.first(), self.unsorted.last()) {
            (Some(&first), Some(&last)) => {
                Some(Unsorted { count: self.unsorted.len(), first, last })
            }
            _ => None,
        };
        FeedPending { region: self.log.pending_region(), unsorted }
    }

    /// Returns whether the walk has yet to land anything.
    ///
    /// It is the region, the set, or the landing's own rewrite once every
    /// position is sorted ([`Inner::landing_owed`]) — what the record step's
    /// appends and a compaction's rewrites wait on.
    fn pends(&self) -> bool {
        self.landing_owed || self.log.pending_region().is_some() || !self.unsorted.is_empty()
    }

    /// Returns the first position above `since` the walk has yet to land.
    ///
    /// It is the page's reach test ([`Feed::page`]): the lower of the
    /// region's first position above `since` — `max(low, since) + 1`, where
    /// `since` lies below the region's head — and the first unsorted
    /// position above `since`; `None` where no pending position lies above
    /// `since`, the page serving from the twins.
    fn first_pending_above(&self, since: u64) -> Option<u64> {
        let region = self
            .log
            .pending_region()
            .filter(|&(_, head)| since < head)
            .map(|(low, _)| low.max(since).saturating_add(1));
        let unsorted = self.unsorted.range(since.saturating_add(1)..).next().copied();
        match (region, unsorted) {
            (Some(r), Some(u)) => Some(r.min(u)),
            (r, u) => r.or(u),
        }
    }

    /// Appends the index file's records up to `at`, the position just sorted.
    ///
    /// It is the progress a kill keeps ([`Feed::land_sorted`]): every
    /// classified position from the file's coverage up to `at` takes its
    /// record, in order — the recorded positions the open classified from
    /// their records among them, so no position below the claim lacks its
    /// record — and the file is fenced at `at` where no record raised its
    /// coverage to it, so a position the journal classified empty is not
    /// sorted twice. A stopped file takes nothing ([`LineFile::append`]).
    fn append_the_index_through(&mut self, at: u64) {
        let from = self.files.index.first_uncovered();
        let records: Vec<(u64, Value)> =
            self.docs.range(from..=at).map(|(p, ds)| (*p, doc_strings(ds))).collect();
        for (p, docs) in records {
            self.files.index.append_or_report(p, vec![(INDEX_DOCS, docs)]);
        }
        if self.files.index.coverage() < at {
            self.files.index.fence_or_report(at);
        }
    }

    /// Drops every position at or below `min_since` from the twins.
    ///
    /// Three of the four twins — the index with the classification map, the
    /// bitmap with the published stream, the streams — the unsorted set and
    /// the attest store's served window drop them, the offset array's twin
    /// being the log's own: the positions the log has just dropped
    /// ([`CommitsLog::compact_to`], [`CommitsLog::compact_in_memory`], or
    /// [`CommitsLog::fold_the_walk`] at the walk's landing), unreachable by
    /// every route — so the twins and the log name one set of positions, a
    /// rewrite from the twins writes that set, no slot stays resident for a
    /// position no page renders, and the walk sorts no position the journal
    /// reclaimed.
    fn drop_at_or_below(&mut self, min_since: u64) {
        self.attest.drop_at_or_below(min_since);
        let keep_from = min_since.saturating_add(1);
        self.docs = self.docs.split_off(&keep_from);
        self.masked = self.masked.split_off(&keep_from);
        self.published = self.published.split_off(&keep_from);
        self.unsorted = self.unsorted.split_off(&keep_from);
        self.index.retain(|_, (_, positions)| {
            positions.retain(|&at| at > min_since);
            !positions.is_empty()
        });
        self.streams.retain(|_, positions| {
            positions.retain(|&at| at > min_since);
            !positions.is_empty()
        });
    }

    /// Rewrites the four derived files whole from the twins.
    ///
    /// Each is fenced at `covered` — the compaction's rewrite, at open and
    /// after a checkpoint alike: the index, the bitmap and the streams
    /// ([`Inner::rewrite_classified_files`]), then the offset array —
    /// answering each file that failed with how ([`Unwritten`]), every file
    /// attempted whatever the one before it answered. A fifth derived
    /// structure owes a line in one of its two halves, which the walk's
    /// landing calls apart ([`Feed::land`]), beside its fold and its replay.
    fn rewrite_derived_files(&mut self, covered: u64) -> Vec<Unwritten> {
        let mut failures = self.rewrite_classified_files(covered, false);
        failures.extend(self.rewrite_offsets_file(covered, false));
        failures
    }

    /// Rewrites the index, the bitmap and the streams whole from the twins.
    ///
    /// Each is fenced at `covered` and holds no record above it, each
    /// attempted whatever the one before it answered, and each that failed is
    /// answered with how. `stop` is the walk's landing's (`Feed::land`): a
    /// file whose rewrite failed before its rename is stopped at the fence it
    /// stands at ([`rewrite_or_stop`]).
    fn rewrite_classified_files(&mut self, covered: u64, stop: bool) -> Vec<Unwritten> {
        let mut failures = Vec::new();
        let records = self.index_records(covered);
        failures.extend(rewrite_or_stop(&mut self.files.index, INDEX_FILE, records, covered, stop));
        let records = self.masked_records(covered);
        failures.extend(rewrite_or_stop(
            &mut self.files.masked,
            MASKED_FILE,
            records,
            covered,
            stop,
        ));
        let records = self.stream_records(covered);
        failures.extend(rewrite_or_stop(
            &mut self.files.streams,
            STREAMS_FILE,
            records,
            covered,
            stop,
        ));
        failures
    }

    /// Rewrites the offset array alone from the log's offsets.
    ///
    /// It is the open's answer where the log stands and the file's offsets
    /// disagree with it, the fourth file of [`Inner::rewrite_derived_files`],
    /// and the walk's landing's last file, written after `commits.log`
    /// because it names that file's lines; `stop` as
    /// [`Inner::rewrite_classified_files`] reads it.
    fn rewrite_offsets_file(&mut self, covered: u64, stop: bool) -> Vec<Unwritten> {
        let records = self.offset_records(covered);
        rewrite_or_stop(&mut self.files.offsets, OFFSETS_FILE, records, covered, stop)
            .into_iter()
            .collect()
    }

    /// Returns the index file's records at or below `covered`.
    ///
    /// They come from the classification map; a record above the fence is
    /// left out, since a file's coverage is the higher of its fence and its
    /// highest record ([`LineFile::open`]), and a claim past an unsorted
    /// position would read it as contributing nothing at the next open.
    fn index_records(&self, covered: u64) -> Vec<Value> {
        self.docs
            .range(..=covered)
            .map(|(at, ds)| derived::record_object(*at, vec![(INDEX_DOCS, doc_strings(ds))]))
            .collect()
    }

    /// Returns the bitmap's records at or below `covered`, from the masked set.
    fn masked_records(&self, covered: u64) -> Vec<Value> {
        self.masked.range(..=covered).map(|at| derived::record_object(*at, Vec::new())).collect()
    }

    /// Returns the streams file's records at or below `covered`.
    ///
    /// They come from the classification map's owners.
    fn stream_records(&self, covered: u64) -> Vec<Value> {
        self.docs
            .range(..=covered)
            .filter_map(|(at, ds)| {
                let owners = owners_of(ds);
                (!owners.is_empty()).then(|| {
                    derived::record_object(*at, vec![(STREAMS_OWNERS, addr_strings(&owners))])
                })
            })
            .collect()
    }

    /// Returns the offset array's records at or below `covered`.
    ///
    /// They come from the log's offsets.
    fn offset_records(&self, covered: u64) -> Vec<Value> {
        self.log
            .offsets()
            .range(..=covered)
            .map(|(at, o)| {
                derived::record_object(*at, vec![(OFFSETS_OFFSET, Value::Number(o.0.into()))])
            })
            .collect()
    }

    /// Folds one classified position into the twins and appends its lines.
    ///
    /// Three of the four twins take the position here — the offset array's
    /// takes it at the log's record ([`CommitsLog::record`]), where the line
    /// is appended — and their four files its lines; where `attest` is the
    /// marker slot this write filled, it is mirrored into the attest store
    /// ([`AttestStore::record`]) too. This is the one path at record time, so
    /// a live commit cannot leave a twin and its file disagreeing about what
    /// a position contributed.
    ///
    /// It is not the only path that contribution takes, and a fifth derived
    /// structure owes all three: this fold; [`Feed::open`]'s
    /// replay-then-derive, where the file is the authority for a position at or
    /// below its coverage and the classification for one above it; and the
    /// compaction rewrite that renders the twin back to lines
    /// ([`Inner::rewrite_derived_files`], with the trim before it). A structure
    /// wired here alone is empty from every open until the next commit, with
    /// its file's fence reporting it covered — which is a short candidate set
    /// claiming completeness, not the silent incompleteness the coverage check
    /// closes. (The attest store owes its own two, on its own card, and by its
    /// class no third.)
    ///
    /// Answers the attest line's sync, owed where this write filled its marker
    /// slot ([`OwedSync`]: the caller makes it off the lock); the four twins
    /// and their files are folded whatever it answers.
    ///
    /// **While the walk's region is pending** (`Recorded::Held`) the twins
    /// alone take the position and the four files take no line — the offset the
    /// array's line would carry does not exist until the landing's rewrite
    /// assigns it, and the landing rewrites the four files whole from the
    /// twins, this position among them; the attest store's line is appended and
    /// its sync owed all the same, the store's file being its own. **While the
    /// bare positions the index lost are pending**, and until the landing has
    /// rewritten the files ([`Inner::landing_owed`]), the log took the line
    /// and the four files take none, for the same reason: each is fenced
    /// below the set, and a line above it would raise the file's claim over
    /// positions the walk has yet to land, or sorted since, which the next
    /// open would read as contributing nothing — a draft write unmasked.
    ///
    /// # Errors
    ///
    /// [`AttestStoreFailed`] where the attest store's line could not be written
    /// (SO-I5 (d)).
    fn fold_position(
        &mut self,
        at: u64,
        recorded: Recorded,
        docs: Vec<Doc>,
        attest: Option<Attestation>,
    ) -> Result<Option<OwedSync>, AttestStoreFailed> {
        let stored = attest.map(|slot| self.attest.record(at, slot)).transpose();
        let folded = self.fold_into_maps(at, docs);
        let Recorded::Appended(offset) = recorded else {
            return stored;
        };
        if self.landing_owed {
            return stored;
        }
        self.files
            .offsets
            .append_or_report(at, vec![(OFFSETS_OFFSET, Value::Number(offset.0.into()))]);
        if let Some(docs) = &folded.docs {
            self.files.index.append_or_report(at, vec![(INDEX_DOCS, docs.clone())]);
        }
        if folded.masked {
            self.files.masked.append_or_report(at, vec![]);
        }
        if let Some(owners) = &folded.owners {
            self.files.streams.append_or_report(at, vec![(STREAMS_OWNERS, owners.clone())]);
        }
        stored
    }

    /// Folds one classified position into three twins and nothing else.
    ///
    /// It is the maps' half of [`Inner::fold_position`], shared with the
    /// walk's landing ([`Feed::land`]), which folds the region's positions
    /// this way and then rewrites the files whole: the index (docs
    /// non-empty), the bitmap or the published stream, each named draft's
    /// owner stream, and the classification map, the index's inverse — the
    /// fourth twin, the offset array, being the log's. Answers what the
    /// files' lines would carry ([`Folded`]), so the record step appends
    /// exactly what the maps took.
    fn fold_into_maps(&mut self, at: u64, docs: Vec<Doc>) -> Folded {
        let mut folded = Folded { docs: None, masked: false, owners: None };
        if !docs.is_empty() {
            for d in &docs {
                let list = self
                    .index
                    .entry(d.addr.tumbler().clone())
                    .or_insert_with(|| (d.addr.clone(), Vec::new()));
                push_in_order(&mut list.1, at);
            }
            folded.docs = Some(doc_strings(&docs));
        }
        if masked_at_commit(&docs) {
            self.masked.insert(at);
            folded.masked = true;
        } else {
            self.published.insert(at);
        }
        let owners = owners_of(&docs);
        if !owners.is_empty() {
            for owner in &owners {
                push_in_order(self.streams.entry(owner.clone()).or_default(), at);
            }
            folded.owners = Some(addr_strings(&owners));
        }
        if !docs.is_empty() {
            self.docs.insert(at, docs);
        }
        folded
    }

    /// Applies the mask per entry (PUB-7.20; PUB-6.44–6.45) and the narrowings.
    ///
    /// Beside the mask it tests the narrowings' per-entry predicates, and
    /// answers the entry's meta and its docs reduced to the requester's
    /// readable ones — and whether the reduction kept the record's docs
    /// whole, which is what decides the row's `attest` (the third absence,
    /// which [`Feed::page`] states) — or `None` when the entry is omitted. A
    /// position the walk has yet to sort ([`Inner::unsorted`]) is omitted at
    /// every class: its class is unknown until the journal answers, and the
    /// page's reach test keeps it off every merge, so this is the guard
    /// behind that test and never the answer a page is built on.
    fn visible(&self, class: &FeedClass<'_>, query: &ChangesQuery, at: u64) -> Option<Visible<'_>> {
        if self.unsorted.contains(&at) {
            return None;
        }
        let meta = self.log.entries().get(&at)?;
        let docs: &[Doc] = self.docs.get(&at).map(Vec::as_slice).unwrap_or(&[]);
        let reduced: Vec<&Doc> = docs.iter().filter(|d| class.readable(&d.addr)).collect();
        if !docs.is_empty() && reduced.is_empty() {
            return None; // masked at this class
        }
        if let Some(under) = &query.under {
            if !reduced.iter().any(|d| is_prefix(under, d.addr.tumbler())) {
                return None;
            }
        }
        if query.drafts_only && !reduced.iter().any(|d| d.is_draft()) {
            return None;
        }
        let whole = reduced.len() == docs.len();
        Some(Visible { meta, reduced, whole })
    }

    /// Returns the candidate sources for `class` and `query`.
    ///
    /// Each is an ascending iterator of positions at or above `start` — what
    /// the merge unions. Exact by the mask, and complete by construction in
    /// each of the two branches this function has, which are complete for
    /// different reasons.
    ///
    /// The walk branch's six source kinds cover every visible position: a
    /// `[]`-docs or published-touching entry is in the published walk; a
    /// draft entry is in its owner's stream, which the subtree clause — by
    /// key for the requester's own and ancestor accounts, by range for the
    /// owner accounts beneath it — or the grant clause selects, or in the
    /// index lists the universal term selects.
    ///
    /// The merge branch returns before any of them, from the index alone,
    /// and is complete for its own narrower question: a position visible
    /// under `under=` has a reduced doc under that prefix, that doc is
    /// readable (reduction is by the mask) and so survives the skip, and its
    /// index list carries the position — so the position is in that list's
    /// source. Nothing else is asked of the branch, because `under=` is the
    /// only query it serves.
    fn sources<'s>(
        &'s self,
        class: &'s FeedClass<'_>,
        query: &'s ChangesQuery,
        start: u64,
    ) -> Vec<Box<dyn Iterator<Item = u64> + 's>> {
        let mut sources: Vec<Box<dyn Iterator<Item = u64> + 's>> = Vec::new();
        if let Some(under) = &query.under {
            if self.merge_beats_walk(under, start) {
                // Merge (PUB-7.32, PUB-7.33): the index lists under the
                // prefix, an unreadable document's whole list skipped on one
                // test — the doc-granular skip.
                for (doc, positions) in self.under_prefix(under) {
                    if !class.readable(doc) {
                        continue;
                    }
                    sources.push(Box::new(at_or_above(positions, start)));
                }
                return sources;
            }
            // Walk: the visible stream below, the prefix tested per entry
            // by `visible`.
        }
        if !query.drafts_only {
            sources.push(Box::new(self.published.range(start..).copied()));
        }
        for account in &class.enclosing_subtrees {
            if let Some(stream) = self.streams.get(account) {
                sources.push(Box::new(at_or_above(stream, start)));
            }
        }
        // PUB-7.24's subtree term, the descendant owner accounts' streams
        // (RES-220): the subtree clause runs both ways, so a parent's page
        // carries the draft positions of every owner account beneath its own —
        // which the masked bitmap keeps off the published walk and no key above
        // opens.
        if let Some(account) = &class.descendants_under {
            for (_owner, stream) in streams_beneath(&self.streams, account) {
                sources.push(Box::new(at_or_above(stream, start)));
            }
        }
        for IssuerGrantIndexRow { issuer, content_prefixes: prefixes } in &class.issuers {
            let Some(stream) = self.streams.get(*issuer) else { continue };
            // A grant at the issuer's account depth or wider is the stream
            // (PUB-7.25); narrower prefixes take the per-entry containment
            // test against their union — while that union is small enough
            // for the test to be worth making ([`MAX_FILTERED_PREFIXES`]).
            if prefixes.len() > MAX_FILTERED_PREFIXES
                || prefixes.iter().any(|p| is_prefix(p.tumbler(), issuer.tumbler()))
            {
                sources.push(Box::new(at_or_above(stream, start)));
            } else {
                sources.push(Box::new(
                    at_or_above(stream, start)
                        .filter(move |at| self.names_under(*at, issuer, prefixes)),
                ));
            }
        }
        // A covered prefix, not an issuer account: this keys the position
        // index, never `streams`, which the loop above keys by owner.
        for prefix in &class.universal_prefixes {
            // The universal term (PUB-7.22): the live any-principal prefix's
            // own index lists — the mask's grant clause admits exactly the
            // entries the issuing owner covers.
            for (_doc, positions) in self.under_prefix(prefix.tumbler()) {
                sources.push(Box::new(at_or_above(positions, start)));
            }
        }
        sources
    }

    /// Returns the per-entry containment test of a narrower grant.
    ///
    /// It answers whether the entry at `at` names a draft of `issuer` under
    /// one of `prefixes`.
    ///
    /// A candidate filter and never the answer, and the reason it may be
    /// stood aside past [`MAX_FILTERED_PREFIXES`] is weaker than "it drops
    /// only what the mask drops", which is false: an entry naming a
    /// published document beside a draft of this issuer outside the granted
    /// prefixes is dropped here and kept by the mask, and reaches the page
    /// through the published walk. What holds is that this filter only ever
    /// removes candidates from one source, [`Merge`] unions and deduplicates
    /// the sources, and [`Inner::visible`] is the authority on every
    /// candidate that survives — so standing it aside can only widen a
    /// candidate set the mask then decides, and no page moves.
    fn names_under(&self, at: u64, issuer: &Address, prefixes: &[&Address]) -> bool {
        self.docs.get(&at).is_some_and(|ds| {
            ds.iter().any(|d| {
                d.draft_owner.as_ref() == Some(issuer)
                    && prefixes.iter().any(|p| is_prefix(p.tumbler(), d.addr.tumbler()))
            })
        })
    }

    /// Returns the index lists under `p`, each document with its positions.
    ///
    /// They are the documents whose key `p` is a prefix of. This is the one
    /// spelling of the fact [`Inner::index`] is keyed for — a prefix's
    /// documents are one contiguous key range under M1's ordering, so the
    /// enumeration is a `range` from `p` cut at the first key `p` does not
    /// cover, never a walk of the map.
    ///
    /// One home because [`Inner::merge_beats_walk`] prices the set
    /// [`Inner::sources`]' merge branch then enumerates: the two must range
    /// over the same documents, or the rule chooses its branch by counting
    /// something else. The branch additionally skips the unreadable ones,
    /// which is its own doc-granular skip and stays at the call site; the
    /// cost rule deliberately counts them, and the direction that biases it
    /// is stated there.
    fn under_prefix<'a>(
        &'a self,
        p: &'a Tumbler,
    ) -> impl Iterator<Item = (&'a Address, &'a [u64])> + 'a {
        self.index
            .range(p..)
            .take_while(move |(k, _)| is_prefix(p, k))
            .map(|(_, (doc, positions))| (doc, positions.as_slice()))
    }

    /// Applies the merge-or-walk rule (PUB-7.33), answering `true` to merge.
    ///
    /// Merge iff the prefix holds no more documents than the range holds
    /// positions. Both counts advance together and stop at the first to run
    /// out, so the rule costs O(min(documents, positions)) and needs no rank
    /// structure.
    ///
    /// The documents counted are [`Inner::under_prefix`]'s — the same set
    /// the merge branch enumerates, which is what makes this a price of
    /// that branch rather than of some other set that happens to be nearby.
    /// It counts the unreadable ones too, which the branch then skips one
    /// whole list at a time, so the count is an over-estimate of the merge's
    /// real work and never an under-estimate. That biases the rule toward
    /// the walk — it can decline a merge that would have been marginally
    /// cheaper over the readable subset — and never toward a merge whose
    /// sources outnumber what was measured.
    fn merge_beats_walk(&self, under: &Tumbler, start: u64) -> bool {
        let mut docs = self.under_prefix(under);
        let mut positions = self.log.entries().range(start..);
        loop {
            match (docs.next(), positions.next()) {
                (Some(_), Some(_)) => {}
                (None, _) => return true,
                (Some(_), None) => return false,
            }
        }
    }
}

/// Returns a position list from its first member at or above `start`.
///
/// It is the fence, applied to every slice-backed source. [`Inner::sources`]'
/// contract has two clauses and this call discharges one of them: the
/// at-or-above half, which it and `published.range(start..)` discharge and
/// nothing else does, since [`Inner::visible`] tests the mask and the two
/// narrowings and does not re-test the fence — a source that skipped this
/// would serve positions at or below `since`, which is a client re-reading
/// its own history on every poll, with `last` going backwards.
///
/// The ascending half is the collections', each stated on its own field:
/// `published` is a `BTreeSet`, and `index` and `streams` are each ordered
/// at each of their three construction paths — by the container at replay
/// (the index) or by an explicit sort (the streams), by the write-path
/// serialization guard's commit order at the record, and by placement at
/// the walk's landings ([`push_in_order`]). `partition_point` is meaningless
/// on an unsorted slice, so this returns an arbitrary suffix rather than a
/// fence for a list that lost it.
fn at_or_above(positions: &[u64], start: u64) -> impl Iterator<Item = u64> + '_ {
    let i = positions.partition_point(|&p| p < start);
    positions[i..].iter().copied()
}

/// Places `at` in an ascending position list, once.
///
/// It is the one way a position enters an index list or an owner stream
/// after the open ([`Inner::fold_into_maps`]): a push where `at` lies above
/// the list's last — the record step's case, every commit above the one
/// before — and an insert at its place where it does not — the walk's
/// landings, which place a position the open found unsorted or uncovered
/// below the ones recorded while the walk ran, at most the window's length
/// of moves. A position the list holds is not repeated.
fn push_in_order(list: &mut Vec<u64>, at: u64) {
    match list.last() {
        Some(&last) if last < at => list.push(at),
        Some(&last) if last == at => {}
        _ => {
            if let Err(i) = list.binary_search(&at) {
                list.insert(i, at);
            }
        }
    }
}

/// Returns the draft streams of the owner accounts strictly beneath `account`.
///
/// They are PUB-7.24's subtree term of a principal's supplement, its
/// descendant owner accounts (RES-220 names it). [`Inner::streams`] is keyed
/// by owner account in tumbler order, so the owner accounts under a prefix
/// are one contiguous key range under M1's ordering — the fact
/// [`Inner::under_prefix`] spells for the position index — and the
/// enumeration is a `range` opened past `account` and cut at the first key it
/// does not contain. Never a walk of the map, and never a walk of M3's
/// accounts: it costs the owner accounts beneath `account` that hold a
/// stream, which is the subtree term exactly, and an account beneath it that
/// owns no draft is not in the map to be counted.
///
/// `account`'s own stream is excluded: [`FeedClass::enclosing_subtrees`] keys
/// it, and the range opens past it so that no stream is merged twice.
///
/// A candidate source like the rest, and never the answer: a key this range
/// admits that is no descendant account — reachable only off a
/// `feed-streams.log` this daemon did not write — puts forward positions
/// [`Inner::visible`] then judges entry by entry.
fn streams_beneath<'a>(
    streams: &'a BTreeMap<Address, Vec<u64>>,
    account: &'a Address,
) -> impl Iterator<Item = (&'a Address, &'a [u64])> + 'a {
    streams
        .range::<Address, _>((Bound::Excluded(account), Bound::Unbounded))
        .take_while(move |(owner, _)| is_prefix(account.tumbler(), owner.tumbler()))
        .map(|(owner, positions)| (owner, positions.as_slice()))
}

/// Returns the bitmap's test: docs non-empty and every one a draft.
///
/// The fact is class-independent and fixed at mint, so the name says what it
/// is and not when it is evaluated — [`Feed::open`] calls it for the derived
/// tail, long after the commit.
///
/// It is exactly the mask at the guest's class — a guest reads published
/// documents alone, so "every named document is a draft" is "none readable
/// to a guest" — which is why the bitmap's complement is the published
/// stream a guest page walks in O(page). The mask, the per-class verdict
/// wire.md gives the bare word to, is [`Inner::visible`]'s, computed per
/// entry against the requester's own predicate (PUB-7.20).
fn masked_at_commit(docs: &[Doc]) -> bool {
    !docs.is_empty() && docs.iter().all(Doc::is_draft)
}

/// Returns the owner accounts of an entry's drafts.
///
/// They are the streams the position enters.
fn owners_of(docs: &[Doc]) -> BTreeSet<Address> {
    docs.iter().filter_map(|d| d.draft_owner.clone()).collect()
}

fn doc_strings(docs: &[Doc]) -> Value {
    Value::Array(docs.iter().map(|d| Value::String(d.addr.to_string())).collect())
}

fn addr_strings<'a>(addrs: impl IntoIterator<Item = &'a Address>) -> Value {
    Value::Array(addrs.into_iter().map(|a| Value::String(a.to_string())).collect())
}

/// Returns one derived record's array field, as its raw elements.
///
/// So a caller counting what it could read counts against what the file
/// claimed. Handing back strings loses two things at once: a name every caller
/// parses and discards, and an element that is not a string at all, dropped
/// ahead of the "did every name parse?" test [`Feed::open`]'s docs read
/// makes of the count.
///
/// An element this daemon cannot turn into an address — a non-string, or a
/// string [`parse_dotted`] refuses — is one malformed name, and each of the
/// two reads states for itself what dropping one costs it.
///
/// An absent field and one that is not an array both answer the empty
/// slice, which is the residue [`Inner::masked`]'s own card already accepts
/// for a file this daemon did not write.
fn elements_of(v: Option<&Value>) -> &[Value] {
    v.and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

/// The walk's classification of the bare positions the index lost.
///
/// A lost sidecar never unmasks a draft write (PUB-6.45), so each such
/// position is classified from the journal: its documents are the diff of
/// the world at the entry below it — the previous entry, or genesis — and
/// its own ([`derived_docs`]), each world rebuilt by a history read
/// (`Kernel::world_at`), one base loaded and the journal above it folded,
/// nothing memoized. A run of consecutive bare positions, which is what a
/// walk's landing writes, shares its worlds: the world at one is the world
/// below the next, so it is carried forward, and the run costs one
/// reconstruction a position and one below its first, the region's walk's
/// own count ([`reconstruct`]); the head's own world is the open's snapshot,
/// never rebuilt. A carried world is spent only where the position's
/// previous entry is the one it was rebuilt at, and dropped ahead of any
/// other rebuild, so at most two rebuilt worlds are held at once.
struct BareClassifier<'a> {
    kernel: &'a Kernel<World>,
    /// The open's snapshot of the head, whose world is the head's own.
    head: &'a Snapshot<World>,
    /// The world at the bare position last classified, with its position.
    carried: Option<(u64, World)>,
    /// The world reconstructions the journal answered.
    reconstructions: usize,
}

impl<'a> BareClassifier<'a> {
    fn new(kernel: &'a Kernel<World>, head: &'a Snapshot<World>) -> BareClassifier<'a> {
        BareClassifier { kernel, head, carried: None, reconstructions: 0 }
    }

    /// Returns the documents the commit at the bare position `at` touched.
    ///
    /// `below` is the entry below `at` in the log, genesis where none stands
    /// ([`ToSort`]).
    ///
    /// # Errors
    ///
    /// The journal's refusal of either world (reclaimed, corrupt, I/O): the
    /// position is then the module's unclassifiable residue, served to every
    /// class, and the caller says the refusal. The world at `at` is not
    /// asked for where the world below it was refused, and no world is
    /// carried past a refusal.
    fn classify(&mut self, at: u64, below: u64) -> Result<Vec<Address>, HistoryError> {
        let below = match self.carried.take() {
            Some((carried, world)) if carried == below => world,
            stale => {
                drop(stale);
                self.rebuild(below)?
            }
        };
        if at == self.head.seq().0 {
            return Ok(derived_docs(&below, self.head.world()));
        }
        let above = self.rebuild(at)?;
        let docs = derived_docs(&below, &above);
        self.carried = Some((at, above));
        Ok(docs)
    }

    /// Returns the world at `at`, rebuilt from the journal, and counts it.
    ///
    /// # Errors
    ///
    /// The journal's refusal of the world (reclaimed, corrupt, I/O), which
    /// is not counted.
    fn rebuild(&mut self, at: u64) -> Result<World, HistoryError> {
        let world = self.kernel.world_at(Seq(at))?;
        self.reconstructions += 1;
        Ok(world)
    }

    /// Returns the world reconstructions the journal answered.
    ///
    /// It releases the world carried.
    fn finish(self) -> usize {
        self.reconstructions
    }
}

/// The K-way merge of ascending position sources (PUB-7.26).
///
/// It is deduplicated by position across the whole merge: a min-heap over
/// each source's head, so a page costs O(log K) per candidate.
struct Merge<'a> {
    sources: Vec<Box<dyn Iterator<Item = u64> + 'a>>,
    heap: BinaryHeap<Reverse<(u64, usize)>>,
}

impl<'a> Merge<'a> {
    fn new(mut sources: Vec<Box<dyn Iterator<Item = u64> + 'a>>) -> Merge<'a> {
        let mut heap = BinaryHeap::new();
        for (i, source) in sources.iter_mut().enumerate() {
            if let Some(next_at) = source.next() {
                heap.push(Reverse((next_at, i)));
            }
        }
        Merge { sources, heap }
    }
}

impl Iterator for Merge<'_> {
    type Item = u64;

    /// Returns the next position, each emitted exactly once.
    fn next(&mut self) -> Option<u64> {
        let Reverse((at, i)) = self.heap.pop()?;
        if let Some(next_at) = self.sources[i].next() {
            self.heap.push(Reverse((next_at, i)));
        }
        // Every other source standing at the same position: dropped here, so
        // a position the merge emits is emitted once however many sources
        // carry it.
        while let Some(Reverse((dup_at, j))) = self.heap.peek().copied() {
            if dup_at != at {
                break;
            }
            self.heap.pop();
            if let Some(next_at) = self.sources[j].next() {
                self.heap.push(Reverse((next_at, j)));
            }
        }
        Some(at)
    }
}

#[cfg(test)]
mod tests;
