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
//! and held resident as its twin over the window; and, in their line shape
//! under a class of its own, the attest store ([`AttestStore`], `attest.rs`,
//! which states the class), whose slot for a position the page renders as
//! the entry's `attest` member (`CommitMeta::entry`). The six files are
//! kept whole from genesis (wire.md §The change feed, Retention): the record
//! of events — a commit's position, time, hand, op, documents and terms —
//! is never dropped, whatever the journal reclaims of the board's states,
//! and a mirror may begin from `since=0` at any age. What the daemon holds
//! resident is THE WINDOW — the newest `limits::FEED_RESIDENT_WINDOW`
//! positions' entries and twins (`CommitsLog::resident_from`), trimmed as
//! each record moves its edge ([`Inner::drop_below_the_window`]) — and
//! below it a page reads the files themselves by position (`window.rs`:
//! one search over a file's bytes and one sequential read; [`LogLines`],
//! [`Peek`], [`Candidates`]), so no page's bytes depend on which side of the
//! window its positions lie. The four twins:
//!
//! * the per-document position index (`index`: document → positions, keyed
//!   by tumbler, so an account's documents and any content-prefix are one
//!   contiguous key range) — the `under=` narrowing's and the universal
//!   term's source over the window, with the per-position classification
//!   map (`docs`) as its inverse; below the window the index FILE answers a
//!   position's documents to the page's walk;
//! * the position → offset array (`CommitsLog::offsets`) — position-keyed
//!   access into `commits.log` over the window, from which
//!   `feed-offsets.log`'s lines are appended; the reads below the window
//!   seek by position, not by offset, and the file is kept right for a
//!   reader that would;
//! * the masked-position bitmap (`masked`: positions whose docs are
//!   non-empty and all drafts at commit) and its complement, the
//!   materialized published stream (`published`), which a guest page walks
//!   in O(page) over the window. For a position the bitmap does not hold it
//!   is a skip accelerator and never the authority: the position is walked
//!   and the mask decides. For one it holds, it decides candidacy — the
//!   field's own card states that direction and the invariant it rests on;
//! * the per-owner-account draft-position streams (`streams`: owner →
//!   positions naming one of that owner's drafts — every fully-masked
//!   position plus the straddles).
//!
//! Below the window every page is the position walk itself: each line of
//! `commits.log` above `since`, its documents off the index file, its slot
//! off the attest store's, the mask applied per entry — the oracle's own
//! form, which the twins' merge over the window answers equivalently.
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
//! reconstruction the open does not pay. The four derived files are cut
//! back short of every pending position — the region's lower edge, the
//! first unsorted position less one, whichever is lower — and the write path
//! then runs the walk on a thread of its own ([`Feed::walk_and_land`]) while
//! the board serves — at the open instead, where the OS refuses the thread.
//! Meanwhile a page whose rows would reach a pending position is refused
//! [`ChangesAnswer::Rebuilding`] (`503 feed_rebuilding`, retry-class), pages
//! below and above serving — served, such a page would skip the set's
//! positions in silence or, read off the files that stand, carry rows a
//! class may not see: an issuer stream taken whole past
//! [`MAX_FILTERED_PREFIXES`], a straddle's `attest` — so the refusal is the
//! one answer; a write's record enters the twins and, the region pending,
//! none of the five files, the set pending, the log alone
//! ([`Inner::fold_position`]). The walk sorts the set first, in one pass
//! with the region's walk where both pend: each position classified from
//! the journal off the world below it and its own, carried forward along a
//! run ([`BareClassifier`]), and landed as it is sorted
//! ([`Feed::land_sorted`]) — folded into the twins, the index file appended
//! up to it, so a kill mid-sort keeps the progress and the next open pends
//! the rest. Then the landing under this feed's lock ([`Feed::land`]): the
//! region's classifications folded into the twins as the record step folds
//! a position; the index, the bitmap and the streams rewritten keeping
//! every record they held, the positions above each one's coverage added
//! from the twins and, for the recorded positions between them, from the
//! log and the index read by position ([`Inner::classified_above`]); then
//! one rewrite of `commits.log` — every line it held, the fence where the
//! walk moved it, the walked boundaries bare and the held positions, in
//! position order, every landed line's offset assigned — where a region
//! pended; and last the offset array that names its lines. So a kill
//! between two of them leaves the region to a walk behind the listener
//! again, never to a classification before the board serves; and a derived
//! file whose landing rewrite fails before its rename, short of what the
//! walk landed, takes no further line. The attest store's file is
//! untouched, its resident slots trimmed with the twins, its lines appended
//! all the same and its open having made the window's slots resident from
//! its own lines and, above its coverage, from the kernel's markers.
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
mod window;

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::io;
use std::num::NonZeroUsize;
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use serde_json::{Map, Value};
use skep_address::{is_prefix, parent, Address, Tumbler};
use skep_engine::{Engine, IssuerGrantIndexRow, ReaderClass, World};
use skep_kernel::{Attestation, HistoryError, Kernel, Seq, Snapshot};
use skep_namespace::{HasM3, PrincipalId};
use skep_util::notice::Class;

use self::attest::{attest_of_record, AttestStore};
use self::derived::{
    LineFile, OwedSync, Records, SyncHandle, INDEX_DOCS, INDEX_FILE, MASKED_FILE, OFFSETS_FILE,
    OFFSETS_OFFSET, STREAMS_FILE, STREAMS_OWNERS,
};
use self::window::Cursor;
#[cfg(any(test, feature = "test-hooks"))]
use super::sidecar::{fire_the_feed_walks_fault, FEED_WALK_HOLD};
use super::sidecar::{
    demoted, line_bytes, list_boundaries, parse_line as parse_log_line, reconstruct, Carrier,
    CommitMeta, CommitsLog, Cut, CutHead, FeedPending, IoCause, JournalTerms, MalformedCase,
    MalformedNamesLine, OpTerms, ProgressCadence, Record as LogRecord, Recorded, RewriteFail,
    Unsorted, WalkControl, WalkLandingLine, WalkOpenLine, WalkOutcome, WalkRefusedLine,
    SIDECAR_FILE,
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
    /// The head world the class stands on: the one snapshot the route pinned.
    ///
    /// The page below the resident window classifies each position's
    /// documents against it as it reads them off the index file
    /// (`classify`, an immutable fact of the position — publication is fixed
    /// at mint — so the answer is the one the open or the record step gave
    /// the twins), which is what makes a page's bytes the same on either
    /// side of the window.
    world: &'a World,
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
            world,
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

/// What the change feed holds, as one read of it answers.
///
/// It is the answer of `Feed::figures`, read by the checkpoint thread for
/// its landing line: the feed's files are kept whole from genesis, so what
/// a landing moves of the feed is nothing, and what the line says is what
/// the feed holds — the first position its files hold a line for (the wire's
/// `floor`; `1` on a board that never compacted and never lost a line),
/// `commits.log`'s size, the operator's sizing figure, and the resident
/// window's count beside the most it has held this uptime, so a window that
/// outgrew its span is told from one that holds it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeedFigures {
    /// The first position the feed's files hold a line for, or `None` for none.
    pub first: Option<u64>,
    /// `commits.log`'s size in bytes, as the feed last wrote it.
    pub bytes: u64,
    /// The entries the resident window holds now.
    pub resident: usize,
    /// The most entries the window has held this uptime.
    pub resident_most: usize,
}

/// What `feed-attest.log` holds, as one read of it answers.
///
/// The file is never compacted — below the reclaim floor its lines are an
/// entry signature's only copy — so it grows by one line per attested
/// commit, ~6.9 KB under tag 1, for the life of the board; the slots
/// resident are one per attested position inside the feed's resident window
/// (~3.4 KB each), trimmed with the feed's other twins as the window rises,
/// so the window bounds them. Read by the checkpoint thread at each landing,
/// for its line.
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
    /// The feed's files below the resident window could not be read.
    ///
    /// The page reaches positions below the window, which the files answer
    /// by position (`Candidates`, the module's), and the OS refused the
    /// read — the daemon's own files for a position it holds, so the answer
    /// is the history surface's own for a journal it cannot read, `500
    /// history_io`, with the cause; a page over the window alone reads no
    /// file and never answers this.
    Unreadable {
        /// The OS's words, with the file's name.
        detail: String,
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
    /// The data dir the six files live in — what the reads by position open.
    dir: PathBuf,
    /// Position → its classified docs, over the window (positions with docs only).
    ///
    /// It is the index's inverse, and what the mask reads per entry; below
    /// the window the index file answers the page's walk the same documents.
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
    /// ([`Feed::land_sorted`]); the window's trim never touches it — the
    /// set is whole wherever its positions lie — and a walk's fence drops
    /// the ones at or below it ([`Inner::drop_at_or_below`]).
    unsorted: BTreeSet<u64>,
    /// Whether the walk has yet to land what the open left pending.
    ///
    /// Set at [`Feed::open`] where a region or a set pends, cleared at the
    /// end of [`Feed::land`], once the four files are rewritten whole. It
    /// outlasts the set: the last position sorted leaves the set before the
    /// landing's rewrite, and a line a file took in that window — the four
    /// standing fenced below the set — would raise its claim over the
    /// positions sorted since, so the record step appends to no file while
    /// this stands ([`Inner::fold_position`]), and a suite that waits on the
    /// landing waits on this (`Feed::walk_pending`).
    landing_owed: bool,
    /// The attest store, on its own card ([`AttestStore`]).
    ///
    /// Its class keeps it out of `files` and out of every rewrite here; its
    /// resident slots are trimmed beside the twins
    /// ([`Inner::drop_below_the_window`]), its file never. Read per rendered
    /// entry by [`Feed::page`], the one consumer — off the file by position
    /// below the window.
    attest: AttestStore,
    files: Files,
}

/// The four derived sidecars' files.
///
/// They are the ones the walk's landing rewrites and the open cuts back;
/// the attest store keeps its own.
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
    /// pending, below; holding resident the window alone), replays each of
    /// the four derived sidecars for its cut, its foreign lines and its
    /// coverage, then reads the five files together by position
    /// ([`LogLines`], [`Peek`]) over one range — the window, and every
    /// file's missing tail — deriving each one's tail from `commits.log` and
    /// the index as it goes (a recorded position's contribution from its own
    /// record; a bare position the index no longer classifies is the walk's,
    /// recorded as pending, never classified here) and building the twins
    /// over the window; fences each at the head, or short of the first
    /// pending position where any pends; then opens the attest store
    /// ([`AttestStore::open`]). Runs after M2's load-and-replay and before
    /// the first page (PUB-6.40): every classification here reads the
    /// recovered head's exception set, and the grant fold it stands beside
    /// is seeded by the same load.
    ///
    /// **Cost.** The `commits.log` scan, whose cost `CommitsLog::open`
    /// states — the walk is not the open's, nor is any world reconstruction:
    /// a bare position the index lost is sorted behind the listener — plus
    /// O(each derived file) to replay it, O(the window) to read the five
    /// over it, and O(any missing tail) to close it, a whole-file loss being
    /// one O(the log) derivation of what the log's records classify; and
    /// the attest store's own open, whose cost [`AttestStore::open`] states.
    /// Never a rewrite per restart: a derived file is cut back only while the
    /// walk has a region or a set pending (below), and the offset array
    /// alone is re-derived whole, where `commits.log`'s own offsets moved or
    /// its lines no longer match the log's. Nothing is held resident beyond
    /// the window: the files are kept whole from genesis, and a page below
    /// the window reads them by position.
    ///
    /// **The lines** (`operations.md` §1.1 rows 9, 11, 2), through `lines`,
    /// the classed door the write path made ahead of this open: a derived
    /// file's cut, answered by its replay, is said here with the last trusted
    /// position and that the cut part is re-derived ([`DerivedCutLine`]);
    /// the index file's malformed names are counted and said once with the
    /// first position and how many of them are bare, which no testimony
    /// rescues ([`MalformedNamesLine`]), over the lines the open reads — the
    /// window's and the tails'; a hole the files opened with is said once
    /// ([`OpenHoleLine`]); and the open ends on how far back `/changes`
    /// answers, what waits on the walk, and how long the open took
    /// ([`FeedOpenLine`]). The bare positions the index lost are the walk
    /// thread's to say (`operations.md` §1.1 m15; [`Feed::walk_and_land`]).
    ///
    /// **What pends** (the module doc's walk): where the log's open found
    /// positions it does not cover, or the index's replay left bare positions
    /// of the log's unclassified, the four derived files are cut back short
    /// of the first pending position — the region's lower edge or the first
    /// unsorted position less one, whichever is lower ([`LineFile::cut_back_to`]):
    /// an honest coverage claim, so a crash before the landing, or a derived
    /// rewrite the landing cannot make, leaves no file claiming over
    /// positions it never processed (the derived card's gap rule), the next
    /// open re-deriving from that fence — the set's positions enter no twin
    /// ([`Inner::unsorted`]), and the open's snapshot of the head's world is
    /// answered beside the feed, for the walk to diff from and the landings
    /// to classify against (PUB-7.7's one-snapshot clause: the head's
    /// exception set as the open read it); `None` where the log covers the
    /// head and the index every bare position it holds.
    ///
    /// # Errors
    ///
    /// Every failure of the open, which names its file, the kind kept — the
    /// replays' and the attest store's at their own opens, this open's reads
    /// by position, appends, cuts, fences and the one rewrite through one
    /// closure per file here. A rewrite is fatal either side of its rename.
    pub(super) fn open(
        dir: &Path,
        engine: &Engine,
        lines: &Lines,
    ) -> io::Result<(Feed, Option<Snapshot<World>>)> {
        let started = Instant::now();
        let log = CommitsLog::open(dir, engine, lines)?;
        let head = log.open_head();
        let pending = log.pending_region();
        let resident_from = log.resident_from();
        let fence = log.fence();
        let snap = engine.kernel().snapshot();
        let world = snap.world();

        // Each of the four replayed for its cut, its lines past the head and
        // its coverage, nothing of it held: the window's twins are read off
        // the files below, by position, once each is cut back where it must
        // be. A cut is each file's own to say: re-derived, below. A derived
        // file's lines past the head are re-derived too, so the replay's
        // report of them is not said.
        let nothing = |_: u64| false;
        let (mut f_index, _, replayed) = LineFile::open(dir, INDEX_FILE, head, nothing, lines)?;
        say_derived_cut(lines, INDEX_FILE, replayed.cut);
        if replayed.disordered {
            f_index.sort_in_place().map_err(with_file(INDEX_FILE))?;
        }
        let (mut f_offsets, _, replayed) = LineFile::open(dir, OFFSETS_FILE, head, nothing, lines)?;
        say_derived_cut(lines, OFFSETS_FILE, replayed.cut);
        if replayed.disordered {
            f_offsets.sort_in_place().map_err(with_file(OFFSETS_FILE))?;
        }
        let (mut f_masked, _, replayed) = LineFile::open(dir, MASKED_FILE, head, nothing, lines)?;
        say_derived_cut(lines, MASKED_FILE, replayed.cut);
        if replayed.disordered {
            f_masked.sort_in_place().map_err(with_file(MASKED_FILE))?;
        }
        let (mut f_streams, _, replayed) = LineFile::open(dir, STREAMS_FILE, head, nothing, lines)?;
        say_derived_cut(lines, STREAMS_FILE, replayed.cut);
        if replayed.disordered {
            f_streams.sort_in_place().map_err(with_file(STREAMS_FILE))?;
        }

        // ── the set: the bare positions the index does not classify — those
        //    the log holds bare above the index's coverage, read off the
        //    file; a world reconstruction each that the open does not pay ──
        let mut unsorted: BTreeSet<u64> = BTreeSet::new();
        {
            let mut log_lines = LogLines::above(dir, f_index.coverage().max(fence))
                .map_err(with_file(SIDECAR_FILE))?;
            while let Some((_, at, meta)) = log_lines.next().map_err(with_file(SIDECAR_FILE))? {
                if at > head {
                    break;
                }
                if matches!(meta, CommitMeta::Bare { .. }) {
                    unsorted.insert(at);
                }
            }
        }
        // The coverage the open closes the four files at: the head; the
        // region's lower edge where the walk has the rest to land; and
        // short of the first unsorted position where the set pends,
        // whichever is lower — no file claims over a position the walk has
        // yet to land. A file claiming more is cut back to it.
        let covered = pending.map_or(head, |(low, _)| low);
        let covered =
            unsorted.first().map_or(covered, |&first| covered.min(first.saturating_sub(1)));
        for (name, file) in [
            (INDEX_FILE, &mut f_index),
            (OFFSETS_FILE, &mut f_offsets),
            (MASKED_FILE, &mut f_masked),
            (STREAMS_FILE, &mut f_streams),
        ] {
            file.cut_back_to(covered).map_err(with_file(name))?;
        }
        let coverage =
            [f_index.coverage(), f_offsets.coverage(), f_masked.coverage(), f_streams.coverage()];

        // ── one read of the five files by position, over the window and
        //    over every file's missing tail: each file's tail derived — a
        //    position's documents off the index where the index covers it,
        //    off its own record above — and the twins built over the window;
        //    the offset array's lines checked against the log's own ──
        let from = coverage
            .iter()
            .copied()
            .min()
            .unwrap_or(0)
            .saturating_add(1)
            .min(resident_from)
            .max(fence.saturating_add(1));
        let mut docs: BTreeMap<u64, Vec<Doc>> = BTreeMap::new();
        let mut index: BTreeMap<Tumbler, (Address, Vec<u64>)> = BTreeMap::new();
        let mut masked: BTreeSet<u64> = BTreeSet::new();
        let mut published: BTreeSet<u64> = BTreeSet::new();
        let mut streams: BTreeMap<Address, Vec<u64>> = BTreeMap::new();
        // The index file's malformed names, counted for one line after the
        // read: the positions met, the bare ones among them, and the first.
        let mut malformed: Option<(usize, usize, u64)> = None;
        let mut offsets_agree = !log.rewritten();
        {
            let since = from.saturating_sub(1);
            let mut log_lines = LogLines::above(dir, since).map_err(with_file(SIDECAR_FILE))?;
            let mut idx = Peek::above(dir, INDEX_FILE, since).map_err(with_file(INDEX_FILE))?;
            let mut off = Peek::above(dir, OFFSETS_FILE, since).map_err(with_file(OFFSETS_FILE))?;
            let mut msk = Peek::above(dir, MASKED_FILE, since).map_err(with_file(MASKED_FILE))?;
            let mut stm = Peek::above(dir, STREAMS_FILE, since).map_err(with_file(STREAMS_FILE))?;
            while let Some((offset, at, meta)) =
                log_lines.next().map_err(with_file(SIDECAR_FILE))?
            {
                if at > head {
                    break;
                }
                // A file's line for the position, where the file covers it.
                let index_line = if at <= coverage[0] {
                    idx.take_at(at).map_err(with_file(INDEX_FILE))?
                } else {
                    None
                };
                let offset_line = if at <= coverage[1] {
                    off.take_at(at).map_err(with_file(OFFSETS_FILE))?
                } else {
                    None
                };
                let masked_line = if at <= coverage[2] {
                    msk.take_at(at).map_err(with_file(MASKED_FILE))?.is_some()
                } else {
                    false
                };
                let streams_line = if at <= coverage[3] {
                    stm.take_at(at).map_err(with_file(STREAMS_FILE))?
                } else {
                    None
                };
                if let Some(m) = &offset_line {
                    if m.get(OFFSETS_OFFSET).and_then(Value::as_u64) != Some(offset) {
                        offsets_agree = false;
                    }
                }
                // An unsorted position enters no twin and takes no line: it
                // is in nothing until the walk lands it ([`Inner::unsorted`]),
                // whatever a file that stood claimed of it.
                if unsorted.contains(&at) {
                    continue;
                }
                // The documents: the index's line where the index covers the
                // position — a derived record this daemon cannot parse is
                // never trusted over the authority file, so a recorded
                // position answers from its own testimony and a bare one
                // stays unclassified ([`index_docs`]) — the record's own
                // above it.
                let addrs: Vec<Address> = if at <= coverage[0] {
                    match index_docs(index_line.as_ref(), &meta) {
                        Ok(addrs) => addrs,
                        Err(addrs) => {
                            let (count, bare, first) = malformed.unwrap_or((0, 0, at));
                            let is_bare = matches!(meta, CommitMeta::Bare { .. });
                            malformed =
                                Some((count + 1, bare + usize::from(is_bare), first.min(at)));
                            addrs
                        }
                    }
                } else {
                    record_docs(&meta)
                };
                let classified = classify(world, addrs);
                let is_masked =
                    if at <= coverage[2] { masked_line } else { masked_at_commit(&classified) };
                let owners: BTreeSet<Address> = if at <= coverage[3] {
                    streams_line.as_ref().map(stream_owners).unwrap_or_default()
                } else {
                    owners_of(&classified)
                };
                // The tails: each file's lines for the positions above its
                // coverage, at or below the coverage the open closes it at.
                if at <= covered {
                    if at > coverage[0] && !classified.is_empty() {
                        f_index
                            .append(at, vec![(INDEX_DOCS, doc_strings(&classified))])
                            .map_err(with_file(INDEX_FILE))?;
                    }
                    if at > coverage[1] {
                        f_offsets
                            .append(at, vec![(OFFSETS_OFFSET, Value::Number(offset.into()))])
                            .map_err(with_file(OFFSETS_FILE))?;
                    }
                    if at > coverage[2] && is_masked {
                        f_masked.append(at, vec![]).map_err(with_file(MASKED_FILE))?;
                    }
                    if at > coverage[3] && !owners.is_empty() {
                        f_streams
                            .append(at, vec![(STREAMS_OWNERS, addr_strings(&owners))])
                            .map_err(with_file(STREAMS_FILE))?;
                    }
                }
                // The twins, over the window.
                if at >= resident_from {
                    if !classified.is_empty() {
                        for d in &classified {
                            let list = index
                                .entry(d.addr.tumbler().clone())
                                .or_insert_with(|| (d.addr.clone(), Vec::new()));
                            if list.1.last() != Some(&at) {
                                list.1.push(at);
                            }
                        }
                        docs.insert(at, classified);
                    }
                    if is_masked {
                        masked.insert(at);
                    } else {
                        published.insert(at);
                    }
                    for owner in owners {
                        streams.entry(owner).or_default().push(at);
                    }
                }
            }
        }
        if let Some((positions, bare, first)) = malformed {
            let case = MalformedCase::Index { bare };
            let line = MalformedNamesLine { file: INDEX_FILE, positions, first, case };
            lines.say(Class::Failure, line);
        }
        f_index.fence(covered).map_err(with_file(INDEX_FILE))?;
        f_masked.fence(covered).map_err(with_file(MASKED_FILE))?;
        f_streams.fence(covered).map_err(with_file(STREAMS_FILE))?;
        if offsets_agree {
            f_offsets.fence(covered).map_err(with_file(OFFSETS_FILE))?;
        }

        // ── the attest store, on its own card, and the handle its lines are
        //    made durable through ──
        let (attest, attest_sync) = AttestStore::open(dir, engine, &log, lines)?;

        let landing_owed = pending.is_some() || !unsorted.is_empty();
        let mut inner = Inner {
            log,
            dir: dir.to_path_buf(),
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
        // ── the offset array, re-derived whole where the log's own offsets
        //    moved under it — this open's purge of another journal's lines
        //    rewrote the file — or its lines disagree with the log's: one
        //    stream of `commits.log`, every line's byte, fenced at `covered`.
        //    Fatal here, either side of a rename: nothing is served yet — the
        //    bare I/O error wrapped with the file's name, which
        //    `RewriteFail::into_io` does not carry. ──
        if !offsets_agree {
            inner
                .rewrite_offsets_file_whole(covered)
                .map_err(|failed| with_file(OFFSETS_FILE)(failed))?;
        }
        if let Some((fence, floor)) = inner.log.hole() {
            lines.say(Class::Open, OpenHoleLine { fence, floor });
        }
        let pending = inner.pending();
        let (entries, bare) = inner.log.counts();
        let reach = FeedOpenLine {
            floor: inner.log.floor(),
            head,
            entries,
            bare,
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
    /// walk lands each position ([`Feed::land_sorted`]) and in no other way.
    /// Empty once everything has landed.
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
            // The entry below each position of the set, read off the file:
            // the set lies wherever the index lost its lines, below the
            // window as often as not. A read the OS refuses leaves genesis
            // as the position below, the classification then diffing from
            // genesis, a wider diff and no wrong one.
            let to_sort: Vec<ToSort> = inner
                .unsorted
                .iter()
                .map(|&at| ToSort { at, below: entry_below(&inner.dir, at).unwrap_or(0) })
                .collect();
            (inner.log.pending_region(), to_sort, inner.files.index.coverage())
        };
        if region.is_none() && to_sort.is_empty() {
            // Nothing left to walk and the landing still owed: the files
            // rewritten, the record step freed.
            self.land(None, None, snapshot.world(), control, lines);
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
        self.land(outcome, sorted, snapshot.world(), control, lines);
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
    /// doc's residue. Answers the figures the landing line says ([`SortFigures`]);
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
    /// set.
    fn land_sorted(&self, at: u64, docs: Option<Vec<Address>>, world: &World) {
        let mut inner = self.inner.lock();
        if !inner.unsorted.remove(&at) {
            return;
        }
        let docs = docs.map(|addrs| classify(world, addrs)).unwrap_or_default();
        inner.fold_into_maps(at, docs);
        inner.append_the_index_through(at, world);
    }

    /// Lands the walk under this feed's lock, the five files written in order.
    ///
    /// The lock is the record step's and the page's, so a write's record and
    /// a page wait on it for the rewrites' length and never see a half-landed
    /// feed. The region's classifications are folded into the twins as the
    /// record step folds a position ([`Inner::fold_into_maps`]), classified
    /// against `world` — the open's head, PUB-7.7's one snapshot — and into
    /// `commits.log`'s resident entries behind the walk's own fence
    /// ([`CommitsLog::fold_the_walk`]: where the journal stopped answering,
    /// the lines at or below it are below the hole from here on), the twins
    /// trimmed to the same fence; the set's positions landed as they were
    /// sorted ([`Feed::land_sorted`]). Then the files, each keeping every
    /// record it held, in the order that keeps a kill between any two inside
    /// the walk behind the listener (`operations.md` §3.3 step 2): the
    /// index, the bitmap and the streams, the positions above each one's
    /// coverage added ([`Inner::rewrite_classified_files`]), fenced at the
    /// last position the log holds; then `commits.log` — the region's
    /// landing ([`CommitsLog::write_the_landing`]) where one pended, the file
    /// otherwise standing complete, every line appended as it was recorded;
    /// then the offset array, which names the lines that rewrite placed.
    /// Killed before `commits.log`'s rewrite, the file stands as the open
    /// found it, so the next open's region pends again and the three are cut
    /// back at its lower edge; killed after it, the three cover the region,
    /// so that open classifies nothing from the journal before it serves.
    /// Last the window settles — every position is on disk — and the twins
    /// with it; the attest store's file is untouched; the `landing:` lines
    /// are said last — the region's ([`WalkLandingLine`]), then the set's
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
    /// ([`CommitsLog::write_the_landing`] says why). Past its rename a file
    /// is in place and has said its own stop. A stop asked while the walk
    /// ran writes nothing.
    fn land(
        &self,
        outcome: Option<WalkOutcome>,
        sorted: Option<SortFigures>,
        world: &World,
        control: &WalkControl,
        lines: &Lines,
    ) {
        let mut inner = self.inner.lock();
        let held = Instant::now();
        if control.stop.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        // The region's half: its boundaries into the twins, each placed
        // below the positions recorded during the walk, and into the log's
        // resident entries behind the walk's fence.
        let region = outcome.as_ref().and_then(|outcome| {
            for w in &outcome.boundaries {
                let docs =
                    w.docs.as_ref().map(|addrs| classify(world, addrs.clone())).unwrap_or_default();
                inner.fold_into_maps(w.at, docs);
            }
            inner.log.fold_the_walk(&outcome.boundaries, outcome.min_since)
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
        let classified = inner.rewrite_classified_files(covered, true, world);
        say_the_landings_refusals(lines, classified);
        #[cfg(test)]
        if CUT_THE_NEXT_LANDING.swap(false, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        // The log: the region's landing, said at the log — before its rename
        // as the landing's own refusal, past it as the file's stop. No region
        // pending, the file stands complete, every line appended as it was
        // recorded. The resident entries are complete either way.
        let in_memory_alone = match region {
            Some(((low, _), _)) => {
                matches!(inner.log.write_the_landing(low), Err(RewriteFail::BeforeRename(_)))
            }
            None => false,
        };
        let offsets = inner.rewrite_offsets_file(covered, true);
        say_the_landings_refusals(lines, offsets);
        inner.landing_owed = false;
        inner.log.settle_the_window();
        inner.trim_to_the_window();
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

    /// Returns what the feed holds ([`FeedFigures`]).
    ///
    /// It is what the daemon's checkpoint thread reads after each landing
    /// for its line, under this feed's lock and no guard: the first position
    /// the files hold a line for, `commits.log`'s size, and the resident
    /// window's count beside the most it has held. A landing moves nothing
    /// of the feed — its files are kept whole from genesis — so the line
    /// says what the feed holds rather than what the landing did to it.
    pub(super) fn figures(&self) -> FeedFigures {
        let inner = self.inner.lock();
        let (resident, resident_most) = inner.log.resident_figures();
        FeedFigures { first: inner.log.floor(), bytes: inner.log.len(), resident, resident_most }
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
            let owed = inner.fold_position(at, recorded, classify(world, docs), attest);
            inner.trim_to_the_window();
            owed?
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
            let owed = inner.fold_position(at, recorded, classify(world, docs), attest);
            inner.trim_to_the_window();
            owed?
        };
        self.sync_the_attest_line(serial, owed)
    }

    /// Makes the attest line the record step appended durable, off the lock.
    ///
    /// The line was written under the feed's lock ([`AttestStore::record`]),
    /// its sync owed; it is synced here through the store's second handle
    /// ([`SyncHandle`]) with that lock released, so a page, a `/health` probe
    /// or a landing that comes meanwhile waits on no fsync. The guard
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
    /// The attest store's next write is refused
    /// ([`AttestStore::fail_next_write`]). Not a stable API.
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
    /// **Below the resident window** the candidates come off the files
    /// ([`Candidates`]: `commits.log` read from the first line above `since`
    /// by one search over its bytes, the index file and the attest store's
    /// beside it in step, each position's documents classified against the
    /// class's world), the same mask applied per entry, then the twins' merge
    /// from the window's edge where the page reaches it — so a page's bytes
    /// are the same whichever side of the window its positions lie, and a
    /// page over the window alone reads no file. The read is under the lock,
    /// as the merge is: one search and one sequential read of the page's
    /// lines, milliseconds from the page cache, which a write's record step
    /// waits on as it waits on the merge; a read the OS refuses answers
    /// [`ChangesAnswer::Unreadable`].
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
            let mut candidates = match inner.candidates(class, query, start) {
                Ok(candidates) => candidates,
                Err(e) => return ChangesAnswer::Unreadable { detail: e.to_string() },
            };
            loop {
                let candidate = match candidates.next() {
                    Ok(Some(candidate)) => candidate,
                    Ok(None) => break,
                    Err(e) => return ChangesAnswer::Unreadable { detail: e.to_string() },
                };
                let at = candidate.at();
                if reach.is_some_and(|pending| at >= pending) {
                    break;
                }
                let Some(row) = inner.visible(class, query, &candidate) else {
                    continue;
                };
                if rows.len() == query.limit.get() {
                    more = true;
                    break;
                }
                rows.push(row);
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
    /// It is the width [`Inner::sources`] hands [`Merge`] over the window,
    /// the term PUB-7.28 prices a page by: the published walk (absent under
    /// `drafts=true`) and one stream per owner account the class opens —
    /// never one list per visible draft document (PUB-7.24) — and one index
    /// list per document under each universal prefix; an `under=` the merge
    /// rule takes is one index list per readable document under it instead.
    #[cfg(test)]
    pub(super) fn merge_width(&self, class: &FeedClass<'_>, query: &ChangesQuery) -> usize {
        let inner = self.inner.lock();
        let start = query.since.saturating_add(1).max(inner.log.resident_from());
        let width = inner.sources(class, query, start).len();
        width
    }

    /// Returns the head position's recorded wall-clock time.
    ///
    /// It is `CommitsLog::head_time`.
    pub(crate) fn head_time(&self) -> Option<u64> {
        self.inner.lock().log.head_time()
    }

    /// Returns every entry above `position`, in position order.
    ///
    /// It is the head writer's resume's read (`CommitsLog::entries_above`
    /// states what it reads): the lines below the resident window off the
    /// file by position ([`LogLines`]), above the fence, then the window's
    /// own entries. A read the OS refuses leaves the window's entries alone
    /// — the resume then counts fewer commits since the last head, and the
    /// hour's trigger bounds how late the next head comes.
    pub(crate) fn entries_above(&self, position: u64) -> Vec<(u64, CommitMeta)> {
        let inner = self.inner.lock();
        let resident_from = inner.log.resident_from();
        let mut above = Vec::new();
        let since = position.max(inner.log.fence());
        if since.saturating_add(1) < resident_from {
            if let Ok(mut lines) = LogLines::above(&inner.dir, since) {
                while let Ok(Some((_, at, meta))) = lines.next() {
                    if at >= resident_from {
                        break;
                    }
                    above.push((at, meta));
                }
            }
        }
        above.extend(inner.log.entries_above(position));
        above
    }

    /// Returns the recorded wall-clock time of the entry at `position`.
    ///
    /// It is the one line's `time` — the daemon's testimony of when that
    /// commit landed, the minute a link's or a member's age is answered to
    /// (wire.md §Links (raw reads), `read_link`'s `time`; §Namespace,
    /// `doc_metadata`'s) — read off the resident window where the position
    /// lies in it, else off `commits.log` by position through the one
    /// on-disk read ([`Cursor`]): a binary search over the file, order
    /// log₂(its bytes) probes, never a walk. `None` where the feed holds no
    /// time for the position: a bare entry (its testimony lost), a position
    /// the walk behind the listener has yet to land, one at or below the
    /// fence an earlier build's compaction left, one no entry was ever
    /// written for, or a file the OS refuses to read — every one a case the
    /// reader falls back from to the hour record kept in the world
    /// (`commits/time.rs`, `hour_at`), never an invented value.
    pub(crate) fn time_at(&self, position: u64) -> Option<u64> {
        let inner = self.inner.lock();
        if position == 0 || position <= inner.log.fence() {
            return None;
        }
        if position >= inner.log.resident_from() {
            return inner.log.entries().get(&position).and_then(CommitMeta::time);
        }
        let mut lines = LogLines::above(&inner.dir, position - 1).ok()?;
        match lines.next() {
            Ok(Some((_, at, meta))) if at == position => meta.time(),
            _ => None,
        }
    }
}

/// The lines of `commits.log` above a position, read off the file.
///
/// It is `commits.log`'s read below the resident window ([`Cursor`]): each
/// entry in position order with the byte its line begins at, parsed by the
/// file's own parser and demoted as the open's scan demotes
/// (`sidecar.rs`'s `parse_line` and `demoted`), the fence lines skipped —
/// the lines at or below the fence are never asked for — ending where the
/// file ends, at a torn last line, or at a line that does not parse. Every
/// read of it runs under the feed's lock, so no append lands under it.
struct LogLines {
    cursor: Cursor,
}

impl LogLines {
    /// Opens `commits.log` in `dir` at the first entry above `since`.
    ///
    /// # Errors
    ///
    /// The OS refused the open, the search's seeks or reads.
    fn above(dir: &Path, since: u64) -> io::Result<LogLines> {
        Ok(LogLines { cursor: Cursor::open_above(&dir.join(SIDECAR_FILE), since)? })
    }

    /// Returns the next entry: the byte its line begins at, its position, its meta.
    ///
    /// # Errors
    ///
    /// The OS refused the read.
    fn next(&mut self) -> io::Result<Option<(u64, u64, CommitMeta)>> {
        while let Some((offset, line)) = self.cursor.next_line()? {
            match parse_log_line(&line) {
                Some(LogRecord::Entry(at, meta)) => {
                    let (meta, _) = demoted(meta);
                    return Ok(Some((offset, at, meta)));
                }
                Some(LogRecord::MinSince(_)) => continue,
                None => return Ok(None),
            }
        }
        Ok(None)
    }
}

/// A derived file's records above a position, read in step with the log.
///
/// It is a [`Records`] cursor with one record of lookahead, so a reader
/// walking `commits.log` asks each file for its record at the position in
/// hand ([`Peek::take_at`]) and the files are read together, each once, in
/// position order.
struct Peek {
    records: Records,
    next: Option<(u64, Map<String, Value>)>,
}

impl Peek {
    /// Opens `name` in `dir` at the first record above `since`.
    ///
    /// # Errors
    ///
    /// The OS refused the open, the search's seeks or reads.
    fn above(dir: &Path, name: &str, since: u64) -> io::Result<Peek> {
        let mut records = Records::above(dir, name, since)?;
        let next = records.next()?;
        Ok(Peek { records, next })
    }

    /// Returns the file's record at `at`, where it holds one, advancing past it.
    ///
    /// Records below `at` are passed over — the reader asks in ascending
    /// order — and one above it is kept for the next ask.
    ///
    /// # Errors
    ///
    /// The OS refused a read.
    fn take_at(&mut self, at: u64) -> io::Result<Option<Map<String, Value>>> {
        while self.next.as_ref().is_some_and(|(p, _)| *p < at) {
            self.next = self.records.next()?;
        }
        match &self.next {
            Some((p, _)) if *p == at => {
                let taken = self.next.take().map(|(_, m)| m);
                self.next = self.records.next()?;
                Ok(taken)
            }
            _ => Ok(None),
        }
    }
}

/// Returns the entry below `at` in `commits.log`, read off the file.
///
/// It is the position whose world a bare position's classification diffs
/// from ([`ToSort`]): the nearest entry line before `at`'s own, fence lines
/// passed over, genesis where none stands.
///
/// # Errors
///
/// The OS refused the open, a seek or a read.
fn entry_below(dir: &Path, at: u64) -> io::Result<u64> {
    let path = dir.join(SIDECAR_FILE);
    let mut offset = Cursor::open_above(&path, at.saturating_sub(1))?.offset();
    loop {
        let Some(line) = Cursor::line_before(&path, offset)? else { return Ok(0) };
        match parse_log_line(&line) {
            Some(LogRecord::Entry(below, _)) => return Ok(below),
            Some(LogRecord::MinSince(_)) => offset -= line.len() as u64 + 1,
            None => return Ok(0),
        }
    }
}

/// Returns a position's documents as its index record names them, or the fallback.
///
/// `Ok` is the record's names, parsed — every one of them; `[]` where the
/// index holds no record for the position, which contributed nothing. `Err`
/// is the fallback where a name did not parse, or an element was no string:
/// a derived record this daemon cannot parse is never trusted over the
/// authority file, so a recorded position answers from its own testimony
/// (every name of which parses, the log standing behind it) and a bare one
/// has none and stays unclassified — accepting the short list would mask
/// the position by a smaller set than the write touched, and accepting an
/// empty one would make it a `[]`-docs entry, which is never masked. The
/// open counts the `Err`s for its one line; the page's walk below the
/// window takes the fallback in silence, the line having been said at the
/// open where the window reached it.
fn index_docs(
    record: Option<&Map<String, Value>>,
    meta: &CommitMeta,
) -> Result<Vec<Address>, Vec<Address>> {
    let Some(m) = record else { return Ok(Vec::new()) };
    // Counted against what the file claimed, not against what could be read
    // out of it: an element that is not a string is one malformed name like
    // any other, and dropping it ahead of this count is what would let a
    // short list pass the test.
    let named = elements_of(m.get(INDEX_DOCS));
    let addrs: Vec<Address> =
        named.iter().filter_map(Value::as_str).filter_map(parse_dotted).collect();
    if addrs.len() == named.len() {
        Ok(addrs)
    } else {
        Err(record_docs(meta))
    }
}

/// Returns a recorded position's documents off its own record; none for a bare one.
fn record_docs(meta: &CommitMeta) -> Vec<Address> {
    match meta {
        CommitMeta::Recorded { docs, .. } => docs.iter().filter_map(|s| parse_dotted(s)).collect(),
        CommitMeta::Bare { .. } => Vec::new(),
    }
}

/// Returns the owner accounts a streams record names.
///
/// An owner name this daemon cannot parse is dropped, and that is the safe
/// direction: the position leaves that owner's stream, so their supplement
/// is short by it and nothing is unmasked.
fn stream_owners(record: &Map<String, Value>) -> BTreeSet<Address> {
    elements_of(record.get(STREAMS_OWNERS))
        .iter()
        .filter_map(Value::as_str)
        .filter_map(parse_dotted)
        .collect()
}

/// One candidate of a page, from the files below the window or the twins above it.
///
/// Below the window a candidate carries what the files answered for it —
/// its meta, its documents classified, its slot — since nothing of it is
/// resident; over the window it is the position alone, the twins answering
/// the rest ([`Inner::visible`]).
enum Candidate {
    /// A line read off the files, with everything the mask and the row need.
    Disk { at: u64, meta: CommitMeta, docs: Vec<Doc>, slot: Option<Arc<Attestation>> },
    /// A position the twins' merge put forward.
    Resident(u64),
}

impl Candidate {
    /// Returns the candidate's position.
    fn at(&self) -> u64 {
        match self {
            Candidate::Disk { at, .. } | Candidate::Resident(at) => *at,
        }
    }
}

/// A page's candidates in position order: the files below the window, then the twins.
///
/// The files' half is the position walk itself ([`LogLines`] from the first
/// entry above `since`, the index file and the attest store's read in step
/// through [`Peek`]), each position's documents the index's where the index
/// covers it and the record's own above that ([`index_docs`]), classified
/// against the class's world; it ends at the window's edge, where the
/// twins' merge ([`Merge`] over [`Inner::sources`]) takes over. The two
/// halves put forward every position a page may carry, the files' half by
/// construction — every line — and the twins' as [`Inner::sources`] states;
/// [`Inner::visible`] decides each.
struct Candidates<'a> {
    disk: Option<DiskWalk<'a>>,
    resident: Merge<'a>,
}

impl Candidates<'_> {
    /// Returns the next candidate, or `None` past the last.
    ///
    /// # Errors
    ///
    /// The OS refused a read of a file below the window.
    fn next(&mut self) -> io::Result<Option<Candidate>> {
        if let Some(disk) = &mut self.disk {
            if let Some(candidate) = disk.next()? {
                return Ok(Some(candidate));
            }
            self.disk = None;
        }
        Ok(self.resident.next().map(Candidate::Resident))
    }
}

/// The files read together below the window, for a page ([`Candidates`]).
struct DiskWalk<'a> {
    log: LogLines,
    index: Peek,
    attest: Peek,
    /// The index file's coverage: a position at or below it answers its
    /// documents off the index, one above it off its own record.
    index_covers: u64,
    /// The window's edge: the walk ends at the first line at or above it.
    until: u64,
    world: &'a World,
}

impl DiskWalk<'_> {
    /// Returns the next line below the window as a candidate.
    ///
    /// # Errors
    ///
    /// The OS refused a read.
    fn next(&mut self) -> io::Result<Option<Candidate>> {
        let Some((_, at, meta)) = self.log.next()? else { return Ok(None) };
        if at >= self.until {
            return Ok(None);
        }
        let record = if at <= self.index_covers { self.index.take_at(at)? } else { None };
        let addrs = match (at <= self.index_covers, &meta) {
            (true, _) => index_docs(record.as_ref(), &meta).unwrap_or_else(|fallback| fallback),
            (false, _) => record_docs(&meta),
        };
        let docs = classify(self.world, addrs);
        let slot = self.attest.take_at(at)?.and_then(|m| attest_of_record(&m)).map(Arc::new);
        Ok(Some(Candidate::Disk { at, meta, docs, slot }))
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

/// Rewrites one derived file, keeping its records, stopping it where a landing left it short.
///
/// The rewrite is [`LineFile::rewrite_keeping`]'s: every record the file
/// held, then `new`, fenced at `covered`. Where `stop` — the walk's
/// landing's — and the rewrite failed before its rename, the file stands
/// fenced where it was, short of what the walk landed, and is stopped there
/// ([`LineFile::stop_at`]). Answers the failure, with the fence the file
/// stands at ([`Unwritten`]).
fn rewrite_or_stop(
    file: &mut LineFile,
    name: &'static str,
    new: impl Iterator<Item = Vec<u8>>,
    covered: u64,
    stop: bool,
) -> Option<Unwritten> {
    let failed = file.rewrite_keeping(new, covered).err()?;
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
    entries: u64,
    bare: u64,
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

/// The open's line for the hole its files opened with.
///
/// The words: `the change feed's files hold no line at or below position
/// {fence}: an earlier build's compaction, or a walk the journal refused,
/// left the fence there; /changes answers 410 history_reclaimed for every
/// since below position {floor}, the first line held` — or, where no line
/// stands above the fence, `…left the fence there; no line is held above
/// it`. Said once per open where the fence stands above genesis, which this
/// build keeps as it found it and never moves for the journal's
/// reclamation. A pure value, pinned by `to_string()` in the unit suite;
/// emitted under `Class::Open` by [`Feed::open`] once the files are closed.
struct OpenHoleLine {
    fence: u64,
    floor: Option<u64>,
}

impl std::fmt::Display for OpenHoleLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the change feed's files hold no line at or below position {}: an earlier build's \
             compaction, or a walk the journal refused, left the fence there; ",
            self.fence
        )?;
        match self.floor {
            Some(floor) => write!(
                f,
                "/changes answers 410 history_reclaimed for every since below position {floor}, \
                 the first line held"
            ),
            None => f.write_str("no line is held above it"),
        }
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

/// One row as a class sees it ([`Inner::visible`]), owned for the render.
///
/// It is the position, its meta, its docs reduced to the ones the class may
/// read, whether that reduction dropped none of them — `false` where it
/// dropped any, as on a straddle row at a class that cannot read its
/// drafts, whose `attest` the page then withholds (the third absence, which
/// [`Feed::page`] states) — and its slot.
type Row = (u64, CommitMeta, Vec<String>, bool, Option<Arc<Attestation>>);

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
    /// appends wait on, and what the test seam `Feed::walk_pending` reads.
    #[cfg(any(test, feature = "test-hooks"))]
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
    /// record, in order — the recorded positions between the sorted ones,
    /// read off `commits.log` by position and classified from their own
    /// records against `world`, so no position below the claim lacks its
    /// record, and `at`'s own off the twins, where the sort just folded it —
    /// and the file is fenced at `at` where no record raised its coverage to
    /// it, so a position the journal classified empty is not sorted twice. A
    /// stopped file takes nothing ([`LineFile::append`]); a read the OS
    /// refuses is said once through the classed door, the file stopped at
    /// its coverage, so its claim never passes a position it lacks.
    fn append_the_index_through(&mut self, at: u64, world: &World) {
        let from = self.files.index.first_uncovered();
        if from < at {
            let gap = (|| -> io::Result<Vec<(u64, Vec<Doc>)>> {
                let mut lines = LogLines::above(&self.dir, from.saturating_sub(1))?;
                let mut records = Vec::new();
                while let Some((_, p, meta)) = lines.next()? {
                    if p >= at {
                        break;
                    }
                    let docs = match self.docs.get(&p) {
                        Some(docs) => docs.clone(),
                        None => classify(world, record_docs(&meta)),
                    };
                    if !docs.is_empty() {
                        records.push((p, docs));
                    }
                }
                Ok(records)
            })();
            match gap {
                Ok(records) => {
                    for (p, docs) in records {
                        self.files
                            .index
                            .append_or_report(p, vec![(INDEX_DOCS, doc_strings(&docs))]);
                    }
                }
                Err(e) => {
                    self.files.index.stop_reading_refused(at, &e);
                    return;
                }
            }
        }
        if let Some(docs) = self.docs.get(&at) {
            let docs = doc_strings(docs);
            self.files.index.append_or_report(at, vec![(INDEX_DOCS, docs)]);
        }
        if self.files.index.coverage() < at {
            self.files.index.fence_or_report(at);
        }
    }

    /// Drops every position at or below `min_since` from the twins.
    ///
    /// It is the walk's landing's trim to its own fence: three of the four
    /// twins — the index with the classification map, the bitmap with the
    /// published stream, the streams — the unsorted set and the attest
    /// store's resident slots drop them, the offset array's twin being the
    /// log's own: the positions the log has just put below its fence
    /// ([`CommitsLog::fold_the_walk`]), served by no route — so the twins
    /// and the log name one set of positions, no slot stays resident for a
    /// position no page renders, and the walk sorts no position below the
    /// hole.
    fn drop_at_or_below(&mut self, min_since: u64) {
        self.unsorted = self.unsorted.split_off(&min_since.saturating_add(1));
        self.drop_below_the_window(min_since.saturating_add(1));
    }

    /// Drops every position below `from` from the twins, the unsorted set aside.
    ///
    /// It is the window's trim ([`Inner::trim_to_the_window`]): the twins
    /// hold the window's positions and no more — the index with the
    /// classification map, the bitmap with the published stream, the
    /// streams, and the attest store's resident slots — and a page below
    /// the window reads the files instead. The unsorted set stays whole:
    /// its positions lie wherever the index lost its lines, and each leaves
    /// as the walk lands it.
    fn drop_below_the_window(&mut self, from: u64) {
        self.attest.drop_at_or_below(from.saturating_sub(1));
        self.docs = self.docs.split_off(&from);
        self.masked = self.masked.split_off(&from);
        self.published = self.published.split_off(&from);
        self.index.retain(|_, (_, positions)| {
            positions.retain(|&at| at >= from);
            !positions.is_empty()
        });
        self.streams.retain(|_, positions| {
            positions.retain(|&at| at >= from);
            !positions.is_empty()
        });
    }

    /// Trims the twins to the resident window as the log holds it.
    ///
    /// Run after every record and at the landing: the log's own window has
    /// moved ([`CommitsLog::evict`]), and the twins follow its edge.
    fn trim_to_the_window(&mut self) {
        let from = self.log.resident_from();
        if self.docs.keys().next().is_some_and(|&at| at < from)
            || self.published.first().is_some_and(|&at| at < from)
            || self.masked.first().is_some_and(|&at| at < from)
        {
            self.drop_below_the_window(from);
        } else {
            self.attest.drop_at_or_below(from.saturating_sub(1));
        }
    }

    /// Rewrites the index, the bitmap and the streams, keeping their records.
    ///
    /// Each is rewritten with every record it held and the positions above
    /// its coverage up to `covered` added ([`Inner::classified_above`]:
    /// the twins' positions, and the recorded positions the log holds
    /// between them, classified against `world`), fenced at `covered`; each
    /// attempted whatever the one before it answered, and each that failed is
    /// answered with how. `stop` is the walk's landing's (`Feed::land`): a
    /// file whose rewrite failed before its rename is stopped at the fence it
    /// stands at ([`rewrite_or_stop`]); a read the OS refused ahead of the
    /// rewrites is each file's failure before its rename.
    fn rewrite_classified_files(
        &mut self,
        covered: u64,
        stop: bool,
        world: &World,
    ) -> Vec<Unwritten> {
        let from = [
            self.files.index.coverage(),
            self.files.masked.coverage(),
            self.files.streams.coverage(),
        ]
        .into_iter()
        .min()
        .unwrap_or(0)
        .saturating_add(1);
        let classified = match self.classified_above(from, covered, world) {
            Ok(classified) => classified,
            Err(e) => {
                return [
                    (INDEX_FILE, &mut self.files.index),
                    (MASKED_FILE, &mut self.files.masked),
                    (STREAMS_FILE, &mut self.files.streams),
                ]
                .into_iter()
                .map(|(name, file)| {
                    if stop {
                        file.stop_at(file.coverage());
                    }
                    let failed = RewriteFail::BeforeRename(io::Error::new(e.kind(), e.to_string()));
                    Unwritten { name, failed, fence: file.coverage() }
                })
                .collect();
            }
        };
        let mut failures = Vec::new();
        let c = self.files.index.coverage();
        let new = classified
            .iter()
            .filter(|(at, _)| *at > c)
            .map(|(at, docs)| derived::record_object(*at, vec![(INDEX_DOCS, doc_strings(docs))]))
            .map(|r| line_bytes(&r));
        failures.extend(rewrite_or_stop(&mut self.files.index, INDEX_FILE, new, covered, stop));
        let c = self.files.masked.coverage();
        let new = classified
            .iter()
            .filter(|(at, docs)| *at > c && masked_at_commit(docs))
            .map(|(at, _)| line_bytes(&derived::record_object(*at, Vec::new())));
        failures.extend(rewrite_or_stop(&mut self.files.masked, MASKED_FILE, new, covered, stop));
        let c = self.files.streams.coverage();
        let new = classified.iter().filter(|(at, _)| *at > c).filter_map(|(at, docs)| {
            let owners = owners_of(docs);
            (!owners.is_empty()).then(|| {
                line_bytes(&derived::record_object(
                    *at,
                    vec![(STREAMS_OWNERS, addr_strings(&owners))],
                ))
            })
        });
        failures.extend(rewrite_or_stop(&mut self.files.streams, STREAMS_FILE, new, covered, stop));
        failures
    }

    /// Returns the classified positions in `[from, covered]`, in position order.
    ///
    /// They are what the three classified files' rewrites add above their
    /// coverage ([`Inner::rewrite_classified_files`]): the twins' positions
    /// — the walk's boundaries, the set's sorted positions, the positions
    /// recorded since the open — and, between them, the recorded positions
    /// `commits.log` holds that the window does not, each classified from
    /// its own record against `world` as the open classifies it, and a bare
    /// one off the index file where the sort landed its record there; a
    /// position with no document is left out, contributing nothing to any
    /// of the three.
    ///
    /// # Errors
    ///
    /// The OS refused a read of `commits.log` or the index.
    fn classified_above(
        &self,
        from: u64,
        covered: u64,
        world: &World,
    ) -> io::Result<Vec<(u64, Vec<Doc>)>> {
        let mut out: BTreeMap<u64, Vec<Doc>> = BTreeMap::new();
        for (at, docs) in self.docs.range(from..=covered) {
            out.insert(*at, docs.clone());
        }
        let since = from.saturating_sub(1).max(self.log.fence());
        let mut lines = LogLines::above(&self.dir, since)?;
        let mut index = Peek::above(&self.dir, INDEX_FILE, since)?;
        let index_covers = self.files.index.coverage();
        while let Some((_, at, meta)) = lines.next()? {
            if at > covered {
                break;
            }
            if out.contains_key(&at) || self.docs.contains_key(&at) || self.unsorted.contains(&at) {
                continue;
            }
            let record = if at <= index_covers { index.take_at(at)? } else { None };
            let addrs = match (at <= index_covers, &meta) {
                (true, _) => index_docs(record.as_ref(), &meta).unwrap_or_else(|fallback| fallback),
                (false, _) => record_docs(&meta),
            };
            let docs = classify(world, addrs);
            if !docs.is_empty() {
                out.insert(at, docs);
            }
        }
        Ok(out.into_iter().collect())
    }

    /// Rewrites the offset array, keeping its records, from the log's lines.
    ///
    /// It is the walk's landing's last file, written after `commits.log`
    /// because it names that file's lines: every record it held, then one
    /// for each line of `commits.log` above its coverage up to `covered`,
    /// read off the file by position with the byte each line begins at;
    /// `stop` as [`Inner::rewrite_classified_files`] reads it, a read the OS
    /// refused being the failure before the rename.
    fn rewrite_offsets_file(&mut self, covered: u64, stop: bool) -> Vec<Unwritten> {
        let from = self.files.offsets.first_uncovered();
        let new = (|| -> io::Result<Vec<Vec<u8>>> {
            let mut lines =
                LogLines::above(&self.dir, from.saturating_sub(1).max(self.log.fence()))?;
            let mut out = Vec::new();
            while let Some((offset, at, _)) = lines.next()? {
                if at > covered {
                    break;
                }
                let record = derived::record_object(
                    at,
                    vec![(OFFSETS_OFFSET, Value::Number(offset.into()))],
                );
                out.push(line_bytes(&record));
            }
            Ok(out)
        })();
        let new = match new {
            Ok(new) => new,
            Err(e) => {
                if stop {
                    self.files.offsets.stop_at(self.files.offsets.coverage());
                }
                let failed = RewriteFail::BeforeRename(e);
                let fence = self.files.offsets.coverage();
                return vec![Unwritten { name: OFFSETS_FILE, failed, fence }];
            }
        };
        rewrite_or_stop(&mut self.files.offsets, OFFSETS_FILE, new.into_iter(), covered, stop)
            .into_iter()
            .collect()
    }

    /// Rewrites the offset array whole from the log's lines, fenced at `covered`.
    ///
    /// It is the open's answer where `commits.log`'s own offsets moved —
    /// this open's purge rewrote it — or the file's lines disagree with the
    /// log's: one stream of `commits.log` above the fence, a record per line
    /// with the byte it begins at, nothing of the old file kept.
    ///
    /// # Errors
    ///
    /// The read's I/O error, or the rewrite's failure either side of its
    /// rename, as one I/O error — fatal at the open, which wraps it with the
    /// file's name.
    fn rewrite_offsets_file_whole(&mut self, covered: u64) -> io::Result<()> {
        let mut lines = LogLines::above(&self.dir, self.log.fence())?;
        let mut records = Vec::new();
        while let Some((offset, at, _)) = lines.next()? {
            if at > covered {
                break;
            }
            records.push(derived::record_object(
                at,
                vec![(OFFSETS_OFFSET, Value::Number(offset.into()))],
            ));
        }
        self.files.offsets.rewrite(records, covered).map_err(RewriteFail::into_io)
    }

    /// Returns a page's candidates for `class` and `query` from `start`.
    ///
    /// They are the files' lines below the resident window where `start`
    /// lies below it, then the twins' sources from the window's edge
    /// ([`Candidates`]).
    ///
    /// # Errors
    ///
    /// The OS refused to open a file below the window, or the search's reads.
    fn candidates<'s>(
        &'s self,
        class: &'s FeedClass<'_>,
        query: &'s ChangesQuery,
        start: u64,
    ) -> io::Result<Candidates<'s>> {
        let until = self.log.resident_from();
        let disk = if start < until {
            let since = start - 1;
            Some(DiskWalk {
                log: LogLines::above(&self.dir, since)?,
                index: Peek::above(&self.dir, INDEX_FILE, since)?,
                attest: Peek::above(&self.dir, attest::ATTEST_FILE, since)?,
                index_covers: self.files.index.coverage(),
                until,
                world: class.world,
            })
        } else {
            None
        };
        let resident = Merge::new(self.sources(class, query, start.max(until)));
        Ok(Candidates { disk, resident })
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
    /// landing's rewrite that renders the twin back to lines
    /// ([`Inner::rewrite_classified_files`], the window's trim after it). A structure
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
    /// answers the row ([`Row`]): the entry's meta and its docs reduced to
    /// the requester's readable ones — and whether the reduction kept the
    /// record's docs whole, which is what decides the row's `attest` (the
    /// third absence, which [`Feed::page`] states) — or `None` when the
    /// entry is omitted. A candidate the twins put forward answers off the
    /// twins; one the files put forward carries its own meta, documents and
    /// slot ([`Candidate`]), and the one test runs over both, which is what
    /// makes a row the same bytes on either side of the window. A position
    /// the walk has yet to sort ([`Inner::unsorted`]) is omitted at every
    /// class: its class is unknown until the journal answers, and the page's
    /// reach test keeps it off every merge, so this is the guard behind that
    /// test and never the answer a page is built on.
    fn visible(
        &self,
        class: &FeedClass<'_>,
        query: &ChangesQuery,
        candidate: &Candidate,
    ) -> Option<Row> {
        let at = candidate.at();
        if self.unsorted.contains(&at) {
            return None;
        }
        let (meta, docs, slot): (&CommitMeta, &[Doc], Option<Arc<Attestation>>) = match candidate {
            Candidate::Disk { meta, docs, slot, .. } => (meta, docs.as_slice(), slot.clone()),
            Candidate::Resident(at) => (
                self.log.entries().get(at)?,
                self.docs.get(at).map(Vec::as_slice).unwrap_or(&[]),
                self.attest.slot(*at),
            ),
        };
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
        let reduced: Vec<String> = reduced.iter().map(|d| d.addr.to_string()).collect();
        Some((at, meta.clone(), reduced, whole, slot))
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
        let mut positions = self.log.entries().range(start.max(self.log.resident_from())..);
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
