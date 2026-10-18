//! The change feed's PUBLICATION HALF (PUB round 2, lane 3.6): `commits.log`
//! composed with its four derived sidecars, the per-class mask, the
//! supplement merge, the universal term, and the two narrowings — with the
//! attest store (`attest.rs`) beside them, whose slots a page renders. The
//! wire surface is `GET /changes` (wire.md §The change feed); what this module
//! owes it is ONE answer — the FEED-CLASS ORACLE (PUB-6.59): for any class,
//! every page equals the position walk over `(since, head]` with
//! `readable()` applied per entry and `docs` reduced, masked entries
//! omitted, `limit`/`last`/`more` over the visible stream (PUB-6.44). Every
//! structure below is a way of finding the candidates for that walk at a
//! cost the spec pins (PUB-7.19–7.35); none of them decides the answer,
//! which is the read predicate's per entry (PUB-7.20).
//!
//! # The mask (PUB-6.44–6.46)
//!
//! An entry classifies over its `docs` — the target for arrangement writes,
//! the HOME for link writes, the MINTED document for mints, and for
//! `nullify` the record's home AND the target link's home as a set — never
//! over sources read. It is MASKED iff `docs` is non-empty and none is
//! readable to the requester; otherwise it is shown with `docs` REDUCED to
//! the readable ones. `[]`-docs entries (`delegate`, `register_node`) are
//! never masked. A masked entry is OMITTED — never present with nulled
//! fields, which is the reserved rendering of lost testimony. A BARE entry
//! classifies from the journal (`classify::derived_docs`, computed at the
//! open that reconstructs it): its class is the journal's, its rendering
//! stays the nulls.
//!
//! # The structures (PUB-7.19–7.21)
//!
//! `commits.log` (`sidecar.rs`) is the authority for what an entry says.
//! Beside it, four derived sidecars (`derived.rs`), each appended at commit
//! and held resident as its twin; and, in their line shape under a class of
//! its own, the ATTEST STORE ([`AttestStore`], `attest.rs`, which states the
//! class), whose slot for a position the page renders as the entry's `attest`
//! member (`CommitMeta::entry`). The five files `commits.log` and the four
//! derived hold are COMPACTED to the journal's reclaim floor — at open, and
//! after each checkpoint the daemon's checkpoint thread lands, the floor
//! moving at a checkpoint and at no other moment ([`Feed::compact_below_reclaim_floor`],
//! one rewrite for both moments, under this feed's lock); the attest store
//! never (its class). The four twins:
//!
//! * the per-document POSITION INDEX (`index`: document → positions, keyed
//!   by tumbler, so an account's documents and any content-prefix are one
//!   contiguous key range) — the `under=` narrowing's and the universal
//!   term's source, with the per-position classification map (`docs`) as
//!   its inverse;
//! * the position → OFFSET array (`CommitsLog::offsets`) — position-keyed
//!   access into `commits.log`; this build's reader is resident, so
//!   `CommitsLog::entries` is what answers a position and this array
//!   answers nothing. The file is what a non-resident reader would seek
//!   by, and the array is what keeps that file right;
//! * the MASKED-POSITION BITMAP (`masked`: positions whose docs are
//!   non-empty and all drafts at commit) and its complement, the
//!   MATERIALIZED PUBLISHED STREAM (`published`), which a guest page walks
//!   in O(page). For a position the bitmap does NOT hold it is a skip
//!   accelerator and never the authority: the position is walked and the
//!   mask decides. For one it holds, it decides candidacy — the field's own
//!   card states that direction and the invariant it rests on;
//! * the PER-OWNER-ACCOUNT DRAFT-POSITION STREAMS (`streams`: owner →
//!   positions naming one of that owner's drafts — every fully-masked
//!   position plus the straddles).
//!
//! # The walk behind the listener (`operations.md` §3.3 step 2; §4 row 16)
//!
//! Where `commits.log` was lost or torn, its open records the uncovered
//! region `(low, head]` as PENDING and the four derived files are rebuilt
//! for what the log HOLDS, fenced at `low`; the write path then runs the
//! walk on a thread of its own ([`Feed::walk_and_land`]) while the board
//! serves. Meanwhile a page whose rows would have to come from the region
//! is refused [`ChangesAnswer::Rebuilding`] (`503 feed_rebuilding`,
//! retry-class), pages below and above it serving; a write's record enters
//! the twins and no file ([`Inner::fold_into_maps`]); a checkpoint's
//! compaction moves the fence in memory and writes nothing. The walk LANDS
//! under this feed's lock ([`Feed::land`]): the region's classifications
//! folded into the twins as the record step folds a position, ONE rewrite
//! of `commits.log` — the walked boundaries bare among the held positions,
//! in position order, every offset assigned — then the four derived files
//! rewritten whole from the twins, the same rewrite the open and the
//! checkpoint thread run; the attest store is untouched, its lines appended
//! as today and its open having served the region's slots off the kernel's
//! markers.
//!
//! # The supplement (PUB-7.22–7.28)
//!
//! A principal's page is the K-way merge, deduplicated by position, of: the
//! published walk; its OWN account's, its ANCESTOR accounts' and its
//! DESCENDANT owner accounts' streams (the subtree clause runs both ways,
//! PUB-1.32 as amended — its own and ancestor accounts, the subtrees that
//! enclose it, by key; the owner accounts beneath it as one key range of
//! `streams` under its account — PUB-7.24's SUBTREE TERM, the price of the
//! ancestor read; a node-tier principal opens neither); its grant-selected
//! ISSUER streams, each under a per-entry containment test against the union
//! of that issuer's covered prefixes for this principal (an account-depth
//! grant is the stream whole); and the UNIVERSAL term, derived at serve — the
//! position index's lists under each live any-principal prefix, enumerated
//! once per request off the same head snapshot as the rest of the class. The
//! CLASS is `server.rs`'s to resolve, off ONE head snapshot per request
//! (PUB-6.40), and arrives here as [`FeedClass`]; this module resolves
//! nothing itself. Guests never merge the universal term (PUB-5.109).
//!
//! # The narrowings (PUB-7.31–7.35)
//!
//! `under=<address-or-prefix>` serves off the position index with
//! DOC-GRANULAR SKIPPING — an unreadable document's whole list is skipped on
//! one test — under the MERGE-OR-WALK rule: merge the lists under the
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
    LineFile, INDEX_DOCS, INDEX_FILE, MASKED_FILE, OFFSETS_FILE, OFFSETS_OFFSET, STREAMS_FILE,
    STREAMS_OWNERS,
};
use super::sidecar::{
    reclaim_floor, reclaim_floor_of, reconstruct, Carrier, CommitMeta, CommitsLog, Cut, CutHead,
    IoCause, JournalTerms, MalformedCase, MalformedNamesLine, OpTerms, ProgressCadence, Recorded,
    RewriteFail, WalkControl, WalkLandingLine, WalkOutcome,
};
use super::classify::{classify, derived_docs, parse_dotted, Doc};
use super::{Lines, Signed};
use crate::codec::to_bytes;
use crate::limits::{
    FEED_WALK_PROGRESS_BOUNDARIES, FEED_WALK_PROGRESS_INTERVAL, MAX_CHANGES_PAGE_BYTES,
};
use crate::serial::SerialGuard;

/// The most granted prefixes [`Inner::names_under`] scans per candidate
/// before [`Inner::sources`] stands the filter aside and lets the mask
/// decide.
///
/// The filter is a CANDIDATE optimization and never the answer: it only
/// REMOVES candidates from one source, the merge deduplicates, and
/// [`Inner::visible`] decides every candidate that survives — so standing it
/// aside can only widen a candidate set the mask then judges, and the page
/// does not move. That is what makes a cap here answer-preserving rather
/// than a narrowing, and it is weaker than "it drops only what the mask
/// drops", which [`Inner::names_under`] records as false.
///
/// The budget is the cost of the probe this filter PRECEDES. `World::readable`
/// answers the grant clause by testing a document's O(depth) ancestor prefixes
/// against a prefix-keyed set; this filter walks the issuer's whole granted
/// union linearly, per candidate. Past the depth bound the linear walk costs
/// more per candidate than the indexed probe that follows it, so the filter
/// stops being an optimization and becomes a tax — and the union is a quantity
/// the ISSUER writes, one prefix per grant, uncapped by the fold, so a holder
/// of thousands of narrow grants would otherwise buy an O(union) scan per
/// candidate on every page, under the lock [`crate::commits::Commits`]
/// takes to record a commit. The number is M3's `MAX_PRINCIPAL_COMPONENTS`,
/// which is that depth bound, taken from M3 so the two cannot part.
const MAX_FILTERED_PREFIXES: usize = skep_namespace::MAX_PRINCIPAL_COMPONENTS;

/// The requester's FEED CLASS, resolved by the route off ONE head snapshot
/// (PUB-6.40) and threaded down: the read predicate at the requester's
/// class, the stream keys its class opens, and the universal term's live
/// set. The feed evaluates it and resolves nothing of its own.
pub struct FeedClass<'a> {
    /// The requester's READER CLASS (`None` is the guest) over the HEAD
    /// world every field below stands on — the one snapshot the route pinned
    /// for this request — with the requester's seat looked up at most once
    /// for the whole request.
    ///
    /// [`FeedClass::of`] builds it from the request's `(world, principal)`
    /// pair and derives the stream keys below from ITS seat, and
    /// [`FeedClass::readable`] answers the mask off it, so a class whose mask
    /// and whose stream keys belong to different principals is not
    /// constructible — the keys would open a principal's drafts while the
    /// mask refused all of them, which fails into an emptier page with
    /// nothing to report it.
    reader: ReaderClass<'a>,
    /// The requester's ENCLOSING SUBTREES — its own account and its ancestor
    /// accounts, every account whose subtree holds the requester: the subtree
    /// clause's first compare (the requester at or beneath the owner,
    /// PUB-1.32) and PUB-7.24's "its own account's, its ancestor accounts'"
    /// streams, each a draft-stream key, O(depth). Empty for the guest and for
    /// a node-tier principal. NOT PUB-7.24's SUBTREE TERM, which is the
    /// requester's own subtree beneath it — the descendants',
    /// [`FeedClass::descendants_under`].
    enclosing_subtrees: Vec<Address>,
    /// The requester's own ACCOUNT, as the prefix its DESCENDANT OWNER
    /// ACCOUNTS' streams lie under (the subtree clause's second compare — the
    /// requester at or above the owner, PUB-1.32 as amended; PUB-7.24's
    /// SUBTREE TERM, the price of the ancestor read, as RES-220 names it). A
    /// PREFIX and never a key list, as the universal term's are: the streams
    /// are keyed per owner account in tumbler order, so every owner account
    /// beneath this one is ONE contiguous key range, which [`streams_beneath`]
    /// enumerates at serve — O(descendant owner accounts), and an account
    /// beneath it that owns no draft stream costs nothing.
    ///
    /// `None` for the guest and for a NODE-TIER principal, and the second is
    /// the read predicate's principal-0 exclusion, kept here as its twin:
    /// principal 0 is seated at a node, whose prefix contains every owner
    /// account on the board, and it is no account's ancestor for the subtree
    /// clause (PUB-1.32: excluded by name) — so it opens no descendant range.
    /// The mask would refuse every entry such a range put forward, so what
    /// the `None` keeps off principal 0's page is the COST, a merge of every
    /// draft stream there is, and never an answer.
    descendants_under: Option<Address>,
    /// The grant-selected issuers (`World::issuers_for`, PUB-7.25) — each an
    /// issuing account with the union of the content prefixes it granted this
    /// principal, the issuer being the draft-stream key this clause opens.
    issuers: Vec<IssuerGrantIndexRow<'a>>,
    /// The live ANY-PRINCIPAL prefixes (`World::universal_grants`, PUB-7.22)
    /// — a key range over the position index, never a stream key. Empty for
    /// the guest (grants reach principals alone, PUB-5.109).
    ///
    /// The PREFIX alone, where the engine's row carries the issuing accounts
    /// beside it: this term needs no issuer, because the mask's own grant
    /// clause admits exactly the entries the issuing owner covers, so
    /// [`Inner::visible`] decides every candidate the prefix's index lists
    /// put forward.
    universal_prefixes: Vec<&'a Address>,
}

impl<'a> FeedClass<'a> {
    /// The whole class one `(world, principal)` pair opens, resolved off ONE
    /// head snapshot (PUB-6.40): the route pins the snapshot and hands the
    /// world in, and every field's own rule is stated on the field above —
    /// which is why the resolution lives here rather than at the route,
    /// where it would restate them.
    pub fn of(world: &'a World, principal: Option<PrincipalId>) -> FeedClass<'a> {
        let reader = world.reader_class(principal);
        // The seat the mask resolves, handed out: the stream keys below and
        // the mask stand on one lookup in M3's principal registry.
        let account = reader.seat().cloned();
        let enclosing_subtrees: Vec<Address> = std::iter::successors(account.clone(), parent)
            .filter(|a| world.m3().is_registered_account(a))
            .collect();
        // The grants BORROW the world rather than the account they select on,
        // so this term runs ahead of the one that consumes it.
        let issuers = account.as_ref().map(|pa| world.issuers_for(pa)).unwrap_or_default();
        // An ACCOUNT alone opens the descendant range — the tier test the
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

    /// `readable(principal, ·)` at the head — THE mask (PUB-7.20), which
    /// [`Inner::visible`] applies per entry and [`Inner::sources`] applies
    /// per document in the merge arm's skip.
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

/// WHAT ONE COMPACTION OF THE FEED's FILES DID — the answer of
/// `Feed::compact_below_reclaim_floor`, read by the checkpoint thread for
/// its landing line: the fence compacted to, or `None` where nothing lay
/// below the reclaim floor and nothing was written; and, beside the fence,
/// the files that STOOD — each whose rewrite failed BEFORE its rename, the
/// old file whole and the next compaction trying again — by name, so the
/// line is truthful of each file. A file whose rewrite failed PAST its
/// rename was compacted (the new file is in place) and has said its own
/// stop; it is none of these. Empty with no fence: nothing was attempted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeedCompaction {
    /// The last position dropped — the files are compacted below the
    /// position after it — or `None` where nothing lay below the floor.
    pub fence: Option<u64>,
    /// The files whose rewrite failed before its rename, standing as they
    /// were, in the order the compaction attempted them.
    pub standing: Vec<&'static str>,
    /// The pending region `(low, head]` whose landing the rewrite waits on.
    ///
    /// The walk behind the listener has yet to land it, so the fence moved
    /// in the resident entries alone and no file was written. `None` where
    /// the files were rewritten, or nothing lay below the floor.
    pub deferred: Option<(u64, u64)>,
}

/// What `feed-attest.log` holds, as one read of it answers.
///
/// The file is never compacted — below the reclaim floor its lines are an
/// entry signature's only copy — so it grows by one line per attested
/// commit, ~6.9 KB under tag 1, for the life of the board; and the slots
/// resident for the positions the feed serves (~3.4 KB each) grow with every
/// attested commit for the uptime, the one structure of the core that does.
/// Read by the checkpoint thread at each landing, for its line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestStoreFigures {
    /// The file's size in bytes, or `None` where its metadata did not answer.
    pub bytes: Option<u64>,
    /// The marker slots held resident for the positions the feed serves.
    pub slots: usize,
}

/// One `/changes` question — the parsed query string, beside
/// [`ChangesAnswer`], its answer.
#[derive(Clone, Debug)]
pub struct ChangesQuery {
    /// The fence: positions strictly above it.
    pub since: u64,
    /// The page cap, over the VISIBLE stream — at least one, BY TYPE. A zero
    /// cap is not a smaller page: `Feed::page` would break on the first
    /// visible candidate and answer `more: true` with `last` echoing `since`,
    /// a client told to poll again at a fence that never advances. The wire's
    /// parser refuses it (`limit: must be 1..=4096`) rather than clamping, and
    /// the type is what makes that the only answer: no constructor, the
    /// parser or a second one, can build a zero cap.
    pub limit: NonZeroUsize,
    /// `under=`: only entries whose reduced docs name a document under this
    /// tumbler (PUB-7.31).
    pub under: Option<Tumbler>,
    /// `drafts=true`: only entries whose reduced docs name a draft
    /// (PUB-7.35).
    pub drafts_only: bool,
}

/// The answer `GET /changes` marshals.
#[derive(Debug)]
pub enum ChangesAnswer {
    /// `since` reaches below what the feed can enumerate
    /// (`CommitsLog::admits_since`); `floor` is the wire's sense of the
    /// word (wire.md §Reading history: the oldest position still
    /// answerable), which is NOT the fence that predicate tests — the
    /// distinction, and the step between the two numbers, are
    /// `CommitsLog::floor`'s, which is what this field is filled from.
    /// Class-invariant, like every position (PUB-6.52's residue).
    Reclaimed {
        /// The oldest position still answerable, or `None` where none is.
        floor: Option<u64>,
    },
    /// The visible entries in `(since, head]`, oldest first, rendered,
    /// capped at `limit`; `last` is the final entry's position (or `since`
    /// echoed when the page is empty) and `more` says whether a visible
    /// entry remains past it (PUB-6.44).
    Page {
        /// The rendered rows, oldest first.
        entries: Vec<Value>,
        /// The final entry's position, or `since` where the page is empty.
        last: u64,
        /// Whether a visible entry remains past `last`.
        more: bool,
    },
    /// THE PAGE BYTE BUDGET (bu7-2 = reg-H1; SO-I9; P29): the page the query
    /// asks for, marshaled, would pass [`MAX_CHANGES_PAGE_BYTES`] — so it is
    /// REFUSED whole, never shortened (PUB-6.44: a page is never short of
    /// `limit` before the head), with the budget and `fits`, the largest
    /// `limit` whose page from this `since` stays within it: the rows
    /// measured before the one that crossed. A `fits` of zero says the first
    /// row alone passes the budget — no `limit` serves this fence.
    OverBudget {
        /// The page byte budget.
        budget: usize,
        /// The largest `limit` whose page from this `since` fits the budget.
        fits: usize,
    },
    /// THE REGION PENDING (`operations.md` §3.3 step 2; §4 row 16): the
    /// page's rows would have to come from `(low, head]`, the positions a
    /// lost or torn `commits.log` left uncovered, which the walk behind the
    /// listener has yet to land — refused `503 feed_rebuilding`,
    /// retry-class as `index_rebuilding` is, under its own token. `low` is
    /// covered, `head` the last of the region; the route words them and
    /// carries no member for them. `Feed::page` states the test: not
    /// only a `since` inside the region — a page starting below it whose
    /// `limit` rows are not all at or below `low` would otherwise skip its
    /// positions in silence.
    Rebuilding {
        /// The last covered position below the region.
        low: u64,
        /// The last position of the region.
        head: u64,
    },
}

/// The feed: `commits.log`, the four derived twins and the attest store,
/// under one lock.
pub(super) struct Feed {
    inner: Mutex<Inner>,
}

/// A feed file STOPPED this uptime — `commits.log` or one of the four
/// derived files, taking no further line — by name, with the position its
/// stop was set at: the failed append's position, or the fence a rewrite
/// failed past its rename at (each file's `stopped` field says which). What
/// the standing line re-says a stopped file by, once an hour while it
/// stands (`operations.md` §1 THE RATES, `{file} stopped since position
/// {p}`); the attest store is never among them — its stop halts the write
/// path, which the halt's own clause carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoppedFile {
    /// The file's name, as its own lines name it.
    pub name: &'static str,
    /// The position the stop was set at — an ordering (THE JOINS), the one
    /// the file's own stop line names.
    pub since: u64,
}

/// THE ATTEST STORE'S FAILURE (SO-I5 (d)): a line [`AttestStore::record`]
/// could not make durable — its write or its sync failed, said once on the
/// operator stream there — answered through [`Feed::record`] to the write
/// path, which refuses every later write for the uptime on it. The attest
/// store's alone: a derived file's failed append is reported and fails no
/// op (P22), so it is never answered as this.
#[derive(Debug)]
pub(super) struct AttestStoreFailed;

struct Inner {
    log: CommitsLog,
    /// Position → its classified docs (positions with docs only) — the
    /// index's inverse, and what the mask reads per entry.
    docs: BTreeMap<u64, Vec<Doc>>,
    /// The position index: document (by tumbler, so a prefix is a range) →
    /// the address as named, and its positions ASCENDING, which is what
    /// makes [`at_or_above`]'s `partition_point` meaningful over a list of
    /// them and what the consecutive-repeat dedup beside each push rests on.
    ///
    /// TWO construction paths establish it, differently. At [`Feed::open`]
    /// the lists are built by iterating [`Inner::docs`], a `BTreeMap`, so
    /// the container supplies the order. At [`Inner::fold_position`] they
    /// are PUSHED, and the order comes from the write path instead:
    /// positions are recorded under the serialization guard
    /// ([`crate::commits::Commits::commit_recorded`], which both of the
    /// write path's doors run, executes and records as one operation under
    /// it), so each push is strictly above every prior one.
    index: BTreeMap<Tumbler, (Address, Vec<u64>)>,
    /// The bitmap: positions masked at commit (docs non-empty, all drafts).
    ///
    /// INVARIANT its use rests on: every member has a non-empty entry in
    /// [`Inner::docs`]. [`Inner::fold_position`] establishes it, one
    /// classification deciding both. The REPLAY does not: this set is seeded
    /// from `feed-masked.log` and `docs` from `feed-index.log`,
    /// independently.
    ///
    /// Where the two disagree this set DECIDES the GUEST's page, because
    /// [`Inner::published`] is exactly its complement and a guest has no
    /// other source: a member the classification has nothing for is excluded
    /// from the published walk and absent from the index (which `docs`
    /// builds), so a guest never sees it — where [`Inner::visible`], reading
    /// it as a `[]`-docs entry, would show it to every class. A PRINCIPAL
    /// may still reach it, since the streams are seeded from
    /// `feed-streams.log` rather than from `docs`.
    ///
    /// No live commit produces that disagreement, and the two shapes that
    /// could are edge: a `commits.log` line demoted for malformed names,
    /// whose entry is then BARE and discloses its position alone either way,
    /// and an edited file. NOT filtered against `docs` at open on purpose —
    /// the filter is a change to which entries a class sees, taken off a
    /// file this daemon did not write.
    masked: BTreeSet<u64>,
    /// The materialized published stream: every entry not in `masked`.
    published: BTreeSet<u64>,
    /// Owner account → the positions naming one of its drafts, ascending.
    /// The ONE position collection built from a FILE's own sequence: `masked`
    /// and `published` are `BTreeSet`s and [`Inner::index`] takes its replay
    /// order from `docs`, a `BTreeMap`, while this is pushed — in file order
    /// at replay, in position order at the record ([`Inner::index`]'s second
    /// path, and the same guard). [`Feed::open`] sorts the replayed half,
    /// which is what establishes the invariant [`at_or_above`]'s
    /// `partition_point` reads.
    streams: BTreeMap<Address, Vec<u64>>,
    /// THE ATTEST STORE — its own card, [`AttestStore`], whose class keeps it
    /// out of `files` and out of every rewrite here. Read per rendered entry
    /// by [`Feed::page`], which is the one consumer.
    attest: AttestStore,
    files: Files,
}

/// The four derived sidecars' files — the ones [`Feed::open`]'s compaction
/// rewrites; the attest store keeps its own.
struct Files {
    index: LineFile,
    offsets: LineFile,
    masked: LineFile,
    streams: LineFile,
}

impl Feed {
    /// Open the feed over `dir`: replay `commits.log` (reconstructing and
    /// classifying its uncovered tail from the journal), replay the four
    /// derived sidecars, re-derive each one's missing tail — a recorded
    /// position's contribution from its own record, a bare position's from
    /// the journal — and fence each at the head; then open the attest store
    /// ([`AttestStore::open`]). Runs AFTER M2's load-and-replay and BEFORE
    /// the first page (PUB-6.40): every classification here reads the
    /// recovered head's exception set, and the grant fold it stands beside is
    /// seeded by the same load.
    ///
    /// COST: the `commits.log` replay and walk (`CommitsLog::open` states
    /// them), plus O(each derived file) to replay it and O(its missing
    /// tail) to close it — a whole-file loss is one O(journal) rebuild, and a
    /// bare position outside the index's coverage one targeted pair of
    /// world reconstructions — and the attest store's own open, whose cost
    /// [`AttestStore::open`] states. Never a rewrite per restart: a derived
    /// file is rewritten only when the log compacted under it, when it
    /// carries another journal's lines, or (the offset array) when its
    /// offsets no longer match the log's.
    ///
    /// THE LINES (`operations.md` §1.1 rows 9, 11, 2), through `lines`, the
    /// classed door the write path made ahead of this open: a derived file's
    /// cut, answered by its replay, is said here with the last trusted
    /// position and that the cut part is re-derived ([`DerivedCutLine`]);
    /// the index file's malformed names are counted and said once with the
    /// first position and how many of them are bare, which no testimony
    /// rescues ([`MalformedNamesLine`]); the classification of the bare
    /// positions the index lost is said ahead of its cost, at the walk's
    /// cadence while it runs and with its figures once done; the open ends
    /// on how far back `/changes` answers and how long the open took
    /// ([`FeedOpenLine`]); and every failure of the open names its file, the
    /// kind kept — the replays' and the attest store's at their own opens,
    /// this open's appends, fences and rewrites through one closure per file
    /// here.
    ///
    /// THE REGION PENDING (the module doc's walk): where the log's open
    /// found positions it does not cover, the four derived files are
    /// rebuilt for the entries the log HOLDS and REWRITTEN fenced at the
    /// region's lower edge — an honest coverage claim, so a crash before
    /// the landing, or a derived rewrite the landing cannot make, leaves no
    /// file claiming over positions it never processed (the derived card's
    /// GAP rule), the next open re-deriving from that fence — and the
    /// open's snapshot of the head's world is answered beside the feed, for
    /// the walk to diff from and the landing to classify against (PUB-7.7's
    /// one-snapshot clause: the head's exception set as the open read it);
    /// `None` where the log covers the head.
    pub(super) fn open(
        dir: &Path,
        engine: &Engine,
        lines: &Lines,
    ) -> io::Result<(Feed, Option<Snapshot<World>>)> {
        let started = Instant::now();
        let log = CommitsLog::open(dir, engine, lines)?;
        let head = log.open_head();
        let pending = log.pending_region();
        // The coverage the open closes the four files at: the head, or the
        // region's lower edge where the walk has the rest to land.
        let covered = pending.map_or(head, |(low, _)| low);
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
        //    the log holds, then this open's walk, then the index's tail ──
        let mut docs: BTreeMap<u64, Vec<Doc>> = BTreeMap::new();
        // The index file's malformed names, counted for one line after the
        // read: the positions met, the bare ones among them, and the first.
        let mut malformed: Option<(usize, usize, u64)> = None;
        for (at, m) in &index_entries {
            let Some(meta) = log.entries().get(at) else { continue };
            // Counted against what the file CLAIMED, not against what could
            // be read out of it: an element that is not a string is one
            // malformed name like any other, and dropping it ahead of this
            // count is what would let a short list pass the test below.
            let named = elements_of(m.get(INDEX_DOCS));
            let addrs: Vec<Address> =
                named.iter().filter_map(Value::as_str).filter_map(parse_dotted).collect();
            let addrs = if addrs.len() == named.len() {
                addrs
            } else {
                // A DERIVED record this daemon cannot parse. Never trusted
                // OVER the authority file — that is the derived layer's
                // whole standing — so a recorded position answers from its
                // own testimony instead, which `CommitsLog` stands behind
                // (its entries are checked at its own open); a bare one has
                // none, and stays unclassified, which is the residue it
                // already carries. Accepting the SHORT list would mask the
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
        // The bare positions the index lost are classified from the journal
        // before the board serves, at two world reconstructions each — said
        // ahead of the cost, at a cadence while it runs and with its figures
        // once done, so a slow open is told from a hung one.
        let tail = f_index.first_uncovered()..;
        let unclassified = log
            .entries()
            .range(tail.clone())
            .filter(|(at, meta)| matches!(meta, CommitMeta::Bare { .. }) && !docs.contains_key(at))
            .count();
        if unclassified > 0 {
            let coverage = f_index.coverage();
            lines.say(Class::Open, BareClassificationLine { coverage, positions: unclassified });
        }
        let classifying = Instant::now();
        let mut cadence = ProgressCadence::new();
        let mut attempted = 0usize;
        // The journal's refusals of that classification: counted, the first
        // kept in the kernel's words, said once after the walk.
        let mut refused: Option<(usize, u64, String)> = None;
        for (&at, meta) in log.entries().range(tail) {
            if let std::collections::btree_map::Entry::Vacant(vacant) = docs.entry(at) {
                let addrs: Vec<Address> = match meta {
                    // Every name reads: `CommitsLog` demoted the recorded
                    // positions whose did not, so this parse drops nothing.
                    CommitMeta::Recorded { docs: strings, .. } => {
                        strings.iter().filter_map(|s| parse_dotted(s)).collect()
                    }
                    // A bare position the index lost: the journal answers —
                    // one pair of world reconstructions per such position,
                    // the per-position cost the walk's landing never pays
                    // (it classifies off the worlds it already holds).
                    CommitMeta::Bare { .. } => {
                        attempted += 1;
                        let addrs = match classify_bare(engine, &log, at) {
                            Ok(addrs) => addrs,
                            Err(e) => {
                                refused = Some(match refused {
                                    None => (1, at, e.to_string()),
                                    Some((n, first, account)) => (n + 1, first, account),
                                });
                                Vec::new()
                            }
                        };
                        let every = FEED_WALK_PROGRESS_BOUNDARIES;
                        if cadence.due(attempted, every, FEED_WALK_PROGRESS_INTERVAL) {
                            let elapsed_ms = classifying.elapsed().as_millis();
                            let progress = BareClassifyingLine {
                                position: at,
                                done: attempted,
                                of: unclassified,
                                elapsed_ms,
                            };
                            lines.say(Class::Open, progress);
                        }
                        addrs
                    }
                };
                if !addrs.is_empty() {
                    vacant.insert(classify(world, addrs));
                }
            }
            if let Some(ds) = docs.get(&at) {
                f_index
                    .append(at, vec![(INDEX_DOCS, doc_strings(ds))])
                    .map_err(with_file(INDEX_FILE))?;
            }
        }
        if attempted > 0 {
            let classified = attempted - refused.as_ref().map_or(0, |(n, ..)| *n);
            let elapsed_ms = classifying.elapsed().as_millis();
            lines.say(Class::Open, BareClassifiedLine { classified, of: attempted, elapsed_ms });
        }
        if let Some((positions, first, account)) = refused {
            lines.say(Class::Failure, ClassificationRefusedLine { positions, first, account });
        }
        f_index.fence(covered).map_err(with_file(INDEX_FILE))?;

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
        let mut masked: BTreeSet<u64> = masked_entries
            .iter()
            .map(|(at, _)| *at)
            .filter(|at| log.entries().contains_key(at))
            .collect();
        for (&at, _) in log.entries().range(f_masked.first_uncovered()..) {
            if masked_at_commit(docs.get(&at).map(Vec::as_slice).unwrap_or(&[])) {
                masked.insert(at);
                f_masked.append(at, vec![]).map_err(with_file(MASKED_FILE))?;
            }
        }
        f_masked.fence(covered).map_err(with_file(MASKED_FILE))?;
        let published: BTreeSet<u64> =
            log.entries().keys().copied().filter(|at| !masked.contains(at)).collect();

        // ── the per-owner draft streams ──
        //
        // An owner name this daemon cannot parse is DROPPED here, and that is
        // the safe direction: the position leaves that owner's stream, so
        // their supplement is short by it and nothing is unmasked. The index
        // above cannot be lossy in the same way — a dropped DOCUMENT shortens
        // the class the mask is computed over — which is why that read
        // refuses a half-record and this one does not.
        let mut streams: BTreeMap<Address, Vec<u64>> = BTreeMap::new();
        for (at, m) in &stream_entries {
            if !log.entries().contains_key(at) {
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
        // The replay above pushed in FILE order, which establishes nothing:
        // this map's lists are ASCENDING by invariant, which is what makes
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
            let owners = owners_of(docs.get(&at).map(Vec::as_slice).unwrap_or(&[]));
            if !owners.is_empty() {
                for owner in &owners {
                    streams.entry(owner.clone()).or_default().push(at);
                }
                f_streams
                    .append(at, vec![(STREAMS_OWNERS, addr_strings(&owners))])
                    .map_err(with_file(STREAMS_FILE))?;
            }
        }
        f_streams.fence(covered).map_err(with_file(STREAMS_FILE))?;

        // ── the offset array, checked against the log's own replay ──
        //
        // `!log.rewritten()` is this file's half of COMPACTION as well as its
        // agreement test: a compacted log moved every offset, so the file is
        // rewritten below — with the other three where the log compacted,
        // alone where the log stands and its offsets merely disagree.
        let offsets_agree = !log.rewritten()
            && offset_entries.iter().all(|(at, m)| {
                m.get(OFFSETS_OFFSET).and_then(Value::as_u64)
                    == log.offsets().get(at).map(|o| o.0)
            });
        if offsets_agree {
            for (&at, &offset) in log.offsets().range(f_offsets.first_uncovered()..) {
                f_offsets
                    .append(at, vec![(OFFSETS_OFFSET, Value::Number(offset.0.into()))])
                    .map_err(with_file(OFFSETS_FILE))?;
            }
            f_offsets.fence(covered).map_err(with_file(OFFSETS_FILE))?;
        }

        // ── the attest store, on its own card ──
        let attest = AttestStore::open(dir, engine, &log, lines)?;

        // ── compaction: the log dropped what the journal reclaimed, so the
        //    derived files drop it too, rewritten from the twins — the SAME
        //    rewrite the checkpoint thread runs after each checkpoint lands
        //    (`Feed::compact_below_reclaim_floor`), through the same method,
        //    the four files at once; or the offset array alone, where the
        //    log stands and its offsets disagree; or, THE REGION PENDING,
        //    the four fenced at its lower edge whatever they claimed — a
        //    file fenced at the head over positions it never processed
        //    would read them as contributing nothing at the next open, a
        //    draft write unmasked, where the walk's landing then cannot
        //    rewrite it. A fifth DERIVED file belongs in that method; the
        //    attest store is not one, and `Files` does not hold it. Fatal
        //    here, either side of a rename: nothing is served yet — the
        //    bare I/O error wrapped with the file's name, which
        //    `RewriteFail::into_io` does not carry. ──
        let compacted = log.rewritten();
        let mut inner = Inner {
            log,
            docs,
            index,
            masked,
            published,
            streams,
            attest,
            files: Files {
                index: f_index,
                offsets: f_offsets,
                masked: f_masked,
                streams: f_streams,
            },
        };
        let failures = if compacted || pending.is_some() {
            inner.rewrite_derived_files(covered)
        } else if !offsets_agree {
            inner.rewrite_offsets_file(covered)
        } else {
            Vec::new()
        };
        if let Some((name, failed)) = failures.into_iter().next() {
            return Err(with_file(name)(failed.into_io()));
        }
        if let Some((floor, dropped)) = inner.log.compacted_at_open() {
            lines.say(Class::Open, OpenCompactionLine { floor, dropped });
        }
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
        Ok((Feed { inner: Mutex::new(inner) }, pending.map(|_| snap)))
    }

    /// Returns what the attest store holds ([`AttestStoreFigures`]).
    ///
    /// Read under the feed's lock and no guard.
    pub(super) fn attest_store_figures(&self) -> AttestStoreFigures {
        self.inner.lock().attest.figures()
    }

    /// THE REGION PENDING, as a read — `CommitsLog::pending_region`, under
    /// the feed's lock: `(low, head]`, or `None` once the walk has landed.
    pub(super) fn pending_region(&self) -> Option<(u64, u64)> {
        self.inner.lock().log.pending_region()
    }

    /// THE WALK BEHIND THE LISTENER — the thread's body, less the catch,
    /// which the write path puts around it (`operations.md` §3.3 step 2;
    /// §1.1 m15): the walk over the pending region
    /// ([`reconstruct`]: the `open:` line, the hold, the `progress:` lines)
    /// off `kernel` and the open's `snapshot` of the head's world, then the
    /// landing ([`Feed::land`]). Returns with nothing written where the stop
    /// was asked before the landing, or where no region is pending.
    pub(super) fn walk_and_land(
        &self,
        kernel: &Kernel<World>,
        snapshot: &Snapshot<World>,
        control: &WalkControl,
        lines: &Lines,
    ) {
        let Some((low, head)) = self.pending_region() else { return };
        let Some(outcome) = reconstruct(kernel, snapshot.world(), low, head, lines, control) else {
            return;
        };
        self.land(outcome, kernel, snapshot.world(), control, lines);
    }

    /// THE LANDING, under this feed's lock — the record step's and the
    /// page's one lock, so a write's record and a page wait on it for the
    /// rewrite's length and never see a half-landed feed: the walk's
    /// classifications folded into the twins as the record step folds a
    /// position ([`Inner::fold_into_maps`]), classified against `world` —
    /// the open's head, PUB-7.7's one snapshot; ONE rewrite of
    /// `commits.log` ([`CommitsLog::land`]) with the fence as the floor
    /// stands AT the landing — a checkpoint that landed during the walk
    /// moved it, its compaction deferred to this rewrite — the twins
    /// trimmed to the same fence; then the four derived files rewritten
    /// whole from the twins, fenced at the last position the log holds —
    /// the compaction's own rewrite ([`Inner::rewrite_derived_files`]), the
    /// open's and the checkpoint thread's; the attest store untouched; the
    /// region cleared; the `landing:` line said. A rewrite that fails is
    /// said as the compaction's is — before its rename the file stands,
    /// the four derived ones fenced at the region's lower edge since the
    /// open and so re-derived by the next open, `commits.log` stopped
    /// ([`CommitsLog::land`] says why); past it the file is in place and
    /// has said its own stop — and fails no op. A stop asked while the
    /// walk ran writes nothing.
    fn land(
        &self,
        outcome: WalkOutcome,
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
        for w in &outcome.boundaries {
            let docs = w.docs.as_ref().map(|addrs| classify(world, addrs.clone())).unwrap_or_default();
            inner.fold_into_maps(w.at, docs);
        }
        // The region's positions were pushed after the ones recorded during
        // the walk, above the head: the lists are ASCENDING by invariant
        // (`at_or_above`'s `partition_point` reads it), restored here as
        // the open restores the replayed streams'.
        inner.sort_the_lists();
        let region = inner.log.pending_region();
        let landed = inner.log.land(&outcome.boundaries, outcome.min_since, floor_fence);
        let in_memory_alone = matches!(landed, Err(RewriteFail::BeforeRename(_)));
        let fence = match landed {
            Ok(fence) => fence,
            // Said at the log: before its rename as the landing's own
            // refusal, past it as the file's stop. The resident entries are
            // complete either way, and the twins follow them below.
            Err(_) => inner.log.min_since_in_force(),
        };
        inner.drop_at_or_below(fence);
        let covered = inner.log.entries().keys().next_back().copied().unwrap_or(fence);
        let (low, head) = region.unwrap_or((fence, fence));
        for (name, failed) in inner.rewrite_derived_files(covered) {
            if let RewriteFail::BeforeRename(e) = failed {
                lines.say(
                    Class::Failure,
                    format_args!(
                        "{name}: the walk's landing rewrite failed before its rename: {}; the \
                         file stands fenced below the region at position {low}, and the next \
                         open re-derives it",
                        IoCause(&e)
                    ),
                );
            }
        }
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

    /// COMPACT THE FIVE FILES TO THE JOURNAL's RECLAIM FLOOR, while serving —
    /// what the daemon's checkpoint thread runs after each checkpoint lands,
    /// under this feed's lock, which is the one lock the record step and the
    /// page take: the same rewrite [`Feed::open`] runs, the fence found by
    /// the same probe ([`reclaim_floor`]). `commits.log` drops every entry
    /// at or below the fence just under the floor and rewrites itself around
    /// the survivors ([`CommitsLog::compact_to`]); the four twins drop the
    /// same positions and the four derived files are rewritten from them
    /// whole, fenced at the last recorded position; the attest store is
    /// untouched (its class: below the floor its lines are primary). Answers
    /// what it did ([`FeedCompaction`]): the fence compacted to, or none
    /// where the floor has not moved past the oldest entry — the ordinary
    /// answer between reclaiming checkpoints — and nothing is written; and
    /// beside the fence, by name, each file that STOOD.
    ///
    /// THE DISPOSITION while serving is the record step's own (the settled
    /// rule for `record`): reported on the operator stream, never failing an
    /// op. A rewrite that fails BEFORE its rename leaves that file whole and
    /// standing and is said here, the next checkpoint's compaction trying
    /// again — and that file is named in the answer, so the checkpoint
    /// thread's landing line is truthful of it; one that fails PAST its
    /// rename stops its file for the uptime and is said by the file itself,
    /// once — the new file is in place, so it is not one that stood — the
    /// resident twins are trimmed either way and serve this uptime, and the
    /// next open re-derives (P22).
    ///
    /// WHILE THE WALK's REGION IS PENDING the rewrite is DEFERRED: the fence
    /// moves in memory — the log's entries and the twins trimmed, so a page
    /// below it answers 410 at once, as `/op-at` does — and no file is
    /// written, the twins lacking the region the files must carry; the
    /// landing's one rewrite writes the fence, which it reads from the floor
    /// again then ([`Feed::land`]). The deferral's record is that fence:
    /// `commits.log`'s `min_since` ahead of the line its file holds until
    /// the landing. The answer names the fence and the region the files'
    /// rewrite waits on (`deferred`), and no file standing, so the
    /// checkpoint thread's line says the files were not written.
    ///
    /// THE LINES (`operations.md` §1.1 rows 27 and 28) go through `lines`,
    /// the write path's classed door, handed at the call as the walk's
    /// landing is handed it: a rewrite that failed BEFORE its rename, with
    /// the reclaim floor's position it compacted to, said per ATTEMPT — each
    /// landing while the cause stands is a fresh act whose failure is news,
    /// the rule's named exception — under `Class::Failure`.
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
        let dropped = match inner.log.compact_to(fence) {
            Ok(dropped) => dropped,
            // The file said its own stop; the entries are trimmed all the
            // same, and the twins follow them below.
            Err(RewriteFail::PastRename(_)) => true,
            Err(before) => {
                lines.say(
                    Class::Failure,
                    format_args!(
                        "commits.log compaction below the reclaim floor at position {floor} \
                         failed {before}; the file stands as it was, and the next checkpoint's \
                         compaction tries again"
                    ),
                );
                standing.push("commits.log");
                true
            }
        };
        if !dropped {
            return FeedCompaction::default();
        }
        inner.drop_at_or_below(fence);
        if let Some(region) = inner.log.pending_region() {
            return FeedCompaction { fence: Some(fence), standing, deferred: Some(region) };
        }
        let covered = inner.log.entries().keys().next_back().copied().unwrap_or(fence);
        for (name, failed) in inner.rewrite_derived_files(covered) {
            if let RewriteFail::BeforeRename(e) = failed {
                lines.say(
                    Class::Failure,
                    format_args!(
                        "{name} compaction below the reclaim floor at position {floor} failed \
                         before its rename: {}; the file stands as it was, and the next \
                         checkpoint's compaction tries again",
                        IoCause(&e)
                    ),
                );
                standing.push(name);
            }
        }
        FeedCompaction { fence: Some(fence), standing, deferred: None }
    }

    /// The test seam behind `skepd::Daemon::fail_the_feeds_next_rewrite_past_rename`:
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

    /// THE STOPPED FILES, as a read: of `commits.log` and the four derived
    /// files, those that take no further line this uptime, each with the
    /// position its stop was set at ([`StoppedFile`]) — `commits.log` first,
    /// then the four in their table's order — under the feed's lock and no
    /// guard. The standing line's read (once an hour while any stands) and
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

    /// Record one committed write at ack time — under the write-serialization
    /// guard, between a commit and its ack, which is [`CommitsLog::record`]'s
    /// contract and this method's; the guard argument is that contract's
    /// cheap half — and classify it against `world` — the POST-COMMIT head, so
    /// the minted document's registration and bit are in it — into the four
    /// derived structures: the offset array, the index (docs non-empty), the
    /// bitmap or the published stream, and each named draft's owner stream —
    /// and, where the write's marker slot was filled, into the attest store
    /// ([`AttestStore::record`]), the admitted value itself. Declined exactly
    /// when the log declines (an old commit's re-ack).
    ///
    /// The derived appends are testimony too: a failed one is reported and
    /// the resident twin stays right, so this uptime answers correctly and
    /// the next open's tail check re-derives what the file missed. The attest
    /// store's line is the exception (SO-I5 (d)): synced before this
    /// returns, and where its write or its sync fails, answered
    /// [`AttestStoreFailed`], on which the write path halts — the slot still served
    /// this uptime, the line rebuilt from the journal by the restart's open.
    ///
    /// `docs` arrives as ADDRESSES and is rendered once, here, for the
    /// authority file alone: the classification reads them as addresses, so
    /// text handed down from the write path would be parsed straight back —
    /// and a parse that could not read a name would have nowhere to report
    /// it, leaving the position classified short and, where every name
    /// dropped, served to every class as a `[]`-docs entry.
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
        let mut inner = self.inner.lock();
        let rendered: Vec<String> = docs.iter().map(|a| a.tumbler().to_string()).collect();
        let (carrier, attest) = match signed {
            Some(Signed::Marker(a)) => (Some(Carrier::Marker), Some(a)),
            Some(Signed::RecordSig) => (Some(Carrier::RecordSig), None),
            None => (None, None),
        };
        let Some(recorded) = inner.log.record(serial, at, op, rendered, testimony, carrier, terms)
        else {
            return Ok(());
        };
        inner.fold_position(at, recorded, classify(world, docs), attest)
    }

    /// THE THIRD ARM's RECORD (`operations.md` §4 row 34): one BARE entry at
    /// `at` — the position a write committed before it panicked, which the
    /// write path's door caught — under the same guard and contract as
    /// [`Feed::record`], between the commit and the re-raise. What the
    /// recorded row would have carried is lost with the answer, so the entry
    /// is the walk's own form ([`CommitMeta::Bare`] with the journal's
    /// answer, `null` for the rest), and its classification the walk's:
    /// `docs` and `journal` as `classify::derived_journal` read them off the
    /// two worlds the door held, `docs` classified here against `world` —
    /// the post-commit head — as a recorded position's are, so the mask, the
    /// index, the bitmap and the streams take the position as the walk's
    /// landing would, at the commit rather than at the next open. `attest`
    /// is the marker slot the write FILLED, where it filled one — the value
    /// the plain sequence admitted and handed the kernel — mirrored into the
    /// attest store and synced as every admitted marker is (SO-I5 (d)), the
    /// store's refusal answered as [`Feed::record`] answers it. Declined
    /// exactly when the log declines.
    pub(super) fn record_bare(
        &self,
        serial: &SerialGuard<'_>,
        at: u64,
        docs: Vec<Address>,
        journal: JournalTerms,
        attest: Option<Attestation>,
        world: &World,
    ) -> Result<(), AttestStoreFailed> {
        let mut inner = self.inner.lock();
        let Some(recorded) = inner.log.record_bare(serial, at, journal) else {
            return Ok(());
        };
        inner.fold_position(at, recorded, classify(world, docs), attest)
    }

    /// The test seam behind `skepd::Daemon::attest_store_synced_through`:
    /// the coverage the attest store's last successful sync made durable.
    /// Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn attest_store_synced_through(&self) -> u64 {
        self.inner.lock().attest.synced_through()
    }

    /// The test seam behind `skepd::Daemon::fail_the_attest_stores_next_write`:
    /// the attest store's next write fails at the OS. Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn fail_the_attest_stores_next_write(&self) {
        self.inner.lock().attest.fail_next_write();
    }

    /// The data behind `GET /changes` at `class`.
    ///
    /// The rows are COLLECTED under the feed's lock and RENDERED after it is
    /// released: [`Feed::record`], the write path's step under the
    /// serialization lock, waits on that lock, and an attested row's render —
    /// its `attest` member, 6,746 hex characters under tag 1 — is the dearest
    /// part of a page. Under the lock: the merge, the mask, and a clone per
    /// row, the slot an `Arc`.
    ///
    /// THE PAGE BYTE BUDGET (bu7-2; SO-I9): the rows are MEASURED as they
    /// are rendered — each entry's marshaled bytes and the comma between
    /// entries, the page object's own envelope (`changes`, `last`, `more`:
    /// under forty bytes) aside — and where the sum passes
    /// [`MAX_CHANGES_PAGE_BYTES`] the whole request is refused
    /// ([`ChangesAnswer::OverBudget`]), naming the budget and the rows that
    /// fit, never a page shorter than `limit` (PUB-6.44). The budget is
    /// paid at the layer that produces the page (P29), so a guest asking
    /// the maximum `limit` over attested rows costs the daemon the render of
    /// at most the budget's worth of rows and one more.
    ///
    /// THE REGION PENDING (`operations.md` §3.3 step 2: "for any page whose
    /// range reaches into the uncovered region, not only a `since` inside
    /// it — a page starting below the region would otherwise silently skip
    /// its positions"): after the reclaimed check and before the merge
    /// serves a row, where `(low, head]` is pending and `since < head`, the
    /// page is refused [`ChangesAnswer::Rebuilding`] UNLESS its `limit`
    /// rows all lie at or below `low` — the merge walked up to `low` and no
    /// further, since the twins hold nothing of the region and the next
    /// candidate past `low` would be a position recorded above the head,
    /// the region skipped between. THE ARITHMETIC, pinned by the walk
    /// suite: `low` is covered (a page's last row may be it), `head`
    /// uncovered (the last of the region); a page refused by the position
    /// test `since + limit > low` is refused here too, since fewer than
    /// `limit` positions, hence rows, lie in `(since, low]`, and a page
    /// that test would serve over sparse positions — fewer than `limit`
    /// rows below `low`, the merge then reaching past the region — is
    /// refused as well. A page served below the region answers `more:
    /// true`: the region holds positions this class may see, which the
    /// next page meets as the refusal or, landed, as rows. A page with
    /// `since` at or above `head` serves from the twins as ever — every
    /// position recorded since the open is in them.
    pub(crate) fn page(&self, class: &FeedClass<'_>, query: &ChangesQuery) -> ChangesAnswer {
        let (rows, more) = {
            let inner = self.inner.lock();
            if !inner.log.admits_since(query.since) {
                return ChangesAnswer::Reclaimed { floor: inner.log.floor() };
            }
            let Some(start) = query.since.checked_add(1) else {
                return ChangesAnswer::Page { entries: Vec::new(), last: query.since, more: false };
            };
            let region = inner.log.pending_region().filter(|&(_, head)| query.since < head);
            let mut rows = Vec::new();
            let mut more = false;
            for at in Merge::new(inner.sources(class, query, start)) {
                if region.is_some_and(|(low, _)| at > low) {
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
            if let Some((low, head)) = region {
                if rows.len() < query.limit.get() {
                    return ChangesAnswer::Rebuilding { low, head };
                }
                more = true;
            }
            (rows, more)
        };
        let last = rows.last().map_or(query.since, |(at, ..)| *at);
        let mut entries = Vec::with_capacity(rows.len());
        let mut bytes = 0usize;
        for (at, meta, reduced, whole, slot) in rows {
            let mut entry = meta.entry(at, reduced, slot.as_deref());
            // THE THIRD ABSENCE (mi7-E2; SO-I5 (e)): a row whose `docs` this
            // class REDUCES — a straddle, a draft-homed `nullify` of a public
            // link or an `edit_link` with one home a draft (PUB-6.47) —
            // carries no `attest`, ABSENT and never `null`: the signature is
            // a function of the home the row withholds, and served it would
            // confirm a guess at that home, the confirmation the chain's
            // salt exists to deny. The verdict there is undeterminable from
            // this feed; the owner's own page carries the member whole.
            if !whole {
                entry.as_object_mut().expect("an entry is an object").remove("attest");
            }
            // The entry's marshaled length — key order moves no byte of it
            // — and the comma that joins it to the one before.
            bytes += to_bytes(&entry).len() + usize::from(!entries.is_empty());
            if bytes > MAX_CHANGES_PAGE_BYTES {
                return ChangesAnswer::OverBudget {
                    budget: MAX_CHANGES_PAGE_BYTES,
                    fits: entries.len(),
                };
            }
            entries.push(entry);
        }
        ChangesAnswer::Page { entries, last, more }
    }

    /// The HEAD position's recorded wall-clock time — `CommitsLog::head_time`.
    pub(crate) fn head_time(&self) -> Option<u64> {
        self.inner.lock().log.head_time()
    }

    /// Every recorded entry above `position` — `CommitsLog::entries_above`,
    /// for the head writer's resume.
    pub(crate) fn entries_above(&self, position: u64) -> Vec<(u64, CommitMeta)> {
        self.inner.lock().log.entries_above(position)
    }
}

/// An open-time failure on a derived file, naming the file — the closure
/// `BlockedSupply::read` wraps its path with, per file: the kind kept, the
/// name before the OS's text, so the daemon's `change-feed sidecar: {e}`
/// reads `change-feed sidecar: feed-index.log: {e}` (`operations.md` §1.1
/// row 2).
fn with_file(name: &'static str) -> impl Fn(io::Error) -> io::Error {
    move |e| io::Error::new(e.kind(), format!("{name}: {e}"))
}

/// Row 9 for a derived file, said where its replay answered a cut: the head,
/// then this file's case — the cut part is re-derived, by the tail
/// derivation [`Feed::open`] runs from the last trusted position.
fn say_derived_cut(lines: &Lines, name: &'static str, cut: Option<Cut>) {
    if let Some(cut) = cut {
        lines.say(Class::Failure, DerivedCutLine { name, cut });
    }
}

/// Row 9's words for one of the four derived files (`operations.md` §1.1
/// row 9): `{file}: trust ends at position {c} (byte {n} of {len}); the {k}
/// bytes after it are cut; the cut part is re-derived`. A pure value, pinned
/// by `to_string()` in the unit suite; emitted under `Class::Failure` by
/// [`say_derived_cut`].
struct DerivedCutLine {
    name: &'static str,
    cut: Cut,
}

impl std::fmt::Display for DerivedCutLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; the cut part is re-derived", CutHead { name: self.name, cut: self.cut })
    }
}

/// The open's line ahead of the bare positions it classifies from the
/// journal before the board serves.
///
/// The words: `feed-index.log covers to position {c}: {n} bare positions
/// are classified from the journal before the board serves, two world
/// reconstructions each` — the cost said ahead of paying it. A pure value,
/// pinned by `to_string()` in the unit suite; emitted under `Class::Open`
/// by [`Feed::open`].
struct BareClassificationLine {
    coverage: u64,
    positions: usize,
}

impl std::fmt::Display for BareClassificationLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{INDEX_FILE} covers to position {}: {} bare positions are classified from the \
             journal before the board serves, two world reconstructions each",
            self.coverage, self.positions
        )
    }
}

/// The open's bare classification while it runs, at the walk's cadence.
///
/// The words: `feed-index.log: the bare classification at position {p},
/// {i} of {n}, {d} ms in` — `{p}` the position last classified, `{i}` how
/// many are done of the `{n}` the announcing line named, `{d}` since the
/// classification began. Said every [`FEED_WALK_PROGRESS_BOUNDARIES`]
/// positions or [`FEED_WALK_PROGRESS_INTERVAL`], whichever comes first: the
/// board serves nothing until the open is done, and two world
/// reconstructions a position can run past a supervisor's start window. A
/// pure value, pinned by `to_string()` in the unit suite; emitted under
/// `Class::Open` by [`Feed::open`] — the open's own line, the `progress:`
/// class being the walk thread's.
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

/// The open's bare classification, done.
///
/// The words: `feed-index.log: {c} of {n} bare positions classified from the
/// journal in {d} ms` — the ones the journal refused said beside it
/// ([`ClassificationRefusedLine`]). A pure value, pinned by `to_string()` in
/// the unit suite; emitted under `Class::Open` by [`Feed::open`].
struct BareClassifiedLine {
    classified: usize,
    of: usize,
    elapsed_ms: u128,
}

impl std::fmt::Display for BareClassifiedLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{INDEX_FILE}: {} of {} bare positions classified from the journal in {} ms",
            self.classified, self.of, self.elapsed_ms
        )
    }
}

/// The feed's open, done: how far back `/changes` answers, and the cost.
///
/// The words: `the change feed answers from position {f} to position {h}:
/// commits.log {n} entries, {b} of them bare[; positions ({low}, {head}]
/// wait on the walk], in {d} ms` — `{f}` the oldest position still
/// answerable, the `floor` a `410 history_reclaimed` names; the bare
/// entries those whose testimony is lost; the region the walk behind the
/// listener has yet to land, where one is pending; and the open's whole
/// span. A feed that answers no position — no entry, no region pending —
/// says `the change feed answers no position yet, the head at position {h},
/// in {d} ms`. A pure value, pinned by `to_string()` in the unit suite;
/// emitted under `Class::Open` by [`Feed::open`], last.
struct FeedOpenLine {
    floor: Option<u64>,
    head: u64,
    entries: usize,
    bare: usize,
    pending: Option<(u64, u64)>,
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
        if let Some((low, head)) = self.pending {
            write!(f, "; positions ({low}, {head}] wait on the walk")?;
        }
        write!(f, ", in {} ms", self.elapsed_ms)
    }
}

/// The journal's refusals of the open's bare classification, said once.
///
/// The words: `feed-index.log: the journal refused to classify {n} bare
/// positions, the first at position {p} ({account}): each is served to
/// every class, its position alone` — `{account}` the first refusal's, in
/// the kernel's words. A pure value, pinned by `to_string()` in the unit
/// suite; emitted under `Class::Failure` by [`Feed::open`].
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

/// What one position's fold into the twins would put on the four files'
/// lines ([`Inner::fold_into_maps`]): the index record's documents where it
/// named any, whether the bitmap takes it, the owner streams it enters.
struct Folded {
    docs: Option<Value>,
    masked: bool,
    owners: Option<Value>,
}

/// One entry as a class sees it ([`Inner::visible`]): its meta, its docs
/// REDUCED to the ones the class may read, and whether that reduction dropped
/// none of them — `false` on a straddle row, whose `attest` the page then
/// withholds (mi7-E2).
struct Visible<'a> {
    meta: &'a CommitMeta,
    reduced: Vec<&'a Doc>,
    whole: bool,
}

impl Inner {
    /// Sort every index list and every owner stream and drop the repeats —
    /// the ASCENDING invariant the two slice-backed sources rest on
    /// ([`at_or_above`]), established by the open for the replayed streams
    /// and by the record step's order for a live commit, and re-established
    /// by the walk's landing, which folds the region's positions after the
    /// ones recorded above the head while it walked.
    fn sort_the_lists(&mut self) {
        for (_, positions) in self.index.values_mut() {
            positions.sort_unstable();
            positions.dedup();
        }
        for positions in self.streams.values_mut() {
            positions.sort_unstable();
            positions.dedup();
        }
    }

    /// Drop every position at or below `min_since` from the four twins —
    /// the positions the log has just dropped ([`CommitsLog::compact_to`]),
    /// unreachable by every route — so the twins and the log name one set
    /// of positions, and a rewrite from the twins writes that set.
    fn drop_at_or_below(&mut self, min_since: u64) {
        let keep_from = min_since.saturating_add(1);
        self.docs = self.docs.split_off(&keep_from);
        self.masked = self.masked.split_off(&keep_from);
        self.published = self.published.split_off(&keep_from);
        self.index.retain(|_, (_, positions)| {
            positions.retain(|&at| at > min_since);
            !positions.is_empty()
        });
        self.streams.retain(|_, positions| {
            positions.retain(|&at| at > min_since);
            !positions.is_empty()
        });
    }

    /// Rewrite the FOUR derived files whole from the twins, each fenced at
    /// `covered` — the compaction's rewrite, at open and after a checkpoint
    /// alike — answering each file that failed with how
    /// ([`RewriteFail`]), every file attempted whatever the one before it
    /// answered. A fifth derived structure owes a line here, beside its
    /// fold and its replay.
    fn rewrite_derived_files(&mut self, covered: u64) -> Vec<(&'static str, RewriteFail)> {
        let mut failures = Vec::new();
        let records = self.index_records();
        if let Err(failed) = self.files.index.rewrite(records, covered) {
            failures.push((INDEX_FILE, failed));
        }
        let records = self.masked_records();
        if let Err(failed) = self.files.masked.rewrite(records, covered) {
            failures.push((MASKED_FILE, failed));
        }
        let records = self.stream_records();
        if let Err(failed) = self.files.streams.rewrite(records, covered) {
            failures.push((STREAMS_FILE, failed));
        }
        failures.extend(self.rewrite_offsets_file(covered));
        failures
    }

    /// Rewrite the offset array alone from the log's offsets — the open's
    /// answer where the log stands and the file's offsets disagree with it,
    /// and the fourth file of [`Inner::rewrite_derived_files`].
    fn rewrite_offsets_file(&mut self, covered: u64) -> Vec<(&'static str, RewriteFail)> {
        let records = self.offset_records();
        match self.files.offsets.rewrite(records, covered) {
            Ok(()) => Vec::new(),
            Err(failed) => vec![(OFFSETS_FILE, failed)],
        }
    }

    /// The index file's records, from the classification map.
    fn index_records(&self) -> Vec<Value> {
        self.docs
            .iter()
            .map(|(at, ds)| derived::record_object(*at, vec![(INDEX_DOCS, doc_strings(ds))]))
            .collect()
    }

    /// The bitmap's records, from the masked set.
    fn masked_records(&self) -> Vec<Value> {
        self.masked.iter().map(|at| derived::record_object(*at, Vec::new())).collect()
    }

    /// The streams file's records, from the classification map's owners.
    fn stream_records(&self) -> Vec<Value> {
        self.docs
            .iter()
            .filter_map(|(at, ds)| {
                let owners = owners_of(ds);
                (!owners.is_empty()).then(|| {
                    derived::record_object(*at, vec![(STREAMS_OWNERS, addr_strings(&owners))])
                })
            })
            .collect()
    }

    /// The offset array's records, from the log's offsets.
    fn offset_records(&self) -> Vec<Value> {
        self.log
            .offsets()
            .iter()
            .map(|(at, o)| {
                derived::record_object(*at, vec![(OFFSETS_OFFSET, Value::Number(o.0.into()))])
            })
            .collect()
    }

    /// Fold one classified position into the four twins and append its
    /// lines — and, where `attest` is the marker slot this write filled,
    /// mirror it into the attest store ([`AttestStore::record`]) — the ONE
    /// path at RECORD time, so a live commit cannot leave a twin and its file
    /// disagreeing about what a position contributed.
    ///
    /// It is NOT the only path that contribution takes, and a fifth derived
    /// structure owes all three: this fold; [`Feed::open`]'s
    /// replay-then-derive, where the file is the authority for a position at
    /// or below its coverage and the classification for one above it; and the
    /// compaction rewrite that renders the twin back to lines
    /// ([`Inner::rewrite_derived_files`], with the trim before it). A structure
    /// wired here alone is empty from every open until the next commit, with
    /// its file's fence reporting it covered — which is a short candidate set
    /// claiming completeness, not the silent incompleteness the coverage
    /// check closes. (The attest store owes its own two, on its own card, and
    /// by its class no third.)
    ///
    /// Answers the attest store's [`AttestStoreFailed`] where its line failed
    /// (SO-I5 (d)); the four twins and their files are folded whatever it
    /// answers.
    ///
    /// WHILE THE WALK's REGION IS PENDING (`Recorded::Held`) the twins alone
    /// take the position and the four files take no line — the offset the
    /// array's line would carry does not exist until the landing's rewrite
    /// assigns it, and the landing rewrites the four files whole from the
    /// twins, this position among them; the attest store's line is
    /// appended and synced as ever, the store's file being its own.
    fn fold_position(
        &mut self,
        at: u64,
        recorded: Recorded,
        docs: Vec<Doc>,
        attest: Option<Attestation>,
    ) -> Result<(), AttestStoreFailed> {
        let stored = match attest {
            Some(slot) => self.attest.record(at, slot),
            None => Ok(()),
        };
        let folded = self.fold_into_maps(at, docs);
        let Recorded::Appended(offset) = recorded else {
            return stored;
        };
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

    /// One classified position into the four TWINS and nothing else — the
    /// maps' half of [`Inner::fold_position`], shared with the walk's
    /// landing ([`Feed::land`]), which folds the region's positions this way
    /// and then rewrites the files whole: the index (docs non-empty), the
    /// bitmap or the published stream, each named draft's owner stream, and
    /// the classification map. Answers what the files' lines would carry
    /// ([`Folded`]), so the record step appends exactly what the maps took.
    fn fold_into_maps(&mut self, at: u64, docs: Vec<Doc>) -> Folded {
        let mut folded = Folded { docs: None, masked: false, owners: None };
        if !docs.is_empty() {
            for d in &docs {
                let list = self
                    .index
                    .entry(d.addr.tumbler().clone())
                    .or_insert_with(|| (d.addr.clone(), Vec::new()));
                if list.1.last() != Some(&at) {
                    list.1.push(at);
                }
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
                let stream = self.streams.entry(owner.clone()).or_default();
                if stream.last() != Some(&at) {
                    stream.push(at);
                }
            }
            folded.owners = Some(addr_strings(&owners));
        }
        if !docs.is_empty() {
            self.docs.insert(at, docs);
        }
        folded
    }

    /// THE MASK, per entry (PUB-7.20; PUB-6.44–6.45), plus the narrowings'
    /// per-entry predicates: the entry's meta and its docs REDUCED to the
    /// requester's readable ones — and whether the reduction kept the record's
    /// docs WHOLE, which is what decides the row's `attest` (mi7-E2) — or
    /// `None` when the entry is omitted.
    fn visible(&self, class: &FeedClass<'_>, query: &ChangesQuery, at: u64) -> Option<Visible<'_>> {
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

    /// The candidate sources for `class` and `query`, each an ascending iterator
    /// of positions at or above `start` — what the merge unions. Exact by
    /// the mask, and complete by construction in each of the two branches
    /// this function has, which are complete for different reasons.
    ///
    /// The WALK branch's six source kinds cover every visible position: a
    /// `[]`-docs or published-touching entry is in the published walk; a
    /// draft entry is in its owner's stream, which the subtree clause — by
    /// key for the requester's own and ancestor accounts, by range for the
    /// owner accounts beneath it — the grant clause or the universal term
    /// selects.
    ///
    /// The MERGE branch returns before any of them, from the index alone,
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
                // MERGE (PUB-7.32, PUB-7.33): the index lists under the
                // prefix, an unreadable document's whole list skipped on ONE
                // test — the doc-granular skip.
                for (doc, positions) in self.under_prefix(under) {
                    if !class.readable(doc) {
                        continue;
                    }
                    sources.push(Box::new(at_or_above(positions, start)));
                }
                return sources;
            }
            // WALK: the visible stream below, the prefix tested per entry
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
        // PUB-7.24's SUBTREE TERM, the DESCENDANT OWNER ACCOUNTS' streams
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
            // A grant at the issuer's account depth or wider IS the stream
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
        // A covered PREFIX, not an issuer account: this keys the position
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

    /// Does the entry at `at` name a draft of `issuer` under one of
    /// `prefixes` — the per-entry containment test of a narrower grant.
    ///
    /// A CANDIDATE filter and never the answer, and the reason it may be
    /// stood aside past [`MAX_FILTERED_PREFIXES`] is weaker than "it drops
    /// only what the mask drops", which is false: an entry naming a
    /// published document beside a draft of this issuer outside the granted
    /// prefixes is dropped here and kept by the mask, and reaches the page
    /// through the published walk. What holds is that this filter only ever
    /// REMOVES candidates from ONE source, [`Merge`] unions and deduplicates
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

    /// The index lists under `p`: the documents whose key `p` is a prefix of,
    /// each with its positions. THE one spelling of the fact [`Inner::index`]
    /// is keyed for — a prefix's documents are one CONTIGUOUS key range under
    /// M1's ordering, so the enumeration is a `range` from `p` cut at the
    /// first key `p` does not cover, never a walk of the map.
    ///
    /// One home because [`Inner::merge_beats_walk`] prices the set
    /// [`Inner::sources`]' merge branch then enumerates: the two must range
    /// over the SAME documents, or the rule chooses its branch by counting
    /// something else. The branch additionally skips the UNREADABLE ones,
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

    /// The MERGE-OR-WALK rule (PUB-7.33): merge iff the prefix holds no more
    /// documents than the range holds positions. Both counts advance
    /// together and stop at the first to run out, so the rule costs
    /// O(min(documents, positions)) and needs no rank structure.
    ///
    /// The documents counted are [`Inner::under_prefix`]'s — the same set
    /// the merge branch enumerates, which is what makes this a price of
    /// THAT branch rather than of some other set that happens to be nearby.
    /// It counts the UNREADABLE ones too, which the branch then skips one
    /// whole list at a time, so the count is an over-estimate of the merge's
    /// real work and never an under-estimate. That biases the rule toward
    /// the WALK — it can decline a merge that would have been marginally
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

/// A position list from its first member at or above `start` — THE fence,
/// applied to every slice-backed source. [`Inner::sources`]' contract has
/// two clauses and this call discharges one of them: the AT-OR-ABOVE half,
/// which it and `published.range(start..)` discharge and nothing else does,
/// since [`Inner::visible`] tests the mask and the two narrowings and does
/// NOT re-test the fence — a source that skipped this would serve positions
/// at or below `since`, which is a client re-reading its own history on
/// every poll, with `last` going backwards.
///
/// The ASCENDING half is the collections', each stated on its own field:
/// `published` is a `BTreeSet`, and `index` and `streams` are each ordered
/// at both of their construction paths — by the container at replay (the
/// index) or by an explicit sort (the streams), and by the write-path
/// serialization guard's commit order at the record. `partition_point` is
/// meaningless on an unsorted slice, so this returns an arbitrary suffix
/// rather than a fence for a list that lost it.
fn at_or_above(positions: &[u64], start: u64) -> impl Iterator<Item = u64> + '_ {
    let i = positions.partition_point(|&p| p < start);
    positions[i..].iter().copied()
}

/// The draft streams of the owner accounts STRICTLY beneath `account` —
/// PUB-7.24's SUBTREE TERM of a principal's supplement, its DESCENDANT OWNER
/// ACCOUNTS (RES-220 names it). [`Inner::streams`] is keyed by owner account
/// in tumbler order, so the owner accounts under a prefix are one CONTIGUOUS
/// key range under M1's ordering — the fact [`Inner::under_prefix`] spells for
/// the position index — and the enumeration is a `range` opened past
/// `account` and cut at the first key it does not contain. Never a walk of
/// the map, and never a walk of M3's accounts: it costs the owner accounts
/// beneath `account` that HOLD a stream, which is the subtree term exactly,
/// and an account beneath it that owns no draft is not in the map to be
/// counted.
///
/// `account`'s own stream is excluded: [`FeedClass::enclosing_subtrees`] keys
/// it, and the range opens past it so that no stream is merged twice.
///
/// A CANDIDATE source like the rest, and never the answer: a key this range
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

/// The bitmap's test: docs non-empty and every one a draft. The fact is
/// class-independent and fixed at mint, so the name says what it IS and
/// not when it is evaluated — [`Feed::open`] calls it for the derived
/// tail, long after the commit.
///
/// It is exactly the mask at the GUEST's class — a guest reads published
/// documents alone, so "every named document is a draft" is "none readable
/// to a guest" — which is why the bitmap's complement is the published
/// stream a guest page walks in O(page). THE mask, the per-class verdict
/// wire.md gives the bare word to, is [`Inner::visible`]'s, computed per
/// entry against the requester's own predicate (PUB-7.20).
fn masked_at_commit(docs: &[Doc]) -> bool {
    !docs.is_empty() && docs.iter().all(Doc::is_draft)
}

/// The owner accounts of an entry's drafts — the streams the position
/// enters.
fn owners_of(docs: &[Doc]) -> BTreeSet<Address> {
    docs.iter().filter_map(|d| d.draft_owner.clone()).collect()
}

fn doc_strings(docs: &[Doc]) -> Value {
    Value::Array(docs.iter().map(|d| Value::String(d.addr.to_string())).collect())
}

fn addr_strings<'a>(addrs: impl IntoIterator<Item = &'a Address>) -> Value {
    Value::Array(addrs.into_iter().map(|a| Value::String(a.to_string())).collect())
}

/// One derived record's array field, as its RAW elements — so a caller
/// counting what it could read counts against what the FILE CLAIMED.
/// Handing back strings loses two things at once: a name every caller
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

/// Returns the journal's classification of a bare position the index lost.
///
/// It is read from the world at the boundary below it (the previous entry,
/// or genesis) and its own.
///
/// # Errors
///
/// The journal's refusal of either world (reclaimed, corrupt, I/O): the
/// position is then the module's unclassifiable residue, served to every
/// class, and the caller says the refusal.
fn classify_bare(engine: &Engine, log: &CommitsLog, at: u64) -> Result<Vec<Address>, HistoryError> {
    let prev = log.entries().range(..at).next_back().map(|(k, _)| *k).unwrap_or(0);
    let below = engine.world_at(Seq(prev))?;
    let above = engine.world_at(Seq(at))?;
    Ok(derived_docs(&below, &above))
}

/// The K-way merge of ascending position sources, deduplicated by
/// position across the whole merge (PUB-7.26): a min-heap over each
/// source's head, so a page costs O(log K) per candidate.
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

    /// The next position, each emitted exactly once.
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
mod tests {
    use super::*;

    /// The merge unions its sources in order and emits each position once.
    #[test]
    fn the_merge_dedups_by_position_across_every_source() {
        let a = [1u64, 4, 9];
        let b = [4u64, 5, 9, 12];
        let c: [u64; 0] = [];
        let sources: Vec<Box<dyn Iterator<Item = u64> + '_>> = vec![
            Box::new(a.iter().copied()),
            Box::new(b.iter().copied()),
            Box::new(c.iter().copied()),
            Box::new(a.iter().copied()),
        ];
        let out: Vec<u64> = Merge::new(sources).collect();
        assert_eq!(out, vec![1, 4, 5, 9, 12]);
    }

    /// The descendant range is the owner accounts STRICTLY beneath the
    /// requester's own, and nothing else: its own stream is keyed beside it
    /// and never ranged, a sibling's is past the cut, and containment is by
    /// COMPONENT — `1.0.21` is no account under `1.0.2`, though its text
    /// extends it.
    #[test]
    fn the_descendant_range_is_the_owner_accounts_strictly_beneath() {
        let a = |s: &str| parse_dotted(s).expect("a test address");
        let streams: BTreeMap<Address, Vec<u64>> =
            ["1.0.2", "1.0.2.1", "1.0.2.1.1", "1.0.2.2", "1.0.3", "1.0.21"]
                .iter()
                .zip(1u64..)
                .map(|(owner, at)| (a(owner), vec![at]))
                .collect();
        let beneath = |account: &str| -> Vec<String> {
            streams_beneath(&streams, &a(account)).map(|(owner, _)| owner.to_string()).collect()
        };
        assert_eq!(beneath("1.0.2"), ["1.0.2.1", "1.0.2.1.1", "1.0.2.2"]);
        assert_eq!(beneath("1.0.2.1"), ["1.0.2.1.1"], "the middle of a chain ranges what is below it");
        assert!(beneath("1.0.2.2").is_empty() && beneath("1.0.3").is_empty(), "a leaf ranges nothing");
        // The range hands back each stream it admits, not merely its key.
        let middle = a("1.0.2.1");
        let positions: Vec<&[u64]> = streams_beneath(&streams, &middle).map(|(_, p)| p).collect();
        assert_eq!(positions, [&[3u64][..]]);
    }

    /// A list starts at its first member at or above the fence — the fence
    /// every slice-backed source is narrowed by, and the reason a page never
    /// carries a position at or below `since`.
    #[test]
    fn a_list_starts_at_the_fence() {
        let s = [3u64, 7, 8, 20];
        assert_eq!(at_or_above(&s, 8).collect::<Vec<_>>(), vec![8, 20]);
        assert_eq!(at_or_above(&s, 9).collect::<Vec<_>>(), vec![20]);
        assert_eq!(at_or_above(&s, 21).count(), 0);
        assert_eq!(at_or_above(&s, 0).count(), 4);
    }

    /// Row 9's words for a derived file: the head with the last trusted
    /// position and the bytes, then that the cut part is re-derived — and
    /// the open's failures name their file ahead of the OS's text, the kind
    /// kept.
    #[test]
    fn a_derived_cut_says_it_is_re_derived_and_a_failure_names_its_file() {
        let cut = Cut { valid_end: 120, len: 131, trusted: 32, first: Some(33), whole_after: None };
        assert_eq!(
            DerivedCutLine { name: INDEX_FILE, cut }.to_string(),
            "feed-index.log: trust ends at position 32 (byte 120 of 131); the 11 bytes after it \
             are cut; the cut part is re-derived"
        );
        let refused = with_file(MASKED_FILE)(io::Error::new(io::ErrorKind::StorageFull, "no room"));
        assert_eq!(refused.kind(), io::ErrorKind::StorageFull, "the kind is kept");
        assert_eq!(refused.to_string(), "feed-masked.log: no room");
    }

    /// The open's own lines at fixed figures: the bare positions it
    /// classifies before the board serves — ahead of the cost, while it runs
    /// and once done — the journal's refusal of that classification in the
    /// kernel's words, what its compaction dropped below the reclaim floor,
    /// and, last, how far back `/changes` answers, the region the walk has
    /// yet to land where one is pending, and how long the open took.
    #[test]
    fn the_opens_classification_and_compaction_lines_render_the_ruled_words() {
        assert_eq!(
            BareClassificationLine { coverage: 12, positions: 3 }.to_string(),
            "feed-index.log covers to position 12: 3 bare positions are classified from the \
             journal before the board serves, two world reconstructions each"
        );
        assert_eq!(
            BareClassifyingLine { position: 2_040, done: 1_000, of: 3_000, elapsed_ms: 9_800 }
                .to_string(),
            "feed-index.log: the bare classification at position 2040, 1000 of 3000, 9800 ms in"
        );
        assert_eq!(
            BareClassifiedLine { classified: 2_999, of: 3_000, elapsed_ms: 29_400 }.to_string(),
            "feed-index.log: 2999 of 3000 bare positions classified from the journal in 29400 ms"
        );
        let reach = |pending| FeedOpenLine {
            floor: Some(2_049),
            head: 3_100,
            entries: 1_052,
            bare: 6,
            pending,
            elapsed_ms: 41,
        };
        assert_eq!(
            reach(None).to_string(),
            "the change feed answers from position 2049 to position 3100: commits.log 1052 \
             entries, 6 of them bare, in 41 ms"
        );
        assert_eq!(
            reach(Some((3_000, 3_100))).to_string(),
            "the change feed answers from position 2049 to position 3100: commits.log 1052 \
             entries, 6 of them bare; positions (3000, 3100] wait on the walk, in 41 ms"
        );
        let empty = FeedOpenLine {
            floor: None,
            head: 0,
            entries: 0,
            bare: 0,
            pending: None,
            elapsed_ms: 2,
        };
        assert_eq!(
            empty.to_string(),
            "the change feed answers no position yet, the head at position 0, in 2 ms"
        );
        let refused = ClassificationRefusedLine {
            positions: 3,
            first: 13,
            account: "journal corrupt at rest".into(),
        };
        assert_eq!(
            refused.to_string(),
            "feed-index.log: the journal refused to classify 3 bare positions, the first at \
             position 13 (journal corrupt at rest): each is served to every class, its position \
             alone"
        );
        assert_eq!(
            OpenCompactionLine { floor: 2049, dropped: 7 }.to_string(),
            "the change feed's files compacted below the reclaim floor at position 2049: 7 \
             entries dropped"
        );
    }
}
