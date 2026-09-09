//! The change feed's PUBLICATION HALF (PUB round 2, lane 3.6): `commits.log`
//! composed with its four derived sidecars, the per-class mask, the
//! supplement merge, the universal term, and the two narrowings. The wire
//! surface is `GET /changes` (wire.md §The change feed); what this module
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
//! and held resident as its twin:
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
//! # The supplement (PUB-7.22–7.28)
//!
//! A principal's page is the K-way merge, deduplicated by position, of: the
//! published walk; its OWN account's and its ANCESTOR accounts' streams (the
//! subtree clause reads upward); its grant-selected ISSUER streams, each
//! under a per-entry containment test against the union of that issuer's
//! covered prefixes for this principal (an account-depth grant is the
//! stream whole); and the UNIVERSAL term, derived at serve — the position
//! index's lists under each live any-principal prefix, enumerated once per
//! request off the same head snapshot as the rest of the class. The CLASS
//! is `server.rs`'s to resolve, off ONE head snapshot per request
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

pub(crate) mod classify;
mod derived;

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::io::{self, Write};
use std::path::Path;

use parking_lot::Mutex;
use serde_json::Value;
use skep_address::{is_prefix, parent, Address, Tumbler};
use skep_engine::{Engine, World};
use skep_kernel::Seq;
use skep_namespace::{HasM3, PrincipalId};

use self::classify::{classify, derived_docs, parse_dotted, Doc};
use self::derived::{
    DerivedFile, INDEX_DOCS, INDEX_FILE, MASKED_FILE, OFFSETS_FILE, OFFSETS_OFFSET, STREAMS_FILE,
    STREAMS_OWNERS,
};
use crate::sidecar::{report_malformed_names, CommitMeta, CommitsLog, LineOffset};
use crate::write_path::SerialGuard;

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
/// candidate on every page, under the lock [`crate::write_path::WritePath`]
/// takes to record a commit. The number is M3's `MAX_PRINCIPAL_COMPONENTS`,
/// which is that depth bound.
const MAX_FILTERED_PREFIXES: usize = 64;

/// The requester's FEED CLASS, resolved by the route off ONE head snapshot
/// (PUB-6.40) and threaded down: the read predicate at the requester's
/// class, the stream keys its class opens, and the universal term's live
/// set. The feed evaluates it and resolves nothing of its own.
pub(crate) struct FeedClass<'a> {
    /// The HEAD world every field below stands on: the one snapshot the
    /// route pinned for this request.
    world: &'a World,
    /// The requester this class is of — `None` is the guest.
    ///
    /// It and `world` are the whole input: [`FeedClass::of`] derives the
    /// three stream-key lists below from the pair and [`FeedClass::readable`]
    /// answers the mask off the same pair, so a class whose mask and whose
    /// stream keys belong to different principals is not constructible —
    /// the keys would open a principal's drafts while the mask refused all
    /// of them, which fails into an emptier page with nothing to report it.
    principal: Option<PrincipalId>,
    /// The requester's own account and its ancestor accounts (the subtree
    /// clause, PUB-7.24) — each a draft-stream key. Empty for the guest and
    /// for a node-tier principal.
    subtree: Vec<Address>,
    /// The grant-selected issuers (`World::issuers_for`, PUB-7.25), each
    /// `(issuer account, the union of the content prefixes it granted this
    /// principal)` — the issuer being the draft-stream key this clause
    /// opens.
    issuers: Vec<(Address, Vec<Address>)>,
    /// The live ANY-PRINCIPAL prefixes (`World::universal_grants`, PUB-7.22)
    /// — a key range over the position index, never a stream key. Empty for
    /// the guest (grants reach principals alone, PUB-5.109).
    ///
    /// The PREFIX alone, where the engine's pair carries the issuing
    /// accounts beside it: this term needs no issuer, because the mask's own
    /// grant clause admits exactly the entries the issuing owner covers, so
    /// [`Inner::visible`] decides every candidate the prefix's index lists
    /// put forward. Dropping the half nothing reads also parts this field's
    /// type from [`FeedClass::issuers`]', which is the same pair TRANSPOSED
    /// — issuer first, prefixes second — so a loop reading one as the other
    /// stops compiling instead of looking a content prefix up in a map keyed
    /// by owner account and silently serving no universal term at all.
    universal_prefixes: Vec<Address>,
}

impl<'a> FeedClass<'a> {
    /// The whole class one `(world, principal)` pair opens, resolved off ONE
    /// head snapshot (PUB-6.40): the route pins the snapshot and hands the
    /// world in, and every field's own rule is stated on the field above —
    /// which is why the resolution lives here rather than at the route,
    /// where it would restate them.
    pub fn of(world: &'a World, principal: Option<PrincipalId>) -> FeedClass<'a> {
        let account = principal.and_then(|p| world.m3().principal_prefix(p).cloned());
        let mut subtree = Vec::new();
        let mut cur = account.clone();
        while let Some(a) = cur {
            if world.m3().is_registered_account(&a) {
                subtree.push(a.clone());
            }
            cur = parent(&a);
        }
        let issuers = account.as_ref().map(|pa| world.issuers_for(pa)).unwrap_or_default();
        // The issuing accounts the engine hands back beside each prefix are
        // dropped at this seam, for the reason the field states.
        let universal_prefixes = match principal {
            Some(_) => world.universal_grants().into_iter().map(|(prefix, _)| prefix).collect(),
            None => Vec::new(),
        };
        FeedClass { world, principal, subtree, issuers, universal_prefixes }
    }

    /// `readable(principal, ·)` at the head — THE mask (PUB-7.20), which
    /// [`Inner::visible`] applies per entry and [`Inner::sources`] applies
    /// per document in the merge arm's skip.
    ///
    /// A method over the stored `(world, principal)` rather than a closure
    /// the route hands in: the answer is a pure function of that pair, so
    /// it costs no box and no indirect call per candidate, and there is no
    /// separately supplied mask to disagree with the keys.
    fn readable(&self, doc: &Address) -> bool {
        self.world.readable(self.principal, doc)
    }
}

/// One `/changes` question.
#[derive(Clone, Debug)]
pub(crate) struct Query {
    /// The fence: positions strictly above it.
    pub since: u64,
    /// The page cap, over the VISIBLE stream.
    pub limit: usize,
    /// `under=`: only entries whose reduced docs name a document under this
    /// tumbler (PUB-7.31).
    pub under: Option<Tumbler>,
    /// `drafts=true`: only entries whose reduced docs name a draft
    /// (PUB-7.35).
    pub drafts_only: bool,
}

/// The answer `GET /changes` marshals.
#[derive(Debug)]
pub(crate) enum ChangesAnswer {
    /// `since` reaches below what the feed can enumerate; `floor` is the
    /// wire's sense of the word (wire.md §Reading history: the oldest
    /// position still answerable), which is NOT `CommitsLog::min_since` —
    /// the distinction, and the step between the two numbers, are
    /// [`CommitsLog::floor`]'s, which is what this field is filled from.
    /// Class-invariant, like every position (PUB-6.52's residue).
    Reclaimed { floor: Option<u64> },
    /// The visible entries in `(since, head]`, oldest first, rendered,
    /// capped at `limit`; `last` is the final entry's position (or `since`
    /// echoed when the page is empty) and `more` says whether a visible
    /// entry remains past it (PUB-6.44).
    Page { entries: Vec<Value>, last: u64, more: bool },
}

/// The feed: `commits.log` and the four derived twins, under one lock.
pub(crate) struct Feed {
    inner: Mutex<Inner>,
}

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
    /// ([`crate::write_path::WritePath::commit_under`] runs the execute and
    /// the record as one operation under it), so each push is strictly above
    /// every prior one.
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
    files: Files,
}

struct Files {
    index: DerivedFile,
    offsets: DerivedFile,
    masked: DerivedFile,
    streams: DerivedFile,
}

impl Feed {
    /// Open the feed over `dir`: replay `commits.log` (reconstructing and
    /// classifying its uncovered tail from the journal), replay the four
    /// derived sidecars, re-derive each one's missing tail — a recorded
    /// position's contribution from its own record, a bare position's from
    /// the journal — and fence each at the head. Runs AFTER M2's
    /// load-and-replay and BEFORE the first page (PUB-6.40): every
    /// classification here reads the recovered head's exception set, and
    /// the grant fold it stands beside is seeded by the same load.
    ///
    /// COST: the `commits.log` replay and walk (`CommitsLog::open` states
    /// them), plus O(each derived file) to replay it and O(its missing
    /// tail) to close it — a whole-file loss is one O(journal) rebuild, a
    /// bare position outside the index's coverage one targeted pair of
    /// world reconstructions. Never a rewrite per restart: a file is
    /// rewritten only when the log compacted under it, when it carries
    /// another journal's lines, or (the offset array) when its offsets no
    /// longer match the log's.
    pub fn open(dir: &Path, engine: &Engine) -> io::Result<Feed> {
        let (log, walked) = CommitsLog::open(dir, engine)?;
        let head = log.open_head;
        let snap = engine.kernel().snapshot();
        let world = snap.world();

        let (mut f_index, index_entries) = DerivedFile::open(dir, INDEX_FILE, head)?;
        let (mut f_offsets, offset_entries) = DerivedFile::open(dir, OFFSETS_FILE, head)?;
        let (mut f_masked, masked_entries) = DerivedFile::open(dir, MASKED_FILE, head)?;
        let (mut f_streams, stream_entries) = DerivedFile::open(dir, STREAMS_FILE, head)?;

        // ── the classification map: the index file's entries for positions
        //    the log holds, then this open's walk, then the index's tail ──
        let mut docs: BTreeMap<u64, Vec<Doc>> = BTreeMap::new();
        for (at, m) in &index_entries {
            let Some(meta) = log.entries.get(at) else { continue };
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
                report_malformed_names(INDEX_FILE, *at, named.len() - addrs.len());
                match meta {
                    CommitMeta::Recorded { docs: authority, .. } => {
                        authority.iter().filter_map(|s| parse_dotted(s)).collect()
                    }
                    CommitMeta::Bare => Vec::new(),
                }
            };
            if !addrs.is_empty() {
                docs.insert(*at, classify(world, addrs));
            }
        }
        let walked_at: BTreeSet<u64> = walked.iter().map(|w| w.at).collect();
        for w in &walked {
            if let Some(addrs) = &w.docs {
                if !addrs.is_empty() && !docs.contains_key(&w.at) {
                    docs.insert(w.at, classify(world, addrs.clone()));
                }
            }
        }
        let index_coverage = f_index.coverage();
        let index_tail: Vec<u64> =
            log.entries.range(index_coverage.saturating_add(1)..).map(|(k, _)| *k).collect();
        for &at in &index_tail {
            if let std::collections::btree_map::Entry::Vacant(vacant) = docs.entry(at) {
                let addrs: Vec<Address> = match log.entries.get(&at) {
                    // Every name reads: `CommitsLog` demoted the recorded
                    // positions whose did not, so this parse drops nothing.
                    Some(CommitMeta::Recorded { docs: strings, .. }) => {
                        strings.iter().filter_map(|s| parse_dotted(s)).collect()
                    }
                    // Walked this open: classified above, or empty/unclassifiable.
                    Some(CommitMeta::Bare) if walked_at.contains(&at) => Vec::new(),
                    // A bare position the index lost: the journal answers.
                    Some(CommitMeta::Bare) => classify_bare(engine, &log, at).unwrap_or_default(),
                    None => Vec::new(),
                };
                if !addrs.is_empty() {
                    vacant.insert(classify(world, addrs));
                }
            }
            if let Some(ds) = docs.get(&at) {
                f_index.append(at, vec![(INDEX_DOCS, doc_strings(ds))])?;
            }
        }
        f_index.fence(head)?;

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
            .filter(|at| log.entries.contains_key(at))
            .collect();
        let masked_coverage = f_masked.coverage();
        let masked_tail: Vec<u64> =
            log.entries.range(masked_coverage.saturating_add(1)..).map(|(k, _)| *k).collect();
        for at in masked_tail {
            if masked_at_commit(docs.get(&at).map(Vec::as_slice).unwrap_or(&[])) {
                masked.insert(at);
                f_masked.append(at, vec![])?;
            }
        }
        f_masked.fence(head)?;
        let published: BTreeSet<u64> =
            log.entries.keys().copied().filter(|at| !masked.contains(at)).collect();

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
            if !log.entries.contains_key(at) {
                continue;
            }
            for owner in elements_of(m.get(STREAMS_OWNERS))
                .iter()
                .filter_map(Value::as_str)
                .filter_map(parse_dotted)
            {
                let s = streams.entry(owner).or_default();
                if s.last() != Some(at) {
                    s.push(*at);
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
        let streams_coverage = f_streams.coverage();
        let streams_tail: Vec<u64> =
            log.entries.range(streams_coverage.saturating_add(1)..).map(|(k, _)| *k).collect();
        for at in streams_tail {
            let owners = owners_of(docs.get(&at).map(Vec::as_slice).unwrap_or(&[]));
            if !owners.is_empty() {
                for owner in &owners {
                    streams.entry(owner.clone()).or_default().push(at);
                }
                f_streams.append(at, vec![(STREAMS_OWNERS, addr_strings(owners.iter()))])?;
            }
        }
        f_streams.fence(head)?;

        // ── the offset array, checked against the log's own replay ──
        //
        // `!log.rewritten` is this file's half of COMPACTION as well as its
        // agreement test: a compacted log moved every offset, so the branch
        // below rewrites — which is why `feed-offsets.log` is absent from
        // the compaction block that follows.
        let offsets_agree = !log.rewritten
            && offset_entries.iter().all(|(at, m)| {
                m.get(OFFSETS_OFFSET).and_then(Value::as_u64)
                    == log.offsets.get(at).map(|o| o.0)
            });
        if offsets_agree {
            let offsets_coverage = f_offsets.coverage();
            let offsets_tail: Vec<(u64, LineOffset)> = log
                .offsets
                .range(offsets_coverage.saturating_add(1)..)
                .map(|(k, v)| (*k, *v))
                .collect();
            for (at, offset) in offsets_tail {
                f_offsets.append(at, vec![(OFFSETS_OFFSET, Value::Number(offset.0.into()))])?;
            }
            f_offsets.fence(head)?;
        } else {
            f_offsets.rewrite(
                log.offsets
                    .iter()
                    .map(|(at, o)| {
                        derived::record_object(
                            *at,
                            vec![(OFFSETS_OFFSET, Value::Number(o.0.into()))],
                        )
                    })
                    .collect(),
                head,
            )?;
        }

        // ── compaction: the log dropped what the journal reclaimed, so the
        //    derived files drop it too, rewritten from the twins. THREE of
        //    the four — `feed-offsets.log` took its rewrite above, on the
        //    same `log.rewritten`. A fifth derived file belongs HERE. ──
        if log.rewritten {
            f_index.rewrite(
                docs.iter()
                    .map(|(at, ds)| derived::record_object(*at, vec![(INDEX_DOCS, doc_strings(ds))]))
                    .collect(),
                head,
            )?;
            f_masked.rewrite(
                masked.iter().map(|at| derived::record_object(*at, Vec::new())).collect(),
                head,
            )?;
            f_streams.rewrite(
                docs.iter()
                    .filter_map(|(at, ds)| {
                        let owners = owners_of(ds);
                        (!owners.is_empty()).then(|| {
                            derived::record_object(
                                *at,
                                vec![(STREAMS_OWNERS, addr_strings(owners.iter()))],
                            )
                        })
                    })
                    .collect(),
                head,
            )?;
        }

        Ok(Feed {
            inner: Mutex::new(Inner {
                log,
                docs,
                index,
                masked,
                published,
                streams,
                files: Files {
                    index: f_index,
                    offsets: f_offsets,
                    masked: f_masked,
                    streams: f_streams,
                },
            }),
        })
    }

    /// Record one committed write at ack time — under the write-serialization
    /// guard, between a commit and its ack, which is [`CommitsLog::record`]'s
    /// contract and this method's; the guard argument is that contract's
    /// cheap half — and classify it against `world` — the POST-COMMIT head, so
    /// the minted document's registration and bit are in it — into the four
    /// derived structures: the offset array, the index (docs non-empty), the
    /// bitmap or the published stream, and each named draft's owner stream.
    /// Declined exactly when the log declines (an old commit's re-ack).
    ///
    /// The derived appends are testimony too: a failed one is reported and
    /// the resident twin stays right, so this uptime answers correctly and
    /// the next open's tail check re-derives what the file missed.
    ///
    /// `docs` arrives as ADDRESSES and is rendered once, here, for the
    /// authority file alone: the classification reads them as addresses, so
    /// text handed down from the write path would be parsed straight back —
    /// and a parse that could not read a name would have nowhere to report
    /// it, leaving the position classified short and, where every name
    /// dropped, served to every class as a `[]`-docs entry.
    pub fn record(
        &self,
        serial: &SerialGuard<'_>,
        at: u64,
        op: &'static str,
        docs: Vec<Address>,
        key: String,
        world: &World,
    ) {
        let mut inner = self.inner.lock();
        let rendered: Vec<String> = docs.iter().map(|a| a.tumbler().to_string()).collect();
        let Some(offset) = inner.log.record(serial, at, op, rendered, key) else {
            return;
        };
        inner.fold_position(at, offset, classify(world, docs));
    }

    /// The data behind `GET /changes` at `class`.
    pub fn page(&self, class: &FeedClass<'_>, query: &Query) -> ChangesAnswer {
        let inner = self.inner.lock();
        if query.since < inner.log.min_since {
            return ChangesAnswer::Reclaimed { floor: inner.log.floor() };
        }
        let Some(start) = query.since.checked_add(1) else {
            return ChangesAnswer::Page { entries: Vec::new(), last: query.since, more: false };
        };
        let merge = Merge::new(inner.sources(class, query, start));
        let mut entries = Vec::new();
        let mut last = query.since;
        let mut more = false;
        for at in merge {
            let Some((meta, reduced)) = inner.visible(class, query, at) else { continue };
            if entries.len() == query.limit {
                more = true;
                break;
            }
            entries.push(meta.entry(at, reduced.iter().map(|d| d.addr.to_string()).collect()));
            last = at;
        }
        ChangesAnswer::Page { entries, last, more }
    }

    /// The HEAD position's recorded wall-clock time — `CommitsLog::head_time`.
    pub fn head_time(&self) -> Option<u64> {
        self.inner.lock().log.head_time()
    }
}

impl Inner {
    /// Fold one classified position into the four twins and append its
    /// lines — the ONE path at RECORD time, so a live commit cannot leave a
    /// twin and its file disagreeing about what a position contributed.
    ///
    /// It is NOT the only path that contribution takes, and a fifth derived
    /// structure owes all three: this fold; [`Feed::open`]'s
    /// replay-then-derive, where the file is the authority for a position at
    /// or below its coverage and the classification for one above it; and the
    /// compaction rewrite that renders the twin back to lines. A structure
    /// wired here alone is empty from every open until the next commit, with
    /// its file's fence reporting it covered — which is a short candidate set
    /// claiming completeness, not the silent incompleteness the coverage
    /// check closes.
    fn fold_position(&mut self, at: u64, offset: LineOffset, docs: Vec<Doc>) {
        report_append_failure(
            self.files
                .offsets
                .append(at, vec![(OFFSETS_OFFSET, Value::Number(offset.0.into()))]),
            OFFSETS_FILE,
            at,
        );
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
            report_append_failure(
                self.files.index.append(at, vec![(INDEX_DOCS, doc_strings(&docs))]),
                INDEX_FILE,
                at,
            );
        }
        if masked_at_commit(&docs) {
            self.masked.insert(at);
            report_append_failure(self.files.masked.append(at, vec![]), MASKED_FILE, at);
        } else {
            self.published.insert(at);
        }
        let owners = owners_of(&docs);
        if !owners.is_empty() {
            for owner in &owners {
                self.streams.entry(owner.clone()).or_default().push(at);
            }
            report_append_failure(
                self.files.streams.append(at, vec![(STREAMS_OWNERS, addr_strings(owners.iter()))]),
                STREAMS_FILE,
                at,
            );
        }
        if !docs.is_empty() {
            self.docs.insert(at, docs);
        }
    }

    /// THE MASK, per entry (PUB-7.20; PUB-6.44–6.45), plus the narrowings'
    /// per-entry predicates: the entry's meta and its docs REDUCED to the
    /// requester's readable ones, or `None` when the entry is omitted.
    fn visible(
        &self,
        class: &FeedClass<'_>,
        query: &Query,
        at: u64,
    ) -> Option<(&CommitMeta, Vec<&Doc>)> {
        let meta = self.log.entries.get(&at)?;
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
        Some((meta, reduced))
    }

    /// The candidate sources for `class` and `query`, each an ascending iterator
    /// of positions at or above `start` — what the merge unions. Exact by
    /// the mask, and complete by construction in each of the two branches
    /// this function has, which are complete for different reasons.
    ///
    /// The WALK branch's five source kinds cover every visible position: a
    /// `[]`-docs or published-touching entry is in the published walk; a
    /// draft entry is in its owner's stream, which the subtree clause, the
    /// grant clause or the universal term selects.
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
        query: &'s Query,
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
        for account in &class.subtree {
            if let Some(stream) = self.streams.get(account) {
                sources.push(Box::new(at_or_above(stream, start)));
            }
        }
        for (issuer, prefixes) in &class.issuers {
            let Some(stream) = self.streams.get(issuer) else { continue };
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
    fn names_under(&self, at: u64, issuer: &Address, prefixes: &[Address]) -> bool {
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
        let mut positions = self.log.entries.range(start..);
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

fn addr_strings<'a>(addrs: impl Iterator<Item = &'a Address>) -> Value {
    Value::Array(addrs.map(|a| Value::String(a.to_string())).collect())
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

/// A bare position the index lost: the journal's classification, from the
/// world at the boundary below it (the previous entry, or genesis) and its
/// own — `None` where either cannot be answered (reclaimed), the module's
/// unclassifiable residue.
fn classify_bare(engine: &Engine, log: &CommitsLog, at: u64) -> Option<Vec<Address>> {
    let prev = log.entries.range(..at).next_back().map(|(k, _)| *k).unwrap_or(0);
    let below = engine.world_at(Seq(prev)).ok()?;
    let above = engine.world_at(Seq(at)).ok()?;
    Some(derived_docs(&below, &above))
}

/// A derived append that failed: reported, never a failed op — the resident
/// twin is right for this uptime, the file stops taking lines
/// ([`DerivedFile`]'s own `stopped` states why), and the next open's tail
/// derivation re-covers this position and every one after it. So ONE notice
/// per file per uptime: the appends behind a stopped file answer `Ok` and
/// write nothing, and a busy board's stderr carries the first failure alone.
/// `writeln!` rather than `eprintln!`, for `sidecar.rs`'s reason (a lost log
/// pipe must not panic a committed write's ack).
fn report_append_failure(r: io::Result<()>, file: &str, at: u64) {
    if let Err(e) = r {
        let _ = writeln!(std::io::stderr(), "skepd: {file} append failed at position {at}: {e}");
    }
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
}
