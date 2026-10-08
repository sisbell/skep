//! # skep-search — the search index a client embeds
//!
//! R9b's board-wide lexical search — "query → ranked span hits → jump to the
//! position with structure live — implemented client-side over the /changes
//! feed" — is THE READER's OWN INDEX, built from the reader's own reads of
//! the feed; the substrate stays search-free (the design's `search.md`, its
//! head and §0; ux-FC2 (1), sx-D1). This crate is that index's library
//! (§1.1, RULED `skep-search`; §1.2): TEXT AND ADDRESSES IN, HITS OUT. It
//! parses no wire JSON, dials nothing, holds no token, knows no principal
//! but as the class the embedder passes it, and reads and writes no file of
//! its own. The FRONTEND's shell embeds it beside `skep-client` (§1.2); the
//! shell's half — the feed consumer, the directory, the triggers, the bridge
//! call, the state event — is `client.md` §4e's and no part of this crate.
//!
//! The design's modules stand here (§1.2's table), the file's in three files
//! and the engine's one type in `index` with the pair beside it:
//!
//! * [`mod@unit`] — the document model (§2.1, §2.4): [`Unit`], one document
//!   version's arranged content, delivered in parts and JOINED; [`UnitKey`],
//!   the bare document address alone; the typed delivery [`Item`]s the crate
//!   takes — text, a `hex` run's bytes, a `Gap` for every item that is not
//!   text — and the item table; [`Class`]; and §2.4's head rule,
//!   [`moved_head`].
//! * [`token`] — the tokenizer (§2.3): UAX #29 word boundaries, the fold
//!   (NFD, the marks sr-E1 scopes as ITEM 3 amended it, the apostrophe
//!   variants, the invisible format controls), lowercasing; each
//!   occurrence's byte range from the unit's start; the tokenizer
//!   [`REVISION`] the index records; the rule over one stretch,
//!   [`segments`], which the query shares.
//! * [`index`] — the inverted index with positions behind the ONE CONCRETE
//!   TYPE [`Index`] (§1.4; §5.1's in-memory shape): the sorted dictionary,
//!   the postings with ordinals and ranges, the unit records with their term
//!   lists, the tombstones, the live counts, the index's own class and
//!   revision; the write side — `new`, `prepare`, `merge`, `index`,
//!   `compacted`, `install` — and `stats`; the class check (§2.1) and THE
//!   CEILING (§7.4), both made at `merge`; and THE ONE READ over the unit
//!   keys, [`Index::keys_by_range`] under a [`Prefix`] (§1.4; RULED (b)).
//! * [`query`] — [`Query::parse`], THE ONE GRAMMAR (§3.2): a word, the
//!   trailing prefix, a quoted phrase, an unclosed quote's phrase-prefix, a
//!   split chunk's implicit phrase, the conjunction; and the evaluator — the
//!   term lookup, the prefix expansion over the sorted dictionary, the phrase
//!   by adjacent ordinals, the phrase-prefix over the terms that follow the
//!   fixed words, the fuzzy word within one edit, the conjunctive window —
//!   under its three INTERIM pins, [`EXPANSION_BOUND_ENTRIES`],
//!   [`POSITIONS_BOUND`] and [`FUZZY_WORDS`], EACH A FLAG on the answer.
//! * [`rank`] — BM25 (§3.3) with k₁ = 1.2 and b = 0.75, the idf pinned in
//!   its one form, one score per query form, the pair's merged
//!   [`Statistics`], and the one tie order.
//! * [`hit`] — [`Hit`] and [`Answer`], THE CONTRACT the UX designs to
//!   (§3.1, §3.5): the byte-exact [`Span`], the [`Standing`], the
//!   [`Snippet`] cut from the stored text with its start and marks (§6).
//! * [`pair`] — [`Pair`], the two indexes passed BY ROLE with the standing's
//!   inputs beside them, [`QueryOpts`], and [`Index::query`], the one call
//!   (§1.4, §5.2).
//! * The file (§5.1, §5.3, §5.4), in three: [`header`] — the typed
//!   [`Header`] the embedder composes (`board`, `floor`, the per-range
//!   records, the newest head's `H.k`), [`Chain`] and [`ChainAt`], and the
//!   header line's one canonical writer and parser, `v` first;
//!   [`mod@file`] — the body's layout, the CRC-32C trailer, [`Index::save`] and
//!   [`Index::load`] with every disposition as [`LoadError`], the migration
//!   from the stored text tagged by [`Index::migrated_from`], and the
//!   aside's spelling, [`aside_name`]; [`resume`] — the resume read's
//!   answers judged as a pure function, [`Resume::judge`] over a
//!   [`ChainAnswer`] the shell fills.
//!
//! This surface is §1.4 whole; §7's timing tests are measured and reported
//! (lane SR-4); and the shell's embedding — the feed consumer, the
//! directory, the file modes, the lock, the moving aside, the `/health` and
//! `/chain?at` reads, the state event, the bridge call that composes the
//! pair and forwards the flags (`client.md` §4e) — is landed as
//! `skep-client`'s `search` module behind its default-off `search` feature
//! (lane SH), which takes this crate as an optional dependency. The crate's
//! `README.md` says what remains outside both crates, and `ARCHITECTURE.md`
//! §The search index the rules below.
//!
//! ## Rules that hold across its files
//!
//! * **One class per index** (§5.2 D7; §4's invariants (i) and (ii)): an
//!   [`Index`] carries exactly one [`Class`] from [`Index::new`] and no call
//!   changes it; `merge` refuses a unit read at any other class, both
//!   classes named. The separation of a published index from a supplement,
//!   and of one principal's supplement from another's, is STRUCTURAL — two
//!   values, never a filter column — and a query names its members BY ROLE.
//! * **Cut once at `merge`** (§1.4, §7.4): the class check and the ceiling
//!   are made where a unit enters, and nowhere else. Past the ceiling the
//!   unit is not indexed, the unit it would have replaced is KEPT, the
//!   refusal names the bytes held and the limit, and the offer is counted in
//!   `seen`.
//! * **Prepare under no lock, install by one swap** (§5.6): [`Index::prepare`]
//!   takes no index — the tokenizing and the postings' build run outside
//!   whatever lock the embedder keeps around the engine — and
//!   [`Index::install`] replaces the compacted body by one assignment. The
//!   crate holds no lock of its own: the read-write lock is the embedder's,
//!   and every type here is `Send + Sync` so it can stand under one.
//! * **Every bound is a flag** (§3.2; PATTERNS P29 as sr-P1 amended it): the
//!   expansion's bound in postings entries, the keystroke's positions bound
//!   and the fuzzy words bound are INTERIM pins, constants whose docs quote
//!   §7.1; each stops the work where it is met and says so on the
//!   [`Answer`] — `more_terms`, `positions_bounded`, `fuzzy_bounded` — and
//!   never cuts silently; `total` is then a lower bound.
//! * **One score, one order** (§3.3): BM25's idf in its pinned form, one
//!   score per query form over the pair's MERGED statistics — each member's
//!   units counted once — a higher score the better match, and ties by
//!   document address, member, span start: the same pair and query give the
//!   same hits in the same order on every run.
//! * **Nothing of the network, the keys or the board** (§1.3): the
//!   dependencies are `skep-address` and the two Unicode crates, and nothing
//!   else — NOT `skepd`, NOT `skep-client`, NOT `serde_json`: the file's one
//!   JSON line is written and read by the crate's own bounded code. Plain
//!   Rust with `std` and no platform call, no feature, no target-specific
//!   code.
//! * **One file, one spelling, read whole** (§5.1; PATTERNS P35, P38): an
//!   index is one versioned file, loaded whole; its header line has the one
//!   spelling `save` writes and `parse` admits no other, `v` read first; its
//!   trailer covers the header line and the body, so nothing damaged is
//!   loaded as written. The file is DERIVED STATE: every refusal is a
//!   disposition — faced, moved aside, migrated, rebuilt — and never a halt.
//! * **The crate moves no file and reads no board** (§1.2, §5.4): `save`
//!   and `load` take the `Write` and `Read` the embedder hands them; the
//!   rename, the aside and the resume's reads are the shell's, the crate
//!   spelling the aside's name and judging the resume over values alone; a
//!   hit's standing is composed from the ranges the pair carries, no read
//!   made (§3.1), and the one read over the unit keys reads the keys alone.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod file;
pub mod header;
pub mod hit;
pub mod index;
pub mod pair;
pub mod query;
pub mod rank;
pub mod resume;
pub mod token;
pub mod unit;

pub use file::{aside_name, crc32c, LoadError};
pub use header::{
    Chain, ChainAt, Grant, GrantKind, HeadRecord, Header, HeaderError, Parsed, RangeRecord, Refusal,
};
pub use hit::{Answer, Hit, Mark, MarkKind, Matched, Rung, Snippet, Span, Standing, SNIPPET_BOUND};
pub use index::{Compacted, Index, IndexError, Occurrence, Prefix, Prepared, Stats, CEILING_BYTES};
pub use pair::{Pair, QueryOpts, DEFAULT_LIMIT};
pub use query::{
    Form, Query, Word, EXPANSION_BOUND_ENTRIES, FUZZY_MIN_CHARS, FUZZY_WORDS, POSITIONS_BOUND,
    PREFIX_MIN_CHARS,
};
pub use rank::Statistics;
pub use resume::{ChainAnswer, Resume};
pub use token::{fold, segments, tokenize, Revision, Segment, Token, REVISION};
pub use unit::{moved_head, Class, GapKind, Item, Kind, Unit, UnitError, UnitKey};

/// The auto traits the embedder's lock needs (`search.md` §5.6): the engine
/// stands under the shell's read-write lock, read by the bridge's search
/// thread and written by the feed thread, so every value that crosses that
/// lock owes `Send + Sync`, and owes it by what its private fields contain.
/// Asserted in the library rather than the suite, because that is the build
/// a dependency change is made in — skep-address's own precedent.
const _: fn() = || {
    fn owed<T: Send + Sync + 'static>() {}
    owed::<Index>();
    owed::<Prepared>();
    owed::<Compacted>();
    owed::<Stats>();
    owed::<Unit>();
    owed::<UnitKey>();
    owed::<Item>();
    owed::<Class>();
    owed::<Token>();
    owed::<Segment>();
    owed::<Revision>();
    owed::<Header>();
    owed::<Chain>();
    owed::<ChainAt>();
    owed::<Resume>();
    owed::<ChainAnswer>();
    // The query and the answer cross the same lock: the pair is composed
    // under the read side, the hits leave it.
    owed::<Query>();
    owed::<Form>();
    owed::<Word>();
    owed::<Pair<'static>>();
    owed::<QueryOpts>();
    owed::<Prefix>();
    owed::<Statistics>();
    owed::<Answer>();
    owed::<Hit>();
    owed::<Span>();
    owed::<Standing>();
    owed::<Rung>();
    owed::<Snippet>();
    owed::<Mark>();
    owed::<MarkKind>();
    owed::<Matched>();
    // Every refusal too: a caller that boxes one meets
    // `Box<dyn Error + Send + Sync>`, which is the crossing form.
    owed::<IndexError>();
    owed::<UnitError>();
    owed::<HeaderError>();
    owed::<LoadError>();
};
