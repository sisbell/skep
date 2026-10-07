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
//! Three of the design's six modules stand here (§1.2's table):
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
//!   [`REVISION`] the index records.
//! * [`index`] — the inverted index with positions behind the ONE CONCRETE
//!   TYPE [`Index`] (§1.4; §5.1's in-memory shape): the sorted dictionary,
//!   the postings with ordinals and ranges, the unit records with their term
//!   lists, the tombstones, the live counts, the index's own class and
//!   revision; the write side — `new`, `prepare`, `merge`, `index`,
//!   `compacted`, `install` — and `stats`; the class check (§2.1) and THE
//!   CEILING (§7.4), both made at `merge`.
//!
//! What later lanes add, so this surface reads as §1.4 minus them: the
//! query and the answer — `Query::parse`, the evaluator, `rank`, `hit`,
//! `Pair`, `keys_by_range` (§3; lane SR-3); the file — `save`, `load`,
//! `Header`, `LoadError`, the aside and the resume dispositions (§5.1, §5.4;
//! lane SR-2); §7's timing tests, reported (lane SR-4); the shell's
//! embedding (`client.md` §4e; lane SH). The crate's `README.md` lists the
//! same, and `ARCHITECTURE.md` §The search index the rules below.
//!
//! ## Rules that hold across its files
//!
//! * **One class per index** (§5.2 D7; §4's invariants (i) and (ii)): an
//!   [`Index`] carries exactly one [`Class`] from [`Index::new`] and no call
//!   changes it; `merge` refuses a unit read at any other class, both
//!   classes named. The separation of a published index from a supplement,
//!   and of one principal's supplement from another's, is STRUCTURAL — two
//!   values, never a filter column.
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
//! * **Nothing of the network, the keys or the board** (§1.3): the
//!   dependencies are `skep-address` and the two Unicode crates, and nothing
//!   else — NOT `skepd`, NOT `skep-client`, NOT `serde_json`. Plain Rust
//!   with `std` and no platform call, no feature, no target-specific code.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod index;
pub mod token;
pub mod unit;

pub use index::{Compacted, Index, IndexError, Occurrence, Prepared, Stats, CEILING_BYTES};
pub use token::{fold, tokenize, Revision, Token, REVISION};
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
    owed::<Revision>();
    // Every refusal too: a caller that boxes one meets
    // `Box<dyn Error + Send + Sync>`, which is the crossing form.
    owed::<IndexError>();
    owed::<UnitError>();
};
