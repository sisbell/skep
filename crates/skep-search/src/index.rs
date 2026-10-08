//! The inverted index with positions (`search.md` §1.2's `index` row; §5.1's
//! in-memory shape) behind the ONE CONCRETE TYPE [`Index`] (§1.4): the term
//! dictionary, SORTED, so a prefix is a range found by binary search (the
//! expansion over it is `query`'s); the postings — per term, per unit, the
//! token ORDINALS and each occurrence's RANGE FROM THE UNIT's START, its
//! V-ordinal offset and its length in bytes ([`Occurrence`]); the UNIT
//! RECORDS — the unit itself, its stored text among its items (§6, D10 (i)),
//! and its TERM LIST, kept per unit so a tombstone decrements every count
//! from it; the TOMBSTONES; the LIVE COUNTS — units, distinct terms, posting
//! entries, bytes of text — and the dead ones beside them; and the index's
//! own CLASS and tokenizer REVISION, set at `new` and changed by no call.
//!
//! THE WRITE SIDE (§1.4, §5.6), two operations where one stood, so §5.6's
//! lock split is the design's and never the build's: [`Index::prepare`]
//! tokenizes a unit and builds its postings against NO index, under no lock;
//! [`Index::merge`] takes the write side for the merge alone — THE CLASS
//! CHECK (§2.1) and THE CEILING (§7.4) are made here and nowhere else, a
//! unit whose key is already held is REPLACED and the replaced unit
//! TOMBSTONED; [`Index::index`] is their composition for an embedder that
//! holds no lock. Between saves a tombstoned unit's postings stay resident
//! and are skipped at query, while the unit leaves EVERY statistic at once —
//! itself from the unit count, its bytes from the ceiling's count, its
//! distinct terms from each term's live count and so from the dictionary's
//! membership — so a term held only by dead units is no term (§5.1).
//! COMPACTION is two operations too: [`Index::compacted`] builds the new
//! postings from this value, under the embedder's read side — the
//! tombstoned units and their postings dropped — and [`Index::install`]
//! installs them by ONE SWAP under the write side; the feed thread, the one
//! writer, calls each pair in sequence, so no `merge` lands between a
//! `compacted` and its `install`. The trigger is counted in DEAD POSTINGS
//! ([`Index::compaction_due`]; §5.1, §7.1's INTERIM pin). `delete` is no
//! operation of v1 (§1.4). The file's `save` and `load` stand in `file`,
//! over this module's shape; the query over it stands in `query`, `rank` and
//! `hit`, behind `Index::query` (the `pair` module).
//!
//! THE ONE READ over the unit keys ([`Index::keys_by_range`]; §1.4; THE
//! ENUMERATOR RULED (b)): the keys held under a range — the documents under
//! its [`Prefix`] — at the cost of one scan of those keys, which sort in the
//! address order, so every document below a prefix is one contiguous run of
//! the key map. Its callers are the two REFRESHES (§5.4's bare-count refresh,
//! §5.5's `opts.reindex`) and no other; it reads nothing but the keys.
//!
//! THE CEILING ([`CEILING_BYTES`]; §7.4): v1 scale is counted in BYTES OF
//! TEXT PER INDEX, the index loaded whole; the crate declares a ceiling on
//! the live bytes it holds and SAYS SO rather than degrading silently —
//! `merge` past it indexes nothing and changes nothing, a refused
//! REPLACEMENT leaving the unit it would have replaced in place, and answers
//! a typed error naming the bytes held and the limit, with the units held
//! beside them; a tombstoned unit's bytes count toward it no longer; the
//! units offered past it are counted in `seen`, reported by [`Index::stats`]
//! and listed nowhere, so the embedder's `past the ceiling` state composes
//! after a restart as before it (`file` keeps `seen` in the body).

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io;
use std::ops::Bound;

use skep_address::{is_prefix, Address};

use crate::token::{self, Revision, REVISION};
use crate::unit::{Class, Unit, UnitKey};

/// THE CEILING on the bytes of text one index holds (`search.md` §7.4): "the
/// CEILING is then sized AT OR ABOVE the records' size where those numbers
/// hold — the build's to derive from that M1 and M5's resident multiple, not
/// a round number". INTERIM PIN, named so: the records tier's own size,
/// §7.3's cut re-measured to the byte — every file tracked at the design
/// repository's `b17656e9` that is not a generated `_context.*` bundle and
/// not an image or a video, 3,598 files, the design's "93.1 MB over 3,598
/// files" — the floor ITEM 2 RULED (d) fixes. Counted in LIVE bytes of text,
/// what a rebuild would hold, as `merge` adds them; the postings ride beside
/// at M1's multiple (≤ 1× the text in the file) and are not counted twice.
///
/// MEASURED at that tier by lane SR-4 (2026-10-07; `tests/it/budgets.rs`, a
/// release build, the tier fed through a dev board and read back): the
/// build 4.7 s, the postings 0.73× the text, the file 1.78× (157.5 MiB), the
/// load 0.79 s, the save 0.83 s — M1's two ratios HOLD, the three timings
/// reported, no pin standing at this tier. M5 does NOT hold: the index
/// loaded whole is 5.0× its file resident (790 MiB), and 6.9× at 10⁴ and
/// 7.5× at 10³ — the ratio is the in-memory shape's (a `Vec` per posting,
/// sixteen bytes an occurrence, the stored text beside) and not the tier's,
/// so no lower tier holds it either and §7.4's "moved down to where the
/// numbers hold" has no tier to land on. The figure therefore STANDS
/// UNCONFIRMED at the records tier's size, the owner's decision, with §7.1's
/// remedies ahead of any disk-backed index: the lazy stored text (the load
/// row at 10⁴ missed its 500 ms at 620 ms too), the save cadence scaled to
/// the file (18.5 GiB an hour at thirty-second saves of this file), and the
/// compaction trigger (M5's dead residue was 3.4 MiB, the two copies across
/// a compaction 189 MiB).
pub const CEILING_BYTES: u64 = 93_075_924;

/// The compaction trigger's fraction (§5.1; §7.1's INTERIM pin): compaction
/// is due where the DEAD POSTINGS exceed one eighth of the live, counted in
/// entries.
const COMPACTION_TRIGGER_DIVISOR: usize = 8;

/// A unit's id: its index among the unit records. Dense after a compaction,
/// with holes where tombstones stand before one.
pub(crate) type UnitId = usize;

/// A term's id: its index among the term entries; the dictionary maps the
/// term's spelling to it.
pub(crate) type TermId = usize;

/// One occurrence in a posting (§5.1): the token's ORDINAL in its unit's
/// sequence — adjacency is a phrase (§3.2) — and its RANGE FROM THE UNIT's
/// START, the V-ordinal offset and the length in bytes the hit's span is read
/// off, byte-exact, with no re-tokenizing at result time (§2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Occurrence {
    /// The token's ordinal in the unit.
    pub ordinal: u32,
    /// The first byte's V-ordinal offset from the unit's start.
    pub offset: u64,
    /// The unfolded segment's length in bytes.
    pub len: u32,
}

/// One unit's occurrences of one term, in ordinal order.
#[derive(Debug, Clone)]
pub(crate) struct Posting {
    pub(crate) unit: UnitId,
    pub(crate) occurrences: Vec<Occurrence>,
}

/// One term's postings, in unit-id order, and the LIVE count of units
/// holding it — df(t) over the live units, and the dictionary's membership:
/// a term whose live count is zero is no term until compaction drops it.
#[derive(Debug, Clone, Default)]
pub(crate) struct TermEntry {
    pub(crate) postings: Vec<Posting>,
    pub(crate) live_units: usize,
}

/// A unit record: the unit with its term list and its posting entries
/// counted, or the tombstone left where it stood — a bare marker, its
/// postings resident under the dead tally until compaction drops both.
#[derive(Debug, Clone)]
pub(crate) enum Record {
    Live { unit: Unit, terms: Vec<TermId>, entries: usize },
    Dead,
}

/// The counts `stats` reports, kept live: decremented at a tombstone from the
/// unit's own term list, never recomputed from the postings — except at
/// `load`, which recomputes them to check the file's.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Counts {
    pub(crate) units: usize,
    pub(crate) terms: usize,
    pub(crate) postings: usize,
    pub(crate) bytes: u64,
    pub(crate) tombstones: usize,
    pub(crate) dead_postings: usize,
}

/// Everything a compaction rewrites, so `install` replaces it by one
/// assignment (§5.6) — and everything the file's body holds of the index
/// (`file`), which reads and writes these fields.
#[derive(Debug, Clone, Default)]
pub(crate) struct Body {
    pub(crate) dictionary: BTreeMap<String, TermId>,
    pub(crate) terms: Vec<TermEntry>,
    pub(crate) units: Vec<Record>,
    pub(crate) keys: BTreeMap<UnitKey, UnitId>,
    pub(crate) counts: Counts,
}

impl Body {
    /// The live bytes of the unit at `id`; none for a tombstone.
    fn bytes_of(&self, id: UnitId) -> u64 {
        match &self.units[id] {
            Record::Live { unit, .. } => unit.bytes(),
            Record::Dead => 0,
        }
    }

    /// The live unit at `id` with its token count — its posting entries,
    /// one per token, BM25's `dl` (§3.3); `None` for a tombstone, whose
    /// postings are skipped at query (§5.1).
    pub(crate) fn live(&self, id: UnitId) -> Option<(&Unit, usize)> {
        match &self.units[id] {
            Record::Live { unit, entries, .. } => Some((unit, *entries)),
            Record::Dead => None,
        }
    }

    /// The term `term` where some live unit holds it (§5.1: "a term held
    /// only by dead units is no term for §3.2's exact-match test, D15's
    /// correction or the expansion's df order"): its id and its entry.
    pub(crate) fn live_term(&self, term: &str) -> Option<(&str, TermId)> {
        let (spelling, &id) = self.dictionary.get_key_value(term)?;
        (self.terms[id].live_units > 0).then_some((spelling.as_str(), id))
    }

    /// The live terms under `prefix` in the dictionary's order (§3.2's
    /// prefix: "expanded over the sorted term dictionary (a binary search
    /// for the range)") — the range entered at the prefix and left at the
    /// first term not starting with it.
    pub(crate) fn live_terms_under(&self, prefix: &str) -> Vec<(&str, TermId)> {
        self.dictionary
            .range::<str, _>((Bound::Included(prefix), Bound::Unbounded))
            .take_while(|(term, _)| term.starts_with(prefix))
            .filter(|(_, &id)| self.terms[id].live_units > 0)
            .map(|(term, &id)| (term.as_str(), id))
            .collect()
    }

    /// Every live term with its id, in the dictionary's order — the fuzzy
    /// word's linear candidate scan (§3.2: "The candidate scan is linear over
    /// the dictionary at v1's scale").
    pub(crate) fn live_terms(&self) -> impl Iterator<Item = (&str, TermId)> + '_ {
        self.dictionary
            .iter()
            .filter(|(_, &id)| self.terms[id].live_units > 0)
            .map(|(term, &id)| (term.as_str(), id))
    }

    /// A term's LIVE posting entries: its occurrences in live units, the
    /// quantity the two bounds of §3.2 are counted in.
    pub(crate) fn live_entries(&self, term: TermId) -> usize {
        self.terms[term]
            .postings
            .iter()
            .filter(|p| self.live(p.unit).is_some())
            .map(|p| p.occurrences.len())
            .sum()
    }

    /// The posting of `term` at `unit`, by binary search over the postings'
    /// unit-id order; `None` where the unit does not hold the term.
    pub(crate) fn posting(&self, term: TermId, unit: UnitId) -> Option<&Posting> {
        let postings = &self.terms[term].postings;
        postings.binary_search_by_key(&unit, |p| p.unit).ok().map(|at| &postings[at])
    }

    /// The tombstone (§5.1): the record becomes `Dead`, its postings stay
    /// where they are, and every live count moves at once from the unit's
    /// own term list.
    fn tombstone(&mut self, id: UnitId) {
        let (unit, terms, entries) = match &self.units[id] {
            Record::Live { unit, terms, entries } => (unit, terms, *entries),
            Record::Dead => return,
        };
        for &term in terms {
            let entry = &mut self.terms[term];
            entry.live_units -= 1;
            if entry.live_units == 0 {
                self.counts.terms -= 1;
            }
        }
        self.keys.remove(unit.key());
        self.counts.units -= 1;
        self.counts.bytes -= unit.bytes();
        self.counts.postings -= entries;
        self.counts.tombstones += 1;
        self.counts.dead_postings += entries;
        self.units[id] = Record::Dead;
    }

    /// The add: a fresh id, one posting per term appended in unit-id order,
    /// the dictionary and the live counts grown. The key must not be held:
    /// `merge` tombstones a held key first, and a migration (`file`) adds
    /// the live units of a file whose keys `load` checked distinct.
    pub(crate) fn add(&mut self, prepared: Prepared) {
        let id = self.units.len();
        let mut terms = Vec::with_capacity(prepared.postings.len());
        let mut entries = 0usize;
        for (term, occurrences) in prepared.postings {
            let term_id = *self.dictionary.entry(term).or_insert_with(|| {
                self.terms.push(TermEntry::default());
                self.terms.len() - 1
            });
            let entry = &mut self.terms[term_id];
            if entry.live_units == 0 {
                self.counts.terms += 1;
            }
            entry.live_units += 1;
            entries += occurrences.len();
            entry.postings.push(Posting { unit: id, occurrences });
            terms.push(term_id);
        }
        self.keys.insert(prepared.unit.key().clone(), id);
        self.counts.units += 1;
        self.counts.bytes += prepared.unit.bytes();
        self.counts.postings += entries;
        self.units.push(Record::Live { unit: prepared.unit, terms, entries });
    }

    /// The body rebuilt without the tombstoned units (§5.1): live records
    /// re-numbered densely in their old order, dead terms dropped from the
    /// dictionary, every posting of a dead unit dropped, the counts carried
    /// with nothing dead left.
    fn compacted(&self) -> Body {
        let mut unit_ids: Vec<Option<UnitId>> = vec![None; self.units.len()];
        let mut units = Vec::with_capacity(self.counts.units);
        for (old, record) in self.units.iter().enumerate() {
            if let Record::Live { .. } = record {
                unit_ids[old] = Some(units.len());
                units.push(record.clone());
            }
        }
        let mut term_ids: Vec<Option<TermId>> = vec![None; self.terms.len()];
        let mut dictionary = BTreeMap::new();
        let mut terms = Vec::with_capacity(self.counts.terms);
        for (spelling, &old) in &self.dictionary {
            let entry = &self.terms[old];
            if entry.live_units == 0 {
                continue;
            }
            let postings = entry
                .postings
                .iter()
                .filter_map(|p| {
                    unit_ids[p.unit]
                        .map(|unit| Posting { unit, occurrences: p.occurrences.clone() })
                })
                .collect();
            term_ids[old] = Some(terms.len());
            terms.push(TermEntry { postings, live_units: entry.live_units });
            dictionary.insert(spelling.clone(), terms.len() - 1);
        }
        let mut keys = BTreeMap::new();
        for (id, record) in units.iter_mut().enumerate() {
            if let Record::Live { unit, terms, .. } = record {
                for term in terms.iter_mut() {
                    *term = term_ids[*term].expect("a live unit's term is live");
                }
                keys.insert(unit.key().clone(), id);
            }
        }
        Body {
            dictionary,
            terms,
            units,
            keys,
            counts: Counts { tombstones: 0, dead_postings: 0, ..self.counts },
        }
    }
}

/// A RANGE's PREFIX (`search.md` §1.4's `keys_by_range`; R20: "all versions
/// of a document are ONE PREFIX — one `under=` range"): the address a
/// widening named as `under=` — an account's or a document's, or the node's
/// for the board's whole feed — under which a document lies where the
/// prefix's tumbler is a prefix of the document's. The crate's own type over
/// the vocabulary's own test, `skep_address::is_prefix` (T1/T2's order is
/// prefix-smaller, so the documents under a prefix are one contiguous run
/// of the keys); the vocabulary has the test and no type for it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Prefix(Address);

impl Prefix {
    /// The prefix of every document under `under`.
    pub fn new(under: Address) -> Prefix {
        Prefix(under)
    }

    /// The address the prefix is.
    pub fn address(&self) -> &Address {
        &self.0
    }

    /// Whether `doc` lies under this prefix.
    pub fn admits(&self, doc: &Address) -> bool {
        is_prefix(self.0.tumbler(), doc.tumbler())
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// THE ENGINE, one concrete type (`search.md` §1.4): an index of ONE CLASS —
/// `Guest` for a published index, `Principal(n)` for `n`'s supplement — the
/// dictionary, the postings, the unit records, the live counts, and the
/// tokenizer revision it was made under. The embedder keeps it under a
/// read-write lock of its own (§5.6): the write side for `merge` and
/// `install`, the read side for `compacted`, `stats`, `save`, `query` and
/// `keys_by_range`; this crate holds no lock.
#[derive(Debug, Clone)]
pub struct Index {
    pub(crate) class: Class,
    pub(crate) revision: Revision,
    pub(crate) ceiling: u64,
    pub(crate) seen: u64,
    pub(crate) body: Body,
    /// The file's revision where `load` migrated this value from its stored
    /// text (§5.1); `None` for an index `new` made or loaded at the running
    /// revision.
    pub(crate) migrated_from: Option<Revision>,
}

/// A unit tokenized and its postings built against NO index, under no lock
/// (§1.4, §5.6) — one unit's postings held between `prepare` and `merge`,
/// at most the unit's text again. It carries the unit's class and its live
/// bytes, what the class check (§2.1) and the ceiling (§7.4) read.
#[derive(Debug, Clone)]
pub struct Prepared {
    unit: Unit,
    postings: BTreeMap<String, Vec<Occurrence>>,
}

impl Prepared {
    /// The unit's key.
    pub fn key(&self) -> &UnitKey {
        self.unit.key()
    }

    /// The class the unit was read at (§2.1's class check reads it).
    pub fn class(&self) -> Class {
        self.unit.class()
    }

    /// The unit's live bytes (§7.4's ceiling reads them).
    pub fn bytes(&self) -> u64 {
        self.unit.bytes()
    }

    /// The unit itself.
    pub fn unit(&self) -> &Unit {
        &self.unit
    }

    /// The distinct terms the unit holds.
    pub fn terms(&self) -> usize {
        self.postings.len()
    }

    /// The posting entries the unit would add: one per occurrence.
    pub fn entries(&self) -> usize {
        self.postings.values().map(Vec::len).sum()
    }
}

/// The postings rebuilt without the tombstoned units (§5.1, §5.6), built by
/// `compacted` from one value under the read side and awaiting `install`
/// under the write side — the second copy of the postings M5 counts across
/// a compaction lives here, between the two calls.
#[derive(Debug, Clone)]
pub struct Compacted(Body);

/// The live counts (`search.md` §1.4's `stats`; §4 (iii); §5.1; §7.4): the
/// state event's inputs, per index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// The units held — live, a tombstone not among them.
    pub units: usize,
    /// The distinct terms live units hold: the dictionary's membership.
    pub terms: usize,
    /// The live posting entries, one per occurrence.
    pub postings: usize,
    /// The live bytes of text — the ceiling's count.
    pub bytes: u64,
    /// The tombstoned units resident until the next compaction.
    pub tombstones: usize,
    /// Their posting entries, resident until the next compaction — the
    /// compaction trigger's count.
    pub dead_postings: usize,
    /// The ceiling, in bytes of text.
    pub ceiling: u64,
    /// The units offered past the ceiling and refused — counted, listed
    /// nowhere (§7.4).
    pub seen: u64,
}

/// A refusal of `merge` (`search.md` §1.4), named by the design's two
/// refusals and carrying what each names.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IndexError {
    /// §2.1: the unit was not read at this index's class — `Guest` for a
    /// published index, this principal's for a supplement — and §4's
    /// invariants (i) and (ii) refuse it, both classes named.
    ClassMismatch {
        /// The index's class.
        index: Class,
        /// The class the unit was read at.
        unit: Class,
    },
    /// §7.4: the unit would carry the index past its ceiling; nothing was
    /// indexed and nothing changed, the unit it would have replaced in
    /// place. The bytes held and the limit, with the units held beside them.
    PastTheCeiling {
        /// The live bytes of text the index holds.
        held: u64,
        /// The ceiling, in bytes of text.
        limit: u64,
        /// The live units the index holds.
        units: usize,
    },
    /// §5.1: the writer the embedder handed `save` failed; the file is the
    /// embedder's `<name>.tmp`, which it does not rename.
    Write {
        /// The failure's kind.
        kind: io::ErrorKind,
        /// The failure's text.
        detail: String,
    },
}

impl fmt::Display for IndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IndexError::ClassMismatch { index, unit } => {
                write!(f, "an index of class {index} refuses a unit read at {unit}")
            }
            IndexError::PastTheCeiling {
                held,
                limit,
                units,
            } => write!(
                f,
                "past the ceiling: the index holds {held} bytes of text in {units} units and its ceiling is {limit} bytes"
            ),
            IndexError::Write { kind, detail } => {
                write!(f, "the index could not be written: {detail} ({kind:?})")
            }
        }
    }
}

impl Error for IndexError {}

impl Index {
    /// A fresh index of one CLASS — `Guest` for a published index,
    /// `Principal(n)` for `n`'s supplement (§1.4, §5.2 D7) — under the
    /// running crate's tokenizer revision and the ceiling.
    pub fn new(class: Class) -> Index {
        Index {
            class,
            revision: REVISION,
            ceiling: CEILING_BYTES,
            seen: 0,
            body: Body::default(),
            migrated_from: None,
        }
    }

    /// The suite's seam: a fresh index whose ceiling is `ceiling` bytes, so
    /// the refusal's arithmetic is exercised at sizes a unit test holds.
    #[cfg(test)]
    pub(crate) fn with_ceiling(class: Class, ceiling: u64) -> Index {
        Index { ceiling, ..Index::new(class) }
    }

    /// The one class this index holds, from `new`; no call changes it.
    pub fn class(&self) -> Class {
        self.class
    }

    /// The tokenizer revision the index's postings were cut under — the
    /// running crate's, for an index `new` made or `load` migrated.
    pub fn revision(&self) -> Revision {
        self.revision
    }

    /// THE MIGRATION's tag (§5.1): `Some(older)` where `load` found the file
    /// cut under an older tokenizer revision and re-indexed every unit from
    /// its stored text under the running one — the embedder SAVES such an
    /// index, "under the running crate's revision so the next `load`
    /// migrates nothing" — and `None` for an index `new` made or loaded at
    /// the running revision. One shape: the postings are the running
    /// revision's either way, which `revision` states.
    pub fn migrated_from(&self) -> Option<Revision> {
        self.migrated_from
    }

    /// The unit tokenized and its postings built against NO index, under no
    /// lock (§5.6): the tokenizing and the build of a 1 MB unit's postings
    /// hold nothing of the embedder's. `Prepared` carries the unit's class
    /// and its live bytes, what `merge`'s two checks read.
    pub fn prepare(unit: Unit) -> Prepared {
        let mut postings: BTreeMap<String, Vec<Occurrence>> = BTreeMap::new();
        for token in token::tokenize(&unit) {
            postings.entry(token.term).or_default().push(Occurrence {
                ordinal: token.ordinal,
                offset: token.offset,
                len: token.len,
            });
        }
        Prepared { unit, postings }
    }

    /// Under the write side: THE CLASS CHECK and THE CEILING made here, and
    /// nowhere else (§1.4). A unit not read at this index's class is refused,
    /// both classes named (§2.1). A unit whose key is already held is
    /// REPLACED — the re-read's one call — the replaced unit TOMBSTONED,
    /// leaving every statistic at once (§5.1). Past the ceiling (§7.4) the
    /// unit is not indexed and nothing changes — a refused replacement leaves
    /// the unit it would have replaced in place — the error names the bytes
    /// held and the limit, and the offer is counted in `seen`.
    pub fn merge(&mut self, prepared: Prepared) -> Result<(), IndexError> {
        if prepared.class() != self.class {
            return Err(IndexError::ClassMismatch { index: self.class, unit: prepared.class() });
        }
        let replaced = self.body.keys.get(prepared.key()).copied();
        let replaced_bytes = replaced.map_or(0, |id| self.body.bytes_of(id));
        let after = self.body.counts.bytes - replaced_bytes + prepared.bytes();
        if after > self.ceiling {
            self.seen += 1;
            return Err(IndexError::PastTheCeiling {
                held: self.body.counts.bytes,
                limit: self.ceiling,
                units: self.body.counts.units,
            });
        }
        if let Some(id) = replaced {
            self.body.tombstone(id);
        }
        self.body.add(prepared);
        Ok(())
    }

    /// `merge(prepare(unit))`, kept for an embedder that holds no lock
    /// (§1.4).
    pub fn index(&mut self, unit: Unit) -> Result<(), IndexError> {
        self.merge(Index::prepare(unit))
    }

    /// The postings rebuilt without the tombstoned units, from THIS value
    /// (§5.1, §5.6) — the read-locked snapshot is the caller's. Dead postings
    /// are dropped, dead terms leave the dictionary, the unit ids are dense
    /// again; the live counts are unchanged.
    pub fn compacted(&self) -> Compacted {
        Compacted(self.body.compacted())
    }

    /// The compacted postings installed by ONE SWAP under the write side
    /// (§5.6): one assignment, the old value gone with this call. The feed
    /// thread calls `compacted` then `install` in sequence, so no `merge`
    /// lands between them.
    pub fn install(&mut self, compacted: Compacted) {
        self.body = compacted.0;
    }

    /// Whether compaction is due (§5.1; §7.1's INTERIM pin): the dead
    /// postings exceed one eighth of the live ones, counted in entries.
    pub fn compaction_due(&self) -> bool {
        self.body.counts.dead_postings * COMPACTION_TRIGGER_DIVISOR > self.body.counts.postings
    }

    /// The live counts (§1.4), the ceiling and the units offered past it.
    pub fn stats(&self) -> Stats {
        let counts = self.body.counts;
        Stats {
            units: counts.units,
            terms: counts.terms,
            postings: counts.postings,
            bytes: counts.bytes,
            tombstones: counts.tombstones,
            dead_postings: counts.dead_postings,
            ceiling: self.ceiling,
            seen: self.seen,
        }
    }

    /// The dictionary's live membership in its sorted order: every term some
    /// live unit holds, a term held by dead units alone not among them
    /// (§5.1). The structure, for the embedder's and the suite's eyes; the
    /// query over it is `Index::query`.
    pub fn terms(&self) -> impl Iterator<Item = &str> {
        self.body.live_terms().map(|(term, _)| term)
    }

    /// THE ONE READ over the index's own unit keys (§1.4; THE ENUMERATOR
    /// RULED (b): "the crate gains ONE read, keys-by-range, over its own unit
    /// keys"): the keys held under `range` — the documents under its prefix —
    /// in the address order, at the cost of one scan of those keys. The keys
    /// sort in the tumbler order, which is prefix-smaller (T1/T2), so the
    /// keys under a prefix are one contiguous run of the key map, entered at
    /// the prefix itself by binary search and left at the first key not under
    /// it; a tombstoned unit's key is not held, so none is yielded. Its
    /// callers are the two REFRESHES — §5.4's bare-count refresh and §5.5's
    /// `opts.reindex`, each re-reading every unit held under a range at its
    /// own class — and no other; it reads nothing but the keys: never a
    /// posting, never the stored text, never the shell's document index.
    pub fn keys_by_range<'a>(
        &'a self,
        range: &'a Prefix,
    ) -> impl Iterator<Item = &'a UnitKey> + 'a {
        self.body
            .keys
            .range(UnitKey::new(range.address().clone())..)
            .map(|(key, _)| key)
            .take_while(move |key| range.admits(key.doc()))
    }
}

#[cfg(test)]
mod tests;
