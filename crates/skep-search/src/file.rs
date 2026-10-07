//! THE FILE (`search.md` §5.1, §5.3, §5.4; §1.4's `save` and `load`): ONE
//! VERSIONED FILE PER INDEX, written WHOLE to the one writer the embedder
//! hands [`Index::save`] and loaded WHOLE from the one reader it hands
//! [`Index::load`]. The crate opens, renames and moves no file: the atomic
//! replace, the modes and the lock are the shell's (`client.md` §4e.4,
//! §3.3), and so is THE ASIDE's rename, whose spelling alone is here
//! ([`aside_name`]). The file is DERIVED STATE (PATTERNS P22, P38), so its
//! refusals are DISPOSITIONS ([`LoadError`]) and never a halt: a newer `v`
//! or a newer tokenizer revision is FACED and the file left untouched, an
//! older tokenizer revision is MIGRATED from the file's own stored text, a
//! damaged file is REBUILT with its loss stated, another class's file is
//! MOVED ASIDE.
//!
//! ## The layout
//!
//! ```text
//! <header line>   `header`'s one spelling; its `body` member is the body's length
//! <body>          seven sections, each a varint LENGTH and then its bytes:
//!   1 ranges      the `Header`'s per-range records — a count, then per range:
//!                 `under` (0, or 1 and an address), `held` (a position and a
//!                 chain), the refusals (a count; per refusal a document and a
//!                 reason), the bare-row count, the grant (0, or 1 and a kind
//!                 and an issuer)
//!   2 head        the newest head's `H.k` — 0, or 1 and its member, its
//!                 position and its chain
//!   3 seen        the units offered past the ceiling (§7.4)
//!   4 dictionary  the terms, SORTED, each a string
//!   5 units       a count, then per record: 0 for a tombstone, or 1 and the
//!                 key, the member, the kind, the class, `as_of`, the item
//!                 table — each text item carrying the STORED TEXT (§6) — and
//!                 the unit's TERM LIST
//!   6 postings    per term in dictionary order: a count, then per posting the
//!                 unit id, a count of occurrences and each one's ordinal,
//!                 offset and length — the ids, ordinals and offsets delta-coded
//!   7 counts      the live counts: units, terms, postings, bytes, tombstones,
//!                 dead postings
//! <trailer>       CRC-32C over the HEADER LINE's bytes, its `\n` included, and
//!                 the body — u32 little-endian
//! ```
//!
//! An integer is an unsigned LEB128 varint, canonical; a string is its length
//! and its UTF-8 bytes; an address is its component count and, per component,
//! the length and the little-endian bytes of its magnitude; a chain is its
//! thirty-two bytes; a flag is one byte, 0 or 1. Each section's length is
//! checked as it is read, so a section that overruns or underruns its length
//! is DAMAGED by name, as is one that fails to parse. The term ids in the file
//! are the sorted dictionary's positions, whatever ids the index held in
//! memory, so one index has one file.
//!
//! ## `load`'s order
//!
//! The header line first, `v` first inside it (`header`); then `kind` and
//! `principal` against the class expected — a mismatch is
//! [`LoadError::OtherClass`], both named, BEFORE the body is read (§5.4: the
//! file is a misplaced holding, moved aside); then `tokenizer` — NEWER than
//! the running crate's is [`LoadError::NewerTokenizer`], faced, the body
//! unread, never migrated down; then the body under its trailer — a trailer
//! that disagrees, a section that overruns, a section that fails to parse, a
//! term list or the counts that disagree with the postings:
//! [`LoadError::Damaged`], naming what; then an OLDER tokenizer revision:
//! every live unit re-tokenized from its stored text under the running
//! revision, the postings rebuilt, the index tagged by
//! [`Index::migrated_from`] so the embedder saves it, "under the running
//! crate's revision so the next `load` migrates nothing" (§5.1). No older
//! `v` exists at `v = 1`, so the migrate arm is the tokenizer's alone.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};

use skep_address::{validate, Address, Nat, Tumbler};

use crate::header::{
    self, Chain, ChainAt, Grant, GrantKind, HeadRecord, Header, HeaderError, RangeRecord, Refusal,
};
use crate::index::{
    Body, Counts, Index, IndexError, Occurrence, Posting, Record, TermEntry, TermId, CEILING_BYTES,
};
use crate::token::{Revision, REVISION};
use crate::unit::{Class, GapKind, Item, Kind, Unit, UnitKey};

/// The trailer's bytes: one `u32`, little-endian.
const TRAILER_LEN: usize = 4;

/// A load's refusal (§5.1; P38): every disposition the design names, each
/// carrying what its face states — the UX writes the words. Non-exhaustive:
/// the next format version brings dispositions of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoadError {
    /// FACED, the file left untouched: `v` above 1 — "this index was written
    /// by a newer skep than this one"; this skep searches nothing from the
    /// file and writes none in its place.
    NewerVersion {
        /// The version the header names.
        v: u64,
    },
    /// FACED, as a newer `v` is: the file was cut under a tokenizer revision
    /// newer than the running crate's — searched not, written not, never
    /// migrated down, so two builds alternating on one file re-migrate at no
    /// launch.
    NewerTokenizer {
        /// The revision the header names.
        revision: Revision,
    },
    /// REFUSED before the body is read, the file MOVED ASIDE (§5.4): the
    /// file's `kind` and `principal` name another class than the one the
    /// embedder opened it as — another board's holding, another principal's
    /// — CRC-valid or not.
    OtherClass {
        /// The class the file names.
        file: Class,
        /// The class the embedder expected.
        expected: Class,
    },
    /// DAMAGED and REBUILT: a member this crate does not know, at the file's
    /// own `v`.
    UnknownMember {
        /// The member's name.
        name: String,
    },
    /// DAMAGED and REBUILT, the loss stated: the header in another spelling,
    /// a trailer that disagrees, a section that overruns its length or fails
    /// to parse, counts that disagree with the postings — `what` names the
    /// check.
    Damaged {
        /// The check that refused the file, and where.
        what: String,
    },
    /// The embedder's reader failed before any byte was judged: no
    /// disposition of the file's own.
    Read {
        /// The failure's kind.
        kind: io::ErrorKind,
        /// The failure's text.
        detail: String,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::NewerVersion { v } => {
                write!(f, "this index was written by a newer skep than this one (v {v})")
            }
            LoadError::NewerTokenizer { revision } => write!(
                f,
                "this index was cut under a newer tokenizer than this one ({revision} against {REVISION})"
            ),
            LoadError::OtherClass { file, expected } => write!(
                f,
                "this is an index of class {file}, opened where an index of class {expected} was expected"
            ),
            LoadError::UnknownMember { name } => {
                write!(f, "the header names a member this skep does not know: `{name}`")
            }
            LoadError::Damaged { what } => write!(f, "this index is damaged: {what}"),
            LoadError::Read { kind, detail } => write!(f, "the index could not be read: {detail} ({kind:?})"),
        }
    }
}

impl Error for LoadError {}

impl From<HeaderError> for LoadError {
    fn from(e: HeaderError) -> LoadError {
        match e {
            HeaderError::NewerVersion { v } => LoadError::NewerVersion { v },
            HeaderError::UnknownMember { name } => LoadError::UnknownMember { name },
            HeaderError::Damaged { what } => {
                LoadError::Damaged { what: format!("the header line: {what}") }
            }
        }
    }
}

/// THE ASIDE's spelling (§5.4; `client.md` §4e.4): `<name>.aside.<chain>.<n>`
/// — `published.index.aside.<64 hex>.1`, `principal-<n>.index.aside.<64
/// hex>.1` — `chain` the misplaced file's OWN board's chain, off its header,
/// and `n` the first free ordinal, so a second misplaced file of the same
/// board lands beside the first at 2 and nothing is ever overwritten. The
/// name alone: no file is moved, renamed or opened by this crate — the rename
/// is the shell's, as the save's rename is, and no open re-adopts the aside.
pub fn aside_name(name: &str, chain: &Chain, n: u32) -> String {
    format!("{name}.aside.{chain}.{n}")
}

/// CRC-32C (Castagnoli, the polynomial `0x1EDC6F41`, reflected) over `bytes`
/// — the trailer's checksum, computed in-crate over the header line and the
/// body (§5.1). The standard check value: `crc32c(b"123456789")` is
/// `0xE3069283`.
pub fn crc32c(bytes: &[u8]) -> u32 {
    extend(0, bytes)
}

/// The checksum continued: `extend(crc32c(a), b) == crc32c(a ++ b)`.
fn extend(crc: u32, bytes: &[u8]) -> u32 {
    let mut register = !crc;
    for &byte in bytes {
        register = CRC_TABLE[((register ^ u32::from(byte)) & 0xFF) as usize] ^ (register >> 8);
    }
    !register
}

/// The byte-at-a-time table for the reflected polynomial `0x82F63B78`.
const CRC_TABLE: [u32; 256] = crc_table();

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 1 != 0 { 0x82F6_3B78 ^ (c >> 1) } else { c >> 1 };
            bit += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

impl Index {
    /// THE WHOLE INDEX TO ONE WRITER (§1.4, §5.1): the header line — `board`
    /// and `floor` from the typed `Header` the embedder composes, `kind`,
    /// `principal` and `tokenizer` from the `Index` ALONE (the class it was
    /// made or loaded with, the running crate's tokenizer revision) — then the
    /// body, the `Header`'s per-range records and the head's pair in their
    /// sections, then the trailer. A READ of the index, serialized beside
    /// queries under the embedder's read side (§5.6); the tombstoned units'
    /// postings are written as they stand, so the embedder compacts AHEAD of
    /// a save that is due (§5.1). The writer is the embedder's `<name>.tmp`
    /// (`client.md` §4e.4); the sync and the rename are its.
    pub fn save(&self, header: &Header, to: &mut dyn Write) -> Result<(), IndexError> {
        let body = self.body_bytes(header);
        let line = header::encode(header, self.class, self.revision, body.len() as u64);
        let trailer = extend(crc32c(&line), &body).to_le_bytes();
        let failed = |e: io::Error| IndexError::Write { kind: e.kind(), detail: e.to_string() };
        for part in [line.as_slice(), body.as_slice(), trailer.as_slice()] {
            to.write_all(part).map_err(failed)?;
        }
        to.flush().map_err(failed)
    }

    /// THE WHOLE FILE FROM ONE READER (§1.4, §5.1), in the module doc's
    /// order: the header read back typed by the one canonical parser, its `v`
    /// first; a file whose `kind` and `principal` name another class than
    /// `expected` refused, both named, before any query can run over it and
    /// before its body is read (§5.4: moved aside); a newer `v`, a newer
    /// tokenizer revision, an unknown member or a damaged file a typed
    /// refusal carrying its disposition; an older tokenizer revision
    /// MIGRATED from the stored text, the result at the running revision and
    /// tagged by [`Index::migrated_from`]. The index comes back under the
    /// running crate's ceiling with `seen` as the file holds it.
    pub fn load(from: &mut dyn Read, expected: Class) -> Result<(Index, Header), LoadError> {
        let mut bytes = Vec::new();
        from.read_to_end(&mut bytes)
            .map_err(|e| LoadError::Read { kind: e.kind(), detail: e.to_string() })?;
        // 1. The header line, `v` first inside it.
        let line_len = bytes
            .iter()
            .position(|&b| b == b'\n')
            .map(|at| at + 1)
            .ok_or_else(|| damaged("the header line", "no line ends with `\\n`"))?;
        let line = &bytes[..line_len];
        let parsed = header::parse(line)?;
        // 2. The class, before the body.
        if parsed.class != expected {
            return Err(LoadError::OtherClass { file: parsed.class, expected });
        }
        // 3. The tokenizer: newer is faced, the body unread.
        if newer(parsed.tokenizer) {
            return Err(LoadError::NewerTokenizer { revision: parsed.tokenizer });
        }
        // 4. The body under its trailer.
        let present = bytes.len() - line_len;
        let needed = usize::try_from(parsed.body).ok().and_then(|n| n.checked_add(TRAILER_LEN));
        if needed.is_none_or(|n| n > present) {
            return Err(damaged(
                "the body",
                "the header's `body` and the trailer overrun the file",
            ));
        }
        if needed != Some(present) {
            return Err(damaged("the body", "bytes stand past the trailer"));
        }
        let body_end = bytes.len() - TRAILER_LEN;
        let body = &bytes[line_len..body_end];
        let trailer = u32::from_le_bytes(bytes[body_end..].try_into().expect("four bytes"));
        if extend(crc32c(line), body) != trailer {
            return Err(damaged("the trailer", "it disagrees with the header line and the body"));
        }
        let mut sections = Reader::new("body", body);
        let ranges = sections.section("ranges", read_ranges)?;
        let head = sections.section("head", read_head)?;
        let seen = sections.section("seen", Reader::varint)?;
        let dictionary = sections.section("dictionary", read_dictionary)?;
        let records =
            sections.section("units", |r| read_units(r, parsed.class, dictionary.len()))?;
        let postings =
            sections.section("postings", |r| read_postings(r, dictionary.len(), records.len()))?;
        let counts = sections.section("counts", read_counts)?;
        sections.done()?;
        let body = assemble(dictionary, records, postings, counts)?;
        // 5. An older tokenizer revision: migrated from the stored text.
        let (body, migrated_from) = if parsed.tokenizer == REVISION {
            (body, None)
        } else {
            (migrated(body), Some(parsed.tokenizer))
        };
        let index = Index {
            class: expected,
            revision: REVISION,
            ceiling: CEILING_BYTES,
            seen,
            body,
            migrated_from,
        };
        let header = Header { board: parsed.board, floor: parsed.floor, ranges, head };
        Ok((index, header))
    }

    /// The body's seven sections, each length-prefixed.
    fn body_bytes(&self, header: &Header) -> Vec<u8> {
        let body = &self.body;
        // The file's term ids are the sorted dictionary's positions.
        let order: Vec<TermId> = body.dictionary.values().copied().collect();
        let mut rank = vec![0 as TermId; body.terms.len()];
        for (new, &old) in order.iter().enumerate() {
            rank[old] = new;
        }
        let mut seen = Vec::new();
        put_varint(&mut seen, self.seen);
        let mut out = Vec::new();
        for section in [
            ranges_section(header),
            head_section(header),
            seen,
            dictionary_section(body),
            units_section(body, &rank),
            postings_section(body, &order),
            counts_section(body.counts),
        ] {
            put_bytes(&mut out, &section);
        }
        out
    }
}

/// Whether `found` is newer than the running crate's revision: the rule's
/// version first, then the Unicode version of the tables.
fn newer(found: Revision) -> bool {
    (found.rule, found.unicode) > (REVISION.rule, REVISION.unicode)
}

/// The live units re-indexed under the running revision (§5.1, §6): every
/// live unit's stored text re-tokenized and its postings rebuilt; a tombstone
/// has no text and is dropped, so the migrated body is compacted.
fn migrated(old: Body) -> Body {
    let mut fresh = Body::default();
    for record in old.units {
        if let Record::Live { unit, .. } = record {
            fresh.add(Index::prepare(unit));
        }
    }
    fresh
}

fn damaged(section: &str, fault: &str) -> LoadError {
    LoadError::Damaged { what: format!("{section}: {fault}") }
}

// ---- the writer ---------------------------------------------------------

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn put_address(out: &mut Vec<u8>, address: &Address) {
    put_varint(out, address.tumbler().len() as u64);
    for component in address.tumbler().iter() {
        put_bytes(out, &component.to_bytes_le());
    }
}

fn put_option_address(out: &mut Vec<u8>, address: Option<&Address>) {
    match address {
        None => out.push(0),
        Some(address) => {
            out.push(1);
            put_address(out, address);
        }
    }
}

fn put_chain_at(out: &mut Vec<u8>, at: &ChainAt) {
    put_varint(out, at.position);
    out.extend_from_slice(at.chain.as_bytes());
}

/// The delta of a strictly ascending sequence: the first value whole, each
/// next one as the gap past its predecessor.
fn gap(prev: Option<u64>, value: u64) -> u64 {
    match prev {
        None => value,
        Some(prev) => value - prev - 1,
    }
}

fn ranges_section(header: &Header) -> Vec<u8> {
    let mut s = Vec::new();
    put_varint(&mut s, header.ranges.len() as u64);
    for range in &header.ranges {
        put_option_address(&mut s, range.under.as_ref());
        put_chain_at(&mut s, &range.held);
        put_varint(&mut s, range.refusals.len() as u64);
        for refusal in &range.refusals {
            put_address(&mut s, &refusal.doc);
            put_bytes(&mut s, refusal.reason.as_bytes());
        }
        put_varint(&mut s, range.bare_rows);
        match &range.grant {
            None => s.push(0),
            Some(grant) => {
                s.push(1);
                s.push(match grant.kind {
                    GrantKind::Named => 0,
                    GrantKind::AnyPrincipal => 1,
                });
                put_address(&mut s, &grant.issuer);
            }
        }
    }
    s
}

fn head_section(header: &Header) -> Vec<u8> {
    match &header.head {
        None => vec![0],
        Some(head) => {
            let mut s = vec![1];
            put_address(&mut s, &head.member);
            put_chain_at(&mut s, &head.at);
            s
        }
    }
}

fn dictionary_section(body: &Body) -> Vec<u8> {
    let mut s = Vec::new();
    put_varint(&mut s, body.dictionary.len() as u64);
    for term in body.dictionary.keys() {
        put_bytes(&mut s, term.as_bytes());
    }
    s
}

fn units_section(body: &Body, rank: &[TermId]) -> Vec<u8> {
    let mut s = Vec::new();
    put_varint(&mut s, body.units.len() as u64);
    for record in &body.units {
        let Record::Live { unit, terms, .. } = record else {
            s.push(0);
            continue;
        };
        s.push(1);
        put_address(&mut s, unit.key().doc());
        put_option_address(&mut s, unit.member());
        s.push(match unit.kind() {
            Kind::Edition => 0,
            Kind::Draft => 1,
        });
        match unit.class() {
            Class::Guest => s.push(0),
            Class::Principal(n) => {
                s.push(1);
                put_varint(&mut s, n);
            }
        }
        put_varint(&mut s, unit.as_of());
        put_varint(&mut s, unit.items().len() as u64);
        for item in unit.items() {
            match item {
                Item::Text { start, bytes } => {
                    s.push(0);
                    put_varint(&mut s, *start);
                    put_bytes(&mut s, bytes);
                }
                Item::Gap { start, width, kind } => {
                    s.push(match kind {
                        GapKind::Atom => 1,
                        GapKind::Withheld { .. } => 2,
                        GapKind::Unknown => 3,
                    });
                    put_varint(&mut s, *start);
                    put_varint(&mut s, *width);
                    if let GapKind::Withheld { origin } = kind {
                        put_address(&mut s, origin);
                    }
                }
            }
        }
        let mut ids: Vec<TermId> = terms.iter().map(|&term| rank[term]).collect();
        ids.sort_unstable();
        put_varint(&mut s, ids.len() as u64);
        let mut prev = None;
        for id in ids {
            put_varint(&mut s, gap(prev, id as u64));
            prev = Some(id as u64);
        }
    }
    s
}

fn postings_section(body: &Body, order: &[TermId]) -> Vec<u8> {
    let mut s = Vec::new();
    for &old in order {
        let entry = &body.terms[old];
        put_varint(&mut s, entry.postings.len() as u64);
        let mut prev_unit = None;
        for posting in &entry.postings {
            put_varint(&mut s, gap(prev_unit, posting.unit as u64));
            prev_unit = Some(posting.unit as u64);
            put_varint(&mut s, posting.occurrences.len() as u64);
            let mut prev_ordinal = None;
            let mut prev_offset = 0u64;
            for occurrence in &posting.occurrences {
                put_varint(&mut s, gap(prev_ordinal, u64::from(occurrence.ordinal)));
                prev_ordinal = Some(u64::from(occurrence.ordinal));
                put_varint(&mut s, occurrence.offset - prev_offset);
                prev_offset = occurrence.offset;
                put_varint(&mut s, u64::from(occurrence.len));
            }
        }
    }
    s
}

fn counts_section(counts: Counts) -> Vec<u8> {
    let mut s = Vec::new();
    for count in [
        counts.units as u64,
        counts.terms as u64,
        counts.postings as u64,
        counts.bytes,
        counts.tombstones as u64,
        counts.dead_postings as u64,
    ] {
        put_varint(&mut s, count);
    }
    s
}

// ---- the reader ---------------------------------------------------------

/// A bounded cursor over one section's bytes — the body's for the section
/// lengths themselves — every read checked against the section's end.
struct Reader<'a> {
    section: &'static str,
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(section: &'static str, bytes: &'a [u8]) -> Reader<'a> {
        Reader { section, bytes, at: 0 }
    }

    fn damaged(&self, fault: &str) -> LoadError {
        damaged(&format!("the `{}` section", self.section), fault)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], LoadError> {
        let end = self
            .at
            .checked_add(n)
            .filter(|&end| end <= self.bytes.len())
            .ok_or_else(|| self.damaged("it overruns its length"))?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn byte(&mut self) -> Result<u8, LoadError> {
        Ok(self.take(1)?[0])
    }

    fn flag(&mut self) -> Result<bool, LoadError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(self.damaged("a flag that is neither 0 nor 1")),
        }
    }

    /// A canonical unsigned LEB128 varint.
    fn varint(&mut self) -> Result<u64, LoadError> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.byte()?;
            if shift == 63 && byte > 1 {
                return Err(self.damaged("a varint overflows"));
            }
            value |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                if shift > 0 && byte == 0 {
                    return Err(self.damaged("an overlong varint"));
                }
                return Ok(value);
            }
            shift += 7;
            if shift > 63 {
                return Err(self.damaged("a varint overflows"));
            }
        }
    }

    fn len(&mut self) -> Result<usize, LoadError> {
        usize::try_from(self.varint()?).map_err(|_| self.damaged("a count past the address space"))
    }

    fn u32(&mut self) -> Result<u32, LoadError> {
        u32::try_from(self.varint()?).map_err(|_| self.damaged("a value past u32"))
    }

    fn bytes(&mut self) -> Result<&'a [u8], LoadError> {
        let n = self.len()?;
        self.take(n)
    }

    fn string(&mut self) -> Result<String, LoadError> {
        std::str::from_utf8(self.bytes()?)
            .map(str::to_string)
            .map_err(|_| self.damaged("a string that is not UTF-8"))
    }

    /// An address: its components in their one spelling, T4-valid.
    fn address(&mut self) -> Result<Address, LoadError> {
        let n = self.len()?;
        let mut components = Vec::new();
        for _ in 0..n {
            let bytes = self.bytes()?;
            let component = Nat::from_bytes_le(bytes);
            if component.to_bytes_le() != bytes {
                return Err(self.damaged("an address component not in its one spelling"));
            }
            components.push(component);
        }
        let tumbler =
            Tumbler::new(components).map_err(|_| self.damaged("an address of no components"))?;
        validate(tumbler).map_err(|_| self.damaged("an address that is not T4-valid"))
    }

    fn option_address(&mut self) -> Result<Option<Address>, LoadError> {
        if self.flag()? {
            Ok(Some(self.address()?))
        } else {
            Ok(None)
        }
    }

    fn chain_at(&mut self) -> Result<ChainAt, LoadError> {
        let position = self.varint()?;
        let chain = Chain::from_bytes(self.take(32)?.try_into().expect("thirty-two bytes"));
        Ok(ChainAt { position, chain })
    }

    /// The next value of a strictly ascending, delta-coded sequence.
    fn ascending(&mut self, prev: Option<u64>) -> Result<u64, LoadError> {
        let delta = self.varint()?;
        match prev {
            None => Ok(delta),
            Some(prev) => prev
                .checked_add(delta)
                .and_then(|v| v.checked_add(1))
                .ok_or_else(|| self.damaged("a delta overflows")),
        }
    }

    /// One section's bytes, read by `read`, which must consume them whole.
    fn section<T>(
        &mut self,
        name: &'static str,
        read: impl FnOnce(&mut Reader<'a>) -> Result<T, LoadError>,
    ) -> Result<T, LoadError> {
        let overrun = || damaged(&format!("the `{name}` section"), "it overruns the body");
        let len = usize::try_from(self.varint().map_err(|_| overrun())?).map_err(|_| overrun())?;
        let bytes = self.take(len).map_err(|_| overrun())?;
        let mut reader = Reader::new(name, bytes);
        let value = read(&mut reader)?;
        reader.done()?;
        Ok(value)
    }

    fn done(&self) -> Result<(), LoadError> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(self.damaged("it underruns its length: bytes stand past its last member"))
        }
    }
}

fn read_ranges(r: &mut Reader<'_>) -> Result<Vec<RangeRecord>, LoadError> {
    let n = r.len()?;
    let mut ranges = Vec::new();
    for _ in 0..n {
        let under = r.option_address()?;
        let held = r.chain_at()?;
        let refusals = r.len()?;
        let mut recorded = Vec::new();
        for _ in 0..refusals {
            recorded.push(Refusal { doc: r.address()?, reason: r.string()? });
        }
        let bare_rows = r.varint()?;
        let grant = if r.flag()? {
            let kind = match r.byte()? {
                0 => GrantKind::Named,
                1 => GrantKind::AnyPrincipal,
                _ => return Err(r.damaged("a grant of no known kind")),
            };
            Some(Grant { kind, issuer: r.address()? })
        } else {
            None
        };
        ranges.push(RangeRecord { under, held, refusals: recorded, bare_rows, grant });
    }
    Ok(ranges)
}

fn read_head(r: &mut Reader<'_>) -> Result<Option<HeadRecord>, LoadError> {
    if !r.flag()? {
        return Ok(None);
    }
    Ok(Some(HeadRecord { member: r.address()?, at: r.chain_at()? }))
}

/// The terms, strictly ascending.
fn read_dictionary(r: &mut Reader<'_>) -> Result<Vec<String>, LoadError> {
    let n = r.len()?;
    let mut terms: Vec<String> = Vec::new();
    for _ in 0..n {
        let term = r.string()?;
        if terms.last().is_some_and(|prev| *prev >= term) {
            return Err(r.damaged("a term out of the sorted order"));
        }
        terms.push(term);
    }
    Ok(terms)
}

/// The unit records: `None` for a tombstone, else the unit and its stored
/// term list.
type Records = Vec<Option<(Unit, Vec<TermId>)>>;

fn read_units(r: &mut Reader<'_>, class: Class, terms: usize) -> Result<Records, LoadError> {
    let n = r.len()?;
    let mut records = Vec::new();
    for _ in 0..n {
        if !r.flag()? {
            records.push(None);
            continue;
        }
        let key = UnitKey::new(r.address()?);
        let member = r.option_address()?;
        let kind = match r.byte()? {
            0 => Kind::Edition,
            1 => Kind::Draft,
            _ => return Err(r.damaged("a unit of no known kind")),
        };
        let unit_class = if r.flag()? { Class::Principal(r.varint()?) } else { Class::Guest };
        if unit_class != class {
            return Err(r.damaged("a unit of another class than the file's"));
        }
        let as_of = r.varint()?;
        let items = r.len()?;
        let mut table = Vec::new();
        for _ in 0..items {
            let tag = r.byte()?;
            if tag > 3 {
                return Err(r.damaged("an item of no known kind"));
            }
            let start = r.varint()?;
            table.push(match tag {
                0 => Item::Text { start, bytes: r.bytes()?.to_vec() },
                1 => Item::Gap { start, width: r.varint()?, kind: GapKind::Atom },
                2 => {
                    let width = r.varint()?;
                    Item::Gap { start, width, kind: GapKind::Withheld { origin: r.address()? } }
                }
                _ => Item::Gap { start, width: r.varint()?, kind: GapKind::Unknown },
            });
        }
        let unit = Unit::new(key, member, kind, unit_class, as_of, table)
            .map_err(|_| r.damaged("a unit whose items are not one extent"))?;
        let listed = r.len()?;
        let mut list = Vec::new();
        let mut prev = None;
        for _ in 0..listed {
            let id = r.ascending(prev)?;
            if id >= terms as u64 {
                return Err(r.damaged("a term id past the dictionary"));
            }
            list.push(id as TermId);
            prev = Some(id);
        }
        records.push(Some((unit, list)));
    }
    Ok(records)
}

/// Per term in dictionary order, its postings.
fn read_postings(
    r: &mut Reader<'_>,
    terms: usize,
    units: usize,
) -> Result<Vec<Vec<Posting>>, LoadError> {
    let mut all = Vec::new();
    for _ in 0..terms {
        let n = r.len()?;
        let mut postings = Vec::new();
        let mut prev_unit = None;
        for _ in 0..n {
            let unit = r.ascending(prev_unit)?;
            if unit >= units as u64 {
                return Err(r.damaged("a unit id past the unit records"));
            }
            prev_unit = Some(unit);
            let count = r.len()?;
            let mut occurrences = Vec::new();
            let mut prev_ordinal = None;
            let mut prev_offset = 0u64;
            for _ in 0..count {
                let ordinal = r.ascending(prev_ordinal)?;
                prev_ordinal = Some(ordinal);
                let ordinal =
                    u32::try_from(ordinal).map_err(|_| r.damaged("an ordinal past u32"))?;
                let offset = prev_offset
                    .checked_add(r.varint()?)
                    .ok_or_else(|| r.damaged("an offset overflows"))?;
                prev_offset = offset;
                let len = r.u32()?;
                occurrences.push(Occurrence { ordinal, offset, len });
            }
            postings.push(Posting { unit: unit as usize, occurrences });
        }
        all.push(postings);
    }
    Ok(all)
}

fn read_counts(r: &mut Reader<'_>) -> Result<Counts, LoadError> {
    Ok(Counts {
        units: r.len()?,
        terms: r.len()?,
        postings: r.len()?,
        bytes: r.varint()?,
        tombstones: r.len()?,
        dead_postings: r.len()?,
    })
}

/// The body assembled and checked: each unit's stored term list against the
/// postings, the live keys distinct, the counts against the recomputation.
fn assemble(
    dictionary: Vec<String>,
    records: Records,
    postings: Vec<Vec<Posting>>,
    stored: Counts,
) -> Result<Body, LoadError> {
    let mut derived: Vec<Vec<TermId>> = vec![Vec::new(); records.len()];
    let mut entries = vec![0usize; records.len()];
    let mut terms = Vec::with_capacity(postings.len());
    for (term, postings) in postings.into_iter().enumerate() {
        let mut live_units = 0;
        for posting in &postings {
            derived[posting.unit].push(term);
            entries[posting.unit] += posting.occurrences.len();
            if records[posting.unit].is_some() {
                live_units += 1;
            }
        }
        terms.push(TermEntry { postings, live_units });
    }
    let mut units = Vec::with_capacity(records.len());
    let mut keys = BTreeMap::new();
    let mut counts = Counts::default();
    for (id, record) in records.into_iter().enumerate() {
        match record {
            None => {
                counts.tombstones += 1;
                counts.dead_postings += entries[id];
                units.push(Record::Dead);
            }
            Some((unit, list)) => {
                if list != derived[id] {
                    return Err(damaged(
                        "the `units` section",
                        "a term list disagrees with the postings",
                    ));
                }
                if keys.insert(unit.key().clone(), id).is_some() {
                    return Err(damaged("the `units` section", "two live units under one key"));
                }
                counts.units += 1;
                counts.bytes += unit.bytes();
                counts.postings += entries[id];
                units.push(Record::Live { unit, terms: list, entries: entries[id] });
            }
        }
    }
    counts.terms = terms.iter().filter(|entry| entry.live_units > 0).count();
    if counts != stored {
        return Err(damaged(
            "the `counts` section",
            "it disagrees with the units and the postings",
        ));
    }
    let dictionary = dictionary.into_iter().enumerate().map(|(id, term)| (term, id)).collect();
    Ok(Body { dictionary, terms, units, keys, counts })
}

#[cfg(test)]
mod tests;
