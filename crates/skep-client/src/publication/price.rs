//! THE PRICE (the link-sets design §5.6; wire.md §The publish shot and
//! head-float, the in-lock reads' budget): the request priced against every
//! cap BEFORE the act, from the worst-case table the daemon prices by.
//!
//! The five terms the wire names, each a [`Term`] with how far it passes
//! its cap: THE LISTS — `runs`, `places`, `links`, `retract`, `read_with`,
//! each against the codec's wire-list cap, 4,096; THE BODY — the signed
//! body against the frame routes' request-body cap, 8 MiB; THE VALUES — the
//! distinct draft-native positions against the shot's re-insert budget; THE
//! IN-LOCK READS — the person's link-holding home count × (`links` +
//! `read_with` entries) + the draft's content run count × the request's
//! runs, against `MAX_PUBLICATION_READS` = 65,536; THE STAGED BYTES — the
//! bytes the one commit would stage, from the table, against the kernel's
//! transaction budget, 64 MiB. The table's figures are MIRRORED from the
//! daemon's `crates/skep-links/src/writes/publication/sizes.rs` and pinned
//! equal to it by a cell (`tests`), as the shell pins its three budgets; a
//! slot in the member-position form is priced at up to `MAX_SLOT_SPANS` =
//! 4,096 stored spans (the owner: priced here until ruled lower). The
//! verdict is DATA — which term, by how much — and the caller refuses the
//! act on it with the caps' lines, which are the copy's; past a cap the act
//! that exists is a narrower request.
//!
//! The price is an UPPER BOUND, as the daemon's is: the twin fence refuses
//! before anything is staged, a skip stages less, a byte of prose costs a
//! fraction of an atom. The same board prices the same request the same, so
//! a refusal the daemon answers after this price admits is a race, and one
//! it answers where this price refused is this library's own bug — the
//! send's budget arm tells them apart.

use skep_address::Address;

use super::enumerate::MAX_WIRE_LIST;
use super::{ISpan, Run};

/// The most spans one link slot may resolve to: M7's `MAX_SLOT_SPANS`.
pub const MAX_SLOT_SPANS: usize = 4096;

/// The in-lock reads' budget: `MAX_PUBLICATION_READS` = 16 ×
/// `MAX_SLOT_SPANS`.
pub const MAX_PUBLICATION_READS: usize = 16 * MAX_SLOT_SPANS;

/// The kernel's transaction budget, `MAX_TXN_BYTES`, 64 MiB.
pub const MAX_TXN_BYTES: u64 = 64 * 1024 * 1024;

/// The shot's re-insert budget: M5's `MAX_REINSERTED_VALUES`, the distinct
/// draft-native positions.
pub const MAX_REINSERTED_VALUES: u64 = 1 << 17;

/// The frame routes' request-body cap, 8 MiB, the parity the daemon holds a
/// signed body to.
pub const REQUEST_BODY_BYTES: usize = 8 * 1024 * 1024;

/// The bytes one correspondence record stages (the daemon's
/// `CORRESPONDENCE_RECORD_BYTES`).
pub const CORRESPONDENCE_RECORD_BYTES: u64 = 1_057;
/// The bytes one `links` entry's copy stages past its spans
/// (`COPY_FIXED_BYTES`).
pub const COPY_FIXED_BYTES: u64 = 561;
/// The bytes one `links` entry's claim stages (`CLAIM_BYTES`).
pub const CLAIM_BYTES: u64 = 857;
/// The bytes one `retract` entry stages (`RETRACTION_BYTES`).
pub const RETRACTION_BYTES: u64 = 845;
/// The bytes one `read_with` entry stages (`READ_WITH_BYTES`).
pub const READ_WITH_BYTES: u64 = 925;
/// The bytes the re-window stages per piece at a kept place
/// (`KEPT_PLACE_BYTES`).
pub const KEPT_PLACE_BYTES: u64 = 364;
/// The bytes one run of the member's placement adds (`PLACED_RUN_BYTES`).
pub const PLACED_RUN_BYTES: u64 = 104;
/// The bytes the re-insert stages per value at the worst case
/// (`REINSERTED_VALUE_BYTES`).
pub const REINSERTED_VALUE_BYTES: u64 = 287;
/// The bytes the shot stages whatever it places (`SHOT_BYTES`).
pub const SHOT_BYTES: u64 = 270;
/// The bytes the mint form adds (`EDITION_MINT_BYTES`).
pub const EDITION_MINT_BYTES: u64 = 109;
/// The bytes the edition claim stages (`EDITION_CLAIM_BYTES`).
pub const EDITION_CLAIM_BYTES: u64 = 925;

/// One term of the price.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Term {
    /// The `runs` list against the wire-list cap.
    Runs,
    /// The `places` list against the wire-list cap.
    Places,
    /// The `links` list against the wire-list cap.
    Links,
    /// The `retract` list against the wire-list cap.
    Retract,
    /// The `read_with` list against the wire-list cap.
    ReadWith,
    /// The signed body against the request-body cap.
    Body,
    /// The distinct draft-native positions against the re-insert budget.
    Values,
    /// The in-lock reads against `MAX_PUBLICATION_READS`.
    Reads,
    /// The staged bytes against `MAX_TXN_BYTES`.
    Bytes,
}

/// One end of a `links` entry, as priced: its spelling's shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndShape {
    /// The address form: each address, or a tag (`member`, `edition`).
    Addrs(Vec<String>),
    /// The I-span form.
    Spans(Vec<ISpan>),
    /// The member-position form: `(ordinal, width)` each.
    Member(Vec<(u64, u64)>),
}

/// One `links` entry, as priced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryShape {
    /// The `from` end.
    pub from: EndShape,
    /// The `to` end.
    pub to: EndShape,
    /// The type slot.
    pub ty: EndShape,
    /// Whether the entry names an original — a claim staged beside the copy.
    pub old: bool,
}

/// The request's shape, as the price reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shape<'a> {
    /// The runs, in order.
    pub runs: &'a [Run],
    /// The named drafts — the rendering draft, then each draft `also` names
    /// — whose runs the shot re-inserts, priced as values and records; empty
    /// at a bare shot naming none.
    pub drafts: &'a [Address],
    /// The term the request's addresses are minted under — the trunk at the
    /// document form, the account at the mint form.
    pub term: &'a Address,
    /// Whether the request is the mint form.
    pub mint: bool,
    /// Whether it carries the edition claim, at either form.
    pub claim: bool,
    /// The kept places, parallel to the runs.
    pub places: &'a [Option<u64>],
    /// Per run, the records covering it where it is a stray run re-composed
    /// by reference with a place — priced at one piece each; zero where it
    /// is none.
    pub stray_records: &'a [usize],
    /// The `links` entries.
    pub entries: &'a [EntryShape],
    /// The `retract` entries.
    pub retract: usize,
    /// The `read_with` entries.
    pub read_with: usize,
    /// The signed body's bytes.
    pub body_bytes: usize,
    /// The person's link-holding homes, as the client knows them — the homes
    /// the enumeration saw and the person's published documents beside
    /// them; the design names no read for the daemon's exact count, so this
    /// is the caller's figure.
    pub homes: usize,
    /// The rendering draft's content run count — its image's runs; the
    /// `also` drafts, never re-windowed, add none.
    pub draft_runs: usize,
}

/// The price.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Price {
    /// Each list's length: `runs`, `places`, `links`, `retract`, `read_with`.
    pub lists: [usize; 5],
    /// The signed body's bytes.
    pub body: usize,
    /// The distinct draft-native positions.
    pub values: u64,
    /// The in-lock reads.
    pub reads: usize,
    /// The staged bytes.
    pub bytes: u64,
    /// Every term past its cap, with how far past.
    pub over: Vec<(Term, u64)>,
}

impl Price {
    /// Whether the request is within every cap.
    pub fn admits(&self) -> bool {
        self.over.is_empty()
    }
}

/// Returns the bytes one tumbler component stores: an 8-byte length before
/// the magnitude's 32-bit digits, 4 bytes each, zero having none.
fn nat_bytes(n: u64) -> u64 {
    let bits = 64 - u64::from(n.leading_zeros());
    8 + 4 * bits.div_ceil(32)
}

/// Returns the bytes a tumbler of `comps` stores as the kernel encodes it:
/// an 8-byte length and, per component, its `nat_bytes` — the daemon's
/// `stored_tumbler_bytes`.
pub fn stored_tumbler_bytes(comps: &[u64]) -> u64 {
    8 + comps.iter().map(|c| nat_bytes(*c)).sum::<u64>()
}

/// Returns the bytes a span stores: its start's and its width's tumblers
/// (the daemon's `stored_span_bytes`).
pub fn stored_span_bytes(start: &[u64], width: &[u64]) -> u64 {
    stored_tumbler_bytes(start) + stored_tumbler_bytes(width)
}

/// Returns the components of a dotted spelling, a component past `u64` read
/// as the top — a bound, never under.
fn comps(text: &str) -> Vec<u64> {
    text.split('.').map(|c| c.parse().unwrap_or(u64::MAX)).collect()
}

/// Returns the bytes of the unit span at `addr`: the address as the start,
/// zeros then one as the width.
fn unit_span_bytes(addr: &str) -> u64 {
    let start = comps(addr);
    let mut width = vec![0u64; start.len()];
    if let Some(last) = width.last_mut() {
        *last = 1;
    }
    stored_span_bytes(&start, &width)
}

/// Returns the bytes of an I-span: its start, and a width of zeros then the
/// count.
fn i_span_bytes(span: &ISpan) -> u64 {
    let mut start = comps(&span.chain);
    start.push(span.first);
    let mut width = vec![0u64; start.len()];
    if let Some(last) = width.last_mut() {
        *last = span.width;
    }
    stored_span_bytes(&start, &width)
}

/// Returns the bytes of a content span of the edition's chain at the depth
/// the member-position form resolves to — the daemon's `content_span_of`:
/// the trunk then `0·1·k` at the document form, the account then
/// `0·d·0·1·k` at the mint form.
fn content_span_bytes(term: &Address, mint: bool) -> u64 {
    let mut start = comps(&term.to_string());
    start.extend(if mint { vec![0, 1, 0, 1, 1] } else { vec![0, 1, 1] });
    let mut width = vec![0u64; start.len()];
    if let Some(last) = width.last_mut() {
        *last = 1;
    }
    stored_span_bytes(&start, &width)
}

/// Returns the bytes of a tag's unit span at the depth it resolves to — the
/// member's address (the daemon's `tag_depth_of`).
fn tag_span_bytes(term: &Address, mint: bool) -> u64 {
    let mut start = comps(&term.to_string());
    start.extend(if mint { vec![0, 1, 1] } else { vec![1] });
    let mut width = vec![0u64; start.len()];
    if let Some(last) = width.last_mut() {
        *last = 1;
    }
    stored_span_bytes(&start, &width)
}

/// Returns the distinct positions the draft-native runs name — the store's
/// re-insert count, a position two runs name counted once — over every
/// named draft: the positions of two drafts are distinct addresses, so each
/// draft's are counted on its own chain and summed.
pub fn distinct_draft_positions(runs: &[Run], drafts: &[Address]) -> u64 {
    let mut total = 0u64;
    for draft in drafts {
        let mut ranges: Vec<(u64, u64)> = runs.iter().filter(|r| r.origin == *draft).map(|r| (r.i_start, r.reach())).collect();
        ranges.sort_unstable();
        let mut cursor = 0u64;
        for (lo, hi) in ranges {
            let lo = lo.max(cursor);
            if hi > lo {
                total += hi - lo;
                cursor = hi;
            }
        }
    }
    total
}

/// Prices the request's shape against every cap.
pub fn price(shape: &Shape<'_>) -> Price {
    let drafts = shape.drafts;
    let is_draft = |run: &Run| drafts.contains(&run.origin);
    let lists = [shape.runs.len(), shape.places.iter().filter(|p| p.is_some()).count(), shape.entries.len(), shape.retract, shape.read_with];
    let values = distinct_draft_positions(shape.runs, drafts);
    let reads = shape.homes.saturating_mul(shape.entries.len() + shape.read_with).saturating_add(shape.draft_runs.saturating_mul(shape.runs.len()));

    // The staged bytes, the daemon's `price_staged_bytes` term by term.
    let mut bytes = SHOT_BYTES;
    if shape.mint {
        bytes += EDITION_MINT_BYTES;
    }
    if shape.claim {
        bytes += EDITION_CLAIM_BYTES;
    }
    // The pieces bound, per named draft: the endpoints of that draft's runs,
    // sorted, since a run is cut only where another run of the same chain
    // begins or ends.
    let ends: Vec<(Address, Vec<u64>)> = drafts
        .iter()
        .map(|draft| {
            let mut ends: Vec<u64> = shape.runs.iter().filter(|r| r.origin == *draft).flat_map(|r| [r.i_start, r.reach()]).collect();
            ends.sort_unstable();
            (draft.clone(), ends)
        })
        .collect();
    let pieces_bound = |run: &Run| -> u64 {
        let ends = ends.iter().find(|(draft, _)| *draft == run.origin).map(|(_, ends)| ends.as_slice()).unwrap_or(&[]);
        let first = ends.partition_point(|e| *e <= run.i_start);
        let past = ends.partition_point(|e| *e < run.reach());
        1 + past.saturating_sub(first) as u64
    };
    for (index, run) in shape.runs.iter().enumerate() {
        let placed = shape.places.get(index).is_some_and(Option::is_some);
        if is_draft(run) {
            let pieces = pieces_bound(run);
            bytes = bytes.saturating_add(pieces.saturating_mul(PLACED_RUN_BYTES + CORRESPONDENCE_RECORD_BYTES));
            if placed {
                bytes = bytes.saturating_add(pieces.saturating_mul(KEPT_PLACE_BYTES));
            }
        } else {
            bytes = bytes.saturating_add(PLACED_RUN_BYTES);
            if placed {
                let records = shape.stray_records.get(index).copied().unwrap_or(0) as u64;
                bytes = bytes.saturating_add(records.max(1).saturating_mul(KEPT_PLACE_BYTES));
            }
        }
    }
    bytes = bytes.saturating_add(values.saturating_mul(REINSERTED_VALUE_BYTES));
    let content_span = content_span_bytes(shape.term, shape.mint);
    let tag_span = tag_span_bytes(shape.term, shape.mint);
    let runs = shape.runs.len() as u64;
    let end_bytes = |end: &EndShape| -> u64 {
        match end {
            EndShape::Addrs(list) => list.iter().map(|a| if a == "member" || a == "edition" { tag_span } else { unit_span_bytes(a) }).fold(0u64, u64::saturating_add),
            EndShape::Spans(list) => list.iter().map(i_span_bytes).fold(0u64, u64::saturating_add),
            EndShape::Member(list) => list.iter().map(|(_, width)| width.min(&runs).min(&(MAX_SLOT_SPANS as u64)).saturating_mul(content_span)).fold(0u64, u64::saturating_add),
        }
    };
    for entry in shape.entries {
        bytes = bytes.saturating_add(COPY_FIXED_BYTES).saturating_add(end_bytes(&entry.from)).saturating_add(end_bytes(&entry.to)).saturating_add(end_bytes(&entry.ty));
        if entry.old {
            bytes = bytes.saturating_add(CLAIM_BYTES);
        }
    }
    bytes = bytes.saturating_add((shape.retract as u64).saturating_mul(RETRACTION_BYTES));
    bytes = bytes.saturating_add((shape.read_with as u64).saturating_mul(READ_WITH_BYTES));

    let mut over = Vec::new();
    for (term, n) in [Term::Runs, Term::Places, Term::Links, Term::Retract, Term::ReadWith].into_iter().zip(lists) {
        if n > MAX_WIRE_LIST {
            over.push((term, (n - MAX_WIRE_LIST) as u64));
        }
    }
    if shape.body_bytes > REQUEST_BODY_BYTES {
        over.push((Term::Body, (shape.body_bytes - REQUEST_BODY_BYTES) as u64));
    }
    if values > MAX_REINSERTED_VALUES {
        over.push((Term::Values, values - MAX_REINSERTED_VALUES));
    }
    if reads > MAX_PUBLICATION_READS {
        over.push((Term::Reads, (reads - MAX_PUBLICATION_READS) as u64));
    }
    if bytes > MAX_TXN_BYTES {
        over.push((Term::Bytes, bytes - MAX_TXN_BYTES));
    }
    Price { lists, body: shape.body_bytes, values, reads, bytes, over }
}
