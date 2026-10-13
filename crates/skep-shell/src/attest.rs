//! THE ATTEST a signed session composes for every write of the CHECKED SET
//! (t5: "the shell checks it, signs where signed ops requires"; `client.md`
//! §4b.3: the shell "signs only the ENTRY FRAME of an op it has checked,
//! composing every axis of that frame itself — the `board` term from its own
//! read of the board it dials, the account from the session — and never a
//! preimage the page supplies"): for a frame of the TEN KINDS that have an
//! entry frame (wire.md §Credential refusals) — `create_new_document`, `fork`,
//! `version`, `insert`, `publish`, `make_link`, `emit`, `nullify`,
//! `assert_sup`, `edit_link` — the entry frame under `H.1`'s pair, the
//! session's account, the frame's `doc` term and the body the kind's
//! grammar spells, signed by the session's key, attached as the frame's
//! `attest` member. ATTACH WHEN IN DOUBT (the wire's own rule): the publish
//! class is the daemon's classification, and an `attest` on a write outside
//! it is dropped unread, so every write of the ten kinds under a signed
//! session is attested here, a draft's included. One composer: the body
//! builders are `skep-identity`'s, as the daemon's verifier composes
//! through them (`skepd`'s `auth/entry.rs`), the slots AS STORED — an
//! address-form slot's unit spans, a V-spec slot's I-extents resolved
//! through `image`, as `skep-dev seed`'s link is — and a `publish`'s copied
//! runs by their values, READ BACK through the origin's arrangement under
//! the session's own token, a window by its address. A frame the composer
//! cannot make — a value it cannot read, a slot source it may not read, a
//! term it cannot spell — halts naming what stopped it, and nothing is
//! sent: the shell never sends a frame it could not sign. A death signal
//! met at one of those reads is no halt of the composer's but the
//! session's end ([`Unattested::Died`]), which its caller runs. The
//! wire's value forms, both ways, are `wire`'s: the composer spells a
//! frame's `values` and reads a delivery back through them, and faces what
//! they refuse as its own halt.
//!
//! THE BOARD's BUDGETS, KEPT AS THE BOARD KEEPS THEM. Every read the
//! composer makes is one a page's frame names, and every value it holds is
//! one a board answered, so each of its costs is held to the budget the
//! board's own parse, store or composer holds the same frame to — an array's
//! length ([`MAX_WIRE_LIST`]), a tumbler's components
//! ([`MAX_TUMBLER_COMPONENTS`]), an insert's values ([`MAX_INSERT_VALUES`]),
//! a slot's resolved spans ([`MAX_SLOT_SPANS`]), a shot's re-inserted values
//! ([`MAX_REINSERTED_VALUES`]) and its body ([`MAX_FRAME_BYTES`]) — each
//! counted BEFORE the work it bounds, a shot's whole arithmetic before its
//! first read. A frame past one is a frame the board refuses whatever it
//! carries, so the composer halts on it as on any frame it cannot make; no
//! budget here is one the board does not keep, so no frame the board takes
//! is refused for one.

use std::collections::HashMap;
use std::fmt;
use std::num::NonZeroU64;

use serde_json::{json, Value};
use skep_address::{Address, Nat, Span, Tumbler};
use skep_client::address::document_of;
use skep_client::board::{frames, Answer, Board, Rejection, Token, T_SUPERSEDES};
use skep_client::dial::MAX_ANSWER_BYTES;
use skep_client::halt::Halt;
use skep_client::sign::{sig_hex, Signer};
use skep_identity::{
    entry_body_assert_sup, entry_body_edit_link, entry_body_emit, entry_body_empty, entry_body_insert, entry_body_make_link,
    entry_body_make_link_replacing, entry_body_nullify, entry_frame, unit_span, BoardTerm, ContentFreeOp, DocTerm, EntryBody,
    EntrySlot, LinkSlots, PublishBody, PublishRefusal, ShotBase, SIG_ALGS,
};

use crate::refusal::{Name, Refusal};
use crate::wire::{bounded_address, delivered_values, values_of, within_components, ValuesFault, MAX_FRAME_BYTES, MAX_INSERT_VALUES, MAX_TUMBLER_COMPONENTS};

/// THE RETRACTION CLASS's reserved ghost tumbler — `[R]`, the fifth of the
/// format's five (`1.1.0.1.0.1.0.1.x`, x = 1..=5: pred_def, pred_stable,
/// retired, supersedes, retraction) — the type slot of the tuple a
/// `nullify` deposits, fixed by kind (`skep-links`'s `retraction_tuple`).
const T_RETRACTION: &str = "1.1.0.1.0.1.0.1.5";

/// The ten kinds, as the wire spells them.
const CHECKED_SET: [&str; 10] = ["create_new_document", "fork", "version", "insert", "publish", "make_link", "emit", "nullify", "assert_sup", "edit_link"];

/// The most elements one wire ARRAY may carry — skepd's codec's
/// `MAX_WIRE_LIST`, refused at the board's parse (`malformed`, the frame
/// unparsed: `op: unparseable`) whatever the array holds: a slot's
/// addresses, V-specs or spans, `emit`'s `to`, a shot's `runs`. The codec's
/// constant is private, so the suite pins this one by the board's
/// behaviour: a list at it parsed, one past it refused.
pub const MAX_WIRE_LIST: usize = 4096;

/// The most spans one link slot may resolve to — M7's `MAX_SLOT_SPANS`, the
/// per-slot budget the store charges a slot in whichever form, one span per
/// run a V-spec resolves to, refused `slot_too_large`: a number the frame
/// does not show, so the composer stops at the first span past it. Pinned
/// equal to M7's by the suite.
const MAX_SLOT_SPANS: usize = 4096;

/// The most values a shot may RE-INSERT — M5's `MAX_REINSERTED_VALUES`: the
/// staging draft's runs' widths, summed, refused by the store as
/// `too_many_values` by its request's arithmetic before a value is read
/// (wire.md §The publish shot). Pinned equal to M5's by the suite.
const MAX_REINSERTED_VALUES: u64 = 1 << 17;

/// The most positions a shot may COPY IN by value — the body budget's own
/// consequence and no number of its own: every value costs a shot's body at
/// least its four-byte length prefix (`PublishBody::push`), so a body within
/// [`MAX_FRAME_BYTES`] carries at most a quarter as many copied positions as
/// it has bytes, whatever they hold.
const MAX_COPIED_POSITIONS: u64 = (MAX_FRAME_BYTES / 4) as u64;

/// Whether `op` is one of the ten kinds that have an entry frame.
pub fn in_checked_set(op: &str) -> bool {
    CHECKED_SET.contains(&op)
}

/// Whether the shell composes an attest for `frame`: its op is one of the
/// ten kinds and no `attest` rides it already — a page-supplied attest is
/// left as it stands, the board's to judge, since the shell signs only what
/// it composed.
pub fn wants_attest(frame: &Value) -> bool {
    frame["op"].as_str().is_some_and(in_checked_set) && frame.get("attest").is_none()
}

/// The most bytes the attest this composer attaches adds to a frame: the
/// member `,"attest":{"alg":"…","sig":"…"}` at the longest algorithm token
/// and the longest signature, in hex, of the rows a key signs under
/// (`SIG_ALGS`) — the room a burst's frame keeps for the attest every send of
/// it under a signed session carries.
pub fn attest_room() -> usize {
    let token = SIG_ALGS.iter().map(|row| row.token.len()).max().unwrap_or(0);
    let sig = SIG_ALGS.iter().map(|row| row.sig_len()).max().unwrap_or(0);
    r#","attest":{"alg":"","sig":""}"#.len() + token + 2 * sig
}

/// The composer: the board the reads are made at under `token`, the key
/// that signs, the session's account, and the board term, `H.1`'s pair.
pub struct Composer<'a> {
    pub board: &'a Board,
    pub token: &'a Token,
    pub signer: &'a dyn Signer,
    pub account: &'a str,
    pub board_term: BoardTerm,
}

/// Why the composer attached no attest: the call's REFUSAL — its own halt
/// as `attest_not_composed`, a board's refusal of a read verbatim,
/// `unreachable` where a read went unanswered — or the session's DEATH
/// SIGNAL met at one of its reads, which is no refusal of the composer's:
/// the caller ends the session (`Sessions::end`) and answers
/// `session_died` with the reason the end derives.
#[derive(Debug)]
pub enum Unattested {
    /// The call's refusal: nothing was sent.
    Refused(Refusal),
    /// The death signal on the session's token, met at a read the composer
    /// made: nothing was sent.
    Died,
}

/// The composer's own halt named `attest_not_composed`; a halt of another
/// member — a board's refusal of a read, a read unanswered — carried as
/// that member.
impl From<Halt> for Unattested {
    fn from(h: Halt) -> Unattested {
        Unattested::Refused(Refusal::of_named(Name::ATTEST_NOT_COMPOSED, h))
    }
}

impl From<Refusal> for Unattested {
    fn from(r: Refusal) -> Unattested {
        Unattested::Refused(r)
    }
}

impl fmt::Display for Unattested {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unattested::Refused(r) => r.fmt(f),
            Unattested::Died => f.write_str("the session died at a read the attest's composer made"),
        }
    }
}

impl std::error::Error for Unattested {}

/// The frame's `doc` term, owned.
enum OwnedDocTerm {
    One(Address),
    Pair { d_s: Address, d_a: Address },
}

impl OwnedDocTerm {
    /// The term as [`entry_frame`] takes it: a view of this owned term.
    fn as_doc_term(&self) -> DocTerm<'_> {
        match self {
            OwnedDocTerm::One(a) => DocTerm::One(a),
            OwnedDocTerm::Pair { d_s, d_a } => DocTerm::Pair { d_s, d_a },
        }
    }
}

/// One run of a shot as its body takes it, in the shot's V-order: a COPIED
/// run by the I-addresses whose values it brings in — its origin, and the
/// prefix, first last component and width of its I-addresses — or a WINDOW
/// onto another document's I-space.
enum ShotPart<'f> {
    Copied { origin: &'f str, prefix: &'f str, first: u64, width: u64 },
    Window { start: Address, width: NonZeroU64 },
}

/// The positions a shot copies in from ONE origin document, WANTED: the
/// I-ranges of each I-address prefix the shot's runs name, gathered before
/// any read, so the read that follows holds the values the shot names and
/// never one per position the origin holds beside them. The read-back's
/// first phase of three, each a type of its own so no phase's step is taken
/// out of turn: [`Wanted::seal`] numbers the wanted positions and begins the
/// [`Reading`], whose [`Reading::finish`] answers the [`ReadBack`].
#[derive(Debug)]
struct Wanted<'f> {
    origin: &'f str,
    ranges: HashMap<&'f str, Vec<WantedRange>>,
}

/// The wanted I-ranges of each prefix, MERGED AND SORTED, each with the
/// INDEX its first position takes — a dense numbering of the wanted
/// positions. Made by [`Wanted::seal`] alone, so every lookup through it
/// stands on ranges its binary search can read.
#[derive(Debug)]
struct WantedIndex<'f>(HashMap<&'f str, Vec<WantedRange>>);

/// One origin's read under way: the wanted positions' index, a bit per
/// wanted position marking it read — never a stored value per position a
/// run's width claims, only one bit — and each read position's value kept
/// once, as an offset and a length in `bytes`.
#[derive(Debug)]
struct Reading<'f> {
    wanted: WantedIndex<'f>,
    seen: Vec<u64>,
    kept: Vec<Kept>,
    bytes: Vec<u8>,
}

/// One origin's values READ BACK: each kept value sorted by its index, for
/// [`ReadBack::value`] to find.
#[derive(Debug)]
struct ReadBack<'f> {
    wanted: WantedIndex<'f>,
    kept: Vec<Kept>,
    bytes: Vec<u8>,
}

/// One merged wanted I-range: its first position's last component, its
/// reach — one past its last position's — and the index its first position
/// takes.
#[derive(Debug, Clone, Copy)]
struct WantedRange {
    first: u64,
    reach: u64,
    index: u64,
}

/// One value read back: its index, and its offset and length in its read's
/// `bytes` — each under 2^32, the shot's positions and its kept bytes both
/// being held under [`MAX_FRAME_BYTES`].
#[derive(Debug, Clone, Copy)]
struct Kept {
    index: u32,
    offset: u32,
    len: u32,
}

fn fault(state: impl Into<String>, cause: impl Into<String>) -> Halt {
    Halt::face(state, cause, "this is the shell's frame and never your act; nothing was sent")
}

/// `text` as an address, or the halt a frame naming no address is.
fn addr(text: &str, what: &str) -> Result<Address, Halt> {
    bounded_address(text).ok_or_else(|| {
        fault(format!("the frame's `{what}` is not an address: `{text}`"), format!("the attest's frame names every address in its dotted spelling, at most {MAX_TUMBLER_COMPONENTS} components long"))
    })
}

/// The frame's member `name` as a string.
fn member<'f>(frame: &'f Value, name: &str) -> Result<&'f str, Halt> {
    frame[name].as_str().ok_or_else(|| fault(format!("the frame carries no `{name}`"), "the attest's grammar for this op names the member"))
}

/// The halt for a wire array past [`MAX_WIRE_LIST`] elements, which the
/// board's parse refuses `malformed` — asked before the first element is
/// read or resolved.
fn check_wire_list(list: &[Value], what: &str) -> Result<(), Halt> {
    if list.len() > MAX_WIRE_LIST {
        return Err(fault(format!("the frame's `{what}` lists {} elements, past the wire's {MAX_WIRE_LIST}", list.len()), "the board refuses a frame holding a longer array `malformed`, unparsed"));
    }
    Ok(())
}

/// `span` pushed onto a slot's spans, or the halt for a slot past
/// [`MAX_SLOT_SPANS`] — the store's `slot_too_large` — met at the first span
/// past it, as M7's own resolution meets it.
fn push_span(spans: &mut Vec<Span>, span: Span, what: &str) -> Result<(), Halt> {
    if spans.len() == MAX_SLOT_SPANS {
        return Err(fault(format!("the frame's `{what}` slot resolves to more than {MAX_SLOT_SPANS} spans"), "the board refuses such a slot `slot_too_large`, the store's per-slot budget"));
    }
    spans.push(span);
    Ok(())
}

/// The halt for what a shot's [`PublishBody`] refused.
fn body_refused(refusal: PublishRefusal) -> Halt {
    match refusal {
        PublishRefusal::PastBudget => fault(format!("the shot's body passes the board's {MAX_FRAME_BYTES}-byte budget"), "the board refuses such a shot `attestation_invalid:frame_too_large`"),
        PublishRefusal::Unspellable => fault("the shot places more than 2^64 − 1 positions", "a shot's count is eight bytes; the board refuses a longer one"),
    }
}

/// The halt for what [`values_of`] refused: a frame's `values` the
/// composer cannot spell as the entry body's value sequence.
fn values_refused(why: ValuesFault) -> Halt {
    match why {
        ValuesFault::NotAWireForm => fault("the frame's `values` are not the wire's forms", "a value is a string, `{\"hex\"}`, `{\"atom\"}` or `{\"atom_hex\"}`"),
        ValuesFault::PastBudget => fault(
            format!("the frame's `values` mint more than {MAX_INSERT_VALUES} values"),
            "the board refuses an insert past its value budget `malformed`, unparsed, whatever its values hold",
        ),
    }
}

/// THE TRUNK of a document-level address text: the address with its version
/// components dropped — the document field after the second `0` separator
/// kept to its first component (`1.0.1.0.1.2` → `1.0.1.0.1`); an element
/// address is taken to its document first. The projection
/// `skep-arrangement`'s `trunk_of` makes, reproduced over the spelling, of a
/// text within [`MAX_TUMBLER_COMPONENTS`] — counted before it is split.
fn trunk_text(text: &str) -> Option<String> {
    if !within_components(text) {
        return None;
    }
    let doc = document_of(text).unwrap_or_else(|| text.to_string());
    let comps: Vec<&str> = doc.split('.').collect();
    let mut zeros = comps.iter().enumerate().filter(|(_, c)| **c == "0").map(|(i, _)| i);
    let (_first, second) = (zeros.next()?, zeros.next()?);
    if zeros.next().is_some() || second + 1 >= comps.len() {
        return None;
    }
    Some(comps[..=second + 1].join("."))
}

/// A tumbler from its dotted decimal, within [`MAX_TUMBLER_COMPONENTS`] —
/// counted before a component is converted.
fn tumbler(text: &str) -> Option<Tumbler> {
    if !within_components(text) {
        return None;
    }
    let comps: Option<Vec<Nat>> = text.split('.').map(|c| c.parse::<u64>().ok().map(Nat::from)).collect();
    Tumbler::new(comps?).ok()
}

/// A stored content extent from a run as `image` answers it: the start's
/// own tumbler, and a width of zeros at every component but the last,
/// which holds the count (`skep-dev seed`'s `extent_span`).
fn extent_span(i_start: &str, width: u64) -> Option<Span> {
    let start = tumbler(i_start)?;
    let mut comps = vec![Nat::from(0u64); start.len()];
    *comps.last_mut()? = Nat::from(width);
    Span::new(start, Tumbler::new(comps).ok()?).ok()
}

/// An I-address split at its last component: the prefix, and the last
/// component as a number — the coordinate a run's positions advance along.
fn split_i(i_addr: &str) -> Option<(&str, u64)> {
    let (prefix, last) = i_addr.rsplit_once('.')?;
    Some((prefix, last.parse().ok()?))
}

/// THE `insert` ARM's TERMS, read off the frame alone — no read made: the
/// document's trunk, and the body over the declared deposit and the values,
/// each recognized as the board's parse recognizes it, within its budgets.
/// The composer's `insert` arm, and the hold's door for a burst a signed
/// session attests at every send (`hold`'s `Burst::admit`), which asks it
/// before the burst can be held: an insert the composer cannot attest is
/// one no resend of it could ever send.
pub fn insert_terms(frame: &Value) -> Result<(Address, EntryBody), Halt> {
    let doc = member(frame, "doc")?;
    let trunk = trunk_text(doc).ok_or_else(|| fault(format!("the frame's `doc` has no trunk: `{doc}`"), "an insert's doc term is the document's trunk"))?;
    let declared = frame["deposit"].as_str().map(|t| addr(t, "deposit")).transpose()?;
    let values = values_of(&frame["values"]).map_err(values_refused)?;
    Ok((addr(&trunk, "doc")?, entry_body_insert(declared.as_ref(), values.iter().map(AsRef::as_ref))))
}

/// One run of an `image` answer: its I-address's prefix and first last
/// component, and its width — the run's positions, `first` to `first +
/// width`, all spellable.
fn image_run<'v>(run: &'v Value, origin: &str) -> Result<(&'v str, u64, u64), Halt> {
    let bad = || fault(format!("a run `image` answered over {origin} is no I-extent"), run.to_string());
    let (prefix, first) = run["i_start"].as_str().and_then(split_i).ok_or_else(bad)?;
    let width: u64 = run["width"].as_str().and_then(|w| w.parse().ok()).ok_or_else(bad)?;
    first.checked_add(width).ok_or_else(bad)?;
    Ok((prefix, first, width))
}

impl<'f> Wanted<'f> {
    fn new(origin: &'f str) -> Wanted<'f> {
        Wanted { origin, ranges: HashMap::new() }
    }

    /// The run of `width` positions from `prefix.first` wanted. PRECONDITION:
    /// `first + width` is spellable, as [`Composer::publish_body`] has asked.
    fn want(&mut self, prefix: &'f str, first: u64, width: u64) {
        self.ranges.entry(prefix).or_default().push(WantedRange { first, reach: first + width, index: 0 });
    }

    /// THE READ BEGUN: the wanted ranges of each prefix merged and sorted,
    /// every wanted position given an index — under [`MAX_COPIED_POSITIONS`]
    /// in all, the widths summed having been held to it — and a bit to mark
    /// it read.
    fn seal(self) -> Reading<'f> {
        let mut ranges = self.ranges;
        let mut positions = 0u64;
        for prefix_ranges in ranges.values_mut() {
            prefix_ranges.sort_unstable_by_key(|r| r.first);
            let mut merged: Vec<WantedRange> = Vec::with_capacity(prefix_ranges.len());
            for r in prefix_ranges.drain(..) {
                match merged.last_mut() {
                    Some(last) if r.first <= last.reach => last.reach = last.reach.max(r.reach),
                    _ => merged.push(r),
                }
            }
            for r in &mut merged {
                r.index = positions;
                positions += r.reach - r.first;
            }
            *prefix_ranges = merged;
        }
        Reading { wanted: WantedIndex(ranges), seen: vec![0; positions.div_ceil(64) as usize], kept: Vec::new(), bytes: Vec::new() }
    }
}

impl WantedIndex<'_> {
    /// The index of the wanted position `prefix.n`, where one is wanted.
    fn index(&self, prefix: &str, n: u64) -> Option<u64> {
        let ranges = self.0.get(prefix)?;
        let r = ranges.get(ranges.partition_point(|r| r.reach <= n))?;
        (r.first <= n).then(|| r.index + (n - r.first))
    }
}

impl<'f> Reading<'f> {
    /// The value read at `prefix.n`, kept where the shot wants it and the
    /// first time it is read — and counted against `spent`, the body budget
    /// every origin's kept values share: a distinct value the shot copies in
    /// is one its body carries at least once, at its length and its
    /// four-byte prefix, so the kept values never pass [`MAX_FRAME_BYTES`].
    fn keep(&mut self, prefix: &str, n: u64, value: &[u8], spent: &mut usize) -> Result<(), Halt> {
        let Some(index) = self.wanted.index(prefix, n) else { return Ok(()) };
        let (word, bit) = ((index / 64) as usize, 1u64 << (index % 64));
        if self.seen[word] & bit != 0 {
            return Ok(());
        }
        self.seen[word] |= bit;
        *spent = spent.checked_add(4).and_then(|s| s.checked_add(value.len())).filter(|s| *s <= MAX_FRAME_BYTES).ok_or_else(|| body_refused(PublishRefusal::PastBudget))?;
        let to_u32 = |n: u64| u32::try_from(n).map_err(|_| body_refused(PublishRefusal::PastBudget));
        let kept = Kept { index: to_u32(index)?, offset: to_u32(self.bytes.len() as u64)?, len: to_u32(value.len() as u64)? };
        self.bytes.extend_from_slice(value);
        self.kept.push(kept);
        Ok(())
    }

    /// THE READ DONE: the kept values sorted by index, the marks of what was
    /// read let go.
    fn finish(self) -> ReadBack<'f> {
        let Reading { wanted, mut kept, bytes, .. } = self;
        kept.sort_unstable_by_key(|k| k.index);
        ReadBack { wanted, kept, bytes }
    }
}

impl ReadBack<'_> {
    /// The value read back at `prefix.n`, where the shot wants it and the
    /// origin holds it.
    fn value(&self, prefix: &str, n: u64) -> Option<&[u8]> {
        let index = u32::try_from(self.wanted.index(prefix, n)?).ok()?;
        let kept = self.kept[self.kept.binary_search_by_key(&index, |k| k.index).ok()?];
        let offset = kept.offset as usize;
        self.bytes.get(offset..offset + kept.len as usize)
    }
}

impl Composer<'_> {
    /// One READ under the session: the document; a rejection the board's
    /// refusal, verbatim; the death signal [`Unattested::Died`].
    fn read(&self, frame: &Value) -> Result<Value, Unattested> {
        match self.board.op(Some(self.token), frame)? {
            Answer::Closed => Err(Unattested::Died),
            Answer::Document(v) => match Rejection::of(&v) {
                Some(r) => Err(r.refused(&v).into()),
                None => Ok(v),
            },
        }
    }

    /// A slot's spans AS STORED: the address form's unit spans; a V-spec
    /// list's I-extents resolved through `image` — bare, as `make_link`'s
    /// slots spell it, or as `edit_link`'s successor `ty` spells it,
    /// `{"resolve": […]}` (wire.md §Links (writes)); or a span list verbatim
    /// (`emit`'s `ty`). The list within [`MAX_WIRE_LIST`] before its first
    /// element is read, and its spans within [`MAX_SLOT_SPANS`] as they
    /// resolve.
    fn slot(&self, slot: &Value, what: &str) -> Result<Vec<Span>, Unattested> {
        if let Some(addrs) = slot["addrs"].as_array() {
            check_wire_list(addrs, what)?;
            return addrs.iter().map(|a| Ok(unit_span(&addr(a.as_str().unwrap_or(""), what)?))).collect();
        }
        let Some(list) = slot["resolve"].as_array().or_else(|| slot.as_array()) else {
            return Err(
                fault(format!("the frame's `{what}` slot is neither the address form nor a list"), "a slot is `{\"addrs\": […]}`, `{\"resolve\": [V-specs]}`, a V-spec list, or a span list").into()
            );
        };
        check_wire_list(list, what)?;
        let mut spans = Vec::new();
        for item in list {
            if let Some(source) = item["source"].as_str() {
                let (from, width) = v_spec(&item["span"]).ok_or_else(|| fault(format!("the frame's `{what}` V-spec is not a content span"), "a V-spec's span is `{\"start\": \"1.<ordinal>\", \"width\": \"0.<width>\"}`"))?;
                let v = self.read(&frames::image(source, from, width))?;
                let runs = v["runs"].as_array().ok_or_else(|| fault("`image` answered no runs", v.to_string()))?;
                for r in runs {
                    let i_start = r["i_start"].as_str().unwrap_or("");
                    let w: u64 = r["width"].as_str().and_then(|w| w.parse().ok()).unwrap_or(0);
                    let span = extent_span(i_start, w).ok_or_else(|| fault("a run `image` answered is no content extent", r.to_string()))?;
                    push_span(&mut spans, span, what)?;
                }
            } else if let (Some(start), Some(width)) = (item["start"].as_str(), item["width"].as_str()) {
                let span = tumbler(start).zip(tumbler(width)).and_then(|(s, w)| Span::new(s, w).ok());
                push_span(&mut spans, span.ok_or_else(|| fault(format!("the frame's `{what}` span does not parse"), item.to_string()))?, what)?;
            } else {
                return Err(fault(format!("the frame's `{what}` slot holds an element of no known form"), item.to_string()).into());
            }
        }
        Ok(spans)
    }

    /// The values `wanted` names in its origin, READ BACK through the
    /// origin's own arrangement under the session's token: the extent,
    /// refused past what one delivery can carry (every position costs a
    /// delivery at least a byte); the V→I map through `image`, its widths
    /// summed to that extent before the values are asked for; and the
    /// values through `retrieve_v`, walked beside the map position by
    /// position, each position the shot copies in kept once against `spent`.
    fn read_back<'f>(&self, wanted: Wanted<'f>, spent: &mut usize) -> Result<ReadBack<'f>, Unattested> {
        let origin = wanted.origin;
        let mut reading = wanted.seal();
        let set = self.read(&frames::span_set(origin))?;
        let extent = set["set"]
            .as_array()
            .and_then(|s| s.iter().find(|x| x["start"].as_str() == Some("1.1")))
            .and_then(|s| s["width"].as_str()?.rsplit('.').next()?.parse::<u64>().ok())
            .unwrap_or(0);
        if extent > MAX_ANSWER_BYTES as u64 {
            return Err(fault(
                format!("{origin} holds {extent} positions, more than one delivery can carry"),
                format!("a delivery answers at most {MAX_ANSWER_BYTES} bytes, and every position costs it one at least"),
            )
            .into());
        }
        if extent > 0 {
            let image = self.read(&frames::image(origin, 1, extent))?;
            let runs = image["runs"].as_array().map(Vec::as_slice).unwrap_or_default();
            let mut mapped = 0u64;
            for run in runs {
                let (_, _, width) = image_run(run, origin)?;
                mapped = mapped.checked_add(width).filter(|m| *m <= extent).ok_or_else(|| disagree(origin, "maps more positions than its extent"))?;
            }
            if mapped != extent {
                return Err(disagree(origin, "maps fewer positions than its extent").into());
            }
            let delivery = self.read(&frames::retrieve_v(origin, 1, extent))?;
            let mut positions = delivered_values(&delivery);
            for run in runs {
                let (prefix, first, width) = image_run(run, origin)?;
                for n in first..first + width {
                    match positions.next() {
                        Some(Ok(value)) => reading.keep(prefix, n, &value, spent)?,
                        Some(Err(item)) => {
                            return Err(fault(
                                format!("a position of {origin} cannot be read back for the shot's body"),
                                format!("the delivery holds an item the composer cannot spell as values — a withheld run, a reference, a hex that does not decode, or one it does not know: {item}"),
                            )
                            .into())
                        }
                        None => return Err(disagree(origin, "is delivered short of its extent").into()),
                    }
                }
            }
            if positions.next().is_some() {
                return Err(disagree(origin, "is delivered past its extent").into());
            }
        }
        Ok(reading.finish())
    }

    /// The `publish` body, under the board's frame budget ([`MAX_FRAME_BYTES`],
    /// the parity the daemon holds a shot's body to): each run the shot names
    /// in V-order, a run onto the shot document's own trunk or the staging
    /// draft COPIED by its values, any other a WINDOW; then the base group.
    /// THE REQUEST's ARITHMETIC first, every run classed and counted before a
    /// value is read: the runs within [`MAX_WIRE_LIST`], the positions placed
    /// within the body's eight-byte count, the staging draft's within the
    /// store's re-insert budget, and the copied ones within what a body
    /// under the budget can carry. Then each origin's values read back,
    /// keeping the positions the shot copies in, and the body built.
    fn publish_body(&self, frame: &Value, trunk: &str) -> Result<EntryBody, Unattested> {
        let draft = frame["draft"].as_str();
        let draft_trunk = draft.and_then(trunk_text);
        let runs = frame["runs"].as_array().ok_or_else(|| fault("the shot names no `runs`", "a `publish` frame carries its runs in V-order"))?;
        check_wire_list(runs, "runs")?;
        let (mut placed, mut reinserted, mut copied) = (0u64, 0u64, 0u64);
        let mut parts: Vec<ShotPart<'_>> = Vec::with_capacity(runs.len());
        let mut origins: HashMap<&str, usize> = HashMap::new();
        let mut wants: Vec<Wanted<'_>> = Vec::new();
        for run in runs {
            let origin = member(run, "origin")?;
            let i_start = member(run, "i_start")?;
            let width = run["width"].as_str().and_then(|w| w.parse().ok()).and_then(NonZeroU64::new).ok_or_else(|| fault("a run's `width` is not a count of one or more", run.to_string()))?;
            placed = placed.checked_add(width.get()).ok_or_else(|| body_refused(PublishRefusal::Unspellable))?;
            let origin_trunk = trunk_text(origin);
            let draft_native = draft.is_some_and(|d| d == origin || draft_trunk.as_deref() == origin_trunk.as_deref());
            if origin_trunk.as_deref() == Some(trunk) || draft_native {
                let (prefix, first) = split_i(i_start)
                    .filter(|(_, first)| first.checked_add(width.get()).is_some())
                    .ok_or_else(|| fault("a copied run's `i_start` is no I-address its width can follow", run.to_string()))?;
                // Each a sum of some of the runs `placed` sums, so neither
                // passes it.
                copied += width.get();
                if draft_native {
                    reinserted += width.get();
                }
                let i = *origins.entry(origin).or_insert_with(|| {
                    wants.push(Wanted::new(origin));
                    wants.len() - 1
                });
                wants[i].want(prefix, first, width.get());
                parts.push(ShotPart::Copied { origin, prefix, first, width: width.get() });
            } else {
                parts.push(ShotPart::Window { start: addr(i_start, "runs[].i_start")?, width });
            }
        }
        if reinserted > MAX_REINSERTED_VALUES {
            return Err(fault(
                format!("the shot re-inserts {reinserted} values from its draft, past the store's {MAX_REINSERTED_VALUES}"),
                "the board refuses such a shot `too_many_values`, by its request's arithmetic",
            )
            .into());
        }
        if copied > MAX_COPIED_POSITIONS {
            return Err(fault(
                format!("the shot copies in {copied} positions, more than a body of {MAX_FRAME_BYTES} bytes can carry"),
                "every value a shot copies in costs its body four bytes at least; the board refuses a longer body",
            )
            .into());
        }
        let base_member = frame["base"].as_str().map(|b| addr(b, "base")).transpose()?;
        let base_extent: Option<u64> = frame["base_extent"].as_str().and_then(|e| e.parse().ok());
        let base = match (&base_member, base_extent) {
            (Some(member), Some(extent)) => Some(ShotBase { member, extent }),
            (None, None) => None,
            _ => return Err(fault("the shot names `base` without `base_extent`, or the reverse", "either both or neither (wire.md §The publish shot)").into()),
        };
        let mut spent = 0usize;
        let read_backs: Vec<ReadBack<'_>> = wants.into_iter().map(|wanted| self.read_back(wanted, &mut spent)).collect::<Result<_, _>>()?;
        let mut body = PublishBody::within(MAX_FRAME_BYTES, base).map_err(body_refused)?;
        for part in &parts {
            match part {
                ShotPart::Copied { origin, prefix, first, width } => {
                    let read_back = &read_backs[origins[origin]];
                    for n in *first..*first + *width {
                        let value = read_back.value(prefix, n).ok_or_else(|| {
                            fault(
                                format!("the shot copies in {prefix}.{n}, which {origin}'s arrangement does not hold"),
                                "a copied run's values are read back through its origin's own arrangement; a position outside it cannot be composed",
                            )
                        })?;
                        body = body.push(value).map_err(body_refused)?;
                    }
                }
                ShotPart::Window { start, width } => body = body.window(start, *width).map_err(body_refused)?,
            }
        }
        Ok(body.finish())
    }

    /// The frame's `doc` term and body, its kind one of the ten
    /// ([`Composer::attach`]'s precondition).
    fn doc_term_and_body(&self, frame: &Value) -> Result<(OwnedDocTerm, EntryBody), Unattested> {
        let one = |text: &str, what: &str| -> Result<OwnedDocTerm, Halt> { Ok(OwnedDocTerm::One(addr(text, what)?)) };
        Ok(match frame["op"].as_str() {
            Some("create_new_document") => (one(member(frame, "account")?, "account")?, entry_body_empty(ContentFreeOp::CreateNewDocument)),
            Some("fork") => (one(self.account, "account")?, entry_body_empty(ContentFreeOp::Fork)),
            Some("version") => (one(self.account, "account")?, entry_body_empty(ContentFreeOp::Version)),
            Some("insert") => {
                let (trunk, body) = insert_terms(frame)?;
                (OwnedDocTerm::One(trunk), body)
            }
            Some("make_link") => {
                let home = member(frame, "home")?;
                let (from, to, ty) = (self.slot(&frame["from"], "from")?, self.slot(&frame["to"], "to")?, self.slot(&frame["ty"], "ty")?);
                let slots = LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) };
                let body = match frame["replaces"].as_str() {
                    None => entry_body_make_link(slots),
                    Some(r) => entry_body_make_link_replacing(slots, &addr(r, "replaces")?),
                };
                (one(home, "home")?, body)
            }
            Some("emit") => {
                let home = member(frame, "home")?;
                let from = [unit_span(&addr(member(frame, "from")?, "from")?)];
                let to_list = frame["to"].as_array().map(Vec::as_slice).unwrap_or_default();
                check_wire_list(to_list, "to")?;
                let to: Vec<Span> = to_list.iter().map(|a| Ok(unit_span(&addr(a.as_str().unwrap_or(""), "to")?))).collect::<Result<_, Halt>>()?;
                let ty = self.slot(&frame["ty"], "ty")?;
                (one(home, "home")?, entry_body_emit(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) }))
            }
            Some("nullify") => {
                let home = member(frame, "home")?;
                let from = [unit_span(&addr(home, "home")?)];
                let to = [unit_span(&addr(member(frame, "target")?, "target")?)];
                let ty = [unit_span(&addr(T_RETRACTION, "retraction")?)];
                (one(home, "home")?, entry_body_nullify(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) }))
            }
            Some("assert_sup") => {
                let home = member(frame, "home")?;
                let from = [unit_span(&addr(member(frame, "old")?, "old")?)];
                let to = [unit_span(&addr(member(frame, "new")?, "new")?)];
                let ty = [unit_span(&addr(T_SUPERSEDES, "supersedes")?)];
                (one(home, "home")?, entry_body_assert_sup(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) }))
            }
            Some("edit_link") => {
                let successor = &frame["successor"];
                let (from, to, ty) = (self.slot(&successor["from"], "successor.from")?, self.slot(&successor["to"], "successor.to")?, self.slot(&successor["ty"], "successor.ty")?);
                let original = unit_span(&addr(member(frame, "original")?, "original")?);
                let body = entry_body_edit_link(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) }, &original);
                (OwnedDocTerm::Pair { d_s: addr(member(frame, "d_s")?, "d_s")?, d_a: addr(member(frame, "d_a")?, "d_a")? }, body)
            }
            Some("publish") => {
                let doc = member(frame, "doc")?;
                let trunk = trunk_text(doc).ok_or_else(|| fault(format!("the frame's `doc` has no trunk: `{doc}`"), "a publish's doc term is the document's trunk"))?;
                let body = self.publish_body(frame, &trunk)?;
                (one(&trunk, "doc")?, body)
            }
            _ => unreachable!("Composer::attach's precondition: wants_attest admitted the frame, its op one of the ten kinds"),
        })
    }

    /// THE ATTEST for `frame`: its entry frame composed, signed by the
    /// session's key and attached as the frame's `attest`. PRECONDITION, the
    /// caller's — discharged by `SessionEntry::attest` through
    /// [`wants_attest`]: the frame's op one of the ten kinds, no `attest`
    /// riding it; a frame outside it is a bug of this crate's, and `attach`
    /// panics naming the obligation.
    pub fn attach(&self, frame: &mut Value) -> Result<(), Unattested> {
        assert!(wants_attest(frame), "Composer::attach's precondition: wants_attest admitted the frame");
        let (doc_term, body) = self.doc_term_and_body(frame)?;
        let account = addr(self.account, "account")?;
        let alg = self.signer.public_key().alg();
        let bytes = entry_frame(alg, self.board_term, &account, doc_term.as_doc_term(), &body);
        frame["attest"] = json!({"alg": alg, "sig": sig_hex(&self.signer.sign(&bytes))});
        Ok(())
    }
}

/// The halt for an origin whose map and delivery disagree with its extent.
fn disagree(origin: &str, how: &str) -> Halt {
    fault(format!("{origin}'s arrangement {how}"), "an origin's image and its delivery each cover its extent, position for position")
}

/// A V-spec's span as `(from, width)` over the content subspace: `start`
/// `1.<ordinal>`, `width` `0.<count>`.
fn v_spec(span: &Value) -> Option<(u64, u64)> {
    let start = span["start"].as_str()?.strip_prefix("1.")?.parse().ok()?;
    let width = span["width"].as_str()?.strip_prefix("0.")?.parse().ok()?;
    Some((start, width))
}

#[cfg(test)]
mod tests;
