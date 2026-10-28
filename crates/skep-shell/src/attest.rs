//! The attest a signed session composes for every write of the checked set.
//!
//! The shell checks a write and signs where signed ops requires; as
//! `client.md` §4b.3 has it, the shell "signs only the entry frame of an op
//! it has checked, composing every axis of that frame itself — the `board`
//! term from its own read of the board it dials, the account from the
//! session — and never a preimage the page supplies". For a frame of the
//! ten kinds that have an entry frame ([`CheckedKind`]; wire.md §Credential
//! refusals) — `create_new_document`, `fork`, `version`, `insert`,
//! `publish`, `make_link`, `emit`, `nullify`, `assert_sup`, `edit_link` —
//! the attest is the entry frame under `H.1`'s pair, the session's account,
//! the frame's `doc` term and the body the kind's grammar spells, signed by
//! the session's key, attached as the frame's `attest` member. The wire's
//! own rule is to attach when in doubt: the publish class is the daemon's
//! classification, and an `attest` on a write outside it is dropped unread,
//! so every write of the ten kinds under a signed session is attested, a
//! draft's included — save a frame an `attest` already rides
//! ([`wants_attest`]) and a write at a board with no `H.1` to sign over
//! (`SessionEntry::attest`). One composer: the body builders are
//! `skep-identity`'s, as the daemon's verifier composes through them
//! (`skep-core`'s `auth/entry.rs`), the slots as stored — an address-form
//! slot's unit spans, a V-spec slot's I-extents resolved through `image`,
//! as `skep-dev seed`'s link is — and a `publish`'s copied runs by their
//! values, read back through the origin's arrangement under the session's
//! own token, a window by its address. A frame the composer cannot make — a
//! value it cannot read, a slot source it may not read, a term it cannot
//! spell — halts naming what stopped it, and nothing is sent: the shell
//! never sends a frame it could not sign. A death signal met at one of
//! those reads is no halt of the composer's but the session's end
//! ([`Unattested::Died`]), which its caller runs. The wire's value forms,
//! both ways, are `wire`'s: the composer spells a frame's `values` and
//! reads a delivery back through them, and faces what they refuse as its
//! own halt.
//!
//! **The board's budgets, kept as the board keeps them.** Every read the
//! composer makes is one a page's frame names, and every value it holds is
//! one a board answered, so each of its costs is held to the budget the
//! board's own parse, store or composer holds the same frame to — an array's
//! length ([`MAX_WIRE_LIST`]), a tumbler's components
//! ([`MAX_TUMBLER_COMPONENTS`]), an insert's values ([`MAX_INSERT_VALUES`]),
//! a slot's resolved spans ([`MAX_SLOT_SPANS`]), a shot's re-inserted values
//! ([`MAX_REINSERTED_VALUES`]) and its body ([`MAX_FRAME_BYTES`]) — each
//! counted before the work it bounds, a shot's whole arithmetic before its
//! first read. A frame past one is a frame the board refuses whatever it
//! carries, so the composer halts on it as on any frame it cannot make; no
//! budget here is one the board does not keep, so no frame the board takes
//! is refused for one.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::num::NonZeroU64;
use std::ops::Range;

use serde_json::{json, Value};
use skep_address::{Address, Nat, Span, Tumbler};
use skep_client::address::document_of;
use skep_client::board::{frames, Answer, Board, Rejection, Token, T_SUPERSEDES};
use skep_client::dial::MAX_ANSWER_BYTES;
use skep_client::halt::Halt;
use skep_client::sign::{sig_hex, Signer};
use skep_identity::{
    entry_body_assert_sup, entry_body_edit_link, entry_body_emit, entry_body_empty, entry_body_insert, entry_body_make_link,
    entry_body_make_link_replacing, entry_body_nullify, entry_body_publication, entry_frame, unit_span, BoardTerm, ContentFreeOp,
    DepositHome, DepositKind, DepositRow, DepositSlot, DocTerm, EntryBody, EntrySlot, LinkSlots, MemberPositions, PublishBody,
    PublishRefusal, ShotBase, SlotElement, SIG_ALGS,
};

use crate::refusal::{Name, Refusal};
use crate::wire::{bounded_address, delivered_values, values_of, within_components, ValuesFault, MAX_FRAME_BYTES, MAX_INSERT_VALUES, MAX_TUMBLER_COMPONENTS};

/// The retraction class's reserved ghost tumbler, `[R]`.
///
/// It is the fifth of the format's five (`1.1.0.1.0.1.0.1.x`, x = 1..=5:
/// pred_def, pred_stable, retired, supersedes, retraction) — the type slot
/// of the tuple a `nullify` deposits, fixed by kind (`skep-links`'s
/// `retraction_tuple`).
const T_RETRACTION: &str = "1.1.0.1.0.1.0.1.5";

/// A kind of the checked set: one of the ten that have an entry frame.
///
/// The ten (wire.md §Credential refusals) are read off a frame's op by
/// [`CheckedKind::named`] alone, so the composer's dispatch is one arm per
/// kind, which the compiler holds exhaustive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckedKind {
    CreateNewDocument,
    Fork,
    Version,
    Insert,
    Publish,
    MakeLink,
    Emit,
    Nullify,
    AssertSup,
    EditLink,
}

impl CheckedKind {
    /// The ten, in the wire's order.
    const ALL: [CheckedKind; 10] = [
        CheckedKind::CreateNewDocument,
        CheckedKind::Fork,
        CheckedKind::Version,
        CheckedKind::Insert,
        CheckedKind::Publish,
        CheckedKind::MakeLink,
        CheckedKind::Emit,
        CheckedKind::Nullify,
        CheckedKind::AssertSup,
        CheckedKind::EditLink,
    ];

    /// Returns the kind as the wire spells it.
    const fn as_str(self) -> &'static str {
        match self {
            CheckedKind::CreateNewDocument => "create_new_document",
            CheckedKind::Fork => "fork",
            CheckedKind::Version => "version",
            CheckedKind::Insert => "insert",
            CheckedKind::Publish => "publish",
            CheckedKind::MakeLink => "make_link",
            CheckedKind::Emit => "emit",
            CheckedKind::Nullify => "nullify",
            CheckedKind::AssertSup => "assert_sup",
            CheckedKind::EditLink => "edit_link",
        }
    }

    /// Returns the kind the wire spells `op`, where it is one of the ten.
    fn named(op: &str) -> Option<CheckedKind> {
        CheckedKind::ALL.into_iter().find(|kind| kind.as_str() == op)
    }
}

/// The most elements one wire array may carry: the codec's `MAX_WIRE_LIST`.
///
/// It is `skep-core`'s codec's constant, refused at the board's parse
/// (`malformed`, the frame unparsed: `op: unparseable`) whatever the array
/// holds: a slot's addresses, V-specs or spans, `emit`'s `to`, a shot's
/// `runs`. The codec's constant is private, so the suite pins this one by
/// the board's behaviour: a list at it parsed, one past it refused.
pub const MAX_WIRE_LIST: usize = 4096;

/// The most spans one link slot may resolve to: M7's `MAX_SLOT_SPANS`.
///
/// It is the per-slot budget the store charges a slot in whichever form,
/// one span per run a V-spec resolves to, refused `slot_too_large`: a
/// number the frame does not show, so the composer stops at the first span
/// past it. Pinned equal to M7's by the suite.
const MAX_SLOT_SPANS: usize = 4096;

/// The most values a shot may re-insert: M5's `MAX_REINSERTED_VALUES`.
///
/// It bounds the DISTINCT positions the staging draft's runs name — the
/// store mints each draft identity once per shot and places a later
/// occurrence by reference (the link-sets design §5.7) — refused by the
/// store as `too_many_values` by its request's arithmetic before a value is
/// read (wire.md §The publish shot). Pinned equal to M5's by the suite.
const MAX_REINSERTED_VALUES: u64 = 1 << 17;

/// The most positions a shot may copy in by value.
///
/// It is the body budget's own consequence and no number of its own: every
/// value costs a shot's body at least its four-byte length prefix
/// (`PublishBody::push`), so a body within [`MAX_FRAME_BYTES`] carries at
/// most a quarter as many copied positions as it has bytes, whatever they
/// hold.
const MAX_COPIED_POSITIONS: u64 = (MAX_FRAME_BYTES / 4) as u64;

/// Returns whether `op` is one of the ten kinds that have an entry frame.
pub fn in_checked_set(op: &str) -> bool {
    CheckedKind::named(op).is_some()
}

/// Returns the kind of `frame` the shell composes an attest for.
///
/// Its op is one of the ten, no `attest` riding it — the one reader of the
/// composer's precondition, which [`wants_attest`] and [`Composer::attach`]
/// share.
fn wanted_kind(frame: &Value) -> Option<CheckedKind> {
    frame["op"].as_str().and_then(CheckedKind::named).filter(|_| frame.get("attest").is_none())
}

/// Returns whether the shell composes an attest for `frame`.
///
/// It does where its op is one of the ten kinds and no `attest` rides it
/// already — a page-supplied attest is left as it stands, the board's to
/// judge, since the shell signs only what it composed.
pub fn wants_attest(frame: &Value) -> bool {
    wanted_kind(frame).is_some()
}

/// Returns the most bytes the attest this composer attaches adds to a frame.
///
/// It is the member `,"attest":{"alg":"…","sig":"…"}` at the longest
/// algorithm token and the longest signature, in hex, of the rows a key
/// signs under (`SIG_ALGS`) — the room a burst's frame keeps for the attest
/// every send of it under a signed session carries.
pub fn attest_room() -> usize {
    let token = SIG_ALGS.iter().map(|row| row.token.len()).max().unwrap_or(0);
    let sig = SIG_ALGS.iter().map(|row| row.sig_len()).max().unwrap_or(0);
    r#","attest":{"alg":"","sig":""}"#.len() + token + 2 * sig
}

/// The composer: a board, a token, a key, an account and the board term.
///
/// The reads are made at the board under `token`; the key is the one that
/// signs, the account the session's, and the board term `H.1`'s pair.
pub struct Composer<'a> {
    pub board: &'a Board,
    pub token: &'a Token,
    pub signer: &'a dyn Signer,
    pub account: &'a str,
    pub board_term: BoardTerm,
}

/// Why the composer attached no attest.
///
/// Either the call's refusal — its own halt, and the halt of the `H.1` read
/// it signs over, as `attest_not_composed`; `store_unreadable` where the
/// session's key file cannot be read and `no_account` where the board
/// answered the session none (`SessionEntry::attest`); a board's refusal of
/// a read verbatim; `unreachable` where a read went unanswered — or the
/// session's death signal met at one of its reads, which is no refusal of
/// the composer's: the caller ends the session (`Sessions::end`) and
/// answers `session_died` with the reason the end derives.
#[derive(Debug)]
pub enum Unattested {
    /// The call's refusal: nothing was sent.
    Refused(Refusal),
    /// The death signal on the session's token: nothing was sent.
    ///
    /// It was met at a read the composer made.
    Died,
}

/// The composer's own halt, named `attest_not_composed`.
///
/// A halt of another member — a board's refusal of a read, a read
/// unanswered — is carried as that member.
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
#[derive(Debug)]
enum OwnedDocTerm {
    One(Address),
    Pair { d_s: Address, d_a: Address },
}

impl OwnedDocTerm {
    /// Returns the term as [`entry_frame`] takes it: a view of this owned term.
    fn as_doc_term(&self) -> DocTerm<'_> {
        match self {
            OwnedDocTerm::One(a) => DocTerm::One(a),
            OwnedDocTerm::Pair { d_s, d_a } => DocTerm::Pair { d_s, d_a },
        }
    }
}

/// An I-range as the composer counts it.
///
/// It holds the I-addresses `prefix.first` up to, not including,
/// `prefix.reach` — a run `image` answers, or one a shot copies in, its
/// `i_start` split at its last component ([`split_i`]) and its width added.
/// Made by [`IRange::new`] alone, where the reach is spellable, so every
/// walk of its positions stands on one bound, asked once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IRange<'a> {
    prefix: &'a str,
    first: u64,
    reach: u64,
}

impl<'a> IRange<'a> {
    /// Returns the `width` positions from `prefix.first`.
    ///
    /// They are a range where `first + width` is spellable; none where it is
    /// not.
    fn new(prefix: &'a str, first: u64, width: u64) -> Option<IRange<'a>> {
        Some(IRange { prefix, first, reach: first.checked_add(width)? })
    }

    /// Returns the last components of its positions, in order.
    fn positions(self) -> Range<u64> {
        self.first..self.reach
    }

    /// Returns how many positions it holds.
    fn width(self) -> u64 {
        self.reach - self.first
    }
}

/// Returns how many distinct positions `ranges` name, merging them in place.
///
/// It is the count the store holds a shot's re-insert to: the ranges sorted
/// by prefix then first position, each walked against the reach the merge
/// holds for its prefix, so a position two ranges name counts once and a
/// range inside an earlier one adds nothing. `O(n log n)` in the ranges.
fn distinct_positions(ranges: &mut [IRange<'_>]) -> u64 {
    ranges.sort_by(|a, b| a.prefix.cmp(b.prefix).then(a.first.cmp(&b.first)));
    let mut count = 0u64;
    let mut held: Option<(&str, u64)> = None; // the prefix and the reach merged so far
    for range in ranges.iter() {
        let reach = match held {
            Some((prefix, reach)) if prefix == range.prefix => reach,
            _ => range.first,
        };
        let from = range.first.max(reach);
        if range.reach > from {
            count += range.reach - from;
        }
        held = Some((range.prefix, range.reach.max(reach)));
    }
    count
}

/// One run of a shot as its body takes it, in the shot's V-order.
///
/// It is a copied run, by the I-range whose values it brings in and its
/// origin, or a window onto another document's I-space.
#[derive(Debug)]
enum ShotPart<'f> {
    Copied { origin: &'f str, range: IRange<'f> },
    Window { start: Address, width: NonZeroU64 },
}

/// The positions a shot copies in from one origin document, wanted.
///
/// It holds the I-ranges of each I-address prefix the shot's runs name,
/// gathered before any read, so the read that follows holds the values the
/// shot names and never one per position the origin holds beside them. It
/// is the read-back's first phase of three, each a type of its own so no
/// phase's step is taken out of turn: [`Wanted::seal`] numbers the wanted
/// positions and begins the [`Reading`], whose [`Reading::finish`] answers
/// the [`ReadBack`].
#[derive(Debug)]
struct Wanted<'f> {
    origin: &'f str,
    ranges: HashMap<&'f str, Vec<WantedRange>>,
}

/// The wanted I-ranges of each prefix, merged and sorted, each indexed.
///
/// Each takes the index its first position takes — a dense numbering of
/// the wanted positions. Made by [`Wanted::seal`] alone, so every lookup
/// through it stands on ranges its binary search can read.
#[derive(Debug)]
struct WantedIndex<'f>(HashMap<&'f str, Vec<WantedRange>>);

/// One origin's read under way.
///
/// It holds the wanted positions' index, a bit per wanted position marking
/// it read — never a stored value per position a run's width claims, only
/// one bit — and each read position's value kept once, as an offset and a
/// length in `bytes`.
#[derive(Debug)]
struct Reading<'f> {
    wanted: WantedIndex<'f>,
    seen: Vec<u64>,
    kept: Vec<Kept>,
    bytes: Vec<u8>,
}

/// One origin's values read back, each kept value sorted by its index.
///
/// They are sorted for [`ReadBack::value`] to find.
#[derive(Debug)]
struct ReadBack<'f> {
    wanted: WantedIndex<'f>,
    kept: Vec<Kept>,
    bytes: Vec<u8>,
}

/// One merged wanted I-range.
///
/// It holds its first position's last component, its reach — one past its
/// last position's — and the index its first position takes.
#[derive(Debug, Clone, Copy)]
struct WantedRange {
    first: u64,
    reach: u64,
    index: u64,
}

/// One value read back: its index, offset and length in its read's `bytes`.
///
/// Each is under 2^32, the shot's positions and its kept bytes both being
/// held under [`MAX_FRAME_BYTES`].
#[derive(Debug, Clone, Copy)]
struct Kept {
    index: u32,
    offset: u32,
    len: u32,
}

fn fault(state: impl Into<String>, cause: impl Into<String>) -> Halt {
    Halt::face(state, cause, "this is the shell's frame and never your act; nothing was sent")
}

/// Returns `text` as an address.
///
/// # Errors
///
/// Returns the halt a frame naming no address is, where `text` is no dotted
/// address within [`MAX_TUMBLER_COMPONENTS`] components.
fn addr(text: &str, what: &str) -> Result<Address, Halt> {
    bounded_address(text).ok_or_else(|| {
        fault(format!("the frame's `{what}` is not an address: `{text}`"), format!("the attest's frame names every address in its dotted spelling, at most {MAX_TUMBLER_COMPONENTS} components long"))
    })
}

/// Returns the frame's member `name` as a string.
///
/// # Errors
///
/// Returns a halt where the frame carries no string `name`.
fn member<'f>(frame: &'f Value, name: &str) -> Result<&'f str, Halt> {
    frame[name].as_str().ok_or_else(|| fault(format!("the frame carries no `{name}`"), "the attest's grammar for this op names the member"))
}

/// Checks a wire array against [`MAX_WIRE_LIST`].
///
/// It is asked before the first element is read or resolved.
///
/// # Errors
///
/// Returns the halt for an array past [`MAX_WIRE_LIST`] elements, which the
/// board's parse refuses `malformed`.
fn check_wire_list(list: &[Value], what: &str) -> Result<(), Halt> {
    if list.len() > MAX_WIRE_LIST {
        return Err(fault(format!("the frame's `{what}` lists {} elements, past the wire's {MAX_WIRE_LIST}", list.len()), "the board refuses a frame holding a longer array `malformed`, unparsed"));
    }
    Ok(())
}

/// Pushes `span` onto a slot's spans.
///
/// # Errors
///
/// Returns the halt for a slot past [`MAX_SLOT_SPANS`] — the store's
/// `slot_too_large` — met at the first span past it, as M7's own resolution
/// meets it.
fn push_span(spans: &mut Vec<Span>, span: Span, what: &str) -> Result<(), Halt> {
    if spans.len() == MAX_SLOT_SPANS {
        return Err(fault(format!("the frame's `{what}` slot resolves to more than {MAX_SLOT_SPANS} spans"), "the board refuses such a slot `slot_too_large`, the store's per-slot budget"));
    }
    spans.push(span);
    Ok(())
}

/// Returns the halt for what a shot's [`PublishBody`] refused.
fn body_refused(refusal: PublishRefusal) -> Halt {
    match refusal {
        PublishRefusal::PastBudget => fault(format!("the shot's body passes the board's {MAX_FRAME_BYTES}-byte budget"), "the board refuses such a shot `attestation_invalid:frame_too_large`"),
        PublishRefusal::Unspellable => fault("the shot places more than 2^64 − 1 positions", "a shot's count is eight bytes; the board refuses a longer one"),
    }
}

/// Returns the halt for what [`values_of`] refused.
///
/// That is a frame's `values` the composer cannot spell as the entry body's
/// value sequence.
fn values_refused(why: ValuesFault) -> Halt {
    match why {
        ValuesFault::NotAWireForm => fault("the frame's `values` are not the wire's forms", "a value is a string, `{\"hex\"}`, `{\"atom\"}` or `{\"atom_hex\"}`"),
        ValuesFault::PastBudget => fault(
            format!("the frame's `values` mint more than {MAX_INSERT_VALUES} values"),
            "the board refuses an insert past its value budget `malformed`, unparsed, whatever its values hold",
        ),
    }
}

/// Returns the trunk of a document-level address text.
///
/// The trunk is the address with its version components dropped — the
/// document field after the second `0` separator kept to its first
/// component (`1.0.1.0.1.2` → `1.0.1.0.1`); an element address is taken to
/// its document first. It is the projection `skep-arrangement`'s `trunk_of`
/// makes, reproduced over the spelling, of a text within
/// [`MAX_TUMBLER_COMPONENTS`] — counted before it is split.
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

/// Returns a tumbler from its dotted decimal within [`MAX_TUMBLER_COMPONENTS`].
///
/// The components are counted before one is converted.
fn tumbler(text: &str) -> Option<Tumbler> {
    if !within_components(text) {
        return None;
    }
    let comps: Option<Vec<Nat>> = text.split('.').map(|c| c.parse::<u64>().ok().map(Nat::from)).collect();
    Tumbler::new(comps?).ok()
}

/// Returns a stored content extent from a run as `image` answers it.
///
/// It is the start's own tumbler, and a width of zeros at every component
/// but the last, which holds the count (`skep-dev seed`'s `extent_span`).
fn extent_span(i_start: &str, width: u64) -> Option<Span> {
    let start = tumbler(i_start)?;
    let mut comps = vec![Nat::from(0u64); start.len()];
    *comps.last_mut()? = Nat::from(width);
    Span::new(start, Tumbler::new(comps).ok()?).ok()
}

/// Splits an I-address at its last component.
///
/// It answers the prefix, and the last component as a number — the
/// coordinate a run's positions advance along.
fn split_i(i_addr: &str) -> Option<(&str, u64)> {
    let (prefix, last) = i_addr.rsplit_once('.')?;
    Some((prefix, last.parse().ok()?))
}

/// Returns the `insert` arm's terms, read off the frame alone.
///
/// No read is made: the terms are the document's trunk, and the body over
/// the declared deposit and the values, each recognized as the board's
/// parse recognizes it, within its budgets. They are the composer's
/// `insert` arm, and what the burst's door (`hold`'s `Burst::admit`) asks
/// of an insert a signed session attests at every send, before the burst
/// can be held: an insert the composer cannot attest is one no resend of it
/// could ever send.
///
/// # Errors
///
/// Returns a halt where the frame carries no `doc`, where its `doc` has no
/// trunk or its `deposit` is no address, and where its `values` are not the
/// wire's forms or mint past [`MAX_INSERT_VALUES`].
pub fn insert_terms(frame: &Value) -> Result<(Address, EntryBody), Halt> {
    let doc = member(frame, "doc")?;
    let trunk = trunk_text(doc).ok_or_else(|| fault(format!("the frame's `doc` has no trunk: `{doc}`"), "an insert's doc term is the document's trunk"))?;
    let declared = frame["deposit"].as_str().map(|t| addr(t, "deposit")).transpose()?;
    let values = values_of(&frame["values"]).map_err(values_refused)?;
    Ok((addr(&trunk, "doc")?, entry_body_insert(declared.as_ref(), values.iter().map(AsRef::as_ref))))
}

/// Returns one run of an `image` answer as the I-range it maps.
///
/// Its `i_start` is split at its last component and its width added, the
/// reach spellable.
///
/// # Errors
///
/// Returns a halt where the run is no I-extent: its `i_start` or its
/// `width` unreadable, or its reach unspellable.
fn image_run<'v>(run: &'v Value, origin: &str) -> Result<IRange<'v>, Halt> {
    let bad = || fault(format!("a run `image` answered over {origin} is no I-extent"), run.to_string());
    let (prefix, first) = run["i_start"].as_str().and_then(split_i).ok_or_else(bad)?;
    let width: u64 = run["width"].as_str().and_then(|w| w.parse().ok()).ok_or_else(bad)?;
    IRange::new(prefix, first, width).ok_or_else(bad)
}

impl<'f> Wanted<'f> {
    fn new(origin: &'f str) -> Wanted<'f> {
        Wanted { origin, ranges: HashMap::new() }
    }

    /// Adds the positions of `range` to those wanted.
    fn want(&mut self, range: IRange<'f>) {
        self.ranges.entry(range.prefix).or_default().push(WantedRange { first: range.first, reach: range.reach, index: 0 });
    }

    /// Begins the read, every wanted position given an index.
    ///
    /// The wanted ranges of each prefix are merged and sorted, every wanted
    /// position given an index — under [`MAX_COPIED_POSITIONS`] in all, the
    /// widths summed having been held to it — and a bit to mark it read.
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
    /// Returns the index of the position `prefix.n`, where it is wanted.
    fn index(&self, prefix: &str, n: u64) -> Option<u64> {
        let ranges = self.0.get(prefix)?;
        let r = ranges.get(ranges.partition_point(|r| r.reach <= n))?;
        (r.first <= n).then(|| r.index + (n - r.first))
    }
}

impl<'f> Reading<'f> {
    /// Keeps the value read at `prefix.n`, where the shot wants it.
    ///
    /// It is kept the first time it is read — and counted against `spent`,
    /// the body budget every origin's kept values share: a distinct value the
    /// shot copies in is one its body carries at least once, at its length
    /// and its four-byte prefix, so the kept values never pass
    /// [`MAX_FRAME_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns the halt for a shot's body past its budget where the value
    /// would take the kept values past [`MAX_FRAME_BYTES`].
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

    /// Finishes the read, the kept values sorted by index.
    ///
    /// The marks of what was read are let go.
    fn finish(self) -> ReadBack<'f> {
        let Reading { wanted, mut kept, bytes, .. } = self;
        kept.sort_unstable_by_key(|k| k.index);
        ReadBack { wanted, kept, bytes }
    }
}

impl ReadBack<'_> {
    /// Returns the value read back at `prefix.n`.
    ///
    /// It answers one where the shot wants it and the origin holds it.
    fn value(&self, prefix: &str, n: u64) -> Option<&[u8]> {
        let index = u32::try_from(self.wanted.index(prefix, n)?).ok()?;
        let kept = self.kept[self.kept.binary_search_by_key(&index, |k| k.index).ok()?];
        let offset = kept.offset as usize;
        self.bytes.get(offset..offset + kept.len as usize)
    }
}

impl Composer<'_> {
    /// Makes one read under the session, answering the document.
    ///
    /// # Errors
    ///
    /// Returns a rejection as the board's refusal, verbatim; the death signal
    /// as [`Unattested::Died`]; and a halt of the read as its member — a
    /// refused exchange the board's refusal, the block `blocked`, a read
    /// unanswered `unreachable`, the library's own halt
    /// `attest_not_composed`.
    fn read(&self, frame: &Value) -> Result<Value, Unattested> {
        match self.board.op(Some(self.token), frame)? {
            Answer::Closed => Err(Unattested::Died),
            Answer::Document(v) => match Rejection::of(&v) {
                Some(r) => Err(r.refused(&v).into()),
                None => Ok(v),
            },
        }
    }

    /// Returns a slot's spans as stored.
    ///
    /// They are the address form's unit spans; a V-spec list's I-extents
    /// resolved through `image` — bare, as `make_link`'s slots spell it, or
    /// as `edit_link`'s successor `ty` spells it, `{"resolve": […]}` (wire.md
    /// §Links (writes)); or a span list verbatim (`emit`'s `ty`). The list is
    /// held within [`MAX_WIRE_LIST`] before its first element is read, and
    /// its spans within [`MAX_SLOT_SPANS`] as they resolve.
    ///
    /// # Errors
    ///
    /// Returns a halt where the slot is of neither form, its list passes
    /// [`MAX_WIRE_LIST`], an address, a V-spec's span or a span does not
    /// parse, an element is of no known form, `image` answers no runs or a
    /// run that is no content extent, or the spans pass [`MAX_SLOT_SPANS`];
    /// and whatever an `image` read refuses ([`Composer::read`]).
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

    /// Reads back `wanted`'s values through the origin's own arrangement.
    ///
    /// The read is made under the session's token: the extent, refused past
    /// what one delivery can carry (every position costs a delivery at least
    /// a byte); the V→I map through `image`, its widths summed to that extent
    /// before the values are asked for; and the values through `retrieve_v`,
    /// walked beside the map position by position, each position the shot
    /// copies in kept once against `spent`.
    ///
    /// # Errors
    ///
    /// Returns a halt where the extent passes [`MAX_ANSWER_BYTES`] positions,
    /// a run of the map is no I-extent, the map or the delivery disagrees
    /// with the extent, a position cannot be read back as values, or the
    /// kept values pass [`MAX_FRAME_BYTES`]; and whatever a read refuses
    /// ([`Composer::read`]).
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
                let width = image_run(run, origin)?.width();
                mapped = mapped.checked_add(width).filter(|m| *m <= extent).ok_or_else(|| disagree(origin, "maps more positions than its extent"))?;
            }
            if mapped != extent {
                return Err(disagree(origin, "maps fewer positions than its extent").into());
            }
            let delivery = self.read(&frames::retrieve_v(origin, 1, extent))?;
            let mut positions = delivered_values(&delivery);
            for run in runs {
                let range = image_run(run, origin)?;
                for n in range.positions() {
                    match positions.next() {
                        Some(Ok(value)) => reading.keep(range.prefix, n, &value, spent)?,
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

    /// Returns the `publish` body, under the board's frame budget.
    ///
    /// The budget is [`MAX_FRAME_BYTES`], the parity the daemon holds a
    /// shot's body to. The body holds each run the shot names in V-order, a
    /// run onto the shot document's own trunk or the staging draft copied by
    /// its values, any other a window; then the base group.
    ///
    /// # Errors
    ///
    /// The request's arithmetic comes first, every run classed and counted
    /// before a value is read: the runs within [`MAX_WIRE_LIST`], the
    /// positions placed within the body's eight-byte count, the staging
    /// draft's within the store's re-insert budget, and the copied ones
    /// within what a body under the budget can carry — a halt past each, and
    /// for a shot that names no `runs` or a run whose member, count or
    /// I-address does not read. Then `base` and `base_extent` are read, both
    /// or neither. Then each origin's values are read back
    /// ([`Composer::read_back`]), keeping the positions the shot copies in,
    /// and the body is built — a halt for a copied position its origin's
    /// arrangement does not hold, and for a body past the budget.
    fn publish_body(&self, frame: &Value, trunk: &str) -> Result<EntryBody, Unattested> {
        let draft = frame["draft"].as_str();
        let draft_trunk = draft.and_then(trunk_text);
        let runs = frame["runs"].as_array().ok_or_else(|| fault("the shot names no `runs`", "a `publish` frame carries its runs in V-order"))?;
        check_wire_list(runs, "runs")?;
        let (mut placed, mut copied) = (0u64, 0u64);
        // The draft-native ranges, for the distinct count the store holds
        // to its budget: merged once every run is read.
        let mut draft_ranges: Vec<IRange<'_>> = Vec::new();
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
                let range = split_i(i_start)
                    .and_then(|(prefix, first)| IRange::new(prefix, first, width.get()))
                    .ok_or_else(|| fault("a copied run's `i_start` is no I-address its width can follow", run.to_string()))?;
                // A sum of some of the runs `placed` sums, so it never
                // passes it.
                copied += width.get();
                if draft_native {
                    draft_ranges.push(range);
                }
                let i = *origins.entry(origin).or_insert_with(|| {
                    wants.push(Wanted::new(origin));
                    wants.len() - 1
                });
                wants[i].want(range);
                parts.push(ShotPart::Copied { origin, range });
            } else {
                parts.push(ShotPart::Window { start: addr(i_start, "runs[].i_start")?, width });
            }
        }
        // The distinct positions the draft-native runs name, as the store
        // counts them: the ranges of each prefix merged, each position once
        // however many runs name it.
        let reinserted = distinct_positions(&mut draft_ranges);
        if reinserted > MAX_REINSERTED_VALUES {
            return Err(fault(
                format!("the shot re-inserts {reinserted} distinct values from its draft, past the store's {MAX_REINSERTED_VALUES}"),
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
                ShotPart::Copied { origin, range } => {
                    let read_back = &read_backs[origins[origin]];
                    for n in range.positions() {
                        let value = read_back.value(range.prefix, n).ok_or_else(|| {
                            fault(
                                format!("the shot copies in {}.{n}, which {origin}'s arrangement does not hold", range.prefix),
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

    /// Returns whether a retraction of `target` stands on the board — the
    /// skip the board's plan decides for a `retract` entry: a tuple of the
    /// retraction class whose `to` names the target, read by `find_links_ftt`.
    ///
    /// # Errors
    ///
    /// Returns whatever the read refuses ([`Composer::read`]).
    fn retraction_stands(&self, target: &str) -> Result<bool, Unattested> {
        let v = self.read(&frames::find_links_ftt(T_RETRACTION, target))?;
        Ok(v["addrs"].as_array().is_some_and(|hits| !hits.is_empty()))
    }

    /// Returns whether a read-with from `edition` to `set` stands in a
    /// PUBLISHED home the session's account owns — the skip the board's plan
    /// decides for a `read_with` entry at the document form: the rows the
    /// three slots match, each kept where its stored `from` and `to` are
    /// exactly the two unit spans, its home's ω the account's and its home
    /// published.
    ///
    /// # Errors
    ///
    /// Returns whatever a read refuses ([`Composer::read`]).
    fn read_with_stands(&self, edition: &str, set: &str) -> Result<bool, Unattested> {
        let q = json!({"op": "find_links_ftt", "q": {"home": "any", "from": frames::unit_span(edition), "to": frames::unit_span(set), "ty": frames::unit_span(T_READ_WITH)}});
        let v = self.read(&q)?;
        let hits: Vec<String> = v["addrs"].as_array().map(|hits| hits.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default();
        for hit in hits {
            let Some(home) = home_of_link(&hit) else { continue };
            let link = self.read(&frames::read_link(&hit))?;
            let exact = |slot: usize, start: &str| {
                let spans = link["link"]["slots"][slot].as_array();
                spans.is_some_and(|s| s.len() == 1) && link["link"]["slots"][slot][0]["start"].as_str() == Some(start)
            };
            if !(exact(0, edition) && exact(1, set)) {
                continue;
            }
            let owner = self.read(&frames::effective_owner(home))?;
            if owner["prefix"].as_str() != Some(self.account) {
                continue;
            }
            let meta = self.read(&frames::doc_metadata(home))?;
            if meta["published"].as_bool() == Some(true) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Returns the deposit rows of a `publish` frame (the link-sets design
    /// §5.7's signed entry), as the board's composer spells them from its
    /// plan: per home in the signed order — the member by tag, then a minted
    /// edition, then every other home in address order — the edition claim
    /// (`claim: true` with `mint`: `from` the edition by tag, `to` the
    /// `draft`), the copies (`links`, in order: the type slot as stored, each
    /// end as spelled), the retractions (`retract`, in order, each homed in
    /// its target's document) and the read-withs (`read_with`, in order,
    /// each homed in its set, `from` the edition — the trunk, or the tag at
    /// the mint form). The two skips the plan decides are read off the board
    /// ([`Composer::retraction_stands`], [`Composer::read_with_stands`]) and
    /// the skipped entries' rows left out, so the body signed is the body
    /// the board composes. A frame carrying no deposit composes no row and
    /// makes no read.
    ///
    /// # Errors
    ///
    /// Returns a halt where a list passes [`MAX_WIRE_LIST`], an entry lacks
    /// a member or names what does not parse, or `claim` names no `draft`;
    /// and whatever a read refuses ([`Composer::read`]).
    fn deposit_rows(&self, frame: &Value) -> Result<Vec<OwnedRow>, Unattested> {
        let mints = frame["mint"].as_bool().unwrap_or(false);
        let claims = frame["claim"].as_bool().unwrap_or(false);
        let trunk = frame["doc"].as_str().and_then(trunk_text);
        let empty = Vec::new();
        let list = |name: &str| -> Result<&Vec<Value>, Halt> {
            let list = frame[name].as_array().unwrap_or(&empty);
            check_wire_list(list, name)?;
            Ok(list)
        };
        let mut homes: BTreeMap<OwnedHome, Vec<OwnedRow>> = BTreeMap::new();
        let mut push = |home: OwnedHome, kind, ty, from, to| {
            homes.entry(home.clone()).or_default().push(OwnedRow { home, kind, ty, from, to });
        };
        if claims && mints {
            let draft = addr(member(frame, "draft")?, "draft")?;
            push(OwnedHome::Edition, DepositKind::EditionClaim, OwnedSlot::unit(&addr(T_EDITION, "edition type")?), OwnedSlot::Stored(vec![OwnedElement::Edition]), OwnedSlot::unit(&draft));
        }
        for entry in list("links")? {
            let home = match member(entry, "home")? {
                "member" => OwnedHome::Member,
                "edition" => OwnedHome::Edition,
                text => OwnedHome::Addr(addr(text, "links[].home")?),
            };
            push(home, DepositKind::Copy, deposit_end(&entry["ty"], "links[].ty")?, deposit_end(&entry["from"], "links[].from")?, deposit_end(&entry["to"], "links[].to")?);
        }
        for target in list("retract")? {
            let target = target.as_str().ok_or_else(|| fault("the frame's `retract` names an entry that is no address", target.to_string()))?;
            if self.retraction_stands(target)? {
                continue;
            }
            let home = home_of_link(target).ok_or_else(|| fault(format!("the frame's `retract` entry is no link address: `{target}`"), "a link address lies in its home's link subspace, `<home>.0.2.<n>`"))?;
            let home = addr(home, "retract[]")?;
            push(OwnedHome::Addr(home.clone()), DepositKind::Retraction, OwnedSlot::unit(&addr(T_RETRACTION, "retraction type")?), OwnedSlot::unit(&home), OwnedSlot::unit(&addr(target, "retract[]")?));
        }
        for set in list("read_with")? {
            let set = set.as_str().ok_or_else(|| fault("the frame's `read_with` names an entry that is no address", set.to_string()))?;
            if let Some(trunk) = &trunk {
                if self.read_with_stands(trunk, set)? {
                    continue;
                }
            }
            let from = match &trunk {
                Some(trunk) => OwnedSlot::unit(&addr(trunk, "doc")?),
                None => OwnedSlot::Stored(vec![OwnedElement::Edition]),
            };
            push(OwnedHome::Addr(addr(set, "read_with[]")?), DepositKind::ReadWith, OwnedSlot::unit(&addr(T_READ_WITH, "read-with type")?), from, OwnedSlot::unit(&addr(set, "read_with[]")?));
        }
        Ok(homes.into_values().flatten().collect())
    }

    /// Returns the frame's `doc` term and body, as its `kind` spells them.
    ///
    /// # Errors
    ///
    /// Returns a halt where the frame lacks a member its kind's grammar names
    /// or names an address the composer cannot spell, and whatever
    /// [`insert_terms`], [`Composer::slot`], [`Composer::publish_body`] and
    /// [`Composer::deposit_rows`] refuse.
    fn doc_term_and_body(&self, kind: CheckedKind, frame: &Value) -> Result<(OwnedDocTerm, EntryBody), Unattested> {
        let one = |text: &str, what: &str| -> Result<OwnedDocTerm, Halt> { Ok(OwnedDocTerm::One(addr(text, what)?)) };
        Ok(match kind {
            CheckedKind::CreateNewDocument => (one(member(frame, "account")?, "account")?, entry_body_empty(ContentFreeOp::CreateNewDocument)),
            CheckedKind::Fork => (one(self.account, "account")?, entry_body_empty(ContentFreeOp::Fork)),
            CheckedKind::Version => (one(self.account, "account")?, entry_body_empty(ContentFreeOp::Version)),
            CheckedKind::Insert => {
                let (trunk, body) = insert_terms(frame)?;
                (OwnedDocTerm::One(trunk), body)
            }
            CheckedKind::MakeLink => {
                let home = member(frame, "home")?;
                let (from, to, ty) = (self.slot(&frame["from"], "from")?, self.slot(&frame["to"], "to")?, self.slot(&frame["ty"], "ty")?);
                let slots = LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) };
                let body = match frame["replaces"].as_str() {
                    None => entry_body_make_link(slots),
                    Some(r) => entry_body_make_link_replacing(slots, &addr(r, "replaces")?),
                };
                (one(home, "home")?, body)
            }
            CheckedKind::Emit => {
                let home = member(frame, "home")?;
                let from = [unit_span(&addr(member(frame, "from")?, "from")?)];
                let to_list = frame["to"].as_array().map(Vec::as_slice).unwrap_or_default();
                check_wire_list(to_list, "to")?;
                let to: Vec<Span> = to_list.iter().map(|a| Ok(unit_span(&addr(a.as_str().unwrap_or(""), "to")?))).collect::<Result<_, Halt>>()?;
                let ty = self.slot(&frame["ty"], "ty")?;
                (one(home, "home")?, entry_body_emit(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) }))
            }
            CheckedKind::Nullify => {
                let home = member(frame, "home")?;
                let from = [unit_span(&addr(home, "home")?)];
                let to = [unit_span(&addr(member(frame, "target")?, "target")?)];
                let ty = [unit_span(&addr(T_RETRACTION, "retraction")?)];
                (one(home, "home")?, entry_body_nullify(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) }))
            }
            CheckedKind::AssertSup => {
                let home = member(frame, "home")?;
                let from = [unit_span(&addr(member(frame, "old")?, "old")?)];
                let to = [unit_span(&addr(member(frame, "new")?, "new")?)];
                let ty = [unit_span(&addr(T_SUPERSEDES, "supersedes")?)];
                (one(home, "home")?, entry_body_assert_sup(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) }))
            }
            CheckedKind::EditLink => {
                let successor = &frame["successor"];
                let (from, to, ty) = (self.slot(&successor["from"], "successor.from")?, self.slot(&successor["to"], "successor.to")?, self.slot(&successor["ty"], "successor.ty")?);
                let original = unit_span(&addr(member(frame, "original")?, "original")?);
                let body = entry_body_edit_link(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) }, &original);
                (OwnedDocTerm::Pair { d_s: addr(member(frame, "d_s")?, "d_s")?, d_a: addr(member(frame, "d_a")?, "d_a")? }, body)
            }
            CheckedKind::Publish => {
                let term = publish_term(frame)?;
                let shot = self.publish_body(frame, &term)?;
                let rows = self.deposit_rows(frame)?;
                let rows: Vec<DepositRow<'_>> = rows.iter().map(OwnedRow::borrow).collect();
                (one(&term, "doc")?, entry_body_publication(shot, &rows))
            }
        })
    }

    /// Attaches the attest for `frame`, signed by the session's key.
    ///
    /// Its entry frame is composed, signed by the session's key and attached
    /// as the frame's `attest`.
    ///
    /// # Errors
    ///
    /// Returns [`Unattested::Died`] where a read the composer made met the
    /// session's death signal, and [`Unattested::Refused`] for a frame it
    /// cannot compose ([`Composer::read`], [`Composer::doc_term_and_body`])
    /// or whose session's account is no address.
    ///
    /// # Panics
    ///
    /// Panics where its precondition, the caller's, is broken — discharged
    /// by `SessionEntry::attest` through [`wants_attest`]: the frame's op one
    /// of the ten kinds, no `attest` riding it; a frame outside it is a bug of
    /// this crate's, and `attach` panics naming the obligation.
    pub fn attach(&self, frame: &mut Value) -> Result<(), Unattested> {
        let kind = wanted_kind(frame).expect("Composer::attach's precondition: wants_attest admitted the frame");
        let (doc_term, body) = self.doc_term_and_body(kind, frame)?;
        let account = addr(self.account, "account")?;
        let alg = self.signer.public_key().alg();
        let bytes = entry_frame(alg, self.board_term, &account, doc_term.as_doc_term(), &body);
        frame["attest"] = json!({"alg": alg, "sig": sig_hex(&self.signer.sign(&bytes))});
        Ok(())
    }
}

/// Returns a `publish` frame's `doc` term (the link-sets design §5.7): the
/// trunk of `doc` at the document form, the `account` at the mint form —
/// `mint: true` with `account` and no `doc`.
///
/// # Errors
///
/// Returns a halt where the frame is of neither form — `doc` beside `mint`,
/// `account` without it, neither member, `claim` without `mint` — or where
/// its `doc` has no trunk.
fn publish_term(frame: &Value) -> Result<String, Halt> {
    let mint = frame["mint"].as_bool().unwrap_or(false);
    let claim = frame["claim"].as_bool().unwrap_or(false);
    match (frame["doc"].as_str(), frame["account"].as_str(), mint) {
        (Some(doc), None, false) => {
            if claim {
                return Err(fault("the frame carries `claim` without `mint`", "a claim into an edition the request does not mint is not admitted in this build"));
            }
            trunk_text(doc).ok_or_else(|| fault(format!("the frame's `doc` has no trunk: `{doc}`"), "a publish's doc term is the document's trunk"))
        }
        (None, Some(account), true) => Ok(account.to_string()),
        _ => Err(fault("the frame names neither `doc` alone nor `account` with `mint`", "a publish is the document form or the mint form (wire.md §Arrangement)")),
    }
}

/// The home of a deposit's rows, as the signed entry orders homes: the
/// member by tag, then the edition, then every address in address order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum OwnedHome {
    Member,
    Edition,
    Addr(Address),
}

/// One element of a deposit's slot row, owned ahead of the builder's borrow.
#[derive(Debug, Clone)]
enum OwnedElement {
    Span(Span),
    Member,
    Edition,
}

/// One slot of a deposit's rows, owned: as stored, or the member positions.
#[derive(Debug, Clone)]
enum OwnedSlot {
    Stored(Vec<OwnedElement>),
    Member(Vec<MemberPositions>),
}

/// One deposit's rows, owned — [`DepositRow`]'s owning twin.
#[derive(Debug, Clone)]
struct OwnedRow {
    home: OwnedHome,
    kind: DepositKind,
    ty: OwnedSlot,
    from: OwnedSlot,
    to: OwnedSlot,
}

impl OwnedSlot {
    fn unit(a: &Address) -> OwnedSlot {
        OwnedSlot::Stored(vec![OwnedElement::Span(unit_span(a))])
    }

    fn borrow(&self) -> DepositSlot<'_> {
        match self {
            OwnedSlot::Stored(elements) => DepositSlot::Stored(
                elements
                    .iter()
                    .map(|e| match e {
                        OwnedElement::Span(s) => SlotElement::Span(s),
                        OwnedElement::Member => SlotElement::Member,
                        OwnedElement::Edition => SlotElement::Edition,
                    })
                    .collect(),
            ),
            OwnedSlot::Member(spans) => DepositSlot::MemberPositions(spans.clone()),
        }
    }
}

impl OwnedRow {
    fn borrow(&self) -> DepositRow<'_> {
        let home = match &self.home {
            OwnedHome::Member => DepositHome::Member,
            OwnedHome::Edition => DepositHome::Edition,
            OwnedHome::Addr(a) => DepositHome::Address(a),
        };
        DepositRow { home, kind: self.kind, ty: self.ty.borrow(), from: self.from.borrow(), to: self.to.borrow() }
    }
}

/// Returns one end of a `links` entry as the body spells it: the address
/// form's elements — a tag as the tag, an address as its unit span — the
/// I-span form's spans verbatim, the member-position form's row as spelled.
///
/// # Errors
///
/// Returns a halt where the end is of no form, or an element does not read.
fn deposit_end(end: &Value, what: &str) -> Result<OwnedSlot, Halt> {
    if let Some(addrs) = end["addrs"].as_array() {
        check_wire_list(addrs, what)?;
        let elements = addrs
            .iter()
            .map(|a| match a.as_str() {
                Some("member") => Ok(OwnedElement::Member),
                Some("edition") => Ok(OwnedElement::Edition),
                Some(text) => Ok(OwnedElement::Span(unit_span(&addr(text, what)?))),
                None => Err(fault(format!("the frame's `{what}` names an element that is no address"), a.to_string())),
            })
            .collect::<Result<Vec<_>, Halt>>()?;
        return Ok(OwnedSlot::Stored(elements));
    }
    if let Some(spans) = end["spans"].as_array() {
        check_wire_list(spans, what)?;
        let elements = spans
            .iter()
            .map(|s| {
                let width: u64 = s["width"].as_str().and_then(|w| w.parse().ok()).ok_or_else(|| fault(format!("the frame's `{what}` span has no width"), s.to_string()))?;
                let span = s["start"].as_str().and_then(|start| extent_span(start, width)).ok_or_else(|| fault(format!("the frame's `{what}` span does not parse"), s.to_string()))?;
                Ok(OwnedElement::Span(span))
            })
            .collect::<Result<Vec<_>, Halt>>()?;
        return Ok(OwnedSlot::Stored(elements));
    }
    if let Some(positions) = end["member"].as_array() {
        check_wire_list(positions, what)?;
        let rows = positions
            .iter()
            .map(|p| {
                let number = |k: &str| p[k].as_str().and_then(|n| n.parse::<u64>().ok()).ok_or_else(|| fault(format!("the frame's `{what}` member span has no `{k}`"), p.to_string()));
                Ok(MemberPositions { ordinal: number("ordinal")?, width: number("width")? })
            })
            .collect::<Result<Vec<_>, Halt>>()?;
        return Ok(OwnedSlot::Member(rows));
    }
    Err(fault(format!("the frame's `{what}` end is of no form"), "an end is `{\"addrs\": […]}`, `{\"spans\": […]}` or `{\"member\": […]}` (wire.md §Arrangement, `publish`)"))
}

/// Returns the document a link address is homed in: the text before its
/// `.0.2.`.
fn home_of_link(link: &str) -> Option<&str> {
    link.rfind(".0.2.").map(|idx| &link[..idx])
}

/// The read-with type and the edition-claim type, as the board spells them.
const T_READ_WITH: &str = "1.1.0.1.0.1.0.3.71";
const T_EDITION: &str = "1.1.0.1.0.1.0.3.14";

/// Returns the halt where map and delivery disagree with an origin's extent.
fn disagree(origin: &str, how: &str) -> Halt {
    fault(format!("{origin}'s arrangement {how}"), "an origin's image and its delivery each cover its extent, position for position")
}

/// Returns a V-spec's span as `(from, width)` over the content subspace.
///
/// Its `start` is `1.<ordinal>` and its `width` `0.<count>`.
fn v_spec(span: &Value) -> Option<(u64, u64)> {
    let start = span["start"].as_str()?.strip_prefix("1.")?.parse().ok()?;
    let width = span["width"].as_str()?.strip_prefix("0.")?.parse().ok()?;
    Some((start, width))
}

#[cfg(test)]
mod tests;
