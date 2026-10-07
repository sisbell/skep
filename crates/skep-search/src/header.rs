//! The file's HEADER (`search.md` §5.1; §1.4's `save` and `load`): the typed
//! [`Header`] the embedder composes and hands `save`, and `load` hands back —
//! `board`, `floor`, the PER-RANGE RECORDS and the newest head's `H.k` — and
//! the HEADER LINE, the file's first line: ONE JSON OBJECT in the key file's
//! conventions (`client.md` §3.2 — members in one order, no whitespace
//! outside strings, lowercase hex, a `v`, no other member, one `\n` after the
//! brace), written by [`encode`] and read by [`parse`], the crate's ONE
//! canonical parser. Of the `Header`'s members, `board` and `floor` go on the
//! line; the range records and the head's pair go into a body section (the
//! `file` module), so the line stays one line of the file's own facts under
//! the CRC. The line's other members are the INDEX's own — `kind` and
//! `principal` from its class, `tokenizer` from the running revision — and
//! `body`, the body's length in bytes, which `save` computes.
//!
//! ```text
//! {"type":"skep-index","v":1,"board":"<64 hex>","kind":"published","floor":<F|null>,"tokenizer":"<revision>","body":<bytes>}
//! {"type":"skep-index","v":1,"board":"<64 hex>","kind":"supplement","principal":<n>,"floor":<F|null>,"tokenizer":"<revision>","body":<bytes>}
//! ```
//!
//! THE ONE SPELLING, READ CANONICALLY (§5.1; PATTERNS P35, P38): `parse`
//! reads `v` FIRST — a `v` above 1 is [`HeaderError::NewerVersion`], "written
//! by a newer skep", before any other member is judged, so an older skep
//! never calls a newer skep's header damaged — then, under `v = 1`, admits
//! the line only where `b == encode(parse(b))`, P35's form: a member out of
//! its order, a space, an uppercase hex digit, a second spelling of a number,
//! a missing newline are each [`HeaderError::Damaged`], and a member this
//! crate does not know is [`HeaderError::UnknownMember`], named. No JSON crate
//! reads it (§1.3): the object's members are written and read by the bounded
//! code below, the key file's writer applied to one line.

use std::fmt;
use std::fmt::Write as _;

use skep_address::Address;

use crate::token::Revision;
use crate::unit::Class;

/// A commit chain's value — the 64 lowercase hex `/health` serves as
/// `chain_head` and `GET /chain?at=<position>` serves as `chain` (wire.md §The
/// other endpoints): `H.1`'s names the board and its directory (§5.2;
/// `client.md` §4e.4), a range's `held` pair fixes a position by one (§5.1).
/// Thirty-two bytes, so it has one spelling: lowercase on the way out, and
/// lowercase alone on the way in.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Chain([u8; 32]);

impl Chain {
    /// The chain from its 64 lowercase hex; `None` for any other text — an
    /// uppercase digit, a shorter or longer run, a character outside hex.
    pub fn parse(text: &str) -> Option<Chain> {
        let bytes = text.as_bytes();
        if bytes.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (slot, pair) in out.iter_mut().zip(bytes.chunks(2)) {
            *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Some(Chain(out))
    }

    /// The chain from its thirty-two bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Chain {
        Chain(bytes)
    }

    /// The thirty-two bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

impl fmt::Display for Chain {
    /// The 64 lowercase hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Chain({self})")
    }
}

/// A `(position, chain)` pair (§5.1, §5.4): `/health`'s `(log_position,
/// chain_head)`, read off one kernel snapshot before a draining poll, or
/// `/chain?at=<position>`'s answer — the pair a range's `held` is fixed as,
/// and the pair an `H.k` record names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChainAt {
    /// The board position.
    pub position: u64,
    /// The chain's value as of that position.
    pub chain: Chain,
}

/// The typed header the EMBEDDER composes (§5.1, §1.4): what `save` takes
/// beside the index and `load` hands back beside it, written in one file with
/// the body and parsed by the one reader, so the shell reads `board` and
/// `held` off `load` and parses no line of its own. `board` and `floor` go on
/// the header line; the range records and the head's pair go into a body
/// section. `kind`, `principal` and `tokenizer` are NOT here: they are the
/// index's own, set by `new`, read at `load`, written by `save` from the
/// `Index` alone (sweep-2 lampson `header-holds-the-crates-facts`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The board's key: `H.1`'s chain (§5.2 D7 (β)), the directory's name.
    pub board: Chain,
    /// The reclaim floor the consumer last saw, so the file states its own
    /// completeness (§5.4); `None` where no answer has carried one.
    pub floor: Option<u64>,
    /// The per-range records (§4 WIDEN, §5.1): the published index's one
    /// range, the board; a supplement's one per widened range.
    pub ranges: Vec<RangeRecord>,
    /// The newest head member `H.k` the feed delivered at or below `held`,
    /// with the `(position, chain)` its record names (§5.4; ITEM 1 (a)'s
    /// first rider) — the below-floor check's input; `None` before the feed
    /// has delivered one.
    pub head: Option<HeadRecord>,
}

/// One range's record (§5.1's body; §4 WIDEN; §5.4): what a restart keeps
/// beside the range's `held` — every recorded refusal and the bare-row count
/// — and, for a granted range, the cell's keys the `Held` standing is
/// composed from (§3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeRecord {
    /// The prefix the widening named as `under=` — an account's or a
    /// document's; `None` for the board's whole feed, the published index's
    /// one range. The range's shape yields the rung (§3.1: by document or by
    /// account); the grant below carries the kind and the issuer.
    pub under: Option<Address>,
    /// The consumer's last-held position for this range, as a `(position,
    /// chain)` pair (§5.1): the `/health` pair read before the draining poll
    /// that indexed everything at or below it, or `/chain?at`'s answer where
    /// no poll fenced the save.
    pub held: ChainAt,
    /// The RETRY-ABLE refusals recorded beside the range (§4): a `withheld`
    /// rejection, `too_many_items` on a part — each naming the document and
    /// its reason, retried at the next widening over it. The ceiling's
    /// refusals are counted in `seen` and listed nowhere; a transport error
    /// records nothing.
    pub refusals: Vec<Refusal>,
    /// The BARE ROWS counted against this range (§5.4): changes the feed
    /// could not name a document for, so `complete` is withheld while the
    /// count stands and a REFRESH of the range clears it.
    pub bare_rows: u64,
    /// For a granted range, the grant's kind and issuer (§3.1, §5.1), written
    /// when the widening added the range; `None` for the board's feed and
    /// for the subtree's own and ancestors' ranges, which are never `Held`.
    pub grant: Option<Grant>,
}

/// A refusal recorded beside a range (§4): the document and the reason the
/// board gave, as the shell spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The document whose read was refused.
    pub doc: Address,
    /// The reason — the wire's word, kept as the shell's string.
    pub reason: String,
}

/// A granted range's cell keys (§3.1; PUB-5.115's KIND × RUNG split): the
/// kind, and the issuer the departure face names; the rung is the range's
/// own shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Named, or any-principal.
    pub kind: GrantKind,
    /// The grant's issuer.
    pub issuer: Address,
}

/// The kind of a grant (§3.1, R90): to a named principal, or to any.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrantKind {
    /// A grant to a named principal.
    Named,
    /// An any-principal grant.
    AnyPrincipal,
}

/// The newest head member `H.k` the feed delivered (§5.4): its address and
/// the `(position, chain)` its pinned record names — "pinned forever", and it
/// "survives reclamation as checkpoint state" (wire.md §The other endpoints),
/// so the shell re-reads it where `/chain?at=<held>` answers
/// `history_reclaimed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadRecord {
    /// The head member's address, `H.k`.
    pub member: Address,
    /// The pair its record names.
    pub at: ChainAt,
}

/// The header LINE's facts (§5.1), as [`parse`] reads them and as
/// [`Parsed::encode`] writes them: the `Header`'s two line members, the
/// index's three, and the body's length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// `board`: the board's chain.
    pub board: Chain,
    /// `kind`, and `principal` for a supplement: the index's class.
    pub class: Class,
    /// `floor`: the reclaim floor, or `null`.
    pub floor: Option<u64>,
    /// `tokenizer`: the revision the index was cut under.
    pub tokenizer: Revision,
    /// `body`: the body's length in bytes, the trailer not counted.
    pub body: u64,
}

/// A header line's refusal (§5.1; P38): what the parser found, each the
/// fact a disposition names — a newer version is FACED, the other two are
/// DAMAGED and the file is rebuilt (§5.4). Non-exhaustive: the next format
/// version brings refusals of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderError {
    /// `v` above 1: "this index was written by a newer skep than this one",
    /// never "not an index" (the key file's rule, `client.md` §3.2); judged
    /// before any other member.
    NewerVersion {
        /// The version the line names.
        v: u64,
    },
    /// A member this crate does not know, at the file's own `v`.
    UnknownMember {
        /// The member's name.
        name: String,
    },
    /// Any other spelling than the one `save` writes — or no header line at
    /// all; `what` says which check refused it.
    Damaged {
        /// The check that refused the line.
        what: &'static str,
    },
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderError::NewerVersion { v } => {
                write!(f, "this index was written by a newer skep than this one (v {v})")
            }
            HeaderError::UnknownMember { name } => {
                write!(f, "the header names a member this skep does not know: `{name}`")
            }
            HeaderError::Damaged { what } => write!(f, "the header line is damaged: {what}"),
        }
    }
}

impl std::error::Error for HeaderError {}

/// The header line's one spelling (§5.1; `client.md` §3.2), from the
/// `Header`'s line members, the index's class and revision, and the body's
/// length: members in the order the module doc shows, no whitespace outside
/// strings, hex lowercase, one `\n` after the brace. `save` calls this and
/// nothing else writes the line.
pub fn encode(header: &Header, class: Class, tokenizer: Revision, body: u64) -> Vec<u8> {
    Parsed { board: header.board, class, floor: header.floor, tokenizer, body }.encode()
}

impl Parsed {
    /// The line in its one spelling: `encode`'s bytes for these facts.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = String::from("{\"type\":\"skep-index\",\"v\":1,\"board\":\"");
        write!(out, "{}\",\"kind\":", self.board).expect("a String takes every write");
        match self.class {
            Class::Guest => out.push_str("\"published\""),
            Class::Principal(n) => {
                write!(out, "\"supplement\",\"principal\":{n}").expect("a String takes every write")
            }
        }
        out.push_str(",\"floor\":");
        match self.floor {
            None => out.push_str("null"),
            Some(floor) => write!(out, "{floor}").expect("a String takes every write"),
        }
        write!(out, ",\"tokenizer\":\"{}\",\"body\":{}}}\n", self.tokenizer, self.body)
            .expect("a String takes every write");
        out.into_bytes()
    }
}

/// THE ONE CANONICAL PARSER (§5.1; P35, P38) over a header line, its `\n`
/// included. `v` is read FIRST: the version member is found and its integer
/// read before any other member is judged, and a `v` above 1 answers
/// [`HeaderError::NewerVersion`] whatever follows it. Under `v = 1` the
/// members are walked — a member this crate does not know answers
/// [`HeaderError::UnknownMember`] by name — and the line is admitted only
/// where `b == encode(parse(b))`: every other spelling is
/// [`HeaderError::Damaged`].
pub fn parse(line: &[u8]) -> Result<Parsed, HeaderError> {
    let v = version_first(line)?;
    if v > 1 {
        return Err(HeaderError::NewerVersion { v });
    }
    if v == 0 {
        return Err(damaged("`v` is 0, a version no skep wrote"));
    }
    let mut cursor = Cursor { line, at: 0 };
    cursor.expect(b"{", "the line does not open an object")?;
    let mut members = Members::default();
    loop {
        let key = cursor.key()?;
        match key {
            b"type" => {
                if cursor.string()? != b"skep-index" {
                    return Err(damaged("`type` is not `skep-index`"));
                }
                set(&mut members.typed, ())?;
            }
            b"v" => {
                if cursor.integer()? != 1 {
                    return Err(damaged("`v` is not 1"));
                }
                set(&mut members.versioned, ())?;
            }
            b"board" => {
                let text = std::str::from_utf8(cursor.string()?)
                    .map_err(|_| damaged("`board` is not 64 lowercase hex"))?;
                let chain = Chain::parse(text).ok_or(damaged("`board` is not 64 lowercase hex"))?;
                set(&mut members.board, chain)?;
            }
            b"kind" => {
                let supplement = match cursor.string()? {
                    b"published" => false,
                    b"supplement" => true,
                    _ => return Err(damaged("`kind` is neither `published` nor `supplement`")),
                };
                set(&mut members.supplement, supplement)?;
            }
            b"principal" => {
                let n = cursor.integer()?;
                set(&mut members.principal, n)?;
            }
            b"floor" => {
                let floor = if cursor.take(b"null") { None } else { Some(cursor.integer()?) };
                set(&mut members.floor, floor)?;
            }
            b"tokenizer" => {
                let revision = revision(cursor.string()?)
                    .ok_or(damaged("`tokenizer` is not `<rule>/<major>.<minor>.<update>`"))?;
                set(&mut members.tokenizer, revision)?;
            }
            b"body" => {
                let body = cursor.integer()?;
                set(&mut members.body, body)?;
            }
            name => {
                return Err(HeaderError::UnknownMember {
                    name: String::from_utf8_lossy(name).into_owned(),
                })
            }
        }
        if cursor.take(b",") {
            continue;
        }
        cursor.expect(b"}\n", "the object does not close with `}` and one `\\n`")?;
        break;
    }
    if cursor.at != line.len() {
        return Err(damaged("bytes follow the line's `\\n`"));
    }
    let parsed = members.parsed()?;
    // P35: the bytes `save` writes and no other spelling — the one compare
    // that holds the member order and every spelling the walk above admits.
    if parsed.encode() != line {
        return Err(damaged("another spelling than the one `save` writes"));
    }
    Ok(parsed)
}

fn damaged(what: &'static str) -> HeaderError {
    HeaderError::Damaged { what }
}

/// `v` FIRST (§5.1): the version member — the first `"v":` at a member
/// boundary — and the canonical integer after it, read before any other
/// member is judged. A run of digits past `u64` is above 1 for certain and
/// saturates, so it is faced and never called damage.
fn version_first(line: &[u8]) -> Result<u64, HeaderError> {
    const KEY: &[u8] = b"\"v\":";
    let mut from = 0;
    while let Some(found) = line.get(from..).and_then(|rest| find(rest, KEY)) {
        let at = from + found;
        if at > 0 && matches!(line[at - 1], b'{' | b',') {
            let digits = &line[at + KEY.len()..];
            let run = digits.iter().take_while(|b| b.is_ascii_digit()).count();
            if run == 0 || (run > 1 && digits[0] == b'0') {
                return Err(damaged("`v` is not a canonical integer"));
            }
            let text = std::str::from_utf8(&digits[..run]).expect("ASCII digits");
            return Ok(text.parse::<u64>().unwrap_or(u64::MAX));
        }
        from = at + 1;
    }
    Err(damaged("no `v` member"))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// A canonical non-negative integer at the start of `bytes` — `0`, or a
/// digit 1–9 and digits after it, within `u64` — and the bytes after it.
fn integer(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let run = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    if run == 0 || (run > 1 && bytes[0] == b'0') {
        return None;
    }
    let value = std::str::from_utf8(&bytes[..run]).ok()?.parse::<u64>().ok()?;
    Some((value, &bytes[run..]))
}

/// `tokenizer`'s text, `Revision`'s own spelling: `<rule>/<major>.<minor>.<update>`,
/// each a canonical integer, the rule within `u32`.
fn revision(text: &[u8]) -> Option<Revision> {
    let (rule, rest) = integer(text)?;
    let rule = u32::try_from(rule).ok()?;
    let (major, rest) = integer(rest.strip_prefix(b"/")?)?;
    let (minor, rest) = integer(rest.strip_prefix(b".")?)?;
    let (update, rest) = integer(rest.strip_prefix(b".")?)?;
    rest.is_empty().then_some(Revision { rule, unicode: (major, minor, update) })
}

/// The walk's position in the line.
struct Cursor<'a> {
    line: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    /// `literal` consumed where it stands here.
    fn take(&mut self, literal: &[u8]) -> bool {
        if self.line[self.at..].starts_with(literal) {
            self.at += literal.len();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, literal: &[u8], what: &'static str) -> Result<(), HeaderError> {
        if self.take(literal) {
            Ok(())
        } else {
            Err(damaged(what))
        }
    }

    /// `"name":` — the member's name.
    fn key(&mut self) -> Result<&'a [u8], HeaderError> {
        let name = self.string()?;
        self.expect(b":", "a member name is not followed by `:`")?;
        Ok(name)
    }

    /// A string of no escapes — none of the line's members needs one — its
    /// quotes consumed.
    fn string(&mut self) -> Result<&'a [u8], HeaderError> {
        self.expect(b"\"", "a string is expected")?;
        let rest = &self.line[self.at..];
        let end =
            rest.iter().position(|&b| b == b'"').ok_or(damaged("a string is unterminated"))?;
        let text = &rest[..end];
        if text.iter().any(|&b| b == b'\\' || b < 0x20) {
            return Err(damaged("an escape or a control character stands inside a string"));
        }
        self.at += end + 1;
        Ok(text)
    }

    /// A canonical integer.
    fn integer(&mut self) -> Result<u64, HeaderError> {
        let (value, rest) =
            integer(&self.line[self.at..]).ok_or(damaged("a number is not in its one spelling"))?;
        self.at = self.line.len() - rest.len();
        Ok(value)
    }
}

/// A member met for the first time takes its slot; a second time is refused.
fn set<T>(slot: &mut Option<T>, value: T) -> Result<(), HeaderError> {
    if slot.is_some() {
        return Err(damaged("a member stands twice"));
    }
    *slot = Some(value);
    Ok(())
}

/// The members met so far, each at most once.
#[derive(Default)]
struct Members {
    typed: Option<()>,
    versioned: Option<()>,
    board: Option<Chain>,
    supplement: Option<bool>,
    principal: Option<u64>,
    floor: Option<Option<u64>>,
    tokenizer: Option<Revision>,
    body: Option<u64>,
}

impl Members {
    /// The line's facts, every required member present and `principal` on a
    /// supplement's header alone.
    fn parsed(self) -> Result<Parsed, HeaderError> {
        self.typed.ok_or(damaged("no `type` member"))?;
        self.versioned.ok_or(damaged("no `v` member"))?;
        let board = self.board.ok_or(damaged("no `board` member"))?;
        let class = match (self.supplement, self.principal) {
            (Some(false), None) => Class::Guest,
            (Some(true), Some(n)) => Class::Principal(n),
            (None, _) => return Err(damaged("no `kind` member")),
            (Some(false), Some(_)) => {
                return Err(damaged("a `principal` member on a published header"))
            }
            (Some(true), None) => {
                return Err(damaged("no `principal` member on a supplement header"))
            }
        };
        let floor = self.floor.ok_or(damaged("no `floor` member"))?;
        let tokenizer = self.tokenizer.ok_or(damaged("no `tokenizer` member"))?;
        let body = self.body.ok_or(damaged("no `body` member"))?;
        Ok(Parsed { board, class, floor, tokenizer, body })
    }
}

#[cfg(test)]
mod tests;
