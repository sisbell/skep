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
//! sent: the shell never sends a frame it could not sign.

use std::borrow::Cow;
use std::collections::HashMap;
use std::num::NonZeroU64;

use serde_json::{json, Value};
use skep_address::{Address, Nat, Span, Tumbler};
use skep_client::address::{document_of, parse_address};
use skep_client::board::{frames, Answer, Board, Rejection, Token, T_SUPERSEDES};
use skep_client::halt::Halt;
use skep_client::sign::{sig_hex, Signer};
use skep_identity::{
    entry_body_assert_sup, entry_body_edit_link, entry_body_emit, entry_body_empty, entry_body_insert, entry_body_make_link,
    entry_body_make_link_replacing, entry_body_nullify, entry_body_publish, entry_frame, unit_span, BoardTerm, ContentFreeOp,
    DocTerm, EntryBody, EntrySlot, LinkSlots, ShotBase, ShotSegmentPiece,
};

/// THE RETRACTION CLASS's reserved ghost tumbler — `[R]`, the fifth of the
/// format's five (`1.1.0.1.0.1.0.1.x`, x = 1..=5: pred_def, pred_stable,
/// retired, supersedes, retraction) — the type slot of the tuple a
/// `nullify` deposits, fixed by kind (`skep-links`'s `retraction_tuple`).
pub const T_RETRACTION: &str = "1.1.0.1.0.1.0.1.5";

/// The ten kinds, as the wire spells them.
pub const CHECKED_SET: [&str; 10] = ["create_new_document", "fork", "version", "insert", "publish", "make_link", "emit", "nullify", "assert_sup", "edit_link"];

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

/// The composer: the board the reads are made at under `token`, the key
/// that signs, the session's account, and `H.1`'s pair.
pub struct Composer<'a> {
    pub board: &'a Board,
    pub token: &'a Token,
    pub signer: &'a dyn Signer,
    pub account: &'a str,
    pub term: BoardTerm,
}

/// The frame's `doc` term, owned.
enum Doc {
    One(Address),
    Pair { d_s: Address, d_a: Address },
}

/// One origin document's content read back: the I-address of each position
/// and the value at it, keyed by the address's spelling.
struct ReadBack {
    values: HashMap<String, Vec<u8>>,
}

/// One run of a shot as its body takes it, in the shot's V-order: the
/// values a COPIED run brings in, or a WINDOW onto another document's
/// I-space.
enum ShotPart {
    Copied(Vec<Vec<u8>>),
    Window { start: Address, width: NonZeroU64 },
}

fn fault(state: impl Into<String>, cause: impl Into<String>) -> Halt {
    Halt::face(state, cause, "this is the shell's frame and never your act; nothing was sent")
}

/// `text` as an address, or the halt a frame naming no address is.
fn addr(text: &str, what: &str) -> Result<Address, Halt> {
    parse_address(text).ok_or_else(|| fault(format!("the frame's `{what}` is not an address: `{text}`"), "the attest's frame names every address in its dotted spelling"))
}

/// The frame's member `name` as a string.
fn member<'f>(frame: &'f Value, name: &str) -> Result<&'f str, Halt> {
    frame[name].as_str().ok_or_else(|| fault(format!("the frame carries no `{name}`"), "the attest's grammar for this op names the member"))
}

/// THE TRUNK of a document-level address text: the address with its version
/// components dropped — the document field after the second `0` separator
/// kept to its first component (`1.0.1.0.1.2` → `1.0.1.0.1`); an element
/// address is taken to its document first. The projection
/// `skep-arrangement`'s `trunk_of` makes, reproduced over the spelling.
pub fn trunk_text(text: &str) -> Option<String> {
    let doc = document_of(text).unwrap_or_else(|| text.to_string());
    let comps: Vec<&str> = doc.split('.').collect();
    let mut zeros = comps.iter().enumerate().filter(|(_, c)| **c == "0").map(|(i, _)| i);
    let (_first, second) = (zeros.next()?, zeros.next()?);
    if zeros.next().is_some() || second + 1 >= comps.len() {
        return None;
    }
    Some(comps[..=second + 1].join("."))
}

/// A tumbler from its dotted decimal.
fn tumbler(text: &str) -> Option<Tumbler> {
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

/// The I-address `k` positions past `i_start`, by its last component.
fn i_addr_at(i_start: &str, k: u64) -> Option<String> {
    let (prefix, last) = i_start.rsplit_once('.')?;
    let first: u64 = last.parse().ok()?;
    Some(format!("{prefix}.{}", first.checked_add(k)?))
}

/// The wire's `values` as the entry body's value sequence — the value at each
/// position the frame fills: a string and a `{"hex"}` mint one value per
/// byte, an `{"atom"}` and an `{"atom_hex"}` one composite value (wire.md
/// §Value encodings). A text's and an atom's values are borrowed from the
/// frame; a hex's are decoded, and so owned.
pub fn values_of(values: &Value) -> Result<Vec<Cow<'_, [u8]>>, Halt> {
    let bad = || fault("the frame's `values` are not the wire's forms", "a value is a string, `{\"hex\"}`, `{\"atom\"}` or `{\"atom_hex\"}`");
    let mut out = Vec::new();
    for v in values.as_array().ok_or_else(bad)? {
        match v {
            Value::String(s) => out.extend(s.as_bytes().chunks(1).map(Cow::Borrowed)),
            Value::Object(m) => {
                if let Some(h) = m.get("hex").and_then(Value::as_str) {
                    out.extend(decode_hex(h).ok_or_else(bad)?.into_iter().map(|b| Cow::Owned(vec![b])));
                } else if let Some(a) = m.get("atom").and_then(Value::as_str) {
                    out.push(Cow::Borrowed(a.as_bytes()));
                } else if let Some(h) = m.get("atom_hex").and_then(Value::as_str) {
                    out.push(Cow::Owned(decode_hex(h).ok_or_else(bad)?));
                } else {
                    return Err(bad());
                }
            }
            _ => return Err(bad()),
        }
    }
    Ok(out)
}

/// A delivery's items as the value at each position they deliver, the
/// inverse of [`values_of`]: a `content` text and a `hex` item one value per
/// byte (adjacent text arrives as one item), an `atom` and an `atom_hex` one
/// composite value — borrowed from the delivery where it spells them, owned
/// where a hex is decoded. An item no value spells — a withheld run, a
/// reference, a `hex` that does not decode, one this shell does not know —
/// is the error.
pub fn delivered_values(delivery: &Value) -> Result<Vec<Cow<'_, [u8]>>, Value> {
    let mut positions = Vec::new();
    for item in delivery["items"].as_array().into_iter().flatten() {
        let unread = || item.clone();
        if let Some(text) = item["content"].as_str() {
            positions.extend(text.as_bytes().chunks(1).map(Cow::Borrowed));
        } else if let Some(h) = item["hex"].as_str() {
            positions.extend(decode_hex(h).ok_or_else(unread)?.into_iter().map(|b| Cow::Owned(vec![b])));
        } else if let Some(a) = item["atom"].as_str() {
            positions.push(Cow::Borrowed(a.as_bytes()));
        } else if let Some(h) = item["atom_hex"].as_str() {
            positions.push(Cow::Owned(decode_hex(h).ok_or_else(unread)?));
        } else {
            return Err(unread());
        }
    }
    Ok(positions)
}

/// Lowercase or uppercase hex decoded, `None` where it is none: an odd
/// length, or any byte that is no ASCII hex digit — a sign, or a byte of a
/// multi-byte character. The text is read byte by byte, so no character
/// boundary can be cut.
fn decode_hex(h: &str) -> Option<Vec<u8>> {
    let digit = |b: u8| char::from(b).to_digit(16);
    let (pairs, odd) = h.as_bytes().as_chunks::<2>();
    if !odd.is_empty() {
        return None;
    }
    // Two hex digits make a value below 256, so the cast keeps every bit.
    pairs.iter().map(|&[hi, lo]| Some(((digit(hi)? << 4) | digit(lo)?) as u8)).collect()
}

impl Composer<'_> {
    /// One READ under the session: the document, a rejection the board's
    /// refusal, the death signal a halt.
    fn read(&self, frame: &Value) -> Result<Value, Halt> {
        match self.board.op(Some(self.token), frame)? {
            Answer::Closed => Err(fault("the session ended while the attest was being composed", "the board answered `Skepd-Session: closed` to a read the composer made")),
            Answer::Document(v) => match Rejection::of(&v) {
                Some(r) => Err(r.refused(&v)),
                None => Ok(v),
            },
        }
    }

    /// A slot's spans AS STORED: the address form's unit spans, a V-spec
    /// list's I-extents resolved through `image`, or a span list verbatim
    /// (`emit`'s `ty`).
    fn slot(&self, slot: &Value, what: &str) -> Result<Vec<Span>, Halt> {
        if let Some(addrs) = slot["addrs"].as_array() {
            return addrs.iter().map(|a| Ok(unit_span(&addr(a.as_str().unwrap_or(""), what)?))).collect();
        }
        let Some(list) = slot.as_array() else {
            return Err(fault(format!("the frame's `{what}` slot is neither the address form nor a list"), "a slot is `{\"addrs\": […]}`, a V-spec list, or a span list"));
        };
        let mut spans = Vec::new();
        for item in list {
            if let Some(source) = item["source"].as_str() {
                let (from, width) = v_spec(&item["span"]).ok_or_else(|| fault(format!("the frame's `{what}` V-spec is not a content span"), "a V-spec's span is `{\"start\": \"1.<ordinal>\", \"width\": \"0.<width>\"}`"))?;
                let v = self.read(&frames::image(source, from, width))?;
                let runs = v["runs"].as_array().ok_or_else(|| fault("`image` answered no runs", v.to_string()))?;
                for r in runs {
                    let i_start = r["i_start"].as_str().unwrap_or("");
                    let w: u64 = r["width"].as_str().and_then(|w| w.parse().ok()).unwrap_or(0);
                    spans.push(extent_span(i_start, w).ok_or_else(|| fault("a run `image` answered is no content extent", r.to_string()))?);
                }
            } else if let (Some(start), Some(width)) = (item["start"].as_str(), item["width"].as_str()) {
                let span = tumbler(start).zip(tumbler(width)).and_then(|(s, w)| Span::new(s, w).ok());
                spans.push(span.ok_or_else(|| fault(format!("the frame's `{what}` span does not parse"), item.to_string()))?);
            } else {
                return Err(fault(format!("the frame's `{what}` slot holds an element of no known form"), item.to_string()));
            }
        }
        Ok(spans)
    }

    /// An origin document's content READ BACK: its extent, its V→I map
    /// through `image`, and the value at every position through
    /// `retrieve_v`, each position's value keyed by its I-address.
    fn read_back(&self, origin: &str) -> Result<ReadBack, Halt> {
        let set = self.read(&frames::span_set(origin))?;
        let extent = set["set"]
            .as_array()
            .and_then(|s| s.iter().find(|x| x["start"].as_str() == Some("1.1")))
            .and_then(|s| s["width"].as_str()?.rsplit('.').next()?.parse::<u64>().ok())
            .unwrap_or(0);
        let mut values = HashMap::new();
        if extent == 0 {
            return Ok(ReadBack { values });
        }
        let image = self.read(&frames::image(origin, 1, extent))?;
        let mut addrs: Vec<String> = Vec::new();
        for run in image["runs"].as_array().into_iter().flatten() {
            let i_start = run["i_start"].as_str().unwrap_or("");
            let width: u64 = run["width"].as_str().and_then(|w| w.parse().ok()).unwrap_or(0);
            for k in 0..width {
                addrs.push(i_addr_at(i_start, k).ok_or_else(|| fault("a run `image` answered has no I-start", run.to_string()))?);
            }
        }
        let delivery = self.read(&frames::retrieve_v(origin, 1, extent))?;
        let positions = delivered_values(&delivery).map_err(|item| {
            fault(
                format!("a position of {origin} cannot be read back for the shot's body"),
                format!("the delivery holds an item the composer cannot spell as values — a withheld run, a reference, a hex that does not decode, or one it does not know: {item}"),
            )
        })?;
        if positions.len() != addrs.len() {
            return Err(fault(format!("{origin}'s delivery and its image disagree on its extent"), format!("{} positions delivered against {} addresses imaged", positions.len(), addrs.len())));
        }
        for (a, v) in addrs.into_iter().zip(positions) {
            values.insert(a, v.into_owned());
        }
        Ok(ReadBack { values })
    }

    /// The `publish` body: each run the shot names in V-order, a run onto
    /// the shot document's own trunk or the staging draft COPIED by its
    /// values, any other a WINDOW; then the base group.
    fn publish_body(&self, frame: &Value, trunk: &str) -> Result<EntryBody, Halt> {
        let draft = frame["draft"].as_str();
        let runs = frame["runs"].as_array().ok_or_else(|| fault("the shot names no `runs`", "a `publish` frame carries its runs in V-order"))?;
        let mut read_backs: HashMap<String, ReadBack> = HashMap::new();
        let mut parts: Vec<ShotPart> = Vec::with_capacity(runs.len());
        for run in runs {
            let origin = member(run, "origin")?;
            let i_start = member(run, "i_start")?;
            let width: u64 = run["width"].as_str().and_then(|w| w.parse().ok()).ok_or_else(|| fault("a run's `width` is not a count", run.to_string()))?;
            let origin_trunk = trunk_text(origin);
            let is_copied = origin_trunk.as_deref() == Some(trunk) || draft.is_some_and(|d| d == origin || trunk_text(d).as_deref() == origin_trunk.as_deref());
            if is_copied {
                if !read_backs.contains_key(origin) {
                    read_backs.insert(origin.to_string(), self.read_back(origin)?);
                }
                let read = &read_backs[origin];
                let mut values = Vec::new();
                for k in 0..width {
                    let a = i_addr_at(i_start, k).ok_or_else(|| fault("a run's `i_start` has no last component", run.to_string()))?;
                    let v = read.values.get(&a).ok_or_else(|| fault(format!("the shot copies in {a}, which {origin}'s arrangement does not hold"), "a copied run's values are read back through its origin's own arrangement; a position outside it cannot be composed"))?;
                    values.push(v.clone());
                }
                parts.push(ShotPart::Copied(values));
            } else {
                let start = addr(i_start, "runs[].i_start")?;
                let width = NonZeroU64::new(width).ok_or_else(|| fault("a window of width 0", run.to_string()))?;
                parts.push(ShotPart::Window { start, width });
            }
        }
        let base_member = frame["base"].as_str().map(|b| addr(b, "base")).transpose()?;
        let base_extent: Option<u64> = frame["base_extent"].as_str().and_then(|e| e.parse().ok());
        let base = match (&base_member, base_extent) {
            (Some(member), Some(extent)) => Some(ShotBase { member, extent }),
            (None, None) => None,
            _ => return Err(fault("the shot names `base` without `base_extent`, or the reverse", "either both or neither (wire.md §The publish shot)")),
        };
        let mut pieces: Vec<ShotSegmentPiece<'_>> = Vec::new();
        for part in &parts {
            match part {
                ShotPart::Copied(values) => pieces.extend(values.iter().map(|v| ShotSegmentPiece::Value(v))),
                ShotPart::Window { start, width } => pieces.push(ShotSegmentPiece::Window { start, width: *width }),
            }
        }
        Ok(entry_body_publish(pieces, base))
    }

    /// The frame's `doc` term and body for `op`, or `None` outside the ten.
    fn doc_and_body(&self, op: &str, frame: &Value) -> Result<Option<(Doc, EntryBody)>, Halt> {
        let one = |text: &str, what: &str| -> Result<Doc, Halt> { Ok(Doc::One(addr(text, what)?)) };
        let out = match op {
            "create_new_document" => (one(member(frame, "account")?, "account")?, entry_body_empty(ContentFreeOp::CreateNewDocument)),
            "fork" => (one(self.account, "account")?, entry_body_empty(ContentFreeOp::Fork)),
            "version" => (one(self.account, "account")?, entry_body_empty(ContentFreeOp::Version)),
            "insert" => {
                let doc = member(frame, "doc")?;
                let trunk = trunk_text(doc).ok_or_else(|| fault(format!("the frame's `doc` has no trunk: `{doc}`"), "an insert's doc term is the document's trunk"))?;
                let declared = frame["deposit"].as_str().map(|t| addr(t, "deposit")).transpose()?;
                let values = values_of(&frame["values"])?;
                (one(&trunk, "doc")?, entry_body_insert(declared.as_ref(), values.iter().map(AsRef::as_ref)))
            }
            "make_link" => {
                let home = member(frame, "home")?;
                let (from, to, ty) = (self.slot(&frame["from"], "from")?, self.slot(&frame["to"], "to")?, self.slot(&frame["ty"], "ty")?);
                let slots = LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) };
                let body = match frame["replaces"].as_str() {
                    None => entry_body_make_link(slots),
                    Some(r) => entry_body_make_link_replacing(slots, &addr(r, "replaces")?),
                };
                (one(home, "home")?, body)
            }
            "emit" => {
                let home = member(frame, "home")?;
                let from = [unit_span(&addr(member(frame, "from")?, "from")?)];
                let to: Vec<Span> = frame["to"].as_array().into_iter().flatten().map(|a| Ok(unit_span(&addr(a.as_str().unwrap_or(""), "to")?))).collect::<Result<_, Halt>>()?;
                let ty = self.slot(&frame["ty"], "ty")?;
                (one(home, "home")?, entry_body_emit(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) }))
            }
            "nullify" => {
                let home = member(frame, "home")?;
                let from = [unit_span(&addr(home, "home")?)];
                let to = [unit_span(&addr(member(frame, "target")?, "target")?)];
                let ty = [unit_span(&addr(T_RETRACTION, "retraction")?)];
                (one(home, "home")?, entry_body_nullify(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) }))
            }
            "assert_sup" => {
                let home = member(frame, "home")?;
                let from = [unit_span(&addr(member(frame, "old")?, "old")?)];
                let to = [unit_span(&addr(member(frame, "new")?, "new")?)];
                let ty = [unit_span(&addr(T_SUPERSEDES, "supersedes")?)];
                (one(home, "home")?, entry_body_assert_sup(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) }))
            }
            "edit_link" => {
                let successor = &frame["successor"];
                let (from, to, ty) = (self.slot(&successor["from"], "successor.from")?, self.slot(&successor["to"], "successor.to")?, self.slot(&successor["ty"], "successor.ty")?);
                let original = unit_span(&addr(member(frame, "original")?, "original")?);
                let body = entry_body_edit_link(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) }, &original);
                (Doc::Pair { d_s: addr(member(frame, "d_s")?, "d_s")?, d_a: addr(member(frame, "d_a")?, "d_a")? }, body)
            }
            "publish" => {
                let doc = member(frame, "doc")?;
                let trunk = trunk_text(doc).ok_or_else(|| fault(format!("the frame's `doc` has no trunk: `{doc}`"), "a publish's doc term is the document's trunk"))?;
                let body = self.publish_body(frame, &trunk)?;
                (one(&trunk, "doc")?, body)
            }
            _ => return Ok(None),
        };
        Ok(Some(out))
    }

    /// THE ATTEST for `frame`, which [`wants_attest`] admitted: its entry
    /// frame composed, signed by the session's key and attached as the
    /// frame's `attest`.
    pub fn attach(&self, frame: &mut Value) -> Result<(), Halt> {
        let Some(op) = frame["op"].as_str().map(str::to_string) else { return Ok(()) };
        let Some((doc, body)) = self.doc_and_body(&op, frame)? else { return Ok(()) };
        let account = addr(self.account, "account")?;
        let alg = self.signer.public_key().alg().to_string();
        let bytes = match &doc {
            Doc::One(a) => entry_frame(&alg, self.term, &account, DocTerm::One(a), &body),
            Doc::Pair { d_s, d_a } => entry_frame(&alg, self.term, &account, DocTerm::Pair { d_s, d_a }, &body),
        };
        frame["attest"] = json!({"alg": alg, "sig": sig_hex(&self.signer.sign(&bytes))});
        Ok(())
    }
}

/// A V-spec's span as `(from, width)` over the content subspace: `start`
/// `1.<ordinal>`, `width` `0.<count>`.
fn v_spec(span: &Value) -> Option<(u64, u64)> {
    let start = span["start"].as_str()?.strip_prefix("1.")?.parse().ok()?;
    let width = span["width"].as_str()?.strip_prefix("0.")?.parse().ok()?;
    Some((start, width))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The trunk projection over the spelling: a member drops its version
    /// components, a bare document is itself, an element is taken to its
    /// document, an account has none.
    #[test]
    fn the_trunk_is_the_document_field_cut_to_its_first_component() {
        assert_eq!(trunk_text("1.0.1.0.1.2").as_deref(), Some("1.0.1.0.1"));
        assert_eq!(trunk_text("1.0.1.0.1").as_deref(), Some("1.0.1.0.1"));
        assert_eq!(trunk_text("1.0.1.0.7.3.1").as_deref(), Some("1.0.1.0.7"));
        assert_eq!(trunk_text("1.0.1.0.1.0.1.7").as_deref(), Some("1.0.1.0.1"));
        assert_eq!(trunk_text("1.0.1"), None);
        assert_eq!(trunk_text("1"), None);
    }

    /// The wire's four value forms mint the body's values: per byte for a
    /// string and a `hex`, one composite for an `atom` and an `atom_hex`,
    /// the text's and the atom's borrowed from the frame; a hex of either
    /// case decodes, and one with a sign or a multi-byte character is no
    /// value (never a panic at a character boundary); a V-spec's span reads
    /// as `(from, width)`; an I-address advances by its last component; the
    /// ten kinds are the checked set.
    #[test]
    fn the_values_the_v_spec_and_the_i_address_read_as_the_wire_spells_them() {
        let frame = json!(["ab", {"hex": "c328"}, {"atom": "one"}, {"atom_hex": "00ff"}]);
        let values = values_of(&frame).unwrap();
        assert_eq!(values, vec![b"a".to_vec(), b"b".to_vec(), vec![0xc3], vec![0x28], b"one".to_vec(), vec![0x00, 0xff]]);
        assert!(matches!((&values[0], &values[4], &values[2]), (Cow::Borrowed(_), Cow::Borrowed(_), Cow::Owned(_))), "text and atoms borrowed, hex decoded: {values:?}");
        assert!(values_of(&json!([7])).is_err());
        assert_eq!(values_of(&json!([{"hex": "C3"}, {"atom_hex": "Ab"}])).unwrap(), vec![vec![0xc3], vec![0xab]]);
        assert!(values_of(&json!([{"hex": "+a"}])).is_err(), "a sign is no hex digit");
        assert!(values_of(&json!([{"atom_hex": "+a+b"}])).is_err());
        assert!(values_of(&json!([{"hex": "aé0"}])).is_err(), "a multi-byte character is no hex digit, and cuts no boundary");
        assert!(values_of(&json!([{"hex": "abc"}])).is_err(), "an odd length");
        assert_eq!(v_spec(&json!({"start": "1.6", "width": "0.2"})), Some((6, 2)));
        assert_eq!(v_spec(&json!({"start": "2.6", "width": "0.2"})), None);
        assert_eq!(i_addr_at("1.0.1.0.1.0.1.4", 3).as_deref(), Some("1.0.1.0.1.0.1.7"));
        assert!(in_checked_set("publish") && !in_checked_set("delete"));
        assert_eq!(CHECKED_SET.len(), 10);
        assert!(wants_attest(&json!({"op": "publish"})));
        assert!(!wants_attest(&json!({"op": "publish", "attest": {"alg": "x", "sig": "00"}})), "a page-supplied attest stands as it is");
        assert!(!wants_attest(&json!({"op": "delete"})) && !wants_attest(&json!({})));
        let span = extent_span("1.0.1.0.1.0.1.4", 3).unwrap();
        assert_eq!((span.start().to_string(), span.width().to_string()), ("1.0.1.0.1.0.1.4".to_string(), "0.0.0.0.0.0.0.3".to_string()));
    }

    /// A delivery reads back as the values a frame spells them in: adjacent
    /// text arrives as ONE item and is one value per byte, as the frame's
    /// string was; a withheld run, or a `hex` that does not decode, is no
    /// value and is answered as the item that stopped the read.
    #[test]
    fn a_delivery_reads_back_as_the_values_its_frame_spelled() {
        let frame = json!(["he", "llo", {"hex": "c328"}, {"atom": "one"}, {"atom_hex": "00ff"}]);
        let delivery = json!({"resp": "delivery", "items": [{"content": "hello"}, {"hex": "c328"}, {"atom": "one"}, {"atom_hex": "00ff"}]});
        assert_eq!(delivered_values(&delivery).unwrap(), values_of(&frame).unwrap());
        let withheld = json!({"withheld": {"width": "3"}});
        assert_eq!(delivered_values(&json!({"items": [{"content": "a"}, withheld]})), Err(withheld));
        assert_eq!(delivered_values(&json!({"items": [{"hex": "zz"}]})), Err(json!({"hex": "zz"})));
        assert_eq!(delivered_values(&json!({"items": [{"hex": "+a"}]})), Err(json!({"hex": "+a"})));
        assert_eq!(delivered_values(&json!({"items": [{"atom_hex": "aé0"}]})), Err(json!({"atom_hex": "aé0"})));
    }
}
