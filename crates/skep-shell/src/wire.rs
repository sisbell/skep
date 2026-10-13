//! THE WIRE's SHARED FACTS: what the composer (`attest`), the held store
//! (`held`), the hold's door and its resend (`hold`) and the call log the
//! shell keeps (`shell`) each read of the board's wire and none of them owns
//! — the board's frame cap and how a frame is measured against it, the
//! tumbler component budget and an address read within it, a document
//! address in its one spelling, and the wire's VALUE FORMS both ways
//! (wire.md §Value encodings) with the insert's value budget: a frame's
//! `values` minted as the composer signs them, and a delivery read back as
//! the composer's read-back and the resend's content confirm hold it. A
//! leaf: it names no other module of the crate.

use std::borrow::Cow;
use std::io;

use serde_json::Value;
use skep_address::{Address, Level};
use skep_client::address::{is_address_text, parse_address};

/// THE BOARD's FRAME CAP — the most bytes one `/op` body may carry: skepd's
/// `body_cap("POST", "/op")`, its `MAX_REQUEST_BODY`, refused `413` on the
/// declared length before a byte is read. Two budgets are this number: a
/// burst whose frame the board takes at no send never enters the hold
/// (`hold`'s `Burst::admit`), and a shot's body is built under it — the
/// parity the daemon's own composer holds a shot's body to (`auth/entry.rs`'s
/// `MAX_SHOT_BODY_BYTES`), answering a longer one
/// `attestation_invalid:frame_too_large`. Pinned equal to the board's by the
/// suite.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// The most components one tumbler may carry, an address or a width —
/// skepd's codec's `MAX_TUMBLER_COMPONENTS`, refused at the board's parse,
/// `malformed`; counted here before a component is converted or collected.
/// The codec's constant is private, so the suite pins this one by the
/// board's behaviour: an address at it parsed, one past it refused.
pub const MAX_TUMBLER_COMPONENTS: usize = 256;

/// The most values one `insert` may mint — skepd's codec's
/// `MAX_INSERT_VALUES`, refused at the board's parse, `malformed`; counted
/// by [`values_of`] ahead of each element it is about to mint, a hex by its
/// encoded length, as the codec counts it. Pinned by the board's behaviour,
/// as [`MAX_TUMBLER_COMPONENTS`] is.
pub const MAX_INSERT_VALUES: usize = 1 << 18;

/// Whether `text` splits into at most [`MAX_TUMBLER_COMPONENTS`]
/// components — counted without converting or collecting one.
pub fn within_components(text: &str) -> bool {
    text.split('.').nth(MAX_TUMBLER_COMPONENTS).is_none()
}

/// `text` as an address — within [`MAX_TUMBLER_COMPONENTS`], counted before
/// a component is converted, each a decimal natural, and T4-valid — or
/// `None`.
pub fn bounded_address(text: &str) -> Option<Address> {
    within_components(text).then(|| parse_address(text)).flatten()
}

/// `text` as a DOCUMENT address in its ONE spelling — dotted decimal
/// naturals, no sign and no leading zero (`is_address_text`) — within
/// [`MAX_TUMBLER_COMPONENTS`], T4-valid and of the document level, or
/// `None`. The one spelling, because the hold keys a document's lines by
/// its text and reads its rows `under` that text, and a trunk is split by
/// text (`attest`'s `trunk_text`): two spellings of one document would be
/// two documents to the hold, and a `00` is no `0` to a split.
pub fn document_address(text: &str) -> Option<Address> {
    is_address_text(text).then(|| bounded_address(text)).flatten().filter(|a| a.level() == Level::Document)
}

/// The length of `v`'s compact JSON text — the bytes a value carries on the
/// wire, as the shell counts a call's for its log and measures a frame
/// against the board's cap — counted as it is written and never kept.
pub fn json_len(v: &Value) -> usize {
    /// A writer that keeps nothing but the count.
    struct Count(usize);
    impl io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, v).expect("a `Value` has string keys and finite numbers, and the count's writer never fails");
    count.0
}

/// Why a frame's `values` mint no value sequence (wire.md §Value encodings).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValuesFault {
    /// An element of no wire form, or a hex that does not decode.
    NotAWireForm,
    /// More values than the board's parse admits ([`MAX_INSERT_VALUES`]).
    PastBudget,
}

/// The wire's `values` as the value at each position the frame fills: a
/// string and a `{"hex"}` mint one value per byte, an `{"atom"}` and an
/// `{"atom_hex"}` one composite value (wire.md §Value encodings). A text's
/// and an atom's values are borrowed from the frame; a hex's are decoded,
/// and so owned. At most [`MAX_INSERT_VALUES`], asked of each element
/// before it mints — a hex by its encoded length — so a frame past the
/// budget mints nothing past it.
pub fn values_of(values: &Value) -> Result<Vec<Cow<'_, [u8]>>, ValuesFault> {
    let room = |minted: usize, adding: usize| if minted.saturating_add(adding) > MAX_INSERT_VALUES { Err(ValuesFault::PastBudget) } else { Ok(()) };
    let mut out = Vec::new();
    for v in values.as_array().ok_or(ValuesFault::NotAWireForm)? {
        match v {
            Value::String(s) => {
                room(out.len(), s.len())?;
                out.extend(s.as_bytes().chunks(1).map(Cow::Borrowed));
            }
            Value::Object(m) => {
                if let Some(h) = m.get("hex").and_then(Value::as_str) {
                    room(out.len(), h.len() / 2)?;
                    out.extend(decode_hex(h).ok_or(ValuesFault::NotAWireForm)?.into_iter().map(|b| Cow::Owned(vec![b])));
                } else if let Some(a) = m.get("atom").and_then(Value::as_str) {
                    room(out.len(), 1)?;
                    out.push(Cow::Borrowed(a.as_bytes()));
                } else if let Some(h) = m.get("atom_hex").and_then(Value::as_str) {
                    room(out.len(), 1)?;
                    out.push(Cow::Owned(decode_hex(h).ok_or(ValuesFault::NotAWireForm)?));
                } else {
                    return Err(ValuesFault::NotAWireForm);
                }
            }
            _ => return Err(ValuesFault::NotAWireForm),
        }
    }
    Ok(out)
}

/// A delivery's items as the value at each position they deliver, in order —
/// the inverse of [`values_of`]: a `content` text and a `hex` item one value
/// per byte (adjacent text arrives as one item), an `atom` and an `atom_hex`
/// one composite value — borrowed from the delivery where it spells them,
/// owned where a hex is decoded. An item no value spells — a withheld run, a
/// reference, a `hex` that does not decode, one this shell does not know —
/// is answered in its place as the item itself, and nothing after it. LAZY:
/// a reader walks a board's delivery position by position and holds what it
/// keeps, never a value for every position the board chose to deliver.
pub fn delivered_values(delivery: &Value) -> impl Iterator<Item = Result<Cow<'_, [u8]>, Value>> + '_ {
    let items = delivery["items"].as_array().map(Vec::as_slice).unwrap_or_default();
    let mut stopped = false;
    items.iter().flat_map(item_values).map_while(move |position| {
        if stopped {
            return None;
        }
        stopped = position.is_err();
        Some(position)
    })
}

/// One delivered item's positions, as [`delivered_values`] reads them.
fn item_values(item: &Value) -> Box<dyn Iterator<Item = Result<Cow<'_, [u8]>, Value>> + '_> {
    let unread = || -> Box<dyn Iterator<Item = Result<Cow<'_, [u8]>, Value>> + '_> { Box::new(std::iter::once(Err(item.clone()))) };
    if let Some(text) = item["content"].as_str() {
        Box::new(text.as_bytes().chunks(1).map(|b| Ok(Cow::Borrowed(b))))
    } else if let Some(h) = item["hex"].as_str() {
        match decode_hex(h) {
            Some(bytes) => Box::new(bytes.into_iter().map(|b| Ok(Cow::Owned(vec![b])))),
            None => unread(),
        }
    } else if let Some(a) = item["atom"].as_str() {
        Box::new(std::iter::once(Ok(Cow::Borrowed(a.as_bytes()))))
    } else if let Some(h) = item["atom_hex"].as_str() {
        match decode_hex(h) {
            Some(bytes) => Box::new(std::iter::once(Ok(Cow::Owned(bytes)))),
            None => unread(),
        }
    } else {
        unread()
    }
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// A delivery's values collected, or the item that stopped them.
    fn delivered(delivery: &Value) -> Result<Vec<Cow<'_, [u8]>>, Value> {
        delivered_values(delivery).collect()
    }

    /// The wire's four value forms mint the body's values: per byte for a
    /// string and a `hex`, one composite for an `atom` and an `atom_hex`,
    /// the text's and the atom's borrowed from the frame; a hex of either
    /// case decodes, and one with a sign or a multi-byte character is no
    /// value (never a panic at a character boundary), its fault named.
    #[test]
    fn the_values_read_as_the_wire_spells_them() {
        let frame = json!(["ab", {"hex": "c328"}, {"atom": "one"}, {"atom_hex": "00ff"}]);
        let values = values_of(&frame).unwrap();
        assert_eq!(values, vec![b"a".to_vec(), b"b".to_vec(), vec![0xc3], vec![0x28], b"one".to_vec(), vec![0x00, 0xff]]);
        assert!(matches!((&values[0], &values[4], &values[2]), (Cow::Borrowed(_), Cow::Borrowed(_), Cow::Owned(_))), "text and atoms borrowed, hex decoded: {values:?}");
        assert_eq!(values_of(&json!([7])), Err(ValuesFault::NotAWireForm));
        assert_eq!(values_of(&json!("ab")), Err(ValuesFault::NotAWireForm), "the values are a list");
        assert_eq!(values_of(&json!([{"hex": "C3"}, {"atom_hex": "Ab"}])).unwrap(), vec![vec![0xc3], vec![0xab]]);
        assert_eq!(values_of(&json!([{"hex": "+a"}])), Err(ValuesFault::NotAWireForm), "a sign is no hex digit");
        assert_eq!(values_of(&json!([{"atom_hex": "+a+b"}])), Err(ValuesFault::NotAWireForm));
        assert_eq!(values_of(&json!([{"hex": "aé0"}])), Err(ValuesFault::NotAWireForm), "a multi-byte character is no hex digit, and cuts no boundary");
        assert_eq!(values_of(&json!([{"hex": "abc"}])), Err(ValuesFault::NotAWireForm), "an odd length");
    }

    /// A delivery reads back as the values a frame spells them in: adjacent
    /// text arrives as ONE item and is one value per byte, as the frame's
    /// string was; a withheld run, or a `hex` that does not decode, is no
    /// value and is answered as the item that stopped the read.
    #[test]
    fn a_delivery_reads_back_as_the_values_its_frame_spelled() {
        let frame = json!(["he", "llo", {"hex": "c328"}, {"atom": "one"}, {"atom_hex": "00ff"}]);
        let delivery = json!({"resp": "delivery", "items": [{"content": "hello"}, {"hex": "c328"}, {"atom": "one"}, {"atom_hex": "00ff"}]});
        assert_eq!(delivered(&delivery).unwrap(), values_of(&frame).unwrap());
        let withheld = json!({"withheld": {"width": "3"}});
        assert_eq!(delivered(&json!({"items": [{"content": "a"}, withheld]})), Err(withheld));
        assert_eq!(delivered(&json!({"items": [{"hex": "zz"}]})), Err(json!({"hex": "zz"})));
        assert_eq!(delivered(&json!({"items": [{"hex": "+a"}]})), Err(json!({"hex": "+a"})));
        assert_eq!(delivered(&json!({"items": [{"atom_hex": "aé0"}]})), Err(json!({"atom_hex": "aé0"})));
        let after = json!({"items": [{"content": "a"}, {"withheld": {}}, {"content": "b"}]});
        let stopped: Vec<_> = delivered_values(&after).collect();
        assert_eq!(stopped.len(), 2, "nothing is read past the item that stopped the read: {stopped:?}");
    }

    /// An insert's values are held to the codec's count AHEAD of each element:
    /// a string of exactly the budget mints, one byte more is refused as past
    /// it, and a hex is counted by its encoded length, an atom as one value.
    #[test]
    fn the_values_are_held_to_the_insert_budget_before_they_mint() {
        let at = "a".repeat(MAX_INSERT_VALUES);
        assert_eq!(values_of(&json!([at])).unwrap().len(), MAX_INSERT_VALUES);
        assert_eq!(values_of(&json!([at, "b"])), Err(ValuesFault::PastBudget), "one value past the budget");
        assert_eq!(values_of(&json!([at, {"atom": "b"}])), Err(ValuesFault::PastBudget), "an atom is one value");
        assert_eq!(values_of(&json!([{"hex": "00".repeat(MAX_INSERT_VALUES + 1)}])), Err(ValuesFault::PastBudget), "a hex counted by its encoded length");
        assert_eq!(values_of(&json!([{"hex": "00".repeat(MAX_INSERT_VALUES)}])).unwrap().len(), MAX_INSERT_VALUES);
    }

    /// An address is recognized within its component budget — counted before a
    /// component is converted — and a burst's document in its ONE spelling: no
    /// sign, no leading zero, of the document level.
    #[test]
    fn an_address_is_recognized_within_its_budget_and_a_document_in_its_one_spelling() {
        let at = format!("1{}", ".1".repeat(MAX_TUMBLER_COMPONENTS - 1));
        assert!(bounded_address(&at).is_some(), "a node address at the budget");
        assert!(bounded_address(&format!("{at}.1")).is_none(), "one component past it");
        assert!(document_address("1.0.1.0.1").is_some());
        assert!(document_address("1.0.1.0.1.2").is_some(), "a member is a document address");
        for refused in ["01.0.1.0.1", "+1.0.1.0.1", "1.00.1.0.1", "1.0.1", "1.0.1.0.1.0.1.1", "1..0.1", "", "1.0.1.0.1 "] {
            assert!(document_address(refused).is_none(), "`{refused}`");
        }
        let deep = format!("1.0.1.0.1{}", ".1".repeat(MAX_TUMBLER_COMPONENTS - 5));
        assert!(document_address(&deep).is_some() && document_address(&format!("{deep}.1")).is_none());
    }
}
