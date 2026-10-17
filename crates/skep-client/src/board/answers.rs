//! The wire's read answers, decoded (wire.md §The response envelope).
//!
//! The module is the read-side counterpart of [`frames`](super::frames),
//! each answer shape this crate reads spelled once — a discovery's `addrs`,
//! a `read_link`'s slots, a `delivery`'s first value, a `span_set`'s
//! content extent and a `runs` answer's I-map, and behind `search` and
//! `merge` a `delivery`'s typed items and its values, a `doc_metadata`'s
//! terms, a `universal_grants` answer's rows, a head member's pair, a
//! `compare` answer's pairs, a `claims` answer's rows and an answer's
//! `as_of`. Pure functions of a document the caller already holds: the
//! dial stays the caller's — under its token or as a guest — and with it
//! what the death signal means. The ack and refusal readers (`acked_at`,
//! `acked_addr`, [`Rejection`](super::Rejection)) and the registry reads'
//! decoding stay at `board`'s root, where `Board` itself and the suites
//! read them, and a caller reads an envelope member such as `as_of` in
//! place.

// Every reader but `first_atom` — the board term's — is in the acting half;
// the feature-free build decodes the board term alone.
#![cfg_attr(not(feature = "acting"), allow(dead_code))]

use serde_json::Value;

/// Returns a discovery's addresses — the `addrs` answer — in the order served.
///
/// A discovery is `find_links_*`, `find_docs_containing` or `show_origin`;
/// the answer is none where the document is no such answer.
pub(crate) fn addrs(v: &Value) -> Vec<&str> {
    v["addrs"].as_array().into_iter().flatten().filter_map(Value::as_str).collect()
}

/// Returns the first address a `read_link` answer's from slot names.
///
/// It is a credential link's record atom (AUTH-2.113).
pub(crate) fn link_from(v: &Value) -> Option<&str> {
    slot_start(v, 0)
}

/// Returns the first address a `read_link` answer's to slot names.
///
/// It is a credential link's subject, a supersession claim's new link.
pub(crate) fn link_to(v: &Value) -> Option<&str> {
    slot_start(v, 1)
}

/// Returns the first span's start in slot `index` of a `read_link` answer.
///
/// The slots are served in their read-back order: from, to, type.
fn slot_start(v: &Value, index: usize) -> Option<&str> {
    v["link"]["slots"].get(index)?.get(0)?["start"].as_str()
}

/// Returns the start of every span of a `read_link` answer's slot at `index`.
///
/// The read-back order is 0 from, 1 to, 2 type; the starts come in the
/// order served — empty for an empty slot, the any-principal grant's `to`
/// (PUB-5.8) — and `None` where the document holds no link: `link: null`,
/// the absent address's answer (wire.md §The read predicate), or no
/// `link_value` at all. A grant reader needs the whole slot, where
/// `link_to` answers one address: a `to` naming two is a record of neither
/// kind (PUB-5.15).
pub(crate) fn link_slot_starts(v: &Value, index: usize) -> Option<Vec<&str>> {
    let slots = v["link"]["slots"].as_array()?;
    Some(slots.get(index)?.as_array()?.iter().filter_map(|s| s["start"].as_str()).collect())
}

/// Returns a `delivery`'s first item as the one composite value a record is.
///
/// The value (wire.md §Content values) is an `atom` item's text, or an
/// `atom_hex` item's bytes. `None` for any other item — a `content` or
/// `hex` item is a run of per-byte values and never a record's text, a
/// `ref` a link position, a `withheld` item a value the reader may not read
/// — and for a document that is no delivery, holds no item, or whose
/// `atom_hex` does not decode.
pub(crate) fn first_atom(v: &Value) -> Option<Vec<u8>> {
    if v["resp"].as_str() != Some("delivery") {
        return None;
    }
    let item = v["items"].as_array()?.first()?;
    if let Some(text) = item["atom"].as_str() {
        return Some(text.as_bytes().to_vec());
    }
    crate::hex::decode(item["atom_hex"].as_str()?)
}

/// One item of a `delivery`, as the wire types it (wire.md §Value encodings).
///
/// It comes before the search index's own typing: a `content` item's bytes
/// or a `hex` run's, an `atom`/`atom_hex` at one position, a `withheld` run
/// at its width with its origin, and an item kind this crate does not know,
/// kept at the width it carries by the wire's forward rule.
#[cfg_attr(not(feature = "search"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Delivered {
    /// One `content` item's UTF-8 bytes, or a `hex` run's bytes.
    ///
    /// The bytes are one per position.
    Text(Vec<u8>),
    /// An `atom` or `atom_hex`: one position, a composite value.
    Atom,
    /// A `withheld` run: `width` positions, the origin document's address.
    Withheld { origin: String, width: u64 },
    /// A kind this crate does not know, at the width it carries.
    ///
    /// The width is 1 where it carries none.
    Unknown { width: u64 },
}

/// Returns a `delivery`'s items in order with its `as_of`.
///
/// It is the feed consumer's read of a document's content (wire.md §The
/// response envelope), each item typed as [`Delivered`]; `None` for a
/// document that is no delivery or carries no `as_of`, or one whose `hex`
/// run or `withheld` item does not parse.
#[cfg_attr(not(feature = "search"), allow(dead_code))]
pub(crate) fn delivery(v: &Value) -> Option<(Vec<Delivered>, u64)> {
    if v["resp"].as_str() != Some("delivery") {
        return None;
    }
    let as_of = v["as_of"].as_u64()?;
    let mut items = Vec::new();
    for item in v["items"].as_array()? {
        let typed = if let Some(text) = item["content"].as_str() {
            Delivered::Text(text.as_bytes().to_vec())
        } else if let Some(hex) = item["hex"].as_str() {
            Delivered::Text(crate::hex::decode(hex)?)
        } else if item.get("atom").is_some() || item.get("atom_hex").is_some() {
            Delivered::Atom
        } else if let Some(w) = item.get("withheld") {
            let width = w["width"].as_str().and_then(|w| w.parse().ok())?;
            Delivered::Withheld { origin: w["origin"].as_str()?.to_string(), width }
        } else {
            let width = item["width"].as_str().and_then(|w| w.parse().ok()).unwrap_or(1);
            Delivered::Unknown { width }
        };
        items.push(typed);
    }
    Some((items, as_of))
}

/// Returns a `doc_metadata` answer's `published` bit (wire.md §Namespace).
///
/// `None` for a document that is no such answer — a rejection among them —
/// or one without the bit.
#[cfg_attr(not(feature = "search"), allow(dead_code))]
pub(crate) fn published(v: &Value) -> Option<bool> {
    (v["resp"].as_str() == Some("doc_metadata")).then(|| v["published"].as_bool()).flatten()
}

/// Returns a `universal_grants` answer's rows (wire.md §Grants).
///
/// Each covered prefix comes with the issuers who granted it, in the order
/// served; empty for a guest and for a document that is no such answer.
#[cfg_attr(not(feature = "search"), allow(dead_code))]
pub(crate) fn universal_rows(v: &Value) -> Vec<(&str, Vec<&str>)> {
    v["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| {
            let prefix = row["prefix"].as_str()?;
            let issuers = row["issuers"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
            Some((prefix, issuers))
        })
        .collect()
}

/// Returns the `(position, chain)` pair a `skep-head` record names.
///
/// It is read off the delivery of a head member's first atom (wire.md §The
/// other endpoints) — the pair an `H.k` names, re-read byte-equal at the
/// resume (`search.md` §5.4); `None` where the delivery holds no such
/// record.
#[cfg_attr(not(feature = "search"), allow(dead_code))]
pub(crate) fn head_pair(v: &Value) -> Option<(u64, [u8; 32])> {
    let bytes = first_atom(v)?;
    let rec: Value = serde_json::from_slice(&bytes).ok()?;
    if rec["type"].as_str() != Some("skep-head") {
        return None;
    }
    Some((rec["position"].as_u64()?, rec["chain"].as_str().and_then(crate::hex::decode32)?))
}

/// One pair of a `compare` answer (wire.md §The response envelope).
///
/// It is a shared run of `width` positions at content ordinal `u1` in `d1`
/// and `u2` in `d2` — the jump's landing rule reads these (`search.md`
/// §3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Correspondence {
    /// The first operand's document.
    pub d1: String,
    /// The second operand's document.
    pub d2: String,
    /// The run's first content ordinal in `d1`.
    pub u1: u64,
    /// The run's first content ordinal in `d2`.
    pub u2: u64,
    /// The run's positions.
    pub width: u64,
}

/// Returns a `compare` answer's pairs, in the order served.
///
/// Each is over the content subspace; `None` for a document that is no such
/// answer, or one whose pair names another subspace or does not parse — the
/// landing rule reads a whole answer or none.
#[cfg_attr(not(feature = "search"), allow(dead_code))]
pub(crate) fn compare_pairs(v: &Value) -> Option<Vec<Correspondence>> {
    if v["resp"].as_str() != Some("compare") {
        return None;
    }
    let ordinal = |p: &Value| -> Option<u64> {
        (p["subspace"].as_str() == Some("1")).then(|| p["ordinal"].as_str()?.parse().ok()).flatten()
    };
    v["pairs"]
        .as_array()?
        .iter()
        .map(|pair| {
            Some(Correspondence {
                d1: pair["d1"].as_str()?.to_string(),
                d2: pair["d2"].as_str()?.to_string(),
                u1: ordinal(&pair["u1"])?,
                u2: ordinal(&pair["u2"])?,
                width: pair["width"].as_str()?.parse().ok()?,
            })
        })
        .collect()
}

/// Returns a `delivery`'s items as the value at each position, in order.
///
/// The values follow wire.md §Value encodings: a `content` item's bytes one
/// per position, a `hex` run's likewise, an `atom` or `atom_hex` item the
/// one composite value at its position — the values a `publish` body
/// spells, and the value rule compares, one item a position. `None` for a
/// document that is no delivery, and for an item that is no value a caller
/// can spell: a `withheld` run, a `ref`, a hex that does not decode, a kind
/// this crate does not know.
#[cfg_attr(not(feature = "merge"), allow(dead_code))]
pub(crate) fn delivery_values(v: &Value) -> Option<Vec<Vec<u8>>> {
    if v["resp"].as_str() != Some("delivery") {
        return None;
    }
    let mut out = Vec::new();
    for item in v["items"].as_array()? {
        if let Some(text) = item["content"].as_str() {
            out.extend(text.bytes().map(|b| vec![b]));
        } else if let Some(hex) = item["hex"].as_str() {
            out.extend(crate::hex::decode(hex)?.into_iter().map(|b| vec![b]));
        } else if let Some(text) = item["atom"].as_str() {
            out.push(text.as_bytes().to_vec());
        } else if let Some(hex) = item["atom_hex"].as_str() {
            out.push(crate::hex::decode(hex)?);
        } else {
            return None;
        }
    }
    Some(out)
}

/// A `doc_metadata` answer's terms (wire.md §The response envelope).
///
/// They are the publication bit, the owner account, and the shot terms a
/// member carries — `placed`, the positions the client's runs cover, and
/// `base_extent` — each `None` where the address carries none.
#[cfg_attr(not(feature = "merge"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Metadata {
    pub(crate) published: bool,
    pub(crate) owner: String,
    pub(crate) placed: Option<u64>,
    pub(crate) base_extent: Option<u64>,
}

/// Decodes a `doc_metadata` answer.
///
/// `None` for a document that is no such answer — a rejection among them —
/// or one without its owner or its `published` bit.
#[cfg_attr(not(feature = "merge"), allow(dead_code))]
pub(crate) fn metadata(v: &Value) -> Option<Metadata> {
    if v["resp"].as_str() != Some("doc_metadata") {
        return None;
    }
    let count = |member: &str| v[member].as_str().and_then(natural);
    Some(Metadata {
        published: v["published"].as_bool()?,
        owner: v["owner"].as_str()?.to_string(),
        placed: count("placed"),
        base_extent: count("base_extent"),
    })
}

/// One claim of an `in_claims` or `out_claims` answer.
///
/// It holds the claim's address, its `old`, its `new`, its home and whether
/// it is active (wire.md §The response envelope, `claims`).
#[cfg_attr(not(feature = "merge"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Claim {
    pub(crate) claim: String,
    pub(crate) old: String,
    pub(crate) new: String,
    pub(crate) home: String,
    pub(crate) active: bool,
}

/// Returns a `claims` answer's rows in the order served.
///
/// Empty for a document that is no such answer, a row missing a member
/// dropped — save `active`, which an absent member leaves true.
#[cfg_attr(not(feature = "merge"), allow(dead_code))]
pub(crate) fn claims(v: &Value) -> Vec<Claim> {
    if v["resp"].as_str() != Some("claims") {
        return Vec::new();
    }
    v["claims"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| {
            Some(Claim {
                claim: row["claim"].as_str()?.to_string(),
                old: row["old"].as_str()?.to_string(),
                new: row["new"].as_str()?.to_string(),
                home: row["home"].as_str()?.to_string(),
                active: row["active"].as_bool().unwrap_or(true),
            })
        })
        .collect()
}

/// Returns an answer's `as_of` (wire.md §The response envelope).
///
/// It is `None` where the document carries none.
#[cfg_attr(not(feature = "merge"), allow(dead_code))]
pub(crate) fn as_of(v: &Value) -> Option<u64> {
    v["as_of"].as_u64()
}

/// Returns how many content positions a `span_set` answer arranges.
///
/// The answer is `retrieve_doc_v_span_set`'s; the count is the width of its
/// span at the content subspace's first position, `1.1` — and 0 where no
/// content stands.
pub(crate) fn content_extent(v: &Value) -> u64 {
    v["set"]
        .as_array()
        .and_then(|s| s.iter().find(|x| x["start"].as_str() == Some("1.1")))
        .and_then(|s| s["width"].as_str()?.rsplit('.').next()?.parse().ok())
        .unwrap_or(0)
}

/// The most runs an `image` answer carries — M8's run budget.
///
/// The budget is `MAX_IMAGE_RUNS`; a read past it is `image_too_large`
/// (wire.md §Rejection codes). The number alone is mirrored here, as the
/// delivery budget is beside the feed consumer.
pub(crate) const MAX_IMAGE_RUNS: usize = 1 << 12;

/// One run of an `image` answer.
///
/// It holds `width` content I-addresses from `first` — each the run's
/// `prefix` and one ordinal — arranged from V-ordinal `ordinal` on, in
/// order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IRun {
    /// The I-addresses' components before their last.
    pub(crate) prefix: String,
    /// The first I-address's last component.
    pub(crate) first: u64,
    /// The I-addresses the run holds.
    pub(crate) width: u64,
    /// The V-ordinal the run's first I-address is arranged at.
    pub(crate) ordinal: u64,
}

/// Returns an `image` answer's I-map over content ordinals `1 ..= extent`.
///
/// The map is the answer's runs in V order — AUTH-2.114's I→V inversion, the
/// deposit's read-back and the admitted read alike; [`ordinal_of`] answers
/// an I-address's V-ordinal off it. `None` for a document that is no `runs`
/// answer, a run that does not parse, more runs than the run budget, a run
/// whose last I-address passes the range, or widths that arrange more
/// positions than the extent asked: one unreadable run would shift every
/// ordinal after it onto another position's bytes, so the map is whole or
/// absent, and its size is the runs' whatever widths the board names. Both
/// readers reach a record's bytes through the arrangement and never by
/// identity (`retrieve_i`): an atom a later edit un-arranged must fail the
/// read-back (AUTH-2.115).
pub(crate) fn i_runs(v: &Value, extent: u64) -> Option<Vec<IRun>> {
    if v["resp"].as_str() != Some("runs") {
        return None;
    }
    let runs = v["runs"].as_array()?;
    if runs.len() > MAX_IMAGE_RUNS {
        return None;
    }
    let mut arranged: u64 = 0;
    let mut out = Vec::with_capacity(runs.len());
    for run in runs {
        let (prefix, last) = run["i_start"].as_str()?.rsplit_once('.')?;
        let first = natural(last)?;
        let width = natural(run["width"].as_str()?)?;
        // The run's last I-address, `first + width - 1`, within the range.
        first.checked_add(width.saturating_sub(1))?;
        let ordinal = arranged.checked_add(1)?;
        arranged = arranged.checked_add(width).filter(|a| *a <= extent)?;
        out.push(IRun { prefix: prefix.to_string(), first, width, ordinal });
    }
    Some(out)
}

/// Returns the V-ordinal `atom` is arranged at among `runs`, in V order.
///
/// The first run holding it answers; `None` where no run does.
pub(crate) fn ordinal_of(runs: &[IRun], atom: &str) -> Option<u64> {
    let (prefix, last) = atom.rsplit_once('.')?;
    let n = natural(last)?;
    runs.iter()
        .find(|r| r.prefix == prefix && r.first <= n && n - r.first < r.width)
        .and_then(|r| r.ordinal.checked_add(n - r.first))
}

/// Parses a natural in its one spelling.
///
/// The spelling is decimal digits, no sign, no leading zero. The value must
/// lie within `u64`; any other text is `None`.
fn natural(text: &str) -> Option<u64> {
    let canonical = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) && (text == "0" || !text.starts_with('0'));
    canonical.then(|| text.parse().ok()).flatten()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// wire.md's own example answers, decoded.
    ///
    /// They are the `addrs` of a discovery, the slots of a `read_link`, the
    /// extent of a `span_set`.
    #[test]
    fn the_reads_decode_the_wires_own_examples() {
        assert_eq!(addrs(&json!({"addrs":["1.0.1.0.1.0.2.1"],"as_of":9,"resp":"addrs"})), ["1.0.1.0.1.0.2.1"]);
        assert!(addrs(&json!({"as_of":9,"n":2,"resp":"count"})).is_empty());
        let link = json!({"as_of":9,"link":{"slots":[[{"start":"1.0.1.0.1.0.1.1","width":"0.0.0.0.0.0.0.5"}],[{"start":"1.0.1.0.2.0.1.1","width":"0.0.0.0.0.0.0.6"}],[{"start":"1.0.1.0.3.0.1.1","width":"0.0.0.0.0.0.0.1"}]]},"resp":"link_value"});
        assert_eq!((link_from(&link), link_to(&link)), (Some("1.0.1.0.1.0.1.1"), Some("1.0.1.0.2.0.1.1")));
        assert_eq!(link_to(&json!({"as_of":9,"link":null,"resp":"link_value"})), None);
        assert_eq!(content_extent(&json!({"as_of":9,"resp":"span_set","set":[{"start":"1.1","width":"0.5"}]})), 5);
        assert_eq!(content_extent(&json!({"as_of":9,"resp":"span_set","set":[]})), 0);
    }

    /// A record's value is a delivery's composite item, `atom` or `atom_hex`.
    ///
    /// It is never a run of per-byte values, whatever it spells.
    #[test]
    fn the_first_atom_is_a_composite_value_and_never_a_run() {
        assert_eq!(first_atom(&json!({"as_of":9,"items":[{"content":"hi"},{"atom":"chunk"}],"resp":"delivery"})), None, "a run is first");
        assert_eq!(first_atom(&json!({"as_of":9,"items":[{"atom":"chunk"}],"resp":"delivery"})).as_deref(), Some(&b"chunk"[..]));
        assert_eq!(first_atom(&json!({"as_of":9,"items":[{"atom_hex":"00ff"}],"resp":"delivery"})).as_deref(), Some(&[0x00, 0xff][..]));
        assert_eq!(first_atom(&json!({"as_of":9,"items":[{"ref":"1.0.1.0.1.0.2.1"}],"resp":"delivery"})), None);
        assert_eq!(first_atom(&json!({"code":"withheld","op":"retrieve_v","resp":"rejected"})), None);
    }

    /// The `runs` example maps its five I-positions to ordinals 1–5.
    ///
    /// A second run continues the count; one run that does not parse leaves
    /// no map, never a shifted one.
    #[test]
    fn the_i_map_is_whole_or_absent() {
        let one = json!({"as_of":9,"resp":"runs","runs":[{"i_start":"1.0.1.0.1.0.1.1","width":"5"}]});
        let runs = i_runs(&one, 5).expect("a whole map");
        assert_eq!((ordinal_of(&runs, "1.0.1.0.1.0.1.1"), ordinal_of(&runs, "1.0.1.0.1.0.1.5")), (Some(1), Some(5)));
        assert_eq!((ordinal_of(&runs, "1.0.1.0.1.0.1.6"), ordinal_of(&runs, "1.0.1.0.1.0.2.1")), (None, None));
        let two = json!({"resp":"runs","runs":[{"i_start":"1.0.1.0.1.0.1.4","width":"1"},{"i_start":"1.0.1.0.1.0.1.9","width":"2"}]});
        let runs = i_runs(&two, 3).expect("a whole map");
        let ordinals: Vec<Option<u64>> = ["1.0.1.0.1.0.1.4", "1.0.1.0.1.0.1.9", "1.0.1.0.1.0.1.10", "1.0.1.0.1.0.1.5"].iter().map(|a| ordinal_of(&runs, a)).collect();
        assert_eq!(ordinals, [Some(1), Some(2), Some(3), None]);
        let broken = json!({"resp":"runs","runs":[{"i_start":"1.0.1.0.1.0.1.1","width":"x"},{"i_start":"1.0.1.0.1.0.1.9","width":"1"}]});
        assert_eq!(i_runs(&broken, 5), None);
        assert_eq!(i_runs(&json!({"resp":"runs","runs":[]}), 5), Some(Vec::new()));
    }

    /// The map's size is its runs' and never the widths' a board names.
    ///
    /// A run past the extent asked, a run whose last I-address passes the
    /// range, more runs than the run budget and a refusal each answer no map,
    /// and a run as wide as the range answers its ordinal at once.
    #[test]
    fn the_i_map_is_bounded_by_its_runs_and_the_extent_asked() {
        let wide = json!({"resp":"runs","runs":[{"i_start":"1.0.1.0.1.0.1.1","width":"18446744073709551615"}]});
        assert_eq!(i_runs(&wide, 5), None, "a run past the extent asked");
        let runs = i_runs(&wide, u64::MAX).expect("one run");
        assert_eq!(runs.len(), 1);
        assert_eq!(ordinal_of(&runs, "1.0.1.0.1.0.1.3"), Some(3));
        let top = json!({"resp":"runs","runs":[{"i_start":"1.0.1.0.1.0.1.18446744073709551615","width":"2"}]});
        assert_eq!(i_runs(&top, 5), None, "the run's last I-address past the range");
        let many: Vec<Value> = (1..=MAX_IMAGE_RUNS as u64 + 1).map(|k| json!({"i_start": format!("1.0.1.0.1.0.1.{}", 2 * k), "width": "1"})).collect();
        assert_eq!(i_runs(&json!({"resp":"runs","runs":many}), u64::MAX), None, "past the run budget");
        assert_eq!(i_runs(&json!({"code":"image_too_large","op":"image","resp":"rejected"}), 5), None);
        let padded = json!({"resp":"runs","runs":[{"i_start":"1.0.1.0.1.0.1.01","width":"1"}]});
        assert_eq!(i_runs(&padded, 5), None, "a component off its one spelling");
    }
}
