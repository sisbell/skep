//! The wire's READ answers, decoded (wire.md §The response envelope): the
//! read-side counterpart of [`frames`](super::frames), each answer shape this
//! crate reads spelled once — a discovery's `addrs`, a `read_link`'s slots, a
//! `delivery`'s first value, a `span_set`'s content extent and a `runs`
//! answer's I-map. Pure functions of a document the caller already holds:
//! the dial stays the caller's — under its token or as a guest — and with it
//! what the death signal means. The ack and refusal readers (`acked_at`,
//! `acked_addr`, [`Rejection`](super::Rejection)) stay at `board`'s root,
//! where `Board` itself and the suites read them.

// Every reader but `first_atom` — the board term's — is in the acting half;
// the feature-free build decodes the board term alone.
#![cfg_attr(not(feature = "acting"), allow(dead_code))]

use serde_json::Value;

/// A discovery's addresses — `find_links_*`, `find_docs_containing`,
/// `show_origin`, the `addrs` answer — in the order served; none where the
/// document is no such answer.
pub(crate) fn addrs(v: &Value) -> Vec<&str> {
    v["addrs"].as_array().into_iter().flatten().filter_map(Value::as_str).collect()
}

/// The first address a `read_link` answer's FROM slot names — a credential
/// link's record atom (AUTH-2.113).
pub(crate) fn link_from(v: &Value) -> Option<&str> {
    slot_start(v, 0)
}

/// The first address a `read_link` answer's TO slot names — a credential
/// link's subject, a supersession claim's new link.
pub(crate) fn link_to(v: &Value) -> Option<&str> {
    slot_start(v, 1)
}

/// The start of the first span of a `read_link` answer's slot at `index`,
/// the slots served in their read-back order: FROM, TO, TYPE.
fn slot_start(v: &Value, index: usize) -> Option<&str> {
    v["link"]["slots"].get(index)?.get(0)?["start"].as_str()
}

/// A `delivery`'s FIRST item read as the one composite value a record is
/// (wire.md §Content values): an `atom` item's text, or an `atom_hex` item's
/// bytes. `None` for any other item — a `content` or `hex` item is a RUN of
/// per-byte values and never a record's text, a `ref` a link position, a
/// `withheld` item a value the reader may not read — and for a document that
/// is no delivery.
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

/// One item of a `delivery`, as the wire types it (wire.md §Value
/// encodings) and before the search index's own typing: a `content` item's
/// bytes or a `hex` run's, an `atom`/`atom_hex` at one position, a
/// `withheld` run at its width with its origin, and an item kind this crate
/// does not know, kept at the width it carries by the wire's forward rule.
#[cfg_attr(not(feature = "search"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Delivered {
    /// One `content` item's UTF-8 bytes, or a `hex` run's bytes: one per
    /// position.
    Text(Vec<u8>),
    /// An `atom` or `atom_hex`: one position, a composite value.
    Atom,
    /// A `withheld` run: `width` positions, the origin document's address.
    Withheld { origin: String, width: u64 },
    /// A kind this crate does not know, at the width it carries (1 where it
    /// carries none).
    Unknown { width: u64 },
}

/// A `delivery`'s items in order with its `as_of` (wire.md §The response
/// envelope) — the feed consumer's read of a document's content, each item
/// typed as [`Delivered`]; `None` for a document that is no delivery, or
/// one whose `hex` run does not parse.
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

/// A `doc_metadata` answer's `published` bit (wire.md §Namespace); `None`
/// for a document that is no such answer — a rejection among them.
#[cfg_attr(not(feature = "search"), allow(dead_code))]
pub(crate) fn published(v: &Value) -> Option<bool> {
    (v["resp"].as_str() == Some("doc_metadata")).then(|| v["published"].as_bool()).flatten()
}

/// A `universal_grants` answer's rows (wire.md §Grants): each covered
/// prefix with the issuers who granted it, in the order served; empty for a
/// guest and for a document that is no such answer.
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

/// A `skep-head` record's `(position, chain)` pair (wire.md §The other
/// endpoints) off the delivery of a head member's first atom — the pair an
/// `H.k` names, re-read byte-equal at the resume (`search.md` §5.4);
/// `None` where the delivery holds no such record.
#[cfg_attr(not(feature = "search"), allow(dead_code))]
pub(crate) fn head_pair(v: &Value) -> Option<(u64, [u8; 32])> {
    let bytes = first_atom(v)?;
    let rec: Value = serde_json::from_slice(&bytes).ok()?;
    if rec["type"].as_str() != Some("skep-head") {
        return None;
    }
    Some((rec["position"].as_u64()?, rec["chain"].as_str().and_then(crate::hex::decode32)?))
}

/// One pair of a `compare` answer (wire.md §The response envelope): a shared
/// run of `width` positions at content ordinal `u1` in `d1` and `u2` in `d2`
/// — the jump's landing rule reads these (`search.md` §3.4).
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

/// A `compare` answer's pairs, in the order served, each over the content
/// subspace; `None` for a document that is no such answer, or one whose
/// pair names another subspace or does not parse — the landing rule reads a
/// whole answer or none.
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

/// The number of content positions a `retrieve_doc_v_span_set` answer
/// arranges — the width of its span at the content subspace's first
/// position, `1.1` — and 0 where no content stands.
pub(crate) fn content_extent(v: &Value) -> u64 {
    v["set"]
        .as_array()
        .and_then(|s| s.iter().find(|x| x["start"].as_str() == Some("1.1")))
        .and_then(|s| s["width"].as_str()?.rsplit('.').next()?.parse().ok())
        .unwrap_or(0)
}

/// THE I-MAP of an `image` answer over content ordinals `1 ..`: every
/// content I-address the region arranges, beside its V-ordinal, in V order —
/// AUTH-2.114's I→V inversion, the deposit's read-back and the admitted read
/// alike. `None` where a run does not parse: one unreadable run would shift
/// every ordinal after it onto another position's bytes, so the map is whole
/// or absent. Both readers reach a record's bytes THROUGH the arrangement
/// and never by identity (`retrieve_i`): an atom a later edit un-arranged
/// must fail the read-back (AUTH-2.115).
pub(crate) fn i_map(v: &Value) -> Option<Vec<(String, u64)>> {
    let mut map = Vec::new();
    let mut ordinal: u64 = 1;
    for run in v["runs"].as_array().into_iter().flatten() {
        let start = run["i_start"].as_str()?;
        let width: u64 = run["width"].as_str()?.parse().ok()?;
        let (prefix, last) = start.rsplit_once('.')?;
        let first: u64 = last.parse().ok()?;
        for k in 0..width {
            map.push((format!("{prefix}.{}", first + k), ordinal));
            ordinal += 1;
        }
    }
    Some(map)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// wire.md's own example answers, decoded: the `addrs` of a discovery,
    /// the slots of a `read_link`, the extent of a `span_set`.
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

    /// A record's value is a delivery's composite item, `atom` or
    /// `atom_hex` — never a run of per-byte values, whatever it spells.
    #[test]
    fn the_first_atom_is_a_composite_value_and_never_a_run() {
        assert_eq!(first_atom(&json!({"as_of":9,"items":[{"content":"hi"},{"atom":"chunk"}],"resp":"delivery"})), None, "a run is first");
        assert_eq!(first_atom(&json!({"as_of":9,"items":[{"atom":"chunk"}],"resp":"delivery"})).as_deref(), Some(&b"chunk"[..]));
        assert_eq!(first_atom(&json!({"as_of":9,"items":[{"atom_hex":"00ff"}],"resp":"delivery"})).as_deref(), Some(&[0x00, 0xff][..]));
        assert_eq!(first_atom(&json!({"as_of":9,"items":[{"ref":"1.0.1.0.1.0.2.1"}],"resp":"delivery"})), None);
        assert_eq!(first_atom(&json!({"code":"withheld","op":"retrieve_v","resp":"rejected"})), None);
    }

    /// The `runs` example maps its five I-positions to ordinals 1–5, a
    /// second run continuing the count; one run that does not parse leaves
    /// NO map, never a shifted one.
    #[test]
    fn the_i_map_is_whole_or_absent() {
        let one = json!({"as_of":9,"resp":"runs","runs":[{"i_start":"1.0.1.0.1.0.1.1","width":"5"}]});
        let map = i_map(&one).expect("a whole map");
        assert_eq!(map.len(), 5);
        assert_eq!(map[0], ("1.0.1.0.1.0.1.1".to_string(), 1));
        assert_eq!(map[4], ("1.0.1.0.1.0.1.5".to_string(), 5));
        let two = json!({"resp":"runs","runs":[{"i_start":"1.0.1.0.1.0.1.4","width":"1"},{"i_start":"1.0.1.0.1.0.1.9","width":"2"}]});
        assert_eq!(i_map(&two).expect("a whole map"), [("1.0.1.0.1.0.1.4".to_string(), 1), ("1.0.1.0.1.0.1.9".to_string(), 2), ("1.0.1.0.1.0.1.10".to_string(), 3)]);
        let broken = json!({"resp":"runs","runs":[{"i_start":"1.0.1.0.1.0.1.1","width":"x"},{"i_start":"1.0.1.0.1.0.1.9","width":"1"}]});
        assert_eq!(i_map(&broken), None);
        assert_eq!(i_map(&json!({"resp":"runs","runs":[]})), Some(Vec::new()));
    }
}
