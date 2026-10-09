//! Dotted-decimal tumbler helpers — the one place golden address/offset
//! strings ("1.1.0.1.0.1", "0.13") become skep `Tumbler`/`Address`/`Span`
//! values, a golden V-position or V-region is named as numbers ([`VPoint`],
//! [`VRegion`]), and a golden address string's shape is read (a link
//! address, and the document it lives under). The golden encoding is
//! client.py's `Tumbler.__str__`: period-separated components, zeros
//! explicit — which is M1's own `Display`, so a skep value renders back for
//! the report through `Display` and nothing here restates it.

use skep_address::{classify, validate, Address, Class, Nat, Span, Tumbler};
use skep_arrangement::{ordinal_vspan, VPos};

/// Parse "1.1.0.1" → component vector. `None` on empty or non-numeric
/// components (a non-address string like "source" simply fails here and the
/// caller treats it as a symbolic name).
pub fn parse_dotted(s: &str) -> Option<Vec<u64>> {
    if s.is_empty() {
        return None;
    }
    s.split('.').map(|c| c.parse::<u64>().ok()).collect()
}

/// Components → `Tumbler`. Panics on empty input — every caller passes a
/// nonempty literal or a `parse_dotted` result (nonempty by construction).
pub fn tumbler(comps: &[u64]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty component list")
}

/// Components → validated `Address`. `None` if not T4-valid.
pub fn addr(comps: &[u64]) -> Option<Address> {
    validate(tumbler(comps)).ok()
}

/// A golden V-position in numbers: subspace (1 content, 2 link) and 1-based
/// ordinal. Named fields for the reason skep-arrangement's `ordinal_vspan`
/// takes a `VPos`: same-typed numbers handed over positionally can swap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VPoint {
    pub sub: u64,
    pub ord: u64,
}

impl VPoint {
    /// The CONTENT position at `ord` — subspace 1, the one every edit
    /// writes to.
    pub fn content(ord: u64) -> VPoint {
        VPoint { sub: 1, ord }
    }

    /// The `width` positions from here.
    pub fn region(self, width: u64) -> VRegion {
        VRegion { sub: self.sub, ord: self.ord, width }
    }

    /// skep's V-position for this point.
    pub fn vpos(self) -> VPos {
        VPos { subspace: Nat::from(self.sub), ordinal: Nat::from(self.ord) }
    }
}

/// A golden V-region in numbers: `width` positions from (`sub`, `ord`) — a
/// recording's `{start, width}` span. No positional constructor: a region
/// is a struct literal, or a [`VPoint`] given its width
/// ([`VPoint::region`]), so each number is named where it is chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VRegion {
    pub sub: u64,
    pub ord: u64,
    pub width: u64,
}

impl VRegion {
    /// The position the region opens at.
    pub fn at(self) -> VPoint {
        VPoint { sub: self.sub, ord: self.ord }
    }

    /// skep's V-span for this region, built by skep-arrangement's own
    /// `ordinal_vspan` — the depth-2 ordinal-level shape every content/link
    /// subspace read and every M7/M5 V-spec demands. `None` iff
    /// `width == 0`: T12 rejects a zero width, and the golden encodes
    /// emptiness as an absent span, never a zero span.
    pub fn span(self) -> Option<Span> {
        ordinal_vspan(self.at().vpos(), Nat::from(self.width))
    }
}

/// A golden local V-position: "1.5" → subspace 1, ordinal 5; "2.1" →
/// subspace 2, ordinal 1. A bare integer is a content ordinal (subspace 1).
pub fn parse_vpos(s: &str) -> Option<VPoint> {
    match parse_dotted(s)?.as_slice() {
        [ord] => Some(VPoint::content(*ord)),
        [sub, ord] => Some(VPoint { sub: *sub, ord: *ord }),
        _ => None,
    }
}

/// A golden local width offset: "0.13" → 13; "13" → 13. The golden encodes
/// ordinal-level widths as a two-component offset with leading zero.
pub fn parse_width(s: &str) -> Option<u64> {
    let c = parse_dotted(s)?;
    match c.as_slice() {
        [w] => Some(*w),
        [0, w] => Some(*w),
        _ => None,
    }
}

/// The document address a link address lives under, textually: strip the
/// final `0.2.n` local part ("1.1.0.1.0.1.0.2.1" → "1.1.0.1.0.1").
pub fn link_home_docid(link: &str) -> Option<String> {
    let comps = parse_dotted(link)?;
    if comps.len() >= 4 {
        let n = comps.len();
        if comps[n - 3] == 0 && comps[n - 2] == 2 && comps[n - 1] > 0 {
            let head: Vec<String> = comps[..n - 3].iter().map(|c| c.to_string()).collect();
            return Some(head.join("."));
        }
    }
    None
}

/// A link address in golden terms: `…·0·2·n` (a document's link subspace).
pub fn is_link_address(s: &str) -> bool {
    link_home_docid(s).is_some()
}

/// Is `s` a golden ADDRESS — dotted decimal that M1 classifies as an
/// account, a document or an element? A decimal ("2.5", "0123456789.1")
/// is a node tumbler or no address at all, so document text that happens
/// to be dotted is never mistaken for one.
pub fn is_golden_address(s: &str) -> bool {
    parse_dotted(s).is_some_and(|comps| {
        matches!(classify(&tumbler(&comps)), Class::Account | Class::Document | Class::Element)
    })
}

/// Render a skep V-span back to the golden `{start, width}` string pair.
pub fn span_strings(s: &Span) -> (String, String) {
    (s.start().to_string(), s.width().to_string())
}

/// Build a V-span from arbitrary-depth dotted start/width components — the
/// boundary corpus reads at NESTED local addresses ("1.1.1" width "0.0.1",
/// boundary_deep_vaddress_reads) that a depth-2 [`VRegion`] cannot speak but
/// skep's tumbler spans can; M6 answers them (empty or a typed rejection)
/// and the harness records what it says. `None` when the span itself is not
/// constructible (all-zero width).
pub fn deep_span(start: &[u64], width: &[u64]) -> Option<Span> {
    if start.is_empty() || width.is_empty() || width.iter().all(|&w| w == 0) {
        return None;
    }
    Span::new(tumbler(start), tumbler(width)).ok()
}

/// The final component of `t` as a `u64` — `None` when it does not fit.
pub fn last_component(t: &Tumbler) -> Option<u64> {
    u64::try_from(t.get(t.len())?).ok()
}

/// The element count of a span whose width is ordinal-level (`[…, 0, n]`
/// with a single trailing nonzero) — the shape of every content-element
/// I-extent `Run::iextent` yields. `None` for coarser widths.
pub fn span_elem_width(s: &Span) -> Option<u64> {
    let w = s.width();
    let last = last_component(w)?;
    let zero = Nat::from(0u64);
    if w.iter().take(w.len() - 1).any(|c| *c != zero) {
        return None;
    }
    Some(last)
}

/// Slice `len` elements starting `off` elements in from a contiguous
/// element-level span (start's final component advances by `off`; the width
/// keeps its shape with the final component set to `len`). Sound only for
/// spans whose elements are consecutive final-component ordinals — exactly
/// what a single I-extent run is. `None` on shape mismatch or empty result.
pub fn subspan(s: &Span, off: u64, len: u64) -> Option<Span> {
    if len == 0 {
        return None;
    }
    let total = span_elem_width(s)?;
    if off + len > total {
        return None;
    }
    let mut start: Vec<Nat> = s.start().iter().cloned().collect();
    *start.last_mut()? += off;
    let mut width = vec![0; s.width().len().saturating_sub(1)];
    width.push(len);
    Span::new(Tumbler::new(start).ok()?, tumbler(&width)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A region's span is skep-arrangement's depth-2 V-span — start
    /// `[sub, ord]`, width `[0, width]` — read back as the golden wrote it,
    /// and an empty region has none.
    #[test]
    fn a_region_spans_from_its_point() {
        let at = parse_vpos("2.3").expect("a V-position");
        assert_eq!(at, VPoint { sub: 2, ord: 3 });
        assert_eq!(parse_vpos("7"), Some(VPoint::content(7)));
        let span = at.region(4).span().expect("a nonempty region");
        assert_eq!(span_strings(&span), ("2.3".to_string(), "0.4".to_string()));
        assert_eq!(at.region(4).at(), at);
        assert_eq!(at.region(0).span(), None);
    }

    /// A golden address is an account, a document or an element; a dotted
    /// decimal is no address, and neither is a malformed tumbler.
    #[test]
    fn only_an_account_a_document_or_an_element_is_a_golden_address() {
        for address in ["1.1.0.1", "1.1.0.1.0.1", "1.1.0.1.0.1.0.2.1"] {
            assert!(is_golden_address(address), "{address}");
        }
        for text in ["2.5", "0123456789.1", "1.1", "0.5", "1.0", "1..2", "x", ""] {
            assert!(!is_golden_address(text), "{text}");
        }
    }
}
