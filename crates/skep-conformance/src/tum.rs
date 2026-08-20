//! Dotted-decimal tumbler helpers — the one place golden address/offset
//! strings ("1.1.0.1.0.1", "0.13") become skep `Tumbler`/`Address`/`Span`
//! values and skep values are rendered back for the report. The golden
//! encoding is client.py's `Tumbler.__str__`: period-separated components,
//! zeros explicit.

use skep_address::{validate, Address, Nat, Span, Tumbler};

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
pub fn tum(comps: &[u64]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty component list")
}

/// Components → validated `Address`. `None` if not T4-valid.
pub fn addr(comps: &[u64]) -> Option<Address> {
    validate(tum(comps)).ok()
}

/// Render any tumbler dotted ("1.1.0.1"), matching the golden encoding —
/// which is M1's own `Display`, so the harness compares against the goldens
/// using the tumbler's canonical text rather than a second rendering of it.
pub fn tum_str(t: &Tumbler) -> String {
    t.to_string()
}

/// Render an address dotted.
pub fn addr_str(a: &Address) -> String {
    a.to_string()
}

/// A golden local V-position: "1.5" → (subspace 1, ordinal 5); "2.1" →
/// (subspace 2, ordinal 1). A bare integer is a content ordinal (subspace 1).
pub fn parse_vpos(s: &str) -> Option<(u64, u64)> {
    let c = parse_dotted(s)?;
    match c.as_slice() {
        [ord] => Some((1, *ord)),
        [sub, ord] => Some((*sub, *ord)),
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

/// Build a depth-2 ordinal-level V-span — the shape every content/link
/// subspace read and every M7/M5 V-spec demands: start `[subspace, ord]`,
/// width `[0, w]`. `None` on `w == 0` (T12 rejects zero width; the golden
/// encodes emptiness as an absent span, never a zero span).
pub fn vspan(subspace: u64, ord: u64, w: u64) -> Option<Span> {
    Span::new(tum(&[subspace, ord]), tum(&[0, w])).ok()
}

/// Render a skep V-span back to the golden `{start, width}` string pair.
pub fn span_strings(s: &Span) -> (String, String) {
    (tum_str(s.start()), tum_str(s.width()))
}

/// Build a V-span from arbitrary-depth dotted start/width components — the
/// boundary corpus reads at NESTED local addresses ("1.1.1" width "0.0.1",
/// boundary_deep_vaddress_reads) that the depth-2 [`vspan`] cannot speak but
/// skep's tumbler spans can; M6 answers them (empty or a typed rejection)
/// and the harness records what it says. `None` when the span itself is not
/// constructible (all-zero width).
pub fn deep_span(start: &[u64], width: &[u64]) -> Option<Span> {
    if start.is_empty() || width.is_empty() || width.iter().all(|&w| w == 0) {
        return None;
    }
    Span::new(tum(start), tum(width)).ok()
}

/// The element count of a span whose width is ordinal-level (`[…, 0, n]`
/// with a single trailing nonzero) — the shape of every content-element
/// I-extent `Run::iextent` yields. `None` for coarser widths.
pub fn span_elem_width(s: &Span) -> Option<u64> {
    let w = s.width();
    let last: u64 = w.get(w.len())?.to_string().parse().ok()?;
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
    let st = s.start();
    let mut comps: Vec<u64> = st.iter().map(|c| c.to_string().parse().unwrap_or(0)).collect();
    let last = comps.len() - 1;
    comps[last] += off;
    let mut wcomps: Vec<u64> = vec![0; s.width().len().saturating_sub(1)];
    wcomps.push(len);
    Span::new(tum(&comps), tum(&wcomps)).ok()
}
