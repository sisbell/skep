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

/// Render any tumbler dotted ("1.1.0.1"), matching the golden encoding.
pub fn tum_str(t: &Tumbler) -> String {
    let mut s = String::new();
    for i in 1..=t.len() {
        if i > 1 {
            s.push('.');
        }
        s.push_str(&t.get(i).to_string());
    }
    s
}

/// Render an address dotted.
pub fn addr_str(a: &Address) -> String {
    tum_str(a.tumbler())
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
