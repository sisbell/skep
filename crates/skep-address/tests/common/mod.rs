//! Shared literal-construction helpers for the integration tests.
#![allow(dead_code)] // each test binary uses a subset of these helpers

use skep_address::{validate, Address, Nat, Span, SpanSet, Tumbler};

/// ℕ literal.
pub fn n(x: u32) -> Nat {
    Nat::from(x)
}

/// Tumbler literal from small components.
pub fn t(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
}

/// Tumbler literal from arbitrary ℕ components — the door for magnitudes no
/// `u32` literal reaches.
pub fn tw(comps: impl IntoIterator<Item = Nat>) -> Tumbler {
    Tumbler::new(comps).expect("test tumblers are nonempty")
}

/// 2⁶⁴ — a component no fixed-width representation holds (T0(a)).
pub fn wide() -> Nat {
    Nat::from(u64::MAX) + Nat::from(1u32)
}

/// Every tumbler of length `1..=max_len` over `alphabet`, in odometer order —
/// the mechanical family a law is asserted over, so the cases it visits are
/// not the ones a test author would have chosen.
pub fn tumblers_upto(alphabet: &[u32], max_len: usize) -> Vec<Tumbler> {
    let mut out: Vec<Tumbler> = Vec::new();
    let mut rows: Vec<Vec<u32>> = vec![Vec::new()];
    for _ in 0..max_len {
        let mut next = Vec::with_capacity(rows.len() * alphabet.len());
        for row in &rows {
            for &c in alphabet {
                let mut r = row.clone();
                r.push(c);
                next.push(r);
            }
        }
        rows = next;
        out.extend(rows.iter().map(|r| t(r)));
    }
    out
}

/// T4-valid Address literal.
pub fn addr(comps: &[u32]) -> Address {
    validate(t(comps)).expect("test addresses are T4-valid")
}

/// Level-uniform span from endpoints.
pub fn sp(s: &[u32], r: &[u32]) -> Span {
    Span::from_endpoints(t(s), &t(r)).expect("test spans are well-formed")
}

/// Span-set collected as-given (un-normalized).
pub fn set(spans: &[Span]) -> SpanSet {
    spans.iter().cloned().collect()
}
