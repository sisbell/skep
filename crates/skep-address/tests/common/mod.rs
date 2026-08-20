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
