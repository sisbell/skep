//! §A — tumbler value, identity, order (ASN-0034: T0–T3, TA-PosDom).

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::error::EmptySequence;

/// ℕ. Unbounded component magnitude is T0(a) and non-negotiable: a fixed-width
/// component would be a spec violation absent a discharged finite-model proof
/// (the reference design's recorded digit-overflow wrap). `⊕` touches exactly
/// one component — no carry propagation — so arbitrary precision is paid at
/// one position, not across the address.
pub type Nat = num_bigint::BigUint;

/// 1-based component index, matching the spec's `t₁..t_{#t}` (implemented over
/// 0-based storage). T0(b) leaves the component *count* unbounded in
/// principle, but 2⁶⁴ components is unreachable, so `usize` is safe without
/// violating the spec (unlike a fixed component-magnitude width, which would).
pub type Pos = usize;

/// True iff a component is the ℕ zero (allocation- and trait-free:
/// `bits() == 0 ⟺ value = 0`).
pub(crate) fn nat_is_zero(c: &Nat) -> bool {
    c.bits() == 0
}

/// A tumbler: an immutable, **nonempty** sequence of ℕ components with zeros
/// stored explicitly — the literal component sequence (T0). Canonical identity
/// (T3) holds **by construction**: no mantissa/exponent, no normalization map,
/// no quotient — the representation admits no aliases, deleting the reference
/// design's leading-zero alias bug class outright.
///
/// Zero and leading-zero sequences are legal *carrier* elements (span
/// sentinels and displacement values — TA6), but they are not addresses;
/// address admission is [`crate::validate`].
///
/// Serde: the derived `Serialize` (a newtype over the sequence) emits the bare
/// `Vec<Nat>` shape; `Deserialize` is a mint path and routes through
/// [`Tumbler::new`] via the `try_from` shadow, re-checking T0 nonemptiness at
/// the trust boundary (design preamble: validating deserialization, never a
/// bare derive).
///
/// OPEN DECISION: storage is a plain contiguous `Vec<Nat>` — the simplest
/// contiguous form, which the `&[Nat]` field projections (§B) rely on. The
/// design's small-length inline-buffer refinement and the `im::Vector`
/// alternative are profiling-gated options, not defaults; `im` earns its keep
/// on span-sets, not on the short flat tumbler.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "Vec<Nat>")]
pub struct Tumbler(Vec<Nat>);

#[allow(clippy::len_without_is_empty)] // len ≥ 1 by invariant: is_empty would be constantly false, and the interface does not declare it
impl Tumbler {
    /// Carrier admission only (T0): rejects the empty sequence; admits zero
    /// and leading-zero sequences (legal carrier elements and legal span
    /// sentinels — NOT addresses).
    pub fn new(comps: impl IntoIterator<Item = Nat>) -> Result<Tumbler, EmptySequence> {
        let comps: Vec<Nat> = comps.into_iter().collect();
        if comps.is_empty() {
            Err(EmptySequence)
        } else {
            Ok(Tumbler(comps))
        }
    }

    /// `#t` — the component count.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `tᵢ`, **1-based** (the spec's indexing). PANICS on `i = 0` or `i > #t`
    /// — the documented panic contract for a low-level accessor.
    pub fn get(&self, i: Pos) -> &Nat {
        assert!(
            i >= 1 && i <= self.0.len(),
            "Tumbler::get: 1-based index {} out of range 1..={}",
            i,
            self.0.len()
        );
        &self.0[i - 1]
    }

    /// Internal 0-based view of the component sequence.
    pub(crate) fn comps(&self) -> &[Nat] {
        &self.0
    }

    /// Internal constructor for sequences known nonempty by construction.
    pub(crate) fn from_vec(comps: Vec<Nat>) -> Tumbler {
        debug_assert!(!comps.is_empty(), "internal tumbler construction must be nonempty");
        Tumbler(comps)
    }
}

/// Deserialization mint path: `Vec<Nat>` → `Tumbler` through [`Tumbler::new`]
/// (T0), so no journal replay can mint an empty tumbler.
impl TryFrom<Vec<Nat>> for Tumbler {
    type Error = EmptySequence;
    fn try_from(comps: Vec<Nat>) -> Result<Tumbler, EmptySequence> {
        Tumbler::new(comps)
    }
}

/// T1/T2 — the intrinsic lexicographic total order, **prefix-smaller**,
/// defined over *all* of carrier T including zero tumblers (TA-PosDom:
/// positive > zero), with no special-casing of zero separators. This
/// zero-agnostic flatness is load-bearing: it is why an all-zero sequence
/// sorts below everything and can serve as a span lower-bound sentinel, and
/// hierarchy is projected on top (§B), never baked into the comparator.
/// `Vec`'s slice ordering is exactly this order; the delegation is deliberate.
impl Ord for Tumbler {
    fn cmp(&self, other: &Tumbler) -> Ordering {
        self.0.cmp(&other.0)
    }
}

/// Exists only to satisfy `Ord: PartialOrd + Eq`; agrees with [`Ord`].
impl PartialOrd for Tumbler {
    fn partial_cmp(&self, other: &Tumbler) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// `p ≼ q` — `p` is a (possibly improper) prefix of `q`.
pub fn is_prefix(p: &Tumbler, q: &Tumbler) -> bool {
    p.len() <= q.len() && p.comps() == &q.comps()[..p.len()]
}
