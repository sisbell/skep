//! §A — tumbler value, identity, order (ASN-0034: T0–T3, TA-PosDom).

use std::cmp::Ordering;
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

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

/// [`Tumbler::new`] on the empty sequence — T0's carrier is the *nonempty*
/// finite sequences over ℕ (resolves ASN-0045's empty-tumbler question
/// upstream: `[]` is not a tumbler at all, so the classifier never sees it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptySequence;

impl fmt::Display for EmptySequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("empty component sequence (T0 admits only nonempty tumblers)")
    }
}
impl Error for EmptySequence {}

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

    /// `tᵢ`, **1-based** (the spec's indexing) and **total**: `None` for
    /// `i = 0` and for `i > #t`. Out of range is an answer, not a fault, so
    /// nothing has to establish `#t` before it asks — and a caller that HAS
    /// established it discharges that fact at the read, with an `expect` whose
    /// message names the obligation relied on. Fallible like every other `get`
    /// in std.
    pub fn get(&self, i: Pos) -> Option<&Nat> {
        i.checked_sub(1).and_then(|z| self.0.get(z))
    }

    /// The component sequence in order, `t₁..t_{#t}` — the walk every
    /// rendering, encoding and prefix-reconstruction path needs. Borrowing,
    /// because a tumbler is a value (T0) rather than a container to dismantle:
    /// the way to a new one is [`Tumbler::new`].
    pub fn iter(&self) -> Components<'_> {
        Components(self.0.iter())
    }

    /// Internal 0-based view of the component sequence.
    pub(crate) fn comps(&self) -> &[Nat] {
        &self.0
    }

    /// Internal constructor for sequences a call site has already established
    /// nonempty — by the arithmetic (`⊕` writes at least the action point,
    /// `⊖` at least one padded position) or by a T4 clause (the peel in
    /// [`crate::parent`] survives because no valid address leads with a zero).
    ///
    /// The check runs in EVERY build, not only under debug assertions: T0 is
    /// what the validating scan's first- and last-component reads and
    /// [`crate::ordinal`]'s last-component read stand on, so a call site whose
    /// premise moved is named here rather than surfacing as an anonymous index
    /// panic two functions away. One branch, beside an allocation already paid
    /// for.
    pub(crate) fn from_vec(comps: Vec<Nat>) -> Tumbler {
        assert!(!comps.is_empty(), "internal tumbler construction must be nonempty");
        Tumbler(comps)
    }
}

/// The component sequence of a [`Tumbler`], in order. Opaque, so the storage
/// decision above stays open: the sequence is what a caller walks, and the
/// container it is walked out of is the tumbler's own business.
///
/// Opacity hides the *container*, never the walk's capabilities: the reverse
/// walk, the exact length and the fused guarantee are all forwarded below,
/// because the tail of a tumbler is where the meaning is — `sig` is an
/// `rposition`, `ordinal` is a `last`, and a caller that could not reach
/// backwards would have to clone every component to read the final two.
#[derive(Debug, Clone)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Components<'a>(std::slice::Iter<'a, Nat>);

impl<'a> Iterator for Components<'a> {
    type Item = &'a Nat;
    fn next(&mut self) -> Option<&'a Nat> {
        self.0.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl<'a> DoubleEndedIterator for Components<'a> {
    fn next_back(&mut self) -> Option<&'a Nat> {
        self.0.next_back()
    }
}

impl ExactSizeIterator for Components<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl std::iter::FusedIterator for Components<'_> {}

impl<'a> IntoIterator for &'a Tumbler {
    type Item = &'a Nat;
    type IntoIter = Components<'a>;
    fn into_iter(self) -> Components<'a> {
        self.iter()
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

/// The canonical rendering: components in order, `.`-separated (`1.0.2.0.5`).
/// Lossless and unambiguous by T3 — the representation admits no aliases, so
/// the text and the value determine each other. This is the dotted-decimal
/// form the daemon puts on the wire and the conformance harness compares
/// against the golden, spelled once here because `Display` is std's trait and
/// `Tumbler` is M1's type: no crate above can supply it.
impl fmt::Display for Tumbler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, c) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{c}")?;
        }
        Ok(())
    }
}

/// `p ≼ q` — `p` is a (possibly improper) prefix of `q`.
pub fn is_prefix(p: &Tumbler, q: &Tumbler) -> bool {
    p.len() <= q.len() && p.comps() == &q.comps()[..p.len()]
}
