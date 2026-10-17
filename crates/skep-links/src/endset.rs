//! M7's readable carrier types (§Core data model): endsets, links and `enc`.
//!
//! [`Endset`] is the verbatim span decomposition, [`Link`] a positional
//! sequence of endsets and [`enc`] the canonical address-set encoding. Their
//! type identity — the class every type, dedup and fence question compares —
//! is `class.rs`'s.

use std::fmt;

use im::Vector;
use serde::{Deserialize, Serialize};
use skep_address::{subtree_of, Address, Span, SpanSet, Tumbler};

/// An M7-owned endset: a readable finite span sequence, held verbatim.
///
/// What it holds is the as-created decomposition (observable via raw
/// read-back — ML2/RL1). Not M1's `SpanSet`, which is read-opaque to M7.
/// Coverage is a query-time projection ([`Endset::covers`]); the sequence is
/// read through [`Endset::spans`]/[`Endset::addrs`] and folds to a `SpanSet`
/// only at an M1-call boundary — the crate-internal whole-endset fold
/// FOLLOWLINK's read and [`coverage_class`](crate::coverage_class)'s
/// content-extent partition perform.
///
/// Derived `PartialEq`/`Eq`/`Hash` are structural (decomposition- and
/// span-order-sensitive) — serde/container plumbing only, never link or type
/// identity (§Core data model structural-derives contract): link identity is
/// the store address (L11b), type/dedup identity is
/// [`coverage_class`](crate::coverage_class). They are value identity — same
/// spans, same order — which is the right relation for deduplicating stored
/// endset values; they are not type identity, so nothing that means a type
/// (a registration, a type index, a catalog key) may key on them.
///
/// A span collection: `Default` is `⟨⟩`, `FromIterator<Span>` is the same
/// verbatim construction [`Endset::from_spans`] performs, so a span pipeline
/// `.collect()`s here, and `IntoIterator` walks the decomposition in both
/// forms — borrowed ([`Spans`], what [`Endset::spans`] lends) and owned
/// ([`IntoSpans`], the spans moved out of an endset the caller is finished
/// with, so `Endset::from_spans(e)` costs no `Tumbler` copies).
///
/// `Extend` is the one collection trait deliberately absent: it is a
/// `&mut self` mutator, and an endset is verbatim at rest (ML2/RL1) — the
/// decomposition a write deposited is the decomposition a read gets back.
/// Growing one means building the new sequence and constructing from it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endset(Vector<Span>);

impl FromIterator<Span> for Endset {
    fn from_iter<I: IntoIterator<Item = Span>>(spans: I) -> Endset {
        Endset::from_spans(spans)
    }
}

impl Endset {
    /// Returns `⟨⟩`, the empty endset.
    ///
    /// It is distinct from any zero-width span, which M1's span constructor
    /// rejects outright.
    pub fn empty() -> Endset {
        Endset(Vector::new())
    }

    /// Builds an endset from `spans`, verbatim.
    ///
    /// The spans are stored exactly as given, never normalized at rest
    /// (ML2/RL1): M1's canonical form is a query-time key
    /// ([`coverage_class`](crate::coverage_class)), never the stored shape.
    /// MAKELINK and M10 content successors build here.
    pub fn from_spans(spans: impl IntoIterator<Item = Span>) -> Endset {
        Endset(spans.into_iter().collect())
    }

    /// Returns the readable decomposition.
    ///
    /// L5 reads an endset by membership, not position — this iterator is a
    /// representation view, not a positional contract. The same walk
    /// `&Endset` yields.
    pub fn spans(&self) -> Spans<'_> {
        Spans(self.0.iter())
    }

    /// Returns the number of spans in the stored sequence.
    ///
    /// It is what the managed surface's [`Shape`](crate::Shape) gate counts.
    /// ASN-0126's `|F|` and `|G|` are set cardinalities, and the two agree
    /// exactly on a duplicate-free decomposition: every [`enc`]-built endset
    /// is one unless the caller names an address twice, and an
    /// `iextent`-built one (M5's construction) is one unless its resolution
    /// meets one I-extent twice — two specs naming one span, or content
    /// transcluded twice into what they name. A repeated span counts twice
    /// here and once there.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the endset is `⟨⟩`.
    ///
    /// The `e₃ ≠ ∅` write-boundary check (L3/ML6) reads this.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns whether some span of the endset contains `t`.
    ///
    /// That is `t ∈ coverage(e)`: `∃ s ∈ spans : s.contains(t)` — total over
    /// all of carrier T (the membership projection ASN-0086's pattern domain
    /// rides). Coverage, the coarser of the module's two matching regimes:
    /// every tumbler a span reaches, not just the addresses it denotes. The
    /// finer one — AD denotation, `x ∈ addrs(e)` — is [`Endset::addrs`].
    pub fn covers(&self, t: &Tumbler) -> bool {
        self.0.iter().any(|s| s.contains(t))
    }

    /// Returns the addresses the endset denotes (AD readback).
    ///
    /// Denotation, the finer regime: the start of each unit-depth span (a
    /// span `s` with `s == subtree_of(s.start())`); non-unit spans contribute
    /// nothing. `enc(X).addrs() = X`.
    pub fn addrs(&self) -> impl Iterator<Item = &Tumbler> {
        self.0.iter().filter(|s| is_unit_depth(s)).map(|s| s.start())
    }

    /// Returns whether every span is unit-depth — the address-denoting test.
    ///
    /// Vacuously true for `⟨⟩`. Selects
    /// [`coverage_class`](crate::coverage_class)'s exact denoted branch, and
    /// is verbatim the admission rule of the managed surface's `ty`
    /// (`NonAddressDenotingType`), so a caller can ask before it is refused.
    /// Strictly stronger than [`Endset::is_level_uniform`], which is what
    /// [`coverage_class`](crate::coverage_class) itself requires.
    pub fn is_address_denoting(&self) -> bool {
        self.spans().all(is_unit_depth)
    }

    /// Returns whether every span is level-uniform (`#start = #width`).
    ///
    /// That is exactly [`coverage_class`](crate::coverage_class)'s
    /// precondition, and the test a caller applies to an endset of its own
    /// making. Implied by [`Endset::is_address_denoting`] (a unit-depth span
    /// is its own start's subtree, so start and width share a length) and
    /// strictly weaker than it: a content endset of M5 `Run::iextent`s passes
    /// this, fails that wherever a run is wider than one position, and is a
    /// legal `coverage_class` input.
    pub fn is_level_uniform(&self) -> bool {
        self.spans().all(Span::is_level_uniform)
    }

    /// Returns the one address the endset denotes, if it denotes exactly one.
    ///
    /// It is the "unit-depth single-addr" slot test (ASN-0125 Df-DISC(ii)
    /// schema; the BH3 `target_of` single-address-G rule): every span
    /// unit-depth and exactly one distinct denoted address. A pure question
    /// about this endset, so it sits beside the module's other projections.
    ///
    /// This is what the `[K_sup]` sole-writer fences establish of every stored
    /// claim, and the test a reader of one applies to read its endpoints back
    /// — never [`Shape`](crate::Shape), whose span-count conformance is a gate
    /// on the managed surface and says nothing about denotation. Strictly
    /// stronger than `addrs().next()`, which takes the first unit-depth start
    /// where this refuses a slot naming several distinct addresses; the two
    /// agree on every claim the fences admit.
    pub fn single_denoted(&self) -> Option<&Tumbler> {
        if !self.is_address_denoting() {
            return None;
        }
        let mut denoted = self.addrs();
        let first = denoted.next()?;
        if denoted.any(|t| t != first) {
            return None;
        }
        Some(first)
    }

    /// Returns the endset folded whole into a `SpanSet` — the one such fold.
    ///
    /// Crate-internal: concatenation, order-preserving, exactly M1's
    /// singleton+union, where an endset meets M1's set algebra — FOLLOWLINK's
    /// (F1/F3) read and [`coverage_class`](crate::coverage_class)'s partition
    /// of a content extent.
    pub(crate) fn to_spanset(&self) -> SpanSet {
        self.0.iter().cloned().collect()
    }
}

/// The borrowed component spans of an [`Endset`], in stored order.
///
/// They are what [`Endset::spans`] lends and what `&Endset` yields. Opaque,
/// so the storage decision stays M7's: the sequence is what a caller walks,
/// and the container it is walked out of is the endset's own business.
///
/// Opacity hides the *container*, never the walk's capabilities: the reverse
/// walk, the exact length and the fused guarantee are forwarded below, so a
/// reader of a slot need not collect it to size it or to read it from the
/// end. `Clone` is the one capability that does not reach the caller —
/// `im`'s vector iterator is not cloneable — so a caller that needs two
/// independent cursors takes them from the endset, which is.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Spans<'a>(<&'a Vector<Span> as IntoIterator>::IntoIter);

impl<'a> Iterator for Spans<'a> {
    type Item = &'a Span;
    fn next(&mut self) -> Option<&'a Span> {
        self.0.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl<'a> DoubleEndedIterator for Spans<'a> {
    fn next_back(&mut self) -> Option<&'a Span> {
        self.0.next_back()
    }
}

impl ExactSizeIterator for Spans<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl std::iter::FusedIterator for Spans<'_> {}

/// Prints the cursor, not the spans.
///
/// The backing's iterator is neither `Clone` nor `Debug`, so there is no way
/// to show what is left without consuming it, and the endset it came from is
/// `Debug` already.
impl fmt::Debug for Spans<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Spans").finish_non_exhaustive()
    }
}

impl<'a> IntoIterator for &'a Endset {
    type Item = &'a Span;
    type IntoIter = Spans<'a>;
    fn into_iter(self) -> Spans<'a> {
        self.spans()
    }
}

/// The owned component spans of an [`Endset`], in stored order.
///
/// They are the decomposition moved out of an endset the caller is finished
/// with, so a re-collection need not clone each one: `Endset::from_spans(e)`
/// and `enc(x).into_iter()` cost no `Tumbler` copies. Carries the same
/// reverse walk, exact length and fused guarantee as [`Spans`], and withholds
/// `Clone` for the same reason: the backing's consuming iterator is not
/// cloneable.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct IntoSpans(<Vector<Span> as IntoIterator>::IntoIter);

impl Iterator for IntoSpans {
    type Item = Span;
    fn next(&mut self) -> Option<Span> {
        self.0.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl DoubleEndedIterator for IntoSpans {
    fn next_back(&mut self) -> Option<Span> {
        self.0.next_back()
    }
}

impl ExactSizeIterator for IntoSpans {
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl std::iter::FusedIterator for IntoSpans {}

/// Prints the cursor, not the spans — as for [`Spans`].
impl fmt::Debug for IntoSpans {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntoSpans").finish_non_exhaustive()
    }
}

impl IntoIterator for Endset {
    type Item = Span;
    type IntoIter = IntoSpans;
    fn into_iter(self) -> IntoSpans {
        IntoSpans(self.0.into_iter())
    }
}

/// Returns whether a span is unit-depth (address-denoting).
///
/// A span is unit-depth iff it is exactly its own start's subtree span:
/// `s == subtree_of(s.start())` (§Core data model).
fn is_unit_depth(s: &Span) -> bool {
    *s == subtree_of(s.start())
}

/// A link value: a positional sequence of at least three endsets.
///
/// Its arity is `slots.len() ≥ 3` (ASN-0043 L3 *capacity*; every creation op
/// realizes exactly 3 — the arity-3 store, §Core data model). Positional
/// accessors (L6: slot index is a primitive), and one whole-value walk,
/// [`Link::slots`]. Derived `Eq` is structural, never link-value identity —
/// identity is the store address (L11b).
///
/// Serde: a **symmetric shadow pair** — the derived `Serialize` emits the one
/// named `slots` field and `Deserialize` reads that same shape back through a
/// private shadow into [`Link::new`], so the arity floor holds at the trust
/// boundary too. Load-bearing: [`crate::LinkState`] rides M2 checkpoints, and
/// the positional accessors index slots 0–2 directly, so a sub-arity value
/// smuggled in through a decoded checkpoint would fault inside the replay
/// fold rather than at the boundary that admitted it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "LinkShadow")]
pub struct Link {
    slots: Vector<Endset>,
}

/// The deserialization shadow: the one `slots` field.
///
/// Its shape is the one the derived `Serialize` writes.
#[derive(Deserialize)]
struct LinkShadow {
    slots: Vector<Endset>,
}

/// The deserialization mint path, routed through [`Link::new`].
///
/// # Errors
///
/// Refuses a shadow of fewer than three slots, so no decoded checkpoint can
/// smuggle in a link below the L3 arity floor.
impl TryFrom<LinkShadow> for Link {
    type Error = &'static str;
    fn try_from(shadow: LinkShadow) -> Result<Link, &'static str> {
        Link::new(shadow.slots).ok_or("link value has arity < 3 (the L3 capacity floor)")
    }
}

impl Link {
    /// Builds the standard triple `[e₁, e₂, e₃]`.
    ///
    /// It is the one shape every creation op realizes (the arity-3 store,
    /// §Core data model). Infallible, so a write path states the shape instead
    /// of discharging an arity `Option` that cannot be `None`; [`Link::new`]
    /// covers the general L3 capacity case.
    pub fn triple(from: Endset, to: Endset, ty: Endset) -> Link {
        Link {
            slots: [from, to, ty].into_iter().collect(),
        }
    }

    /// Builds a link of arity ≥ 3 — the general L3-capacity constructor.
    ///
    /// `None ⇔ arity < 3` — the type floor only. `e₃ ≠ ∅` (L3) is a
    /// write-boundary check (`emit_core`'s gate / MAKELINK's ML6), not the
    /// type's (Conflicts §3).
    pub fn new(slots: impl IntoIterator<Item = Endset>) -> Option<Link> {
        let slots: Vector<Endset> = slots.into_iter().collect();
        if slots.len() < 3 {
            None
        } else {
            Some(Link { slots })
        }
    }

    /// Returns the arity, `|L| ≥ 3`.
    pub fn arity(&self) -> usize {
        self.slots.len()
    }

    /// Returns the slot sequence, in order.
    ///
    /// It is a representation view, not a positional contract: [`Link::slot`]
    /// stays the 1-based primitive (L6), and this is for the reads that are
    /// about the whole value rather than about a position in it.
    /// [`Endset::spans`] is its counterpart one level down. A caller that
    /// walks every slot asks here instead of indexing over `1..=arity()` and
    /// then discharging an `Option` the bound has already made `Some`.
    pub fn slots(&self) -> impl Iterator<Item = &Endset> {
        self.slots.iter()
    }

    /// Looks up a 1-based slot: `None` iff `slot < 1 ∨ slot > arity`.
    ///
    /// That is FOLLOWLINK's post-lookup arity bound.
    pub fn slot(&self, slot: usize) -> Option<&Endset> {
        if (1..=self.slots.len()).contains(&slot) {
            self.slots.get(slot - 1)
        } else {
            None
        }
    }

    /// Returns `e₁` (`FROM` = 1).
    pub fn from_slot(&self) -> &Endset {
        &self.slots[0]
    }

    /// Returns `e₂` (`TO` = 2).
    pub fn to_slot(&self) -> &Endset {
        &self.slots[1]
    }

    /// Returns `e₃` (`TYPE` = 3).
    pub fn type_slot(&self) -> &Endset {
        &self.slots[2]
    }
}

/// Encodes an address set canonically (AD): one unit-depth span per address.
///
/// The encoding is `⟨subtree_of(x) : x ∈ X⟩`, in `X`'s order and one span per
/// element, a sequence map rather than a set, so a repeated address is a
/// repeated span (which is what the managed shape gate counts) — exactly what
/// the managed surface (Emit_K/Nullify/assert_sup/claims) emits, with
/// `enc(X).addrs() = X`. "Canonical" in AD's sense — the standard encoding
/// of a name — and not in M1's: the spans are never normalized, so
/// `enc([doc, elem])` keeps a span inside another. Takes anything that
/// yields addresses by reference, so a slice, a `Vec` and a one-address
/// array `[addr]` all read the same at the call.
pub fn enc<'a>(addrs: impl IntoIterator<Item = &'a Address>) -> Endset {
    Endset::from_spans(addrs.into_iter().map(|a| subtree_of(a.tumbler())))
}
