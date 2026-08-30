//! §Core data model — M7's readable carrier types: [`Endset`] (the verbatim
//! span decomposition), [`Link`] (a positional sequence of endsets), the
//! canonical address-set encoding [`enc`], and the one pure coverage
//! classifier [`coverage_class`] with its [`CoverageClass`] key.

use std::collections::BTreeMap;

use im::{OrdMap, OrdSet, Vector};
use serde::{Deserialize, Serialize};
use skep_address::{
    canonical_key, is_prefix, subtree_of, Address, CanonicalForm, Span, SpanSet, Tumbler,
};

/// M7-OWNED endset — a READABLE finite span sequence, the as-created
/// decomposition held VERBATIM (observable via raw read-back — ML2/RL1). NOT
/// M1's `SpanSet`, which is read-opaque to M7. Coverage is a query-time
/// projection ([`Endset::covers`]); the sequence is read through
/// [`Endset::spans`]/[`Endset::addrs`] and folds to a `SpanSet` only at an
/// M1-call boundary: the crate-internal whole-endset fold FOLLOWLINK
/// performs.
///
/// Derived `PartialEq`/`Eq`/`Hash` are STRUCTURAL (decomposition- and
/// span-order-sensitive) — serde/container plumbing only, NEVER identity
/// (§Core data model structural-derives contract): link identity is the store
/// address (L11b), type/dedup identity is [`coverage_class`]. They are VALUE
/// identity — same spans, same order — which is the right relation for
/// deduplicating stored endset values; they are not TYPE identity, so nothing
/// that means a type (a registration, a type index, a catalog key) may key on
/// them.
///
/// A span collection: `Default` is `⟨⟩` and `FromIterator<Span>` is the same
/// verbatim construction [`Endset::from_spans`] performs, so a span pipeline
/// `.collect()`s here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endset(Vector<Span>);

impl FromIterator<Span> for Endset {
    fn from_iter<I: IntoIterator<Item = Span>>(spans: I) -> Endset {
        Endset::from_spans(spans)
    }
}

impl Endset {
    /// `⟨⟩` — the empty endset (distinct from any zero-width span, which M1's
    /// span constructor rejects outright).
    pub fn empty() -> Endset {
        Endset(Vector::new())
    }

    /// Verbatim construction — the spans are stored exactly as given, never
    /// canonicalized at rest (ML2/RL1). MAKELINK and M10 content successors
    /// build here.
    pub fn from_spans(spans: impl IntoIterator<Item = Span>) -> Endset {
        Endset(spans.into_iter().collect())
    }

    /// The readable decomposition (L5 reads an endset by membership, not
    /// position — this iterator is a representation view, not a positional
    /// contract).
    pub fn spans(&self) -> impl Iterator<Item = &Span> {
        self.0.iter()
    }

    /// The number of spans in the stored SEQUENCE — what the managed
    /// surface's [`Shape`](crate::Shape) gate counts. ASN-0126's `|F|` and
    /// `|G|` are set cardinalities, and the two agree exactly on a
    /// duplicate-free decomposition: every [`enc`]-built endset is one unless
    /// the caller names an address twice, and every `iextent`-built one is by
    /// M5's construction. A repeated span counts twice here and once there.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `== ⟨⟩` — the `e₃ ≠ ∅` write-boundary check (L3/ML6) reads this.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `t ∈ coverage(e)`: `∃ s ∈ spans : s.contains(t)` — total over all of
    /// carrier T (the membership projection ASN-0086's pattern domain rides).
    /// COVERAGE, the coarser of the module's two matching regimes: every
    /// tumbler a span reaches, not just the addresses it denotes. The finer
    /// one — AD denotation, `x ∈ addrs(e)` — is [`Endset::addrs`].
    pub fn covers(&self, t: &Tumbler) -> bool {
        self.0.iter().any(|s| s.contains(t))
    }

    /// AD readback — DENOTATION, the finer regime: the start of each
    /// unit-depth span (a span `s` with `s == subtree_of(s.start())`);
    /// non-unit spans contribute nothing. `enc(X).addrs() = X`.
    pub fn addrs(&self) -> impl Iterator<Item = &Tumbler> {
        self.0.iter().filter(|s| is_unit_depth(s)).map(|s| s.start())
    }

    /// Every span unit-depth — the address-denoting test, vacuously true for
    /// `⟨⟩`. Selects [`coverage_class`]'s exact denoted branch, and is
    /// verbatim the admission rule of the managed surface's `ty`
    /// (`NonAddressDenotingType`), so a caller can ask before it is refused.
    /// STRICTLY STRONGER than [`Endset::is_level_uniform`], which is what
    /// [`coverage_class`] itself requires.
    pub fn is_address_denoting(&self) -> bool {
        self.spans().all(is_unit_depth)
    }

    /// Every span level-uniform (`#start = #width`) — EXACTLY
    /// [`coverage_class`]'s precondition, and the test a caller applies to an
    /// endset of its own making. Implied by
    /// [`Endset::is_address_denoting`] (a unit-depth span is its own start's
    /// subtree, so start and width share a length) and strictly weaker than
    /// it: a content endset of M5 `Run::iextent`s passes this and fails that,
    /// and is a legal `coverage_class` input.
    pub fn is_level_uniform(&self) -> bool {
        self.spans().all(Span::is_level_uniform)
    }

    /// The "unit-depth single-addr" slot test (ASN-0125 Df-DISC(ii) schema;
    /// the BH3 `target_of` single-address-G rule): every span unit-depth AND
    /// exactly one distinct denoted address — returns it. A pure question
    /// about this endset, so it sits beside the module's other projections.
    ///
    /// This is what the `[K_sup]` SOLE-WRITER FENCES establish of every stored
    /// claim, and the test a reader of one applies to read its endpoints back
    /// — never [`Shape`](crate::Shape), whose span-count conformance is a gate
    /// on the managed surface and says nothing about denotation. STRICTLY
    /// STRONGER than `addrs().next()`, which takes the first unit-depth start
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

    /// INTERNAL — the one WHOLE-ENDSET fold to a `SpanSet` (concatenation,
    /// order-preserving, exactly M1's singleton+union), and FOLLOWLINK's
    /// (F1/F3) sole use.
    pub(crate) fn to_spanset(&self) -> SpanSet {
        self.0.iter().cloned().collect()
    }
}

/// A span is unit-depth (address-denoting) iff it is exactly its own start's
/// subtree span: `s == subtree_of(s.start())` (§Core data model).
pub(crate) fn is_unit_depth(s: &Span) -> bool {
    *s == subtree_of(s.start())
}

/// A link value: a positional sequence of endsets, arity = `slots.len() ≥ 3`
/// (ASN-0043 L3 *capacity*; every creation op realizes exactly 3 — the
/// arity-3 store, §Core data model). Positional accessors only (L6: slot
/// index is a primitive). Derived `Eq` is STRUCTURAL, never link-value
/// identity — identity is the store address (L11b).
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

/// Deserialization shadow: the one `slots` field, in the shape the derived
/// `Serialize` writes.
#[derive(Deserialize)]
struct LinkShadow {
    slots: Vector<Endset>,
}

/// Deserialization mint path: routes through [`Link::new`], so no decoded
/// checkpoint can smuggle in a link below the L3 arity floor.
impl TryFrom<LinkShadow> for Link {
    type Error = &'static str;
    fn try_from(s: LinkShadow) -> Result<Link, &'static str> {
        Link::new(s.slots).ok_or("link value has arity < 3 (the L3 capacity floor)")
    }
}

impl Link {
    /// The standard triple `[e₁, e₂, e₃]` — the one shape every creation op
    /// realizes (the arity-3 store, §Core data model). Infallible, so a write
    /// path states the shape instead of discharging an arity `Option` that
    /// cannot be `None`; [`Link::new`] covers the general L3 capacity case.
    pub fn triple(from: Endset, to: Endset, ty: Endset) -> Link {
        Link {
            slots: [from, to, ty].into_iter().collect(),
        }
    }

    /// The general L3-capacity constructor: `None ⇔ arity < 3` — the type
    /// floor only. `e₃ ≠ ∅` (L3) is a WRITE-boundary check (`emit_core`'s
    /// gate / MAKELINK's ML6), not the type's (Conflicts §3).
    pub fn new(slots: impl IntoIterator<Item = Endset>) -> Option<Link> {
        let slots: Vector<Endset> = slots.into_iter().collect();
        if slots.len() < 3 {
            None
        } else {
            Some(Link { slots })
        }
    }

    /// `|L| ≥ 3`.
    pub fn arity(&self) -> usize {
        self.slots.len()
    }

    /// 1-based slot lookup; `None` iff `slot < 1 ∨ slot > arity`
    /// (FOLLOWLINK's post-lookup arity bound).
    pub fn slot(&self, slot: usize) -> Option<&Endset> {
        if (1..=self.slots.len()).contains(&slot) {
            self.slots.get(slot - 1)
        } else {
            None
        }
    }

    /// `e₁` (FROM = 1).
    pub fn from_slot(&self) -> &Endset {
        &self.slots[0]
    }

    /// `e₂` (TO = 2).
    pub fn to_slot(&self) -> &Endset {
        &self.slots[1]
    }

    /// `e₃` (TYPE = 3).
    pub fn type_slot(&self) -> &Endset {
        &self.slots[2]
    }
}

/// Canonical address-set encoding (AD): one unit-depth span per address —
/// `{subtree_of(x) : x ∈ X}` — exactly what the managed surface
/// (Emit_K/Nullify/assert_sup/claims) emits, with `enc(X).addrs() = X`.
/// Takes anything that yields addresses by reference, so a slice, a `Vec` and
/// a one-address array `[addr]` all read the same at the call.
pub fn enc<'a>(addrs: impl IntoIterator<Item = &'a Address>) -> Endset {
    Endset::from_spans(addrs.into_iter().map(|a| subtree_of(a.tumbler())))
}

/// Type / I0 identity of an endset — coverage equality, NEVER decomposition
/// (§Core data model). An address-denoting endset's class is exact (the
/// ≼-minimal denoted antichain, I0a); a content extent's is the conservative
/// per-endpoint-length canonical partition (over-discriminates across
/// lengths, never merges distinct classes — the safe direction for
/// type-matching and dedup).
///
/// OPAQUE, and that is what makes it an identity: [`coverage_class`] is the
/// only constructor, so holding one of these is a FACT about some endset
/// rather than an assertion a caller can make. A hand-assembled non-minimal
/// antichain would be the class of no endset — unregistered by accident
/// rather than by fact, and forgeable as a key of the map
/// [`crate::LinkState::targets_keyed`] returns.
/// [`CoverageClass::denoted`] is the one observation of the representation.
///
/// NOT `Serialize`: the extent case wraps M1's non-`Serialize`
/// `CanonicalForm` — this type lives only in the skip-serialized
/// registry/hints, and every idem⊤ dedup `LockKey` serializes a denoted
/// class only (§Core data model).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoverageClass(Class);

/// The two coverage regimes, private so the representation stays M7's: the
/// extent partition is a documented over-discrimination the design reserves
/// the right to tighten, which it can only do while nothing outside this
/// crate can name it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Class {
    /// ≼-minimal antichain — address-denoting endsets (exact).
    Addrs(OrdSet<Tumbler>),
    /// Per-length canonical coverage — content extents (safe, conservative).
    Extents(OrdMap<usize, CanonicalForm>),
}

impl CoverageClass {
    /// The ≼-minimal denoted antichain (I0a) of an address-denoting endset's
    /// class; `None` for a content-extent class, whose partition is
    /// conservative and carries no denotation. Read-only: there is no
    /// constructor taking one, so a caller can inspect the identity without
    /// being able to state one.
    pub fn denoted(&self) -> Option<&OrdSet<Tumbler>> {
        match &self.0 {
            Class::Addrs(set) => Some(set),
            Class::Extents(_) => None,
        }
    }
}

/// PURE coverage CLASS of an endset (no store state, hence no `&self`) — the
/// ONE constructor of [`CoverageClass`].
///
/// Address-denoting endset (every span unit-depth) ⇒ its ≼-minimal denoted
/// antichain (I0a, exact, readable through [`CoverageClass::denoted`]);
/// general level-uniform content endset ⇒ the per-`#start` partition, each
/// part folded to a `SpanSet` then `canonical_key`d — built per part from its
/// own spans, never through the whole-endset fold, the parts being span
/// groups rather than endsets. PUBLIC so M9 can key `targets_keyed`'s map via
/// `coverage_class(ty)`.
///
/// TOTAL ON LEVEL-UNIFORM INPUT — which is all it ever receives: managed
/// paths validate address-denoting, content paths are `iextent`-level-uniform
/// by M5's construction, and read-side `ty` arguments are registered
/// address-denoting types by caller contract (§Core data model totality).
/// [`Endset::is_level_uniform`] is the test a caller applies to discharge the
/// precondition on an endset of its own making — one hop from here;
/// [`Endset::is_address_denoting`] is the stronger condition the managed
/// paths establish, sufficient but not necessary.
/// OFF-CONTRACT INPUT PANICS: a hand-built non-level-uniform span (e.g. the
/// T12-valid `([5,3],[0,2,7])`) hits M1's `LevelMismatch` inside
/// `canonical_key`, surfaced as a panic naming the precondition — NEVER a
/// skipped span or a coarser class, either of which would silently corrupt
/// type/dedup identity.
pub fn coverage_class(e: &Endset) -> CoverageClass {
    if e.is_address_denoting() {
        // I0a: dedup, then drop every address with a distinct denoted prefix
        // — in ONE ascending pass, comparing each candidate only against the
        // last address retained.
        //
        // Sound because T1's order is lexicographic prefix-smaller, which
        // makes a retained address's extensions CONTIGUOUS: if `y ≼ t` and
        // `y < z < t`, then `y ≼ z`, since a `z` diverging from `y` at some
        // position `i < #y` would need `z_i > y_i = t_i` and so would sort
        // above `t`. So the shortest denoted prefix of `t` is itself
        // retained, and every element between it and `t` is skipped, leaving
        // it as `last` when `t` is reached. One prefix test per address
        // instead of |denoted|² — the count is caller-chosen, and the class
        // of a stored type slot is recomputed for every link at every replay.
        let denoted: OrdSet<Tumbler> = e.spans().map(|s| s.start().clone()).collect();
        let mut minimal: OrdSet<Tumbler> = OrdSet::new();
        let mut last: Option<&Tumbler> = None;
        for t in denoted.iter() {
            if last.is_some_and(|y| is_prefix(y, t)) {
                continue; // t extends the retained ≼-minimal y
            }
            minimal.insert(t.clone());
            last = Some(t);
        }
        CoverageClass(Class::Addrs(minimal))
    } else {
        let mut by_start_len: BTreeMap<usize, Vec<Span>> = BTreeMap::new();
        for s in e.spans() {
            by_start_len
                .entry(s.start().len())
                .or_default()
                .push(s.clone());
        }
        let mut extents: OrdMap<usize, CanonicalForm> = OrdMap::new();
        for (start_len, spans) in by_start_len {
            let set: SpanSet = spans.into_iter().collect();
            let canonical = canonical_key(&set).expect(
                "coverage_class precondition violated: every span must be level-uniform \
                 (#start == #width); an off-contract hand-built span is a caller error, \
                 never skipped and never coarsened (§Core data model)",
            );
            extents.insert(start_len, canonical);
        }
        CoverageClass(Class::Extents(extents))
    }
}
