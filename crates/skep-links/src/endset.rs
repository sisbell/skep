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
/// M1-call boundary ([`Endset::to_spanset`], the lone use).
///
/// Derived `PartialEq`/`Eq`/`Hash` are STRUCTURAL (decomposition- and
/// span-order-sensitive) — serde/container plumbing only, NEVER identity
/// (§Core data model structural-derives contract): link identity is the store
/// address (L11b), type/dedup identity is [`coverage_class`]. No seam may key
/// on the derived impls.
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

    /// `|Σ|` — the span count (the shape gate's `|F|`/`|G|`).
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

    /// INTERNAL — the one Endset → `SpanSet` boundary fold (concatenation,
    /// order-preserving, exactly M1's singleton+union). Used by FOLLOWLINK
    /// (F1/F3) and the `Extents` partition of [`coverage_class`].
    pub(crate) fn to_spanset(&self) -> SpanSet {
        self.0.iter().cloned().collect()
    }
}

/// A span is unit-depth (address-denoting) iff it is exactly its own start's
/// subtree span: `s == subtree_of(s.start())` (§Core data model).
pub(crate) fn is_unit_depth(s: &Span) -> bool {
    *s == subtree_of(s.start())
}

/// Every span unit-depth — the address-denoting endset test (the managed
/// surface's `ty` precondition and `TypeRegistry::build`'s key-denotation
/// clause). Vacuously true for `⟨⟩`.
pub(crate) fn is_address_denoting(e: &Endset) -> bool {
    e.spans().all(is_unit_depth)
}

/// "Unit-depth single-addr" slot test (ASN-0125 Df-DISC(ii) schema; the BH3
/// `target_of` single-address-G rule): every span unit-depth AND exactly one
/// distinct denoted address — returns it.
pub(crate) fn single_denoted(e: &Endset) -> Option<&Tumbler> {
    if !is_address_denoting(e) {
        return None;
    }
    let mut it = e.addrs();
    let first = it.next()?;
    if it.any(|t| t != first) {
        return None;
    }
    Some(first)
}

/// A link value: a positional sequence of endsets, arity = `slots.len() ≥ 3`
/// (ASN-0043 L3 *capacity*; every creation op realizes exactly 3 — the
/// arity-3 store, §Core data model). Positional accessors only (L6: slot
/// index is a primitive). Derived `Eq` is STRUCTURAL, never link-value
/// identity — identity is the store address (L11b).
///
/// Serde: a **symmetric shadow pair** — the derived `Serialize` emits the one
/// named `slots` field and `Deserialize` reads that same shape back through
/// [`LinkShadow`] into [`Link::new`], so the arity floor holds at the trust
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

    /// 1-based slot lookup; `None` iff `i < 1 ∨ i > arity` (FOLLOWLINK's
    /// post-lookup arity bound).
    pub fn slot(&self, i: usize) -> Option<&Endset> {
        if (1..=self.slots.len()).contains(&i) {
            self.slots.get(i - 1)
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
/// (§Core data model). `Addrs` is exact (the ≼-minimal denoted antichain,
/// I0a); `Extents` is the conservative per-endpoint-length canonical
/// partition for content extents (over-discriminates across lengths, never
/// merges distinct classes — the safe direction for type-matching and dedup).
///
/// NOT `Serialize`: `Extents` wraps M1's non-`Serialize` `CanonicalForm` —
/// this type lives only in the skip-serialized registry/hints, and every
/// idem⊤ dedup `LockKey` serializes an `Addrs` class only (§Core data model).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CoverageClass {
    /// ≼-minimal antichain — address-denoting endsets (exact).
    Addrs(OrdSet<Tumbler>),
    /// Per-length canonical coverage — content extents (safe, conservative).
    Extents(OrdMap<usize, CanonicalForm>),
}

/// PURE coverage CLASS of an endset (no store state, hence no `&self`).
///
/// Address-denoting endset (every span unit-depth) ⇒ `Addrs` = its ≼-minimal
/// denoted antichain (I0a, exact); general level-uniform content endset ⇒
/// `Extents` = per-`#start` partition, each folded to a `SpanSet` then
/// `canonical_key`d. The lone place an endset folds to a `SpanSet`. PUBLIC so
/// M9 can key `targets_keyed`'s map via `coverage_class(ty)`.
///
/// TOTAL ON LEVEL-UNIFORM INPUT — which is all it ever receives: managed
/// paths validate address-denoting, content paths are `iextent`-level-uniform
/// by M5's construction, and read-side `ty` arguments are registered
/// address-denoting types by caller contract (§Core data model totality).
/// OFF-CONTRACT INPUT PANICS: a hand-built non-level-uniform span (e.g. the
/// T12-valid `([5,3],[0,2,7])`) hits M1's `LevelMismatch` inside
/// `canonical_key`, surfaced as a panic naming the precondition — NEVER a
/// skipped span or a coarser class, either of which would silently corrupt
/// type/dedup identity.
pub fn coverage_class(e: &Endset) -> CoverageClass {
    if is_address_denoting(e) {
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
        CoverageClass::Addrs(minimal)
    } else {
        let mut parts: BTreeMap<usize, Vec<Span>> = BTreeMap::new();
        for s in e.spans() {
            parts.entry(s.start().len()).or_default().push(s.clone());
        }
        let mut map: OrdMap<usize, CanonicalForm> = OrdMap::new();
        for (len, spans) in parts {
            let set: SpanSet = spans.into_iter().collect();
            let key = canonical_key(&set).expect(
                "coverage_class precondition violated: every span must be level-uniform \
                 (#start == #width); an off-contract hand-built span is a caller error, \
                 never skipped and never coarsened (§Core data model)",
            );
            map.insert(len, key);
        }
        CoverageClass::Extents(map)
    }
}
