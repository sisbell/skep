//! §Core data model — type identity: [`CoverageClass`], the key every type,
//! dedup and fence question compares, and [`coverage_class`], its one
//! constructor and the one pure classifier in M7. It sits apart from the
//! carriers it classifies so that "the only constructor" is a boundary the
//! compiler keeps: the representation, `Class`, is private to this file.

use im::{OrdMap, OrdSet};
use skep_address::{canonical_key, is_prefix, CanonicalForm, Tumbler};

use crate::endset::Endset;

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
/// general level-uniform content endset ⇒ M1's per-`#start` partition of the
/// whole-endset fold
/// ([`SpanSet::by_level_class`](skep_address::SpanSet::by_level_class)), each part
/// `canonical_key`d — the composition M1's `canonical_key` names as M7's,
/// cross-length canonicalization being absent from the source algebra.
///
/// PUBLIC because a caller may ask type identity of endsets of its own: two
/// endsets are one type exactly when their classes are equal (M9's def layer
/// asks it of an F slot and a start). A caller holding a shipped type asks
/// [`TypeRegistry::shipped_class`](crate::TypeRegistry::shipped_class)
/// instead of classifying the endset it reports.
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
        // M1's partition of the whole-endset fold, one `canonical_key` per
        // part: cross-length canonicalization is absent from the source
        // algebra, so the class is the composition of per-length keys, and
        // the partition is M1's to state. An `OrdMap`, because a class is a
        // hint key cloned at every fold and every replay.
        let mut extents: OrdMap<usize, CanonicalForm> = OrdMap::new();
        for (start_len, part) in e.to_spanset().by_level_class() {
            let canonical = canonical_key(&part).expect(
                "coverage_class precondition violated: every span must be level-uniform \
                 (#start == #width); an off-contract hand-built span is a caller error, \
                 never skipped and never coarsened (§Core data model)",
            );
            extents.insert(start_len, canonical);
        }
        CoverageClass(Class::Extents(extents))
    }
}
