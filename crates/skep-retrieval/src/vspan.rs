//! §Internal design — how M6 reads one request V-span: which subspace its
//! start names, whether it is well-formed, and how far M5's resolution of it
//! can walk. The two-subspace vocabulary a classification lands in
//! ([`Subspace`]) lists both subspaces, reads itself off a span's start or a
//! numeral, writes its own numeral (M1's) and anchor, and asks M5 for its
//! count, runs and run count — so no site re-derives which subspace a start
//! names, lists the two, or pairs a subspace with a numeral, an anchor, a
//! count, a run-list or a run count by hand.

use std::sync::LazyLock;

use num_traits::{One, ToPrimitive};
use skep_address::{action_point, content_subspace, link_subspace, zeros, Address, Nat, Span};
use skep_arrangement::{as_ordinal_vspan, M5State, Runs, VPos};

use crate::error::SpanFault;

// Content (s_C) / link (s_L) subspace numerals. M1 owns T7 and names them
// ([`content_subspace`]/[`link_subspace`]); M6 memoizes what M1 names, because
// `Nat = BigUint` cannot be `const` and a bare call would re-allocate a fresh
// `BigUint` on every reference. [`Subspace::numeral`] is the one place they
// are named: [`Subspace::of_numeral`] compares against them through it — by
// reference, with no allocation — and the O(1)-per-query construction sites,
// [`Subspace::anchor`] among them, clone through it.
//
// Private — the statics and [`Subspace::numeral`], the one accessor that
// hands them out — which is the point of [`Subspace`] carrying both
// directions: no file but this one can name a raw subspace numeral, so a
// numeral cannot be handed to a function expecting a count.

/// `s_C` = M1's content-subspace numeral (ASN-0047; T7 convention).
static S_C: LazyLock<Nat> = LazyLock::new(content_subspace);

/// `s_L` = M1's link-subspace numeral (ASN-0047; T7 convention).
static S_L: LazyLock<Nat> = LazyLock::new(link_subspace);

/// One of a document's two subspaces (T7; ASN-0047) — the vocabulary every
/// site that must tell content from link matches on, and the one type that
/// answers for every direction of it. It lists both ([`Subspace::ALL`]),
/// reads itself off a numeral ([`Subspace::of_numeral`]) or off a request
/// span's start ([`Subspace::of_span`]), writes the numeral M1 names it by
/// ([`Subspace::numeral`]) and the anchor its extent starts at
/// ([`Subspace::anchor`]), and asks M5 for its own count, runs and run count
/// ([`Subspace::count`], [`Subspace::runs`], [`Subspace::run_count`]). A
/// site therefore matches on the classification instead of re-deriving the
/// comparison chain and carrying its own fall-through, and never lists the
/// two, or pairs a subspace with a numeral, an anchor, a count, a run-list or
/// a run count, by hand.
///
/// `pub(crate)`, because M1 owns T7 and a second published subspace
/// vocabulary is exactly what memoizing M1's numerals avoids.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Subspace {
    Content,
    Link,
}

impl Subspace {
    /// Both subspaces, ONCE — content, then link: their numerals' order
    /// (`s_C < s_L`, T7), and so the T1 order of the per-subspace extents
    /// `doc_vspanset` collects AS GIVEN into W13's normal form. Every walk
    /// over the two reads it here, [`Subspace::of_numeral`] included; a second
    /// copy is how a walk comes to miss one, or to list them out of that
    /// order.
    pub(crate) const ALL: [Subspace; 2] = [Subspace::Content, Subspace::Link];

    /// Which subspace a numeral names, or `None` for a foreign one —
    /// [`Subspace::numeral`] read backwards: the subspace in [`Subspace::ALL`]
    /// whose numeral it is. `Nat` cannot appear in a pattern, so the pairing
    /// of each subspace with its numeral is written ONCE, in `numeral`'s
    /// exhaustive match, and this inverts it rather than spelling it again —
    /// comparing by reference against the memoized statics, with no
    /// allocation. Every site that must tell content from link matches on the
    /// answer instead.
    fn of_numeral(s: &Nat) -> Option<Subspace> {
        Subspace::ALL.into_iter().find(|sub| sub.numeral() == s)
    }

    /// The subspace a V-span's start names — position 1 of the start, read
    /// through [`Subspace::of_numeral`].
    ///
    /// TOTAL: `Tumbler` indexing is 1-based over a nonempty carrier, so every
    /// span has a position 1 whatever its depth, gated or not. `None`
    /// therefore means the numeral there is neither `s_C` nor `s_L`, NEVER
    /// that the start is too shallow to name one — which is why COMPARE may
    /// ask this BEFORE [`gate_vspan`] and still get an unambiguous answer, and
    /// why a one-component start reports a foreign subspace rather than
    /// falling through some depth-shaped hole.
    pub(crate) fn of_span(span: &Span) -> Option<Subspace> {
        Subspace::of_numeral(
            span.start()
                .get(1)
                .expect("a nonempty start has a position 1"),
        )
    }

    /// The numeral M1 names this subspace by (T7) — the writing direction of
    /// [`Subspace::of_numeral`], which reads one. Its match is the one place
    /// a subspace is paired with its numeral, and [`Subspace::of_numeral`]
    /// inverts it, so the two directions are one definition read two ways —
    /// the reason M5 keeps `ordinal_vspan` beside `is_ordinal_vspan` — and
    /// cannot come apart.
    ///
    /// Borrowed from the memoized static, so a caller that must own one
    /// clones at the O(1)-per-query site rather than on every comparison.
    fn numeral(self) -> &'static Nat {
        match self {
            Subspace::Content => &S_C,
            Subspace::Link => &S_L,
        }
    }

    /// The subspace's ANCHOR `[S, 1]` — ASN-0113's `start_S`, the position an
    /// occupied subspace's dense prefix begins at (D-MIN★) — written ONCE,
    /// here: the start of every extent `ext_span` builds, and the position the
    /// D-SEQ★ tripwire asks M5 to find bound.
    pub(crate) fn anchor(self) -> VPos {
        VPos {
            subspace: self.numeral().clone(),
            ordinal: Nat::one(),
        }
    }

    /// `n_S(doc)` — M5's arranged width of this subspace of `doc`. Routed
    /// here so a subspace asks for ITS OWN count: no caller pairs a variant
    /// with an accessor by hand, which closes at the pairing the swap
    /// `ext_span`'s typed argument closes at the call — a subspace handed
    /// another's count builds a well-formed extent of the wrong width, or
    /// reports a subspace empty that is not.
    pub(crate) fn count(self, m5: &M5State, doc: &Address) -> Nat {
        match self {
            Subspace::Content => m5.content_count(doc),
            Subspace::Link => m5.link_count(doc),
        }
    }

    /// This subspace's canonical, V-ordered run decomposition of `doc` — the
    /// runs whose widths sum to [`Subspace::count`] — selected the way the
    /// count is, so the two reads of one subspace cannot be paired with
    /// different subspaces.
    pub(crate) fn runs<'a>(self, m5: &'a M5State, doc: &Address) -> Runs<'a> {
        match self {
            Subspace::Content => m5.content_runs(doc),
            Subspace::Link => m5.link_runs(doc),
        }
    }

    /// `#runs` of this subspace's run list in `doc` — how many runs
    /// [`Subspace::runs`] would hand back, without handing them back: M5's
    /// own count, one map lookup reading no run, selected as `count` and
    /// `runs` are. The quantity a resolution's walk is priced in, and private
    /// to this file so that a walk is priced in [`walk_ceiling`] and nowhere
    /// else.
    fn run_count(self, m5: &M5State, doc: &Address) -> usize {
        match self {
            Subspace::Content => m5.content_run_count(doc),
            Subspace::Link => m5.link_run_count(doc),
        }
    }
}

/// An upper bound on the run-list steps M5's resolution of `span` against
/// `doc` can take, read before the walk from M5's O(1) run counts — what each
/// span is charged against the walk budget (`MAX_WALK_STEPS`).
///
/// M5 reaches a span by walking the selected run list from its first run, and
/// stops at the first run opening at or past the span's reach ordinal `e`
/// (`ordinal + count`). Every run is at least one position wide, so at most
/// `e − 1` runs open before `e`, and the walk examines those and the one that
/// stops it: `min(#runs, e)` steps, `#runs` for a span opening past the
/// arranged end.
///
/// UPPER BOUNDS WHERE THE READING CANNOT SAY MORE. A start in neither subspace
/// is priced at both lists, and a span M5's reader declines, or whose reach
/// does not fit a `usize`, at the whole of its list: read off M6's own
/// classification and M5's own reader, never off a restatement of which spans
/// M5 folds to nothing, so the price errs only toward refusing. A start in
/// neither subspace and a span the reader declines both resolve to nothing,
/// so their request pays for a walk M5 never makes; the crate doc's *What M6
/// refuses for size* is where a caller is told.
pub(crate) fn walk_ceiling(m5: &M5State, doc: &Address, span: &Span) -> usize {
    let run_count = match Subspace::of_span(span) {
        Some(sub) => sub.run_count(m5, doc),
        None => Subspace::ALL.into_iter().fold(0, |total: usize, sub| {
            total.saturating_add(sub.run_count(m5, doc))
        }),
    };
    as_ordinal_vspan(span)
        .and_then(|shape| (shape.ordinal + shape.count).to_usize())
        .map_or(run_count, |reach| reach.min(run_count))
}

/// The SPAN half of ASN-0115's V-spec well-formedness: zero-free,
/// ordinal-level, level-uniform, depth `#start ≥ 2`. A V-spec is the pair
/// `ρ = (d, σ)`, so the other half — that `d` is a registered document — is
/// the per-operation registry gate, which raises its own typed rejection.
///
/// A span may fail several of the four at once, so which fault it reports is
/// fixed HERE and nowhere else — level-uniformity, then ordinal-level, then
/// zero-freedom, then depth, the first that fails being the one returned. That
/// is the whole of `SpanFault`'s precedence: its declaration order is a
/// vocabulary's, not this ladder's. The ladder is PUBLISHED on [`SpanFault`],
/// since a caller holding one may act on it; this is where it is enforced.
///
/// It deliberately does NOT gate depth-COMPATIBILITY (`#start == 2`):
/// ASN-0115 is explicit that depth-compatibility is a consulting-state
/// predicate, NOT a well-formedness condition, so a well-formed `#start ≥ 3`
/// span passes here and resolves to ⟨⟩ downstream (R6 silent-empty;
/// SHOWORIGIN_V alone rejects it, as its own WF_V(v) precondition).
pub(crate) fn gate_vspan(span: &Span) -> Result<(), SpanFault> {
    if !span.is_level_uniform() {
        return Err(SpanFault::NotLevelUniform); // #start == #width
    }
    if action_point(span.width()) != Some(span.width().len()) {
        return Err(SpanFault::NotOrdinalLevel); // width acts at deepest
    }
    if zeros(span.start()) != 0 {
        return Err(SpanFault::StartNotZeroFree); // ⇒ all components > 0
    }
    if span.start().len() < 2 {
        return Err(SpanFault::StartTooShallow); // ASN-0115 WF: #start ≥ 2
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Zero;
    use skep_address::Tumbler;
    use skep_arrangement::is_ordinal_vspan;

    fn t(comps: &[u32]) -> Tumbler {
        Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
    }

    fn span(start: &[u32], width: &[u32]) -> Span {
        Span::new(t(start), t(width)).expect("test spans are T12-valid")
    }

    #[test]
    fn the_subspace_numerals_are_m1s_and_the_two_directions_round_trip() {
        // M1 owns T7, so the numeral that decides content-from-link is read
        // from M1 and memoized here, never restated.
        assert_eq!(*Subspace::Content.numeral(), content_subspace());
        assert_eq!(*Subspace::Link.numeral(), link_subspace());
        // Writing a subspace and reading it back is the identity. `of_numeral`
        // inverts `numeral` over `ALL`, so this holds exactly when no two
        // subspaces share a numeral — the one way the inversion could answer
        // for the wrong subspace.
        for s in Subspace::ALL {
            assert_eq!(Subspace::of_numeral(s.numeral()), Some(s));
        }
    }

    #[test]
    fn all_lists_both_subspaces_in_their_numerals_order() {
        // `doc_vspanset` collects one extent per subspace AS GIVEN, so ALL's
        // order is W13's normal form exactly when it is the numerals' order —
        // and a strictly increasing pair is two DIFFERENT subspaces, so both.
        let [first, second] = Subspace::ALL;
        assert!(first.numeral() < second.numeral());
    }

    #[test]
    fn of_numeral_classifies_the_two_real_subspaces_and_refuses_the_rest() {
        // The one place content-from-link is decided: every operation matches
        // on this answer rather than re-deriving the comparison chain.
        assert_eq!(
            Subspace::of_numeral(&content_subspace()),
            Some(Subspace::Content)
        );
        assert_eq!(Subspace::of_numeral(&link_subspace()), Some(Subspace::Link));
        assert_eq!(Subspace::of_numeral(&Nat::from(3u32)), None);
        assert_eq!(Subspace::of_numeral(&Nat::zero()), None);
    }

    #[test]
    fn gate_vspan_admits_wellformed_spans_of_any_depth_at_least_2() {
        // ASN-0115 WF admits #start ≥ 2; a #start ≥ 3 span is well-formed
        // (depth-COMPATIBILITY is consulting-state, gated elsewhere).
        assert!(gate_vspan(&span(&[1, 1], &[0, 3])).is_ok());
        assert!(gate_vspan(&span(&[2, 1], &[0, 1])).is_ok());
        assert!(gate_vspan(&span(&[1, 1, 1], &[0, 0, 1])).is_ok());
        // A foreign start subspace is not a WELL-FORMEDNESS matter either.
        assert!(gate_vspan(&span(&[3, 1], &[0, 1])).is_ok());
    }

    #[test]
    fn gate_vspan_rejects_each_fault_in_documented_order() {
        // Every fault, and for each ADJACENT pair of the ladder one span that
        // fails BOTH — so swapping any two neighbouring checks changes a
        // verdict here, where `SpanFault`'s card says the order is tested.
        //
        // Level-uniformity is checked before ordinal-level: a [1]-width on a
        // depth-2 start fails BOTH, and NotLevelUniform wins.
        assert_eq!(
            gate_vspan(&span(&[1, 1], &[1])),
            Err(SpanFault::NotLevelUniform)
        );
        // Level-uniform but action point 1 ≠ 2: not ordinal-level.
        assert_eq!(
            gate_vspan(&span(&[1, 1], &[1, 0])),
            Err(SpanFault::NotOrdinalLevel)
        );
        // Ordinal-level is checked before zero-freedom: a level-uniform
        // depth-3 span whose width acts at component 2 AND whose start
        // carries a separator fails BOTH, and NotOrdinalLevel wins.
        assert_eq!(
            gate_vspan(&span(&[1, 0, 1], &[0, 1, 0])),
            Err(SpanFault::NotOrdinalLevel)
        );
        // Ordinal-level and uniform, but the start carries a separator.
        assert_eq!(
            gate_vspan(&span(&[1, 0, 1], &[0, 0, 1])),
            Err(SpanFault::StartNotZeroFree)
        );
        // Zero-freedom is checked before depth: the one-component start `0`
        // — a legal endpoint, T12 asking only that the width be positive and
        // act within the start — fails BOTH, and StartNotZeroFree wins.
        assert_eq!(
            gate_vspan(&span(&[0], &[1])),
            Err(SpanFault::StartNotZeroFree)
        );
        // Everything else passes, but #start = 1 < 2.
        assert_eq!(
            gate_vspan(&span(&[5], &[1])),
            Err(SpanFault::StartTooShallow)
        );
    }

    #[test]
    fn a_gated_span_has_m5s_shape_exactly_when_its_start_is_depth_2() {
        // What lets SHOWORIGIN_V and COMPARE put WF_V(v) to M5's own span
        // reader (`as_ordinal_vspan`, whose verdict this is) instead of
        // measuring the start themselves: after this gate, DEPTH is the only
        // clause of M5's shape still open. Level-uniformity ties #width to
        // #start and ordinal-level puts the width's one nonzero component
        // last, so a gated depth-2 span IS `[s, o] × [0, n≥1]`, and every
        // deeper gated span fails M5's shape on depth alone.
        for (start, width) in [
            (&[1u32, 1][..], &[0u32, 3][..]),
            (&[2, 4], &[0, 1]),
            (&[3, 1], &[0, 1]), // a foreign subspace is still this SHAPE
        ] {
            let s = span(start, width);
            assert!(gate_vspan(&s).is_ok());
            assert!(is_ordinal_vspan(&s), "gated depth-2 ⇒ M5 serves it");
        }
        for (start, width) in [
            (&[1u32, 1, 1][..], &[0u32, 0, 1][..]),
            (&[1, 1, 1, 1], &[0, 0, 0, 2]),
        ] {
            let s = span(start, width);
            assert!(gate_vspan(&s).is_ok(), "deeper spans are WELL-FORMED");
            assert!(!is_ordinal_vspan(&s), "…and M5 declines them, on depth");
        }
    }

    #[test]
    fn of_span_is_total_over_every_span_including_the_shallowest() {
        // Position 1 of a start exists at EVERY depth — `Tumbler` indexing is
        // 1-based over a nonempty carrier — so this answers for a span the
        // gate would reject and for one it would not, alike. A `None` here
        // means "foreign numeral", never "too shallow to have one", which is
        // what lets COMPARE ask it before gating.
        assert_eq!(
            Subspace::of_span(&span(&[1, 1], &[0, 3])),
            Some(Subspace::Content)
        );
        assert_eq!(
            Subspace::of_span(&span(&[2, 1], &[0, 1])),
            Some(Subspace::Link)
        );
        assert_eq!(
            Subspace::of_span(&span(&[1, 1, 1], &[0, 0, 1])),
            Some(Subspace::Content)
        );
        assert_eq!(Subspace::of_span(&span(&[3, 1], &[0, 1])), None);
        // Depth 1: too shallow for the gate (`StartTooShallow`), and still an
        // unambiguous subspace reading.
        assert_eq!(
            Subspace::of_span(&span(&[1], &[1])),
            Some(Subspace::Content)
        );
        assert_eq!(Subspace::of_span(&span(&[5], &[1])), None);
    }
}
