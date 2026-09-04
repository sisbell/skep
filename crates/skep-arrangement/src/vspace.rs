//! §Request-side V-space values — the depth-2 V-position ([`VPos`]), COPY's
//! source specification ([`VSpec`]), and the ONE predicate deciding whether a
//! `Span` names an ordinal-level depth-2 V-range ([`is_ordinal_vspan`]).

use num_traits::Zero;
use skep_address::{Address, Nat, Span};

/// A depth-2 V-position `[subspace, ordinal]` (m = 2 — ASN-0036 S8-depth;
/// structurally depth-2, so "depth" needs no separate check).
#[derive(Clone, Debug)]
pub struct VPos {
    /// s_C = 1 (content) or s_L = 2 (link), per ASN-0047.
    pub subspace: Nat,
    /// 1-based ordinal within the subspace.
    pub ordinal: Nat,
}

/// One source-span for COPY (ASN-0118): transclude `span` of `source`'s
/// arrangement. The span must satisfy [`is_ordinal_vspan`] and lie in the
/// content subspace (`BadSpan`/`SourceNotContentSubspace` otherwise —
/// Conflicts #7).
#[derive(Clone, Debug)]
pub struct VSpec {
    pub source: Address,
    pub span: Span,
}

/// Does `span` name an ordinal-level depth-2 V-range — a count of positions
/// within one subspace (ASN-0118 action point 2)? The COMPLETE condition is
/// `#start == 2 ∧ #width == 2 ∧ width.get(1) == 0`: a span with `#start ≠ 2`
/// (below or above), a `#width ≠ 2`, or a level-uniform `[m, n]` width with
/// `m > 0` (action-point-1, which makes `width.get(2)` the wrong extraction)
/// each fail it.
///
/// THE ONE DEFINITION of that shape in M5, so its two verdicts cannot drift
/// apart: [`M5State::resolve`](crate::M5State::resolve) folds a span failing
/// it to ⟨⟩, and COPY rejects the same span as
/// [`CopyError::BadSpan`](crate::CopyError::BadSpan). Published so a caller
/// building V-spans from a request can pre-validate and tell "bad request"
/// from "genuinely empty" before it asks.
pub fn is_ordinal_vspan(span: &Span) -> bool {
    span.start().len() == 2
        && span.width().len() == 2
        && span.width().get(1).is_some_and(|w| w.is_zero())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{t, vspan};

    #[test]
    fn the_ordinal_vspan_shape_is_exactly_the_three_clauses() {
        // §2/§5: the usable form, and each way of failing it.
        // The link subspace is as usable a shape as the content one.
        assert!(is_ordinal_vspan(&vspan(1, 1, 3)));
        assert!(is_ordinal_vspan(&vspan(2, 4, 1)));
        // #start ≠ 2, below and above.
        let shallow = Span::new(t(&[5]), t(&[1])).expect("T12");
        assert!(!is_ordinal_vspan(&shallow));
        let deep = Span::new(t(&[1, 1, 1]), t(&[0, 0, 1])).expect("T12");
        assert!(!is_ordinal_vspan(&deep));
        // A level-uniform [m, n] width with m > 0 is action-point-1.
        let level_uniform = Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12");
        assert!(!is_ordinal_vspan(&level_uniform));
    }
}
