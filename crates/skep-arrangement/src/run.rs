//! §A — the `Run` value: one contiguous I-extent placed in an arrangement,
//! and the ONE admissible Run→Span lift ([`Run::iextent`]).

use num_traits::Zero;
use serde::{Deserialize, Serialize};
use skep_address::{shift, Address, Level, Nat, Span};

/// One arrangement run: `width` consecutive I-addresses starting at
/// `i_start`, occupying implicit consecutive V-ordinals (§Core data model —
/// V-positions are never stored; a run's V-start is a prefix sum, which is
/// what makes D-SEQ★/D-CTG★/D-MIN★ hold by construction).
///
/// STANDING INVARIANTS: every `Run` has `width ≥ 1` AND an element-level
/// `i_start` (`zeros = 3`). Fields are CRATE-PRIVATE: a foreign crate can
/// neither build a `Run` by struct literal nor mutate one it holds —
/// including an OWNED `Run` returned by `resolve`/`content_runs`/`link_runs`
/// — so runs are read-only across every seam (M6/M7/M8 read via the
/// [`i_start`](Run::i_start)/[`width`](Run::width) accessors). [`Run::new`]
/// is therefore the sole foreign CONSTRUCTOR. The one field-by-field bypass
/// is derived `Deserialize`: a *recovered* Run's shape rests on M2 checkpoint
/// integrity (the same trust posture as all of recovery), not the type
/// system. On that basis the invariants hold for every
/// minted-or-validly-recovered Run — which is exactly what justifies
/// `iextent`'s `.expect`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    pub(crate) i_start: Address,
    pub(crate) width: Nat,
}

impl Run {
    /// Checked constructor — the seam guard for an EXTERNAL producer (none in
    /// v1): `None` iff `width == 0` OR `i_start` is not element-level
    /// (`zeros(i_start) ≠ 3`, equivalently `i_start.level() ≠
    /// Level::Element`). M5's own emission sites (run-list split/coalesce,
    /// `resolve`, `content_runs`/`link_runs`, the folds) build Runs with
    /// `width ≥ 1` and an element-level `i_start` STRUCTURALLY by the
    /// in-crate struct literal — their starts are minted element addresses or
    /// ordinal-shifts of one. Field privacy then closes the
    /// mutate-after-obtain path: a foreign holder cannot later set
    /// `width = 0` or swap `i_start` on any Run it obtained, owned or
    /// borrowed.
    pub fn new(i_start: Address, width: Nat) -> Option<Run> {
        if width.is_zero() || i_start.level() != Level::Element {
            return None;
        }
        Some(Run { i_start, width })
    }

    /// Read accessor — with [`width`](Run::width), the only foreign field
    /// access.
    pub fn i_start(&self) -> &Address {
        &self.i_start
    }

    /// Read accessor — the run's width (≥ 1 by standing invariant).
    pub fn width(&self) -> &Nat {
        &self.width
    }

    /// The ONE admissible Run→Span lift: the level-uniform, element-level
    /// I-extent `[i_start, shift(i_start, width))`. Centralized (public) so
    /// no consumer re-derives it and none writes the malformed
    /// `Span(i_start, [0, width])` — an element-level start against a depth-2
    /// width gives `#start ≠ #width`, faulting every downstream
    /// `intersect`/`difference`/`normalize` with `LevelMismatch`.
    ///
    /// TOTAL given the two standing invariants: `width ≥ 1` makes `shift`
    /// advance (`start < reach`, TS4) and length-preserving
    /// (`#start = #reach`), so `from_endpoints` cannot fault; the
    /// element-level `i_start` makes that raw `shift` land on the ordinal
    /// field, not the text→link separator (M1's stated safe window for raw
    /// `shift` — TA7a). A SpanSet aggregating iextents across
    /// origin-documents is mixed-length — consume it under the level-class
    /// discipline (see [`M5State::resolve_coverage`]).
    ///
    /// [`M5State::resolve_coverage`]: crate::M5State::resolve_coverage
    pub fn iextent(&self) -> Span {
        Span::from_endpoints(
            self.i_start.tumbler().clone(),
            &shift(self.i_start.tumbler(), &self.width),
        )
        .expect("width ≥ 1 ⇒ start < reach ∧ #start = #reach ⇒ from_endpoints cannot fault")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{a, ca, n};

    #[test]
    fn new_rejects_width_zero_and_non_element_starts() {
        // Interface: None ⇔ width == 0 ∨ zeros(i_start) ≠ 3.
        assert!(Run::new(ca(1), n(0)).is_none());
        assert!(Run::new(a(&[1, 0, 1, 0, 1]), n(1)).is_none()); // Document, zeros = 2
        assert!(Run::new(a(&[1, 0, 1]), n(1)).is_none()); // Account, zeros = 1
        let r = Run::new(ca(3), n(2)).expect("element-level start with width ≥ 1 is admitted");
        assert_eq!(r.i_start(), &ca(3));
        assert_eq!(r.width(), &n(2));
    }

    #[test]
    fn iextent_is_the_half_open_ordinal_shift_extent() {
        // §2: [i_start, shift(i_start, width)) — level-uniform, element-level.
        let r = Run::new(ca(2), n(3)).expect("valid run");
        let s = r.iextent();
        assert_eq!(s.start(), ca(2).tumbler());
        assert_eq!(s.reach(), *ca(5).tumbler()); // ordinal 2 + width 3
        assert!(s.is_level_uniform());
        assert!(s.contains(ca(2).tumbler()));
        assert!(s.contains(ca(4).tumbler()));
        assert!(!s.contains(ca(5).tumbler())); // half-open
    }

    #[test]
    fn run_survives_a_bincode_round_trip() {
        // §A: Run is a journaled type (inside ContentPlace); bincode is M2's
        // actual wire format.
        let r = Run::new(ca(7), n(4)).expect("valid run");
        let bytes = bincode::serialize(&r).expect("run serializes");
        let back: Run = bincode::deserialize(&bytes).expect("run deserializes");
        assert!(back == r);
        assert_eq!(back.i_start(), &ca(7));
        assert_eq!(back.width(), &n(4));
    }
}
