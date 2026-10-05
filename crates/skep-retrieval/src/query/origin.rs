//! §C SHOWORIGIN over a V-span (ASN-0077, V-arity): one origin per run,
//! deduplicated, in tumbler order. The I-arity is de-scoped (crate doc).

use num_traits::Zero;
use skep_address::{Address, Nat, Span};
use skep_arrangement::{as_ordinal_vspan, reading_surface};

use super::{run_origin, sorted_addr_set, Query, RetrievalWorld};
use crate::error::OriginError;
use crate::vspan::{gate_vspan, Subspace};

impl<W: RetrievalWorld> Query<'_, W> {
    /// SHOWORIGIN over a V-span (ASN-0077, V-arity) — block-decompose, then
    /// project ONE origin per run (M1's `document_of` of each run's I-start):
    /// block uniformity (O2) means all addresses in one run share an origin,
    /// so this is O(runs), not O(positions). Returns
    /// deduplicated origin documents in tumbler order; for the link subspace
    /// the origin is the home document (CL-OWN) — handled uniformly, no
    /// special case. The I-arity is de-scoped (see the crate docs); only this
    /// V-arity exists.
    ///
    /// Projects over `doc`'s READING SURFACE (crate doc, *Which arrangement an
    /// operation answers from*): the gate and the span checks below run on
    /// the address named, and the surface's runs are the ones whose origins
    /// are reported.
    ///
    /// UNFILTERED (PUB-6.15): the origins come back whole for a readable
    /// argument, an unreadable origin's identity included; no predicate is
    /// threaded, the argument's consult being M10's pre-dispatch.
    ///
    /// A success is never empty: an admissible request has an occupied
    /// subspace (`n_s ≥ 1`), a depth-2 span, and a fully resolved width, so at
    /// least one run is projected and `Ok(vec![])` is not an answer this
    /// operation gives. So a registered-empty document has no empty form
    /// here: it is `EmptySubspace`, the one exception to the crate doc's
    /// registered-empty rule.
    ///
    /// Inadmissible (Err) — reject, never clip to the surviving sub-span as
    /// RETRIEVEV's R6 would (O13), and the listing below IS the precedence:
    /// the checks run in this order and the FIRST condition that holds is the
    /// one reported. A document that is not registered (WF_V i), a malformed
    /// span (ii/iv), a foreign subspace (`NoSuchSubspace`) or empty real
    /// subspace (`EmptySubspace`, iii), a
    /// depth-incompatible `#start ≥ 3` span (`DepthIncompatible`, WF_V v —
    /// kept distinct from the range case so a client can tell "wrong depth"
    /// from "unbound positions"), and a depth-2 span overrunning the bound
    /// prefix (`RangeNotPresent`, WF_V vi — fewer positions resolve than the
    /// span names). So a malformed span in a foreign subspace is
    /// `MalformedSpan`, and a deep span over an empty subspace is
    /// `EmptySubspace`.
    pub fn show_origin_v(&self, doc: &Address, span: &Span) -> Result<Vec<Address>, OriginError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        if !m3.is_registered_document(doc) {
            return Err(OriginError::DocNotRegistered); // WF_V (i)
        }
        gate_vspan(span).map_err(OriginError::MalformedSpan)?; // (ii)/(iv)
        // Gated on the address named; every arrangement read below is the
        // surface's.
        let surface = reading_surface(m3, doc);
        // The start's subspace, at any depth. Foreign (∉ {s_C, s_L}) is
        // distinct from real-but-empty.
        let Some(sub) = Subspace::of_span(span) else {
            return Err(OriginError::NoSuchSubspace);
        };
        if sub.count(m5, &surface).is_zero() {
            return Err(OriginError::EmptySubspace); // (iii)
        }
        // (v): depth must equal the subspace common depth m_S ≡ 2, asked as
        // "the shape `resolve` serves" — M5's own reader, so this refusal and
        // `resolve`'s silent ⟨⟩ can never name different spans. After
        // `gate_vspan` the only clause of M5's shape still open IS the depth
        // one: level-uniformity ties `#width` to `#start`, and ordinal-level
        // puts the width's only nonzero component last, so `#start == 2`
        // gives `width = [0, n≥1]` and every other gated span fails on depth
        // alone.
        let Some(shape) = as_ordinal_vspan(span) else {
            return Err(OriginError::DepthIncompatible);
        };
        // Span now depth-2 (≥ 3 rejected above); the resolution may still be
        // partial if the span overruns the bound prefix. One pass over M5's
        // lazy resolution: each run's width summed for (vi), its origin taken
        // into the set as it arrives — the answer and the run in hand held
        // live, never the span's run list.
        let mut resolved_width = Nat::zero();
        let origins = sorted_addr_set(m5.iter_resolve(&surface, span).map(|run| {
            resolved_width += run.width();
            run_origin(&run)
        }));
        // `shape.count` is the span's NOMINAL EXTENT — ASN-0115's name for the
        // width's deepest component, the count the span names — read off M5's
        // reading rather than by index, the same part the resolution read;
        // `resolved_width` is `|act|`, and (vi) is the corpus's nominal-extent
        // attainment failing: `|act| < ℓ_{#ℓ}`.
        if &resolved_width < shape.count {
            return Err(OriginError::RangeNotPresent); // (vi): reject, never clip (O13)
        }
        Ok(origins)
    }
}
