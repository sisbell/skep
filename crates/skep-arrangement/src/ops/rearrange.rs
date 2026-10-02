//! REARRANGE (ASN-0119/0084; §6): the pivot and the swap, a cut-determined
//! permutation of the content subspace.

use skep_address::{Address, Nat};
use skep_kernel::{Seq, TxnError, WorldState};
use skep_namespace::{HasM3, M3State};

use super::Vstream;
use crate::chain::published_target;
use crate::error::RearrangeError;
use crate::ownership::{gate_write, Caller};
use crate::state::M5Rec;
use crate::vspace::VPos;
use crate::HasM5;

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3, // reads M3 registration + M5 only
    W::Record: From<M5Rec>,        // stages only M5Rec
{
    /// REARRANGE (ASN-0119/0084; §6): pivot (3 cuts) / swap (4 cuts)
    /// transpose in the content subspace. Pure cut-determined, value-blind
    /// permutation — content, links, R untouched (a duplicate-I interval
    /// correctly yields π ≠ id with M' = M).
    ///
    /// THE RESULTING ORDER, which is what a caller relays. With THREE cuts the
    /// two adjacent regions `α = [c₀, c₁)` and `β = [c₁, c₂)` exchange in
    /// place, so the arranged content reads `α`'s positions where `β`'s stood
    /// and `β`'s where `α`'s stood. With FOUR, the outer regions
    /// `α = [c₀, c₁)` and `β = [c₂, c₃)` exchange around `μ = [c₁, c₂)`, which
    /// keeps its positions. Everything outside `[ord(c₀), ord(c_last))` is
    /// untouched, and the result is a permutation of the same POSITIONS — the
    /// same multiset of I-addresses, re-decomposed maximally, so an exchange
    /// that rejoins two runs of one origin leaves fewer runs than it found:
    /// `content_count` is unchanged, no I-address enters or leaves the
    /// arrangement, and `deletions` therefore reports exactly what it did
    /// before (RA1/RA6).
    ///
    /// `cuts` is borrowed, as COPY's specs are, so the caller keeps the cut
    /// sequence it asked with — to report it beside a rejection, say. The
    /// record then clones the three or four ordinals out; against a
    /// transaction that will fsync, four small clones buy the caller its own
    /// value back.
    ///
    /// Check order (which error wins, per R-PRE): `DocNotRegistered` →
    /// `NotOwner` (the ω gate) → `PublishedTarget` (PUB-2.11 on the document
    /// `doc` projects to, PUB-2.15; a re-arrangement is an in-place edit and
    /// has no deposit form) → `BadCutCount` (3|4) →
    /// `NotAscending` (strict) → `NotContentSubspace` (every cut) →
    /// `OutOfBounds` (CS5 lower bound `1 ≤ ord(c₀)` and upper bound
    /// `ord(c_last) ≤ n_C + 1`) → `EmptyContentSubspace` (R-PRE(ii)). That
    /// last verdict is defensive completeness, not a reachable one: an empty
    /// subspace admits ordinal 1 alone, and three or four strictly ascending
    /// cuts from `1 ≤ ord(c₀)` put the last cut past it, so the bounds check
    /// answers `OutOfBounds` first — which is why the two checks may not be
    /// transposed (`rearrange_rejects_in_documented_order` pins it on an
    /// empty draft). Strict ascent already forces every region width ≥ 1, so
    /// no per-region emptiness check is reachable either.
    pub fn rearrange(
        &self,
        caller: Caller,
        doc: &Address,
        cuts: &[VPos],
    ) -> Result<Seq, TxnError<RearrangeError>> {
        let key = M3State::content_lock_key(doc);
        self.kernel
            .transact(&[key], |stg| {
                gate_write(
                    stg.working().m3(),
                    caller,
                    doc,
                    RearrangeError::DocNotRegistered,
                    RearrangeError::NotOwner,
                )?;
                // PUB-6.36 slot 5: the in-place advance refusal (PUB-2.11).
                if published_target(stg.working().m3(), doc) {
                    return Err(RearrangeError::PublishedTarget);
                }
                // Three cuts or four (R-PRE), binding the first and the last:
                // the two the bounds check below asks the arrangement about.
                let (first, last) = match cuts {
                    [first, _, last] | [first, _, _, last] => (first, last),
                    _ => return Err(RearrangeError::BadCutCount),
                };
                // Ascent is judged on the ordinals alone, not on `VPos`'s own
                // order: a cut's subspace is the NEXT verdict's subject, and
                // comparing whole positions would answer a stray subspace here
                // as `NotAscending`.
                if !cuts.windows(2).all(|w| w[0].ordinal < w[1].ordinal) {
                    return Err(RearrangeError::NotAscending);
                }
                if cuts.iter().any(|c| !c.is_content()) {
                    return Err(RearrangeError::NotContentSubspace);
                }
                let m5 = stg.working().m5();
                // Strict ascent is established above, so asking the
                // arrangement about the first and last cut settles CS5 for
                // every cut between them.
                if !m5.admits_content_boundary(doc, &first.ordinal)
                    || !m5.admits_content_boundary(doc, &last.ordinal)
                {
                    return Err(RearrangeError::OutOfBounds);
                }
                if m5.content_is_empty(doc) {
                    return Err(RearrangeError::EmptyContentSubspace);
                }
                let cut_ordinals: Vec<Nat> = cuts.iter().map(|c| c.ordinal.clone()).collect();
                stg.push(
                    M5Rec::ContentReorder {
                        doc: doc.clone(),
                        cut_ordinals,
                    }
                    .into(),
                );
                Ok(())
            })
            .map(|((), seq)| seq)
    }
}
