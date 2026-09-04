//! §Public interface — the [`LinkQuery`] handle: every method takes ONE fresh
//! M2 snapshot and delegates to its pure `*_on` twin, threading that one
//! snapshot through all internal composition (the one-`(L, M, registry)`
//! coherence ASN-0127 forces; M2 clause 6). Which of the two routes a caller
//! wants is answered on [`LinkQuery`] itself.

use std::fmt;

use skep_address::{Address, Nat, Span, SpanSet};
use skep_arrangement::{Run, VPos};
use skep_kernel::{Kernel, WorldState};
use skep_links::{Endset, View};

use crate::types::{Cursor, FourSet, OrphanError, OrphanReport, QueryError, SupClaim, Window};
use crate::{
    addressably_discoverable_from_on, count_ftt_on, count_v_on, delete_orphans_on,
    findlinks_ftt_on, findlinks_v_on, image_on, in_claims_on, out_claims_on, project_on,
    retrieve_endsets_on, window_ftt_on, window_v_on, DiscoveryWorld,
};

/// The read-only query/presentation handle over the link subsystem (M8). Owns
/// no authoritative state and no index; recomputes every answer from upstream
/// (M7/M5/M3) over one snapshot per call.
///
/// The convenience is that a caller needs no snapshot of its own to read
/// current state; the cost is that the snapshot is taken and dropped INSIDE
/// each call, so the answer comes back with no way to learn which state
/// produced it, and two answers come from two states. A caller that must name
/// the state it read (reporting it as an `as_of`, say) or read two answers off
/// one state uses the pure `*_on` twins over its own `&Snapshot<W>` instead.
pub struct LinkQuery<'k, W: WorldState> {
    kernel: &'k Kernel<W>,
}

/// The handle prints as itself: `Kernel` is deliberately opaque, and the
/// answer comes from a snapshot taken and dropped inside the call, so there is
/// no pinned coordinate to render. Written out rather than derived: a derive
/// would bound the impl on `W: Debug`, which a world composed of persistent
/// store slices need not be — and asking for it would make this type the
/// reason a consumer's own derive fails.
impl<W: WorldState> fmt::Debug for LinkQuery<'_, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkQuery").finish_non_exhaustive()
    }
}

/// A `LinkQuery` IS a borrow of the kernel, so it copies like one; a copy
/// binds the same kernel and, like the original, snapshots afresh per call.
/// The charter above — no slice, no index, no state — is what keeps this safe
/// to promise: the day this holds a field of its own it stops being a borrow
/// and loses `Copy` with it.
///
/// Hand-written because the derives would put `W: Clone`/`W: Copy` on impls
/// that never touch `W`, and no `WorldState` is `Copy`.
impl<W: WorldState> Clone for LinkQuery<'_, W> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<W: WorldState> Copy for LinkQuery<'_, W> {}

impl<'k, W: DiscoveryWorld> LinkQuery<'k, W> {
    /// Bind the kernel. Each method then takes ONE fresh snapshot and
    /// delegates to its `*_on` twin.
    pub fn new(kernel: &'k Kernel<W>) -> Self {
        LinkQuery { kernel }
    }

    // ── Content-region discovery (V-anchored, present-tense, doc-gated;
    //    disjunctive over slots; every result is the selection index
    //    `findlinks_V ∩ addressable`, so nullified links never appear) ──

    /// The I-runs `region` resolves to through `d`'s live arrangement
    /// (ASN-0127 image). See [`image_on`].
    pub fn image(&self, d: &Address, region: &[Span]) -> Result<Vec<Run>, QueryError> {
        image_on(&self.kernel.snapshot(), d, region)
    }

    /// The links touching `region` (ASN-0127 findlinks over the image). See
    /// [`findlinks_v_on`].
    pub fn findlinks_v(&self, d: &Address, region: &[Span]) -> Result<Vec<Address>, QueryError> {
        findlinks_v_on(&self.kernel.snapshot(), d, region)
    }

    /// How many links touch `region` — the present-tense census. See
    /// [`count_v_on`].
    pub fn count_v(&self, d: &Address, region: &[Span]) -> Result<usize, QueryError> {
        count_v_on(&self.kernel.snapshot(), d, region)
    }

    /// One window of the links touching `region` (ASN-0108). See
    /// [`window_v_on`].
    pub fn window_v(
        &self,
        d: &Address,
        region: &[Span],
        cur: Cursor,
        n: usize,
    ) -> Result<Window, QueryError> {
        window_v_on(&self.kernel.snapshot(), d, region, cur, n)
    }

    /// RETRIEVEENDSETS (ASN-0131): the `(slot, endset)` pairs touching
    /// `region`. See [`retrieve_endsets_on`].
    pub fn retrieve_endsets(
        &self,
        d: &Address,
        region: &[Span],
    ) -> Result<Vec<(usize, Endset)>, QueryError> {
        retrieve_endsets_on(&self.kernel.snapshot(), d, region)
    }

    // ── Four-set descriptor query (address-keyed, conjunctive,
    //    link-store-local, monotone absent retraction) ──

    /// FINDLINKS over the four-set descriptor (ASN-0121). See
    /// [`findlinks_ftt_on`].
    pub fn findlinks_ftt(&self, q: &FourSet) -> Vec<Address> {
        findlinks_ftt_on(&self.kernel.snapshot(), q)
    }

    /// The count operation (ASN-0132). See [`count_ftt_on`].
    pub fn count_ftt(&self, q: &FourSet) -> usize {
        count_ftt_on(&self.kernel.snapshot(), q)
    }

    /// Windowed enumeration over the descriptor family (ASN-0108, the FTT
    /// Match reading). See [`window_ftt_on`].
    pub fn window_ftt(&self, q: &FourSet, cur: Cursor, n: usize) -> Window {
        window_ftt_on(&self.kernel.snapshot(), q, cur, n)
    }

    // ── Pointwise projection & discoverability (content subspace) ──

    /// The V-positions of `d`'s CONTENT that link `a`'s slot covers (ASN-0098
    /// project) — the module's one UNFILTERED read, so a retracted link still
    /// projects. See [`project_on`].
    pub fn project(&self, a: &Address, slot: usize, d: &Address) -> Result<SpanSet, QueryError> {
        project_on(&self.kernel.snapshot(), a, slot, d)
    }

    /// Is link `a` discoverable from `d` (LP12) AND addressable? See
    /// [`addressably_discoverable_from_on`].
    pub fn addressably_discoverable_from(
        &self,
        a: &Address,
        d: &Address,
    ) -> Result<bool, QueryError> {
        addressably_discoverable_from_on(&self.kernel.snapshot(), a, d)
    }

    // ── Pre-edit link-survival (read-only; never touches the edit path) ──

    /// The links a proposed DELETE of `[p, p+width)` would drop from `d` —
    /// a pure what-if, never the edit path. See [`delete_orphans_on`].
    pub fn delete_orphans(
        &self,
        d: &Address,
        p: &VPos,
        width: &Nat,
    ) -> Result<OrphanReport, OrphanError> {
        delete_orphans_on(&self.kernel.snapshot(), d, p, width)
    }

    // ── Archival supersession/edit lineage (y/x intended as resident link
    //    addresses — dom(L)) ──

    /// The supersession claims with `old = y`, under `v` (ASN-0125 EL11b).
    /// See [`in_claims_on`].
    pub fn in_claims(&self, y: &Address, v: View) -> Vec<SupClaim> {
        in_claims_on(&self.kernel.snapshot(), y, v)
    }

    /// The supersession claims with `new = x`, under `v` (ASN-0125 EL11b).
    /// See [`out_claims_on`].
    pub fn out_claims(&self, x: &Address, v: View) -> Vec<SupClaim> {
        out_claims_on(&self.kernel.snapshot(), x, v)
    }
}
