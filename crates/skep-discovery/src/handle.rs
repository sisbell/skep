//! §Public interface — the [`LinkQuery`] handle: every method takes ONE fresh
//! M2 snapshot and delegates to its pure `*_on` twin, threading that one
//! snapshot through all internal composition (the one-`(L, M, registry)`
//! coherence ASN-0127 forces; M2 clause 6). For a consistent multi-call
//! verdict — a count and its window — a caller uses the `*_on` twins over one
//! shared `&Snapshot<W>` instead.

use skep_address::{Address, Nat, Span, SpanSet};
use skep_arrangement::{HasM5, Run, VPos};
use skep_kernel::{Kernel, WorldState};
use skep_links::{Endset, HasLinks, View};
use skep_namespace::HasM3;

use crate::types::{Cursor, FourSet, OrphanError, OrphanReport, QueryError, SupClaim, Window};
use crate::{
    count_ftt_on, count_v_on, delete_orphans_on, discoverable_from_on, findlinks_ftt_on,
    findlinks_v_on, image_on, in_claims_on, out_claims_on, project_on, retrieve_endsets_on,
    window_ftt_on, window_v_on,
};

/// The read-only query/presentation handle over the link subsystem (M8). Owns
/// no authoritative state and no index; recomputes every answer from upstream
/// (M7/M5/M3) over one snapshot per call.
pub struct LinkQuery<'k, W: WorldState> {
    kernel: &'k Kernel<W>,
}

impl<'k, W> LinkQuery<'k, W>
where
    W: WorldState + HasLinks + HasM5 + HasM3,
{
    /// Bind the kernel. Each method then takes ONE fresh snapshot and
    /// delegates to its `*_on` twin.
    pub fn new(kernel: &'k Kernel<W>) -> Self {
        LinkQuery { kernel }
    }

    // ── Content-region discovery (V-anchored, present-tense, doc-gated;
    //    disjunctive over slots; every result is foundation ∩ View::Active =
    //    addressable, so nullified links never appear) ──

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

    /// Is link `a` reachable through `d`'s arrangement AND active? Compound,
    /// NOT pure LP12. See [`discoverable_from_on`].
    pub fn discoverable_from(&self, a: &Address, d: &Address) -> Result<bool, QueryError> {
        discoverable_from_on(&self.kernel.snapshot(), a, d)
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
