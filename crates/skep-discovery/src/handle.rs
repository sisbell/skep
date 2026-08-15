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

use crate::types::{Cursor, FourSet, OrphanReport, QueryError, SupClaim, Window};
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

    /// V→I resolution of `region` through `d`'s live arrangement (ASN-0127
    /// image). Deduped at the boundary by `Run: Eq` — no exact-equal `Run`
    /// repeat; overlapping INPUT region spans may still yield
    /// partially-overlapping runs (not an address-disjoint partition — don't
    /// sum widths). See [`image_on`].
    pub fn image(&self, d: &Address, region: &[Span]) -> Result<Vec<Run>, QueryError> {
        image_on(&self.kernel.snapshot(), d, region)
    }

    /// result = foundation ∩ active (`View::Active`) — nullified links never
    /// surface; diverges from ASN-0127's UNFILTERED `findlinks_V` (active
    /// only). See [`findlinks_v_on`].
    pub fn findlinks_v(&self, d: &Address, region: &[Span]) -> Result<Vec<Address>, QueryError> {
        findlinks_v_on(&self.kernel.snapshot(), d, region)
    }

    /// Present-tense census; result = foundation ∩ active — nullified links
    /// never surface. Non-monotone (ASN-0127 D-NONMONO/D-ZERO). See
    /// [`count_v_on`].
    pub fn count_v(&self, d: &Address, region: &[Span]) -> Result<usize, QueryError> {
        count_v_on(&self.kernel.snapshot(), d, region)
    }

    /// Windowed enumeration (ASN-0108); result = foundation ∩ active —
    /// nullified links never surface. `n = 0` is clamped to 1 (the API is
    /// total). See [`window_v_on`].
    pub fn window_v(
        &self,
        d: &Address,
        region: &[Span],
        cur: Cursor,
        n: usize,
    ) -> Result<Window, QueryError> {
        window_v_on(&self.kernel.snapshot(), d, region, cur, n)
    }

    /// RETRIEVEENDSETS (ASN-0131): `(slot, endset)` pairs touching `region`,
    /// identity withheld, whole endsets, pinned output order. See
    /// [`retrieve_endsets_on`].
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

    /// I→V projection of link `a`'s slot into `d`'s CONTENT subspace
    /// (ASN-0098 project). Content-subspace ONLY — strictly weaker than
    /// ASN-0098's subspace-agnostic project; a link reachable solely through
    /// `d`'s LINK subspace projects ∅ here. `NotALink` subsumes BOTH
    /// `a ∉ dom(L)` AND an out-of-range `slot`. See [`project_on`].
    pub fn project(&self, a: &Address, slot: usize, d: &Address) -> Result<SpanSet, QueryError> {
        project_on(&self.kernel.snapshot(), a, slot, d)
    }

    /// NOT pure LP12 — active-filtered. Compound "arrangement-reachable AND
    /// active": a nullified-but-reachable link returns `Ok(false)` where LP12
    /// would call it discoverable. For raw LP12 compose `followlink` + M5
    /// `project`. `NotALink` if `a ∉ dom(L)`. See [`discoverable_from_on`].
    pub fn discoverable_from(&self, a: &Address, d: &Address) -> Result<bool, QueryError> {
        discoverable_from_on(&self.kernel.snapshot(), a, d)
    }

    // ── Pre-edit link-survival (read-only; never touches the edit path) ──

    /// Pre-edit what-if (read-only; never the edit path). result = foundation
    /// ∩ active — a nullified link that lost its last witness in `d` is NOT
    /// reported (diverges from ASN-0117's `D(d,Σ)` over `dom(L)`). Mirrors
    /// DELETE's preconditions: `NotContentSubspace` / `EmptyWidth` /
    /// `OutOfBounds` — `OutOfBounds` deliberately folds M5's `NotArranged` +
    /// `OutOfBounds` (jointly equivalent under width ≥ 1). See
    /// [`delete_orphans_on`].
    pub fn delete_orphans(
        &self,
        d: &Address,
        p: &VPos,
        width: &Nat,
    ) -> Result<OrphanReport, QueryError> {
        delete_orphans_on(&self.kernel.snapshot(), d, p, width)
    }

    // ── Archival supersession/edit lineage (y/x intended as resident link
    //    addresses — dom(L)) ──

    /// Claims with `old = y` (ASN-0125 EL11b). `v`: `Active` = operative
    /// graph (`succ_o`), `Audit` = full history (`succ_h`); `Default` behaves
    /// as `Active` (M7's §G primitives coerce it). See [`in_claims_on`].
    pub fn in_claims(&self, y: &Address, v: View) -> Vec<SupClaim> {
        in_claims_on(&self.kernel.snapshot(), y, v)
    }

    /// Claims with `new = x` (ASN-0125 EL11b). Same view contract as
    /// [`LinkQuery::in_claims`]. See [`out_claims_on`].
    pub fn out_claims(&self, x: &Address, v: View) -> Vec<SupClaim> {
        out_claims_on(&self.kernel.snapshot(), x, v)
    }
}
