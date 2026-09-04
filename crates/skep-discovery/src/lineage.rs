//! §7 — archival supersession/edit lineage (ASN-0125 EL11b, the archival,
//! arrangement-independent half of the decomposed scope): raw claim
//! enumeration over M7's `match_links ∩ type_slice(Supersedes)` composition —
//! distinct from M7's own `succs`/`chain`/`tip`/`current` walks, which stay
//! M7's. Contextual discovery (EL11a) is out of scope and composed above M8.

use skep_address::{validate, Address};
use skep_arrangement::HasM5;
use skep_kernel::{Snapshot, WorldState};
use skep_links::{enc, Endset, HasLinks, LinkState, ShippedType, View};
use skep_namespace::HasM3;

use crate::helpers::home_of;
use crate::types::SupClaim;
use crate::{FROM, TO};

/// What one resident claim says: its two endpoints under the flipped
/// convention, its home attribution (EL8b), and its own activity.
///
/// **Schema-conformance reliance (Ŝ^Σ = S^Σ):** the endpoints are read out
/// with NO per-claim conformance filter, faithful because the assembled
/// system is edit-disciplined (EL-DM — every `[K_sup]` claim is born through
/// M7's `assert_sup`/`editlink`, which schema-conform their emission). The
/// reliance is semantic only, never safety-bearing: every stored `[K_sup]`
/// tuple carries unit-depth single-address F and G by M7's `[K_sup]`
/// sole-writer fences — `Endset::single_denoted`, the test those fences
/// establish — so the read-out cannot fault.
///
/// `c` is a claim resident in `l`, as every address the enumeration hands
/// over comes off M7's own index keys.
fn claim_at(l: &LinkState, c: &Address) -> SupClaim {
    let link = l.readlink(c).expect("hit keys are resident links");
    SupClaim {
        old: endpoint(
            link.from_slot(),
            "a [K_sup] F denotes exactly one address (Df-DISC(ii), held by M7's sole-writer fences)",
        ),
        new: endpoint(
            link.to_slot(),
            "a [K_sup] G denotes exactly one address (Df-DISC(ii), held by M7's sole-writer fences)",
        ),
        home: home_of(c), // EL8b
        active: l.is_active(c),
        claim: c.clone(),
    }
}

/// The single address a claim endpoint denotes. `denotes` states the fence
/// the read-out rests on, naming which endpoint — F or G — it is reading.
fn endpoint(e: &Endset, denotes: &'static str) -> Address {
    let t = e.single_denoted().expect(denotes).clone();
    validate(t).expect("denoted claim endpoints are T4-valid link addresses")
}

/// The shared claim enumeration: claims naming `key` at `slot`, restricted to
/// the `[K_sup]` class.
///
/// **Flipped storage convention** (the M7→M8 seam, diverging from ASN-0125's
/// textual Df-DIR): `FROM = old/superseded`, `TO = new/superseding` — so
/// `in(y)` (old = y) probes FROM and `out(x)` (new = x) probes TO.
///
/// **Resident-key gate (enforced, not merely documented):** exactness of the
/// `match_links ∩ type_slice` composition rests on the `dom(L)`
/// prefix-antichain (EL4 + R0a); for a NON-link `key`, `enc([key])`'s prefix
/// coverage could overlap a prefix-comparable claim and silently over-match.
/// These reads return `Vec`, not `Result`, so the gate short-circuits to `[]`
/// when `readlink(key)` is `None` — the correct empty lineage, a defensive
/// backstop, not a license to pass arbitrary tumblers.
fn claims_on<W>(s: &Snapshot<W>, slot: usize, key: &Address, v: View) -> Vec<SupClaim>
where
    W: WorldState + HasLinks + HasM5 + HasM3,
{
    let l = s.world().links();
    if l.readlink(key).is_none() {
        return Vec::new(); // residence gate (EL4 + R0a)
    }
    let sup = l.reserved_type(ShippedType::Supersedes);
    let named = enc([key]); // bound: M7 borrows a constraint's query
    let hits = l
        .match_links(&[(slot, &named)], v) // claims naming `key` at `slot`
        .intersection(l.type_slice(sup, v)); // restrict to supersession claims (Ŝ^Σ = S^Σ)
    hits.iter().map(|c| claim_at(l, c)).collect()
}

/// The claims with `old = y` (ASN-0125 EL11b `in(y)`): probes FROM under the
/// flipped convention. `y` is intended as a resident link address (`dom(L)`);
/// a non-link key is gated internally and returns `[]`. `v = Active` yields
/// the operative graph (`succ_o`), `Audit` the full history (`succ_h`);
/// `Default` behaves as `Active` (M7's §G primitives coerce it).
pub fn in_claims_on<W>(s: &Snapshot<W>, y: &Address, v: View) -> Vec<SupClaim>
where
    W: WorldState + HasLinks + HasM5 + HasM3,
{
    claims_on(s, FROM, y, v)
}

/// The claims with `new = x` (ASN-0125 EL11b `out(x)`): probes TO under the
/// flipped convention. Same key/view contract as [`in_claims_on`].
pub fn out_claims_on<W>(s: &Snapshot<W>, x: &Address, v: View) -> Vec<SupClaim>
where
    W: WorldState + HasLinks + HasM5 + HasM3,
{
    claims_on(s, TO, x, v)
}
