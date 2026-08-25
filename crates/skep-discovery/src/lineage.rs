//! §7 — archival supersession/edit lineage (ASN-0125 EL11b, the archival,
//! arrangement-independent half of the decomposed scope): raw claim
//! enumeration over M7's `match_links ∩ type_slice(Supersedes)` composition —
//! distinct from M7's own `succs`/`chain`/`tip`/`current` walks, which stay
//! M7's. Contextual discovery (EL11a) is out of scope and composed above M8.

use skep_address::{document_of, validate, Address};
use skep_arrangement::HasM5;
use skep_kernel::{Snapshot, WorldState};
use skep_links::{enc, HasLinks, ShippedType, View};
use skep_namespace::HasM3;

use crate::types::SupClaim;
use crate::{FROM, TO};

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
///
/// **Schema-conformance reliance (Ŝ^Σ = S^Σ):** the slice is ranged with NO
/// per-claim conformance filter, faithful because the assembled system is
/// edit-disciplined (EL-DM — every `[K_sup]` claim is born through M7's
/// `assert_sup`/`editlink`, which schema-conform their emission). The
/// reliance is semantic only, never safety-bearing: every emit-shaped
/// `[K_sup]` tuple carries unit-depth single-address F and G by M7's shape
/// gates, so the endpoint read-out cannot fault.
fn claims_on<W>(s: &Snapshot<W>, slot: usize, key: &Address, v: View) -> Vec<SupClaim>
where
    W: WorldState + HasLinks + HasM5 + HasM3,
{
    let l = s.world().links();
    if l.readlink(key).is_none() {
        return Vec::new(); // residence gate (EL4 + R0a)
    }
    let sup = l.reserved_type(ShippedType::Supersedes);
    let hits = l
        .match_links(&[(slot, enc([key]))], v) // claims naming `key` at `slot`
        .intersection(l.type_slice(sup, v)); // restrict to supersession claims (Ŝ^Σ = S^Σ)
    hits.iter()
        .map(|c| {
            let link = l.readlink(c).expect("hit keys are resident links");
            let old = validate(
                link.from_slot()
                    .addrs()
                    .next()
                    .expect("[K_sup] F is unit-depth single-address (M7's shape gate)")
                    .clone(),
            )
            .expect("denoted claim endpoints are T4-valid link addresses");
            let new = validate(
                link.to_slot()
                    .addrs()
                    .next()
                    .expect("[K_sup] G is unit-depth single-address (M7's shape gate)")
                    .clone(),
            )
            .expect("denoted claim endpoints are T4-valid link addresses");
            SupClaim {
                old,
                new,
                home: document_of(c)
                    .expect("a link address has zeros = 3, so its origin Document exists"), // EL8b
                active: l.is_active(c),
                claim: c.clone(),
            }
        })
        .collect()
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
