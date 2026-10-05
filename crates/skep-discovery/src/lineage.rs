//! §7 — archival supersession/edit lineage (ASN-0125 EL11b, the archival,
//! arrangement-independent half of the decomposed scope): raw claim
//! enumeration through M7's typed `observe` of the supersession class — the
//! typed slice M7's BH3 reverse read walks, over that class alone — distinct
//! from M7's own `succs`/`chain`/`tip`/`current` walks, which stay M7's.
//! Contextual discovery (EL11a) is out of scope and composed above M8.

use skep_address::{validate, Address};
use skep_kernel::Snapshot;
use skep_links::{Endset, LinkState, Pattern, ShippedType, Tuple, View};

use crate::home::{home_of, home_readable};
use crate::types::SupClaim;
use crate::DiscoveryWorld;

/// Which ENDPOINT of a claim a probe key is — `old` for `in(y)`, `new` for
/// `out(x)` — and the slot M7 stores it in, under the FLIPPED storage
/// convention (the M7→M8 seam, diverging from ASN-0125's textual Df-DIR):
/// `FROM = old/superseded`, `TO = new/superseding`. The endpoint is
/// ASN-0125's and fixed; the slot — the SIDE, in ASN-0125's and M7's word
/// (from-side/to-side, F-side/G-side) — is the storage convention's, and
/// [`Endpoint::pattern`] is the one place the first is mapped to the
/// second, so the two probes cannot put the key on the wrong slot.
#[derive(Clone, Copy)]
enum Endpoint {
    /// `in(y)` — the claims whose `old` is the key, asked of F.
    Old,
    /// `out(x)` — the claims whose `new` is the key, asked of G.
    New,
}

impl Endpoint {
    /// ASN-0086's pattern asking for `key` in the slot M7 stores this endpoint
    /// in, and nothing in the other's: the probe IS the key, one tumbler, so
    /// the side it fills is never the empty side `observe` reads as no
    /// constraint.
    fn pattern(self, key: &Address) -> Pattern<'_> {
        let probe = std::slice::from_ref(key.tumbler());
        match self {
            Endpoint::Old => Pattern {
                from: probe,
                ..Pattern::default()
            },
            Endpoint::New => Pattern {
                to: probe,
                ..Pattern::default()
            },
        }
    }
}

/// What one resident claim says: its two endpoints under the flipped
/// convention, its home attribution (EL8b), and its own activity.
///
/// **Schema-conformance reliance (Ŝ^Σ = S^Σ):** the endpoints are read out
/// with NO per-claim conformance filter, faithful because the assembled
/// system is edit-disciplined (EL-DM — every `[K_sup]` claim is born through
/// M7's `assert_sup`/`editlink`, which schema-conform their emission). The
/// reliance is semantic only, never safety-bearing, and it rests on BOTH
/// clauses of M7's `[K_sup]` sole-writer fences, since the read-out takes
/// something from each: every stored tuple carries unit-depth single-address
/// F and G, so `Endset::single_denoted` answers rather than faulting; and
/// each denotes a RESIDENT link — `assert_sup` checks residence outright, the
/// `editlink` guard requires it of a caller-supplied successor, and the two
/// open deposit paths refuse the class — so the tumbler it denotes is a store
/// key minted by M3, hence T4-valid, and the address lift cannot fault
/// either.
///
/// `t` is a tuple M7's `observe` handed over: its address is a key of the
/// supersession class's typed slice, so resident in `l`, and its slots are the
/// claim's stored F and G — read once, by `observe`, and not again here.
fn claim_at(l: &LinkState, t: Tuple) -> SupClaim {
    let Tuple { addr, from, to } = t;
    let home = home_of(&addr); // EL8b
    let active = l.is_active(&addr);
    SupClaim {
        old: endpoint(
            &from,
            "a [K_sup] F denotes exactly one address (Df-DISC(ii), held by M7's sole-writer fences)",
        ),
        new: endpoint(
            &to,
            "a [K_sup] G denotes exactly one address (Df-DISC(ii), held by M7's sole-writer fences)",
        ),
        home,
        active,
        claim: addr,
    }
}

/// The single address a claim endpoint denotes. `fence` is the expect
/// message, naming which of M7's `[K_sup]` sole-writer fences — F or G — this
/// read-out rests on.
fn endpoint(e: &Endset, fence: &'static str) -> Address {
    let t = e.single_denoted().expect(fence).clone();
    validate(t).expect(
        "a [K_sup] endpoint denotes a RESIDENT link — assert_sup checks residence, editlink's \
         DC guard requires it of a caller's successor, and makelink/emit refuse the class — so \
         it is a minted store key and T4-valid",
    )
}

/// The shared claim enumeration: the `[K_sup]` claims whose `endpoint` is
/// `key`. TOTAL on every address — the obligations below are all this
/// function's own, discharged here and owed by no caller.
///
/// **Asked of the class, never of the store.** M7's `observe` — ASN-0086's
/// Observe, over the same typed slice M7's BH3 reverse read walks — visits
/// the supersession class alone under `view`, tests each claim's F or G for
/// coverage of `key`, and hands back the matches in ascending claim-address
/// order with their slots: no store scan, no class materialized, no claim
/// read twice. BH3's own reverse read, `sources_to`, answers a claim's
/// SOURCES rather than the claim and reads the active slice alone, so it
/// serves neither the read-out nor the `Audit` view.
///
/// **The resident-key gate is what makes the composition compute the right
/// function**, not a guard against misuse. `observe` matches by COVERAGE —
/// a claim's F is `enc([old])`, which covers every address BENEATH `old` —
/// and coverage coincides with denotation only on the `dom(L)`
/// prefix-antichain (EL4 + R0a): for a non-link `key` lying under some
/// endpoint, the read would answer *claims whose endpoint lies ABOVE `key`*
/// rather than *claims whose endpoint IS `key`*. The gate cuts that off, and
/// `[]` is then the TRUE answer rather than a fallback — a `[K_sup]` endpoint
/// is `single_denoted` to a resident link address, so a non-link is no
/// claim's endpoint. Resident, not active: a nullified link is still resident
/// and remains a legal probe key.
///
/// **Two upstream preconditions are discharged here**, and they arrive on
/// DIFFERENT channels. `observe` FAULTS on a `ty` that is neither
/// address-denoting nor `iextent`-built, and `sup` comes from
/// `reserved_type`, which is address-denoting by construction. `observe`
/// reads an EMPTY pattern side as no constraint — SEMANTICALLY, not by
/// panicking — so a probe built empty would answer every claim of the class,
/// indistinguishable from a true answer; [`Endpoint::pattern`] builds the
/// probe out of `key` itself, one tumbler, so it cannot arise.
///
/// The home rule is asked of each claim's own address, and only a claim it
/// admits is read out by [`claim_at`].
///
/// It reads the link store alone, so it takes the store, as [`claim_at`]
/// beside it and `descriptor`'s `candidates` do: the two public reads are its
/// generic shell, and monomorphizing them for a world copies their one call,
/// never this body.
fn claims_on(
    l: &LinkState,
    key: &Address,
    endpoint: Endpoint,
    view: View,
    readable: &dyn Fn(&Address) -> bool,
) -> Vec<SupClaim> {
    if l.readlink(key).is_none() {
        return Vec::new(); // resident-key gate (EL4 + R0a)
    }
    let sup = l.reserved_type(ShippedType::Supersedes);
    l.observe(sup, endpoint.pattern(key), view) // the [K_sup] claims whose `endpoint` is `key`
        .into_iter()
        // The result-set filter (PUB round 2, lane 3.3, §3), asked of the
        // claim's own address before it is read out. The endpoints
        // (`old`/`new`) stay as recorded: only the CLAIM's home is asked.
        .filter(|t| home_readable(readable, &t.addr))
        .map(|t| claim_at(l, t))
        .collect()
}

/// The claims with `old = y` (ASN-0125 EL11b `in(y)`): asks about F (FROM)
/// under the flipped convention, in ASCENDING CLAIM-ADDRESS order — the same
/// permanent key both query families page by, read off M7's own index.
///
/// TOTAL: every `Address` is admitted, and a `y` that is no resident link is
/// no claim's `old`, so `[]` is the answer rather than a refusal — a caller
/// owes no check that `y` is resident before asking. `view = Active` yields
/// the operative graph (`succ_o`), `Audit` the full history (`succ_h`);
/// `Default` behaves as `Active` (M7's reads coerce it).
///
/// The view selects which CLAIMS are disclosed, never which endpoints: each
/// [`SupClaim`]'s `old`/`new` are the addresses the claim names, read out as
/// recorded, so under any view a live claim can name a nullified link. A
/// caller that needs the endpoints' activity asks M7's `is_active` for them.
///
/// The result-set filter (PUB round 2, lane 3.3, §3): claims homed in a
/// document `readable` refuses are dropped. The KEY takes no rule: `y` is a
/// filter value, never consulted (PUB-6.12), so a `y` homed where `readable`
/// refuses is answered with every claim naming it that the rule admits. The
/// pointwise pair, asked about the same address as an argument, reads it as
/// absent (PUB-6.6).
pub fn in_claims_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    y: &Address,
    view: View,
    readable: &dyn Fn(&Address) -> bool,
) -> Vec<SupClaim> {
    claims_on(s.world().links(), y, Endpoint::Old, view, readable)
}

/// The claims with `new = x` (ASN-0125 EL11b `out(x)`): asks about G (TO)
/// under the flipped convention. Same key, view, order, endpoint-disclosure
/// and reader contract (PUB round 2, lane 3.3, §3) as [`in_claims_on`].
pub fn out_claims_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    x: &Address,
    view: View,
    readable: &dyn Fn(&Address) -> bool,
) -> Vec<SupClaim> {
    claims_on(s.world().links(), x, Endpoint::New, view, readable)
}
