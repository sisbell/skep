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
/// this type is the one place the first is mapped to the second, in both
/// directions the read asks: [`Endpoint::pattern`] puts a key in the slot
/// that holds the endpoint, and [`Endpoint::slot`] reads the endpoint out of
/// a stored tuple. So a probe, a claim's read-out and the equality
/// [`claims_naming`] asks between them answer from one mapping, and a change
/// of convention is an edit to this type alone. The convention itself is
/// M7's, stated on its `assert_sup`.
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

    /// The slot of a stored `[K_sup]` tuple that holds this endpoint — its F
    /// for [`Endpoint::Old`], its G for [`Endpoint::New`]: the mapping
    /// [`Endpoint::pattern`] probes by, read the other way, so a claim's
    /// endpoints come out of the slots its probe asked about. The destructure
    /// is exhaustive, so a field M7 adds to [`Tuple`] fails to build here, at
    /// the one place the mapping lives.
    fn slot(self, t: &Tuple) -> &Endset {
        let Tuple { addr: _, from, to } = t;
        match self {
            Endpoint::Old => from,
            Endpoint::New => to,
        }
    }

    /// The address `c` names at this endpoint — its `old` for
    /// [`Endpoint::Old`], its `new` for [`Endpoint::New`]: ASN-0125's own
    /// reading of a claim, with no storage convention in it.
    fn of(self, c: &SupClaim) -> &Address {
        match self {
            Endpoint::Old => &c.old,
            Endpoint::New => &c.new,
        }
    }
}

/// What one `[K_sup]` tuple says, if it is a claim: its two endpoints, each
/// read out of the slot [`Endpoint::slot`] names, its home attribution
/// (EL8b), and its own activity — or `None` for a tuple that is not one.
///
/// RECOGNIZED BEFORE IT IS REPORTED. ASN-0125's archival read ranges over the
/// schema-conforming claims Ŝ^Σ (Df-DISC(ii)), and a tuple is read out only
/// where the part of that schema a [`SupClaim`] is built from holds: its F
/// and its G each denote ONE address, T4-valid, and its own address has a
/// home. The schema's remaining clauses — the two endpoints distinct, both
/// resident — M7 holds at its two `[K_sup]` writers (`assert_sup` checks them,
/// and `editlink`'s DC guard asks them of a caller's successor through a
/// predicate M7 keeps crate-private). Of those the read restates residence
/// alone, and only for the endpoint a probe names: [`claims_naming`] keeps a
/// claim only where that endpoint EQUALS a key it has found resident. The
/// other endpoint's residence, and the two endpoints' distinctness, it never
/// asks.
///
/// In an edit-disciplined store (EL-DM — every `[K_sup]` tuple born through
/// those two writers, which schema-conform their emission) every tuple is
/// recognized, Ŝ^Σ = S^Σ, and nothing is skipped. The recognition is what
/// keeps the read TOTAL over every state M7's fold accepts, which is wider:
/// the fold builds the supersession adjacency off every address a slot
/// denotes, so it admits a slot naming two addresses, or a tumbler that is no
/// address; and a checkpoint M2 restores, or a frame it replays, decodes
/// through serde, which checks a link's arity and nothing of this schema.
/// Such a tuple is no claim of Ŝ^Σ, so skipping it IS the read's answer —
/// where treating it as one would fail every probe that reaches it, for as
/// long as it is stored.
///
/// `t` is a tuple M7's `observe` handed over: its address is a key of the
/// supersession class's typed slice, and its slots are the tuple's stored F
/// and G — read once, by `observe`, and not again here.
fn claim_at(l: &LinkState, t: Tuple) -> Option<SupClaim> {
    let old = endpoint(Endpoint::Old.slot(&t))?;
    let new = endpoint(Endpoint::New.slot(&t))?;
    let home = home_of(&t.addr)?; // EL8b
    let active = l.is_active(&t.addr);
    Some(SupClaim {
        claim: t.addr,
        old,
        new,
        home,
        active,
    })
}

/// The one T4-valid address an endpoint slot denotes (Df-DISC(ii)), or `None`
/// where it denotes several, none, or a tumbler that is no address.
fn endpoint(e: &Endset) -> Option<Address> {
    validate(e.single_denoted()?.clone()).ok()
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
/// **Denotation, not coverage, decides.** `observe` matches by COVERAGE — the
/// probed slot holds `enc([endpoint])`, which covers every address BENEATH
/// that endpoint — so it hands over every claim whose probed endpoint lies AT
/// OR ABOVE `key`, and the read-out keeps only those whose probed endpoint
/// EQUALS `key`. That makes `old = y` (resp. `new = x`) a postcondition this
/// function establishes in every state M7's fold accepts, not a fact it
/// borrows from the store. On an edit-disciplined store the equality removes
/// nothing: every endpoint is a resident link, and coverage coincides with
/// denotation on the `dom(L)` prefix-antichain (EL4 + R0a). On a store a
/// restored checkpoint or a replayed journal frame folded, a recognized
/// endpoint can be any T4-valid address — a document's own among them, which
/// lies above every link the document homes — and the equality is what keeps
/// such a tuple from being reported as naming `key`.
///
/// **The resident-key gate** ahead of the walk holds the schema's residence
/// clause for the probed endpoint, which the equality makes `key` itself: a
/// `[K_sup]` endpoint is a resident link (Df-DISC(ii)), so no claim names a
/// non-link `key`, and `[]` is the TRUE answer rather than a fallback,
/// reached without walking the class. Resident, not active: a nullified link
/// is still resident and remains a legal probe key.
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
/// [`claim_at`] reads each observed tuple out as a claim or skips it, the
/// equality keeps the claims naming `key`, and the home rule is then asked of
/// each kept claim's own address — past the read's other filters, as the
/// crate header's predicate contract states.
///
/// It reads the link store alone, so it takes the store, as [`claim_at`]
/// beside it and `descriptor`'s `candidates` do: the two public reads are its
/// generic shell, and monomorphizing them for a world copies their one call,
/// never this body.
fn claims_naming(
    l: &LinkState,
    key: &Address,
    endpoint: Endpoint,
    view: View,
    readable: &dyn Fn(&Address) -> bool,
) -> Vec<SupClaim> {
    if l.readlink(key).is_none() {
        return Vec::new(); // resident-key gate: the probed endpoint's residence (Df-DISC(ii))
    }
    let sup = l.reserved_type(ShippedType::Supersedes);
    l.observe(sup, endpoint.pattern(key), view) // the [K_sup] tuples whose probed slot covers `key`
        .into_iter()
        .filter_map(|t| claim_at(l, t)) // a tuple that is no claim is skipped (Df-DISC(ii))
        .filter(|c| endpoint.of(c) == key) // DENOTATION, not coverage: the endpoint IS `key`
        // The result-set filter (PUB round 2, lane 3.3, §3), asked of each
        // claim's own address. The endpoints (`old`/`new`) stay as recorded:
        // only the CLAIM's home is asked.
        .filter(|c| home_readable(readable, &c.claim))
        .collect()
}

/// The claims with `old = y` (ASN-0125 EL11b `in(y)`), in ASCENDING
/// CLAIM-ADDRESS order — the same permanent key both query families page by.
///
/// TOTAL: every `Address` is admitted, and a `y` that is no resident link is
/// no claim's `old`, so `[]` is the answer rather than a refusal — a caller
/// owes no check that `y` is resident before asking. `view = Active` yields
/// the operative graph (`succ_o`), `Audit` the full history (`succ_h`);
/// `Default` behaves as `Active` (M7's reads coerce it).
///
/// CLAIMS, and `old = y` EXACTLY: a `[K_sup]` tuple whose F and G do not
/// each denote one T4-valid address is no claim (ASN-0125 Df-DISC(ii)) and is
/// not returned, and a claim is returned only where its `old` IS `y` — never
/// where it merely lies above `y`, as a document's address lies above every
/// link the document homes. On a store M7's two `[K_sup]` writers alone have
/// written, neither clause removes anything; both hold of the answer in every
/// state M7's fold accepts, a restored checkpoint or a replayed journal frame
/// included.
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
    claims_naming(s.world().links(), y, Endpoint::Old, view, readable)
}

/// The claims with `new = x` (ASN-0125 EL11b `out(x)`). Same key, view,
/// order, endpoint-disclosure, exactness and reader contract (PUB round 2,
/// lane 3.3, §3) as [`in_claims_on`]: every claim returned has `new` EQUAL
/// to `x`.
pub fn out_claims_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    x: &Address,
    view: View,
    readable: &dyn Fn(&Address) -> bool,
) -> Vec<SupClaim> {
    claims_naming(s.world().links(), x, Endpoint::New, view, readable)
}
