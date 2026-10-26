//! §7 — archival supersession lineage: the claims naming a link.
//!
//! It is ASN-0125 EL11b, the archival, arrangement-independent half of the
//! decomposed scope: raw claim enumeration home by home — M7's candidate
//! homes for the key's own span on the claim's slot, the home rule asked of
//! each once ahead of its claims, and M7's typed stab of the supersession
//! class within each home it admits — distinct from M7's own
//! `succs`/`chain`/`tip`/`current` walks, which stay M7's. Contextual
//! discovery (EL11a) is out of scope and composed above M8.

use skep_address::{validate, Address};
use skep_kernel::Snapshot;
use skep_links::{enc, registry, LinkState, ShippedType, Tuple, View, FROM, TO};

use crate::home::{home_admitted, home_of};
use crate::types::SupClaim;
use crate::DiscoveryWorld;

/// Which ENDPOINT of a claim a probe key is — `old` for `in(y)`, `new` for
/// `out(x)` — and the slot M7 stores it in, under the FLIPPED storage
/// convention (the M7→M8 seam, diverging from ASN-0125's textual Df-DIR):
/// `FROM = old/superseded`, `TO = new/superseding`. The endpoint is
/// ASN-0125's and fixed; the slot — the SIDE, in ASN-0125's and M7's word
/// (from-side/to-side, F-side/G-side) — is the storage convention's, and
/// this type is the one place the first is mapped to the second, in both
/// directions the read asks: [`Endpoint::slot`] names the slot that holds
/// the endpoint, which the probe is stabbed at, and [`Endpoint::read_out`]
/// reads the endpoint out of that slot of a stored claim, where EL4 defines
/// it. So a probe, a claim's read-out and the equality [`claims_naming`] asks
/// between them answer from one mapping, and a change of convention is an
/// edit to this type alone. The convention itself is M7's, stated on its
/// `assert_sup`.
#[derive(Clone, Copy)]
enum Endpoint {
    /// `in(y)` — the claims whose `old` is the key, asked of F.
    Old,
    /// `out(x)` — the claims whose `new` is the key, asked of G.
    New,
}

impl Endpoint {
    /// The slot M7 stores this endpoint in: the one the probe is stabbed at,
    /// and the one [`Endpoint::read_out`] reads the endpoint back out of.
    fn slot(self) -> usize {
        match self {
            Endpoint::Old => FROM,
            Endpoint::New => TO,
        }
    }

    /// EL4's accessor for this endpoint — `old` for [`Endpoint::Old`], `new`
    /// for [`Endpoint::New`] — read out of a stored `[K_sup]` claim: the one
    /// address the slot holding the endpoint names in Df-DISC(ii)'s canonical
    /// form, UNIT-DEPTH spans alone denoting one tumbler (M7's
    /// `single_denoted`), T4-valid — its F for `old` and its G for `new`. That
    /// is the mapping [`Endpoint::slot`] probes by, read the other way, so a
    /// claim's endpoints come out of the slots its probe asked about. `None`
    /// where that slot carries a span that is not unit-depth, denotes several
    /// addresses or none, or denotes a tumbler that is no address: there the
    /// accessor is undefined (Df-DISC(ii)). The destructure is exhaustive, so a
    /// field M7 adds to [`Tuple`] fails to build here, at the one place the
    /// mapping lives.
    fn read_out(self, t: &Tuple) -> Option<Address> {
        let Tuple { addr: _, from, to } = t;
        let slot = match self {
            Endpoint::Old => from,
            Endpoint::New => to,
        };
        validate(slot.single_denoted()?.clone()).ok()
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

/// Returns `t` read out as a claim, or `None` where an endpoint is undefined.
///
/// The read-out is its `old` and `new` — ASN-0125 EL4's accessors, each read
/// out by [`Endpoint::read_out`] — its home attribution (EL8b), and its own
/// activity.
///
/// **Read out only where `old` and `new` are defined.** ASN-0125's archival
/// read ranges over the schema-conforming claims Ŝ^Σ (Df-DISC(ii)), and a
/// claim is read out only where the part of that schema a [`SupClaim`] is
/// built from holds: its F and its G each in the schema's canonical form,
/// unit-depth spans alone denoting one address, T4-valid — the part of it
/// EL4's `old` and `new` are read out of. The schema's remaining clauses —
/// the two endpoints distinct, both resident — M7 holds at its two `[K_sup]`
/// writers (`assert_sup` checks them, and `editlink`'s DC guard asks them of
/// a caller's successor through a predicate M7 keeps crate-private). This
/// read-out asks neither; [`claims_naming`] states which of them the read
/// restates.
///
/// **The home is M7's, not a condition.** `t.addr` is a key of M7's store,
/// and every key there has a home (EL8b): `LinkState`'s invariant, gated by
/// the fold that admits a deposit and by the one that rebuilds a restored
/// checkpoint, each of which fail-stops on a key with none, and
/// `tests/it/lineage.rs` pins that fence. So `home(claim)` always exists, and
/// the read asserts it rather than testing it: a skip would hide M7's fault
/// as a missing answer.
///
/// In an edit-disciplined store (EL-DM — every `[K_sup]` claim born through
/// those two writers, which schema-conform their emission) every claim
/// conforms, Ŝ^Σ = S^Σ, and nothing is skipped. The check is what keeps the
/// read total over every state M7's fold accepts, which is wider: the fold
/// builds the supersession adjacency off every address a slot denotes, so it
/// admits a slot naming two addresses, a tumbler that is no address, or a
/// span that is not unit-depth beside one that is; and a checkpoint M2
/// restores, or a frame it replays, decodes through serde, which checks a
/// link's arity and nothing of this schema. Such a claim is a non-conformer
/// — in S^Σ, outside Ŝ^Σ (EL4) — with no `old` or no `new` to read out, so
/// skipping it is the read's answer, where reading it out would fail every
/// probe that reaches it, for as long as it is stored.
///
/// `t` is a claim M7's `stab_typed_in` handed over as a [`Tuple`]: its
/// address is a key of the supersession class's typed slice, and its slots
/// are the claim's stored F and G — read once, by the stab, and not again
/// here.
fn sup_claim(l: &LinkState, t: Tuple) -> Option<SupClaim> {
    let old = Endpoint::Old.read_out(&t)?;
    let new = Endpoint::New.read_out(&t)?;
    let home = home_of(&t.addr)
        .expect("M7's fold admits no link key without a home, so every claim has one (EL8b)");
    let active = l.is_active(&t.addr);
    Some(SupClaim {
        claim: t.addr,
        old,
        new,
        home,
        active,
    })
}

/// Returns the `[K_sup]` claims naming `key` at `endpoint` for a reader.
///
/// They are the claims whose `endpoint` is `key`, homed where `readable`
/// admits, in ascending claim-address order: the one enumeration both public
/// reads share, total on every address. The obligations below are all this
/// function's own, discharged here and owed by no caller.
///
/// **Asked home by home, never of the class or the store.** M7's
/// `homes_touching` names the candidate homes of `key`'s unit span,
/// `enc([key])`, on the slot that holds the probed endpoint — every home
/// holding a link whose slot there could overlap the span, each once, in
/// address order — and the reader's predicate is asked of each candidate
/// once, ahead of its claims, through [`home_admitted`] (PUB-6.13,
/// PUB-7.18). A home it refuses is passed: none of its links is stabbed,
/// lifted or read out, so it costs the walk's step and the test, whatever it
/// holds. A home it admits is stabbed by M7's `stab_typed_in` over the spans
/// that named it, cut to the supersession class under `view`, which hands
/// back the home's claims whose probed slot overlaps the span, in ascending
/// claim-address order with their slots. The homes ascend and a home's links
/// are one key range of the store, so the per-home answers concatenated are
/// in ascending claim-address order with no merge. The class is the
/// registry's own shipped class, so the read classifies no type, and the
/// probe is `key`'s own unit span, never empty. BH3's own reverse read,
/// `sources_to`, answers a claim's sources rather than the claim and reads
/// the active slice alone, so it serves neither the read-out nor the `Audit`
/// view; `observe`, the typed read by coverage of a probe, walks the whole
/// class for every probe.
///
/// **Denotation, not coverage, decides.** The stab matches by overlap with
/// `key`'s subtree — it hands over every claim whose probed slot covers
/// `key`, a claim naming `key`'s document among them, and every claim whose
/// probed slot starts strictly beneath `key`, which no deposit path mints —
/// and the read-out keeps only those whose probed endpoint equals `key`.
/// That makes `old = y` (resp. `new = x`) a postcondition this function
/// establishes in every state M7's fold accepts, not a fact it borrows from
/// the store. On an edit-disciplined store the equality removes nothing:
/// every endpoint is a resident link, and coverage coincides with denotation
/// on the `dom(L)` prefix-antichain (EL4 + R0a). On a store a restored
/// checkpoint or a replayed journal frame folded, a defined endpoint can be
/// any T4-valid address — a document's own among them, which lies above
/// every link the document homes — and the equality is what keeps such a
/// claim from being reported as naming `key`.
///
/// **The probed endpoint's residence** is the one clause of the schema
/// beyond the definedness [`sup_claim`] reads out that the read restates: a
/// schema-conforming claim's endpoint is a resident link (Df-DISC(ii)), so no
/// conforming claim names a non-link `key`, and `[]` is the true answer for
/// one. It is asked by one `readlink` of `key` — resident, not active: a
/// nullified link is still resident and remains a legal probe key — once,
/// where an admitted home's stab first finds a claim, never ahead of one and
/// never for a claim of a home the reader refuses. So a key no admitted
/// claim names costs the same whether or not a link resides there: a gate
/// asked ahead of the walk does visibly different work on its two branches,
/// a non-resident key answering at once and a resident one walking the
/// homes, and a guest could read a private link's residence off the
/// difference (skep #647). The clause is kept because the equality does not
/// imply it: a decoded frame can fold a claim naming an unminted address at
/// its probed endpoint, and such a non-conformer is not read out, as
/// `tests/it/lineage.rs` pins. The other endpoint's residence, and the two
/// endpoints' distinctness, the read never asks — M7 holds both at its two
/// `[K_sup]` writers — so a claim it returns can name, at its other endpoint,
/// an address that is no resident link, or `key` itself.
///
/// Within an admitted home, [`sup_claim`] reads each stabbed claim out, or
/// skips it where its `old` or `new` is undefined, and the equality keeps the
/// claims naming `key`.
///
/// It reads the link store alone, so it takes the store, as [`sup_claim`]
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
    let sup = registry().shipped_class(ShippedType::Supersedes);
    let probe = enc([key]);
    let slot = endpoint.slot();
    let mut found = Vec::new();
    let mut resident = false; // whether `key` has been found a resident link
    for touch in l.homes_touching([(slot, &probe)]) {
        if !home_admitted(readable, touch.home()) {
            continue; // a refused home is never stabbed (PUB-6.13, PUB-7.18)
        }
        let claims = l.stab_typed_in(sup, touch.home(), slot, touch.spans(0), view);
        if claims.is_empty() {
            continue;
        }
        if !resident {
            if l.readlink(key).is_none() {
                return Vec::new(); // no claim names a non-link (Df-DISC(ii))
            }
            resident = true;
        }
        // A claim with no `old` or `new` is skipped (Df-DISC(ii)), and the
        // equality is denotation, not coverage: the endpoint is `key` itself.
        found.extend(
            claims
                .into_iter()
                .filter_map(|t| sup_claim(l, t))
                .filter(|c| endpoint.of(c) == key),
        );
    }
    found
}

/// Returns the claims whose `old` is `y` — ASN-0125 EL11b's `in(y)`.
///
/// They come in ascending claim-address order, the same permanent key both
/// query families page by.
///
/// **Total.** Every `Address` is admitted, and a `y` that is no resident
/// link is no schema-conforming claim's `old` (Df-DISC(ii)), so `[]` is the
/// answer rather than a refusal — a caller owes no check that `y` is
/// resident before asking. `view = Active` yields the operative graph
/// (`succ_o`), `Audit` the full history (`succ_h`); `Default` behaves as
/// `Active` (M7's reads coerce it).
///
/// **The domain, exactly.** The claims whose F and G are each in
/// Df-DISC(ii)'s canonical form — unit-depth spans alone, denoting one
/// T4-valid address — so that EL4's `old` and `new` can be read out, and
/// whose `old` is `y` itself, never merely lying above it, as a document's
/// address lies above every link the document homes. A claim outside that
/// form is a non-conformer (ASN-0125 EL4) and is not returned. The rest of
/// the schema is asked of the probed endpoint alone, whose residence the
/// read-out holds: the other endpoint's residence, and the two endpoints'
/// distinctness, are never asked, so a returned claim's `new` can be an
/// address that is no resident link, or `y` itself. On a store M7's two
/// `[K_sup]` writers alone have written, every claim is schema-conforming
/// (Ŝ^Σ = S^Σ), none of this removes or admits anything, and the two views
/// answer exactly `succ_o`'s and `succ_h`'s claims at `y`; the domain above
/// holds in every state M7's fold accepts, a restored checkpoint or a
/// replayed journal frame included.
///
/// **What it costs.** M7's candidate homes for `y`'s own span on the claim's
/// slot, one test of `readable` apiece, and the claims of the homes it
/// admits — never the supersession class, never the store, and nothing of a
/// refused home but its test — so a `y` no admitted claim names costs the
/// same whether or not a link resides at it, and a `y` with claims costs the
/// claims the reader may read.
///
/// The view selects which claims are disclosed, never which endpoints: each
/// [`SupClaim`]'s `old`/`new` are the addresses the claim names, read out as
/// recorded, so under any view a live claim can name a nullified link. A
/// caller that needs the endpoints' activity asks M7's `is_active` for them.
///
/// The result-set filter (PUB round 2, lane 3.3, §3): the claims homed in a
/// document `readable` refuses are never read, the rule asked of each
/// candidate home once, ahead of its claims (PUB-7.18), and a claim the rule
/// admits is returned whole (PUB-6.13) — the rule, like the view, selects
/// claims and never endpoints, so a returned claim's `old` or `new` can name
/// a link homed where `readable` refuses. The key takes no rule: `y` is a
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
/// order, cost, endpoint-disclosure, domain and reader contract (PUB round 2,
/// lane 3.3, §3) as [`in_claims_on`], the two endpoints' roles exchanged:
/// every claim returned has `new` EQUAL to `x`, and its `old` is the
/// endpoint whose residence is never asked.
pub fn out_claims_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    x: &Address,
    view: View,
    readable: &dyn Fn(&Address) -> bool,
) -> Vec<SupClaim> {
    claims_naming(s.world().links(), x, Endpoint::New, view, readable)
}
