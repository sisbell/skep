//! The identity slice's SEAT in the World (AUTH-2.79–2.84): the fold hook
//! `World::apply` runs after every link deposit, the slice-less resolution
//! the load runs, the trailing field's reading, and the fold's seam —
//! [`Values`], [`FoldCtx`], [`HasIdentity`] — implemented over the assembled
//! world, so `skep-identity`'s pure fold reads every fact it needs off ONE
//! `World` and the engine implements the record read ZERO times.
//!
//! The fold's decisions are the fold's (`skep-identity`'s `IdentityState`,
//! AUTH-2.56–2.78); what this module decides is WHEN the fold runs and over
//! WHICH facts: at the deposit's own commit, over the world the deposit has
//! just entered (AUTH-2.66's "evaluated at the deposit's commit"), live and on
//! every replay alike — which is what makes the table a checkpoint carries
//! the table the live fold answered, and why no rebuild of it from the
//! deposit SET exists anywhere: the verdicts depend on the commit order, and
//! the journal is the one record of that order.

use serde::{Deserialize, Deserializer};
use skep_address::{document_of, validate, Address, Span, Tumbler};
use skep_identity::{FoldCtx, HasIdentity, IdentityState, LinkDeposit, Owner, Values};
use skep_kernel::RebuildError;
use skep_links::{enc, LinkRec, LinkState, View};
use skep_namespace::BOOTSTRAP_PRINCIPAL;

use super::World;
use crate::types::{t_claim, t_enroll, t_retire, IDENTITY_TYPES};

/// The slice's name in M2's slice-agnostic refusal (AUTH-2.85), and in the
/// line an operator reads when the chain is exhausted (AUTH-2.88).
const SLICE: &str = "identity";

/// The TYPE slot's number in M7's 1-based slot vocabulary (`Link::slot`;
/// FROM = 1, TO = 2, TYPE = 3) — what [`LinkState::match_links`]'s
/// constraints are keyed by.
const TYPE_SLOT: usize = 3;

/// THE FOLD HOOK (AUTH-2.80): step the identity slice of `w` — the world the
/// link deposit `rec` has just entered — by that deposit, or return `w`
/// un-folded. Two fast exits, both inside `kind_of` (AUTH-2.22): a type slot
/// that is not exactly one span, decided in at most two steps of the slot's
/// walk, and a span `Equal` to none of the three precomputed credential
/// spans, at most three comparisons — no allocation on either, which is
/// nearly every link deposit. Slots are materialized only for a recognized
/// kind.
///
/// THE DEPOSIT'S ADDRESS IS READ ONCE (AUTH-2.82), lifted through `validate`
/// then `document_of`, both unreachable to fail for a minted link address —
/// T4-valid and element-level by construction — so a failure there is a
/// defect and is said so: a `debug_assert`, then the un-folded world, NEVER a
/// panic (M2 requires `apply` total) and never a silent drop.
///
/// THE POST-LOAD INVARIANT (AUTH-2.81) — every world reaching this hook
/// carries `Some` — is debug-asserted HERE, where a violation would cost its
/// first deposit; the `None` arm returns the un-folded world, total either
/// way. `HasIdentity for World` `expect`s the same invariant at the read, so
/// the two handlings of one unreachable state agree about what it means: a
/// defect, surfaced where it is caused in a debug build and where it is read
/// in a release one.
///
/// The verdict is dropped: the daemon's precheck classified this deposit
/// before it committed (the fold's `classify`, AUTH-2.57), and the fold reads
/// every deposit that reached the journal — honored or inert — as the AUDIT
/// view it is (AUTH-2.78): an inert deposit leaves the slice as it was.
pub(super) fn fold(w: World, rec: &LinkRec) -> World {
    // M7's record enum is `#[non_exhaustive]` from here: a variant it does
    // not have today deposits nothing the fold reads.
    let (addr, value) = match rec {
        LinkRec::Deposit { addr, value, .. } => (addr, value),
        _ => return w,
    };
    if IDENTITY_TYPES.kind_of(value.type_slot().spans()).is_none() {
        return w;
    }
    debug_assert!(
        w.identity.is_some(),
        "post-load invariant (AUTH-2.81): a world reaching the fold hook carries its slice"
    );
    let Some(identity) = w.identity.as_ref() else {
        return w;
    };
    let home = match validate(addr.clone()).ok().and_then(|a| document_of(&a)) {
        Some(home) => home,
        None => {
            debug_assert!(false, "a minted link address validates and has a document (AUTH-2.82)");
            return w;
        }
    };
    let from: Vec<Span> = value.from_slot().spans().cloned().collect();
    let to: Vec<Span> = value.to_slot().spans().cloned().collect();
    let ty: Vec<Span> = value.type_slot().spans().cloned().collect();
    let dep = LinkDeposit { home: &home, from: &from, to: &to, ty: &ty };
    let (next, _verdict) = identity.step(&IDENTITY_TYPES, &w, &dep);
    World { identity: Some(next), ..w }
}

/// SLICE-LESS RESOLUTION (AUTH-2.83), at load: `Some` is carried; `None` —
/// a body written without the slice — is resolved from the REBUILT link
/// slice, or refused. The candidates are the deposits
/// `match_links(&[(TYPE, enc([T]))], View::Audit)` answers for each
/// credential type `T`, a deposit-level, registration-independent read off
/// M7's SERIALIZED authoritative map (so the order among the rebuilds does
/// not decide it), filtered EXACTLY by `kind_of` on each candidate's stored
/// type slot (overlap ⊇ equality, so the filter loses nothing). No candidate
/// recognized ⇒ the fold over that stream is provably empty ⇒ the genesis
/// table, flagged RESOLVED for the open's warning (AUTH-2.86). Any
/// recognized ⇒ `Err`: the table those deposits fold to depends on the order
/// they committed in, which no checkpoint holds, so the base is NOT A START
/// POINT (AUTH-2.84) and M2's fallback chain steps back to one that is — a
/// REPLAY in position order, never a re-fold out of order.
pub(super) fn resolve(
    identity: Option<IdentityState>,
    links: &LinkState,
) -> Result<(IdentityState, bool), RebuildError> {
    if let Some(carried) = identity {
        return Ok((carried, false));
    }
    for ty in [t_enroll(), t_retire(), t_claim()] {
        let query = enc([ty]);
        let recognized = links.match_links(&[(TYPE_SLOT, &query)], View::Audit).iter().any(|a| {
            links
                .readlink(a)
                .is_some_and(|link| IDENTITY_TYPES.kind_of(link.type_slot().spans()).is_some())
        });
        if recognized {
            return Err(RebuildError::Unresolved { slice: SLICE });
        }
    }
    Ok((IdentityState::genesis(), true))
}

/// THE TRAILING FIELD'S READING: `identity: None` ⇔ the body was written
/// without the slice (AUTH-2.79). Serde's `default` fills a field a
/// SELF-DESCRIBING body omits; M2's codec is not one — bincode lays fields
/// down positionally with no names — so a body written before the slice does
/// not omit the field, it ENDS where the field would begin, and the derived
/// `Deserialize` would refuse the whole body at that end. This reads a slice
/// the deserializer cannot produce as the absent slice instead — `None`, the
/// shape AUTH-2.83 then resolves or refuses at load — and so realizes the
/// spec's `#[serde(default)]` under this codec.
///
/// EVERY refusal of the slice reads as absence, not the end-of-body alone,
/// and that is sound rather than lenient: the body's bytes are what the
/// header's CRC and hash verified, so no refusal here is rot, and whatever
/// the slice's bytes were, `None` is never SERVED — it is resolved to the
/// empty table only over a link slice holding no credential deposit, where
/// the empty table is the true one, and refused as a start point everywhere
/// else. A slice whose own LAYOUT moves meets `FormatStamp`'s rule before
/// this arm: a slice's layout change is a World layout change and bumps the
/// count, so such a body is refused at byte 0 and never reaches it.
pub(super) fn slice_or_absent<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<IdentityState>, D::Error> {
    Ok(Option::<IdentityState>::deserialize(deserializer).unwrap_or(None))
}

/// AUTH-2.60 — the slice, read off the world (the host that SEATS it, in
/// AUTH-2.79's cast). The post-load invariant (AUTH-2.81) makes the `expect`
/// unreachable: every loaded World carries `Some` — resolved or refused at
/// load — and every world this crate constructs does ([`World::genesis`]);
/// so this is where a construction path that broke it is caught at the first
/// identity read, beside the fold hook's `debug_assert`, which catches it at
/// the first deposit.
impl HasIdentity for World {
    fn identity(&self) -> &IdentityState {
        self.identity
            .as_ref()
            .expect("post-load invariant (AUTH-2.81): every loaded World carries its identity slice")
    }
}

/// AUTH-2.29 — the WHOLE world side of the payload read, and the only line
/// of it that is engine-specific: one M4 lookup at one I-address, keyed by
/// the walk's own `Tumbler` as M4 keys it, AS OF THIS WORLD — which, at the
/// fold hook, is the deposit's own commit (I-bytes are immutable, so the
/// bytes at a covered address never move; COVERAGE advances with the home's
/// mint frontier, which is why the read is this world's and not the head's).
/// The endset-order concatenation, the per-span checks, the reach walk and
/// the byte cap are `skep-identity`'s `record_bytes`, implemented once there.
/// AUTH-1.22's "at least one byte" is M5's write gate's, which refuses empty
/// content values upstream.
impl Values for World {
    fn value_at(&self, at: &Tumbler) -> Option<&[u8]> {
        self.content.value_at(at).map(|v| v.as_bytes())
    }
}

/// AUTH-2.31 — the fold's four facts, every one answered off THIS world
/// (AUTH-2.66's commit-time reading): ω from M3, unprojected, with the
/// bootstrap comparison made here where the principal ids live (AUTH-2.32,
/// AUTH-2.108); account-hood from M3's registry (AUTH-2.33); and publication
/// from the engine's exception set — `doc ∉ exception_set` and nothing else
/// (AUTH-2.34; PUB-7.5, owner ruling D1: ONE publication definition), the
/// document's BIRTH state and so constant over every record's life. The
/// daemon's publish-class gate reads the same set after PUB-2.15's
/// version-member projection; the fold reads the member's own bit, and the
/// one cell where the two differ (a private member under a published
/// document, PUB-2.7) both refuse, by different tokens.
impl FoldCtx for World {
    fn owner_of(&self, a: &Address) -> Option<Owner> {
        let prefix = self.namespace.effective_owner_prefix(a)?.clone();
        Some(Owner { prefix, is_bootstrap: self.namespace.is_effective_owner(BOOTSTRAP_PRINCIPAL, a) })
    }

    fn is_account(&self, a: &Address) -> bool {
        self.namespace.is_registered_account(a)
    }

    fn is_published(&self, doc: &Address) -> bool {
        self.published(doc)
    }
}

#[cfg(test)]
mod tests;
