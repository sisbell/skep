//! The identity slice's seat in the World (AUTH-2.79–2.84).
//!
//! It holds the fold hook `World::apply` runs after every link deposit, the
//! slice-less resolution the load runs, the trailing field's reading, and the
//! fold's seam — [`Values`], [`FoldCtx`], [`HasIdentity`] — implemented over
//! the assembled world, so `skep-identity`'s pure fold reads every fact it
//! needs off one `World` and the engine implements the record read zero
//! times.
//!
//! The fold's decisions are the fold's (`skep-identity`'s `IdentityState`,
//! AUTH-2.56–2.78); what this module decides is *when* the fold runs and over
//! *which* facts: at the deposit's own commit, over the world the deposit has
//! just entered (AUTH-2.66's "evaluated at the deposit's commit"), live and on
//! every replay alike — which is what makes the table a checkpoint carries
//! the table the live fold answered, and why no rebuild of it from the
//! deposit set exists anywhere: the verdicts depend on the commit order, and
//! the journal is the one record of that order.

use serde::{Deserialize, Deserializer};
use skep_address::{document_of, validate, Address, Span, Tumbler};
use skep_identity::{FoldCtx, HasIdentity, IdentityState, LinkDeposit, Owner, Values};
use skep_kernel::RebuildError;
use skep_links::{enc, LinkRec, LinkState, View};
use skep_namespace::BOOTSTRAP_PRINCIPAL;

use super::World;
use crate::types::{t_claim, t_enroll, t_retire, IDENTITY_TYPES};

/// The slice's name in M2's slice-agnostic refusal (AUTH-2.85).
///
/// It is also the name in the line an operator reads when the chain is
/// exhausted (AUTH-2.88).
const SLICE: &str = "identity";

/// The type slot's number in M7's 1-based slot vocabulary.
///
/// The vocabulary is `Link::slot`'s — `FROM` = 1, `TO` = 2, `TYPE` = 3 — and
/// the number is what [`LinkState::match_links`]'s constraints are keyed by.
const TYPE_SLOT: usize = 3;

/// Steps the identity slice of `w` by the link deposit `rec` (AUTH-2.80).
///
/// `w` is the world the deposit has just entered; where the deposit is no
/// credential, `w` comes back un-folded. Two fast exits, both inside
/// `kind_of` (AUTH-2.22): a type slot that is not exactly one span, decided
/// in at most two steps of the slot's walk with no allocation, and a span
/// `Equal` to none of the three precomputed credential spans, at most three
/// comparisons, each deriving both spans' endpoints (`classify_spans`) —
/// which is nearly every link deposit. Slots are materialized only for a
/// recognized kind.
///
/// **The deposit's address is read once.** It is lifted through `validate`
/// then `document_of` (AUTH-2.82), both unreachable to fail for a minted link
/// address — T4-valid and element-level by construction.
///
/// The verdict is dropped: the daemon's precheck classified this deposit
/// before it committed (the fold's `classify`, AUTH-2.57), and the fold reads
/// every deposit that reached the journal — honored or inert — as the audit
/// view it is (AUTH-2.78): an inert deposit leaves the slice as it was.
///
/// # Panics
///
/// Panics in a debug build at either of two defects of its own, each
/// unreachable by construction; a release build returns the un-folded world
/// at each, never a panic (M2 requires `apply` total), and says nothing.
///
/// * A deposit's address that fails that lift is a defect, and a debug build
///   says so at its `debug_assert!` rather than dropping the deposit
///   silently.
/// * The post-load invariant (AUTH-2.81) — every world reaching this hook
///   carries `Some` — is debug-asserted here, where a violation would cost
///   its first deposit; the `None` arm returns the un-folded world, total
///   either way. `HasIdentity for World` `expect`s the same invariant at the
///   read, so the two handlings of one unreachable state agree about what it
///   means: a defect, surfaced where it is caused in a debug build and where
///   it is read in a release one.
///
/// A debug build also panics inside `IdentityState::step`, at its assertion
/// that no value an enrollment's or a retirement's `from` covers is empty.
/// That one is reachable: this world's [`Values`] answers whatever value it
/// holds, and only the wire codec keeps a zero-byte value out (its impl's
/// card below says so).
pub(super) fn fold(w: World, rec: &LinkRec) -> World {
    // M7's record enum is `#[non_exhaustive]` from here: a variant it has not
    // written yet deposits nothing the fold reads.
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

/// Resolves a slice-less body at load (AUTH-2.83), or carries the slice.
///
/// `Some` is carried; `None` — a body written without the slice — is
/// resolved from the rebuilt link slice, or refused. The candidates are the
/// deposits `match_links(&[(TYPE, enc([T]))], View::Audit)` answers for each
/// credential type `T`, a deposit-level, registration-independent read that
/// M7 answers from its coverage index — a hint the link slice's own rebuild
/// re-derives from its serialized map, which is why `World::rebuild_derived`
/// rebuilds that slice ahead of this one — filtered exactly by `kind_of` on
/// each candidate's stored type slot (overlap ⊇ equality, so the filter loses
/// nothing). No candidate recognized ⇒ the fold over that stream is provably
/// empty ⇒ the genesis table, flagged resolved for the open's warning
/// (AUTH-2.86).
///
/// # Errors
///
/// Any candidate recognized ⇒ `Err(RebuildError::Unresolved)` naming this
/// slice: the table those deposits fold to depends on the order they
/// committed in, which no checkpoint holds, so the base is not a start point
/// (AUTH-2.84) and M2's fallback chain steps back to one that is — a replay
/// in position order, never a re-fold out of order.
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

/// Reads the trailing field, so a body without the slice decodes as `None`.
///
/// `identity: None` is what a body written without the slice reads as
/// (AUTH-2.79); a slice that does not decode, or that encodes `None`, reads
/// as it too. Serde's `default` fills a field a self-describing body omits;
/// M2's codec is not one — bincode lays fields down positionally with no
/// names — so a body written without the slice does not omit the field, it
/// *ends* where the field would begin, and the derived `Deserialize` would
/// refuse the whole body at that end. This reads a slice the deserializer
/// cannot produce as the absent slice instead — `None`, the shape AUTH-2.83
/// then resolves or refuses at load — and so realizes the spec's
/// `#[serde(default)]` under this codec.
///
/// A slice whose own layout moves meets `FormatStamp`'s rule before this arm:
/// a slice's layout change is a World layout change and bumps the count, so
/// such a body is refused at byte 0 and never reaches it.
///
/// # Errors
///
/// None: every refusal of the slice reads as absence, not the end-of-body
/// alone, and that is sound rather than lenient. The body's bytes are what
/// the header's CRC and hash verified, so no refusal here is rot, and
/// whatever the slice's bytes were, `None` is never served — it is resolved
/// to the empty table only over a link slice holding no credential deposit,
/// where the empty table is the true one, and refused as a start point
/// everywhere else.
pub(super) fn slice_or_absent<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<IdentityState>, D::Error> {
    Ok(Option::<IdentityState>::deserialize(deserializer).unwrap_or(None))
}

/// The slice, read off the world (AUTH-2.60).
///
/// The world is the host that seats it, in AUTH-2.79's cast. The post-load
/// invariant (AUTH-2.81) makes the `expect` unreachable: every loaded World
/// carries `Some` — resolved or refused at load — and so does every world
/// this crate builds but a decoded one before its rebuild ([`World::genesis`]
/// among them).
///
/// # Panics
///
/// Panics where the world carries no slice: this is where a construction
/// path that broke the invariant is caught, at the first identity read,
/// beside the fold hook's `debug_assert`, which catches it at the first
/// credential deposit.
impl HasIdentity for World {
    fn identity(&self) -> &IdentityState {
        self.identity
            .as_ref()
            .expect("post-load invariant (AUTH-2.81): every loaded World carries its identity slice")
    }
}

/// The whole world side of the payload read (AUTH-2.29).
///
/// It is the only line of that read that is engine-specific: one M4 lookup at
/// one I-address, keyed by the walk's own `Tumbler` as M4 keys it, as of this
/// world — which, at the fold hook, is the deposit's own commit (I-bytes are
/// immutable, so the bytes at a covered address never move; coverage advances
/// with the home's mint frontier, which is why the read is this world's and
/// not the head's). The endset-order concatenation, the per-span checks, the
/// reach walk and the byte cap are `skep-identity`'s `record_bytes`,
/// implemented once there. AUTH-1.22's "at least one byte" is the daemon's
/// wire codec's, which cannot express a zero-byte atom, upstream of M5's
/// write gate, which refuses an empty value list and not a zero-byte value.
impl Values for World {
    fn value_at(&self, at: &Tumbler) -> Option<&[u8]> {
        // A borrowed piece either way: a value's bytes, or the one byte at a
        // position inside a stretch — one O(log n) read per position, whichever
        // the piece.
        self.content.value_at(at).map(|piece| piece.as_bytes())
    }
}

/// The fold's four facts, every one answered off this world (AUTH-2.31).
///
/// Each is AUTH-2.66's commit-time reading: ω from M3, unprojected, with
/// the bootstrap comparison made here where the principal ids live
/// (AUTH-2.32, AUTH-2.108); account-hood from M3's registry (AUTH-2.33); and
/// publication from the engine's exception set — `doc ∉ exception_set` and
/// nothing else (AUTH-2.34; PUB-7.5, PUB-kickoff D1: one publication
/// definition), the document's birth state and so constant over every
/// record's life. The daemon's publish-class gate reads the same set after
/// PUB-2.15's version-member projection; the fold reads the member's own bit,
/// and the one cell where the two differ (a private member under a published
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
