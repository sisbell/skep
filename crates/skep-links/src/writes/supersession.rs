//! The `[K_sup]` writers (ASN-0125): [`LinkWriter::assert_sup`], the claim
//! alone, and [`LinkWriter::editlink`], a fresh successor and its claim in one
//! composite — the two paths that establish the Df-DISC(ii) schema every
//! stored claim holds — and [`Edit`], the pair an edit deposits.

use skep_address::Address;
use skep_arrangement::Caller;
use skep_kernel::{Seq, TxnError};
use skep_namespace::{M3Rec, M3State};

use super::{deposit_lock_set, emit_core, home_gate, replaces_class, Gate, LinkWriter};
use crate::budget::MAX_SLOT_SPANS;
use crate::class::coverage_class;
use crate::endset::{enc, Endset, Link};
use crate::error::{AssertSupError, EditLinkError};
use crate::registry::{registry, ShippedType};
use crate::state::{LinkRec, SupSchemaFault};
use crate::LinkWorld;

/// What an edit deposited (ASN-0125 EDITop): the fresh successor, and the
/// `[K_sup]` claim asserting it supersedes the original. Two same-typed
/// addresses, NAMED — the pair is permanently distinguishable only by which
/// home's link chain each landed on, the successor in `d_s` and the claim in
/// `d_a`, so a positional pair would carry that distinction in a convention
/// rather than in the value. M10 puts the two on the wire under these same
/// names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edit {
    /// The fresh successor, deposited in `d_s`.
    pub successor: Address,
    /// The `[K_sup]` claim that `original` is superseded by `successor`,
    /// deposited in `d_a`.
    pub claim: Address,
}

/// The claim schema's verdict in `assert_sup`'s vocabulary: residence, then
/// irreflexivity, the two rejections its contract orders. Its F and G are
/// built through `enc`, one denoted address each, so the denotation clause
/// cannot fail there.
impl From<SupSchemaFault> for AssertSupError {
    fn from(fault: SupSchemaFault) -> Self {
        match fault {
            SupSchemaFault::NotResident => AssertSupError::EndpointNotResident,
            SupSchemaFault::Reflexive => AssertSupError::SelfSupersession,
            SupSchemaFault::NotSingleDenoted => {
                unreachable!("assert_sup builds F and G through enc, one denoted address each")
            }
        }
    }
}

impl<'k, W> LinkWriter<'k, W>
where
    W: LinkWorld,
    W::Record: From<LinkRec> + From<M3Rec>,
{
    /// assert_sup (ASN-0125/0128): emit "old is superseded by new" —
    /// `F = enc({old})`, `G = enc({new})`, type `[K_sup]` (slot convention
    /// per Conflicts §2: F holds the OLD/superseded link; edges run
    /// old → new). Idem⊤ keyed on `([K_sup], {old}, {new})` — home excluded,
    /// so a duplicate `(old, new)` even from a different home dedups to the
    /// first claim (Conflicts §9) — WITHIN THE CALLER'S VISIBILITY CLASS
    /// (PUB-6.25): a claim homed in a document the caller cannot read is
    /// invisible to the dedup, and the caller's own claim is minted beside
    /// it. Requires `home` registered, then the Df-DISC(ii) claim schema as
    /// `LinkState` answers it — both endpoints resident, then `old ≠ new`;
    /// checked in that order.
    ///
    /// RETURNS `(claim, seq)`: the address of the `[K_sup]` claim — never an
    /// endpoint — or, on a dedup hit, the incumbent claim's, with the base
    /// `Seq`.
    ///
    /// OWNERSHIP is required on `home` and on NOTHING ELSE: the caller need
    /// not own `old` or `new`, so a claim may be asserted over links owned by
    /// others, and the walk family and M8's lineage reads then report it as
    /// fact. Retracting it needs ω on the CLAIM, whose home is the asserter's
    /// — so the endpoints' owner cannot retract a foreign claim about their
    /// own links. The wider question this belongs to (moderation, viewer-side
    /// filtering) is the deferred scope decision `nullify` names.
    pub fn assert_sup(
        &self,
        caller: Caller,
        home: &Address,
        old: &Address,
        new: &Address,
    ) -> Result<(Address, Seq), TxnError<AssertSupError>> {
        let sup = registry().reserved_type(ShippedType::Supersedes).clone();
        let value = Link::triple(enc([old]), enc([new]), sup);
        let keys = deposit_lock_set(&value, home);
        // The attested arm (signed ops), as `emit`'s.
        self.kernel.transact_attested(&keys, self.attest, |stg| {
            {
                let base = stg.base();
                // P0 then ω on home, before the schema's verdicts.
                home_gate(base.m3(), caller, &[home])?;
                // Df-DISC(ii), asked of the store: residence, then
                // irreflexivity.
                base.links().check_sup_schema(&value)?;
            }
            Ok(emit_core(stg, self.visibility, caller, home, value, Gate::Managed)?.address())
        })
    }

    /// editlink (ASN-0125 EDITop): ONE composite over the two home alloc
    /// keys — sorted and deduped before the transact, so the pair reaches M2
    /// in a canonical order rather than the caller's, and `d_s == d_a`
    /// collapses `[k, k]` to `[k]` (M2's `transact(keys)` promises nothing
    /// about order or duplicates, and this is the only op handing it two keys
    /// of one space) — inlining two `emit_core` calls (the public
    /// `assert_sup` CANNOT be called: M2 is non-reentrant). Allocates the
    /// fresh successor (value supplied — M10 builds it via M5 `iter_resolve` +
    /// `Run::iextent` + `Endset::from_spans`/`enc` + `Link::triple`, off any
    /// prior snapshot — ML8/EL0), then asserts it supersedes `original`.
    /// Successor born UNSEATED; both writes commit atomically (EL7);
    /// `original` untouched (L12).
    ///
    /// RETURNS `(edit, seq)`, where [`Edit`] carries the successor's address
    /// and the claim's each under its own name — the successor deposited in
    /// `d_s`, the claim in `d_a` — so the two cannot trade places at a call.
    ///
    /// OWNERSHIP is required on `d_s` and `d_a` and on NOTHING ELSE: the
    /// caller need not own `original`, so an edit may claim to supersede a
    /// link owned by another account, exactly as `assert_sup` may. What the
    /// operation deposits lands in the caller's own homes; what it asserts
    /// about `original` is retractable only by ω on the claim, which is
    /// `d_a`'s.
    ///
    /// Rejects (against the txn base): unregistered `d_s`/`d_a`;
    /// non-resident `original`; a successor slot past [`MAX_SLOT_SPANS`]
    /// spans (`SlotTooLarge` — the slots are the caller's, resolve-built, so
    /// their span count is a source document's fragmentation rather than the
    /// request's size, and every per-span step after this one runs inside the
    /// transact); a successor of arity ≠ 3 (Conflicts §11),
    /// empty type slot, or a non-level-uniform span in any slot
    /// (`IllFormedSuccessor` — the last keeps `coverage_class` total for
    /// both the DC guard and the fold's dedup key); DC — a
    /// retraction-typed successor, a `replaces`-typed one (that class's one
    /// writer is [`LinkWriter::makelink_replacing`], so an edit mints no
    /// authority successor — PUB-5.15, RES-309), or a `[K_sup]`-typed one
    /// without the Df-DISC(ii) schema (unit-depth single-addr F/G, resident
    /// endpoints, irreflexive) (`DcViolation`). The claim's dedup check is a guaranteed
    /// miss (its key carries the fresh successor), so no claim dedup lock is
    /// taken (§3).
    pub fn editlink(
        &self,
        caller: Caller,
        original: &Address,
        successor_value: Link,
        d_s: &Address,
        d_a: &Address,
    ) -> Result<(Edit, Seq), TxnError<EditLinkError>> {
        // The one op that hands M2 two keys of ONE space, so the one whose
        // relative order would otherwise be the caller's: two concurrent
        // edits over the same pair of homes, named in opposite orders, would
        // present them in opposite orders. Emitted in M2's own bytewise
        // order, so the pair is the same set in the same sequence however it
        // was written, whatever the applier does with it. `dedup` behind the
        // sort subsumes `d_s == d_a` (M2 promises nothing about duplicates).
        //
        // No dedup section, so `deposit_lock_set` is not the shape here: the
        // successor takes the Open gate, which runs no dedup check, and the
        // claim's check is a guaranteed miss (its I0 carries a successor
        // minted inside this transaction).
        let mut keys = vec![M3State::link_lock_key(d_s), M3State::link_lock_key(d_a)];
        keys.sort();
        keys.dedup();
        let sup = registry().reserved_type(ShippedType::Supersedes).clone();
        let sup_class = registry().shipped_class(ShippedType::Supersedes);
        let r_class = registry().shipped_class(ShippedType::Retraction);
        // The attested arm (signed ops): one attestation over the one
        // transaction both deposits ride, as `makelink_replacing`'s pair.
        self.kernel.transact_attested(&keys, self.attest, |stg| {
            {
                let base = stg.base();
                // P0 on both homes, then ω on both: the successor deposits
                // into d_s, the claim into d_a — the rejection carries the
                // home that failed.
                home_gate(base.m3(), caller, &[d_s, d_a])?;
                if !base.links().resident(original.tumbler()) {
                    return Err(EditLinkError::OriginalNotResident);
                }
                // The successor's span budget, ahead of every per-span
                // verdict: the level-uniformity walk below, the DC guard's
                // `coverage_class`, and the fold's dedup key over ALL THREE
                // slots are each linear in this count, and all three run
                // inside the transact under M2's applier lock. The slots are
                // built by the CALLER — M10 resolves V-specs into them — so
                // the count is the SOURCE document's fragmentation rather
                // than the request's size, which is the same expansion
                // MAKELINK's `Resolve` slots are bounded against.
                if successor_value.slots().any(|e| e.len() > MAX_SLOT_SPANS) {
                    return Err(EditLinkError::SlotTooLarge);
                }
                // Level-uniformity is required of EVERY slot, not just the
                // one the DC guard classifies: a deposit of a registered
                // idem⊤ class folds a dedup key over all three slots
                // ([`crate::LinkState::apply_link`]), and `coverage_class`
                // aborts on a non-level-uniform span. Checking only the type
                // slot would leave a caller-supplied F or G reaching that
                // abort from inside the transact.
                //
                // `e₃ ≠ ∅` is NOT restated here: it is the deposit gate's
                // check, and `⟨⟩` classifies as the empty denoted antichain —
                // neither shipped class — so it passes the DC guard untouched
                // and comes back from the gate as `IllFormedSuccessor`.
                let well_formed = successor_value.arity() == 3
                    && successor_value.slots().all(Endset::is_level_uniform);
                if !well_formed {
                    return Err(EditLinkError::IllFormedSuccessor);
                }
                // DC guard — total: every slot was just checked
                // level-uniform.
                let successor_class = coverage_class(successor_value.type_slot());
                if successor_class == *r_class || successor_class == *replaces_class() {
                    return Err(EditLinkError::DcViolation);
                }
                if successor_class == *sup_class
                    && base.links().check_sup_schema(&successor_value).is_err()
                {
                    return Err(EditLinkError::DcViolation);
                }
            }
            // Both `minted`: this op reports each address as one it deposited,
            // and the claim's own I0 carries `successor`, minted a line above
            // in this same transaction, so no incumbent of that I0 class
            // exists at any visibility class.
            let successor =
                emit_core(stg, self.visibility, caller, d_s, successor_value, Gate::Open)?
                    .minted();
            let claim_value = Link::triple(enc([original]), enc([&successor]), sup);
            let claim =
                emit_core(stg, self.visibility, caller, d_a, claim_value, Gate::Managed)?.minted();
            Ok(Edit { successor, claim })
        })
    }
}
