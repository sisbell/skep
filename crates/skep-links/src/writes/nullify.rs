//! Nullify (ASN-0128): [`LinkWriter::nullify`], the sole retraction path,
//! and the BH4 batch built on it (§7), [`LinkWriter::retract_stale`] — a
//! sequence of nullifies, each failure lifted into the batch's error space.

use skep_address::Address;
use skep_arrangement::Caller;
use skep_kernel::{Seq, TxnError};
use skep_namespace::M3Rec;

use super::{deposit_lock_set, emit_core, home_gate, Gate, LinkWriter};
use crate::endset::{enc, Endset, Link};
use crate::error::{NotBh4, NullifyError, RetractStaleError};
use crate::registry::{registry, ShippedType};
use crate::state::LinkRec;
use crate::LinkWorld;

/// §7 error mapping: lift a constituent `nullify` transact error into the
/// batch op's space — a typed rejection rides `RetractStaleError::Nullify`;
/// kernel-level failures pass through unchanged.
fn lift_nullify(e: TxnError<NullifyError>) -> TxnError<RetractStaleError> {
    match e {
        TxnError::Rejected(n) => TxnError::Rejected(n.into()),
        TxnError::Durability(io) => TxnError::Durability(io),
        TxnError::Unencodable(io) => TxnError::Unencodable(io),
        TxnError::OverBudget { bytes } => TxnError::OverBudget { bytes },
        TxnError::Poisoned => TxnError::Poisoned,
    }
}

impl<'k, W> LinkWriter<'k, W>
where
    W: LinkWorld,
    W::Record: From<LinkRec> + From<M3Rec>,
{
    /// Nullify_Binary (ASN-0128): the SOLE retraction path — an `[R]` tuple
    /// with canonical from-fill `enc({home})` and unit-depth to-span
    /// `enc({target})`, idem⊤ WITHIN THE CALLER'S VISIBILITY CLASS
    /// (PUB-6.25): re-retracting the same target from the same home dedups
    /// at every visibility class that reads `home`, which a read predicate's
    /// does ([`Visibility`](crate::Visibility)); a visibility class blind to `home` mints a
    /// fresh retraction beside the hidden one, and the postcondition below
    /// holds either way.
    /// P-tgt is a REJECTING precondition against the txn base:
    /// `target` is a resident link OR the address this call's own retraction
    /// tuple would occupy (`a_emit`) — the address the slice reports
    /// `mint_link(home)` would mint next, an O(1) read equal to that mint by
    /// construction (FrontierUnification, Conflicts §7) — so sterilization is
    /// unreachable through this surface (DR). Lock set `[dedup_key,
    /// link_lock_key(home)]`.
    ///
    /// Ownership (as amended 2026-08-16): the caller must own `home` AND the
    /// TARGET link — ω applied to the link's own address, which resolves to
    /// the account of the link's home document. Self-retraction only; the
    /// broader moderation question (territorial retraction, viewer-side
    /// filtering) is an explicitly deferred scope decision (wire.md). Both
    /// checks precede P-tgt, so the auth verdict never depends on residence
    /// timing, and `home` is checked BEFORE the target — the address
    /// `NotOwner` carries is `home`'s when a caller owns neither. The
    /// self-target case passes by arithmetic: `a_emit`'s account IS home's
    /// account.
    ///
    /// POSTCONDITION, on a fresh deposit and on a dedup hit alike:
    /// `is_nullified(target)` holds, and `target` is gone from every
    /// `View::Active` slice and every `stale` set — and, where `target` is
    /// itself a `[K_sup]` claim, from every operative `succ_o` edge — while
    /// `readlink` and the `Audit` view keep it (R3).
    ///
    /// A nullified ENDPOINT leaves its edges operative: Df-SUCC reads the
    /// CLAIM's activity and never the endpoint's, so the walk family still
    /// names a nullified successor and `current` still discloses it as a
    /// sink, carrying its own activity (EL14e). Suppressing an endpoint from
    /// the supersession graph means retracting the claims that name it.
    ///
    /// IRREVOCABLE. The tombstone set is monotone (R3/R6a) and the hint fold
    /// re-derives it from the `[R]` link at every replay, whether or not that
    /// link is itself nullified — so retracting a retraction restores
    /// nothing. This is where the module's two suppression mechanisms part
    /// company, and a caller chooses between them here: the BH1 `Retired`
    /// filter reads the ACTIVE retired slice, so retiring is undoable by
    /// nullifying the retirement; nullifying is not undoable by anything.
    ///
    /// RETURNS `(retraction, seq)`: the address of the `[R]` tuple itself —
    /// never `target` — or, on a dedup hit, the incumbent retraction's, with
    /// the base `Seq`. (The born-nullified case is where the two coincide:
    /// there `target` IS the address this tuple occupies.)
    pub fn nullify(
        &self,
        caller: Caller,
        home: &Address,
        target: &Address,
    ) -> Result<(Address, Seq), TxnError<NullifyError>> {
        let retraction = registry().reserved_type(ShippedType::Retraction).clone();
        let value = Link::triple(enc([home]), enc([target]), retraction);
        let keys = deposit_lock_set(&value, home);
        // The attested arm (signed ops), as `emit`'s.
        self.kernel.transact_attested(&keys, self.attest, |stg| {
            {
                let base = stg.base();
                home_gate(base.m3(), caller, &[home])?; // P0 then ω on home
                if !caller.is_owner(base.m3(), target) {
                    return Err(NullifyError::NotOwner(target.clone())); // v1 target policy
                }
                if !base.links().resident(target.tumbler())
                    && *target != base.links().next_link_address(home)
                {
                    return Err(NullifyError::BadTarget); // P-tgt
                }
            }
            Ok(emit_core(stg, self.visibility, caller, home, value, Gate::Retraction)?.address())
        })
    }

    /// BH4 batch tooling (§7): nullify every stale tuple of `ty` (age >
    /// `horizon` over the type-`ty` active slice), the stale set snapshotted
    /// at entry. Served only where declared, and the snapshot read that
    /// builds the batch is what declares it: `stale`'s own `NotBh4` refusal
    /// lifts into `TxnError::Rejected(RetractStaleError::NotBh4)` —
    /// PRE-TRANSACT, no transaction opened, the same channel as `emit`'s
    /// pre-transact rejections — so the batch nullifier can never be aimed
    /// at an idem⊤ class (e.g. mass-nullifying old `[K_sup]` claims). In THIS
    /// format that fence covers every input: the registry's population is the
    /// shipped five, all of them idem⊤ and none declaring BH4, so no `ty` a
    /// caller can name is served and this op cannot succeed. Kept as the one
    /// statement of the rule rather than specialized to the population, as
    /// `reverse_lookup_classes` is. NOT atomic — a sequence of
    /// `nullify` transacts, each failure lifted through
    /// `RetractStaleError::Nullify`; on the first `TxnError` it returns
    /// `Err`, leaving earlier nullifies committed and durable (append-only,
    /// no rollback) — a re-run with the same `d_retr` is safe
    /// (already-nullified targets from this `d_retr` dedup; the recomputed
    /// stale set excludes them).
    ///
    /// `ty` PRECONDITION, inherited from [`stale`](crate::LinkState::stale),
    /// which builds the batch: address-denoting (a registered or reserved
    /// type) or `iextent`-built. That read classifies `ty` BEFORE the BH4
    /// lookup, so a hand-built non-level-uniform `ty` panics naming the
    /// precondition (§Core data model totality) rather than arriving as
    /// `NotBh4`. The refusal above is the verdict for an IN-CONTRACT `ty` that
    /// is simply not a BH4 type; it is not the answer to a malformed one, and
    /// the typed rejection exists precisely so that sentence is never said
    /// about something else. This is the ONE write op that carries the
    /// obligation as a panic: `emit`, the other write taking a caller-built
    /// `ty` endset, converts the same obligation into a typed rejection
    /// (`NonAddressDenotingType`, ahead of any class computation) and says so.
    ///
    /// COMPLETABLE ONLY BY AN OWNER OF EVERY STALE TUPLE. The batch comes
    /// from `stale`, which reads the WHOLE active type-`ty` slice — across
    /// homes and across accounts, `d_retr` scoping only where the retractions
    /// land — while each constituent `nullify` demands ω on its target (v1
    /// self-retraction). So a foreign-owned stale tuple halts the batch at
    /// the same point on every re-run: safe, and not progressive past it.
    /// Nullifying what one owns is the caller's business, done by aiming
    /// `nullify` directly.
    ///
    /// "The same point on every re-run" is a property rather than a hope
    /// because the batch is issued in [`stale`](crate::LinkState::stale)'s
    /// order, which that read publishes as ascending by address. Results come
    /// back in it, one `(retraction address, seq)` per nullified target.
    pub fn retract_stale(
        &self,
        caller: Caller,
        d_retr: &Address,
        ty: &Endset,
        horizon: u64,
    ) -> Result<Vec<(Address, Seq)>, TxnError<RetractStaleError>> {
        let stale: Vec<Address> = {
            let snap = self.kernel.snapshot();
            let world = snap.world();
            world
                .links()
                .stale(ty, horizon)
                .map_err(|NotBh4| TxnError::Rejected(RetractStaleError::NotBh4))? // §7
        };
        let mut out = Vec::with_capacity(stale.len());
        for target in &stale {
            out.push(self.nullify(caller, d_retr, target).map_err(lift_nullify)?);
        }
        Ok(out)
    }
}
