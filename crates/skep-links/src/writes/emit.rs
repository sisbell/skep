//! Emit_K (ASN-0086/0126/0128): the managed surface's gated emission.
//!
//! [`emit_tuple`] is the tuple an emission deposits, and [`LinkWriter::emit`]
//! the gated typed-relation emission — its pre-transact fences in firing
//! order, then the deposit gate's Managed discipline with its idem⊤ dedup at
//! the caller's visibility class.

use skep_address::Address;
use skep_arrangement::Caller;
use skep_kernel::{Seq, TxnError};
use skep_namespace::M3Rec;

use super::{deposit_lock_set, emit_core, replaces_class, Gate, LinkWriter};
use crate::budget::MAX_SLOT_SPANS;
use crate::class::coverage_class;
use crate::endset::{enc, Endset, Link};
use crate::error::EmitError;
use crate::registry::{registry, ShippedType};
use crate::state::LinkRec;
use crate::LinkWorld;

/// Builds the Emit_K tuple [`LinkWriter::emit`] deposits for `(ty, from, to)`.
///
/// The tuple is `(enc({from}), enc(to), ty)`, `ty` stored verbatim as e₃; the
/// answer is `None` when either caller-sized slot is past [`MAX_SLOT_SPANS`]
/// spans: `to`'s addresses or `ty`'s own spans. (`enc({from})` is one span,
/// so `from` needs no clause.)
///
/// `ty` is held to the budget as squarely as `to`: its class collapses
/// repeated addresses, so a registered class is no bound on the slot naming
/// it. What the budget prevents differs between the two. An over-budget `to`
/// could never be stored — no class in this format admits `|G| > 1` — so for
/// `to` it saves the building of a value the shape gate would refuse. An
/// over-budget `ty` has no such backstop under any shape: no gate on `emit`'s
/// path but this budget reads e₃'s span count, so for `ty` the budget is all
/// that stands between a request and an arbitrarily wide permanent slot.
///
/// It builds the value and judges nothing else — `emit`'s class fences run
/// before it and its Managed gate after. Public as
/// [`slot_endset`](crate::slot_endset) is, for the same caller: `emit` builds
/// through it and so does the daemon's entry-frame composer (signed ops), so
/// the row an attestation covers and the link the store deposits agree by
/// construction.
pub fn emit_tuple(ty: &Endset, from: &Address, to: &[Address]) -> Option<Link> {
    if to.len() > MAX_SLOT_SPANS || ty.len() > MAX_SLOT_SPANS {
        return None;
    }
    Some(Link::triple(enc([from]), enc(to), ty.clone()))
}

impl<'k, W> LinkWriter<'k, W>
where
    W: LinkWorld,
    W::Record: From<LinkRec> + From<M3Rec>,
{
    /// Emit_K (ASN-0086/0126/0128): emits the tuple [`emit_tuple`] builds.
    ///
    /// The emission is gated, of the typed-relation tuple
    /// `Link[enc({from}), enc(to), ty]`: `|F| = 1` forced, `to`'s span count
    /// shape-checked, `ty` stored verbatim as e₃. Does not seat. idem⊤ ⇒
    /// dedup against the active view within the caller's visibility class
    /// (PUB-6.25); a hit returns the incumbent with the base `Seq` and
    /// commits nothing.
    ///
    /// The shape gate counts spans, not distinct addresses: `enc(to)` yields
    /// one span per element, so `to = [x, x]` carries `|G| = 2` here and is
    /// refused under Binary, where ASN-0126's set-valued `|G|` admits it
    /// ([`Shape`](crate::Shape)).
    ///
    /// **What a hit returns.** The T1-least active tuple of the I0 class the
    /// caller can read — the earliest incumbent homed in a document its
    /// [`Visibility`](crate::Visibility) class admits (PUB-6.26;
    /// deterministic given the visibility class) — which is the I0 class's
    /// incumbent and not a tuple this call admitted. An incumbent homed in a
    /// document the caller cannot read is invisible, and the emit mints fresh
    /// beside it: value-identical tuples may coexist across the visibility
    /// boundary. The gate runs over the value this call built; the incumbent
    /// may have been deposited through the open surface, which applies
    /// neither the shape gate nor a dedup check ([`Shape`](crate::Shape),
    /// [`Registration`](crate::Registration)) — so a caller that reads the
    /// returned address back may find a link its own emission would have been
    /// refused for, and one of several active tuples of that identity.
    ///
    /// The lock set is `[dedup_key, link_lock_key(home)]` for a registered
    /// idem⊤ `ty`, else `[link_lock_key(home)]` — the registration read goes
    /// to the module's format registry, race-free because that registry is a
    /// compiled constant (§3 step 1).
    ///
    /// Returns `(tuple, seq)`: the address of the deposited tuple, or — on a
    /// dedup hit — the incumbent's, with the base `Seq`.
    ///
    /// # Errors
    ///
    /// Each refusal comes as `TxnError::Rejected`. Pre-transact (no
    /// transaction opened — §3), in firing order: `ty` not address-denoting
    /// (`NonAddressDenotingType`, before any class computation, keeping
    /// `coverage_class` on the safe denoted path); `ty ~ [K_sup]`
    /// (`SupersessionClass` — assert_sup/editlink are the sole
    /// `[K_sup]`-writers, the parallel of the `[R]` fence; Conflicts §10);
    /// `ty ~ replaces` (`ReplacesClass` — [`LinkWriter::makelink_replacing`]
    /// is that class's sole writer,
    /// [`is_replaces_class`](crate::is_replaces_class); PUB-5.15); and either
    /// caller-sized slot past [`MAX_SLOT_SPANS`] spans (`SlotTooLarge`,
    /// [`emit_tuple`]'s budget) — all four ahead of `ShapeViolation`, which
    /// an over-budget `to` also satisfies. Then, inside the transaction:
    /// `HomeNotRegistered` and `NotOwner` for `home`, the Managed gate's
    /// `NotRegistered`, `RetractionClass` (`ty ~ [R]`) and `ShapeViolation`,
    /// and `Mint` where the mint fails. The kernel's own failures —
    /// `Durability`, `Unencodable`, `OverBudget`, `Poisoned` — come back as
    /// `transact` returns them.
    pub fn emit(
        &self,
        caller: Caller,
        home: &Address,
        ty: &Endset,
        from: &Address,
        to: &[Address],
    ) -> Result<(Address, Seq), TxnError<EmitError>> {
        if !ty.is_address_denoting() {
            return Err(TxnError::Rejected(EmitError::NonAddressDenotingType));
        }
        let class = coverage_class(ty);
        if class == *registry().shipped_class(ShippedType::Supersedes) {
            return Err(TxnError::Rejected(EmitError::SupersessionClass));
        }
        if class == *replaces_class() {
            return Err(TxnError::Rejected(EmitError::ReplacesClass));
        }
        let value = emit_tuple(ty, from, to).ok_or(TxnError::Rejected(EmitError::SlotTooLarge))?;
        let keys = deposit_lock_set(&value, home);
        // The attested arm (signed ops): `transact` itself where this handle
        // carries no attestation, else the same commit with its marker's
        // signature slot filled. A dedup hit commits nothing and fills none.
        self.kernel.transact_attested(&keys, self.attest, |stg| {
            Ok(emit_core(stg, self.visibility, caller, home, value, Gate::Managed)?.address())
        })
    }
}
