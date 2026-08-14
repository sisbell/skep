//! §C — the standalone transact-wrapped write (M2 contract 3's second form).

use skep_address::{document_of, Address, Tumbler};
use skep_kernel::{Kernel, Seq, TxnError, WorldState};
use skep_namespace::M3State;

use crate::error::ContentError;
use crate::store::{stage_write, ContentWrite};
use crate::value::Val;
use crate::HasContent;

#[cfg(feature = "content-addr-guard")]
use crate::store::debug_assert_content_address;

/// STANDALONE OP — the contract-required transact-wrapped form (M2 contract
/// 3; §C). Generic over `W`. ISOLATION/TEST USE ONLY: committing a content
/// write *alone* creates content with no placement, violating J0
/// (content-allocation ⇒ placement) — production content writes MUST ride
/// M5's J0/J1★-coupled composite via [`stage_write`]. `#[doc(hidden)]`
/// because it exists ONLY to satisfy the contract's two-composable-forms
/// rule, hidden so callers reach for M5's composite instead; the symbol is
/// KEPT in the production build (not `cfg(test)`-gated) — the contract
/// requires the form to exist.
///
/// Locks the per-(document, content-subspace) namespace key — the SAME key
/// M3's content allocation and M5's placement composite hold, so alloc,
/// write, and placement serialize in one scope. `home` is derived by M1's
/// [`document_of`]; a content address has zeros = 3, so it is always `Some`
/// — the `.expect` IS the trusted-address contract on this
/// trusted-address-only op, turning the unreachable `None` into a
/// documented internal-invariant violation, never a domain rejection. With
/// the `content-addr-guard` feature on, the routing check runs BEFORE key
/// derivation (mirroring [`stage_write`]'s check order): without the hoist
/// a zeros < 2 input would hit the `.expect` first and the guard could
/// never fire on this path.
///
/// On success returns the flat storage key and the committed `Seq` (the
/// write's V1 coordinate); rejections surface verbatim as
/// `TxnError::Rejected(ContentError)`.
///
/// OPEN DECISION (drift-forced; §Dependencies & seams "M2"): the design
/// derives this key via a shared base-crate `key(home, …)` constructor plus
/// an `s_C` LockKey space-tag in `skep-kernel`; neither exists in the built
/// workspace — M3's injective `ns_lock_key` encoding and its public
/// per-namespace constructors are the one source of
/// `Space::Namespace`-tagged key bytes (they supersede the base-crate
/// sketch, per M3's own recorded open decision). The design's load-bearing
/// requirement — ONE source, so M3-alloc / M4-write / M5-placement keys are
/// byte-identical by construction — is kept by calling
/// [`M3State::content_lock_key`] rather than re-spelling the encoding
/// locally (which the design forbids). Cost: an M4 → M3 crate edge the
/// design's DAG did not carry, for a pure key constructor only; no M3
/// *state* is ever read, so "M4 reads no module above M1/M2" holds in the
/// state sense.
#[doc(hidden)]
pub fn write<W>(
    k: &Kernel<W>,
    addr: &Address,
    val: Val,
) -> Result<(Tumbler, Seq), TxnError<ContentError>>
where
    W: WorldState + HasContent,
    W::Record: From<ContentWrite>,
{
    #[cfg(feature = "content-addr-guard")]
    debug_assert_content_address(addr, "write");
    let home = document_of(addr).expect("content address ⇒ zeros = 3 (trusted-address contract)");
    k.transact(&[M3State::content_lock_key(&home)], |stg| {
        let r = stage_write(stg.working().content(), addr, val)?;
        stg.push(r.into());
        Ok(addr.tumbler().clone())
    })
}
