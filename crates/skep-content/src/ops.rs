//! §C — the standalone transact-wrapped write (M2 contract 3's second form),
//! `test-hooks` builds only.

use skep_address::{document_of, Address, Tumbler};
use skep_kernel::{Kernel, Seq, TxnError, WorldState};
use skep_namespace::M3State;

use crate::error::ContentError;
use crate::routing::debug_assert_content_address_routing;
use crate::store::{stage_write, ContentWrite};
use crate::value::Val;
use crate::HasContent;

/// STANDALONE OP — the contract-required transact-wrapped form (M2 contract
/// 3; §C). Generic over `W`. ISOLATION/TEST USE ONLY: committing a content
/// write *alone* creates content with no placement, violating J0
/// (content-allocation ⇒ placement) — production content writes MUST ride
/// M5's J0/J1★-coupled composite via [`stage_write`].
///
/// So it is compiled only under the `test-hooks` feature (default off),
/// which this crate's suite turns on through its self dev-dependency: a
/// build that compiles no test holds none of it, and a production path that
/// reached for it would not compile. The contract's two-composable-forms
/// rule asks only that the form exist, and under the feature it does; a
/// `cfg(test)` gate would not serve, because the suite in `tests/it` is a
/// separate crate that never sees this library's `cfg(test)`.
/// `#[doc(hidden)]` as well, so even a `test-hooks` build's docs send a
/// reader to M5's composite.
///
/// Locks the per-(document, content-subspace) lock key — the SAME key
/// M3's content allocation and M5's placement composite hold, so alloc,
/// write, and placement serialize in one scope. `home` is derived by M1's
/// [`document_of`]; a content address has zeros = 3, so it is always `Some`,
/// and the `.expect` turns the `None` of an address with no document
/// (zeros < 2) into a documented violation of the trusted-address contract,
/// never a domain rejection. It is a release build's only check of that
/// contract, and a partial one: a document-level or mis-routed element
/// address has a document, passes it, and is written as given. In debug
/// builds the routing assertion runs BEFORE key derivation (mirroring
/// [`stage_write`]'s order), so every non-content address panics on its own
/// terms; in release it is compiled out. Either panic is located at the
/// caller's line: `write` is `#[track_caller]`.
///
/// On success returns the flat storage key and the committed `Seq` (the
/// write's V1 coordinate). `stage_write`'s refusal surfaces verbatim as
/// `TxnError::Rejected(ContentError)`; every other `TxnError` is M2's own,
/// in the precedence [`Kernel::transact`] states.
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
/// design's DAG did not carry, for a pure key constructor only. The edge is
/// optional and only `test-hooks` takes it, so the shipped library carries
/// none — nor its M2 edge, which `write` alone takes too — and no M3
/// *state* is ever read.
#[doc(hidden)]
#[track_caller]
pub fn write<W>(
    kernel: &Kernel<W>,
    addr: &Address,
    val: Val,
) -> Result<(Tumbler, Seq), TxnError<ContentError>>
where
    W: WorldState + HasContent,
    W::Record: From<ContentWrite>,
{
    debug_assert_content_address_routing(addr, "write");
    let home = document_of(addr).expect("content address ⇒ zeros = 3 (trusted-address contract)");
    kernel.transact(&[M3State::content_lock_key(&home)], |stg| {
        let rec = stage_write(stg.working().content(), addr, val)?;
        stg.push(rec.into());
        Ok(addr.tumbler().clone())
    })
}
