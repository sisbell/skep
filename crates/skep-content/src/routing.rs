//! The routing assertion the four write doors share (Open build decision #4).
//!
//! It is taken as a debug assertion.

use skep_address::{content_subspace, Address, Level};

/// Asserts `level == Element ∧ subspace == s_C` before a door writes `addr`.
///
/// The four doors are [`stage_write`](crate::stage_write),
/// [`stage_stretch`](crate::stage_stretch), and the test-only `write` and
/// `write_stretch`. The condition is ASN-0093's C1 and L0, the two
/// content-address conditions routing decides; C1b's `#E(a) ≥ 2` and C1c's
/// allocator conformance are M3's mint discipline and are not asserted here.
/// The numeral is read from M1's [`content_subspace`] (ASN-0093's
/// SubspaceConventionAxiom fixes `s_C = 1`). That is the element field's
/// subspace, not the kernel-side LockKey space-tag — different constant,
/// different layer (§Dependencies & seams).
///
/// # Panics
///
/// Panics in a debug build where `addr` is not a content-subspace element
/// address. A `debug_assert!`: every debug build in the workspace, its test
/// builds included, checks every content write, and a release build, a
/// release test build included, pays nothing. `#[track_caller]`, as all four
/// doors are, so the panic's location is the line that handed the address
/// in, and `door` names which of the four it came through.
#[track_caller]
pub(crate) fn debug_assert_content_address_routing(addr: &Address, door: &str) {
    debug_assert!(
        addr.level() == Level::Element && addr.subspace() == Some(&content_subspace()),
        "content routing: {door}: not a content-subspace element address \
         (level == Element ∧ subspace == s_C = 1 required)"
    );
}
