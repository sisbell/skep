//! The routing assertion (Open build decision #4, taken as a debug
//! assertion), shared by the two write doors.

use skep_address::{content_subspace, Address, Level};

/// Asserts `level == Element ∧ subspace == s_C` for an address
/// [`stage_write`](crate::stage_write) or the test-only `write` is about to
/// write — ASN-0093's C1 and L0, the two content-address conditions routing
/// decides; C1b's `#E(a) ≥ 2` and C1c's allocator conformance are M3's mint
/// discipline and are not asserted here. The numeral is read from M1's
/// [`content_subspace`] (ASN-0093's SubspaceConventionAxiom fixes
/// `s_C = 1`). That is the element field's subspace, NOT the kernel-side
/// LockKey space-tag — different constant, different layer (§Dependencies &
/// seams). A `debug_assert!`: every debug and test build in the workspace
/// checks every content write, and release pays nothing.
pub(crate) fn debug_assert_content_address_routing(addr: &Address, site: &str) {
    debug_assert!(
        addr.level() == Level::Element && addr.subspace() == Some(&content_subspace()),
        "content routing: {site}: not a content-subspace element address \
         (level == Element ∧ subspace == s_C = 1 required)"
    );
}
