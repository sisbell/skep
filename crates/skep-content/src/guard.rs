//! Open build decision #4 — the routing assertion, compiled only under
//! `content-addr-guard`, shared by its two doors.

use skep_address::{content_subspace, Address, Level};

/// The one routing guard behind Open build decision #4, shared by its two
/// doors ([`stage_write`](crate::stage_write) and the standalone `write`):
/// asserts `level == Element ∧ subspace == s_C`, the numeral read from M1's
/// [`content_subspace`] (ASN-0093's SubspaceConventionAxiom fixes `s_C = 1`).
/// That is the element field's subspace, NOT the kernel-side LockKey
/// space-tag — different constant, different layer (§Dependencies & seams).
/// Debug-assert sub-choice (the design's recommendation): fatal in debug
/// builds, free in release.
pub(crate) fn debug_assert_content_address(addr: &Address, site: &str) {
    debug_assert!(
        addr.level() == Level::Element && addr.subspace() == Some(&content_subspace()),
        "content-addr-guard: {site}: not a content-subspace element address \
         (level == Element ∧ subspace == s_C = 1 required)"
    );
}
