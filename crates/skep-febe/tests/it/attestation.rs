//! Which commits an attestation lands in, read back off the journal. Three
//! modules decide it together — the transport sets the value, M10 hands it
//! to every M5 and M7 driver a write acquires, and each store signs the
//! transactions its handle states — and this is the one place all three are
//! observed at once. M10 holds no copy of the checked set — skepd's name for
//! the writes an attestation is admitted on — so the set is pinned here, over
//! all fifteen writes.

use std::sync::Arc;

use crate::common;

use common::*;
use skep_febe::{Attestation, OpKind};
use tempfile::tempdir;

/// THE CHECKED SET, at the seam where it is observable: every one of the
/// fifteen writes carries one attestation, and it lands in the commit marker
/// of `insert`, `publish` and `make_link` alone, every other write committing
/// an empty signature slot. Over a journaled kernel, since an in-memory one
/// keeps no marker; and each write must commit a transaction of its own, or
/// the marker read at its `at` would be another write's.
#[test]
fn an_attestation_lands_in_the_marker_of_insert_publish_and_make_link_alone() {
    let dir = tempdir().expect("a temporary directory");
    let kernel = journaled_kernel(dir.path());
    let fx = fixture_on(surface_over(Arc::clone(&kernel)));
    let attestation =
        Attestation::new(1, vec![0xA5]).expect("a non-zero tag over a non-empty blob");

    let mut seen: Vec<OpKind> = Vec::new();
    commit_every_write(&fx, Some(&attestation), |kind, before, r| {
        let at = at_of(kind, r);
        assert!(at > before, "{kind:?} committed no transaction of its own");
        let signed = matches!(kind, OpKind::Insert | OpKind::Publish | OpKind::MakeLink);
        assert_eq!(
            kernel.attestation_at(at).expect("a journaled kernel reads its own markers"),
            signed.then(|| attestation.clone()),
            "{kind:?}: its marker's signature slot"
        );
        seen.push(kind);
    });
    assert_eq!(seen.len(), 15, "the write half of the partition is 15 operations: {seen:?}");
}
