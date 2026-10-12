//! Which commits an attestation lands in, read back off the journal. Three
//! modules decide it together — the transport sets the value, M10 hands it
//! to every M3, M5 and M7 driver a write acquires, and each store signs the
//! transactions its handle states — and this is the one place all three are
//! observed at once. M10 holds no copy of the checked set — skepd's name for
//! the writes an attestation is admitted on — so the set is pinned here, over
//! all sixteen writes.

use std::sync::Arc;

use crate::common;

use common::*;
use skep_address::{elem_addr, ElemPos};
use skep_febe::{Attestation, Op, OpKind, Request, Run, ShotRun};
use tempfile::tempdir;

/// THE CHECKED SET, at the seam where it is observable (SO-I4: every
/// publishing act above the claim is signed): every one of the sixteen
/// writes carries one attestation, and it lands in the commit marker of the
/// TEN publish-class kinds alone — `create_new_document`, `fork`, `version`,
/// `insert`, `publish`, `make_link`, `emit`, `nullify`, `assert_sup`,
/// `edit_link` — every other write (`delete`, `copy`, `reinstate`,
/// `rearrange`, `delegate`, `register_node`) committing an empty signature
/// slot. Over a journaled kernel, since an in-memory one keeps no marker;
/// and each write must commit a transaction of its own, or the marker read
/// at its `at` would be another write's. Fifteen run as the fixture's one
/// chain (`commit_every_write`); the sixteenth, the write by identity, is
/// committed beside it over a draft of its own.
#[test]
fn an_attestation_lands_in_the_marker_of_the_ten_publish_class_kinds_alone() {
    let dir = tempdir().expect("a temporary directory");
    let kernel = journaled_kernel(dir.path());
    let fx = fixture_on(surface_over(Arc::clone(&kernel)));
    let attestation =
        Attestation::new(1, vec![0xA5]).expect("a non-zero tag over a non-empty blob");

    // The sixteenth write, `reinstate`: a draft's second position removed
    // and re-placed by its own address, the attestation riding the request
    // — and dropped unread, the kind being outside the checked set, so the
    // marker slot of the commit it makes is empty.
    let draft = create_doc(&fx);
    insert3(&fx, &draft);
    ack(ex(&fx.febe, fx.user, Op::Delete { doc: draft.clone(), p: vp(1, 2), width: nat(1) }));
    let second = elem_addr(ElemPos { doc: draft.clone(), subspace: nat(1), ordinal: nat(2) })
        .unwrap_or_else(|_| panic!("valid element position"));
    let before = fx.febe.log_position();
    let reinstate = Op::Reinstate {
        doc: draft.clone(),
        at: vp(1, 2),
        runs: vec![ShotRun {
            origin: draft,
            run: Run::new(second, nat(1)).expect("a content run"),
        }],
    };
    let at = ack(
        fx.febe
            .execute(fx.user, Request { attest: Some(attestation.clone()), ..Request::from(reinstate) }),
    );
    assert!(at > before, "reinstate committed a transaction of its own");
    assert_eq!(
        kernel.attestation_at(at).expect("a journaled kernel reads its own markers"),
        None,
        "reinstate: outside the checked set, its marker's signature slot stays empty"
    );

    let mut seen: Vec<OpKind> = Vec::new();
    commit_every_write(&fx, Some(&attestation), |kind, before, r| {
        let at = at_of(kind, r);
        assert!(at > before, "{kind:?} committed no transaction of its own");
        let signed = matches!(
            kind,
            OpKind::CreateNewDocument
                | OpKind::Fork
                | OpKind::Version
                | OpKind::Insert
                | OpKind::Publish
                | OpKind::MakeLink
                | OpKind::Emit
                | OpKind::Nullify
                | OpKind::AssertSup
                | OpKind::EditLink
        );
        assert_eq!(
            kernel.attestation_at(at).expect("a journaled kernel reads its own markers"),
            signed.then(|| attestation.clone()),
            "{kind:?}: its marker's signature slot"
        );
        seen.push(kind);
    });
    assert_eq!(seen.len(), 15, "the fixture's chain is 15 of the partition's 16 writes: {seen:?}");
    let empty: Vec<&OpKind> = seen
        .iter()
        .filter(|k| matches!(k, OpKind::Delete | OpKind::Copy | OpKind::Reinstate | OpKind::Rearrange | OpKind::Delegate | OpKind::RegisterNode))
        .collect();
    assert_eq!(
        empty.len(),
        5,
        "the chain's five unsigned kinds each committed once (the sixth, reinstate, above): {seen:?}"
    );
}
