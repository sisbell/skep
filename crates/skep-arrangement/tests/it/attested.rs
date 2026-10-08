//! The attested handle (signed ops): its `insert`, `publish` and `version`
//! fill their own transaction's signature slot and no other.

use skep_arrangement::{Deposit, Shot, VSpec, Vstream};
use skep_kernel::Kernel;
use skep_namespace::PrincipalId;
use tempfile::tempdir;

use crate::common::*;

/// THE ATTESTED HANDLE FILLS THE SLOT OF ITS OWN TRANSACTION AND NO OTHER
/// (signed ops; the design record §2.4's route, the attestation riding the
/// handle; SO-I4): a `Vstream::attested` handle's `insert`, `publish` and
/// `version` — the three publish-class kinds of this surface — commit under
/// the attestation it carries — the kernel reads it back at exactly those
/// boundaries — while a plain `Vstream::new` handle's writes, and the
/// attested handle's three others (`delete`, `copy`, `rearrange`, which no
/// published document admits), leave their slots empty. The driver's own
/// signature is unchanged; the value rides the handle. And the slot moves
/// the chain: an unattested twin history chains identically up to the first
/// filled slot and parts there, the slot's digest being a chain input
/// (r6-2c).
#[test]
fn an_attested_handle_fills_the_slot_of_its_own_transaction_alone() {
    use skep_kernel::Attestation;
    let dir = tempdir().expect("tempdir");
    let k = Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("open");
    let tag1 = Attestation::new(1, vec![0x11; 3_373]).expect("tag 1, a 3,373-byte blob");
    let tag3 = Attestation::new(3, vec![0x33; 730]).expect("tag 3, a 730-byte blob");

    // A plain handle's writes: the slot empty.
    let plain = Vstream::new(&k);
    let (_, s_plain) = plain
        .insert(P1, &doc1(), vp(1, 1), vec![val(b"a"), val(b"b"), val(b"c")], Deposit::Undeclared)
        .expect("insert commits");
    // An attested handle's `insert`: the slot filled for that transaction.
    let attested = Vstream::attested(&k, Some(&tag1));
    let (_, s_att) = attested
        .insert(P1, &pdoc(), vp(1, 1), vec![val(b"a"), val(b"b"), val(b"c")], declared())
        .expect("the declared deposit commits");
    // The same attested handle's `delete`: outside the checked set, the plain arm.
    let s_del = attested.delete(P1, &doc1(), vp(1, 2), n(1)).expect("delete commits");
    // …and its `copy` and `rearrange`: the plain arm as well; its `version`
    // — a publish-class kind — the attested arm.
    let from_doc1 = [VSpec {
        source: doc1(),
        span: vspan(1, 1, 2),
    }];
    let pivot = [vp(1, 1), vp(1, 2), vp(1, 3)];
    let s_copy = attested
        .copy(P1, &doc2(), vp(1, 1), &from_doc1)
        .expect("copy commits");
    let s_rearrange = attested
        .rearrange(P1, &doc1(), &pivot)
        .expect("rearrange commits");
    let (_, s_fork) = attested
        .version(PrincipalId(2), &doc1(), None)
        .expect("a cross-owner fork");
    // A shot under tag 3: the slot filled with tag 3's blob.
    let shot = Shot {
        base: None,
        draft: Some(doc1()),
        runs: vec![shot_run(&doc1(), &ca(1), 1), shot_run(&doc1(), &ca(3), 1)],
    };
    let readable = readable_by(PrincipalId(1));
    let (member, s_pub) = Vstream::attested(&k, Some(&tag3))
        .publish(P1, &pdoc(), &shot, &readable)
        .expect("the shot commits");
    assert_eq!(member, vdoc());

    assert_eq!(k.attestation_at(s_plain).unwrap(), None, "the plain handle's insert");
    assert_eq!(k.attestation_at(s_att).unwrap(), Some(tag1.clone()), "the attested insert");
    assert_eq!(k.attestation_at(s_del).unwrap(), None, "delete takes the plain arm");
    for (seq, write) in [(s_copy, "copy"), (s_rearrange, "rearrange")] {
        assert_eq!(
            k.attestation_at(seq).unwrap(),
            None,
            "{write} takes the plain arm"
        );
    }
    assert_eq!(k.attestation_at(s_fork).unwrap(), Some(tag1.clone()), "the attested version");
    assert_eq!(k.attestation_at(s_pub).unwrap(), Some(tag3), "the attested shot");

    // A `Copy` handle copied still carries the borrow; a handle built with
    // `None` is the plain handle exactly. The deposits land in the HEAD
    // member the shot minted (two positions), at its fresh positions. The
    // suite reuses one handle across writes to pin what the type does; a
    // producer builds one per call, each attestation signing one entry body
    // (`Vstream::attested`'s obligation).
    let copied = attested;
    let (_, s_copied) = copied
        .insert(P1, &pdoc(), vp(1, 3), vec![val(b"d")], declared())
        .expect("a second deposit commits");
    assert_eq!(k.attestation_at(s_copied).unwrap(), Some(tag1.clone()));
    let none = Vstream::attested(&k, None);
    let (_, s_none) = none
        .insert(P1, &pdoc(), vp(1, 4), vec![val(b"e")], declared())
        .expect("a third deposit commits");
    assert_eq!(k.attestation_at(s_none).unwrap(), None);

    // The unattested twin chains identically up to the first filled slot and
    // parts there: the slot's digest is a chain input (r6-2c).
    let twin_dir = tempdir().expect("tempdir");
    let twin = Kernel::<World>::open(cfg_fsync(twin_dir.path()), genesis()).expect("open");
    let vs = Vstream::new(&twin);
    vs.insert(P1, &doc1(), vp(1, 1), vec![val(b"a"), val(b"b"), val(b"c")], Deposit::Undeclared)
        .unwrap();
    vs.insert(P1, &pdoc(), vp(1, 1), vec![val(b"a"), val(b"b"), val(b"c")], declared()).unwrap();
    vs.delete(P1, &doc1(), vp(1, 2), n(1)).unwrap();
    vs.copy(P1, &doc2(), vp(1, 1), &from_doc1).unwrap();
    vs.rearrange(P1, &doc1(), &pivot).unwrap();
    vs.version(PrincipalId(2), &doc1(), None).unwrap();
    let shot = Shot {
        base: None,
        draft: Some(doc1()),
        runs: vec![shot_run(&doc1(), &ca(1), 1), shot_run(&doc1(), &ca(3), 1)],
    };
    vs.publish(P1, &pdoc(), &shot, &readable_by(PrincipalId(1))).unwrap();
    vs.insert(P1, &pdoc(), vp(1, 3), vec![val(b"d")], declared()).unwrap();
    vs.insert(P1, &pdoc(), vp(1, 4), vec![val(b"e")], declared()).unwrap();
    assert_eq!(twin.chain_at(s_plain).unwrap(), k.chain_at(s_plain).unwrap(), "unsigned alike");
    assert_ne!(twin.chain_at(s_att).unwrap(), k.chain_at(s_att).unwrap(), "the first filled slot parts them");
    assert_ne!(twin.chain_head(), k.chain_head(), "the slot is inside its link");
}
