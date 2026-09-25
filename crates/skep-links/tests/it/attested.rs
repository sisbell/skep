//! THE ATTESTED WRITER (signed ops, the seam build; the confirmed placement):
//! `LinkWriter::attested`'s `makelink` commits under the attestation it
//! carries and the kernel reads it back at that boundary alone — a plain
//! writer's `makelink`, and the attested writer's other link writes, leave
//! their slots empty. No driver method signature moves.

use crate::common::*;

use skep_kernel::{
    Attestation, BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelConfig, SaltSource,
};
use skep_links::{LinkWriter, SlotArg};
use tempfile::tempdir;

fn journaled(dir: &std::path::Path) -> Kernel<World> {
    let cfg = KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 1,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    };
    Kernel::open(cfg, genesis_world()).expect("journaled open")
}

#[test]
fn an_attested_writer_fills_the_slot_of_its_own_makelink_alone() {
    let dir = tempdir().expect("tempdir");
    let k = journaled(dir.path());
    seed_content(&k, &doc1(), 4);
    let tag1 = Attestation::new(1, vec![0x11; 3_373]).expect("tag 1");

    // The plain writer: an empty slot.
    let (plain_link, s_plain) = writer(&k)
        .makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(1)]),
            SlotArg::Addrs(vec![ca(2)]),
            SlotArg::Addrs(vec![unregistered_ta(13)]),
        )
        .expect("makelink");
    // The attested writer: the slot filled for that transaction.
    let attested = LinkWriter::attested(&k, &ALL_VISIBLE, Some(&tag1));
    let (_, s_att) = attested
        .makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 2)]),
            SlotArg::Addrs(vec![ca(3)]),
            SlotArg::Addrs(vec![unregistered_ta(14)]),
        )
        .expect("makelink");
    // The attested writer's `nullify` — outside the slice — takes the plain
    // arm: the retraction of the plain link commits with an empty slot.
    let (_, s_null) = attested.nullify(P1, &doc1(), &plain_link).expect("nullify commits");
    assert_eq!(k.attestation_at(s_plain).unwrap(), None, "the plain writer's makelink");
    assert_eq!(k.attestation_at(s_att).unwrap(), Some(tag1), "the attested makelink");
    assert_eq!(k.attestation_at(s_null).unwrap(), None, "nullify takes the plain arm");
    // `attested(…, None)` is `new` exactly.
    let (_, s_none) = LinkWriter::attested(&k, &ALL_VISIBLE, None)
        .makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(4)]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![unregistered_ta(16)]),
        )
        .expect("makelink");
    assert_eq!(k.attestation_at(s_none).unwrap(), None);
}
