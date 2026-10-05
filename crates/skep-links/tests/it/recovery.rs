//! Recovery over a real kernel (InMemory): a checkpoint round trip and
//! `rebuild_derived` restore every hint the writes maintain.

use crate::common;

use common::*;
use skep_links::{HasLinks, SlotArg, View};

#[test]
fn checkpoint_roundtrip_then_rebuild_derived_restores_every_hint() {
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    let (a1, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("idem⊤");
    let (x, _) = w.emit(P1, &doc1(), &pred_stable_ty(), &ca(3), &[]).expect("x");
    let (y, _) = w.emit(P1, &doc1(), &pred_stable_ty(), &ca(4), &[]).expect("y");
    let (_unregistered, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(5)]),
            SlotArg::Addrs(vec![ca(6)]),
            SlotArg::Addrs(vec![unregistered_ta(11)]),
        )
        .expect("an unregistered-class deposit, so its slice is rebuilt too");
    let (c, _) = w.assert_sup(P1, &doc1(), &x, &y).expect("claim");
    w.nullify(P1, &doc1(), &x).expect("nullify the claim's old endpoint");

    // The checkpoint wire format: serialize the world, deserialize (skip
    // fields default), rebuild_derived BEFORE any read/replay.
    let snap = k.snapshot();
    let bytes = bincode::serialize(snap.world()).expect("world serializes");
    let recovered: World = bincode::deserialize(&bytes).expect("world deserializes");
    let recovered =
        skep_kernel::WorldState::rebuild_derived(recovered).expect("this world's seed never refuses");

    let live = snap.world().links();
    let back = recovered.links();
    for addr in [&a1, &x, &y, &c] {
        assert_eq!(live.readlink(addr), back.readlink(addr));
    }
    assert!(back.is_nullified(&x));
    assert_eq!(back.succs(&sup, &x), vec![y.clone()]); // sup_fwd rebuilt
    assert_eq!(
        live.type_slice(&pred_def_ty(), View::Audit),
        back.type_slice(&pred_def_ty(), View::Audit)
    );
    assert_eq!(
        live.type_slice(&unregistered_ty(11), View::Active),
        back.type_slice(&unregistered_ty(11), View::Active)
    );
    assert!(!back.type_slice(&unregistered_ty(11), View::Active).is_empty());
    // The home-frontier hint, which age/stale and nullify's `a_emit`
    // prediction all stand on — and a live value, so the pair is not two
    // zeros agreeing.
    assert_ne!(live.age(&a1), Some(0));
    assert_eq!(live.age(&a1), back.age(&a1), "the home frontier is rebuilt");

    // The dedup hint is rebuilt too: a kernel opened over the recovered world
    // dedups the same idem⊤ emission to the ORIGINAL incumbent.
    let cfg = skep_kernel::KernelConfig {
        durability: skep_kernel::Durability::InMemory,
        checkpoint: skep_kernel::CheckpointPolicy::Manual,
        salt: skep_kernel::SaltSource::Seeded(0),
    };
    let k2 = skep_kernel::Kernel::open(cfg, recovered).expect("reopen");
    let w2 = writer(&k2);
    let (again, _) = w2.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("dedup hit");
    assert_eq!(again, a1);
}
