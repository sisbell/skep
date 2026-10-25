//! Recovery over a real kernel (InMemory): a checkpoint round trip and
//! `rebuild_derived` restore every hint the writes maintain, the directory
//! of homes among them, and what the rebuild costs at a links-heavy board,
//! timed and reported.

use std::time::Instant;

use crate::common;

use common::*;
use skep_address::{Address, Span};
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
    // The spanfilade and its directory of homes: the candidate homes a query
    // opens, with the spans naming each, and the stab they compose.
    let query = skep_links::enc(&[ca(1), ca(5)]);
    let touches = |links: &skep_links::LinkState| -> Vec<(Address, Vec<Span>)> {
        links
            .homes_touching([(skep_links::FROM, &query)])
            .map(|touch| (touch.home().clone(), touch.spans(0).cloned().collect()))
            .collect()
    };
    assert_eq!(touches(live), touches(back), "the directory is rebuilt");
    assert_eq!(touches(back).len(), 1, "doc1 is the one home, and is named");
    assert_eq!(
        live.stab(skep_links::FROM, &query, View::Audit),
        back.stab(skep_links::FROM, &query, View::Audit)
    );
    assert!(!back.stab(skep_links::FROM, &query, View::Audit).is_empty());

    // The dedup hint is rebuilt too: a kernel opened over the recovered world
    // dedups the same idem⊤ emission to the ORIGINAL incumbent.
    let k2 = kernel_over(recovered);
    let w2 = writer(&k2);
    let (again, _) = w2.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("dedup hit");
    assert_eq!(again, a1);
}

/// The open's cost at a links-heavy board, REPORTED and not asserted: a
/// hundred thousand links homed in a thousand documents — each FROM its own
/// position of doc1's content, TO one of a hundred positions, typed one of ten
/// ways, so every hint has something to fold — rebuilt from the decoded map
/// once, as the daemon's open rebuilds a checkpoint, with the wall-clock time
/// printed. A figure for the record, which no clock bound would hold steadily
/// under the gate's load; the hints' agreement with the live state is the
/// test above's.
#[test]
#[ignore = "timing test - gate-full only"]
fn rebuild_derived_at_a_hundred_thousand_links_reports_its_time() {
    const LINKS: u32 = 100_000;
    const HOMES: u32 = 1_000;
    let k = kernel_with_documents(HOMES);
    let built = Instant::now();
    for i in 0..LINKS {
        deposit_in(
            &k,
            &doc(1 + i % HOMES),
            &[ca(1 + i)],
            &[ca(1 + i % 100)],
            &unregistered_ta(1 + i % 10),
        );
    }
    let building = built.elapsed();
    let snap = k.snapshot();
    let live = snap.world().links();
    assert_eq!(live.match_links(&[], View::Audit).len(), LINKS as usize);
    let decoded: skep_links::LinkState =
        bincode::deserialize(&bincode::serialize(live).expect("the slice serializes"))
            .expect("the slice deserializes");
    let rebuilt_at = Instant::now();
    let rebuilt = decoded.rebuild_derived();
    let rebuilding = rebuilt_at.elapsed();
    assert_eq!(
        rebuilt.stab(skep_links::FROM, &skep_links::enc(&[ca(7)]), View::Active),
        live.stab(skep_links::FROM, &skep_links::enc(&[ca(7)]), View::Active),
        "the rebuilt index answers as the live one"
    );
    eprintln!(
        "rebuild_derived at {LINKS} links in {HOMES} homes: {rebuilding:?} (the board took {building:?} to deposit)"
    );
}
