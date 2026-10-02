//! M2-driven recovery: the slice survives checkpoint load and tail replay,
//! byte for byte.

use skep_address::Span;
use skep_arrangement::{reading_surface, seat_link, Deposit, HasM5, Shot, Vstream};
use skep_kernel::Kernel;
use skep_namespace::{HasM3, PrincipalId};
use tempfile::tempdir;

use crate::common::*;

#[test]
fn the_arrangement_survives_durable_recovery_by_checkpoint_and_replay() {
    // §10: M5 owns no recovery machinery — M2 loads the checkpoint
    // (deserializing the slice) and replays the tail through apply → apply_m5.
    // The draft's insert and the edition's deposit ride the checkpoint path;
    // the delete, the rearrangement, the seat, the fork, the post-fork source
    // deposit and the shot ride the replay path — every `M5Rec` variant among
    // them; the recovered slice is byte-identical.
    //
    // The fork is the CROSS-OWNER one (principal 2's copy of the edition):
    // an owned fork would be the edition's first member, and the deposit
    // after it would then land in that member rather than in the source
    // (PUB-2.66) — the source-changes-after-the-fork case this test is about
    // needs a source that still takes deposits itself.
    let dir = tempdir().expect("tempdir");
    let link1 = a(&[1, 0, 1, 0, 3, 0, 2, 1]);
    let fork = a(&[1, 0, 2, 0, 1]);
    let bytes_before;
    {
        let k = Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("open");
        let vs = Vstream::new(&k);
        vs.insert(P1, &doc1(), vp(1, 1), vec![val(b"a"), val(b"b"), val(b"c")], Deposit::Undeclared)
            .expect("insert commits");
        vs.insert(P1, &pdoc(), vp(1, 1), vec![val(b"a"), val(b"b"), val(b"c")], declared())
            .expect("deposit commits");
        k.checkpoint().expect("checkpoint");
        vs.delete(P1, &doc1(), vp(1, 2), n(1)).expect("delete commits");
        vs.insert(P1, &doc2(), vp(1, 1), vec![val(b"x"), val(b"y"), val(b"z")], Deposit::Undeclared)
            .expect("the second draft takes three values");
        vs.rearrange(P1, &doc2(), &[vp(1, 1), vp(1, 2), vp(1, 4)])
            .expect("rearrange commits"); // pivot: x | y z → y z x
        seat_link(&k, &pdoc(), &link1).expect("seat commits");
        let (minted, _) = vs.version(PrincipalId(2), &pdoc(), None).expect("fork commits");
        assert_eq!(minted, fork);
        // A source deposit AFTER the fork: on replay the VersionSnapshot must
        // fold at its own journal slot and read pdoc as it was there, not as
        // the source ends up.
        vs.insert(P1, &pdoc(), vp(1, 4), vec![val(b"d")], declared())
            .expect("post-fork source deposit commits");
        // The shot: the edition's four positions by reference and doc1's
        // surviving `c` re-inserted as fresh identity — the member holds five.
        let readable = readable_by(PrincipalId(1));
        let (member, _) = vs
            .publish(
                P1,
                &pdoc(),
                Shot {
                    base: Some(base(&pdoc(), 4)),
                    draft: Some(doc1()),
                    runs: vec![shot_run(&pdoc(), &pca(1), 4), shot_run(&doc1(), &ca(3), 1)],
                },
                &readable,
            )
            .expect("the shot commits");
        assert_eq!(member, vdoc());
        let s = k.snapshot();
        bytes_before = bincode::serialize(s.world().m5()).expect("slice serializes");
    }
    let k = Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("reopen");
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(
        bincode::serialize(m5).expect("slice serializes"),
        bytes_before
    );
    assert_eq!(m5.content_count(&doc1()), n(2));
    assert_eq!(m5.point(&doc1(), &vp(1, 2)), Some(ca(3)));
    let d = m5.deletions(&doc1());
    let spans: Vec<Span> = d.iter().cloned().collect();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].start(), ca(2).tumbler());
    let got: Vec<Vec<u8>> = (1..=3).map(|i| read_v(&s, &doc2(), i)).collect();
    assert_eq!(
        got,
        vec![b"y".to_vec(), b"z".to_vec(), b"x".to_vec()],
        "the rearrangement replayed"
    );
    assert_eq!(m5.content_count(&pdoc()), n(4));
    assert_eq!(m5.link_count(&pdoc()), n(1));
    // The fork replayed at ITS slot: it holds what pdoc held at the fork
    // point, not what pdoc holds now. Byte-identity above would fail either
    // way; these say which value is the right one.
    assert_eq!(m5.content_count(&fork), n(3));
    assert_eq!(m5.point(&fork, &vp(1, 1)), Some(pca(1)));
    assert_eq!(m5.point(&fork, &vp(1, 3)), Some(pca(3)));
    assert_eq!(m5.point(&fork, &vp(1, 4)), None);
    // The shot replayed as one placement: the member holds the four by
    // reference and the fresh `c` under the edition's own content chain, and
    // the bare address floats to it.
    assert_eq!(m5.content_count(&vdoc()), n(5));
    assert_eq!(m5.point(&vdoc(), &vp(1, 5)), Some(pca(5)));
    assert_eq!(read_v(&s, &vdoc(), 5), b"c".to_vec());
    assert_eq!(reading_surface(s.world().m3(), &pdoc()), vdoc());
    // The recovered arrangement still drives edits.
    let vs = Vstream::new(&k);
    vs.insert(P1, &doc1(), vp(1, 3), vec![val(b"e")], Deposit::Undeclared)
        .expect("post-recovery insert commits");
}
