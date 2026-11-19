//! M2-driven recovery: the slice survives checkpoint load and tail replay,
//! byte for byte.

use skep_address::Span;
use skep_arrangement::{
    reading_surface, seat_link, Deposit, DraftBase, HasM5, Marker, SetArrangement, SetMerge, Shot,
    Vstream,
};
use skep_kernel::Kernel;
use skep_namespace::{HasM3, PrincipalId};
use tempfile::tempdir;

use crate::common::*;

#[test]
fn the_arrangement_survives_durable_recovery_by_checkpoint_and_replay() {
    // §10: M5 owns no recovery machinery — M2 loads the checkpoint
    // (deserializing the slice) and replays the tail through apply → apply_m5.
    // The draft's insert, the edition's deposit, a staging draft of the
    // edition and a merge landed in it ride the checkpoint path; the merge
    // taken out and put back, the delete, the rearrangement, the seat, the
    // fork, the post-fork source deposit and the shot ride the replay path —
    // every `M5Rec` variant among them; the recovered slice is
    // byte-identical.
    //
    // The fork is the CROSS-OWNER one (principal 2's copy of the edition):
    // an owned fork would be the edition's first member, and the deposit
    // after it would then land in that member rather than in the source
    // (PUB-2.66) — the source-changes-after-the-fork case this test is about
    // needs a source that still takes deposits itself.
    let dir = tempdir().expect("tempdir");
    let link1 = a(&[1, 0, 1, 0, nth_doc(3), 0, 2, 1]);
    let fork = a(&[1, 0, 2, 0, 1]);
    let bytes_before;
    let arranged_before;
    let staged;
    let landed_at;
    {
        let k = Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("open");
        let vs = Vstream::new(&k);
        vs.insert(P1, &doc1(), vp(1, 1), vec![val(b"a"), val(b"b"), val(b"c")], Deposit::Undeclared, now(&k))
            .expect("insert commits");
        vs.insert(P1, &pdoc(), vp(1, 1), vec![val(b"a"), val(b"b"), val(b"c")], declared(), now(&k))
            .expect("deposit commits");
        // The staging draft of the memberless edition, and a merge landed in
        // it: the draft set to the edition's last two positions, its base the
        // edition at three, the marker stamped at the landing's own commit.
        (staged, _) = vs.stage(PrincipalId(1), &pdoc()).expect("the staging draft");
        let merged = |at| SetArrangement {
            runs: vec![shot_run(&pdoc(), &pca(2), 2)],
            head: Some(base(&pdoc(), 3)),
            base: Some(base(&pdoc(), 3)),
            merge: Some(SetMerge { sides: vec![doc2()], at }),
        };
        (landed_at, _) = vs.set_arrangement(P1, &staged, &merged(None), now(&k)).expect("the landing");
        k.checkpoint().expect("checkpoint");
        // The merge taken out — the edition's text set back, the marker
        // cleared and its stamp kept — and put back at the landing's
        // position: a base record and a restore record, both replayed.
        let taken_out = SetArrangement {
            runs: vec![shot_run(&pdoc(), &pca(1), 3)],
            head: None,
            base: Some(base(&pdoc(), 3)),
            merge: None,
        };
        vs.set_arrangement(P1, &staged, &taken_out, now(&k)).expect("the merge taken out");
        vs.set_arrangement(P1, &staged, &merged(Some(landed_at)), now(&k)).expect("the merge put back");
        vs.delete(P1, &doc1(), vp(1, 2), n(1), now(&k)).expect("delete commits");
        vs.insert(P1, &doc2(), vp(1, 1), vec![val(b"x"), val(b"y"), val(b"z")], Deposit::Undeclared, now(&k))
            .expect("the second draft takes three values");
        vs.rearrange(P1, &doc2(), &[vp(1, 1), vp(1, 2), vp(1, 4)], now(&k))
            .expect("rearrange commits"); // pivot: x | y z → y z x
        seat_link(&k, &pdoc(), &link1).expect("seat commits");
        let (minted, _) = vs.version(PrincipalId(2), &pdoc(), None).expect("fork commits");
        assert_eq!(minted, fork);
        // A source deposit AFTER the fork: on replay the VersionSnapshot must
        // fold at its own journal slot and read pdoc as it was there, not as
        // the source ends up.
        vs.insert(P1, &pdoc(), vp(1, 4), vec![val(b"d")], declared(), now(&k))
            .expect("post-fork source deposit commits");
        // The shot: the edition's four positions by reference and doc1's
        // surviving `c` re-inserted as fresh identity — the member holds five.
        let readable = readable_by(PrincipalId(1));
        let (member, _) = vs
            .publish(
                P1,
                &pdoc(),
                &Shot {
                    base: Some(base(&pdoc(), 4)),
                    draft: Some(doc1()),
                    also: vec![],
                    keep_base: false,
                    runs: vec![shot_run(&pdoc(), &pca(1), 4), shot_run(&doc1(), &ca(3), 1)],
                },
                &readable,
            )
            .expect("the shot commits");
        assert_eq!(member, vdoc());
        let s = k.snapshot();
        bytes_before = bincode::serialize(s.world().m5()).expect("slice serializes");
        // The arranged-at positions (skep #442) as the live fold left them:
        // doc1's and pdoc's first entries rode the checkpoint path, the
        // delete, the pivot, the fork, the post-fork deposit, the shot and
        // the staging draft's two settings the replay path — each the
        // position its own commit answered.
        arranged_before = [doc1(), doc2(), pdoc(), fork.clone(), vdoc(), staged.clone()]
            .map(|d| s.world().m5().arranged_at(&d));
        assert!(arranged_before.iter().all(Option::is_some), "{arranged_before:?}");
    }
    let k = Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("reopen");
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(
        bincode::serialize(m5).expect("slice serializes"),
        bytes_before
    );
    assert_eq!(
        [doc1(), doc2(), pdoc(), fork.clone(), vdoc(), staged.clone()].map(|d| m5.arranged_at(&d)),
        arranged_before,
        "the arranged-at positions survive the checkpoint and the replay alike"
    );
    // The landing's marker, taken out and put back on the replay path,
    // stands as the landing stamped it: its position the landing's, never
    // the restore's own, its one stamp beside it.
    let marker = Marker { sides: vec![doc2()], head: pdoc(), head_copied: n(3), at: landed_at };
    assert_eq!(
        m5.draft_base(&staged),
        Some(&DraftBase {
            base: pdoc(),
            extent: n(3),
            source: pdoc(),
            merge: Some(marker.clone()),
            stamped: vec![marker],
        }),
        "the restore replayed with the marker it carried"
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
    // The count the fork's copy took, noted at the same slot: three, though
    // pdoc holds four by now — and the staging draft's, carried by the
    // checkpoint, three as well (skep #1111).
    assert_eq!(m5.fork_source_copied(&fork), Some(&n(3)), "the fork's copy, replayed at its slot");
    assert_eq!(
        m5.fork_source_copied(&staged),
        Some(&n(3)),
        "the staging draft's, off the checkpoint"
    );
    // The shot replayed as one placement: the member holds the four by
    // reference and the fresh `c` under the edition's own content chain, and
    // the bare address floats to it.
    assert_eq!(m5.content_count(&vdoc()), n(5));
    assert_eq!(m5.point(&vdoc(), &vp(1, 5)), Some(pca(5)));
    assert_eq!(read_v(&s, &vdoc(), 5), b"c".to_vec());
    assert_eq!(reading_surface(s.world().m3(), &pdoc()), vdoc());
    // The shot's terms replayed with its record: the base its request named,
    // the memberless edition, at the extent its copy took.
    let terms = m5.shot_terms(&vdoc()).expect("the replayed shot carries its terms");
    assert_eq!((terms.base.as_ref(), terms.base_extent.as_ref()), (Some(&pdoc()), Some(&n(4))));
    // The recovered arrangement still drives edits.
    let vs = Vstream::new(&k);
    vs.insert(P1, &doc1(), vp(1, 3), vec![val(b"e")], Deposit::Undeclared, now(&k))
        .expect("post-recovery insert commits");
}
