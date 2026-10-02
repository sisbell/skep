//! Which arrangement each op answers from: a declared deposit lands in the
//! head, a version of a pinned member forks the member, COPY reads as named.

use skep_arrangement::{reading_surface, CopyError, DeleteError, HasM5, InsertError, VSpec, Vstream};
use skep_namespace::{HasM3, PrincipalId};

use crate::common::*;

#[test]
fn a_declared_deposit_into_a_published_chain_lands_in_the_head_member_alone() {
    // PUB-2.65/2.66 (lane 3.2's ruling): once a head exists, a declared deposit
    // appends to the HEAD member's arrangement — named by the bare address,
    // by the head, or by a pinned member — and to nothing else; the atom's
    // identity is minted under the content chain of the address named; and
    // the in-place refusal on the chain stands as before. `version` of the
    // bare address then shares the HEAD's arrangement, not the pre-chain one.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    let (member1, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("the first member");
    assert_eq!(member1, vdoc());
    // Named by the bare address: minted under pdoc's content chain, placed
    // in member1.
    let (bare_start, _) = vs.insert(P1, &pdoc(), vp(1, 4), vec![val(b"z")], declared()).expect("deposit");
    assert_eq!(bare_start, pca(4));
    {
        let s = k.snapshot();
        let m5 = s.world().m5();
        assert_eq!(m5.content_count(&member1), n(4), "the head grew");
        assert_eq!(m5.point(&member1, &vp(1, 4)), Some(pca(4)));
        assert_eq!(m5.content_count(&pdoc()), n(3), "the pre-chain arrangement did not");
    }
    // Named by the head itself: minted under the member's content chain,
    // placed in it; judged fresh against the head's extent.
    let (head_start, _) = vs.insert(P1, &member1, vp(1, 5), vec![val(b"y")], declared()).expect("deposit");
    assert_eq!(head_start, vca(1));
    assert!(matches!(
        rejected(vs.insert(P1, &pdoc(), vp(1, 4), vec![val(b"q")], declared())),
        InsertError::PublishedTarget
    ), "ordinal 4 is arranged in the head: not a deposit shape");
    // A second member: `version` shares the HEAD's arrangement (five
    // positions), and the bare address floats to it.
    let (member2, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("the second member");
    {
        let s = k.snapshot();
        let m5 = s.world().m5();
        assert_eq!(m5.content_count(&member2), n(5));
        assert_eq!(
            m5.content_runs(&member2).collect::<Vec<_>>(),
            m5.content_runs(&member1).collect::<Vec<_>>()
        );
        assert_eq!(reading_surface(s.world().m3(), &pdoc()), member2);
    }
    // Named by the PINNED member1: the deposit lands in the head member2,
    // and member1 never grows (PUB-2.66).
    vs.insert(P1, &member1, vp(1, 6), vec![val(b"x")], declared()).expect("deposit named by a pinned member");
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(m5.content_count(&member1), n(5), "a pinned member's arrangement never grows");
    assert_eq!(m5.content_count(&member2), n(6), "the head's did");
    assert_eq!(read_v(&s, &member2, 6), b"x".to_vec());
    // The in-place refusal still holds on every address of the chain.
    assert!(matches!(rejected(vs.delete(P1, &pdoc(), vp(1, 1), n(1))), DeleteError::PublishedTarget));
    assert!(matches!(rejected(vs.delete(P1, &member2, vp(1, 1), n(1))), DeleteError::PublishedTarget));
}

#[test]
fn a_version_of_a_pinned_member_forks_the_member_not_the_head() {
    // PUB-2.50 on `version`'s snapshot: a version address answers its own
    // member forever, so a fork of a PINNED member shares that member's
    // arrangement — never the head's, where a declared deposit naming the
    // member lands. This is the one address at which the reading surface and
    // the deposit surface differ, and the fork takes the reader's.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    let (member1, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("the first member");
    vs.insert(P1, &pdoc(), vp(1, 4), vec![val(b"z")], declared())
        .expect("lands in the head member1");
    let (member2, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("the second member");
    vs.insert(P1, &pdoc(), vp(1, 5), vec![val(b"y")], declared())
        .expect("lands in the head member2");
    {
        let s = k.snapshot();
        assert_eq!(s.world().m5().content_count(&member1), n(4), "member1 is pinned at four");
        assert_eq!(s.world().m5().content_count(&member2), n(5), "the head grew to five");
    }
    let (daughter, _) = vs.version(PrincipalId(1), &member1, None).expect("a pinned member's daughter");
    assert_eq!(daughter, a(&[1, 0, 1, 0, 3, 1, 1]));
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(
        m5.content_runs(&daughter).collect::<Vec<_>>(),
        m5.content_runs(&member1).collect::<Vec<_>>(),
        "the member it names, not the head"
    );
}

#[test]
fn copy_reads_a_published_source_at_the_address_named_not_at_its_head() {
    // wire.md's head-float section pins COPY's source spans UNFLOATED, the
    // other side of the seam `version`'s snapshot sits on: a spec naming a
    // bare published document with members resolves against the document's
    // own pre-chain arrangement, never the trunk head its readers answer from.
    let k = mem_kernel();
    let vs = deposit_abc(&k); // pdoc: a b c
    let (member1, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("the first member");
    vs.insert(P1, &pdoc(), vp(1, 4), vec![val(b"z")], declared())
        .expect("lands in the head member1"); // member1: a b c z; pdoc: a b c
    assert_eq!(reading_surface(k.snapshot().world().m3(), &pdoc()), member1);
    // Named by the bare address: the pre-chain arrangement's three positions,
    // the span's fourth clipped away — not the head's four.
    vs.copy(P1, &doc1(), vp(1, 1), &[VSpec { source: pdoc(), span: vspan(1, 1, 4) }])
        .expect("a copy naming the bare address commits");
    assert_eq!(k.snapshot().world().m5().content_count(&doc1()), n(3));
    // Named by the head: its four.
    vs.copy(P1, &doc2(), vp(1, 1), &[VSpec { source: member1, span: vspan(1, 1, 4) }])
        .expect("a copy naming the head commits");
    assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(4));
}

#[test]
fn copy_refuses_as_empty_a_bare_edition_whose_content_lives_in_its_head() {
    // The seam's sharpest edge, and the reason a caller names the head: every
    // reader of the bare address answers the head's one position, while COPY,
    // naming that address, is told its source is empty.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    let (head, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("an empty-source member");
    vs.insert(P1, &pdoc(), vp(1, 1), vec![val(b"z")], declared())
        .expect("lands in the head");
    let s = k.snapshot();
    assert_eq!(s.world().m5().content_count(&head), n(1));
    assert_eq!(reading_surface(s.world().m3(), &pdoc()), head, "readers answer the head");
    let before = k.current_seq();
    assert!(matches!(
        rejected(vs.copy(P1, &doc1(), vp(1, 1), &[VSpec { source: pdoc(), span: vspan(1, 1, 1) }])),
        CopyError::EmptySource
    ));
    assert_eq!(k.current_seq(), before, "the refusal commits nothing");
}
