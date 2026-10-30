//! THE FAMILY (the Nelson way, B3-S10; the link-sets design §5.7, THE
//! REQUEST): one shot re-minting the identity of more than one private draft
//! of the caller's own — `draft`, the rendering draft, and `also`, the
//! family's other drafts — every run of a named draft fresh identity in the
//! member, each draft identity once across them, the address forms agreeing
//! over two homes as the body spells them, `also` outside the preimage, and
//! the re-insert count over both drafts' distinct positions.

use skep_address::{document_of, Address};
use skep_arrangement::{trunk_of, Caller, Deposit, HasM5, Run, SegmentRun, Shot, ShotRun, Vstream};
use skep_content::{ContentStore, HasContent};
use skep_namespace::{HasM3, PrincipalId};

use crate::common::*;

/// doc2's content element at `ordinal` (length 8) — the family's other
/// draft's own identity.
fn ca2(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 2, 0, 1, ordinal])
}

/// Leave doc2 — P1's second private draft, the family's other draft —
/// holding `x`, `y` at ca2(1..2).
fn insert_xy(vs: &Vstream<'_, World>) {
    vs.insert(P1, &doc2(), vp(1, 1), vec![val(b"x"), val(b"y")], Deposit::Undeclared)
        .expect("doc2 holds x y");
}

/// A run of `width` positions from `start`.
fn run(start: &Address, width: u32) -> Run {
    Run::new(start.clone(), n(width)).expect("a run")
}

/// A family shot off the edition's three: the rendering draft doc1, `also`
/// as given, the runs as given.
fn family(also: Vec<Address>, runs: Vec<ShotRun>) -> Shot {
    Shot { base: Some(base(&pdoc(), 3)), draft: Some(doc1()), also, runs }
}

/// One item of a shot's signed body as it spells the address form: a
/// position of a VALUE run by its value, a WINDOW by its run.
#[derive(Debug, PartialEq)]
enum Spelled {
    Value(Vec<u8>),
    Window(Run),
}

/// `form` as the signed body spells it, each value run's values read off
/// `content`.
fn spelled(form: &[SegmentRun], content: &ContentStore) -> Vec<Spelled> {
    let mut out = Vec::new();
    for segment_run in form {
        match segment_run {
            SegmentRun::Value(run) => out.extend(run.addrs().map(|a| {
                let value = content.value_at(a.tumbler()).expect("a value run's position holds a value");
                Spelled::Value(value.as_bytes().to_vec())
            })),
            SegmentRun::Window(run) => out.push(Spelled::Window(run.clone())),
        }
    }
    out
}

#[test]
fn a_shot_naming_also_re_inserts_the_other_drafts_runs_as_fresh_identity() {
    // The family rule's one spelling: `named_drafts` is the rendering draft
    // then each of `also`, `is_draft_native` the test over them, and the
    // runs a shot re-inserts are the runs of every named draft, per draft
    // through `reinserted_runs_of`. The commit re-inserts doc2's words as it
    // re-inserts doc1's: fresh identity under the edition's own I-space, one
    // stretch apiece, so no address of either draft survives in the member
    // and the member reads every placed byte.
    let k = mem_kernel();
    let vs = deposit_abc(&k); // pdoc: a b c at pca(1..3), memberless
    insert_abc(&k); // doc1, the rendering draft: a b c at ca(1..3)
    insert_xy(&vs); // doc2, the family's other draft: x y at ca2(1..2)
    let shot = family(
        vec![doc2()],
        vec![shot_run(&pdoc(), &pca(1), 3), shot_run(&doc1(), &ca(1), 3), shot_run(&doc2(), &ca2(1), 2)],
    );
    assert_eq!(shot.named_drafts().collect::<Vec<_>>(), vec![doc1(), doc2()], "the rendering draft first, then `also`");
    assert!(shot.is_draft_native(&doc1()) && shot.is_draft_native(&doc2()));
    assert!(!shot.is_draft_native(&pdoc()), "the document's own I-space is no draft's");
    assert_eq!(
        shot.reinserted_runs().cloned().collect::<Vec<_>>(),
        vec![run(&ca(1), 3), run(&ca2(1), 2)],
        "both drafts' runs, in the order given"
    );
    assert_eq!(shot.reinserted_runs_of(&doc1()).cloned().collect::<Vec<_>>(), vec![run(&ca(1), 3)]);
    assert_eq!(shot.reinserted_runs_of(&doc2()).cloned().collect::<Vec<_>>(), vec![run(&ca2(1), 2)]);
    assert_eq!(shot.reinserted_runs_of(&pdoc()).count(), 0, "a document that is no named draft has no re-inserted run");
    assert_eq!(shot.reinserted_values(), n(5), "both drafts' distinct positions");
    let stored = k.snapshot().world().content().len();
    let (member, _) = vs
        .publish(P1, &pdoc(), &shot, &readable_by(PrincipalId(1)))
        .expect("the family shot commits");
    let s = k.snapshot();
    assert_eq!(s.world().content().len() - stored, 2, "two stretches: doc1's a b c and doc2's x y, each minted once");
    assert_eq!(
        s.world().m3().next_content_address(&pdoc()),
        Some(pca(9)),
        "five fresh identities past the edition's three, nothing else minted under its chain"
    );
    assert_eq!(
        bytes_of(&s, &member),
        [b"a", b"b", b"c", b"a", b"b", b"c", b"x", b"y"].map(|b| b.to_vec()).to_vec(),
        "the member reads every placed byte"
    );
    assert_eq!(
        content_runs_of(&s, &member),
        vec![run(&pca(1), 8)],
        "one run: the edition's own three and the two drafts' fresh identity, I-adjacent"
    );
    for placed in s.world().m5().content_runs(&member) {
        assert_eq!(
            document_of(placed.i_start()).map(|d| trunk_of(&d)),
            Some(pdoc()),
            "no address of either draft survives in the member"
        );
    }
    assert_eq!(bytes_of(&s, &doc1()), [b"a", b"b", b"c"].map(|b| b.to_vec()).to_vec(), "doc1 untouched");
    assert_eq!(bytes_of(&s, &doc2()), [b"x", b"y"].map(|b| b.to_vec()).to_vec(), "doc2 untouched");
}

#[test]
fn an_identity_two_named_drafts_share_is_minted_once_and_placed_by_reference_after() {
    // The alternative holds the staging draft's words BY IDENTITY (a
    // placement by identity into doc2 of doc1's `b c`) and words of its own.
    // A shot rendering doc1's `a b c` and then the alternative's `b c` names
    // doc1's identity twice: EACH DRAFT IDENTITY ONCE PER SHOT holds across
    // the family — minted at the first run, placed by reference at the
    // second — and doc2's own `x` is minted once beside it.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    insert_abc(&k); // doc1: a b c at ca(1..3)
    vs.reinstate(P1, &doc2(), vp(1, 1), &[shot_run(&doc1(), &ca(2), 2)])
        .expect("doc2 holds doc1's b c by identity");
    vs.insert(P1, &doc2(), vp(1, 3), vec![val(b"x")], Deposit::Undeclared)
        .expect("doc2 holds x of its own at ca2(1)");
    let shot = family(
        vec![doc2()],
        vec![
            shot_run(&pdoc(), &pca(1), 3),
            shot_run(&doc1(), &ca(1), 3),
            shot_run(&doc1(), &ca(2), 2), // the alternative's copy: the same identity
            shot_run(&doc2(), &ca2(1), 1),
        ],
    );
    assert_eq!(shot.reinserted_values(), n(4), "a b c once, and x: the shared identity counted once");
    let stored = k.snapshot().world().content().len();
    let (member, _) = vs
        .publish(P1, &pdoc(), &shot, &readable_by(PrincipalId(1)))
        .expect("the family shot commits");
    let s = k.snapshot();
    assert_eq!(s.world().content().len() - stored, 2, "two stretches: a b c, and x — the shared b c written once");
    assert_eq!(s.world().m3().next_content_address(&pdoc()), Some(pca(8)));
    assert_eq!(
        content_runs_of(&s, &member),
        vec![run(&pca(1), 6), run(&pca(5), 3)],
        "the fresh a b c merged with the edition's own; then b c by reference to it and x, I-adjacent, as one run"
    );
    assert_eq!(
        bytes_of(&s, &member),
        [b"a", b"b", b"c", b"a", b"b", b"c", b"b", b"c", b"x"].map(|b| b.to_vec()).to_vec()
    );
}

#[test]
fn the_address_forms_agree_as_the_body_spells_them_over_two_homes() {
    // l6-A4 over the family: the request names the edition's own `a`, doc2's
    // `x y`, a window onto the sub-account's draft and doc1's `a b`; the
    // member holds the two drafts' text at fresh addresses under the
    // edition's own I-space. Spelled — a value run by its values, a window
    // by its run — the two sides read alike, the window in the same V-place.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    insert_abc(&k);
    insert_xy(&vs);
    let subdoc = a(&[1, 0, 1, 1, 0, 1]);
    let (w, _) = vs
        .insert(Caller::Principal(PrincipalId(3)), &subdoc, vp(1, 1), vec![val(b"w")], Deposit::Undeclared)
        .expect("the sub-account's draft holds w");
    let shot = family(
        vec![doc2()],
        vec![
            shot_run(&pdoc(), &pca(1), 1),
            shot_run(&doc2(), &ca2(1), 2),
            shot_run(&subdoc, &w, 1),
            shot_run(&doc1(), &ca(1), 2),
        ],
    );
    let requested = shot.address_form(&pdoc());
    let anyone = |_: &World, _: &Address| true;
    let (member, _) = vs.publish(P1, &pdoc(), &shot, &anyone).expect("the shot commits");
    let s = k.snapshot();
    let (m5, content) = (s.world().m5(), s.world().content());
    let terms = m5.shot_terms(&member).expect("the member carries its terms");
    let at_member = m5.address_form_of(&member, &terms.placed);
    assert_eq!(requested.len(), 4, "{requested:?}");
    assert_eq!(at_member.len(), 4, "{at_member:?}");
    assert_eq!(requested[1], SegmentRun::Value(run(&ca2(1), 2)), "doc2's run is a value run of the request");
    assert_eq!(at_member[1], SegmentRun::Value(run(&pca(4), 2)), "and fresh identity at the member");
    assert_eq!(requested[3], SegmentRun::Value(run(&ca(1), 2)));
    assert_eq!(at_member[3], SegmentRun::Value(run(&pca(6), 2)));
    let spelled_at_member = spelled(&at_member, content);
    assert_eq!(spelled(&requested, content), spelled_at_member, "spelled, the two sides agree");
    assert_eq!(
        spelled_at_member,
        vec![
            Spelled::Value(b"a".to_vec()),
            Spelled::Value(b"x".to_vec()),
            Spelled::Value(b"y".to_vec()),
            Spelled::Window(run(&w, 1)),
            Spelled::Value(b"a".to_vec()),
            Spelled::Value(b"b".to_vec()),
        ]
    );
}

#[test]
fn also_lies_outside_the_preimage_the_body_differing_only_where_runs_became_values() {
    // The body spells the member and names no draft: a shot WITH `also`
    // differs from the same shot WITHOUT it exactly in the runs that became
    // values — doc2's run a value stretch here, a window there — and a shot
    // naming no draft at all makes a window of both drafts' runs. Request
    // arithmetic, reading no world.
    let with = family(
        vec![doc2()],
        vec![
            shot_run(&pdoc(), &pca(1), 1),
            shot_run(&doc1(), &ca(1), 2),
            shot_run(&doc2(), &ca2(1), 2),
            shot_run(&doc1(), &ca(3), 1),
        ],
    );
    let without = Shot { also: vec![], ..with.clone() };
    let (f_with, f_without) = (with.address_form(&pdoc()), without.address_form(&pdoc()));
    assert_eq!((f_with.len(), f_without.len()), (4, 4));
    for (k, (a, b)) in f_with.iter().zip(&f_without).enumerate() {
        if k == 2 {
            assert_eq!(a, &SegmentRun::Value(run(&ca2(1), 2)), "doc2's run: a value with `also`");
            assert_eq!(b, &SegmentRun::Window(run(&ca2(1), 2)), "a window without it");
        } else {
            assert_eq!(a, b, "every other segment the same: {k}");
        }
    }
    let draftless = Shot { draft: None, also: vec![], ..with.clone() };
    assert!(
        draftless.address_form(&pdoc())[1..].iter().all(|s| matches!(s, SegmentRun::Window(_))),
        "with no draft named, both drafts' runs are windows"
    );
    assert_eq!(draftless.reinserted_values(), n(0));
}

#[test]
fn the_reinsert_count_is_the_distinct_positions_over_every_named_draft() {
    // `reinserted_values` merges each run's I-extent: a position two runs
    // name counts once, and the same ordinals on two drafts' chains are two
    // addresses, so each draft's positions count on their own.
    let shot = family(
        vec![doc2()],
        vec![
            shot_run(&doc1(), &ca(1), 3),
            shot_run(&doc1(), &ca(2), 2),
            shot_run(&doc2(), &ca2(1), 2),
            shot_run(&doc2(), &ca2(2), 2),
            shot_run(&doc2(), &ca2(1), 1),
        ],
    );
    assert_eq!(shot.reinserted_values(), n(6), "doc1's three and doc2's three, overlaps counted once");
    let same_ordinals = family(vec![doc2()], vec![shot_run(&doc1(), &ca(1), 2), shot_run(&doc2(), &ca2(1), 2)]);
    assert_eq!(same_ordinals.reinserted_values(), n(4), "the same ordinals on two chains are distinct addresses");
    let one_draft = Shot { also: vec![], ..shot.clone() };
    assert_eq!(one_draft.reinserted_values(), n(3), "without `also`, doc2's runs are windows and count nothing");
}
