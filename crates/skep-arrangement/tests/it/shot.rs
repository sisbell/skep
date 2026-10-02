//! The publish shot (PUB round 2, lane 3.2): the member it appends from the
//! client's runs, the windows it keeps, the deposits it carries, the birth
//! extent and terms it records, and its address form on both sides.

use skep_address::{Address, SpanSet};
use skep_arrangement::{
    reading_surface, seat_link, trunk_head, Base, Deposit, HasM5, M5State, PlacedSegment,
    PublishError, Run, Shot, ShotTerms, VSpec, Vstream,
};
use skep_content::HasContent;
use skep_namespace::{HasM3, PrincipalId};

use crate::common::*;

/// The addresses a document's content runs start at, in V-order — what "no
/// address of the draft" is asserted over.
fn run_starts(m5: &M5State, doc: &Address) -> Vec<Address> {
    m5.content_runs(doc).map(|r| r.i_start().clone()).collect()
}

#[test]
fn a_shot_appends_the_next_trunk_member_from_the_clients_runs() {
    // PUB-2.33/2.37/2.40/2.41: the ordinary shot. The staging draft (doc1)
    // holds the edition's three positions by `copy` (PUB-2.27) and two
    // draft-native bytes; the client supplies that whole arrangement as
    // runs; the member born is the trunk's first, holding the edition's own
    // addresses by reference and the draft-native text as FRESH identity
    // under the edition's own I-space — no address of the draft survives.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    vs.copy(P1, &doc1(), vp(1, 1), &[VSpec { source: pdoc(), span: vspan(1, 1, 3) }])
        .expect("the staging copy shares identity");
    vs.insert(P1, &doc1(), vp(1, 4), vec![val(b"d"), val(b"e")], Deposit::Undeclared)
        .expect("the stager types");
    // A home link seated in the base: the shot places content alone, so it
    // stays the base's (CL-OWN, PUB-2.12) and the member is born with an
    // empty link subspace.
    seat_link(&k, &pdoc(), &a(&[1, 0, 1, 0, 3, 0, 2, 1]))
        .expect("a home link seats into the edition");
    let readable = readable_by(PrincipalId(1));
    let shot = Shot {
        base: Some(base(&pdoc(), 3)),
        draft: Some(doc1()),
        runs: vec![shot_run(&pdoc(), &pca(1), 3), shot_run(&doc1(), &ca(1), 2)],
    };
    let before = k.current_seq();
    let (member, seq) = vs.publish(P1, &pdoc(), shot, &readable).expect("the shot commits");
    assert_eq!(member, vdoc(), "the chain's first member");
    assert_eq!(seq, k.current_seq(), "one commit");
    assert!(seq > before);
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert!(s.world().m3().published(&member), "born published (PUB-2.5)");
    assert_eq!(m5.content_count(&member), n(5));
    assert_eq!(m5.link_count(&member), n(0), "the shot places content alone");
    assert_eq!(m5.link_count(&pdoc()), n(1), "the base keeps its link");
    // The re-inserted text continues the edition's own content chain, so it
    // coalesces with the by-reference run: ONE run under pdoc.
    assert_eq!(
        m5.content_runs(&member).cloned().collect::<Vec<_>>(),
        vec![Run::new(pca(1), n(5)).expect("a run")]
    );
    assert_eq!(read_v(&s, &member, 4), b"d".to_vec());
    assert_eq!(read_v(&s, &member, 5), b"e".to_vec());
    assert!(
        run_starts(m5, &member).iter().all(|a| skep_arrangement::trunk_of(
            &skep_address::document_of(a).expect("an element")
        ) == pdoc()),
        "nothing in the member resolves through the draft (PUB-2.41)"
    );
    // The fresh identities are R-recorded for the member (J1★), as COPY's
    // by-reference placements are — read the way FINDDOCSCONTAINING reads R
    // (§9): `docs_ever_containing` is the overlap SUPERSET, and it admits an
    // ADJACENT recorded span — the edition's and the draft's `[pca1, pca4)`
    // touches the fresh `[pca4, pca6)` — so the member is asserted a
    // candidate rather than the only one, and the present-containment
    // narrowing `project` picks it out alone: neither the edition's pre-chain
    // arrangement nor the draft arranges a fresh address.
    let fresh = SpanSet::singleton(Run::new(pca(4), n(2)).expect("a run").iextent());
    let candidates = m5.docs_ever_containing(&fresh);
    assert!(candidates.contains(&member), "the member placed the fresh run: {candidates:?}");
    assert!(!m5.project(&member, &fresh).is_empty(), "the member arranges the fresh run");
    assert!(m5.project(&pdoc(), &fresh).is_empty(), "the pre-chain arrangement holds no fresh address");
    assert!(m5.project(&doc1(), &fresh).is_empty(), "nor does the draft");
    // Head-float: the bare address now answers the member; the draft and the
    // edition's own arrangement are what they were.
    assert_eq!(trunk_head(s.world().m3(), &pdoc()), Some(member.clone()));
    assert_eq!(reading_surface(s.world().m3(), &pdoc()), member);
    assert_eq!(m5.content_count(&pdoc()), n(3));
    assert_eq!(m5.content_count(&doc1()), n(5));
}

#[test]
fn a_shot_places_the_runs_the_client_rendered_not_what_the_draft_holds_at_commit() {
    // PUB-8.1: the member's arrangement comes from the CLIENT-SUPPLIED runs
    // "and from nothing any draft holds at commit" — draft-native bytes are
    // read at the draft's addresses, "a byte read, never an arrangement
    // read". So a draft edited between the render and the shot changes
    // nothing the shot places: the client rendered `a b c`, the stager then
    // un-arranged `b`, and the member is still born `a b c`, `b` re-inserted
    // from the bytes the permascroll keeps (P0). Judged against what the
    // draft arranges at commit — for existence or for the re-insert — the
    // shot would be refused `DanglingSource`, or born `a c`.
    let k = mem_kernel();
    let vs = deposit_abc(&k); // pdoc: a b c, memberless
    insert_abc(&k); // the draft doc1: a b c at ca(1..3)
    vs.delete(P1, &doc1(), vp(1, 2), n(1))
        .expect("the stager un-arranges b after the render");
    let (member, _) = vs
        .publish(
            P1,
            &pdoc(),
            Shot {
                base: Some(base(&pdoc(), 3)),
                draft: Some(doc1()),
                runs: vec![shot_run(&doc1(), &ca(1), 3)],
            },
            &readable_by(PrincipalId(1)),
        )
        .expect("the shot places what the client rendered");
    let s = k.snapshot();
    let got: Vec<Vec<u8>> = (1..=3).map(|i| read_v(&s, &member, i)).collect();
    assert_eq!(got, vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    assert_eq!(s.world().m5().content_count(&member), n(3));
    assert_eq!(
        s.world().m5().content_count(&doc1()),
        n(2),
        "the draft stays as its stager left it"
    );
}

#[test]
fn a_window_stays_a_window_and_a_daughter_lands_under_its_base() {
    // PUB-2.40 (c), PUB-2.39/2.44/2.55: a run onto ANOTHER document stays a
    // window answering its origin; two shots staged off one head both
    // commit, the first advancing the trunk and the second landing as the
    // head's DAUGHTER in the nested form — and the bare address floats to
    // the trunk alone (PUB-2.53).
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    let readable = readable_by(PrincipalId(1));
    let (member1, _) = vs
        .publish(
            P1,
            &pdoc(),
            Shot { base: Some(base(&pdoc(), 3)), draft: None, runs: vec![shot_run(&pdoc(), &pca(1), 3)] },
            &readable,
        )
        .expect("the first member");
    assert_eq!(member1, vdoc());
    // The window's origin: doc2, P1's own private draft (readable to P1).
    vs.insert(P1, &doc2(), vp(1, 1), vec![val(b"w")], Deposit::Undeclared).expect("doc2 holds a byte");
    let w = a(&[1, 0, 1, 0, 2, 0, 1, 1]);
    let staged = |member: &Address| Shot {
        base: Some(base(member, 3)),
        draft: None,
        runs: vec![shot_run(&pdoc(), &pca(1), 3), shot_run(&doc2(), &w, 1)],
    };
    // Shot A off the head member1 → the trunk's next member.
    let (member2, _) = vs.publish(P1, &pdoc(), staged(&member1), &readable).expect("A commits");
    assert_eq!(member2, a(&[1, 0, 1, 0, 3, 2]));
    // Shot B, ALSO staged off member1, after A landed → member1's daughter,
    // and no refusal (PUB-2.38: the gesture never fails for want of a base).
    let (daughter, _) = vs.publish(P1, &pdoc(), staged(&member1), &readable).expect("B commits");
    assert_eq!(daughter, a(&[1, 0, 1, 0, 3, 1, 1]), "the nested form (PUB-2.55)");
    let s = k.snapshot();
    let m5 = s.world().m5();
    for member in [&member2, &daughter] {
        assert_eq!(m5.content_count(member), n(4));
        assert_eq!(m5.point(member, &vp(1, 4)), Some(w.clone()), "the window answers doc2");
        assert_eq!(read_v(&s, member, 4), b"w".to_vec());
    }
    // The bare address floats to the trunk head; the daughter is reached by
    // its own address alone; every version address answers itself.
    assert_eq!(reading_surface(s.world().m3(), &pdoc()), member2);
    assert_eq!(trunk_head(s.world().m3(), &daughter), Some(member2.clone()));
    assert_eq!(reading_surface(s.world().m3(), &daughter), daughter);
    assert_eq!(reading_surface(s.world().m3(), &member1), member1);
    // And a member is itself a base: a shot off the daughter nests again.
    let (granddaughter, _) = vs
        .publish(P1, &pdoc(), staged(&daughter), &readable)
        .expect("nests again");
    assert_eq!(granddaughter, a(&[1, 0, 1, 0, 3, 1, 1, 1]));
    // A shot may name a member as `doc`: it is the document's shot.
    let (member3, _) = vs
        .publish(P1, &member2, staged(&member2), &readable)
        .expect("named by a member");
    assert_eq!(member3, a(&[1, 0, 1, 0, 3, 3]));
}

#[test]
fn a_declared_deposit_in_the_staging_interval_is_carried_by_the_shot() {
    // PUB-2.42/2.43/2.45 (F22): a declared deposit lands at the HEAD's fresh
    // position while a draft is staged from it; the shot supplies the whole
    // rendered arrangement with the extent the copy took, and the composite
    // APPENDS the deposit the render post-dates — no positional apply,
    // nothing lost.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    let readable = readable_by(PrincipalId(1));
    let (member1, _) = vs
        .publish(
            P1,
            &pdoc(),
            Shot { base: Some(base(&pdoc(), 3)), draft: None, runs: vec![shot_run(&pdoc(), &pca(1), 3)] },
            &readable,
        )
        .expect("the head");
    // The stager copies the head's three positions and drops the middle one.
    vs.copy(P1, &doc1(), vp(1, 1), &[VSpec { source: member1.clone(), span: vspan(1, 1, 3) }])
        .expect("staged");
    vs.delete(P1, &doc1(), vp(1, 2), n(1)).expect("the stager un-arranges b");
    // The interval's deposit: into the BARE address, landing in the head.
    let (start, _) = vs
        .insert(P1, &pdoc(), vp(1, 4), vec![val(b"z")], declared())
        .expect("a deposit at the head's fresh position");
    assert_eq!(start, pca(4), "minted under the document's own content chain");
    assert_eq!(k.snapshot().world().m5().content_count(&member1), n(4), "it landed in the HEAD (PUB-2.66)");
    assert_eq!(k.snapshot().world().m5().content_count(&pdoc()), n(3), "not in the pre-chain arrangement");
    // The shot: the client's rendering (a, c) with the extent its copy took.
    let (member2, _) = vs
        .publish(
            P1,
            &pdoc(),
            Shot {
                base: Some(base(&member1, 3)),
                draft: None,
                runs: vec![shot_run(&pdoc(), &pca(1), 1), shot_run(&pdoc(), &pca(3), 1)],
            },
            &readable,
        )
        .expect("the shot commits");
    let s = k.snapshot();
    let got: Vec<Vec<u8>> = (1..=3).map(|i| read_v(&s, &member2, i)).collect();
    assert_eq!(got, vec![b"a".to_vec(), b"c".to_vec(), b"z".to_vec()], "the delta, then the deposit");
    assert_eq!(s.world().m5().content_count(&member2), n(3));
    // A pinned base never grows, so a daughter shot with the full extent
    // carries nothing extra; an extent one past the base's count is refused.
    let daughter_shot = Shot {
        base: Some(base(&member1, 4)),
        draft: None,
        runs: vec![shot_run(&pdoc(), &pca(1), 4)],
    };
    let (daughter, _) = vs.publish(P1, &pdoc(), daughter_shot, &readable).expect("a daughter");
    assert_eq!(daughter, a(&[1, 0, 1, 0, 3, 1, 1]));
    assert_eq!(k.snapshot().world().m5().content_count(&daughter), n(4));
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            Shot { base: Some(base(&member1, 5)), draft: None, runs: vec![] },
            &readable
        )),
        PublishError::BaseExtentTooLarge
    ));
}

#[test]
fn a_birth_shot_carries_no_tail_and_a_memberless_base_carries_its_deposits() {
    // PUB-2.34 against PUB-2.42/2.66: the base absent and the base naming the
    // memberless document itself are ONE destination — the chain's first
    // member — and not one arrangement. A deposit lands in the memberless
    // edition after the client's render took its three positions. A birth
    // shot naming the document as its base carries it; one with no base has
    // no extent and so no tail, and leaves the deposit in the pre-chain
    // arrangement the member supersedes, where no reader of the bare address
    // sees it.
    let birth = |base_named: Option<Base>| {
        let k = mem_kernel();
        let vs = deposit_abc(&k); // pdoc: a b c, memberless
        vs.insert(P1, &pdoc(), vp(1, 4), vec![val(b"z")], declared())
            .expect("a deposit into the memberless edition, after the render");
        let (member, _) = vs
            .publish(
                P1,
                &pdoc(),
                Shot { base: base_named, draft: None, runs: vec![shot_run(&pdoc(), &pca(1), 3)] },
                &readable_by(PrincipalId(1)),
            )
            .expect("the birth shot commits");
        assert_eq!(member, vdoc(), "the chain's first member, either way");
        let s = k.snapshot();
        assert_eq!(reading_surface(s.world().m3(), &pdoc()), member, "readers float to it");
        assert_eq!(
            s.world().m5().content_count(&pdoc()),
            n(4),
            "the pre-chain arrangement keeps the deposit either way"
        );
        s.world().m5().content_count(&member)
    };
    assert_eq!(birth(Some(base(&pdoc(), 3))), n(4), "the memberless base carries the deposit");
    assert_eq!(birth(None), n(3), "the birth shape carries no tail");
}

#[test]
fn the_birth_extent_of_a_shot_born_version_counts_its_whole_placement_and_no_later_deposit() {
    // BIRTH★ through the ops (PUB-3.19, RES-276): the extent the doc-metadata
    // read serves for `D.1` is the count its MINTING commit left, and the
    // fold knows that count only because the shot journals the member's
    // whole arrangement — the runs by reference, the draft's re-inserted text
    // and the base's carried tail — as ONE placement, the first naming it. A
    // shot that staged any family as a placement of its own would leave the
    // first one's count as the birth while every content read and R answered
    // as they do now; this read alone sees it.
    let k = mem_kernel();
    let vs = deposit_abc(&k); // pdoc: a b c at pca(1..3), memberless
    insert_abc(&k); // the staging draft doc1: a b c at ca(1..3)
    vs.insert(P1, &pdoc(), vp(1, 4), vec![val(b"z")], declared())
        .expect("a deposit into the memberless edition, after the render took three");
    let (member, _) = vs
        .publish(
            P1,
            &pdoc(),
            Shot {
                base: Some(base(&pdoc(), 3)),
                draft: Some(doc1()),
                runs: vec![shot_run(&pdoc(), &pca(1), 3), shot_run(&doc1(), &ca(1), 1)],
            },
            &readable_by(PrincipalId(1)),
        )
        .expect("the birth version");
    assert_eq!(member, vdoc(), "the chain's first member");
    {
        let s = k.snapshot();
        let m5 = s.world().m5();
        // a b c by reference, the draft's a re-inserted at pca(5), z carried
        // from pca(4): three families, none I-adjacent to the next.
        assert_eq!(m5.content_run_count(&member), 3, "the fixture places three families");
        assert_eq!(m5.content_count(&member), n(5));
        assert_eq!(m5.birth_extent(&member), n(5), "born with all five");
    }
    // A deposit into the head grows the member and not its birth.
    vs.insert(P1, &pdoc(), vp(1, 6), vec![val(b"y")], declared())
        .expect("a deposit landing in the head D.1");
    let s = k.snapshot();
    assert_eq!(s.world().m5().content_count(&member), n(6));
    assert_eq!(s.world().m5().birth_extent(&member), n(5), "the deposit is no part of the birth");
}

#[test]
fn a_birth_version_the_shot_minted_empty_is_noted_at_zero_and_carries_its_terms() {
    // BIRTH★'s one residue, CLOSED through the ops by D25's (c′): the shot
    // journals its placing record for every member it mints, an empty
    // placement included — the record carries the shot's terms, which exist
    // whatever the placement holds — so a birth version born empty is noted
    // at zero by its own mint, and its first deposit grows the count alone.
    // The terms are read off the member: the count zero, and no base extent
    // — the birth bit. (Until the record carried the terms, an empty shot
    // journaled no placement and that deposit was read as the birth.)
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    let (member, _) = vs
        .publish(
            P1,
            &pdoc(),
            Shot { base: None, draft: None, runs: vec![] },
            &readable_by(PrincipalId(1)),
        )
        .expect("an empty birth version, in the birth shape");
    assert_eq!(member, vdoc(), "the chain's first member");
    {
        let s = k.snapshot();
        assert_eq!(s.world().m5().birth_extent(&member), n(0), "noted at zero by the mint");
        assert_eq!(
            s.world().m5().shot_terms(&member),
            Some(&ShotTerms { placed: n(0), base_extent: None }),
            "the terms: nothing placed, no base — the birth bit"
        );
    }
    vs.insert(P1, &pdoc(), vp(1, 1), vec![val(b"z")], declared())
        .expect("a deposit landing in the head the shot minted");
    let s = k.snapshot();
    assert_eq!(s.world().m5().content_count(&member), n(1), "the head took the deposit");
    assert_eq!(s.world().m5().birth_extent(&member), n(0), "born empty, whatever it took since");
}

#[test]
fn the_address_form_of_a_request_is_the_address_form_read_at_the_member() {
    // l6-A4 = r6-4 on both sides of the commit: `Shot::address_form` for the
    // request and `M5State::address_form_of` for the member it minted agree
    // run for run — the same classes, the same widths, every window the
    // same run, every copied run the same VALUES — over a shot holding all
    // three families with the two seams the member's run-list erases: two
    // I-ADJACENT WINDOWS the placement merges into one, and the base's
    // CARRIED TAIL merged into the client's last own-origin run, which the
    // member side CLIPS back at `placed`. And the terms the member carries
    // are the request's: `placed` the runs' Σ width, `base_extent` the base's.
    let k = mem_kernel();
    let vs = deposit_abc(&k); // pdoc: a b c at pca(1..3), memberless
    insert_abc(&k); // the staging draft doc1: a b c at ca(1..3)
    vs.insert(P1, &doc2(), vp(1, 1), vec![val(b"d"), val(b"e")], Deposit::Undeclared)
        .expect("doc2, the window's source: d e at its first two addresses");
    let d2 = |k: u32| a(&[1, 0, 1, 0, 2, 0, 1, k]);
    // Two windows onto doc2, adjacent; the draft's `a` re-inserted; the
    // edition's own `a b` by reference — with the base taken at two, so `c`
    // is the carried tail, I-adjacent to that last run.
    let shot = Shot {
        base: Some(base(&pdoc(), 2)),
        draft: Some(doc1()),
        runs: vec![
            shot_run(&doc2(), &d2(1), 1),
            shot_run(&doc2(), &d2(2), 1),
            shot_run(&doc1(), &ca(1), 1),
            shot_run(&pdoc(), &pca(1), 2),
        ],
    };
    let requested = shot.address_form(&pdoc());
    let (member, _) = vs
        .publish(P1, &pdoc(), shot, &readable_by(PrincipalId(1)))
        .expect("the shot commits");
    assert_eq!(member, vdoc());
    let s = k.snapshot();
    let (m5, content) = (s.world().m5(), s.world().content());
    let terms = m5.shot_terms(&member).expect("the shot's member carries its terms");
    assert_eq!(*terms, ShotTerms { placed: n(5), base_extent: Some(n(2)) });
    // The member: [doc2 d e][pdoc a′ (fresh)][pdoc a b c] — the tail merged
    // into the last own run, so three runs where the client named four.
    assert_eq!(m5.content_run_count(&member), 3);
    assert_eq!(m5.content_count(&member), n(6));
    let at_member = m5.address_form_of(&member, &terms.placed);
    let values_of = |seg: &PlacedSegment| -> Vec<Vec<u8>> {
        let run = match seg {
            PlacedSegment::Copied(run) | PlacedSegment::Window(run) => run,
        };
        run.addrs()
            .map(|a| content.value_at(a.tumbler()).expect("a placed value").as_bytes().to_vec())
            .collect()
    };
    assert_eq!(requested.len(), 3, "the two windows merged, then two copied runs");
    assert_eq!(at_member.len(), 3, "read back the same, the last clipped at `placed`");
    for (r, m) in requested.iter().zip(&at_member) {
        match (r, m) {
            (PlacedSegment::Window(x), PlacedSegment::Window(y)) => {
                assert_eq!(x, y, "a window is the same run on both sides")
            }
            (PlacedSegment::Copied(x), PlacedSegment::Copied(y)) => {
                assert_eq!(x.width(), y.width(), "a copied run keeps its width");
                assert_eq!(values_of(r), values_of(m), "…and spells the same values");
            }
            other => panic!("the classes differ: {other:?}"),
        }
    }
    assert!(
        matches!(&at_member[0], PlacedSegment::Window(w) if *w.i_start() == d2(1) && *w.width() == n(2)),
        "the merged window: {at_member:?}"
    );
    assert!(
        matches!(&at_member[2], PlacedSegment::Copied(c) if *c.i_start() == pca(1) && *c.width() == n(2)),
        "the last own run clipped from three to the two the client placed: {at_member:?}"
    );
    // Asked past the client's positions, the member answers what it has —
    // the whole run, the tail included; asked of nothing, nothing.
    assert!(
        matches!(&m5.address_form_of(&member, &n(9))[2], PlacedSegment::Copied(c) if *c.width() == n(3))
    );
    assert!(m5.address_form_of(&member, &n(0)).is_empty());
    assert!(m5.address_form_of(&doc2(), &n(2)).iter().all(|s| matches!(s, PlacedSegment::Copied(_))),
        "a document's own runs are copied, read at the address named");
}
