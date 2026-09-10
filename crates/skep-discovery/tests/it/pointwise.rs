//! §5 — projection and addressable discoverability: what each answers,
//! the order their refusals speak in, the trunk head both read, the
//! absence rule both apply, and the run budget and join square that hold them.

use crate::common;

use common::*;
use skep_address::Address;
use skep_arrangement::{HasM5, Vstream};
use skep_discovery::{
    addressably_discoverable_from_on, project_on, LinkQuery, QueryError, FROM, MAX_IMAGE_RUNS, TO,
    TYPE,
};
use skep_links::{LinkWriter, SlotArg};

#[test]
fn project_is_content_subspace_i_to_v_with_conflated_not_a_link() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k, &every_home);
    let e1 = link(&store, &doc1(), &[ca(2)], &[ca(101)]);

    // FROM covers ca(2) ⇒ exactly V-position [s_C, 2] of doc1.
    let proj = lq.project(&e1, FROM, &doc1()).expect("project");
    assert!(proj.denotes(&t(&[1, 2])));
    assert!(!proj.denotes(&t(&[1, 1])));
    assert!(!proj.denotes(&t(&[1, 3])));

    // A slot whose coverage lands nowhere in d's content projects ∅ (TO is a
    // ghost position; TYPE lives in the reserved subspace).
    assert!(lq.project(&e1, TO, &doc1()).expect("project").is_empty());
    assert!(lq.project(&e1, TYPE, &doc1()).expect("project").is_empty());

    // NotALink covers BOTH a non-link `a` AND an out-of-range slot.
    assert_eq!(lq.project(&ca(1), FROM, &doc1()), Err(QueryError::NotALink));
    assert_eq!(lq.project(&e1, 4, &doc1()), Err(QueryError::NotALink));
    // The doc gate comes first.
    assert_eq!(
        lq.project(&e1, FROM, &unregistered_doc()),
        Err(QueryError::DocNotRegistered)
    );
    // A registered-but-empty d projects ∅, a defined answer — never
    // DocNotRegistered, which is the distinction the document gate draws.
    assert!(lq
        .project(&e1, FROM, &doc2())
        .expect("registered-empty answers")
        .is_empty());

    // NOT ADDRESSABLE-FILTERED — the one read here that is not narrowed to
    // the active view.
    // Nullifying e1 leaves its projection exactly as it was (followlink
    // reports what is RECORDED), while addressably_discoverable_from, which
    // conjoins is_active, flips: the two answer different questions about one
    // link.
    store.nullify(SYS, &doc2(), &e1).expect("nullify succeeds");
    let retracted = lq.project(&e1, FROM, &doc1()).expect("project");
    assert_eq!(retracted, proj);
    assert!(retracted.denotes(&t(&[1, 2])));
    assert_eq!(lq.addressably_discoverable_from(&e1, &doc1()), Ok(false));
}

/// §5 — `project` is CONTENT-SUBSPACE ONLY, strictly weaker than ASN-0098's
/// subspace-agnostic `project`: a link reachable solely through `d`'s LINK
/// subspace projects ∅. That is the reason `project` and
/// `addressably_discoverable_from` are two functions, so the case is stated
/// as the pair answering oppositely off one state. The ∅ cases beside it are
/// coverage that lands nowhere at all; this is coverage that lands squarely
/// in `d`, in the other subspace — which the second assertion is what
/// witnesses.
#[test]
fn project_is_content_subspace_only_where_discoverability_reaches_the_link_subspace() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k, &every_home);
    let m1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let m2 = link(&store, &doc1(), &[ca(2)], &[ca(102)]);
    // The claim's F and G cover m1 and m2 — link addresses makelink SEATED in
    // doc1's link runs, and nothing of doc1's content.
    let (claim, _) = store
        .assert_sup(SYS, &doc1(), &m1, &m2)
        .expect("assert_sup succeeds");

    assert!(lq.project(&claim, FROM, &doc1()).expect("project").is_empty());
    assert!(lq.project(&claim, TO, &doc1()).expect("project").is_empty());
    assert_eq!(lq.addressably_discoverable_from(&claim, &doc1()), Ok(true));
}

#[test]
fn addressably_discoverable_from_is_lp12_and_addressable_over_both_subspaces() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k, &every_home);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    assert_eq!(lq.addressably_discoverable_from(&e1, &doc1()), Ok(true));
    // Registered-but-empty d: nothing is reachable.
    assert_eq!(lq.addressably_discoverable_from(&e1, &doc2()), Ok(false));

    // The LINK-subspace half of LP12: a supersession claim's slots cover only
    // link addresses, which are seated in doc1's link runs by makelink.
    let (m1, _) = store
        .makelink(
            SYS,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 2, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)]),
        )
        .expect("makelink succeeds");
    let (m2, _) = store
        .makelink(
            SYS,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 2, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 2, 1)]),
        )
        .expect("makelink succeeds");
    let (claim, _) = store.assert_sup(SYS, &doc2(), &m1, &m2).expect("assert_sup succeeds");
    assert_eq!(lq.addressably_discoverable_from(&claim, &doc1()), Ok(true));
    // The claim is homed in doc2 but reaches nothing arranged there
    // (assert_sup never seats).
    assert_eq!(lq.addressably_discoverable_from(&claim, &doc2()), Ok(false));

    // LP12 conjoined with addressability: a nullified-but-reachable link is
    // discoverable and not addressable, so it answers Ok(false) — and a
    // nullified link is still a link (it is still resident, so it passes the
    // resident-link read rather than erring NotALink).
    store.nullify(SYS, &doc2(), &e1).expect("nullify succeeds");
    assert_eq!(lq.addressably_discoverable_from(&e1, &doc1()), Ok(false));

    assert_eq!(
        lq.addressably_discoverable_from(&ca(1), &doc1()),
        Err(QueryError::NotALink)
    );
    assert_eq!(
        lq.addressably_discoverable_from(&e1, &unregistered_doc()),
        Err(QueryError::DocNotRegistered)
    );
}

/// §5 — the precedence between the two gates, on the call that is faulty in
/// BOTH arguments at once. Each read states its refusal order, and only a
/// doubly-faulty call can tell the stated order from the other one: every
/// other case in the suite is faulty in `d` alone or in `a` alone, where
/// either order answers alike. The rule is the pair's — every argument
/// about `d` is settled before any argument about `a` — so an unregistered
/// document with a non-link address names the document.
#[test]
fn the_pointwise_gates_settle_the_document_before_the_address() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let lq = LinkQuery::new(&k, &every_home);

    // `ca(1)` is arranged content, not a link, and `unregistered_doc()` names
    // nothing — two faults, one verdict.
    assert_eq!(
        lq.project(&ca(1), FROM, &unregistered_doc()),
        Err(QueryError::DocNotRegistered)
    );
    assert_eq!(
        lq.addressably_discoverable_from(&ca(1), &unregistered_doc()),
        Err(QueryError::DocNotRegistered)
    );
    // Each fault alone, so the doubly-faulty verdict above is a precedence
    // and not the only refusal either read can give.
    assert_eq!(lq.project(&ca(1), FROM, &doc1()), Err(QueryError::NotALink));
    assert_eq!(
        lq.addressably_discoverable_from(&ca(1), &doc1()),
        Err(QueryError::NotALink)
    );
}

/// §5 — HEAD-FLOAT on the pointwise pair: a bare PUBLISHED address is read
/// through its trunk head, the pin the region family resolves through, so
/// the two families agree about which links reach it — every link
/// `findlinks_v` finds through `pdoc` is one `addressably_discoverable_from`
/// calls reachable from `pdoc`, and `project` answers in the head's
/// positions. Every other fixture in this suite is a private document, where
/// the float is inert and reading `d`'s own arrangement is reading the right
/// one; here a link reaching only the head's positions tells them apart.
#[test]
fn the_pointwise_pair_reads_the_trunk_head_the_region_family_resolves() {
    let k = published_world();
    let store = LinkWriter::new(&k, &EVERYONE);
    let pre_chain = link(&store, &doc1(), &[pca(1)], &[ca(101)]); // a position both arrangements hold
    let head_only = link(&store, &doc1(), &[pca(3)], &[ca(102)]); // a position only the head holds
    let lq = LinkQuery::new(&k, &every_home);

    // The premise: the head holds four positions, pdoc's own arrangement two.
    let snap = k.snapshot();
    assert_eq!(snap.world().m5().content_count(&phead()), n(4));
    assert_eq!(snap.world().m5().content_count(&pdoc()), n(2));

    // The law, and it is not vacuous: both links are found through pdoc.
    let found = lq.findlinks_v(&pdoc(), &[vspan(1, 1, 4)]).expect("findlinks_v");
    assert_eq!(found, vec![pre_chain, head_only.clone()]);
    for a in &found {
        assert_eq!(
            lq.addressably_discoverable_from(a, &pdoc()),
            Ok(true),
            "{a:?} is found through pdoc, so it reaches pdoc"
        );
    }
    // `project` answers in the positions `image` resolves — the head's.
    assert_eq!(lq.image(&pdoc(), &[vspan(1, 3, 1)]), Ok(vec![run(&pca(3), 1)]));
    assert!(lq
        .project(&head_only, FROM, &pdoc())
        .expect("project")
        .denotes(&t(&[1, 3])));
    // And the bare address answers exactly as its head does: the pin, not a
    // coincidence of this fixture.
    for a in &found {
        assert_eq!(
            lq.addressably_discoverable_from(a, &pdoc()),
            lq.addressably_discoverable_from(a, &phead())
        );
        assert_eq!(lq.project(a, FROM, &pdoc()), lq.project(a, FROM, &phead()));
    }
}

/// §5 — the pointwise pair apply the ABSENCE RULE: a link homed where the
/// reader may not read is ABSENT — `project` gives the non-link's
/// `NotALink`, `addressably_discoverable_from` the retracted link's
/// `Ok(false)`. The absence rule sits where both cards put it: after the
/// document gate, so an unregistered `d` still names the document fault; and
/// ahead of the resident-link read, so a refused link and an address naming
/// nothing under the same unreadable document answer alike — the reader
/// learns nothing of that document's link chain. An address with no home is
/// no one's to withhold, so the store answers for it, whatever the reader.
#[test]
fn the_pointwise_reads_apply_the_absence_rule_after_the_document_and_before_residence() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let doc2_link = link(&store, &doc2(), &[ca(1)], &[ca(101)]);
    let nothing = la2(99); // under doc2, naming no link
    let snap = k.snapshot();
    let cannot_read_doc2 = |d: &Address| *d != doc2();

    // Admitted, the link answers as a link and the non-link as a non-link …
    assert!(project_on(&snap, &doc2_link, FROM, &doc1(), &every_home)
        .expect("project")
        .denotes(&t(&[1, 1])));
    assert_eq!(
        addressably_discoverable_from_on(&snap, &doc2_link, &doc1(), &every_home),
        Ok(true)
    );
    assert_eq!(
        project_on(&snap, &nothing, FROM, &doc1(), &every_home),
        Err(QueryError::NotALink)
    );
    assert_eq!(
        addressably_discoverable_from_on(&snap, &nothing, &doc1(), &every_home),
        Err(QueryError::NotALink)
    );
    // … and refused, the two cannot be told apart.
    for addr in [&doc2_link, &nothing] {
        assert_eq!(
            project_on(&snap, addr, FROM, &doc1(), &cannot_read_doc2),
            Err(QueryError::NotALink),
            "{addr:?} is absent to project"
        );
        assert_eq!(
            addressably_discoverable_from_on(&snap, addr, &doc1(), &cannot_read_doc2),
            Ok(false),
            "{addr:?} is absent, so not discoverable"
        );
    }
    // After the document gate: the document fault still speaks first.
    assert_eq!(
        project_on(&snap, &doc2_link, FROM, &unregistered_doc(), &cannot_read_doc2),
        Err(QueryError::DocNotRegistered)
    );
    assert_eq!(
        addressably_discoverable_from_on(&snap, &doc2_link, &unregistered_doc(), &cannot_read_doc2),
        Err(QueryError::DocNotRegistered)
    );
    // An ACCOUNT address has no home: nothing to withhold, even from a reader
    // who may read nothing, and the store's own answer stands.
    let account = a(&[1, 0, 1]);
    let no_one = |_: &Address| false;
    assert_eq!(
        project_on(&snap, &account, FROM, &doc1(), &no_one),
        Err(QueryError::NotALink)
    );
    assert_eq!(
        addressably_discoverable_from_on(&snap, &account, &doc1(), &no_one),
        Err(QueryError::NotALink)
    );
}

/// §5 — the same run CONSTANT at both pointwise reads, over the two
/// different quantities each of them multiplies: `project` prices `d`'s
/// content runs, which is what M5's join reads, and
/// `addressably_discoverable_from` prices content plus link runs, which is
/// what LP12 ranges over. So the two do not refuse the same documents, and
/// the last case here is the one link that separates them — without it the
/// fixture seats every link in doc1, leaving doc2's link runs at zero, where
/// the two quantities coincide and the wrong rule passes. Once `d` is past
/// the budget it also shows each read's refusal ORDER, which no in-budget
/// `d` can: every argument about `a` is refused ahead of the budget, and a
/// retracted `a` gets its answer from `addressably_discoverable_from` before
/// the budget, while `project`, which no retraction narrows, still meets it.
#[test]
fn the_pointwise_pair_holds_one_run_constant_over_two_quantities() {
    let k = kernel();
    let store = LinkWriter::new(&k, &EVERYONE);
    seed_content(&k, &doc1(), 1);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let lq = LinkQuery::new(&k, &every_home);

    // Well under the budget, both answer.
    assert!(lq.project(&e1, FROM, &doc1()).is_ok());
    assert_eq!(lq.addressably_discoverable_from(&e1, &doc1()), Ok(true));

    // Fragment doc2 to exactly the budget: one COPY placing the SAME source
    // position many times — each placement is a width-1 run that abuts
    // nothing, so the arrangement holds one run per spec rather than
    // coalescing them. This is the world quantity the budget prices, and a
    // caller can build it far faster than a reader can pay for it.
    let vs = Vstream::new(&k);
    let many = vec![spec(&doc1(), 1, 1, 1); MAX_IMAGE_RUNS];
    vs.copy(SYS, &doc2(), vp(1, 1), &many).expect("copy succeeds");
    let snap = k.snapshot();
    assert_eq!(snap.world().m5().content_runs(&doc2()).len(), MAX_IMAGE_RUNS);
    assert_eq!(snap.world().m5().link_runs(&doc2()).len(), 0);
    assert!(lq.project(&e1, FROM, &doc2()).is_ok());
    assert!(lq.addressably_discoverable_from(&e1, &doc2()).is_ok());

    // ONE link run seated in doc2 — and the two counts part company. The
    // content runs are untouched, so `project` still answers; the LINK runs
    // put `addressably_discoverable_from` one over, because LP12 ranges over
    // both subspaces and it must price both.
    link(&store, &doc2(), &[ca(1)], &[ca(103)]);
    let snap = k.snapshot();
    assert_eq!(snap.world().m5().content_runs(&doc2()).len(), MAX_IMAGE_RUNS);
    assert_eq!(snap.world().m5().link_runs(&doc2()).len(), 1);
    assert!(lq.project(&e1, FROM, &doc2()).is_ok());
    assert_eq!(
        lq.addressably_discoverable_from(&e1, &doc2()),
        Err(QueryError::ImageTooLarge)
    );

    // One CONTENT run past it, and both refuse — the quantities differ, the
    // constant does not.
    vs.copy(SYS, &doc2(), vp(1, 1), &[spec(&doc1(), 1, 1, 1)])
        .expect("copy succeeds");
    assert_eq!(
        lq.project(&e1, FROM, &doc2()),
        Err(QueryError::ImageTooLarge)
    );
    assert_eq!(
        lq.addressably_discoverable_from(&e1, &doc2()),
        Err(QueryError::ImageTooLarge)
    );
    // The unregistered `d` shows the document gate's own verdict, and no
    // order: an unregistered document carries no runs, so it has no budget to
    // be refused ahead of. The order is shown by the arguments about `a`,
    // asked of a `d` PAST the budget — a non-link, and an `a` absent to the
    // reader, are each refused ahead of it, on both reads.
    assert_eq!(
        lq.project(&e1, FROM, &unregistered_doc()),
        Err(QueryError::DocNotRegistered)
    );
    assert_eq!(lq.project(&ca(1), FROM, &doc2()), Err(QueryError::NotALink));
    assert_eq!(
        lq.addressably_discoverable_from(&ca(1), &doc2()),
        Err(QueryError::NotALink)
    );
    let cannot_read_doc1 = |d: &Address| *d != doc1();
    let snap = k.snapshot();
    assert_eq!(
        addressably_discoverable_from_on(&snap, &e1, &doc2(), &cannot_read_doc1),
        Ok(false)
    );
    assert_eq!(
        project_on(&snap, &e1, FROM, &doc2(), &cannot_read_doc1),
        Err(QueryError::NotALink)
    );
    // A RETRACTED `a` answers `addressably_discoverable_from` between its
    // `NotALink` and its budget, so it never meets the budget; `project`,
    // which no retraction narrows, still does.
    store.nullify(SYS, &doc2(), &e1).expect("nullify succeeds");
    assert_eq!(lq.addressably_discoverable_from(&e1, &doc2()), Ok(false));
    assert_eq!(
        lq.project(&e1, FROM, &doc2()),
        Err(QueryError::ImageTooLarge)
    );
}

/// §5 — the touch test's JOIN, which the run count cannot see:
/// `addressably_discoverable_from` tests every span of a link's WHOLE
/// coverage against every run of `d`'s surface, and each of a link's three
/// slots may carry M7's `MAX_SLOT_SPANS`. So the product is held to the
/// square of the run budget beside the run count. With `M` the budget, a
/// link `M + 1` spans wide is answered against `M − 1` runs, where the
/// product is `M² − 1`, and refused against exactly `M`, which the run count
/// admits and the product does not; a link `M` spans wide is answered there,
/// at the square itself. Every one of these links opens its FROM with the one
/// position each of doc2's runs holds, so an admitted case touches at its
/// first test and the suite never pays the join it prices.
#[test]
fn addressably_discoverable_from_holds_its_join_to_the_square_of_the_run_budget() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let m = MAX_IMAGE_RUNS as u32;
    // A FROM of `M − 1` spans beside a one-span TO and TYPE: `M + 1` in all.
    let wider = link(&store, &doc1(), &wide_from(1, m - 1), &[ca(101)]);
    // A FROM of `M − 2`: `M` in all.
    let exact = link(&store, &doc1(), &wide_from(0, m - 2), &[ca(101)]);
    let vs = Vstream::new(&k);
    let many = vec![spec(&doc1(), 1, 1, 1); MAX_IMAGE_RUNS - 1];
    vs.copy(SYS, &doc2(), vp(1, 1), &many).expect("copy succeeds");
    let lq = LinkQuery::new(&k, &every_home);
    assert_eq!(
        k.snapshot().world().m5().link_runs(&doc2()).len(),
        0,
        "both links are seated in doc1, so doc2's runs are its content alone"
    );

    // (M + 1)(M − 1) = M² − 1: inside the square.
    assert_eq!(lq.addressably_discoverable_from(&wider, &doc2()), Ok(true));

    // One run more. The run count is AT the budget, which admits it; the
    // product is (M + 1)M, past the square.
    vs.copy(SYS, &doc2(), vp(1, 1), &[spec(&doc1(), 1, 1, 1)])
        .expect("copy succeeds");
    assert_eq!(
        k.snapshot().world().m5().content_runs(&doc2()).len(),
        MAX_IMAGE_RUNS
    );
    assert_eq!(
        lq.addressably_discoverable_from(&wider, &doc2()),
        Err(QueryError::ImageTooLarge)
    );
    // M × M: the square itself is admitted.
    assert_eq!(lq.addressably_discoverable_from(&exact, &doc2()), Ok(true));
}
