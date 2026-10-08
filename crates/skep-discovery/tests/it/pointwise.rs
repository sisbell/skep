//! §5 — projection and addressable discoverability: what each answers, the
//! overlap discoverability shares with the region family's stab, the order
//! their refusals speak in, the trunk head both read, the absence rule both
//! apply, and the run budget and join square that hold them — the square at a
//! step that builds nothing per pair.

use crate::common;
use crate::heap::heap_bytes;

use common::*;
use skep_address::{classify_spans, Address, Span, SpanRel};
use skep_arrangement::{HasM5, Vstream};
use skep_discovery::{
    addressably_discoverable_from_on, project_on, QueryError, FROM, MAX_ANSWER_SPANS,
    MAX_IMAGE_RUNS, TO, TYPE,
};
use skep_kernel::Snapshot;
use skep_links::{HasLinks, LinkWriter, SlotArg};

#[test]
fn project_is_content_subspace_i_to_v_with_conflated_not_a_link() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    let e1 = link(&store, &doc1(), &[ca(2)], &[ca(101)]);

    // FROM covers ca(2) ⇒ exactly V-position [s_C, 2] of doc1.
    let proj = reads.project(&e1, FROM, &doc1()).expect("project");
    assert!(proj.denotes(&t(&[1, 2])));
    assert!(!proj.denotes(&t(&[1, 1])));
    assert!(!proj.denotes(&t(&[1, 3])));

    // A slot whose coverage lands nowhere in d's content projects ∅: TO names
    // ca(101), a content address doc1 never minted, and TYPE names `rel()`,
    // an ordinary content address of another document.
    assert!(reads.project(&e1, TO, &doc1()).expect("project").is_empty());
    assert!(reads.project(&e1, TYPE, &doc1()).expect("project").is_empty());

    // NotALink covers BOTH a non-link `a` AND an out-of-range slot.
    assert_eq!(reads.project(&ca(1), FROM, &doc1()), Err(QueryError::NotALink));
    assert_eq!(reads.project(&e1, 4, &doc1()), Err(QueryError::NotALink));
    // Slot numerals are 1-based: 0 is as far out of range below as 4 is above.
    assert_eq!(reads.project(&e1, 0, &doc1()), Err(QueryError::NotALink));
    // The doc gate comes first.
    assert_eq!(
        reads.project(&e1, FROM, &unregistered_doc()),
        Err(QueryError::DocNotRegistered)
    );
    // A registered-but-empty d projects ∅, a defined answer — never
    // DocNotRegistered, which is the distinction the document gate draws.
    assert!(reads
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
    let after_retraction = reads.project(&e1, FROM, &doc1()).expect("project");
    assert_eq!(after_retraction, proj);
    assert!(after_retraction.denotes(&t(&[1, 2])));
    assert_eq!(reads.addressably_discoverable_from(&e1, &doc1()), Ok(false));
}

/// §5 — `project` is CONTENT-SUBSPACE ONLY, strictly weaker than ASN-0098's
/// subspace-agnostic `project`: a link reachable solely through `d`'s LINK
/// subspace projects ∅. That is the reason `project` and
/// `addressably_discoverable_from` are two functions, so the case is stated
/// as the pair answering oppositely off one state. The ∅ cases beside it are
/// coverage that lands nowhere at all; this is coverage that lands squarely
/// in `d`, in the other subspace — which the last assertion is what
/// witnesses. Every slot projects ∅, TYPE included, so `followlink` composed
/// with `project` calls this live claim unreachable from `d` where LP12 calls
/// it reachable: the composition is not LP12, and
/// `addressably_discoverable_from_on`'s card says so.
#[test]
fn project_is_content_subspace_only_where_discoverability_reaches_the_link_subspace() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    let m1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let m2 = link(&store, &doc1(), &[ca(2)], &[ca(102)]);
    // The claim's F and G cover m1 and m2 — link addresses makelink SEATED in
    // doc1's link runs, and nothing of doc1's content.
    let (claim, _) = store
        .assert_sup(SYS, &doc1(), &m1, &m2)
        .expect("assert_sup succeeds");

    assert!(reads.project(&claim, FROM, &doc1()).expect("project").is_empty());
    assert!(reads.project(&claim, TO, &doc1()).expect("project").is_empty());
    assert!(reads.project(&claim, TYPE, &doc1()).expect("project").is_empty());
    assert_eq!(reads.addressably_discoverable_from(&claim, &doc1()), Ok(true));
}

#[test]
fn addressably_discoverable_from_is_lp12_and_addressable_over_both_subspaces() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    assert_eq!(reads.addressably_discoverable_from(&e1, &doc1()), Ok(true));
    // Registered-but-empty d: nothing is reachable.
    assert_eq!(reads.addressably_discoverable_from(&e1, &doc2()), Ok(false));

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
    assert_eq!(reads.addressably_discoverable_from(&claim, &doc1()), Ok(true));
    // The claim is homed in doc2 but reaches nothing arranged there
    // (assert_sup never seats).
    assert_eq!(reads.addressably_discoverable_from(&claim, &doc2()), Ok(false));

    // LP12 conjoined with addressability: a nullified-but-reachable link is
    // discoverable and not addressable, so it answers Ok(false) — and a
    // nullified link is still a link (it is still resident, so it passes the
    // resident-link read rather than erring NotALink).
    store.nullify(SYS, &doc2(), &e1).expect("nullify succeeds");
    assert_eq!(reads.addressably_discoverable_from(&e1, &doc1()), Ok(false));

    assert_eq!(
        reads.addressably_discoverable_from(&ca(1), &doc1()),
        Err(QueryError::NotALink)
    );
    assert_eq!(
        reads.addressably_discoverable_from(&e1, &unregistered_doc()),
        Err(QueryError::DocNotRegistered)
    );
}

/// §5 — `addressably_discoverable_from` tests its touch by a second statement
/// of M7's per-link overlap, which M7 keeps private, so the two must give one
/// answer: a live link is discoverable from `d` exactly when the region
/// family's stab finds it through `d`'s content, on every relation
/// `classify_spans` draws. doc1 arranges one run and seats no link, and six
/// links meet that run at FROM under the five relations — Equal, Containment
/// from either side, ProperOverlap, Adjacent, Separated — while their TO and
/// TYPE meet nothing doc1 arranges. Every other discoverability fixture meets
/// a run Equal or contained, so a touch test that dropped ProperOverlap, or
/// took Adjacent for a touch, would pass them all and part from M7 here.
#[test]
fn discoverability_agrees_with_the_region_familys_stab_on_every_span_relation() {
    let k = kernel();
    seed_content(&k, &doc1(), 4); // one run: V 1..4 → ca(1..4)
    let store = LinkWriter::new(&k, &EVERYONE);
    // Homed in doc2, so doc1 seats none of them and its one content run is all
    // `addressably_discoverable_from` tests a link against.
    let from_positions = |at: u32, count: u32| {
        store
            .makelink(
                SYS,
                &doc2(),
                SlotArg::Resolve(vec![spec(&doc1(), 1, at, count)]),
                SlotArg::Addrs(vec![ca(101)]),
                SlotArg::Addrs(vec![rel()]),
            )
            .expect("makelink succeeds")
            .0
    };
    let equal = from_positions(1, 3); // [ca(1), ca(4))
    let containing = from_positions(1, 4); // [ca(1), ca(5))
    let straddling = from_positions(3, 2); // [ca(3), ca(5))
    let contained = link(&store, &doc2(), &[ca(2)], &[ca(101)]); // [ca(2), ca(3))
    let adjacent = link(&store, &doc2(), &[ca(4)], &[ca(101)]); // [ca(4), ca(5))
    let separated = link(&store, &doc2(), &[ca(9)], &[ca(101)]); // [ca(9), ca(10))

    // Position 4 leaves doc1, which then arranges `[ca(1), ca(4))` alone.
    Vstream::new(&k)
        .delete(SYS, &doc1(), vp(1, 4), n(1))
        .expect("delete succeeds");
    let reads = Reads(&k);
    let region = [vspan(1, 1, 3)];
    assert_eq!(reads.image(&doc1(), &region), Ok(vec![run(&ca(1), 3)]));
    let cases = [
        (&equal, SpanRel::Equal),
        (&containing, SpanRel::Containment),
        (&straddling, SpanRel::ProperOverlap),
        (&contained, SpanRel::Containment),
        (&adjacent, SpanRel::Adjacent),
        (&separated, SpanRel::Separated),
    ];

    // The premise: each link's FROM meets that run under the relation it is
    // paired with.
    let arranged = run(&ca(1), 3).iextent();
    let snap = k.snapshot();
    for &(addr, relation) in &cases {
        let from = snap
            .world()
            .links()
            .readlink(addr)
            .expect("a deposited link")
            .from_slot();
        let spans: Vec<&Span> = from.spans().collect();
        assert_eq!(spans.len(), 1, "{addr:?}: one FROM span");
        assert_eq!(classify_spans(spans[0], &arranged), relation, "{addr:?}");
    }

    let found = reads.findlinks_v(&doc1(), &region).expect("findlinks_v");
    assert_eq!(
        found,
        vec![
            equal.clone(),
            containing.clone(),
            straddling.clone(),
            contained.clone()
        ]
    );
    for &(addr, _) in &cases {
        assert_eq!(
            reads.addressably_discoverable_from(addr, &doc1()),
            Ok(found.contains(addr)),
            "{addr:?}: discoverable from doc1 exactly where the stab finds it"
        );
    }
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
    let reads = Reads(&k);

    // `ca(1)` is arranged content, not a link, and `unregistered_doc()` names
    // nothing — two faults, one verdict.
    assert_eq!(
        reads.project(&ca(1), FROM, &unregistered_doc()),
        Err(QueryError::DocNotRegistered)
    );
    assert_eq!(
        reads.addressably_discoverable_from(&ca(1), &unregistered_doc()),
        Err(QueryError::DocNotRegistered)
    );
    // Each fault alone, so the doubly-faulty verdict above is a precedence
    // and not the only refusal either read can give.
    assert_eq!(reads.project(&ca(1), FROM, &doc1()), Err(QueryError::NotALink));
    assert_eq!(
        reads.addressably_discoverable_from(&ca(1), &doc1()),
        Err(QueryError::NotALink)
    );
}

/// §5 — HEAD-FLOAT on the pointwise pair: a bare PUBLISHED address is read
/// through its trunk head, the pin the region family resolves through, so
/// the pointwise pair and the region family agree about which links reach it
/// — every link `findlinks_v` finds through `pdoc` is one
/// `addressably_discoverable_from` calls reachable from `pdoc`, and `project`
/// answers in the head's positions. On a private document the float is inert
/// and reading `d`'s own arrangement is reading the right one; here a link
/// reaching only the head's positions tells them apart.
#[test]
fn the_pointwise_pair_reads_the_trunk_head_the_region_family_resolves() {
    let k = published_world();
    let store = LinkWriter::new(&k, &EVERYONE);
    let pre_chain = link(&store, &doc1(), &[pca(1)], &[ca(101)]); // a position both arrangements hold
    let head_only = link(&store, &doc1(), &[pca(3)], &[ca(102)]); // a position only the head holds
    let reads = Reads(&k);

    // The premise: the head holds four positions, pdoc's own arrangement two.
    let snap = k.snapshot();
    assert_eq!(snap.world().m5().content_count(&phead()), n(4));
    assert_eq!(snap.world().m5().content_count(&pdoc()), n(2));

    // The law, and it is not vacuous: both links are found through pdoc.
    let found = reads.findlinks_v(&pdoc(), &[vspan(1, 1, 4)]).expect("findlinks_v");
    assert_eq!(found, vec![pre_chain, head_only.clone()]);
    for a in &found {
        assert_eq!(
            reads.addressably_discoverable_from(a, &pdoc()),
            Ok(true),
            "{a:?} is found through pdoc, so it reaches pdoc"
        );
    }
    // `project` answers in the positions `image` resolves — the head's.
    assert_eq!(reads.image(&pdoc(), &[vspan(1, 3, 1)]), Ok(vec![run(&pca(3), 1)]));
    assert!(reads
        .project(&head_only, FROM, &pdoc())
        .expect("project")
        .denotes(&t(&[1, 3])));
    // And the bare address answers exactly as its head does: the pin, not a
    // coincidence of this fixture.
    for a in &found {
        assert_eq!(
            reads.addressably_discoverable_from(a, &pdoc()),
            reads.addressably_discoverable_from(a, &phead())
        );
        assert_eq!(reads.project(a, FROM, &pdoc()), reads.project(a, FROM, &phead()));
    }
}

/// §5 — HEAD-FLOAT on discoverability's LINK half. LP12 ranges over both
/// subspaces of `d`'s reading surface, and the head-float law above meets
/// only the content half: every link there reaches the head through content.
/// A link HOMED in the head is seated in the head's own link subspace — a link
/// is seated in its home document alone (ASN-0047 CL-OWN), and a link write
/// is outside a published document's edit refusal (PUB-2.12) — so a link
/// naming it, with no witness in content in any slot, reaches the published
/// address exactly as it reaches the head. A read that floated the content
/// runs and took the link runs off pdoc's own frozen arrangement — which
/// seats no link — would call it unreachable from pdoc, and no other fixture
/// here can tell the two apart.
#[test]
fn discoverability_reaches_a_published_address_through_its_heads_link_subspace() {
    let k = published_world();
    let store = LinkWriter::new(&k, &EVERYONE);
    let seated = link(&store, &phead(), &[ca(101)], &[ca(102)]); // homed, so seated, in the head
    let naming = link(&store, &doc1(), std::slice::from_ref(&seated), &[ca(103)]);
    let snap = k.snapshot();
    assert_eq!(
        snap.world().m5().link_runs(&phead()).len(),
        1,
        "seated in the head"
    );
    assert_eq!(
        snap.world().m5().link_runs(&pdoc()).len(),
        0,
        "and in none of pdoc's own"
    );
    let reads = Reads(&k);
    for d in [pdoc(), phead()] {
        for slot in [FROM, TO, TYPE] {
            assert!(
                reads
                    .project(&naming, slot, &d)
                    .expect("project")
                    .is_empty(),
                "{d:?}: slot {slot} has no witness in content"
            );
        }
        assert_eq!(
            reads.addressably_discoverable_from(&naming, &d),
            Ok(true),
            "{d:?}: reached through the head's link subspace"
        );
    }
}

/// §5 — the pointwise pair apply the ABSENCE RULE: a link homed where the
/// reader may not read is ABSENT — both `project` and
/// `addressably_discoverable_from` give the non-link's `NotALink`, never the
/// retracted link's `Ok(false)`, which would tell the reader a link is
/// there. The rule sits where both cards put it: after the document gate, so
/// an unregistered `d` still names the document fault; and ahead of the
/// resident-link read, so a refused link and an address naming nothing under
/// the same unreadable document answer alike — the reader learns nothing of
/// that document's link chain. A RETRACTED link in that home is among the
/// refused, because it is the address whose answer changes if the rule slips
/// behind the addressable half. No answer can show the rule ahead of the
/// resident-link read itself — placed between that read and the addressable
/// half, it still answers every refused address `NotALink` — so a recording
/// predicate does: it is asked the home of an address that names nothing. An
/// address with no home is no one's to withhold, so the store answers for
/// it, whatever the reader.
#[test]
fn the_pointwise_reads_apply_the_absence_rule_after_the_document_and_before_residence() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let doc2_link = link(&store, &doc2(), &[ca(1)], &[ca(101)]);
    // Homed in doc2 as well, reaching position 1 — and then RETRACTED.
    let retracted = link(&store, &doc2(), &[ca(1)], &[ca(102)]);
    store.nullify(SYS, &doc2(), &retracted).expect("nullify succeeds");
    let nothing = la2(99); // under doc2, naming no link
    let snap = k.snapshot();
    let cannot_read_doc2 = |d: &Address| *d != doc2();

    // Admitted, the link answers as a link, the retracted link as present and
    // not active, and the non-link as a non-link …
    assert!(project_on(&snap, &doc2_link, FROM, &doc1(), &every_home)
        .expect("project")
        .denotes(&t(&[1, 1])));
    assert_eq!(
        addressably_discoverable_from_on(&snap, &doc2_link, &doc1(), &every_home),
        Ok(true)
    );
    assert_eq!(
        addressably_discoverable_from_on(&snap, &retracted, &doc1(), &every_home),
        Ok(false)
    );
    assert_eq!(
        project_on(&snap, &nothing, FROM, &doc1(), &every_home),
        Err(QueryError::NotALink)
    );
    assert_eq!(
        addressably_discoverable_from_on(&snap, &nothing, &doc1(), &every_home),
        Err(QueryError::NotALink)
    );
    // … and refused, the three cannot be told apart — the retracted link
    // included.
    for addr in [&doc2_link, &retracted, &nothing] {
        assert_eq!(
            project_on(&snap, addr, FROM, &doc1(), &cannot_read_doc2),
            Err(QueryError::NotALink),
            "{addr:?} is absent to project"
        );
        assert_eq!(
            addressably_discoverable_from_on(&snap, addr, &doc1(), &cannot_read_doc2),
            Err(QueryError::NotALink),
            "{addr:?} is absent to addressably_discoverable_from"
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
    // A NODE or an ACCOUNT address has no home: nothing to withhold, even
    // from a reader who may read nothing, and the store's own answer stands —
    // under every reader, since a read that took the caller's `a` for a link
    // and asked its home would fault here rather than answer.
    let no_one = |_: &Address| false;
    for homeless in [a(&[1]), a(&[1, 0, 1])] {
        for reader in [&every_home as &dyn Fn(&Address) -> bool, &no_one] {
            assert_eq!(
                project_on(&snap, &homeless, FROM, &doc1(), reader),
                Err(QueryError::NotALink),
                "project, {homeless:?}"
            );
            assert_eq!(
                addressably_discoverable_from_on(&snap, &homeless, &doc1(), reader),
                Err(QueryError::NotALink),
                "addressably_discoverable_from, {homeless:?}"
            );
        }
    }
    // AHEAD of the resident-link read, literally: the predicate is asked the
    // home of an address that names nothing, before anything establishes that
    // it does. A rule moved just behind the read answers every case above
    // alike, and asks nothing here.
    let asked = Asked::default();
    let recorder = asked.recorder();
    assert_eq!(
        project_on(&snap, &nothing, FROM, &doc1(), &recorder),
        Err(QueryError::NotALink)
    );
    assert_eq!(
        asked.take(),
        vec![doc2()],
        "project asks before the resident-link read"
    );
    assert_eq!(
        addressably_discoverable_from_on(&snap, &nothing, &doc1(), &recorder),
        Err(QueryError::NotALink)
    );
    assert_eq!(
        asked.take(),
        vec![doc2()],
        "addressably_discoverable_from asks before the resident-link read"
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
    let reads = Reads(&k);

    // Well under the budget, both answer.
    reads
        .project(&e1, FROM, &doc1())
        .expect("well under the budget");
    assert_eq!(reads.addressably_discoverable_from(&e1, &doc1()), Ok(true));

    // Fragment doc2 to exactly the budget: one COPY placing the SAME source
    // position many times — each placement is a width-1 run that abuts
    // nothing, so the arrangement holds one run per spec rather than
    // coalescing them. This is the world quantity the budget prices, and a
    // caller can build it far faster than a reader can pay for it.
    let vstream = Vstream::new(&k);
    let specs = vec![spec(&doc1(), 1, 1, 1); MAX_IMAGE_RUNS];
    vstream.copy(SYS, &doc2(), vp(1, 1), &specs).expect("copy succeeds");
    let snap = k.snapshot();
    assert_eq!(snap.world().m5().content_runs(&doc2()).len(), MAX_IMAGE_RUNS);
    assert_eq!(snap.world().m5().link_runs(&doc2()).len(), 0);
    reads
        .project(&e1, FROM, &doc2())
        .expect("MAX content runs");
    reads
        .addressably_discoverable_from(&e1, &doc2())
        .expect("MAX runs over both subspaces");

    // ONE link run seated in doc2 — and the two counts part company. The
    // content runs are untouched, so `project` still answers; the LINK runs
    // put `addressably_discoverable_from` one over, because LP12 ranges over
    // both subspaces and it must price both.
    link(&store, &doc2(), &[ca(1)], &[ca(103)]);
    let snap = k.snapshot();
    assert_eq!(snap.world().m5().content_runs(&doc2()).len(), MAX_IMAGE_RUNS);
    assert_eq!(snap.world().m5().link_runs(&doc2()).len(), 1);
    reads
        .project(&e1, FROM, &doc2())
        .expect("its content runs are still MAX");
    assert_eq!(
        reads.addressably_discoverable_from(&e1, &doc2()),
        Err(QueryError::ImageTooLarge)
    );

    // One CONTENT run past it, and both refuse — the quantities differ, the
    // constant does not.
    vstream.copy(SYS, &doc2(), vp(1, 1), &[spec(&doc1(), 1, 1, 1)])
        .expect("copy succeeds");
    assert_eq!(
        reads.project(&e1, FROM, &doc2()),
        Err(QueryError::ImageTooLarge)
    );
    assert_eq!(
        reads.addressably_discoverable_from(&e1, &doc2()),
        Err(QueryError::ImageTooLarge)
    );
    // The unregistered `d` shows the document gate's own verdict, and no
    // order: an unregistered document carries no runs, so it has no budget to
    // be refused ahead of. The order is shown by the arguments about `a`,
    // asked of a `d` PAST the budget — a non-link, and an `a` absent to the
    // reader, are each refused ahead of it, on both reads.
    assert_eq!(
        reads.project(&e1, FROM, &unregistered_doc()),
        Err(QueryError::DocNotRegistered)
    );
    assert_eq!(reads.project(&ca(1), FROM, &doc2()), Err(QueryError::NotALink));
    assert_eq!(
        reads.addressably_discoverable_from(&ca(1), &doc2()),
        Err(QueryError::NotALink)
    );
    let cannot_read_doc1 = |d: &Address| *d != doc1();
    let snap = k.snapshot();
    assert_eq!(
        addressably_discoverable_from_on(&snap, &e1, &doc2(), &cannot_read_doc1),
        Err(QueryError::NotALink)
    );
    assert_eq!(
        project_on(&snap, &e1, FROM, &doc2(), &cannot_read_doc1),
        Err(QueryError::NotALink)
    );
    // A RETRACTED `a` answers `addressably_discoverable_from` between its
    // `NotALink` and its budget, so it never meets the budget; `project`,
    // which no retraction narrows, still does.
    store.nullify(SYS, &doc2(), &e1).expect("nullify succeeds");
    assert_eq!(reads.addressably_discoverable_from(&e1, &doc2()), Ok(false));
    assert_eq!(
        reads.project(&e1, FROM, &doc2()),
        Err(QueryError::ImageTooLarge)
    );
}

/// §5 — both pointwise budgets count the runs of `d`'s READING SURFACE, the
/// arrangement each read joins against, never the document named
/// (HEAD-FLOAT, PUB-2.53). The test above holds the run constant on a private
/// document, where the two are one arrangement, and `published_world` holds
/// one run on either side, so a count taken off the address named — the count
/// the delete preview takes, which reads `d` because the preview does not
/// float — passes every other test. Here pdoc's own arrangement holds one
/// run and its head `MAX`, and the steps are that test's: at `MAX` content
/// runs both reads answer; one link seated in the head puts
/// `addressably_discoverable_from`, which counts both subspaces, past its
/// budget while `project`, which counts content alone, answers; one declared
/// deposit on the head puts both past it. Each verdict is asked of pdoc and
/// of the head, which must agree. These are reads the daemon runs with no
/// scan permit, on documents a guest may read.
#[test]
fn the_pointwise_budgets_count_the_trunk_heads_runs_not_the_address_named() {
    let k = fragmented_head_world(MAX_IMAGE_RUNS);
    let store = LinkWriter::new(&k, &EVERYONE);
    let e1 = link(&store, &doc1(), &[pca(1)], &[ca(101)]); // touches every run of the head
    let reads = Reads(&k);
    let snap = k.snapshot();
    assert_eq!(
        snap.world().m5().content_runs(&phead()).len(),
        MAX_IMAGE_RUNS
    );
    assert_eq!(snap.world().m5().content_runs(&pdoc()).len(), 1);
    for d in [pdoc(), phead()] {
        assert_eq!(
            reads.project(&e1, FROM, &d).err(),
            None,
            "{d:?}: MAX content runs"
        );
        assert_eq!(
            reads.addressably_discoverable_from(&e1, &d),
            Ok(true),
            "{d:?}"
        );
    }

    // One link HOMED in the head, so seated in the head's own link subspace
    // (ASN-0047 CL-OWN), and in none of pdoc's.
    link(&store, &phead(), &[pca(1)], &[ca(102)]);
    let snap = k.snapshot();
    assert_eq!(snap.world().m5().link_runs(&phead()).len(), 1);
    assert_eq!(snap.world().m5().link_runs(&pdoc()).len(), 0);
    for d in [pdoc(), phead()] {
        assert_eq!(
            reads.project(&e1, FROM, &d).err(),
            None,
            "{d:?}: content alone, still MAX"
        );
        assert_eq!(
            reads.addressably_discoverable_from(&e1, &d),
            Err(QueryError::ImageTooLarge),
            "{d:?}: both subspaces, MAX + 1"
        );
    }

    // One declared deposit, which lands on the head as a run of its own.
    seed_published_content(&k, &pdoc(), 1);
    assert_eq!(
        k.snapshot().world().m5().content_runs(&phead()).len(),
        MAX_IMAGE_RUNS + 1
    );
    for d in [pdoc(), phead()] {
        assert_eq!(
            reads.project(&e1, FROM, &d),
            Err(QueryError::ImageTooLarge),
            "{d:?}"
        );
        assert_eq!(
            reads.addressably_discoverable_from(&e1, &d),
            Err(QueryError::ImageTooLarge),
            "{d:?}"
        );
    }
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
    let vstream = Vstream::new(&k);
    let specs = vec![spec(&doc1(), 1, 1, 1); MAX_IMAGE_RUNS - 1];
    vstream.copy(SYS, &doc2(), vp(1, 1), &specs).expect("copy succeeds");
    let reads = Reads(&k);
    assert_eq!(
        k.snapshot().world().m5().link_runs(&doc2()).len(),
        0,
        "both links are seated in doc1, so doc2's runs are its content alone"
    );

    // (M + 1)(M − 1) = M² − 1: inside the square.
    assert_eq!(reads.addressably_discoverable_from(&wider, &doc2()), Ok(true));

    // One run more. The run count is AT the budget, which admits it; the
    // product is (M + 1)M, past the square.
    vstream.copy(SYS, &doc2(), vp(1, 1), &[spec(&doc1(), 1, 1, 1)])
        .expect("copy succeeds");
    assert_eq!(
        k.snapshot().world().m5().content_runs(&doc2()).len(),
        MAX_IMAGE_RUNS
    );
    assert_eq!(
        reads.addressably_discoverable_from(&wider, &doc2()),
        Err(QueryError::ImageTooLarge)
    );
    // M × M: the square itself is admitted.
    assert_eq!(reads.addressably_discoverable_from(&exact, &doc2()), Ok(true));
}

/// §5 — the touch test BUILDS NOTHING PER PAIR. Its join is held to the
/// square of `MAX_IMAGE_RUNS`, which that constant argues as M6's COMPARE
/// budget — comparisons of endpoints derived once — and the daemon runs this
/// read with no scan permit on the strength of it. A test that derived a
/// span's reach for every (coverage span, run) PAIR, as M1's `classify_spans`
/// does and M7's private overlap does through it, answers exactly as the
/// right one does while paying heap work the square never priced: no answer
/// shows it, and the heap does. Every span of both links names an address
/// past doc2's one arranged position, so no pair touches, `any` never stops
/// early, and every pair is tested — and thirty-two runs more then cost a
/// link three spans wide exactly the heap bytes they cost a link forty-two
/// spans wide: their extents and a reach apiece, and nothing per span they
/// meet.
#[test]
fn the_touch_test_builds_nothing_per_pair() {
    let k = kernel();
    seed_content(&k, &doc1(), 1); // ca(1): the one address every run of doc2 holds
    let store = LinkWriter::new(&k, &EVERYONE);
    // Homed, and so seated, in doc1, so doc2's runs are its content alone.
    let narrow = link(&store, &doc1(), &[ca(1001)], &[ca(101)]); // three spans in all
    let forty: Vec<Address> = (1001..1041).map(ca).collect();
    let wide = link(&store, &doc1(), &forty, &[ca(101)]); // forty-two
    let vstream = Vstream::new(&k);
    let specs = vec![spec(&doc1(), 1, 1, 1); 32];
    vstream
        .copy(SYS, &doc2(), vp(1, 1), &specs)
        .expect("copy succeeds");
    let fewer = k.snapshot();
    vstream
        .copy(SYS, &doc2(), vp(1, 1), &specs)
        .expect("copy succeeds");
    let more = k.snapshot();
    assert_eq!(fewer.world().m5().content_runs(&doc2()).len(), 32);
    assert_eq!(more.world().m5().content_runs(&doc2()).len(), 64);
    assert_eq!(more.world().m5().link_runs(&doc2()).len(), 0);

    let d = doc2();
    let heap_of = |snap: &Snapshot<World>, a: &Address| -> u64 {
        let (answer, bytes) =
            heap_bytes(|| addressably_discoverable_from_on(snap, a, &d, &every_home));
        assert_eq!(
            answer,
            Ok(false),
            "{a:?}: every pair is tested, and none touches"
        );
        bytes
    };
    let narrow_added = heap_of(&more, &narrow) - heap_of(&fewer, &narrow);
    let wide_added = heap_of(&more, &wide) - heap_of(&fewer, &wide);
    assert_eq!(
        wide_added, narrow_added,
        "thirty-two runs more cost the same heap whatever the coverage they meet"
    );
}

/// §5 — `project`'s join product is the ANSWER it builds and not merely the
/// work it does: M5 pushes one V-span per overlapping (run, coverage span)
/// pair into one vector before it normalizes. A coverage of REPEATED spans —
/// `enc` maps a repeated address to a repeated span, so the count is the
/// depositor's to choose up to M7's slot cap — over a document whose runs all
/// sit at one address realizes that product in full, for an answer that
/// normalizes to a single span. So it is held at the ANSWER budget, where the
/// touch test beside it, whose join is a boolean that builds nothing per
/// pair, keeps the square: the same link the projection refuses is answered
/// there, which is what shows the two products are two numbers for a reason.
#[test]
fn project_holds_its_product_to_the_answer_budget() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    // Every run of doc2 at ONE address, so every coverage span covers every
    // run and no (run, span) pair is skipped.
    Vstream::new(&k)
        .copy(
            SYS,
            &doc2(),
            vp(1, 1),
            &vec![spec(&doc1(), 1, 1, 1); MAX_IMAGE_RUNS],
        )
        .expect("copy succeeds");
    assert_eq!(
        k.snapshot().world().m5().content_runs(&doc2()).len(),
        MAX_IMAGE_RUNS
    );
    let spans = MAX_ANSWER_SPANS / MAX_IMAGE_RUNS; // 16: the answer budget exactly
    let at_budget = link(&store, &doc1(), &vec![ca(1); spans], &[ca(101)]);
    let past = link(&store, &doc1(), &vec![ca(1); spans + 1], &[ca(101)]);
    let reads = Reads(&k);

    // At the budget the product is realized in full and normalizes to doc2's
    // whole content — one span out of the 2^16 M5 built to find it.
    let proj = reads
        .project(&at_budget, FROM, &doc2())
        .expect("at the answer budget");
    assert_eq!(
        proj.len(),
        1,
        "normalized — the 2^16 spans M5 built are one"
    );
    assert!(proj.denotes(&t(&[1, 1])));
    assert!(proj.denotes(&t(&[1, MAX_IMAGE_RUNS as u32])));
    assert!(!proj.denotes(&t(&[1, MAX_IMAGE_RUNS as u32 + 1])));
    // One span more in the slot, and the product is past it. The run count is
    // unchanged and still within its own budget, so this refusal is the
    // product's alone.
    assert_eq!(
        reads.project(&past, FROM, &doc2()),
        Err(QueryError::ImageTooLarge)
    );
    // The touch test keeps the square, so the same link answers there.
    assert_eq!(reads.addressably_discoverable_from(&past, &doc2()), Ok(true));
}
