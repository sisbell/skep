//! HEAD-FLOAT (PUB-2.49, PUB-2.50, PUB-2.53) — which arrangement a read
//! answers from, the law the crate doc states for every read but the
//! preview: a bare published address floats to its trunk head, a pinned
//! version member answers its own, and registered-empty is decided of the
//! reading surface — asked of the region family and the pointwise pair
//! alike, and of both subspaces discoverability reads. What a budget counts
//! on a head is its family's (`region`, `pointwise`), and the preview, which
//! does not float, is `survival`'s.

use crate::common;

use common::*;
use skep_arrangement::{HasM5, Vstream};
use skep_discovery::{FROM, TO, TYPE};
use skep_links::{enc, LinkWriter};
use skep_namespace::PrincipalId;

/// §1 — HEAD-FLOAT on every region read, not only the two the pointwise
/// pair's head-float law composes with: `image_on` states that the whole
/// family inherits its float, so each of the five is asked. Position 3 exists
/// only in pdoc's trunk head, so any one read resolving pdoc's own frozen
/// arrangement would answer empty there.
#[test]
fn every_region_read_resolves_a_published_document_through_its_trunk_head() {
    let k = published_world();
    let store = LinkWriter::new(&k, &EVERYONE);
    let head_only = link(&store, &doc1(), &[pca(3)], &[ca(102)]);
    let reads = Reads(&k);
    let region = [vspan(1, 3, 1)];
    assert_eq!(reads.image(&pdoc(), &region), Ok(vec![run(&pca(3), 1)]));
    assert_eq!(reads.findlinks_v(&pdoc(), &region), Ok(vec![head_only.clone()]));
    assert_eq!(reads.count_v(&pdoc(), &region), Ok(1));
    assert_eq!(
        reads.window_v(&pdoc(), &region, None, 5).map(|w| w.batch),
        Ok(vec![head_only])
    );
    assert_eq!(
        reads.retrieve_endsets(&pdoc(), &region),
        Ok(vec![(FROM, enc(&[pca(3)]))])
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

/// §1 — the empty answer the document gate draws apart from
/// `DocNotRegistered` is the READING SURFACE's, not the address named's: a
/// published document versioned while it arranges nothing takes every later
/// deposit on its head, so its own arrangement stays empty while every reader
/// of it sees the head. Each read here answers from the head, and a caller
/// that skipped one because `d` itself arranges nothing — the count the
/// delete preview reads, which does not float — would miss what it answers.
/// The other published fixtures arrange something of pdoc's own, where a read
/// that took `d`'s own emptiness for its surface's would answer alike.
#[test]
fn a_published_document_whose_own_arrangement_is_empty_answers_from_its_head() {
    let k = kernel();
    let (head, _) = Vstream::new(&k)
        .version(PrincipalId(1), &pdoc(), None)
        .expect("the owner versions its empty published document");
    assert_eq!(head, phead(), "the chain's first member");
    seed_published_content(&k, &pdoc(), 2); // lands on the head alone
    let store = LinkWriter::new(&k, &EVERYONE);
    let e1 = link(&store, &doc1(), &[pca(1)], &[ca(101)]);
    let snap = k.snapshot();
    assert_eq!(
        snap.world().m5().content_count(&pdoc()),
        n(0),
        "pdoc arranges nothing of its own"
    );
    assert_eq!(snap.world().m5().content_count(&phead()), n(2));

    let reads = Reads(&k);
    let region = [vspan(1, 1, 2)];
    assert_eq!(reads.image(&pdoc(), &region), Ok(vec![run(&pca(1), 2)]));
    assert_eq!(reads.findlinks_v(&pdoc(), &region), Ok(vec![e1.clone()]));
    assert!(reads
        .project(&e1, FROM, &pdoc())
        .expect("project")
        .denotes(&t(&[1, 1])));
    assert_eq!(reads.addressably_discoverable_from(&e1, &pdoc()), Ok(true));
}

/// §1/§5 — HEAD-FLOAT moves the BARE published address and nothing else: a
/// VERSION address answers its own arrangement forever (PUB-2.50), even once
/// a later member has become the head. Every other published fixture reads
/// `phead` while it IS the head, where "a member answers itself" and "every
/// address of the chain answers the head" — the rule M5's deposit surface
/// keeps, and a reader must not — give one answer, so a read that floated a
/// member to the head would pass them all and answer a question about an
/// older version with the latest one. Here a second VERSION pins `phead`, and
/// one declared deposit lands on the new head alone: the link naming that
/// position reaches the bare address and the head, and no read finds it
/// through the pinned member.
#[test]
fn a_pinned_version_member_answers_its_own_arrangement_not_the_heads() {
    let k = published_world(); // phead holds pca(1..=4)
    let (new_head, _) = Vstream::new(&k)
        .version(PrincipalId(1), &pdoc(), None)
        .expect("the owner versions its published document again");
    assert_eq!(
        new_head,
        a(&[1, 0, 1, 0, 3, 2]),
        "the chain's second member"
    );
    seed_published_content(&k, &pdoc(), 1); // pca(5), on the new head alone
    let store = LinkWriter::new(&k, &EVERYONE);
    let latest = link(&store, &doc1(), &[pca(5)], &[ca(101)]);
    let snap = k.snapshot();
    assert_eq!(snap.world().m5().content_count(&new_head), n(5));
    assert_eq!(
        snap.world().m5().content_count(&phead()),
        n(4),
        "phead keeps what it held when it was pinned"
    );

    let reads = Reads(&k);
    let fifth = [vspan(1, 5, 1)];
    for d in [pdoc(), new_head.clone()] {
        assert_eq!(reads.image(&d, &fifth), Ok(vec![run(&pca(5), 1)]), "{d:?}");
        assert_eq!(
            reads.findlinks_v(&d, &fifth),
            Ok(vec![latest.clone()]),
            "{d:?}"
        );
        assert_eq!(
            reads.addressably_discoverable_from(&latest, &d),
            Ok(true),
            "{d:?}"
        );
    }
    assert_eq!(reads.image(&phead(), &fifth), Ok(vec![]));
    assert_eq!(reads.findlinks_v(&phead(), &fifth), Ok(vec![]));
    assert_eq!(reads.count_v(&phead(), &fifth), Ok(0));
    assert!(reads
        .project(&latest, FROM, &phead())
        .expect("project")
        .is_empty());
    assert_eq!(
        reads.addressably_discoverable_from(&latest, &phead()),
        Ok(false)
    );
}
