//! The promises M8 makes to a consumer rather than to itself, checked from
//! outside the crate: the snapshot twins, one named world bound, the
//! standard traits its values carry, the handle's bound reader, and
//! rejection enums that stay exhaustively matchable.

use crate::common;

use std::collections::HashSet;

use common::*;
use skep_address::{Address, Span};
use skep_discovery::{
    addressably_discoverable_from_on, count_ftt_on, count_v_on, delete_orphans_on,
    findlinks_ftt_on, findlinks_v_on, in_claims_on, out_claims_on, project_on, retrieve_endsets_on,
    window_ftt_on, window_v_on, DiscoveryWorld, FourSet, LinkQuery, OrphanError, OrphanReport,
    QueryError, SlotSpec, SupClaim, Window, FROM,
};
use skep_kernel::Snapshot;
use skep_links::{enc, Endset, LinkWriter, View};

#[test]
fn snapshot_twins_read_one_pinned_state() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k, &every_home);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let region = [vspan(1, 1, 1)];

    // Pin one snapshot, then write past it: the twins keep answering off the
    // pinned root (a count and its window off ONE consistent state), while
    // the handle's fresh snapshot sees the new link.
    let snap = k.snapshot();
    assert_eq!(count_v_on(&snap, &doc1(), &region, &every_home), Ok(1));
    link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    assert_eq!(count_v_on(&snap, &doc1(), &region, &every_home), Ok(1));
    let w = window_v_on(&snap, &doc1(), &region, None, 10, &every_home).expect("window");
    assert_eq!(w.batch, vec![la(1)]);
    assert_eq!(lq.count_v(&doc1(), &region), Ok(2));
}

/// The shape a caller composing two M8 reads has to write: ONE bound naming
/// the world, not the four slices behind it. Blanket-implemented, so the
/// assembled test world satisfies it by satisfying the accessors — which is
/// what the call below proves.
fn region_and_home_census<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
) -> Result<(usize, usize), QueryError> {
    let reaching = count_v_on(s, d, region, &every_home)?;
    let homed = count_ftt_on(
        s,
        &FourSet {
            home: SlotSpec::Spans(enc([d])),
            ..Default::default()
        },
        &every_home,
    );
    Ok((reaching, homed))
}

/// One bound names the world M8 reads under, and `Default` is the wildcard
/// base a narrowed descriptor is built from — so a consumer writes the query
/// it means and leaves no slot at something other than the unit by accident.
#[test]
fn one_named_bound_and_the_unit_descriptor_serve_a_composing_caller() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    link(&store, &doc2(), &[ca(1)], &[ca(102)]);

    // Both reads off ONE pinned snapshot, through one bound. The two censuses
    // answer different questions about doc1: BOTH links reach its position 1
    // (each from-slot covers ca(1)), and only one is homed there.
    let snap = k.snapshot();
    assert_eq!(
        region_and_home_census(&snap, &doc1(), &[vspan(1, 1, 1)]),
        Ok((2, 1))
    );
    // And about doc2, which arranges nothing yet homes a link — the region
    // zero and the descriptor count, side by side.
    assert_eq!(
        region_and_home_census(&snap, &doc2(), &[vspan(1, 1, 1)]),
        Ok((0, 1))
    );

    // Default IS the unit, at both levels: an unstated slot constrains
    // nothing, and a descriptor built from neither constrains anything.
    assert_eq!(SlotSpec::default(), SlotSpec::Any);
    assert_eq!(FourSet::default(), FourSet::any());
}

/// The values M8 hands back are hashable, so a caller can key on a request
/// and dedup an answer — every field they hold already hashes, and the
/// orphan rule puts the impl out of a consumer's reach.
///
/// Keying is REPRESENTATIONAL: the two spellings of the zero are one query
/// and two keys. A missed hit, never a wrong answer, and the semantic test is
/// `is_unsatisfiable`.
#[test]
fn the_value_surface_is_hashable_and_keys_by_representation() {
    let q_any = FourSet::any();
    let q_from = FourSet {
        from: SlotSpec::Spans(enc(&[ca(1)])),
        ..FourSet::any()
    };
    let mut memo: HashSet<FourSet> = HashSet::new();
    assert!(memo.insert(q_any.clone()));
    assert!(memo.insert(q_from.clone()));
    assert!(!memo.insert(q_any.clone())); // an equal descriptor hits
    assert!(memo.contains(&q_from));

    let explicit = FourSet {
        to: SlotSpec::Empty,
        ..FourSet::any()
    };
    let spelled = FourSet {
        to: SlotSpec::Spans(Endset::empty()),
        ..FourSet::any()
    };
    assert!(explicit.is_unsatisfiable() && spelled.is_unsatisfiable()); // one query
    assert!(memo.insert(explicit) && memo.insert(spelled)); // two keys

    // The answer types too: a lineage graph dedups its claims, a window and a
    // report ride in whatever container a caller reaches for.
    let claim = SupClaim {
        claim: la(3),
        old: la(1),
        new: la(2),
        home: doc1(),
        active: true,
    };
    let mut claims: HashSet<SupClaim> = HashSet::new();
    assert!(claims.insert(claim.clone()));
    assert!(!claims.insert(claim));
    let mut windows: HashSet<Window> = HashSet::new();
    assert!(windows.insert(Window {
        batch: vec![la(1)],
        next: Some(la(1)),
        exhausted: true,
    }));
    let mut reports: HashSet<OrphanReport> = HashSet::new();
    assert!(reports.insert(OrphanReport {
        orphaned: vec![la(1)]
    }));
}

/// The handle is a borrow — of the kernel and its reader — and behaves as one:
/// it prints without asking `W: Debug`, and it copies — a copy binds the same
/// kernel and reader and snapshots afresh, so it answers what the original
/// answers. A consumer holding one in a struct of its own derives over it,
/// which is the wall a missing impl would be.
#[test]
fn the_handle_debugs_and_copies_like_the_borrow_it_is() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let lq = LinkQuery::new(&k, &every_home);
    assert_eq!(format!("{lq:?}"), "LinkQuery { .. }");

    #[derive(Debug, Clone, Copy)]
    struct Consumer<'k> {
        links: LinkQuery<'k, World>,
    }
    let consumer = Consumer { links: lq }; // lq is Copy — not moved
    assert!(format!("{consumer:?}").starts_with("Consumer { links: LinkQuery { .. }"));
    assert_eq!(consumer.links.count_ftt(&FourSet::any()), 1);
    assert_eq!(lq.count_ftt(&FourSet::any()), 1);
}

/// The handle answers for the reader it is BOUND to, on every method that
/// takes one: bound to a reader that may not read doc2, each of the twelve
/// answers what its `*_on` read answers under that reader off the same state,
/// and differently from the handle bound to the total predicate — so a method
/// that swapped the bound reader for a total one would return doc2's links.
/// The reader it binds is `Sync`, so the handle crosses threads wherever the
/// kernel does.
#[test]
fn the_handle_answers_for_the_reader_it_is_bound_to() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let m0 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    // Homed in doc2, under a FROM no doc1 link carries, so it is also a pair
    // of its own to RETRIEVEENDSETS.
    let t0 = link(&store, &doc2(), &[ca(1), ca(102)], &[ca(103)]);
    let (claim, _) = store
        .assert_sup(SYS, &doc2(), &m0, &t0)
        .expect("assert_sup succeeds");
    assert_eq!(claim, la2(2), "the claim is homed in doc2 too");
    let cannot_read_doc2 = |d: &Address| *d != doc2();
    let bound = LinkQuery::new(&k, &cannot_read_doc2);
    let total = LinkQuery::new(&k, &every_home);
    let snap = k.snapshot();
    let region = [vspan(1, 1, 1)];
    let q = FourSet::any();

    // The region family.
    let found = bound.findlinks_v(&doc1(), &region);
    assert_eq!(
        found,
        findlinks_v_on(&snap, &doc1(), &region, &cannot_read_doc2)
    );
    assert_ne!(found, total.findlinks_v(&doc1(), &region));
    let counted = bound.count_v(&doc1(), &region);
    assert_eq!(
        counted,
        count_v_on(&snap, &doc1(), &region, &cannot_read_doc2)
    );
    assert_ne!(counted, total.count_v(&doc1(), &region));
    let page = bound.window_v(&doc1(), &region, None, 5);
    assert_eq!(
        page,
        window_v_on(&snap, &doc1(), &region, None, 5, &cannot_read_doc2)
    );
    assert_ne!(page, total.window_v(&doc1(), &region, None, 5));
    let pairs = bound.retrieve_endsets(&doc1(), &region);
    assert_eq!(
        pairs,
        retrieve_endsets_on(&snap, &doc1(), &region, &cannot_read_doc2)
    );
    assert_ne!(pairs, total.retrieve_endsets(&doc1(), &region));

    // The descriptor family.
    let found = bound.findlinks_ftt(&q);
    assert_eq!(found, findlinks_ftt_on(&snap, &q, &cannot_read_doc2));
    assert_ne!(found, total.findlinks_ftt(&q));
    let counted = bound.count_ftt(&q);
    assert_eq!(counted, count_ftt_on(&snap, &q, &cannot_read_doc2));
    assert_ne!(counted, total.count_ftt(&q));
    let page = bound.window_ftt(&q, None, 5);
    assert_eq!(page, window_ftt_on(&snap, &q, None, 5, &cannot_read_doc2));
    assert_ne!(page, total.window_ftt(&q, None, 5));

    // The pointwise pair, asked of the doc2-homed link.
    let projected = bound.project(&t0, FROM, &doc1());
    assert_eq!(
        projected,
        project_on(&snap, &t0, FROM, &doc1(), &cannot_read_doc2)
    );
    assert_ne!(projected, total.project(&t0, FROM, &doc1()));
    let reached = bound.addressably_discoverable_from(&t0, &doc1());
    assert_eq!(
        reached,
        addressably_discoverable_from_on(&snap, &t0, &doc1(), &cannot_read_doc2)
    );
    assert_ne!(reached, total.addressably_discoverable_from(&t0, &doc1()));

    // The preview: both links lose their only witness, and only m0 is
    // reported to the bound reader.
    let orphans = bound.delete_orphans(&doc1(), &vp(1, 1), &n(1));
    assert_eq!(
        orphans,
        delete_orphans_on(&snap, &doc1(), &vp(1, 1), &n(1), &cannot_read_doc2)
    );
    assert_ne!(orphans, total.delete_orphans(&doc1(), &vp(1, 1), &n(1)));

    // The lineage pair: the claim is homed in doc2.
    let claims = bound.in_claims(&m0, View::Active);
    assert_eq!(
        claims,
        in_claims_on(&snap, &m0, View::Active, &cannot_read_doc2)
    );
    assert_ne!(claims, total.in_claims(&m0, View::Active));
    let claims = bound.out_claims(&t0, View::Active);
    assert_eq!(
        claims,
        out_claims_on(&snap, &t0, View::Active, &cannot_read_doc2)
    );
    assert_ne!(claims, total.out_claims(&t0, View::Active));

    // The bound reader is `Sync`, so the handle crosses threads as the kernel
    // does; this fails to compile the day it does not.
    fn crosses_threads<T: Send + Sync>(_: &T) {}
    crosses_threads(&bound);
}

/// Both rejection enums are exhaustively matchable from OUTSIDE the crate —
/// this suite is a crate of its own, so these matches are the check that
/// they stay so. A consumer's `match` without a catch-all is a completeness
/// proof (M10 must give every refusal a wire code); sealing either enum, or
/// adding a variant, has to fail a build rather than fall into a default arm.
#[test]
fn every_refusal_is_matchable_without_a_catch_all() {
    fn query_word(e: QueryError) -> &'static str {
        match e {
            QueryError::DocNotRegistered => "doc",
            QueryError::NotALink => "link",
            QueryError::BadRegion => "region",
            QueryError::ImageTooLarge => "runs",
            QueryError::EndsetsTooLarge => "spans",
        }
    }
    fn orphan_word(e: OrphanError) -> &'static str {
        match e {
            OrphanError::DocNotRegistered => "doc",
            OrphanError::NotContentSubspace => "subspace",
            OrphanError::EmptyWidth => "width",
            OrphanError::OutOfBounds => "bounds",
            OrphanError::ImageTooLarge => "runs",
        }
    }
    assert_eq!(query_word(QueryError::BadRegion), "region");
    assert_eq!(orphan_word(OrphanError::EmptyWidth), "width");

    // `Display` names the surface that refused, on EVERY variant, so a
    // relayed refusal says which of the two vocabularies it came from. The
    // matches above fail the build when a variant is added; these lists do
    // not, and are extended beside them by hand.
    for e in [
        QueryError::DocNotRegistered,
        QueryError::NotALink,
        QueryError::BadRegion,
        QueryError::ImageTooLarge,
        QueryError::EndsetsTooLarge,
    ] {
        assert!(e.to_string().starts_with("query: "), "{e:?} renders {e}");
    }
    for e in [
        OrphanError::DocNotRegistered,
        OrphanError::NotContentSubspace,
        OrphanError::EmptyWidth,
        OrphanError::OutOfBounds,
        OrphanError::ImageTooLarge,
    ] {
        assert!(
            e.to_string().starts_with("delete-orphans: "),
            "{e:?} renders {e}"
        );
    }
}
