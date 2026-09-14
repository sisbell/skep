//! The promises M8 makes to a consumer rather than to itself, checked from
//! outside the crate: reads that answer off the snapshot they are handed,
//! one named world bound, the standard traits its values carry, a request and
//! answer vocabulary reachable through this crate alone, and rejection enums
//! that stay exhaustively matchable.

use crate::common;

use std::collections::HashSet;

use common::*;
use skep_address::{Address, Span};
use skep_discovery::{
    count_ftt_on, count_v_on, window_v_on, DiscoveryWorld, FourSet, OrphanError, OrphanReport,
    QueryError, SlotSpec, SupClaim, Window,
};
use skep_kernel::Snapshot;
use skep_links::{enc, Endset, LinkWriter};

#[test]
fn a_read_answers_off_the_snapshot_it_is_handed() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let region = [vspan(1, 1, 1)];

    // Pin one snapshot, then write past it: the reads handed the pinned
    // snapshot keep answering off it (a count and its window off ONE state),
    // while a read handed a fresh snapshot sees the new link.
    let snap = k.snapshot();
    assert_eq!(count_v_on(&snap, &doc1(), &region, &every_home), Ok(1));
    link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    assert_eq!(count_v_on(&snap, &doc1(), &region, &every_home), Ok(1));
    let w = window_v_on(&snap, &doc1(), &region, None, 10, &every_home).expect("window");
    assert_eq!(w.batch, vec![la(1)]);
    assert_eq!(count_v_on(&k.snapshot(), &doc1(), &region, &every_home), Ok(2));
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

/// Every type M8's own signatures name is reachable under `skep_discovery`:
/// the descriptor slot's `Endset` and the lift that builds one, the lineage
/// pair's `View`, the runs `image_on` answers with, and the `VPos` the region
/// constructor and the delete preview are asked at. So a caller that depends
/// on this crate can build M8's requests and name its answers without also
/// naming the store each type came from — only M1's value calculus is left
/// out, which every consumer of any store crate already holds.
///
/// The check is the BUILD: every path below is spelled `m8::`, so dropping a
/// re-export fails to compile rather than leaving a signature a caller cannot
/// spell. Without the `View` re-export the lineage pair is uncallable, and
/// without `Endset`/`enc` a descriptor cannot be narrowed past the wildcard.
#[test]
fn m8s_request_and_answer_types_are_reachable_through_this_crate() {
    use skep_discovery as m8;

    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let e2 = link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    let (claim, _) = store
        .assert_sup(SYS, &doc1(), &e1, &e2)
        .expect("assert_sup succeeds");
    let snap = k.snapshot();

    // A descriptor narrowed past the wildcard: the slot's endset, and the
    // address lift that builds one. Under the flipped storage convention the
    // claim is the one link naming `e1` at FROM.
    let from_e1: m8::Endset = m8::enc([&e1]);
    let q = m8::FourSet {
        from: m8::SlotSpec::Spans(from_e1),
        ..m8::FourSet::any()
    };
    assert_eq!(
        m8::findlinks_ftt_on(&snap, &q, &every_home),
        vec![claim.clone()]
    );

    // The lineage pair's view, which without the re-export has no path at all.
    let found: Vec<m8::SupClaim> = m8::in_claims_on(&snap, &e1, m8::View::Active, &every_home);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].claim, claim);

    // The V-position both the region constructor and the preview are asked at,
    // and the runs the image answers with.
    let at = m8::VPos {
        subspace: n(1),
        ordinal: n(1),
    };
    let region = [m8::content_vspan(&at, &n(1)).expect("s_C, count ≥ 1")];
    let image: Vec<m8::Run> = m8::image_on(&snap, &doc1(), &region).expect("image");
    assert_eq!(image.len(), 1);
    assert_eq!(image[0].i_start(), &ca(1));
    let pairs: Vec<(usize, m8::Endset)> =
        m8::retrieve_endsets_on(&snap, &doc1(), &region, &every_home).expect("retrieve_endsets");
    assert_eq!(pairs, vec![(m8::FROM, m8::enc(&[ca(1)]))]);
    let report: m8::OrphanReport =
        m8::delete_orphans_on(&snap, &doc1(), &at, &n(1), &every_home).expect("preview");
    assert_eq!(report.orphaned, vec![e1, e2]);
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
