//! §1 — content-region discovery: `image_on`'s gates, order, every placement
//! answered, and budget — the runs a region resolves, however far along a
//! surface its spans reach, refused before the work it exists to refuse — and
//! the six region reads that inherit them, with the document gate asked,
//! where it is one rule, of every read that names a document; and the
//! retracted-links read's own law beside the active family's. Which
//! arrangement the reads resolve is `head_float`'s.

use crate::common;
use crate::heap::settled_heap_bytes;

use common::*;
use im::OrdSet;
use skep_address::{document_of, Address, Span};
use skep_arrangement::AsOf;
use skep_arrangement::{HasM5, Run, Vstream};
use skep_discovery::{
    content_vspan, count_v_by_home_on, count_v_on, find_links_v_history_on, findlinks_v_on,
    image_on, window_v_on, HomeCounts, LinkRow, LinkRows, OrphanError, OrphanReport, QueryError,
    FROM, MAX_IMAGE_RUNS, TO, TYPE,
};
use skep_kernel::Snapshot;
use skep_links::{enc, Endset, HasLinks, LinkWriter, SlotArg, View, MAX_SLOT_SPANS};
use skep_namespace::{HasM3, Namespace, PrincipalId};

#[test]
fn region_family_gates_doc_then_region_then_defines_empty() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let reads = Reads(&k);

    // Unregistered d → DocNotRegistered, even with a bad region: the document
    // gate is the first act, the region gate second.
    assert_eq!(
        reads.image(&unregistered_doc(), &[vspan(2, 1, 1)]),
        Err(QueryError::DocNotRegistered)
    );
    assert_eq!(
        reads.retrieve_endsets(&unregistered_doc(), &[vspan(1, 1, 1)]),
        Err(QueryError::DocNotRegistered)
    );

    // Region gate: M5's ordinal-level depth-2 V-span shape, restricted to the
    // content subspace — never a silently-clipped different query. The
    // link-subspace span is a shape M5 accepts and M8's added clause refuses …
    assert_eq!(
        reads.findlinks_v(&doc1(), &[vspan(2, 1, 1)]),
        Err(QueryError::BadRegion)
    );
    // … while a non-depth-2 span and an action-point-1 width fail the shape
    // itself, exactly as M5's `is_ordinal_vspan` reads them.
    let deep = skep_address::Span::new(t(&[1, 1, 1]), t(&[0, 0, 1])).expect("T12-valid");
    assert!(!skep_arrangement::is_ordinal_vspan(&deep));
    assert_eq!(reads.count_v(&doc1(), &[deep]), Err(QueryError::BadRegion));
    let action_point_1 = skep_address::Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12-valid");
    assert!(!skep_arrangement::is_ordinal_vspan(&action_point_1));
    assert_eq!(
        reads.count_v(&doc1(), &[action_point_1]),
        Err(QueryError::BadRegion)
    );
    // One bad span anywhere in the region rejects the whole request.
    assert_eq!(
        reads.findlinks_v(&doc1(), &[vspan(1, 1, 1), vspan(2, 1, 1)]),
        Err(QueryError::BadRegion)
    );

    // The published constructor and the gate are two halves of ONE shape:
    // what content_vspan builds the gate accepts, and it declines exactly the
    // two requests that would have been BadRegion — a non-s_C subspace and a
    // zero count.
    let built = content_vspan(&vp(1, 1), &n(1)).expect("s_C, count ≥ 1");
    reads
        .count_v(&doc1(), &[built])
        .expect("the gate accepts what content_vspan builds");
    assert_eq!(content_vspan(&vp(2, 1), &n(1)), None);
    assert_eq!(content_vspan(&vp(1, 1), &n(0)), None);
    // The rule is "the content subspace", not "anything but the link
    // subspace", and it holds at every opening ordinal: over subspaces either
    // side of both numerals, ordinals from 0 — which names no position, and
    // which M5's constructor builds all the same — and counts from 0, the
    // constructor builds exactly at `s_C` with a count, builds the span it was
    // asked for, and the gate refuses exactly what it declines. A subspace-0 or
    // subspace-3 span it admitted would resolve silently to ∅, a different
    // query; a gate that refused ordinal 0 would refuse a span the constructor
    // builds.
    for subspace in 0..=3u32 {
        for ordinal in 0..=2u32 {
            for count in 0..=2u32 {
                let built = content_vspan(&vp(subspace, ordinal), &n(count));
                assert_eq!(
                    built.is_some(),
                    subspace == 1 && count >= 1,
                    "content_vspan at ({subspace}, {ordinal}), count {count}"
                );
                if let Some(span) = built {
                    // WHICH span, not merely that there is one: `count`
                    // positions FROM `at`, so a constructor that transposed the
                    // two, or ignored the ordinal, would still build a shape
                    // the gate accepts and name a different region.
                    assert_eq!(
                        span,
                        vspan(subspace, ordinal, count),
                        "content_vspan builds `count` positions from `at`"
                    );
                    assert_eq!(
                        reads.count_v(&doc1(), &[span]).err(),
                        None,
                        "the gate accepts what content_vspan builds at ordinal {ordinal}, \
                         count {count}"
                    );
                } else if count >= 1 {
                    assert_eq!(
                        reads.count_v(&doc1(), &[vspan(subspace, ordinal, count)]),
                        Err(QueryError::BadRegion),
                        "a region in subspace {subspace} is refused at ordinal {ordinal}"
                    );
                }
            }
        }
    }

    // Registered-but-empty d → a DEFINED empty result, distinct from
    // DocNotRegistered.
    assert_eq!(reads.findlinks_v(&doc2(), &[vspan(1, 1, 5)]), Ok(vec![]));
    assert_eq!(reads.count_v(&doc2(), &[vspan(1, 1, 5)]), Ok(0));
    let w = reads.window_v(&doc2(), &[vspan(1, 1, 5)], None, 3).expect("window");
    assert_eq!(w.batch, vec![]);
    assert_eq!(w.next, None);
    assert!(w.exhausted);
    assert_eq!(reads.retrieve_endsets(&doc2(), &[vspan(1, 1, 5)]), Ok(vec![]));
    assert_eq!(
        reads.count_v_by_home(&doc2(), &[vspan(1, 1, 5)], 3, &[]),
        Ok(HomeCounts { homes: vec![], exhausted: true }),
        "no row, and a walk of nothing is exhausted"
    );
    assert_eq!(
        reads.find_links_v_history(&doc2(), &[vspan(1, 1, 5)], None, 3),
        Ok(LinkRows { links: vec![], next: None, exhausted: true }),
        "the retracted-links read: no row, the cursor unchanged, exhausted"
    );

    // An empty region trivially passes the gate and yields the empty image.
    assert!(reads.image(&doc1(), &[]).expect("empty region is defined").is_empty());
}

/// One region ENTRY POINT — `image` or one of the six reads that route
/// through it — reduced to the refusal it answers with, so the gate rule can
/// be stated once and applied to all seven.
type RegionRefusal<'a> = Box<dyn Fn(&Address, &[Span]) -> Option<QueryError> + 'a>;

/// The one list every "every region entry point" law reads: `image_on` and
/// the six reads that inherit its gates and budget, each reduced to its
/// refusal through a copy of `reads`. A region read added to the family is
/// added here, and every such law then covers it.
fn region_entry_points<'a>(reads: Reads<'a>) -> Vec<(&'static str, RegionRefusal<'a>)> {
    vec![
        ("image", Box::new(move |d, r| reads.image(d, r).err())),
        ("findlinks_v", Box::new(move |d, r| reads.findlinks_v(d, r).err())),
        ("count_v", Box::new(move |d, r| reads.count_v(d, r).err())),
        ("window_v", Box::new(move |d, r| reads.window_v(d, r, None, 3).err())),
        (
            "count_v_by_home",
            Box::new(move |d, r| reads.count_v_by_home(d, r, 3, &[]).err()),
        ),
        (
            "find_links_v_history",
            Box::new(move |d, r| reads.find_links_v_history(d, r, None, 3).err()),
        ),
        (
            "retrieve_endsets",
            Box::new(move |d, r| reads.retrieve_endsets(d, r).err()),
        ),
    ]
}

/// §1 — the gate order `image_on` states is inherited by the six operations
/// that compose it, so it is checked on all seven entry points rather than on
/// the one whose doc-comment carries the sentence. An entry point that
/// swallowed an unregistered `d` into an empty answer, or that read the
/// region before the registry, would be invisible to a test of `image` alone.
#[test]
fn every_region_entry_point_answers_both_gates_in_order() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let reads = Reads(&k);

    for (name, refusal) in &region_entry_points(reads) {
        assert_eq!(
            refusal(&unregistered_doc(), &[vspan(1, 1, 1)]),
            Some(QueryError::DocNotRegistered),
            "{name}: an unregistered d is refused"
        );
        for subspace in [0, 2, 3] {
            assert_eq!(
                refusal(&doc1(), &[vspan(subspace, 1, 1)]),
                Some(QueryError::BadRegion),
                "{name}: a region in subspace {subspace}, not s_C, is refused"
            );
        }
        assert_eq!(
            refusal(&unregistered_doc(), &[vspan(2, 1, 1)]),
            Some(QueryError::DocNotRegistered),
            "{name}: the document gate is the FIRST act"
        );
    }
}

/// §1/§5/§6 — every read that names a document refuses a `d` that is not a
/// registered DOCUMENT, and not only one M3 never minted. M3's allocation
/// oracle answers for nodes, accounts and every element M3 mints as well, so a
/// gate loosened to "M3 allocated it" would pass each of these on to M5, whose
/// reads answer an address that arranges nothing with ∅: the caller would get
/// a defined empty answer for a document that does not exist — the conflation
/// the gate exists to prevent — and the preview a range fault. Every other
/// refusal in the suite names a document-shaped address past the frontier,
/// which such a gate refuses all the same. Each `d` here is allocated and is
/// no document — a node, an account, a content element and a link element —
/// and the premise says so off M3 before any read is asked.
#[test]
fn every_document_gate_refuses_an_allocated_address_that_is_no_document() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let snap = k.snapshot();
    let m3 = snap.world().m3();
    let reads = Reads(&k);
    let entry_points = region_entry_points(reads);
    for d in [a(&[1]), a(&[1, 0, 1]), ca(1), e1.clone()] {
        assert!(
            m3.is_allocated(&d) && !m3.is_registered_document(&d),
            "{d:?}: allocated in M3, and no document"
        );
        for (name, refusal) in &entry_points {
            assert_eq!(
                refusal(&d, &[vspan(1, 1, 1)]),
                Some(QueryError::DocNotRegistered),
                "{name} at {d:?}"
            );
        }
        assert_eq!(
            reads.project(&e1, FROM, &d),
            Err(QueryError::DocNotRegistered),
            "project at {d:?}"
        );
        assert_eq!(
            reads.addressably_discoverable_from(&e1, &d),
            Err(QueryError::DocNotRegistered),
            "addressably_discoverable_from at {d:?}"
        );
        assert_eq!(
            reads.delete_orphans(&d, &vp(1, 1), &n(1)),
            Err(OrphanError::DocNotRegistered),
            "delete_orphans at {d:?}"
        );
    }
}

#[test]
fn image_resolves_and_clips() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let reads = Reads(&k);

    // Ordinary V→I resolution.
    assert_eq!(
        reads.image(&doc1(), &[vspan(1, 1, 2)]),
        Ok(vec![run(&ca(1), 2)])
    );
    // Overlapping INPUT spans yield partially-overlapping runs — the answer
    // is the region's positions in order, not an address-disjoint partition.
    assert_eq!(
        reads.image(&doc1(), &[vspan(1, 1, 2), vspan(1, 2, 2)]),
        Ok(vec![run(&ca(1), 2), run(&ca(2), 2)])
    );
    // Out-of-range tails are the arrangement intersection (W ∩ dom M(d)) …
    assert_eq!(reads.image(&doc1(), &[vspan(1, 2, 99)]), Ok(vec![run(&ca(2), 2)]));
    // … and so is a span opening below the first position: ordinal 0 names no
    // position, so a span opening there contributes from position 1 on, and
    // one naming 0 alone names nothing arranged.
    assert_eq!(
        reads.image(&doc1(), &[vspan(1, 0, 2)]),
        Ok(vec![run(&ca(1), 1)])
    );
    assert_eq!(reads.image(&doc1(), &[vspan(1, 0, 1)]), Ok(vec![]));
}

/// §1 — the I-runs come back in REGION-SPAN order, and in V-order within each
/// span. Two INSERTs at V-position 1 seat the later-minted addresses at the
/// earlier V-positions, so V-order runs DESCENDING in address here: a sort or
/// an ordered-set dedup would reverse both expected values below, and a
/// one-INSERT fixture — where region order, V-order and address order all
/// coincide — cannot see the difference.
#[test]
fn image_returns_runs_in_region_span_order_then_v_order() {
    let k = kernel();
    seed_content(&k, &doc1(), 3); // V 1..3 → ca(1..3)
    seed_content(&k, &doc1(), 3); // inserted AT V 1: ca(4..6) take V 1..3, ca(1..3) shift to V 4..6
    let reads = Reads(&k);

    // One span, two runs: V-order within the span.
    assert_eq!(
        reads.image(&doc1(), &[vspan(1, 1, 6)]),
        Ok(vec![run(&ca(4), 3), run(&ca(1), 3)])
    );
    // Two spans, one run each: the order the caller's region asked in.
    assert_eq!(
        reads.image(&doc1(), &[vspan(1, 1, 1), vspan(1, 4, 1)]),
        Ok(vec![run(&ca(4), 1), run(&ca(1), 1)])
    );
}

/// §1 — the image is the region's POSITIONS in order and never a set (skep
/// #753): a run the surface places twice is answered at each place, and a
/// span the region names twice is answered twice, so a reader walking the
/// runs end to end — the shell's shift, the attest's read-back, the
/// conformance harness's V-ordinals — finds each position where the surface
/// arranges it. doc2 is one COPY placing doc1's two positions twice over, so
/// its surface holds one run at two places: the whole-document image is that
/// run twice, and a region naming one span twice answers the span's run
/// twice. Nested spans over one run are two runs, each clipped to its span —
/// `resolve` clips to the span asked for. AND NO LINK ANSWER MOVES on the
/// repeat: the region family lifts the runs to its query as a set, and M7
/// answers each `(link, slot)` pair once, so one link FROM the doubled run
/// is answered once by every region read over doc2 — found, counted, counted
/// by home, windowed, its endset one pair, its history one row — and the
/// delete preview, which lifts both sides the same way, keeps it while
/// either placement survives and reports it when neither does.
#[test]
fn image_answers_every_placement_of_a_run_the_surface_places_twice() {
    let k = kernel();
    seed_content(&k, &doc1(), 2); // V 1..2 → one run at ca(1)
    Vstream::new(&k)
        .copy(
            SYS,
            &doc2(),
            vp(1, 1),
            &[spec(&doc1(), 1, 1, 2), spec(&doc1(), 1, 1, 2)],
            AsOf::Typed(k.current_seq()),
        )
        .expect("copy succeeds");
    let store = LinkWriter::new(&k, &EVERYONE);
    let from_the_run = link(&store, &doc1(), &[ca(1)], &[ca(9)]);
    let reads = Reads(&k);
    let twice = run(&ca(1), 2);
    let whole = [vspan(1, 1, 4)];

    // The surface holds the run at two places, and the image answers both.
    assert_eq!(k.snapshot().world().m5().content_runs(&doc2()).len(), 2);
    assert_eq!(
        reads.image(&doc2(), &whole),
        Ok(vec![twice.clone(), twice.clone()]),
        "each placement at its place"
    );
    // A span named twice is answered twice …
    assert_eq!(
        reads.image(&doc1(), &[vspan(1, 1, 2), vspan(1, 1, 2)]),
        Ok(vec![twice.clone(), twice.clone()])
    );
    // … and nested spans over one run are two runs, each clipped to its span.
    assert_eq!(
        reads.image(&doc1(), &[vspan(1, 1, 1), vspan(1, 1, 2)]),
        Ok(vec![run(&ca(1), 1), twice])
    );

    // No link answer moves on the repeat.
    assert_eq!(
        reads.findlinks_v(&doc2(), &whole),
        Ok(vec![from_the_run.clone()]),
        "findlinks_v"
    );
    assert_eq!(reads.count_v(&doc2(), &whole), Ok(1), "count_v");
    assert_eq!(
        reads
            .count_v_by_home(&doc2(), &whole, usize::MAX, &[])
            .map(|counts| counts.homes),
        Ok(vec![(doc1(), 1)]),
        "count_v_by_home"
    );
    assert_eq!(
        drain_window(1, 2, |cur| reads
            .window_v(&doc2(), &whole, cur, 1)
            .expect("window_v")),
        vec![from_the_run.clone()],
        "window_v"
    );
    assert_eq!(
        reads.retrieve_endsets(&doc2(), &whole),
        Ok(vec![(FROM, enc(&[ca(1)]))]),
        "retrieve_endsets"
    );
    assert_eq!(
        rows_window(
            &reads
                .find_links_v_history(&doc2(), &whole, None, 64)
                .expect("find_links_v_history")
        )
        .batch,
        vec![from_the_run.clone()],
        "find_links_v_history"
    );
    // The preview: a delete of the first place leaves the second, and the
    // link with it; a delete of both places strands it.
    assert_eq!(
        reads.delete_orphans(&doc2(), &vp(1, 1), &n(2)),
        Ok(OrphanReport { orphaned: vec![] }),
        "the second placement keeps the link"
    );
    assert_eq!(
        reads.delete_orphans(&doc2(), &vp(1, 1), &n(4)),
        Ok(OrphanReport {
            orphaned: vec![from_the_run]
        }),
        "neither placement survives"
    );
}

/// §1 — the query endset a read lifts from a document's runs and hands M7 is
/// MIXED-LENGTH wherever `d` transcludes content from a document at another
/// depth: each run's I-extent starts at its origin's length, and nothing
/// partitions them. That is sound because the endset's one consumer is M7's
/// `classify_spans` overlap, which is total across lengths; a level-gated step
/// added to the lift — normalizing the query, keying a cache on
/// `canonical_key` — would fault on this image and on no other fixture's,
/// every other document here minting eight-component content. So each read
/// that lifts the runs is asked over it: the region family's stab, the
/// pointwise touch test, and the preview's two stabs.
#[test]
fn the_region_family_answers_over_an_image_that_mixes_address_lengths() {
    let k = kernel();
    // A sub-account of the fixture's account, and its first document: one
    // tier deeper than doc1, so the content it mints has NINE components.
    let ns = Namespace::new(&k);
    let (sub, _) = ns
        .delegate(PrincipalId(1), t(&[1, 0, 1, 1]), PrincipalId(2))
        .expect("the account's owner delegates its first sub-account");
    let (deep, _) = ns
        .create_new_document(PrincipalId(2), &sub, Some(false))
        .expect("the sub-account's owner mints a private document");
    seed_content(&k, &deep, 1);
    let deep_ca = a(&[1, 0, 1, 1, 0, 1, 0, 1, 1]);
    // doc1: its own position at V1, the deeper document's transcluded at V2.
    seed_content(&k, &doc1(), 1);
    Vstream::new(&k)
        .copy(SYS, &doc1(), vp(1, 2), &[spec(&deep, 1, 1, 1)], AsOf::Typed(k.current_seq()))
        .expect("copy succeeds");
    let store = LinkWriter::new(&k, &EVERYONE);
    let near = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let far = link(&store, &doc1(), std::slice::from_ref(&deep_ca), &[ca(102)]);
    let reads = Reads(&k);
    let region = [vspan(1, 1, 2)];

    // The premise: one image, its runs starting at two lengths.
    let image = reads.image(&doc1(), &region).expect("image");
    assert_eq!(image, vec![run(&ca(1), 1), run(&deep_ca, 1)]);
    assert_eq!(
        image
            .iter()
            .map(|r| r.i_start().tumbler().len())
            .collect::<Vec<_>>(),
        vec![8, 9]
    );

    assert_eq!(
        reads.findlinks_v(&doc1(), &region),
        Ok(vec![near.clone(), far.clone()])
    );
    assert_eq!(reads.count_v(&doc1(), &region), Ok(2));
    assert_eq!(
        reads.retrieve_endsets(&doc1(), &region),
        Ok(vec![(FROM, enc(&[ca(1)])), (FROM, enc([&deep_ca]))])
    );
    assert_eq!(reads.addressably_discoverable_from(&far, &doc1()), Ok(true));
    // The preview stabs the mix twice over: the deleted run is doc1's own, and
    // the retained side holds the transcluded run beside doc1's link runs.
    assert_eq!(
        reads.delete_orphans(&doc1(), &vp(1, 1), &n(1)),
        Ok(OrphanReport {
            orphaned: vec![near]
        })
    );
}

/// §1 — the run budget, at its boundary and on every entry point that
/// inherits `image_on`. The shape it prices is the region×image PRODUCT, not
/// the region: each span here is well-formed, in-budget for the transport,
/// and resolves to the document's whole arrangement, so a request the wire
/// admits whole can still name work no wire cap bounds. Counted over runs
/// RESOLVED, so four runs under 1024 spans is the budget exactly, and one
/// single-run span more is one run past it — the value just above the limit,
/// where a comparison off by one would still admit.
///
/// Two things beside the boundary. The budget is refused THIRD, so an
/// over-budget region whose malformed span comes last still names the region
/// gate: the whole region is judged before any span resolves. The constant is
/// the number its doc gives it, which a symbolic boundary cannot see: the
/// largest FLAT region the transport admits — one span per wire slot, each
/// resolving to one run — is admitted unchanged over a document within the
/// run budget, as this one is — and far along a document past the budget
/// as at its front, which the test of a region's reach pins.
#[test]
fn the_region_family_refuses_an_image_past_the_run_budget() {
    let k = kernel();
    for _ in 0..4 {
        seed_content(&k, &doc1(), 1); // four separate INSERTs ⇒ four runs
    }
    let reads = Reads(&k);
    // Every span the same: the whole document, resolving to all four runs.
    let at_budget: Vec<Span> = vec![vspan(1, 1, 4); MAX_IMAGE_RUNS / 4];
    let past: Vec<Span> = at_budget.iter().cloned().chain([vspan(1, 1, 1)]).collect();
    let past_then_malformed: Vec<Span> =
        past.iter().cloned().chain([vspan(2, 1, 1)]).collect();
    let flat: Vec<Span> = vec![vspan(1, 1, 1); MAX_SLOT_SPANS];
    assert_eq!(reads.image(&doc1(), &at_budget[..1]).map(|r| r.len()), Ok(4));
    // At the budget the answer is every run resolved — the four runs once per
    // span, `MAX` in all — which is what the budget counts.
    assert_eq!(
        reads.image(&doc1(), &at_budget).map(|r| r.len()),
        Ok(MAX_IMAGE_RUNS)
    );

    for (name, refusal) in &region_entry_points(reads) {
        assert_eq!(
            refusal(&doc1(), &at_budget),
            None,
            "{name}: the budget itself is admitted"
        );
        assert_eq!(
            refusal(&doc1(), &past),
            Some(QueryError::ImageTooLarge),
            "{name}: one run past the budget is refused, not truncated"
        );
        assert_eq!(
            refusal(&doc1(), &past_then_malformed),
            Some(QueryError::BadRegion),
            "{name}: the whole region is judged before any span resolves"
        );
        assert_eq!(
            refusal(&doc1(), &flat),
            None,
            "{name}: the largest flat region the transport admits is admitted"
        );
    }
}

/// §1 — the run budget counts the runs a region RESOLVES, pulled one at a
/// time from M5's lazy resolution, and never the positions its spans name.
/// The surface is one wide run followed by `MAX` width-1 runs: a span from its
/// first position naming `MAX + 1` positions resolves ONE run — answered, over
/// a surface holding more runs than the budget — a span of `2 × MAX`
/// positions resolves `MAX` runs and is answered at the budget exactly, and
/// one position more resolves `MAX + 1` and is refused, not truncated. The
/// budget-exact span's answer is the wide run and then `MAX − 1` of width 1:
/// every run resolved, answered.
///
/// What no verdict shows is what M8 HOLDS while it counts — the budget and
/// the run that trips it, never the span's whole image; the heap shows that,
/// in the test after this one.
#[test]
fn image_counts_the_runs_a_span_resolves_not_the_positions_it_names() {
    let max = MAX_IMAGE_RUNS as u32;
    let wide = max + 1;
    let k = kernel();
    seed_content(&k, &doc1(), wide); // one run, `MAX + 1` positions
    let vstream = Vstream::new(&k);
    // doc2: that whole run transcluded, then `MAX` width-1 runs behind it,
    // none abutting the next — `MAX + 1` runs over `2 × MAX + 1` positions.
    vstream.copy(SYS, &doc2(), vp(1, 1), &[spec(&doc1(), 1, 1, wide)], AsOf::Typed(k.current_seq()))
        .expect("copy succeeds");
    vstream.copy(
        SYS,
        &doc2(),
        vp(1, wide + 1),
        &vec![spec(&doc1(), 1, 1, 1); MAX_IMAGE_RUNS],
        AsOf::Typed(k.current_seq()),
    )
    .expect("copy succeeds");
    assert_eq!(
        k.snapshot().world().m5().content_runs(&doc2()).len(),
        MAX_IMAGE_RUNS + 1
    );
    let reads = Reads(&k);

    assert_eq!(
        reads.image(&doc2(), &[vspan(1, 1, wide)]),
        Ok(vec![run(&ca(1), wide)]),
        "`MAX + 1` positions, one run resolved"
    );
    let at_budget = reads
        .image(&doc2(), &[vspan(1, 1, 2 * max)])
        .expect("`MAX` runs resolved is the budget exactly");
    assert_eq!(
        at_budget.len(),
        MAX_IMAGE_RUNS,
        "`MAX` runs resolved, every one answered"
    );
    assert_eq!(at_budget[0], run(&ca(1), wide), "the wide run first");
    assert!(
        at_budget[1..].iter().all(|r| *r == run(&ca(1), 1)),
        "then `MAX − 1` of width 1"
    );
    for (name, refusal) in &region_entry_points(reads) {
        assert_eq!(
            refusal(&doc2(), &[vspan(1, 1, wide)]),
            None,
            "{name}: one run resolved is answered, whatever the span names"
        );
        assert_eq!(
            refusal(&doc2(), &[vspan(1, 1, 2 * max)]),
            None,
            "{name}: one span resolving the budget exactly is answered"
        );
        assert_eq!(
            refusal(&doc2(), &[vspan(1, 1, 2 * max + 1)]),
            Some(QueryError::ImageTooLarge),
            "{name}: one run more is refused, not truncated"
        );
    }
}

/// §1 — the run budget is held AS THE RUNS ARE PULLED: "the run past the
/// budget is refused as it is pulled, before the next is built, so what a
/// request makes M8 hold is the budget and the one run that trips it — never
/// a span's whole image, however fragmented the surface" (`image_on`), the
/// promise the daemon runs `image` on with no scan permit ("so no region
/// materializes a fragmented document whole"). No verdict shows it: a
/// resolver that collected each span's runs and counted them afterwards
/// refuses exactly these requests, holding the source's whole fragmentation
/// live for each. The heap shows it. One span across doc2 at two run counts
/// past the budget is refused at the same pulled run over both, so it costs
/// the same heap bytes over both, and the `MAX − 1` runs `more` holds past
/// that run are never built.
#[test]
fn image_refuses_past_the_run_budget_without_resolving_the_rest_of_the_span() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let (fewer, more) = doc2_past_the_run_budget_at_two_run_counts(&k);
    let d = doc2();
    // Every position doc2 arranges in `more`: the RUN budget refuses over
    // both.
    let region = [vspan(1, 1, 2 * MAX_IMAGE_RUNS as u32)];
    let heap_of = |snap: &Snapshot<World>| -> u64 {
        let (answer, bytes) = settled_heap_bytes(|| image_on(snap, &d, &region));
        assert_eq!(
            answer,
            Err(QueryError::ImageTooLarge),
            "refused at the run past the budget"
        );
        bytes
    };
    assert_eq!(
        heap_of(&more),
        heap_of(&fewer),
        "no run past the one that trips the budget is built"
    );
}

/// §1 — a region is priced by the runs it RESOLVES and by nothing else: M5
/// reaches a span by a descent of the surface's run-list, a node a level of
/// its tree, so where along a surface a span reaches, and how many runs the
/// surface holds left of it, cost a region nothing. A span past the end of
/// a fragmented document resolves no run and reads none, and a region of
/// such spans is answered, empty; a flat region at the very end of a
/// surface one run past the budget — each span one run — is answered like
/// one at its front; and the run budget alone refuses, at the run past it.
/// Each over a document of `MAX + 1` runs, on every entry point, and the
/// region gate still speaks first.
///
/// Two further shapes. A span whose reach ordinal does not fit a `usize`
/// resolves nothing and is answered so. And a region read of a published
/// address resolves through the trunk head its readers answer from
/// (HEAD-FLOAT, PUB-2.53): spans past the end of a head of `MAX + 1` runs
/// are answered asked of the document as of the head itself, the runs of
/// neither being read.
#[test]
fn a_region_is_answered_for_the_runs_it_resolves_however_far_its_spans_reach() {
    let k = kernel();
    seed_content(&k, &doc1(), 1); // one run
    // doc2 one run past the budget: one COPY placing doc1's position many
    // times, each placement a width-1 run that abuts nothing.
    let specs = vec![spec(&doc1(), 1, 1, 1); MAX_IMAGE_RUNS + 1];
    Vstream::new(&k)
        .copy(SYS, &doc2(), vp(1, 1), &specs, AsOf::Typed(k.current_seq()))
        .expect("copy succeeds");
    assert_eq!(
        k.snapshot().world().m5().content_runs(&doc2()).len(),
        MAX_IMAGE_RUNS + 1
    );
    let reads = Reads(&k);

    // Every span one past doc2's arranged end, and past doc1's.
    let past_end: Vec<Span> = vec![vspan(1, MAX_IMAGE_RUNS as u32 + 2, 1); MAX_IMAGE_RUNS];
    let past_end_then_malformed: Vec<Span> =
        past_end.iter().cloned().chain([vspan(2, 1, 1)]).collect();
    let flat: Vec<Span> = vec![vspan(1, 1, 1); MAX_IMAGE_RUNS];
    // A FLAT region at the end of the fragmented surface: every span names
    // doc2's last position and resolves exactly one run — the budget's runs
    // exactly — and one span more is one run past it.
    let flat_at_end: Vec<Span> = vec![vspan(1, MAX_IMAGE_RUNS as u32 + 1, 1); MAX_IMAGE_RUNS];
    let one_run_more: Vec<Span> = flat_at_end.iter().cloned().chain([vspan(1, 1, 1)]).collect();
    // Spans whose reach ordinal is past `usize`, which resolve nothing.
    let past_usize: Vec<Span> = vec![vspan_reaching_past_usize(1); MAX_IMAGE_RUNS];
    assert_eq!(reads.image(&doc2(), &flat_at_end[..1]), Ok(vec![run(&ca(1), 1)]));
    assert_eq!(reads.image(&doc2(), &past_end), Ok(vec![]), "spans past the end resolve no run");
    assert_eq!(reads.image(&doc1(), &past_end), Ok(vec![]));
    assert_eq!(reads.image(&doc2(), &past_usize), Ok(vec![]), "a reach past `usize` resolves no run either");
    assert_eq!(
        reads.image(&doc2(), &flat_at_end).map(|runs| runs.len()),
        Ok(MAX_IMAGE_RUNS),
        "the budget's runs, each resolved at the surface's end"
    );

    for (name, refusal) in &region_entry_points(reads) {
        assert_eq!(
            refusal(&doc2(), &past_end),
            None,
            "{name}: spans past the end of a fragmented surface are answered"
        );
        assert_eq!(
            refusal(&doc2(), &past_end_then_malformed),
            Some(QueryError::BadRegion),
            "{name}: the whole region is judged before any span resolves"
        );
        assert_eq!(refusal(&doc1(), &past_end), None, "{name}: and over one run");
        assert_eq!(
            refusal(&doc2(), &flat),
            None,
            "{name}: a flat region at the front is inside the run budget"
        );
        assert_eq!(
            refusal(&doc2(), &flat_at_end),
            None,
            "{name}: a flat region at the end of a surface past the run budget is inside it too"
        );
        assert_eq!(
            refusal(&doc2(), &one_run_more),
            Some(QueryError::ImageTooLarge),
            "{name}: the run past the budget is what refuses"
        );
        assert_eq!(
            refusal(&doc2(), &past_usize),
            None,
            "{name}: spans reaching past `usize` resolve nothing and are answered"
        );
    }

    // Asked of a published address, whose readers answer from its trunk
    // head: pdoc's own arrangement holds one run and its head `MAX + 1`.
    let k = fragmented_head_world(MAX_IMAGE_RUNS + 1);
    let snap = k.snapshot();
    assert_eq!(
        snap.world().m5().content_runs(&phead()).len(),
        MAX_IMAGE_RUNS + 1
    );
    assert_eq!(snap.world().m5().content_runs(&pdoc()).len(), 1);
    let reads = Reads(&k);
    for (name, refusal) in &region_entry_points(reads) {
        for d in [pdoc(), phead()] {
            assert_eq!(
                refusal(&d, &past_end),
                None,
                "{name} at {d:?}: spans past the head's end are answered"
            );
        }
    }
}

/// §1 — a surface of WIDE runs, twice the run budget of them: half the
/// budget's spans and one more, each naming one position far along the
/// surface and resolving one run, are inside the run budget and answered.
/// The product of the spans' count and the runs left of them, past the
/// budget's square, prices nothing.
#[test]
fn a_region_far_along_a_surface_of_many_runs_is_inside_the_run_budget_it_resolves() {
    const WIDTH: u32 = MAX_IMAGE_RUNS as u32 / 2;
    let run_count = 2 * MAX_IMAGE_RUNS;
    let k = kernel();
    seed_content(&k, &doc1(), WIDTH); // one run, WIDTH positions wide
    // doc2: `2 × MAX` runs of `WIDTH` positions each, none abutting the next.
    let specs = vec![spec(&doc1(), 1, 1, WIDTH); run_count];
    Vstream::new(&k)
        .copy(SYS, &doc2(), vp(1, 1), &specs, AsOf::Typed(k.current_seq()))
        .expect("copy succeeds");
    assert_eq!(
        k.snapshot().world().m5().content_runs(&doc2()).len(),
        run_count
    );
    let reads = Reads(&k);

    // `MAX / 2 + 1` spans, each naming one position `2 × MAX` runs' worth of
    // ordinals along: their count times the runs left of them is past the
    // square of the budget, and each resolves one run.
    let far: Vec<Span> = vec![vspan(1, run_count as u32 * WIDTH, 1); MAX_IMAGE_RUNS / 2 + 1];
    assert!(far.len() * (run_count - 1) > MAX_IMAGE_RUNS * MAX_IMAGE_RUNS, "premise: the product is past the square");
    assert_eq!(reads.image(&doc2(), &far[..1]).map(|r| r.len()), Ok(1));
    assert_eq!(reads.image(&doc2(), &far).map(|r| r.len()), Ok(far.len()));
    for (name, refusal) in &region_entry_points(reads) {
        assert_eq!(refusal(&doc2(), &far), None, "{name}: answered, its runs inside the budget");
    }
}

#[test]
fn findlinks_v_is_disjunctive_and_addressable_filtered() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);

    // e1 reaches position 1 via FROM (the `link` fixture's FROM is enc({ca1})).
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(9)]);
    assert_eq!(e1, la(1));
    // m1 reaches position 2 via FROM, 3 via TO, and 1 via TYPE (makelink
    // resolves V-specs to content extents).
    let (m1, _) = store
        .makelink(
            SYS,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 2, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)]),
        )
        .expect("makelink succeeds");
    assert_eq!(m1, la(2));

    // Disjunction: any slot reaching the region surfaces the link.
    assert_eq!(reads.findlinks_v(&doc1(), &[vspan(1, 2, 1)]), Ok(vec![la(2)]));
    assert_eq!(reads.findlinks_v(&doc1(), &[vspan(1, 3, 1)]), Ok(vec![la(2)]));
    // OR across links: position 1 is reached by e1's FROM and m1's TYPE.
    assert_eq!(
        reads.findlinks_v(&doc1(), &[vspan(1, 1, 1)]),
        Ok(vec![la(1), la(2)])
    );
    assert_eq!(reads.count_v(&doc1(), &[vspan(1, 1, 1)]), Ok(2));
    // Result-as-set: a link touching the region through several slots is
    // found once.
    assert_eq!(
        reads.findlinks_v(&doc1(), &[vspan(1, 1, 3)]),
        Ok(vec![la(1), la(2)])
    );

    // findlinks_V ∩ addressable: a nullified link never surfaces, even though its
    // coverage still reaches the region. (Homed in doc2 so the retraction
    // tuple's own enc({doc2}) from-fill stays off doc1's content.)
    store.nullify(SYS, &doc2(), &e1).expect("nullify succeeds");
    assert_eq!(reads.findlinks_v(&doc1(), &[vspan(1, 1, 1)]), Ok(vec![la(2)]));
    assert_eq!(reads.count_v(&doc1(), &[vspan(1, 1, 1)]), Ok(1));
}

/// §1 — THE RETRACTED-LINKS READ'S OWN LAW (the link-sets design §7, lane
/// 7; the survey's C1): `sel_audit = findlinks_V` over the AUDIT slice, so
/// its rows are every link ever made whose endsets touch the region — the
/// nullified one `findlinks_v` drops included — and its ACTIVE rows, those
/// carrying no retraction position, are exactly `findlinks_v`'s answer under
/// the same reader. Each row carries the link's own commit position and,
/// retracted, the position of its EARLIEST retraction across every home
/// (the owner's ruling B (2)): a second retraction of the same link from
/// another home — this one homed in doc1 itself, so the retraction record
/// is a row of its own — moves nothing. The disjunction over slots and the
/// once-per-link rule hold of the audit answer as of the active one. Under
/// a reader refusing doc2, the retraction homed there is no row and its
/// position still crosses on the link's row (ruling B (4); PUB-6.47).
#[test]
fn the_retracted_links_read_lists_every_link_ever_made_and_its_active_rows_are_findlinks_v() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    // e1 reaches position 1 via FROM; m1 reaches 2 via FROM, 3 via TO and 1
    // via TYPE; t0, homed in doc2, reaches 1 via FROM.
    let (e1, e1_at) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(9)]), SlotArg::Addrs(vec![rel()]))
        .expect("makelink succeeds");
    let (m1, m1_at) = store
        .makelink(
            SYS,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 2, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)]),
        )
        .expect("makelink succeeds");
    let t0 = link(&store, &doc2(), &[ca(1)], &[ca(10)]);
    let whole = [vspan(1, 1, 3)];
    let row_of = |rows: &LinkRows, a: &Address| -> LinkRow {
        rows.links.iter().find(|row| row.a == *a).cloned().unwrap_or_else(|| panic!("{a:?} is a row: {rows:?}"))
    };

    // Nothing retracted: the audit rows are the active answer, each at its
    // own position, none with a retraction's.
    let rows = reads.find_links_v_history(&doc1(), &whole, None, 64).expect("find_links_v_history");
    assert_eq!(active_rows(&rows), vec![e1.clone(), m1.clone(), t0.clone()]);
    assert_eq!(active_rows(&rows), reads.findlinks_v(&doc1(), &whole).expect("findlinks_v"));
    assert_eq!(row_of(&rows, &e1), LinkRow { a: e1.clone(), at: Some(e1_at), retracted_at: None });
    assert_eq!(row_of(&rows, &m1).at, Some(m1_at));
    assert!(rows.exhausted);
    // The disjunction and the once-per-link rule, over the audit answer.
    assert_eq!(rows_window(&reads.find_links_v_history(&doc1(), &[vspan(1, 2, 1)], None, 64).expect("rows")).batch, vec![m1.clone()]);
    assert_eq!(rows_window(&reads.find_links_v_history(&doc1(), &[vspan(1, 3, 1)], None, 64).expect("rows")).batch, vec![m1.clone()]);

    // e1 retracted from doc2: off `findlinks_v`, a ROW here with the
    // retraction's position; the retraction record, homed in doc2 with its
    // FROM over doc2's content, touches nothing of doc1's region.
    let (r_doc2, first_at) = store.nullify(SYS, &doc2(), &e1).expect("nullify succeeds");
    let r_doc2 = r_doc2.into_address();
    assert!(first_at > m1_at);
    let rows = reads.find_links_v_history(&doc1(), &whole, None, 64).expect("find_links_v_history");
    assert_eq!(rows_window(&rows).batch, vec![e1.clone(), m1.clone(), t0.clone()], "every link ever made on the region");
    assert_eq!(active_rows(&rows), reads.findlinks_v(&doc1(), &whole).expect("findlinks_v"));
    assert_eq!(active_rows(&rows), vec![m1.clone(), t0.clone()]);
    assert_eq!(row_of(&rows, &e1), LinkRow { a: e1.clone(), at: Some(e1_at), retracted_at: Some(first_at) });
    assert!(rows.links.iter().all(|row| row.a != r_doc2), "the retraction record is no row of doc1's region");
    // At the one position: e1 and m1 (TYPE) still, e1 retracted.
    let at_one = reads.find_links_v_history(&doc1(), &[vspan(1, 1, 1)], None, 64).expect("rows");
    assert_eq!(rows_window(&at_one).batch, vec![e1.clone(), m1.clone(), t0.clone()]);
    assert_eq!(reads.findlinks_v(&doc1(), &[vspan(1, 1, 1)]), Ok(vec![m1.clone(), t0.clone()]));

    // e1 retracted AGAIN, from doc1: a distinct, later record whose FROM
    // covers doc1's content — so it is itself a row, active, at its own
    // position — and e1's `retracted_at` stays the EARLIEST.
    let (r_doc1, second_at) = store.nullify(SYS, &doc1(), &e1).expect("nullify succeeds");
    let r_doc1 = r_doc1.into_address();
    assert!(second_at > first_at);
    let rows = reads.find_links_v_history(&doc1(), &whole, None, 64).expect("find_links_v_history");
    assert_eq!(rows_window(&rows).batch, vec![e1.clone(), m1.clone(), r_doc1.clone(), t0.clone()]);
    assert_eq!(row_of(&rows, &e1).retracted_at, Some(first_at), "the earliest retraction decides, whatever its home");
    assert_eq!(row_of(&rows, &r_doc1), LinkRow { a: r_doc1.clone(), at: Some(second_at), retracted_at: None });
    assert_eq!(active_rows(&rows), reads.findlinks_v(&doc1(), &whole).expect("findlinks_v"));
    assert_eq!(active_rows(&rows), vec![m1.clone(), r_doc1.clone(), t0.clone()]);

    // A reader refusing doc2: its link and its retraction record are no
    // rows, and e1's row still carries the doc2-homed retraction's position
    // — the position crosses, never the record.
    let snap = k.snapshot();
    let cannot_read_doc2 = |d: &Address| *d != doc2();
    let theirs = find_links_v_history_on(&snap, &doc1(), &whole, None, 64, &cannot_read_doc2).expect("rows");
    assert_eq!(rows_window(&theirs).batch, vec![e1.clone(), m1.clone(), r_doc1.clone()]);
    assert_eq!(row_of(&theirs, &e1).retracted_at, Some(first_at), "a retraction homed where the reader may not read crosses as its position");
    assert_eq!(active_rows(&theirs), findlinks_v_on(&snap, &doc1(), &whole, &cannot_read_doc2).expect("findlinks_v"));
    assert!(theirs.links.iter().all(|row| document_of(&row.a) != Some(doc2())), "no address under doc2 leaves the read");
}

/// §1 — THE HOMES-FIRST COMPOSITION ANSWERS THE UNION OF EACH HOME'S
/// PER-SLOT STABS (PUB-7.18; #656): on a board whose links are homed in
/// every address shape the mint produces — two documents of one account, a
/// sub-account's deeper document, the published document and a version
/// member of it — each candidate home's share of the region read is the
/// union of its three per-slot stabs, M7's `stab_in` at FROM, TO and TYPE
/// over the spans that named the home, in address order; and the shares
/// concatenated in home order are `findlinks_v`'s answer, `count_v`'s
/// cardinality and what every `window_v` drains, under the reader of every
/// home and under one refusing two of the homes. A link touching the region
/// at two slots is answered once; a retracted one never; and a home the
/// passage's block names that holds no link on the passage is asked and
/// contributes nothing. A composition that merged two slots' hits wrongly,
/// dropped a slot, answered a home's links out of order or counted a two-slot
/// link twice parts from the oracle somewhere here.
#[test]
fn the_region_read_answers_the_union_of_each_homes_per_slot_stabs_and_an_empty_home_contributes_nothing() {
    let k = published_world();
    seed_content(&k, &doc1(), 100); // positions 1..=100: the passage's block and the next
    let ns = Namespace::new(&k);
    let (sub, _) = ns
        .delegate(PrincipalId(1), t(&[1, 0, 1, 1]), PrincipalId(2))
        .expect("the account's owner delegates its first sub-account");
    let (deep, _) = ns
        .create_new_document(PrincipalId(2), &sub, Some(false))
        .expect("the sub-account's owner mints a private document");
    let (extra, _) = ns
        .create_new_document(PrincipalId(1), &a(&[1, 0, 1]), Some(false))
        .expect("the owner mints a fourth document");
    let store = LinkWriter::new(&k, &EVERYONE);
    let region = [vspan(1, 1, 10)];
    // doc1: FROM 1; and FROM 2 TO 3, touching the region at two slots.
    link(&store, &doc1(), &[ca(1)], &[ca(200)]);
    let twice = link(&store, &doc1(), &[ca(2)], &[ca(3)]);
    // doc2: TO 4; a TYPE that is position 5 itself; and FROM 6, retracted.
    link(&store, &doc2(), &[ca(201)], &[ca(4)]);
    typed_link(&store, &doc2(), &[ca(202)], &[ca(203)], &ca(5));
    let gone = link(&store, &doc2(), &[ca(6)], &[ca(204)]);
    store.nullify(SYS, &doc2(), &gone).expect("nullify succeeds");
    // The deeper document: FROM 7. The published document: TO 8. Its member:
    // FROM 9 and TO 10.
    link(&store, &deep, &[ca(7)], &[ca(205)]);
    link(&store, &pdoc(), &[ca(206)], &[ca(8)]);
    link(&store, &phead(), &[ca(9)], &[ca(207)]);
    link(&store, &phead(), &[ca(208)], &[ca(10)]);
    // The fourth document: one link in the passage's block, off the passage.
    link(&store, &extra, &[ca(50)], &[ca(209)]);

    let snap = k.snapshot();
    let l = snap.world().links();
    let image = image_on(&snap, &doc1(), &region).expect("image");
    let query = Endset::from_spans(image.iter().map(Run::iextent));
    // The oracle: the old composition, home by home — three per-slot stabs
    // over the spans that named the home, their union, the unions
    // concatenated — and the homes it asked.
    let old = |readable: &dyn Fn(&Address) -> bool| -> (Vec<Address>, Vec<Address>) {
        let (mut answer, mut asked) = (Vec::new(), Vec::new());
        for touch in l.homes_touching([(FROM, &query), (TO, &query), (TYPE, &query)]) {
            asked.push(touch.home().clone());
            if !readable(touch.home()) {
                continue;
            }
            let mut union = OrdSet::new();
            for (i, slot) in [FROM, TO, TYPE].into_iter().enumerate() {
                union = union.union(l.stab_in(touch.home(), slot, touch.spans(i), View::Active));
            }
            answer.extend(union);
        }
        (answer, asked)
    };
    let refuses_two = |d: &Address| *d != doc2() && *d != phead();
    let readers: [(&str, &dyn Fn(&Address) -> bool); 2] =
        [("every home", &every_home), ("refusing doc2 and the member", &refuses_two)];
    for (who, reader) in readers {
        let (answer, asked) = old(reader);
        assert_eq!(
            findlinks_v_on(&snap, &doc1(), &region, reader),
            Ok(answer.clone()),
            "{who}: findlinks_v is the per-home unions concatenated"
        );
        assert_eq!(
            count_v_on(&snap, &doc1(), &region, reader),
            Ok(answer.len()),
            "{who}: count_v is their cardinality"
        );
        assert_eq!(
            count_v_by_home_on(&snap, &doc1(), &region, usize::MAX, &[], reader)
                .expect("count_v_by_home")
                .homes,
            by_home(&answer),
            "{who}: the count by home is the per-home unions' sizes, in home order"
        );
        for n in [1, 3, 100] {
            assert_eq!(
                drain_window(n, answer.len() + 1, |cur| {
                    window_v_on(&snap, &doc1(), &region, cur, n, reader).expect("window")
                }),
                answer,
                "{who}: a window of {n} drains them"
            );
        }
        let recorded = Asked::default();
        let recorder = recorded.recording(reader);
        findlinks_v_on(&snap, &doc1(), &region, &recorder).expect("findlinks_v");
        assert_eq!(recorded.take(), asked, "{who}: the homes asked, in order");
        assert!(asked.contains(&extra), "{who}: the block names the fourth document");
        assert!(
            !answer.iter().any(|a| document_of(a) == Some(extra.clone())),
            "{who}: a home with no hit on the passage contributes nothing"
        );
    }
    // The premises: every shape contributes a link, the two-slot link is
    // answered once, and the retracted one never.
    let (answer, _) = old(&every_home);
    let homes: Vec<Address> = answer.iter().map(|a| document_of(a).expect("a link has a home")).collect();
    for home in [doc1(), doc2(), deep, pdoc(), phead()] {
        assert!(homes.contains(&home), "{home:?} contributes to the answer");
    }
    assert_eq!(answer.iter().filter(|a| **a == twice).count(), 1, "answered once");
    assert!(!answer.contains(&gone), "never the retracted link");
    assert_eq!(answer.len(), 8, "the eight live links on the passage: {answer:?}");
}
