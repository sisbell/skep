//! §1 — content-region discovery: `image_on`'s gates, order, dedup, budgets
//! and float, and the four region reads that inherit them.

use crate::common;

use common::*;
use skep_address::{Address, Span};
use skep_arrangement::{HasM5, Vstream};
use skep_discovery::{content_vspan, OrphanReport, QueryError, FROM, MAX_IMAGE_RUNS};
use skep_links::{enc, LinkWriter, SlotArg, MAX_SLOT_SPANS};
use skep_namespace::{Namespace, PrincipalId};

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
    let level_uniform = skep_address::Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12-valid");
    assert!(!skep_arrangement::is_ordinal_vspan(&level_uniform));
    assert_eq!(
        reads.count_v(&doc1(), &[level_uniform]),
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
    assert!(reads.count_v(&doc1(), &[built]).is_ok());
    assert_eq!(content_vspan(&vp(2, 1), &n(1)), None);
    assert_eq!(content_vspan(&vp(1, 1), &n(0)), None);
    // The rule is "the content subspace", not "anything but the link
    // subspace": over subspaces either side of both numerals, the constructor
    // builds exactly at `s_C` with a count, and the gate refuses exactly what
    // it declines — a subspace-0 or subspace-3 span it admitted would resolve
    // silently to ∅, a different query.
    for subspace in 0..=3u32 {
        for count in 0..=2u32 {
            let built = content_vspan(&vp(subspace, 1), &n(count));
            assert_eq!(
                built.is_some(),
                subspace == 1 && count >= 1,
                "content_vspan at subspace {subspace}, count {count}"
            );
            if let Some(span) = built {
                assert!(reads.count_v(&doc1(), &[span]).is_ok());
            } else if count >= 1 {
                assert_eq!(
                    reads.count_v(&doc1(), &[vspan(subspace, 1, count)]),
                    Err(QueryError::BadRegion),
                    "a region in subspace {subspace} is refused"
                );
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

    // An empty region trivially passes the gate and yields the empty image.
    assert!(reads.image(&doc1(), &[]).expect("empty region is defined").is_empty());
}

/// One region-family entry point reduced to the refusal it answers with, so
/// the gate rule can be stated once and applied to all five.
type RegionRefusal<'a> = Box<dyn Fn(&Address, &[Span]) -> Option<QueryError> + 'a>;

/// The one list every "every region entry point" law reads: the five reads
/// that inherit `image_on`'s gates and budget, each reduced to its refusal
/// through a copy of `reads`. A region read added to the family is added here,
/// and every such law then covers it.
fn region_entry_points<'a>(reads: Reads<'a>) -> Vec<(&'static str, RegionRefusal<'a>)> {
    vec![
        ("image", Box::new(move |d, r| reads.image(d, r).err())),
        ("findlinks_v", Box::new(move |d, r| reads.findlinks_v(d, r).err())),
        ("count_v", Box::new(move |d, r| reads.count_v(d, r).err())),
        ("window_v", Box::new(move |d, r| reads.window_v(d, r, None, 3).err())),
        (
            "retrieve_endsets",
            Box::new(move |d, r| reads.retrieve_endsets(d, r).err()),
        ),
    ]
}

/// §1 — the gate order `image_on` states is inherited by the four operations
/// that compose it, so it is checked on all five entry points rather than on
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

#[test]
fn image_resolves_dedups_and_clips() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let reads = Reads(&k);

    // Ordinary V→I resolution.
    assert_eq!(
        reads.image(&doc1(), &[vspan(1, 1, 2)]),
        Ok(vec![run(&ca(1), 2)])
    );
    // Exact-equal repeats are deduped at the boundary (Run: Eq).
    assert_eq!(
        reads.image(&doc1(), &[vspan(1, 1, 2), vspan(1, 1, 2)]),
        Ok(vec![run(&ca(1), 2)])
    );
    // Overlapping INPUT spans may still yield partially-overlapping runs —
    // the dedup claim is exact-equality only, not an address-disjoint
    // partition.
    assert_eq!(
        reads.image(&doc1(), &[vspan(1, 1, 2), vspan(1, 2, 2)]),
        Ok(vec![run(&ca(1), 2), run(&ca(2), 2)])
    );
    // Out-of-range tails are the arrangement intersection (W ∩ dom M(d)).
    assert_eq!(reads.image(&doc1(), &[vspan(1, 2, 99)]), Ok(vec![run(&ca(2), 2)]));
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

/// §1 — the dedup keys on `(i_start, width)`, which is exactly `Run`'s
/// equality and not one component of it. Two runs sharing a start and
/// differing in width are two runs, and a key that dropped the width would
/// collapse them — the one mistake the spelled-out key can make, since `Run`
/// itself carries no `Hash`. `resolve` clips to the span asked for, so two
/// nested region spans over one arranged run produce exactly that pair.
#[test]
fn image_dedups_on_a_runs_whole_identity_not_its_start() {
    let k = kernel();
    seed_content(&k, &doc1(), 3); // V 1..3 → one run at ca(1)
    let reads = Reads(&k);

    assert_eq!(
        reads.image(&doc1(), &[vspan(1, 1, 1), vspan(1, 1, 2)]),
        Ok(vec![run(&ca(1), 1), run(&ca(1), 2)])
    );
    // The collapse the same key MUST still make: an exact repeat is one run.
    assert_eq!(
        reads.image(&doc1(), &[vspan(1, 1, 2), vspan(1, 1, 2)]),
        Ok(vec![run(&ca(1), 2)])
    );
}

/// §1 — the query endset every run-anchored read hands M7 is MIXED-LENGTH
/// wherever `d` transcludes content from a document at another depth: each
/// run's I-extent starts at its origin's length, and nothing partitions them.
/// That is sound because the endset's one consumer is M7's `classify_spans`
/// overlap, which is total across lengths; a level-gated step added to the
/// lift — normalizing the query, keying a cache on `canonical_key` — would
/// fault on this image and on no other fixture's, every other document here
/// minting eight-component content. So each read that lifts the runs is asked
/// over it: the region family's stab, the pointwise touch test, and the
/// preview's two stabs.
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
        .copy(SYS, &doc1(), vp(1, 2), &[spec(&deep, 1, 1, 1)])
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
/// run budget, as this one is. Deep in a document past the budget the walk
/// decides, and the walk's own test pins that.
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
    // At the budget the answer is still those four distinct runs — the dedup
    // is not what the budget counts.
    assert_eq!(reads.image(&doc1(), &at_budget).map(|r| r.len()), Ok(4));

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

/// §1 — the RUN-LIST WALK, which the run budget cannot see. M5 reaches every
/// span by walking the surface's run-list from its first run, so a span past
/// the end of a fragmented document walks every run and returns none, and a
/// region of such spans resolves no run for the run budget to count. The walk
/// is held to that budget's square, ahead of the first `resolve`: `MAX` spans
/// past the end of a document one run over the budget walk `MAX × (MAX + 1)`
/// runs and are refused on every entry point, while the same region over a
/// one-run document — the same depth, a different run count — is answered,
/// because the walk is priced in runs and never in positions. Beside those:
/// one span that deep over the fragmented document is one walk and answered;
/// a flat region at its front is the run budget's own case and answered,
/// while a FLAT region deep in the surface — each span resolving one run, so
/// the run count admits it — is the walk's to refuse; and the region gate
/// still speaks first.
#[test]
fn the_region_family_holds_the_run_list_walk_to_the_square_of_the_run_budget() {
    let k = kernel();
    seed_content(&k, &doc1(), 1); // one run
    // doc2 one run past the budget: one COPY placing doc1's position many
    // times, each placement a width-1 run that abuts nothing.
    let many = vec![spec(&doc1(), 1, 1, 1); MAX_IMAGE_RUNS + 1];
    Vstream::new(&k)
        .copy(SYS, &doc2(), vp(1, 1), &many)
        .expect("copy succeeds");
    assert_eq!(
        k.snapshot().world().m5().content_runs(&doc2()).len(),
        MAX_IMAGE_RUNS + 1
    );
    let reads = Reads(&k);

    // Every span one past doc2's arranged end, and past doc1's.
    let past_the_end = MAX_IMAGE_RUNS as u32 + 2;
    let deep: Vec<Span> = vec![vspan(1, past_the_end, 1); MAX_IMAGE_RUNS];
    let deep_then_malformed: Vec<Span> =
        deep.iter().cloned().chain([vspan(2, 1, 1)]).collect();
    let flat: Vec<Span> = vec![vspan(1, 1, 1); MAX_IMAGE_RUNS];
    // A FLAT region deep in the fragmented surface: every span names doc2's
    // last position and resolves exactly one run, so the run count admits it;
    // the walk — MAX × (MAX + 1) runs — does not.
    let flat_deep: Vec<Span> = vec![vspan(1, MAX_IMAGE_RUNS as u32 + 1, 1); MAX_IMAGE_RUNS];
    assert_eq!(reads.image(&doc2(), &flat_deep[..1]), Ok(vec![run(&ca(1), 1)]));
    assert_eq!(
        reads.image(&doc2(), &deep[..1]),
        Ok(vec![]),
        "a span past the end resolves no run, whatever it walks"
    );
    assert_eq!(reads.image(&doc1(), &deep), Ok(vec![]));

    for (name, refusal) in &region_entry_points(reads) {
        assert_eq!(
            refusal(&doc2(), &deep),
            Some(QueryError::ImageTooLarge),
            "{name}: a walk past the square is refused though it resolves nothing"
        );
        assert_eq!(
            refusal(&doc2(), &deep_then_malformed),
            Some(QueryError::BadRegion),
            "{name}: the whole region is judged before the walk is priced"
        );
        assert_eq!(
            refusal(&doc1(), &deep),
            None,
            "{name}: priced in runs — the same depth over one run is answered"
        );
        assert_eq!(
            refusal(&doc2(), &deep[..1]),
            None,
            "{name}: one walk is never refused for its depth"
        );
        assert_eq!(
            refusal(&doc2(), &flat),
            None,
            "{name}: a flat region at the front is the run budget's own case"
        );
        assert_eq!(
            refusal(&doc2(), &flat_deep),
            Some(QueryError::ImageTooLarge),
            "{name}: a flat region deep in a surface past the run budget is the walk's to refuse"
        );
    }
}

#[test]
fn findlinks_v_is_disjunctive_and_active_filtered() {
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
