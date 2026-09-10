//! M8 contract tests over a real kernel (InMemory), stating what the design
//! and interface assert: the doc-then-region gate order, checked on every
//! entry point that inherits it and against every subspace but `s_C`, and
//! the defined-empty result; image dedup, the region-span-then-V order it
//! returns in, and an image whose runs start at two address lengths, which
//! every read lifting it answers over; disjunctive + active-filtered region
//! discovery, and the trunk head every region read resolves a published
//! document through; the stateless key-cut windowing — the clamp, and every
//! drained page held to
//! the batch order, `next` and exhaustion a returned window promises — whose
//! cursor survives its link's orphaning, its retraction, and a state that
//! never minted it, over the one selection index its three read-outs share;
//! RETRIEVEENDSETS' identity-withholding whole-endset read-out in its total
//! pinned order; the FTT unit/zero/conjunction algebra over all three link
//! slots, the home address-projection filter and its prefix-coverage reach;
//! the two families' zeros and their two stabilities; projection, its
//! content-subspace-only narrowing, addressable discoverability, the defined
//! answer both give a registered-but-empty document, the precedence that
//! settles their document argument before their address one and both ahead
//! of the budget, the trunk head both read a published document through, and
//! the absence rule both apply to a link the home rule refuses; the
//! delete-orphan preview measured against the DELETE it previews, over that
//! operation's whole accepted domain, against M5's own admission, and at the
//! ω and publication gates and the run budget where the two part, with a
//! registered-but-empty document refused for range; the flipped lineage
//! probes with the resident-key gate, `Default` read as `Active` where the
//! two views part,
//! the supersession class they restrict to, the claim's own home
//! attribution, the endpoints it reads out as recorded and the write-surface
//! fences that read-out rests on; every result-set read dropping exactly the
//! links homed where its reader may not read, whichever end of the address
//! order they sit at — filtered at a link's home and whole at its endsets'
//! origins, and asked of a claim rather than of its endpoints; the two
//! budgets, each refused one past its boundary and on every entry point that
//! inherits it, held at the numbers their docs give them, over the quantities
//! the run constant is held to and the collapsed answer the span budget
//! prices, and the run constant's square over the two joins no run count
//! shows — the run-list walk a region asks of M5 and the touch test of a
//! link's whole coverage; the snapshot twins; and — because this file is a
//! crate of its own — the promises M8 makes to a consumer rather than to
//! itself: one named
//! world bound, the standard traits its values carry, and rejection enums
//! that stay exhaustively matchable and name their surface.

use crate::common;

use std::collections::HashSet;

use common::*;
use skep_address::{document_of, Address, Span};
use skep_arrangement::{Caller, DeleteError, HasM5, Vstream};
use skep_discovery::{
    addressably_discoverable_from_on, content_vspan, count_ftt_on, count_v_on, delete_orphans_on,
    findlinks_ftt_on, findlinks_v_on, in_claims_on, out_claims_on, project_on,
    retrieve_endsets_on, window_ftt_on, window_v_on, Cursor, DiscoveryWorld, FourSet, LinkQuery,
    OrphanError, OrphanReport, QueryError, SlotSpec, SupClaim, Window, FROM, MAX_ENDSET_SPANS,
    MAX_IMAGE_RUNS, TO, TYPE,
};
use skep_kernel::{Kernel, Snapshot, TxnError};
use skep_links::{
    enc, EditLinkError, Endset, HasLinks, Link, LinkWriter, MakeLinkError, ShippedType, SlotArg,
    View, MAX_SLOT_SPANS,
};
use skep_namespace::{Namespace, PrincipalId};

// ───────────────────── §1 — content-region discovery ─────────────────────

#[test]
fn region_family_gates_doc_then_region_then_defines_empty() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let lq = LinkQuery::new(&k);

    // Unregistered d → DocNotRegistered, even with a bad region: the document
    // gate is the first act, the region gate second.
    assert_eq!(
        lq.image(&unregistered_doc(), &[vspan(2, 1, 1)]),
        Err(QueryError::DocNotRegistered)
    );
    assert_eq!(
        lq.retrieve_endsets(&unregistered_doc(), &[vspan(1, 1, 1)]),
        Err(QueryError::DocNotRegistered)
    );

    // Region gate: M5's ordinal-level depth-2 V-span shape, restricted to the
    // content subspace — never a silently-clipped different query. The
    // link-subspace span is a shape M5 accepts and M8's added clause refuses …
    assert_eq!(
        lq.findlinks_v(&doc1(), &[vspan(2, 1, 1)]),
        Err(QueryError::BadRegion)
    );
    // … while a non-depth-2 span and an action-point-1 width fail the shape
    // itself, exactly as M5's `is_ordinal_vspan` reads them.
    let deep = skep_address::Span::new(t(&[1, 1, 1]), t(&[0, 0, 1])).expect("T12-valid");
    assert!(!skep_arrangement::is_ordinal_vspan(&deep));
    assert_eq!(lq.count_v(&doc1(), &[deep]), Err(QueryError::BadRegion));
    let level_uniform = skep_address::Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12-valid");
    assert!(!skep_arrangement::is_ordinal_vspan(&level_uniform));
    assert_eq!(
        lq.count_v(&doc1(), &[level_uniform]),
        Err(QueryError::BadRegion)
    );
    // One bad span anywhere in the region rejects the whole request.
    assert_eq!(
        lq.findlinks_v(&doc1(), &[vspan(1, 1, 1), vspan(2, 1, 1)]),
        Err(QueryError::BadRegion)
    );

    // The published constructor and the gate are two halves of ONE shape:
    // what content_vspan builds the gate accepts, and it declines exactly the
    // two requests that would have been BadRegion — a non-s_C subspace and a
    // zero count.
    let built = content_vspan(&vp(1, 1), &n(1)).expect("s_C, count ≥ 1");
    assert!(lq.count_v(&doc1(), &[built]).is_ok());
    assert_eq!(content_vspan(&vp(2, 1), &n(1)), None);
    assert_eq!(content_vspan(&vp(1, 1), &n(0)), None);
    // The rule is "the content subspace", not "anything but the link
    // subspace": over subspaces either side of both numerals, the constructor
    // builds exactly at `s_C` with a count, and the gate refuses exactly what
    // it declines — a subspace-0 or subspace-3 span it admitted would resolve
    // silently to ∅, a different query.
    for s in 0..=3u32 {
        for c in 0..=2u32 {
            let built = content_vspan(&vp(s, 1), &n(c));
            assert_eq!(
                built.is_some(),
                s == 1 && c >= 1,
                "content_vspan at subspace {s}, count {c}"
            );
            if let Some(span) = built {
                assert!(lq.count_v(&doc1(), &[span]).is_ok());
            } else if c >= 1 {
                assert_eq!(
                    lq.count_v(&doc1(), &[vspan(s, 1, c)]),
                    Err(QueryError::BadRegion),
                    "a region in subspace {s} is refused"
                );
            }
        }
    }

    // Registered-but-empty d → a DEFINED empty result, distinct from
    // DocNotRegistered.
    assert_eq!(lq.findlinks_v(&doc2(), &[vspan(1, 1, 5)]), Ok(vec![]));
    assert_eq!(lq.count_v(&doc2(), &[vspan(1, 1, 5)]), Ok(0));
    let w = lq.window_v(&doc2(), &[vspan(1, 1, 5)], None, 3).expect("window");
    assert_eq!(w.batch, vec![]);
    assert_eq!(w.next, None);
    assert!(w.exhausted);
    assert_eq!(lq.retrieve_endsets(&doc2(), &[vspan(1, 1, 5)]), Ok(vec![]));

    // An empty region trivially passes the gate and yields the empty image.
    assert!(lq.image(&doc1(), &[]).expect("empty region is defined").is_empty());
}

/// One region-family entry point reduced to the refusal it answers with, so
/// the gate rule can be stated once and applied to all five.
type RegionRefusal<'a> = Box<dyn Fn(&Address, &[Span]) -> Option<QueryError> + 'a>;

/// The one list every "every region entry point" law reads: the five reads
/// that inherit `image_on`'s gates and budget, each reduced to its refusal
/// through a copy of `lq`. A region read added to the family is added here,
/// and every such law then covers it.
fn region_entry_points<'a>(lq: LinkQuery<'a, World>) -> Vec<(&'static str, RegionRefusal<'a>)> {
    vec![
        ("image", Box::new(move |d, r| lq.image(d, r).err())),
        ("findlinks_v", Box::new(move |d, r| lq.findlinks_v(d, r).err())),
        ("count_v", Box::new(move |d, r| lq.count_v(d, r).err())),
        ("window_v", Box::new(move |d, r| lq.window_v(d, r, None, 3).err())),
        (
            "retrieve_endsets",
            Box::new(move |d, r| lq.retrieve_endsets(d, r).err()),
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
    let lq = LinkQuery::new(&k);

    for (name, refusal) in &region_entry_points(lq) {
        assert_eq!(
            refusal(&unregistered_doc(), &[vspan(1, 1, 1)]),
            Some(QueryError::DocNotRegistered),
            "{name}: an unregistered d is refused"
        );
        for s in [0, 2, 3] {
            assert_eq!(
                refusal(&doc1(), &[vspan(s, 1, 1)]),
                Some(QueryError::BadRegion),
                "{name}: a region in subspace {s}, not s_C, is refused"
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
    let lq = LinkQuery::new(&k);

    // Ordinary V→I resolution.
    assert_eq!(
        lq.image(&doc1(), &[vspan(1, 1, 2)]),
        Ok(vec![run(&ca(1), 2)])
    );
    // Exact-equal repeats are deduped at the boundary (Run: Eq).
    assert_eq!(
        lq.image(&doc1(), &[vspan(1, 1, 2), vspan(1, 1, 2)]),
        Ok(vec![run(&ca(1), 2)])
    );
    // Overlapping INPUT spans may still yield partially-overlapping runs —
    // the dedup claim is exact-equality only, not an address-disjoint
    // partition.
    assert_eq!(
        lq.image(&doc1(), &[vspan(1, 1, 2), vspan(1, 2, 2)]),
        Ok(vec![run(&ca(1), 2), run(&ca(2), 2)])
    );
    // Out-of-range tails are the arrangement intersection (W ∩ dom M(d)).
    assert_eq!(lq.image(&doc1(), &[vspan(1, 2, 99)]), Ok(vec![run(&ca(2), 2)]));
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
    let lq = LinkQuery::new(&k);

    // One span, two runs: V-order within the span.
    assert_eq!(
        lq.image(&doc1(), &[vspan(1, 1, 6)]),
        Ok(vec![run(&ca(4), 3), run(&ca(1), 3)])
    );
    // Two spans, one run each: the order the caller's region asked in.
    assert_eq!(
        lq.image(&doc1(), &[vspan(1, 1, 1), vspan(1, 4, 1)]),
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
    let lq = LinkQuery::new(&k);

    assert_eq!(
        lq.image(&doc1(), &[vspan(1, 1, 1), vspan(1, 1, 2)]),
        Ok(vec![run(&ca(1), 1), run(&ca(1), 2)])
    );
    // The collapse the same key MUST still make: an exact repeat is one run.
    assert_eq!(
        lq.image(&doc1(), &[vspan(1, 1, 2), vspan(1, 1, 2)]),
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
    let lq = LinkQuery::new(&k);
    let region = [vspan(1, 1, 2)];

    // The premise: one image, its runs starting at two lengths.
    let image = lq.image(&doc1(), &region).expect("image");
    assert_eq!(image, vec![run(&ca(1), 1), run(&deep_ca, 1)]);
    assert_eq!(
        image
            .iter()
            .map(|r| r.i_start().tumbler().len())
            .collect::<Vec<_>>(),
        vec![8, 9]
    );

    assert_eq!(
        lq.findlinks_v(&doc1(), &region),
        Ok(vec![near.clone(), far.clone()])
    );
    assert_eq!(lq.count_v(&doc1(), &region), Ok(2));
    assert_eq!(
        lq.retrieve_endsets(&doc1(), &region),
        Ok(vec![(FROM, enc(&[ca(1)])), (FROM, enc([&deep_ca]))])
    );
    assert_eq!(lq.addressably_discoverable_from(&far, &doc1()), Ok(true));
    // The preview stabs the mix twice over: the deleted run is doc1's own, and
    // the retained side holds the transcluded run beside doc1's link runs.
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(1, 1), &n(1)),
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
/// resolving to one run — is admitted unchanged.
#[test]
fn the_region_family_refuses_an_image_past_the_run_budget() {
    let k = kernel();
    for _ in 0..4 {
        seed_content(&k, &doc1(), 1); // four separate INSERTs ⇒ four runs
    }
    let lq = LinkQuery::new(&k);
    // Every span the same: the whole document, resolving to all four runs.
    let at_budget: Vec<Span> = vec![vspan(1, 1, 4); MAX_IMAGE_RUNS / 4];
    let past: Vec<Span> = at_budget.iter().cloned().chain([vspan(1, 1, 1)]).collect();
    let past_then_malformed: Vec<Span> =
        past.iter().cloned().chain([vspan(2, 1, 1)]).collect();
    let flat: Vec<Span> = vec![vspan(1, 1, 1); MAX_SLOT_SPANS];
    assert_eq!(lq.image(&doc1(), &at_budget[..1]).map(|r| r.len()), Ok(4));
    // At the budget the answer is still those four distinct runs — the dedup
    // is not what the budget counts.
    assert_eq!(lq.image(&doc1(), &at_budget).map(|r| r.len()), Ok(4));

    for (name, refusal) in &region_entry_points(lq) {
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
/// one span that deep over the fragmented document is one walk and answered,
/// a flat region at its front is the run budget's own case and answered, and
/// the region gate still speaks first.
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
    let lq = LinkQuery::new(&k);

    // Every span one past doc2's arranged end, and past doc1's.
    let past_the_end = MAX_IMAGE_RUNS as u32 + 2;
    let deep: Vec<Span> = vec![vspan(1, past_the_end, 1); MAX_IMAGE_RUNS];
    let deep_then_malformed: Vec<Span> =
        deep.iter().cloned().chain([vspan(2, 1, 1)]).collect();
    let flat: Vec<Span> = vec![vspan(1, 1, 1); MAX_IMAGE_RUNS];
    assert_eq!(
        lq.image(&doc2(), &deep[..1]),
        Ok(vec![]),
        "a span past the end resolves no run, whatever it walks"
    );
    assert_eq!(lq.image(&doc1(), &deep), Ok(vec![]));

    for (name, refusal) in &region_entry_points(lq) {
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
    }
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
/// `d` can: every argument about `a` is refused ahead of the budget.
#[test]
fn the_pointwise_family_holds_one_run_constant_over_two_quantities() {
    let k = kernel();
    let store = LinkWriter::new(&k, &EVERYONE);
    seed_content(&k, &doc1(), 1);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let lq = LinkQuery::new(&k);

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
    let lq = LinkQuery::new(&k);
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

/// §5 — the precedence between the two gates, on the call that is faulty in
/// BOTH arguments at once. Each read states its refusal order, and only a
/// doubly-faulty call can tell the stated order from the other one: every
/// other case in the suite is faulty in `d` alone or in `a` alone, where
/// either order answers alike. The rule is the family's — every argument
/// about `d` is settled before any argument about `a` — so an unregistered
/// document with a non-link address names the document.
#[test]
fn the_pointwise_gates_settle_the_document_before_the_address() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let lq = LinkQuery::new(&k);

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

#[test]
fn findlinks_v_is_disjunctive_and_active_filtered() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);

    // e1 reaches position 1 via FROM (emit encodes from = enc({ca1})).
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
    assert_eq!(lq.findlinks_v(&doc1(), &[vspan(1, 2, 1)]), Ok(vec![la(2)]));
    assert_eq!(lq.findlinks_v(&doc1(), &[vspan(1, 3, 1)]), Ok(vec![la(2)]));
    // OR across links: position 1 is reached by e1's FROM and m1's TYPE.
    assert_eq!(
        lq.findlinks_v(&doc1(), &[vspan(1, 1, 1)]),
        Ok(vec![la(1), la(2)])
    );
    assert_eq!(lq.count_v(&doc1(), &[vspan(1, 1, 1)]), Ok(2));
    // Result-as-set: a link touching the region through several slots is
    // found once.
    assert_eq!(
        lq.findlinks_v(&doc1(), &[vspan(1, 1, 3)]),
        Ok(vec![la(1), la(2)])
    );

    // findlinks_V ∩ addressable: a nullified link never surfaces, even though its
    // coverage still reaches the region. (Homed in doc2 so the retraction
    // tuple's own enc({doc2}) from-fill stays off doc1's content.)
    store.nullify(SYS, &doc2(), &e1).expect("nullify succeeds");
    assert_eq!(lq.findlinks_v(&doc1(), &[vspan(1, 1, 1)]), Ok(vec![la(2)]));
    assert_eq!(lq.count_v(&doc1(), &[vspan(1, 1, 1)]), Ok(1));
}

// ───────────────────────── §2 — windowed enumeration ─────────────────────────

/// Drain one window read to exhaustion at batch size `n`, holding EVERY page
/// to what a returned `Window` promises — `batch` strictly ascending and no
/// longer than the clamped `n`, `next` its ≺-max or else the cursor
/// unchanged, `exhausted` iff the batch is short — and answer the
/// concatenation. A post-filter moved after the slice keeps the concatenation
/// and breaks a page, so the pages are where it shows. Bounded by `limit`
/// pages, so a window that never reports exhaustion fails rather than hangs.
fn drain_window(n: usize, limit: usize, page: impl Fn(Cursor) -> Window) -> Vec<Address> {
    let clamped = n.max(1);
    let mut drained = Vec::new();
    let mut cur: Cursor = None;
    for _ in 0..limit {
        let w = page(cur.clone());
        assert!(
            w.batch.windows(2).all(|p| p[0] < p[1]),
            "batch strictly ascending: {w:?}"
        );
        assert!(w.batch.len() <= clamped, "at most n = {n} links: {w:?}");
        assert_eq!(
            w.exhausted,
            w.batch.len() < clamped,
            "exhausted iff short, n = {n}: {w:?}"
        );
        assert_eq!(
            w.next,
            w.batch.last().cloned().or(cur),
            "next is the batch's max, else the cursor: {w:?}"
        );
        drained.extend(w.batch);
        if w.exhausted {
            return drained;
        }
        cur = w.next;
    }
    panic!("the window never reported exhaustion within {limit} pages at n = {n}");
}

/// §2 — the key-cut pages, and its cursor survives its link's departure from
/// the matched set by either of the two roads the corpus keeps apart
/// (ASN-0132): ORPHANING, where the link loses its content mapping and stays
/// active — ASN-0108's view-loss, the case W8 names — and RETRACTION, where
/// it is nullified. Resume is a cut past the cursor and never a lookup of
/// it, so neither road can fault it; each departed cursor sits between live
/// links, so a resume that restarted from the top when its cursor was gone
/// would answer wide and fail.
#[test]
fn window_v_pages_by_key_cut_and_survives_orphaning() {
    let k = kernel();
    seed_content(&k, &doc1(), 2); // V 1..2 → ca(1..2)
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]); // la(1): position 1
    link(&store, &doc1(), &[ca(2)], &[ca(102)]); // la(2): position 2 alone
    link(&store, &doc1(), &[ca(1)], &[ca(103)]); // la(3): position 1
    link(&store, &doc1(), &[ca(1)], &[ca(104)]); // la(4): position 1
    let region = [vspan(1, 1, 2)];

    // Ascending address order; next = ≺-max of the batch; full batch ⇒ not
    // exhausted.
    let w1 = lq.window_v(&doc1(), &region, None, 2).expect("window");
    assert_eq!(w1.batch, vec![la(1), la(2)]);
    assert_eq!(w1.next, Some(la(2)));
    assert!(!w1.exhausted);
    // Resume strictly past the cursor; short batch ⇒ exhausted (W9).
    let w2 = lq.window_v(&doc1(), &region, w1.next, 3).expect("window");
    assert_eq!(w2.batch, vec![la(3), la(4)]);
    assert_eq!(w2.next, Some(la(4)));
    assert!(w2.exhausted);
    // Past the end: empty batch, cursor unchanged, still exhausted.
    let w3 = lq.window_v(&doc1(), &region, w2.next, 2).expect("window");
    assert_eq!(w3.batch, vec![]);
    assert_eq!(w3.next, Some(la(4)));
    assert!(w3.exhausted);

    // n = 0 is clamped to 1 (total API) — never a false non-terminal.
    let w0 = lq.window_v(&doc1(), &region, None, 0).expect("window");
    assert_eq!(w0.batch, vec![la(1)]);
    assert!(!w0.exhausted);

    // Cursor survives ORPHANING (W8): la(2)'s only witness in doc1 leaves the
    // arrangement, so la(2) leaves the matched set by view-loss while it
    // stays active — and the key-cut resume needs no lookup of it.
    Vstream::new(&k)
        .delete(SYS, &doc1(), vp(1, 2), n(1))
        .expect("delete succeeds");
    assert!(
        k.snapshot().world().links().is_active(&la(2)),
        "orphaned, not retracted"
    );
    assert_eq!(
        lq.findlinks_v(&doc1(), &region),
        Ok(vec![la(1), la(3), la(4)])
    );
    let w4 = lq.window_v(&doc1(), &region, Some(la(2)), 5).expect("window");
    assert_eq!(w4.batch, vec![la(3), la(4)]);
    assert!(w4.exhausted);

    // And survives RETRACTION, the other road: la(3) is nullified and leaves
    // the set with its content mapping intact, and the resume past it needs
    // no lookup of it either.
    store.nullify(SYS, &doc2(), &la(3)).expect("nullify succeeds");
    let w5 = lq.window_v(&doc1(), &region, Some(la(3)), 5).expect("window");
    assert_eq!(w5.batch, vec![la(4)]);
    assert!(w5.exhausted);
}

/// §2 — W8 on the descriptor family, whose one road out of a set is
/// retraction (CN-MONO). The departed cursor sits between live links, so a
/// resume that looked it up and restarted from the top when it was gone would
/// answer wide.
#[test]
fn window_ftt_resumes_past_a_cursor_whose_link_was_retracted() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    for to in [ca(101), ca(102), ca(103)] {
        link(&store, &doc1(), &[ca(1)], &[to]); // la(1..=3)
    }
    // Homed here, so the retraction tuple (homed in doc2) stays out of the set.
    let homed_here = FourSet {
        home: SlotSpec::Spans(enc(&[doc1()])),
        ..FourSet::any()
    };
    let w1 = lq.window_ftt(&homed_here, None, 2);
    assert_eq!(w1.batch, vec![la(1), la(2)]);
    store.nullify(SYS, &doc2(), &la(2)).expect("nullify succeeds");
    assert_eq!(
        lq.findlinks_ftt(&homed_here),
        vec![la(1), la(3)],
        "la(2) has left the set"
    );
    let w2 = lq.window_ftt(&homed_here, w1.next, 5);
    assert_eq!(w2.batch, vec![la(3)]);
    assert!(w2.exhausted);
}

/// §2 — EVERY `Address` is a legal cursor, including one naming a link the
/// state being read never minted: a cursor paged off the head and replayed
/// against an earlier position (`POST /op-at` runs a window frame as of one)
/// names exactly that. Resume is a cut past it, never a lookup of it, so it
/// resumes where it would have — and a cursor naming no link at all cuts by
/// the same order.
#[test]
fn a_window_resumes_past_a_cursor_its_state_never_minted() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let first = link(&store, &doc1(), &[ca(1)], &[ca(101)]); // la(1)
    let theirs = link(&store, &doc2(), &[ca(1)], &[ca(102)]); // la2(1): after every doc1 link
    let earlier = k.snapshot();
    let later = link(&store, &doc1(), &[ca(1)], &[ca(103)]); // la(2), minted after `earlier`
    assert!(
        earlier.world().links().readlink(&later).is_none(),
        "the cursor names nothing at `earlier`"
    );
    let region = [vspan(1, 1, 1)];

    let head = window_v_on(&k.snapshot(), &doc1(), &region, None, 2, &every_home).expect("window");
    assert_eq!(head.batch, vec![first, later]);
    let resumed = window_v_on(&earlier, &doc1(), &region, head.next.clone(), 5, &every_home)
        .expect("any Address is a legal cursor");
    assert_eq!(resumed.batch, vec![theirs.clone()]);
    assert!(resumed.exhausted);
    assert_eq!(
        window_ftt_on(&earlier, &FourSet::any(), head.next, 5, &every_home).batch,
        vec![theirs.clone()]
    );
    // A cursor that is no link at all cuts the same way: doc2's own address
    // sorts after every doc1 link and before every doc2 one.
    assert_eq!(
        window_ftt_on(&earlier, &FourSet::any(), Some(doc2()), 5, &every_home).batch,
        vec![theirs]
    );
}

/// §2 — one selection index, read out three ways: `count_v`, `findlinks_v`
/// and `window_v` at EVERY batch size answer off the same
/// `findlinks_V ∩ addressable`, so they cannot disagree about which links
/// touch a region (W4/W5 — no continuously-matching link duplicated or
/// skipped). The descriptor family states this over five descriptors; the
/// region family is entitled to the law rather than to one hand-picked
/// pagination, so this walks five regions × every batch size from the clamp
/// at 0 through one past the set, holding every page to what a returned
/// window promises.
#[test]
fn region_count_enumeration_and_window_read_out_one_selection_index() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    // Varied slot reach, so the regions below select different subsets …
    for (from, to) in [
        (ca(1), ca(101)),
        (ca(2), ca(3)),
        (ca(3), ca(101)),
        (ca(1), ca(2)),
    ] {
        link(&store, &doc1(), &[from], &[to]);
    }
    // … and one retracted link reaching position 2, which no read-out may
    // surface.
    let dead = link(&store, &doc1(), &[ca(2)], &[ca(102)]);
    store.nullify(SYS, &doc2(), &dead).expect("nullify succeeds");

    // The law is not vacuous: the wide region selects all four live links and
    // none of the retracted one.
    assert_eq!(
        lq.findlinks_v(&doc1(), &[vspan(1, 1, 3)]),
        Ok(vec![la(1), la(2), la(3), la(4)])
    );

    for region in [
        vec![],
        vec![vspan(1, 1, 1)],
        vec![vspan(1, 2, 1)],
        vec![vspan(1, 1, 3)],
        vec![vspan(1, 1, 1), vspan(1, 3, 1)],
    ] {
        let enumerated = lq.findlinks_v(&doc1(), &region).expect("findlinks_v");
        assert!(
            !enumerated.contains(&dead),
            "a nullified link never surfaces: {region:?}"
        );
        assert_eq!(
            lq.count_v(&doc1(), &region),
            Ok(enumerated.len()),
            "count = |enum| for {region:?}"
        );

        // n = 0 is the clamp (W9); n = |enumerated| is the equal case, where
        // the batch exactly drains the set and one further call is owed to
        // report exhaustion. Every clamped batch admits at least one link, so
        // a drain of `len` links owes at most `len + 1` pages.
        for n in 0..=enumerated.len() + 1 {
            let drained = drain_window(n, enumerated.len() + 1, |cur| {
                lq.window_v(&doc1(), &region, cur, n).expect("window")
            });
            assert_eq!(
                drained, enumerated,
                "the window drains sel for {region:?} at n = {n}"
            );
        }
    }
}

// ───────────────────────── §4 — RETRIEVEENDSETS ─────────────────────────

#[test]
fn retrieve_endsets_withholds_identity_whole_endsets_pinned_order() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    // Two distinct links with VALUE-IDENTICAL from-endsets (dedup collapse),
    // plus one makelink whose from spans all three positions.
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    store
        .makelink(
            SYS,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 3)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)]),
        )
        .expect("makelink succeeds");
    let whole = Endset::from_spans([run(&ca(1), 3).iextent()]);

    // A query touching only position 2 surfaces the WHOLE stored endset,
    // never a clip (RE-CLIP/RE-WHOLE); abutting endsets (the emits' enc({ca1})
    // at position 1, the makelink's TO at 3 and TYPE at 1) are Adjacent to
    // the image — not matches.
    assert_eq!(
        lq.retrieve_endsets(&doc1(), &[vspan(1, 2, 1)]),
        Ok(vec![(FROM, whole.clone())])
    );

    // The wide query: identity withheld — the two emits collapse to ONE
    // (FROM, enc({ca1})) pair (RE-UNIT) — and the output order is pinned:
    // slot, then lexicographic span-sequence.
    assert_eq!(
        lq.retrieve_endsets(&doc1(), &[vspan(1, 1, 3)]),
        Ok(vec![
            (FROM, enc(&[ca(1)])),
            (FROM, whole),
            (TO, Endset::from_spans([run(&ca(3), 1).iextent()])),
            (TYPE, Endset::from_spans([run(&ca(1), 1).iextent()])),
        ])
    );
}

/// §4 — the pinned order is TOTAL: fourteen FROM endsets that tie on every
/// key but one — eight sharing their one span's start and differing in its
/// width, six sharing their first span and differing in the second — come
/// back in one order, twice, whatever order the throwaway hash set held them
/// in. `enc(&[ca(1)])` and the width-1 run's extent are one span (both are
/// `ca(1)` to the next position at its length), so the width-1 endset is a
/// strict prefix of every two-span one, and each of those sorts ahead of
/// every wider single span.
#[test]
fn retrieve_endsets_orders_pairs_that_tie_on_every_key_but_the_last() {
    let k = kernel();
    seed_content(&k, &doc1(), 8); // one run: V 1..8 → ca(1..8)
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    for w in 1..=8 {
        store
            .makelink(
                SYS,
                &doc1(),
                SlotArg::Resolve(vec![spec(&doc1(), 1, 1, w)]),
                SlotArg::Addrs(vec![ca(101)]),
                SlotArg::Addrs(vec![rel()]),
            )
            .expect("makelink succeeds");
    }
    for j in 3..=8 {
        link(&store, &doc1(), &[ca(1), ca(j)], &[ca(101)]);
    }
    let one = |w: u32| (FROM, Endset::from_spans([run(&ca(1), w).iextent()]));
    let two = |j: u32| (FROM, enc(&[ca(1), ca(j)]));
    let expected: Vec<(usize, Endset)> = std::iter::once(one(1))
        .chain((3..=8).map(two))
        .chain((2..=8).map(one))
        .collect();
    for _ in 0..2 {
        assert_eq!(
            lq.retrieve_endsets(&doc1(), &[vspan(1, 1, 1)]),
            Ok(expected.clone())
        );
    }
}

/// A FROM endset of `spans` addresses touching doc1's position 1: `ca(1)` is
/// the span a region naming that position touches, and the rest name
/// unarranged positions of doc1. Endsets collapse by VALUE, so the filler is
/// keyed on `link`: the same `link` number gives the same endset, distinct
/// numbers give distinct ones.
fn wide_from(link: u32, spans: u32) -> Vec<Address> {
    let mut addrs = vec![ca(1)];
    addrs.extend((1..spans).map(|j| ca(1000 + link * spans + j)));
    addrs
}

/// §4 — the answer's span budget, at its boundary. The amplification it
/// prices is the one no request-shaped cap reaches: a two-hundred-byte query
/// naming ONE position, answered with every whole endset touching it, each of
/// which M7 admits at `MAX_SLOT_SPANS` on deposit. Sixty-four such endsets is
/// the budget exactly, and one span more — a sixty-fifth link naming position
/// 1 alone — is refused rather than dropped: RE-UNIT licenses withholding a
/// link's IDENTITY, never its endset.
#[test]
fn retrieve_endsets_refuses_an_answer_past_the_span_budget() {
    const SPANS: u32 = 1024;
    let at_budget = MAX_ENDSET_SPANS / SPANS as usize; // 64 whole endsets

    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    let region = [vspan(1, 1, 1)];
    assert!(SPANS as usize <= MAX_SLOT_SPANS, "each slot is in M7's budget");
    for i in 0..at_budget as u32 {
        link(&store, &doc1(), &wide_from(i, SPANS), &[ca(101)]);
    }

    // At the budget: one pair per link, each endset WHOLE, none clipped.
    let pairs = lq.retrieve_endsets(&doc1(), &region).expect("at budget");
    assert_eq!(pairs.len(), at_budget);
    assert!(pairs.iter().all(|(i, e)| *i == FROM && e.len() == SPANS as usize));

    // One span more, and the answer is refused rather than shortened.
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    assert_eq!(
        lq.retrieve_endsets(&doc1(), &region),
        Err(QueryError::EndsetsTooLarge)
    );
    // The region family's other read-outs carry no such budget: they enumerate
    // ADDRESSES, whose size is the link count and not the endsets'.
    assert_eq!(lq.count_v(&doc1(), &region), Ok(at_budget + 1));
}

/// §4 — the span budget prices what the answer CARRIES: links sharing one
/// wide endset are one pair and one charge. A per-link charge would refuse
/// this answer, which is a single pair — the collapse RE-UNIT licenses,
/// refused for being collapsed.
#[test]
fn retrieve_endsets_prices_the_collapsed_answer_not_the_links_behind_it() {
    const SPANS: u32 = 1024;
    let links = MAX_ENDSET_SPANS / SPANS as usize + 1; // one more than a per-link charge admits
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    let shared = wide_from(0, SPANS);
    for i in 0..links as u32 {
        link(&store, &doc1(), &shared, &[ca(101 + i)]);
    }
    let region = [vspan(1, 1, 1)];
    assert_eq!(
        lq.count_v(&doc1(), &region),
        Ok(links),
        "every link touches the region"
    );
    assert_eq!(
        lq.retrieve_endsets(&doc1(), &region),
        Ok(vec![(FROM, enc(&shared))])
    );
}

/// §4 — the answer budget is not M7's slot budget: two links each carrying
/// the most spans M7 admits in one slot are answered whole. That is the case
/// the constant's own doc gives for `2^16` over `2^12`, and a symbolic
/// boundary test cannot see it.
#[test]
fn retrieve_endsets_answers_a_region_two_maximal_endsets_touch() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    for i in 0..2 {
        link(&store, &doc1(), &wide_from(i, MAX_SLOT_SPANS as u32), &[ca(101)]);
    }
    let pairs = lq
        .retrieve_endsets(&doc1(), &[vspan(1, 1, 1)])
        .expect("inside the answer budget");
    assert_eq!(pairs.len(), 2);
    assert!(pairs
        .iter()
        .all(|(i, e)| *i == FROM && e.len() == MAX_SLOT_SPANS));
}

// ─────────────────── §3 — four-set descriptor query ───────────────────

#[test]
fn ftt_the_unit_matches_all_the_zero_annihilates_and_slots_conjoin() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    link(&store, &doc1(), &[ca(2)], &[ca(101)]);
    link(&store, &doc2(), &[ca(1)], &[ca(102)]);

    // (∗,∗,∗,∗) — the whole addressable slice (FL-WILD), address order.
    assert_eq!(lq.findlinks_ftt(&FourSet::any()), vec![la(1), la(2), la2(1)]);
    assert_eq!(lq.count_ftt(&FourSet::any()), 3);

    // Any constrained-empty slot annihilates (FL-EMP) — both the explicit
    // zero and an empty Spans endset, which never reaches M7.
    let q = FourSet {
        to: SlotSpec::Empty,
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&q), vec![]);
    assert_eq!(lq.count_ftt(&q), 0);
    let q = FourSet {
        from: SlotSpec::Spans(Endset::empty()),
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&q), vec![]);

    // One constrained slot.
    let q_from = FourSet {
        from: SlotSpec::Spans(enc(&[ca(1)])),
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&q_from), vec![la(1), la2(1)]);
    // Conjunction across slots (AND-of-ORs, M7's combiner).
    let q_both = FourSet {
        from: SlotSpec::Spans(enc(&[ca(1)])),
        to: SlotSpec::Spans(enc(&[ca(102)])),
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&q_both), vec![la2(1)]);
    assert_eq!(lq.count_ftt(&q_both), 1);

    // Retraction shrinks the active slice: a found link stays found ONLY
    // absent retraction (FL-MON's hypothesis).
    store.nullify(SYS, &doc2(), &e1).expect("nullify succeeds");
    assert_eq!(lq.findlinks_ftt(&q_from), vec![la2(1)]);
}

/// §3 — the descriptor answers FL-EMP off its own slots, for all four of
/// them, without asking the store: an `Empty` slot carries no endset to ask
/// the store WITH, so a query built from the slots alone would drop it as
/// though it were the unit.
#[test]
fn the_descriptor_states_its_own_zero() {
    assert!(!FourSet::any().is_unsatisfiable());
    for zero in [SlotSpec::Empty, SlotSpec::Spans(Endset::empty())] {
        for q in [
            FourSet {
                home: zero.clone(),
                ..FourSet::any()
            },
            FourSet {
                from: zero.clone(),
                ..FourSet::any()
            },
            FourSet {
                to: zero.clone(),
                ..FourSet::any()
            },
            FourSet {
                ty: zero.clone(),
                ..FourSet::any()
            },
        ] {
            assert!(q.is_unsatisfiable(), "{q:?} carries the zero");
        }
    }
}

/// §3 — the conjunction is handed to M7 smallest constraint first, because
/// M7 drives ONE whole-store scan with the first and narrows the survivors
/// with the rest. That reordering must move work and not the answer, and the
/// way it could move the answer is by decoupling an endset from its slot: a
/// descriptor whose big constraint is FROM and small is TO answers the same
/// links as it did unsorted, and its MIRROR — the same two endsets in the
/// other slots — answers different links, not the same ones. A sort that lost
/// the pairing would make the two agree.
#[test]
fn ftt_hands_the_smallest_constraint_first_without_moving_the_answer() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    link(&store, &doc1(), &[ca(1)], &[ca(2)]); // la(1): from ca(1), to ca(2)
    link(&store, &doc1(), &[ca(2)], &[ca(1)]); // la(2): the mirror

    // A many-span constraint and a one-span one, so the sort actually
    // reorders rather than leaving the list as written.
    let wide = enc(&[ca(1), ca(101), ca(102), ca(103), ca(104)]);
    let narrow = enc(&[ca(2)]);
    assert!(wide.len() > narrow.len(), "the sort has something to do");

    let wide_from = FourSet {
        from: SlotSpec::Spans(wide.clone()),
        to: SlotSpec::Spans(narrow.clone()),
        ..FourSet::any()
    };
    let wide_to = FourSet {
        from: SlotSpec::Spans(narrow),
        to: SlotSpec::Spans(wide),
        ..FourSet::any()
    };
    // Each descriptor names exactly one of the two links, and they are
    // different links: the endsets stayed with the slots they were written in
    // however the list was ordered on the way to M7.
    assert_eq!(lq.findlinks_ftt(&wide_from), vec![la(1)]);
    assert_eq!(lq.findlinks_ftt(&wide_to), vec![la(2)]);
    assert_eq!(lq.count_ftt(&wide_from), 1);
}

/// §3 — Θ constrains like the other link slots: a descriptor naming a type
/// answers the links carrying it, alone and conjoined. Every other descriptor
/// here constrains FROM, TO or home, so a constraint list that dropped Θ, or
/// paired it with the wrong slot numeral, would pass them all.
#[test]
fn ftt_the_type_slot_answers_the_links_carrying_the_type() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]); // the suite's relation type
    let e2 = link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    let (claim, _) = store
        .assert_sup(SYS, &doc1(), &e1, &e2)
        .expect("assert_sup succeeds");
    let sup = enc(&[ra(4)]); // Supersedes, as the fence test reads it off the store
    let of_type = |ty: Endset| FourSet {
        ty: SlotSpec::Spans(ty),
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&of_type(rel_ty())), vec![e1.clone(), e2]);
    assert_eq!(lq.findlinks_ftt(&of_type(sup.clone())), vec![claim.clone()]);
    assert_eq!(lq.count_ftt(&of_type(sup.clone())), 1);
    let from_e1 = |ty: Endset| FourSet {
        from: SlotSpec::Spans(enc([&e1])),
        ty: SlotSpec::Spans(ty),
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&from_e1(sup)), vec![claim]);
    assert_eq!(lq.findlinks_ftt(&from_e1(rel_ty())), vec![]);
}

#[test]
fn ftt_home_filter_is_an_address_projection_applied_lazily() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    link(&store, &doc1(), &[ca(2)], &[ca(101)]);
    link(&store, &doc2(), &[ca(1)], &[ca(102)]);

    // The home slot is matched against home(a) = document_of — an address
    // projection, not a link slot and not an arrangement test.
    let q_home1 = FourSet {
        home: SlotSpec::Spans(enc(&[doc1()])),
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&q_home1), vec![la(1), la(2)]);
    assert_eq!(lq.count_ftt(&q_home1), 2);
    let q_home2 = FourSet {
        home: SlotSpec::Spans(enc(&[doc2()])),
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&q_home2), vec![la2(1)]);

    // home composes conjunctively with slot constraints.
    let q_h2_from = FourSet {
        home: SlotSpec::Spans(enc(&[doc2()])),
        from: SlotSpec::Spans(enc(&[ca(1)])),
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&q_h2_from), vec![la2(1)]);

    // The home slot's zero admits nothing — FL-EMP for a slot that is never
    // carried into M7's conjunction, so the descriptor answers it alone.
    for zero in [SlotSpec::Empty, SlotSpec::Spans(Endset::empty())] {
        let q = FourSet {
            home: zero,
            ..FourSet::any()
        };
        assert_eq!(lq.findlinks_ftt(&q), vec![]);
        assert_eq!(lq.count_ftt(&q), 0);
        assert_eq!(lq.window_ftt(&q, None, 5).batch, vec![]);
    }

    // The home filter is applied lazily during the window walk: pagination
    // over the home-narrowed set with the same cursor mechanism.
    let w1 = lq.window_ftt(&q_home1, None, 1);
    assert_eq!(w1.batch, vec![la(1)]);
    assert!(!w1.exhausted);
    let w2 = lq.window_ftt(&q_home1, w1.next, 5);
    assert_eq!(w2.batch, vec![la(2)]);
    assert!(w2.exhausted);
}

/// §3 — `athome` is PREFIX COVERAGE, not address equality: the constraint's
/// coverage must name `home(a)`, and `enc` builds a subtree span. So an
/// ACCOUNT names every link homed under it — the query M10 passes through
/// from the wire unaltered, and the one a rewrite to equality would silently
/// answer `[]` for. Every other home test here names a document address,
/// where coverage and equality agree.
#[test]
fn ftt_home_is_prefix_coverage_not_address_equality() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    link(&store, &doc1(), &[ca(2)], &[ca(101)]);
    link(&store, &doc2(), &[ca(1)], &[ca(102)]);

    // The account both documents hang under admits the links homed in each.
    let account = FourSet {
        home: SlotSpec::Spans(enc(&[a(&[1, 0, 1])])),
        ..FourSet::any()
    };
    assert_eq!(lq.findlinks_ftt(&account), vec![la(1), la(2), la2(1)]);
    assert_eq!(lq.count_ftt(&account), 3);

    // And the relation has a direction: an address UNDER doc1 is not a prefix
    // of it, so its coverage names no link's home — a satisfiable request
    // with an empty answer, not the zero.
    let under = FourSet {
        home: SlotSpec::Spans(enc(&[ca(1)])),
        ..FourSet::any()
    };
    assert!(!under.is_unsatisfiable(), "the request names something");
    assert_eq!(lq.findlinks_ftt(&under), vec![]);
}

/// §3 — CN-ENUM: one `sat` consumed by every read-out, so the count, the
/// enumeration and the windowed drain cannot disagree about which links match.
/// The home-constrained descriptors are the load-bearing cases: they are the
/// only ones where the residence post-filter narrows the candidate set, so a
/// read-out that evaluated the candidates instead of `sat` would answer wide
/// here and nowhere else — and a residence post-filter applied after the
/// window's slice would come back with a short page claiming more to come.
#[test]
fn ftt_count_enumeration_and_window_read_out_one_sat() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    link(&store, &doc1(), &[ca(2)], &[ca(101)]);
    link(&store, &doc2(), &[ca(1)], &[ca(102)]);

    for q in [
        FourSet::any(),
        FourSet {
            home: SlotSpec::Spans(enc(&[doc1()])),
            ..FourSet::any()
        },
        FourSet {
            home: SlotSpec::Spans(enc(&[doc2()])),
            ..FourSet::any()
        },
        FourSet {
            home: SlotSpec::Spans(enc(&[doc1()])),
            from: SlotSpec::Spans(enc(&[ca(1)])),
            ..FourSet::any()
        },
        FourSet {
            home: SlotSpec::Empty,
            ..FourSet::any()
        },
    ] {
        let enumerated = lq.findlinks_ftt(&q);
        assert_eq!(lq.count_ftt(&q), enumerated.len(), "count = |enum| for {q:?}");

        // The same set again, drained through the cursor at every batch size
        // from the clamp at 0 through one past the set, every page held to
        // what a returned window promises.
        for n in 0..=enumerated.len() + 1 {
            assert_eq!(
                drain_window(n, enumerated.len() + 1, |cur| lq.window_ftt(&q, cur, n)),
                enumerated,
                "the window drains sat for {q:?} at n = {n}"
            );
        }
    }

    // `n = 0` is clamped to 1 on this family too (W9 totality): the drains
    // above visit it, and this pins the one link it answers.
    assert_eq!(lq.window_ftt(&FourSet::any(), None, 0).batch, vec![la(1)]);
}

/// §3 — the two zeros ASN-0132 keeps apart: `count_v`'s D-ZERO asserts present
/// unreachability through one document, `count_ftt`'s CN-ZERO a verdict over
/// the whole addressable store. A link homed in a document that arranges
/// nothing shows they are different assertions about one world — the region
/// census says nothing reaches there, the descriptor census counts the link.
#[test]
fn the_region_zero_and_the_descriptor_zero_assert_different_things() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    link(&store, &doc2(), &[ca(1)], &[ca(101)]);

    // D-ZERO: nothing reaches doc2's region — it arranges nothing.
    assert_eq!(lq.count_v(&doc2(), &[vspan(1, 1, 5)]), Ok(0));
    // CN-ZERO over the same link: the store's census finds it, unreachable or
    // not (CN-STAB — the descriptor family asks no arrangement question).
    let q_home2 = FourSet {
        home: SlotSpec::Spans(enc(&[doc2()])),
        ..FourSet::any()
    };
    assert_eq!(lq.count_ftt(&q_home2), 1);
    // And CN-ZERO proper, over a home no link resides in: a store-wide
    // verdict, not present unreachability.
    let q_home_none = FourSet {
        home: SlotSpec::Spans(enc(&[unregistered_doc()])),
        ..FourSet::any()
    };
    assert_eq!(lq.count_ftt(&q_home_none), 0);
    assert!(!q_home_none.is_unsatisfiable()); // the request names something
}

/// §3 — the two families' documented STABILITY, which is a different
/// distinction from the two zeros above: `count_v` is non-monotone
/// (D-NONMONO — an arrangement change alone drops it), while `count_ftt` is
/// monotone absent retraction (CN-MONO — nothing but a nullification shrinks
/// it). One delete, no retraction anywhere, separates them; every other drop
/// in this suite is caused by a nullification, which BOTH families honour.
#[test]
fn the_region_census_drops_when_content_leaves_while_the_descriptor_census_holds() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let region = [vspan(1, 1, 2)];
    let homed_here = FourSet {
        home: SlotSpec::Spans(enc(&[doc1()])),
        ..FourSet::any()
    };
    assert_eq!(lq.count_v(&doc1(), &region), Ok(1));
    assert_eq!(lq.count_ftt(&homed_here), 1);

    // The link's only witness in doc1 leaves the arrangement. The link is not
    // retracted, and it is still resident.
    Vstream::new(&k)
        .delete(SYS, &doc1(), vp(1, 1), n(1))
        .expect("delete succeeds");
    assert!(k.snapshot().world().links().is_active(&la(1)));

    assert_eq!(lq.count_v(&doc1(), &region), Ok(0)); // present unreachability
    assert_eq!(lq.count_ftt(&homed_here), 1); // existence, unchanged
}

// ─────────────── §5 — projection & discoverability ───────────────

#[test]
fn project_is_content_subspace_i_to_v_with_conflated_notalink() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
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
    let lq = LinkQuery::new(&k);
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
    let lq = LinkQuery::new(&k);
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

/// The published fixture, and the one shape where head-float decides an
/// answer: `pdoc` takes two positions while memberless — they land in its
/// OWN arrangement — then VERSION mints its head member, which shares that
/// arrangement, and two more deposits land in the HEAD alone. So pdoc's own
/// arrangement is frozen at its pre-chain state (`pca(1..=2)`) while every
/// reader of pdoc answers from the head (`pca(1..=4)`).
fn published_world() -> Kernel<World> {
    let k = kernel();
    seed_published_content(&k, &pdoc(), 2); // memberless: pdoc's own V 1..2
    let (head, _) = Vstream::new(&k)
        .version(PrincipalId(1), &pdoc(), None)
        .expect("the owner versions its published document");
    assert_eq!(head, phead(), "the chain's first member");
    seed_published_content(&k, &pdoc(), 2); // the head's V 3..4, and nowhere else
    k
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
    let lq = LinkQuery::new(&k);

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

/// §1 — HEAD-FLOAT on every region read, not only the two the pointwise law
/// above composes with: `image_on` states that the whole family inherits its
/// float, so each of the five is asked. Position 3 exists only in pdoc's trunk
/// head, so any one read resolving pdoc's own frozen arrangement would answer
/// empty there.
#[test]
fn every_region_read_resolves_a_published_document_through_its_trunk_head() {
    let k = published_world();
    let store = LinkWriter::new(&k, &EVERYONE);
    let head_only = link(&store, &doc1(), &[pca(3)], &[ca(102)]);
    let lq = LinkQuery::new(&k);
    let region = [vspan(1, 3, 1)];
    assert_eq!(lq.image(&pdoc(), &region), Ok(vec![run(&pca(3), 1)]));
    assert_eq!(lq.findlinks_v(&pdoc(), &region), Ok(vec![head_only.clone()]));
    assert_eq!(lq.count_v(&pdoc(), &region), Ok(1));
    assert_eq!(
        lq.window_v(&pdoc(), &region, None, 5).map(|w| w.batch),
        Ok(vec![head_only])
    );
    assert_eq!(
        lq.retrieve_endsets(&pdoc(), &region),
        Ok(vec![(FROM, enc(&[pca(3)]))])
    );
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

// ─────────────────── §6 — pre-edit link-survival ───────────────────

#[test]
fn delete_orphans_mirrors_delete_preconditions() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let lq = LinkQuery::new(&k);

    assert_eq!(
        lq.delete_orphans(&unregistered_doc(), &vp(1, 1), &n(1)),
        Err(OrphanError::DocNotRegistered)
    );
    // A registered-but-empty d is refused for RANGE, never as unregistered:
    // n_C = 0 admits no range, and which variant answers says which fault.
    assert_eq!(
        lq.delete_orphans(&doc2(), &vp(1, 1), &n(1)),
        Err(OrphanError::OutOfBounds)
    );
    assert_eq!(
        lq.delete_orphans(&doc2(), &vp(1, 1), &n(0)),
        Err(OrphanError::EmptyWidth)
    );
    // Check order mirrors §6: subspace, then width, then the folded bounds.
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(2, 1), &n(0)),
        Err(OrphanError::NotContentSubspace)
    );
    // Width ahead of bounds: an out-of-range p with width 0 is labelled
    // EmptyWidth here where M5's DELETE, checking bounds first, says
    // NotArranged — the same refusal under a different word (§6).
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(1, 0), &n(0)),
        Err(OrphanError::EmptyWidth)
    );
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(1, 0), &n(1)),
        Err(OrphanError::OutOfBounds)
    );
    // OutOfBounds folds M5's NotArranged (start beyond the arranged run) …
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(1, 4), &n(1)),
        Err(OrphanError::OutOfBounds)
    );
    // … and M5's OutOfBounds (range overrun).
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(1, 2), &n(3)),
        Err(OrphanError::OutOfBounds)
    );
    // Boundary acceptance: the last position, and the whole range.
    assert!(lq.delete_orphans(&doc1(), &vp(1, 3), &n(1)).is_ok());
    assert!(lq.delete_orphans(&doc1(), &vp(1, 1), &n(3)).is_ok());
}

#[test]
fn delete_orphans_reports_active_last_witness_losses() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    // link_a witnesses positions 1 (FROM) and 2 (TO); link_b only 3.
    let _link_a = link(&store, &doc1(), &[ca(1)], &[ca(2)]);
    let link_b = link(&store, &doc1(), &[ca(3)], &[ca(3)]);

    // Deleting position 3 drops link_b's last witness in d.
    let r = lq.delete_orphans(&doc1(), &vp(1, 3), &n(1)).expect("preview");
    assert_eq!(r.orphaned, vec![la(2)]);
    // Deleting position 1 leaves link_a witnessed at position 2 — no orphan.
    let r = lq.delete_orphans(&doc1(), &vp(1, 1), &n(1)).expect("preview");
    assert_eq!(r.orphaned, vec![]);
    // Deleting everything orphans both (no retained content, no link runs).
    let r = lq.delete_orphans(&doc1(), &vp(1, 1), &n(3)).expect("preview");
    assert_eq!(r.orphaned, vec![la(1), la(2)]);

    // Orphans are reported over the ACTIVE view: a nullified link that loses
    // its last witness is NOT reported (divergence from ASN-0117's D(d,Σ)).
    store.nullify(SYS, &doc2(), &link_b).expect("nullify succeeds");
    let r = lq.delete_orphans(&doc1(), &vp(1, 3), &n(1)).expect("preview");
    assert_eq!(r.orphaned, vec![]);

    // The preview is a pure what-if — the arrangement is untouched.
    assert_eq!(k.snapshot().world().m5().content_count(&doc1()), n(3));
}

/// The survival fixture, rebuilt per case: the preview is read off one kernel
/// and the DELETE that follows mutates it, so each `(p, width)` owns its own
/// world. Every witness shape the `orphaned` identity's three retained terms
/// answer for is present — a prefix-only witness, a suffix-only one, a split
/// one, a LINK-subspace one, a link reaching nothing doc1 arranges, and a
/// retracted one.
fn survival_world() -> Kernel<World> {
    let k = kernel();
    seed_content(&k, &doc1(), 4); // V 1..4 → ca(1..4)
    {
        let store = LinkWriter::new(&k, &EVERYONE);
        link(&store, &doc1(), &[ca(1)], &[ca(2)]); // la(1): positions 1 and 2
        link(&store, &doc1(), &[ca(4)], &[ca(4)]); // la(2): position 4 alone
        link(&store, &doc1(), &[ca(1)], &[ca(4)]); // la(3): positions 1 and 4 — witnesses on both sides
        link(&store, &doc1(), &[ca(2)], &[la(1)]); // la(4): position 2, and doc1's LINK subspace
        link(&store, &doc1(), &[ca(101)], &[ca(102)]); // la(5): reaches nothing doc1 arranges
        let dead = link(&store, &doc1(), &[ca(3)], &[ca(3)]); // la(6): position 3 …
        store.nullify(SYS, &doc2(), &dead).expect("nullify succeeds"); // … then retracted
    }
    k
}

/// §6 — the preview is a preview OF THE DELETE: over the whole accepted
/// domain of a four-position document, the links it names as orphaned are
/// exactly the links that stop being addressably discoverable from `d` once
/// that delete is performed. Ten cases, because each of the identity's three
/// retained terms — the prefix, the suffix, and the link runs a text delete
/// never touches — is load-bearing only at particular `(p, width)`, and the
/// suite's hand-picked cases left two of the three unwatched.
#[test]
fn delete_orphans_previews_exactly_what_the_delete_drops() {
    let mut ever_orphaned = false;
    for p in 1..=4u32 {
        for width in 1..=(5 - p) {
            let k = survival_world();
            let lq = LinkQuery::new(&k);

            let preview = lq
                .delete_orphans(&doc1(), &vp(1, p), &n(width))
                .expect("the accepted domain");
            ever_orphaned |= !preview.orphaned.is_empty();
            // What doc1 reaches now, in the ascending address order
            // `orphaned` also carries.
            let before: Vec<Address> = lq
                .findlinks_ftt(&FourSet::any())
                .into_iter()
                .filter(|a| lq.addressably_discoverable_from(a, &doc1()) == Ok(true))
                .collect();

            Vstream::new(&k)
                .delete(SYS, &doc1(), vp(1, p), n(width))
                .expect("the request the preview accepted");

            let dropped: Vec<Address> = before
                .into_iter()
                .filter(|a| lq.addressably_discoverable_from(a, &doc1()) == Ok(false))
                .collect();
            assert_eq!(
                preview.orphaned, dropped,
                "preview of DELETE [{p}, {p}+{width}) on doc1"
            );
        }
    }
    assert!(
        ever_orphaned,
        "the fixture must orphan something, else the law above is vacuous"
    );
}

/// §6 — a link witnessed by content the delete RETAINS AHEAD of it survives.
/// The prefix term of `retained` is the only thing that says so, and no case
/// in the suite's example test has a prefix witness.
#[test]
fn delete_orphans_keeps_a_link_witnessed_by_the_retained_prefix() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    link(&store, &doc1(), &[ca(1)], &[ca(3)]);

    // Deleting position 3 takes the link's TO witness; its FROM witness is in
    // the retained prefix, so the link keeps its reach.
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(1, 3), &n(1)),
        Ok(OrphanReport { orphaned: vec![] })
    );
    // Deleting everything takes both, so the prefix term cannot be
    // over-retaining either.
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(1, 1), &n(3)),
        Ok(OrphanReport {
            orphaned: vec![la(1)]
        })
    );
}

/// §6 — a text delete never touches the link subspace, so a link whose only
/// witness in `d` is a LINK address stays reachable however much content
/// goes. The `link_runs` term of `retained` is the only thing that says so.
#[test]
fn delete_orphans_keeps_a_link_witnessed_in_the_link_subspace_a_text_delete_never_touches() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    let seated = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    link(&store, &doc1(), &[ca(1)], &[seated]);

    // Both links reach position 1, and the whole content goes. Only la(2)
    // keeps a witness — la(1), which makelink seated in doc1's link runs.
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(1, 1), &n(3)),
        Ok(OrphanReport {
            orphaned: vec![la(1)]
        })
    );
}

/// §6 — the preview's ADMISSION equality with M5's DELETE, asked from both
/// sides over a grid that visits requests nobody chose: an overrun from every
/// start, the `p + width = n_C + 1` equality, the zero width at an
/// out-of-range start, every subspace but `s_C` on either side of it, an
/// empty document and an unregistered one. Eight hand-picked points on M8's own error contract
/// would all still pass if M5's admission moved; this would not.
///
/// The comparison runs as `SYS`, which is exactly the caller class the
/// equality holds for: `Caller::System` is exempt from M5's ω gate, so
/// ownership never enters, and admission is all that is left to compare. For
/// a caller the gate does NOT exempt the two sets differ, which the test
/// below pins. And it runs over documents the PUBLICATION gate admits —
/// doc1 and doc2 are private — because a published `d` is the second place
/// the two sets part: a gap §6 states, pinned by a test of its own rather
/// than added here, where it would fail the very equality this grid holds.
/// Its documents are within the run budget too, the third place: a `d` past
/// it is one DELETE edits and the preview refuses, pinned by its own test as
/// well. Verdicts only here: the two vocabularies label one refusal
/// differently by design, and the example test above is what pins WHICH
/// word.
#[test]
fn delete_orphans_refuses_exactly_what_the_delete_refuses() {
    for doc in [doc1(), doc2(), unregistered_doc()] {
        for subspace in 0..=3u32 {
            for ordinal in 0..=4u32 {
                for width in 0..=4u32 {
                    // An accepted delete mutates the arrangement, so each
                    // case gets its own world.
                    let k = kernel();
                    seed_content(&k, &doc1(), 3); // n_C(doc1) = 3; doc2 stays empty
                    let preview = delete_orphans_on(
                        &k.snapshot(),
                        &doc,
                        &vp(subspace, ordinal),
                        &n(width),
                        &every_home,
                    );
                    let done = Vstream::new(&k).delete(
                        SYS,
                        &doc,
                        vp(subspace, ordinal),
                        n(width),
                    );
                    assert_eq!(
                        preview.is_ok(),
                        done.is_ok(),
                        "preview and DELETE disagree on {doc:?} ({subspace},{ordinal}) width {width}"
                    );
                }
            }
        }
    }
}

/// §6 — the first of the two checks of M5's DELETE the preview does NOT
/// hold, and the one it omits by decision: the ω gate. `delete_orphans_on`
/// takes no `Caller`, so it answers a request DELETE would refuse the asker —
/// a non-owner previewing a delete they cannot perform. The grid above
/// cannot see this, because `SYS` is exempt from the gate by construction,
/// so this is the case that fixes what the ω half of "the accepted set is
/// M5's minus two gates" means: same document, same request, one answer and
/// one refusal. The other half, the publication refusal, is the test after
/// this one.
#[test]
fn the_preview_answers_a_request_the_delete_refuses_for_ownership() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);

    // `seeded_m3` registers PrincipalId(1) as doc1's account, so id 2 is not
    // its effective owner — the ω gate's own verdict, not a registration one.
    let stranger = Caller::Principal(PrincipalId(2));

    // The preview accepts, naming the links the delete would drop …
    assert!(delete_orphans_on(&k.snapshot(), &doc1(), &vp(1, 1), &n(1), &every_home).is_ok());
    // … and the DELETE it previews refuses this caller outright.
    assert!(matches!(
        Vstream::new(&k).delete(stranger, &doc1(), vp(1, 1), n(1)),
        Err(TxnError::Rejected(DeleteError::NotOwner(_)))
    ));

    // On this private document the gate is the only divergence: the same
    // caller is refused the same way for a request the preview ALSO refuses,
    // so ownership is orthogonal to admission rather than folded into it.
    assert_eq!(
        delete_orphans_on(&k.snapshot(), &doc1(), &vp(1, 9), &n(1), &every_home),
        Err(OrphanError::OutOfBounds)
    );
    assert!(matches!(
        Vstream::new(&k).delete(stranger, &doc1(), vp(1, 9), n(1)),
        Err(TxnError::Rejected(DeleteError::NotOwner(_)))
    ));
}

/// §6 — the second check of M5's DELETE the preview does not hold, and the
/// one §6 states as a GAP rather than a decision: the publication refusal
/// (PUB-2.11). DELETE refuses every published target — `SYS` included, so
/// no ownership question enters — while the preview answers; and it answers
/// about pdoc's OWN arrangement, frozen at its pre-chain state, where every
/// reader of pdoc sees the trunk head. This pins the divergence the contract
/// states, so closing the gap is a change this test has to be told about.
#[test]
fn the_preview_answers_a_published_target_the_delete_refuses() {
    let k = published_world();
    let store = LinkWriter::new(&k, &EVERYONE);
    let witness = link(&store, &doc1(), &[pca(1)], &[ca(101)]);

    // The preview answers — the witness's one position goes …
    assert_eq!(
        delete_orphans_on(&k.snapshot(), &pdoc(), &vp(1, 1), &n(1), &every_home),
        Ok(OrphanReport {
            orphaned: vec![witness]
        })
    );
    // … and the DELETE it previews is refused outright.
    assert!(matches!(
        Vstream::new(&k).delete(SYS, &pdoc(), vp(1, 1), n(1)),
        Err(TxnError::Rejected(DeleteError::PublishedTarget))
    ));

    // What it judged is pdoc's own two positions, not the four its readers
    // see: position 3 is arranged in the head, which `image` resolves, and
    // out of bounds for the preview.
    assert_eq!(
        LinkQuery::new(&k).image(&pdoc(), &[vspan(1, 3, 1)]),
        Ok(vec![run(&pca(3), 1)])
    );
    assert_eq!(
        delete_orphans_on(&k.snapshot(), &pdoc(), &vp(1, 3), &n(1), &every_home),
        Err(OrphanError::OutOfBounds)
    );
}

/// §6 — the one refusal the preview holds and DELETE does not: the run
/// budget, on the preview's own work. Its two stabs take the deleted range's
/// runs and the retained as their query — `d`'s own arrangement split at most
/// twice — and each walks the whole link store testing those spans against
/// every slot span of every link, where DELETE stabs nothing. At the budget
/// the preview answers; one run past it, it refuses every range, the whole
/// document included, while the DELETE it previews still admits the request.
/// The request's own faults are named first, on a document the budget
/// refuses.
#[test]
fn delete_orphans_refuses_a_document_past_the_run_budget() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let vs = Vstream::new(&k);
    let many = vec![spec(&doc1(), 1, 1, 1); MAX_IMAGE_RUNS];
    vs.copy(SYS, &doc2(), vp(1, 1), &many).expect("copy succeeds");
    let lq = LinkQuery::new(&k);

    // At the budget: one run deleted and every other retained, `MAX` in all.
    assert!(lq.delete_orphans(&doc2(), &vp(1, 1), &n(1)).is_ok());

    vs.copy(SYS, &doc2(), vp(1, 1), &[spec(&doc1(), 1, 1, 1)])
        .expect("copy succeeds");
    assert_eq!(
        k.snapshot().world().m5().content_runs(&doc2()).len(),
        MAX_IMAGE_RUNS + 1
    );
    let whole = n(MAX_IMAGE_RUNS as u32 + 1);
    for (p, width) in [(vp(1, 1), n(1)), (vp(1, 2), n(1)), (vp(1, 1), whole)] {
        assert_eq!(
            lq.delete_orphans(&doc2(), &p, &width),
            Err(OrphanError::ImageTooLarge),
            "the preview of DELETE at {p:?}, width {width}, is refused"
        );
    }
    // Every fault in the request is named ahead of the budget.
    assert_eq!(
        lq.delete_orphans(&doc2(), &vp(2, 1), &n(1)),
        Err(OrphanError::NotContentSubspace)
    );
    assert_eq!(
        lq.delete_orphans(&doc2(), &vp(1, 1), &n(0)),
        Err(OrphanError::EmptyWidth)
    );
    assert_eq!(
        lq.delete_orphans(&doc2(), &vp(1, 0), &n(1)),
        Err(OrphanError::OutOfBounds)
    );
    // And the DELETE it previews, which stabs nothing, admits the request.
    assert!(vs.delete(SYS, &doc2(), vp(1, 1), n(1)).is_ok());
}

// ─────────────── §7 — archival supersession lineage ───────────────

#[test]
fn lineage_probes_flipped_slots_with_residence_gate() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let e2 = link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    let (claim, _) = store.assert_sup(SYS, &doc1(), &e1, &e2).expect("assert_sup succeeds");

    let expected = SupClaim {
        claim: claim.clone(),
        old: e1.clone(),
        new: e2.clone(),
        home: doc1(),
        active: true,
    };
    // Flipped storage: in(y) = old probes FROM; out(x) = new probes TO.
    assert_eq!(lq.in_claims(&e1, View::Active), vec![expected.clone()]);
    assert_eq!(lq.out_claims(&e2, View::Active), vec![expected.clone()]);
    assert_eq!(lq.in_claims(&e2, View::Active), vec![]);
    assert_eq!(lq.out_claims(&e1, View::Active), vec![]);
    // Default behaves as Active (M7's §G primitives coerce it) — asserted
    // here while the claim is live, where Audit answers the same; the
    // assertion that separates them follows the retraction.
    assert_eq!(lq.in_claims(&e1, View::Default), vec![expected]);

    // Resident-key gate: a non-link key returns [] — without it, doc1's
    // prefix coverage would over-match the claim (whose endpoints live under
    // doc1).
    assert_eq!(lq.in_claims(&doc1(), View::Active), vec![]);
    assert_eq!(lq.in_claims(&ca(1), View::Active), vec![]);

    // Nullifying the claim removes it from the operative graph but keeps it
    // in the audit history, with its own activity disclosed honestly.
    store.nullify(SYS, &doc2(), &claim).expect("nullify succeeds");
    assert_eq!(lq.in_claims(&e1, View::Active), vec![]);
    let audit = lq.in_claims(&e1, View::Audit);
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].claim, claim);
    assert!(!audit[0].active);
    // After the retraction Active and Audit part — the one state where
    // "Default reads as Active" can be told from "Default reads as Audit".
    assert_eq!(lq.in_claims(&e1, View::Default), vec![]);
    assert_eq!(lq.out_claims(&e2, View::Default), vec![]);
}

/// §7 — `home` is the CLAIM's own attribution (EL8b), never an endpoint's.
/// `assert_sup` requires ω on the home and on nothing else, so a claim can be
/// asserted in a document its endpoints do not live in — the one shape where
/// a home read off the claim and a home read off `old` (which sits three
/// lines away in the same read-out) disagree. Every other lineage fixture
/// asserts in the document the endpoints were minted in, where the right
/// answer and the wrong one coincide.
#[test]
fn lineage_attributes_a_claim_to_its_own_home_not_its_endpoints() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let e2 = link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    let (claim, _) = store
        .assert_sup(SYS, &doc2(), &e1, &e2)
        .expect("assert_sup succeeds");
    assert_eq!(claim, la2(1), "the claim is minted in doc2's link chain");

    assert_eq!(
        lq.in_claims(&e1, View::Active),
        vec![SupClaim {
            claim,
            old: e1,
            new: e2,
            home: doc2(), // NOT doc1, where both endpoints are homed
            active: true,
        }]
    );
}

/// §7 — the view filters CLAIMS, never their endpoints: under any view a
/// claim's `old`/`new` are the addresses it NAMES, read out as recorded, so a
/// live claim can name a nullified link and `active` stays the claim's own.
/// And the enumeration's gate asks RESIDENT, not active — a nullified link
/// is still resident, so it is still a legal probe key. Every other lineage
/// case nullifies the claim; neither promise is watched by that.
#[test]
fn a_live_claim_names_a_nullified_endpoint_and_a_nullified_key_still_probes() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let e2 = link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    let (claim, _) = store
        .assert_sup(SYS, &doc1(), &e1, &e2)
        .expect("assert_sup succeeds");
    store.nullify(SYS, &doc2(), &e2).expect("nullify succeeds");

    // The premise: the ENDPOINT is retracted, and the claim naming it is not.
    let snap = k.snapshot();
    assert!(!snap.world().links().is_active(&e2));
    assert!(snap.world().links().is_active(&claim));

    assert_eq!(
        lq.in_claims(&e1, View::Active),
        vec![SupClaim {
            claim: claim.clone(),
            old: e1,
            new: e2.clone(),
            home: doc1(),
            active: true,
        }]
    );
    // A nullified link is resident, so it is still a legal probe key: the
    // gate asks resident, not active.
    assert_eq!(
        lq.out_claims(&e2, View::Active)
            .into_iter()
            .map(|c| c.claim)
            .collect::<Vec<_>>(),
        vec![claim]
    );
}

/// §7 — the lineage read-out is in ascending CLAIM-address order, the same
/// permanent key every enumeration here reads out by, off both probes: two
/// claims naming one `old`, and two naming one `new`, come back ordered, not
/// in whatever order the index handed them over.
#[test]
fn lineage_reads_out_in_claim_address_order() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    let mut made = Vec::new();
    for to in [ca(101), ca(102), ca(103)] {
        let e = link(&store, &doc1(), &[ca(1)], &[to]);
        made.push(e);
    }
    // Two successors of one superseded link: two claims, both probed by in().
    let (c1, _) = store
        .assert_sup(SYS, &doc1(), &made[0], &made[1])
        .expect("assert_sup succeeds");
    let (c2, _) = store
        .assert_sup(SYS, &doc1(), &made[0], &made[2])
        .expect("assert_sup succeeds");
    // And a second claim naming made[2] as new, so the TO probe has an order
    // of its own to read out.
    let (c3, _) = store
        .assert_sup(SYS, &doc1(), &made[1], &made[2])
        .expect("assert_sup succeeds");
    assert!(c1 < c2 && c2 < c3, "later claims mint later addresses");

    let claims: Vec<Address> = lq
        .in_claims(&made[0], View::Active)
        .into_iter()
        .map(|c| c.claim)
        .collect();
    assert_eq!(claims, vec![c1.clone(), c2.clone()]);
    // out() reads the same order off the TO probe: made[2] is `new` to two
    // claims, made[1] to one.
    let claims_of =
        |found: Vec<SupClaim>| -> Vec<Address> { found.into_iter().map(|c| c.claim).collect() };
    assert_eq!(
        claims_of(lq.out_claims(&made[2], View::Active)),
        vec![c2, c3]
    );
    assert_eq!(claims_of(lq.out_claims(&made[1], View::Active)), vec![c1]);
}

/// §7 — the enumeration reads out SUPERSESSION claims alone. M7's probe finds
/// every link naming the key at the slot, whatever its type, and the
/// `[K_sup]` class is what narrows it — so an ordinary link naming `e1` at
/// FROM and `e2` at TO, which both probes reach, must never come back as a
/// claim. It is the one shape that tells a read restricting to the class from
/// one reading out every hit: every other lineage fixture's endpoints are
/// named by supersession claims alone, where the two agree.
#[test]
fn lineage_reads_out_supersession_claims_alone_among_the_links_naming_the_key() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let e2 = link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    // Of the suite's relation type, and shaped exactly like a claim over e1→e2.
    let ordinary = link(
        &store,
        &doc1(),
        std::slice::from_ref(&e1),
        std::slice::from_ref(&e2),
    );
    let (claim, _) = store
        .assert_sup(SYS, &doc1(), &e1, &e2)
        .expect("assert_sup succeeds");

    // The premise: both probes reach the ordinary link as well as the claim,
    // so the restriction has something to drop.
    let snap = k.snapshot();
    let links = snap.world().links();
    for (slot, key) in [(FROM, &e1), (TO, &e2)] {
        let probed = links.match_links(&[(slot, &enc([key]))], View::Active);
        assert!(
            probed.contains(&ordinary) && probed.contains(&claim),
            "the probe at slot {slot} reaches both"
        );
    }

    let only_the_claim = vec![SupClaim {
        claim,
        old: e1.clone(),
        new: e2.clone(),
        home: doc1(),
        active: true,
    }];
    assert_eq!(lq.in_claims(&e1, View::Active), only_the_claim);
    assert_eq!(lq.out_claims(&e2, View::Active), only_the_claim);
}

/// §7 — the lineage read-out reports a claim's endpoints with NO per-claim
/// conformance filter, and cannot fault because every stored `[K_sup]` tuple
/// carries unit-depth single-address F and G. That is a fence on the WRITE
/// surface, held at sites M8 cannot see and cannot ask about, so what M8 can
/// do is pin its own reliance: the two routes by which a caller-shaped tuple
/// could reach the `[K_sup]` class are closed, in the build where a change to
/// either would surface as this test rather than as a panic in `claim_at`.
///
/// The open route is `editlink`, whose successor is the caller's: its DC
/// guard is the very predicate the read-out applies, so a successor with a
/// two-address F is refused rather than deposited. `makelink` refuses the
/// class outright.
#[test]
fn lineage_endpoints_rest_on_a_fence_the_write_surface_keeps() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let e2 = link(&store, &doc1(), &[ca(1)], &[ca(102)]);

    // The reserved Supersedes type, read off the store rather than spelled:
    // the ghost tumbler is the compiled format constant, and the two are
    // asserted equal so the fixture below names the class M7 recognizes.
    let sup = k
        .snapshot()
        .world()
        .links()
        .reserved_type(ShippedType::Supersedes)
        .clone();
    assert_eq!(sup, enc(&[ra(4)]), "Supersedes is ghost position 4");

    // The open surface refuses the class outright, so no MAKELINK can deposit
    // a [K_sup] tuple of any shape.
    assert!(matches!(
        store.makelink(
            SYS,
            &doc1(),
            SlotArg::Addrs(vec![e1.clone()]),
            SlotArg::Addrs(vec![e2.clone()]),
            SlotArg::Addrs(vec![ra(4)]),
        ),
        Err(TxnError::Rejected(MakeLinkError::SupersessionClass))
    ));

    // The caller-supplied route is gated by the schema the read-out reads
    // back: a [K_sup]-typed successor whose F denotes TWO addresses — the
    // shape `single_denoted` answers `None` for — is refused.
    let two = enc(&[e1.clone(), e2.clone()]);
    assert!(two.single_denoted().is_none(), "F denotes two addresses");
    assert!(matches!(
        store.editlink(
            SYS,
            &e1,
            Link::triple(two, enc(&[e2]), sup),
            &doc1(),
            &doc1(),
        ),
        Err(TxnError::Rejected(EditLinkError::DcViolation))
    ));

    // And the schema-conforming edit IS admitted, so the fence above is a
    // fence and not a closed door: the claim it deposits reads back through
    // the lineage surface with both endpoints named.
    let (edit, _) = store
        .editlink(
            SYS,
            &e1,
            Link::triple(enc(&[ca(1)]), enc(&[ca(103)]), rel_ty()),
            &doc1(),
            &doc1(),
        )
        .expect("a schema-conforming successor is admitted");
    let lq = LinkQuery::new(&k);
    assert_eq!(
        lq.in_claims(&e1, View::Active),
        vec![SupClaim {
            claim: edit.claim,
            old: e1,
            new: edit.successor,
            home: doc1(),
            active: true,
        }]
    );
}

// ───────────── the home rule — the reader argument (PUB-6.13) ─────────────

/// Every result-set read drops EXACTLY the links homed where the reader may
/// not read, and counts and pages what survives (PUB-6.13, PUB-6.14,
/// PUB-6.19) — asked of each read against the same read under a reader
/// admitting every home, never against a hand-written answer. The fixture
/// homes links in both documents, every one touching doc1's content, so each
/// read-out has something to drop and something to keep. The mistake the law
/// exists for is a site that asks the home rule's question of the LINK
/// instead of its home: a link address is no draft, so it reads as published
/// and the rule admits every link — and that one read then keeps doc2's
/// links.
///
/// Two readers, because the windows page in address order and doc1's links
/// all sort ahead of doc2's. The first may read everything but doc2, so
/// every link it refuses sorts AFTER every link it keeps. The second may read
/// everything but doc1, so its refused links sort FIRST. A window that
/// stopped at the first page the rule emptied would still hand the first
/// reader every survivor, and loses all of them for the second. Every page is
/// held to the window's postconditions, so a refused link counted against `n`
/// (PUB-6.14) shows as a short page claiming more to come.
#[test]
fn every_result_set_read_drops_exactly_the_links_homed_where_the_reader_may_not_read() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k, &EVERYONE);
    // doc1's: position 1; positions 2 and 3; position 3 alone.
    let m0 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let m1 = link(&store, &doc1(), &[ca(2)], &[ca(3)]);
    let m2 = link(&store, &doc1(), &[ca(3)], &[ca(104)]);
    // doc2's: position 1 under an endset no doc1 link carries, and position 3
    // alone under the FROM value m2 carries too.
    let t0 = link(&store, &doc2(), &[ca(1), ca(102)], &[ca(105)]);
    let t1 = link(&store, &doc2(), &[ca(3)], &[ca(103)]);
    // One supersession claim homed in each document, both with old = m0.
    let (kept, _) = store.assert_sup(SYS, &doc1(), &m0, &m1).expect("assert_sup succeeds");
    let (dropped, _) = store.assert_sup(SYS, &doc2(), &m0, &t0).expect("assert_sup succeeds");

    let snap = k.snapshot();
    let reader = |d: &Address| *d != doc2();
    let survivors = |links: Vec<Address>| -> Vec<Address> {
        links
            .into_iter()
            .filter(|a| document_of(a) != Some(doc2()))
            .collect()
    };

    // The descriptor family over the unit descriptor: every link in the store.
    let q = FourSet::any();
    let all = findlinks_ftt_on(&snap, &q, &every_home);
    assert!(all.contains(&t0) && all.contains(&dropped), "doc2's links are in the store");
    let seen = findlinks_ftt_on(&snap, &q, &reader);
    assert_eq!(seen, survivors(all), "findlinks_ftt");
    assert_eq!(count_ftt_on(&snap, &q, &reader), seen.len(), "count_ftt");
    assert_eq!(
        drain_window(1, seen.len() + 1, |cur| window_ftt_on(&snap, &q, cur, 1, &reader)),
        seen,
        "window_ftt"
    );

    // The region family over doc1's whole content.
    let region = [vspan(1, 1, 3)];
    let all = findlinks_v_on(&snap, &doc1(), &region, &every_home).expect("findlinks_v");
    assert!(all.contains(&t0) && all.contains(&t1), "doc2's links touch the region");
    let seen = findlinks_v_on(&snap, &doc1(), &region, &reader).expect("findlinks_v");
    assert_eq!(seen, survivors(all), "findlinks_v");
    assert_eq!(count_v_on(&snap, &doc1(), &region, &reader), Ok(seen.len()), "count_v");
    assert_eq!(
        drain_window(1, seen.len() + 1, |cur| {
            window_v_on(&snap, &doc1(), &region, cur, 1, &reader).expect("window_v")
        }),
        seen,
        "window_v"
    );

    // The second reader refuses doc1, whose links sort FIRST, so both windows
    // open on pages the rule empties. (It reads doc1's region though it may
    // not read doc1: the named document's own readability is the caller's
    // consult, never M8's.)
    let cannot_read_doc1 = |d: &Address| *d != doc1();
    let seen = findlinks_ftt_on(&snap, &q, &cannot_read_doc1);
    assert_eq!(
        seen,
        vec![t0.clone(), t1.clone(), dropped.clone()],
        "doc2's links survive"
    );
    assert_eq!(
        drain_window(1, seen.len() + 1, |cur| {
            window_ftt_on(&snap, &q, cur, 1, &cannot_read_doc1)
        }),
        seen,
        "window_ftt, refused links first"
    );
    let seen = findlinks_v_on(&snap, &doc1(), &region, &cannot_read_doc1).expect("findlinks_v");
    assert_eq!(seen, vec![t0.clone(), t1.clone()]);
    assert_eq!(
        drain_window(1, seen.len() + 1, |cur| {
            window_v_on(&snap, &doc1(), &region, cur, 1, &cannot_read_doc1).expect("window_v")
        }),
        seen,
        "window_v, refused links first"
    );

    // RETRIEVEENDSETS withholds identity, so what it drops is PAIRS: t0's own
    // pair goes, and the one t1 shares with m2 stays, since m2 still carries
    // it.
    let every_pair =
        retrieve_endsets_on(&snap, &doc1(), &region, &every_home).expect("retrieve_endsets");
    assert_eq!(every_pair.len(), 5);
    assert!(every_pair.contains(&(FROM, enc(&[ca(1), ca(102)]))), "t0's own pair");
    assert_eq!(
        retrieve_endsets_on(&snap, &doc1(), &region, &reader),
        Ok(vec![
            (FROM, enc(&[ca(1)])),
            (FROM, enc(&[ca(2)])),
            (FROM, enc(&[ca(3)])),
            (TO, enc(&[ca(3)])),
        ])
    );

    // The delete-orphan preview of position 3: m2 and t1 lose their last
    // witness, and only m2 is reported — the home rule reads the orphan set
    // after it is computed, so it never changes which links are orphaned.
    let orphaned = delete_orphans_on(&snap, &doc1(), &vp(1, 3), &n(1), &every_home)
        .expect("preview")
        .orphaned;
    assert_eq!(orphaned, vec![m2, t1]);
    assert_eq!(
        delete_orphans_on(&snap, &doc1(), &vp(1, 3), &n(1), &reader).map(|r| r.orphaned),
        Ok(survivors(orphaned))
    );

    // The lineage pair: the doc2-homed claim goes, from both probes.
    let claims = |found: Vec<SupClaim>| -> Vec<Address> { found.into_iter().map(|c| c.claim).collect() };
    let all = claims(in_claims_on(&snap, &m0, View::Active, &every_home));
    assert_eq!(all, vec![kept.clone(), dropped.clone()]);
    assert_eq!(claims(in_claims_on(&snap, &m0, View::Active, &reader)), survivors(all));
    for new in [&m1, &t0] {
        let all = claims(out_claims_on(&snap, new, View::Active, &every_home));
        assert_eq!(all.len(), 1, "one claim names {new:?} as new");
        assert_eq!(
            claims(out_claims_on(&snap, new, View::Active, &reader)),
            survivors(all),
            "out_claims({new:?})"
        );
    }
}

/// §4 — PUB-6.15: filtered at link HOME, UNFILTERED at origin. The home rule
/// decides which links contribute a pair and never reaches into a surviving
/// link's endset. The result-set law cannot see this: every link its readers
/// keep names only addresses under one document, where an endset clipped to
/// the reader is unchanged. Here a doc1-homed link names doc2's content too.
#[test]
fn retrieve_endsets_filters_at_the_links_home_and_ships_its_endset_whole_at_origin() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    link(&store, &doc1(), &[ca(1), ca2(1)], &[ca(101)]); // homed in doc1, naming doc2 too
    link(&store, &doc2(), &[ca(1)], &[ca(102)]); // homed in doc2
    let snap = k.snapshot();
    let region = [vspan(1, 1, 1)];
    assert_eq!(
        retrieve_endsets_on(&snap, &doc1(), &region, &every_home),
        Ok(vec![(FROM, enc(&[ca(1)])), (FROM, enc(&[ca(1), ca2(1)]))])
    );
    let cannot_read_doc2 = |d: &Address| *d != doc2();
    assert_eq!(
        retrieve_endsets_on(&snap, &doc1(), &region, &cannot_read_doc2),
        Ok(vec![(FROM, enc(&[ca(1), ca2(1)]))]),
        "the doc2-homed link's pair goes; the doc1-homed link's endset ships whole"
    );
}

/// §7 — the home rule is asked of the CLAIM's own address, and a surviving
/// claim's endpoints read out as recorded, whatever the reader may read. The
/// result-set law's claims each share a home with their `new`, so a read that
/// asked `new`'s home would answer exactly as the right one there; here the
/// two part. The probe keys are homed where the reader may read, so nothing
/// here turns on the key's own home.
#[test]
fn the_lineage_pair_asks_the_home_rule_of_the_claim_and_reads_its_endpoints_as_recorded() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let e2 = link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    let theirs = link(&store, &doc2(), &[ca(1)], &[ca(103)]);
    // Homed in doc1, naming a doc2 link as new …
    let (kept, _) = store
        .assert_sup(SYS, &doc1(), &e1, &theirs)
        .expect("assert_sup succeeds");
    // … and homed in doc2, naming only doc1 links.
    let (refused, _) = store
        .assert_sup(SYS, &doc2(), &e1, &e2)
        .expect("assert_sup succeeds");
    let snap = k.snapshot();
    let claims =
        |found: Vec<SupClaim>| -> Vec<Address> { found.into_iter().map(|c| c.claim).collect() };
    assert_eq!(
        claims(in_claims_on(&snap, &e1, View::Active, &every_home)),
        vec![kept.clone(), refused.clone()]
    );
    assert_eq!(
        claims(out_claims_on(&snap, &e2, View::Active, &every_home)),
        vec![refused]
    );

    let cannot_read_doc2 = |d: &Address| *d != doc2();
    assert_eq!(
        in_claims_on(&snap, &e1, View::Active, &cannot_read_doc2),
        vec![SupClaim {
            claim: kept,
            old: e1,
            new: theirs,
            home: doc1(),
            active: true,
        }]
    );
    assert_eq!(
        out_claims_on(&snap, &e2, View::Active, &cannot_read_doc2),
        vec![]
    );
}

// ───────────────────────── snapshot twins ─────────────────────────

#[test]
fn snapshot_twins_read_one_pinned_state() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let lq = LinkQuery::new(&k);
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

// ─────────────────────── the promises to a consumer ───────────────────────

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

/// The handle is a kernel borrow and behaves as one: it prints without asking
/// `W: Debug`, and it copies — a copy binds the same kernel and snapshots
/// afresh, so it answers what the original answers. A consumer holding one in
/// a struct of its own derives over it, which is the wall a missing impl
/// would be.
#[test]
fn the_handle_debugs_and_copies_like_the_borrow_it_is() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let lq = LinkQuery::new(&k);
    assert_eq!(format!("{lq:?}"), "LinkQuery { .. }");

    #[derive(Debug, Clone, Copy)]
    struct Reader<'k> {
        links: LinkQuery<'k, World>,
    }
    let reader = Reader { links: lq }; // lq is Copy — not moved
    assert!(format!("{reader:?}").starts_with("Reader { links: LinkQuery { .. }"));
    assert_eq!(reader.links.count_ftt(&FourSet::any()), 1);
    assert_eq!(lq.count_ftt(&FourSet::any()), 1);
}

/// Both rejection enums are exhaustively matchable from OUTSIDE the crate —
/// this file is a crate of its own, so these matches are the check that they
/// stay so. A consumer's `match` without a catch-all is a completeness proof
/// (M10 must give every refusal a wire code); sealing either enum, or adding
/// a variant, has to fail a build rather than fall into a default arm.
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
