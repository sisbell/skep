//! M8 contract tests over a real kernel (InMemory), stating what the design
//! and interface assert: the doc-then-region gate order, checked on every
//! entry point that inherits it, and the defined-empty result; image dedup
//! and the region-span-then-V order it returns in; disjunctive +
//! active-filtered region discovery; the stateless key-cut windowing (clamp,
//! exhaustion, cursor-survives-orphaning) and the one selection index its
//! three read-outs share; RETRIEVEENDSETS' identity-withholding whole-endset
//! pinned-order read-out; the FTT unit/zero/conjunction algebra, the home
//! address-projection filter and its prefix-coverage reach; the two families'
//! zeros and their two stabilities; projection, its content-subspace-only
//! narrowing, and addressable discoverability; the delete-orphan preview
//! measured against the DELETE it previews, over that operation's whole
//! accepted domain and against M5's own admission; the flipped lineage probes
//! with the residence gate, the claim's own home attribution, the endpoints it
//! reads out as recorded and the write-surface fences that read-out rests on;
//! the two budgets, each refused at its boundary and on every entry point that
//! inherits it; the snapshot twins; and — because this file is a crate of its
//! own — the promises M8 makes to a consumer rather than to itself: one named
//! world bound, the standard traits its values carry, and rejection enums that
//! stay exhaustively matchable.

mod common;

use std::collections::HashSet;

use common::*;
use skep_address::{Address, Span};
use skep_arrangement::{HasM5, Vstream};
use skep_discovery::{
    content_vspan, count_ftt_on, count_v_on, delete_orphans_on, window_v_on, DiscoveryWorld,
    FourSet, LinkQuery, OrphanError, OrphanReport, QueryError, SlotSpec, SupClaim, Window,
    FROM, MAX_ENDSET_SPANS, MAX_IMAGE_RUNS, TO, TYPE,
};
use skep_kernel::{Kernel, Snapshot, TxnError};
use skep_links::{
    enc, EditLinkError, Endset, HasLinks, Link, LinkWriter, MakeLinkError, ShippedType, SlotArg,
    View, MAX_SLOT_SPANS,
};

// ───────────────────── §1 — content-region discovery ─────────────────────

#[test]
fn region_family_gates_doc_then_region_then_defines_empty() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let lq = LinkQuery::new(&k);

    // Unregistered d → DocNotRegistered, even with a bad region: the document
    // gate is the first act, the region gate second.
    assert_eq!(
        lq.image(&d7(), &[vspan(2, 1, 1)]),
        Err(QueryError::DocNotRegistered)
    );
    assert_eq!(
        lq.retrieve_endsets(&d7(), &[vspan(1, 1, 1)]),
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

    // Each entry point reduced to its refusal, so the rule below is stated
    // once rather than transcribed five times.
    let entries: Vec<(&str, RegionRefusal<'_>)> = vec![
        ("image", Box::new(|d, r| lq.image(d, r).err())),
        ("findlinks_v", Box::new(|d, r| lq.findlinks_v(d, r).err())),
        ("count_v", Box::new(|d, r| lq.count_v(d, r).err())),
        ("window_v", Box::new(|d, r| lq.window_v(d, r, None, 3).err())),
        (
            "retrieve_endsets",
            Box::new(|d, r| lq.retrieve_endsets(d, r).err()),
        ),
    ];
    for (name, refusal) in &entries {
        assert_eq!(
            refusal(&d7(), &[vspan(1, 1, 1)]),
            Some(QueryError::DocNotRegistered),
            "{name}: an unregistered d is refused"
        );
        assert_eq!(
            refusal(&doc1(), &[vspan(2, 1, 1)]),
            Some(QueryError::BadRegion),
            "{name}: a non-content-subspace region is refused"
        );
        assert_eq!(
            refusal(&d7(), &[vspan(2, 1, 1)]),
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

/// §1 — the run budget, at its boundary and on every entry point that
/// inherits `image_on`. The shape it prices is the region×image PRODUCT, not
/// the region: each span here is well-formed, in-budget for the transport,
/// and resolves to the document's whole arrangement, so a request the wire
/// admits whole can still name work no wire cap bounds. Counted over runs
/// RESOLVED, so four runs under 1024 spans is the budget exactly and one more
/// span is past it.
#[test]
fn the_region_family_refuses_an_image_past_the_run_budget() {
    let k = kernel();
    for _ in 0..4 {
        seed_content(&k, &doc1(), 1); // four separate INSERTs ⇒ four runs
    }
    let lq = LinkQuery::new(&k);
    // Every span the same: the whole document, resolving to all four runs.
    let past: Vec<Span> = vec![vspan(1, 1, 4); MAX_IMAGE_RUNS / 4 + 1];
    let at_budget = &past[..MAX_IMAGE_RUNS / 4];
    assert_eq!(lq.image(&doc1(), &past[..1]).map(|r| r.len()), Ok(4));
    // At the budget the answer is still those four distinct runs — the dedup
    // is not what the budget counts.
    assert_eq!(lq.image(&doc1(), at_budget).map(|r| r.len()), Ok(4));

    let entries: Vec<(&str, RegionRefusal<'_>)> = vec![
        ("image", Box::new(|d, r| lq.image(d, r).err())),
        ("findlinks_v", Box::new(|d, r| lq.findlinks_v(d, r).err())),
        ("count_v", Box::new(|d, r| lq.count_v(d, r).err())),
        ("window_v", Box::new(|d, r| lq.window_v(d, r, None, 3).err())),
        (
            "retrieve_endsets",
            Box::new(|d, r| lq.retrieve_endsets(d, r).err()),
        ),
    ];
    for (name, refusal) in &entries {
        assert_eq!(
            refusal(&doc1(), at_budget),
            None,
            "{name}: the budget itself is admitted"
        );
        assert_eq!(
            refusal(&doc1(), &past),
            Some(QueryError::ImageTooLarge),
            "{name}: one span past the budget is refused, not truncated"
        );
    }
}

/// §5 — the same run budget over `ran(M(d))`, which is what makes the three
/// reads of a document's runs refuse the same documents: a `d` the region
/// family declines is not one the pointwise family answers about. Both
/// pointwise reads are checked, since each reaches the runs by its own route
/// — `project` through M5's join, `addressably_discoverable_from` through the
/// extents it lifts itself.
#[test]
fn the_pointwise_family_holds_the_same_run_budget_over_the_documents_runs() {
    let k = kernel();
    let store = LinkWriter::new(&k);
    seed_content(&k, &doc1(), 1);
    let (e1, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
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
    assert!(lq.project(&e1, FROM, &doc2()).is_ok());
    assert!(lq.addressably_discoverable_from(&e1, &doc2()).is_ok());

    // One run past it, and both routes to `d`'s runs refuse — the region
    // family's image, checked above, refuses the same document.
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
    // The gates above the budget still answer first: an unregistered `d` and
    // a non-link `a` are not swallowed by it.
    assert_eq!(
        lq.project(&e1, FROM, &d7()),
        Err(QueryError::DocNotRegistered)
    );
    assert_eq!(lq.project(&ca(1), FROM, &doc2()), Err(QueryError::NotALink));
}

#[test]
fn findlinks_v_is_disjunctive_and_active_filtered() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);

    // e1 reaches position 1 via FROM (emit encodes from = enc({ca1})).
    let (e1, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(9)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
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

#[test]
fn window_v_pages_by_key_cut_and_survives_orphaning() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    for to in [ca(101), ca(102), ca(103)] {
        store
            .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![to]), SlotArg::Addrs(vec![ra(10)]))
            .expect("emit succeeds");
    }
    let region = [vspan(1, 1, 1)];

    // Ascending address order; next = ≺-max of the batch; full batch ⇒ not
    // exhausted.
    let w1 = lq.window_v(&doc1(), &region, None, 2).expect("window");
    assert_eq!(w1.batch, vec![la(1), la(2)]);
    assert_eq!(w1.next, Some(la(2)));
    assert!(!w1.exhausted);
    // Resume strictly past the cursor; short batch ⇒ exhausted (W9).
    let w2 = lq.window_v(&doc1(), &region, w1.next, 2).expect("window");
    assert_eq!(w2.batch, vec![la(3)]);
    assert_eq!(w2.next, Some(la(3)));
    assert!(w2.exhausted);
    // Past the end: empty batch, cursor unchanged, still exhausted.
    let w3 = lq.window_v(&doc1(), &region, w2.next, 2).expect("window");
    assert_eq!(w3.batch, vec![]);
    assert_eq!(w3.next, Some(la(3)));
    assert!(w3.exhausted);

    // n = 0 is clamped to 1 (total API) — never a false non-terminal.
    let w0 = lq.window_v(&doc1(), &region, None, 0).expect("window");
    assert_eq!(w0.batch, vec![la(1)]);
    assert!(!w0.exhausted);

    // Cursor survives orphaning (W8): la(2) leaves the matched set under
    // nullification, but the key-cut resume needs no lookup of it.
    store.nullify(SYS, &doc2(), &la(2)).expect("nullify succeeds");
    let w4 = lq.window_v(&doc1(), &region, Some(la(2)), 5).expect("window");
    assert_eq!(w4.batch, vec![la(3)]);
    assert!(w4.exhausted);
}

/// §2 — one selection index, read out three ways: `count_v`, `findlinks_v`
/// and `window_v` at EVERY batch size answer off the same
/// `findlinks_V ∩ addressable`, so they cannot disagree about which links
/// touch a region (W4/W5 — no continuously-matching link duplicated or
/// skipped). The descriptor family states this over five descriptors; the
/// region family is entitled to the law rather than to one hand-picked
/// pagination, so this walks five regions × every batch size from the clamp
/// at 0 through one past the set.
#[test]
fn region_count_enumeration_and_window_read_out_one_selection_index() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    // Varied slot reach, so the regions below select different subsets …
    for (from, to) in [
        (ca(1), ca(101)),
        (ca(2), ca(3)),
        (ca(3), ca(101)),
        (ca(1), ca(2)),
    ] {
        store
            .makelink(SYS, &doc1(), SlotArg::Addrs(vec![from]), SlotArg::Addrs(vec![to]), SlotArg::Addrs(vec![ra(10)]))
            .expect("emit succeeds");
    }
    // … and one retracted link reaching position 2, which no read-out may
    // surface.
    let (dead, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(2)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
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
        // report exhaustion.
        for n in 0..=enumerated.len() + 1 {
            let mut drained: Vec<Address> = Vec::new();
            let mut cur = None;
            // Every clamped batch admits at least one link, so a drain of
            // `len` links owes at most `len + 1` calls; a budget turns the
            // silent non-terminating signal an unclamped `n = 0` produces
            // into a failure rather than a hang.
            let mut budget = enumerated.len() + 1;
            loop {
                let w = lq.window_v(&doc1(), &region, cur, n).expect("window");
                drained.extend(w.batch.iter().cloned());
                cur = w.next;
                if w.exhausted {
                    break;
                }
                budget -= 1;
                assert!(
                    budget > 0,
                    "window_v never reported exhaustion for {region:?} at n = {n}"
                );
            }
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
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    // Two distinct links with VALUE-IDENTICAL from-endsets (dedup collapse),
    // plus one makelink whose from spans all three positions.
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
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

/// §4 — the answer's span budget, at its boundary. The amplification it
/// prices is the one no request-shaped cap reaches: a two-hundred-byte query
/// naming ONE position, answered with every whole endset touching it, each of
/// which M7 admits at `MAX_SLOT_SPANS` on deposit. Sixty-four such endsets is
/// the budget exactly, and the sixty-fifth is refused rather than dropped —
/// RE-UNIT licenses withholding a link's IDENTITY, never its endset.
#[test]
fn retrieve_endsets_refuses_an_answer_past_the_span_budget() {
    /// Endsets are collapsed by VALUE, so each link needs its own filler set
    /// or the sixty-four would ship as one pair. `ca(1)` is the span that
    /// touches the region; the rest name unarranged positions of doc1.
    fn wide_from(link: u32, spans: u32) -> Vec<Address> {
        let mut addrs = vec![ca(1)];
        addrs.extend((1..spans).map(|j| ca(1000 + link * spans + j)));
        addrs
    }
    const SPANS: u32 = 1024;
    let at_budget = MAX_ENDSET_SPANS / SPANS as usize; // 64 whole endsets

    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    let region = [vspan(1, 1, 1)];
    let deposit = |i: u32| {
        store
            .makelink(
                SYS,
                &doc1(),
                SlotArg::Addrs(wide_from(i, SPANS)),
                SlotArg::Addrs(vec![ca(101)]),
                SlotArg::Addrs(vec![ra(10)]),
            )
            .expect("a slot at MAX_SLOT_SPANS is admitted");
    };
    assert!(SPANS as usize <= MAX_SLOT_SPANS, "each slot is in M7's budget");
    for i in 0..at_budget as u32 {
        deposit(i);
    }

    // At the budget: one pair per link, each endset WHOLE, none clipped.
    let pairs = lq.retrieve_endsets(&doc1(), &region).expect("at budget");
    assert_eq!(pairs.len(), at_budget);
    assert!(pairs.iter().all(|(i, e)| *i == FROM && e.len() == SPANS as usize));

    // One link more, and the answer is refused rather than shortened.
    deposit(at_budget as u32);
    assert_eq!(
        lq.retrieve_endsets(&doc1(), &region),
        Err(QueryError::EndsetsTooLarge)
    );
    // The region family's other read-outs carry no such budget: they enumerate
    // ADDRESSES, whose size is the link count and not the endsets'.
    assert_eq!(lq.count_v(&doc1(), &region), Ok(at_budget + 1));
}

// ─────────────────── §3 — four-set descriptor query ───────────────────

#[test]
fn ftt_wildcard_unit_empty_zero_and_conjunction() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    let (e1, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(2)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    store
        .makelink(SYS, &doc2(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");

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
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(2)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds"); // la(1): from ca(1), to ca(2)
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(2)]), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds"); // la(2): the mirror

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

#[test]
fn ftt_home_filter_is_an_address_projection_applied_lazily() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(2)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    store
        .makelink(SYS, &doc2(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");

    // home is matched against home(a) = document_of — an address projection,
    // not a slot and not an arrangement test.
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
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(2)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    store
        .makelink(SYS, &doc2(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");

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
/// here and nowhere else.
#[test]
fn ftt_count_enumeration_and_window_read_out_one_sat() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(2)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    store
        .makelink(SYS, &doc2(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");

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

        // The same set again, drained one link at a time through the cursor.
        let mut drained: Vec<_> = Vec::new();
        let mut cur = None;
        loop {
            let w = lq.window_ftt(&q, cur, 1);
            drained.extend(w.batch.iter().cloned());
            cur = w.next;
            if w.exhausted {
                break;
            }
        }
        assert_eq!(drained, enumerated, "the window drains sat for {q:?}");
    }

    // `n = 0` is clamped to 1 on this family too (W9 totality) — the drain
    // above never reaches the clamp, since it pages at 1.
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
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    store
        .makelink(SYS, &doc2(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");

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
        home: SlotSpec::Spans(enc(&[d7()])),
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
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
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
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    let (e1, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(2)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");

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
        lq.project(&e1, FROM, &d7()),
        Err(QueryError::DocNotRegistered)
    );

    // UNFILTERED — the one read here that is not narrowed to the active view.
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
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    let (m1, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    let (m2, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(2)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
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
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    let (e1, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
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
    // nullified link is still a link (it passes the residence gate rather
    // than erring NotALink).
    store.nullify(SYS, &doc2(), &e1).expect("nullify succeeds");
    assert_eq!(lq.addressably_discoverable_from(&e1, &doc1()), Ok(false));

    assert_eq!(
        lq.addressably_discoverable_from(&ca(1), &doc1()),
        Err(QueryError::NotALink)
    );
    assert_eq!(
        lq.addressably_discoverable_from(&e1, &d7()),
        Err(QueryError::DocNotRegistered)
    );
}

// ─────────────────── §6 — pre-edit link-survival ───────────────────

#[test]
fn delete_orphans_mirrors_delete_preconditions() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let lq = LinkQuery::new(&k);

    assert_eq!(
        lq.delete_orphans(&d7(), &vp(1, 1), &n(1)),
        Err(OrphanError::DocNotRegistered)
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
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    // link_a witnesses positions 1 (FROM) and 2 (TO); link_b only 3.
    let (_link_a, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(2)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    let (link_b, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(3)]), SlotArg::Addrs(vec![ca(3)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");

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
        let store = LinkWriter::new(&k);
        let make = |from: Address, to: Address| {
            store
                .makelink(SYS, &doc1(), SlotArg::Addrs(vec![from]), SlotArg::Addrs(vec![to]), SlotArg::Addrs(vec![ra(10)]))
                .expect("emit succeeds")
                .0
        };
        make(ca(1), ca(2)); // la(1): positions 1 and 2
        make(ca(4), ca(4)); // la(2): position 4 alone
        make(ca(1), ca(4)); // la(3): positions 1 and 4 — witnesses on both sides
        make(ca(2), la(1)); // la(4): position 2, and doc1's LINK subspace
        make(ca(101), ca(102)); // la(5): reaches nothing doc1 arranges
        let dead = make(ca(3), ca(3)); // la(6): position 3 …
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
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(3)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");

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
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    let (seated, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![seated]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");

    // Both links reach position 1, and the whole content goes. Only la(2)
    // keeps a witness — la(1), which makelink seated in doc1's link runs.
    assert_eq!(
        lq.delete_orphans(&doc1(), &vp(1, 1), &n(3)),
        Ok(OrphanReport {
            orphaned: vec![la(1)]
        })
    );
}

/// §6 — "the accepted set is M5's exactly" is a cross-module equality, and
/// the suite checked it from one side only: eight hand-picked points on M8's
/// own error contract, every one of which would still pass if M5's DELETE
/// admission moved. This asks BOTH, over a grid that visits requests nobody
/// chose — an overrun from every start, the `p + width = n_C + 1` equality,
/// the zero width at an out-of-range start, the link subspace, an empty
/// document and an unregistered one. Verdicts only: the two vocabularies
/// label one refusal differently by design, and the example test above is
/// what pins WHICH word.
#[test]
fn delete_orphans_refuses_exactly_what_the_delete_refuses() {
    for doc in [doc1(), doc2(), d7()] {
        for subspace in 1..=2u32 {
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

// ─────────────── §7 — archival supersession lineage ───────────────

#[test]
fn lineage_probes_flipped_slots_with_residence_gate() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    let (e1, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    let (e2, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
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
    // Default behaves as Active (M7's §G primitives coerce it).
    assert_eq!(lq.in_claims(&e1, View::Default), vec![expected]);

    // Residence gate: a non-link key returns [] — without it, doc1's prefix
    // coverage would over-match the claim (whose endpoints live under doc1).
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
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    let (e1, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    let (e2, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
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
/// And the enumeration's gate is RESIDENCE, not activity — a nullified link
/// is still resident, so it is still a legal probe key. Every other lineage
/// case nullifies the claim; neither promise is watched by that.
#[test]
fn a_live_claim_names_a_nullified_endpoint_and_a_nullified_key_still_probes() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    let (e1, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    let (e2, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
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
    // gate is residence, not activity.
    assert_eq!(
        lq.out_claims(&e2, View::Active)
            .into_iter()
            .map(|c| c.claim)
            .collect::<Vec<_>>(),
        vec![claim]
    );
}

/// §7 — the lineage read-out is in ascending CLAIM-address order, the same
/// permanent key every enumeration here reads out by: two claims naming one
/// `old` come back ordered, not in whatever order the index handed them over.
#[test]
fn lineage_reads_out_in_claim_address_order() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    let mut made = Vec::new();
    for to in [ca(101), ca(102), ca(103)] {
        let (e, _) = store
            .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![to]), SlotArg::Addrs(vec![ra(10)]))
            .expect("emit succeeds");
        made.push(e);
    }
    // Two successors of one superseded link: two claims, both probed by in().
    let (c1, _) = store
        .assert_sup(SYS, &doc1(), &made[0], &made[1])
        .expect("assert_sup succeeds");
    let (c2, _) = store
        .assert_sup(SYS, &doc1(), &made[0], &made[2])
        .expect("assert_sup succeeds");
    assert!(c1 < c2, "later claims mint later addresses");

    let claims: Vec<Address> = lq
        .in_claims(&made[0], View::Active)
        .into_iter()
        .map(|c| c.claim)
        .collect();
    assert_eq!(claims, vec![c1.clone(), c2.clone()]);
    // out() reads the same order off the TO probe — one claim each here, so
    // the pair is read back through the union of the two probes.
    assert_eq!(
        lq.out_claims(&made[1], View::Active)[0].claim,
        c1
    );
    assert_eq!(
        lq.out_claims(&made[2], View::Active)[0].claim,
        c2
    );
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
    let store = LinkWriter::new(&k);
    let (e1, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    let (e2, _) = store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");

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
    let (succ, claim, _) = store
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
            claim,
            old: e1,
            new: succ,
            home: doc1(),
            active: true,
        }]
    );
}

// ───────────────────────── snapshot twins ─────────────────────────

#[test]
fn snapshot_twins_read_one_pinned_state() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k);
    let lq = LinkQuery::new(&k);
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    let region = [vspan(1, 1, 1)];

    // Pin one snapshot, then write past it: the twins keep answering off the
    // pinned root (a count and its window off ONE consistent state), while
    // the handle's fresh snapshot sees the new link.
    let snap = k.snapshot();
    assert_eq!(count_v_on(&snap, &doc1(), &region), Ok(1));
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    assert_eq!(count_v_on(&snap, &doc1(), &region), Ok(1));
    let w = window_v_on(&snap, &doc1(), &region, None, 10).expect("window");
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
    let reaching = count_v_on(s, d, region)?;
    let resident = count_ftt_on(
        s,
        &FourSet {
            home: SlotSpec::Spans(enc([d])),
            ..Default::default()
        },
    );
    Ok((reaching, resident))
}

/// One bound names the world M8 reads under, and `Default` is the wildcard
/// base a narrowed descriptor is built from — so a consumer writes the query
/// it means and leaves no slot at something other than the unit by accident.
#[test]
fn one_named_bound_and_the_unit_descriptor_serve_a_composing_caller() {
    let k = kernel();
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k);
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
    store
        .makelink(SYS, &doc2(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(102)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");

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
    let store = LinkWriter::new(&k);
    store
        .makelink(SYS, &doc1(), SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(101)]), SlotArg::Addrs(vec![ra(10)]))
        .expect("emit succeeds");
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
        }
    }
    assert_eq!(query_word(QueryError::BadRegion), "region");
    assert_eq!(orphan_word(OrphanError::EmptyWidth), "width");

    // `Display` names the surface that refused, so a relayed refusal says
    // which of the two vocabularies it came from.
    assert!(QueryError::NotALink.to_string().starts_with("query: "));
    assert!(OrphanError::DocNotRegistered
        .to_string()
        .starts_with("delete-orphans: "));
}
