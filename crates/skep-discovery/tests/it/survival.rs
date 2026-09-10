//! §6 — the delete-orphan preview, measured against the DELETE it previews:
//! its orphan set, its admission, the two gates where preview and DELETE
//! part, and its run budget.

use crate::common;

use common::*;
use skep_address::Address;
use skep_arrangement::{Caller, DeleteError, HasM5, Vstream};
use skep_discovery::{
    delete_orphans_on, FourSet, LinkQuery, OrphanError, OrphanReport, MAX_IMAGE_RUNS,
};
use skep_kernel::{Kernel, TxnError};
use skep_links::LinkWriter;
use skep_namespace::PrincipalId;

#[test]
fn delete_orphans_mirrors_delete_preconditions() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let lq = LinkQuery::new(&k, &every_home);

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
    let lq = LinkQuery::new(&k, &every_home);
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
            let lq = LinkQuery::new(&k, &every_home);

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
    let lq = LinkQuery::new(&k, &every_home);
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
    let lq = LinkQuery::new(&k, &every_home);
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
/// Its requests are within the run budget too, the third place: a request
/// whose runs, as its range splits them, are past it is one DELETE admits and
/// the preview refuses, pinned by tests of its own as well. Verdicts only
/// here: the two vocabularies label one refusal
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
        LinkQuery::new(&k, &every_home).image(&pdoc(), &[vspan(1, 3, 1)]),
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
    let lq = LinkQuery::new(&k, &every_home);

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

/// §6 — the preview's budget counts `d`'s runs AS THE RANGE SPLITS THEM: each
/// end of the range that falls inside a run adds one. `d` here holds
/// `MAX − 1` runs, so a range cutting one run at both ends is refused, while
/// a range cutting it at one end, and a range taking a run whole, are
/// answered — the budget is a fact about the request, not about `d` alone.
#[test]
fn the_preview_budget_counts_the_runs_the_range_splits() {
    let k = kernel();
    seed_content(&k, &doc1(), 3); // one run: ca(1..3)
    // doc2: one width-3 run, then `MAX − 2` width-1 runs, none abutting the
    // next — `MAX − 1` in all.
    let mut specs = vec![spec(&doc1(), 1, 1, 3)];
    specs.extend(vec![spec(&doc1(), 1, 1, 1); MAX_IMAGE_RUNS - 2]);
    Vstream::new(&k)
        .copy(SYS, &doc2(), vp(1, 1), &specs)
        .expect("copy succeeds");
    assert_eq!(
        k.snapshot().world().m5().content_runs(&doc2()).len(),
        MAX_IMAGE_RUNS - 1
    );
    let lq = LinkQuery::new(&k, &every_home);

    // Position 2 is the width-3 run's middle: both ends cut it, so `MAX + 1`
    // runs to stab.
    assert_eq!(
        lq.delete_orphans(&doc2(), &vp(1, 2), &n(1)),
        Err(OrphanError::ImageTooLarge)
    );
    // Position 1 is its first: one end cuts it, `MAX` runs — the budget itself.
    assert!(lq.delete_orphans(&doc2(), &vp(1, 1), &n(1)).is_ok());
    // Position 4 is a whole width-1 run: no end cuts one, `MAX − 1` runs.
    assert!(lq.delete_orphans(&doc2(), &vp(1, 4), &n(1)).is_ok());
}
