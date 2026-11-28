use num_traits::Zero;
use skep_address::{Span, Tumbler};

use super::*;
use crate::run_list::Splice;
use crate::testutil::{a, ca, doc1, doc2, la, n, nth_doc, pca, pdoc, run, vca, vdoc};
use crate::vspace::VPos;

fn place(s: &M5State, doc: &Address, at: u32, runs: Vec<Run>) -> M5State {
    s.apply_m5(Seq(1), &M5Rec::ContentPlace {
        doc: doc.clone(),
        at: n(at),
        runs,
    })
}

/// The six maps the slice writes after R, in the order it writes them,
/// the first `kept` of them.
fn maps_after_r(s: &M5State, kept: usize) -> Vec<u8> {
    let maps = [
        bincode::serialize(&s.birth_extents),
        bincode::serialize(&s.shot_terms),
        bincode::serialize(&s.fork_sources),
        bincode::serialize(&s.arranged_at),
        bincode::serialize(&s.draft_bases),
        bincode::serialize(&s.source_copied),
    ];
    maps.into_iter().take(kept).flat_map(|map| map.expect("a map serializes")).collect()
}

/// The slice's checkpoint form cut short after the first `kept` of the six
/// maps it writes after R: the body a build wrote before the others joined
/// the slice.
fn cut_after(s: &M5State, kept: usize) -> Vec<u8> {
    let bytes = bincode::serialize(s).expect("state serializes");
    let lists = bytes.len() - maps_after_r(s, 6).len();
    [&bytes[..lists], &maps_after_r(s, kept)].concat()
}

/// Holds the slice's fields to their order in both its forms.
///
/// The checkpoint form `bytes` ends with the six maps after R as they
/// stand, in declaration order — what stands before them, the node table,
/// the arrangements and R, is the byte pin's — and the run-sequence form is
/// the eight fields in declaration order, each as it writes itself.
#[track_caller]
fn assert_field_order(s: &M5State, bytes: &[u8], said: &str) {
    assert!(bytes.ends_with(&maps_after_r(s, 6)), "{said}");
    let fields = bincode::serialize(&(
        &s.arrangements,
        &s.provenance,
        &s.birth_extents,
        &s.shot_terms,
        &s.fork_sources,
        &s.arranged_at,
        &s.draft_bases,
        &s.source_copied,
    ))
    .expect("the fields serialize");
    assert_eq!(bincode::serialize(&s.as_run_sequences()).expect("the run-sequence form serializes"), fields, "{said}");
}

#[test]
fn content_place_splices_and_appends_provenance_in_one_fold() {
    // §3: J1★ by construction — the same fold updates M and R, so one
    // state carries both; the R entry is the placed run's iextent.
    let s0 = M5State::genesis();
    let s1 = place(&s0, &doc1(), 1, vec![run(&ca(1), 3)]);
    assert_eq!(s1.content_count(&doc1()), n(3));
    assert_eq!(s1.content_runs(&doc1()).cloned().collect::<Vec<_>>(), vec![run(&ca(1), 3)]);
    // ever_contained ∖ image is empty right after a place…
    assert!(s1.deletions(&doc1()).is_empty());
    // …and the R side is visible through docs_ever_containing.
    let cov = skep_address::SpanSet::singleton(run(&ca(1), 3).iextent());
    assert_eq!(s1.docs_ever_containing(&cov), vec![doc1()]);
    // Purity: the receiver was untouched.
    assert_eq!(s0.content_count(&doc1()), n(0));
}

#[test]
fn content_remove_contracts_the_arrangement_and_leaves_r_standing() {
    // §4: DELETE drops arrangement entries only; R keeps the pair (P2),
    // which is exactly what SHOWDELETIONS reads.
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 5)]);
    let s = s.apply_m5(Seq(1), &M5Rec::ContentRemove {
        doc: doc1(),
        from: n(2),
        width: n(2),
    });
    assert_eq!(s.content_count(&doc1()), n(3));
    assert_eq!(
        s.content_runs(&doc1()).cloned().collect::<Vec<_>>(),
        vec![run(&ca(1), 1), run(&ca(4), 2)]
    );
    // The deleted iextent [ca(2), ca(4)) is ever-contained minus image.
    let d = s.deletions(&doc1());
    let spans: Vec<_> = d.iter().cloned().collect();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].start(), ca(2).tumbler());
    assert_eq!(spans[0].reach(), *ca(4).tumbler());
    // R permanence: the placing doc is still a candidate for the deleted
    // region.
    let cov = skep_address::SpanSet::singleton(spans[0].clone());
    assert_eq!(s.docs_ever_containing(&cov), vec![doc1()]);
}

#[test]
fn link_seat_appends_at_the_next_link_position_and_never_touches_r() {
    // §8: append at n_L(d) + 1; sequential A_L(d) allocations coalesce to
    // one maximally-merged run (a valid S8★ witness); J-LV — no R.
    let s = M5State::genesis();
    let s = s.apply_m5(Seq(1), &M5Rec::LinkSeat { doc: doc1(), link: la(1) });
    let s = s.apply_m5(Seq(1), &M5Rec::LinkSeat { doc: doc1(), link: la(2) });
    assert_eq!(s.link_count(&doc1()), n(2));
    assert_eq!(s.link_runs(&doc1()).cloned().collect::<Vec<_>>(), vec![run(&la(1), 2)]);
    assert_eq!(s.content_count(&doc1()), n(0));
    // J-LV: no provenance from link seating.
    let cov = skep_address::SpanSet::singleton(run(&la(1), 2).iextent());
    assert!(s.docs_ever_containing(&cov).is_empty());
}

#[test]
fn the_link_seat_fold_mints_through_the_run_door_and_drops_what_it_refuses() {
    // §8/§10: the seated address becomes a Run START, and on the REPLAY
    // path a record's `Address` has re-entered only M1's `validate` —
    // T4-validity does not imply a full element position, which is the
    // clause the run's ordinal arithmetic stands on. So the fold mints
    // through `Run::new`, and an address the door refuses is dropped.
    //
    // Dropping rather than placing is the point: a document address and a
    // subspace base are both T4-valid, and seating either would give a
    // width-1 run whose I-extent covers a whole document or a whole link
    // subspace — after which CL-UNIQ, which IS I-extent membership,
    // reports every later link of that document as already seated, with no
    // unseat anywhere in the module. Panicking is not the alternative:
    // this fold runs inside `Kernel::open`.
    let s = M5State::genesis();
    for link in [doc1(), a(&[1, 0, 1, 0, 1, 0, 2])] {
        let out = s.apply_m5(Seq(1), &M5Rec::LinkSeat {
            doc: doc1(),
            link: link.clone(),
        });
        assert_eq!(out.link_count(&doc1()), n(0), "{link:?} is no run start");
        assert_eq!(out.link_runs(&doc1()).len(), 0, "{link:?}");
        // And the subspace is still seatable afterwards, which is what
        // dropping buys and placing would have cost permanently.
        let after = out.apply_m5(Seq(1), &M5Rec::LinkSeat {
            doc: doc1(),
            link: la(1),
        });
        assert_eq!(
            after.link_runs(&doc1()).cloned().collect::<Vec<_>>(),
            vec![run(&la(1), 1)],
            "{link:?}"
        );
        assert!(after.seats_link(&doc1(), &la(1)), "{link:?}");
    }
    // A well-formed seat still lands, so the assertions above are not
    // earned by a fold that has stopped seating anything.
    let ok = s.apply_m5(Seq(1), &M5Rec::LinkSeat {
        doc: doc1(),
        link: la(1),
    });
    assert_eq!(ok.link_runs(&doc1()).cloned().collect::<Vec<_>>(), vec![run(&la(1), 1)]);
}

#[test]
fn version_snapshot_shares_the_map_preserving_multiplicity() {
    // ASN-0123 V2: the V→I map is copied, not the I-range — a
    // within-document transclusion duplicate survives into the fork.
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 2)]);
    let s = place(&s, &doc1(), 3, vec![run(&ca(1), 2)]); // duplicate placement
    assert_eq!(s.content_count(&doc1()), n(4));
    let s = s.apply_m5(Seq(1), &M5Rec::VersionSnapshot {
        source: doc1(),
        new: vdoc(),
    });
    assert_eq!(s.content_count(&vdoc()), n(4));
    assert_eq!(
        s.content_runs(&vdoc()).collect::<Vec<_>>(),
        s.content_runs(&doc1()).collect::<Vec<_>>()
    );
    // Fork provenance recorded (a candidate for the shared region).
    let cov = skep_address::SpanSet::singleton(run(&ca(1), 2).iextent());
    assert_eq!(s.docs_ever_containing(&cov), vec![doc1(), vdoc()]);
    // Source untouched (V3).
    assert_eq!(
        s.content_runs(&doc1()).cloned().collect::<Vec<_>>(),
        vec![run(&ca(1), 2), run(&ca(1), 2)]
    );
}

#[test]
fn a_fork_names_its_sources_list_in_r_and_appends_no_span() {
    // §7: a snapshot's two halves are both O(1) at the fold. The
    // arrangement is a structural share, and R↾new is that same list NAMED
    // — one more handle on the vector — with no span appended, whatever the
    // source holds: the record is two addresses, and it commands two
    // handles. What R↾new answers is unchanged — one span a run of the
    // list as it stood — and what the document places afterwards is
    // appended beside it. `ContentPlace` carries its runs and appends a
    // span for each, so it is priced for them; the contrast is measured
    // here rather than remembered.
    //
    // Non-adjacent starts, so nothing coalesces and the source really
    // holds one run per placed address.
    let runs = |count: u32| -> Vec<Run> { (1..=count).map(|k| run(&ca(2 * k), 1)).collect() };
    let fork = |count: u32| {
        let s = place(&M5State::genesis(), &doc1(), 1, runs(count));
        let rec = M5Rec::VersionSnapshot {
            source: doc1(),
            new: vdoc(),
        };
        let fork_bytes = bincode::serialize(&rec).expect("the record encodes").len();
        let forked = s.apply_m5(Seq(1), &rec);
        assert_eq!(
            forked.content_runs(&vdoc()).collect::<Vec<_>>(),
            s.content_runs(&doc1()).collect::<Vec<_>>()
        );
        // Nothing appended at the snapshot, and the count of what R↾new
        // walks is the named list's runs — once, never those runs again as
        // spans.
        assert_eq!(forked.provenance.appended_span_count(&vdoc()), 0, "a snapshot appends no span");
        assert_eq!(forked.recorded_span_count(&vdoc()), count as usize);
        // What the fork places afterwards is recorded beside the name, and
        // what it then removes is still what it ever contained.
        let edited = place(&forked, &vdoc(), 1, vec![run(&vca(9), 1)]);
        assert_eq!(edited.provenance.appended_span_count(&vdoc()), 1);
        assert_eq!(edited.recorded_span_count(&vdoc()), count as usize + 1);
        let emptied = edited.apply_m5(Seq(2), &M5Rec::ContentRemove {
            doc: vdoc(),
            from: n(1),
            width: n(count + 1),
        });
        let deleted = emptied.deletions(&vdoc());
        assert!(
            runs(count).iter().flat_map(Run::addrs).all(|a| deleted.denotes(a.tumbler())),
            "every address the fork was born holding is in R↾fork by name"
        );
        assert!(deleted.denotes(vca(9).tumbler()), "and so is the one it placed since");
        (
            s.content_runs(&doc1()).len(),
            fork_bytes,
            forked.provenance.ever_contained(&vdoc()).len(),
        )
    };
    // One span of R↾fork per source run, at both sizes…
    assert_eq!(fork(2), (2, fork(2).1, 2));
    let (source_run_count, fork_bytes, r_span_count) = fork(64);
    assert_eq!((source_run_count, r_span_count), (64, 64));
    // …from a record whose size did not move between them.
    assert_eq!(fork_bytes, fork(2).1);
    // And the record that carries what it places, for contrast: the same
    // runs into R as spans.
    let placing_bytes = bincode::serialize(&M5Rec::ContentPlace {
        doc: doc1(),
        at: n(1),
        runs: runs(64),
    })
    .expect("the record encodes")
    .len();
    assert!(
        fork_bytes * 10 < placing_bytes,
        "a fork names {r_span_count} runs in R in {fork_bytes} bytes; \
         placing the same runs costs {placing_bytes}"
    );
}

#[test]
fn version_snapshot_leaves_the_forks_link_subspace_empty() {
    // ASN-0123 V2: what the fork receives is the source's CONTENT map,
    // restricted — the link subspace does not travel with it. Carrying
    // it would seat, in the fork, links whose origin is the SOURCE
    // document: the state CL-OWN forbids and `stage_seat_link` will not
    // create, reachable then only through versioning.
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 2)]);
    let s = s.apply_m5(Seq(1), &M5Rec::LinkSeat { doc: doc1(), link: la(1) });
    let s = s.apply_m5(Seq(1), &M5Rec::LinkSeat { doc: doc1(), link: la(2) });
    assert_eq!(s.link_count(&doc1()), n(2));
    let s = s.apply_m5(Seq(1), &M5Rec::VersionSnapshot {
        source: doc1(),
        new: vdoc(),
    });
    // The content map is shared…
    assert_eq!(
        s.content_runs(&vdoc()).collect::<Vec<_>>(),
        s.content_runs(&doc1()).collect::<Vec<_>>()
    );
    // …and the link subspace is not.
    assert_eq!(s.link_count(&vdoc()), n(0));
    assert_eq!(s.link_runs(&vdoc()).len(), 0);
    // Both subspaces of the source are untouched (V3).
    assert_eq!(s.link_count(&doc1()), n(2));
    assert_eq!(s.content_count(&doc1()), n(2));
}

#[test]
fn a_fork_keeps_the_arrangement_its_source_had_at_the_fork_point() {
    // ASN-0123 V11, the half V3 does not cover: the source is untouched
    // by the fork, AND the fork is untouched by later edits to the
    // source. That is what makes the divergence copy-on-write, and it is
    // the property a lazy or by-reference share — the explicit-runs
    // migration this record's own doc anticipates — would quietly lose.
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 2)]);
    let s = s.apply_m5(Seq(1), &M5Rec::VersionSnapshot {
        source: doc1(),
        new: vdoc(),
    });
    // The source grows…
    let s = place(&s, &doc1(), 3, vec![run(&ca(5), 1)]);
    // …and shrinks, after the fork was taken.
    let s = s.apply_m5(Seq(1), &M5Rec::ContentRemove {
        doc: doc1(),
        from: n(1),
        width: n(1),
    });
    assert_eq!(s.content_count(&doc1()), n(2));
    assert_eq!(
        s.content_runs(&doc1()).cloned().collect::<Vec<_>>(),
        vec![run(&ca(2), 1), run(&ca(5), 1)]
    );
    // The fork still reads as doc1 did at the fork point.
    assert_eq!(s.content_count(&vdoc()), n(2));
    assert_eq!(s.content_runs(&vdoc()).cloned().collect::<Vec<_>>(), vec![run(&ca(1), 2)]);
    // And the fork's R records the fork-point placement and nothing the
    // source placed afterwards.
    let later = skep_address::SpanSet::singleton(run(&ca(5), 1).iextent());
    assert_eq!(s.docs_ever_containing(&later), vec![doc1()]);
}

#[test]
fn every_address_a_document_arranged_is_recorded_in_r() {
    // P4★ (the class invariant on M5State), at ADDRESS granularity. The
    // per-class assertions elsewhere catch dropping a whole origin
    // length; a truncated append records spans of the right classes and
    // passes them. Here the subject is the addresses: remove a
    // document's whole content, and every address it ever arranged must
    // surface in `deletions` — which is `ever_contained ∖ image` with the
    // image empty, hence exactly what R holds.
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 2)]);
    // ONE record placing TWO runs — the shape COPY stages, and the only
    // shape in which a truncated ContentPlace append is observable.
    let s = place(&s, &doc1(), 3, vec![run(&vca(1), 1), run(&ca(5), 2)]);
    let s = s.apply_m5(Seq(1), &M5Rec::VersionSnapshot {
        source: doc1(),
        new: vdoc(),
    });
    for doc in [doc1(), vdoc()] {
        let arranged: Vec<Address> = s.content_runs(&doc).flat_map(Run::addrs).collect();
        assert_eq!(
            arranged.len(),
            5,
            "the fixture arranges five positions in {doc:?}"
        );
        let gone = s.apply_m5(Seq(1), &M5Rec::ContentRemove {
            doc: doc.clone(),
            from: n(1),
            width: n(5),
        });
        assert_eq!(gone.content_count(&doc), n(0));
        let deleted = gone.deletions(&doc);
        for address in arranged {
            assert!(
                deleted.denotes(address.tumbler()),
                "{address:?} was arranged in {doc:?}; P4★ says R recorded it"
            );
        }
    }
}

#[test]
fn only_a_placement_appends_to_r_and_only_a_snapshot_names_in_it() {
    // §4/§6/§8: DELETE, REARRANGE and link seating leave R alone — P2 is
    // about never LOSING a pair, and J-LV uncouples link placement from R
    // altogether — and so does the shot's placing record, whose member's
    // arrangement is its own record. No public read can witness this: R's
    // denotation is the set-union of its pairs, so a redundant append
    // answers every query identically and shows up only as unbounded
    // growth. R itself has to be compared directly.
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 4)]);
    let s = s.apply_m5(Seq(1), &M5Rec::LinkSeat { doc: doc1(), link: la(1) });
    for r in [
        M5Rec::ContentRemove {
            doc: doc1(),
            from: n(2),
            width: n(1),
        },
        M5Rec::ContentReorder {
            doc: doc1(),
            cut_ordinals: vec![n(1), n(2), n(3)],
        },
        M5Rec::LinkSeat {
            doc: doc1(),
            link: la(2),
        },
    ] {
        assert_eq!(
            s.apply_m5(Seq(1), &r).provenance,
            s.provenance,
            "{r:?} must not append to R"
        );
    }
    // The shot's record places a member's runs and leaves R as it stands:
    // nothing is appended and nothing named for the member it mints.
    let shot = s.apply_m5(Seq(1), &M5Rec::ShotPlace {
        doc: vdoc(),
        runs: vec![run(&ca(1), 1)],
        terms: ShotTerms {
            placed: n(1),
            base_extent: None,
            base: None,
            stretches: Vec::new(),
            chain_depth: 0,
        },
        draft: None,
    });
    assert_eq!(shot.content_count(&vdoc()), n(1), "the member is placed");
    assert_eq!(shot.provenance, s.provenance, "a shot's member stores no span");
    // The two that DO move R, so the comparisons above cannot pass
    // vacuously — a `provenance` that had stopped changing at all would
    // satisfy them: a placement appends a span a run, and a snapshot names
    // the list it shares and appends none.
    let placed = s.apply_m5(Seq(1), &M5Rec::ContentPlace {
        doc: doc2(),
        at: n(1),
        runs: vec![run(&ca(1), 1)],
    });
    assert_ne!(placed.provenance, s.provenance);
    assert_eq!(placed.provenance.appended_span_count(&doc2()), 1);
    let forked = s.apply_m5(Seq(1), &M5Rec::VersionSnapshot {
        source: doc1(),
        new: vdoc(),
    });
    assert_ne!(forked.provenance, s.provenance);
    assert_eq!(forked.provenance.appended_span_count(&vdoc()), 0, "named, never appended");
    assert!(forked.provenance.is_recorded(&vdoc()));
}

#[test]
fn version_snapshot_of_an_empty_source_gives_the_fork_no_arrangement_entry_and_no_provenance() {
    // §7: n = 0 ⇒ no provenance append AND no arrangements entry — the
    // lazy absent-⇒-empty convention stays clean.
    let s0 = M5State::genesis();
    let s1 = s0.apply_m5(Seq(1), &M5Rec::VersionSnapshot {
        source: doc2(),
        new: vdoc(),
    });
    assert!(s1.arrangements.get(&vdoc()).is_none());
    assert!(!s1.provenance.is_recorded(&vdoc()));
    assert_eq!(s1.content_count(&vdoc()), n(0));
}

#[test]
fn a_birth_version_s_extent_is_frozen_at_its_mint_and_a_deposit_never_joins_it() {
    // BIRTH★ (PUB-3.19, RES-276): the shot journals a member's whole
    // arrangement as ONE `ShotPlace` at ordinal 1, the record that mints
    // `D.1`, and the count it leaves is the birth extent. Every later
    // placement is a deposit the head took — a `ContentPlace`, which notes
    // nothing: the arrangement grows (PUB-2.66) and the birth extent does
    // not.
    let born = M5State::genesis().apply_m5(Seq(1), &M5Rec::ShotPlace {
        doc: vdoc(),
        runs: vec![run(&ca(1), 3)],
        terms: ShotTerms { placed: n(3), base_extent: None, base: None, stretches: Vec::new(), chain_depth: 0 },
        draft: None,
    });
    assert_eq!(born.birth_extent(&vdoc()), Some(&n(3)));
    // An I-ADJACENT deposit, which is why the extent is noted at the mint
    // rather than read off the arrangement: the run-list merges the
    // deposit INTO the last birth run, so afterwards no run boundary marks
    // where the birth content ended.
    let grown = place(&born, &vdoc(), 4, vec![run(&ca(4), 1)]);
    assert_eq!(grown.content_runs(&vdoc()).cloned().collect::<Vec<_>>(), vec![run(&ca(1), 4)]);
    assert_eq!(grown.content_count(&vdoc()), n(4), "the head's arrangement grew");
    assert_eq!(grown.birth_extent(&vdoc()), Some(&n(3)), "the birth content did not");
    // A second deposit, minted under the member's own content chain: the
    // same.
    let grown = place(&grown, &vdoc(), 5, vec![run(&vca(1), 1)]);
    assert_eq!(grown.content_count(&vdoc()), n(5));
    assert_eq!(grown.birth_extent(&vdoc()), Some(&n(3)));
    // Purity: the state the deposit folded onto still answers its own.
    assert_eq!(born.content_count(&vdoc()), n(3));
}

#[test]
fn only_a_trunk_s_birth_version_has_its_extent_noted() {
    // `birth_extents` holds one entry per TRUNK, keyed by its birth
    // version `D.1` — the one address the doc-metadata read serves an
    // extent for. A trunk, a later trunk member, a daughter of the birth
    // version and the first daughter of a later member each take the record
    // that mints a member — `ShotPlace`, which notes — and note nothing:
    // the last is `first_version_address` of ITS anchor, which is why the
    // test asks the chain the TRUNK opens. The birth version beside them is
    // noted by the same record, so the silence is the predicate's.
    let mint = |doc: &Address| M5Rec::ShotPlace {
        doc: doc.clone(),
        runs: vec![run(&ca(1), 2)],
        terms: ShotTerms { placed: n(2), base_extent: None, base: None, stretches: Vec::new(), chain_depth: 0 },
        draft: None,
    };
    let mut s = M5State::genesis();
    for doc in [
        doc1(),
        a(&[1, 0, 1, 0, 1, 2]),
        a(&[1, 0, 1, 0, 1, 1, 1]),
        a(&[1, 0, 1, 0, 1, 3, 1]),
    ] {
        s = s.apply_m5(Seq(1), &mint(&doc));
        assert_eq!(s.content_count(&doc), n(2));
        assert_eq!(s.birth_extent(&doc), None, "{doc:?} is no birth version");
    }
    assert!(
        s.birth_extents.is_empty(),
        "and `birth_extents` holds no entry for any of them"
    );
    let s = s.apply_m5(Seq(1), &mint(&vdoc()));
    assert_eq!(
        s.birth_extent(&vdoc()),
        Some(&n(2)),
        "the birth version beside them is noted"
    );
}

#[test]
fn a_snapshot_born_version_is_noted_at_what_it_shares_and_an_empty_birth_at_zero() {
    // An owned VERSION of a memberless published document mints the birth
    // version by `VersionSnapshot`: what it shares is what it is born with.
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 3)]);
    let s = s.apply_m5(Seq(1), &M5Rec::VersionSnapshot {
        source: doc1(),
        new: vdoc(),
    });
    assert_eq!(s.birth_extent(&vdoc()), Some(&n(3)));
    let s = place(&s, &vdoc(), 4, vec![run(&ca(9), 1)]);
    assert_eq!((s.content_count(&vdoc()), s.birth_extent(&vdoc())), (n(4), Some(&n(3))));
    // The record is staged whatever the surface holds, so an EMPTY birth
    // is noted as zero — the arrangement and R still gain no entry — and
    // the version's first deposit, which notes nothing, leaves it so: a
    // home born with no content stays an edition of nothing (RES-130).
    let born_empty = M5State::genesis().apply_m5(Seq(1), &M5Rec::VersionSnapshot {
        source: doc2(),
        new: vdoc(),
    });
    assert_eq!(born_empty.birth_extent(&vdoc()), Some(&n(0)), "noted at zero, not absent");
    assert!(born_empty.arrangements.get(&vdoc()).is_none());
    let deposited = place(&born_empty, &vdoc(), 1, vec![run(&ca(1), 1)]);
    assert_eq!(deposited.content_count(&vdoc()), n(1));
    assert_eq!(deposited.birth_extent(&vdoc()), Some(&n(0)), "born empty, whatever it took since");
    // A cross-owner fork's `new` is a fresh DOCUMENT and notes nothing.
    let forked = s.apply_m5(Seq(1), &M5Rec::VersionSnapshot {
        source: doc1(),
        new: doc2(),
    });
    assert_eq!(forked.birth_extents, s.birth_extents);
}

#[test]
fn a_member_the_shot_minted_empty_is_noted_at_zero_by_its_own_record() {
    // D25's (c′): the shot's record is pushed whatever the placement holds,
    // since it carries the shot's terms, so an empty shot-born member is
    // noted at zero by its own mint — the arrangement and R gaining no
    // entry, as the snapshot arm's empty birth leaves them — and its first
    // DEPOSIT, a `ContentPlace` at the same ordinal into the same absent
    // arrangement, notes nothing and grows the count alone. No conforming
    // mint is empty (PUB-3.11).
    let minted_empty = M5State::genesis().apply_m5(Seq(1), &M5Rec::ShotPlace {
        doc: vdoc(),
        runs: vec![],
        terms: ShotTerms { placed: n(0), base_extent: None, base: None, stretches: Vec::new(), chain_depth: 0 },
        draft: None,
    });
    assert_eq!(minted_empty.birth_extent(&vdoc()), Some(&n(0)), "noted at zero by the mint");
    assert!(minted_empty.arrangements.get(&vdoc()).is_none(), "the lazy empty arrangement");
    assert!(!minted_empty.provenance.is_recorded(&vdoc()), "no R entry");
    assert_eq!(
        minted_empty.shot_terms(&vdoc()),
        Some(&ShotTerms { placed: n(0), base_extent: None, base: None, stretches: Vec::new(), chain_depth: 0 }),
        "the terms are noted all the same: the count zero, the birth bit"
    );
    let deposited = place(&minted_empty, &vdoc(), 1, vec![run(&ca(1), 1)]);
    assert_eq!(deposited.content_count(&vdoc()), n(1), "the head took the deposit");
    assert_eq!(deposited.birth_extent(&vdoc()), Some(&n(0)), "born empty, whatever it took since");
}

#[test]
fn shot_place_builds_the_member_from_its_base_and_notes_the_terms() {
    // D25's (c′): the shot's record carries the runs the shot placed and
    // its terms, and the fold builds the member from the BASE's list, read
    // at the record's own slot: the base's positions `[1, base_extent]`
    // replaced by the runs, its positions past the extent left standing —
    // the carried tail, which no run of the record holds. It appends
    // nothing to R, and notes the birth extent and the member's TERMS —
    // neither of which an insert's or copy's placement does, a placement
    // minting nothing. The terms ride the checkpoint with the rest of the
    // slice. And the two records keep their indices — `ContentPlace` 0,
    // `ShotPlace` 5 — as every variant does (`M5Rec`'s card), the shot's
    // record writing its fields in order with its terms nested in place,
    // no framing of their own. The member is doc1's birth version, its
    // base the memberless doc1 itself, holding four positions and taken at
    // two.
    let base = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 4)]);
    let runs = vec![run(&vca(1), 3), run(&pca(1), 2)];
    let by_place = place(&base, &vdoc(), 1, runs.clone());
    let terms = ShotTerms { placed: n(5), base_extent: Some(n(2)), base: Some(doc1()), stretches: Vec::new(), chain_depth: 0 };
    let shot = M5Rec::ShotPlace {
        doc: vdoc(),
        runs: runs.clone(),
        terms: terms.clone(),
        draft: None,
    };
    let by_shot = base.apply_m5(Seq(1), &shot);
    assert_eq!(
        by_shot.content_runs(&vdoc()).cloned().collect::<Vec<_>>(),
        vec![run(&vca(1), 3), run(&pca(1), 2), run(&ca(3), 2)],
        "the runs placed, then the base's positions past the extent its copy took"
    );
    assert_eq!(by_shot.provenance, base.provenance, "nothing appended to R, nothing named");
    assert_eq!(by_shot.recorded_span_count(&vdoc()), 3, "R↾member is its arrangement, run for run");
    assert_eq!(by_shot.birth_extent(&vdoc()), Some(&n(7)), "the whole member is the birth");
    assert_eq!(
        by_shot.shot_terms(&vdoc()),
        Some(&terms),
        "the shot's client terms, as the record carried them"
    );
    assert_eq!(by_place.shot_terms(&vdoc()), None, "a `ContentPlace` notes no terms");
    assert_eq!(
        by_place.birth_extent(&vdoc()),
        None,
        "a `ContentPlace` mints nothing: naming a birth version first, it notes no birth"
    );
    assert_eq!(by_shot.shot_terms(&doc1()), None, "answers the address named");
    let bytes = bincode::serialize(&by_shot).expect("state serializes");
    let back: M5State = bincode::deserialize(&bytes).expect("state deserializes");
    assert_eq!(back, by_shot, "the terms ride the checkpoint");
    assert_eq!(
        &bincode::serialize(&M5Rec::ContentPlace { doc: vdoc(), at: n(1), runs: runs.clone() })
            .expect("encodes")[..4],
        &0u32.to_le_bytes(),
        "`ContentPlace` is index 0, as every journaled insert and copy encodes"
    );
    assert_eq!(
        bincode::serialize(&shot).expect("encodes"),
        bincode::serialize(&(
            5u32,
            vdoc(),
            &runs,
            n(5),
            Some(n(2)),
            Some(doc1()),
            Vec::<(Nat, Nat, Nat)>::new(),
            0u64,
            None::<Address>
        ))
        .expect("encodes"),
        "`ShotPlace` is index 5, then its fields in order, the terms' five flat in place — the \
         count, the extent, the base, the stretches (none: the whole form) and the depth — the \
         rendering draft last"
    );
    // A record with a stretch list writes each stretch as its three counts.
    let places = M5Rec::ShotPlace {
        doc: vdoc(),
        runs: vec![run(&pca(1), 2)],
        terms: ShotTerms {
            placed: n(2),
            base_extent: Some(n(4)),
            base: Some(doc1()),
            stretches: vec![Stretch { start: n(2), width: n(1), placed: n(2) }],
            chain_depth: 1,
        },
        draft: None,
    };
    assert_eq!(
        bincode::serialize(&places).expect("encodes"),
        bincode::serialize(&(
            5u32,
            vdoc(),
            vec![run(&pca(1), 2)],
            n(2),
            Some(n(4)),
            Some(doc1()),
            vec![(n(2), n(1), n(2))],
            1u64,
            None::<Address>
        ))
        .expect("encodes"),
        "a stretch is its start, its width and its placed count, in that order"
    );
    assert_eq!(
        base.apply_m5(Seq(1), &places).content_runs(&vdoc()).cloned().collect::<Vec<_>>(),
        vec![run(&ca(1), 1), run(&pca(1), 2), run(&ca(3), 2)],
        "the base whole, its one stretch replaced"
    );
}

#[test]
fn the_fold_answers_records_outside_its_input_class_without_panicking() {
    // §10 TOTALITY DOMAIN: an out-of-contract record can arise only from
    // corruption and is deliberately NOT re-validated here — what the
    // fold promises instead is that the run-list clamps keep it
    // panic-free. `Nat` is a BigUint, so a lost clamp is an UNDERFLOW
    // PANIC, and this fold runs on the replay path: the failure would be
    // an abort inside `Kernel::open` rather than a rejected request.
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 5)]);
    let content_at = |k: &Nat| VPos::content(k.clone());
    for r in [
        // `at` below the first boundary, past the append boundary, and a
        // placement carrying no runs at all.
        M5Rec::ContentPlace {
            doc: doc1(),
            at: n(0),
            runs: vec![run(&ca(9), 1)],
        },
        M5Rec::ContentPlace {
            doc: doc1(),
            at: n(99),
            runs: vec![run(&ca(9), 1)],
        },
        M5Rec::ContentPlace {
            doc: doc1(),
            at: n(1),
            runs: vec![],
        },
        // Removals that overrun, open below 1, or open past the end.
        M5Rec::ContentRemove {
            doc: doc1(),
            from: n(3),
            width: n(999),
        },
        M5Rec::ContentRemove {
            doc: doc1(),
            from: n(0),
            width: n(0),
        },
        M5Rec::ContentRemove {
            doc: doc1(),
            from: n(999),
            width: n(1),
        },
        // Cut vectors violating R-PRE, the COUNT clause included: the
        // 3|4 rule is the OP's, discharged at staging by `BadCutCount`,
        // so a corrupt record can carry any vector and the tiling has to
        // answer for all of them.
        M5Rec::ContentReorder {
            doc: doc1(),
            cut_ordinals: vec![n(3), n(2), n(1)],
        },
        M5Rec::ContentReorder {
            doc: doc1(),
            cut_ordinals: vec![n(0), n(0), n(0)],
        },
        M5Rec::ContentReorder {
            doc: doc1(),
            cut_ordinals: vec![n(1), n(2), n(999)],
        },
        M5Rec::ContentReorder {
            doc: doc1(),
            cut_ordinals: vec![n(1), n(2)],
        },
        M5Rec::ContentReorder {
            doc: doc1(),
            cut_ordinals: vec![n(1), n(2), n(3), n(4), n(5)],
        },
        // And against a document the arrangement has never touched.
        M5Rec::ContentRemove {
            doc: doc2(),
            from: n(1),
            width: n(1),
        },
        M5Rec::ContentReorder {
            doc: doc2(),
            cut_ordinals: vec![n(1), n(2), n(3)],
        },
    ] {
        let out = s.apply_m5(Seq(1), &r);
        // It answered — and what it answered is still an arrangement:
        // D-SEQ★ holds, the count being the largest arranged ordinal.
        let n_c = out.content_count(&doc1());
        assert_eq!(out.point(&doc1(), &content_at(&n(0))), None, "{r:?}");
        assert_eq!(out.point(&doc1(), &content_at(&(&n_c + &n(1)))), None, "{r:?}");
        if !n_c.is_zero() {
            assert!(out.point(&doc1(), &content_at(&n_c)).is_some(), "{r:?}");
        }
    }
}

#[test]
fn fold_is_deterministic_and_state_serde_round_trips() {
    // §10: replaying the same records yields byte-identical state
    // (bincode is M2's wire format; the OrdMap serialization is ordered,
    // hence canonical); rebuild_derived is the identity.
    let build = || {
        let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 3)]);
        let s = s.apply_m5(Seq(1), &M5Rec::ContentRemove {
            doc: doc1(),
            from: n(2),
            width: n(1),
        });
        s.apply_m5(Seq(1), &M5Rec::LinkSeat { doc: doc1(), link: la(1) })
    };
    let first = build();
    let second = build();
    assert_eq!(first, second); // the same records fold to the same state…
    let first_bytes = bincode::serialize(&first).expect("state serializes");
    let second_bytes = bincode::serialize(&second).expect("state serializes");
    assert_eq!(first_bytes, second_bytes); // …and that state encodes alike
    let back: M5State = bincode::deserialize(&first_bytes).expect("state deserializes");
    assert_eq!(bincode::serialize(&back).expect("reserializes"), first_bytes);
    assert_eq!(back.content_count(&doc1()), n(2));
    let rebuilt_bytes =
        bincode::serialize(&back.clone().rebuild_derived()).expect("serializes");
    assert_eq!(rebuilt_bytes, first_bytes);
}

#[test]
fn the_birth_extents_ride_the_checkpoint_because_nothing_can_rebuild_them() {
    // The birth extents are DERIVED by the fold and CARRIED by the
    // checkpoint: a checkpoint replaces the journal prefix it was folded
    // from, and the arrangement it holds no longer says where the birth
    // content ended (the deposit below merged into the birth run). So they
    // are a serialized field, not a skip-serialized hint —
    // `rebuild_derived` is still the identity — and a decoded state
    // answers the extent its records folded to, where a rebuild off the
    // arrangement could only answer the live count.
    let mint = M5Rec::ShotPlace {
        doc: vdoc(),
        runs: vec![run(&ca(1), 3)],
        terms: ShotTerms { placed: n(3), base_extent: None, base: None, stretches: Vec::new(), chain_depth: 0 },
        draft: None,
    };
    let born = M5State::genesis().apply_m5(Seq(1), &mint);
    let grown = place(&born, &vdoc(), 4, vec![run(&ca(4), 1)]);
    let bytes = bincode::serialize(&grown).expect("state serializes");
    let back: M5State = bincode::deserialize(&bytes).expect("state deserializes");
    assert_eq!(back, grown);
    assert_eq!(back.content_count(&vdoc()), n(4));
    assert_eq!(back.birth_extent(&vdoc()), Some(&n(3)), "the frozen extent, not the live count");
    assert_eq!(back.clone().rebuild_derived(), back);
    // Replay re-derives them: the same records fold to the same birth
    // extents.
    let again = place(
        &M5State::genesis().apply_m5(Seq(1), &mint),
        &vdoc(),
        4,
        vec![run(&ca(4), 1)],
    );
    assert_eq!(bincode::serialize(&again).expect("serializes"), bytes);
}

/// The account's fourth document: an alternative staged from `vdoc`.
///
/// It is `[1,0,1,0,nth_doc(4)]`.
fn alternative() -> Address {
    a(&[1, 0, 1, 0, nth_doc(4)])
}

/// A slice whose every collection holds entries, folded from records alone.
///
/// Two tests read its bytes: the hostile-count sweep writes over every count
/// in them, and the byte pin holds them against a twin spelled from the
/// literals below. doc1 holds two content runs and a link, and doc2 is its
/// snapshot, the copy taking doc1's four positions; two members are minted
/// by shots, one carrying a base — the memberless doc1 — with its extent
/// and one the birth shape. Of the two draft bases, doc2's carries the
/// marker of its first landing, put back after a second landing, with both
/// stamps standing; the alternative's merge was withdrawn, its stamp kept.
/// Every record folds at a position of its own but the staging pair, which
/// is one commit, so the arranged-at entries and the markers' `at`s each
/// read the commit that wrote them.
fn every_field_held() -> M5State {
    let first = Merge { sides: vec![vdoc()], head: doc1(), head_copied: n(4) };
    let second = Merge { sides: vec![vdoc(), pca_member()], head: doc1(), head_copied: n(4) };
    let withdrawn = Merge { sides: vec![], head: vdoc(), head_copied: n(2) };
    let doc2_base = |merge: Option<Merge>| M5Rec::DraftBase {
        draft: doc2(),
        base: doc1(),
        extent: n(4),
        source: doc1(),
        merge,
    };
    let alternative_base = |merge: Option<Merge>| M5Rec::DraftBase {
        draft: alternative(),
        base: vdoc(),
        extent: n(2),
        source: vdoc(),
        merge,
    };
    let shot = |doc: Address, runs: Vec<Run>, placed: u32, base: Option<(Address, u32)>| {
        M5Rec::ShotPlace {
            doc,
            runs,
            terms: ShotTerms {
                placed: n(placed),
                base_extent: base.as_ref().map(|(_, extent)| n(*extent)),
                base: base.map(|(member, _)| member),
                stretches: Vec::new(),
                chain_depth: 0,
            },
            draft: None,
        }
    };
    [
        (1, M5Rec::ContentPlace { doc: doc1(), at: n(1), runs: vec![run(&ca(1), 3)] }),
        (2, M5Rec::ContentPlace { doc: doc1(), at: n(4), runs: vec![run(&vca(1), 1)] }),
        (3, M5Rec::LinkSeat { doc: doc1(), link: la(1) }),
        (4, shot(vdoc(), vec![run(&ca(1), 2)], 2, Some((doc1(), 1)))),
        (5, shot(pca_member(), vec![run(&pca(1), 1)], 1, None)),
        (6, M5Rec::VersionSnapshot { source: doc1(), new: doc2() }),
        (6, doc2_base(None)),
        (8, doc2_base(Some(first.clone()))),
        (11, doc2_base(Some(second))),
        (13, M5Rec::MarkerRestore {
            draft: doc2(),
            base: doc1(),
            extent: n(4),
            source: doc1(),
            marker: first.stamped(Seq(8)),
        }),
        (15, alternative_base(Some(withdrawn))),
        (17, alternative_base(None)),
    ]
    .iter()
    .fold(M5State::genesis(), |s, (at, rec)| s.apply_m5(Seq(*at), rec))
}

#[test]
fn the_slice_decodes_or_refuses_whatever_count_its_bytes_declare() {
    // M2's HOSTILE-INPUT OBLIGATION on `WorldState`: a checkpoint body is
    // bytes M2 does not trust, and its load refuses one that will not decode
    // and falls back to an older base. So no count the body declares may size
    // a reservation before the entries it counts have arrived — past
    // `isize::MAX` bytes the reservation panics, and short of it a count the
    // allocator cannot grant aborts the process where the load must refuse.
    // Every collection the slice holds — the node table and each node's
    // entries, the arrangement map, R's two maps and each document's spans,
    // the birth extents, the shot terms, the fork sources, the arranged-at
    // positions, the draft bases and each base's stamps, the copied counts —
    // decodes through
    // `decode`'s doors, the table's own or reserves cautiously, and so does every sequence
    // beneath them (a marker's sides, an address's components, a natural's
    // digits). So `u64::MAX` written over ANY eight bytes
    // of a body holding every one of them is decoded or refused, and never
    // reserved for: a collection decoded by `im`'s own visitor fails here,
    // the empty count of a field added since included. It fails one of two
    // ways, both the hazard itself. Written squarely over a count, `u64::MAX`
    // overflows the reservation's layout and panics, caught below and
    // reported at its offset; written across one, the window reads part of it
    // and part of the bytes beside it — a count the layout admits and the
    // allocator cannot grant — and the process aborts, which nextest reports
    // against this test. A corpus seed for the fuzzing tier: this body, at
    // every offset, under every count.
    //
    // The premise: every collection the slice decodes holds an entry, so the
    // sweep writes over each one's count and over the counts within it.
    let s = every_field_held();
    assert_eq!(s.arrangements.len(), 4);
    assert_eq!(s.link_run_count(&doc1()), 1);
    assert_eq!(s.recorded_span_count(&doc1()), 2);
    assert_eq!(s.birth_extents.len(), 2);
    assert_eq!(s.shot_terms.len(), 2);
    assert_eq!(s.fork_sources.len(), 1);
    assert_eq!(s.arranged_at.len(), 4);
    assert_eq!(s.draft_bases.len(), 2);
    assert_eq!(s.source_copied.len(), 1);
    assert_eq!(s.draft_base(&doc2()).map(|b| b.stamped.len()), Some(2), "the entry's stamps");
    assert_eq!(
        s.draft_base(&alternative()).map(|b| (b.merge.is_none(), b.stamped.len())),
        Some((true, 1)),
        "the withdrawn merge's stamp, standing"
    );
    let bytes = bincode::serialize(&s).expect("state serializes");
    assert_eq!(
        bincode::deserialize::<M5State>(&bytes).expect("state deserializes"),
        s
    );
    let mut refused_at = Vec::new();
    for at in 0..=bytes.len() - 8 {
        let mut lying = bytes.clone();
        lying[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        match std::panic::catch_unwind(|| bincode::deserialize::<M5State>(&lying)) {
            Ok(Err(_)) => refused_at.push(at),
            Ok(Ok(_)) => {}
            Err(_) => panic!(
                "u64::MAX over bytes {at}..{} panicked the decode: a reservation sized by a \
                 count the body does not carry",
                at + 8
            ),
        }
    }
    assert_eq!(
        refused_at.first(),
        Some(&0),
        "the node table's count, the body's first eight bytes, is refused"
    );
}

/// A run as the slice writes it: its start, then its width.
type RawRun = (Tumbler, Nat);

/// A document's arrangement as the run-sequence form writes it: content,
/// then links.
type RawArrangement = (Vec<RawRun>, Vec<RawRun>);

/// A leaf of the node table as the checkpoint form writes it: the variant's
/// index, 0, then its runs.
type RawLeaf = (u32, Vec<RawRun>);

/// A list as the checkpoint form writes it: its root's id in the node
/// table, none for the empty list.
type RawRoot = Option<u64>;

/// A marker as the slice writes it.
///
/// Its sides, its head, the head's extent as read at the compose, then the
/// position it was put at.
type RawMarker = (Vec<Tumbler>, Tumbler, Nat, u64);

/// A draft base as the slice writes it.
///
/// Its base, extent and source, then its marker and its stamps.
type RawDraftBase = (Tumbler, Nat, Tumbler, Option<RawMarker>, Vec<RawMarker>);

/// The slice's bytes down to each entry's fields, against a plain twin, in
/// both its forms.
///
/// The twins are spelled in plain types from the fixture's literals, never
/// read off the state. The checkpoint form's bytes are a format: M2 hashes
/// them into a checkpoint's header and the engine's `World` lays them down
/// as one slice of its layout. The engine's own pin sees the slice's field
/// names alone, so a field gained, lost or reordered *beneath* them — a
/// draft base's marker or stamps, a marker's position, a shot's terms, a
/// run, a node of the table — moves the World's bytes with every name
/// unchanged. This pin sees it. The checkpoint twin is the node table and
/// then the eight fields in declaration order: the table a `Vec` of nodes,
/// each list's root written at its first meeting — a document's content
/// list, then its link list, the documents in address order, then R's named
/// lists — and a list two documents share written once; the arrangements a
/// `Vec` of pairs in address order (bincode writes a map exactly so), each
/// a document's two root ids; R's appended spans each run's I-extent in
/// placing order and then its named lists each a root id; and the six maps
/// after R every entry its fields in order — a shot's terms its count,
/// extent, base, stretches and depth, a draft base its base, extent,
/// source, marker and stamps. The run-sequence twin is the eight fields
/// with every list its runs in V-order, the form the engine's world dump
/// renders. Each twin decodes back to the fixture through its own door, so
/// it is the slice's form and not merely bytes alike.
#[test]
fn the_slice_serializes_as_its_node_table_and_nine_maps_down_to_each_entry_s_fields() {
    let tumbler = |address: Address| address.tumbler().clone();
    let raw_run = |start: Address, width: u32| -> RawRun { (tumbler(start), n(width)) };
    let extent = |start: Address, reach: Address| {
        Span::from_endpoints(tumbler(start), reach.tumbler()).expect("a run's I-extent is a span")
    };
    let raw_marker = |sides: Vec<Address>, head: Address, copied: u32, at: u64| -> RawMarker {
        (sides.into_iter().map(tumbler).collect(), tumbler(head), n(copied), at)
    };
    // The lists, each a leaf: doc1's content, which its snapshot doc2 and
    // doc2's named list share; doc1's link; the shot's member — its two
    // positions, then doc1's past the one its copy took, the base's list
    // with its first position replaced; and the birth member's.
    let doc1_content = || vec![raw_run(ca(1), 3), raw_run(vca(1), 1)];
    let doc1_link = || vec![raw_run(la(1), 1)];
    let member = || vec![raw_run(ca(1), 2), raw_run(ca(2), 2), raw_run(vca(1), 1)];
    let birth = || vec![raw_run(pca(1), 1)];
    let nodes: Vec<RawLeaf> = vec![(0, doc1_content()), (0, doc1_link()), (0, member()), (0, birth())];
    let rooted: Vec<(Tumbler, (RawRoot, RawRoot))> = vec![
        (tumbler(doc1()), (Some(0), Some(1))),
        (tumbler(vdoc()), (Some(2), None)),
        (tumbler(doc2()), (Some(0), None)),
        (tumbler(pca_member()), (Some(3), None)),
    ];
    let arrangements: Vec<(Tumbler, RawArrangement)> = vec![
        (tumbler(doc1()), (doc1_content(), doc1_link())),
        (tumbler(vdoc()), (member(), vec![])),
        (tumbler(doc2()), (doc1_content(), vec![])),
        (tumbler(pca_member()), (birth(), vec![])),
    ];
    // R's two maps: the spans appended — the placements' alone, a shot's
    // member storing none — then the lists named, the snapshot's.
    let appended = || -> Vec<(Tumbler, Vec<Span>)> { vec![(tumbler(doc1()), vec![extent(ca(1), ca(4)), extent(vca(1), vca(2))])] };
    let named_roots: Vec<(Tumbler, RawRoot)> = vec![(tumbler(doc2()), Some(0))];
    let named_runs: Vec<(Tumbler, Vec<RawRun>)> = vec![(tumbler(doc2()), doc1_content())];
    let birth_extents: Vec<(Tumbler, Nat)> =
        vec![(tumbler(vdoc()), n(5)), (tumbler(pca_member()), n(1))];
    type RawTerms = (Nat, Option<Nat>, Option<Tumbler>, Vec<(Nat, Nat, Nat)>, u64);
    let shot_terms: Vec<(Tumbler, RawTerms)> = vec![
        (tumbler(vdoc()), (n(2), Some(n(1)), Some(tumbler(doc1())), vec![], 0)),
        (tumbler(pca_member()), (n(1), None, None, vec![], 0)),
    ];
    let fork_sources: Vec<(Tumbler, Tumbler)> = vec![(tumbler(doc2()), tumbler(doc1()))];
    let arranged_at: Vec<(Tumbler, u64)> = vec![
        (tumbler(doc1()), 2),
        (tumbler(vdoc()), 4),
        (tumbler(doc2()), 6),
        (tumbler(pca_member()), 5),
    ];
    let first = || raw_marker(vec![vdoc()], doc1(), 4, 8);
    let draft_bases: Vec<(Tumbler, RawDraftBase)> = vec![
        (
            tumbler(doc2()),
            (
                tumbler(doc1()),
                n(4),
                tumbler(doc1()),
                Some(first()),
                vec![first(), raw_marker(vec![vdoc(), pca_member()], doc1(), 4, 11)],
            ),
        ),
        (
            tumbler(alternative()),
            (tumbler(vdoc()), n(2), tumbler(vdoc()), None, vec![raw_marker(vec![], vdoc(), 2, 15)]),
        ),
    ];
    let source_copied: Vec<(Tumbler, Nat)> = vec![(tumbler(doc2()), n(4))];
    let maps = (&birth_extents, &shot_terms, &fork_sources, &arranged_at, &draft_bases, &source_copied);
    let twin = bincode::serialize(&(nodes, rooted, (appended(), named_roots), maps)).expect("the twin encodes");
    let state = every_field_held();
    assert!(
        bincode::serialize(&state).expect("the slice serializes") == twin,
        "M5's slice serialized as something other than its node table and then its nine maps in declaration \
         order, each in address order and each entry its fields as the twin spells them: those bytes are M2's \
         hashed checkpoint body and a slice of the engine's World layout — a change to them owes the engine's \
         WORLD_FORMAT bump (or, under the owner's no-stamp ruling, a line in its list of the layouts its count \
         names)"
    );
    assert_eq!(
        bincode::deserialize::<M5State>(&twin).expect("the twin decodes"),
        state,
        "the twin's bytes are the fixture's slice"
    );
    // The run-sequence form: the eight fields, every list its runs.
    let by_runs = bincode::serialize(&(arrangements, (appended(), named_runs), maps)).expect("the twin encodes");
    assert!(
        bincode::serialize(&state.as_run_sequences()).expect("the form serializes") == by_runs,
        "M5's run-sequence form serialized as something other than its nine maps in declaration order, each \
         list its runs in V-order: the engine's world dump renders it — a change to it owes a dump-filter \
         disposition"
    );
    let read_back = {
        use bincode::Options;
        let options = bincode::DefaultOptions::new().with_fixint_encoding().allow_trailing_bytes();
        M5State::from_run_sequences(&mut bincode::Deserializer::from_slice(&by_runs, options)).expect("the twin decodes")
    };
    assert_eq!(read_back, state, "the run-sequence twin's bytes are the fixture's slice");
    // One list, three handles: the snapshot's document, its source and its
    // named list are one root in the fixture, and one again once decoded
    // from the checkpoint form — where the run-sequence form, which writes
    // each list whole, reads them back apart.
    for (label, held, shared) in [
        ("the fold's", &state, true),
        ("the checkpoint form's", &bincode::deserialize::<M5State>(&twin).expect("the twin decodes"), true),
        ("the run-sequence form's", &read_back, false),
    ] {
        let named = held.provenance.named_list(&doc2()).expect("the snapshot's named list");
        assert_eq!(held.content_list(&doc2()).shares_root_with(held.content_list(&doc1())), shared, "{label} snapshot and its source");
        assert_eq!(named.shares_root_with(held.content_list(&doc1())), shared, "{label} named list and its source");
    }
}

/// Another account's document, `[1,0,2,0,1]`: where a cross-owner fork of
/// `doc1` is minted.
fn fork_doc() -> Address {
    a(&[1, 0, 2, 0, 1])
}

/// A second document of that account, `[1,0,2,0,64]`: a fork of the fork.
fn fork_of_fork_doc() -> Address {
    a(&[1, 0, 2, 0, 64])
}

#[test]
fn a_version_minted_document_is_noted_with_the_source_it_was_born_sharing() {
    // SOURCE★, the noting half: the `VersionSnapshot` arm writes `new →
    // source` for an OWNED version — the member minted against its bare
    // memberless document — and for a CROSS-OWNER fork alike, and the
    // source noted is the record's `source`, the surface the op resolved:
    // a bare document here, and a MEMBER where the source had a chain. The
    // source itself answers none: the read answers the address named.
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 3)]);
    let owned = s.apply_m5(Seq(1), &M5Rec::VersionSnapshot {
        source: doc1(),
        new: vdoc(),
    });
    assert_eq!(owned.fork_source(&vdoc()), Some(&doc1()), "the owned version's source");
    assert_eq!(owned.fork_source_copied(&vdoc()), Some(&n(3)), "…beside the count the copy took");
    assert_eq!(owned.fork_source(&doc1()), None, "the trunk answers none, never its member's");
    assert_eq!(owned.fork_source_copied(&doc1()), None, "…and no count");
    // A cross-owner fork taken off the chain's member: the surface a bare
    // published source with members resolves to is its head, and the record
    // names that member, so the fork's source IS the member.
    let forked = owned.apply_m5(Seq(1), &M5Rec::VersionSnapshot {
        source: vdoc(),
        new: fork_doc(),
    });
    assert_eq!(forked.fork_source(&fork_doc()), Some(&vdoc()), "the member, not its trunk");
    assert_eq!(forked.fork_source_copied(&fork_doc()), Some(&n(3)), "the member's count");
    assert_eq!(forked.fork_source(&vdoc()), Some(&doc1()), "the member keeps its own");
    // The arrangement shared and the source noted come from one record, so
    // the fork reads as the member did and names it.
    assert_eq!(
        forked.content_runs(&fork_doc()).collect::<Vec<_>>(),
        forked.content_runs(&vdoc()).collect::<Vec<_>>()
    );
    // Purity: the receiver was untouched.
    assert_eq!(owned.fork_source(&fork_doc()), None);
}

#[test]
fn a_fork_of_an_empty_source_is_noted_all_the_same() {
    // SOURCE★: the fact is the source, not the content — the empty arm
    // installs no arrangement and appends no provenance, and writes the one
    // entry a snapshot writes whatever the surface holds.
    let s = M5State::genesis().apply_m5(Seq(1), &M5Rec::VersionSnapshot {
        source: doc2(),
        new: fork_doc(),
    });
    assert!(s.arrangements.get(&fork_doc()).is_none(), "nothing shared");
    assert!(!s.provenance.is_recorded(&fork_doc()), "no R entry");
    assert_eq!(s.fork_source(&fork_doc()), Some(&doc2()), "noted, an empty surface included");
    assert_eq!(
        s.fork_source_copied(&fork_doc()),
        Some(&n(0)),
        "the count the copy took noted beside it, a zero and never an absence"
    );
}

#[test]
fn only_a_version_record_notes_a_fork_source() {
    // SOURCE★, the silence half: a shot's member is minted off no source
    // and notes none, a placement mints nothing, a `fork`-minted document
    // reaches this slice with no record at all — so each answers `None`,
    // as does a document nothing has touched and the trunk the version
    // chain belongs to.
    let shot = M5State::genesis().apply_m5(Seq(1), &M5Rec::ShotPlace {
        doc: vdoc(),
        runs: vec![run(&ca(1), 2)],
        terms: ShotTerms { placed: n(2), base_extent: None, base: None, stretches: Vec::new(), chain_depth: 0 },
        draft: None,
    });
    assert_eq!(shot.fork_source(&vdoc()), None, "a shot member");
    assert_eq!(shot.birth_extent(&vdoc()), Some(&n(2)), "…minted all the same");
    let placed = place(&shot, &doc2(), 1, vec![run(&ca(1), 1)]);
    assert_eq!(placed.fork_source(&doc2()), None, "a placement mints nothing");
    // A `fork` stages M3's record alone: the slice sees nothing, so the
    // document it minted is, here, an untouched one.
    assert_eq!(placed.fork_source(&fork_doc()), None, "a `fork`-minted or untouched document");
    assert_eq!(placed.fork_source(&doc1()), None, "the trunk");
    assert!(placed.fork_sources.is_empty(), "and the map holds no entry for any of them");
    assert!(placed.source_copied.is_empty(), "nor the copied counts beside it");
}

#[test]
fn a_fork_of_a_fork_answers_its_own_source_one_hop() {
    // SOURCE★: the fact as journaled, one hop — the second fork names the
    // first, never the line's root; the whole line is read by iterating,
    // each hop under its own document's gate.
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 2)]);
    let s = s.apply_m5(Seq(1), &M5Rec::VersionSnapshot {
        source: doc1(),
        new: fork_doc(),
    });
    let s = s.apply_m5(Seq(1), &M5Rec::VersionSnapshot {
        source: fork_doc(),
        new: fork_of_fork_doc(),
    });
    assert_eq!(s.fork_source(&fork_of_fork_doc()), Some(&fork_doc()), "one hop");
    assert_eq!(s.fork_source(&fork_doc()), Some(&doc1()), "the hop before it");
    assert_eq!(s.fork_source(&doc1()), None, "the root");
}

#[test]
fn the_fork_sources_ride_the_checkpoint_and_replay_re_derives_them() {
    // The map is carried by every checkpoint as its four siblings are, and
    // a replay of the same records folds to the same map and the same
    // bytes — so a board opened from a checkpoint and one replayed from
    // genesis answer one source. A source the fork has since edited away
    // from is still its source: the fact is the mint's, not the content's.
    let build = || {
        let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 3)]);
        let s = s.apply_m5(Seq(1), &M5Rec::VersionSnapshot {
            source: doc1(),
            new: fork_doc(),
        });
        s.apply_m5(Seq(1), &M5Rec::ContentRemove {
            doc: fork_doc(),
            from: n(1),
            width: n(3),
        })
    };
    let live = build();
    assert_eq!(live.content_count(&fork_doc()), n(0), "the fork edited away every shared run");
    assert_eq!(live.fork_source(&fork_doc()), Some(&doc1()), "…and keeps its source");
    let bytes = bincode::serialize(&live).expect("state serializes");
    let back: M5State = bincode::deserialize(&bytes).expect("state deserializes");
    assert_eq!(back, live);
    assert_eq!(back.fork_source(&fork_doc()), Some(&doc1()), "the checkpoint carries it");
    assert_eq!(back.clone().rebuild_derived(), back);
    let replayed = build();
    assert_eq!(bincode::serialize(&replayed).expect("serializes"), bytes, "replay equals live");
    // A checkpoint written before the map misreads every field after it,
    // and decodes no default (the engine's World door holds that refusal;
    // the field order is pinned here).
    assert_field_order(&live, &bytes, "`fork_sources` is written after `shot_terms`, before `arranged_at`");
}

#[test]
fn m5rec_survives_a_bincode_round_trip() {
    // §A: M5Rec is THE journaled delta, and every variant of it rides
    // replay — so each one comes back as the same record, and the
    // replayed record folds to the same effect. Folded off a base that
    // arranges doc1, so that no arm answers by leaving the state alone.
    let base = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 5)]);
    for rec in [
        M5Rec::ContentPlace {
            doc: doc1(),
            at: n(1),
            runs: vec![run(&ca(1), 2), run(&vca(1), 1)],
        },
        M5Rec::ContentRemove {
            doc: doc1(),
            from: n(2),
            width: n(2),
        },
        M5Rec::ContentReorder {
            doc: doc1(),
            cut_ordinals: vec![n(1), n(2), n(4), n(6)],
        },
        M5Rec::LinkSeat {
            doc: doc1(),
            link: la(1),
        },
        M5Rec::VersionSnapshot {
            source: doc1(),
            new: vdoc(),
        },
        M5Rec::ShotPlace {
            doc: vdoc(),
            runs: vec![run(&ca(1), 2), run(&pca(1), 1)],
            terms: ShotTerms { placed: n(3), base_extent: Some(n(1)), base: Some(doc1()), stretches: Vec::new(), chain_depth: 0 },
            draft: None,
        },
        M5Rec::ShotPlace {
            doc: a(&[1, 0, 1, 0, 64, 1]),
            runs: vec![],
            terms: ShotTerms { placed: n(0), base_extent: None, base: None, stretches: Vec::new(), chain_depth: 0 },
            draft: Some(doc2()),
        },
        M5Rec::DraftBase { draft: doc2(), base: doc1(), extent: n(5), source: doc1(), merge: None },
        M5Rec::MarkerRestore {
            draft: doc2(),
            base: doc1(),
            extent: n(5),
            source: doc1(),
            marker: Marker { sides: vec![vdoc()], head: doc1(), head_copied: n(5), at: Seq(3) },
        },
        M5Rec::ContentEdit {
            doc: doc1(),
            changes: vec![
                Splice { at: n(2), width: n(1), runs: vec![run(&vca(1), 2)] },
                Splice { at: n(6), width: n(0), runs: vec![run(&pca(1), 1)] },
            ],
        },
    ] {
        let bytes = bincode::serialize(&rec).expect("record serializes");
        let back: M5Rec = bincode::deserialize(&bytes).expect("record deserializes");
        assert_eq!(back, rec, "the same record, not merely one folding alike");
        let folded = base.apply_m5(Seq(1), &rec);
        assert_ne!(folded, base, "{rec:?} changes the base it folds onto");
        assert_eq!(
            bincode::serialize(&folded).expect("serializes"),
            bincode::serialize(&base.apply_m5(Seq(1), &back)).expect("serializes"),
            "{rec:?}"
        );
    }
}

/// MOVED★ (skep #442), arm by arm: the four content-touching records and
/// the snapshot move their document's arranged-at entry to the position
/// the fold is handed — the shot's and the snapshot's on both branches,
/// an empty placement and an empty source included — and the link seat
/// moves none; the snapshot leaves its source's entry where it stood.
#[test]
fn every_arm_that_changes_a_content_arrangement_notes_its_position_and_the_link_seat_does_not() {
    let s = M5State::genesis();
    assert_eq!(s.arranged_at(&doc1()), None, "never arranged");
    let s = s.apply_m5(
        Seq(3),
        &M5Rec::ContentPlace { doc: doc1(), at: n(1), runs: vec![run(&ca(1), 3)] },
    );
    assert_eq!(s.arranged_at(&doc1()), Some(Seq(3)), "the placement");
    let s = s.apply_m5(Seq(5), &M5Rec::ContentRemove { doc: doc1(), from: n(2), width: n(1) });
    assert_eq!(s.arranged_at(&doc1()), Some(Seq(5)), "the removal");
    let s = s.apply_m5(
        Seq(7),
        &M5Rec::ContentReorder { doc: doc1(), cut_ordinals: vec![n(1), n(2), n(3)] },
    );
    assert_eq!(s.arranged_at(&doc1()), Some(Seq(7)), "the reorder");
    let s = s.apply_m5(Seq(9), &M5Rec::LinkSeat { doc: doc1(), link: la(1) });
    assert_eq!(s.link_count(&doc1()), n(1), "the link was seated…");
    assert_eq!(s.arranged_at(&doc1()), Some(Seq(7)), "…and moved the entry nowhere");
    // The snapshot: `new` at its mint, the source where it stood — on the
    // sharing branch and the empty-source branch alike.
    let s = s.apply_m5(Seq(11), &M5Rec::VersionSnapshot { source: doc1(), new: vdoc() });
    assert_eq!(s.arranged_at(&vdoc()), Some(Seq(11)), "the fork starts at its mint");
    assert_eq!(s.arranged_at(&doc1()), Some(Seq(7)), "the source is untouched");
    let s = s.apply_m5(Seq(13), &M5Rec::VersionSnapshot { source: doc2(), new: a(&[1, 0, 2, 0, 1]) });
    assert_eq!(s.content_count(&a(&[1, 0, 2, 0, 1])), n(0), "an empty source shares nothing…");
    assert_eq!(s.arranged_at(&a(&[1, 0, 2, 0, 1])), Some(Seq(13)), "…and its fork is noted all the same");
    assert_eq!(s.arranged_at(&doc2()), None, "an empty source never arranged stays so");
    // The shot's placement: the member at the shot, placed or empty.
    let terms = ShotTerms { placed: n(1), base_extent: None, base: None, stretches: Vec::new(), chain_depth: 0 };
    let s = s.apply_m5(
        Seq(17),
        &M5Rec::ShotPlace { doc: pca_member(), runs: vec![run(&pca(1), 1)], terms: terms.clone(), draft: None },
    );
    assert_eq!(s.arranged_at(&pca_member()), Some(Seq(17)), "the shot's member");
    let empty_member = a(&[1, 0, 1, 0, 64, 1]);
    let s = s.apply_m5(Seq(19), &M5Rec::ShotPlace { doc: empty_member.clone(), runs: vec![], terms, draft: None });
    assert_eq!(s.content_count(&empty_member), n(0));
    assert_eq!(s.arranged_at(&empty_member), Some(Seq(19)), "an empty placement is noted too");
}

/// The member the shot places into in the cell above: pdoc's first member.
fn pca_member() -> Address {
    a(&[1, 0, 1, 0, 65, 1])
}

/// The arranged-at map rides the checkpoint as its siblings do, is
/// re-derived by replay to the same bytes, and is the slice's sixth field —
/// after `fork_sources`, before `draft_bases`, under the same no-default rule
/// — so a checkpoint written before it ends where it would begin and
/// decodes no default.
#[test]
fn the_arranged_at_positions_ride_the_checkpoint_sixth_and_replay_re_derives_them() {
    let build = || {
        let s = M5State::genesis().apply_m5(
            Seq(4),
            &M5Rec::ContentPlace { doc: doc1(), at: n(1), runs: vec![run(&ca(1), 3)] },
        );
        let s = s.apply_m5(Seq(6), &M5Rec::VersionSnapshot { source: doc1(), new: vdoc() });
        s.apply_m5(Seq(9), &M5Rec::ContentRemove { doc: doc1(), from: n(1), width: n(3) })
    };
    let live = build();
    assert_eq!(live.arranged_at(&doc1()), Some(Seq(9)));
    assert_eq!(live.arranged_at(&vdoc()), Some(Seq(6)));
    let bytes = bincode::serialize(&live).expect("state serializes");
    let back: M5State = bincode::deserialize(&bytes).expect("state deserializes");
    assert_eq!(back, live);
    assert_eq!(back.arranged_at(&doc1()), Some(Seq(9)), "the checkpoint carries it");
    assert_eq!(bincode::serialize(&build()).expect("serializes"), bytes, "replay equals live");
    assert_field_order(&live, &bytes, "`arranged_at` is written after `fork_sources`, before `draft_bases`");
    // A body cut short of the map — a checkpoint written before it — does
    // not decode: the no-default rule.
    let without = cut_after(&live, 3);
    assert!(
        bincode::deserialize::<M5State>(&without).is_err(),
        "a checkpoint body without the map must fail to decode, never read as never arranged"
    );
}

/// BASE★ (the staging act, B3-S10), the noting half: the staging record
/// installs the draft's base, extent and source as it carries them,
/// touching no arrangement and no arranged-at entry; the read answers the
/// address named — the draft, never its source or its base — and a draft no
/// record names answers none.
#[test]
fn a_staging_record_notes_the_drafts_base_extent_and_source_and_moves_nothing_else() {
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 3)]);
    let shared = s.apply_m5(Seq(5), &M5Rec::VersionSnapshot { source: doc1(), new: doc2() });
    let staged = shared.apply_m5(
        Seq(5),
        &M5Rec::DraftBase { draft: doc2(), base: doc1(), extent: n(3), source: doc1(), merge: None },
    );
    assert_eq!(
        staged.draft_base(&doc2()),
        Some(&DraftBase { base: doc1(), extent: n(3), source: doc1(), merge: None, stamped: vec![] }),
        "the record as it was carried"
    );
    assert_eq!(staged.draft_base(&doc1()), None, "the source answers none: the address named");
    assert_eq!(staged.arrangements, shared.arrangements, "no arrangement moves");
    assert_eq!(staged.provenance, shared.provenance, "no R-append");
    assert_eq!(staged.arranged_at, shared.arranged_at, "no arranged-at entry moves");
    assert_eq!(staged.fork_sources, shared.fork_sources, "the snapshot noted the source already");
    // An alternative's record names the source draft and its inherited base.
    let alternative = staged.apply_m5(
        Seq(7),
        &M5Rec::DraftBase { draft: pdoc(), base: doc1(), extent: n(3), source: doc2(), merge: None },
    );
    assert_eq!(
        alternative.draft_base(&pdoc()),
        Some(&DraftBase { base: doc1(), extent: n(3), source: doc2(), merge: None, stamped: vec![] })
    );
    // Purity: the receiver was untouched.
    assert_eq!(shared.draft_base(&doc2()), None);
}

/// BASE★, the moving half: a shot naming its rendering draft moves that
/// draft's base to the member minted and its extent to the member's whole
/// count — the carried tail counted, the source kept — on both of the arm's
/// branches, an empty placement included; a shot naming no draft moves
/// nothing; and a shot naming a draft the map holds no entry for makes one,
/// the member its source too.
#[test]
fn a_shot_naming_its_draft_moves_the_drafts_base_to_the_member_it_minted() {
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 3)]);
    let s = s.apply_m5(
        Seq(5),
        &M5Rec::DraftBase { draft: doc2(), base: pdoc(), extent: n(2), source: pdoc(), merge: None },
    );
    let terms = ShotTerms { placed: n(2), base_extent: Some(n(2)), base: Some(pdoc()), stretches: Vec::new(), chain_depth: 0 };
    // The shot that renders doc2 into pdoc's first member, placing two runs
    // of three positions in all.
    let rendered = s.apply_m5(
        Seq(8),
        &M5Rec::ShotPlace {
            doc: vdoc(),
            runs: vec![run(&ca(1), 2), run(&pca(1), 1)],
            terms: terms.clone(),
            draft: Some(doc2()),
        },
    );
    assert_eq!(
        rendered.draft_base(&doc2()),
        Some(&DraftBase { base: vdoc(), extent: n(3), source: pdoc(), merge: None, stamped: vec![] }),
        "the base moved to the member, the extent its whole count, the source kept"
    );
    // A shot naming no draft moves nothing.
    let unnamed = s.apply_m5(
        Seq(8),
        &M5Rec::ShotPlace {
            doc: vdoc(),
            runs: vec![run(&ca(1), 2)],
            terms: terms.clone(),
            draft: None,
        },
    );
    assert_eq!(unnamed.draft_bases, s.draft_bases, "no draft named, no base moved");
    // An empty placement moves the base all the same, the extent zero.
    let empty = s.apply_m5(
        Seq(9),
        &M5Rec::ShotPlace {
            doc: vdoc(),
            runs: vec![],
            terms: ShotTerms { placed: n(0), base_extent: Some(n(2)), base: Some(pdoc()), stretches: Vec::new(), chain_depth: 0 },
            draft: Some(doc2()),
        },
    );
    assert_eq!(
        empty.draft_base(&doc2()),
        Some(&DraftBase { base: vdoc(), extent: n(0), source: pdoc(), merge: None, stamped: vec![] })
    );
    // A draft the map holds no entry for gains one: the member it rendered
    // as its base and its source, its extent the member's count.
    let first = s.apply_m5(
        Seq(10),
        &M5Rec::ShotPlace {
            doc: vdoc(),
            runs: vec![run(&ca(1), 3)],
            terms: ShotTerms { placed: n(3), base_extent: None, base: None, stretches: Vec::new(), chain_depth: 0 },
            draft: Some(pdoc()),
        },
    );
    assert_eq!(
        first.draft_base(&pdoc()),
        Some(&DraftBase { base: vdoc(), extent: n(3), source: vdoc(), merge: None, stamped: vec![] })
    );
    assert_eq!(first.draft_base(&doc2()), Some(&DraftBase { base: pdoc(), extent: n(2), source: pdoc(), merge: None, stamped: vec![] }), "another draft's entry stands");
    // Purity: the receiver was untouched.
    assert_eq!(s.draft_base(&doc2()), Some(&DraftBase { base: pdoc(), extent: n(2), source: pdoc(), merge: None, stamped: vec![] }));
}

/// The draft bases ride the checkpoint as their siblings do, are re-derived
/// by replay to the same bytes, and are the slice's seventh field — after
/// `arranged_at`, before `source_copied`, under the same no-default rule —
/// so a checkpoint written before the map ends where it would begin and
/// decodes no default.
#[test]
fn the_draft_bases_ride_the_checkpoint_seventh_and_replay_re_derives_them() {
    let build = || {
        let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 3)]);
        let s = s.apply_m5(Seq(6), &M5Rec::VersionSnapshot { source: doc1(), new: doc2() });
        let s = s.apply_m5(
            Seq(6),
            &M5Rec::DraftBase { draft: doc2(), base: doc1(), extent: n(3), source: doc1(), merge: None },
        );
        s.apply_m5(
            Seq(9),
            &M5Rec::ShotPlace {
                doc: vdoc(),
                runs: vec![run(&ca(1), 3)],
                terms: ShotTerms { placed: n(3), base_extent: Some(n(3)), base: Some(doc1()), stretches: Vec::new(), chain_depth: 0 },
                draft: Some(doc2()),
            },
        )
    };
    let live = build();
    assert_eq!(live.draft_base(&doc2()), Some(&DraftBase { base: vdoc(), extent: n(3), source: doc1(), merge: None, stamped: vec![] }));
    let bytes = bincode::serialize(&live).expect("state serializes");
    let back: M5State = bincode::deserialize(&bytes).expect("state deserializes");
    assert_eq!(back, live);
    assert_eq!(back.draft_base(&doc2()), live.draft_base(&doc2()), "the checkpoint carries it");
    assert_eq!(back.clone().rebuild_derived(), back);
    assert_eq!(bincode::serialize(&build()).expect("serializes"), bytes, "replay equals live");
    assert_field_order(&live, &bytes, "`draft_bases` is written after `arranged_at`, before `source_copied`");
    // A body cut short of the map — a checkpoint written before it — does
    // not decode: the no-default rule.
    let without = cut_after(&live, 4);
    assert!(
        bincode::deserialize::<M5State>(&without).is_err(),
        "a checkpoint body without the map must fail to decode, never read as no base"
    );
    // The base record's index: appended after the shot's, its fields in
    // order, as every variant encodes (`M5Rec`'s card) — the marker its
    // fifth and last, appended at the landing lane, so a record journaled
    // before it stays decodable as it was written.
    let rec = M5Rec::DraftBase { draft: doc2(), base: doc1(), extent: n(3), source: doc1(), merge: None };
    assert_eq!(
        bincode::serialize(&rec).expect("encodes"),
        bincode::serialize(&(6u32, doc2(), doc1(), n(3), doc1(), None::<Merge>)).expect("encodes"),
        "`DraftBase` is index 6, then its five fields in order"
    );
    let marked = M5Rec::DraftBase {
        draft: doc2(),
        base: doc1(),
        extent: n(3),
        source: doc1(),
        merge: Some(Merge { sides: vec![vdoc()], head: doc1(), head_copied: n(3) }),
    };
    assert_eq!(
        bincode::serialize(&marked).expect("encodes"),
        bincode::serialize(&(6u32, doc2(), doc1(), n(3), doc1(), Some((vec![vdoc()], doc1(), n(3)))))
            .expect("encodes"),
        "the marker's content: its sides, its head and the head's extent, in order, with no position"
    );
    // An entry written before the marker — three fields — or before the
    // stamps — four — no longer decodes: the entry carries no default for
    // either (the owner's accepted cost, a development board regenerating).
    let old_entry: Vec<u8> = bincode::serialize(&(doc1(), n(3), doc1())).expect("encodes");
    assert!(
        bincode::deserialize::<DraftBase>(&old_entry).is_err(),
        "an entry without the marker must fail to decode, never read as unmarked"
    );
    let unstamped: Vec<u8> = bincode::serialize(&(doc1(), n(3), doc1(), None::<Marker>)).expect("encodes");
    assert!(
        bincode::deserialize::<DraftBase>(&unstamped).is_err(),
        "an entry without the stamps must fail to decode, never read as stamping nothing"
    );
}

/// SOURCE★, the count half (skep #1111): the snapshot notes the count its
/// copy took beside the source, on both branches, and nothing moves it — a
/// deposit into the source after the copy grows the source and leaves the
/// fork's count where the copy ended, and an edit to the fork leaves it
/// too. An owned version, a cross-owner fork and a staged draft (whose
/// staging record rides beside the snapshot) are noted alike.
#[test]
fn a_snapshot_notes_the_count_its_copy_took_and_nothing_moves_it() {
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 3)]);
    let forked = s.apply_m5(Seq(4), &M5Rec::VersionSnapshot { source: doc1(), new: fork_doc() });
    assert_eq!(
        forked.fork_source_copied(&fork_doc()),
        Some(&n(3)),
        "the source's count at the copy"
    );
    // The source grows by a deposit after the copy, and the fork's count
    // stays where its copy ended.
    let grown = place(&forked, &doc1(), 4, vec![run(&ca(9), 2)]);
    assert_eq!(grown.content_count(&doc1()), n(5), "the source took the deposit");
    assert_eq!(grown.fork_source_copied(&fork_doc()), Some(&n(3)), "the count is the mint's");
    // The fork's own edits leave it too.
    let edited =
        grown.apply_m5(Seq(6), &M5Rec::ContentRemove { doc: fork_doc(), from: n(1), width: n(2) });
    assert_eq!(edited.content_count(&fork_doc()), n(1));
    assert_eq!(
        edited.fork_source_copied(&fork_doc()),
        Some(&n(3)),
        "an edit to the fork moves nothing"
    );
    // A staged draft: the snapshot and the staging record of one commit,
    // the count the snapshot's own.
    let staged =
        edited.apply_m5(Seq(8), &M5Rec::VersionSnapshot { source: doc1(), new: doc2() }).apply_m5(
            Seq(8),
            &M5Rec::DraftBase {
                draft: doc2(),
                base: doc1(),
                extent: n(5),
                source: doc1(),
                merge: None,
            },
        );
    assert_eq!(staged.fork_source_copied(&doc2()), Some(&n(5)), "the staged draft's copy");
    // A shot moving that draft's base moves no count.
    let published = staged.apply_m5(
        Seq(10),
        &M5Rec::ShotPlace {
            doc: pca_member(),
            runs: vec![run(&pca(1), 1)],
            terms: ShotTerms { placed: n(1), base_extent: None, base: None, stretches: Vec::new(), chain_depth: 0 },
            draft: Some(doc2()),
        },
    );
    assert_eq!(
        published.draft_base(&doc2()).map(|b| &b.base),
        Some(&pca_member()),
        "the base moved…"
    );
    assert_eq!(published.fork_source_copied(&doc2()), Some(&n(5)), "…and the count did not");
    assert_eq!(published.fork_source_copied(&pca_member()), None, "a shot member notes none");
    // Every record but the snapshot leaves the map whole.
    assert_eq!(published.source_copied, staged.source_copied);
    // Purity: the receiver was untouched.
    assert_eq!(s.fork_source_copied(&fork_doc()), None);
}

/// The copied counts ride the checkpoint as their siblings do, are
/// re-derived by replay to the same bytes, and are the slice's LAST field —
/// after `draft_bases`, under the same no-default rule — so a checkpoint
/// written before the map ends where it would begin and decodes no default.
#[test]
fn the_copied_counts_ride_the_checkpoint_last_and_replay_re_derives_them() {
    let build = || {
        let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 3)]);
        let s = s.apply_m5(Seq(4), &M5Rec::VersionSnapshot { source: doc1(), new: fork_doc() });
        let s = place(&s, &doc1(), 4, vec![run(&ca(9), 1)]);
        s.apply_m5(Seq(7), &M5Rec::VersionSnapshot { source: doc2(), new: fork_of_fork_doc() })
    };
    let live = build();
    assert_eq!(
        (live.fork_source_copied(&fork_doc()), live.fork_source_copied(&fork_of_fork_doc())),
        (Some(&n(3)), Some(&n(0))),
        "the count at the copy, and an empty surface's zero"
    );
    let bytes = bincode::serialize(&live).expect("state serializes");
    let back: M5State = bincode::deserialize(&bytes).expect("state deserializes");
    assert_eq!(back, live);
    assert_eq!(back.fork_source_copied(&fork_doc()), Some(&n(3)), "the checkpoint carries it");
    assert_eq!(back.clone().rebuild_derived(), back);
    assert_eq!(bincode::serialize(&build()).expect("serializes"), bytes, "replay equals live");
    assert_field_order(&live, &bytes, "`source_copied` is written after `draft_bases`, last");
    // A body cut short of the map — a checkpoint written before it — does
    // not decode: the no-default rule.
    let without = cut_after(&live, 5);
    assert!(
        bincode::deserialize::<M5State>(&without).is_err(),
        "a checkpoint body without the map must fail to decode, never read as no count"
    );
}

/// BASE★'s three arms for the marker (the owner's ruling N3; skep #764): a
/// base record carrying a merge installs the marker with THIS commit's
/// position stamped — the landing's own, or a stage's for the content it
/// inherited — never a position the record names; a shot naming the draft
/// moves the base and CLEARS the marker; a placement and a removal naming
/// the draft (the publication's re-window of an `also` draft) touch neither
/// the base nor the marker; and a base record carrying no merge clears a
/// marker that stood.
#[test]
fn the_marker_is_stamped_at_the_fold_cleared_by_the_shot_and_kept_by_the_rewindow() {
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 3)]);
    let s = s.apply_m5(
        Seq(5),
        &M5Rec::DraftBase { draft: doc2(), base: pdoc(), extent: n(2), source: pdoc(), merge: None },
    );
    let merge = Merge { sides: vec![vdoc(), vca(1)], head: pdoc(), head_copied: n(2) };
    // The landing's record at 8: the marker stamped 8.
    let landed = s.apply_m5(
        Seq(8),
        &M5Rec::DraftBase {
            draft: doc2(),
            base: pdoc(),
            extent: n(2),
            source: pdoc(),
            merge: Some(merge.clone()),
        },
    );
    let marker = Marker { sides: vec![vdoc(), vca(1)], head: pdoc(), head_copied: n(2), at: Seq(8) };
    assert_eq!(
        landed.draft_base(&doc2()),
        Some(&DraftBase {
            base: pdoc(),
            extent: n(2),
            source: pdoc(),
            merge: Some(marker.clone()),
            stamped: vec![marker.clone()],
        }),
        "the marker's content as carried, its position the commit's own"
    );
    assert_eq!(landed.arranged_at(&doc2()), None, "the record moves no arranged-at entry");
    // A stage of the marked draft at 11 carries the content and is stamped
    // 11: the position the marker was put on the alternative.
    let staged = landed.apply_m5(
        Seq(11),
        &M5Rec::DraftBase {
            draft: a(&[1, 0, 1, 0, 66]),
            base: pdoc(),
            extent: n(2),
            source: doc2(),
            merge: Some(Merge::from(&marker)),
        },
    );
    assert_eq!(
        staged.draft_base(&a(&[1, 0, 1, 0, 66])).and_then(|b| b.merge.as_ref()),
        Some(&Marker { at: Seq(11), ..marker.clone() }),
        "inherited content, the stage's own position"
    );
    assert_eq!(staged.draft_base(&doc2()).and_then(|b| b.merge.as_ref()), Some(&marker), "the source's stands");
    // The re-window: a placement and a removal naming the draft move the
    // arrangement and nothing of the record.
    let rewindowed = landed
        .apply_m5(Seq(12), &M5Rec::ContentPlace { doc: doc2(), at: n(1), runs: vec![run(&pca(1), 1)] })
        .apply_m5(Seq(12), &M5Rec::ContentRemove { doc: doc2(), from: n(1), width: n(1) });
    assert_eq!(rewindowed.draft_base(&doc2()), landed.draft_base(&doc2()), "the base and the marker stand");
    assert_eq!(rewindowed.arranged_at(&doc2()), Some(Seq(12)), "the arrangement moved all the same");
    // The shot naming the draft: the base to the member, the marker cleared.
    let shot = landed.apply_m5(
        Seq(14),
        &M5Rec::ShotPlace {
            doc: vdoc(),
            runs: vec![run(&pca(1), 2)],
            terms: ShotTerms { placed: n(2), base_extent: Some(n(2)), base: Some(pdoc()), stretches: Vec::new(), chain_depth: 0 },
            draft: Some(doc2()),
        },
    );
    assert_eq!(
        shot.draft_base(&doc2()),
        Some(&DraftBase { base: vdoc(), extent: n(2), source: pdoc(), merge: None, stamped: vec![] }),
        "the shot folds the merge into the member and clears the marker"
    );
    // A base record carrying no merge — an undo's, or a plain landing's —
    // clears a marker that stood.
    let cleared = landed.apply_m5(
        Seq(15),
        &M5Rec::DraftBase { draft: doc2(), base: pdoc(), extent: n(2), source: pdoc(), merge: None },
    );
    assert_eq!(cleared.draft_base(&doc2()).and_then(|b| b.merge.as_ref()), None);
    // Purity: the receiver was untouched throughout.
    assert_eq!(landed.draft_base(&doc2()).and_then(|b| b.merge.as_ref()), Some(&marker));
}

/// BASE★'s stamps, record by record (skep #870).
///
/// A base record carrying a merge appends the marker it stamps to the
/// draft's stamps, every base record keeps those
/// that stood, a stage's record starts the alternative's with its inherited
/// marker alone, the restore record installs its marker as carried — its
/// `at` the stamp's, never the commit's — keeping the stamps and moving no
/// arrangement, and a shot naming the draft empties them while one naming
/// none keeps them. The restore record is index 7, its fields in order.
#[test]
fn the_stamps_keep_every_marker_stamped_and_the_restore_installs_one_as_carried() {
    let base_record = |s: &M5State, at: u64, merge: Option<Merge>| {
        s.apply_m5(Seq(at), &M5Rec::DraftBase { draft: doc2(), base: pdoc(), extent: n(2), source: pdoc(), merge })
    };
    let staged = base_record(&place(&M5State::genesis(), &doc2(), 1, vec![run(&pca(1), 2)]), 5, None);
    assert_eq!(staged.draft_base(&doc2()).map(|b| b.stamped.len()), Some(0), "nothing stamped");
    let merge = Merge { sides: vec![vca(1)], head: pdoc(), head_copied: n(2) };
    let (m8, m11) = (merge.stamped(Seq(8)), merge.stamped(Seq(11)));
    // A landing, its withdrawal, the same merge landed again.
    let relanded = base_record(&base_record(&base_record(&staged, 8, Some(merge.clone())), 9, None), 11, Some(merge.clone()));
    let stamps = vec![m8.clone(), m11.clone()];
    assert_eq!(
        relanded.draft_base(&doc2()),
        Some(&DraftBase { base: pdoc(), extent: n(2), source: pdoc(), merge: Some(m11.clone()), stamped: stamps.clone() }),
        "each landing's stamp kept, in stamp order, through the withdrawal between"
    );
    // The restore at 13 puts the first landing's marker back as carried.
    let restore = M5Rec::MarkerRestore { draft: doc2(), base: pdoc(), extent: n(2), source: pdoc(), marker: m8.clone() };
    let restored = relanded.apply_m5(Seq(13), &restore);
    assert_eq!(
        restored.draft_base(&doc2()),
        Some(&DraftBase { base: pdoc(), extent: n(2), source: pdoc(), merge: Some(m8.clone()), stamped: stamps.clone() }),
        "the marker as carried, its `at` the stamp's and never 13, the stamps kept"
    );
    assert_eq!(restored.arrangements, relanded.arrangements, "no arrangement moves");
    assert_eq!(restored.arranged_at(&doc2()), relanded.arranged_at(&doc2()), "no arranged-at entry moves");
    // A stage of the restored draft: the alternative's stamps hold its
    // inherited marker alone, stamped at the stage.
    let alternative = a(&[1, 0, 1, 0, 66]);
    let inherited = restored.apply_m5(
        Seq(15),
        &M5Rec::DraftBase { draft: alternative.clone(), base: pdoc(), extent: n(2), source: doc2(), merge: Some(Merge::from(&m8)) },
    );
    assert_eq!(
        inherited.draft_base(&alternative).map(|b| b.stamped.clone()),
        Some(vec![Marker { at: Seq(15), ..m8.clone() }]),
        "none of the source's stamps"
    );
    // A shot naming the draft empties its stamps; one naming none keeps them.
    let shot = |draft: Option<Address>| M5Rec::ShotPlace {
        doc: vdoc(),
        runs: vec![run(&pca(1), 2)],
        terms: ShotTerms { placed: n(2), base_extent: Some(n(2)), base: Some(pdoc()), stretches: Vec::new(), chain_depth: 0 },
        draft,
    };
    let published = restored.apply_m5(Seq(17), &shot(Some(doc2())));
    assert_eq!(published.draft_base(&doc2()).map(|b| b.stamped.is_empty()), Some(true), "the merge is the member's");
    let kept = restored.apply_m5(Seq(17), &shot(None));
    assert_eq!(kept.draft_base(&doc2()), restored.draft_base(&doc2()), "a shot keeping the base keeps the stamps");
    // The record's index and its fields, in order.
    assert_eq!(
        bincode::serialize(&restore).expect("encodes"),
        bincode::serialize(&(7u32, doc2(), pdoc(), n(2), pdoc(), (vec![vca(1)], pdoc(), n(2), Seq(8)))).expect("encodes"),
        "`MarkerRestore` is index 7, then its five fields, the marker whole with its position"
    );
}

/// The edit's record: its changes spliced in one fold, each placed run
/// appended to R and nothing a change removes taken from it (P4★, P2), and
/// the document's arranged-at entry moved to the record's position whatever
/// it holds (MOVED★) — a record of no change included, which leaves the
/// arrangement and R as they stand, an absent document absent.
#[test]
fn the_edits_record_splices_its_changes_appends_what_it_places_and_always_moves_the_position() {
    let base = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 5)]);
    let edit = M5Rec::ContentEdit {
        doc: doc1(),
        changes: vec![
            Splice { at: n(2), width: n(2), runs: vec![run(&vca(1), 1)] },
            Splice { at: n(5), width: n(1), runs: vec![] },
            Splice { at: n(6), width: n(0), runs: vec![run(&pca(1), 2)] },
        ],
    };
    let s = base.apply_m5(Seq(7), &edit);
    assert_eq!(
        s.content_runs(&doc1()).cloned().collect::<Vec<_>>(),
        vec![run(&ca(1), 1), run(&vca(1), 1), run(&ca(4), 1), run(&pca(1), 2)]
    );
    assert_eq!(s.arranged_at(&doc1()), Some(Seq(7)));
    // R: the two placed runs appended, in the changes' order, after what
    // stood; the removed addresses keep the span that placed them.
    assert_eq!(s.recorded_span_count(&doc1()), base.recorded_span_count(&doc1()) + 2);
    let ever = s.provenance.ever_contained(&doc1());
    for placed in [run(&ca(1), 5), run(&vca(1), 1), run(&pca(1), 2)] {
        assert!(ever.iter().any(|span| *span == placed.iextent()), "{placed:?} is recorded");
    }
    assert!(!s.deletions(&doc1()).is_empty(), "what the changes removed reads as deleted");
    // A record of removals alone appends nothing to R.
    let removing = M5Rec::ContentEdit { doc: doc1(), changes: vec![Splice { at: n(1), width: n(2), runs: vec![] }] };
    assert_eq!(base.apply_m5(Seq(7), &removing).provenance, base.provenance);
    // A record of no change: the position moves, and nothing else does.
    let none = M5Rec::ContentEdit { doc: doc1(), changes: vec![] };
    let bytes = bincode::serialize(&none).expect("record serializes");
    assert_eq!(bincode::deserialize::<M5Rec>(&bytes).expect("record deserializes"), none);
    let moved = base.apply_m5(Seq(9), &none);
    assert_eq!(moved.arranged_at(&doc1()), Some(Seq(9)));
    assert_eq!(moved.arrangement_map(), base.arrangement_map());
    assert_eq!(moved.provenance, base.provenance);
    let absent = M5State::genesis().apply_m5(Seq(9), &M5Rec::ContentEdit { doc: doc2(), changes: vec![] });
    assert_eq!(absent.arranged_at(&doc2()), Some(Seq(9)));
    assert!(absent.arrangement_map().is_empty(), "an absent document stays absent");
    assert!(!absent.provenance.is_recorded(&doc2()));
    // Outside the input class the fold answers without a panic: changes
    // that overlap, and one past the list.
    let wild = M5Rec::ContentEdit {
        doc: doc1(),
        changes: vec![
            Splice { at: n(3), width: n(9), runs: vec![] },
            Splice { at: n(2), width: n(0), runs: vec![run(&vca(1), 1)] },
            Splice { at: n(99), width: n(4), runs: vec![run(&pca(1), 1)] },
        ],
    };
    let folded = base.apply_m5(Seq(7), &wild);
    assert_eq!(
        folded.content_runs(&doc1()).cloned().collect::<Vec<_>>(),
        vec![run(&ca(1), 2), run(&vca(1), 1), run(&pca(1), 1)]
    );
}

/// THE SHAPE A RE-WINDOW STAGES, OUTSIDE ITS INPUT CLASS. A publication's
/// kept places are one edit record: a change a place, as wide as the runs
/// it puts in, a run a piece. Where such a record does not fit the list it
/// is folded over, the fold answers without a panic and by the splice's
/// clamps: a place past the end is made at the end; a place reaching past
/// the end removes what is there; of two places that overlap, or stand out
/// of order, the later is made where the build stands; and a
/// record replayed over a shorter draft, or an absent one, places every run
/// it carries. Each fold appends a span for every run of the record and
/// moves the arranged-at position.
#[test]
fn a_re_windows_record_that_does_not_fit_its_draft_is_folded_without_a_panic() {
    let base = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 6)]);
    let kept = |at: u32, to: u32, width: u32| Splice { at: n(at), width: n(width), runs: vec![run(&pca(to), width)] };
    let folded = |over: &M5State, changes: Vec<Splice>| -> (Vec<Run>, usize) {
        let s = over.apply_m5(Seq(7), &M5Rec::ContentEdit { doc: doc1(), changes });
        assert_eq!(s.arranged_at(&doc1()), Some(Seq(7)));
        (s.content_runs(&doc1()).cloned().collect(), s.recorded_span_count(&doc1()) - over.recorded_span_count(&doc1()))
    };
    // An ordinal past the end: made at the end, nothing there to remove.
    assert_eq!(folded(&base, vec![kept(9, 1, 2)]), (vec![run(&ca(1), 6), run(&pca(1), 2)], 1));
    // A place reaching past the end removes the one position there.
    assert_eq!(folded(&base, vec![kept(6, 1, 3)]), (vec![run(&ca(1), 5), run(&pca(1), 3)], 1));
    // Two places that overlap, positions 2–4 and 3–4: the second is made
    // where the first's removal ends, and removes from there.
    assert_eq!(folded(&base, vec![kept(2, 1, 3), kept(3, 5, 2)]), (vec![run(&ca(1), 1), run(&pca(1), 3), run(&pca(5), 2)], 2));
    // Two places out of order: the second, behind the walk, is made where
    // the walk stands.
    assert_eq!(folded(&base, vec![kept(5, 1, 1), kept(2, 3, 1)]), (vec![run(&ca(1), 4), run(&pca(1), 1), run(&pca(3), 1)], 2));
    // A record replayed over a draft it no longer fits: a shorter one, and
    // an absent one.
    let record = || vec![kept(2, 1, 2), kept(5, 3, 2)];
    assert_eq!(folded(&base, record()), (vec![run(&ca(1), 1), run(&pca(1), 2), run(&ca(4), 1), run(&pca(3), 2)], 2), "the draft it was staged for");
    let shorter = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 2)]);
    assert_eq!(folded(&shorter, record()), (vec![run(&ca(1), 1), run(&pca(1), 4)], 2));
    assert_eq!(folded(&M5State::genesis(), record()), (vec![run(&pca(1), 4)], 2));
    // A piece's run stays a span of its own in R though the list holds two
    // adjacent pieces as one run.
    let pieces = Splice { at: n(2), width: n(2), runs: vec![run(&pca(1), 1), run(&pca(2), 1)] };
    assert_eq!(folded(&base, vec![pieces]), (vec![run(&ca(1), 1), run(&pca(1), 2), run(&ca(4), 3)], 2));
}

#[test]
fn a_shots_fold_reads_its_base_at_its_stretches_alone_and_shares_the_rest() {
    // The fold builds a shot's member from its base's tree: each stretch
    // found by a descent, its runs placed, and every node of the base no
    // stretch reaches shared with the member. The count is the stretches'
    // and the placed runs' — a bound the base's 65,536 runs do not enter —
    // whether the shot names one stretch or four thousand.
    let base_run_count = 1u32 << 16;
    let base_runs: Vec<Run> = (1..=base_run_count).map(|k| run(&ca(2 * k), 1)).collect();
    let base = place(&M5State::genesis(), &doc1(), 1, base_runs.clone());
    let base_list = base.content_list(&doc1()).clone();
    for stretches in [1u32, 64, 4_096] {
        // Each stretch replaces one position of the base by one run, the
        // stretches spread evenly over it.
        let spread = base_run_count / stretches;
        let terms = ShotTerms {
            placed: n(stretches),
            base_extent: Some(n(base_run_count)),
            base: Some(doc1()),
            stretches: (0..stretches).map(|i| Stretch { start: n(1 + i * spread), width: n(1), placed: n(1) }).collect(),
            chain_depth: 1,
        };
        let runs: Vec<Run> = (1..=stretches).map(|i| run(&pca(2 * i), 1)).collect();
        let mut steps = 0u64;
        let member = base.shot_member_list(&runs, &terms, &mut |n| steps += n);
        let bound = (u64::from(stretches) + 1) * base_list.cut_steps() + u64::from(stretches);
        assert!(steps <= bound, "{stretches} stretches: {steps} steps past {bound}");
        if stretches < 4_096 {
            assert!(steps < u64::from(base_run_count) / 8, "{stretches} stretches: {steps} steps follow the base");
        }
        // The member holds the base's nodes but for the stretches' paths:
        // a leaf a stretch, and the nodes above it.
        member.check().expect("the member's tree holds");
        let (leaves, inner) = member.made_anew(&[&base_list]);
        assert_eq!(leaves, stretches as usize, "{stretches} stretches: one leaf made anew a stretch");
        assert!(inner <= stretches as usize * base_list.height(), "{stretches} stretches: {inner} inner nodes made anew");
        assert_eq!(member.run_count(), base_run_count as usize);
        let mut expected = base_runs.clone();
        for i in 0..stretches {
            expected[(i * spread) as usize] = run(&pca(2 * (i + 1)), 1);
        }
        assert!(member.iter().eq(expected.iter()), "{stretches} stretches: the base, each stretch replaced");
        // The record's fold is that list, installed.
        let folded = base.apply_m5(Seq(2), &M5Rec::ShotPlace { doc: vdoc(), runs: runs.clone(), terms, draft: None });
        assert!(folded.content_runs(&vdoc()).eq(expected.iter()));
    }
}

#[test]
fn the_fold_leaves_each_list_sharing_what_its_record_did_not_change() {
    // Each arm that makes a list from another leaves the two sharing every
    // node the record did not reach, by address. A snapshot's document, its
    // source and the list R names for it are three handles on one root. An
    // edit's list holds its document's old one but for the paths to its
    // changes. Ten edits in a row, a snapshot kept after each, keep ten
    // such paths beside the first list, not ten lists. And a shot that
    // carries its whole arrangement shares nothing with its base and reads
    // none of it.
    let runs = 1u32 << 16;
    let base_runs: Vec<Run> = (1..=runs).map(|k| run(&ca(2 * k), 1)).collect();
    let mut state = place(&M5State::genesis(), &doc1(), 1, base_runs.clone());
    let first = state.content_list(&doc1()).clone();
    let height = first.height();
    let mut kept: Vec<Address> = Vec::new();
    for j in 0..10u32 {
        // One position of the draft replaced by one run of another origin.
        let at = 1 + j * (runs / 10) + 7;
        let edit = M5Rec::ContentEdit { doc: doc1(), changes: vec![Splice { at: n(at), width: n(1), runs: vec![run(&pca(2 * j + 1), 1)] }] };
        let before = state.content_list(&doc1()).clone();
        state = state.apply_m5(Seq(u64::from(2 * j + 2)), &edit);
        let edited = state.content_list(&doc1());
        assert_eq!(edited.made_anew(&[&before]), (1, height), "edit {j}: its leaf and the node above it at each level");
        // The snapshot: the new document, its source and the named list,
        // one root.
        let version = a(&[1, 0, 2, 0, 100 + j]);
        state = state.apply_m5(Seq(u64::from(2 * j + 3)), &M5Rec::VersionSnapshot { source: doc1(), new: version.clone() });
        let source = state.content_list(&doc1());
        assert!(state.content_list(&version).shares_root_with(source), "version {j}: the document and its source");
        assert!(state.provenance.named_list(&version).expect("named").shares_root_with(source), "version {j}: the named list and its source");
        kept.push(version);
    }
    // Every version still holds the list its edit left, and they hold
    // between them the first list's nodes and ten paths.
    let lists: Vec<&RunList> = kept.iter().map(|doc| state.content_list(doc)).chain([&first]).collect();
    let named: Vec<&RunList> = kept.iter().map(|doc| state.provenance.named_list(doc).expect("named")).collect();
    for (version, named) in kept.iter().zip(&named) {
        assert!(state.content_list(version).shares_root_with(named), "a named list stands as its version does");
    }
    let alone = RunList::nodes_among(&[&first]);
    let together = RunList::nodes_among(&lists);
    assert_eq!(together - alone, 10 * (height + 1), "ten versions: ten leaves and ten paths beside the first list's {alone} nodes");
    assert_eq!(RunList::nodes_among(&named), RunList::nodes_among(&lists[..10]), "the named lists hold no node the versions do not");
    // The source edited once more: the last version and its named list
    // keep the list as it stood, reached from the version and from R.
    let last = kept.last().expect("a version");
    let before = state.content_list(last).clone();
    let edited = state.apply_m5(Seq(99), &M5Rec::ContentRemove { doc: doc1(), from: n(1), width: n(runs / 2) });
    assert!(edited.content_list(last).shares_root_with(&before));
    assert!(edited.provenance.named_list(last).expect("named").shares_root_with(&before));
    assert!(!edited.content_list(&doc1()).shares_root_with(&before));
    // A shot carrying its whole arrangement over a base: one change over
    // the base's extent. Its member is the bulk build of its runs: no node
    // of the base is opened, none is shared, and the count is the placed
    // runs' alone.
    let whole: Vec<Run> = (1..=runs).map(|k| run(&pca(2 * k), 1)).collect();
    let terms = ShotTerms { placed: n(runs), base_extent: Some(n(runs)), base: Some(doc1()), stretches: Vec::new(), chain_depth: 1 };
    let mut steps = 0u64;
    let member = state.shot_member_list(&whole, &terms, &mut |by| steps += by);
    assert_eq!(steps, 1 + u64::from(runs), "the whole form: its one change and each run placed, no step of the base's");
    let base_list = state.content_list(&doc1());
    let (leaves, inner) = member.made_anew(&[base_list]);
    assert_eq!(leaves + inner, RunList::nodes_among(&[&member]), "the whole form shares no node with its base");
    assert!(member.iter().eq(whole.iter()));
    assert_eq!(member.fill(), RunList::from_runs(whole.clone()).fill(), "the member is the bulk build of its runs");
    // …and where the base grew past the extent the copy took, the tail is
    // kept after the runs placed, by a descent to it.
    let grown = state.apply_m5(Seq(100), &M5Rec::ContentPlace { doc: doc1(), at: n(runs + 1), runs: vec![run(&vca(1), 3)] });
    let mut steps = 0u64;
    let member = grown.shot_member_list(&whole, &terms, &mut |by| steps += by);
    assert!(member.iter().eq(whole.iter().chain([&run(&vca(1), 3)])), "the base's tail past the extent stands after the runs placed");
    assert!(steps <= 1 + u64::from(runs) + grown.content_list(&doc1()).cut_steps(), "the tail kept by one descent: {steps} steps");
}

/// Every run-list `s` holds: both lists of every document, then every list
/// R names — the roots its checkpoint form writes, in the order it takes
/// them.
fn every_list(s: &M5State) -> Vec<&RunList> {
    s.arrangements.values().flat_map(|arrangement| [&arrangement.content, &arrangement.link]).chain(s.provenance.named_lists()).collect()
}

/// How many nodes the slice's checkpoint form writes: the table's count,
/// which leads its bytes.
fn table_nodes(bytes: &[u8]) -> usize {
    u64::from_le_bytes(bytes[..8].try_into().expect("eight bytes")) as usize
}

/// A draft of `runs` runs, then `versions` rounds of one change and a
/// snapshot kept, and a second document sharing nothing with it.
fn a_document_and_its_versions(runs: u32, versions: u32) -> M5State {
    let base_runs: Vec<Run> = (1..=runs).map(|k| run(&ca(2 * k), 1)).collect();
    let mut state = place(&M5State::genesis(), &doc1(), 1, base_runs);
    for j in 0..versions {
        let at = 1 + j * (runs / versions) + 7;
        let edit = M5Rec::ContentEdit { doc: doc1(), changes: vec![Splice { at: n(at), width: n(1), runs: vec![run(&pca(2 * j + 1), 1)] }] };
        state = state.apply_m5(Seq(u64::from(2 * j + 2)), &edit);
        state = state.apply_m5(Seq(u64::from(2 * j + 3)), &M5Rec::VersionSnapshot { source: doc1(), new: a(&[1, 0, 2, 0, 100 + j]) });
    }
    place(&state, &doc2(), 1, (1..=300).map(|k| run(&vca(2 * k), 1)).collect())
}

#[test]
fn the_checkpoint_form_writes_each_node_the_slices_lists_share_once() {
    // A document of 65,536 runs, ten versions each a change on from the
    // last — each a document of its own and a list R names — and a second
    // document sharing nothing: twenty-three lists, of which twenty-one hold
    // the first document's runs, whole. The checkpoint form writes exactly
    // the nodes those lists hold between them, each once, and is far under
    // the lists written whole; decoded, the slice is equal, shares every
    // node it shared, and holds as many nodes as the table has.
    let state = a_document_and_its_versions(1 << 16, 10);
    let lists = every_list(&state);
    assert_eq!(lists.iter().filter(|list| !list.is_empty()).count(), 22, "the document, its ten versions and their ten named lists, and the second document");
    let distinct = RunList::nodes_among(&lists);
    let bytes = bincode::serialize(&state).expect("the slice serializes");
    assert_eq!(table_nodes(&bytes), distinct, "the table holds each node the lists hold, once");
    // The lists' own bytes in each form. Written whole, a list is a count
    // and 104 bytes a run of these lists; in the checkpoint form it is a
    // root — one byte for the empty list, nine for any other — and its
    // nodes' share of the table. Everything else the two forms write alike.
    let by_runs = bincode::serialize(&state.as_run_sequences()).expect("the run-sequence form serializes");
    let whole: usize = lists.iter().map(|list| 8 + 104 * list.run_count()).sum();
    let roots: usize = lists.iter().map(|list| if list.is_empty() { 1 } else { 9 }).sum();
    let table = bytes.len() - (by_runs.len() - whole) - roots;
    let one_list = 8 + (1usize << 16) * 104;
    assert!(whole > 21 * one_list, "the lists written whole: {whole} bytes");
    assert!(table < one_list + one_list / 20, "the table: {table} bytes against one list's {one_list}");
    eprintln!("slice: 21 lists of 65,536 runs and one of 300: a table of {distinct} nodes in {table} bytes, {whole} bytes written whole");
    // Decoded: equal, and sharing as written — across the document, its
    // versions and the lists R names.
    let back: M5State = bincode::deserialize(&bytes).expect("the slice decodes");
    assert_eq!(back, state);
    assert_eq!(RunList::nodes_among(&every_list(&back)), distinct, "the decoded lists hold between them the table's nodes");
    for j in 0..10u32 {
        let version = a(&[1, 0, 2, 0, 100 + j]);
        let named = back.provenance.named_list(&version).expect("the version's named list");
        assert!(named.shares_root_with(back.content_list(&version)), "version {j} and its named list are one root after the decode");
        assert_eq!(back.content_list(&version).fill(), state.content_list(&version).fill(), "version {j} has the shape that was written");
    }
    assert!(back.content_list(&doc1()).shares_root_with(back.content_list(&a(&[1, 0, 2, 0, 109]))), "the document and its last version are one root");
    // A list R names whose version has since been edited away from it is
    // reached from R alone: it is in the table, and decodes equal.
    let first = a(&[1, 0, 2, 0, 100]);
    let moved_on = state.apply_m5(Seq(90), &M5Rec::ContentRemove { doc: first.clone(), from: n(1), width: n(40_000) });
    let named = moved_on.provenance.named_list(&first).expect("named").clone();
    assert!(!named.shares_root_with(moved_on.content_list(&first)));
    let back: M5State = bincode::deserialize(&bincode::serialize(&moved_on).expect("the slice serializes")).expect("the slice decodes");
    assert_eq!(back, moved_on);
    assert_eq!(back.provenance.named_list(&first), Some(&named), "the named list stands as it stood");
    assert_eq!(RunList::nodes_among(&every_list(&back)), RunList::nodes_among(&every_list(&moved_on)));
}

#[test]
fn the_checkpoint_form_is_a_function_of_the_records_folded() {
    // M2 names a checkpoint by the hash of its body, so the slice's bytes
    // are one byte string however the state was reached: folded twice from
    // one record stream; decoded and written again; decoded part way and
    // folded on, against a fold of the whole; and with a change made and
    // then reversed, whose path of nodes is new in memory and equal in
    // content to the one it replaced.
    let records = |upto: u32| -> Vec<(u64, M5Rec)> {
        let mut records = vec![(1, M5Rec::ContentPlace { doc: doc1(), at: n(1), runs: (1..=3_000u32).map(|k| run(&ca(2 * k), 1)).collect() })];
        for j in 0..upto {
            let at = 1 + (j * 211) % 2_900;
            let rec = match j % 5 {
                0 => M5Rec::ContentEdit { doc: doc1(), changes: vec![Splice { at: n(at), width: n(1), runs: vec![run(&pca(2 * j + 1), 2)] }] },
                1 => M5Rec::VersionSnapshot { source: doc1(), new: a(&[1, 0, 2, 0, 100 + j]) },
                2 => M5Rec::ContentRemove { doc: doc1(), from: n(at), width: n(3) },
                3 => M5Rec::ContentPlace { doc: doc1(), at: n(at), runs: vec![run(&vca(2 * j + 1), 1), run(&vca(2 * j + 9), 1)] },
                _ => M5Rec::ContentReorder { doc: doc1(), cut_ordinals: vec![n(at), n(at + 5), n(at + 40)] },
            };
            records.push((u64::from(j) + 2, rec));
        }
        records
    };
    let folded = |from: M5State, records: &[(u64, M5Rec)]| records.iter().fold(from, |s, (at, rec)| s.apply_m5(Seq(*at), rec));
    let all = records(60);
    // One record stream folded twice: one body.
    let (first, second) = (folded(M5State::genesis(), &all), folded(M5State::genesis(), &all));
    let bytes = bincode::serialize(&first).expect("the slice serializes");
    assert_eq!(bincode::serialize(&second).expect("the slice serializes"), bytes, "two folds of one record stream");
    assert!(first.content_list(&doc1()).height() >= 2, "the premise: a list of several levels");
    // Decoded and written again with no record between: the same body.
    let back: M5State = bincode::deserialize(&bytes).expect("the slice decodes");
    assert_eq!(bincode::serialize(&back).expect("the slice serializes"), bytes, "decoded and written again");
    // Decoded part way and folded on, against the fold of the whole — at
    // every cut of the stream.
    for cut in [1usize, 2, 7, 23, 40, 59] {
        let part = bincode::serialize(&folded(M5State::genesis(), &all[..cut])).expect("the slice serializes");
        let opened: M5State = bincode::deserialize(&part).expect("the slice decodes");
        assert_eq!(
            bincode::serialize(&folded(opened, &all[cut..])).expect("the slice serializes"),
            bytes,
            "opened after {cut} records and folded on, against the fold of the whole"
        );
    }
    // A change and its reversal: the document's list is the one a version
    // kept, in content, on nodes of its own along one path. The table
    // writes that path once.
    let kept = first.apply_m5(Seq(100), &M5Rec::VersionSnapshot { source: doc1(), new: a(&[1, 0, 2, 0, 99]) });
    let was = kept.content_list(&doc1()).point(&n(500)).expect("arranged");
    let changed = kept.apply_m5(Seq(101), &M5Rec::ContentEdit { doc: doc1(), changes: vec![Splice { at: n(500), width: n(1), runs: vec![run(&pca(9_001), 1)] }] });
    let reverted = changed.apply_m5(Seq(102), &M5Rec::ContentEdit { doc: doc1(), changes: vec![Splice { at: n(500), width: n(1), runs: vec![Run::new(was, n(1)).expect("a run")] }] });
    let (list, version) = (reverted.content_list(&doc1()), reverted.content_list(&a(&[1, 0, 2, 0, 99])));
    assert_eq!(list, version, "the change reversed leaves the version's runs");
    assert!(!list.shares_root_with(version) && list.made_anew(&[version]).0 >= 1, "the premise: on nodes of its own");
    assert_eq!(
        table_nodes(&bincode::serialize(&reverted).expect("the slice serializes")),
        table_nodes(&bincode::serialize(&kept).expect("the slice serializes")),
        "nodes equal in content at two addresses are one entry"
    );
    assert!(RunList::nodes_among(&every_list(&reverted)) > RunList::nodes_among(&every_list(&kept)));
}

