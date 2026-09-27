use num_traits::Zero;

use super::*;
use crate::testutil::{a, ca, doc1, doc2, la, n, run, vca, vdoc};
use crate::vspace::VPos;

fn place(s: &M5State, doc: &Address, at: u32, runs: Vec<Run>) -> M5State {
    s.apply_m5(&M5Rec::ContentPlace {
        doc: doc.clone(),
        at: n(at),
        runs,
    })
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
    let s = s.apply_m5(&M5Rec::ContentRemove {
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
    let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(1) });
    let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(2) });
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
        let out = s.apply_m5(&M5Rec::LinkSeat {
            doc: doc1(),
            link: link.clone(),
        });
        assert_eq!(out.link_count(&doc1()), n(0), "{link:?} is no run start");
        assert_eq!(out.link_runs(&doc1()).len(), 0, "{link:?}");
        // And the subspace is still seatable afterwards, which is what
        // dropping buys and placing would have cost permanently.
        let after = out.apply_m5(&M5Rec::LinkSeat {
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
    let ok = s.apply_m5(&M5Rec::LinkSeat {
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
    let s = s.apply_m5(&M5Rec::VersionSnapshot {
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
fn a_fork_appends_one_r_span_per_source_run_from_a_two_address_record() {
    // §7: the amplification `Vstream::version`'s cost note names. The
    // arrangement half is O(1) (structural im share); the R half is one
    // freshly-built span per source run, permanent (P2). The record that
    // commands it is two addresses WHATEVER the source holds, so M2's
    // MAX_TXN_BYTES weighs those two addresses and bounds the expansion
    // not at all — and replay re-reads the same two addresses to re-do it.
    // `ContentPlace` appends to R by the same mechanism and carries its
    // runs, so it is priced for them; that contrast is the finding, and it
    // is measured here rather than remembered. Corpus seed for the
    // fuzzing tier.
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
        let forked = s.apply_m5(&rec);
        assert_eq!(
            forked.content_runs(&vdoc()).collect::<Vec<_>>(),
            s.content_runs(&doc1()).collect::<Vec<_>>()
        );
        (
            s.content_runs(&doc1()).len(),
            fork_bytes,
            forked.provenance.ever_contained(&vdoc()).len(),
        )
    };
    // One R span per source run, at both sizes…
    assert_eq!(fork(2), (2, fork(2).1, 2));
    let (source_runs, fork_bytes, r_spans) = fork(64);
    assert_eq!((source_runs, r_spans), (64, 64));
    // …from a record whose size did not move between them.
    assert_eq!(fork_bytes, fork(2).1);
    // And the record that PAYS for what it commands, for contrast: the
    // same spans into R, carried.
    let placing_bytes = bincode::serialize(&M5Rec::ContentPlace {
        doc: doc1(),
        at: n(1),
        runs: runs(64),
    })
    .expect("the record encodes")
    .len();
    assert!(
        fork_bytes * 10 < placing_bytes,
        "a fork commands {r_spans} permanent R spans in {fork_bytes} bytes; \
         placing the same spans costs {placing_bytes}"
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
    let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(1) });
    let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(2) });
    assert_eq!(s.link_count(&doc1()), n(2));
    let s = s.apply_m5(&M5Rec::VersionSnapshot {
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
    let s = s.apply_m5(&M5Rec::VersionSnapshot {
        source: doc1(),
        new: vdoc(),
    });
    // The source grows…
    let s = place(&s, &doc1(), 3, vec![run(&ca(5), 1)]);
    // …and shrinks, after the fork was taken.
    let s = s.apply_m5(&M5Rec::ContentRemove {
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
    let s = s.apply_m5(&M5Rec::VersionSnapshot {
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
        let gone = s.apply_m5(&M5Rec::ContentRemove {
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
fn only_placement_and_version_append_to_r() {
    // §4/§6/§8: DELETE, REARRANGE and link seating leave R alone — P2 is
    // about never LOSING a pair, and J-LV uncouples link placement from R
    // altogether. No public read can witness this: R's denotation is the
    // set-union of its pairs, so a redundant append answers every query
    // identically and shows up only as unbounded growth. R itself has to
    // be compared directly.
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 4)]);
    let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(1) });
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
            s.apply_m5(&r).provenance,
            s.provenance,
            "{r:?} must not append to R"
        );
    }
    // The two that DO append, so the comparisons above cannot pass
    // vacuously — a `provenance` that had stopped changing at all would
    // satisfy them.
    let placed = s.apply_m5(&M5Rec::ContentPlace {
        doc: doc2(),
        at: n(1),
        runs: vec![run(&ca(1), 1)],
    });
    assert_ne!(placed.provenance, s.provenance);
    let forked = s.apply_m5(&M5Rec::VersionSnapshot {
        source: doc1(),
        new: vdoc(),
    });
    assert_ne!(forked.provenance, s.provenance);
}

#[test]
fn version_snapshot_of_an_empty_source_leaves_the_fork_absent() {
    // §7: n = 0 ⇒ no provenance append AND no arrangements entry — the
    // lazy absent-⇒-empty convention stays clean.
    let s0 = M5State::genesis();
    let s1 = s0.apply_m5(&M5Rec::VersionSnapshot {
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
    // arrangement as ONE placement at ordinal 1, so the first placement
    // naming `D.1` is its mint and the count it leaves is the birth
    // extent. Every later placement is a deposit the head took: the
    // arrangement grows (PUB-2.66) and the birth extent does not.
    let born = place(&M5State::genesis(), &vdoc(), 1, vec![run(&ca(1), 3)]);
    assert_eq!(born.birth_extent(&vdoc()), n(3));
    // An I-ADJACENT deposit, which is why the extent is noted at the mint
    // rather than read off the arrangement: the run-list merges the
    // deposit INTO the last birth run, so afterwards no run boundary marks
    // where the birth content ended.
    let grown = place(&born, &vdoc(), 4, vec![run(&ca(4), 1)]);
    assert_eq!(grown.content_runs(&vdoc()).cloned().collect::<Vec<_>>(), vec![run(&ca(1), 4)]);
    assert_eq!(grown.content_count(&vdoc()), n(4), "the head's arrangement grew");
    assert_eq!(grown.birth_extent(&vdoc()), n(3), "the birth content did not");
    // A second deposit, minted under the member's own content chain: the
    // same.
    let grown = place(&grown, &vdoc(), 5, vec![run(&vca(1), 1)]);
    assert_eq!(grown.content_count(&vdoc()), n(5));
    assert_eq!(grown.birth_extent(&vdoc()), n(3));
    // Purity: the state the deposit folded onto still answers its own.
    assert_eq!(born.content_count(&vdoc()), n(3));
}

#[test]
fn only_a_trunk_s_birth_version_has_its_extent_noted() {
    // `birth_extents` holds one entry per TRUNK, keyed by its birth
    // version `D.1` — the one address the doc-metadata read serves an
    // extent for. A trunk, a later trunk member, a daughter of the birth
    // version and the first daughter of a later member each take a
    // placement and note nothing:
    // the last is `first_version_address` of ITS anchor, which is why the
    // test asks the chain the TRUNK opens.
    let mut s = M5State::genesis();
    for doc in [
        doc1(),
        a(&[1, 0, 1, 0, 1, 2]),
        a(&[1, 0, 1, 0, 1, 1, 1]),
        a(&[1, 0, 1, 0, 1, 3, 1]),
    ] {
        s = place(&s, &doc, 1, vec![run(&ca(1), 2)]);
        assert_eq!(s.content_count(&doc), n(2));
        assert_eq!(s.birth_extent(&doc), n(0), "{doc:?} is no birth version");
    }
    assert!(
        s.birth_extents.is_empty(),
        "and `birth_extents` holds no entry for any of them"
    );
}

#[test]
fn a_snapshot_born_version_is_noted_at_what_it_shares_and_an_empty_birth_at_zero() {
    // An owned VERSION of a memberless published document mints the birth
    // version by `VersionSnapshot`: what it shares is what it is born with.
    let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 3)]);
    let s = s.apply_m5(&M5Rec::VersionSnapshot {
        source: doc1(),
        new: vdoc(),
    });
    assert_eq!(s.birth_extent(&vdoc()), n(3));
    let s = place(&s, &vdoc(), 4, vec![run(&ca(9), 1)]);
    assert_eq!((s.content_count(&vdoc()), s.birth_extent(&vdoc())), (n(4), n(3)));
    // The record is staged whatever the surface holds, so an EMPTY birth
    // is noted as zero — the arrangement and R still gain no entry — and
    // the version's first deposit then finds its extent already noted: a
    // home born with no content stays an edition of nothing (RES-130).
    let born_empty = M5State::genesis().apply_m5(&M5Rec::VersionSnapshot {
        source: doc2(),
        new: vdoc(),
    });
    assert_eq!(born_empty.birth_extents.get(&vdoc()), Some(&n(0)));
    assert!(born_empty.arrangements.get(&vdoc()).is_none());
    let deposited = place(&born_empty, &vdoc(), 1, vec![run(&ca(1), 1)]);
    assert_eq!(deposited.content_count(&vdoc()), n(1));
    assert_eq!(deposited.birth_extent(&vdoc()), n(0), "born empty, whatever it took since");
    // A cross-owner fork's `new` is a fresh DOCUMENT and notes nothing.
    let forked = s.apply_m5(&M5Rec::VersionSnapshot {
        source: doc1(),
        new: doc2(),
    });
    assert_eq!(forked.birth_extents, s.birth_extents);
}

#[test]
fn a_member_the_shot_minted_empty_is_the_one_state_the_fold_cannot_tell() {
    // THE RESIDUE BIRTH★ names, pinned so that whoever closes it meets
    // this test: a shot with no runs pushes NO placement, so an empty
    // shot-born member leaves nothing in this slice at its mint, and its
    // first DEPOSIT is the first placement the fold sees for it — the
    // same record, at the same ordinal, into the same absent arrangement
    // as a mint. It is noted as the birth. No conforming mint is empty
    // (PUB-3.11), and the snapshot arm's empty birth is exact (above).
    let minted_empty = M5State::genesis();
    assert_eq!(minted_empty.birth_extent(&vdoc()), n(0), "exact until a deposit lands");
    let deposited = place(&minted_empty, &vdoc(), 1, vec![run(&ca(1), 1)]);
    assert_eq!(deposited.birth_extent(&vdoc()), n(1), "the deposit, read as the birth");
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
        let out = s.apply_m5(&r);
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
        let s = s.apply_m5(&M5Rec::ContentRemove {
            doc: doc1(),
            from: n(2),
            width: n(1),
        });
        s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(1) })
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
    let born = place(&M5State::genesis(), &vdoc(), 1, vec![run(&ca(1), 3)]);
    let grown = place(&born, &vdoc(), 4, vec![run(&ca(4), 1)]);
    let bytes = bincode::serialize(&grown).expect("state serializes");
    let back: M5State = bincode::deserialize(&bytes).expect("state deserializes");
    assert_eq!(back, grown);
    assert_eq!(back.content_count(&vdoc()), n(4));
    assert_eq!(back.birth_extent(&vdoc()), n(3), "the frozen extent, not the live count");
    assert_eq!(back.clone().rebuild_derived(), back);
    // Replay re-derives them: the same records fold to the same birth
    // extents.
    let again = place(
        &place(&M5State::genesis(), &vdoc(), 1, vec![run(&ca(1), 3)]),
        &vdoc(),
        4,
        vec![run(&ca(4), 1)],
    );
    assert_eq!(bincode::serialize(&again).expect("serializes"), bytes);
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
    ] {
        let bytes = bincode::serialize(&rec).expect("record serializes");
        let back: M5Rec = bincode::deserialize(&bytes).expect("record deserializes");
        assert_eq!(back, rec, "the same record, not merely one folding alike");
        let folded = base.apply_m5(&rec);
        assert_ne!(folded, base, "{rec:?} changes the base it folds onto");
        assert_eq!(
            bincode::serialize(&folded).expect("serializes"),
            bincode::serialize(&base.apply_m5(&back)).expect("serializes"),
            "{rec:?}"
        );
    }
}
