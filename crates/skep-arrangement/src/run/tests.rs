use std::collections::HashSet;

use skep_address::subtree_of;

use super::*;
use crate::testutil::{a, ca, n, t, vca};

#[test]
fn new_rejects_width_zero_and_starts_that_are_not_full_element_positions() {
    // Interface: Err ⇔ width == 0 ∨ the element field is not exactly
    // [subspace, ordinal], and the verdict names the clause broken.
    let bad_start = Err(RunError::NotAnElementPosition);
    assert_eq!(Run::new(ca(1), n(0)), Err(RunError::ZeroWidth));
    assert_eq!(Run::new(a(&[1, 0, 1, 0, 1]), n(1)), bad_start); // Document, zeros = 2
    assert_eq!(Run::new(a(&[1, 0, 1]), n(1)), bad_start); // Account, zeros = 1
    // The starts element level alone would have admitted. A SUBSPACE BASE
    // `doc·0·s`: T4-valid, zeros = 3, `subspace()` answers — and its last
    // component is the subspace id, so `tumbler_at(1)` would advance
    // content → link (M1's TA7a) and `iextent` would cover the whole
    // subspace rather than one position.
    assert_eq!(a(&[1, 0, 1, 0, 1, 0, 1]).level(), skep_address::Level::Element);
    assert_eq!(Run::new(a(&[1, 0, 1, 0, 1, 0, 1]), n(1)), bad_start); // content base
    assert_eq!(Run::new(a(&[1, 0, 1, 0, 1, 0, 2]), n(1)), bad_start); // link base
    // And a field T7 leaves open to further subdivision, whose last
    // component is not an ordinal either.
    assert_eq!(Run::new(a(&[1, 0, 1, 0, 1, 0, 1, 2, 3]), n(1)), bad_start);
    // Both clauses broken: the width is asked first, as `Run::new` states,
    // so the verdict does not depend on which bad start it is.
    assert_eq!(Run::new(a(&[1, 0, 1, 0, 1]), n(0)), Err(RunError::ZeroWidth));
    let r = Run::new(ca(3), n(2)).expect("a full element position with width ≥ 1 is admitted");
    assert_eq!(r.i_start(), &ca(3));
    assert_eq!(r.width(), &n(2));
}

#[test]
fn iextent_is_the_half_open_ordinal_shift_span() {
    // §2: [i_start, shift(i_start, width)) — level-uniform, element-level.
    let r = Run::new(ca(2), n(3)).expect("valid run");
    let s = r.iextent();
    assert_eq!(s.start(), ca(2).tumbler());
    assert_eq!(s.reach(), *ca(5).tumbler()); // ordinal 2 + width 3
    assert!(s.is_level_uniform());
    assert!(s.contains(ca(2).tumbler()));
    assert!(s.contains(ca(4).tumbler()));
    assert!(!s.contains(ca(5).tumbler())); // half-open
}

#[test]
fn a_run_answers_for_its_own_positions() {
    // §A: offset 0 is the start, offset k the k-th position, and `reach`
    // is one I-step past the last — the same tumbler offset `width`
    // names, asked without an offset, which is why it is the published
    // form. addr_at re-validates what the shift advances.
    let r = Run::new(ca(2), n(3)).expect("valid run");
    assert_eq!(r.addr_at(&n(0)), ca(2));
    assert_eq!(r.addr_at(&n(2)), ca(4));
    assert_eq!(r.reach(), *ca(5).tumbler());
    assert_eq!(r.reach(), r.tumbler_at(&n(3)));
    // And it is the I-extent's own upper endpoint, which is what makes the
    // lift the run's two endpoints and nothing derived twice.
    assert_eq!(r.iextent().reach(), r.reach());
}

#[test]
fn a_run_hashes_on_its_start_and_width() {
    // §A: a run's identity is its start AND its width, and a set keyed on
    // runs keys on both — two runs sharing a start and differing in width
    // are two runs, and an exact repeat is one. The distinction a key that
    // dropped the width would lose is held where the identity lives.
    let runs: HashSet<Run> = [
        Run::new(ca(1), n(1)).expect("valid run"),
        Run::new(ca(1), n(2)).expect("valid run"),
        Run::new(ca(1), n(2)).expect("valid run"),
    ]
    .into_iter()
    .collect();
    assert_eq!(runs.len(), 2);
    assert!(runs.contains(&Run::new(ca(1), n(1)).expect("valid run")));
    assert!(runs.contains(&Run::new(ca(1), n(2)).expect("valid run")));
}

#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "run offset past the reach")]
fn asking_a_run_past_its_reach_is_the_callers_bug_and_stops() {
    // §A: `k ≤ width` is the caller's obligation, and past it there is no
    // honest value to return — `addr_at(width + 2)` would be a T4-valid
    // element address two positions OUTSIDE the run, indistinguishable
    // from one the run holds. A precondition violation is the caller's
    // bug, so it stops rather than answering.
    let r = Run::new(ca(2), n(3)).expect("valid run");
    let _ = r.addr_at(&n(5));
}

#[test]
fn addrs_enumerates_the_half_open_offset_range() {
    // §A: the run's own sequence — offsets [0, width), never the reach.
    let r = Run::new(ca(2), n(3)).expect("valid run");
    assert_eq!(r.addrs().collect::<Vec<_>>(), vec![ca(2), ca(3), ca(4)]);
    // A width-1 run yields exactly its start.
    let one = Run::new(ca(7), n(1)).expect("valid run");
    assert_eq!(one.addrs().collect::<Vec<_>>(), vec![ca(7)]);
    // Every yielded address is the run's own addr_at of that offset.
    assert!(r
        .addrs()
        .enumerate()
        .all(|(k, a)| a == r.addr_at(&n(k as u32))));
}

#[test]
fn taking_the_run_yields_the_same_sequence_as_borrowing_it() {
    // §A: the owned form is the shape `resolve` hands back — a
    // `Vec<Run>` flat-mapped to addresses — and it must denote exactly
    // what the borrowing form does, since the two carry the same body for
    // the reason stated on `into_addrs` rather than one calling the other.
    let r = Run::new(ca(2), n(3)).expect("valid run");
    let borrowed: Vec<_> = r.addrs().collect();
    assert_eq!(r.clone().into_addrs().collect::<Vec<_>>(), borrowed);
    assert_eq!(borrowed, vec![ca(2), ca(3), ca(4)]);
    // Width 1, and the flat-map over owned runs that motivates it.
    let one = Run::new(ca(7), n(1)).expect("valid run");
    assert_eq!(one.into_addrs().collect::<Vec<_>>(), vec![ca(7)]);
    let runs = vec![
        Run::new(ca(1), n(2)).expect("valid run"),
        Run::new(vca(1), n(1)).expect("valid run"),
    ];
    assert_eq!(
        runs.into_iter().flat_map(Run::into_addrs).collect::<Vec<_>>(),
        vec![ca(1), ca(2), vca(1)]
    );
}

#[test]
fn offsets_covered_by_answers_in_both_branches() {
    // §2: a same-length level-uniform cover goes through M1's intersect;
    // any other cover takes the total boundary search. Both name the
    // run's own half-open offset range.
    let r = Run::new(ca(2), n(3)).expect("valid run"); // ca(2), ca(3), ca(4)
    let inner = Run::new(ca(3), n(1)).expect("valid run").iextent();
    assert_eq!(
        r.offsets_covered_by(&inner),
        Some(OffsetRange { lo: n(1), hi: n(2) })
    );
    // The two quantities the I→V read takes off a range: where it opens,
    // and how many of the run's positions it names — the second derived by
    // the range from its own two bounds, so `project` does not subtract them
    // itself, and the width reaches exactly the bound it was taken from.
    let range = r.offsets_covered_by(&inner).expect("the cover is nonempty");
    assert_eq!(range.lo(), &n(1));
    assert_eq!(range.width(), n(1));
    assert_eq!(range.hi, n(2));
    assert_eq!(range.hi, range.lo() + &range.width());
    let apart = Run::new(ca(9), n(1)).expect("valid run").iextent();
    assert_eq!(r.offsets_covered_by(&apart), None);
    // Cross-length fallback: doc1's content-base subtree covers every
    // length-8 ca(·)…
    let base = subtree_of(&t(&[1, 0, 1, 0, 1, 0, 1]));
    assert_eq!(
        r.offsets_covered_by(&base),
        Some(OffsetRange { lo: n(0), hi: n(3) })
    );
    // …and none of the fork's length-9 elements.
    let forked = Run::new(vca(1), n(2)).expect("valid run");
    assert_eq!(forked.offsets_covered_by(&base), None);
    // The fallback's OTHER entry condition: a span at the run's own
    // endpoint length that is not level-uniform. M1's `intersect` gates
    // on uniformity as well as on length, so this span would fault the
    // same-class branch — and it covers only PART of the run, which is
    // the contiguous-subset half of the claim. `[ca(3), [2])` opens at
    // the run's second position and reaches past its last.
    let partial = Span::new(ca(3).tumbler().clone(), t(&[1])).expect("T12: action point 1 ≤ 8");
    assert_eq!(partial.start().len(), r.i_start.tumbler().len());
    assert!(!partial.is_level_uniform());
    assert_eq!(
        r.offsets_covered_by(&partial),
        Some(OffsetRange { lo: n(1), hi: n(3) })
    );
}

#[test]
fn offsets_covered_by_names_exactly_the_positions_the_span_contains() {
    // §2: the answer is a LAW over covering spans, and the oracle is the
    // span's own membership — for every span, the range must be exactly
    // the offsets whose address it contains. The same-length
    // level-uniform family is small enough to exhaust, and it is the
    // branch the worked example above visits only strictly INSIDE the
    // run: the equal case, a span opening before the run and one
    // reaching past it are all cases M1's `intersect` CLIPS, and the
    // clipping is what those offsets are derived from. The second family
    // is non-uniform at the run's own length, which takes the boundary
    // search, and it walks that search's every boundary.
    let r = Run::new(ca(4), n(3)).expect("valid run"); // ca4, ca5, ca6
    let check = |span: &Span, label: String| {
        let covered: Vec<Nat> = (0..3u32)
            .map(n)
            .filter(|k| span.contains(r.addr_at(k).tumbler()))
            .collect();
        match r.offsets_covered_by(span) {
            None => assert!(
                covered.is_empty(),
                "{label}: covers offsets {covered:?}, answered None"
            ),
            Some(range) => {
                assert!(
                    !covered.is_empty(),
                    "{label}: covers no offset, answered {range:?}"
                );
                assert_eq!(
                    range.lo(),
                    &covered[0],
                    "{label}: opens at the first covered offset"
                );
                assert_eq!(
                    range.width(),
                    n(covered.len() as u32),
                    "{label}: names as many positions as the span contains"
                );
                // Contiguity, the other half of the claim: the covered
                // subset of a run is one unbroken offset range.
                let last = covered.last().expect("nonempty");
                assert_eq!(
                    &covered[0] + &range.width(),
                    last + &n(1),
                    "{label}: the covered offsets are contiguous"
                );
            }
        }
    };
    // Level-uniform at the run's own length ⇒ the intersect branch. 45
    // spans: before, abutting, overlapping either end, equal, containing.
    for lo in 1..=9u32 {
        for hi in lo + 1..=10u32 {
            let span = Span::from_endpoints(ca(lo).tumbler().clone(), ca(hi).tumbler())
                .expect("lo < hi at one length ⇒ well-formed");
            check(&span, format!("[ca{lo}, ca{hi})"));
        }
    }
    // Same length, NOT level-uniform ⇒ the boundary-search branch, whose
    // reach is [2] — every length-8 address at or after ca(k) is covered.
    for k in 1..=9u32 {
        let span = Span::new(ca(k).tumbler().clone(), t(&[1])).expect("T12: action point 1 ≤ 8");
        assert!(!span.is_level_uniform());
        check(&span, format!("[ca{k}, [2])"));
    }
}

#[test]
fn run_survives_a_bincode_round_trip() {
    // §A: Run is a journaled type (inside ContentPlace); bincode is M2's
    // actual wire format.
    let r = Run::new(ca(7), n(4)).expect("valid run");
    let bytes = bincode::serialize(&r).expect("run serializes");
    let back: Run = bincode::deserialize(&bytes).expect("run deserializes");
    assert_eq!(back, r);
    assert_eq!(back.i_start(), &ca(7));
    assert_eq!(back.width(), &n(4));
}

#[test]
fn decoding_a_run_re_enters_the_constructor() {
    // §A: the invariants the position arithmetic's `.expect`s stand on
    // are the TYPE's, so the decode path is the constructor. A field pair
    // no `Run::new` would admit is refused as a decode failure — which
    // M2 reports as checkpoint corruption — rather than admitted as a
    // value that panics `iextent` on the next fold to touch it.
    //
    // The bytes are made by encoding the shadow, which is the exact
    // field-by-field form a corrupt journal would present.
    #[derive(Serialize)]
    struct Wire {
        i_start: Address,
        width: Nat,
    }
    let zero = bincode::serialize(&Wire {
        i_start: ca(7),
        width: n(0),
    })
    .expect("the shadow encodes");
    let refused = bincode::deserialize::<Run>(&zero).expect_err("width 0 is not a run");
    // The corruption report names the clause the bytes broke: the
    // decoder's message is the constructor's own verdict.
    assert!(refused.to_string().contains(&RunError::ZeroWidth.to_string()), "{refused}");
    let document = bincode::serialize(&Wire {
        i_start: a(&[1, 0, 1, 0, 1]),
        width: n(1),
    })
    .expect("the shadow encodes");
    let refused = bincode::deserialize::<Run>(&document)
        .expect_err("a document-level start is not a run start");
    assert!(
        refused.to_string().contains(&RunError::NotAnElementPosition.to_string()),
        "{refused}"
    );
    let base = bincode::serialize(&Wire {
        i_start: a(&[1, 0, 1, 0, 1, 0, 2]),
        width: n(1),
    })
    .expect("the shadow encodes");
    assert!(
        bincode::deserialize::<Run>(&base).is_err(),
        "a subspace base is element-level and still not a run start"
    );
    // The door costs the encoding nothing: a well-formed field pair
    // encodes to exactly the bytes `Run` itself writes, so the shadow is
    // a check on the decode path and not a second wire format.
    let good = Run::new(ca(7), n(4)).expect("valid run");
    assert_eq!(
        bincode::serialize(&Wire {
            i_start: ca(7),
            width: n(4)
        })
        .expect("the shadow encodes"),
        bincode::serialize(&good).expect("the run encodes")
    );
}
