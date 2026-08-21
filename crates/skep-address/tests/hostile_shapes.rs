//! Shapes a peer chooses rather than magnitudes a peer chooses: a width far
//! longer than its start, a tumbler separated to a depth no address reaches,
//! and span-sets at a size the sweeps are actually asked to carry. T0(b) and
//! T12 leave each of these dimensions unbounded, so what contains them is a
//! refusal somewhere else — and these pin the refusal at the size the wire can
//! reach rather than at the size a test author would type. Each case is a
//! candidate corpus seed for the daemon's fuzz targets, whose parsers hand
//! exactly these shapes to M1.

mod common;

use common::*;
use skep_address::*;

/// T12 bounds `#width` neither absolutely nor against `#start`, so a span
/// whose reach is orders of magnitude longer than its start is admissible —
/// and `reach()` recomputes that length at every membership test. What
/// contains the cost is that such a span is not level-uniform, so every
/// constructing operation refuses it rather than working on it. Both halves
/// are pinned here: admitted by T12, refused by the level gate at every door.
#[test]
fn a_width_far_longer_than_its_start_is_admitted_then_refused_by_the_level_gate() {
    let mut comps = vec![n(1)];
    comps.extend(std::iter::repeat_with(|| n(0)).take(511));
    let s = Span::new(t(&[1]), tumbler(comps)).expect("action point 1 ≤ #start");
    assert_eq!(s.reach().len(), 512); // derived on demand, at the width's length
    assert!(s.contains(&t(&[1])));
    assert!(!s.is_level_uniform());

    assert_eq!(intersect(&s, &s), Err(LevelMismatch));
    assert_eq!(merge(&s, &s), Err(LevelMismatch));
    assert_eq!(difference(&s, &s), Err(LevelMismatch));
    assert_eq!(split(&s, &t(&[1])), Err(SplitError::LevelMismatch));
    let set = SpanSet::singleton(s);
    assert_eq!(set.level_class(), Err(LevelMismatch));
    assert_eq!(set.normalize(), Err(LevelMismatch));
    assert_eq!(canonical_key(&set), Err(LevelMismatch));
}

/// T0(b) leaves the component count unbounded, and the validating scan is one
/// pass with O(1) carried state and no early exit precisely so that garbage of
/// any depth classifies rather than faults or wraps a level. Asserted at a
/// depth three orders past T4's ceiling, where a fixed-width separator counter
/// would have wrapped long since.
#[test]
fn a_deeply_separated_tumbler_classifies_without_faulting() {
    // 2047 alternating components `1.0.1.….1`: 1023 separators, and no
    // leading, trailing or adjacent zero, so OverDepth is the only clause.
    let garbage = tumbler((0..2047).map(|i| if i % 2 == 0 { n(1) } else { n(0) }));
    assert_eq!(zeros(&garbage), 1023); // the true count, never a wrapped level
    assert!(!is_t4_valid(&garbage));
    assert_eq!(classify(&garbage), Class::Invalid);
    assert_eq!(
        validate(garbage.clone()).unwrap_err().clauses(),
        &[T4Clause::OverDepth][..]
    );
    // Order and rendering are total at this depth too.
    assert!(garbage > t(&[1]));
    assert_eq!(garbage.to_string().matches('.').count(), 2046);
}

/// The two set-level sweeps interleave two canonical forms, and their cursor
/// logic decides which pieces are emitted: `difference_sets`' outer cursor
/// advances for good across a-spans, so a cursor that ran past a still-relevant
/// b-span changes the answer rather than merely the cost. Two thousand cursor
/// advances of sustained alternation is what this size buys — nothing else runs
/// the sweeps long enough for an off-by-one that only manifests after many
/// crossings to surface.
#[test]
fn the_set_sweeps_interleave_a_thousand_spans_apiece_without_losing_pieces() {
    let a: SpanSet = (0..1000u32).map(|i| sp(&[4 * i + 1], &[4 * i + 3])).collect();
    let b: SpanSet = (0..1000u32).map(|i| sp(&[4 * i + 2], &[4 * i + 4])).collect();
    assert!(a.is_normalized() && b.is_normalized());
    let both = intersect_sets(&a, &b).unwrap();
    let only_a = difference_sets(&a, &b).unwrap();
    assert_eq!(both.len(), 1000); // `[4i+2, 4i+3)` apiece
    assert_eq!(only_a.len(), 1000); // `[4i+1, 4i+2)` apiece
    assert!(both.is_normalized() && only_a.is_normalized());
    // The carve's fan-out, at the size that would expose a sweep emitting a
    // piece per crossing pair rather than per split.
    assert!(only_a.len() <= a.len() + b.len());
}
