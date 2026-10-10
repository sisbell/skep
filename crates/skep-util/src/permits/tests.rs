use super::*;

/// A hold-down the claims below measure against: whole seconds, so each
/// instant in a claim is a figure a reader can check by hand.
const HOLD_DOWN: Duration = Duration::from_secs(15);

/// An instant `secs` after `origin`.
fn at(origin: Instant, secs: u64) -> Instant {
    origin + Duration::from_secs(secs)
}

/// The edges queued on `tracker`, drained in order.
fn drained(tracker: &EdgeTracker) -> Vec<Edge> {
    let mut edges = Vec::new();
    tracker.drain(|edge| edges.push(edge));
    edges
}

/// The pool: exactly `n` permits, the next refused rather than queued, and a
/// drop returning exactly one slot.
#[test]
fn a_pool_hands_out_exactly_its_count_and_a_drop_returns_one_slot() {
    let pool = Permits::new(2);
    let first = pool.try_acquire().expect("permit 1 of 2");
    let second = pool.try_acquire().expect("permit 2 of 2");
    assert!(pool.try_acquire().is_none(), "the pool is exactly two");
    drop(first);
    let third = pool.try_acquire().expect("a dropped permit reopens its slot");
    assert!(pool.try_acquire().is_none(), "exactly one slot came back");
    drop((second, third));
}

/// m12 — THE FIRST EDGE, ONCE: the first refusal opens an episode and is
/// the failure edge; every later refusal inside it is no edge, however many.
#[test]
fn the_first_refusal_is_the_failure_edge_and_later_ones_inside_the_episode_are_none() {
    let tracker = EdgeTracker::new(HOLD_DOWN);
    let t0 = Instant::now();
    assert_eq!(tracker.refused(t0), Some(Edge::Failure), "the request that first meets the bound");
    for secs in 1..=5 {
        assert_eq!(
            tracker.refused(at(t0, secs)),
            None,
            "a refusal inside the episode, {secs} s in"
        );
    }
}

/// m12 — THE SECOND EDGE AFTER THE HOLD-DOWN, MEASURED FROM THE LAST
/// REFUSAL: an admission short of the hold-down lands nothing; a refusal
/// inside it adds no edge and RESTARTS the hold-down, so an admission a
/// whole hold-down past the FIRST refusal but not the last still lands
/// nothing; the admission a whole hold-down past the last refusal is the
/// landing, carrying the episode's refusals; and the next refusal after it
/// opens a new episode with a new failure edge.
#[test]
fn the_landing_is_a_hold_down_after_the_last_refusal_and_the_next_refusal_opens_anew() {
    let tracker = EdgeTracker::new(HOLD_DOWN);
    let t0 = Instant::now();
    assert_eq!(tracker.refused(t0), Some(Edge::Failure));
    assert_eq!(tracker.admitted(at(t0, 10)), None, "short of the hold-down");
    assert_eq!(tracker.refused(at(t0, 10)), None, "a refusal inside the hold-down: no edge");
    assert_eq!(
        tracker.admitted(at(t0, 20)),
        None,
        "a hold-down past the first refusal is not one past the last: the refusal restarted it"
    );
    assert_eq!(tracker.admitted(at(t0, 24)), None, "still a second short");
    assert_eq!(
        tracker.admitted(at(t0, 25)),
        Some(Edge::Landing { refusals: 2 }),
        "a whole hold-down past the last refusal: the landing, with the episode's two refusals"
    );
    assert_eq!(tracker.admitted(at(t0, 26)), None, "no episode stands: an admission is no edge");
    assert_eq!(tracker.refused(at(t0, 26)), Some(Edge::Failure), "the next refusal opens anew");
    assert_eq!(
        tracker.admitted(at(t0, 41)),
        Some(Edge::Landing { refusals: 1 }),
        "the new episode counts from one"
    );
}

/// A refusal NEVER lands, however long after the last: a landing says the
/// condition is clear, and only an admitted act shows it so — the refusal
/// an hour later is read as the same episode, continuing, and the landing
/// comes at the next admission a hold-down after it.
#[test]
fn a_refusal_however_late_never_lands_and_the_episode_continues_through_it() {
    let tracker = EdgeTracker::new(HOLD_DOWN);
    let t0 = Instant::now();
    assert_eq!(tracker.refused(t0), Some(Edge::Failure));
    assert_eq!(tracker.refused(at(t0, 3_600)), None, "an hour later: no landing, no new failure");
    assert_eq!(
        tracker.admitted(at(t0, 3_600 + 14)),
        None,
        "the hold-down counts from that refusal"
    );
    assert_eq!(tracker.admitted(at(t0, 3_600 + 15)), Some(Edge::Landing { refusals: 2 }));
}

/// The quiet holder (the ops lanes record §5.3, the challenge pair's
/// property): with an episode open and no act for an hour, the landing comes
/// at the next admission, however late — nothing lands by itself.
#[test]
fn on_a_quiet_holder_the_landing_comes_at_its_next_admission_however_late() {
    let tracker = EdgeTracker::new(HOLD_DOWN);
    let t0 = Instant::now();
    assert_eq!(tracker.refused(t0), Some(Edge::Failure));
    assert_eq!(
        drained(&tracker),
        [],
        "nothing is queued by itself: an edge is the holder's to queue"
    );
    assert_eq!(tracker.admitted(at(t0, 3_600)), Some(Edge::Landing { refusals: 1 }));
}

/// A fresh tracker admits with no edge; a clock that reads before the last
/// refusal reads as no time passed, so it lands nothing.
#[test]
fn an_admission_with_no_episode_is_no_edge_and_a_clock_gone_backwards_lands_nothing() {
    let tracker = EdgeTracker::new(HOLD_DOWN);
    let t0 = Instant::now() + Duration::from_secs(100);
    assert_eq!(tracker.admitted(t0), None);
    assert_eq!(tracker.refused(t0), Some(Edge::Failure));
    assert_eq!(
        tracker.admitted(t0 - Duration::from_secs(50)),
        None,
        "before the refusal: no time passed"
    );
    assert_eq!(tracker.admitted(at(t0, 15)), Some(Edge::Landing { refusals: 1 }));
    assert_eq!(tracker.hold_down(), HOLD_DOWN);
}

/// THE QUEUE: the edges a holder leaves for a later door drain in the order
/// they were queued, once; `None` queues nothing; a drained tracker drains
/// nothing more.
#[test]
fn queued_edges_drain_in_order_and_once() {
    let tracker = EdgeTracker::new(HOLD_DOWN);
    let t0 = Instant::now();
    tracker.queue(tracker.refused(t0));
    tracker.queue(tracker.refused(at(t0, 1)));
    tracker.queue(tracker.admitted(at(t0, 2)));
    tracker.queue(tracker.admitted(at(t0, 16)));
    tracker.queue(tracker.refused(at(t0, 17)));
    assert_eq!(
        drained(&tracker),
        [Edge::Failure, Edge::Landing { refusals: 2 }, Edge::Failure],
        "the edges crossed, in order; the acts that crossed none queued nothing"
    );
    assert_eq!(drained(&tracker), [], "drained once");
}

/// THE POOL LINES (m12), the ruled words: `the {pool} pool is saturated` and
/// `the {pool} pool has room again`, no digit on either; the counted form's
/// landing alone carries ` after {n} refusals`, its failure none.
#[test]
fn a_pools_two_lines_carry_the_ruled_words_and_a_count_on_the_counted_landing_alone() {
    let landing = Edge::Landing { refusals: 3 };
    assert_eq!(
        PoolEdgeLine::new("history", Edge::Failure).to_string(),
        "the history pool is saturated"
    );
    assert_eq!(
        PoolEdgeLine::new("history", landing).to_string(),
        "the history pool has room again"
    );
    assert_eq!(
        PoolEdgeLine::counted("upload", Edge::Failure).to_string(),
        "the upload pool is saturated"
    );
    assert_eq!(
        PoolEdgeLine::counted("upload", landing).to_string(),
        "the upload pool has room again after 3 refusals"
    );
    for line in [
        PoolEdgeLine::new("scan", Edge::Failure).to_string(),
        PoolEdgeLine::new("scan", landing).to_string(),
        PoolEdgeLine::counted("upload", Edge::Failure).to_string(),
    ] {
        assert!(!line.chars().any(|c| c.is_ascii_digit()), "no digit rides it: {line}");
    }
}

/// Each edge takes the door's class word: the failure edge `failure:`, the
/// landing `landing:`.
#[test]
fn each_edge_takes_the_doors_class_word() {
    assert_eq!(Edge::Failure.class(), Class::Failure);
    assert_eq!(Edge::Landing { refusals: 1 }.class(), Class::Landing);
    assert_eq!(Edge::Failure.class().to_string(), "failure");
    assert_eq!(Edge::Landing { refusals: 9 }.class().to_string(), "landing");
}

/// THE CLOCK SEAM: a reading after an advance stands at least the advance
/// past a reading before it, and never behind the monotonic clock. Another
/// thread advancing meanwhile can only widen the gap, so the claim holds
/// however the process's tests interleave.
#[test]
fn the_edge_clock_advances_by_the_seams_offset_and_never_runs_behind_the_monotonic_clock() {
    let before = edge_clock_now();
    assert!(before >= Instant::now() - Duration::from_secs(1), "at or past the monotonic clock");
    advance_edge_clock_ms(1_500);
    let after = edge_clock_now();
    assert!(
        after.saturating_duration_since(before) >= Duration::from_millis(1_500),
        "the advance moved the reading: {:?}",
        after.saturating_duration_since(before)
    );
}
