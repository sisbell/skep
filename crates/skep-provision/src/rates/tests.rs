//! THE RATES, over instants the suite chooses: an edge opened once, every
//! meeting inside it counted, its end said once a hold-down past its last
//! meeting with the count and the span, a meeting after it opening the next;
//! a stranger's event said once a stretch, the count of like ones riding the
//! next one said, its line built only where it is said; and a count said
//! with its noun.

use std::cell::Cell;

use super::*;

/// THE EDGE: nothing passes where nothing stands; the first meeting opens
/// it, a second inside it is counted and says nothing; a pass inside the
/// hold-down after the LAST meeting ends nothing; the first pass a hold-down
/// past it ends it once, with both meetings and the span between them; a
/// pass after that ends nothing more, and a meeting after it opens the next
/// episode, whose lone meeting says no span.
#[test]
fn an_edge_is_said_as_it_opens_and_once_as_it_ends() {
    assert_eq!(HOLD_DOWN, Duration::from_secs(15), "skepd's EDGE_HOLD_DOWN");
    let edge = Edge::default();
    let t0 = Instant::now();
    let ms = Duration::from_millis;
    assert_eq!(edge.passed(t0), None, "nothing stands");
    assert!(edge.met(t0), "the first meeting opens the episode");
    assert!(!edge.met(t0 + ms(10)), "a second meeting is counted, said never");
    assert_eq!(edge.passed(t0 + HOLD_DOWN), None, "a hold-down past the first meeting, not the last");
    let ended = edge.passed(t0 + ms(10) + HOLD_DOWN).expect("a hold-down past the last meeting");
    assert_eq!(ended, Ended { met: 2, over: ms(10) });
    assert_eq!((ended.count("post", "posts"), ended.across()), ("2 posts".to_owned(), ", across 10 ms".to_owned()));
    assert_eq!(edge.passed(t0 + ms(20) + HOLD_DOWN), None, "ended: said once");
    assert!(edge.met(t0 + ms(30) + HOLD_DOWN), "the next episode opens, said again");
    let lone = edge.passed(t0 + ms(30) + HOLD_DOWN + HOLD_DOWN).expect("its end");
    assert_eq!((lone.count("post", "posts"), lone.across()), ("1 post".to_owned(), String::new()), "one meeting says no span");
}

/// THE STRETCH: its first event said, with the rule; every like one within
/// a minute of the last said counted, its line never built; the first a
/// minute on said with the count of those between; and one a minute after
/// that, with none between, says the rule again.
#[test]
fn a_strangers_event_is_said_once_a_stretch_with_the_count_between() {
    assert_eq!(STRETCH, Duration::from_secs(60), "a minute");
    let stretch = Stretch::default();
    let t0 = Instant::now();
    let built = Cell::new(0);
    let line = || {
        built.set(built.get() + 1);
        "a post refused: no invite code of the code's form".to_owned()
    };
    let rule = "a post refused: no invite code of the code's form — like ones are said at most once a minute, with their count";
    assert_eq!(stretch.said(t0, line).as_deref(), Some(rule));
    for at in 1..=3 {
        assert_eq!(stretch.said(t0 + Duration::from_secs(at), line), None, "inside the stretch");
    }
    assert_eq!(built.get(), 1, "a line counted was built");
    assert_eq!(stretch.said(t0 + STRETCH, line).as_deref(), Some("a post refused: no invite code of the code's form — 3 more since the last said"));
    assert_eq!(stretch.said(t0 + STRETCH + STRETCH, line).as_deref(), Some(rule), "none between: the rule again");
    assert_eq!(built.get(), 3);
}

/// A COUNT is said with its noun, one apart from many.
#[test]
fn a_count_is_said_with_its_noun() {
    assert_eq!([counted(0, "volume", "volumes"), counted(1, "volume", "volumes"), counted(2, "volume", "volumes")], ["0 volumes", "1 volume", "2 volumes"]);
}
