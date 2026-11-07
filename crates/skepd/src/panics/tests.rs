use std::panic::{self, Location};
use std::thread;
use std::time::{Duration, Instant};

use super::*;

/// The interval every claim here runs on: the standing line's hour.
const HOUR: Duration = Duration::from_secs(3600);

/// The one panic the router raises by design, as its site reads.
const ENTROPY: &str = "crates/skep-core/src/auth/entropy.rs:46:9";

/// Checks that a condition's first panic is said and its later ones counted.
///
/// The first is `Some(0)`; two more inside the interval are counted; the
/// same site under another route, and under none, are each a first; the
/// first past the interval carries the two counted, and the interval runs
/// again from it. Through the process's door, a panic of one condition on
/// another thread is counted, never a first: the thread is no part of it.
#[test]
fn a_conditions_first_panic_is_said_and_each_later_one_counted_until_its_interval_passes() {
    let t0 = Instant::now();
    let secs = |s| t0 + Duration::from_secs(s);
    let challenge = Some(RouteName::known("GET", "/challenge"));
    let session = Some(RouteName::known("POST", "/session"));
    let at = |route| (ENTROPY.to_string(), route);
    let mut tally = Tally::new();
    assert_eq!(tally.admit(at(challenge), t0, HOUR), Some(0), "the condition's first panic");
    for s in 1..=2 {
        assert_eq!(tally.admit(at(challenge), secs(s), HOUR), None, "counted, unsaid");
    }
    assert_eq!(tally.admit(at(session), secs(3), HOUR), Some(0), "another route is its own");
    assert_eq!(tally.admit(at(None), secs(4), HOUR), Some(0), "no route is its own too");
    assert_eq!(tally.admit(at(challenge), t0 + HOUR, HOUR), Some(2), "the two counted");
    assert_eq!(
        tally.admit(at(challenge), t0 + HOUR + Duration::from_secs(1), HOUR),
        None,
        "the interval runs again from that line"
    );
    let here = Location::caller();
    let first = admit_panic(Some(here)).expect("a site's first panic is said");
    assert_eq!((first.site(), first.route(), first.repeats()), (&*here.to_string(), None, 0));
    let elsewhere = thread::spawn(move || admit_panic(Some(here))).join().expect("a thread");
    assert_eq!(elsewhere, None, "the same condition on another thread is counted");
}

/// Checks that the tick takes each count once and forgets only quiet ones.
///
/// Each count is answered once, sorted by site whatever order the panics
/// came in, and a second take answers nothing. A condition said and then
/// quiet for an interval is forgotten, so its next panic is a first; one
/// said less than an interval ago stands, so its next panic is counted.
#[test]
fn the_tick_takes_each_count_once_and_forgets_only_a_condition_quiet_for_an_interval() {
    let t0 = Instant::now();
    let secs = |s| t0 + Duration::from_secs(s);
    let op = Some(RouteName::known("POST", "/op"));
    let a = || ("a.rs:1:1".to_string(), None);
    let b = || ("b.rs:2:2".to_string(), op);
    let c = || ("c.rs:3:3".to_string(), None);
    let mut tally = Tally::new();
    for s in 0..2 {
        tally.admit(b(), secs(s), HOUR);
    }
    for s in 2..5 {
        tally.admit(a(), secs(s), HOUR);
    }
    assert_eq!(tally.admit(c(), secs(5), HOUR), Some(0), "said, and nothing counted");
    assert_eq!(
        tally.take_unsaid(secs(10), HOUR).to_string(),
        "2 more panics at a.rs:1:1 since its last line; 1 more panics at b.rs:2:2 while \
         serving POST /op since its last line",
        "each count, by site"
    );
    assert!(tally.take_unsaid(secs(11), HOUR).is_empty(), "a second take answers nothing");
    let quiet = secs(5) + HOUR;
    assert!(tally.take_unsaid(quiet, HOUR).is_empty(), "nothing counted since");
    assert_eq!(tally.admit(c(), quiet, HOUR), Some(0), "c was quiet and forgotten: a first again");
    assert_eq!(tally.admit(b(), quiet, HOUR), None, "b was said at the take: it stands, counted");
}

/// Checks that at the bound quiet conditions make room and no count is lost.
///
/// With the tally full of conditions inside their interval, a new one is
/// counted past the bound; once they are quiet, a new condition forgets them
/// and is said as a first — save the one still counting, whose count the
/// take answers beside the panics counted past the bound, in the bound's
/// words.
#[test]
fn at_the_bound_quiet_conditions_make_room_and_no_count_is_lost() {
    let t0 = Instant::now();
    let secs = |s| t0 + Duration::from_secs(s);
    let site = |n: usize| (format!("site {n:04}"), None);
    let mut tally = Tally::new();
    for n in 0..TALLY_KEYS {
        assert_eq!(tally.admit(site(n), t0, HOUR), Some(0), "condition {n}");
    }
    assert_eq!(tally.admit(site(0), secs(1), HOUR), None, "site 0 counts one");
    for s in 2..4 {
        assert_eq!(tally.admit(("new".to_string(), None), secs(s), HOUR), None, "past the bound");
    }
    let later = t0 + HOUR;
    assert_eq!(tally.admit(("newer".to_string(), None), later, HOUR), Some(0), "room made");
    assert_eq!(tally.seen.len(), 2, "the quiet ones forgotten; site 0 and the new one stand");
    assert_eq!(
        tally.take_unsaid(later, HOUR).to_string(),
        format!(
            "1 more panics at site 0000 since its last line; 2 panics at sites past the hook's \
             memory of {TALLY_KEYS}"
        )
    );
}

/// Checks that a thread's route is the one its guard set until it drops.
///
/// A guard sets the route, a nested one replaces it and restores it as it
/// drops, an unwind through a guard restores the route it found, another
/// thread sees none, and the door reads the route at its call.
#[test]
fn a_threads_route_is_the_one_its_guard_set_until_the_guard_drops() {
    let op = RouteName::known("POST", "/op");
    let health = RouteName::known("GET", "/health");
    assert_eq!(route_served(), None, "no request, no route");
    {
        let _outer = serving(op);
        assert_eq!(route_served(), Some(op));
        {
            let _inner = serving(health);
            assert_eq!(route_served(), Some(health));
        }
        assert_eq!(route_served(), Some(op), "the nested guard restores the outer one");
        let unwound = panic::catch_unwind(|| {
            let _guard = serving(health);
            panic::resume_unwind(Box::new("an unwind through the guard"));
        });
        assert!(unwound.is_err(), "the closure unwinds");
        assert_eq!(route_served(), Some(op), "an unwind restores what the guard found");
        assert_eq!(thread::spawn(route_served).join().expect("a thread"), None, "unseen");
        let admitted = admit_panic(Some(Location::caller())).expect("a first");
        assert_eq!(admitted.route(), Some(op), "the door reads the route at its call");
    }
    assert_eq!(route_served(), None, "every guard dropped");
}

/// Checks that a take reads in the line's words, by site, then route.
///
/// The larger site is counted first and read second; a route rides its
/// clause, the bound's clause comes last, and an empty take says nothing.
/// A route name reads in the router's words, or `an unknown route`.
#[test]
fn unsaid_panics_read_in_the_lines_words() {
    let t0 = Instant::now();
    let op = Some(RouteName::known("POST", "/op"));
    let listen = "crates/skepd/src/server/listen.rs:559:13";
    let mut tally = Tally::new();
    for _ in 0..3 {
        tally.admit((listen.to_string(), None), t0, HOUR);
    }
    for _ in 0..60 {
        tally.admit((ENTROPY.to_string(), op), t0, HOUR);
    }
    tally.past_the_bound = 7;
    let taken = tally.take_unsaid(t0, HOUR);
    assert!(!taken.is_empty());
    assert_eq!(
        taken.to_string(),
        format!(
            "59 more panics at {ENTROPY} while serving POST /op since its last line; 2 more \
             panics at {listen} since its last line; 7 panics at sites past the hook's memory of \
             1024"
        )
    );
    let bound_alone = UnsaidPanics::at_figures(&[], 3);
    assert_eq!(bound_alone.to_string(), "3 panics at sites past the hook's memory of 1024");
    assert!(UnsaidPanics::default().is_empty());
    assert_eq!(UnsaidPanics::default().to_string(), "");
    assert_eq!(RouteName::known("GET", "/challenge").to_string(), "GET /challenge");
    assert_eq!(RouteName::unknown().to_string(), "an unknown route");
}

/// Checks that the tally's source names no hashing collection.
///
/// A hash map draws its keys from the OS the first time a thread makes one,
/// and that draw panics where the OS refuses entropy — inside the hook, an
/// abort. The tally's map is ordered and built at compile time, which this
/// holds to the code lines of `panics.rs`.
#[test]
fn the_tally_hashes_nothing_so_no_first_panic_draws_from_the_os() {
    let code: Vec<&str> = include_str!("../panics.rs")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect();
    for hashing in ["HashMap", "HashSet", "RandomState", "LazyLock"] {
        assert!(
            !code.iter().any(|line| line.contains(hashing)),
            "panics.rs names `{hashing}` in its code"
        );
    }
    assert!(
        code.iter()
            .any(|line| line.contains("static TALLY: Mutex<Tally> = Mutex::new(Tally::new());")),
        "the tally is a static built at compile time"
    );
}
