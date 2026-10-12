//! T6 — THE PAIR off `/health`'s body, and THE WAIT for it over the fake:
//! a claimed, enforcing board answers it; a `null` claimant, a `true`
//! local trust and a body that is not JSON do not; an eighth member changes
//! nothing; the wait answers at the first pair and gives up after its
//! bound, the fake called exactly the bound's times.

use std::cell::Cell;

use super::*;
use crate::docker::fake::{line, FakeDocker};

/// THE BODY a claimed alpha board answers: the daemon's members, keys
/// sorted (`get_health` and `auth_object` in `skepd`).
const PAIRED: &str = r#"{"auth":{"claimant":"1.0.1","local_trust":false,"origins":[],"signed_origins":["https://alice.skep.host"]},"chain_head":"0000000000000000000000000000000000000000000000000000000000000000","head_time":null,"log_position":0,"media":{"uploads":true},"ok":true,"writes":{"halted":false}}"#;

fn alice() -> Name {
    Name::parse(b"alice").expect("a name")
}

/// T6: THE PAIR — answered by the claimed, enforcing body; not by a `null`
/// claimant, not by `local_trust: true`, not by a body that is not JSON;
/// still answered with one more top-level member (the wire's forward rule).
#[test]
fn the_pair_is_a_claimant_and_local_trust_false() {
    assert!(pair(PAIRED.as_bytes()));
    assert!(!pair(PAIRED.replace(r#""claimant":"1.0.1""#, r#""claimant":null"#).as_bytes()), "an unclaimed board");
    assert!(!pair(PAIRED.replace(r#""local_trust":false"#, r#""local_trust":true"#).as_bytes()), "local trust on");
    assert!(pair(PAIRED.replace(r#","writes""#, r#","zeta":{"x":1},"writes""#).as_bytes()), "an eighth member is ignored");
    assert!(!pair(b"not json"), "a body that is not JSON");
    assert!(!pair(br#"{"ok":true}"#), "no auth member");
    assert!(!pair(br#"{"auth":{"claimant":"1.0.1"}}"#), "no local_trust");
    assert!(!pair(br#"{"auth":{"local_trust":false}}"#), "no claimant");
    assert!(!pair(br#"{"auth":{"claimant":1,"local_trust":false}}"#), "a claimant that is no address");
}

/// T6: THE WAIT ANSWERS AT THE FIRST PAIR: a failed run and an unclaimed
/// body are "not yet", the third try pairs, two sleeps between.
#[test]
fn the_wait_answers_at_the_first_pair() {
    let unclaimed = PAIRED.replace(r#""claimant":"1.0.1""#, r#""claimant":null"#);
    let script = [line("health", Some("alice"), 4, "", "the board did not answer\n"), line("health", Some("alice"), 0, &unclaimed, ""), line("health", Some("alice"), 0, PAIRED, "")].concat();
    let fake = FakeDocker::parse(&script).expect("a script");
    let sleeps = Cell::new(0);
    let waited = wait(&fake, &alice(), Wait { tries: 5, interval: Duration::from_secs(1) }, &|_| sleeps.set(sleeps.get() + 1)).expect("docker ran");
    assert_eq!(waited, Waited::Paired { at: 3 });
    assert_eq!(sleeps.get(), 2);
    fake.assert_done();
}

/// T6: THE WAIT GIVES UP AFTER ITS BOUND, the fake called exactly the
/// bound's times and slept between — a small bound, and the service's own.
#[test]
fn the_wait_gives_up_after_its_bound() {
    for bound in [Wait { tries: 3, interval: Duration::from_millis(5) }, HEALTH_WAIT] {
        let unclaimed = PAIRED.replace(r#""claimant":"1.0.1""#, r#""claimant":null"#);
        let script: String = (0..bound.tries).map(|_| line("health", Some("alice"), 0, &unclaimed, "")).collect();
        let fake = FakeDocker::parse(&script).expect("a script");
        let sleeps = Cell::new(0);
        let waited = wait(&fake, &alice(), bound, &|d| {
            assert_eq!(d, bound.interval);
            sleeps.set(sleeps.get() + 1)
        })
        .expect("docker ran");
        assert_eq!(waited, Waited::GaveUp { tries: bound.tries, last: Some(0) });
        assert_eq!(fake.calls().len(), bound.tries as usize, "the fake's call count is the bound");
        assert_eq!(sleeps.get(), bound.tries - 1);
        fake.assert_done();
    }
    assert_eq!(HEALTH_WAIT, Wait { tries: 60, interval: Duration::from_secs(1) }, "the smoke's sixty seconds");
}
