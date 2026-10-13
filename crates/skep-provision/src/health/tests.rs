//! T6 — THE PAIR off `/health`'s body, and THE WAIT for it over the fake:
//! a claimed, enforcing board answers it; a `null` claimant, a `true`
//! local trust and a body that is not JSON do not; an eighth member changes
//! nothing; the wait answers at the first pair — a failed run's stdout never
//! one, whatever it carries — and gives up after its bound of one or more
//! tries, the fake called exactly the bound's times; and a `docker` that
//! cannot be run at all ends the wait at once, the error.

use std::cell::Cell;
use std::sync::atomic::{AtomicU32, Ordering};

use super::*;
use crate::docker::fake::{line, FakeDocker};
use crate::docker::Call;
use crate::process::Exit;

/// THE BODY a claimed alpha board answers: the daemon's members, keys
/// sorted (`get_health` and `auth_object` in `skepd`).
const PAIRED: &str = r#"{"auth":{"claimant":"1.0.1","local_trust":false,"origins":[],"signed_origins":["https://alice.skep.host"]},"chain_head":"0000000000000000000000000000000000000000000000000000000000000000","head_time":null,"log_position":0,"media":{"uploads":true},"ok":true,"writes":{"halted":false}}"#;

fn alice() -> Name {
    Name::parse(b"alice").expect("a name")
}

/// A wait's tries: one or more.
fn tries(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).expect("one or more tries")
}

/// T6: THE PAIR — answered by the claimed, enforcing body; not by a `null`
/// claimant, not by `local_trust: true`, not by a body that is not JSON;
/// still answered with one more top-level member (the wire's forward rule).
#[test]
fn the_pair_is_a_claimant_and_local_trust_false() {
    assert!(paired(PAIRED.as_bytes()));
    assert!(!paired(PAIRED.replace(r#""claimant":"1.0.1""#, r#""claimant":null"#).as_bytes()), "an unclaimed board");
    assert!(!paired(PAIRED.replace(r#""local_trust":false"#, r#""local_trust":true"#).as_bytes()), "local trust on");
    assert!(paired(PAIRED.replace(r#","writes""#, r#","zeta":{"x":1},"writes""#).as_bytes()), "an eighth member is ignored");
    assert!(!paired(b"not json"), "a body that is not JSON");
    assert!(!paired(br#"{"ok":true}"#), "no auth member");
    assert!(!paired(br#"{"auth":{"claimant":"1.0.1"}}"#), "no local_trust");
    assert!(!paired(br#"{"auth":{"local_trust":false}}"#), "no claimant");
    assert!(!paired(br#"{"auth":{"claimant":1,"local_trust":false}}"#), "a claimant that is no address");
}

/// T6: THE WAIT ANSWERS AT THE FIRST PAIR: a failed run — its stdout the
/// pair all the same — and an unclaimed body are "not yet", the third try
/// pairs, two sleeps between.
#[test]
fn the_wait_answers_at_the_first_pair() {
    let unclaimed = PAIRED.replace(r#""claimant":"1.0.1""#, r#""claimant":null"#);
    let script = [line("health", Some("alice"), 4, PAIRED, "the board did not answer\n"), line("health", Some("alice"), 0, &unclaimed, ""), line("health", Some("alice"), 0, PAIRED, "")].concat();
    let fake = FakeDocker::parse(&script).expect("a script");
    let sleeps = Cell::new(0);
    let waited = wait(&fake, &alice(), Wait { tries: tries(5), interval: Duration::from_secs(1) }, &|_| sleeps.set(sleeps.get() + 1)).expect("docker ran");
    assert_eq!(waited, Waited::Paired { at: 3 });
    assert_eq!(sleeps.get(), 2);
    fake.assert_done();
}

/// T6: THE WAIT GIVES UP AFTER ITS BOUND, the fake called exactly the
/// bound's times and slept between — a small bound, and the service's own.
#[test]
fn the_wait_gives_up_after_its_bound() {
    for bound in [Wait { tries: tries(3), interval: Duration::from_millis(5) }, HEALTH_WAIT] {
        let unclaimed = PAIRED.replace(r#""claimant":"1.0.1""#, r#""claimant":null"#);
        let script: String = (0..bound.tries.get()).map(|_| line("health", Some("alice"), 0, &unclaimed, "")).collect();
        let fake = FakeDocker::parse(&script).expect("a script");
        let sleeps = Cell::new(0);
        let waited = wait(&fake, &alice(), bound, &|d| {
            assert_eq!(d, bound.interval);
            sleeps.set(sleeps.get() + 1)
        })
        .expect("docker ran");
        assert_eq!(waited, Waited::GaveUp { tries: bound.tries.get(), last_code: Some(0) });
        assert_eq!(fake.calls().len(), bound.tries.get() as usize, "the fake's call count is the bound");
        assert_eq!(sleeps.get(), bound.tries.get() - 1);
        fake.assert_done();
    }
    assert_eq!((HEALTH_WAIT.tries.get(), HEALTH_WAIT.interval), (60, Duration::from_secs(1)), "the smoke's sixty seconds");
}

/// T6: A `docker` THAT CANNOT BE RUN AT ALL ends the wait at once, the
/// error: one call and no sleep — no try can answer.
#[test]
fn a_docker_that_cannot_run_ends_the_wait_at_once() {
    /// A runner whose `docker` cannot be run: every call the error, counted.
    struct NoDocker(AtomicU32);
    impl Docker for NoDocker {
        fn run(&self, _: Call<'_>) -> io::Result<Exit> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }
    let docker = NoDocker(AtomicU32::new(0));
    let sleeps = Cell::new(0);
    assert!(wait(&docker, &alice(), HEALTH_WAIT, &|_| sleeps.set(sleeps.get() + 1)).is_err());
    assert_eq!((docker.0.load(Ordering::SeqCst), sleeps.get()), (1, 0), "the calls and the sleeps");
}
