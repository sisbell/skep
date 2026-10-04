//! # skep-resolve — the verifying registry resolver
//!
//! A LIBRARY the frontend, the `skep` command and a node's federation
//! transport embed (the registry seam investigation §1.2): it reads the
//! registry board from a shipped ROOT HINT, verifies every binding and
//! endpoint it reads, indexes the verified bindings by prefix, and answers a
//! prefix with its endpoint and key set — or with a NAMED STATE saying why
//! not. It links no daemon and no engine, and it opens no socket to an
//! endpoint: the dial is the caller's.
//!
//! * `hint` — THE ROOT HINT (REG-3.2, REG-3.3): the root's origin(s), the
//!   realm id (the genesis key-set fingerprint, REG-3.39) and the fork point
//!   (REG-3.40), ONE overridable config value, parsed from one line and from
//!   a struct; every resolution the mirror performs is scoped to its realm
//!   by construction (REG-3.42).
//! * `http` — the written-out HTTP/1.1 client (`Transport`, `Http`) and the
//!   typed reads over it (`Board`: the feed's pages, `/op`, `/op-at`,
//!   `/chain`), with the count of every read made.
//! * `mirror` — THE MIRROR (REG-3.10 to REG-3.13, REG-3.17 to REG-3.19): a
//!   `/changes` consumer from the floor that fetches every row's bytes it
//!   needs and keeps an append-only journal copy from genesis; the base from
//!   genesis at the root the hint names or a CHECKED image; a root move
//!   resumed by the byte-identical check; a re-pointed hint re-bootstrapped;
//!   the two refusals; no TTL and no negative cache.
//! * `verify` — THE VERIFY (rm-2; REG-1.86 (e)): the body parsed under the
//!   canonical rule by `skep_registry::parse`, the record frame rebuilt from
//!   the row's own members, the signer found in the set that opens the
//!   home's account as of the record's position, both halves verified.
//! * `index` — THE INDEX (REG-3.21 to REG-3.26; REG-2.8 to REG-2.11,
//!   REG-2.24): the position-annotated prefix → binding index over the
//!   verified bindings, membership the rule's own test, the endpoint's
//!   currency on the active view (REG-1.10, REG-1.11).
//! * `walk` — THE WALK (REG-3.7 to REG-3.9): `resolve(prefix)` → the binding
//!   → the account → its key set and its current endpoint; the guest-reading
//!   resolve with no mirror (REG-3.24, REG-3.33), priced.
//! * `origin` — THE RESOLVER'S OWN CHECKS (REG-3.34 to REG-3.37): the scheme
//!   term, the host term met by an address and never a name, the ordered
//!   walk's one precedence, the dial not made.
//! * `state` — THE STATES (REG-3.79 to REG-3.84) and THE VERDICT (the
//!   signed-ops record §3.5's five values): every outcome a named value the
//!   UI renders; the copy is not this crate's.
//!
//! Every read the resolver makes is the board's own journal or its own copy
//! of it (R5 (a)); no resolution hop reads a third party.

#![forbid(unsafe_code)]

pub mod hint;
pub mod http;
pub mod index;
pub mod mirror;
pub mod origin;
pub mod state;
pub mod verify;
pub mod walk;

pub use hint::{realm_id, HintError, RootHint};
pub use http::{dial_http, Board, BoardError, Dial, Http, Page, Reads, Transport, TransportError};
pub use index::{Cause, Index, Suppressed};
pub use mirror::{Mirror, MirrorError, Opened, Refusal, Stats, WalkStats};
pub use origin::{
    judge_member, routable, walk_members, Dial as EndpointDial, EndpointWalk, MemberKind,
    MemberOutcome, NameResolver, Origin, SystemResolver, Term, Transports,
};
pub use state::{
    BindingRecord, EndpointRecord, Judged, Resolution, Standing, Successor, Unreachable, Verdict,
};
pub use verify::{hybrid_blob, judge, Trial};
pub use walk::{guest_resolve, resolve, GuestCost};

use skep_address::{validate, Address, Nat, Tumbler};

/// An address in its dotted-decimal spelling, as the wire carries one —
/// `None` where the text is no T4-valid address. Every address this crate
/// reads off the wire or a hint passes through here, so a leading-zero
/// spelling names its one address and a malformed one is refused, never
/// framed.
pub fn parse_address(s: &str) -> Option<Address> {
    let comps: Option<Vec<Nat>> = s
        .split('.')
        .map(|c| {
            (!c.is_empty() && c.bytes().all(|b| b.is_ascii_digit()))
                .then(|| c.parse::<u64>().ok().map(Nat::from))
                .flatten()
        })
        .collect();
    validate(Tumbler::new(comps?).ok()?).ok()
}

/// The auto traits a host holds this crate's values to: a mirror lives in a
/// client's own threads, so what it holds is `Send`; the resolutions it
/// answers cross to a UI thread. Asserted here, where a field change would
/// otherwise revoke them in silence.
const _: fn() = || {
    fn send<T: Send + 'static>() {}
    send::<RootHint>();
    send::<Resolution>();
    send::<Index>();
    send::<Stats>();
};
