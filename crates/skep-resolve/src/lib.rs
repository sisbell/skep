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
//! * `hint` — THE ROOT HINT (REG-3.2, REG-3.3): the root's origin(s) and the
//!   realm id (`RealmId`: the genesis key-set fingerprint, REG-3.39, and the
//!   fork point beside it, REG-3.40), ONE overridable config value, parsed
//!   from one line (`RootHint::parse`, `str::parse`) or built from its parts
//!   (`RootHint::new`), never with no origin; the mirror's realm check
//!   compares the id's genesis fingerprint at the base (REG-3.42).
//! * `http` — the written-out HTTP/1.1 client (`Transport`, `Method`,
//!   `Http`): plain `http` alone, an `https` root a transport this build
//!   does not hold, and no answer read past the cap.
//! * `board` — the typed reads over any transport (`Board`: the feed's
//!   pages, `/op`, `/op-at`, `/chain`), with the count of every read made,
//!   every value the resolver takes on the board's word typed where the
//!   wire spells it, and every answer held to the shape the wire promises —
//!   a page or a class scan's window that does not advance refused, a
//!   deposit's retraction the board's own active view.
//! * `mirror` — THE MIRROR (REG-3.10 to REG-3.13, REG-3.17 to REG-3.19): a
//!   `/changes` consumer from the floor that fetches every row's bytes it
//!   needs and keeps a journal copy from genesis; the base from genesis at
//!   the root the hint names or a CHECKED image, the realm compared at the
//!   claim's row on either (REG-3.42); a root move resumed by the
//!   byte-identical check; a re-pointed hint re-bootstrapped; the two
//!   refusals; no TTL and no negative cache.
//! * `verify` — THE VERIFY (rm-2; REG-1.86 (e)): the body parsed under the
//!   canonical rule by `skep_registry::parse`, the record frame rebuilt from
//!   the row's own members, the signer found in the set that opens the
//!   home's account as of the record's position, both halves verified.
//! * `index` — THE INDEX (REG-3.21 to REG-3.26; REG-2.8 to REG-2.11,
//!   REG-2.24): the position-annotated prefix → binding index over the
//!   verified bindings, the mirror's gate its one writer; beneath it the
//!   ledger of the rules alone — membership the rule's own test, the
//!   endpoint's currency on the active view (REG-1.10, REG-1.11) — which the
//!   guest-reading resolve folds into.
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
//!
//! The modules are private: the root is the crate's whole surface — the
//! names re-exported below and [`parse_address`] — each name at one path, so
//! a file moved inside the crate moves nothing a dependent names.

#![forbid(unsafe_code)]

mod board;
mod hint;
mod http;
mod index;
mod mirror;
mod origin;
mod state;
mod verify;
mod walk;

pub use board::{Board, BoardError, Reads};
pub use hint::{HintError, RealmId, RootHint};
pub use http::{dial_http, Dial, Http, Method, Transport, TransportError};
pub use index::{Cause, Counts, Index, Suppressed};
pub use mirror::{
    account_of_document, ChainWalkStats, Mirror, MirrorError, Opened, Refusal, Stats, FEED_COPY, FETCH_CACHE,
};
pub use origin::{
    judge_member, walk_members, EndpointDial, EndpointWalk, MemberKind, MemberOutcome,
    NameResolver, NotCanonical, Origin, SystemResolver, Term, Transports,
};
pub use state::{
    BindingRecord, EndpointRecord, Judged, Resolution, Standing, Successor, Unreachable, Verdict,
};
pub use walk::{guest_resolve, resolve, GuestCost};

use skep_address::{validate, Address, Nat, Tumbler};

/// THE MOST DIGITS one component of an address a board serves carries:
/// skepd's codec's `MAX_NAT_DIGITS`, the cap the board's own wire holds
/// every tumbler to, restated here because this crate links no daemon.
const MAX_COMPONENT_DIGITS: usize = 4096;

/// THE MOST COMPONENTS an address a board serves carries: skepd's codec's
/// `MAX_TUMBLER_COMPONENTS`, restated here for [`MAX_COMPONENT_DIGITS`]'s
/// reason.
const MAX_ADDRESS_COMPONENTS: usize = 256;

/// An address in its dotted-decimal spelling, as the wire carries one — each
/// component one decimal natural, of any size (wire.md §Value encodings) —
/// `None` where the text is no T4-valid address, or passes the board's own
/// wire caps (4096 digits a component, 256 components), which no board
/// serves. Every address this crate reads off the wire, a copy, a cache or a
/// hint passes through here, so a leading-zero spelling names its one
/// address and a malformed one is refused, never framed; an address past the
/// component cap converts nothing, and a component past the digit cap is
/// refused before it is converted.
pub fn parse_address(s: &str) -> Option<Address> {
    if s.split('.').count() > MAX_ADDRESS_COMPONENTS {
        return None;
    }
    let comps: Option<Vec<Nat>> = s
        .split('.')
        .map(|c| {
            let decimal = !c.is_empty() && c.len() <= MAX_COMPONENT_DIGITS && c.bytes().all(|b| b.is_ascii_digit());
            decimal.then(|| c.parse::<Nat>().ok()).flatten()
        })
        .collect();
    validate(Tumbler::new(comps?).ok()?).ok()
}

/// One byte from two hex digits, either case — `None` for any other byte.
/// Every hex string this crate decodes itself — a signature's blob, a chain
/// — passes through here a byte pair at a time, so text of any content,
/// off the wire, a copy or a cache, answers `None` and never panics; a
/// fingerprint or a key is decoded by skep-identity's own reader.
pub(crate) fn hex_byte([hi, lo]: [u8; 2]) -> Option<u8> {
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    Some((nibble(hi)? << 4) | nibble(lo)?)
}

/// The traits a host holds this crate's values to, asserted here, where a
/// field change or a dropped derive would otherwise revoke one in silence.
///
/// A mirror stays on the thread that opened it: it holds the caller's
/// `Transport`, which this crate does not require to be `Send` (both suites'
/// replays hold an `Rc`), so neither `Mirror` nor `Board` is — as `Mirror`'s
/// own doc checks. What a mirror answers crosses threads — a resolution to a
/// UI thread, the stats or a cloned index to a reporter, the hint to the next
/// mirror, an error to whoever reports it — and is `Send` and `Sync` both: an
/// error is boxed as a `Box<dyn Error + Send + Sync>` or taken into an
/// `anyhow::Error`, each of which asks for `Sync`, and a resolution a UI
/// shares behind an `Arc` is read from every thread that holds it.
///
/// Every public type shows itself through `Debug` (C-DEBUG), the three that
/// hold a caller's transport or a socket's address among them, so a host's
/// own state that holds one derives its own; and the values a caller keys a
/// map by — a realm, a hint, a verdict — hash.
const _: fn() = || {
    fn send_sync<T: Send + Sync + 'static>() {}
    fn debug<T: std::fmt::Debug>() {}
    fn hash_key<T: Eq + std::hash::Hash>() {}
    send_sync::<RootHint>();
    send_sync::<Resolution>();
    send_sync::<Index>();
    send_sync::<Stats>();
    send_sync::<MirrorError>();
    send_sync::<BoardError>();
    send_sync::<TransportError>();
    send_sync::<HintError>();
    send_sync::<NotCanonical>();
    debug::<Mirror>();
    debug::<Board>();
    debug::<Http>();
    hash_key::<RealmId>();
    hash_key::<RootHint>();
    hash_key::<Verdict>();
};

#[cfg(test)]
mod tests {
    use super::*;

    /// AN ADDRESS A BOARD SERVES READS WHATEVER ITS COMPONENTS' SIZE (wire.md
    /// §Value encodings: one decimal natural per component): a component past
    /// a machine word reads and renders back as itself, and a leading zero
    /// names its one address; the board's own wire caps bound what reads — at
    /// each an address reads, and one digit or one component past it none
    /// does; and text that spells no natural, or no T4-valid address, is none.
    #[test]
    fn an_address_reads_at_every_size_a_board_serves() {
        let past_a_word = parse_address("1.18446744073709551616").expect("a component past u64");
        assert_eq!(past_a_word.to_string(), "1.18446744073709551616");
        assert_eq!(parse_address("1.07"), parse_address("1.7"), "a leading zero names its one address");
        let digits = |n: usize| format!("1.{}", "9".repeat(n));
        assert!(parse_address(&digits(MAX_COMPONENT_DIGITS)).is_some(), "at the digit cap");
        assert_eq!(parse_address(&digits(MAX_COMPONENT_DIGITS + 1)), None, "a digit past it");
        let components = |n: usize| vec!["1"; n].join(".");
        assert!(parse_address(&components(MAX_ADDRESS_COMPONENTS)).is_some(), "at the component cap");
        assert_eq!(parse_address(&components(MAX_ADDRESS_COMPONENTS + 1)), None, "a component past it");
        for none in ["", "1..2", "1.+2", "1._2", "a.1", "1.0", "0.1"] {
            assert_eq!(parse_address(none), None, "{none:?}");
        }
    }
}
