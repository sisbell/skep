//! THE WALK (REG-3.7 to REG-3.9; REG-1.10, REG-1.11; R5 (l); R2 (d)) —
//! `1.5` → (endpoint, key set) by ONE link: the binding record, resolved
//! under the many-into-one rule, names 1.5's registry-board account; that
//! account's fold gives the current keys and its own records give the
//! endpoint. Answered entirely from the mirror and the registry board, with
//! no runtime dependency on any other party (REG-3.9).
//!
//! `resolve(prefix)`: the binding from the index — read once at the build,
//! never derived at the resolve (REG-3.24) — then the account, its key set
//! as of the mirror's head (or that this reader could not read it, never an
//! empty set in its place), and its CURRENT endpoint: the latest honored
//! deposit on the active view of the account's doc 1, a nullified one gone
//! and the one before it standing (REG-1.10, REG-1.11). The endpoint's
//! members are then judged in the org's order ([`crate::origin`]) and the
//! answer is one of the named states ([`crate::state::Resolution`]). A depth
//! address — `1.5.3` — whose own prefix no binding names resolves to its
//! PARENT's standing and THE HOP NOT MADE (REG-3.82): the subnode's binding
//! is on org 1.5's board, a second mirror over a second hint, and the hop
//! is the caller's.
//!
//! Beneath it, one child: [`guest`], THE GUEST-READING RESOLVE (REG-3.24,
//! REG-3.33) — a reader with no mirror, scanning the board into a ledger of
//! its own and never into an index, its verdicts UNDETERMINABLE HERE — which
//! renders its answer through this module's [`face_of`].

mod guest;

pub use guest::{guest_resolve, GuestCost};

use skep_address::Address;
use skep_identity::{doc_1_of, Enrolled};

use crate::mirror::{Mirror, MirrorError};
use crate::origin::{walk_members, MemberOutcome, NameResolver, Transports};
use crate::state::{EndpointRecord, Judged, Resolution, Unreachable};

/// RESOLVE `prefix` off `mirror` (REG-3.7 to REG-3.9): the walk's answer as
/// a named state. `names` is this resolver's own resolution of a host name
/// (REG-3.35) and `transports` what it can dial (REG-3.34 as RES-28 amends
/// it).
pub fn resolve(
    mirror: &mut Mirror,
    prefix: &Address,
    names: &dyn NameResolver,
    transports: &Transports,
) -> Result<Resolution, MirrorError> {
    let Some(standing) = mirror.index().standing(prefix) else {
        // A depth address whose parent has a standing here, held or retired:
        // the hop not made.
        if let Some(parent) = mirror.index().parent_prefix(prefix) {
            let parent = resolve(mirror, &parent, names, transports)?;
            return Ok(Resolution::HopNotMade { prefix: prefix.clone(), parent: Box::new(parent) });
        }
        return Ok(Resolution::Unregistered { prefix: prefix.clone() });
    };
    let Some(account) = standing.current.record.account.clone() else {
        return Ok(Resolution::RetiredWithHistory { standing, successor: None });
    };
    let keys = mirror.current_keys(&account)?;
    let home = doc_1_of(&account);
    let endpoint = mirror.index().current_endpoint(&home).cloned();
    Ok(face_of(standing, keys, endpoint, mirror.index().any_honored_endpoint(&home), names, transports))
}

/// The face a standing, its keys — `None` where the reader could not read
/// them — and its current endpoint render (REG-3.80; REG-3.34's one
/// precedence over the members).
fn face_of(
    standing: crate::state::Standing,
    keys: Option<Vec<Enrolled>>,
    endpoint: Option<Judged<EndpointRecord>>,
    any_honored: bool,
    names: &dyn NameResolver,
    transports: &Transports,
) -> Resolution {
    let Some(endpoint) = endpoint else {
        let cause = if any_honored { Unreachable::NullifiedLast } else { Unreachable::NoEndpointYet };
        return Resolution::BoundButUnreachable { standing, keys, endpoint: None, cause, members: Vec::new() };
    };
    let walk = walk_members(&endpoint.record.origins, names, transports);
    if let Some(dial) = walk.dial {
        return Resolution::Bound { standing, keys, endpoint, dial, members: walk.outcomes };
    }
    // No member would dial: the FIRST member's outcome is the face's.
    match walk.outcomes.first().cloned() {
        Some(MemberOutcome::Refused { member, term }) => {
            Resolution::UnreachableByPolicy { standing, keys, endpoint, member, term, members: walk.outcomes }
        }
        Some(MemberOutcome::NotDialed { origin, kind }) => Resolution::DialNotMade {
            standing,
            keys,
            endpoint,
            member: origin.as_str().to_string(),
            kind,
            members: walk.outcomes,
        },
        Some(MemberOutcome::Dead { origin }) => Resolution::BoundButUnreachable {
            standing,
            keys,
            endpoint: Some(endpoint),
            cause: Unreachable::DeadOrigin { member: origin.as_str().to_string() },
            members: walk.outcomes,
        },
        // A dial would have been taken above; an endpoint body carries at
        // least one member, so this arm has no population.
        Some(MemberOutcome::WouldDial { .. }) | None => Resolution::BoundButUnreachable {
            standing,
            keys,
            endpoint: Some(endpoint),
            cause: Unreachable::NoEndpointYet,
            members: walk.outcomes,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::IpAddr;

    use skep_identity::Fingerprint;

    use super::*;
    use crate::origin::Term;
    use crate::parse_address;
    use crate::state::{BindingRecord, Standing, Verdict};

    fn a(s: &str) -> Address {
        parse_address(s).unwrap()
    }

    /// This resolver's own resolution of a name, fixed: `acme.example` at a
    /// public address, every other name at none.
    struct Names;

    impl NameResolver for Names {
        fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
            Ok(if host == "acme.example" { vec!["93.184.216.34".parse().unwrap()] } else { Vec::new() })
        }
    }

    /// `1.5` bound to `1.0.2`, its one binding SIGNED.
    fn standing() -> Standing {
        let current = Judged {
            position: 10,
            link: a("1.0.1.0.1.0.2.1"),
            home: a("1.0.1.0.1"),
            record: BindingRecord { prefix: a("1.5"), account: Some(a("1.0.2")), replaces: None, honored: true },
            verdict: Verdict::Signed(Fingerprint::parse_hex(&"ab".repeat(32)).unwrap()),
        };
        Standing { prefix: a("1.5"), current: current.clone(), history: vec![current] }
    }

    /// `1.0.2`'s endpoint, its members `origins` in the org's order.
    fn endpoint(origins: &[&str]) -> Judged<EndpointRecord> {
        Judged {
            position: 11,
            link: a("1.0.2.0.1.0.2.1"),
            home: a("1.0.2.0.1"),
            record: EndpointRecord { origins: origins.iter().map(|o| o.to_string()).collect(), replaces: None, honored: true, nullified: false },
            verdict: Verdict::Signed(Fingerprint::parse_hex(&"cd".repeat(32)).unwrap()),
        }
    }

    fn face(endpoint: Option<Judged<EndpointRecord>>, any_honored: bool) -> Resolution {
        face_of(standing(), None, endpoint, any_honored, &Names, &Transports::default())
    }

    /// BOUND-BUT-UNREACHABLE with no current endpoint (REG-3.80): named by
    /// whether a deposit ever stood — NO ENDPOINT YET where none did, THE
    /// LAST NULLIFIED where every one that did is off the active view — the
    /// standing beside it, never a blank, and the key set as the walk read it.
    #[test]
    fn no_current_endpoint_is_named_by_whether_one_ever_stood() {
        for (any_honored, cause) in [(false, Unreachable::NoEndpointYet), (true, Unreachable::NullifiedLast)] {
            assert_eq!(
                face(None, any_honored),
                Resolution::BoundButUnreachable { standing: standing(), keys: None, endpoint: None, cause, members: Vec::new() },
            );
        }
    }

    /// REG-3.34's ONE PRECEDENCE at the face (REG-3.80): where no member
    /// would dial, the FIRST member's outcome in the org's order is the
    /// face's — a dead origin first is BOUND-BUT-UNREACHABLE, a plaintext
    /// member first unreachable-by-policy on the scheme term — and every
    /// member's outcome rides beside it.
    #[test]
    fn where_no_member_dials_the_first_members_outcome_is_the_face() {
        match face(Some(endpoint(&["https://dead.example", "http://plain.example"])), true) {
            Resolution::BoundButUnreachable { cause: Unreachable::DeadOrigin { member }, endpoint: Some(_), members, .. } => {
                assert_eq!((member.as_str(), members.len()), ("https://dead.example", 2));
            }
            other => panic!("{other:?}"),
        }
        match face(Some(endpoint(&["http://plain.example", "https://dead.example"])), true) {
            Resolution::UnreachableByPolicy { member, term: Term::Scheme, members, .. } => {
                assert_eq!((member.as_str(), members.len()), ("http://plain.example", 2));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(face(Some(endpoint(&["https://dead.example", "https://acme.example"])), true), Resolution::Bound { .. }));
    }
}
