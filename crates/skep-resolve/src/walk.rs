//! THE WALK (REG-3.7 to REG-3.9; REG-1.10, REG-1.11; R5 (l); R2 (d)) —
//! `1.5` → (endpoint, key set) by ONE link: the binding record, resolved
//! under the many-into-one rule, names 1.5's registry-board account; that
//! account's fold gives the current keys and its own records give the
//! endpoint. Answered entirely from the mirror and the registry board, with
//! no runtime dependency on any other party (REG-3.9).
//!
//! `resolve(prefix)`: the binding from the index — read once at the build,
//! never derived at the resolve (REG-3.24) — then the account, its key set
//! as of the mirror's head, and its CURRENT endpoint: the latest honored
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
//! REG-3.33) — a reader with no mirror, scanning the board, its verdicts
//! UNDETERMINABLE HERE — which renders its answer through this module's
//! [`face_of`].

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
        // A depth address whose parent this board binds: the hop not made.
        if let Some(parent) = mirror.index().longest_bound_prefix(prefix) {
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

/// The face a standing, its keys and its current endpoint render (REG-3.80;
/// REG-3.34's one precedence over the members).
fn face_of(
    standing: crate::state::Standing,
    keys: Vec<Enrolled>,
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
