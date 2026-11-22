//! The origin rule and the address arithmetic over a chain's members.
//!
//! [`origin_of`] returns the bare document a content I-address was minted
//! under (the merge record's §1.3 step 3), and [`runs_of`] turns an `image`
//! answer's runs into the core's by it; the rest compare and spell
//! addresses — a trunk, a version component, a daughter, an account, an
//! origin's content prefix.

use skep_address::{validate, Address, Level, Nat, Tumbler};

use crate::address::parse_address;
use crate::board::answers::IRun;
use crate::halt::Halt;
use crate::merge::compose::Run;

// ── the origin rule ───────────────────────────────────────────────────────

/// Returns the bare document a content I-address was minted under.
///
/// It is the prefix before its last `.0.1.` — the content subspace's marker
/// — stripped of any version component to the trunk (the merge record's
/// §1.3 step 3: "derived from its `i_start` by address arithmetic,
/// `document_of` then the trunk"; the rule skep-cli's dev board states as
/// `origin_of`).
///
/// The core's `Run::origin` is this address, never a member's: a
/// version-qualified origin would make every anchor and every `Choice::After`
/// lookup answer none. `None` for a text that is no content I-address.
pub fn origin_of(i_start: &str) -> Option<Address> {
    let at = i_start.rfind(".0.1.")?;
    let minted_under = &i_start[..at];
    parse_address(&crate::address::document_of(minted_under)?)
}

/// Returns the content I-address prefix of `origin`'s positions.
///
/// It is the spelling an `image` answer's `i_start` opens with.
pub(in crate::merge) fn content_prefix(origin: &Address) -> String {
    format!("{origin}.0.1")
}

/// Returns the core's runs for an `image` answer's runs.
///
/// Each origin is by [`origin_of`], I-adjacent runs of one origin coalesced
/// — the daemon's own accumulator, `extend_or_push_run`, whose whole test is
/// I-adjacency — so a run a part boundary cut is one run again (§8).
///
/// # Errors
///
/// A run whose `i_start` is no content I-address is the board's fault,
/// named.
pub(crate) fn runs_of(imaged: &[IRun]) -> Result<Vec<Run>, Halt> {
    let mut out: Vec<Run> = Vec::new();
    for r in imaged {
        let i_start = format!("{}.{}", r.prefix, r.first);
        let origin = origin_of(&i_start).ok_or_else(|| {
            Halt::face(
                "an `image` run is no content I-address",
                format!("`{i_start}` has no `.0.1.` content marker before its ordinal"),
                "this is a board fault; nothing was written",
            )
        })?;
        if let Some(last) = out.last_mut() {
            if last.origin == origin && last.reach() == r.first {
                last.width = last.width.saturating_add(r.width);
                continue;
            }
        }
        out.push(Run::new(origin, r.first, r.width));
    }
    Ok(out)
}

// ── address arithmetic over members ───────────────────────────────────────

/// Returns the trunk a document, member or element address lies in.
///
/// `None` for an account or a node.
pub(in crate::merge) fn trunk_of(a: &Address) -> Option<Address> {
    parse_address(&crate::address::document_of(&a.to_string())?)
}

/// Returns an address's components.
///
/// They serve the comparisons the tumbler's own type does not offer.
pub(in crate::merge) fn comps(a: &Address) -> Vec<Nat> {
    a.tumbler().iter().cloned().collect()
}

/// Returns a member's version components after the trunk `doc`'s.
///
/// `None` where `a` is not under `doc`, or is `doc` itself.
pub(in crate::merge) fn version_components(doc: &Address, a: &Address) -> Option<Vec<Nat>> {
    let (doc, comps) = (comps(doc), comps(a));
    if comps.len() <= doc.len() || comps[..doc.len()] != doc[..] {
        return None;
    }
    Some(comps[doc.len()..].to_vec())
}

/// Returns whether `a` is a trunk member of `doc` — one version component.
pub(in crate::merge) fn is_trunk_member(doc: &Address, a: &Address) -> bool {
    version_components(doc, a).is_some_and(|v| v.len() == 1)
}

/// Returns whether `a` is `doc` itself or a member of its chain: a document
/// address in `doc`'s trunk, never an element within one.
pub(super) fn in_chain(doc: &Address, a: &Address) -> bool {
    a.level() == Level::Document && trunk_of(a).as_ref() == Some(doc)
}

/// Returns the address a member's lies under: its last component stripped.
///
/// `None` for an address of one component.
pub(super) fn address_parent(a: &Address) -> Option<Address> {
    let mut comps = comps(a);
    comps.pop()?;
    validate(Tumbler::new(comps).ok()?).ok()
}

/// Returns the trunk member after `head`: its one version component plus one.
pub(in crate::merge) fn next_trunk_member(head: &Address) -> Option<Address> {
    let mut comps = comps(head);
    let last = comps.last_mut()?;
    *last = &*last + &Nat::from(1u32);
    validate(Tumbler::new(comps).ok()?).ok()
}

/// Returns the `k`-th daughter of `member`, its address extended by `k`.
pub(in crate::merge) fn daughter_of(member: &Address, k: u64) -> Option<Address> {
    let comps = comps(member).into_iter().chain(std::iter::once(Nat::from(k)));
    validate(Tumbler::new(comps).ok()?).ok()
}

/// Returns the account an address lies in, `N.0.U`, as text.
///
/// `None` for a node.
pub(in crate::merge) fn account_of(a: &Address) -> Option<String> {
    let node: Vec<String> = a.node_field().iter().map(ToString::to_string).collect();
    let account: Vec<String> = a.account_field()?.iter().map(ToString::to_string).collect();
    Some(format!("{}.0.{}", node.join("."), account.join(".")))
}

/// Returns an address's last component, its ordinal, where it fits `u64`.
pub(in crate::merge) fn last_component(a: &Address) -> Option<u64> {
    u64::try_from(a.tumbler().iter().last()?).ok()
}
