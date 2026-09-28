//! The board's node prefix in the registry (REG-1.69), admitted only in its
//! one legal form: the comparand of the blocked-prefix list's off-board test.

use std::fmt;

use skep_address::{validate, Address, Level, Nat, Tumbler};
use skep_namespace::prefix_contains;

use crate::codec::wire_address;

// ── the node prefix (REG-1.69) ───────────────────────────────────────────

/// The board's full NODE PREFIX in the registry (REG-1.69): a T4-valid NODE
/// address STRICTLY UNDER the root `1` — an org's `1.N` (REG-1.66: orgs are
/// allocated second components, `1.2`, `1.3`, …), a subnode deeper beneath
/// it (`1.3.2`). The invariant is the TYPE's, as [`super::origin::Origin`]'s canonical form
/// is: every value comes through the [`FromStr`](std::str::FromStr) below,
/// so no field of this type holds the root itself (a board AT the root
/// answers to no prefix but `1`, and every address is under it — the
/// off-board test has no work there), an address under another first
/// component (REG-1.67: no other root is assigned), an account or document
/// address, or text no tumbler spells.
///
/// WHY THE TYPE AND NOT A PRECONDITION: it is the OFF-BOARD TEST's
/// comparand (`BlockedPrefixes::installed_under`) and nothing else, and
/// that test is `prefix_contains(node_prefix, operator)` — address
/// arithmetic, which ANSWERS for any address at all and so cannot refuse a
/// prefix that is not one. An account address there — the obvious slip, the
/// operator field it is compared against being one — or the root would yield
/// an off-board verdict meaning nothing, and a wrong verdict either lifts a
/// standing takedown block or makes the served board's claimant blockable,
/// the two cells REG-4.198 rules out. So the form is checked where a value
/// is made rather than where it is used, and the daemon that holds one holds
/// a prefix.
///
/// ONE door, where [`super::origin::Origin`] keeps two: that type's `parse` exists for an
/// internal predicate use (`Origin::parse(h).is_some_and(…)`) this one has
/// none of, so `str::parse` is the whole surface — which is also what lets
/// `main.rs`'s `from_env` carry this setting like every other.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodePrefix(Address);

impl NodePrefix {
    /// The prefix as an address — what [`prefix_contains`] takes.
    pub fn address(&self) -> &Address {
        &self.0
    }
}

impl fmt::Display for NodePrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.tumbler())
    }
}

/// [`NodePrefix`]'s parse refused: the text is not a node prefix. Carries no
/// reason, as [`super::origin::NotCanonical`] carries none: the form is one shape, and this
/// states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NotANodePrefix;

impl fmt::Display for NotANodePrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a node prefix (1.N — a node address strictly under the root 1)")
    }
}

impl std::error::Error for NotANodePrefix {}

/// The ecosystem door, and the ONLY one: every [`NodePrefix`] is one this
/// parse admitted, which is what makes the type's invariant a fact rather
/// than a precondition a caller owes.
impl std::str::FromStr for NodePrefix {
    type Err = NotANodePrefix;

    fn from_str(s: &str) -> Result<NodePrefix, NotANodePrefix> {
        let prefix = wire_address(s).map_err(|_| NotANodePrefix)?;
        let root = root();
        let under_root =
            prefix.level() == Level::Node && prefix != root && prefix_contains(&root, &prefix);
        under_root.then_some(NodePrefix(prefix)).ok_or(NotANodePrefix)
    }
}

/// The registry's ROOT, `1` (REG-1.66: every global address begins with it;
/// a board's OWN space is `1.x` locally, the leading `1` reading as THIS NODE
/// locally and as the root globally). The reference a [`NodePrefix`] is
/// admitted under — and NOT the off-board test's comparand: under it every
/// global-form address reads as this board's own, which is the defect the
/// node prefix exists to close.
fn root() -> Address {
    let one = Tumbler::new([Nat::from(1u32)]).expect("one component is a tumbler");
    validate(one).expect("`1` is a T4-valid node address")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> Address {
        wire_address(s).expect("a T4-valid address")
    }

    /// REG-1.69's form, at the parse: a NODE address strictly under the root
    /// `1` — an org's `1.N`, a subnode beneath — and nothing else: the root
    /// itself, another first component (REG-1.67), an account or document
    /// address, a trailing zero, text no tumbler spells.
    #[test]
    fn a_node_prefix_is_a_node_address_strictly_under_the_root() {
        for ok in ["1.2", "1.3", "1.3.2", "1.1024.7"] {
            let parsed: NodePrefix =
                ok.parse().unwrap_or_else(|_| panic!("'{ok}' is a node prefix"));
            assert_eq!(parsed.address(), &addr(ok));
            assert_eq!(parsed.address().level(), Level::Node);
            assert_eq!(parsed.to_string(), ok, "and renders as the operator spelled it");
        }
        for bad in ["1", "2.4", "2", "1.3.0.7", "1.3.0.7.0.1", "1.0", "0.3", "1..3", "", "x", "1.3."] {
            assert!(bad.parse::<NodePrefix>().is_err(), "'{bad}' is not a node prefix");
        }
    }
}
