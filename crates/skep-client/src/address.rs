//! The address grammar over the wire's dotted-decimal spelling.
//!
//! The spelling is the one the frames carry and the bindings file keeps.
//! The grammar gives an account's parent account, which AUTH-5.21's walk
//! climbs by; its first child, `inc(X, 1)`, the agents' home (AUTH-5.87);
//! its doc 1 (AUTH-2.109); the document an element or link address lies
//! in; the parse into `skep_address`'s `Address`, T4 checked; the text test
//! a key file's `account` member is held to (§3.2); and the principal depth
//! the namespace delegates to, which every walk upward from a board-named
//! account is held to before its first read. Pure functions of their text,
//! in every build.

use skep_address::{validate, Address, Nat, Tumbler};

/// `skep-namespace`'s `MAX_PRINCIPAL_COMPONENTS`, reproduced.
///
/// A principal prefix names a delegation path and is capped at 64
/// components — deeper is `too_deep` (wire.md §Operations, `delegate`;
/// `skep-namespace/src/state.rs`'s constant, which this crate does not
/// link, as `origin` reproduces the daemon's grammar, and which its suite
/// holds equal to this one). No conforming board seats, names or delegates
/// an account deeper: `next_account_prefix` answers `null` past it, so the
/// cone's descent is bounded here and there alike, and a walk upward from
/// an account past it is refused before its first read
/// ([`within_principal_depth`]).
pub const MAX_PRINCIPAL_COMPONENTS: usize = 64;

/// Returns whether `account` lies within the namespace's principal depth.
///
/// The depth is at most [`MAX_PRINCIPAL_COMPONENTS`] components, decided in
/// at most 65 steps of the text whatever its length, so a board-named
/// account of any size is judged without a copy of it.
pub fn within_principal_depth(account: &str) -> bool {
    account.split('.').nth(MAX_PRINCIPAL_COMPONENTS).is_none()
}

/// Returns the parent account of an account address, by the address grammar.
///
/// The grammar strips the last component; where what remains ends at the
/// account separator (`…0`) the address was top-level and no account
/// stands above it.
pub fn parent_account(account: &str) -> Option<String> {
    let (head, _) = account.rsplit_once('.')?;
    if head.ends_with(".0") || !head.contains(".0.") {
        return None;
    }
    Some(head.to_string())
}

/// Returns the first child of an account — `inc(X, 1)`, the agents' home.
///
/// AUTH-5.87: the layout the fold and the handshake already compute.
pub fn first_child(account: &str) -> String {
    format!("{account}.1")
}

/// Returns an account's doc 1 at its computable address (AUTH-2.109; M3's pin).
pub fn doc_1_of(account: &str) -> String {
    format!("{account}.0.1")
}

/// Parses an address in its dotted-decimal spelling.
pub fn parse_address(s: &str) -> Option<Address> {
    let comps: Option<Vec<Nat>> = s.split('.').map(|c| c.parse::<u64>().ok().map(Nat::from)).collect();
    validate(Tumbler::new(comps?).ok()?).ok()
}

/// Returns the account an address lies in, `N.0.U`, as the wire reads
/// ownership off an address (wire.md §The read predicate).
///
/// It is the node field, the account separator and the account field — the
/// prefix every document, link and element of the account lies under. The
/// publication's owned-home test compares it to the person's account
/// EXACTLY (the link-sets design §5.1: "its account the person's exactly …
/// never an account nested under theirs"), so a sub-account's home is not
/// the person's. `None` for a node, or a text that is no address.
pub fn account_of(addr: &str) -> Option<String> {
    let parsed = parse_address(addr)?;
    let node: Vec<String> = parsed.node_field().iter().map(ToString::to_string).collect();
    let account: Vec<String> = parsed.account_field()?.iter().map(ToString::to_string).collect();
    Some(format!("{}.0.{}", node.join("."), account.join(".")))
}

/// Returns the document an element or link address lies in.
///
/// The document is the components through the one after the second `0`
/// separator.
pub fn document_of(addr: &str) -> Option<String> {
    let comps: Vec<&str> = addr.split('.').collect();
    let mut zeros = comps.iter().enumerate().filter(|(_, c)| **c == "0").map(|(i, _)| i);
    let (_first, second) = (zeros.next()?, zeros.next()?);
    (second + 1 < comps.len()).then(|| comps[..=second + 1].join("."))
}

/// Returns whether `s` is an address in its one spelling.
///
/// The spelling is dotted decimal naturals, no sign, no leading zero, at
/// least one component.
pub fn is_address_text(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|c| {
            !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit()) && (c == "0" || !c.starts_with('0'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The address grammar's parent: a sub-account's parent is an account.
    ///
    /// A top-level account's is none.
    #[test]
    fn the_parent_account_stops_at_the_top_level() {
        assert_eq!(parent_account("1.0.1.1"), Some("1.0.1".into()));
        assert_eq!(parent_account("1.0.1.2.3"), Some("1.0.1.2".into()));
        assert_eq!(parent_account("1.0.1"), None);
        assert_eq!(parent_account("1.3.0.7"), None);
        assert_eq!(first_child("1.0.1"), "1.0.1.1");
        assert_eq!(doc_1_of("1.0.1"), "1.0.1.0.1");
    }

    #[test]
    fn the_document_of_a_link_or_element_address() {
        assert_eq!(document_of("1.0.1.0.1.0.2.3"), Some("1.0.1.0.1".into()));
        assert_eq!(document_of("1.0.1.0.1.0.1.1"), Some("1.0.1.0.1".into()));
        assert_eq!(document_of("1.0.1.1.0.1.0.2.1"), Some("1.0.1.1.0.1".into()));
        assert_eq!(document_of("1.0.1"), None);
    }

    /// The account an address lies in, as the wire reads ownership: a
    /// sub-account's home is the sub-account's, never its parent's — the
    /// owned-home test compares exactly.
    #[test]
    fn the_account_of_an_address_is_its_own_and_never_a_parents() {
        assert_eq!(account_of("1.0.1.0.2.0.2.3"), Some("1.0.1".into()));
        assert_eq!(account_of("1.0.1.0.2"), Some("1.0.1".into()));
        assert_eq!(account_of("1.0.1.2.0.1.0.1.4"), Some("1.0.1.2".into()));
        assert_eq!(account_of("1.0.1"), Some("1.0.1".into()));
        assert_eq!(account_of("1"), None, "a node");
        assert_eq!(account_of("1.x"), None);
        assert_ne!(account_of("1.0.1.2.0.1"), Some("1.0.1".into()), "nested under, not the person's");
    }

    /// The text test admits the one spelling; the parse takes dotted naturals.
    ///
    /// The one spelling is dotted naturals, no sign, no leading zero, no
    /// empty component, and the parse takes nothing else.
    #[test]
    fn the_text_test_and_the_parse_take_dotted_naturals() {
        assert!(is_address_text("1.0.1") && is_address_text("0"));
        for bad in ["", "1..1", "1.01", "+1", "1.0x", "1."] {
            assert!(!is_address_text(bad), "{bad:?} is no address's spelling");
        }
        assert!(parse_address("1.0.1.0.1").is_some());
        assert!(parse_address("1.x").is_none() && parse_address("").is_none());
    }

    /// The depth bound is the namespace's own constant, reproduced.
    ///
    /// Where the namespace moves its bound, this fails, and no walk stops
    /// short of a depth the board still delegates at.
    #[test]
    fn the_depth_bound_is_the_namespaces_own() {
        assert_eq!(MAX_PRINCIPAL_COMPONENTS, skep_namespace::MAX_PRINCIPAL_COMPONENTS);
    }

    /// The namespace's depth admits its last component and refuses one past.
    ///
    /// The refusal holds whatever the text runs to after.
    #[test]
    fn the_principal_depth_admits_sixty_four_components_and_no_more() {
        let deep = |n: usize| format!("1.0.1{}", ".1".repeat(n - 3));
        assert!(within_principal_depth("1.0.1") && within_principal_depth(&deep(64)));
        assert!(!within_principal_depth(&deep(65)) && !within_principal_depth(&deep(4_000_000)));
    }
}
