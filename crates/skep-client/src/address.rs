//! The address grammar over the wire's dotted-decimal spelling — the one
//! the frames carry and the bindings file keeps: an account's PARENT
//! account, which AUTH-5.21's walk climbs by; its FIRST CHILD, `inc(X, 1)`,
//! the agents' home (AUTH-5.87); its DOC 1 (AUTH-2.109); the DOCUMENT an
//! element or link address lies in; the parse into `skep_address`'s
//! `Address`, T4 checked; the text test a key file's `account` member is
//! held to (§3.2); and the PRINCIPAL DEPTH the namespace delegates to, which
//! every walk upward from a board-named account is held to before its first
//! read. Pure functions of their text, in every build.

use skep_address::{validate, Address, Nat, Tumbler};

/// `skep-namespace`'s `MAX_PRINCIPAL_COMPONENTS`, reproduced: a principal
/// prefix names a delegation path and is capped at 64 components — deeper
/// is `too_deep` (wire.md §Operations, `delegate`; `skep-namespace/src/
/// state.rs`'s constant, which this crate does not link, as `origin`
/// reproduces the daemon's grammar, and which its suite holds equal to this
/// one). No conforming board seats, names or delegates an account deeper:
/// `next_account_prefix` answers `null` past it, so the cone's descent is
/// bounded here and there alike, and a walk upward from an account past it
/// is refused before its first read ([`within_principal_depth`]).
pub const MAX_PRINCIPAL_COMPONENTS: usize = 64;

/// Whether `account` lies within the namespace's principal depth — at most
/// [`MAX_PRINCIPAL_COMPONENTS`] components — decided in at most 65 steps of
/// the text whatever its length, so a board-named account of any size is
/// judged without a copy of it.
pub fn within_principal_depth(account: &str) -> bool {
    account.split('.').nth(MAX_PRINCIPAL_COMPONENTS).is_none()
}

/// The parent ACCOUNT of an account address, by the address grammar: strip
/// the last component; where what remains ends at the account separator
/// (`…0`) the address was top-level and no account stands above it.
pub fn parent_account(account: &str) -> Option<String> {
    let (head, _) = account.rsplit_once('.')?;
    if head.ends_with(".0") || !head.contains(".0.") {
        return None;
    }
    Some(head.to_string())
}

/// The first child of an account — `inc(X, 1)`, the agents' home
/// (AUTH-5.87: the layout the fold and the handshake already compute).
pub fn first_child(account: &str) -> String {
    format!("{account}.1")
}

/// An account's doc 1 at its computable address (AUTH-2.109; M3's pin).
pub fn doc_1_of(account: &str) -> String {
    format!("{account}.0.1")
}

/// Parse an address in its dotted-decimal spelling.
pub fn parse_address(s: &str) -> Option<Address> {
    let comps: Option<Vec<Nat>> = s.split('.').map(|c| c.parse::<u64>().ok().map(Nat::from)).collect();
    validate(Tumbler::new(comps?).ok()?).ok()
}

/// The document an element or link address lies in: the components through
/// the one after the SECOND `0` separator.
pub fn document_of(addr: &str) -> Option<String> {
    let comps: Vec<&str> = addr.split('.').collect();
    let mut zeros = comps.iter().enumerate().filter(|(_, c)| **c == "0").map(|(i, _)| i);
    let (_first, second) = (zeros.next()?, zeros.next()?);
    (second + 1 < comps.len()).then(|| comps[..=second + 1].join("."))
}

/// An address in its one spelling: dotted decimal naturals, no sign, no
/// leading zero, at least one component.
pub fn is_address_text(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|c| {
            !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit()) && (c == "0" || !c.starts_with('0'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The address grammar's parent: a sub-account's parent is an account,
    /// a top-level account's is none.
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

    /// The text test admits the one spelling — dotted naturals, no sign, no
    /// leading zero, no empty component — and the parse takes dotted
    /// naturals and nothing else.
    #[test]
    fn the_text_test_and_the_parse_take_dotted_naturals() {
        assert!(is_address_text("1.0.1") && is_address_text("0"));
        for bad in ["", "1..1", "1.01", "+1", "1.0x", "1."] {
            assert!(!is_address_text(bad), "{bad:?} is no address's spelling");
        }
        assert!(parse_address("1.0.1.0.1").is_some());
        assert!(parse_address("1.x").is_none() && parse_address("").is_none());
    }

    /// The depth bound is the namespace's own constant, reproduced: where the
    /// namespace moves its bound, this fails, and no walk stops short of a
    /// depth the board still delegates at.
    #[test]
    fn the_depth_bound_is_the_namespaces_own() {
        assert_eq!(MAX_PRINCIPAL_COMPONENTS, skep_namespace::MAX_PRINCIPAL_COMPONENTS);
    }

    /// The namespace's depth admitted to its last component and refused one
    /// past it, whatever the text runs to after.
    #[test]
    fn the_principal_depth_admits_sixty_four_components_and_no_more() {
        let deep = |n: usize| format!("1.0.1{}", ".1".repeat(n - 3));
        assert!(within_principal_depth("1.0.1") && within_principal_depth(&deep(64)));
        assert!(!within_principal_depth(&deep(65)) && !within_principal_depth(&deep(4_000_000)));
    }
}
