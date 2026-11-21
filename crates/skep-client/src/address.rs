//! The address grammar over the wire's dotted-decimal spelling.
//!
//! The spelling is the one the frames carry and the bindings file keeps.
//! The grammar gives an account's parent account, which AUTH-5.21's walk
//! climbs by; its first child, `inc(X, 1)`, the agents' home (AUTH-5.87);
//! its doc 1 (AUTH-2.109); its four well-known documents, each at a slot of
//! its own — the mailbox at [`MAILBOX_SLOT`], the bio at [`BIO_SLOT`], the
//! link page at [`LINK_PAGE_SLOT`] and the account's policy document at
//! [`POLICY_SLOT`] (the mailbox design §2; REG-4.131); the number its
//! documents are
//! counted from past doc 1, [`FIRST_ORDINARY_DOCUMENT`]; the document an
//! element or link address lies in; the parse into `skep_address`'s
//! `Address`, T4 checked;
//! the text test a key file's `account` member is held to (§3.2); and the
//! principal depth the namespace delegates to, which every walk upward from
//! a board-named account is held to before its first read. Pure functions
//! of their text, in every build.

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

/// `skep-namespace`'s `FIRST_ORDINARY_DOCUMENT`, reproduced.
///
/// It is the first document number an account's counter hands out after its
/// doc 1: an account's documents are numbered 1 and then from here on, and
/// the numbers between are reserved for well-known documents, the four
/// slots from [`MAILBOX_SLOT`] to [`POLICY_SLOT`] among them (the mailbox
/// design §2). So an account's
/// second document stands at `<account>.0.` and this number. The namespace's
/// constant is the one spelling of the number (`skep-namespace/src/ns.rs`);
/// this crate does not link that one, so it holds this copy for the tools
/// above it that link neither, and its suite holds the two equal.
pub const FIRST_ORDINARY_DOCUMENT: u64 = 64;

/// The well-known slot of an account's mailbox: document 2.
///
/// The mailbox design §2: every account but the system account has one
/// mailbox, at this document number. It is `skep-namespace`'s
/// `MAILBOX_SLOT`, reproduced: the board mints an account's mailbox at the
/// namespace's constant (`skep-namespace/src/ns.rs`), which this crate does
/// not link, and its suite holds the two equal.
pub const MAILBOX_SLOT: u64 = 2;

/// The well-known slot of an account's bio: document 3.
///
/// The mailbox design §2: a published document others' apps read at a
/// computed address, with no lookup. It is `skep-namespace`'s `BIO_SLOT`,
/// reproduced as [`MAILBOX_SLOT`] is, and this crate's suite holds the two
/// equal.
pub const BIO_SLOT: u64 = 3;

/// The well-known slot of an account's link page: document 4.
///
/// The mailbox design §2: the account's public link page, published as the
/// bio is. It is `skep-namespace`'s `LINK_PAGE_SLOT`, reproduced as
/// [`MAILBOX_SLOT`] is, and this crate's suite holds the two equal.
pub const LINK_PAGE_SLOT: u64 = 4;

/// The well-known slot of an account's policy document: document 5.
///
/// It is the account's policy document, published: at a registry's door
/// account, the admission policy an applicant reads as a guest (REG-4.131).
/// It is `skep-namespace`'s `POLICY_SLOT`, reproduced as [`MAILBOX_SLOT`]
/// is, and this crate's suite holds the two equal.
pub const POLICY_SLOT: u64 = 5;

/// The four well-known slots, in the order of their numbers.
///
/// They are every number a `create_well_known_document` may name (wire.md
/// §Namespace): the board refuses any other at its parse.
pub const WELL_KNOWN_SLOTS: [u64; 4] = [MAILBOX_SLOT, BIO_SLOT, LINK_PAGE_SLOT, POLICY_SLOT];

/// Returns the address of an account's document at the well-known slot `slot`.
///
/// The address is the account's own, then `.0.` and the slot's number (the
/// mailbox design §2). It names a place whether or not a document stands
/// there, in the spelling the account came in, and it is the address the
/// signature over the slot's creation names (wire.md §Credential refusals).
/// Neither text is checked: the account to be an account's, nor `slot` to be
/// one of [`WELL_KNOWN_SLOTS`]. For the system account the slots are its own
/// table, no account's well-known documents.
pub fn well_known_of(account: &str, slot: u64) -> String {
    format!("{account}.0.{slot}")
}

/// Returns an account's mailbox at its computable address.
///
/// The address is the account's own, then `.0.` and [`MAILBOX_SLOT`] (the
/// mailbox design §2). It names a place whether or not a document stands
/// there: mail points at it from the moment the account exists, and nothing
/// in mail needs the mailbox document minted (§3). The board mints one with
/// every account's home page, in the same commit, so a document stands there
/// wherever the account's doc 1 does. The answer is in the
/// spelling the account came in — a board's own form of an account gives
/// that board's own form of its mailbox, the global form the global one —
/// and the text is not checked to be an account's. The system account has
/// no mailbox: in its table the slot is the head document,
/// `board::HEAD_DOCUMENT`, which `mailbox_of("1.1.0.1")` answers.
pub fn mailbox_of(account: &str) -> String {
    well_known_of(account, MAILBOX_SLOT)
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

    /// An account's mailbox is its address, then `.0.` and the mailbox slot.
    ///
    /// The answer keeps the spelling the account came in, a board's own form
    /// or the global one, and an agent's account has a mailbox as any other
    /// has. The system account has none: there the slot is the head document.
    #[test]
    fn the_mailbox_of_an_account_is_its_slot_2_in_the_spelling_given() {
        assert_eq!(mailbox_of("1.0.5"), "1.0.5.0.2", "a board's own form");
        assert_eq!(mailbox_of("1.3.0.5"), "1.3.0.5.0.2", "the global form, node prefix `1.3`");
        assert_eq!(mailbox_of("1.0.5.1.1"), "1.0.5.1.1.0.2", "an agent's account");
        assert_eq!(MAILBOX_SLOT, 2);
        assert_eq!(account_of(&mailbox_of("1.0.5")), Some("1.0.5".into()));
        assert!(parse_address(&mailbox_of("1.0.5")).is_some(), "the answer is an address");
        assert_eq!(mailbox_of("1.1.0.1"), crate::board::HEAD_DOCUMENT, "the system account's slot is its head document");
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
        assert_eq!(account_of("1.0.1.0.64.0.2.3"), Some("1.0.1".into()));
        assert_eq!(account_of("1.0.1.0.64"), Some("1.0.1".into()));
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

    /// The first ordinary document is the namespace's own constant, held.
    ///
    /// Where the namespace moves the number its counter resumes at, this
    /// fails and names the copy to move, so no tool above this crate looks
    /// for an account's second document where the board no longer puts it.
    /// The mailbox's slot lies below it, in the block the counter steps over.
    #[test]
    fn the_first_ordinary_document_is_the_namespaces_own() {
        assert_eq!(FIRST_ORDINARY_DOCUMENT, u64::from(skep_namespace::FIRST_ORDINARY_DOCUMENT));
        assert!(1 < MAILBOX_SLOT && MAILBOX_SLOT < FIRST_ORDINARY_DOCUMENT);
    }

    /// The mailbox's slot is the namespace's own constant, held.
    ///
    /// Where either number moves alone, this fails and names the other, so
    /// the address this crate computes for an account's mailbox is the one
    /// the board mints it at: the namespace's own address for the slot, in
    /// the wire's spelling, for an account, an agent's account and the
    /// system account alike.
    #[test]
    fn the_mailbox_slot_is_the_namespaces_own() {
        assert_eq!(MAILBOX_SLOT, u64::from(skep_namespace::MAILBOX_SLOT));
        for account in ["1.0.5", "1.3.0.5", "1.0.5.1.1", "1.1.0.1"] {
            let parsed = parse_address(account).expect("an account's address");
            let minted = skep_namespace::mailbox_address(&parsed).expect("an account has a mailbox slot");
            assert_eq!(mailbox_of(account), minted.to_string(), "{account}");
        }
    }

    /// The four well-known slots are the namespace's own, held, number by
    /// number and as a set.
    ///
    /// Where a number moves on either side alone, or the namespace names a
    /// slot this crate does not, this fails and names it, so the address
    /// this crate computes for a slot — the one a creation's signature
    /// names — is the one the board creates the document at, for an
    /// account, an agent's account and an account under another node alike.
    #[test]
    fn the_well_known_slots_are_the_namespaces_own() {
        use skep_namespace::WellKnownSlot;
        assert_eq!(BIO_SLOT, u64::from(skep_namespace::BIO_SLOT));
        assert_eq!(LINK_PAGE_SLOT, u64::from(skep_namespace::LINK_PAGE_SLOT));
        assert_eq!(POLICY_SLOT, u64::from(skep_namespace::POLICY_SLOT));
        assert_eq!(WELL_KNOWN_SLOTS, WellKnownSlot::ALL.map(|slot| u64::from(slot.number())), "every slot the namespace names, and no other");
        for number in 0..=FIRST_ORDINARY_DOCUMENT + 1 {
            let named = u32::try_from(number).ok().and_then(WellKnownSlot::named);
            assert_eq!(WELL_KNOWN_SLOTS.contains(&number), named.is_some(), "document number {number}");
        }
        for account in ["1.0.5", "1.3.0.5", "1.0.5.1.1"] {
            let parsed = parse_address(account).expect("an account's address");
            for slot in WellKnownSlot::ALL {
                let created = skep_namespace::well_known_address(&parsed, slot).expect("an account has the slot");
                assert_eq!(well_known_of(account, u64::from(slot.number())), created.to_string(), "{account} {slot:?}");
            }
        }
        assert_eq!(well_known_of("1.0.5", POLICY_SLOT), "1.0.5.0.5");
        assert!(WELL_KNOWN_SLOTS.iter().all(|slot| 1 < *slot && *slot < FIRST_ORDINARY_DOCUMENT));
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
