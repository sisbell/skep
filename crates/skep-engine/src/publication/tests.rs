use serde::Deserialize;
use skep_address::{validate, Nat, Tumbler};
use skep_namespace::{HasM3, PrincipalId};

use crate::canon::{to_tree, SerdeTree, TreeDe};
use crate::testkit::{addr, delegated_account, mem_engine, USER};

use super::*;

/// M3's slice holding one account under the genesis node and one DRAFT
/// document in it, driven through the real drivers, with the two
/// addresses.
fn account_with_a_draft() -> (M3State, Address, Address) {
    let engine = mem_engine();
    let acct = delegated_account(&engine, USER);
    let (doc, _) = engine
        .namespace()
        .create_new_document(USER, &acct, Some(false))
        .expect("an explicit-false mint is a draft");
    let namespace = engine.kernel().snapshot().world().m3().clone();
    (namespace, acct, doc)
}

/// `namespace` with its serde map field `field` edited by `edit`, then
/// decoded back through M3's own door. Built through the slice's serde form
/// (`crate::canon`), so nothing here reaches a private layout: the coupling
/// is to the field NAME, and the panics below are what stand in for a
/// compiler edge to it.
fn with_map_field_edited(
    namespace: &M3State,
    field: &str,
    edit: impl FnOnce(&mut Vec<(SerdeTree, SerdeTree)>),
) -> M3State {
    let mut tree = to_tree(namespace);
    let SerdeTree::Map(fields) = &mut tree else {
        panic!("M3State serializes as a struct — a map of its fields");
    };
    let map = fields
        .iter_mut()
        .find_map(|(name, value)| match name {
            SerdeTree::Str(s) if s.as_str() == field => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("M3State serializes a `{field}` field"));
    let SerdeTree::Map(entries) = map else {
        panic!("M3's `{field}` serializes as a map keyed by address");
    };
    edit(entries);
    M3State::deserialize(TreeDe(&tree)).expect("M3's own types re-admit what they wrote")
}

/// `namespace` with the entry keyed by `key` struck from its serde map
/// field `field`. A whole `M3State` decodes by bare derive, and M3's own
/// docs name both strikes this suite makes as shapes a slice can arrive
/// in: a SEAT struck from Π (`principals`: "a seat can also arrive inside
/// a whole `M3State`, which decodes by bare derive"), and a registered
/// document's entry struck from the PUBLICATION map (`documents`: a
/// checkpoint "can hold a registered document with NO entry").
fn with_entry_struck(namespace: &M3State, field: &str, key: &Address) -> M3State {
    let rendered = to_tree(key).to_string();
    with_map_field_edited(namespace, field, |entries| {
        let before = entries.len();
        entries.retain(|(entry_key, _)| entry_key.to_string() != rendered);
        assert_eq!(
            before - entries.len(),
            1,
            "the `{field}` entry keyed {key} must have been there to strike"
        );
    })
}

/// …and with an entry `key → value` ADDED: the other shape a slice decoded
/// by bare derive can carry and no fold produces — M3's `documents` names
/// it too, telling a reader that must not fail-stop on a corrupted slice
/// to re-ask registration per entry.
fn with_entry_added(
    namespace: &M3State,
    field: &str,
    key: &Address,
    value: SerdeTree,
) -> M3State {
    let added = to_tree(key);
    let rendered = added.to_string();
    with_map_field_edited(namespace, field, |entries| {
        assert!(
            entries.iter().all(|(entry_key, _)| entry_key.to_string() != rendered),
            "the `{field}` entry keyed {key} must be new"
        );
        entries.push((added, value));
    })
}

/// The seed over a well-formed slice: the draft, memoized against the
/// ACCOUNT it was minted under. The premise the corruptions below are
/// read against — without it, a test that panics or reads a document
/// published proves only that something went wrong.
#[test]
fn the_seed_memoizes_a_draft_s_own_account() {
    let (namespace, acct, doc) = account_with_a_draft();
    let drafts = seed(&namespace);
    assert_eq!(drafts.get(&doc), Some(&acct));
    assert_eq!(acct.level(), Level::Account);
    assert!(!is_published(&drafts, &doc));
}

/// A draft whose OWN account's seat is struck while the genesis NODE above
/// still covers it: ω answers that node, and memoizing it is the fail-OPEN
/// direction — [`crate::World::readable`]'s subtree clause is a bare
/// `prefix_contains` against the memo, and a node prefix contains every
/// account beneath it, so every seated principal in the docuverse would read
/// this draft and each read would look like an ordinary pass. The memo is
/// read from the draft's own account, which answers nobody, and the draft is
/// refused, in every build.
#[test]
#[should_panic(expected = "has no owner account")]
fn a_draft_whose_own_account_is_unseated_is_refused_where_omega_answers_the_node() {
    let (namespace, acct, doc) = account_with_a_draft();
    let corrupt = with_entry_struck(&namespace, "principals", &acct);
    // The fixture must still reach the owner lookup: the document is
    // registered and its bit is still `false`, so `draft_entry` does not
    // return before it…
    assert!(corrupt.is_registered_document(&doc), "the mint's registration is untouched");
    assert!(!corrupt.published(&doc), "the mint's bit is untouched");
    // …and ω must now answer ABOVE the account tier, or this test would
    // pass for some other reason.
    assert_eq!(
        corrupt.effective_owner_prefix(&doc).map(Address::level),
        Some(Level::Node),
        "the struck seat must leave ω answering the node above the account"
    );
    let _ = seed(&corrupt);
}

/// The ANCESTOR-ACCOUNT shape, which no tier check sees: a draft under a
/// sub-account whose seat is struck while its parent's stands, so ω answers
/// the PARENT — account-tier — and a memo of it would admit every principal
/// seated under the parent, the owner's siblings included, through the
/// subtree clause's first compare. The memo is read from the draft's OWN
/// account, which answers nobody, and the draft is refused.
#[test]
#[should_panic(expected = "has no owner account")]
fn a_draft_under_an_unseated_sub_account_is_refused_rather_than_memoized_to_its_parent() {
    let engine = mem_engine();
    let acct = delegated_account(&engine, USER);
    let sub_prefix = engine
        .kernel()
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(&acct)
        .expect("the account has a delegable sub-account slot");
    let owner = PrincipalId(8);
    let (sub, _) = engine
        .namespace()
        .delegate(USER, sub_prefix.into(), owner)
        .expect("the account holder delegates a sub-account");
    let (doc, _) = engine
        .namespace()
        .create_new_document(owner, &sub, Some(false))
        .expect("an explicit-false mint is a draft");
    let namespace = engine.kernel().snapshot().world().m3().clone();
    let corrupt = with_entry_struck(&namespace, "principals", &sub);
    // The fixture must reach the owner lookup with ω answering an ACCOUNT,
    // or this would pass for the node-tier reason the test above pins.
    assert!(corrupt.is_registered_document(&doc), "the mint's registration is untouched");
    assert!(!corrupt.published(&doc), "the mint's bit is untouched");
    assert_eq!(
        corrupt.effective_owner_prefix(&doc),
        Some(&acct),
        "the struck seat must leave ω answering the parent ACCOUNT"
    );
    let _ = seed(&corrupt);
}

/// The EXISTENCE assertion where ω, too, answers NOBODY — the seat of the
/// draft's own account and the genesis node's above it both struck: the
/// draft is refused, never skipped. Skipping is the tempting repair on a load
/// path, and here it fails open: a skipped draft is absent from the set,
/// which every reader class reads as published.
#[test]
#[should_panic(expected = "has no owner account")]
fn a_draft_whose_owner_resolves_to_nobody_is_refused_rather_than_skipped() {
    let (namespace, acct, doc) = account_with_a_draft();
    let seatless = with_entry_struck(
        &with_entry_struck(&namespace, "principals", &acct),
        "principals",
        &addr(&[1]),
    );
    // The fixture must still reach the owner lookup, and reach it with
    // nothing to find: registered, private, and covered by no seat.
    assert!(seatless.is_registered_document(&doc), "the mint's registration is untouched");
    assert!(!seatless.published(&doc), "the mint's bit is untouched");
    assert_eq!(seatless.effective_owner_prefix(&doc), None, "no seat covers the draft");
    let _ = seed(&seatless);
}

/// The OPEN DIRECTION the set inherits from its enumeration, over the one
/// shape that reaches it: a REGISTERED document whose publication entry is
/// gone. M3 answers it private and its walk no longer yields it, so the
/// seed never asks the rule of it, and the set reads it PUBLISHED — past a
/// registration check, since the document IS registered. The rule itself,
/// asked of the document directly, answers DRAFT, which is what locates
/// the gap: in the ENUMERATION, not in the rule.
///
/// Pinned so the direction cannot change unnoticed, not endorsed. The
/// shape lies outside M3's fold's totality domain — a jumped `Allocate`
/// is its live route, and M3's debug contiguity check refuses one — so it
/// is built through M3's serde door, the checkpoint route, rather than
/// through an op.
#[test]
fn a_registered_document_with_no_publication_entry_reads_published_to_the_set() {
    let (namespace, _acct, doc) = account_with_a_draft();
    let corrupt = with_entry_struck(&namespace, "publication", &doc);
    assert!(corrupt.is_registered_document(&doc), "the registration is untouched");
    assert!(
        corrupt.documents().all(|(document, _)| document != &doc),
        "M3's walk no longer yields the document"
    );
    assert!(!corrupt.published(&doc), "M3 answers the missing entry PRIVATE");
    assert!(draft_entry(&corrupt, &doc).is_some(), "the rule, asked of it, answers DRAFT");
    assert!(
        is_published(&seed(&corrupt), &doc),
        "the set, whose seed never asks the rule of it, reads it PUBLISHED"
    );
}

/// The seed's REGISTRATION RE-ASK, stated on both sides of the seam —
/// [`draft_entry`] here, and M3's `documents`, which tells a reader that
/// must not fail-stop on a corrupted slice to re-ask registration per
/// entry "as the engine's seed does". M3's walk yields EVERY entry of its
/// publication map, and a slice decoded by bare derive can carry one for an
/// address the registry never held. A seed trusting the bit the walk yields
/// beside it — one lookup cheaper per document — would memoize that
/// address as a DRAFT here, where the account above it answers ω, and
/// `World::published` would answer `false` for an address no mint
/// produced: the TOTAL contract's postcondition broken, and M10's door
/// answering WITHHELD naming it (PUB-6.12). On a slice M3's fold produced
/// every entry is a registered document, so no other fixture can tell the
/// two seeds apart.
#[test]
fn the_seed_skips_an_entry_for_an_address_the_registry_never_held() {
    let (namespace, acct, doc) = account_with_a_draft();
    let comps = acct.tumbler().iter().cloned().chain([Nat::from(0u32), Nat::from(99u32)]);
    let phantom = validate(Tumbler::new(comps).expect("nonempty"))
        .expect("a document-tier address under the account is T4-valid");
    let corrupt = with_entry_added(&namespace, "publication", &phantom, SerdeTree::Bool(false));
    // The premise, where it can fail: M3's walk yields the entry as private…
    assert!(
        corrupt.documents().any(|(document, published)| document == &phantom && !published),
        "M3's walk yields the added entry, its bit private"
    );
    // …the registry never held the address…
    assert!(!corrupt.is_registered_document(&phantom), "no mint produced it");
    // …and the account above it — its own — holds a seat, so a seed that
    // asked the owner would memoize the address rather than panic.
    assert_eq!(corrupt.account_seat(&phantom).map(|(seat, _)| seat), Some(&acct));

    let drafts = seed(&corrupt);
    assert!(
        is_published(&drafts, &phantom),
        "the seed memoized an address no mint produced as a draft: `published` would answer \
         false"
    );
    assert_eq!(drafts.get(&doc), Some(&acct), "…while the registered draft is memoized");
    assert_eq!(drafts.len(), 1, "one draft, and none for the address the registry never held");
}
