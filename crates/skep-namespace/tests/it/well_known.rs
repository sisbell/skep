//! §B create_well_known_document over every slot: the four well-known
//! documents an account's owner creates (the mailbox design §2, §3;
//! REG-4.131) — the mailbox at 2, the bio at 3, the link page at 4 and the
//! account's policy document at 5. What holds of each slot and of the four
//! together: the address a creation lands at and the state it is created in,
//! the slot's own and no caller's; that a document created published holds
//! nothing and is an ordinary document from then on; that a slot is created
//! once and one slot never answers for another; that no creation moves a
//! count; who may ask, at every slot; that the system account is refused at
//! every slot, by the store itself; which creations commit under the
//! handle's attestation; and that the four recover from the journal and from
//! a checkpoint. The mailbox's own cells are `mailbox.rs`'s.

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::common::*;

use skep_address::{Address, Level};
use skep_kernel::{Attestation, Kernel};
use skep_namespace::{
    first_version_address, head_document, mailbox_address, staging_draft, system_account,
    time_document, well_known_address, CreateDocumentError, HasM3, M3Rec, M3State, MintError,
    Namespace, WellKnown, WellKnownSlot, BIO_SLOT, BOOTSTRAP_PRINCIPAL, FIRST_ORDINARY_DOCUMENT,
    LINK_PAGE_SLOT, MAILBOX_SLOT, POLICY_SLOT, SYSTEM_PRINCIPAL,
};
use tempfile::tempdir;

/// The three slots whose document is created published.
const PUBLISHED_SLOTS: [WellKnownSlot; 3] =
    [WellKnownSlot::Bio, WellKnownSlot::LinkPage, WellKnownSlot::Policy];

/// The slots are four, at document numbers 2, 3, 4 and 5, each constant the
/// one spelling of its number; they are exactly the numbers the fold admits
/// a record at in the reserved block, and each fixes the state its document
/// is created in: the mailbox private, the other three published. The
/// address of a slot is that number on the account's document chain, for an
/// account under any node and at any depth, registered or not, and for no
/// other tier; the mailbox's by name is the same address.
#[test]
fn the_four_slots_are_documents_2_to_5_each_with_a_state_of_its_own() {
    assert_eq!((MAILBOX_SLOT, BIO_SLOT, LINK_PAGE_SLOT, POLICY_SLOT), (2, 3, 4, 5));
    let numbered: Vec<(WellKnownSlot, u32, bool)> =
        WellKnownSlot::ALL.into_iter().map(|s| (s, s.number(), s.born_published())).collect();
    assert_eq!(
        numbered,
        [
            (WellKnownSlot::Mailbox, MAILBOX_SLOT, false),
            (WellKnownSlot::Bio, BIO_SLOT, true),
            (WellKnownSlot::LinkPage, LINK_PAGE_SLOT, true),
            (WellKnownSlot::Policy, POLICY_SLOT, true),
        ],
        "the slot table: its numbers, and the state each document is created in"
    );
    assert_eq!(
        WellKnownSlot::ALL.map(WellKnownSlot::number),
        NAMED_SLOTS,
        "the type names the slots the fold admits a record at, and no other"
    );
    for number in 0..=FIRST_ORDINARY_DOCUMENT + 1 {
        assert_eq!(
            WellKnownSlot::named(number).map(WellKnownSlot::number),
            NAMED_SLOTS.contains(&number).then_some(number),
            "document number {number}"
        );
    }
    assert_eq!(WellKnownSlot::named(u32::MAX), None);

    for account in [a(&[1, 0, 1]), a(&[1, 0, 9]), a(&[1, 0, 5, 1, 1]), a(&[1, 3, 0, 5])] {
        for slot_named in WellKnownSlot::ALL {
            let at = well_known_address(&account, slot_named).expect("an account has the slot");
            assert_eq!(at, slot(&account, slot_named.number()), "{account} {slot_named:?}");
            assert_eq!(at.level(), Level::Document);
            assert!(
                !M3State::genesis().is_allocated(&at),
                "{at}: the address names the slot, and nothing stands there"
            );
        }
        assert_eq!(
            mailbox_address(&account),
            well_known_address(&account, WellKnownSlot::Mailbox),
            "{account}: the mailbox's address by name is its slot's"
        );
    }
    // The system account's table is its own: the same numbers are its head
    // document, its staging draft and its time document, and 5 holds nothing.
    let system = system_account();
    assert_eq!(well_known_address(&system, WellKnownSlot::Mailbox), Some(head_document()));
    assert_eq!(well_known_address(&system, WellKnownSlot::Bio), Some(staging_draft()));
    assert_eq!(well_known_address(&system, WellKnownSlot::LinkPage), Some(time_document()));
    let system_5 = well_known_address(&system, WellKnownSlot::Policy).expect("an account's slot");
    assert!(!M3State::genesis().is_registered_document(&system_5), "genesis seeds nothing at 5");
    // Only an account anchors a document chain.
    for off_tier in [a(&[1]), a(&[1, 0, 1, 0, 1]), a(&[1, 0, 1, 0, 5]), a(&[1, 0, 1, 0, 1, 0, 1, 1])] {
        for slot_named in WellKnownSlot::ALL {
            assert_eq!(well_known_address(&off_tier, slot_named), None, "{off_tier}");
        }
    }
}

/// A creation lands at `<account>.0.<slot>` in the slot's own state, whatever
/// the account's count: the mailbox private, the bio, the link page and the
/// policy document published. No argument of the op chooses the state. The
/// document is registered in the commit that answers it, entered in the
/// position map at that commit, owned at the account's own seat, and holds
/// nothing: no version, no content, no link — a home like any document, whose
/// chains open at their first slots, so its first version is `.1`.
#[test]
fn each_slot_is_created_at_its_own_address_in_its_own_state_holding_nothing() {
    for later in [0u32, 2] {
        let (k, acct, _doc) = kernel_with_account_and_doc();
        let ns = Namespace::new(&k);
        for _ in 0..later {
            ns.create_new_document(ID1, &acct, None).expect("a later document");
        }
        for slot_named in WellKnownSlot::ALL {
            let expected = slot(&acct, slot_named.number());
            let before = k.current_seq();
            assert!(!k.snapshot().world().m3().is_registered_document(&expected));

            let (created, at) = ns
                .create_well_known_document(ID1, &acct, slot_named)
                .expect("the account's owner creates the slot's document");
            assert_eq!(created, WellKnown::Minted(expected.clone()), "{slot_named:?}, {later} later");
            // Commit-before-acknowledge: the position is the creation's own.
            assert_eq!(at, Seq(before.0 + 1), "{slot_named:?}");
            assert_eq!(k.current_seq(), at);

            let m3 = k.snapshot().world().m3().clone();
            assert!(m3.is_registered_document(&expected), "{expected}");
            assert_eq!(
                m3.published(&expected),
                slot_named.born_published(),
                "{expected}: created in the slot's own state"
            );
            assert_eq!(
                m3.published(&expected),
                slot_named != WellKnownSlot::Mailbox,
                "{expected}: the mailbox private, every other slot published"
            );
            assert_eq!(
                m3.documents().find(|(doc, _)| **doc == expected),
                Some((&expected, slot_named.born_published())),
                "the publication walk holds the document with its bit"
            );
            assert_eq!(m3.minted_at(&expected), Some(at));
            assert_eq!(m3.effective_owner(&expected), Some(ID1));
            assert_eq!(m3.account_seat(&expected), Some((&acct, ID1)));
            // It holds nothing, and is a home and a version's source.
            assert_eq!(m3.latest_version(&expected), None, "{expected} holds a version");
            assert_eq!(
                m3.mint_version(&expected, true).expect("a slot document is a version's source").0,
                first_version_address(&expected).expect("a document anchors a version chain"),
                "{expected}: its first version is its chain's first member"
            );
            assert_eq!(
                m3.mint_content(&expected).expect("a slot document is a home").0,
                under(&expected, &[0, 1, 1])
            );
            assert_eq!(
                m3.mint_link(&expected).expect("a slot document is a home").0,
                under(&expected, &[0, 2, 1])
            );
        }
        // The four stand, and no other number of the block does.
        let m3 = k.snapshot().world().m3().clone();
        for number in 2..FIRST_ORDINARY_DOCUMENT {
            assert_eq!(
                m3.is_registered_document(&slot(&acct, number)),
                NAMED_SLOTS.contains(&number),
                "document {number} of the block, {later} later documents"
            );
        }
    }
}

/// A slot is created once, and the test is of that slot alone. A second call
/// at a slot that holds its document answers the same address as standing
/// and stages nothing: no record, no position drawn, the `Seq` beside it the
/// committed position the call read. A document standing at one slot answers
/// nothing for another: with the bio standing, the policy document is still
/// created, at its own address, and the link page and the mailbox after it,
/// whatever the order the slots are asked in.
#[test]
fn a_slot_is_created_once_and_a_document_at_one_slot_never_answers_for_another() {
    for order in [
        [WellKnownSlot::Bio, WellKnownSlot::Policy, WellKnownSlot::LinkPage, WellKnownSlot::Mailbox],
        [WellKnownSlot::Policy, WellKnownSlot::Mailbox, WellKnownSlot::Bio, WellKnownSlot::LinkPage],
        [WellKnownSlot::Mailbox, WellKnownSlot::LinkPage, WellKnownSlot::Policy, WellKnownSlot::Bio],
    ] {
        let (k, acct, _doc) = kernel_with_account_and_doc();
        let ns = Namespace::new(&k);
        let mut standing: Vec<(WellKnownSlot, Address)> = Vec::new();
        for slot_named in order {
            let expected = slot(&acct, slot_named.number());
            let before = k.current_seq();
            let (created, at) = ns
                .create_well_known_document(ID1, &acct, slot_named)
                .expect("an empty slot is created whatever stands at the others");
            assert_eq!(
                created,
                WellKnown::Minted(expected.clone()),
                "{slot_named:?} after {standing:?}: a document at another slot answered for it"
            );
            assert_eq!(at, Seq(before.0 + 1), "{slot_named:?}: the creation committed");
            standing.push((slot_named, expected));

            // Every slot created so far answers itself, standing, and
            // commits nothing.
            let head = k.current_seq();
            let slice = k.snapshot().world().m3().clone();
            for (earlier, address) in &standing {
                assert_eq!(
                    ns.create_well_known_document(ID1, &acct, *earlier).expect("the incumbent"),
                    (WellKnown::Standing(address.clone()), head),
                    "{earlier:?}: a second call answers the same address, at the position read"
                );
            }
            assert_eq!(k.current_seq(), head, "a second call drew a position");
            assert!(k.snapshot().world().m3().clone() == slice, "a second call folded a record");
        }
    }
}

/// No creation moves a count: with all four slots created, the account's
/// next document is the one its counter would have handed out, at a count of
/// 1 and past the block alike; and on an account that holds no document the
/// four are created and the account still holds none its counter handed out,
/// so its first create is still its doc 1, born published.
#[test]
fn creating_every_slot_moves_no_count() {
    for later in [0u32, 1, 3] {
        let (k, acct, _doc) = kernel_with_account_and_doc();
        let ns = Namespace::new(&k);
        for _ in 0..later {
            ns.create_new_document(ID1, &acct, None).expect("a later document");
        }
        let frontier = k.snapshot().world().m3().mint_document(&acct, false).expect("next").0;
        assert_eq!(frontier, nth_document(&acct, later + 2));
        for slot_named in WellKnownSlot::ALL {
            ns.create_well_known_document(ID1, &acct, slot_named).expect("created");
            assert_eq!(
                k.snapshot().world().m3().mint_document(&acct, false).expect("next").0,
                frontier,
                "{slot_named:?} moved the count of {acct}"
            );
        }
        let (next, _) = ns.create_new_document(ID1, &acct, None).expect("the next create");
        assert_eq!(next, frontier, "{later} later documents: the next create's number moved");
    }

    // An account holding no document: the store creates each slot — refusing
    // a well-known document ahead of the home page is the daemon's door's.
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let (acct, _) = ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1).expect("delegate");
    for slot_named in WellKnownSlot::ALL {
        ns.create_well_known_document(ID1, &acct, slot_named).expect("created with no doc 1");
        assert!(!k.snapshot().world().m3().has_documents(&acct), "{slot_named:?} counted");
    }
    let (first, _) = ns.create_new_document(ID1, &acct, None).expect("the first create");
    assert_eq!(first, nth_document(&acct, 1), "the first create is still doc 1");
    assert!(k.snapshot().world().m3().published(&first), "born published by the empty-account rule");
}

/// The refusals keep their order at every slot: a caller that is not ω is
/// refused `NotOwner` whether the account is registered or not and whether
/// the slot holds a document or not, so it learns nothing; ω of an address
/// that is no registered account is refused the mint's `NotAnAccount`. A
/// refusal commits nothing.
#[test]
fn a_stranger_is_refused_at_every_slot_and_an_unregistered_account_after_ownership() {
    let (k, acct, doc) = kernel_with_account_and_doc();
    let ns = Namespace::new(&k);
    ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 2]), ID2).expect("a second account");
    ns.create_well_known_document(ID1, &acct, WellKnownSlot::Bio).expect("the bio stands");
    let before = k.current_seq();
    let unregistered = a(&[1, 0, 9]);
    for slot_named in WellKnownSlot::ALL {
        for stranger in [ID2, UNKNOWN_ID] {
            assert_eq!(
                rejected(ns.create_well_known_document(stranger, &acct, slot_named)),
                CreateDocumentError::NotOwner,
                "{slot_named:?}: {stranger:?} on another's account, the slot filled or empty"
            );
        }
        assert_eq!(
            rejected(ns.create_well_known_document(ID1, &unregistered, slot_named)),
            CreateDocumentError::NotOwner,
            "{slot_named:?}: a caller that is not ω of an unregistered address"
        );
        assert_eq!(
            rejected(ns.create_well_known_document(BOOTSTRAP_PRINCIPAL, &unregistered, slot_named)),
            CreateDocumentError::Mint(MintError::NotAnAccount),
            "{slot_named:?}: ω of an address that is no registered account"
        );
        assert_eq!(
            rejected(ns.create_well_known_document(ID1, &doc, slot_named)),
            CreateDocumentError::Mint(MintError::NotAnAccount),
            "{slot_named:?}: a document is no account"
        );
    }
    assert_eq!(k.current_seq(), before, "a refusal committed something");
}

/// The store refuses the system account at every slot, whoever calls: its
/// slots are its own table, and no system document is placed while a board
/// runs (the mailbox design §2). The refusal is the op's own guard, read off
/// the argument before any transaction opens — made from inside a
/// transaction it is answered, where every other answer of the op meets M2's
/// reentrancy panic. Without it the op, asked by the system principal, would
/// answer the head document, the staging draft and the time document as
/// standing, and at 5 — which genesis leaves empty and the fold admits a
/// record at — would place a document. So the slice stays genesis's: the
/// three seeded documents with the bits they were born with, and nothing at
/// 5.
#[test]
fn the_system_account_is_refused_at_every_slot_by_the_stores_own_guard() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let system = system_account();
    let before = k.current_seq();
    for slot_named in WellKnownSlot::ALL {
        for caller in [SYSTEM_PRINCIPAL, BOOTSTRAP_PRINCIPAL, ID1, UNKNOWN_ID] {
            assert_eq!(
                rejected(ns.create_well_known_document(caller, &system, slot_named)),
                CreateDocumentError::SystemAccountNoWellKnown,
                "{slot_named:?} by {caller:?}"
            );
        }
        // Pre-work: refused with no transaction opened.
        let mut nested = None;
        k.transact::<_, ()>(&[], |_stg| {
            nested = Some(catch_unwind(AssertUnwindSafe(|| {
                ns.create_well_known_document(SYSTEM_PRINCIPAL, &system, slot_named)
            })));
            Ok(())
        })
        .expect("the outer transaction is a zero-step commit");
        let answered = nested.expect("the closure ran").expect("the guard opens no transaction");
        assert_eq!(
            rejected(answered),
            CreateDocumentError::SystemAccountNoWellKnown,
            "{slot_named:?}: decided ahead of any transaction"
        );
    }
    assert_eq!(k.current_seq(), before, "a refused call drew a position");
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3 == M3State::genesis(), "a refused call folded a record");
    assert!(m3.published(&head_document()) && m3.published(&time_document()));
    assert!(!m3.published(&staging_draft()), "the staging draft stays the private document it is");
    let system_5 = slot(&system, POLICY_SLOT);
    assert!(!m3.is_registered_document(&system_5), "{system_5}: the system account holds no document 5");

    // The guard is what stands there: the fold itself admits a record at the
    // system account's slot 5, as at any account's named slot.
    let folded = m3.apply_m3(Seq(1), &M3Rec::allocate(system_5.clone(), true));
    assert!(folded.is_registered_document(&system_5), "the premise: the fold judges the number alone");
}

/// A creation at a published slot commits under the handle's attestation,
/// as a mint born published does: its marker's signature slot holds the
/// value. The mailbox's commits with the slot empty whatever the handle
/// carries — a private mint signs nothing — and so does every creation on a
/// plain handle. Over a journaled kernel, since an in-memory one keeps no
/// marker.
#[test]
fn a_published_slots_creation_commits_under_the_attestation_and_the_mailbox_never() {
    let dir = tempdir().expect("tempdir");
    let k = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("open");
    let attestation =
        Attestation::new(1, vec![0xA5; 64]).expect("a non-zero tag over a non-empty blob");
    let plain = Namespace::new(&k);
    let (acct, _) = plain.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1).expect("delegate");
    let (other, _) = plain.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 2]), ID2).expect("delegate");
    let marker = |at| k.attestation_at(at).expect("a journaled kernel reads its own markers");

    for slot_named in WellKnownSlot::ALL {
        let (created, at) = Namespace::attested(&k, Some(&attestation))
            .create_well_known_document(ID1, &acct, slot_named)
            .expect("the creation commits");
        assert!(matches!(created, WellKnown::Minted(_)), "{slot_named:?}");
        assert_eq!(
            marker(at),
            slot_named.born_published().then(|| attestation.clone()),
            "{slot_named:?}: a published creation is signed, the private mailbox never"
        );
        let (created, at) = plain
            .create_well_known_document(ID2, &other, slot_named)
            .expect("the creation commits on a plain handle");
        assert!(matches!(created, WellKnown::Minted(_)), "{slot_named:?}");
        assert_eq!(marker(at), None, "{slot_named:?}: a plain handle signs nothing");
    }
    assert_eq!(PUBLISHED_SLOTS.map(WellKnownSlot::born_published), [true; 3]);
}

/// The four creations are four ordinary records, and they recover: a board
/// that created them reopens holding each where it was created, in the
/// state it was created in — the bio restored from a checkpoint, the rest by
/// replay — with the counter where it stood. A call after the reopen is
/// answered with the standing document and stages nothing; and a record at
/// document 6, the first number past the named slots, is still refused by
/// the fold, by the reserved block's own words.
#[test]
fn a_board_that_created_every_slot_recovers_them_and_a_record_at_6_is_still_refused() {
    let dir = tempdir().expect("tempdir");
    let (acct, live, head) = {
        let k = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("open");
        let ns = Namespace::new(&k);
        let (acct, _) = ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1).expect("delegate");
        ns.create_new_document(ID1, &acct, None).expect("doc 1");
        ns.create_well_known_document(ID1, &acct, WellKnownSlot::Bio).expect("the bio");
        k.checkpoint().expect("checkpoint");
        for slot_named in [WellKnownSlot::LinkPage, WellKnownSlot::Policy, WellKnownSlot::Mailbox] {
            ns.create_well_known_document(ID1, &acct, slot_named).expect("created");
        }
        (acct, k.snapshot().world().m3().clone(), k.current_seq())
    };
    let bytes = bincode::serialize(&live).expect("checkpoint-encode the slice");
    let restored: M3State = bincode::deserialize(&bytes).expect("the slice re-enters");
    assert_eq!(restored, live);

    let k = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("reopen");
    assert_eq!(k.current_seq(), head);
    let recovered = k.snapshot().world().m3().clone();
    assert!(recovered == live, "recovery rebuilt another slice");
    for (which, m3) in [("round-tripped", &restored), ("recovered", &recovered)] {
        for slot_named in WellKnownSlot::ALL {
            let at = slot(&acct, slot_named.number());
            assert!(m3.is_registered_document(&at), "{which}: {at}");
            assert_eq!(m3.published(&at), slot_named.born_published(), "{which}: {at}");
        }
        for slot_named in PUBLISHED_SLOTS {
            assert!(m3.published(&slot(&acct, slot_named.number())), "{which}: {slot_named:?}");
        }
        assert_eq!(
            m3.mint_document(&acct, false).expect("the counter's next").0,
            nth_document(&acct, 2),
            "{which}: the counter moved"
        );
    }
    let ns = Namespace::new(&k);
    for slot_named in WellKnownSlot::ALL {
        assert_eq!(
            ns.create_well_known_document(ID1, &acct, slot_named).expect("answered after the reopen"),
            (WellKnown::Standing(slot(&acct, slot_named.number())), head),
            "{slot_named:?}"
        );
    }
    assert_eq!(k.current_seq(), head, "a call after the reopen drew a position");

    // Document 6 names no slot: the fold refuses its record at the push.
    let sixth = slot(&acct, POLICY_SLOT + 1);
    let refused = catch_unwind(AssertUnwindSafe(|| {
        k.transact::<_, MintError>(&[M3State::document_lock_key(&acct)], |stg| {
            stg.push(M3Rec::allocate(sixth.clone(), true).into());
            Ok(())
        })
    }));
    let message = refused
        .expect_err("a record at document 6 folded")
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_default();
    assert!(
        message.contains(&format!(
            "an Allocate in the reserved block names a well-known slot: {sixth} is none of them"
        )),
        "the refusal is the reserved block's and names the record: {message:?}"
    );
    assert_eq!(k.current_seq(), head, "the refusal committed something");
    assert!(!k.is_poisoned(), "the refusal poisoned the kernel");
    assert!(!k.snapshot().world().m3().is_registered_document(&sixth));
}
