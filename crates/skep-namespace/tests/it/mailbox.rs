//! §B create_well_known_document: an account's mailbox, minted at its
//! well-known slot 2 (the mailbox design §2, §3) — the address the slot has
//! before anything stands there, where the mint lands and with which bit,
//! that it moves no count, that it happens once, who may ask, where each
//! answer is decided, which of its two answers — minted or standing — each
//! call gives, and what the op answers for an account with no document and
//! for the system account.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Barrier;
use std::thread;

use crate::common::*;

use skep_address::{Address, Level};
use skep_kernel::{Attestation, Kernel};
use skep_namespace::{
    first_document_address, head_document, mailbox_address, system_account, CreateDocumentError,
    HasM3, M3State, MintError, Namespace, PrincipalId, BOOTSTRAP_PRINCIPAL,
    FIRST_ORDINARY_DOCUMENT, MAILBOX_SLOT, SYSTEM_PRINCIPAL, WellKnown,
};
use tempfile::tempdir;

/// A third principal, for the accounts a test seats beside `ID1`'s and
/// `ID2`'s.
const ID3: PrincipalId = PrincipalId(3);

/// The standard fixture — `ID1`'s account `[1,0,1]` holding its doc 1 — with
/// `later` more documents minted by its counter: none leaves the count at 1,
/// and one or more carries it past the reserved block.
fn account_with_documents(later: u32) -> (Kernel<World>, Address) {
    let (k, acct, _doc) = kernel_with_account_and_doc();
    for _ in 0..later {
        Namespace::new(&k)
            .create_new_document(ID1, &acct, None)
            .expect("the owner creates a later document");
    }
    (k, acct)
}

/// The mailbox's slot is document 2, and its address is that slot of the
/// account's document chain: `A·0·2`, for an account under any node and at
/// any depth, registered or not, and for no other tier. The address names
/// the place and claims nothing about it — on genesis no mailbox stands
/// anywhere — and for the system account the same slot is its head document,
/// which is no mailbox.
#[test]
fn the_mailbox_address_is_slot_2_of_an_account_minted_or_not() {
    assert_eq!(MAILBOX_SLOT, 2);
    assert!(
        NAMED_SLOTS.contains(&MAILBOX_SLOT),
        "the fold admits a record in the reserved block at a named slot alone"
    );
    assert!(1 < MAILBOX_SLOT && MAILBOX_SLOT < FIRST_ORDINARY_DOCUMENT);

    for (account, mailbox) in [
        (a(&[1, 0, 1]), a(&[1, 0, 1, 0, 2])),
        (a(&[1, 0, 9]), a(&[1, 0, 9, 0, 2])), // an account no op registered
        (a(&[1, 0, 5, 1, 1]), a(&[1, 0, 5, 1, 1, 0, 2])), // a sub-account's sub-account
        (a(&[1, 3, 0, 5]), a(&[1, 3, 0, 5, 0, 2])), // under another node
    ] {
        assert_eq!(mailbox_address(&account), Some(mailbox.clone()), "{account}");
        assert_eq!(mailbox, slot(&account, MAILBOX_SLOT), "{account}");
        assert_eq!(mailbox.level(), Level::Document, "{account}");
        assert!(
            !M3State::genesis().is_allocated(&mailbox),
            "{mailbox}: the address names the slot, and nothing stands there"
        );
    }
    assert_eq!(mailbox_address(&system_account()), Some(head_document()));

    // Only an account anchors a document chain, so off the account tier there
    // is no slot: a node, a document, a mailbox itself, an element.
    for off_tier in [
        a(&[1]),
        a(&[1, 1]),
        a(&[1, 0, 1, 0, 1]),
        a(&[1, 0, 1, 0, 2]),
        a(&[1, 0, 1, 0, 1, 0, 1, 1]),
    ] {
        assert_eq!(mailbox_address(&off_tier), None, "{off_tier}");
    }
}

/// The mint lands at `<account>.0.2` whatever the account's count: at 1,
/// where document 2 would be the counter's own next were the block not
/// reserved, and past the block, where the counter stands at 64 and at 66.
/// It is born private, registered in the commit that answers it, entered in
/// the position map at that commit, and owned as every document of the
/// account is, at the account's own seat.
#[test]
fn the_mailbox_lands_at_slot_2_private_whether_the_count_stands_at_1_or_past_the_block() {
    for later in [0u32, 1, 3] {
        let (k, acct) = account_with_documents(later);
        let ns = Namespace::new(&k);
        let before = k.current_seq();
        assert!(
            !k.snapshot().world().m3().is_registered_document(&a(&[1, 0, 1, 0, 2])),
            "{later} later documents: the slot is empty before the mint"
        );

        let (mailbox, at) = ns
            .create_well_known_document(ID1, &acct)
            .expect("the account's owner mints its mailbox");
        assert_eq!(mailbox, WellKnown::Minted(a(&[1, 0, 1, 0, 2])), "{later} later documents");
        let mailbox = mailbox.into_address();
        assert_eq!(Some(&mailbox), mailbox_address(&acct).as_ref());
        // Commit-before-acknowledge: the position answered is the mint's own
        // commit, one record past the position before it.
        assert_eq!(at, Seq(before.0 + 1), "{later} later documents");
        assert_eq!(k.current_seq(), at);

        let m3 = k.snapshot().world().m3().clone();
        assert!(m3.is_registered_document(&mailbox));
        assert!(!m3.published(&mailbox), "{later} later documents: a mailbox is born private");
        assert_eq!(
            m3.documents().find(|(doc, _)| **doc == mailbox),
            Some((&mailbox, false)),
            "the publication walk holds the mailbox, unpublished"
        );
        assert_eq!(m3.minted_at(&mailbox), Some(at));
        assert_eq!(
            m3.account_seat(&mailbox),
            Some((&acct, ID1)),
            "the mailbox is owned at its account's seat"
        );
        assert!(m3.is_effective_owner(ID1, &mailbox));
    }
}

/// A slot moves no count. The address the account's counter would hand out
/// next is the same before the mint and after it — the account's second
/// document where the count stood at 1, its next ordinary document where it
/// stood past the block — and the next create really answers it. The
/// account still holds exactly the documents its counter handed out.
#[test]
fn the_counters_next_is_the_same_before_and_after_the_mint() {
    for later in [0u32, 1, 3] {
        let (k, acct) = account_with_documents(later);
        let ns = Namespace::new(&k);
        let handed_out = 1 + later;
        let peek = |k: &Kernel<World>| {
            k.snapshot()
                .world()
                .m3()
                .mint_document(&acct, false)
                .expect("the counter's next")
                .0
        };
        let next_before = peek(&k);
        assert_eq!(next_before, nth_document(&acct, handed_out + 1));

        let mailbox = ns
            .create_well_known_document(ID1, &acct)
            .expect("the mailbox mints")
            .0
            .into_address();
        assert_eq!(
            peek(&k),
            next_before,
            "{later} later documents: the mint moved the counter"
        );
        assert_ne!(mailbox, next_before);
        let m3 = k.snapshot().world().m3().clone();
        assert!(m3.has_documents(&acct));
        assert!(!m3.is_registered_document(&next_before));

        // …and the counter hands that address out: the create after the
        // mailbox answers it, and the one after that the number past it.
        let (created, _) = ns
            .create_new_document(ID1, &acct, None)
            .expect("the next create");
        assert_eq!(created, next_before);
        assert_eq!(peek(&k), nth_document(&acct, handed_out + 2));
    }
}

/// Checks that the mint happens once, and that a second call says so.
///
/// A second call is answered with the same address, as standing, and stages
/// nothing: no position is drawn — `current_seq` stands where the mint left
/// it — the slice is the slice the mint left, and the position beside the
/// address is the committed one the call read. A call made after other
/// commits is answered the same way, at the position it read — another
/// write's, which the answer tells the caller is not its own — and the
/// mailbox's own position stays its mint's. The first call alone answers
/// minted (the mutant that answers a found slot minted hands the caller
/// another write's position as its own commit).
#[test]
fn a_second_call_answers_the_same_address_and_stages_nothing() {
    for later in [0u32, 1] {
        let (k, acct) = account_with_documents(later);
        let ns = Namespace::new(&k);
        let (first, minted) = ns
            .create_well_known_document(ID1, &acct)
            .expect("the first call mints");
        let mailbox = mailbox_address(&acct).expect("an account's slot");
        assert_eq!(first, WellKnown::Minted(mailbox.clone()), "the first call mints, and says so");
        assert_eq!(k.current_seq(), minted);
        let left_by_the_mint = k.snapshot().world().m3().clone();

        let (again, at) = ns
            .create_well_known_document(ID1, &acct)
            .expect("the second call is answered, not refused");
        assert_eq!(again, WellKnown::Standing(mailbox.clone()), "the second finds it standing, and says so");
        assert_eq!(at, minted, "the zero-step answer is the committed position the call read");
        assert_eq!(k.current_seq(), minted, "the second call drew a position");
        assert!(
            *k.snapshot().world().m3() == left_by_the_mint,
            "the second call folded a record"
        );

        // After an unrelated commit: still the incumbent, at the position
        // that commit left, with nothing staged.
        let (_, later_commit) = ns
            .create_new_document(ID1, &acct, None)
            .expect("an unrelated commit");
        assert!(later_commit > minted);
        let standing = k.snapshot().world().m3().clone();
        let (third, at) = ns
            .create_well_known_document(ID1, &acct)
            .expect("a later call is answered");
        assert_eq!(third, WellKnown::Standing(mailbox.clone()));
        assert_eq!(at, later_commit, "the position of the unrelated commit, said to be no mint");
        assert_eq!(k.current_seq(), later_commit, "the later call drew a position");
        assert!(*k.snapshot().world().m3() == standing, "the later call folded a record");
        assert_eq!(standing.minted_at(&mailbox), Some(minted), "the mailbox is as old as its mint");
        assert!(!standing.published(&mailbox));
    }
}

/// Calls racing for one mailbox stage one record. The read of the slot and
/// the mint are one critical section under the account's document-chain
/// key, so of eight callers released together on each of three accounts one
/// mints and seven find the mailbox standing — each answer saying which, the
/// one minted at the mint's own position: every caller of an account is
/// answered the one address, no caller meets the fold's refusal of a second
/// record, and the board's position moves by exactly one record an account.
#[test]
fn racing_calls_for_one_mailbox_stage_one_record() {
    const CALLERS: usize = 8;
    let k = mem_kernel(genesis_world());
    let accounts: Vec<(Address, PrincipalId)> = [(1u32, ID1), (2, ID2), (3, ID3)]
        .into_iter()
        .map(|(number, id)| {
            let (acct, _) = Namespace::new(&k)
                .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, number]), id)
                .expect("an account under the bootstrap node");
            Namespace::new(&k)
                .create_new_document(id, &acct, None)
                .expect("its doc 1");
            (acct, id)
        })
        .collect();
    let before = k.current_seq();

    let start = Barrier::new(CALLERS * accounts.len());
    let answers: Vec<(Address, WellKnown, Seq)> = thread::scope(|scope| {
        let racers: Vec<_> = accounts
            .iter()
            .flat_map(|(acct, id)| (0..CALLERS).map(move |_| (acct, *id)))
            .map(|(acct, id)| {
                let (k, start) = (&k, &start);
                scope.spawn(move || {
                    start.wait();
                    let (mailbox, at) = Namespace::new(k)
                        .create_well_known_document(id, acct)
                        .expect("every racer is answered");
                    (acct.clone(), mailbox, at)
                })
            })
            .collect();
        racers
            .into_iter()
            .map(|racer| racer.join().expect("no racer met the fold's refusal"))
            .collect()
    });

    assert_eq!(answers.len(), CALLERS * accounts.len());
    for (acct, answer, at) in &answers {
        let mailbox = answer.clone().into_address();
        assert_eq!(Some(&mailbox), mailbox_address(acct).as_ref(), "{acct}");
        assert!(*at > before && *at <= k.current_seq(), "{acct}: answered at {at}");
    }
    // One record an account, and nothing else: each record draws one
    // position, so the positions drawn count the records staged.
    assert_eq!(
        k.current_seq(),
        Seq(before.0 + accounts.len() as u64),
        "the racers staged more than one record an account"
    );
    let m3 = k.snapshot().world().m3().clone();
    for (acct, _) in &accounts {
        let mailbox = mailbox_address(acct).expect("an account has a mailbox slot");
        assert!(m3.is_registered_document(&mailbox) && !m3.published(&mailbox));
        // The earliest answer an account's racers hold is its mint's own
        // position; every other is a position some racer read after it.
        let earliest = answers
            .iter()
            .filter(|(racer, ..)| racer == acct)
            .map(|(.., at)| *at)
            .min();
        assert_eq!(m3.minted_at(&mailbox), earliest, "{acct}");
        // The one racer that minted says so, at the mint's own position; the
        // seven others each say they found the mailbox standing.
        let minting: Vec<Seq> = answers
            .iter()
            .filter(|(racer, answer, _)| racer == acct && matches!(answer, WellKnown::Minted(_)))
            .map(|(.., at)| *at)
            .collect();
        assert_eq!(minting, earliest.into_iter().collect::<Vec<_>>(), "{acct}: one racer minted");
    }
}

/// A caller who is not the account's effective owner is refused `NotOwner`,
/// and refused before anything is read: the refusal is the same whether the
/// account is registered or not, whether it is an account at all, and
/// whether its mailbox stands, where the effective owner of each of those
/// targets earns the mint's own gate or the mailbox's address. Containment
/// is no ownership — π₀'s prefix contains the account, and the owner of an
/// account does not own its sub-account's mailbox. Nothing a refused caller
/// sends commits.
#[test]
fn a_caller_who_is_not_the_effective_owner_is_refused_before_anything_is_read() {
    let (k, acct, doc) = kernel_with_account_and_doc();
    let ns = Namespace::new(&k);
    ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 2]), ID2)
        .expect("a second account");
    let (sub, _) = ns
        .delegate(ID1, t(&[1, 0, 1, 1]), ID3)
        .expect("a sub-account of the first");
    let before = k.current_seq();
    let standing = k.snapshot().world().m3().clone();
    let strangers = [UNKNOWN_ID, BOOTSTRAP_PRINCIPAL, ID2, ID3];

    // A registered account whose slot is empty.
    for stranger in strangers {
        assert_eq!(
            rejected(ns.create_well_known_document(stranger, &acct)),
            CreateDocumentError::NotOwner,
            "{stranger:?} is not ω of {acct}"
        );
    }
    // ω of a sub-account is the principal seated at it, never its parent's.
    assert_eq!(
        rejected(ns.create_well_known_document(ID1, &sub)),
        CreateDocumentError::NotOwner
    );
    // The mint's gate is read only for ω. An unregistered account, a node
    // and a document each earn a stranger `NotOwner` and their effective
    // owner `Mint(NotAnAccount)`: the stranger learns nothing of the target.
    let unregistered = a(&[1, 0, 9]);
    let node = a(&[1]);
    for (target, owner) in [
        (&unregistered, BOOTSTRAP_PRINCIPAL),
        (&node, BOOTSTRAP_PRINCIPAL),
        (&doc, ID1),
    ] {
        for stranger in [UNKNOWN_ID, ID2] {
            assert_eq!(
                rejected(ns.create_well_known_document(stranger, target)),
                CreateDocumentError::NotOwner,
                "{stranger:?} at {target}"
            );
        }
        assert_eq!(
            rejected(ns.create_well_known_document(owner, target)),
            CreateDocumentError::Mint(MintError::NotAnAccount),
            "ω at {target}"
        );
    }
    // Refusals all: nothing committed, no slot filled.
    assert_eq!(k.current_seq(), before);
    assert!(*k.snapshot().world().m3() == standing);
    assert!(!standing.is_registered_document(&slot(&acct, MAILBOX_SLOT)));

    // Nor does a stranger learn whether the mailbox stands: with it minted,
    // the owner is answered its address and a stranger the same refusal.
    let (mailbox, minted) = ns
        .create_well_known_document(ID1, &acct)
        .expect("the owner mints");
    let mailbox = mailbox.into_address();
    for stranger in strangers {
        assert_eq!(
            rejected(ns.create_well_known_document(stranger, &acct)),
            CreateDocumentError::NotOwner,
            "{stranger:?} with the mailbox standing"
        );
    }
    assert_eq!(
        ns.create_well_known_document(ID1, &acct).expect("the owner"),
        (WellKnown::Standing(mailbox), minted)
    );
    assert_eq!(k.current_seq(), minted);
}

/// What `call` panicked with when made from inside a transaction on `k`, or
/// `None` if it returned: M2 answers a nested transaction with a panic that
/// names the obligation, before the applier lock is taken, so the outer
/// transaction then commits its zero steps.
fn panic_of_a_nested_call<T>(k: &Kernel<World>, call: impl FnOnce() -> T) -> Option<String> {
    let mut raised = None;
    k.transact::<_, ()>(&[], |_stg| {
        if let Err(payload) = catch_unwind(AssertUnwindSafe(call)) {
            raised = Some(
                payload
                    .downcast_ref::<&str>()
                    .map(|message| (*message).to_owned())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_default(),
            );
        }
        Ok(())
    })
    .expect("the outer transaction is a zero-step commit");
    raised
}

/// Every answer the op gives is decided inside its own transaction, under
/// its held keys, never off a snapshot taken before it: the owner test, the
/// mint's gate, the mint, and the read of a slot that already holds the
/// mailbox. Hoisted onto a snapshot, each would keep every sequential test
/// green while a racing commit decided it on stale state — a delegation
/// landing between the authorization and the mint, or two callers both
/// finding the slot empty. So each case is first earned outside any
/// transaction and then made from inside one, where an op that opens its own
/// transaction before deciding meets M2's reentrancy panic and one that
/// decided early hands its answer back.
#[test]
fn every_answer_is_decided_inside_the_ops_own_transaction() {
    let (k, acct, _doc) = kernel_with_account_and_doc();
    let ns = Namespace::new(&k);
    let (minted_acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 2]), ID2)
        .expect("a second account");
    let incumbent = ns
        .create_well_known_document(ID2, &minted_acct)
        .expect("the second account's mailbox stands")
        .0
        .into_address();
    let decided_inside = |case: &str, raised: Option<String>| {
        assert!(
            raised
                .as_deref()
                .is_some_and(|message| message.contains("transact is not reentrant")),
            "{case}: not decided inside the op's own transaction (nested call raised {raised:?})"
        );
    };

    assert_eq!(
        rejected(ns.create_well_known_document(ID2, &acct)),
        CreateDocumentError::NotOwner,
        "a caller that is not ω: the premise"
    );
    decided_inside(
        "a caller that is not ω",
        panic_of_a_nested_call(&k, || ns.create_well_known_document(ID2, &acct)),
    );

    let unregistered = a(&[1, 0, 9]);
    assert_eq!(
        rejected(ns.create_well_known_document(BOOTSTRAP_PRINCIPAL, &unregistered)),
        CreateDocumentError::Mint(MintError::NotAnAccount),
        "an unregistered account: the premise"
    );
    decided_inside(
        "an unregistered account",
        panic_of_a_nested_call(&k, || {
            ns.create_well_known_document(BOOTSTRAP_PRINCIPAL, &unregistered)
        }),
    );

    assert_eq!(
        ns.create_well_known_document(ID2, &minted_acct)
            .expect("a standing mailbox is answered")
            .0,
        WellKnown::Standing(incumbent),
        "a standing mailbox: the premise"
    );
    decided_inside(
        "a standing mailbox",
        panic_of_a_nested_call(&k, || ns.create_well_known_document(ID2, &minted_acct)),
    );

    let before = k.current_seq();
    decided_inside(
        "an empty slot",
        panic_of_a_nested_call(&k, || ns.create_well_known_document(ID1, &acct)),
    );
    assert_eq!(k.current_seq(), before, "the nested call minted");
    assert!(!k.snapshot().world().m3().is_registered_document(&slot(&acct, MAILBOX_SLOT)));
}

/// After the mint, slot 2 is a registered document and no other number of
/// the reserved block is — slots 3, 4 and 5 by name, and every number up to
/// the block's end — under a count of 1 and under one past the block, at all
/// three membership reads. The mailbox is a home like any document: it takes
/// the links its owner's marks are, content, and versions, on chains of its
/// own that open at their first slots.
#[test]
fn after_the_mint_slot_2_is_a_registered_document_and_slots_3_4_and_5_are_not() {
    for later in [0u32, 1] {
        let (k, acct) = account_with_documents(later);
        let m3 = k.snapshot().world().m3().clone();
        for number in 2..FIRST_ORDINARY_DOCUMENT {
            assert!(
                !m3.is_registered_document(&slot(&acct, number)),
                "{later} later documents: slot {number} reads registered before any mint"
            );
        }

        let mailbox = Namespace::new(&k)
            .create_well_known_document(ID1, &acct)
            .expect("the mailbox mints")
            .0
            .into_address();
        let m3 = k.snapshot().world().m3().clone();
        assert!(m3.is_registered_document(&a(&[1, 0, 1, 0, 2])));
        for unminted in [a(&[1, 0, 1, 0, 3]), a(&[1, 0, 1, 0, 4]), a(&[1, 0, 1, 0, 5])] {
            assert!(
                !m3.is_registered_document(&unminted),
                "{later} later documents: {unminted} reads registered"
            );
        }
        for number in 2..FIRST_ORDINARY_DOCUMENT {
            let placed = slot(&acct, number);
            let is_the_mailbox = number == MAILBOX_SLOT;
            assert_eq!(m3.is_registered_document(&placed), is_the_mailbox, "{placed}");
            assert_eq!(m3.is_allocated(&placed), is_the_mailbox, "{placed}");
            assert_eq!(
                m3.entity_level(&placed),
                is_the_mailbox.then_some(Level::Document),
                "{placed}"
            );
        }
        // The account's own documents stand as they did.
        for nth in 1..=1 + later {
            assert!(m3.is_registered_document(&nth_document(&acct, nth)));
        }

        assert_eq!(
            m3.mint_link(&mailbox).expect("a mailbox is a home for its owner's marks").0,
            under(&mailbox, &[0, 2, 1])
        );
        assert_eq!(
            m3.mint_content(&mailbox).expect("a mailbox is a home").0,
            under(&mailbox, &[0, 1, 1])
        );
        assert_eq!(
            m3.mint_version(&mailbox, false).expect("a mailbox is a version's source").0,
            under(&mailbox, &[1])
        );
    }
}

/// Called for the system account, the op stages nothing and answers the
/// head document's address, as standing. The system account has no mailbox:
/// its document 2 is the head document, which genesis seeds, so the op finds
/// the slot filled. It holds no guard of its own — refusing the call is the
/// daemon's door's — and this pins what stands behind that door: an answer
/// that changes nothing, on a slice that stays genesis's, with the head
/// document published as it was born. A caller who is not the system
/// principal is refused as on any account.
#[test]
fn called_for_the_system_account_it_answers_the_head_document_and_stages_nothing() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let before = k.current_seq();

    let (answered, at) = ns
        .create_well_known_document(SYSTEM_PRINCIPAL, &system_account())
        .expect("the system account's call is answered, not refused");
    assert_eq!(answered, WellKnown::Standing(head_document()), "found standing, and said so");
    let answered = answered.into_address();
    assert_eq!(answered, a(&[1, 1, 0, 1, 0, 2]));
    assert_eq!(at, before, "the zero-step answer is the committed position the call read");
    assert_eq!(k.current_seq(), before, "the call drew a position");
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3 == M3State::genesis(), "the call folded a record");
    assert!(m3.published(&head_document()), "the head document is no private mailbox");
    assert_eq!(m3.minted_at(&head_document()), Some(Seq(0)));

    assert_eq!(
        rejected(ns.create_well_known_document(BOOTSTRAP_PRINCIPAL, &system_account())),
        CreateDocumentError::NotOwner
    );
    assert_eq!(k.current_seq(), before);
}

/// On an account with no document the op mints the slot: it asks for no
/// doc 1. The mailbox stands, private, and the account still holds no
/// document its counter handed out — so its next create is still its doc 1,
/// at the slot its chain opens at, born published by the empty-account rule
/// (PUB-8.21), and the one after it the first ordinary document, private.
/// Refusing a mailbox ahead of the home page is the daemon's door's.
#[test]
fn on_an_account_with_no_document_the_slot_mints_and_the_next_create_is_still_its_published_doc_1() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let (acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("delegate");
    assert!(!k.snapshot().world().m3().has_documents(&acct));

    let (mailbox, minted) = ns
        .create_well_known_document(ID1, &acct)
        .expect("the slot mints on an account with no document");
    assert_eq!(mailbox, WellKnown::Minted(a(&[1, 0, 1, 0, 2])));
    let mailbox = mailbox.into_address();
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3.is_registered_document(&mailbox) && !m3.published(&mailbox));
    assert!(!m3.has_documents(&acct), "a slot is no document the counter handed out");
    let doc_1 = first_document_address(&acct).expect("an account anchors a document chain");
    assert!(!m3.is_registered_document(&doc_1));
    assert_eq!(m3.mint_document(&acct, false).expect("the counter's next").0, doc_1);

    let (first, _) = ns
        .create_new_document(ID1, &acct, None)
        .expect("the account's first create");
    assert_eq!(first, doc_1);
    assert_eq!(first, a(&[1, 0, 1, 0, 1]));
    let (second, _) = ns
        .create_new_document(ID1, &acct, None)
        .expect("the account's second create");
    assert_eq!(second, nth_document(&acct, 2));
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3.published(&first), "the flagless first create is doc 1, born published");
    assert!(!m3.published(&second), "a flagless later create is private");
    assert!(m3.has_documents(&acct));
    // The mailbox stands as it was minted, and a call after the home page is
    // answered with it.
    assert!(!m3.published(&mailbox));
    assert_eq!(m3.minted_at(&mailbox), Some(minted));
    let standing = k.current_seq();
    assert_eq!(
        ns.create_well_known_document(ID1, &acct).expect("the incumbent"),
        (WellKnown::Standing(mailbox), standing)
    );
}

/// The mailbox's mint takes the plain arm whatever the handle carries: a
/// private mint is outside the checked set, so an attested handle's mailbox
/// commits with its marker's signature slot empty, where the same handle's
/// create commits under the attestation. Over a journaled kernel, since an
/// in-memory one keeps no marker.
#[test]
fn an_attested_handles_mailbox_mint_leaves_its_signature_slot_empty() {
    let dir = tempdir().expect("tempdir");
    let k = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("open");
    let attestation =
        Attestation::new(1, vec![0xA5; 64]).expect("a non-zero tag over a non-empty blob");
    let (acct, _) = Namespace::new(&k)
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("the delegation commits");

    let (_, created) = Namespace::attested(&k, Some(&attestation))
        .create_new_document(ID1, &acct, None)
        .expect("the create commits");
    let (mailbox, minted) = Namespace::attested(&k, Some(&attestation))
        .create_well_known_document(ID1, &acct)
        .expect("the mailbox commits");
    let mailbox = mailbox.into_address();
    assert!(minted > created);

    assert_eq!(
        k.attestation_at(created)
            .expect("a journaled kernel reads its own markers"),
        Some(attestation.clone()),
        "the control: an attested create fills its signature slot"
    );
    assert_eq!(
        k.attestation_at(minted)
            .expect("a journaled kernel reads its own markers"),
        None,
        "the mailbox's marker carries a signature"
    );
    assert!(!k.snapshot().world().m3().published(&mailbox));
}

/// The mint is one ordinary record in the journal, and it replays: reopened
/// from its journal alone, the board holds the mailbox where the mint put
/// it, private, at the mint's position, with the counter where it stood. A
/// call after the reopen — another device's, say — is answered with that
/// mailbox and stages nothing.
#[test]
fn the_mailbox_replays_from_the_journal_and_a_call_after_the_reopen_mints_nothing() {
    let dir = tempdir().expect("tempdir");
    let (acct, mailbox, minted, left) = {
        let k = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("open");
        let ns = Namespace::new(&k);
        let (acct, _) = ns
            .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
            .expect("delegate");
        ns.create_new_document(ID1, &acct, None).expect("doc 1");
        ns.create_new_document(ID1, &acct, None)
            .expect("a second document");
        let (mailbox, minted) = ns
            .create_well_known_document(ID1, &acct)
            .expect("the mailbox mints");
        (acct, mailbox.into_address(), minted, k.snapshot().world().m3().clone())
    };

    let k = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("reopen");
    assert_eq!(k.current_seq(), minted);
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3 == left, "replay rebuilt another slice");
    assert!(m3.is_registered_document(&mailbox) && !m3.published(&mailbox));
    assert_eq!(m3.minted_at(&mailbox), Some(minted));
    assert_eq!(
        m3.mint_document(&acct, false).expect("the counter's next").0,
        nth_document(&acct, 3)
    );

    assert_eq!(
        Namespace::new(&k)
            .create_well_known_document(ID1, &acct)
            .expect("a call after the reopen is answered"),
        (WellKnown::Standing(mailbox), minted)
    );
    assert_eq!(k.current_seq(), minted, "the call after the reopen drew a position");
}
