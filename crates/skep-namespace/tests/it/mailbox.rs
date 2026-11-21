//! §B an account's mailbox, its well-known slot 2 (the mailbox design §2,
//! §3): the address the slot has before anything stands there; the mailbox
//! an account's first `create_new_document` creates in the commit that mints
//! its doc 1 — which mints, which do not, at which position, under which
//! marker, and what a mailbox already standing does to it; and
//! `create_well_known_document` at the mailbox's slot, the store's own path
//! to a mailbox on an account that holds none — where the mint lands and
//! with which bit, that it moves no count, that it happens once, who may
//! ask, where each answer is decided, which of its two answers — minted or
//! standing — each call gives, and what the op answers for an account with
//! no document and for the system account. The other three slots, and what
//! holds of every slot alike, are `well_known.rs`'s.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Barrier;
use std::thread;

use crate::common::*;

use skep_address::{Address, Level};
use skep_kernel::{Attestation, HistoryError, Kernel};
use skep_namespace::{
    first_document_address, head_document, mailbox_address, system_account, CreateDocumentError,
    HasM3, M3State, MintError, Namespace, PrincipalId, BOOTSTRAP_PRINCIPAL,
    FIRST_ORDINARY_DOCUMENT, MAILBOX_SLOT, SYSTEM_PRINCIPAL, WellKnown, WellKnownSlot,
};
use tempfile::tempdir;

/// A third principal, for the accounts a test seats beside `ID1`'s and
/// `ID2`'s.
const ID3: PrincipalId = PrincipalId(3);

/// `ID1`'s account `[1,0,1]` holding its doc 1 and no mailbox
/// ([`kernel_with_account_doc_1_and_no_mailbox`]), with `later` more
/// documents minted by its counter: none leaves the count at 1, and one or
/// more carries it past the reserved block — the slot empty under each,
/// which is what the slot op's own cells read. A later create creates no
/// mailbox, so the slot stays empty past them.
fn account_holding_documents_and_no_mailbox(later: u32) -> (Kernel<World>, Address) {
    let (k, acct, _doc) = kernel_with_account_doc_1_and_no_mailbox();
    for _ in 0..later {
        Namespace::new(&k)
            .create_new_document(ID1, &acct, None)
            .expect("the owner creates a later document");
    }
    assert!(
        !k.snapshot().world().m3().is_registered_document(&slot(&acct, MAILBOX_SLOT)),
        "the premise: a later create made no mailbox"
    );
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

/// An account's first create creates its mailbox in the same commit. On a
/// freshly delegated account the flagless create answers the account's doc
/// 1, and leaves `<acct>.0.2` registered, private and owned at the account's
/// seat; the two are dated at one position, the ack's own, which the commit
/// reached by exactly its two records; the counter's next is the first
/// ordinary document, the mailbox having moved no count; and a slot-2 call
/// after it finds the mailbox standing and stages nothing. The rule is keyed
/// on the account's first mint, never on the bit: a `Some(false)` first
/// create — which the store mints and the daemon's door refuses
/// `mint_home_public` — creates the mailbox too.
///
/// On a journaled kernel the commit is one transaction: walking every
/// position the call drew, the committed worlds are the one before it,
/// holding neither document, and the one it returned, holding both — no
/// committed world holds the home without its mailbox — and after a reopen
/// both stand at that one position.
#[test]
fn the_home_mint_creates_the_mailbox_in_its_own_commit() {
    for published in [None, Some(false)] {
        let k = mem_kernel(genesis_world());
        let ns = Namespace::new(&k);
        let (acct, _) = ns
            .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
            .expect("a fresh account");
        let before = k.current_seq();

        let (home, at) = ns
            .create_new_document(ID1, &acct, published)
            .expect("the account's first create");
        assert_eq!(home, a(&[1, 0, 1, 0, 1]), "{published:?}: the first create is doc 1");
        assert_eq!(at, Seq(before.0 + 2), "{published:?}: the commit is the home's record and the mailbox's");
        assert_eq!(k.current_seq(), at);

        let m3 = k.snapshot().world().m3().clone();
        let mailbox = mailbox_address(&acct).expect("an account's slot");
        assert_eq!(mailbox, a(&[1, 0, 1, 0, 2]));
        assert!(m3.is_registered_document(&mailbox), "{published:?}: the mailbox stands");
        assert!(!m3.published(&mailbox), "{published:?}: a mailbox is born private");
        assert_eq!(m3.published(&home), published.unwrap_or(true), "{published:?}: the home's own bit");
        assert_eq!(m3.account_seat(&mailbox), Some((&acct, ID1)));
        assert_eq!(m3.minted_at(&home), Some(at), "{published:?}: the home is dated at the ack");
        assert_eq!(m3.minted_at(&mailbox), Some(at), "{published:?}: the mailbox is dated with it");
        assert_eq!(
            m3.mint_document(&acct, false).expect("the counter's next").0,
            nth_document(&acct, 2),
            "{published:?}: the mailbox moved the count"
        );

        assert_eq!(
            ns.create_well_known_document(ID1, &acct, WellKnownSlot::Mailbox)
                .expect("a slot-2 call is answered"),
            (WellKnown::Standing(mailbox), at),
            "{published:?}: the mailbox the home's commit made answers the slot"
        );
        assert_eq!(k.current_seq(), at, "{published:?}: the slot-2 call staged a record");
    }

    // Journaled: one transaction, and it recovers whole.
    let dir = tempdir().expect("tempdir");
    let (acct, at) = {
        let k = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("open");
        let (acct, _) = Namespace::new(&k)
            .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
            .expect("a fresh account");
        let before = k.current_seq();
        let (_, at) = Namespace::new(&k)
            .create_new_document(ID1, &acct, None)
            .expect("the account's first create");
        let home = first_document_address(&acct).expect("an account's doc 1 slot");
        let mailbox = mailbox_address(&acct).expect("an account's slot");
        let mut answered = Vec::new();
        for position in before.0..=at.0 {
            let world = match k.world_at(Seq(position)) {
                Ok(world) => world,
                // A composite's interior position: no world was ever
                // committed there, so there is nothing to hold.
                Err(HistoryError::NotABoundary { .. }) => continue,
                Err(e) => panic!("world_at(Seq({position})) refused for another reason: {e}"),
            };
            let m3 = world.m3();
            assert_eq!(
                m3.is_registered_document(&home),
                m3.is_registered_document(&mailbox),
                "Seq({position}) is a committed world holding one of the home and its mailbox"
            );
            answered.push((position, m3.is_registered_document(&home)));
        }
        assert_eq!(
            answered,
            vec![(before.0, false), (at.0, true)],
            "the committed positions across the call"
        );
        (acct, at)
    };
    let k = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("reopen");
    let m3 = k.snapshot().world().m3().clone();
    let (home, mailbox) = (
        first_document_address(&acct).expect("an account's doc 1 slot"),
        mailbox_address(&acct).expect("an account's slot"),
    );
    assert!(m3.is_registered_document(&home) && m3.is_registered_document(&mailbox));
    assert_eq!(m3.minted_at(&home), Some(at), "the home recovers at its commit");
    assert_eq!(m3.minted_at(&mailbox), Some(at), "the mailbox recovers at the same position");
    assert!(m3.published(&home) && !m3.published(&mailbox));
}

/// `account`'s first document number past the reserved block, by the
/// constant: where the counter goes after doc 1.
fn slot_past_the_block(account: &Address) -> Address {
    under(account, &[0, FIRST_ORDINARY_DOCUMENT])
}

/// `fork` opens the create's own transaction, so a fork by a principal whose
/// account holds nothing creates the mailbox too: the fork answers the
/// account's doc 1, born published by PUB-8.21, and both documents stand at
/// the one position the fork's commit reached by its two records.
#[test]
fn a_fork_into_an_empty_account_creates_the_mailbox_too() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let (acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("a fresh account");
    let before = k.current_seq();

    let (forked, at) = ns.fork(ID1, None).expect("the fork into the caller's empty account");
    assert_eq!(Some(&forked), first_document_address(&acct).as_ref(), "the fork is doc 1");
    assert_eq!(at, Seq(before.0 + 2), "the fork's commit is two records");
    let m3 = k.snapshot().world().m3().clone();
    let mailbox = mailbox_address(&acct).expect("an account's slot");
    assert!(m3.is_registered_document(&mailbox) && !m3.published(&mailbox));
    assert!(m3.published(&forked), "a flagless first fork is born published");
    assert_eq!(m3.minted_at(&forked), Some(at));
    assert_eq!(m3.minted_at(&mailbox), Some(at), "the mailbox is dated with the fork");
}

/// Only the first mint creates the mailbox. After the home, a flagless
/// create and a `Some(true)` one each commit one record — `current_seq`
/// moves by one — and the mailbox keeps the home's position. So does a fork
/// into the account, which holds its doc 1.
#[test]
fn a_later_mint_creates_no_mailbox_record() {
    let (k, acct, home) = kernel_with_account_and_doc();
    let ns = Namespace::new(&k);
    let mailbox = mailbox_address(&acct).expect("an account's slot");
    let home_at = k.snapshot().world().m3().minted_at(&home).expect("the home's position");
    assert_eq!(
        k.snapshot().world().m3().minted_at(&mailbox),
        Some(home_at),
        "the premise: the mailbox stands from the home's commit"
    );

    for published in [None, Some(true), Some(false)] {
        let before = k.current_seq();
        let (_, at) = ns
            .create_new_document(ID1, &acct, published)
            .expect("a later create");
        assert_eq!(at, Seq(before.0 + 1), "{published:?}: a later create is one record");
    }
    let before = k.current_seq();
    let (_, at) = ns.fork(ID1, Some(true)).expect("a later fork");
    assert_eq!(at, Seq(before.0 + 1), "a later fork is one record");
    let m3 = k.snapshot().world().m3().clone();
    assert_eq!(m3.minted_at(&mailbox), Some(home_at), "the mailbox is as old as its home");
    assert!(!m3.published(&mailbox));
}

/// The system account never meets the rule: genesis counts its doc 1, so its
/// every mint is a later one, and its slot 2 is the head document, born
/// published at genesis. A create by its own principal stages one record,
/// and the head document stands as genesis left it.
#[test]
fn the_system_accounts_mint_creates_no_mailbox() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    assert!(
        k.snapshot().world().m3().has_documents(&system_account()),
        "the premise: genesis counts the system account's doc 1"
    );
    let before = k.current_seq();

    let (created, at) = ns
        .create_new_document(SYSTEM_PRINCIPAL, &system_account(), Some(false))
        .expect("the system principal creates in its own account");
    assert_eq!(at, Seq(before.0 + 1), "the system account's create is one record");
    assert_eq!(created, slot_past_the_block(&system_account()));
    let m3 = k.snapshot().world().m3().clone();
    let slot_2 = mailbox_address(&system_account()).expect("the system account's slot 2");
    assert_eq!(slot_2, head_document());
    assert!(m3.published(&slot_2), "the head document is no private mailbox");
    assert_eq!(m3.minted_at(&slot_2), Some(Seq(0)), "the head document is genesis's");
}

/// On an account holding its doc 1 and no mailbox the mint lands at
/// `<account>.0.2` whatever the account's count: at 1, where document 2
/// would be the counter's own next were the block not reserved, and past the
/// block, where the counter stands at 64 and at 66. It is born private,
/// registered in the commit that answers it, entered in the position map at
/// that commit, and owned as every document of the account is, at the
/// account's own seat.
#[test]
fn the_mailbox_lands_at_slot_2_private_whether_the_count_stands_at_1_or_past_the_block() {
    for later in [0u32, 1, 3] {
        let (k, acct) = account_holding_documents_and_no_mailbox(later);
        let ns = Namespace::new(&k);
        let before = k.current_seq();
        assert!(
            !k.snapshot().world().m3().is_registered_document(&a(&[1, 0, 1, 0, 2])),
            "{later} later documents: the slot is empty before the mint"
        );

        let (mailbox, at) = ns
            .create_well_known_document(ID1, &acct, WellKnownSlot::Mailbox)
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
        let (k, acct) = account_holding_documents_and_no_mailbox(later);
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
            .create_well_known_document(ID1, &acct, WellKnownSlot::Mailbox)
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
        let (k, acct) = account_holding_documents_and_no_mailbox(later);
        let ns = Namespace::new(&k);
        let (first, minted) = ns
            .create_well_known_document(ID1, &acct, WellKnownSlot::Mailbox)
            .expect("the first call mints");
        let mailbox = mailbox_address(&acct).expect("an account's slot");
        assert_eq!(first, WellKnown::Minted(mailbox.clone()), "the first call mints, and says so");
        assert_eq!(k.current_seq(), minted);
        let left_by_the_mint = k.snapshot().world().m3().clone();

        let (again, at) = ns
            .create_well_known_document(ID1, &acct, WellKnownSlot::Mailbox)
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
            .create_well_known_document(ID1, &acct, WellKnownSlot::Mailbox)
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
/// key, so of eight callers released together on each of three accounts —
/// each holding a doc 1 a composite minted, and no mailbox — one mints and
/// seven find the mailbox standing — each answer saying which, the one
/// minted at the mint's own position: every caller of an account is
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
            commit_mint(&k, M3State::document_lock_key(&acct), |m3| m3.mint_document(&acct, true));
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
                        .create_well_known_document(id, acct, WellKnownSlot::Mailbox)
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
/// whether its mailbox stands — created by its home's commit, or by the op
/// itself — where the effective owner of each of those targets earns the
/// mint's own gate or the mailbox's address. Containment is no ownership —
/// π₀'s prefix contains the account, and the owner of an account does not
/// own its sub-account's mailbox. Nothing a refused caller sends commits.
#[test]
fn a_caller_who_is_not_the_effective_owner_is_refused_before_anything_is_read() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let (acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("an account holding no document, its slot empty");
    let (other, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 2]), ID2)
        .expect("a second account");
    let (doc, _) = ns
        .create_new_document(ID2, &other, None)
        .expect("the second account's home, its mailbox beside it");
    let (sub, _) = ns
        .delegate(ID1, t(&[1, 0, 1, 1]), ID3)
        .expect("a sub-account of the first");
    let before = k.current_seq();
    let standing = k.snapshot().world().m3().clone();
    let strangers = [UNKNOWN_ID, BOOTSTRAP_PRINCIPAL, ID2, ID3];

    // A registered account whose slot is empty.
    for stranger in strangers {
        assert_eq!(
            rejected(ns.create_well_known_document(stranger, &acct, WellKnownSlot::Mailbox)),
            CreateDocumentError::NotOwner,
            "{stranger:?} is not ω of {acct}"
        );
    }
    // ω of a sub-account is the principal seated at it, never its parent's.
    assert_eq!(
        rejected(ns.create_well_known_document(ID1, &sub, WellKnownSlot::Mailbox)),
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
        (&doc, ID2),
    ] {
        for stranger in [UNKNOWN_ID, ID3] {
            assert_eq!(
                rejected(ns.create_well_known_document(stranger, target, WellKnownSlot::Mailbox)),
                CreateDocumentError::NotOwner,
                "{stranger:?} at {target}"
            );
        }
        assert_eq!(
            rejected(ns.create_well_known_document(owner, target, WellKnownSlot::Mailbox)),
            CreateDocumentError::Mint(MintError::NotAnAccount),
            "ω at {target}"
        );
    }
    // Refusals all: nothing committed, no slot filled.
    assert_eq!(k.current_seq(), before);
    assert!(*k.snapshot().world().m3() == standing);
    assert!(!standing.is_registered_document(&slot(&acct, MAILBOX_SLOT)));

    // Nor does a stranger learn whether the mailbox stands: with the second
    // account's standing from its home's commit, its owner is answered the
    // address and a stranger the same refusal…
    let other_mailbox = mailbox_address(&other).expect("an account's slot");
    let home_at = standing.minted_at(&doc).expect("the home's position");
    assert_eq!(standing.minted_at(&other_mailbox), Some(home_at), "the premise: it stands");
    for stranger in [UNKNOWN_ID, BOOTSTRAP_PRINCIPAL, ID1, ID3] {
        assert_eq!(
            rejected(ns.create_well_known_document(stranger, &other, WellKnownSlot::Mailbox)),
            CreateDocumentError::NotOwner,
            "{stranger:?} with the home's mailbox standing"
        );
    }
    assert_eq!(
        ns.create_well_known_document(ID2, &other, WellKnownSlot::Mailbox).expect("the owner"),
        (WellKnown::Standing(other_mailbox), before)
    );
    // …and with the first account's minted by the op itself, the same.
    let (mailbox, minted) = ns
        .create_well_known_document(ID1, &acct, WellKnownSlot::Mailbox)
        .expect("the owner mints");
    let mailbox = mailbox.into_address();
    for stranger in strangers {
        assert_eq!(
            rejected(ns.create_well_known_document(stranger, &acct, WellKnownSlot::Mailbox)),
            CreateDocumentError::NotOwner,
            "{stranger:?} with the mailbox standing"
        );
    }
    assert_eq!(
        ns.create_well_known_document(ID1, &acct, WellKnownSlot::Mailbox).expect("the owner"),
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
/// mailbox — here the one the account's home's commit made. Hoisted onto a
/// snapshot, each would keep every sequential test green while a racing
/// commit decided it on stale state — a delegation landing between the
/// authorization and the mint, or two callers both finding the slot empty.
/// So each case is first earned outside any transaction and then made from
/// inside one, where an op that opens its own transaction before deciding
/// meets M2's reentrancy panic and one that decided early hands its answer
/// back.
#[test]
fn every_answer_is_decided_inside_the_ops_own_transaction() {
    let (k, acct, _doc) = kernel_with_account_and_doc();
    let ns = Namespace::new(&k);
    let (empty_acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 2]), ID2)
        .expect("a second account, holding no document");
    let incumbent = mailbox_address(&acct).expect("an account's slot");
    let decided_inside = |case: &str, raised: Option<String>| {
        assert!(
            raised
                .as_deref()
                .is_some_and(|message| message.contains("transact is not reentrant")),
            "{case}: not decided inside the op's own transaction (nested call raised {raised:?})"
        );
    };

    assert_eq!(
        rejected(ns.create_well_known_document(ID2, &acct, WellKnownSlot::Mailbox)),
        CreateDocumentError::NotOwner,
        "a caller that is not ω: the premise"
    );
    decided_inside(
        "a caller that is not ω",
        panic_of_a_nested_call(&k, || ns.create_well_known_document(ID2, &acct, WellKnownSlot::Mailbox)),
    );

    let unregistered = a(&[1, 0, 9]);
    assert_eq!(
        rejected(ns.create_well_known_document(BOOTSTRAP_PRINCIPAL, &unregistered, WellKnownSlot::Mailbox)),
        CreateDocumentError::Mint(MintError::NotAnAccount),
        "an unregistered account: the premise"
    );
    decided_inside(
        "an unregistered account",
        panic_of_a_nested_call(&k, || {
            ns.create_well_known_document(BOOTSTRAP_PRINCIPAL, &unregistered, WellKnownSlot::Mailbox)
        }),
    );

    assert_eq!(
        ns.create_well_known_document(ID1, &acct, WellKnownSlot::Mailbox)
            .expect("a standing mailbox is answered")
            .0,
        WellKnown::Standing(incumbent),
        "a standing mailbox: the premise"
    );
    decided_inside(
        "a standing mailbox",
        panic_of_a_nested_call(&k, || ns.create_well_known_document(ID1, &acct, WellKnownSlot::Mailbox)),
    );

    let before = k.current_seq();
    decided_inside(
        "an empty slot",
        panic_of_a_nested_call(&k, || {
            ns.create_well_known_document(ID2, &empty_acct, WellKnownSlot::Mailbox)
        }),
    );
    assert_eq!(k.current_seq(), before, "the nested call minted");
    assert!(!k.snapshot().world().m3().is_registered_document(&slot(&empty_acct, MAILBOX_SLOT)));
}

/// After the home's mint, slot 2 is a registered document and no other
/// number of the reserved block is — slots 3, 4 and 5 by name, and every
/// number up to the block's end — under a count of 1 and under one past the
/// block, at all three membership reads; before it, no number of the block
/// is. The mailbox is a home like any document: it takes the links its
/// owner's marks are, content, and versions, on chains of its own that open
/// at their first slots.
#[test]
fn after_the_home_slot_2_is_a_registered_document_and_slots_3_4_and_5_are_not() {
    for later in [0u32, 1] {
        let k = mem_kernel(genesis_world());
        let ns = Namespace::new(&k);
        let (acct, _) = ns
            .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
            .expect("a fresh account");
        let m3 = k.snapshot().world().m3().clone();
        for number in 2..FIRST_ORDINARY_DOCUMENT {
            assert!(
                !m3.is_registered_document(&slot(&acct, number)),
                "slot {number} reads registered before the home"
            );
        }

        ns.create_new_document(ID1, &acct, None).expect("the home");
        for _ in 0..later {
            ns.create_new_document(ID1, &acct, None).expect("a later document");
        }
        let mailbox = mailbox_address(&acct).expect("an account's slot");
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
        // The account's own documents stand as the counter handed them out.
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

/// Called for the system account at the mailbox's slot, the op refuses and
/// stages nothing, whoever calls. The system account has no mailbox: its
/// document 2 is the head document, which genesis seeds, and without the
/// guard the op would find that slot filled and answer the head document's
/// address as a mailbox standing. The refusal is the store's own, behind the
/// daemon's door, and it leaves the slice genesis's, the head document
/// published as it was born.
#[test]
fn called_for_the_system_account_it_refuses_and_the_head_document_stands_untouched() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let before = k.current_seq();

    for caller in [SYSTEM_PRINCIPAL, BOOTSTRAP_PRINCIPAL, ID1] {
        assert_eq!(
            rejected(ns.create_well_known_document(caller, &system_account(), WellKnownSlot::Mailbox)),
            CreateDocumentError::SystemAccountNoWellKnown,
            "{caller:?}: refused whoever calls, the account's own principal included"
        );
    }
    assert_eq!(k.current_seq(), before, "a refused call drew a position");
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3 == M3State::genesis(), "a refused call folded a record");
    assert!(m3.published(&head_document()), "the head document is no private mailbox");
    assert_eq!(m3.minted_at(&head_document()), Some(Seq(0)));
}

/// On an account with no document the op mints the slot: it asks for no
/// doc 1. The mailbox stands, private, and the account still holds no
/// document its counter handed out — so its next create is still its doc 1,
/// at the slot its chain opens at, born published by the empty-account rule
/// (PUB-8.21), and the one after it the first ordinary document, private.
/// That first create finds the mailbox standing, so its commit is the home's
/// one record and the mailbox keeps its own earlier position — the fold
/// refusing a second record at the filled slot, nothing fail-stops.
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
        .create_well_known_document(ID1, &acct, WellKnownSlot::Mailbox)
        .expect("the slot mints on an account with no document");
    assert_eq!(mailbox, WellKnown::Minted(a(&[1, 0, 1, 0, 2])));
    let mailbox = mailbox.into_address();
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3.is_registered_document(&mailbox) && !m3.published(&mailbox));
    assert!(!m3.has_documents(&acct), "a slot is no document the counter handed out");
    let doc_1 = first_document_address(&acct).expect("an account anchors a document chain");
    assert!(!m3.is_registered_document(&doc_1));
    assert_eq!(m3.mint_document(&acct, false).expect("the counter's next").0, doc_1);

    let before_the_home = k.current_seq();
    let (first, home_at) = ns
        .create_new_document(ID1, &acct, None)
        .expect("the account's first create");
    assert_eq!(first, doc_1);
    assert_eq!(first, a(&[1, 0, 1, 0, 1]));
    assert_eq!(
        home_at,
        Seq(before_the_home.0 + 1),
        "the home's commit is its own record alone: the mailbox stands"
    );
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
        ns.create_well_known_document(ID1, &acct, WellKnownSlot::Mailbox).expect("the incumbent"),
        (WellKnown::Standing(mailbox), standing)
    );
}

/// The mailbox rides its home's commit, under the home's one marker: an
/// attested handle's first create commits the home and the mailbox at one
/// position, whose marker holds the attestation the create's own act is
/// signed under, and a slot-2 call on the same handle after it finds the
/// mailbox standing and commits nothing, so no second marker is written.
/// The mailbox's own mint, made at the store on an account holding no
/// document, takes the plain arm whatever the handle carries — a private
/// mint signs nothing of its own — and the home after it commits its one
/// record under the attestation. Over a journaled kernel, since an
/// in-memory one keeps no marker.
#[test]
fn an_attested_home_mint_carries_the_mailbox_under_its_one_marker() {
    let dir = tempdir().expect("tempdir");
    let k = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("open");
    let attestation =
        Attestation::new(1, vec![0xA5; 64]).expect("a non-zero tag over a non-empty blob");
    let attested = Namespace::attested(&k, Some(&attestation));
    let (acct, _) = Namespace::new(&k)
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("the delegation commits");
    let (other, _) = Namespace::new(&k)
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 2]), ID2)
        .expect("the delegation commits");
    let marker = |at| k.attestation_at(at).expect("a journaled kernel reads its own markers");

    // The home's commit: both records, one marker, the attestation in it.
    let before = k.current_seq();
    let (_, created) = attested
        .create_new_document(ID1, &acct, None)
        .expect("the create commits");
    assert_eq!(created, Seq(before.0 + 2), "the home's commit is two records");
    let mailbox = mailbox_address(&acct).expect("an account's slot");
    let m3 = k.snapshot().world().m3().clone();
    assert_eq!(m3.minted_at(&mailbox), Some(created), "the mailbox rides the home's commit");
    assert!(!m3.published(&mailbox));
    assert_eq!(
        marker(created),
        Some(attestation.clone()),
        "the home's commit is signed, the mailbox inside it"
    );
    assert_eq!(
        attested
            .create_well_known_document(ID1, &acct, WellKnownSlot::Mailbox)
            .expect("a slot-2 call is answered"),
        (WellKnown::Standing(mailbox), created)
    );
    assert_eq!(k.current_seq(), created, "the slot-2 call committed");

    // The slot's own mint on an account holding no document: the plain arm.
    let (minted, at) = attested
        .create_well_known_document(ID2, &other, WellKnownSlot::Mailbox)
        .expect("the mailbox commits");
    assert!(matches!(minted, WellKnown::Minted(_)));
    assert_eq!(marker(at), None, "the mailbox's own marker carries a signature");
    // …and the home after it: one record, under the attestation.
    let (_, home_at) = attested
        .create_new_document(ID2, &other, None)
        .expect("the home commits");
    assert_eq!(home_at, Seq(at.0 + 1), "the home's commit is its own record alone");
    assert_eq!(marker(home_at), Some(attestation.clone()), "the home's commit is signed");
}

/// The mailbox is one ordinary record of its home's commit, and it replays:
/// reopened from its journal alone, the board holds the mailbox where the
/// home's commit put it, private, at that commit's position, with the
/// counter where it stood. A call before the reopen and a call after it —
/// another device's, say — are each answered with that mailbox and stage
/// nothing.
#[test]
fn the_mailbox_replays_from_the_journal_and_a_call_after_the_reopen_mints_nothing() {
    let dir = tempdir().expect("tempdir");
    let (acct, mailbox, minted, head, left) = {
        let k = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("open");
        let ns = Namespace::new(&k);
        let (acct, _) = ns
            .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
            .expect("delegate");
        let (_, minted) = ns
            .create_new_document(ID1, &acct, None)
            .expect("doc 1, and the mailbox beside it");
        ns.create_new_document(ID1, &acct, None)
            .expect("a second document");
        let head = k.current_seq();
        let (mailbox, at) = ns
            .create_well_known_document(ID1, &acct, WellKnownSlot::Mailbox)
            .expect("a slot-2 call is answered");
        assert!(matches!(mailbox, WellKnown::Standing(_)), "the premise: it stands");
        assert_eq!((at, k.current_seq()), (head, head), "the premise: nothing committed");
        (acct, mailbox.into_address(), minted, head, k.snapshot().world().m3().clone())
    };

    let k = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("reopen");
    assert_eq!(k.current_seq(), head);
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
            .create_well_known_document(ID1, &acct, WellKnownSlot::Mailbox)
            .expect("a call after the reopen is answered"),
        (WellKnown::Standing(mailbox), head)
    );
    assert_eq!(k.current_seq(), head, "the call after the reopen drew a position");
}
