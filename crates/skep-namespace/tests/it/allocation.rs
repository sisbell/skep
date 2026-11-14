//! §A frontier mints — the next address each answers on its own chain, the
//! caller's half of a mint, the allocator's laws, each mint's structural
//! refusals and how a wrapping refusal reports its cause — and §C
//! membership, which is exact chain membership.

use std::error::Error;

use crate::common::*;

use skep_address::{content_subspace, link_subspace, ordinal, Address, GateViolation, Level, Nat};
use skep_kernel::Kernel;
use skep_namespace::{
    first_version_address, system_account, CreateDocumentError, HasM3, M3Rec, M3State, MintError,
    Namespace, PrincipalId, BOOTSTRAP_PRINCIPAL, FIRST_ORDINARY_DOCUMENT, SYSTEM_PRINCIPAL,
};

#[test]
fn pure_mints_answer_the_next_address_on_their_own_chains() {
    let (k, acct, doc) = kernel_with_account_and_doc();
    let snap = k.snapshot();
    let m3 = snap.world().m3();

    // mint_content: namespace (b_C(d), 1), element field [s_C = 1, m+1] (§3).
    let (c1, rec) = m3.mint_content(&doc).expect("content mint");
    assert_eq!(c1, a(&[1, 0, 1, 0, 1, 0, 1, 1]));
    assert_eq!(c1.subspace(), Some(&content_subspace()));
    // The mint hands back exactly the Allocate for the minted address —
    // whole value, variant and payload alike; an element carries no
    // publication state, so the bit is the non-document mints' `false`.
    assert_eq!(rec, M3Rec::allocate(c1.clone(), false));
    // Determinism (B2): a pure function of the frontier — same state, same
    // answer.
    assert_eq!(m3.mint_content(&doc).expect("repeat").0, c1);

    // mint_link: namespace (b_L(d), 1), s_L = 2 — content↔link address
    // spaces disjoint by construction (SD/L14, T7).
    let (l1, _) = m3.mint_link(&doc).expect("link mint");
    assert_eq!(l1, a(&[1, 0, 1, 0, 1, 0, 2, 1]));
    assert_eq!(l1.subspace(), Some(&link_subspace()));

    // mint_version: namespace (d, 1) — the version chain, SEPARATE from the
    // document chain (ASN-0123 VD).
    let (v1, _) = m3.mint_version(&doc, false).expect("version mint");
    assert_eq!(v1, a(&[1, 0, 1, 0, 1, 1]));
    assert_eq!(v1.level(), Level::Document);

    // mint_document: namespace (account, 2) — advances independently of the
    // version chain; no collision (the ASN-0103 fix). The account holds its
    // doc 1, so the counter's next is its second document, past the reserved
    // block.
    let (d2, _) = m3.mint_document(&acct, false).expect("document mint");
    assert_eq!(d2, nth_document(&acct, 2));
    assert_ne!(d2, v1);
}

#[test]
fn successive_mints_in_one_composite_read_working_state() {
    // The M5-shaped composite (§A / M2 contract 3): lock key taken BEFORE
    // the closure, mints read working() so each sees the prior mint, staged
    // records lifted via .into().
    let (k, _acct, doc) = kernel_with_account_and_doc();
    let keys = [M3State::content_lock_key(&doc)];
    let ((c1, c2), seq) = k
        .transact::<_, MintError>(&keys, |stg| {
            let (c1, r1) = stg.working().m3().mint_content(&doc)?;
            stg.push(r1.into());
            let (c2, r2) = stg.working().m3().mint_content(&doc)?;
            stg.push(r2.into());
            Ok((c1, c2))
        })
        .expect("composite commits");
    assert_eq!(c1, a(&[1, 0, 1, 0, 1, 0, 1, 1]));
    assert_eq!(c2, a(&[1, 0, 1, 0, 1, 0, 1, 2])); // saw the prior mint
    let snap = k.snapshot();
    assert_eq!(snap.seq(), seq);
    assert!(snap.world().m3().is_allocated(&c1));
    assert!(snap.world().m3().is_allocated(&c2));
}

#[test]
fn every_chain_survives_the_round_trip_from_mint_to_allocated() {
    // §1/§2: the key a mint READS and the key its staged Allocate ADVANCES
    // are one key, so a minted address is allocated once the fold has seen
    // it and the NEXT mint on that chain differs from it. A divergence
    // between the two derivations would re-hand a live address — the one
    // fatal error — without any mint or query saying so.
    let (k, acct, doc) = kernel_with_account_and_doc();

    // Version chain (d, 1) — ASN-0123's separate chain. Its two ends are
    // M3's to name: the slot it opens at is nameable before anything
    // occupies it, and its latest member is `None` while it has none.
    let slot = first_version_address(&doc).expect("a document anchors a version chain");
    assert_eq!(slot, a(&[1, 0, 1, 0, 1, 1]));
    assert!(k.snapshot().world().m3().latest_version(&doc).is_none());
    let v1 = commit_mint(&k, M3State::version_lock_key(&doc), |m3| {
        m3.mint_version(&doc, false)
    });
    assert_eq!(v1, slot);
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3.is_allocated(&v1));
    assert_eq!(m3.latest_version(&doc), Some(v1.clone()));
    // A version IS a registered Document — the M5 CREATENEWVERSION seam.
    assert!(m3.is_registered_document(&v1));
    assert_eq!(m3.entity_level(&v1), Some(Level::Document));
    // The frontier advanced, so the chain does not re-mint v1, and the
    // latest member moves with it.
    let v2 = commit_mint(&k, M3State::version_lock_key(&doc), |m3| {
        m3.mint_version(&doc, false)
    });
    assert_eq!(v2, a(&[1, 0, 1, 0, 1, 2]));
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3.is_allocated(&v2));
    assert_eq!(m3.latest_version(&doc), Some(v2.clone()));

    // Link chain (b_L(d), 1) — allocated, and NEVER an entity.
    let l1 = commit_mint(&k, M3State::link_lock_key(&doc), |m3| m3.mint_link(&doc));
    let l2 = commit_mint(&k, M3State::link_lock_key(&doc), |m3| m3.mint_link(&doc));
    assert_eq!(l1, a(&[1, 0, 1, 0, 1, 0, 2, 1]));
    assert_eq!(l2, a(&[1, 0, 1, 0, 1, 0, 2, 2]));
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3.is_allocated(&l1) && m3.is_allocated(&l2));
    assert_eq!(m3.entity_level(&l1), None);

    // A version is a usable home in its own right: it carries content and
    // versions of its own, on chains anchored at IT — and that daughter
    // chain has its own two ends, which move nothing on the trunk.
    let daughter_content = commit_mint(&k, M3State::content_lock_key(&v1), |m3| {
        m3.mint_content(&v1)
    });
    assert_eq!(daughter_content, a(&[1, 0, 1, 0, 1, 1, 0, 1, 1]));
    let daughter_version = commit_mint(&k, M3State::version_lock_key(&v1), |m3| {
        m3.mint_version(&v1, false)
    });
    assert_eq!(daughter_version, a(&[1, 0, 1, 0, 1, 1, 1]));
    assert_eq!(
        daughter_version,
        first_version_address(&v1).expect("a member anchors a chain of its own")
    );
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3.is_allocated(&daughter_content) && m3.is_allocated(&daughter_version));
    assert_eq!(m3.latest_version(&v1), Some(daughter_version.clone()));
    assert_eq!(m3.latest_version(&doc), Some(v2.clone()));

    // Only a document anchors a version chain: the `(A, 1)` key under an
    // account is the SUB-ACCOUNT chain, and a node or an element anchors
    // no version chain at all — so neither end answers off the tier.
    for off_tier in [&acct, &a(&[1]), &daughter_content] {
        assert!(first_version_address(off_tier).is_none(), "{off_tier:?}");
        assert!(m3.latest_version(off_tier).is_none(), "{off_tier:?}");
    }

    // Through all of it the document chain (A, 2) stood still — the ASN-0123
    // separation, now checked across real folds rather than one snapshot.
    assert_eq!(
        m3.mint_document(&acct, false).expect("document mint").0,
        nth_document(&acct, 2)
    );
}

#[test]
fn a_mint_whose_record_is_never_staged_re_hands_its_address() {
    // §A: advancing the frontier is the CALLER's half of every mint, and
    // nothing in M3 can enforce it — the record is delivered inside a tuple
    // the caller has already destructured. This is that obligation made
    // executable rather than left as prose: drop the record and the very next
    // mint on the chain returns the SAME address, with no error and no query
    // saying so. The fold's contiguity check cannot see it either, since the
    // second Allocate would be a legitimate m + 1.
    let (k, _acct, doc) = kernel_with_account_and_doc();
    let key = M3State::content_lock_key(&doc);

    // A composite that mints and commits without staging: it commits, and it
    // moves nothing.
    let (dropped, _) = k
        .transact::<_, MintError>(std::slice::from_ref(&key), |stg| {
            Ok(stg.working().m3().mint_content(&doc)?.0)
        })
        .expect("the transaction commits");
    assert_eq!(dropped, a(&[1, 0, 1, 0, 1, 0, 1, 1]));
    assert!(!k.snapshot().world().m3().is_allocated(&dropped));

    // …so the chain hands the address out a second time — the reuse the
    // caller's half exists to prevent, and which M3 alone cannot.
    let staged = commit_mint(&k, key, |m3| m3.mint_content(&doc));
    assert_eq!(staged, dropped);
    assert!(k.snapshot().world().m3().is_allocated(&staged));
}

#[test]
#[should_panic(expected = "Allocate ordinal must equal its namespace's effective frontier + 1")]
fn a_peeked_record_staged_in_a_later_transaction_fail_stops_the_fold() {
    // §A: the caller's half has a second clause the drop above does not
    // reach — a mint's record is staged in the transaction whose working
    // state the mint was called on, and nowhere else (`M3Rec::Allocate`). A
    // peek names the address the chain issues next; once another mint has
    // landed there, the peek's record names an address already issued, and
    // nothing in the record says which state it was read from. The fold's
    // contiguity check refuses it, on every build, at the push — this is
    // that refusal made executable; folded, the record would issue the
    // address twice.
    let (k, _acct, doc) = kernel_with_account_and_doc();
    let (peeked, rec) = k
        .snapshot()
        .world()
        .m3()
        .mint_content(&doc)
        .expect("a peek off a snapshot");
    let landed = commit_mint(&k, M3State::content_lock_key(&doc), |m3| {
        m3.mint_content(&doc)
    });
    assert_eq!(
        landed, peeked,
        "the landed mint took the address the peek named"
    );
    let _ = k.transact::<_, MintError>(&[M3State::content_lock_key(&doc)], |stg| {
        stg.push(rec.into());
        Ok(())
    });
}

#[test]
fn the_allocator_never_repeats_an_address_across_an_interleaved_schedule() {
    // B1/B2 as laws, not examples: over a mechanical round-robin across the
    // four chains, every minted address is distinct and allocated, the next
    // mint on each chain is still fresh, and the whole schedule is
    // deterministic.
    fn run() -> (Kernel<World>, Vec<Address>, Address, Address) {
        let (k, acct, doc) = kernel_with_account_and_doc();
        let keys = [
            M3State::content_lock_key(&doc),
            M3State::link_lock_key(&doc),
            M3State::version_lock_key(&doc),
            M3State::document_lock_key(&acct),
        ];
        let mut minted = Vec::new();
        for _round in 0..5 {
            let round_mints = k
                .transact::<_, MintError>(&keys, |stg| {
                    let (c, rc) = stg.working().m3().mint_content(&doc)?;
                    stg.push(rc.into());
                    let (l, rl) = stg.working().m3().mint_link(&doc)?;
                    stg.push(rl.into());
                    let (v, rv) = stg.working().m3().mint_version(&doc, false)?;
                    stg.push(rv.into());
                    let (d, rd) = stg.working().m3().mint_document(&acct, false)?;
                    stg.push(rd.into());
                    Ok(vec![c, l, v, d])
                })
                .expect("the round commits")
                .0;
            minted.extend(round_mints);
        }
        (k, minted, acct, doc)
    }

    let (k, minted, acct, doc) = run();
    // Never reused: 20 mints, 20 distinct addresses (across chains as well
    // as within one).
    let distinct: std::collections::BTreeSet<&Address> = minted.iter().collect();
    assert_eq!(
        distinct.len(),
        minted.len(),
        "an address was minted twice: {minted:?}"
    );
    // Every one of them is allocated.
    let m3 = k.snapshot().world().m3().clone();
    for addr in &minted {
        assert!(
            m3.is_allocated(addr),
            "{addr:?} was minted but is not allocated"
        );
    }
    // Gap-free and monotone per chain: the next mint on each chain is an
    // address the schedule has not already handed out, and is not yet
    // allocated.
    for (chain, next) in [
        ("content", m3.mint_content(&doc).expect("peek").0),
        ("link", m3.mint_link(&doc).expect("peek").0),
        ("version", m3.mint_version(&doc, false).expect("peek").0),
        ("document", m3.mint_document(&acct, false).expect("peek").0),
    ] {
        assert!(
            !minted.contains(&next),
            "{chain}: the next mint repeats {next:?}"
        );
        assert!(
            !m3.is_allocated(&next),
            "{chain}: the next mint is already allocated"
        );
    }
    // Determinism (B2): the same schedule from genesis yields the same list.
    let (_k2, again, _, _) = run();
    assert_eq!(minted, again);
}

/// The first ordinary document's number, spelled: the one cell that says what
/// `FIRST_ORDINARY_DOCUMENT` is (the mailbox design §2: an account's own
/// documents are 1, then 64, 65 and on). Every other row of this suite reads
/// the constant through `nth_document`, as the helpers and fixtures of the
/// crates above read it, so a moved constant moves them all and this pin
/// alone sees it.
#[test]
fn the_first_ordinary_document_is_number_64() {
    assert_eq!(FIRST_ORDINARY_DOCUMENT, 64);
    // …and the helper every row reads is that number worked out: doc 1, the
    // constant, the one after it.
    let acct = a(&[1, 0, 1]);
    assert_eq!(nth_document(&acct, 1), a(&[1, 0, 1, 0, 1]));
    assert_eq!(nth_document(&acct, 2), under(&acct, &[0, FIRST_ORDINARY_DOCUMENT]));
    assert_eq!(nth_document(&acct, 3), under(&acct, &[0, FIRST_ORDINARY_DOCUMENT + 1]));
}

/// No mint answers a document number of the reserved block (the mailbox
/// design §2), held as a law over a generated run rather than at one
/// account. Eight accounts — six under the bootstrap node, a sub-account, and
/// the system account, whose doc 1 and three named slots genesis seeded —
/// take four hundred steps a fixed generator picks: a document minted
/// through one of the three doors that mint one — the create op, `fork`, and
/// the bare mint a cross-owner version makes — or a record that fills the
/// account's next empty named slot. Every mint answers the account's next
/// document by the helper: doc 1, then the first ordinary document and on,
/// in every account, the system account's included. So none lies in the
/// block, a slot's record moves no count wherever it falls among the mints,
/// and under counts far past the block a number of it reads registered
/// exactly where a record placed a document.
#[test]
fn no_mint_ever_answers_a_document_number_of_the_reserved_block() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    // Each account with its principal, the documents its counter has handed
    // out, and the named slots a record has filled.
    let mut accounts: Vec<(Address, PrincipalId, u32, Vec<u32>)> = (1..=6)
        .map(|i| {
            let id = PrincipalId(10 + u64::from(i));
            let (acct, _) = ns
                .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, i]), id)
                .expect("an account under the bootstrap node");
            (acct, id, 0, Vec::new())
        })
        .collect();
    let (sub_acct, _) = ns
        .delegate(PrincipalId(11), t(&[1, 0, 1, 1]), PrincipalId(20))
        .expect("a sub-account");
    accounts.push((sub_acct, PrincipalId(20), 0, Vec::new()));
    // Genesis handed the system account its doc 1 and filled its three slots.
    accounts.push((system_account(), SYSTEM_PRINCIPAL, 1, NAMED_SLOTS.to_vec()));

    let mut state = 0x9E37_79B9u32;
    for step in 0..400 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let which = (state >> 16) as usize % accounts.len();
        let (acct, id, minted, filled) = &mut accounts[which];
        let door = (state >> 28) % 4;
        if door == 3 {
            // Fill the account's next empty named slot, where one is left.
            let Some(&number) = NAMED_SLOTS.iter().find(|number| !filled.contains(number)) else {
                continue;
            };
            let placed = slot(acct, number);
            k.transact::<_, MintError>(&[M3State::document_lock_key(acct)], |stg| {
                stg.push(M3Rec::allocate(placed.clone(), state & 1 == 1).into());
                Ok(())
            })
            .expect("a named slot's record commits");
            filled.push(number);
            continue;
        }
        let doc = match door {
            0 => ns.create_new_document(*id, acct, None).expect("create").0,
            1 => ns.fork(*id, None).expect("fork").0,
            _ => commit_mint(&k, M3State::document_lock_key(acct), |m3| {
                m3.mint_document(acct, false)
            }),
        };
        *minted += 1;
        assert_eq!(
            doc,
            nth_document(acct, *minted),
            "step {step}: mint {minted} of {acct} is not its next document"
        );
        let number = ordinal(doc.tumbler());
        assert!(
            *number == Nat::from(1u32) || *number >= Nat::from(FIRST_ORDINARY_DOCUMENT),
            "step {step}: a mint answered {doc}, a document number of the reserved block"
        );
    }

    let m3 = k.snapshot().world().m3().clone();
    for (acct, _, minted, filled) in &accounts {
        assert!(
            *minted >= 3,
            "{acct} took {minted} mints: the run never carried it past the block"
        );
        for number in 2..FIRST_ORDINARY_DOCUMENT {
            let placed = slot(acct, number);
            assert_eq!(
                m3.is_registered_document(&placed),
                filled.contains(&number),
                "{placed} under a count past the block"
            );
        }
        for nth in 1..=*minted {
            assert!(m3.is_registered_document(&nth_document(acct, nth)), "{acct}'s document {nth}");
        }
        assert!(!m3.is_registered_document(&nth_document(acct, minted + 1)));
    }
}

#[test]
fn mint_preconditions_reject_structurally() {
    let (k, acct, doc) = kernel_with_account_and_doc();
    // An ALLOCATED content element, so the element-tier refusals below are
    // refusals on TIER and not on allocation.
    let element = commit_mint(&k, M3State::content_lock_key(&doc), |m3| {
        m3.mint_content(&doc)
    });
    let node = a(&[1]); // the registered bootstrap node
    let snap = k.snapshot();
    let m3 = snap.world().m3();
    let unregistered_doc = a(&[1, 0, 1, 0, 71]); // document-level, never registered
    let unregistered_acct = a(&[1, 0, 9]); // account-level, never registered

    // P6/C2/L1a: content/link home must be a REGISTERED Document.
    assert_eq!(
        m3.mint_content(&unregistered_doc).unwrap_err(),
        MintError::HomeNotRegistered
    );
    assert_eq!(
        m3.mint_link(&unregistered_doc).unwrap_err(),
        MintError::HomeNotRegistered
    );
    assert_eq!(
        m3.mint_content(&acct).unwrap_err(),
        MintError::HomeNotRegistered
    );
    // An ACCOUNT home for a link: b_L(A) = inc(b_C(A), 0) = A·0·2, so the key
    // `link_lock_key(A)` builds is the VERSION chain of A's doc 2 — the alias
    // that key's doc names and calls harmless because this mint refuses the
    // home a moment later. Ungated, a link mint under an account hands out
    // doc 2's first version slot, a Document-tier address, as a link.
    assert_eq!(
        m3.mint_link(&acct).unwrap_err(),
        MintError::HomeNotRegistered
    );
    // V-WF: version source must be a registered Document — covers an
    // unregistered address AND a registered non-document alike.
    assert_eq!(
        m3.mint_version(&unregistered_doc, false).unwrap_err(),
        MintError::SourceNotRegistered
    );
    assert_eq!(
        m3.mint_version(&acct, false).unwrap_err(),
        MintError::SourceNotRegistered
    );
    // P8/CND.pre: document target must be a registered Account — covers
    // unregistered AND non-account (document, node) alike.
    assert_eq!(
        m3.mint_document(&unregistered_acct, false).unwrap_err(),
        MintError::NotAnAccount
    );
    assert_eq!(
        m3.mint_document(&doc, false).unwrap_err(),
        MintError::NotAnAccount
    );
    assert_eq!(
        m3.mint_document(&node, false).unwrap_err(),
        MintError::NotAnAccount
    );

    // The remaining wrong tiers, and why each gate is load-bearing rather
    // than tidy. The mints are PUBLIC and take any `&Address`, so a caller's
    // tier mistake is refused here or not at all.
    //
    // A NODE home: b_C([1]) = inc([1], 2) = [1,0,1], so `content_ns([1])` IS
    // `account_ns([1,0,1])` — same NsKey, same lock, same frontier. Ungated,
    // a content mint under a node hands out the SUB-ACCOUNT chain's next
    // address (§1: an alias would under-serialize a namespace and REUSE one).
    assert_eq!(
        m3.mint_content(&node).unwrap_err(),
        MintError::HomeNotRegistered
    );
    assert_eq!(
        m3.mint_link(&node).unwrap_err(),
        MintError::HomeNotRegistered
    );
    // A NODE source: version_ns([1])'s c₁ is [1,1] — the SYSTEM NODE genesis
    // admits (PUB-6.65) — so an ungated version mint would re-hand a live
    // address as a fresh "version", the one fatal error.
    assert!(
        m3.is_allocated(&a(&[1, 1])),
        "[1,1] is the seeded system node"
    );
    assert_eq!(
        m3.mint_version(&node, false).unwrap_err(),
        MintError::SourceNotRegistered
    );
    // An ELEMENT home: b_C(e) = e ++ [0, s_C] carries four separators and is
    // outside T4 — the anchor precondition `first_in` states. Ungated, the
    // anchor lift `expect`s and the mint PANICS instead of refusing.
    assert_eq!(
        m3.mint_content(&element).unwrap_err(),
        MintError::HomeNotRegistered
    );
    assert_eq!(
        m3.mint_link(&element).unwrap_err(),
        MintError::HomeNotRegistered
    );
    assert_eq!(
        m3.mint_version(&element, false).unwrap_err(),
        MintError::SourceNotRegistered
    );
    // An ELEMENT target is the ONE live input that could reach M1's TA5a gate
    // — document_ns(e) asks for k = 2 at the Element tier, which `checked_inc`
    // refuses — so this gate is what keeps `MintError::Gate` the dead,
    // defensive arm its own doc claims it is.
    assert_eq!(
        m3.mint_document(&element, false).unwrap_err(),
        MintError::NotAnAccount
    );
    // The fifth mint's gate through its published face (the document and
    // unregistered cases are pinned in
    // `delegate_mints_the_account_and_registers_its_principal`).
    assert!(m3.next_account_prefix(&element).is_none());
    // The content chain's peek reads the mint's one refusal as an absence, at
    // every home that mint refuses: unregistered, an account, a node, an
    // element.
    for home in [&unregistered_doc, &acct, &node, &element] {
        assert_eq!(m3.next_content_address(home), None, "{home:?}");
    }
}

#[test]
fn a_mint_refusal_lifts_into_the_document_rejection() {
    // The shared mint vocabulary lifts by the standard conversion, so a mint
    // composes with `?` inside an op that creates a document — the same lift
    // M5 and M7 provide into their own op errors.
    fn create(m3: &M3State, account: &Address) -> Result<Address, CreateDocumentError> {
        Ok(m3.mint_document(account, false)?.0)
    }
    let (k, acct, doc) = kernel_with_account_and_doc();
    let snap = k.snapshot();
    let m3 = snap.world().m3();
    assert_eq!(create(m3, &acct), Ok(nth_document(&acct, 2)));
    assert_eq!(
        create(m3, &doc),
        Err(CreateDocumentError::Mint(MintError::NotAnAccount))
    );
}

#[test]
fn a_wrapping_rejection_names_its_own_layer_and_delegates_the_cause() {
    // A wrapping variant's `Display` names its own layer and `source` hands
    // over the cause, so a reporter walking the chain prints each message
    // once — the discipline M5's wrappers of `MintError` keep. Compared
    // against each cause's OWN message, never a literal, so either layer may
    // reword freely.
    let gate = MintError::Gate(GateViolation);
    let cause = gate.source().expect("M1's refusal is the cause");
    assert_eq!(cause.to_string(), GateViolation.to_string());
    assert!(
        !gate.to_string().contains(&cause.to_string()),
        "{gate} repeats its cause"
    );

    let mint = CreateDocumentError::Mint(MintError::NotAnAccount);
    let cause = mint.source().expect("the mint refusal is the cause");
    assert_eq!(cause.to_string(), MintError::NotAnAccount.to_string());
    assert!(
        !mint.to_string().contains(&cause.to_string()),
        "{mint} repeats its cause"
    );

    // The leaves end the chain.
    assert!(MintError::NotAnAccount.source().is_none());
    assert!(CreateDocumentError::NotOwner.source().is_none());
}

// ---- §C queries: membership ----

#[test]
fn membership_is_exact_chain_membership() {
    let (k, acct, doc) = kernel_with_account_and_doc();
    let snap = k.snapshot();
    let m3 = snap.world().m3();

    // Ghost principle (B3): a registered-empty document is an addressable
    // ghost — allocated with no content ever minted.
    assert!(m3.is_allocated(&doc));
    assert!(m3.is_registered_document(&doc));
    assert_eq!(m3.entity_level(&doc), Some(Level::Document));
    assert_eq!(m3.entity_level(&acct), Some(Level::Account));
    // The tier predicates name the two rungs a caller outside M3 asks for,
    // and each discriminates the other's tier.
    assert!(m3.is_registered_account(&acct));
    assert!(!m3.is_registered_account(&doc)); // a document is not an account
    assert!(!m3.is_registered_account(&a(&[1]))); // nor is the bootstrap node

    // Exact range membership (§2): the slot the next mint fills is out —
    // on the document chain the account's second document, past the reserved
    // block; on the account chain the ordinal past the frontier.
    let next_doc = nth_document(&acct, 2);
    assert!(!m3.is_allocated(&next_doc));
    assert!(!m3.is_allocated(&a(&[1, 0, 2])));
    assert_eq!(m3.entity_level(&next_doc), None);
    assert!(!m3.is_registered_document(&next_doc));
    assert!(!m3.is_registered_account(&a(&[1, 0, 2])));

    // Content elements: unallocated before their mint, allocated after —
    // and NEVER entities (content/link are not in E; use is_allocated).
    let c1 = a(&[1, 0, 1, 0, 1, 0, 1, 1]);
    assert!(!m3.is_allocated(&c1));
    let keys = [M3State::content_lock_key(&doc)];
    k.transact::<_, MintError>(&keys, |stg| {
        let (_, r) = stg.working().m3().mint_content(&doc)?;
        stg.push(r.into());
        Ok(())
    })
    .expect("content commit");
    let snap = k.snapshot();
    let m3 = snap.world().m3();
    assert!(m3.is_allocated(&c1));
    assert_eq!(m3.entity_level(&c1), None);
    assert!(!m3.is_registered_document(&c1));
    // Its sibling one past the frontier is not allocated.
    assert!(!m3.is_allocated(&a(&[1, 0, 1, 0, 1, 0, 1, 2])));

    // No FALSE positives (§2): the near-misses of an allocated content
    // element all decompose to a DIFFERENT namespace, so none is a member —
    // membership is genuine chain membership, not an approximation of it.
    for near in [
        a(&[1, 0, 1, 0, 1, 0, 1]),       // b_C(d) — the chain's own anchor
        a(&[1, 0, 1, 0, 1, 0, 2]),       // b_L(d) — the link anchor
        a(&[1, 0, 1, 0, 1, 0, 2, 1]),    // the same ordinal in the link subspace
        a(&[1, 0, 1, 0, 1, 0, 3, 1]),    // the same ordinal in subspace 3, which no chain anchors
        a(&[1, 0, 1, 0, 1, 0, 1, 1, 1]), // one component deeper than c1
        under(&next_doc, &[0, 1, 1]),    // the same ordinal under a sibling doc
        a(&[1, 0, 1, 0, 1, 1]),          // the version chain's first slot
    ] {
        assert!(
            !m3.is_allocated(&near),
            "{near:?} is not allocated but reads as a member"
        );
    }
    assert!(m3.is_allocated(&c1)); // …while the real member still is
}

/// Under a count past the reserved block, membership still answers each
/// number of the block by the document a record placed there, never by the
/// count (§2; the mailbox design §2: a slot can be named, and linked to,
/// before anything stands at it). With the account's second document minted
/// the count covers every number of the block, and all of them read
/// unregistered at all three membership reads, so nothing mints under one.
/// One record then fills one named slot: that slot is registered and is a
/// home like any document, and no other number is. In the system account
/// genesis filled the three named slots, and those three alone read
/// registered, before its counter passes the block and after.
#[test]
fn a_number_of_the_reserved_block_is_registered_only_where_a_record_placed_a_document() {
    let (k, acct, doc) = kernel_with_account_and_doc();
    let second = commit_mint(&k, M3State::document_lock_key(&acct), |m3| {
        m3.mint_document(&acct, false)
    });
    assert_eq!(second, nth_document(&acct, 2), "the count stands past the block");
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3.is_registered_document(&doc) && m3.is_registered_document(&second));
    for number in 2..FIRST_ORDINARY_DOCUMENT {
        let empty = slot(&acct, number);
        assert!(!m3.is_registered_document(&empty), "{empty} reads registered");
        assert!(!m3.is_allocated(&empty), "{empty} reads allocated");
        assert_eq!(m3.entity_level(&empty), None, "{empty} reads as an entity");
        assert_eq!(
            m3.mint_version(&empty, false).unwrap_err(),
            MintError::SourceNotRegistered,
            "{empty}"
        );
        assert_eq!(m3.mint_content(&empty).unwrap_err(), MintError::HomeNotRegistered, "{empty}");
        assert_eq!(m3.mint_link(&empty).unwrap_err(), MintError::HomeNotRegistered, "{empty}");
    }

    let filled = slot(&acct, 2);
    let m3 = m3.apply_m3(Seq(9), &M3Rec::allocate(filled.clone(), false));
    for number in 2..FIRST_ORDINARY_DOCUMENT {
        let placed = slot(&acct, number);
        let is_the_filled_one = placed == filled;
        assert_eq!(m3.is_registered_document(&placed), is_the_filled_one, "{placed}");
        assert_eq!(m3.is_allocated(&placed), is_the_filled_one, "{placed}");
        assert_eq!(
            m3.entity_level(&placed),
            is_the_filled_one.then_some(Level::Document),
            "{placed}"
        );
    }
    assert_eq!(
        m3.mint_version(&filled, false).expect("a filled slot is a version's source").0,
        under(&filled, &[1])
    );
    assert_eq!(
        m3.mint_content(&filled).expect("a filled slot is a home").0,
        under(&filled, &[0, 1, 1])
    );
    assert_eq!(
        m3.mint_link(&filled).expect("a filled slot is a home").0,
        under(&filled, &[0, 2, 1])
    );

    // The seeded half, before the system account's counter passes the block
    // and after its next mint carries it there.
    let (sys_second, rec) = m3
        .mint_document(&system_account(), false)
        .expect("the system account mints");
    assert_eq!(sys_second, nth_document(&system_account(), 2));
    for m3 in [m3.clone(), m3.apply_m3(Seq(10), &rec)] {
        for number in 2..FIRST_ORDINARY_DOCUMENT {
            let placed = slot(&system_account(), number);
            assert_eq!(
                m3.is_registered_document(&placed),
                NAMED_SLOTS.contains(&number),
                "{placed}: genesis fills the system account's named slots and no other"
            );
        }
    }
}

/// The position map (D1; the permanence record's D6): the record each mint
/// hands back, folded at a position, enters that position for a document, a
/// version member and a link — the three families a reader asks the age of —
/// and for nothing else: a content element's record enters no position (a run
/// of bytes is placed, not dated), an account's seat is dated by nothing,
/// and an address never minted answers `None`. Read the same off a kernel's
/// committed world as off the pure fold, at the position the kernel
/// committed the record at. (That an entry is written once is the fold's
/// `contains_key` guard, which the fold's contiguity check stands in front
/// of on every build: a stale record re-folded fail-stops there, so no test
/// here re-folds one.)
#[test]
fn each_mint_enters_its_position_for_a_document_a_member_and_a_link_and_for_nothing_else() {
    let (k, acct, doc) = kernel_with_account_and_doc();
    let m3 = k.snapshot().world().m3().clone();
    let (d2, d2_rec) = m3.mint_document(&acct, false).expect("document mint");
    let (v1, v1_rec) = m3.mint_version(&doc, false).expect("version mint");
    let (l1, l1_rec) = m3.mint_link(&doc).expect("link mint");
    let (c1, c1_rec) = m3.mint_content(&doc).expect("content mint");
    let folded = m3
        .apply_m3(Seq(40), &d2_rec)
        .apply_m3(Seq(41), &v1_rec)
        .apply_m3(Seq(42), &l1_rec)
        .apply_m3(Seq(43), &c1_rec);
    assert_eq!(folded.minted_at(&d2), Some(Seq(40)), "a document enters its mint's position");
    assert_eq!(folded.minted_at(&v1), Some(Seq(41)), "a version member enters its mint's position");
    assert_eq!(folded.minted_at(&l1), Some(Seq(42)), "a link enters its mint's position");
    assert_eq!(folded.minted_at(&c1), None, "a content element enters no position");
    assert_eq!(folded.minted_at(&acct), None, "an account enters no position");
    assert_eq!(folded.minted_at(&a(&[1, 0, 1, 0, 71])), None, "an address never minted has none");
    // Genesis's four seeded documents stand at the genesis coordinate.
    for n in 1..=4 {
        assert_eq!(folded.minted_at(&a(&[1, 1, 0, 1, 0, n])), Some(Seq(0)));
    }

    // Off the kernel: the committed position is the one the fold was handed.
    let (_, at) = k
        .transact::<_, MintError>(&[M3State::link_lock_key(&doc)], |stg| {
            let (l, rec) = stg.working().m3().mint_link(&doc)?;
            stg.push(rec.into());
            Ok(l)
        })
        .expect("the link commits");
    assert_eq!(k.snapshot().world().m3().minted_at(&l1), Some(at));
}
