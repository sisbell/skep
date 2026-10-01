//! §A frontier mints — the next address on each documented chain, the
//! caller's half of a mint, the allocator's laws, and each mint's structural
//! refusals — and §C membership, which is exact chain membership.

use crate::common::*;

use skep_address::{content_subspace, link_subspace, Address, Level};
use skep_kernel::Kernel;
use skep_namespace::{
    first_version_address, CreateDocumentError, HasM3, M3Rec, M3State, MintError,
};

#[test]
fn pure_mints_answer_the_next_address_on_each_documented_chain() {
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
    assert_eq!(
        rec,
        M3Rec::Allocate {
            addr: c1.clone(),
            published: false,
        }
    );
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
    // version chain; no collision (the ASN-0103 fix).
    let (d2, _) = m3.mint_document(&acct, false).expect("document mint");
    assert_eq!(d2, a(&[1, 0, 1, 0, 2]));
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
        a(&[1, 0, 1, 0, 2])
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
    let unregistered_doc = a(&[1, 0, 1, 0, 9]); // document-level, never registered
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
    // A NODE source: version_ns([1])'s c₁ is [1,1], a NODE address, which
    // `is_allocated` answers from the node registry — so an ungated version
    // mint would return an address that reads unallocated.
    assert_eq!(
        m3.mint_version(&node, false).unwrap_err(),
        MintError::SourceNotRegistered
    );
    // An ELEMENT home: b_C(e) = e ++ [0, s_C] carries four separators and is
    // outside T4 — `next_in`'s stated precondition. Ungated, the anchor lift
    // `expect`s and the mint PANICS instead of refusing.
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
    // `delegate_mints_the_account_and_registers_its_principal_atomically`).
    assert!(m3.next_account_prefix(&element).is_none());
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
    assert_eq!(create(m3, &acct), Ok(a(&[1, 0, 1, 0, 2])));
    assert_eq!(
        create(m3, &doc),
        Err(CreateDocumentError::Mint(MintError::NotAnAccount))
    );
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

    // Exact range membership (§2): the ordinal past the frontier is out.
    assert!(!m3.is_allocated(&a(&[1, 0, 1, 0, 2])));
    assert!(!m3.is_allocated(&a(&[1, 0, 2])));
    assert_eq!(m3.entity_level(&a(&[1, 0, 1, 0, 2])), None);
    assert!(!m3.is_registered_document(&a(&[1, 0, 1, 0, 2])));
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
        a(&[1, 0, 1, 0, 1, 0, 1, 1, 1]), // one component deeper than c1
        a(&[1, 0, 1, 0, 2, 0, 1, 1]),    // the same ordinal under a sibling doc
        a(&[1, 0, 1, 0, 1, 1]),          // the version chain's first slot
    ] {
        assert!(
            !m3.is_allocated(&near),
            "{near:?} is not allocated but reads as a member"
        );
    }
    assert!(m3.is_allocated(&c1)); // …while the real member still is
}
