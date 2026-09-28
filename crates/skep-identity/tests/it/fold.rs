//! The fold corpus (AUTH-2.96): step-order vectors (AUTH-2.66), verdict-token
//! vectors (AUTH-2.67–2.76, AUTH-2.127), board-state vectors and the claim walk
//! (AUTH-2.62, AUTH-2.67; I6), the agent space and the handoff latch
//! (AUTH-2.62's RES-80 arm, AUTH-2.71), and shape vectors (AUTH-2.22,
//! AUTH-2.33, AUTH-2.46–2.48). The payload vectors are in `read.rs`, the
//! key-set semantics in `keyset.rs`, the checkpoint byte pins in
//! `checkpoint.rs`.

use crate::common;

use common::*;
use skep_address::{Address, Span, Tumbler};
use skep_identity::{
    single_address, Effect, FoldCtx, IdentityState, Owner, TypeAddrs, Values, Verdict,
    MAX_RECORD_BYTES,
};

// ------------------------------------------------------------- step order

/// Corpus: a draft-homed credential deposit whose `to` is TWO spans —
/// `unpublished`, never `malformed_shape` (AUTH-2.66: publication before
/// the per-kind shape checks; I7 AUTH-2.102).
#[test]
fn publication_precedes_shape() {
    let mut fx = Fixture::new();
    fx.ctx.unpublished.insert(doc1(ACCT_A));
    let genesis_state = IdentityState::genesis();
    let record = enroll_payload(&[(1, false)]);
    let spans = fx.mint(&doc1(ACCT_A), &[record.as_slice()]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: spans,
        to: vec![unit(ACCT_A), unit(ACCT_B)],
        ty: enroll_ty(),
    };
    assert_detail(&fx.classify(&genesis_state, &dep), "unpublished");
}

/// Corpus: a two-span `to` beside a home-minted 128 KiB+1 `from` span —
/// `malformed_shape`, never `too_large` (AUTH-2.66: shape before
/// `record_bytes`).
#[test]
fn shape_precedes_the_payload_read() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let big = vec![b'x'; MAX_RECORD_BYTES + 1];
    let spans = fx.mint(&doc1(ACCT_A), &[&big]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: spans,
        to: vec![unit(ACCT_A), unit(ACCT_B)],
        ty: enroll_ty(),
    };
    assert_detail(&fx.classify(&genesis_state, &dep), "malformed_shape");
}

/// Corpus: an ENROLLMENT homed in a PUBLISHED second document of its account,
/// payload unparseable — `malformed_payload` naming the fault, never
/// `not_doc_one` (AUTH-2.127: the payload precedes the home pin).
#[test]
fn an_enrollment_payload_precedes_the_home_pin() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let dep = fx.enroll_dep(&doc2(ACCT_A), ACCT_A, b"zzz not a record\n");
    assert_detail(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:bad_record",
    );
}

/// AUTH-2.66 item 2 — an unowned home is `malformed_shape` (no ω answer), at
/// every address level: ω is a prefix question, never a level one. No
/// registered document is unowned, so this case lies outside `LinkDeposit`'s
/// precondition, and item 2 decides it anyway.
#[test]
fn unowned_home_is_malformed_shape() {
    let fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    // Under no registered prefix: a node, an account, a document, a position.
    for unowned_home in [
        vec![2, 1],
        vec![2, 1, 0, 9],
        vec![2, 1, 0, 9, 0, 1],
        vec![2, 1, 0, 9, 0, 1, 0, 1, 1],
    ] {
        let dep = fx.claim_dep(&addr(&unowned_home), CLAIMANT);
        assert_detail(&fx.classify(&genesis_state, &dep), "malformed_shape");
    }
}

/// AUTH-2.66 item 1 before item 2 — the KIND is settled first, so a deposit
/// whose `ty` names no credential type is `NotCredential` even where the home
/// has no owner at all. `unowned_home_is_malformed_shape` uses a credential
/// `ty` and `unrecognized_type_slots_are_not_credential` an owned home, so
/// the cell where both hold is decided by nothing: an ω lookup hoisted ahead
/// of `kind_of` refuses an ordinary link the fold has no business judging.
#[test]
fn an_unrecognized_type_in_an_unowned_home_is_not_credential() {
    let fx = Fixture::new();
    let unowned_home = addr(&[2, 1, 0, 9, 0, 1]); // under no registered prefix
    let dep = Dep {
        home: unowned_home,
        from: vec![unit(ACCT_A)],
        to: vec![unit(ACCT_A)],
        ty: vec![unit(&[1, 1, 0, 1, 0, 1, 0, 1, 1])], // a content I-span
    };
    assert_eq!(
        fx.classify(&IdentityState::genesis(), &dep),
        Verdict::NotCredential
    );
}

/// AUTH-2.66 item 2 before item 3 — the home's ACCOUNT is settled before
/// publication, so an unowned home answers `malformed_shape` even on a board
/// where nothing is published. `unowned_home_is_malformed_shape` runs on a
/// fully published board and `unpublished_home_inerts_every_shape` on owned
/// homes, so a publication test hoisted above the ω read flips this cell to
/// `unpublished` and leaves both of them green.
#[test]
fn an_unowned_home_is_malformed_shape_even_on_an_unpublished_board() {
    let mut fx = Fixture::new();
    fx.ctx.all_unpublished = true;
    let unowned_home = addr(&[2, 1, 0, 9, 0, 1]);
    let dep = fx.claim_dep(&unowned_home, CLAIMANT);
    assert_detail(
        &fx.classify(&IdentityState::genesis(), &dep),
        "malformed_shape",
    );
}

/// I7 (AUTH-2.102) — `is_published == false ⇒ Inert(Unpublished)` for every
/// shape: enroll, retire, claim alike (unit arm; the proptest rides in
/// `props.rs`).
#[test]
fn unpublished_home_inerts_every_shape() {
    let mut fx = Fixture::new();
    fx.ctx.all_unpublished = true;
    let genesis_state = IdentityState::genesis();

    let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &enroll_payload(&[(1, true)]));
    assert_detail(&fx.classify(&genesis_state, &dep), "unpublished");

    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[1]));
    assert_detail(&fx.classify(&genesis_state, &dep), "unpublished");

    let dep = fx.claim_dep(&doc1(CLAIMANT), CLAIMANT);
    assert_detail(&fx.classify(&genesis_state, &dep), "unpublished");
}

// ---------------------------------------------------------- verdict tokens

/// Corpus: a genesis enrollment homed in neither A's space nor its genesis
/// registry's — `not_genesis_registry`, never `no_holder` (AUTH-2.71's
/// wrong-delegator face, AUTH-2.72's written order).
#[test]
fn stranger_homed_genesis_is_not_genesis_registry() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let dep = fx.enroll_dep(&doc1(ACCT_B), ACCT_A, &enroll_payload(&[(1, true)]));
    assert_detail(&fx.classify(&genesis_state, &dep), "not_genesis_registry");
}

/// Corpus: a retirement of a member's key homed in the ORG's own doc 1 (the
/// member's genesis registry) — `not_holder_retirement`, never
/// `not_genesis_registry` (AUTH-2.76: the retirement arms never read
/// `delegator`; no ancestor retires a holder's keys).
#[test]
fn registry_homed_retirement_is_not_holder_retirement() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    // Seed the member THROUGH its registry (the org's doc 1) first — the
    // enrollment door that same home legitimately opens (AUTH-2.70).
    let dep = fx.enroll_dep(&doc1(ORG), NESTED, &enroll_payload(&[(1, true), (2, false)]));
    let (st, v) = fx.step(&genesis_state, &dep);
    assert_honored(&v);
    // The retirement through that same home is inert.
    let dep = fx.retire_dep(&doc1(ORG), NESTED, &retire_payload(&[2]));
    assert_detail(&fx.classify(&st, &dep), "not_holder_retirement");
}

/// AUTH-2.71's LATCH — the registry that seeded an account enrolls into it
/// again: `not_genesis_registry`, state unchanged (I5). The I5 property asserts
/// only `Inert(_)`, and every other `not_genesis_registry` vector fires on an
/// EMPTY set, the genesis arm's refusal — never the latch.
#[test]
fn a_registry_homed_enrollment_on_a_seeded_account_is_the_latch() {
    let mut fx = Fixture::new();
    let dep = fx.enroll_dep(&doc1(ORG), NESTED, &enroll_payload(&[(1, true)]));
    let (st, v) = fx.step(&IdentityState::genesis(), &dep);
    assert_honored(&v);
    let dep = fx.enroll_dep(&doc1(ORG), NESTED, &enroll_payload(&[(2, false)]));
    let (next, v) = fx.step(&st, &dep);
    assert_detail(&v, "not_genesis_registry");
    assert_eq!(next, st);
}

/// AUTH-2.69/AUTH-2.74 — `nothing_changed` is the HOLDER arms' token alone: a
/// record homed outside the subject's own space answers its home's refusal
/// even where every entry would change nothing. Every other `nothing_changed`
/// vector is own-space, and the latch and ancestor-retirement vectors each
/// carry an entry that WOULD change the set — so, on a SEEDED account, a
/// "nothing to post" test hoisted above the own-space test keeps them green
/// and flips its kind's cell here.
#[test]
fn a_record_that_changes_nothing_answers_its_homes_refusal_outside_the_holder_arms() {
    let mut fx = Fixture::new();
    let dep = fx.enroll_dep(&doc1(ORG), NESTED, &enroll_payload(&[(1, true)]));
    let (st, v) = fx.step(&IdentityState::genesis(), &dep);
    assert_honored(&v);
    // The registry re-lists the key NESTED already holds: the latch.
    let dep = fx.enroll_dep(&doc1(ORG), NESTED, &enroll_payload(&[(1, true)]));
    assert_detail(&fx.classify(&st, &dep), "not_genesis_registry");
    // The registry retires a key NESTED never held: no ancestor retires.
    let dep = fx.retire_dep(&doc1(ORG), NESTED, &retire_payload(&[5]));
    assert_detail(&fx.classify(&st, &dep), "not_holder_retirement");
}

/// AUTH-2.76's first refusal arm: a retirement homed in the subject's OWN
/// doc 1 on an account that has never held a key — `no_holder`, never
/// `not_holder_retirement`, which is the ancestor-homed refusal and names a
/// relationship this deposit does not have.
#[test]
fn own_space_retirement_on_a_never_keyed_account_is_no_holder() {
    let mut fx = Fixture::new();
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[1]));
    assert_detail(&fx.classify(&IdentityState::genesis(), &dep), "no_holder");
}

/// Corpus: a claim by a KEYLESS TOP-LEVEL account on an already-claimed
/// board — `already_claimed`, never `claimant_keyless` (AUTH-2.68's pinned
/// coexistence cell).
#[test]
fn already_claimed_beats_claimant_keyless() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let st = seed_own(&mut fx, &genesis_state, CLAIMANT, &[(9, true)]);
    let st = claim_as(&mut fx, &st, CLAIMANT);
    let dep = fx.claim_dep(&doc1(ACCT_B), ACCT_B); // ACCT_B is keyless
    assert_detail(&fx.classify(&st, &dep), "already_claimed");
}

/// Corpus: a claim by a NESTED account on an already-claimed board —
/// `claimant_not_top_level`, never `already_claimed` (AUTH-2.68: the
/// delegator read comes first despite costing more).
#[test]
fn claimant_not_top_level_beats_already_claimed() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let st = seed_own(&mut fx, &genesis_state, CLAIMANT, &[(9, true)]);
    let st = claim_as(&mut fx, &st, CLAIMANT);
    let dep = fx.claim_dep(&doc1(NESTED), NESTED);
    assert_detail(&fx.classify(&st, &dep), "claimant_not_top_level");
}

/// AUTH-2.62's `None ⇒ None` and AUTH-2.72's written order: an own-space
/// genesis on an account with no delegator — where `registry == None` and
/// `H == A` BOTH hold — is `not_genesis_registry`, never `no_holder`. The
/// `registry.is_none()` test that precedes the own-space refusal is the only
/// thing that decides this cell.
#[test]
fn own_space_genesis_without_a_delegator_is_not_genesis_registry() {
    let mut fx = Fixture::new();
    fx.register_orphan();
    let dep = fx.enroll_dep(&doc1(ORPHAN), ORPHAN, &enroll_payload(&[(1, true)]));
    assert_detail(
        &fx.classify(&IdentityState::genesis(), &dep),
        "not_genesis_registry",
    );
}

/// AUTH-2.67 condition 3's `None` half: a claim by an account with no
/// delegator is `claimant_not_top_level` — `Some(Account(_))` and `None`
/// alike refuse, and a keyless one answers this before `claimant_keyless`.
#[test]
fn claim_without_a_delegator_is_claimant_not_top_level() {
    let mut fx = Fixture::new();
    fx.register_orphan();
    let dep = fx.claim_dep(&doc1(ORPHAN), ORPHAN);
    assert_detail(
        &fx.classify(&IdentityState::genesis(), &dep),
        "claimant_not_top_level",
    );
}

/// Corpus: a holder enrollment (`H == A`, set non-empty) homed in a
/// PUBLISHED second document of A — `not_doc_one`, never honored: the home
/// pin (AUTH-2.127, RES-17).
#[test]
fn holder_enrollment_outside_doc_1_is_not_doc_one() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let st = seed_own(&mut fx, &genesis_state, ACCT_A, &[(1, true)]);
    let dep = fx.enroll_dep(&doc2(ACCT_A), ACCT_A, &enroll_payload(&[(2, false)]));
    assert_detail(&fx.classify(&st, &dep), "not_doc_one");
}

/// Corpus: a genesis enrollment homed in the delegator's PUBLISHED second
/// document — `not_doc_one`, never `not_genesis_registry` (the pin precedes
/// the account comparisons, AUTH-2.127).
#[test]
fn genesis_in_delegators_second_doc_is_not_doc_one() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let dep = fx.enroll_dep(&doc2(ORG), NESTED, &enroll_payload(&[(3, true)]));
    assert_detail(&fx.classify(&genesis_state, &dep), "not_doc_one");
}

/// Corpus: a claim by a NESTED account homed in its own PUBLISHED second
/// document — `not_doc_one`, never `claimant_not_top_level` (AUTH-2.67
/// condition 2 before condition 3).
#[test]
fn nested_claim_in_second_doc_is_not_doc_one() {
    let fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let dep = fx.claim_dep(&doc2(NESTED), NESTED);
    assert_detail(&fx.classify(&genesis_state, &dep), "not_doc_one");
}

/// AUTH-2.127 on the RETIREMENT path — a holder retirement homed in a
/// PUBLISHED second document of its own account is `not_doc_one`, and the key
/// stays enrolled. `retire_path` makes its own pin call, and every other
/// holder retirement vector is homed in doc 1, so with that call deleted this
/// record retires a real key and no other holder vector notices.
#[test]
fn a_holder_retirement_outside_doc_1_is_not_doc_one_and_retires_nothing() {
    let mut fx = Fixture::new();
    let st = seeded(&mut fx); // fp(1) anchor, fp(2) non-anchor
    let dep = fx.retire_dep(&doc2(ACCT_A), ACCT_A, &retire_payload(&[2]));
    let (next, v) = fx.step(&st, &dep);
    assert_detail(&v, "not_doc_one");
    assert_eq!(next, st);
    assert!(
        next.key_set(&addr(ACCT_A)).contains(&fp(2)),
        "the key is still enrolled"
    );
}

/// AUTH-2.66/AUTH-2.127 for RETIREMENTS — the payload precedes the home pin:
/// an unparseable retirement in a published second document is
/// `malformed_payload:bad_record`, never `not_doc_one`.
/// `an_enrollment_payload_precedes_the_home_pin` states the same order for
/// enrollments only, so a retirement pin hoisted above its parse keeps that
/// vector green.
#[test]
fn a_retirement_payload_precedes_the_home_pin() {
    let mut fx = Fixture::new();
    let dep = fx.retire_dep(&doc2(ACCT_A), ACCT_A, b"zzz not a record\n");
    assert_detail(
        &fx.classify(&IdentityState::genesis(), &dep),
        "malformed_payload:bad_record",
    );
}

/// AUTH-2.127 for RETIREMENTS — the pin precedes the refusal arms: a
/// retirement in the delegator's published second document is `not_doc_one`,
/// never `not_holder_retirement`. A pin tested only where the arms would honor
/// keeps the holder vector above green and flips this one.
#[test]
fn a_registry_homed_retirement_outside_doc_1_is_not_doc_one() {
    let mut fx = Fixture::new();
    let dep = fx.retire_dep(&doc2(ORG), NESTED, &retire_payload(&[1]));
    assert_detail(&fx.classify(&IdentityState::genesis(), &dep), "not_doc_one");
}

/// AUTH-2.67 condition 1 before condition 2 — a claim whose `from` is not its
/// home's account AND which is homed outside doc 1 is `malformed_shape`, never
/// `not_doc_one`: the one adjacent pair of the claim arm's written order no
/// other vector decides.
#[test]
fn a_claims_shape_precedes_the_home_pin() {
    let fx = Fixture::new();
    let dep = Dep {
        home: doc2(CLAIMANT),
        from: vec![unit(ACCT_A)],
        to: vec![],
        ty: vec![unit(T_CLAIM)],
    };
    assert_detail(
        &fx.classify(&IdentityState::genesis(), &dep),
        "malformed_shape",
    );
}

/// AUTH-2.127 — the pin is EQUALITY with `A·0·1`: an enrollment homed in doc
/// 1's published VERSION MEMBER (`A·0·1·1`, owned by A) is `not_doc_one`. The
/// corpus's other wrong homes are second documents, which no prefix test
/// confuses with doc 1, so a pin spelled "doc 1 or under it" passes them all
/// and honors this genesis.
#[test]
fn a_version_member_of_doc_1_is_not_doc_one() {
    let mut fx = Fixture::new();
    let member = first_version_of(&doc1(ACCT_A));
    let dep = fx.enroll_dep(&member, ACCT_A, &enroll_payload(&[(1, true)]));
    assert_detail(&fx.classify(&IdentityState::genesis(), &dep), "not_doc_one");
}

/// A conforming board EXCEPT that ω answers ONE fixed prefix for every
/// address — the ctx `step`'s totality clause calls broken when that prefix
/// is element-level (AUTH-2.126).
struct FixedOwnerCtx {
    board: TestCtx,
    prefix: Address,
}

impl Values for FixedOwnerCtx {
    fn value_at(&self, at: &Tumbler) -> Option<&[u8]> {
        self.board.value_at(at)
    }
}

impl FoldCtx for FixedOwnerCtx {
    fn owner_of(&self, _: &Address) -> Option<Owner> {
        Some(Owner {
            prefix: self.prefix.clone(),
            is_bootstrap: false,
        })
    }

    fn is_account(&self, a: &Address) -> bool {
        self.board.is_account(a)
    }

    fn is_published(&self, doc: &Address) -> bool {
        self.board.is_published(doc)
    }
}

/// A claim under a ctx whose ω answers an ELEMENT-level prefix — a content
/// position — for every address, the claim's `from` naming that same
/// position: the arm's shape check passes, and the home pin hands `doc_1_of`
/// an operand M1's TA5a gate refuses.
fn classify_under_an_element_level_owner() -> Verdict {
    let fx = Fixture::new();
    let position = [1, 1, 0, 5, 0, 1, 0, 1, 1];
    let ctx = FixedOwnerCtx {
        board: fx.ctx.clone(),
        prefix: addr(&position),
    };
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![unit(&position)],
        to: vec![],
        ty: vec![unit(T_CLAIM)],
    };
    IdentityState::genesis().classify(&fx.types, &ctx, &dep.as_link_deposit())
}

/// AUTH-2.126 — an element-level ω prefix is a broken ctx precondition, and a
/// debug build names it at the home pin rather than folding under it. `step`
/// names this obligation beside the zero-byte one; deleting `doc_1_of`'s debug
/// assertion turns this red.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "element-level prefix")]
fn an_element_level_owner_prefix_is_refused_at_the_home_pin() {
    let _ = classify_under_an_element_level_owner();
}

/// AUTH-2.57 — the release-build half: the same broken ctx still gets a
/// VERDICT, never a panic. `doc_1_of` answers its operand back, which is
/// document-of nothing, so the pin refuses `not_doc_one`. `doc_1_of` spelled
/// as `checked_inc(..).expect(..)` — how M3's `first_document_address` writes
/// the same arithmetic — panics the release fold here. Runs under
/// `cargo test --release` only; a debug build stops one step earlier, which
/// [`an_element_level_owner_prefix_is_refused_at_the_home_pin`] pins.
#[cfg(not(debug_assertions))]
#[test]
fn an_element_level_owner_prefix_answers_not_doc_one_in_release() {
    assert_detail(&classify_under_an_element_level_owner(), "not_doc_one");
}

// ------------------------------------------------------------ board state

/// Corpus: bootstrap-delegated A — the SAME genesis record homed in A's OWN
/// doc 1, before / after the claim: `Honored(Genesis)` / `no_holder`
/// (AUTH-2.62's claimant flip; AUTH-2.72's written order keeps the
/// pre-claim own-space genesis honored).
#[test]
fn own_space_genesis_flips_to_no_holder_at_the_claim() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &enroll_payload(&[(1, true)]));
    assert_honored(&fx.classify(&genesis_state, &dep));

    let st = seed_own(&mut fx, &genesis_state, CLAIMANT, &[(9, true)]);
    let st = claim_as(&mut fx, &st, CLAIMANT);
    assert_detail(&fx.classify(&st, &dep), "no_holder");
}

/// Corpus: the same genesis homed in the CLAIMANT's doc 1, before / after
/// the claim: `not_genesis_registry` / `Honored(Genesis)` (AUTH-2.62: the
/// bootstrap tier's registry is the claimant's space once claimed).
#[test]
fn claimant_homed_genesis_flips_to_honored_at_the_claim() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let pre = seed_own(&mut fx, &genesis_state, CLAIMANT, &[(9, true)]);
    let dep = fx.enroll_dep(&doc1(CLAIMANT), ACCT_A, &enroll_payload(&[(1, true)]));
    assert_detail(&fx.classify(&pre, &dep), "not_genesis_registry");

    let post = claim_as(&mut fx, &pre, CLAIMANT);
    match assert_honored(&fx.classify(&post, &dep)) {
        Effect::Genesis { account, .. } => assert_eq!(*account, addr(ACCT_A)),
        _ => panic!("expected a genesis effect"),
    }
}

/// The claim walk end to end: keyless refusal, honored claim, first-wins
/// (AUTH-2.67; I6 AUTH-2.101), and the from≠H shape refusal (AUTH-2.48).
#[test]
fn board_admits_one_claim_and_only_from_a_keyed_account() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();

    // Keyless claimant, pre-claim: condition 5.
    let dep = fx.claim_dep(&doc1(CLAIMANT), CLAIMANT);
    assert_detail(&fx.classify(&genesis_state, &dep), "claimant_keyless");

    // Seed both top-level accounts BEFORE the claim (post-claim, an
    // own-space genesis is `no_holder` — the AUTH-2.62 flip).
    let st = seed_own(&mut fx, &genesis_state, CLAIMANT, &[(9, true)]);
    let st = seed_own(&mut fx, &st, ACCT_B, &[(8, true)]);

    // Claimed: honored; claimant posts.
    let (st, v) = fx.step(&st, &dep);
    match assert_honored(&v) {
        Effect::Claim { account } => assert_eq!(*account, addr(CLAIMANT)),
        _ => panic!("expected a claim effect"),
    }
    assert_eq!(st.claimant(), Some(&addr(CLAIMANT)));

    // First-wins: a second claim, even by another seeded top-level account.
    let second_claim = fx.claim_dep(&doc1(ACCT_B), ACCT_B);
    let (st, v) = fx.step(&st, &second_claim);
    assert_detail(&v, "already_claimed");
    assert_eq!(st.claimant(), Some(&addr(CLAIMANT)));

    // A claim whose `from` is not the home's account: shape (condition 1).
    let dep = Dep {
        home: doc1(CLAIMANT),
        from: vec![unit(ACCT_A)],
        to: vec![],
        ty: vec![unit(T_CLAIM)],
    };
    assert_detail(&fx.classify(&st, &dep), "malformed_shape");
}

// -------------------------------------------- A3 and the handoff latch

// The addresses A3 (AUTH-2.62's RES-80 arm) and the handoff latch (AUTH-2.71)
// reason over, rooted at ACCT_A — a BOOTSTRAP-TIER account `B` (its parent is
// the node, owned by the bootstrap principal). `B_FIRST_CHILD = inc(B, 1)` is
// its computed first sub-account (the AGENT SPACE); `B_SUBDIVISION` is a LATER
// child (a real subdivision); `B_SUB_DEEP` is a child of that subdivision;
// `C_FIRST_CHILD` is the first child of the (non-bootstrap-tier) subdivision.
const B_FIRST_CHILD: &[u32] = &[1, 1, 0, 5, 1]; // inc(ACCT_A, 1) — the agent space
const B_SUBDIVISION: &[u32] = &[1, 1, 0, 5, 2]; // a later child of ACCT_A
const B_SUB_DEEP: &[u32] = &[1, 1, 0, 5, 2, 5]; // a child of B_SUBDIVISION
const C_FIRST_CHILD: &[u32] = &[1, 1, 0, 5, 2, 1]; // inc(B_SUBDIVISION, 1)

/// Seat the A3/latch addresses as accounts. A fold ctx holds no M3, so the test
/// seats ω and account-hood itself; each is owned by its own principal, so
/// `delegator` classifies it `Account(parent)`.
fn seat_accounts(fx: &mut Fixture, accounts: &[&[u32]]) {
    for acct in accounts {
        fx.ctx.owners.push((addr(acct), false));
        fx.ctx.accounts.insert(addr(acct));
    }
}

/// AUTH-2.96 row 51 (A3) — the agent space `inc(B, 1)` of a bootstrap-tier `B`
/// takes NO genesis: `not_genesis_registry` from EVERY hand (homed in `B`'s own
/// doc 1, the claimant's, and the agent space's own), before AND after `B`'s
/// genesis and the claim (AUTH-2.62's RES-80 arm ⇒ `None`, AUTH-2.63).
#[test]
fn a3_the_agent_space_takes_no_genesis_from_any_hand() {
    let mut fx = Fixture::new();
    seat_accounts(&mut fx, &[B_FIRST_CHILD]);
    let st = IdentityState::genesis();
    for home in [ACCT_A, B_FIRST_CHILD, CLAIMANT] {
        let dep = fx.enroll_dep(&doc1(home), B_FIRST_CHILD, &enroll_payload(&[(1, true)]));
        assert_detail(&fx.classify(&st, &dep), "not_genesis_registry");
    }
    // After B is keyed and the board is claimed, still.
    let st = seed_own(&mut fx, &st, ACCT_A, &[(1, true)]);
    let st = seed_own(&mut fx, &st, CLAIMANT, &[(9, true)]);
    let st = claim_as(&mut fx, &st, CLAIMANT);
    let dep = fx.enroll_dep(&doc1(ACCT_A), B_FIRST_CHILD, &enroll_payload(&[(2, false)]));
    assert_detail(&fx.classify(&st, &dep), "not_genesis_registry");
}

/// AUTH-2.96 row 52 (A3) — the arm is BOUNDED to the bootstrap tier's first
/// child: a genesis for `inc(B, 2)` (a later child of bootstrap-tier `B`) and
/// for `inc(C, 1)` (the first child of a NON-bootstrap-tier `C`), each with a
/// fresh key, is `Honored(Genesis)`.
#[test]
fn a3_a_later_child_and_a_non_bootstrap_first_child_are_honored() {
    let mut fx = Fixture::new();
    seat_accounts(&mut fx, &[B_SUBDIVISION, C_FIRST_CHILD]);
    let st = IdentityState::genesis();

    // inc(B, 2) — a later child of the bootstrap-tier B, homed in B's doc 1.
    let dep = fx.enroll_dep(&doc1(ACCT_A), B_SUBDIVISION, &enroll_payload(&[(1, false)]));
    match assert_honored(&fx.classify(&st, &dep)) {
        Effect::Genesis { account, .. } => assert_eq!(*account, addr(B_SUBDIVISION)),
        other => panic!("expected a genesis effect, got {other:?}"),
    }

    // inc(C, 1) where C = B_SUBDIVISION is NOT bootstrap-tier, homed in C's doc 1.
    let dep = fx.enroll_dep(&doc1(B_SUBDIVISION), C_FIRST_CHILD, &enroll_payload(&[(2, false)]));
    match assert_honored(&fx.classify(&st, &dep)) {
        Effect::Genesis { account, .. } => assert_eq!(*account, addr(C_FIRST_CHILD)),
        other => panic!("expected a genesis effect, got {other:?}"),
    }
}

/// AUTH-2.96 row 53 (the latch, AUTH-2.71) — a genesis for `inc(B, 2)` naming a
/// key already ENROLLED in `B`'s set is `not_genesis_registry`; a genesis for
/// the same key one level down at `inc(inc(B, 2), 5)` with `S(inc(B, 2))` EMPTY
/// is too — the comparand is the set that OPENS THE ACCOUNT ABOVE, walked past
/// the empty subdivision to `B`'s set.
#[test]
fn the_handoff_latch_fires_on_a_key_from_the_set_above() {
    let mut fx = Fixture::new();
    seat_accounts(&mut fx, &[B_SUBDIVISION, B_SUB_DEEP]);
    // B holds fp(1); the agent's genesis names B's own key — a handoff to a
    // party that could already open B.
    let st = seed_own(&mut fx, &IdentityState::genesis(), ACCT_A, &[(1, true)]);

    let dep = fx.enroll_dep(&doc1(ACCT_A), B_SUBDIVISION, &enroll_payload(&[(1, true)]));
    assert_detail(&fx.classify(&st, &dep), "not_genesis_registry");

    // One level down, its own set empty: the walk climbs the empty subdivision
    // to B's set (the comparand, AUTH-2.71's row 2009).
    let dep = fx.enroll_dep(&doc1(B_SUBDIVISION), B_SUB_DEEP, &enroll_payload(&[(1, true)]));
    assert_detail(&fx.classify(&st, &dep), "not_genesis_registry");
}

/// AUTH-2.96 row 53 (the latch) — a FRESH-key genesis at `inc(B, 2)` is
/// `Honored(Genesis)`: the comparand is `B`'s set and the key stands in no set
/// above.
#[test]
fn the_handoff_latch_does_not_fire_on_a_fresh_key() {
    let mut fx = Fixture::new();
    seat_accounts(&mut fx, &[B_SUBDIVISION]);
    let st = seed_own(&mut fx, &IdentityState::genesis(), ACCT_A, &[(1, true)]);
    let dep = fx.enroll_dep(&doc1(ACCT_A), B_SUBDIVISION, &enroll_payload(&[(2, false)]));
    match assert_honored(&fx.classify(&st, &dep)) {
        Effect::Genesis { account, .. } => assert_eq!(*account, addr(B_SUBDIVISION)),
        other => panic!("expected a genesis effect, got {other:?}"),
    }
}

/// AUTH-2.96 row 55 (the latch's TERMINUS, RES-137) — a genesis beneath a chain
/// in which NO account above holds a non-empty set is `Honored(Genesis)`: the
/// comparand is EMPTY and the arm does not fire (pinned FOR TOTALITY).
#[test]
fn the_handoff_latch_does_not_fire_beneath_never_keyed_ancestors() {
    let mut fx = Fixture::new();
    seat_accounts(&mut fx, &[B_SUBDIVISION, B_SUB_DEEP]);
    // Nothing above B_SUB_DEEP is keyed — not B_SUBDIVISION, not ACCT_A.
    let st = IdentityState::genesis();
    let dep = fx.enroll_dep(&doc1(B_SUBDIVISION), B_SUB_DEEP, &enroll_payload(&[(1, true)]));
    match assert_honored(&fx.classify(&st, &dep)) {
        Effect::Genesis { account, .. } => assert_eq!(*account, addr(B_SUB_DEEP)),
        other => panic!("expected a genesis effect, got {other:?}"),
    }
}

/// AUTH-2.96 row 54 (the latch, RES-138) — a genesis for `inc(B, 2)` naming a
/// fingerprint RETIRED in `B`'s set and enrolled nowhere in it is
/// `Honored(Genesis)`: the comparand is the ENROLLED half, a retired
/// fingerprint opening nothing (I4, AUTH-2.98).
#[test]
fn the_handoff_latch_reads_the_enrolled_half_only() {
    let mut fx = Fixture::new();
    seat_accounts(&mut fx, &[B_SUBDIVISION]);
    // B: fp(1) enrolled, fp(2) retired.
    let st = seed_own(&mut fx, &IdentityState::genesis(), ACCT_A, &[(1, true), (2, false)]);
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[2]));
    let (st, v) = fx.step(&st, &dep);
    assert_honored(&v);
    // The genesis names fp(2), which stands RETIRED (not enrolled) in B's set.
    let dep = fx.enroll_dep(&doc1(ACCT_A), B_SUBDIVISION, &enroll_payload(&[(2, false)]));
    match assert_honored(&fx.classify(&st, &dep)) {
        Effect::Genesis { account, .. } => assert_eq!(*account, addr(B_SUBDIVISION)),
        other => panic!("expected a genesis effect, got {other:?}"),
    }
}

// ------------------------------------------------------------------ shape

/// Corpus: a `to` slot of two spans; a `to` whose single span is `Equal` to
/// no `subtree_of(its start)` — `malformed_shape` on all three kinds
/// (AUTH-2.46, AUTH-2.48, AUTH-2.26).
#[test]
fn to_slot_shape_is_malformed_on_all_kinds() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();

    // Two spans (enroll; retire; a claim's `to` must be EMPTY, so any span
    // there is the same refusal).
    let spans = fx.mint(&doc1(ACCT_A), &[&enroll_payload(&[(1, true)])]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: spans.clone(),
        to: vec![unit(ACCT_A), unit(ACCT_B)],
        ty: enroll_ty(),
    };
    assert_detail(&fx.classify(&genesis_state, &dep), "malformed_shape");
    let dep = Dep {
        home: doc1(ACCT_A),
        from: spans.clone(),
        to: vec![unit(ACCT_A), unit(ACCT_B)],
        ty: vec![unit(T_RETIRE)],
    };
    assert_detail(&fx.classify(&genesis_state, &dep), "malformed_shape");
    let dep = Dep {
        home: doc1(CLAIMANT),
        from: vec![unit(CLAIMANT)],
        to: vec![unit(ACCT_A)],
        ty: vec![unit(T_CLAIM)],
    };
    assert_detail(&fx.classify(&genesis_state, &dep), "malformed_shape");

    // A single span that is no subtree: it covers TWO account subtrees.
    let two_accounts = Span::new(tum(ACCT_A), width_at_last(ACCT_A.len(), 2)).expect("T12");
    let dep = Dep {
        home: doc1(ACCT_A),
        from: spans,
        to: vec![two_accounts.clone()],
        ty: enroll_ty(),
    };
    assert_detail(&fx.classify(&genesis_state, &dep), "malformed_shape");

    // The claim's FROM under the same test (AUTH-2.26 governs both).
    let dep = Dep {
        home: doc1(CLAIMANT),
        from: vec![Span::new(tum(CLAIMANT), width_at_last(CLAIMANT.len(), 2)).expect("T12")],
        to: vec![],
        ty: vec![unit(T_CLAIM)],
    };
    assert_detail(&fx.classify(&genesis_state, &dep), "malformed_shape");
}

/// AUTH-2.26 — the whole rule, directly: `Some(A)` for exactly one span
/// EQUAL to `subtree_of(its start)`, `None` for every other slot — empty,
/// two spans, a span that is no subtree, and a span whose start does not
/// VALIDATE. That last answers `None`, never a panic (AUTH-2.57).
#[test]
fn single_address_admits_exactly_one_address_form_span() {
    assert_eq!(single_address(&[]), None);
    assert_eq!(single_address(&[unit(ACCT_A)]), Some(addr(ACCT_A)));
    assert_eq!(single_address(&[unit(ACCT_A), unit(ACCT_B)]), None);
    // One span covering TWO account subtrees: `Equal` to no subtree.
    let two_accounts = Span::new(tum(ACCT_A), width_at_last(ACCT_A.len(), 2)).expect("T12");
    assert_eq!(single_address(&[two_accounts]), None);
    // Adjacent zeros: T4-invalid as an address, legal as a carrier tumbler.
    let invalid = Span::new(tum(&[1, 1, 0, 5, 0, 1, 0, 0, 1]), width_at_last(9, 1)).expect("T12");
    assert_eq!(single_address(&[invalid]), None);
}

/// AUTH-2.22/AUTH-2.26 — arity is decided in at most TWO steps of the slot's
/// walk, which is what lets a caller hand in the store's own endset instead of
/// a copy: a slot whose third step would panic is refused without reaching
/// it. The two spans are each a type's own unit subtree, so a rule that read
/// only the first span would answer `Some` here rather than `None`.
#[test]
fn arity_is_decided_in_two_steps_of_the_slot() {
    let fx = Fixture::new();
    let span = unit(T_ENROLL);
    assert_eq!(fx.types.kind_of(panics_past_two(&span)), None);
    assert_eq!(single_address(panics_past_two(&span)), None);
}

/// AUTH-2.57 totality on the `to` slot: a `to` span whose start does not
/// VALIDATE is `malformed_shape` — the refusal
/// `invalid_start_is_foreign_content_not_a_panic` pins on the `from` side.
#[test]
fn invalid_to_start_is_malformed_shape_not_a_panic() {
    let mut fx = Fixture::new();
    let from = fx.mint(&doc1(ACCT_A), &[&enroll_payload(&[(1, true)])]);
    let invalid = Span::new(tum(&[1, 1, 0, 5, 0, 1, 0, 0, 1]), width_at_last(9, 1)).expect("T12");
    let dep = Dep {
        home: doc1(ACCT_A),
        from,
        to: vec![invalid],
        ty: enroll_ty(),
    };
    assert_detail(
        &fx.classify(&IdentityState::genesis(), &dep),
        "malformed_shape",
    );
}

/// AUTH-2.46/AUTH-2.26 — an EMPTY `to` on an enroll deposit is
/// `malformed_shape`: the same slot value the CLAIM kind requires
/// (AUTH-2.48) is a refusal here, so the arity test is per kind.
#[test]
fn empty_to_on_an_enrollment_is_malformed_shape() {
    let mut fx = Fixture::new();
    let from = fx.mint(&doc1(ACCT_A), &[&enroll_payload(&[(1, true)])]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from,
        to: vec![],
        ty: enroll_ty(),
    };
    assert_detail(
        &fx.classify(&IdentityState::genesis(), &dep),
        "malformed_shape",
    );
}

/// AUTH-2.33, `Inert::MalformedShape`'s third count — the address an
/// enroll/retire `to` names must be an ACCOUNT as of the deposit's commit,
/// else `malformed_shape` (the fold has no `not_an_account`). The address here
/// is a later child of ACCT_A that no principal is registered at yet — a name
/// M7 deposits verbatim — and once delegated, the SAME deposit folds a
/// genesis: the verdict is the ctx's point's, which is why every `FoldCtx`
/// fact is answered as of the deposit's commit. Every other vector names a
/// subject that is already an account, so this is the one that watches the
/// arm entry's `is_account` guard: without it this deposit seeds a key set at
/// an address that is no account.
#[test]
fn a_to_that_names_no_account_as_of_the_commit_is_malformed_shape() {
    let mut fx = Fixture::new();
    let dep = fx.enroll_dep(&doc1(ACCT_A), B_SUBDIVISION, &enroll_payload(&[(1, true)]));
    assert_detail(&fx.classify(&IdentityState::genesis(), &dep), "malformed_shape");
    // The same deposit, under a ctx at which the child has since been
    // delegated beneath ACCT_A.
    seat_accounts(&mut fx, &[B_SUBDIVISION]);
    match assert_honored(&fx.classify(&IdentityState::genesis(), &dep)) {
        Effect::Genesis { account, .. } => assert_eq!(*account, addr(B_SUBDIVISION)),
        other => panic!("expected a genesis effect, got {other:?}"),
    }
}

/// Corpus: a `ty` slot of NO spans · one whose single span is a CONTENT
/// I-span of the home · a `ty` of TWO spans, one of which IS
/// `subtree_of(T_enroll)` · a `ty` of ONE span CONTAINING
/// `subtree_of(T_enroll)` · one CONTAINED BY it — `NotCredential` on each
/// (AUTH-2.22's exactly-one-span-`Equal` rule: every other arity, and every
/// `SpanRel` other than `Equal`, `Containment` in BOTH directions).
#[test]
fn unrecognized_type_slots_are_not_credential() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let spans = fx.mint(&doc1(ACCT_A), &[&enroll_payload(&[(1, true)])]);

    for ty in [
        vec![],                                      // no span at all: an arity too
        vec![unit(&[1, 1, 0, 5, 0, 1, 0, 1, 1])],    // a content I-span of the home
        vec![unit(T_ENROLL), unit(T_RETIRE)],        // two spans, one IS the type's
        vec![unit(&[1, 1, 0, 1, 0, 1, 0, 2])],       // CONTAINS subtree_of(T_enroll)
        vec![unit(&[1, 1, 0, 1, 0, 1, 0, 2, 1, 1])], // CONTAINED BY it
    ] {
        let dep = Dep {
            home: doc1(ACCT_A),
            from: spans.clone(),
            to: vec![unit(ACCT_A)],
            ty,
        };
        let (next, v) = fx.step(&genesis_state, &dep);
        assert_eq!(v, Verdict::NotCredential, "expected NotCredential");
        assert_eq!(next, genesis_state, "NotCredential must leave state unchanged");
    }
}

/// AUTH-2.20/AUTH-2.21 — the three type addresses are pairwise distinct. A
/// repeat would make the later kind unreachable: `kind_of` answers the
/// FIRST span a `ty` is `Equal` to, so it would never answer that kind for
/// any `ty`. The refusal is a panic because a duplicate is the engine's
/// mis-wiring and not an input a record can carry.
#[test]
#[should_panic(expected = "pairwise distinct")]
fn type_addrs_refuses_a_repeated_type_address() {
    let _ = TypeAddrs::new(addr(T_ENROLL), addr(T_RETIRE), addr(T_RETIRE));
}

/// AUTH-2.20/AUTH-2.21 — PAIRWISE is three pairs, each repeat shadowing a
/// different kind, and every one is refused at construction by the
/// distinctness assertion. `type_addrs_refuses_a_repeated_type_address` pins
/// the `retire == claim` pair alone, so with the `enroll != retire` or the
/// `enroll != claim` conjunct dropped that vector still passes and this one
/// fails, naming the triple it admitted.
#[test]
fn type_addrs_refuses_a_repeat_in_every_pair() {
    for (enroll, retire, claim) in [
        (T_ENROLL, T_ENROLL, T_CLAIM),
        (T_ENROLL, T_RETIRE, T_ENROLL),
        (T_ENROLL, T_RETIRE, T_RETIRE),
    ] {
        let (e, r, c) = (addr(enroll), addr(retire), addr(claim));
        let refusal = std::panic::catch_unwind(move || TypeAddrs::new(e, r, c))
            .err()
            .unwrap_or_else(|| panic!("admitted {enroll:?} · {retire:?} · {claim:?}"));
        let message = refusal
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| refusal.downcast_ref::<String>().map(String::as_str));
        assert!(
            message.is_some_and(|m| m.contains("pairwise distinct")),
            "{enroll:?} · {retire:?} · {claim:?} was refused by {message:?}, \
             not the distinctness assertion"
        );
    }
}
