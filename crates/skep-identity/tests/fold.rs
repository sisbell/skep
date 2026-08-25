//! The fold corpus (AUTH-2.96): payload vectors over `record_bytes`
//! (AUTH-2.38–2.45), step-order vectors (AUTH-2.66), verdict-token vectors
//! (AUTH-2.67–2.76, AUTH-2.127), board-state vectors (AUTH-2.62), shape
//! vectors (AUTH-2.22, AUTH-2.46–2.48), and the key-set semantics
//! (AUTH-1.30–1.31, I9's conformance arm).

mod common;

use common::*;
use skep_address::Span;
use skep_identity::{Effect, IdentityState, Verdict, MAX_RECORD_BYTES};

fn enroll_ty() -> Vec<Span> {
    vec![unit(T_ENROLL)]
}

// ---------------------------------------------------------------- payload

/// Corpus: payload text `copy`ed from another document, the link naming that
/// run — beside the SAME text `insert`ed into the home and named (AUTH-2.44
/// home anchoring; a home-minted run is native and folds, AUTH-2.96's
/// copy-from-home row).
#[test]
fn foreign_content_vs_native_fold() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let payload = enroll_payload(&[(1, true)]);

    // Native: the record's bytes minted in the home itself.
    let native = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &payload);
    assert_honored(&fx.classify(&genesis, &native));

    // A second home-minted run carrying the same bytes (the shape a `copy`
    // from the HOME itself leaves) is native by the same test.
    let copied = fx.mint(&doc1(ACCT_A), &[&payload]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: copied,
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_honored(&fx.classify(&genesis, &dep));

    // Foreign: the same text minted under ANOTHER document, the link naming
    // that run — inert whole, table unchanged.
    let foreign = fx.mint(&doc1(ACCT_B), &[&payload]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: foreign,
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    let (next, v) = fx.step(&genesis, &dep);
    assert_token(&v, "malformed_payload:foreign_content");
    assert!(next == genesis);
}

/// Corpus: first FROM span home-minted at 64 KiB+1, second span transcluded
/// — `too_large`: span 1's cap fault fires before span 2's home check
/// (AUTH-2.39's per-span interleave).
#[test]
fn cap_fault_fires_before_second_spans_home_check() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let big = vec![b'x'; MAX_RECORD_BYTES + 1];
    let s1 = fx.mint(&doc1(ACCT_A), &[&big]);
    let s2 = fx.mint(&doc1(ACCT_B), &[b"foreign"]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![s1[0].clone(), s2[0].clone()],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(&fx.classify(&genesis, &dep), "malformed_payload:too_large");
}

/// Corpus: first FROM span home-minted at exactly 64 KiB, second span
/// transcluded — `foreign_content`: span 2's home check precedes its values
/// and cap (AUTH-2.38 item 3, AUTH-2.43's not-exceeding boundary).
#[test]
fn exact_cap_passes_then_foreign_span_refuses() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let exact = vec![b'x'; MAX_RECORD_BYTES];
    let s1 = fx.mint(&doc1(ACCT_A), &[&exact]);
    let s2 = fx.mint(&doc1(ACCT_B), &[b"foreign"]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![s1[0].clone(), s2[0].clone()],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(&fx.classify(&genesis, &dep), "malformed_payload:foreign_content");
}

/// Corpus: a two-span FROM named in DESCENDING address order — folds as the
/// ENDSET order, never the address order (AUTH-2.3 span binding).
#[test]
fn endset_order_governs_concatenation() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    // The key line is minted at the LOWER address, the header at the HIGHER:
    // endset order (header first) disagrees with address order.
    let key_line = format!("ed25519 {}\n", key(1).to_hex());
    let s_key = fx.mint(&doc1(ACCT_A), &[key_line.as_bytes()]);
    let s_hdr = fx.mint(&doc1(ACCT_A), &[b"skep-enroll v1\n"]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![s_hdr[0].clone(), s_key[0].clone()],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_honored(&fx.classify(&genesis, &dep));

    // The address-order reading concatenates key-line-first and dies at the
    // header — proving the honored fold above really was endset order.
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![s_key[0].clone(), s_hdr[0].clone()],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(&fx.classify(&genesis, &dep), "malformed_payload:bad_header");
}

/// Corpus: the same spans named twice — `duplicate_key` naming the
/// repeating line (AUTH-2.4: a repeated span repeats its key lines).
#[test]
fn repeated_spans_repeat_their_lines() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let f1 = format!("{}\n", fp(1).to_hex());
    let f2 = format!("{}\n", fp(2).to_hex());
    let spans = fx.mint(
        &doc1(ACCT_A),
        &[b"skep-retire v1\n", f1.as_bytes(), f2.as_bytes()],
    );
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![
            spans[0].clone(),
            spans[1].clone(),
            spans[2].clone(),
            spans[1].clone(),
            spans[2].clone(),
        ],
        to: vec![unit(ACCT_A)],
        ty: vec![unit(T_RETIRE)],
    };
    assert_token(&fx.classify(&genesis, &dep), "malformed_payload:duplicate_key:4");
}

/// Corpus: a FROM span running one position past what the home minted —
/// `missing_value` (AUTH-2.45: an endset names addresses verbatim).
#[test]
fn span_past_the_mint_is_missing_value() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let key_line = format!("ed25519 {}\n", key(1).to_hex());
    fx.mint(&doc1(ACCT_A), &[b"skep-enroll v1\n", key_line.as_bytes()]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![content_run(&doc1(ACCT_A), 1, 3)], // ords 1..4; 3 unminted
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(&fx.classify(&genesis, &dep), "malformed_payload:missing_value");
}

/// Corpus: a FROM span whose start does not VALIDATE — `foreign_content`,
/// never a panic (AUTH-2.38 item 1).
#[test]
fn invalid_start_is_foreign_content_not_a_panic() {
    let fx = Fixture::new();
    let genesis = IdentityState::genesis();
    // Adjacent zeros: T4-invalid as an address, legal as a carrier tumbler.
    let start = tum(&[1, 1, 0, 5, 0, 1, 0, 0, 1]);
    let span = Span::new(start.clone(), width_at_last(9, 1)).expect("T12-valid carrier span");
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![span],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(&fx.classify(&genesis, &dep), "malformed_payload:foreign_content");
}

/// AUTH-1.22 — a ctx answering `Some(&[])` at a covered position breaks the
/// premise the reach walk's only bound rests on (the byte cap, AUTH-2.43:
/// nothing else ends a walk whose span acts above the element level). Debug
/// builds refuse such a ctx at the read rather than folding under it; the
/// span here covers one position, so the refusal is the assertion and never
/// the hang it guards against.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "AUTH-1.22")]
fn zero_byte_value_is_refused_at_the_read() {
    let mut fx = Fixture::new();
    let home = doc1(ACCT_A);
    fx.ctx.values.insert(content_pos(&home, 1), Vec::new());
    let dep = Dep {
        home: home.clone(),
        from: vec![content_run(&home, 1, 1)],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    let _ = fx.classify(&IdentityState::genesis(), &dep);
}

/// Corpus: a document-level start equal to the home · a subspace-only
/// element start · an element field deeper than subspace·ordinal —
/// `foreign_content` on all three, never `missing_value`, never a walk of
/// the home (AUTH-2.40: T4-valid NON-positions, never coerced).
#[test]
fn non_positions_are_foreign_content() {
    let fx = Fixture::new();
    let genesis = IdentityState::genesis();
    for start in [
        vec![1, 1, 0, 5, 0, 1],          // the home's own document address
        vec![1, 1, 0, 5, 0, 1, 0, 1],    // subspace-only element start
        vec![1, 1, 0, 5, 0, 1, 0, 1, 1, 1], // deeper than subspace·ordinal
    ] {
        let dep = Dep {
            home: doc1(ACCT_A),
            from: vec![unit(&start)],
            to: vec![unit(ACCT_A)],
            ty: enroll_ty(),
        };
        assert_token(&fx.classify(&genesis, &dep), "malformed_payload:foreign_content");
    }
}

/// Corpus: a start in the home's LINK subspace (element field `[2, 1]`) —
/// `missing_value`, never `foreign_content` (AUTH-2.41: the position test
/// constrains the field's SHAPE, never which subspace it names).
#[test]
fn link_subspace_start_walks_to_missing_value() {
    let fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![unit(&[1, 1, 0, 5, 0, 1, 0, 2, 1])],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(&fx.classify(&genesis, &dep), "malformed_payload:missing_value");
}

/// Corpus: `Span{start = […,1,1], width = […,1,0]}` (width's action point
/// above the element level) — folded by the REACH WALK, never a count off
/// `width`'s last component, which would read zero positions and answer an
/// empty-payload token (AUTH-2.42).
#[test]
fn reach_walk_never_a_count_off_width() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let key_line = format!("ed25519 {}\n", key(1).to_hex());
    fx.mint(&doc1(ACCT_A), &[b"skep-enroll v1\n", key_line.as_bytes()]);
    let start = content_pos(&doc1(ACCT_A), 1);
    let mut w = vec![0u32; 9];
    w[7] = 1; // action point at the subspace position, above the ordinal
    let span = Span::new(start, tum(&w)).expect("T12-valid width");
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![span],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    // The walk reads ords 1, 2, then outruns the mint: missing_value — NOT
    // `empty`/`bad_header`, which the count-off-width misreading answers.
    assert_token(&fx.classify(&genesis, &dep), "malformed_payload:missing_value");
}

/// Corpus: an EMPTY `from` — `malformed_shape`, never a payload token
/// (AUTH-2.47: pinned ahead of the parser, never reaches `record_bytes`).
#[test]
fn empty_from_is_malformed_shape() {
    let fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(&fx.classify(&genesis, &dep), "malformed_shape");
}

/// Corpus: a two-atom record — the header atom plus one under-cap atom whose
/// SUM exceeds the cap — `too_large`: bytes, never positions (AUTH-1.20:
/// two positions are nowhere near a position cap).
#[test]
fn cap_counts_bytes_never_positions() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let body = vec![b'x'; MAX_RECORD_BYTES - 6]; // under cap alone; over with the header
    let spans = fx.mint(&doc1(ACCT_A), &[b"skep-enroll v1\n", &body]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: spans,
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(&fx.classify(&genesis, &dep), "malformed_payload:too_large");
}

/// Corpus: a three-atom record whose concatenated bytes are under the cap —
/// honored (AUTH-2.3: multi-span records are ordinary).
#[test]
fn three_atom_record_folds() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let l1 = format!("anchor ed25519 {}\n", key(1).to_hex());
    let l2 = format!("ed25519 {}\n", key(2).to_hex());
    let spans = fx.mint(
        &doc1(ACCT_A),
        &[b"skep-enroll v1\n", l1.as_bytes(), l2.as_bytes()],
    );
    let dep = Dep {
        home: doc1(ACCT_A),
        from: spans,
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    match assert_honored(&fx.classify(&genesis, &dep)) {
        Effect::Genesis { account, keys } => {
            assert!(*account == addr(ACCT_A));
            assert_eq!(keys.len(), 2);
            assert!(keys[0].anchor);
            assert!(!keys[1].anchor);
        }
        _ => panic!("expected a genesis effect"),
    }
}

/// Corpus: a 64 KiB record folds · a 64 KiB+1 record is inert (AUTH-2.43's
/// exceed-only boundary; AUTH-1.19's per-record scope).
#[test]
fn record_at_exactly_the_cap_folds_and_one_more_byte_inerts() {
    use skep_identity::{encode_enroll, Enrollment};

    let mut entries: Vec<Enrollment> = (0..897u32)
        .map(|i| Enrollment::new(keyn(i), false, None).expect("label-free"))
        .collect();
    let base_len = encode_enroll(&entries).len();
    let pad = MAX_RECORD_BYTES - base_len;
    assert!(pad >= 2, "fixture arithmetic: need room for a label pad");

    // Exactly the cap: one label of pad−1 chars adds `pad` bytes (the space
    // plus the label).
    entries[0] = Enrollment::new(keyn(0), false, Some("x".repeat(pad - 1))).expect("label");
    let payload = encode_enroll(&entries);
    assert_eq!(payload.len(), MAX_RECORD_BYTES);

    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &payload);
    match assert_honored(&fx.classify(&genesis, &dep)) {
        Effect::Genesis { keys, .. } => assert_eq!(keys.len(), 897),
        _ => panic!("expected a genesis effect"),
    }

    // One byte more: inert.
    entries[0] = Enrollment::new(keyn(0), false, Some("x".repeat(pad))).expect("label");
    let payload = encode_enroll(&entries);
    assert_eq!(payload.len(), MAX_RECORD_BYTES + 1);
    let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &payload);
    assert_token(&fx.classify(&genesis, &dep), "malformed_payload:too_large");
}

// ------------------------------------------------------------- step order

/// Corpus: a draft-homed credential deposit whose `to` is TWO spans —
/// `unpublished`, never `malformed_shape` (AUTH-2.66: publication before
/// the per-kind shape checks; I7 AUTH-2.102).
#[test]
fn publication_precedes_shape() {
    let mut fx = Fixture::new();
    fx.ctx.unpublished.insert(doc1(ACCT_A));
    let genesis = IdentityState::genesis();
    let spans = fx.mint(&doc1(ACCT_A), &[b"skep-enroll v1\n"]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: spans,
        to: vec![unit(ACCT_A), unit(ACCT_B)],
        ty: enroll_ty(),
    };
    assert_token(&fx.classify(&genesis, &dep), "unpublished");
}

/// Corpus: a two-span `to` beside a home-minted 64 KiB+1 `from` span —
/// `malformed_shape`, never `too_large` (AUTH-2.66: shape before
/// `record_bytes`).
#[test]
fn shape_precedes_the_payload_read() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let big = vec![b'x'; MAX_RECORD_BYTES + 1];
    let spans = fx.mint(&doc1(ACCT_A), &[&big]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: spans,
        to: vec![unit(ACCT_A), unit(ACCT_B)],
        ty: enroll_ty(),
    };
    assert_token(&fx.classify(&genesis, &dep), "malformed_shape");
}

/// Corpus: a deposit homed in a PUBLISHED second document of its account,
/// payload unparseable — `malformed_payload` naming the fault, never
/// `not_doc_one` (AUTH-2.127: the payload precedes the home pin).
#[test]
fn payload_precedes_the_home_pin() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let dep = fx.enroll_dep(&doc2(ACCT_A), ACCT_A, b"zzz not a header\n");
    assert_token(&fx.classify(&genesis, &dep), "malformed_payload:bad_header");
}

/// AUTH-2.66 item 2 — an unowned home is `malformed_shape` (no ω answer).
#[test]
fn unowned_home_is_malformed_shape() {
    let fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let outside = addr(&[2, 1, 0, 9, 0, 1]); // under no registered prefix
    let dep = fx.claim_dep(&outside, CLM);
    assert_token(&fx.classify(&genesis, &dep), "malformed_shape");
}

/// I7 (AUTH-2.102) — `is_published == false ⇒ Inert(Unpublished)` for every
/// shape: enroll, retire, claim alike (unit arm; the proptest rides in
/// `props.rs`).
#[test]
fn unpublished_home_inerts_every_shape() {
    let mut fx = Fixture::new();
    fx.ctx.all_unpublished = true;
    let genesis = IdentityState::genesis();

    let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &enroll_payload(&[(1, true)]));
    assert_token(&fx.classify(&genesis, &dep), "unpublished");

    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[1]));
    assert_token(&fx.classify(&genesis, &dep), "unpublished");

    let dep = fx.claim_dep(&doc1(CLM), CLM);
    assert_token(&fx.classify(&genesis, &dep), "unpublished");
}

// ---------------------------------------------------------- verdict tokens

/// Corpus: a genesis enrollment homed in neither A's space nor its genesis
/// registry's — `not_genesis_registry`, never `no_holder` (AUTH-2.71's
/// wrong-delegator face, AUTH-2.72's written order).
#[test]
fn stranger_homed_genesis_is_not_genesis_registry() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let dep = fx.enroll_dep(&doc1(ACCT_B), ACCT_A, &enroll_payload(&[(1, true)]));
    assert_token(&fx.classify(&genesis, &dep), "not_genesis_registry");
}

/// Corpus: a retirement of a member's key homed in the ORG's own doc 1 (the
/// member's genesis registry) — `not_holder_retirement`, never
/// `not_genesis_registry` (AUTH-2.76: the retirement arms never read
/// `delegator`; no ancestor retires a holder's keys).
#[test]
fn registry_homed_retirement_is_not_holder_retirement() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    // Seed the member THROUGH its registry (the org's doc 1) first — the
    // enrollment door that same home legitimately opens (AUTH-2.70).
    let dep = fx.enroll_dep(&doc1(ORG), NESTED, &enroll_payload(&[(1, true), (2, false)]));
    let (st, v) = fx.step(&genesis, &dep);
    assert_honored(&v);
    // The retirement through that same home is inert.
    let dep = fx.retire_dep(&doc1(ORG), NESTED, &retire_payload(&[2]));
    assert_token(&fx.classify(&st, &dep), "not_holder_retirement");
}

/// Corpus: a claim by a KEYLESS TOP-LEVEL account on an already-claimed
/// board — `already_claimed`, never `claimant_keyless` (AUTH-2.68's pinned
/// coexistence cell).
#[test]
fn already_claimed_beats_claimant_keyless() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let st = seed_own(&mut fx, &genesis, CLM, &[(9, true)]);
    let st = claim_as(&mut fx, &st, CLM);
    let dep = fx.claim_dep(&doc1(ACCT_B), ACCT_B); // ACCT_B is keyless
    assert_token(&fx.classify(&st, &dep), "already_claimed");
}

/// Corpus: a claim by a NESTED account on an already-claimed board —
/// `claimant_not_top_level`, never `already_claimed` (AUTH-2.68: the
/// delegator read comes first despite costing more).
#[test]
fn claimant_not_top_level_beats_already_claimed() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let st = seed_own(&mut fx, &genesis, CLM, &[(9, true)]);
    let st = claim_as(&mut fx, &st, CLM);
    let dep = fx.claim_dep(&doc1(NESTED), NESTED);
    assert_token(&fx.classify(&st, &dep), "claimant_not_top_level");
}

/// Corpus: a holder enrollment (`H == A`, set non-empty) homed in a
/// PUBLISHED second document of A — `not_doc_one`, never honored: the home
/// pin (AUTH-2.127, RES-17).
#[test]
fn holder_enrollment_outside_doc_1_is_not_doc_one() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let st = seed_own(&mut fx, &genesis, ACCT_A, &[(1, true)]);
    let dep = fx.enroll_dep(&doc2(ACCT_A), ACCT_A, &enroll_payload(&[(2, false)]));
    assert_token(&fx.classify(&st, &dep), "not_doc_one");
}

/// Corpus: a genesis enrollment homed in the delegator's PUBLISHED second
/// document — `not_doc_one`, never `not_genesis_registry` (the pin precedes
/// the account comparisons, AUTH-2.127).
#[test]
fn genesis_in_delegators_second_doc_is_not_doc_one() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let dep = fx.enroll_dep(&doc2(ORG), NESTED, &enroll_payload(&[(3, true)]));
    assert_token(&fx.classify(&genesis, &dep), "not_doc_one");
}

/// Corpus: a claim by a NESTED account homed in its own PUBLISHED second
/// document — `not_doc_one`, never `claimant_not_top_level` (AUTH-2.67
/// condition 2 before condition 3).
#[test]
fn nested_claim_in_second_doc_is_not_doc_one() {
    let fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let dep = fx.claim_dep(&doc2(NESTED), NESTED);
    assert_token(&fx.classify(&genesis, &dep), "not_doc_one");
}

// ------------------------------------------------------------ board state

/// Corpus: bootstrap-delegated A — the SAME genesis record homed in A's OWN
/// doc 1, before / after the claim: `Honored(Genesis)` / `no_holder`
/// (AUTH-2.62's claimant flip; AUTH-2.72's written order keeps the
/// pre-claim own-space genesis honored).
#[test]
fn own_space_genesis_flips_to_no_holder_at_the_claim() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &enroll_payload(&[(1, true)]));
    assert_honored(&fx.classify(&genesis, &dep));

    let st = seed_own(&mut fx, &genesis, CLM, &[(9, true)]);
    let st = claim_as(&mut fx, &st, CLM);
    assert_token(&fx.classify(&st, &dep), "no_holder");
}

/// Corpus: the same genesis homed in the CLAIMANT's doc 1, before / after
/// the claim: `not_genesis_registry` / `Honored(Genesis)` (AUTH-2.62: the
/// bootstrap tier's registry is the claimant's space once claimed).
#[test]
fn claimant_homed_genesis_flips_to_honored_at_the_claim() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let pre = seed_own(&mut fx, &genesis, CLM, &[(9, true)]);
    let dep = fx.enroll_dep(&doc1(CLM), ACCT_A, &enroll_payload(&[(1, true)]));
    assert_token(&fx.classify(&pre, &dep), "not_genesis_registry");

    let post = claim_as(&mut fx, &pre, CLM);
    match assert_honored(&fx.classify(&post, &dep)) {
        Effect::Genesis { account, .. } => assert!(*account == addr(ACCT_A)),
        _ => panic!("expected a genesis effect"),
    }
}

// ------------------------------------------------------------------ shape

/// Corpus: a `to` slot of two spans; a `to` whose single span is `Equal` to
/// no `subtree_of(its start)` — `malformed_shape` on all three kinds
/// (AUTH-2.46, AUTH-2.48, AUTH-2.26).
#[test]
fn to_slot_shape_is_malformed_on_all_kinds() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();

    // Two spans (enroll; retire; a claim's `to` must be EMPTY, so any span
    // there is the same refusal).
    let spans = fx.mint(&doc1(ACCT_A), &[&enroll_payload(&[(1, true)])]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: spans.clone(),
        to: vec![unit(ACCT_A), unit(ACCT_B)],
        ty: enroll_ty(),
    };
    assert_token(&fx.classify(&genesis, &dep), "malformed_shape");
    let dep = Dep {
        home: doc1(ACCT_A),
        from: spans.clone(),
        to: vec![unit(ACCT_A), unit(ACCT_B)],
        ty: vec![unit(T_RETIRE)],
    };
    assert_token(&fx.classify(&genesis, &dep), "malformed_shape");
    let dep = Dep {
        home: doc1(CLM),
        from: vec![unit(CLM)],
        to: vec![unit(ACCT_A)],
        ty: vec![unit(T_CLAIM)],
    };
    assert_token(&fx.classify(&genesis, &dep), "malformed_shape");

    // A single span that is no subtree: it covers TWO account subtrees.
    let two_accounts = Span::new(tum(ACCT_A), width_at_last(ACCT_A.len(), 2)).expect("T12");
    let dep = Dep {
        home: doc1(ACCT_A),
        from: spans,
        to: vec![two_accounts.clone()],
        ty: enroll_ty(),
    };
    assert_token(&fx.classify(&genesis, &dep), "malformed_shape");

    // The claim's FROM under the same test (AUTH-2.26 governs both).
    let dep = Dep {
        home: doc1(CLM),
        from: vec![Span::new(tum(CLM), width_at_last(CLM.len(), 2)).expect("T12")],
        to: vec![],
        ty: vec![unit(T_CLAIM)],
    };
    assert_token(&fx.classify(&genesis, &dep), "malformed_shape");
}

/// Corpus: a `ty` slot whose single span is a CONTENT I-span of the home ·
/// a `ty` of TWO spans, one of which IS `subtree_of(T_enroll)` · a `ty` of
/// ONE span CONTAINING `subtree_of(T_enroll)` — `NotCredential` on each
/// (AUTH-2.22's exactly-one-span-`Equal` rule).
#[test]
fn unrecognized_type_slots_are_not_credential() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let spans = fx.mint(&doc1(ACCT_A), &[&enroll_payload(&[(1, true)])]);

    for ty in [
        vec![unit(&[1, 1, 0, 5, 0, 1, 0, 1, 1])], // a content I-span of the home
        vec![unit(T_ENROLL), unit(T_RETIRE)],     // two spans, one IS the type's
        vec![unit(&[1, 1, 0, 1, 0, 1, 0, 2])],    // CONTAINS subtree_of(T_enroll)
    ] {
        let dep = Dep {
            home: doc1(ACCT_A),
            from: spans.clone(),
            to: vec![unit(ACCT_A)],
            ty,
        };
        let (next, v) = fx.step(&genesis, &dep);
        assert!(matches!(v, Verdict::NotCredential), "expected NotCredential");
        assert!(next == genesis, "NotCredential must leave state unchanged");
    }
}

// -------------------------------------------------- key-set semantics

/// AUTH-1.30/AUTH-1.31 accessor semantics, the retire flow's flag carriage
/// (AUTH-2.74), `WouldEmpty` (I3), the I4 re-entry refusal, and I9's
/// conformance arm (re-listing an enrolled device key as `anchor` answers
/// `nothing_changed` and the flag stays `false`).
#[test]
fn key_set_lifecycle() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let st = seed_own(&mut fx, &genesis, ACCT_A, &[(1, true), (2, false)]);
    let a = addr(ACCT_A);

    let s = st.key_set(&a);
    assert!(!s.is_empty());
    assert!(s.contains(&fp(1)) && s.is_anchor(&fp(1)));
    assert!(s.contains(&fp(2)) && !s.is_anchor(&fp(2)));
    // Fingerprint-ordered iteration (AUTH-1.31).
    let listed: Vec<_> = s.enrolled().map(|(f, _)| *f).collect();
    let mut sorted = listed.clone();
    sorted.sort();
    assert!(listed == sorted);
    assert_eq!(st.accounts().count(), 1);

    // I9 conformance: re-list the device key under the anchor flag.
    let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &enroll_payload(&[(2, true)]));
    let (st2, v) = fx.step(&st, &dep);
    assert_token(&v, "nothing_changed");
    assert!(st2 == st);
    assert!(!st2.key_set(&a).is_anchor(&fp(2)));

    // Retire the device key: `removed` names it; the retired row carries the
    // flag it was ENROLLED under (false).
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[2]));
    let (st3, v) = fx.step(&st2, &dep);
    match assert_honored(&v) {
        Effect::Retire { account, removed } => {
            assert!(*account == a);
            assert!(*removed == vec![fp(2)]);
        }
        _ => panic!("expected a retire effect"),
    }
    let s3 = st3.key_set(&a);
    assert!(!s3.contains(&fp(2)));
    assert!(!s3.is_anchor(&fp(2)));
    let retired: Vec<_> = s3.retired().collect();
    assert_eq!(retired.len(), 1);
    assert!(*retired[0].0 == fp(2));
    assert!(!retired[0].1);

    // Retiring it again touches nothing: removed = F ∩ enrolled = ∅.
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[2]));
    let (st4, v) = fx.step(&st3, &dep);
    assert_token(&v, "nothing_changed");
    assert!(st4 == st3);

    // I4: a retired fingerprint never re-enters — the re-enrollment line is
    // outside `added` whatever its flag.
    let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &enroll_payload(&[(2, true)]));
    let (st5, v) = fx.step(&st4, &dep);
    assert_token(&v, "nothing_changed");
    assert!(st5 == st4);

    // I3: retiring the whole remaining set is `would_empty`, record inert.
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[1]));
    let (st6, v) = fx.step(&st5, &dep);
    assert_token(&v, "would_empty");
    assert!(st6 == st5);
}

/// The claim walk end to end: keyless refusal, honored claim, first-wins
/// (AUTH-2.67; I6 AUTH-2.101), and the from≠H shape refusal (AUTH-2.48).
#[test]
fn claim_flow() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();

    // Keyless claimant, pre-claim: condition 5.
    let dep = fx.claim_dep(&doc1(CLM), CLM);
    assert_token(&fx.classify(&genesis, &dep), "claimant_keyless");

    // Seed both top-level accounts BEFORE the claim (post-claim, an
    // own-space genesis is `no_holder` — the AUTH-2.62 flip).
    let st = seed_own(&mut fx, &genesis, CLM, &[(9, true)]);
    let st = seed_own(&mut fx, &st, ACCT_B, &[(8, true)]);

    // Claimed: honored; claimant posts.
    let (st, v) = fx.step(&st, &dep);
    match assert_honored(&v) {
        Effect::Claim { account } => assert!(*account == addr(CLM)),
        _ => panic!("expected a claim effect"),
    }
    assert!(st.claimant() == Some(&addr(CLM)));

    // First-wins: a second claim, even by another seeded top-level account.
    let dep2 = fx.claim_dep(&doc1(ACCT_B), ACCT_B);
    let (st3, v) = fx.step(&st, &dep2);
    assert_token(&v, "already_claimed");
    assert!(st3.claimant() == Some(&addr(CLM)));

    // A claim whose `from` is not the home's account: shape (condition 1).
    let dep = Dep {
        home: doc1(CLM),
        from: vec![unit(ACCT_A)],
        to: vec![],
        ty: vec![unit(T_CLAIM)],
    };
    assert_token(&fx.classify(&st3, &dep), "malformed_shape");
}

/// AUTH-1.40 — a populated `IdentityState` (sets, retirements, claimant)
/// survives a serde round trip, and equals itself under `PartialEq`.
#[test]
fn populated_state_survives_serde() {
    let mut fx = Fixture::new();
    let genesis = IdentityState::genesis();
    let st = seed_own(&mut fx, &genesis, ACCT_A, &[(1, true), (2, false), (3, false)]);
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[3]));
    let (st, v) = fx.step(&st, &dep);
    assert_honored(&v);
    let st = seed_own(&mut fx, &st, CLM, &[(9, true)]);
    let st = claim_as(&mut fx, &st, CLM);

    let bytes = bincode::serialize(&st).expect("serialize IdentityState");
    let back: IdentityState = bincode::deserialize(&bytes).expect("deserialize IdentityState");
    assert!(back == st);
    assert!(back.claimant() == Some(&addr(CLM)));
    assert!(back.key_set(&addr(ACCT_A)).contains(&fp(1)));
}
