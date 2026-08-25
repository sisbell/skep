//! The fold corpus (AUTH-2.96): payload vectors over `record_bytes`
//! (AUTH-2.38–2.45), step-order vectors (AUTH-2.66), verdict-token vectors
//! (AUTH-2.67–2.76, AUTH-2.127), board-state vectors (AUTH-2.62), shape
//! vectors (AUTH-2.22, AUTH-2.46–2.48), and the key-set semantics
//! (AUTH-1.30–1.31, I9's conformance arm).

mod common;

use std::collections::BTreeMap;

use common::*;
use skep_address::Span;
use skep_identity::{single_address, Effect, IdentityState, TypeAddrs, Verdict, MAX_RECORD_BYTES};

fn enroll_ty() -> Vec<Span> {
    vec![unit(T_ENROLL)]
}

// ---------------------------------------------------------------- payload

/// Corpus: payload text `copy`ed from another document, the link naming that
/// run — beside the SAME text `insert`ed into the home and named (AUTH-2.44
/// home anchoring; a home-minted run is native and folds, AUTH-2.96's
/// copy-from-home row).
#[test]
fn home_minted_bytes_fold_and_foreign_ones_do_not() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let payload = enroll_payload(&[(1, true)]);

    // Native: the record's bytes minted in the home itself.
    let native = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &payload);
    assert_honored(&fx.classify(&genesis_state, &native));

    // A second home-minted run carrying the same bytes (the shape a `copy`
    // from the HOME itself leaves) is native by the same test.
    let copied = fx.mint(&doc1(ACCT_A), &[&payload]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: copied,
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_honored(&fx.classify(&genesis_state, &dep));

    // Foreign: the same text minted under ANOTHER document, the link naming
    // that run — inert whole, table unchanged.
    let foreign = fx.mint(&doc1(ACCT_B), &[&payload]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: foreign,
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    let (next, v) = fx.step(&genesis_state, &dep);
    assert_token(&v, "malformed_payload:foreign_content");
    assert_eq!(next, genesis_state);
}

/// Corpus: first FROM span home-minted at 64 KiB+1, second span transcluded
/// — `too_large`: span 1's cap fault fires before span 2's home check
/// (AUTH-2.39's per-span interleave).
#[test]
fn cap_fault_fires_before_second_spans_home_check() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let big = vec![b'x'; MAX_RECORD_BYTES + 1];
    let home_span = fx.mint(&doc1(ACCT_A), &[&big]);
    let foreign_span = fx.mint(&doc1(ACCT_B), &[b"foreign"]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![home_span[0].clone(), foreign_span[0].clone()],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:too_large",
    );
}

/// Corpus: first FROM span home-minted at exactly 64 KiB, second span
/// transcluded — `foreign_content`: span 2's home check precedes its values
/// and cap (AUTH-2.38 item 3, AUTH-2.43's not-exceeding boundary).
#[test]
fn exact_cap_passes_then_foreign_span_refuses() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let exact = vec![b'x'; MAX_RECORD_BYTES];
    let home_span = fx.mint(&doc1(ACCT_A), &[&exact]);
    let foreign_span = fx.mint(&doc1(ACCT_B), &[b"foreign"]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![home_span[0].clone(), foreign_span[0].clone()],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:foreign_content",
    );
}

/// Corpus: a two-span FROM named in DESCENDING address order — folds as the
/// ENDSET order, never the address order (AUTH-2.3 span binding).
#[test]
fn endset_order_governs_concatenation() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    // The key line is minted at the LOWER address, the header at the HIGHER:
    // endset order (header first) disagrees with address order.
    let key_line = format!("ed25519 {}\n", key(1).to_hex());
    let key_span = fx.mint(&doc1(ACCT_A), &[key_line.as_bytes()]);
    let header_span = fx.mint(&doc1(ACCT_A), &[b"skep-enroll v1\n"]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![header_span[0].clone(), key_span[0].clone()],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_honored(&fx.classify(&genesis_state, &dep));

    // The address-order reading concatenates key-line-first and dies at the
    // header — proving the honored fold above really was endset order.
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![key_span[0].clone(), header_span[0].clone()],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:bad_header",
    );
}

/// Corpus: the same spans named twice — `duplicate_key` naming the
/// repeating line (AUTH-2.4: a repeated span repeats its key lines).
#[test]
fn repeated_spans_repeat_their_lines() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
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
    assert_token(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:duplicate_key:4",
    );
}

/// Corpus: a FROM span running one position past what the home minted —
/// `missing_value` (AUTH-2.45: an endset names addresses verbatim).
#[test]
fn span_past_the_mint_is_missing_value() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let home = doc1(ACCT_A);
    let key_line = format!("ed25519 {}\n", key(1).to_hex());
    fx.mint(&home, &[b"skep-enroll v1\n", key_line.as_bytes()]);
    // The span reaches exactly ONE position past the mint — asked of the
    // fixture, so the width follows the mint above instead of restating it.
    let dep = Dep {
        home: home.clone(),
        from: vec![content_run(&home, 1, fx.next_ord(&home))],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:missing_value",
    );
}

/// Corpus: a FROM span whose start does not VALIDATE — `foreign_content`,
/// never a panic (AUTH-2.38 item 1).
#[test]
fn invalid_start_is_foreign_content_not_a_panic() {
    let fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    // Adjacent zeros: T4-invalid as an address, legal as a carrier tumbler.
    let start = tum(&[1, 1, 0, 5, 0, 1, 0, 0, 1]);
    let span = Span::new(start.clone(), width_at_last(9, 1)).expect("T12-valid carrier span");
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![span],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:foreign_content",
    );
}

/// AUTH-1.22 — a ctx answering `Some(&[])` at a covered position breaks the
/// premise the byte cap rests on (AUTH-2.43: a value appending nothing can
/// never reach it). Debug builds name the broken premise at the read rather
/// than folding under it, one step before the position budget would refuse
/// the record — the release-build bound
/// [`a_zero_byte_ctx_is_bounded_by_the_position_budget`] pins.
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
    let genesis_state = IdentityState::genesis();
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
        assert_token(
            &fx.classify(&genesis_state, &dep),
            "malformed_payload:foreign_content",
        );
    }
}

/// Corpus: a start in the home's LINK subspace (element field `[2, 1]`) —
/// `missing_value`, never `foreign_content` (AUTH-2.41: the position test
/// constrains the field's SHAPE, never which subspace it names).
#[test]
fn link_subspace_start_walks_to_missing_value() {
    let fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![unit(&[1, 1, 0, 5, 0, 1, 0, 2, 1])],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:missing_value",
    );
}

/// Corpus: `Span{start = […,1,1], width = […,1,0]}` (width's action point
/// above the element level) — folded by the REACH WALK, never a count off
/// `width`'s last component, which would read zero positions and answer an
/// empty-payload token (AUTH-2.42).
#[test]
fn reach_walk_never_a_count_off_width() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
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
    assert_token(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:missing_value",
    );
}

/// Corpus: an EMPTY `from` — `malformed_shape`, never a payload token
/// (AUTH-2.47: pinned ahead of the parser, never reaches `record_bytes`).
#[test]
fn empty_from_is_malformed_shape() {
    let fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(&fx.classify(&genesis_state, &dep), "malformed_shape");
}

/// Corpus: a two-atom record — the header atom plus one under-cap atom whose
/// SUM exceeds the cap — `too_large`: bytes, never positions (AUTH-1.20:
/// two positions are nowhere near a position cap).
#[test]
fn cap_counts_bytes_never_positions() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let body = vec![b'x'; MAX_RECORD_BYTES - 6]; // under cap alone; over with the header
    let spans = fx.mint(&doc1(ACCT_A), &[b"skep-enroll v1\n", &body]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: spans,
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:too_large",
    );
}

/// AUTH-2.38's items in ORDER: with the record already AT the cap, the next
/// position's value is read (item 4) BEFORE the cap is tested (item 5), so
/// an unminted position answers `missing_value` — never `too_large`, which
/// is what a cap test hoisted to the top of the walk would answer.
#[test]
fn a_missing_value_at_the_cap_is_missing_value_not_too_large() {
    let mut fx = Fixture::new();
    let home = doc1(ACCT_A);
    fx.mint(&home, &[&vec![b'x'; MAX_RECORD_BYTES]]); // ord 1 fills the budget
    let dep = Dep {
        home: home.clone(),
        from: vec![content_run(&home, 1, 2)], // ords 1..3; ord 2 unminted
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(
        &fx.classify(&IdentityState::genesis(), &dep),
        "malformed_payload:missing_value",
    );
}

/// Corpus: a three-atom record whose concatenated bytes are under the cap —
/// honored (AUTH-2.3: multi-span records are ordinary).
#[test]
fn three_atom_record_folds() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let anchor_line = format!("anchor ed25519 {}\n", key(1).to_hex());
    let device_line = format!("ed25519 {}\n", key(2).to_hex());
    let spans = fx.mint(
        &doc1(ACCT_A),
        &[
            b"skep-enroll v1\n",
            anchor_line.as_bytes(),
            device_line.as_bytes(),
        ],
    );
    let dep = Dep {
        home: doc1(ACCT_A),
        from: spans,
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    match assert_honored(&fx.classify(&genesis_state, &dep)) {
        Effect::Genesis { account, keys } => {
            assert_eq!(*account, addr(ACCT_A));
            assert_eq!(keys.len(), 2);
            assert!(keys[0].anchor);
            assert!(!keys[1].anchor);
        }
        _ => panic!("expected a genesis effect"),
    }
}

/// The key lines [`cap_sized_enroll_payload`] writes — chosen so that a
/// `MAX_RECORD_BYTES` budget of `ed25519 <64 hex>` lines leaves room for the
/// label that pads the record onto the mark; the helper asserts that as a
/// fixture precondition.
const CAP_SIZED_LINES: u32 = 897;

/// An enrollment record of exactly `MAX_RECORD_BYTES + over` bytes:
/// [`CAP_SIZED_LINES`] key lines, the first carrying a label sized to land
/// the total on the mark. Built FROM the constant, so a change to the cap
/// moves the record with it and `max_record_bytes_is_64_kib` stays the one
/// assertion that discovers it.
fn cap_sized_enroll_payload(over: usize) -> Vec<u8> {
    use skep_identity::{encode_enroll, Enrollment};

    let mut entries: Vec<Enrollment> = (0..CAP_SIZED_LINES)
        .map(|i| Enrollment::new(wide_key(i), false, None).expect("label-free"))
        .collect();
    let base_len = encode_enroll(&entries).len();
    assert!(
        base_len + 2 <= MAX_RECORD_BYTES,
        "fixture arithmetic: {base_len} bytes of key lines leaves no room for a \
         label pad under a {MAX_RECORD_BYTES}-byte cap"
    );
    // One label of pad−1 chars adds `pad` bytes (the space plus the label).
    let pad = MAX_RECORD_BYTES - base_len + over;
    entries[0] = Enrollment::new(wide_key(0), false, Some("x".repeat(pad - 1))).expect("label");
    let payload = encode_enroll(&entries);
    assert_eq!(payload.len(), MAX_RECORD_BYTES + over);
    payload
}

/// Corpus: a 64 KiB record folds · a 64 KiB+1 record is inert (AUTH-2.43's
/// exceed-only boundary; AUTH-1.19's per-record scope).
#[test]
fn record_at_exactly_the_cap_folds_and_one_more_byte_inerts() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();

    let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &cap_sized_enroll_payload(0));
    match assert_honored(&fx.classify(&genesis_state, &dep)) {
        Effect::Genesis { keys, .. } => assert_eq!(keys.len(), CAP_SIZED_LINES as usize),
        _ => panic!("expected a genesis effect"),
    }

    // One byte more: inert.
    let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &cap_sized_enroll_payload(1));
    assert_token(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:too_large",
    );
}

/// AUTH-2.43's exceed-only boundary read in POSITIONS: a 64 KiB record spread
/// ONE BYTE PER POSITION walks exactly `MAX_RECORD_BYTES` positions and folds.
/// The per-record position budget is `>`, never `>=`, so the widest record a
/// conforming ctx can carry is a record and not a refusal — the slip a
/// reviser makes, and the boundary the budget's own soundness argument names.
#[test]
fn a_record_of_cap_many_one_byte_positions_folds() {
    let mut fx = Fixture::new();
    let home = doc1(ACCT_A);
    let payload = cap_sized_enroll_payload(0);

    // One position per byte: the conforming ctx that walks the most positions
    // a record can have, since every value carries at least one (AUTH-1.22).
    for (i, byte) in payload.iter().enumerate() {
        let ord = u32::try_from(i + 1).expect("cap fits a u32 ordinal");
        fx.ctx.values.insert(content_pos(&home, ord), vec![*byte]);
    }
    let width = u32::try_from(MAX_RECORD_BYTES).expect("cap fits a u32 width");
    let dep = Dep {
        home: home.clone(),
        from: vec![content_run(&home, 1, width)],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    match assert_honored(&fx.classify(&IdentityState::genesis(), &dep)) {
        Effect::Genesis { keys, .. } => assert_eq!(keys.len(), CAP_SIZED_LINES as usize),
        _ => panic!("expected a genesis effect"),
    }
}

/// AUTH-1.22 — the release-build bound. A ctx answering `Some(&[])` at a
/// covered position appends nothing, so the byte cap can never fire; the span
/// here has its width acting ABOVE the ordinal, so it covers every ordinal
/// above its start and the reach bounds nothing either. The per-record
/// position budget is what ends this walk, in bounded work, with `too_large`.
///
/// Runs under `cargo test --release` only: a debug build refuses the same ctx
/// one step earlier at the read's `debug_assert`, which is what
/// [`zero_byte_value_is_refused_at_the_read`] pins.
#[cfg(not(debug_assertions))]
#[test]
fn a_zero_byte_ctx_is_bounded_by_the_position_budget() {
    let mut fx = Fixture::new();
    let home = doc1(ACCT_A);

    // One position past the budget, so the walk reaches the refusal rather
    // than outrunning the mint into `missing_value`.
    for ord in 1..=u32::try_from(MAX_RECORD_BYTES + 1).expect("cap fits a u32 ordinal") {
        fx.ctx.values.insert(content_pos(&home, ord), Vec::new());
    }
    let start = content_pos(&home, 1);
    let mut w = vec![0u32; start.len()];
    w[start.len() - 2] = 1; // action point at the subspace, above the ordinal
    let dep = Dep {
        home: home.clone(),
        from: vec![Span::new(start, tum(&w)).expect("T12-valid width")],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(
        &fx.classify(&IdentityState::genesis(), &dep),
        "malformed_payload:too_large",
    );
}

// ------------------------------------------------------------- step order

/// Corpus: a draft-homed credential deposit whose `to` is TWO spans —
/// `unpublished`, never `malformed_shape` (AUTH-2.66: publication before
/// the per-kind shape checks; I7 AUTH-2.102).
#[test]
fn publication_precedes_shape() {
    let mut fx = Fixture::new();
    fx.ctx.unpublished.insert(doc1(ACCT_A));
    let genesis_state = IdentityState::genesis();
    let spans = fx.mint(&doc1(ACCT_A), &[b"skep-enroll v1\n"]);
    let dep = Dep {
        home: doc1(ACCT_A),
        from: spans,
        to: vec![unit(ACCT_A), unit(ACCT_B)],
        ty: enroll_ty(),
    };
    assert_token(&fx.classify(&genesis_state, &dep), "unpublished");
}

/// Corpus: a two-span `to` beside a home-minted 64 KiB+1 `from` span —
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
    assert_token(&fx.classify(&genesis_state, &dep), "malformed_shape");
}

/// Corpus: a deposit homed in a PUBLISHED second document of its account,
/// payload unparseable — `malformed_payload` naming the fault, never
/// `not_doc_one` (AUTH-2.127: the payload precedes the home pin).
#[test]
fn payload_precedes_the_home_pin() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let dep = fx.enroll_dep(&doc2(ACCT_A), ACCT_A, b"zzz not a header\n");
    assert_token(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:bad_header",
    );
}

/// AUTH-2.66 item 2 — an unowned home is `malformed_shape` (no ω answer).
#[test]
fn unowned_home_is_malformed_shape() {
    let fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let outside = addr(&[2, 1, 0, 9, 0, 1]); // under no registered prefix
    let dep = fx.claim_dep(&outside, CLAIMANT);
    assert_token(&fx.classify(&genesis_state, &dep), "malformed_shape");
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
    assert_token(&fx.classify(&genesis_state, &dep), "unpublished");

    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[1]));
    assert_token(&fx.classify(&genesis_state, &dep), "unpublished");

    let dep = fx.claim_dep(&doc1(CLAIMANT), CLAIMANT);
    assert_token(&fx.classify(&genesis_state, &dep), "unpublished");
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
    assert_token(&fx.classify(&genesis_state, &dep), "not_genesis_registry");
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
    assert_token(&fx.classify(&st, &dep), "not_holder_retirement");
}

/// AUTH-2.76's first refusal arm: a retirement homed in the subject's OWN
/// doc 1 on an account that has never held a key — `no_holder`, never
/// `not_holder_retirement`, which is the ancestor-homed refusal and names a
/// relationship this deposit does not have.
#[test]
fn own_space_retirement_on_a_never_keyed_account_is_no_holder() {
    let mut fx = Fixture::new();
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[1]));
    assert_token(&fx.classify(&IdentityState::genesis(), &dep), "no_holder");
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
    assert_token(&fx.classify(&st, &dep), "already_claimed");
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
    assert_token(&fx.classify(&st, &dep), "claimant_not_top_level");
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
    assert_token(
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
    assert_token(
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
    assert_token(&fx.classify(&st, &dep), "not_doc_one");
}

/// Corpus: a genesis enrollment homed in the delegator's PUBLISHED second
/// document — `not_doc_one`, never `not_genesis_registry` (the pin precedes
/// the account comparisons, AUTH-2.127).
#[test]
fn genesis_in_delegators_second_doc_is_not_doc_one() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let dep = fx.enroll_dep(&doc2(ORG), NESTED, &enroll_payload(&[(3, true)]));
    assert_token(&fx.classify(&genesis_state, &dep), "not_doc_one");
}

/// Corpus: a claim by a NESTED account homed in its own PUBLISHED second
/// document — `not_doc_one`, never `claimant_not_top_level` (AUTH-2.67
/// condition 2 before condition 3).
#[test]
fn nested_claim_in_second_doc_is_not_doc_one() {
    let fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let dep = fx.claim_dep(&doc2(NESTED), NESTED);
    assert_token(&fx.classify(&genesis_state, &dep), "not_doc_one");
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
    assert_token(&fx.classify(&st, &dep), "no_holder");
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
    assert_token(&fx.classify(&pre, &dep), "not_genesis_registry");

    let post = claim_as(&mut fx, &pre, CLAIMANT);
    match assert_honored(&fx.classify(&post, &dep)) {
        Effect::Genesis { account, .. } => assert_eq!(*account, addr(ACCT_A)),
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
    assert_token(&fx.classify(&genesis_state, &dep), "malformed_shape");
    let dep = Dep {
        home: doc1(ACCT_A),
        from: spans.clone(),
        to: vec![unit(ACCT_A), unit(ACCT_B)],
        ty: vec![unit(T_RETIRE)],
    };
    assert_token(&fx.classify(&genesis_state, &dep), "malformed_shape");
    let dep = Dep {
        home: doc1(CLAIMANT),
        from: vec![unit(CLAIMANT)],
        to: vec![unit(ACCT_A)],
        ty: vec![unit(T_CLAIM)],
    };
    assert_token(&fx.classify(&genesis_state, &dep), "malformed_shape");

    // A single span that is no subtree: it covers TWO account subtrees.
    let two_accounts = Span::new(tum(ACCT_A), width_at_last(ACCT_A.len(), 2)).expect("T12");
    let dep = Dep {
        home: doc1(ACCT_A),
        from: spans,
        to: vec![two_accounts.clone()],
        ty: enroll_ty(),
    };
    assert_token(&fx.classify(&genesis_state, &dep), "malformed_shape");

    // The claim's FROM under the same test (AUTH-2.26 governs both).
    let dep = Dep {
        home: doc1(CLAIMANT),
        from: vec![Span::new(tum(CLAIMANT), width_at_last(CLAIMANT.len(), 2)).expect("T12")],
        to: vec![],
        ty: vec![unit(T_CLAIM)],
    };
    assert_token(&fx.classify(&genesis_state, &dep), "malformed_shape");
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
    let two = Span::new(tum(ACCT_A), width_at_last(ACCT_A.len(), 2)).expect("T12");
    assert_eq!(single_address(&[two]), None);
    // Adjacent zeros: T4-invalid as an address, legal as a carrier tumbler.
    let invalid = Span::new(tum(&[1, 1, 0, 5, 0, 1, 0, 0, 1]), width_at_last(9, 1)).expect("T12");
    assert_eq!(single_address(&[invalid]), None);
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
    assert_token(
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
    assert_token(
        &fx.classify(&IdentityState::genesis(), &dep),
        "malformed_shape",
    );
}

/// Corpus: a `ty` slot of NO spans · one whose single span is a CONTENT
/// I-span of the home · a `ty` of TWO spans, one of which IS
/// `subtree_of(T_enroll)` · a `ty` of ONE span CONTAINING
/// `subtree_of(T_enroll)` · one CONTAINED BY it — `NotCredential` on each
/// (AUTH-2.22's exactly-one-span-`Equal` rule: every other arity, and every
/// overlap class other than `Equal`, in BOTH containment directions).
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
        assert!(matches!(v, Verdict::NotCredential), "expected NotCredential");
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

// -------------------------------------------------- key-set semantics

/// `ACCT_A` seeded with an anchor key and a device key — the state the
/// enrolled-side claims below start from.
fn seeded(fx: &mut Fixture) -> IdentityState {
    seed_own(
        fx,
        &IdentityState::genesis(),
        ACCT_A,
        &[(1, true), (2, false)],
    )
}

/// The same account with the device key retired — the state the
/// retirement-side claims below start from.
fn seeded_then_retired(fx: &mut Fixture) -> IdentityState {
    let st = seeded(fx);
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[2]));
    let (st, v) = fx.step(&st, &dep);
    assert_honored(&v);
    st
}

/// AUTH-1.31 — `contains` and `is_anchor` report membership NOW and the flag
/// the key entered under; a seeded account's set is non-empty.
#[test]
fn enrolled_reads_report_membership_and_the_anchor_flag() {
    let mut fx = Fixture::new();
    let st = seeded(&mut fx);
    let set = st.key_set(&addr(ACCT_A));
    assert!(!set.is_empty());
    assert!(set.contains(&fp(1)) && set.is_anchor(&fp(1)));
    assert!(set.contains(&fp(2)) && !set.is_anchor(&fp(2)));
}

/// AUTH-1.31 — `enrolled()` answers FINGERPRINT order, not the order the
/// record listed the keys in (the ordering the realm genesis-set framing
/// reuses, AUTH-2.119). The record here lists its lines in DESCENDING
/// fingerprint order, so a set iterating in record order answers the exact
/// reverse of the claim.
#[test]
fn enrolled_iterates_in_fingerprint_order_not_record_order() {
    let mut fx = Fixture::new();
    let mut ascending = [1u8, 2, 3, 4];
    ascending.sort_by_key(|&i| fp(i));
    let record: Vec<(u8, bool)> = ascending.iter().rev().map(|&i| (i, false)).collect();
    let st = seed_own(&mut fx, &IdentityState::genesis(), ACCT_A, &record);

    let got: Vec<_> = st
        .key_set(&addr(ACCT_A))
        .enrolled()
        .map(|(f, _)| *f)
        .collect();
    let want: Vec<_> = ascending.iter().map(|&i| fp(i)).collect();
    assert_eq!(got, want);
}

/// AUTH-1.31 — `retired()` answers FINGERPRINT order, whatever order the
/// retirement record named the fingerprints in.
#[test]
fn retired_iterates_in_fingerprint_order() {
    let mut fx = Fixture::new();
    let mut ascending = [1u8, 2, 3];
    ascending.sort_by_key(|&i| fp(i));
    // A fourth key stays enrolled, so retiring these three is not
    // `would_empty` (I3).
    let st = seed_own(
        &mut fx,
        &IdentityState::genesis(),
        ACCT_A,
        &[(1, false), (2, false), (3, false), (4, false)],
    );
    let named: Vec<u8> = ascending.iter().rev().copied().collect();
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&named));
    let (st, v) = fx.step(&st, &dep);
    assert_honored(&v);

    let got: Vec<_> = st
        .key_set(&addr(ACCT_A))
        .retired()
        .map(|(f, _)| *f)
        .collect();
    let want: Vec<_> = ascending.iter().map(|&i| fp(i)).collect();
    assert_eq!(got, want);
}

/// AUTH-2.59 — `keyed_accounts()` answers ADDRESS order, not the order the
/// accounts were seeded in; `/dump`'s identity section is built from this.
#[test]
fn keyed_accounts_iterates_in_address_order() {
    let mut fx = Fixture::new();
    let st = IdentityState::genesis();
    // Seeded high address first, so insertion order is the reverse of the
    // claim.
    let st = seed_own(&mut fx, &st, ACCT_B, &[(8, true)]);
    let st = seed_own(&mut fx, &st, ACCT_A, &[(7, true)]);
    let st = seed_own(&mut fx, &st, CLAIMANT, &[(9, true)]);

    let got: Vec<_> = st.keyed_accounts().map(|(a, _)| a.clone()).collect();
    let mut want = vec![addr(ACCT_B), addr(ACCT_A), addr(CLAIMANT)];
    want.sort();
    assert_eq!(got, want);
}

/// I9's conformance arm (AUTH-2.104) — re-listing an enrolled device key
/// under the `anchor` flag answers `nothing_changed` and the flag stays
/// `false`: a fingerprint's flag is fixed by the record that FIRST enrolls
/// it, for the fingerprint's lifetime.
#[test]
fn re_listing_an_enrolled_key_under_the_anchor_flag_changes_nothing() {
    let mut fx = Fixture::new();
    let st = seeded(&mut fx);
    let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &enroll_payload(&[(2, true)]));
    let (next, v) = fx.step(&st, &dep);
    assert_token(&v, "nothing_changed");
    assert_eq!(next, st);
    assert!(!next.key_set(&addr(ACCT_A)).is_anchor(&fp(2)));
}

/// AUTH-2.74 — an honored retirement names the removed fingerprints in its
/// effect, and the key leaves `enrolled` for `retired`.
#[test]
fn retiring_an_enrolled_key_names_it_in_the_effect_and_removes_it() {
    let mut fx = Fixture::new();
    let st = seeded(&mut fx);
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[2]));
    let (next, v) = fx.step(&st, &dep);
    match assert_honored(&v) {
        Effect::Retire { account, removed } => {
            assert_eq!(*account, addr(ACCT_A));
            assert_eq!(*removed, vec![fp(2)]);
        }
        other => panic!("expected a retire effect, got {other:?}"),
    }
    let set = next.key_set(&addr(ACCT_A));
    assert!(!set.contains(&fp(2)));
    assert!(!set.is_anchor(&fp(2)));
    assert_eq!(set.retired().count(), 1);
}

/// AUTH-1.30 — each retired row carries the flag its key was ENROLLED under,
/// both ways: an anchor key stays senior in the retired map, a device key
/// stays ordinary. The lifetime claim is what makes "was that a senior key"
/// a head read.
#[test]
fn retired_row_carries_the_flag_the_key_was_enrolled_under() {
    let mut fx = Fixture::new();
    let st = seed_own(
        &mut fx,
        &IdentityState::genesis(),
        ACCT_A,
        &[(1, true), (2, false), (3, false)],
    );
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[1, 2]));
    let (st, v) = fx.step(&st, &dep);
    assert_honored(&v);

    let set = st.key_set(&addr(ACCT_A));
    let flags: BTreeMap<_, _> = set.retired().collect();
    assert_eq!(
        flags.get(&fp(1)),
        Some(&true),
        "the anchor key's flag survives retirement"
    );
    assert_eq!(
        flags.get(&fp(2)),
        Some(&false),
        "the device key's flag survives retirement"
    );
}

/// AUTH-2.74 — retiring an already-retired fingerprint touches nothing:
/// `removed = F ∩ enrolled = ∅`, so the record is `nothing_changed`.
#[test]
fn retiring_an_already_retired_key_changes_nothing() {
    let mut fx = Fixture::new();
    let st = seeded_then_retired(&mut fx);
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[2]));
    let (next, v) = fx.step(&st, &dep);
    assert_token(&v, "nothing_changed");
    assert_eq!(next, st);
}

/// I4 (AUTH-2.98) — a retired fingerprint never re-enters its account's set:
/// the re-enrollment line is outside `added` whatever flag it carries.
#[test]
fn a_retired_fingerprint_never_re_enrolls() {
    let mut fx = Fixture::new();
    let st = seeded_then_retired(&mut fx);
    let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &enroll_payload(&[(2, true)]));
    let (next, v) = fx.step(&st, &dep);
    assert_token(&v, "nothing_changed");
    assert_eq!(next, st);
}

/// I3 (AUTH-2.97) — a retirement naming the WHOLE enrolled set is inert
/// whole: `would_empty`, so non-emptiness stays monotone.
#[test]
fn retiring_the_whole_enrolled_set_is_would_empty() {
    let mut fx = Fixture::new();
    let st = seeded_then_retired(&mut fx);
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[1]));
    let (next, v) = fx.step(&st, &dep);
    assert_token(&v, "would_empty");
    assert_eq!(next, st);
}

/// The claim walk end to end: keyless refusal, honored claim, first-wins
/// (AUTH-2.67; I6 AUTH-2.101), and the from≠H shape refusal (AUTH-2.48).
#[test]
fn board_admits_one_claim_and_only_from_a_keyed_account() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();

    // Keyless claimant, pre-claim: condition 5.
    let dep = fx.claim_dep(&doc1(CLAIMANT), CLAIMANT);
    assert_token(&fx.classify(&genesis_state, &dep), "claimant_keyless");

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
    let dep2 = fx.claim_dep(&doc1(ACCT_B), ACCT_B);
    let (st3, v) = fx.step(&st, &dep2);
    assert_token(&v, "already_claimed");
    assert_eq!(st3.claimant(), Some(&addr(CLAIMANT)));

    // A claim whose `from` is not the home's account: shape (condition 1).
    let dep = Dep {
        home: doc1(CLAIMANT),
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
    let genesis_state = IdentityState::genesis();
    let st = seed_own(
        &mut fx,
        &genesis_state,
        ACCT_A,
        &[(1, true), (2, false), (3, false)],
    );
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[3]));
    let (st, v) = fx.step(&st, &dep);
    assert_honored(&v);
    let st = seed_own(&mut fx, &st, CLAIMANT, &[(9, true)]);
    let st = claim_as(&mut fx, &st, CLAIMANT);

    let bytes = bincode::serialize(&st).expect("serialize IdentityState");
    let back: IdentityState = bincode::deserialize(&bytes).expect("deserialize IdentityState");
    assert_eq!(back, st);
    assert_eq!(back.claimant(), Some(&addr(CLAIMANT)));
    assert!(back.key_set(&addr(ACCT_A)).contains(&fp(1)));
}
