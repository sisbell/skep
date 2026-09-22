//! The fold corpus (AUTH-2.96): payload vectors over `record_bytes`
//! (AUTH-2.38–2.45), step-order vectors (AUTH-2.66), verdict-token vectors
//! (AUTH-2.67–2.76, AUTH-2.127), board-state vectors (AUTH-2.62), shape
//! vectors (AUTH-2.22, AUTH-2.46–2.48), and the key-set semantics
//! (AUTH-1.30–1.31, I9's conformance arm).

use crate::common;

use std::collections::BTreeMap;

use common::*;
use skep_address::{Address, Span, Tumbler};
use skep_identity::{
    encode_enroll, encode_retire, record_bytes, single_address, Effect, Enrolled, Enrollment,
    Fingerprint, FoldCtx, IdentityState, Owner, TypeAddrs, Values, Verdict, MAX_RECORD_BYTES,
};

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
/// ENDSET order, never the address order (AUTH-2.3 span binding). The
/// canonical record is split at its closing `]}`, its HEAD minted ABOVE its
/// TAIL: endset order (head first) reassembles it, address order (tail first)
/// is not a JSON record.
#[test]
fn endset_order_governs_concatenation() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let record = enroll_payload(&[(1, false)]);
    let split = record.len() - 2; // the closing "]}" is the last two bytes
    let tail_span = fx.mint(&doc1(ACCT_A), &[&record[split..]]); // lower address
    let head_span = fx.mint(&doc1(ACCT_A), &[&record[..split]]); // higher address
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![head_span[0].clone(), tail_span[0].clone()],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_honored(&fx.classify(&genesis_state, &dep));

    // The address-order reading concatenates tail-first and is not a record —
    // proving the honored fold above really was endset order.
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![tail_span[0].clone(), head_span[0].clone()],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:bad_record",
    );
}

/// Corpus: a repeated span CUT AT ENTRY BOUNDARIES repeats its entries
/// (AUTH-2.4). A retirement split into the open, entry 1, a comma-prefixed
/// entry 2, and the close: naming entry 2's span twice yields a canonical body
/// with a duplicate at entry 3 — `duplicate_key:3`, the ENTRY index.
#[test]
fn repeated_spans_repeat_their_entries() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let open = b"{\"type\":\"skep-retire\",\"fingerprints\":[".to_vec();
    let entry1 = format!("\"{}\"", fp(1).to_hex());
    let entry2 = format!(",\"{}\"", fp(2).to_hex());
    let close = b"]}".to_vec();
    let spans = fx.mint(
        &doc1(ACCT_A),
        &[open.as_slice(), entry1.as_bytes(), entry2.as_bytes(), close.as_slice()],
    );
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![
            spans[0].clone(),
            spans[1].clone(),
            spans[2].clone(),
            spans[2].clone(), // entry 2 repeated ⇒ a duplicate at entry 3
            spans[3].clone(),
        ],
        to: vec![unit(ACCT_A)],
        ty: vec![unit(T_RETIRE)],
    };
    assert_token(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:duplicate_key:3",
    );
}

/// Corpus: the same repeat CUT ANYWHERE ELSE (AUTH-2.96's row, its second
/// input; AUTH-2.4). The same retirement, entry 2 cut MID-ENTRY — two span
/// boundaries inside the fingerprint's hex. Each span named once, the record
/// folds: the cut is no fault of its own (spans MAY split anything). Any of
/// the three named twice and the concatenation is no canonical record — the
/// head and the tail break the JSON, the middle leaves a 96-hex fingerprint —
/// `bad_record`, inert, never `duplicate_key`: no entry repeats, a piece of
/// one does.
#[test]
fn a_repeated_span_cut_mid_entry_is_bad_record() {
    let mut fx = Fixture::new();
    let st = seed_own(
        &mut fx,
        &IdentityState::genesis(),
        ACCT_A,
        &[(1, false), (2, false), (3, false)],
    );
    let open = b"{\"type\":\"skep-retire\",\"fingerprints\":[".to_vec();
    let entry1 = format!("\"{}\"", fp(1).to_hex());
    let hex2 = fp(2).to_hex();
    let head = format!(",\"{}", &hex2[..16]);
    let middle = &hex2[16..48];
    let tail = format!("{}\"", &hex2[48..]);
    let close = b"]}".to_vec();
    let spans = fx.mint(
        &doc1(ACCT_A),
        &[
            open.as_slice(),
            entry1.as_bytes(),
            head.as_bytes(),
            middle.as_bytes(),
            tail.as_bytes(),
            close.as_slice(),
        ],
    );
    let retirement = |from: Vec<Span>| Dep {
        home: doc1(ACCT_A),
        from,
        to: vec![unit(ACCT_A)],
        ty: vec![unit(T_RETIRE)],
    };

    // Each span once: the bytes are the canonical retirement, and it folds.
    assert_eq!(
        record_bytes(&fx.ctx, &doc1(ACCT_A), &spans).expect("home-minted spans read"),
        retire_payload(&[1, 2])
    );
    match assert_honored(&fx.classify(&st, &retirement(spans.clone()))) {
        Effect::Retire { removed, .. } => assert_eq!(*removed, vec![fp(1), fp(2)]),
        other => panic!("expected a retire effect, got {other:?}"),
    }

    // A piece of entry 2 named twice — the head, the middle, the tail.
    for repeated in [2, 3, 4] {
        let mut from = spans.clone();
        from.insert(repeated, spans[repeated].clone());
        let (next, v) = fx.step(&st, &retirement(from));
        assert_token(&v, "malformed_payload:bad_record");
        assert_eq!(next, st, "span {repeated} named twice: the table is unchanged");
    }
}

/// Corpus: the CANONICAL-BY-CONCATENATION cell (AUTH-2.4's condition, as
/// RES-199 item 17 and RES-202 item 11 leave it; AUTH-2.96's row, its last
/// clause). The same retirement cut at offset `k` INSIDE entry 1's hex and at
/// the SAME offset inside entry 2's, so the middle span runs from one
/// fingerprint's offset to the next's. Named twice, it spells a well-formed
/// fingerprint between the two — entry 2's head on entry 1's tail — and the
/// concatenation IS a canonical three-entry retirement, one its depositor
/// could have written whole. Neither the `duplicate_key` cell nor the
/// `bad_record` one: the read binds the spans verbatim (AUTH-2.3) and the
/// arms fold the record it spells — `Honored(Retire)` removing the two
/// enrolled fingerprints, the spelled middle one — enrolled nowhere —
/// filtered out by `F ∩ enrolled` (AUTH-2.74), the third key standing.
#[test]
fn a_repeated_span_from_one_fingerprints_offset_to_the_nexts_is_canonical_by_concatenation() {
    let mut fx = Fixture::new();
    let st = seed_own(
        &mut fx,
        &IdentityState::genesis(),
        ACCT_A,
        &[(1, false), (2, false), (3, false)],
    );
    let (hex1, hex2) = (fp(1).to_hex(), fp(2).to_hex());
    let retirement = |from: Vec<Span>| Dep {
        home: doc1(ACCT_A),
        from,
        to: vec![unit(ACCT_A)],
        ty: vec![unit(T_RETIRE)],
    };
    for k in [1usize, 32, 63] {
        let head = format!("{{\"type\":\"skep-retire\",\"fingerprints\":[\"{}", &hex1[..k]);
        let middle = format!("{}\",\"{}", &hex1[k..], &hex2[..k]);
        let tail = format!("{}\"]}}", &hex2[k..]);
        let spans = fx.mint(
            &doc1(ACCT_A),
            &[head.as_bytes(), middle.as_bytes(), tail.as_bytes()],
        );

        // Each span once: the canonical two-entry retirement.
        assert_eq!(
            record_bytes(&fx.ctx, &doc1(ACCT_A), &spans).expect("home-minted spans read"),
            retire_payload(&[1, 2]),
            "offset {k}: each span once"
        );

        // The middle named twice: the bytes ARE the canonical retirement of
        // entry 1, the spelled fingerprint, entry 2 — nothing the read did
        // to them, only what the endset named (AUTH-2.3).
        let spelled = Fingerprint::parse_hex(&format!("{}{}", &hex2[..k], &hex1[k..]))
            .expect("two halves of lowercase hex spell a fingerprint");
        assert!(
            ![fp(1), fp(2), fp(3)].contains(&spelled),
            "offset {k}: the spelled fingerprint is enrolled nowhere"
        );
        let twice = vec![spans[0].clone(), spans[1].clone(), spans[1].clone(), spans[2].clone()];
        assert_eq!(
            record_bytes(&fx.ctx, &doc1(ACCT_A), &twice).expect("home-minted spans read"),
            encode_retire(&[fp(1), spelled, fp(2)]).into_bytes(),
            "offset {k}: the concatenation is a canonical record"
        );

        // …and it folds by the arms as that record: the two enrolled
        // fingerprints retire, the spelled one is `F ∩ enrolled`'s discard,
        // the third key stands.
        let (next, v) = fx.step(&st, &retirement(twice));
        match assert_honored(&v) {
            Effect::Retire { removed, .. } => {
                assert_eq!(*removed, vec![fp(1), fp(2)], "offset {k}: `removed` in record order")
            }
            other => panic!("offset {k}: expected a retire effect, got {other:?}"),
        }
        let set = next.key_set(&addr(ACCT_A));
        assert!(!set.contains(&fp(1)) && !set.contains(&fp(2)), "offset {k}: both named keys retired");
        assert!(set.contains(&fp(3)), "offset {k}: the third key stands");
    }
}

/// Corpus: a FROM span running one position past what the home minted —
/// `missing_value` (AUTH-2.45: an endset names addresses verbatim).
#[test]
fn span_past_the_mint_is_missing_value() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let home = doc1(ACCT_A);
    // Two minted positions; the span reaches exactly ONE past them —
    // `missing_value` fires in `record_bytes`, so the bytes need not parse.
    fx.mint(&home, &[b"one", b"two"]);
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

/// AUTH-2.36/AUTH-2.3 — the read's ANSWER, not merely the verdict it leads
/// to: the FROM spans' bytes concatenated in ENDSET ORDER, verbatim. Every
/// other payload vector reads this function through a parse fault, which
/// watches only the normalizations the GRAMMAR would notice. A read that
/// stripped a trailing `\r` is the sharp case: `\r` is an ordinary payload
/// byte (AUTH-2.6), so every other vector in the corpus stays green while a
/// mirror is handed different bytes than the origin. (A trim that also ate
/// the line's `\n` is caught by the grammar-sensitive vectors; the byte the
/// grammar does not judge is the one nothing else watches.) `record_bytes` is
/// `pub` for the non-folding reader AUTH-2.37 requires to LINK it rather than
/// re-implement it, and this is the only vector that calls it as that reader
/// does.
#[test]
fn record_bytes_answers_the_spans_bytes_verbatim_in_endset_order() {
    let mut fx = Fixture::new();
    let home = doc1(ACCT_A);
    // Bytes a helpful read would be tempted to touch — a CR, a trailing
    // 0x20, uppercase hex. Judging them is the GRAMMAR's business
    // (AUTH-2.6, AUTH-2.10, AUTH-2.17), never the read's.
    let spans = fx.mint(&home, &[b"one\r", b"two ", b"THREE"]);
    let got = record_bytes(&fx.ctx, &home, &spans).expect("home-minted spans read");
    assert_eq!(got, b"one\rtwo THREE".to_vec());

    // ENDSET order, not address order: the same three spans, named backwards.
    let reversed: Vec<_> = spans.iter().rev().cloned().collect();
    let got = record_bytes(&fx.ctx, &home, &reversed).expect("home-minted spans read");
    assert_eq!(got, b"THREEtwo one\r".to_vec());
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

/// AUTH-2.38 item 3 — home anchoring is decided BEFORE a byte of the span is
/// read, so a span in ANOTHER document answers `foreign_content` whether or
/// not that document ever minted the position. Every other foreign span in
/// the corpus is minted, so a home check moved down into the walk — the
/// natural place for it once the position is in hand — keeps answering
/// `foreign_content` for those and answers `missing_value` here.
#[test]
fn a_foreign_span_is_foreign_content_even_where_nothing_was_minted() {
    let fx = Fixture::new(); // nothing minted in ACCT_B at all
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![content_run(&doc1(ACCT_B), 1, 1)],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(
        &fx.classify(&IdentityState::genesis(), &dep),
        "malformed_payload:foreign_content",
    );
}

/// AUTH-2.44 — HOME ANCHORING is document EQUALITY, never containment: bytes
/// minted in a VERSION MEMBER of the home (`home·1`, a different document the
/// home's address is a proper prefix of) are `foreign_content`. Every other
/// foreign span in the corpus sits under another ACCOUNT, where equality and
/// containment agree — so a check spelled with M1's `under_document`, or with
/// `is_prefix`, keeps those green and honors this record.
#[test]
fn a_version_members_bytes_are_foreign_to_the_document_it_versions() {
    let mut fx = Fixture::new();
    let home = doc1(ACCT_A);
    let from = fx.mint(&first_version_of(&home), &[&enroll_payload(&[(1, true)])]);
    let dep = Dep {
        home,
        from,
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(
        &fx.classify(&IdentityState::genesis(), &dep),
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
    fx.mint(&doc1(ACCT_A), &[b"one", b"two"]);
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
    // `empty`/`bad_record`, which the count-off-width misreading answers.
    assert_token(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:missing_value",
    );
}

/// AUTH-2.42 — the reach walk's membership test is M1 `Span::contains`' rule
/// (`start ≤ pos < reach`) taken against a reach derived once per span,
/// because `contains` recomputes `start ⊕ width` per call and `⊕`'s cost is
/// the WIDTH's component count, which T12 does not bound. Two spellings of
/// one rule, so the agreement is stated rather than assumed: over widths
/// acting at every admissible position, with and without a trailing tail, and
/// over ordinals below, at, inside and above the reach.
#[test]
fn reach_walk_membership_agrees_with_span_contains() {
    let home = doc1(ACCT_A);
    let start = content_pos(&home, 4);
    for action_point in 0..start.len() {
        for tail in [0usize, 1, 7] {
            let mut w = vec![0u32; start.len() + tail];
            w[action_point] = 1;
            let span = Span::new(start.clone(), tum(&w)).expect("T12-valid width");
            let reach = span.reach();
            for ord in [1u32, 3, 4, 5, 9, 1_000] {
                let pos = content_pos(&home, ord);
                assert_eq!(
                    span.contains(&pos),
                    *span.start() <= pos && pos < reach,
                    "action point {action_point}, tail {tail}, ordinal {ord}"
                );
            }
        }
    }
}

/// AUTH-2.42 — a width whose component COUNT exceeds the start's. T12 bounds
/// the width's ACTION POINT and not its length, so a wire-expressible span can
/// carry an arbitrarily long width tail, which `⊕` copies verbatim into the
/// reach. The verdict is exactly the tail-free span's
/// ([`reach_walk_never_a_count_off_width`]'s), and the work scales with the
/// POSITIONS walked rather than with the width's length — a corpus seed worth
/// promoting to the fuzzing tier, where the wall-clock oracle lives.
#[test]
fn a_long_width_tail_changes_no_verdict() {
    let mut fx = Fixture::new();
    let home = doc1(ACCT_A);
    fx.mint(&home, &[b"one", b"two"]);
    let start = content_pos(&home, 1);
    // The action point `reach_walk_never_a_count_off_width` uses — at the
    // subspace, above the ordinal — plus 4096 trailing components T12 admits
    // and nothing in the read bounds.
    let mut w = vec![0u32; start.len() + 4096];
    w[start.len() - 2] = 1;
    let dep = Dep {
        home: home.clone(),
        from: vec![Span::new(start, tum(&w)).expect("T12-valid width")],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    assert_token(
        &fx.classify(&IdentityState::genesis(), &dep),
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
    // Two atoms whose SUM exceeds the cap though each is one POSITION —
    // too_large is BYTES, never positions (AUTH-1.20). The bytes need not
    // parse: the cap fires in `record_bytes`, ahead of the grammar.
    let head = vec![b'{'; 16];
    let body = vec![b'x'; MAX_RECORD_BYTES - 6]; // under cap alone; over with the head
    let spans = fx.mint(&doc1(ACCT_A), &[&head, &body]);
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
/// honored (AUTH-2.3: multi-span records are ordinary). The canonical two-key
/// record is split at entry boundaries into the open, entry 1, and
/// comma-entry-2-plus-close.
#[test]
fn three_atom_record_folds() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let record = encode_enroll(&[
        Enrollment::new(key(1), true, None).unwrap(),
        Enrollment::new(key(2), false, None).unwrap(),
    ]);
    let bracket = record.find('[').expect("the keys array opens") + 1;
    let comma = record.find("},{").expect("two entries meet") + 1;
    let spans = fx.mint(
        &doc1(ACCT_A),
        &[
            record[..bracket].as_bytes(),
            record[bracket..comma].as_bytes(),
            record[comma..].as_bytes(),
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

/// The key entries [`cap_sized_enroll_payload`] writes — chosen so that a
/// `MAX_RECORD_BYTES` budget of label-free `{"alg":…,"key":…,"anchor":false}`
/// entries leaves room for the label that pads the record onto the mark; the
/// helper asserts that as a fixture precondition. Under AUTH-2.130's canonical
/// spelling the envelope is 32 B, each label-free entry 105 B plus a 1 B
/// comma, so 32 + 617·105 + 616 = 65 433 ≤ 65 536 and 618 entries would
/// overflow — the 897 of the retired line form become 617 here.
const CAP_SIZED_LINES: u32 = 617;

/// An enrolment record of exactly `MAX_RECORD_BYTES + over` bytes:
/// [`CAP_SIZED_LINES`] key entries, the first carrying a label sized to land
/// the total on the mark. Built FROM the constant, so a change to the cap
/// moves the record with it and `max_record_bytes_is_64_kib` stays the one
/// assertion that discovers it.
fn cap_sized_enroll_payload(over: usize) -> Vec<u8> {
    let mut entries: Vec<Enrollment> = (0..CAP_SIZED_LINES)
        .map(|i| Enrollment::new(wide_key(i), false, None).expect("label-free"))
        .collect();
    let base_len = encode_enroll(&entries).len();
    // Adding a label of L chars to a label-free entry adds 11 + L bytes: the
    // `,"label":"…"` wrapper is 11 bytes (AUTH-2.130's canonical spelling).
    assert!(
        base_len + 12 <= MAX_RECORD_BYTES,
        "fixture arithmetic: {base_len} bytes of {CAP_SIZED_LINES} key entries leaves no room \
         for a label under a {MAX_RECORD_BYTES}-byte cap"
    );
    let pad = MAX_RECORD_BYTES - base_len + over;
    entries[0] = Enrollment::new(wide_key(0), false, Some("x".repeat(pad - 11))).expect("label");
    let payload = encode_enroll(&entries).into_bytes();
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
    let record = enroll_payload(&[(1, false)]);
    let spans = fx.mint(&doc1(ACCT_A), &[record.as_slice()]);
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

/// Corpus: an ENROLLMENT homed in a PUBLISHED second document of its account,
/// payload unparseable — `malformed_payload` naming the fault, never
/// `not_doc_one` (AUTH-2.127: the payload precedes the home pin).
#[test]
fn an_enrollment_payload_precedes_the_home_pin() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let dep = fx.enroll_dep(&doc2(ACCT_A), ACCT_A, b"zzz not a record\n");
    assert_token(
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
        assert_token(&fx.classify(&genesis_state, &dep), "malformed_shape");
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
    assert_token(
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
    assert_token(&v, "not_genesis_registry");
    assert_eq!(next, st);
}

/// AUTH-2.69/AUTH-2.74 — `nothing_changed` is the HOLDER arms' token alone: a
/// record homed outside the subject's own space answers its home's refusal
/// even where every line would change nothing. Every other `nothing_changed`
/// vector is own-space, and the latch and ancestor-retirement vectors each
/// carry a line that WOULD change the set — so, on a SEEDED account, a
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
    assert_token(&fx.classify(&st, &dep), "not_genesis_registry");
    // The registry retires a key NESTED never held: no ancestor retires.
    let dep = fx.retire_dep(&doc1(ORG), NESTED, &retire_payload(&[5]));
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
    assert_token(&v, "not_doc_one");
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
    assert_token(
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
    assert_token(&fx.classify(&IdentityState::genesis(), &dep), "not_doc_one");
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
    assert_token(
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
    assert_token(&fx.classify(&IdentityState::genesis(), &dep), "not_doc_one");
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
    assert_token(&classify_under_an_element_level_owner(), "not_doc_one");
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
fn seat_accounts(fx: &mut Fixture, addrs: &[&[u32]]) {
    for acct in addrs {
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
        assert_token(&fx.classify(&st, &dep), "not_genesis_registry");
    }
    // After B is keyed and the board is claimed, still.
    let st = seed_own(&mut fx, &st, ACCT_A, &[(1, true)]);
    let st = seed_own(&mut fx, &st, CLAIMANT, &[(9, true)]);
    let st = claim_as(&mut fx, &st, CLAIMANT);
    let dep = fx.enroll_dep(&doc1(ACCT_A), B_FIRST_CHILD, &enroll_payload(&[(2, false)]));
    assert_token(&fx.classify(&st, &dep), "not_genesis_registry");
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
    assert_token(&fx.classify(&st, &dep), "not_genesis_registry");

    // One level down, its own set empty: the walk climbs the empty subdivision
    // to B's set (the comparand, AUTH-2.71's row 2009).
    let dep = fx.enroll_dep(&doc1(B_SUBDIVISION), B_SUB_DEEP, &enroll_payload(&[(1, true)]));
    assert_token(&fx.classify(&st, &dep), "not_genesis_registry");
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

// -------------------------------------------------- key-set semantics

/// `ACCT_A` seeded with an anchor key and a non-anchor key — the state the
/// enrolled-side claims below start from.
fn seeded(fx: &mut Fixture) -> IdentityState {
    seed_own(
        fx,
        &IdentityState::genesis(),
        ACCT_A,
        &[(1, true), (2, false)],
    )
}

/// The same account with the non-anchor key retired — the state the
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
/// accounts were seeded in: the enumeration the spec builds `/dump`'s identity
/// section from, a section no dump renders as built.
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

/// I9's conformance arm (AUTH-2.104) — re-listing an enrolled non-anchor key
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

/// AUTH-2.69 — the holder post: `added` is exactly the lines whose
/// fingerprints are neither ENROLLED nor RETIRED, whatever flag the line
/// carries (I4 AUTH-2.98, I9 AUTH-2.104), and the filtered lines do NOT ride
/// in on the new key's coat-tails.
/// `re_listing_an_enrolled_key_under_the_anchor_flag_changes_nothing` and
/// `a_retired_fingerprint_never_re_enrolls` pin records where EVERY line is
/// filtered out — which an `added` computed as "all the lines, if any line is
/// new" also satisfies; this mixed record is what tells them apart. It is
/// also the corpus's only assertion of an `Effect::Enroll`.
#[test]
fn a_holder_enrollment_adds_only_the_lines_that_are_neither_enrolled_nor_retired() {
    let mut fx = Fixture::new();
    // enrolled = {fp(1): anchor}, retired = {fp(2): non-anchor}.
    let st = seeded_then_retired(&mut fx);
    // Line 2 re-lists the ENROLLED key under the OPPOSITE flag; line 3 the
    // RETIRED one; line 4 is new, and an anchor.
    let dep = fx.enroll_dep(
        &doc1(ACCT_A),
        ACCT_A,
        &enroll_payload(&[(1, false), (2, true), (3, true)]),
    );
    let (next, v) = fx.step(&st, &dep);
    match assert_honored(&v) {
        Effect::Enroll { account, added } => {
            assert_eq!(*account, addr(ACCT_A));
            assert_eq!(
                *added,
                vec![Enrolled {
                    key: key(3),
                    anchor: true
                }],
                "only the new line is added, with the flag that line carries"
            );
        }
        other => panic!("expected an enroll effect, got {other:?}"),
    }
    let set = next.key_set(&addr(ACCT_A));
    assert!(set.contains(&fp(3)), "the new key is enrolled");
    assert!(set.is_anchor(&fp(3)), "under the flag its line carried");
    assert!(
        set.is_anchor(&fp(1)),
        "I9: the re-listed key keeps its FIRST flag"
    );
    assert!(
        !set.contains(&fp(2)),
        "I4: the retired key does not re-enter"
    );
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

/// AUTH-1.31/AUTH-1.30 — `is_anchor` answers NOW and `retired()` the key's
/// lifetime, and the two disagree for exactly one key: a retired ANCHOR key.
/// `retiring_an_enrolled_key_names_it_in_the_effect_and_removes_it` reads
/// `is_anchor` of a key that was never an anchor, so an `is_anchor` that also
/// consulted the retired map passes it — and fails here.
#[test]
fn a_retired_anchor_key_is_no_longer_an_anchor() {
    let mut fx = Fixture::new();
    let st = seeded(&mut fx); // fp(1) anchor, fp(2) non-anchor
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[1]));
    let (st, v) = fx.step(&st, &dep);
    assert_honored(&v); // anchor-blind (AUTH-2.75): the only anchor may retire
    let set = st.key_set(&addr(ACCT_A));
    assert!(!set.contains(&fp(1)), "retired: no longer enrolled");
    assert!(!set.is_anchor(&fp(1)), "is_anchor answers NOW");
    assert_eq!(
        set.retired()
            .find(|(f, _)| **f == fp(1))
            .map(|(_, anchor)| anchor),
        Some(true),
        "the retired row still says it WAS an anchor"
    );
}

/// AUTH-1.30 — each retired row carries the flag its key was ENROLLED under,
/// both ways: an anchor key stays an anchor in the retired map, a non-anchor
/// key stays a non-anchor. The lifetime claim is what makes "was that an
/// ANCHOR key" a head read.
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
        "the non-anchor key's flag survives retirement"
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

/// I3 (AUTH-2.97) — the whole-set test is SET EQUALITY, never a size
/// coincidence: a retirement naming every enrolled fingerprint AND a
/// fingerprint that is enrolled nowhere is still `would_empty`. `removed` is
/// `F ∩ enrolled` (AUTH-2.74), so the stranger is filtered out and the two
/// sizes agree. A `removed` that carried the stranger — or a `WouldEmpty`
/// test read off the RECORD's length — honors this record, empties the
/// account's set, and voids I3 and AUTH-1.36. Every other retirement vector
/// names only fingerprints the account has held, so this is the one that
/// tells the intersection from the record.
#[test]
fn retiring_the_whole_set_plus_a_stranger_is_still_would_empty() {
    let mut fx = Fixture::new();
    // enrolled = {fp(1), fp(2)}; key 5 is enrolled nowhere on this board.
    let st = seeded(&mut fx);
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[1, 2, 5]));
    let (next, v) = fx.step(&st, &dep);
    assert_token(&v, "would_empty");
    assert_eq!(next, st);
    assert!(
        !next.key_set(&addr(ACCT_A)).is_empty(),
        "I3: an account's set never re-empties"
    );
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
    let second_claim = fx.claim_dep(&doc1(ACCT_B), ACCT_B);
    let (st, v) = fx.step(&st, &second_claim);
    assert_token(&v, "already_claimed");
    assert_eq!(st.claimant(), Some(&addr(CLAIMANT)));

    // A claim whose `from` is not the home's account: shape (condition 1).
    let dep = Dep {
        home: doc1(CLAIMANT),
        from: vec![unit(ACCT_A)],
        to: vec![],
        ty: vec![unit(T_CLAIM)],
    };
    assert_token(&fx.classify(&st, &dep), "malformed_shape");
}

/// AUTH-1.40 — the checkpointed frame AROUND `Enrolled`: `KeySet`'s two maps
/// in declaration order, each a length then its rows, a `Fingerprint` key as
/// its thirty-two raw bytes, and a RETIRED row as the ONE anchor byte
/// AUTH-1.29 fixes. `enrolled_checkpoint_encoding_is_pinned` owns the
/// `Enrolled` row; this owns everything around it. The edit it is here for is
/// the tempting one — storing the whole `Enrolled` in `retired` so the flag
/// comes along instead of being carried by hand — which keeps `retired()`'s
/// `(&Fingerprint, bool)` signature, passes every other vector, and silently
/// rewrites every checkpoint's bytes.
#[test]
fn key_set_checkpoint_encoding_is_pinned() {
    let mut fx = Fixture::new();
    // enrolled = {fp(1): anchor}, retired = {fp(2): non-anchor} — ONE row in
    // each map, so fingerprint order is not a variable in this expectation.
    let st = seeded_then_retired(&mut fx);

    let mut want: Vec<u8> = Vec::new();
    want.extend_from_slice(&1u64.to_le_bytes()); // `enrolled`: one row
    want.extend_from_slice(fp(1).as_bytes()); // the map key: 32 raw bytes
    want.extend_from_slice(&0u32.to_le_bytes()); // the value: Ed25519 variant
    want.extend_from_slice(&[1u8; 32]); // key(1)'s raw bytes
    want.push(1); // the anchor flag
    want.extend_from_slice(&1u64.to_le_bytes()); // `retired`: one row
    want.extend_from_slice(fp(2).as_bytes());
    want.push(0); // the retired row is the FLAG, one byte

    assert_eq!(
        bincode::serialize(st.key_set(&addr(ACCT_A))).expect("serialize KeySet"),
        want
    );
}

/// AUTH-1.40 — `sets` encodes BEFORE `claimant`, which is the half
/// `genesis_checkpoint_encoding_is_pinned` cannot see: at genesis both fields
/// are zero bytes and swapping them changes nothing. A state with one keyed
/// account opens on that map's eight-byte length of 1, where a swapped state
/// opens on `claimant`'s one-byte `None`. Only the PREFIX is asserted — what
/// follows is an `Address`, whose encoding is M1's to pin and not this
/// crate's.
#[test]
fn identity_state_encodes_sets_before_claimant() {
    let mut fx = Fixture::new();
    let st = seeded(&mut fx); // one keyed account, unclaimed
    let bytes = bincode::serialize(&st).expect("serialize IdentityState");
    assert!(
        bytes.starts_with(&1u64.to_le_bytes()),
        "a checkpoint opens on `sets`' row count, not on `claimant`"
    );
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
