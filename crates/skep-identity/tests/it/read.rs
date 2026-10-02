//! The pinned payload read's corpus (AUTH-2.96's payload rows): vectors over
//! `record_bytes` (AUTH-2.36–2.45, AUTH-1.22) — most read through `classify`
//! for the `malformed_payload:<sub>` detail each earns — and the records
//! built to the cap's exact boundary from `MAX_RECORD_BYTES`.

use crate::common;

use common::*;
use skep_address::Span;
use skep_identity::{
    encode_enroll, encode_retire, record_bytes, Effect, Enrollment, Fingerprint, IdentityState,
    MAX_RECORD_BYTES,
};

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
    assert_detail(&v, "malformed_payload:foreign_content");
    assert_eq!(next, genesis_state);
}

/// Corpus: first FROM span home-minted at 128 KiB+1, second span transcluded
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
    assert_detail(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:too_large",
    );
}

/// Corpus: first FROM span home-minted at exactly 128 KiB, second span
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
    assert_detail(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:foreign_content",
    );
}

/// AUTH-2.39 — the per-span interleave at checks 1 and 2, the half
/// [`cap_fault_fires_before_second_spans_home_check`] leaves open: span 1's
/// WALK completes before span 2's VALIDITY or POSITION-HOOD is looked at. That
/// vector's second span is valid AND a position, so hoisting checks 1 and 2
/// into a pre-pass over the whole endset — the natural "refuse a malformed
/// endset before reading anything" shape — keeps it green and answers
/// `foreign_content` for both rows here.
#[test]
fn cap_fault_fires_before_a_second_spans_validity_and_position_checks() {
    let big = vec![b'x'; MAX_RECORD_BYTES + 1];
    for second in [
        // Adjacent zeros: T4-invalid, so check 1 refuses it and it never
        // reaches check 3 at all.
        Span::new(tum(&[1, 1, 0, 5, 0, 1, 0, 0, 1]), width_at_last(9, 1))
            .expect("T12-valid carrier span"),
        // The home's OWN document address: T4-valid and home-anchored, a
        // NON-position, so only check 2 stands between it and the walk.
        unit(&[1, 1, 0, 5, 0, 1]),
    ] {
        // A fresh fixture per row, so neither row's mint depends on the other's.
        let mut fx = Fixture::new();
        let home_span = fx.mint(&doc1(ACCT_A), &[&big]);
        let dep = Dep {
            home: doc1(ACCT_A),
            from: vec![home_span[0].clone(), second],
            to: vec![unit(ACCT_A)],
            ty: enroll_ty(),
        };
        assert_detail(
            &fx.classify(&IdentityState::genesis(), &dep),
            "malformed_payload:too_large",
        );
    }
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
    assert_detail(
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
    assert_detail(
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
        assert_detail(&v, "malformed_payload:bad_record");
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
    assert_detail(
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
/// a byte the grammar judges is caught by the grammar-sensitive vectors; the
/// byte the grammar does not judge is the one nothing else watches.)
/// `record_bytes` is
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
    assert_detail(
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
    assert_detail(
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
    assert_detail(
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

/// AUTH-1.22 — the debug build names a SINGLE zero-byte answer among
/// non-empty ones, which is the violation a host actually ships: the walk
/// appends a real value at ord 1 and meets the empty one at ord 2, where the
/// read's assertion fires. `zero_byte_value_is_refused_at_the_read`'s only
/// value is the empty one and the release bound's are empty at every position,
/// so an assertion narrowed to the all-empty ctx — hoisted out of the loop, or
/// guarded on nothing having been appended yet — keeps both of them green
/// while this record folds on a ctx that broke the premise.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "AUTH-1.22")]
fn a_lone_zero_byte_value_among_non_empty_ones_is_refused_at_the_read() {
    let mut fx = Fixture::new();
    let home = doc1(ACCT_A);
    // ord 1 carries a whole record, so the walk has appended real bytes before
    // it reaches the empty value at ord 2.
    fx.mint(&home, &[&enroll_payload(&[(1, true)])]);
    fx.ctx.values.insert(content_pos(&home, 2), Vec::new());
    let dep = Dep {
        home: home.clone(),
        from: vec![content_run(&home, 1, 2)],
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
        assert_detail(
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
    assert_detail(
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
    w[7] = 1; // action point at the subspace, above the ordinal
    let span = Span::new(start, tum(&w)).expect("T12-valid width");
    let dep = Dep {
        home: doc1(ACCT_A),
        from: vec![span],
        to: vec![unit(ACCT_A)],
        ty: enroll_ty(),
    };
    // The walk reads ords 1, 2, then outruns the mint: missing_value — NOT
    // `empty`/`bad_record`, which the count-off-width misreading answers.
    assert_detail(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:missing_value",
    );
}

/// AUTH-2.42 — the reach walk's membership test is M1 `Span::contains`' rule
/// (`start ≤ pos < reach`) taken against a reach derived once per span,
/// because `contains` recomputes `start ⊕ width` per call and `⊕`'s cost is
/// the WIDTH's component count, which T12 does not bound. Two spellings of
/// one rule, so the agreement is stated rather than assumed: over widths
/// with their action point at each of the start's components, with and
/// without a trailing tail, and over ordinals below, at, inside and above the
/// reach.
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
    assert_detail(
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
    assert_detail(&fx.classify(&genesis_state, &dep), "malformed_shape");
}

/// Corpus: a two-atom record — the head atom plus one under-cap atom whose
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
    assert_detail(
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
    assert_detail(
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
            &record.as_bytes()[..bracket],
            &record.as_bytes()[bracket..comma],
            &record.as_bytes()[comma..],
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
/// entries leaves room for the labels that pad the record onto the mark; the
/// helper asserts that as a fixture precondition. Under AUTH-2.130's canonical
/// spelling over a TAG-1 hybrid entry (`mldsa65-ed25519`, 3,968 hex — the
/// classical row is gone) the envelope is 32 B and each label-free entry is
/// 8 + 15 + 9 + 3,968 + 11 + 5 + 1 = 4,017 B plus a 1 B comma, so
/// 32 + 32·4,017 + 31 = 128,607 ≤ 131,072 and 33 entries would overflow
/// (132,625) — the 617 of the 64 KiB cap over classical entries become 32
/// here (rc-3; the record-cap measurements §5.2 K8; AUTH-2.130's cost note).
const CAP_SIZED_ENTRIES: u8 = 32;

/// The bytes a label of `L` bytes adds to a label-free entry: the
/// `,"label":"…"` wrapper is 11 bytes (AUTH-2.130's canonical spelling), so
/// the widest label the domain admits — 128 bytes (AUTH-1.24) — adds 139.
const LABEL_WRAPPER: usize = 11;
const MAX_PAD_PER_LABEL: usize = 128 + LABEL_WRAPPER;

/// An enrollment record of exactly `MAX_RECORD_BYTES + over` bytes:
/// [`CAP_SIZED_ENTRIES`] key entries, the first carrying labels sized to land
/// the total on the mark — SPREAD OVER SEVERAL ENTRIES, since a label is at
/// most 128 bytes (AUTH-1.24): the 2,465 bytes from the label-free base to
/// the 128 KiB mark take seventeen 128-byte labels and one of 91. Built FROM
/// the constant, so a change to the cap moves the record with it and
/// `max_record_bytes_is_128_kib` stays the one assertion that discovers it.
fn cap_sized_enroll_payload(over: usize) -> Vec<u8> {
    let mut entries: Vec<Enrollment> = (0..CAP_SIZED_ENTRIES)
        .map(|i| Enrollment::new(key(i), false, None).expect("label-free"))
        .collect();
    let base_len = encode_enroll(&entries).len();
    // Room for at least a one-byte label: the wrapper and one byte more.
    assert!(
        base_len + LABEL_WRAPPER < MAX_RECORD_BYTES,
        "fixture arithmetic: {base_len} bytes of {CAP_SIZED_ENTRIES} key entries leaves no room \
         for a label under a {MAX_RECORD_BYTES}-byte cap"
    );
    let mut pad = MAX_RECORD_BYTES - base_len + over;
    assert!(
        pad <= entries.len() * MAX_PAD_PER_LABEL,
        "fixture arithmetic: {pad} bytes of padding do not fit in {} labels of at most 128 bytes",
        entries.len()
    );
    // Full labels while the remainder still leaves room for a legal last one
    // (a label is at least one byte, so a remainder of 1..=LABEL_WRAPPER bytes
    // cannot be spelled — hold one label back so the last two share it).
    let mut i = 0;
    while pad > 0 {
        let take = if pad <= MAX_PAD_PER_LABEL {
            pad
        } else if pad - MAX_PAD_PER_LABEL <= LABEL_WRAPPER {
            // Split the last two labels so neither is under 1 byte.
            pad - (LABEL_WRAPPER + 1)
        } else {
            MAX_PAD_PER_LABEL
        };
        assert!(take > LABEL_WRAPPER, "a label adds at least {} bytes", LABEL_WRAPPER + 1);
        let label = "x".repeat(take - LABEL_WRAPPER);
        entries[i] = Enrollment::new(entries[i].key.clone(), false, Some(label))
            .expect("a label of at most 128 bytes");
        pad -= take;
        i += 1;
    }
    let payload = encode_enroll(&entries).into_bytes();
    assert_eq!(payload.len(), MAX_RECORD_BYTES + over);
    payload
}

/// Corpus: a 128 KiB record folds · a 128 KiB+1 record is inert (AUTH-2.43's
/// exceed-only boundary; AUTH-1.19's per-record scope; AUTH-2.96's row as
/// re-pinned at 128 KiB).
#[test]
fn record_at_exactly_the_cap_folds_and_one_more_byte_inerts() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();

    let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &cap_sized_enroll_payload(0));
    match assert_honored(&fx.classify(&genesis_state, &dep)) {
        Effect::Genesis { keys, .. } => assert_eq!(keys.len(), CAP_SIZED_ENTRIES as usize),
        _ => panic!("expected a genesis effect"),
    }

    // One byte more: inert.
    let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &cap_sized_enroll_payload(1));
    assert_detail(
        &fx.classify(&genesis_state, &dep),
        "malformed_payload:too_large",
    );
}

/// AUTH-2.43's exceed-only boundary read in POSITIONS: a 128 KiB record spread
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
        Effect::Genesis { keys, .. } => assert_eq!(keys.len(), CAP_SIZED_ENTRIES as usize),
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
    assert_detail(
        &fx.classify(&IdentityState::genesis(), &dep),
        "malformed_payload:too_large",
    );
}
