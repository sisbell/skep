use super::*;

/// Leaf strictness: the dotted-decimal grammar admits exactly nonempty
/// runs of digits joined by single dots. Magnitude is unbounded in kind
/// — the carrier is a `BigUint` and a beyond-u64 component round-trips —
/// with only the wire ENCODING capped (see
/// [`tumbler_digit_and_depth_caps_admit_their_maximum`]).
#[test]
fn only_dot_joined_digit_runs_parse_as_tumblers() {
    let ok = p_tum(&Value::String("1.0.1".into())).map(|t| t.to_string());
    assert_eq!(ok.expect("'1.0.1' parses"), "1.0.1");
    // Beyond u64: parses through the BigUint path and renders back.
    let big = "18446744073709551616"; // 2^64
    let t = p_tum(&Value::String(big.into())).expect("a beyond-u64 component parses");
    assert_eq!(t.to_string(), big);
    for bad in ["", ".", "1..2", "1.", ".1", "1.-2", "1.+2", "1.a", "1 .2"] {
        assert!(p_tum(&Value::String(bad.into())).is_err(), "'{bad}' must not parse");
    }
}

/// A refusal names the offending text without copying it: the echoed
/// value is wire-supplied and bounded only by the request body, and it
/// is copied again by every field, element and region wrapper on the way
/// out, so an unbounded echo makes a malformed frame cost a multiple of
/// itself. The multi-byte case is the load-bearing one — the cut is on a
/// character boundary, and a byte-index slice would panic here.
#[test]
fn a_refusal_names_the_offending_text_without_copying_it() {
    let long = "é".repeat(4096); // not digits, and not ASCII
    let e = p_tum(&Value::String(long.clone())).expect_err("not a dotted decimal");
    assert!(e.0.len() < 300, "the refusal is bounded, not a copy of the input: {}", e.0.len());
    assert!(e.0.contains("ééé"), "and still shows what it refused: {e}");
    assert!(e.0.contains(&long.len().to_string()), "naming the length it elided: {e}");
    // Short values are shown whole, so ordinary diagnostics are intact.
    let e = p_tum(&Value::String("1.a".into())).expect_err("not a decimal natural");
    assert!(e.0.contains("'a'"), "a short value is named in full: {e}");
}

/// Both ends of both tumbler wire caps. A component's digit run and a
/// tumbler's depth each multiply against the whole link store on the
/// query path — M8 clones both operands' endpoints per overlap test —
/// so each is capped at the encoding, and each cap is checked at the
/// value it admits as well as the one past it: a `>` that became a `>=`
/// would refuse a tumbler the substrate can legitimately carry.
#[test]
fn tumbler_digit_and_depth_caps_admit_their_maximum() {
    let tum = |s: String| p_tum(&Value::String(s));
    // Magnitude: the longest admitted digit run parses and renders back
    // whole; one digit more is refused with the count named.
    let at_cap = "9".repeat(MAX_NAT_DIGITS);
    let t = tum(at_cap.clone()).expect("a component at the digit cap parses");
    assert_eq!(t.to_string(), at_cap, "and survives the round trip");
    let over = "9".repeat(MAX_NAT_DIGITS + 1);
    let e = tum(over).expect_err("one digit past the cap must not parse");
    assert!(e.0.contains("digit"), "the refusal names the digit cap: {e}");
    // The cap is per COMPONENT, so a tumbler of admitted components is
    // admitted whatever its total length.
    assert!(tum(format!("{at_cap}.{at_cap}")).is_ok(), "the cap is per component");

    // Depth: the same treatment on the other axis.
    let deep = vec!["1"; MAX_TUMBLER_COMPONENTS].join(".");
    assert_eq!(
        tum(deep).expect("a tumbler at the depth cap parses").len(),
        MAX_TUMBLER_COMPONENTS
    );
    let deeper = vec!["1"; MAX_TUMBLER_COMPONENTS + 1].join(".");
    let e = tum(deeper).expect_err("one component past the cap must not parse");
    assert!(e.0.contains("component"), "the refusal names the depth cap: {e}");
}

/// [`wire_address`] is BOTH steps that make a wire address: the capped
/// tumbler parse and M1's T4 refinement. Composing them once is the
/// point, so this pins that each step is present and that neither face
/// of the door can lose one — a caller that re-composed them itself
/// could keep the caps and drop T4, which admits an address no address
/// arithmetic in the system is defined on.
#[test]
fn the_address_door_is_the_capped_parse_and_the_t4_refinement_together() {
    assert_eq!(
        wire_address("1.0.1.0.1").expect("a T4-valid address").to_string(),
        "1.0.1.0.1"
    );
    // The T4 half: a tumbler `wire_tumbler` admits and `validate` does not.
    let not_t4 = "1.0.0.3";
    assert!(wire_tumbler(not_t4).is_ok(), "the tumbler half admits it");
    let e = wire_address(not_t4).expect_err("the T4 half refuses it");
    assert!(e.contains("T4-valid"), "the refusal names the clause: {e}");
    // The CAP half, on both axes, so neither is lost to the refinement.
    for over in
        ["9".repeat(MAX_NAT_DIGITS + 1), vec!["1"; MAX_TUMBLER_COMPONENTS + 1].join(".")]
    {
        let e = wire_address(&over).expect_err("past a wire cap");
        assert!(e.contains("wire cap"), "the refusal names the cap: {e}");
    }
    // The frame's face answers alike, being that door over a JSON string.
    assert!(p_addr(&Value::String(not_t4.into())).is_err());
    assert!(p_addr(&Value::Number(1.into())).is_err(), "and a non-string is refused");
}

/// Both ends of the id cap. The id is the one frame field this daemon
/// never interprets and M10 nonetheless RETAINS — the idempotency memo
/// is keyed by it — so its length is the second factor in a retention
/// bill nothing downstream bounds. The at-cap case is load-bearing: a
/// `>` that became a `>=` would refuse a key a client legitimately sent.
#[test]
fn the_idempotency_id_meets_its_cap_at_both_ends() {
    let frame = |id: &str| format!(r#"{{"op":"fork","id":"{id}"}}"#).into_bytes();
    let at_cap = "k".repeat(MAX_REQ_ID_BYTES);
    let req = parse_request(&frame(&at_cap)).expect("an id at the cap parses");
    assert_eq!(req.id.map(|ReqId(b)| b.len()), Some(MAX_REQ_ID_BYTES));
    let over = "k".repeat(MAX_REQ_ID_BYTES + 1);
    // `Request` derives no Debug upstream, so unwrap the failure by hand.
    let e = match parse_request(&frame(&over)) {
        Err(e) => e,
        Ok(_) => panic!("one byte past the cap must not parse"),
    };
    assert!(e.0.contains("wire cap"), "the refusal names the cap: {e}");
}

/// Both ends of the wire-list cap, at [`p_list`] — the one door every
/// attacker-sized array on the request surface passes through. The
/// at-cap case is the load-bearing half: the cap IS M7's stored-slot
/// budget, so refusing at it would refuse a query exactly as large as a
/// slot that can be stored.
#[test]
fn a_wire_list_at_the_cap_parses_and_one_past_it_does_not() {
    let spans = |n: usize| {
        Value::Array(
            (0..n)
                .map(|_| {
                    obj(vec![
                        ("start", Value::String("1.1".into())),
                        ("width", Value::String("0.1".into())),
                    ])
                })
                .collect(),
        )
    };
    assert_eq!(
        p_list(&spans(MAX_WIRE_LIST), p_span).expect("a list at the cap parses").len(),
        MAX_WIRE_LIST
    );
    let e = p_list(&spans(MAX_WIRE_LIST + 1), p_span)
        .expect_err("one element past the cap must not parse");
    assert!(e.0.contains("wire cap"), "the refusal names the cap: {e}");
}

/// Both ends of the insert-value cap, counted in VALUES rather than
/// elements: one per-byte string mints one value per byte, so a single
/// element can cross the cap on its own and an element-count check
/// would not see it.
#[test]
fn insert_value_cap_counts_values_not_elements() {
    let forms = |n: usize| Value::Array(vec![Value::String("a".repeat(n))]);
    // `Val` derives no Debug upstream, so unwrap the failure by hand.
    let refusal = |v: &Value| match p_values(v) {
        Err(e) => e,
        Ok(vals) => panic!("{} values must not parse", vals.len()),
    };
    assert_eq!(
        p_values(&forms(MAX_INSERT_VALUES))
            .unwrap_or_else(|e| panic!("at the cap: {e}"))
            .len(),
        MAX_INSERT_VALUES
    );
    let e = refusal(&forms(MAX_INSERT_VALUES + 1));
    assert!(e.0.contains("cap on one insert"), "the refusal names the cap: {e}");
    // Split across two elements, the accumulator still sees it — the
    // reason the room asked is measured against what is already there
    // rather than against one element in isolation.
    let split = Value::Array(vec![
        Value::String("a".repeat(MAX_INSERT_VALUES)),
        Value::String("b".into()),
    ]);
    assert!(p_values(&split).is_err(), "the total is what is capped, not one element");
}

/// The cap refuses BEFORE the mint, not after. An element's whole
/// contribution is added in one `extend`, so a check made afterwards has
/// already paid the peak — one 8 MiB per-byte string mints 8.4M [`Val`]s,
/// order 400 MB of live heap, for a frame that is then refused. What a
/// test can see is that nothing was minted.
#[test]
fn an_over_cap_element_mints_nothing() {
    let mut out: Vec<Val> = Vec::new();
    let big = Value::String("a".repeat(MAX_INSERT_VALUES + 1));
    assert!(p_val_form(&big, &mut out).is_err(), "one element past the cap is refused");
    assert!(out.is_empty(), "and mints nothing: the refusal precedes the mint");
    // Hex is measured on its ENCODED length, so neither the decode nor
    // the values are built.
    let mut out: Vec<Val> = Vec::new();
    let hex = obj(vec![("hex", Value::String("ab".repeat(MAX_INSERT_VALUES + 1)))]);
    assert!(p_val_form(&hex, &mut out).is_err(), "the hex form is capped too");
    assert!(out.is_empty());
    // Both ends against a partly-filled accumulator: the room asked is
    // the element's, measured against what is already there.
    let mut out: Vec<Val> =
        (0..MAX_INSERT_VALUES - 1).map(|_| Val::new(vec![b'a'])).collect();
    assert!(
        p_val_form(&Value::String("ab".into()), &mut out).is_err(),
        "two more values do not fit with one slot left"
    );
    assert_eq!(out.len(), MAX_INSERT_VALUES - 1, "and the refused element mints nothing");
    p_val_form(&Value::String("a".into()), &mut out)
        .expect("the element that exactly fills the cap is admitted");
    assert_eq!(out.len(), MAX_INSERT_VALUES);
}

/// Span parse edges — every span on the wire goes through M1's
/// `Span::new`, so no zero-width span and no ill-shaped object survives
/// the trust boundary (wire.md §Value encodings).
#[test]
fn no_zero_width_or_ill_shaped_span_parses() {
    let span = |s: &str| p_span(&serde_json::from_str::<Value>(s).expect("test JSON"));
    let ok = span(r#"{"start":"1.1","width":"0.5"}"#).expect("a depth-2 content span parses");
    assert_eq!(
        (ok.start().to_string(), ok.width().to_string()),
        ("1.1".to_string(), "0.5".to_string())
    );
    for bad in [
        r#"{"start":"1.1","width":"0.0"}"#, // zero width (T12)
        r#"{"start":"1.1","width":"0"}"#,   // zero width, another depth
        r#"{"start":"1.1","width":"0.0.1"}"#, // action point past #start
        r#"{"start":"1.1"}"#,               // missing width
        r#"{"width":"0.5"}"#,               // missing start
        r#"{"start":"1.1","width":"0.5","extra":1}"#, // unknown key
        r#"{"start":"1.1","width":"0.5x"}"#, // not a dotted decimal
        r#"["1.1","0.5"]"#,                 // not an object
        r#""1.1+0.5""#,                     // not an object
    ] {
        assert!(span(bad).is_err(), "{bad} must not parse as a span");
    }
}

/// Value granularity at the leaf: per-byte forms mint one single-byte
/// value per byte, atom forms one composite value; the canonical marshal
/// coalesces maximal per-byte runs (UTF-8 judged on the whole run) and
/// never coalesces atoms.
#[test]
fn value_forms_parse_per_byte_and_atoms_marshal_apart() {
    let mut vs: Vec<Val> = Vec::new();
    p_val_form(&Value::String("hé".into()), &mut vs).expect("a string value form parses");
    assert_eq!(vs.len(), 3, "'h' plus the two bytes of 'é'");
    assert!(vs.iter().all(|v| v.len() == 1));
    p_val_form(&obj(vec![("atom", Value::String("hé".into()))]), &mut vs)
        .expect("an atom value form parses");
    assert_eq!(vs.len(), 4);
    assert_eq!(vs[3].as_bytes(), "hé".as_bytes());
    // Canonical inverse: the run reassembles, the atom stays its own form.
    let canon = j_values(&vs);
    let expect: Value = serde_json::from_str(r#"["hé",{"atom":"hé"}]"#).unwrap();
    assert_eq!(canon, expect);
    // Empty per-byte forms are vacuous; empty atoms are inexpressible;
    // multi-key objects and non-string/object elements are malformed.
    let mut none: Vec<Val> = Vec::new();
    p_val_form(&Value::String(String::new()), &mut none).expect("\"\" is vacuous");
    p_val_form(&obj(vec![("hex", Value::String(String::new()))]), &mut none)
        .expect("an empty hex string is vacuous");
    assert!(none.is_empty());
    for bad in [
        obj(vec![("atom", Value::String(String::new()))]),
        obj(vec![("atom_hex", Value::String(String::new()))]),
        obj(vec![("atom", Value::String("a".into())), ("hex", Value::String("00".into()))]),
        Value::Bool(true),
    ] {
        assert!(p_val_form(&bad, &mut none).is_err(), "{bad} must not parse");
    }
    assert!(p_hex("abc").is_err()); // odd length
    assert!(p_hex("zz").is_err());
}

/// All three documented view values (wire.md §Value encodings:
/// `"audit"`, `"active"`, `"default"`). The request fixtures carry only
/// two, so the third's parse arm and its marshal arm are watched by
/// nothing — and a typo in either makes a frame the document offers a
/// client come back `unparseable`, which tells them their frame is
/// malformed when the value is one wire.md invited.
#[test]
fn every_documented_view_value_round_trips() {
    for name in ["audit", "active", "default"] {
        let v = p_view(&Value::String(name.into()))
            .unwrap_or_else(|e| panic!("'{name}' is a documented view: {e}"));
        assert_eq!(j_view(v), Value::String(name.into()), "'{name}' must be its own inverse");
    }
    for bad in ["Audit", "", "all", "actives"] {
        assert!(p_view(&Value::String(bad.into())).is_err(), "'{bad}' must not parse");
    }
}

/// The one parse-side normalization [`JsonCodec::marshal_request`]'s
/// precondition names rather than excludes: an empty span array IS the
/// empty constraint (M8 documents the empty endset as exactly that
/// zero), so it reads back under the canonical name and a
/// `SlotSpec::Spans` over an empty endset round-trips EQUAL rather than
/// identical. Nothing else pins that the two spellings meet.
#[test]
fn an_empty_slot_constraint_normalizes_onto_its_canonical_name() {
    assert!(
        matches!(p_slotspec(&Value::Array(vec![])), Ok(SlotSpec::Empty)),
        "an empty span array is the empty constraint, not an empty span list"
    );
    assert_eq!(
        j_slotspec(&SlotSpec::Spans(Endset::from_spans([]))),
        Value::Array(vec![]),
        "which is the form an empty Spans marshals as"
    );
    assert_eq!(j_slotspec(&SlotSpec::Empty), Value::String("empty".into()));
}

/// "Non-negative" is the word the wire uses (wire.md §Value encodings)
/// and the word these parsers' own error messages use; a signed or
/// fractional number is neither a natural nor a bounded integer. The
/// failure this guards is not a refusal but a WRAP: the tempting fix
/// when a client sends a signed value is `as_i64() as u64`, under
/// which `-1` becomes 2^64-1 everywhere naturals and bounded integers
/// are read — a `delete` of 2^64-1 positions, a slot index no link
/// has, a principal that is the guest's own id.
#[test]
fn negative_and_fractional_numbers_are_not_integers() {
    let n = |s: &str| serde_json::from_str::<Value>(s).expect("test JSON");
    for bad in ["-1", "-7", "1.5", "-0.5", "1e3"] {
        assert!(p_u64(&n(bad)).is_err(), "{bad} is not a non-negative integer");
        assert!(p_usize(&n(bad)).is_err(), "{bad} is not a count");
        assert!(p_nat(&n(bad)).is_err(), "{bad} is not a natural");
    }
    assert_eq!(p_u64(&n("0")).expect("zero is non-negative"), 0);
    assert_eq!(p_nat(&n("7")).expect("the lenient integer form").to_string(), "7");
}

/// Marshal determinism in miniature: obj() sorts, so construction order
/// cannot leak into bytes.
#[test]
fn obj_is_order_insensitive() {
    let a = obj(vec![("b", j_u64(2)), ("a", j_u64(1))]);
    let b = obj(vec![("a", j_u64(1)), ("b", j_u64(2))]);
    assert_eq!(to_bytes(a), to_bytes(b));
}

/// The duplicate-key rule [`obj`] states and `refuse_with` leans on: the
/// LAST pair given wins, which is what lets `refuse_with` append `error`
/// behind a caller's fields and be sure the field list cannot displace
/// it.
#[test]
fn obj_keeps_the_last_of_duplicate_keys() {
    let v = obj(vec![("k", j_u64(1)), ("a", j_u64(9)), ("k", j_u64(2))]);
    assert_eq!(v["k"], j_u64(2), "the last pair given wins");
    assert_eq!(to_bytes(v), br#"{"a":9,"k":2}"#.to_vec(), "and the keys still sort");
}

/// The class types a `deposit` field can usefully carry are SPELLED
/// TWICE — M5's set, which its insert door tests a declaration against
/// and which sits below this crate, and the daemon's own credential
/// constants, which the fold classifies the pair's `make_link` by — and
/// the two are pinned EQUAL here, member for member in the set's order,
/// ENROLL then RETIRE (PUB-2.11, PUB-2.63; RES-249, RES-261). This is
/// the one place both spellings are in reach: the constants are this
/// crate's own and no integration suite can name them, and the parse
/// above is where a declared type enters the daemon. If this fails, an
/// enrollment a client declares as the fold will classify it is refused
/// `published_target` at the store — or admitted there and typed as
/// nothing the fold honors.
#[test]
fn the_deposit_class_types_are_the_daemons_enroll_and_retire_constants() {
    use crate::auth::policy::{T_ENROLL, T_RETIRE};
    let spelled: Vec<Vec<Nat>> = skep_arrangement::deposit_class_types()
        .iter()
        .map(|ty| ty.tumbler().iter().cloned().collect())
        .collect();
    assert_eq!(spelled, [T_ENROLL.map(Nat::from).to_vec(), T_RETIRE.map(Nat::from).to_vec()]);
}

/// THE DOOR splits the presented `attest` from the request: on the
/// daemon's dispatch path `Request::attest` is EMPTY whatever the frame
/// carried, and the member rides beside it, unverified, for the check —
/// so no route can hand M10 a signature the check never saw.
#[test]
fn the_daemon_parse_splits_the_presented_attest_from_the_request() {
    let frame = format!(
        r#"{{"op":"insert","doc":"1.0.1.0.1","at":{{"subspace":"1","ordinal":"1"}},"values":["x"],"attest":{{"alg":"{}","sig":"{}"}}}}"#,
        skep_identity::ALG_MLDSA65_ED25519,
        "ab".repeat(8)
    );
    let Ok(DaemonOp::Febe { request, presented }) = JsonCodec.parse_daemon(frame.as_bytes())
    else {
        panic!("an insert frame is an M10 request")
    };
    assert!(request.attest.is_none(), "no attest leaves the door inside the request");
    assert_eq!(
        presented.map(|a| a.sig().to_vec()),
        Some(vec![0xab; 8]),
        "it rides beside it"
    );
}

/// `marshal_request`'s `attest` clauses, both ways: on an op of the
/// checked set under a tag a `SIG_ALGS` row names, the member
/// round-trips — the tag lifted to its token and back, the blob byte for
/// byte; on an op OUTSIDE the checked set, marshaling succeeds and yields
/// a frame `parse` refuses by the unknown-field rule — outside the
/// precondition, and the parse side's to refuse (one check, one owner).
#[test]
fn an_attest_round_trips_on_the_checked_set_and_is_refused_off_it() {
    let doc = wire_address("1.0.1.0.1").expect("a document address");
    let attest = Attestation::new(1, vec![0xab; 8]).expect("tag 1 and a non-empty blob");
    let insert = Request {
        id: None,
        op: Op::Insert {
            doc: doc.clone(),
            at: VPos::content(Nat::from(1u32)),
            values: vec![Val::new(vec![b'x'])],
            deposit: Deposit::Undeclared,
        },
        attest: Some(attest.clone()),
    };
    let back = parse_request(&JsonCodec.marshal_request(&insert))
        .unwrap_or_else(|e| panic!("an attest on the checked set parses back: {e}"));
    // `Request` derives no Debug upstream, so the equality is asserted bare.
    assert!(back == insert, "and reproduces the request, the member included");
    let delete = Request {
        id: None,
        op: Op::Delete { doc, p: VPos::content(Nat::from(1u32)), width: Nat::from(1u32) },
        attest: Some(attest),
    };
    let e = match parse_request(&JsonCodec.marshal_request(&delete)) {
        Err(e) => e,
        Ok(_) => panic!("an attest off the checked set must not parse"),
    };
    assert!(e.0.contains("unknown field 'attest'"), "{e}");
}
