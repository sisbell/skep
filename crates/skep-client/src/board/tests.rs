use std::sync::{Arc, Mutex};

use super::*;

#[test]
fn a_token_is_thirty_two_lowercase_hex() {
    assert!(Token::parse("9f3a6c21d4b8e07a5c1b2d4e6f708192").is_some());
    assert!(Token::parse("9F3A6C21D4B8E07A5C1B2D4E6F708192").is_none());
    assert!(Token::parse("9f3a6c21d4b8e07a5c1b2d4e6f70819").is_none());
    assert_eq!(format!("{:?}", Token::parse("9f3a6c21d4b8e07a5c1b2d4e6f708192").unwrap()), "Token(…)");
}

#[test]
fn a_key_set_answer_decodes_and_not_an_account_is_an_answer() {
    let v = json!({"as_of": 9, "resp": "key_set", "enrolled": [], "retired": [{"anchor": false, "fingerprint": "ab".repeat(32)}]});
    match key_set_of(&v).unwrap() {
        KeySetAnswer::Set(set) => {
            assert!(set.enrolled.is_empty() && set.retired.len() == 1 && !set.is_empty());
        }
        KeySetAnswer::NotAnAccount => panic!(),
    }
    let rej = json!({"code": "not_an_account", "disposition": "reorder", "op": "key_set", "resp": "rejected"});
    assert_eq!(key_set_of(&rej).unwrap(), KeySetAnswer::NotAnAccount);
}

/// AUTH-1.7 at the decode: an enrolled entry is admitted only where its
/// fingerprint is its key's hash, so a lookup by fingerprint finds the
/// key it names; an entry whose two disagree is no `key_set` answer.
#[test]
fn an_enrolled_entry_is_admitted_only_where_its_fingerprint_is_its_keys() {
    let key = skep_signature::HybridSigner::from_seed(skep_signature::TAG_MLDSA65_ED25519, &[7; 32]).expect("tag 1").public_key().clone();
    let answer = |fingerprint: String| json!({"as_of": 9, "resp": "key_set", "retired": [], "enrolled": [{"alg": key.alg(), "key": key.to_hex(), "fingerprint": fingerprint, "anchor": true}]});
    let fp = Fingerprint::of(&key);
    match key_set_of(&answer(fp.to_hex())).unwrap() {
        KeySetAnswer::Set(set) => assert!(set.enrolled(&fp).is_some_and(|e| e.anchor && e.key == key)),
        KeySetAnswer::NotAnAccount => panic!(),
    }
    let err = key_set_of(&answer("ab".repeat(32))).expect_err("a fingerprint its key does not hash to");
    assert!(err.to_string().contains("not a key_set answer"), "{err}");
}

#[test]
fn the_frames_spell_the_wire() {
    assert_eq!(frames::unit_span("1.0.1"), json!([{"start": "1.0.1", "width": "0.0.1"}]));
    let f = frames::insert_atom("1.0.1.0.1", 1, "{}", T_ENROLL, 7, Some("x"));
    assert_eq!(f["deposit"], T_ENROLL);
    assert_eq!(f["id"], "x");
    assert_eq!(f["at"]["ordinal"], "1");
    assert_eq!(f["as_of"], 7, "the typed state rides as a position (wire.md §Arrangement)");
    assert_eq!(frames::insert_plain_atom("1.0.1.0.64", 3, "{}", 11, None)["as_of"], 11);
    assert_eq!(frames::delete("1.0.1.0.64", 3, 1, 12, None)["as_of"], 12);
    assert_eq!(frames::reinstate("1.0.1.0.64", 3, &[], 13, None)["as_of"], 13);
    let r = Rejection::of(&json!({"code":"credential_refused","detail":"content_session","disposition":"permanent","op":"make_link","resp":"rejected"})).unwrap();
    assert_eq!(r.token(), "credential_refused:content_session");
}

/// Checks the builders against wire.md's own request examples.
///
/// Each is the line
/// under its `<!-- wire: request … -->` marker — `find_links_v` over one
/// span (§Link discovery reads), `find_links_ftt`'s four-set with a `from`
/// list and an `empty` type, `window_ftt`'s all-`any` four-set past a cursor
/// (and beside it, with no example of the wire's own, the mail search's
/// paged form at the start), the mailbox's mint,
/// `create_well_known_document` (§Namespace) at slot 2, whose frame
/// serializes to the example's line byte for byte, and the same op at
/// another slot, `count_v_by_home` with its `except`, `line_numbers`
/// (§Content & provenance reads) with both its lists, byte for byte,
/// `image` and a `compare` region reading a document's own arrangement
/// (`own`; §Link discovery reads, §Content & provenance reads), byte for
/// byte,
/// `rearrange` (§Arrangement) over three cuts, byte for byte,
/// `copy` (§Arrangement) of one source span, byte for byte, `make_link`
/// (§Links (writes)) with its `from` in the V-spec form, byte for byte,
/// and with an empty one, `retrieve_i` (§Content & provenance reads), byte
/// for byte,
/// `find_links_v_history` at the start, `project`, `edition_claims`,
/// `out_claims` (the example's view is `audit`; this crate reads the active
/// view, the one member that differs) and the `publish` example with every
/// optional member (§Arrangement). A region of several spans is one array.
#[test]
fn the_builders_spell_the_wires_own_examples() {
    assert_eq!(frames::find_links_v("1.0.1.0.1", &[(1, 5)]), json!({"d":"1.0.1.0.1","op":"find_links_v","region":[{"start":"1.1","width":"0.5"}]}));
    assert_eq!(frames::find_links_v("1.0.1.0.1", &[(1, 5), (9, 2)])["region"], json!([{"start":"1.1","width":"0.5"},{"start":"1.9","width":"0.2"}]));
    let from = [frames::i_span("1.0.1.0.1.0.1.1", 5)];
    assert_eq!(
        frames::find_links_four(frames::Slot::Any, frames::Slot::Spans(&from), frames::Slot::Any, frames::Slot::Empty),
        json!({"op":"find_links_ftt","q":{"from":[{"start":"1.0.1.0.1.0.1.1","width":"0.0.0.0.0.0.0.5"}],"home":"any","to":"any","ty":"empty"}})
    );
    assert_eq!(
        frames::window_four(frames::Slot::Any, frames::Slot::Any, frames::Slot::Any, frames::Slot::Any, Some("1.0.1.0.1.0.2.1"), 16),
        json!({"cur":"1.0.1.0.1.0.2.1","n":16,"op":"window_ftt","q":{"from":"any","home":"any","to":"any","ty":"any"}})
    );
    // The mail search in pages: the start's cursor is spelled `null`, never
    // left out, and the query is the unpaged read's own.
    let mailbox = crate::address::mailbox_of("1.0.5");
    let paged = frames::window_ftt(frames::T_MAIL, &mailbox, None, 16);
    assert_eq!(paged, json!({"cur":null,"n":16,"op":"window_ftt","q":{"from":"any","home":"any","to":[{"start":"1.0.5.0.2","width":"0.0.0.0.1"}],"ty":[{"start":"1.1.0.1.0.1.0.3.15","width":"0.0.0.0.0.0.0.0.1"}]}}));
    assert_eq!(paged["q"], frames::find_links_ftt(frames::T_MAIL, &mailbox)["q"], "the paged search asks the unpaged read's query");
    assert_eq!(frames::window_ftt(frames::T_MAIL, &mailbox, Some("1.0.7.0.64.0.2.1"), 16)["cur"], "1.0.7.0.64.0.2.1");
    // The mailbox's mint: the example's own line, as the frame serializes.
    assert_eq!(frames::create_mailbox("1.0.1", None).to_string(), r#"{"account":"1.0.1","op":"create_well_known_document","slot":2}"#);
    assert_eq!(frames::create_mailbox("1.0.1", None), frames::create_well_known_document("1.0.1", crate::address::MAILBOX_SLOT, None, None), "the mailbox's frame is the creation's at slot 2, with no attest");
    assert_eq!(frames::create_well_known_document("1.0.1", 4, None, Some("x")).to_string(), r#"{"account":"1.0.1","id":"x","op":"create_well_known_document","slot":4}"#);
    let attest = json!({"alg": "mldsa65-ed25519", "sig": "00"});
    assert_eq!(
        frames::create_well_known_document("1.0.1", 5, Some(attest), None).to_string(),
        r#"{"account":"1.0.1","attest":{"alg":"mldsa65-ed25519","sig":"00"},"op":"create_well_known_document","slot":5}"#,
        "the policy document's creation, as wire.md's attested example spells it"
    );
    assert_eq!(frames::count_v_by_home("1.0.1.0.1", &[(1, 5)], 64, &["1.0.1.0.64"]), json!({"d":"1.0.1.0.1","except":["1.0.1.0.64"],"n":64,"op":"count_v_by_home","region":[{"start":"1.1","width":"0.5"}]}));
    assert!(frames::count_v_by_home("1.0.1.0.1", &[(1, 5)], 64, &[]).get("except").is_none(), "no `except` where none is named");
    // The line read: the example's own line, as the frame serializes, and
    // the canonical empty lists where nothing is asked but the count.
    assert_eq!(frames::line_numbers("1.0.1.0.1", &[3], &[2, 9]).to_string(), r#"{"doc":"1.0.1.0.1","lines":["2","9"],"op":"line_numbers","positions":[{"ordinal":"3","subspace":"1"}]}"#);
    assert_eq!(frames::line_numbers("1.0.1.0.1", &[], &[]).to_string(), r#"{"doc":"1.0.1.0.1","lines":[],"op":"line_numbers","positions":[]}"#);
    // The reads of a document's own arrangement (PUB-2.66): `image` and a
    // `compare` region carrying `own`, each the example's own line, as the
    // frame serializes; the plain forms carry no `own`.
    assert_eq!(frames::image_own("1.0.1.0.1", 1, 3).to_string(), r#"{"d":"1.0.1.0.1","op":"image","own":true,"region":[{"start":"1.1","width":"0.3"}]}"#);
    assert_eq!(
        frames::compare(&[frames::region_own("1.0.1.0.1", 1, 3)], &[frames::region("1.0.1.0.64", 1, 3)]).to_string(),
        r#"{"op":"compare","rho1":[{"doc":"1.0.1.0.1","own":true,"spans":[{"start":"1.1","width":"0.3"}]}],"rho2":[{"doc":"1.0.1.0.64","spans":[{"start":"1.1","width":"0.3"}]}]}"#
    );
    assert!(frames::image("1.0.1.0.1", 1, 3).get("own").is_none() && frames::region("1.0.1.0.1", 1, 3).get("own").is_none(), "no `own` where none is asked");
    // The move by identity: the example's own line, as the frame serializes.
    assert_eq!(
        frames::rearrange("1.0.1.0.1", &[1, 3, 6], 7, None).to_string(),
        r#"{"as_of":7,"cuts":[{"ordinal":"1","subspace":"1"},{"ordinal":"3","subspace":"1"},{"ordinal":"6","subspace":"1"}],"doc":"1.0.1.0.1","op":"rearrange"}"#
    );
    assert_eq!(frames::rearrange("1.0.1.0.1", &[1, 2, 3, 4], 7, Some("x"))["id"], "x");
    // The copy by identity, the link whose `from` is content and the read by
    // identity: each the example's own line, as the frame serializes.
    assert_eq!(
        frames::copy("1.0.1.0.1", 6, &[("1.0.1.0.64", 1, 5)], 7, None).to_string(),
        r#"{"as_of":7,"at":{"ordinal":"6","subspace":"1"},"doc":"1.0.1.0.1","op":"copy","specs":[{"source":"1.0.1.0.64","span":{"start":"1.1","width":"0.5"}}]}"#
    );
    assert_eq!(frames::copy("1.0.1.0.1", 6, &[("1.0.1.0.64", 1, 5), ("1.0.1.0.65", 3, 2)], 7, Some("x"))["specs"][1], json!({"source":"1.0.1.0.65","span":{"start":"1.3","width":"0.2"}}));
    assert_eq!(
        frames::make_link_spec("1.0.1.0.1", &[("1.0.1.0.1", 1, 5)], &["1.0.1.0.1.0.2.1"], "1.0.1.0.65.0.3.6.1", None).to_string(),
        r#"{"from":[{"source":"1.0.1.0.1","span":{"start":"1.1","width":"0.5"}}],"home":"1.0.1.0.1","op":"make_link","to":{"addrs":["1.0.1.0.1.0.2.1"]},"ty":{"addrs":["1.0.1.0.65.0.3.6.1"]}}"#
    );
    let empty = frames::make_link_spec("1.0.1.0.66", &[], &["1.0.1.0.64"], frames::T_MARKS, Some("x"));
    assert_eq!(
        empty.to_string(),
        r#"{"from":[],"home":"1.0.1.0.66","id":"x","op":"make_link","to":{"addrs":["1.0.1.0.64"]},"ty":{"addrs":["1.1.0.1.0.1.0.3.25"]}}"#,
        "an empty `from` is the empty list"
    );
    assert_ne!(
        frames::make_link_spec("1.0.1.0.66", &[("1.0.1.0.66", 1, 5)], &["1.0.1.0.64"], frames::T_MARKS, None)["from"],
        frames::make_link("1.0.1.0.66", &["1.0.1.0.66"], &["1.0.1.0.64"], frames::T_MARKS, None)["from"],
        "content, never the document's name"
    );
    assert_eq!(frames::retrieve_i(&[("1.0.1.0.1.0.1.1", 5)]).to_string(), r#"{"op":"retrieve_i","spans":[{"start":"1.0.1.0.1.0.1.1","width":"5"}]}"#);
    assert_eq!(frames::retrieve_i(&[("1.0.1.0.1.0.1.1", 5), ("1.0.1.0.64.0.1.9", 2)])["spans"][1], json!({"start":"1.0.1.0.64.0.1.9","width":"2"}));
    assert_eq!(frames::find_links_v_history("1.0.1.0.1", &[(1, 5)], None, 16), json!({"cur":null,"d":"1.0.1.0.1","n":16,"op":"find_links_v_history","region":[{"start":"1.1","width":"0.5"}]}));
    assert_eq!(frames::find_links_v_history("1.0.1.0.1", &[(1, 5)], Some("1.0.1.0.1.0.2.2"), 16)["cur"], "1.0.1.0.1.0.2.2");
    assert_eq!(frames::project("1.0.1.0.1.0.2.1", 2, "1.0.1.0.64"), json!({"a":"1.0.1.0.1.0.2.1","d":"1.0.1.0.64","op":"project","slot":2}));
    assert_eq!(frames::edition_claims("1.0.1.0.1"), json!({"op":"edition_claims","target":"1.0.1.0.1"}));
    let out = frames::out_claims("1.0.1.0.1.0.2.2");
    assert_eq!((out["op"].as_str(), out["x"].as_str(), out["view"].as_str()), (Some("out_claims"), Some("1.0.1.0.1.0.2.2"), Some("active")));
    let runs = [frames::shot_run("1.0.1.0.1", "1.0.1.0.1.0.1.1", 3), frames::shot_run("1.0.1.0.69", "1.0.1.0.69.0.1.1", 2)];
    let places = [Value::Null, frames::place(4)];
    // Two `also` drafts' own places: one carrying a place, one all null —
    // dropped, as a `places` list of nulls is.
    let also_places = [frames::AlsoPlacesFrame { draft: "1.0.1.0.70", places: &[Value::Null, frames::place(9)] }, frames::AlsoPlacesFrame { draft: "1.0.1.0.71", places: &[Value::Null, Value::Null] }];
    let links = [frames::link_entry("member", frames::member_end(&[(4, 2)]), frames::addrs_end(&["1.0.1.0.64"]), frames::addrs_end(&["1.1.0.1.0.1.0.3.13"]), Some("1.0.1.0.69.0.2.1"))];
    let frame = frames::publication(&frames::PublishFrame {
        doc: Some("1.0.1.0.1"),
        base: Some(("1.0.1.0.1.2", 3)),
        draft: Some("1.0.1.0.69"),
        also: &["1.0.1.0.70", "1.0.1.0.71"],
        runs: &runs,
        places: &places,
        also_places: &also_places,
        links: &links,
        retract: &["1.0.1.0.1.0.2.1"],
        read_with: &["1.0.1.0.64"],
        ..frames::PublishFrame::default()
    });
    assert_eq!(
        frame,
        json!({"also":["1.0.1.0.70","1.0.1.0.71"],"also_places":[{"draft":"1.0.1.0.70","places":[null,{"ordinal":"9","subspace":"1"}]}],"base":"1.0.1.0.1.2","base_extent":"3","doc":"1.0.1.0.1","draft":"1.0.1.0.69","links":[{"from":{"member":[{"ordinal":"4","width":"2"}]},"home":"member","old":"1.0.1.0.69.0.2.1","to":{"addrs":["1.0.1.0.64"]},"ty":{"addrs":["1.1.0.1.0.1.0.3.13"]}}],"op":"publish","places":[null,{"ordinal":"4","subspace":"1"}],"read_with":["1.0.1.0.64"],"retract":["1.0.1.0.1.0.2.1"],"runs":[{"i_start":"1.0.1.0.1.0.1.1","origin":"1.0.1.0.1","width":"3"},{"i_start":"1.0.1.0.69.0.1.1","origin":"1.0.1.0.69","width":"2"}]})
    );
    // A frame carrying no optional member is the bare shot — byte for byte.
    let bare = frames::publication(&frames::PublishFrame { doc: Some("1.0.1.0.1"), base: Some(("1.0.1.0.1.2", 3)), draft: Some("1.0.1.0.69"), runs: &runs, id: Some("k"), ..frames::PublishFrame::default() });
    assert_eq!(bare, json!({"base":"1.0.1.0.1.2","base_extent":"3","doc":"1.0.1.0.1","draft":"1.0.1.0.69","id":"k","op":"publish","runs":runs}));
    // The mint form: `account` with `mint` and `claim`, no `doc`; a list of
    // nulls is no `places` member, and `also_places` entries all null are
    // no member either.
    let mint = frames::publication(&frames::PublishFrame { account: Some("1.0.1"), mint: true, claim: true, draft: Some("1.0.1.0.69"), also: &["1.0.1.0.71"], runs: &runs[1..], places: &[Value::Null], also_places: &also_places[1..], ..frames::PublishFrame::default() });
    assert_eq!(mint, json!({"account":"1.0.1","also":["1.0.1.0.71"],"claim":true,"draft":"1.0.1.0.69","mint":true,"op":"publish","runs":runs[1..]}));
}

/// The merge marker read (the merge bridge lane): `merge_marker` decodes
/// the board's `merge` member off a `doc_metadata` answer — the sides by
/// address, the head, its count as read and the landing's position —
/// answers no marker where the board serves `null`, an absent member, or an
/// object naming no head, and no answer at all for a document that is no
/// `doc_metadata` answer, a rejection among them (the mutant that reads a
/// rejection as no marker lets a withheld draft's open claim nothing and
/// say so as a fact).
#[test]
fn the_marker_read_decodes_the_boards_merge_member_and_absent_where_it_serves_none() {
    let marked = json!({"as_of": 9, "at": 8, "base": "1.0.1.0.1.3", "base_copied": "7", "doc": "1.0.1.0.64", "merge": {"sides": ["1.0.1.0.1.2.1", "1.0.1.0.66"], "head": "1.0.1.0.1.3", "head_copied": "7", "at": 8}, "owner": "1.0.1", "published": false, "resp": "doc_metadata"});
    let marker = merge_marker(&marked).expect("a doc_metadata answer").expect("a marker");
    assert_eq!(marker, MergeMarker { sides: vec!["1.0.1.0.1.2.1".into(), "1.0.1.0.66".into()], head: "1.0.1.0.1.3".into(), head_copied: Some(7), at: Some(8) });
    let bare = json!({"as_of": 9, "at": 8, "base": "1.0.1.0.1.3", "base_copied": "7", "doc": "1.0.1.0.64", "merge": null, "owner": "1.0.1", "published": false, "resp": "doc_metadata"});
    assert_eq!(merge_marker(&bare), Some(None), "a draft carrying no marker");
    let absent = json!({"as_of": 9, "doc": "1.0.1.0.64", "owner": "1.0.1", "published": false, "resp": "doc_metadata"});
    assert_eq!(merge_marker(&absent), Some(None), "an older board serving no member");
    let headless = json!({"as_of": 9, "doc": "1.0.1.0.64", "merge": {"sides": []}, "owner": "1.0.1", "published": false, "resp": "doc_metadata"});
    assert_eq!(merge_marker(&headless), Some(None), "an object naming no head is no marker");
    let empty_sides = json!({"as_of": 9, "doc": "1.0.1.0.64", "merge": {"sides": [], "head": "1.0.1.0.1.3"}, "owner": "1.0.1", "published": false, "resp": "doc_metadata"});
    assert_eq!(merge_marker(&empty_sides).flatten().map(|m| (m.sides.len(), m.head_copied, m.at)), Some((0, None, None)), "the draft-side form's marker names no daughter");
    let refused = json!({"code": "withheld", "disposition": "permanent", "op": "doc_metadata", "resp": "rejected", "site": {"addr": "1.0.1.0.64"}});
    assert_eq!(merge_marker(&refused), None, "a rejection is no answer, never no marker");
    assert_eq!(merge_marker(&json!({"as_of": 9, "resp": "span_set", "set": []})), None);
}

/// Checks the type constants against the wire's own spellings.
///
/// The four the publication reads by are each the wire's own
/// spelling (a literal, with its line): the correspondence class the
/// publish shot's records are typed (wire.md §The publish shot and
/// head-float: "`1.1.0.1.0.1.0.3.102.1`"), the held removal (the
/// vocabulary's `3.24`), the read-with ("typed `3.71`") and the edition
/// claim ("typed `3.14`"); the retraction class, the format's fifth
/// reserved tumbler, beside them, the mail type the paged mail search
/// asks by (the vocabulary's `3.15`), the type of a mark's link (the
/// vocabulary's `3.25`), and an issue's three records, the code-link
/// family's `fixes`, `concerns` and `found-while` (the vocabulary's
/// `3.63.1`, `3.63.2` and `3.63.6`).
#[test]
fn the_type_constants_are_the_wires_spellings() {
    assert_eq!(frames::T_CORRESPONDENCE, "1.1.0.1.0.1.0.3.102.1");
    assert_eq!(frames::T_HELD_REMOVAL, "1.1.0.1.0.1.0.3.24");
    assert_eq!(frames::T_READ_WITH, "1.1.0.1.0.1.0.3.71");
    assert_eq!(frames::T_EDITION, "1.1.0.1.0.1.0.3.14");
    assert_eq!(frames::T_MAIL, "1.1.0.1.0.1.0.3.15");
    assert_eq!(frames::T_MARKS, "1.1.0.1.0.1.0.3.25");
    assert_eq!(frames::T_FIXES, "1.1.0.1.0.1.0.3.63.1");
    assert_eq!(frames::T_CONCERNS, "1.1.0.1.0.1.0.3.63.2");
    assert_eq!(frames::T_FOUND_WHILE, "1.1.0.1.0.1.0.3.63.6");
    assert_eq!(T_RETRACTION, "1.1.0.1.0.1.0.1.5");
    assert_eq!(frames::REGISTRY_DOCUMENT, "1.1.0.1.0.1");
    assert_eq!(frames::i_span("1.0.1.0.1.0.1.4", 2), json!({"start":"1.0.1.0.1.0.1.4","width":"0.0.0.0.0.0.0.2"}), "a slot's span: the width a displacement");
    assert_eq!(frames::end_span("1.0.1.0.1.0.1.4", 2), json!({"start":"1.0.1.0.1.0.1.4","width":"2"}), "a request end's span: the width a natural");
}

/// The room a position of a read by identity takes is the constant's.
///
/// An `i_delivery` item is spelled as the board marshals one, a comma after
/// it: beside its address a byte spelled as itself takes 34 bytes, a control
/// byte, which JSON spells in six, the constant's 39, and no single-byte
/// text value, `hex` item or `null` takes more; the wire's own example item
/// takes the first figure (the mutant that sizes a read by a smaller room
/// asks parts whose answers pass the dialer's cap).
#[test]
fn a_position_of_a_read_by_identity_takes_its_room_at_most() {
    let addr = "1.0.1.0.1.0.1.1";
    let room = |value: Value| json!({"at": addr, "value": value}).to_string().len() + ",".len() - addr.len();
    assert_eq!(room(json!({"content": "h"})), 34);
    assert_eq!(room(json!({"content": char::from(1u8).to_string()})), frames::I_ITEM_ROOM, "a control byte, in six");
    assert_eq!(frames::I_ITEM_ROOM, 39);
    for byte in 0u8..0x80 {
        assert!(room(json!({"content": char::from(byte).to_string()})) <= frames::I_ITEM_ROOM, "the byte {byte:#04x}");
    }
    assert!(room(json!({"hex": "e2"})) < frames::I_ITEM_ROOM && room(Value::Null) < frames::I_ITEM_ROOM);
    // `<!-- wire: response i_delivery -->`: the example's first item.
    let example = r#"{"as_of":9,"items":[{"at":"1.0.1.0.1.0.1.1","value":{"content":"h"}},{"at":"1.0.1.0.1.0.1.2","value":null}],"resp":"i_delivery"}"#;
    let first = r#"{"at":"1.0.1.0.1.0.1.1","value":{"content":"h"}},"#;
    assert!(example.contains(first) && first.len() == 34 + addr.len());
    // The answer's envelope at its widest — the largest `as_of` — takes the
    // room the constant gives it.
    let widest = json!({"as_of": u64::MAX, "items": [], "resp": "i_delivery"}).to_string();
    assert!(widest.len() <= frames::I_DELIVERY_ENVELOPE, "{widest}");
    // A part of the delivery budget at that room, under a short address,
    // fits the dialer's cap; under a long one it does not, so a reader sizes
    // its parts by the room.
    let budget = 1usize << 17;
    let envelope = frames::I_DELIVERY_ENVELOPE;
    assert!(budget * (frames::I_ITEM_ROOM + 22) + envelope <= crate::dial::MAX_ANSWER_BYTES);
    assert!(budget * (frames::I_ITEM_ROOM + 31) + envelope > crate::dial::MAX_ANSWER_BYTES);
}

/// A read by identity answers one value a position, `null` in its place.
///
/// The wire's own `i_delivery` example decodes to `h` and a position the
/// document never minted; a `hex` per-byte value is its one byte and a
/// composite its whole bytes. A per-byte item spelling other than one byte,
/// a hex that does not decode, a kind this crate does not know and an item
/// with no `value` spell no answer, and neither does a `delivery` or a
/// rejection (the mutant that reads `null` as an empty value lets a word
/// the board never minted be signed as nothing). A several-span
/// `retrieve_v` is one spec a span, in order, and one span its one spec.
#[test]
fn a_read_by_identity_decodes_one_value_a_position_and_keeps_null_in_its_place() {
    // `<!-- wire: response i_delivery -->`.
    let example: Value = serde_json::from_str(r#"{"as_of":9,"items":[{"at":"1.0.1.0.1.0.1.1","value":{"content":"h"}},{"at":"1.0.1.0.1.0.1.2","value":null}],"resp":"i_delivery"}"#).unwrap();
    assert_eq!(answers::i_delivery_values(&example), Some(vec![Some(b"h".to_vec()), None]));
    let one = |value: Value| {
        answers::i_delivery_values(&json!({"as_of": 9, "items": [{"at": "1.0.1.0.1.0.1.1", "value": value}], "resp": "i_delivery"}))
    };
    assert_eq!(one(json!({"hex": "e2"})), Some(vec![Some(vec![0xe2])]));
    assert_eq!(one(json!({"atom": "chunk"})), Some(vec![Some(b"chunk".to_vec())]));
    assert_eq!(one(json!({"atom_hex": "00ff"})), Some(vec![Some(vec![0x00, 0xff])]));
    for spells_none in [json!({"content": "hi"}), json!({"content": ""}), json!({"hex": "e2e2"}), json!({"hex": "zz"}), json!({"ref": "1.0.1.0.1.0.2.1"})] {
        assert_eq!(one(spells_none.clone()), None, "{spells_none}");
    }
    assert_eq!(answers::i_delivery_values(&json!({"as_of": 9, "items": [{"at": "1.0.1.0.1.0.1.1"}], "resp": "i_delivery"})), None, "an item with no value");
    assert_eq!(answers::i_delivery_values(&json!({"as_of": 9, "items": [{"content": "h"}], "resp": "delivery"})), None, "a delivery is no read by identity");
    assert_eq!(answers::i_delivery_values(&json!({"code": "withheld", "op": "retrieve_i", "resp": "rejected", "site": {"addr": "1.0.1.0.64"}})), None);
    assert_eq!(
        frames::retrieve_v_of("1.0.1.0.1.2", &[(1, 4), (10, 7)]),
        json!({"op": "retrieve_v", "specs": [{"doc": "1.0.1.0.1.2", "span": {"start": "1.1", "width": "0.4"}}, {"doc": "1.0.1.0.1.2", "span": {"start": "1.10", "width": "0.7"}}]})
    );
    assert_eq!(frames::retrieve_v("1.0.1.0.1.2", 1, 4), frames::retrieve_v_of("1.0.1.0.1.2", &[(1, 4)]), "one span, one spec");
}

/// A whole image is decoded whole, its runs tiling the positions from 1.
///
/// The wire's own `runs` example is one run of five positions; runs come in
/// V order with the ordinal each begins at, a run placed twice standing
/// twice and a run of no address dropped; an empty document's image is the
/// empty one; an image of more runs than one answer carries, as its pages
/// answered it, is decoded whole; and an answer that is no image, a short
/// page among them, a run that does not parse and positions that reach the
/// range's end are no image at all, never a part of one (the mutant that
/// reads what it can of a broken answer shifts every position past the
/// break; the one that reads a short page's runs takes a first page for
/// the document).
#[test]
fn a_whole_image_is_decoded_whole_or_not_at_all() {
    // `<!-- wire: response runs -->`.
    let example = whole_image(&json!({"as_of":9,"resp":"runs","runs":[{"i_start":"1.0.1.0.1.0.1.1","width":"5"}]})).expect("an image");
    assert_eq!((example.runs(), example.extent()), (&[IRun { prefix: "1.0.1.0.1.0.1".into(), first: 1, width: 5, ordinal: 1 }][..], 5));
    let twice = json!({"resp":"runs","runs":[{"i_start":"1.0.1.0.1.0.1.4","width":"3"},{"i_start":"1.0.1.0.64.0.1.9","width":"0"},{"i_start":"1.0.1.0.64.0.1.9","width":"2"},{"i_start":"1.0.1.0.1.0.1.4","width":"3"}]});
    let image = whole_image(&twice).expect("an image");
    assert_eq!(
        image.runs().iter().map(|run| (run.prefix.as_str(), run.first, run.width, run.ordinal)).collect::<Vec<_>>(),
        [("1.0.1.0.1.0.1", 4, 3, 1), ("1.0.1.0.64.0.1", 9, 2, 4), ("1.0.1.0.1.0.1", 4, 3, 6)]
    );
    assert_eq!(image.extent(), 8);
    assert_eq!(whole_image(&json!({"as_of":9,"resp":"runs","runs":[]})), Some(Image::default()), "an empty document");
    assert_eq!(Image::default().extent(), 0);
    let broken = json!({"resp":"runs","runs":[{"i_start":"1.0.1.0.1.0.1.1","width":"2"},{"i_start":"1.0.1.0.1.0.1.x","width":"1"}]});
    assert_eq!(whole_image(&broken), None, "one run that does not parse");
    assert_eq!(whole_image(&json!({"code":"image_too_large","op":"image","resp":"rejected"})), None, "a rejection is no image");
    assert_eq!(whole_image(&json!({"as_of":9,"resp":"span_set","set":[]})), None);
    let many: Vec<Value> = (1..=(1u64 << 12) + 1).map(|k| json!({"i_start": format!("1.0.1.0.1.0.1.{}", 2 * k), "width": "1"})).collect();
    assert_eq!(whole_image(&json!({"resp":"runs","runs":many.clone()})).map(|image| image.extent()), Some((1 << 12) + 1), "past one answer's runs, whole");
    // `<!-- wire: response image_page -->`, and a page of the budget's runs.
    let example = json!({"as_of":9,"ispans":[{"i_start":"1.0.1.0.1.0.1.1","width":"5"}],"next":{"arranged_at":7,"at":"6","surface":"1.0.1.0.1"},"resp":"image_page"});
    assert_eq!(whole_image(&example), None, "a short page is no image");
    assert!(example["runs"].is_null(), "and holds no `runs` for a reader of one to take");
    let page = json!({"resp":"image_page","as_of":9,"ispans":many[..1 << 12],"next":{"arranged_at":7,"at":"4097","surface":"1.0.1.0.1"}});
    assert_eq!(whole_image(&page), None, "never its first page as the whole");
    let run = |width: u64| json!({"resp":"runs","runs":[{"i_start":"1.0.1.0.1.0.1.1","width":width.to_string()}]});
    assert_eq!(whole_image(&run(u64::MAX)), None, "positions that leave no position past the last");
    assert_eq!(whole_image(&run(u64::MAX - 1)).map(|image| image.extent()), Some(u64::MAX - 1), "the widest image: one past its last position is a position still");
}

/// Checks that only an `ack_addr` saying so reads as committing nothing.
///
/// wire.md §The response envelope: an `ack_addr` carrying `"committed":
/// false` committed nothing, and every other answer did or is no ack of this
/// kind — the member absent, `true`, an `ack` or `ack_edit` with no such
/// member, a rejection — so only the first reads as a write to note nothing
/// for (the mutant that reads the member off any answer, or reads an absent
/// one as `false`, has the hold note no write at all).
#[test]
fn an_ack_reads_as_committing_nothing_only_where_its_ack_addr_says_so() {
    let ack_addr = |extra: Value| {
        let mut v = json!({"resp": "ack_addr", "addr": "1.0.1.0.2", "at": 75});
        v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        v
    };
    assert!(acked_nothing(&ack_addr(json!({"committed": false}))), "the no-commit ack");
    assert!(!acked_nothing(&ack_addr(json!({}))), "the member absent: a commit");
    assert!(!acked_nothing(&ack_addr(json!({"committed": true}))), "the member true");
    assert!(!acked_nothing(&json!({"resp": "ack", "at": 75, "committed": false})), "an `ack` carries no such member");
    assert!(!acked_nothing(&json!({"resp": "rejected", "code": "not_owner", "committed": false})), "a refusal is no ack");
    assert_eq!(acked_at(&ack_addr(json!({"committed": false}))), Some(75), "its `at` still reads, for the caller to set aside");
}

/// wire.md §Rejections: a rejection's `site` — `addr` at `already_published`
/// (the member), `index` at `kept_place_moved` and the deposit tokens, both
/// absent where the code carries none.
#[test]
fn a_rejection_carries_its_site_where_the_code_names_one() {
    let twin = Rejection::of(&json!({"code":"already_published","disposition":"permanent","op":"publish","resp":"rejected","site":{"addr":"1.0.1.0.64.3"}})).unwrap();
    assert_eq!((twin.site().addr.as_deref(), twin.site().index, twin.code()), (Some("1.0.1.0.64.3"), None, "already_published"));
    let moved = Rejection::of(&json!({"code":"kept_place_moved","disposition":"permanent","op":"publish","resp":"rejected","site":{"index":2}})).unwrap();
    assert_eq!((moved.site().addr.as_deref(), moved.site().index), (None, Some(2)));
    let old = Rejection::of(&json!({"code":"old_refused","detail":"superseded","disposition":"permanent","op":"publish","resp":"rejected","site":{"index":0}})).unwrap();
    assert_eq!((old.key(), old.detail(), old.site().index, old.op()), ("old_refused", Some("superseded"), Some(0), Some("publish")));
    let bare = Rejection::of(&json!({"code":"signed_session_required","disposition":"permanent","op":"publish","resp":"rejected"})).unwrap();
    assert_eq!(*bare.site(), Site::default());
}

/// wire.md §Rejections: a walk keys on the `detail` of the two families
/// that carry a machine token there, and on the `code` everywhere else —
/// never on a `detail` that is prose.
#[test]
fn a_rejection_keys_on_the_one_token_the_wire_dispatches_on() {
    let key = |v: Value| Rejection::of(&v).expect("a rejection").key().to_string();
    assert_eq!(key(json!({"code":"credential_refused","detail":"claim_first","disposition":"permanent","op":"delegate","resp":"rejected"})), "claim_first");
    assert_eq!(key(json!({"code":"credential_refused","detail":"attestation_invalid:signature","disposition":"permanent","op":"insert","resp":"rejected"})), "attestation_invalid:signature");
    assert_eq!(key(json!({"code":"registry_refused","detail":"registry_form","disposition":"permanent","op":"make_link","resp":"rejected"})), "registry_form");
    assert_eq!(key(json!({"code":"not_authorized","disposition":"permanent","op":"delegate","resp":"rejected"})), "not_authorized");
    assert_eq!(key(json!({"code":"malformed","detail":"unknown op 'frobnicate'","disposition":"permanent","op":"unparseable","resp":"rejected"})), "malformed");
    assert!(Rejection::of(&json!({"resp":"ack","at":3})).is_none());
}

/// A board that answers every request with one body, `200` — the death
/// signal on its head where `closed` — keeping each request it serves
/// beside the origin it was dialed at.
struct Answering {
    body: Vec<u8>,
    closed: bool,
    sent: Mutex<Vec<(Origin, Request)>>,
}

impl Answering {
    fn new(body: &str, closed: bool) -> Answering {
        Answering { body: body.as_bytes().to_vec(), closed, sent: Mutex::new(Vec::new()) }
    }
}

impl Dialer for Answering {
    fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, crate::dial::DialError> {
        self.sent.lock().unwrap().push((origin.clone(), req.clone()));
        let headers = crate::dial::Headers(if self.closed { vec![("Skepd-Session".into(), "closed".into())] } else { Vec::new() });
        Ok(Response { status: 200, headers, body: self.body.clone() })
    }

    fn stream(
        &self,
        _origin: &Origin,
        _head: &crate::dial::RequestHead,
        _body: &mut dyn std::io::Read,
        _on_interim: &mut dyn FnMut(&crate::dial::Headers),
    ) -> Result<crate::dial::StreamedResponse, crate::dial::DialError> {
        unreachable!("no read of the board streams")
    }
}

fn origin() -> Origin {
    Origin::parse("http://127.0.0.1:8642").unwrap()
}

/// The death signal is the board's to settle: under a token it is the
/// session's answer; on a token-free read it is a fault, halted at the
/// door — never an empty set, an absent row or a missing head. One
/// dialer, shared through an `Arc`, serves every board that holds it.
#[test]
fn a_guest_read_halts_on_the_death_signal_and_a_session_reads_it() {
    let dialer = Arc::new(Answering::new(r#"{"resp":"key_set","as_of":1,"enrolled":[],"retired":[]}"#, true));
    let board = Board::new(origin(), dialer.clone());
    let token = Token::parse("9f3a6c21d4b8e07a5c1b2d4e6f708192").unwrap();
    let fault = |h: Halt| assert!(h.to_string().contains("a token-free read met the death signal"), "{h}");
    fault(board.guest(&frames::key_set("1.0.1")).unwrap_err());
    fault(board.key_set("1.0.1").unwrap_err());
    fault(board.board_term().unwrap_err());
    fault(board.op_at(None, 3, &frames::key_set("1.0.1")).unwrap_err());
    fault(board.changes_key(3).unwrap_err());
    assert_eq!(board.op(Some(&token), &frames::key_set("1.0.1")).unwrap(), Answer::Closed);
    assert_eq!(board.op_at(Some(&token), 3, &frames::key_set("1.0.1")).unwrap(), AtAnswer::Closed);
    let shared: Arc<dyn Dialer> = dialer.clone();
    fault(Board::new(origin(), shared).key_set("1.0.1").unwrap_err());
    assert_eq!(dialer.sent.lock().unwrap().len(), 8, "both boards rode the one dialer");
}

/// A board signed for another origin than it dials (AUTH-4.57 (a)'s
/// client half): every request goes to the dialed origin, and a signed
/// session body names the SIGNED one (AUTH-4.8) — its scope where the
/// session is scoped (AUTH-6.2) — while a bare body names the principal
/// alone.
#[test]
fn a_board_signing_for_another_origin_dials_its_own_and_frames_the_signed_one() {
    let signed = Origin::parse("https://board.example").unwrap();
    let dialer = Arc::new(Answering::new("{}", false));
    let board = Board::new(origin(), dialer.clone()).signing_for(signed.clone());
    assert_eq!((board.dialed(), board.signed()), (&origin(), &signed));
    let nonce = "ab".repeat(32);
    for scope in [Scope::Content, Scope::Full] {
        let _ = board.session_open(SessionBody::Signed { principal: 7, nonce: &nonce, sig_hex: "cd", scope });
    }
    let _ = board.session_open(SessionBody::Bare { principal: 0 });
    let sent = dialer.sent.lock().unwrap();
    assert!(sent.iter().all(|(dialed, req)| *dialed == origin() && req.path == "/session"), "every request dials the dialed origin");
    let body = |i: usize| serde_json::from_slice::<Value>(&sent[i].1.body).unwrap();
    assert_eq!(body(0), json!({"principal": 7, "nonce": nonce, "origin": "https://board.example", "scope": "content", "sig": "cd"}));
    assert_eq!(body(1), json!({"principal": 7, "nonce": nonce, "origin": "https://board.example", "sig": "cd"}));
    assert_eq!(body(2), json!({"principal": 0}));
}

/// A challenge is the board's nonce and TTL, never a sentinel: a body
/// missing either, or naming a TTL of zero, halts naming the member, and
/// a whole one answers the TTL as a duration.
#[test]
fn a_challenge_missing_its_nonce_or_its_ttl_is_refused_by_name() {
    let nonce = "ab".repeat(32);
    let challenge = |body: String| Board::new(origin(), Answering::new(&body, false)).challenge(7);
    let whole = challenge(format!(r#"{{"nonce":"{nonce}","principal":7,"ttl_ms":60000}}"#)).expect("a whole challenge");
    assert_eq!((whole.nonce.as_str(), whole.principal, whole.ttl), (nonce.as_str(), 7, Duration::from_secs(60)));
    for (body, member) in [
        (r#"{"principal":7,"ttl_ms":60000}"#.to_string(), "nonce"),
        (r#"{"nonce":"","principal":7,"ttl_ms":60000}"#.to_string(), "nonce"),
        (format!(r#"{{"nonce":"{nonce}","principal":7}}"#), "ttl_ms"),
        (format!(r#"{{"nonce":"{nonce}","principal":7,"ttl_ms":0}}"#), "ttl_ms"),
    ] {
        let halt = challenge(body).expect_err("no challenge");
        assert!(halt.to_string().contains(&format!("the challenge carried no {member}")), "{halt}");
        assert_eq!(halt.exit_code(), 3);
    }
}

/// D13: `H.1`'s pair is read ONCE per board and kept only once the board
/// answers one — a board with no head yet is asked again, never answered
/// absent from a cache; a head once read is never asked for again.
#[test]
fn the_board_term_is_read_once_and_never_cached_absent() {
    let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = asked.clone();
    let fake = fake::Fake::new(move |_| {
        let head = json!({"chain": "07".repeat(32), "position": 12, "type": "skep-head"}).to_string();
        let items = if count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 { json!([]) } else { json!([{"atom": head}]) };
        fake::json(200, json!({"as_of": 12, "items": items, "resp": "delivery"}))
    });
    let board = fake::board(&fake);
    let term = BoardTerm { log_position: 12, chain: [7; 32] };
    assert_eq!(board.board_term().unwrap(), None, "no head yet");
    assert_eq!(board.board_term().unwrap(), Some(term), "asked again: the head now stands");
    assert_eq!(board.board_term().unwrap(), Some(term), "kept");
    assert_eq!(fake.log(), ["POST /op retrieve_v", "POST /op retrieve_v"], "the third answered from the cache");
}

/// Checks that only a head record the board does not serve is no term.
///
/// A board serving no `H.1` — the head document not registered, or a
/// delivery holding no item — answers none; a record that stands and cannot
/// be read halts naming why, never read as no record (SP-14), and is read
/// again at the next call; a rejection of another code is the board's
/// refusal (the mutant that reads a damaged record as none lets a signed
/// write go out unsigned).
#[test]
fn a_head_record_present_but_unreadable_halts_and_only_an_absent_one_is_none() {
    let answer = |body: Value| {
        let fake = fake::Fake::new(move |_| fake::json(200, body.clone()));
        (fake::board(&fake), fake)
    };
    let delivery = |items: Value| json!({"as_of": 12, "items": items, "resp": "delivery"});
    let head = |record: Value| delivery(json!([{"atom": record.to_string()}]));
    for absent in [json!({"code": "doc_not_registered", "disposition": "reorder", "op": "retrieve_v", "resp": "rejected"}), delivery(json!([]))] {
        assert_eq!(answer(absent.clone()).0.board_term(), Ok(None), "{absent}");
    }
    let cells = [
        (delivery(json!([{"content": "{}"}])), "no record atom"),
        (delivery(json!([{"atom": "not json"}])), "no JSON"),
        (head(json!({"chain": "07".repeat(32), "position": 12, "type": "skep-other"})), "of another type"),
        (head(json!({"chain": "07".repeat(32), "type": "skep-head"})), "no position"),
        (head(json!({"chain": "07", "position": 12, "type": "skep-head"})), "no chain"),
        (json!({}), "no delivery"),
        (json!({"resp": "delivery"}), "no item list"),
    ];
    for (body, why) in cells {
        let (board, fake) = answer(body.clone());
        for _ in 0..2 {
            match board.board_term() {
                Err(Halt::Halt(face)) => assert!(face.state.contains("`H.1`") && face.cause.contains(why), "{body}: {face}"),
                other => panic!("{body}: {other:?}"),
            }
        }
        assert_eq!(fake.log(), ["POST /op retrieve_v", "POST /op retrieve_v"], "{body}: an error is read again");
    }
    let refused = answer(json!({"code": "out_of_bounds", "disposition": "permanent", "op": "retrieve_v", "resp": "rejected"})).0.board_term();
    assert!(matches!(&refused, Err(Halt::Refused(r)) if r.token() == "out_of_bounds"), "{refused:?}");
}

/// Checks that a board serving no head record is told apart by its claimant.
///
/// `board_head` answers `H.1`'s pair with no `/health` read where the record
/// stands; where none is served, a claimant named is the owed head, never a
/// board no one has claimed, and none named is that board; a record that
/// stands and cannot be read halts before `/health` is asked (SP-14).
#[test]
fn the_board_head_tells_an_owed_head_from_a_board_no_one_has_claimed() {
    let board_over = |items: Value, claimant: Value| {
        let fake = fake::Fake::new(move |req| match req.path.as_str() {
            "/health" => fake::json(200, json!({"auth": {"claimant": claimant.clone()}, "log_position": 12})),
            _ => fake::json(200, json!({"as_of": 12, "items": items.clone(), "resp": "delivery"})),
        });
        (fake::board(&fake), fake)
    };
    let record = json!([{"atom": json!({"chain": "07".repeat(32), "position": 12, "type": "skep-head"}).to_string()}]);
    let (board, fake) = board_over(record, json!("1.0.1"));
    assert_eq!(board.board_head(), Ok(BoardHead::Term(BoardTerm { log_position: 12, chain: [7; 32] })));
    assert_eq!(fake.log(), ["POST /op retrieve_v"], "no `/health` read where the record stands");
    let (board, fake) = board_over(json!([]), json!("1.0.1"));
    assert_eq!(board.board_head(), Ok(BoardHead::Owed { claimant: "1.0.1".into() }));
    assert_eq!(fake.log(), ["POST /op retrieve_v", "GET /health"]);
    assert_eq!(board_over(json!([]), Value::Null).0.board_head(), Ok(BoardHead::Unclaimed));
    for claimant in [json!("1.0.1"), Value::Null] {
        let (board, fake) = board_over(json!([{"atom": "not json"}]), claimant.clone());
        assert!(matches!(board.board_head(), Err(Halt::Halt(face)) if face.cause.contains("no JSON")), "{claimant}");
        assert_eq!(fake.log(), ["POST /op retrieve_v"], "{claimant}: a damaged record halts before `/health` is asked");
    }
}

/// AUTH-6.15: the `key` of the row at one position, as the feed writes it —
/// absent on a signed row, `null` where lost, `bare`, `system`, a
/// fingerprint, and anything else lost — a row at another position no
/// answer for this one, and the feed's floor an answer, never an exit.
#[test]
fn the_changes_key_reads_the_rows_own_testimony() {
    let fp = Fingerprint::parse_hex(&"ab".repeat(32)).unwrap();
    let row = |row: Value| fake::json(200, json!({"changes": [row], "head": 9}));
    let cases = [
        (row(json!({"at": 5})), ChangeKey::Signed),
        (row(json!({"at": 5, "key": null})), ChangeKey::Lost),
        (row(json!({"at": 5, "key": "bare"})), ChangeKey::Bare),
        (row(json!({"at": 5, "key": "system"})), ChangeKey::System),
        (row(json!({"at": 5, "key": fp.to_hex()})), ChangeKey::Key(fp)),
        (row(json!({"at": 5, "key": "not-a-fingerprint"})), ChangeKey::Lost),
        (row(json!({"at": 5, "key": 7})), ChangeKey::Lost),
        (row(json!({"at": 6, "key": "bare"})), ChangeKey::NoEntry),
        (fake::json(410, json!({"error": "history_reclaimed", "floor": 3})), ChangeKey::HistoryReclaimed { floor: Some(3) }),
    ];
    for (answer, expected) in cases {
        let fake = fake::Fake::new(move |_| answer.clone());
        assert_eq!(fake::board(&fake).changes_key(5).unwrap(), expected);
        assert_eq!(fake.log(), ["GET /changes?since=4&limit=1"], "{expected:?}: the one point query");
    }
}

/// wire.md §The change feed, Paging: an answer that would not move its
/// reader on is no answer the wire gives — a page whose `last` falls below
/// `since`, a page claiming `more` without passing `since`, a `fits` of
/// none or not below the limit asked — and halts as the transport's fault;
/// an empty page at `since` and a `fits` below the limit are answers.
#[test]
fn a_page_or_a_fits_that_moves_its_reader_nowhere_is_refused() {
    let page = |body: Value| {
        let fake = fake::Fake::new(move |_| fake::json(200, body.clone()));
        fake::board(&fake).changes(None, &ChangesQuery { since: 5, ..ChangesQuery::default() })
    };
    for stale in [json!({"changes": [], "last": 5, "more": true}), json!({"changes": [], "last": 4, "more": false}), json!({"changes": [], "more": true})] {
        let halt = page(stale.clone()).expect_err("a page that moves nothing");
        assert_eq!(halt.exit_code(), 4, "{stale}: {halt}");
    }
    assert_eq!(page(json!({"changes": [], "last": 5, "more": false})).unwrap(), ChangesAnswer::Page(ChangesPage { changes: Vec::new(), last: 5, more: false }));
    let fits = |fits: u64, limit: Option<u64>| {
        let fake = fake::Fake::new(move |_| fake::json(400, json!({"budget": 2097152, "detail": "the page passes its budget", "error": "malformed_changes", "fits": fits})));
        fake::board(&fake).changes(None, &ChangesQuery { since: 5, limit, ..ChangesQuery::default() })
    };
    for (n, limit) in [(256, None), (0, None), (100, Some(100)), (101, Some(100))] {
        assert_eq!(fits(n, limit).expect_err("a fits that shrinks nothing").exit_code(), 4, "fits {n} at limit {limit:?}");
    }
    assert_eq!(fits(99, Some(100)).unwrap(), ChangesAnswer::TooLarge { fits: 99 });
    assert_eq!(fits(255, None).unwrap(), ChangesAnswer::TooLarge { fits: 255 });
}

/// A signer that keeps every payload it is handed, beside the key it signs
/// with: what a composer signed, byte for byte.
#[cfg(feature = "acting")]
struct Recording {
    key: skep_signature::HybridSigner,
    signed: Mutex<Vec<Vec<u8>>>,
}

#[cfg(feature = "acting")]
impl crate::sign::Signer for Recording {
    fn public_key(&self) -> &PublicKey {
        crate::sign::Signer::public_key(&self.key)
    }

    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        self.signed.lock().unwrap().push(payload.to_vec());
        crate::sign::Signer::sign(&self.key, payload)
    }
}

/// THE WELL-KNOWN CREATION's FRAME (wire.md §Namespace; §Credential
/// refusals, the creation's cell): the mailbox's frame sends `"slot": 2`
/// and no `attest`; the signed frame of a published slot — the bio's, the
/// link page's, the policy document's — sends its `slot` and an `attest`
/// whose signature is over the empty body under the op's own token, the
/// frame's `account` the session's own and its `doc` THE SLOT DOCUMENT's OWN
/// ADDRESS, `<account>.0.<slot>` — never the parent account, never another
/// slot's address, never `create_new_document`'s token — and verifies under
/// the signer's key. The composer signs no mailbox and no number no slot
/// has: each is this client's own fault, nothing composed.
#[cfg(feature = "acting")]
#[test]
fn a_published_slots_creation_frame_carries_its_slot_and_an_attest_over_the_slots_address() {
    use skep_identity::{entry_body_empty, entry_frame, ContentFreeOp, DocTerm};

    use crate::address::{parse_address, well_known_of, BIO_SLOT, LINK_PAGE_SLOT, MAILBOX_SLOT, POLICY_SLOT};
    use crate::ceremony::well_known_frame;
    use crate::sign::Signer;

    let key = Recording {
        key: skep_signature::HybridSigner::from_seed(skep_signature::TAG_MLDSA65_ED25519, &[7; 32]).expect("tag 1"),
        signed: Mutex::new(Vec::new()),
    };
    let term = BoardTerm { log_position: 12, chain: [7; 32] };
    let alg = key.public_key().alg().to_string();
    assert_eq!(frames::create_mailbox("1.0.1", None)["slot"], MAILBOX_SLOT, "the mailbox's frame names its slot");
    assert!(frames::create_mailbox("1.0.1", None).get("attest").is_none(), "and carries no attest");

    // The session's own account, and an account it names beside its own.
    for (own, account) in [("1.0.1", "1.0.1"), ("1.0.1", "1.0.1.2")] {
        let spelled = |doc: &str, op: ContentFreeOp| {
            let (own, doc) = (parse_address(own).unwrap(), parse_address(doc).unwrap());
            entry_frame(&alg, term, &own, DocTerm::One(&doc), &entry_body_empty(op))
        };
        for slot in [BIO_SLOT, LINK_PAGE_SLOT, POLICY_SLOT] {
            let frame = well_known_frame(term, own, account, slot, &key, Some("w-1")).expect("a published slot's frame");
            assert_eq!((frame["op"].as_str(), frame["account"].as_str(), frame["slot"].as_u64(), frame["id"].as_str()), (Some("create_well_known_document"), Some(account), Some(slot), Some("w-1")));
            assert_eq!(frame.as_object().map(|members| members.len()), Some(5), "the op, the account, the slot, the id and the attest: {frame}");
            let signed = std::mem::take(&mut *key.signed.lock().unwrap());
            let document = well_known_of(account, slot);
            assert_eq!(signed, [spelled(&document, ContentFreeOp::CreateWellKnownDocument)], "slot {slot} of {account}: signed over {document}");
            assert_ne!(signed[0], spelled(account, ContentFreeOp::CreateWellKnownDocument), "slot {slot}: never the parent account");
            assert_ne!(signed[0], spelled(&document, ContentFreeOp::CreateNewDocument), "slot {slot}: never `create_new_document`'s token");
            // The member is the wire's: the key's token, and a signature
            // that verifies over those bytes and over no other slot's.
            assert_eq!(frame["attest"]["alg"], alg.as_str());
            let sig = crate::hex::decode(frame["attest"]["sig"].as_str().expect("the signature's hex")).expect("hex");
            assert_eq!(skep_signature::verify(key.tag(), key.public_key(), &signed[0], &sig), Ok(()), "slot {slot}: the attest verifies over the slot's frame");
            for other in [BIO_SLOT, LINK_PAGE_SLOT, POLICY_SLOT].into_iter().filter(|other| *other != slot) {
                let elsewhere = spelled(&well_known_of(account, other), ContentFreeOp::CreateWellKnownDocument);
                assert!(skep_signature::verify(key.tag(), key.public_key(), &elsewhere, &sig).is_err(), "a frame signed for slot {slot} verifies at slot {other}");
            }
        }
    }
    for refused in [MAILBOX_SLOT, 1, 6, 63, 64] {
        assert!(well_known_frame(term, "1.0.1", "1.0.1", refused, &key, None).is_err(), "document {refused} is no published well-known slot");
    }
    assert!(well_known_frame(term, "1.x", "1.0.1", POLICY_SLOT, &key, None).is_err(), "an account that is no address");
    assert!(key.signed.lock().unwrap().is_empty(), "a frame not composed signs nothing");
}

/// The pages a paged read sends, as [`answers::paging::Paged`] logs them.
fn pages(board: &answers::paging::Paged) -> Vec<answers::paging::Served> {
    board.served()
}

/// A long image is read whole, a page a frame and no frame more: a
/// document of R runs is ⌈R ÷ 4,096⌉ frames, each beginning where the page
/// before it ended and asking the rest of the span, none of a halved width;
/// the pages' runs stand in order in one `runs` answer, whose `as_of` is
/// the first page's; and an image within one answer is one frame, its
/// answer the board's own.
#[test]
fn a_paged_image_is_one_frame_a_page_and_answers_every_run() {
    for (runs, frames) in [(5_000u64, 2usize), (12_289, 4), (4_096, 1), (3, 1)] {
        let board = answers::paging::Paged::of("1.0.1.0.64", runs);
        let first = frames::image(&board.doc, 1, runs);
        let answer = paged_image(&first, |frame, at| Ok::<_, ()>(board.answer(frame, at))).expect("answered");
        assert_eq!((answer["resp"].as_str(), answer["as_of"].as_u64()), (Some("runs"), Some(100)), "{runs} runs: the first page's position");
        assert_eq!(answer["runs"].as_array().expect("runs"), &board.wire_runs(), "{runs} runs, every one");
        let image = whole_image(&answer).expect("a whole image");
        assert_eq!((image.runs().len() as u64, image.extent()), (runs, runs));
        let expected: Vec<answers::paging::Served> = (0..frames as u64).map(|page| (None, 1 + page * 4_096, runs - page * 4_096, page > 0)).collect();
        assert_eq!(pages(&board), expected, "{runs} runs: ⌈R ÷ 4,096⌉ frames, each the rest of the span");
    }
    // Under `own`, and from inside the document: the frame's other members
    // ride every page.
    let board = answers::paging::Paged::of("1.0.1.0.64", 9_000);
    let first = frames::image_own(&board.doc, 501, 8_500);
    let mut sent = Vec::new();
    let answer = paged_image(&first, |frame, at| {
        sent.push(frame.clone());
        Ok::<_, ()>(board.answer(frame, at))
    })
    .expect("answered");
    assert_eq!(answer["runs"].as_array().map(Vec::len), Some(8_500));
    assert!(sent.len() == 3 && sent.iter().all(|frame| frame["own"] == true && frame["d"] == "1.0.1.0.64"), "{sent:?}");
    assert_eq!(pages(&board), [(None, 501, 8_500, false), (None, 4_597, 4_404, true), (None, 8_693, 308, true)]);
}

/// A reader refused `page_moved` begins again from its first page and
/// answers the new state whole; past [`PAGE_RESTARTS`] restarts it reads
/// every page as of its last first page's position, and answers that state
/// whole — the restarts counted, and the frames sent at a position.
#[test]
fn a_moved_page_begins_the_read_again_and_past_the_bound_reads_at_one_position() {
    let read = |board: &answers::paging::Paged| {
        let first = frames::image(&board.doc, 1, 5_000);
        paged_image(&first, |frame, at| Ok::<_, ()>(board.answer(frame, at))).expect("answered")
    };
    let (page, rest) = ((None, 1, 5_000, false), (None, 4_097, 904, true));
    // Moved once: one restart, the second reading answered at the head.
    let once = answers::paging::Paged::of("1.0.1.0.64", 5_000).moving(1);
    let answer = read(&once);
    assert_eq!(pages(&once), [page, rest, page, rest], "begun again from its first page");
    assert_eq!(answer["runs"].as_array().map(Vec::len), Some(5_000), "the new state, whole");
    assert_eq!(answer["as_of"].as_u64(), Some(102), "its own first page's position");
    // Moved at every reading the bound allows: still read at the head.
    let bound = answers::paging::Paged::of("1.0.1.0.64", 5_000).moving(PAGE_RESTARTS);
    let answer = read(&bound);
    let restarts = pages(&bound).iter().filter(|served| !served.3).count() as u32 - 1;
    assert_eq!(restarts, PAGE_RESTARTS, "as many restarts as the bound, none at a position");
    assert!(pages(&bound).iter().all(|served| served.0.is_none()) && answer["runs"].as_array().map(Vec::len) == Some(5_000));
    // Moved once more: no further restart; every page at the position the
    // last first page stood at.
    let past = answers::paging::Paged::of("1.0.1.0.64", 5_000).moving(PAGE_RESTARTS + 1);
    let answer = read(&past);
    let served = pages(&past);
    let at_head = served.iter().filter(|served| served.0.is_none()).count() as u32;
    assert_eq!(at_head, 2 * (PAGE_RESTARTS + 1), "the first reading and the bound's restarts, each refused at its second page");
    let stood = 100 + u64::from(2 * PAGE_RESTARTS);
    assert_eq!(served[at_head as usize..], [(Some(stood), 1, 5_000, false), (Some(stood), 4_097, 904, true)], "then every page at the last first page's position");
    assert_eq!((answer["runs"].as_array().map(Vec::len), answer["as_of"].as_u64()), (Some(5_000), Some(stood)), "that state, whole");
}

/// A page that is not the wire's ends the read with no image: one of no
/// run, one past the budget, a go-on that does not advance, and a
/// continuation answered another shape are each the document a reader
/// decodes as no image, and a refusal other than `page_moved` is the
/// board's as it answered. A `page_moved` no restart cures, and one met at
/// a position, is that refusal.
#[test]
fn a_page_that_is_not_the_wires_is_no_image() {
    let run = |k: u64| json!({"i_start": format!("1.0.1.0.64.0.1.{}", 2 * k), "width": "1"});
    let page = |runs: u64, at: &str| json!({"resp": "image_page", "as_of": 9, "ispans": (1..=runs).map(run).collect::<Vec<_>>(), "next": {"arranged_at": 7, "at": at, "surface": "1.0.1.0.64"}});
    let first = frames::image("1.0.1.0.64", 1, 9_000);
    let unread = |answers: Vec<Value>| {
        let mut answers = answers.into_iter();
        let answer = paged_image(&first, |_, _| Ok::<_, ()>(answers.next().expect("a frame no answer was scripted for"))).expect("answered");
        assert_eq!(whole_image(&answer), None, "no image: {}", &answer.to_string()[..answer.to_string().len().min(120)]);
        answer
    };
    unread(vec![page(0, "1")]);
    unread(vec![page(4_097, "4098")]);
    unread(vec![page(4_096, "1")]);
    unread(vec![page(4_096, "9001")]);
    unread(vec![page(4_096, "4097"), json!({"resp": "span_set", "as_of": 9, "set": []})]);
    let withheld = json!({"resp": "rejected", "code": "withheld", "disposition": "reorder", "op": "image", "site": {"addr": "1.0.1.0.64"}});
    assert_eq!(unread(vec![page(4_096, "4097"), withheld.clone()]), withheld, "the board's refusal, as it answered");
    assert_eq!(unread(vec![withheld.clone()]), withheld);
    // A frame of two spans is no page this reader continues.
    let two = json!({"op": "image", "d": "1.0.1.0.64", "region": [{"start": "1.1", "width": "0.5"}, {"start": "1.9", "width": "0.5"}]});
    assert_eq!(frames::image_continued(&two, &page(4_096, "3")["next"]), None);
    // `page_moved` where the first page named no position: no position to
    // read at, so the refusal stands; and at the position, the same.
    let moved = json!({"resp": "rejected", "code": "page_moved", "disposition": "permanent", "op": "image", "site": {"addr": "1.0.1.0.64"}});
    let mut unplaced = page(4_096, "4097");
    unplaced.as_object_mut().expect("a page").remove("as_of");
    let mut sent = 0;
    let answer = paged_image(&first, |frame, at| {
        sent += 1;
        assert_eq!(at, None, "no position to read at");
        Ok::<_, ()>(if frame["cur"].is_null() { unplaced.clone() } else { moved.clone() })
    })
    .expect("answered");
    assert_eq!((answer, sent), (moved.clone(), 2 * (PAGE_RESTARTS + 1)));
    let answer = paged_image(&first, |frame, _| Ok::<_, ()>(if frame["cur"].is_null() { page(4_096, "4097") } else { moved.clone() })).expect("answered");
    assert_eq!(answer, moved, "refused at the position too: the board's refusal");
}

/// The continuation frame is the page's own with its span cut to the rest
/// and the go-on beside it, whole.
#[test]
fn a_continuation_is_the_rest_of_the_span_and_the_go_on_whole() {
    let next = json!({"arranged_at": 7, "at": "4097", "surface": "1.0.1.0.1.3"});
    assert_eq!(
        frames::image_continued(&frames::image("1.0.1.0.1", 1, 5_000), &next).expect("a continuation").to_string(),
        r#"{"cur":{"arranged_at":7,"at":"4097","surface":"1.0.1.0.1.3"},"d":"1.0.1.0.1","op":"image","region":[{"start":"1.4097","width":"0.904"}]}"#
    );
    let whole = frames::image_own("1.0.1.0.1", 1, u64::MAX);
    let continued = frames::image_continued(&whole, &next).expect("a continuation");
    assert_eq!((continued["own"].as_bool(), continued["region"][0]["width"].as_str()), (Some(true), Some(format!("0.{}", u64::MAX - 4_096).as_str())));
    for at in ["1", "0", "5001", "6000", "x", "04097"] {
        let next = json!({"arranged_at": 7, "at": at, "surface": "1.0.1.0.1"});
        assert_eq!(frames::image_continued(&frames::image("1.0.1.0.1", 1, 5_000), &next), None, "{at}: no ordinal inside the span past its start");
    }
}

/// The read over a board's own dials answers as `op` does: the whole image,
/// the death signal at whichever page it rode, and at a position the
/// board's refusal of it under its own name.
#[test]
fn the_whole_image_read_answers_as_op_does_and_names_a_positions_refusal() {
    let paged = Arc::new(answers::paging::Paged::of("1.0.1.0.64", 5_000));
    let at_of = |req: &crate::dial::Request| (req.path == "/op-at").then(|| serde_json::from_slice::<Value>(&req.body).expect("json")["at"].as_u64().expect("at"));
    let serving = paged.clone();
    let fake = fake::Fake::new(move |req| fake::json(200, serving.answer(&fake::frame(req), at_of(req))));
    let token = Token::parse(&"ab".repeat(16)).expect("a token");
    let first = frames::image("1.0.1.0.64", 1, 5_000);
    let Answer::Document(v) = whole_image_read(&fake::board(&fake), Some(&token), &first).expect("answered") else { panic!("a document") };
    assert_eq!(whole_image(&v).map(|image| image.extent()), Some(5_000));
    assert_eq!(fake.log(), ["POST /op image", "POST /op image"]);
    // The death signal on the second page.
    let serving = paged.clone();
    let dying = fake::Fake::new(move |req| if fake::frame(req)["cur"].is_null() { fake::json(200, serving.answer(&fake::frame(req), None)) } else { fake::closed() });
    assert_eq!(whole_image_read(&fake::board(&dying), Some(&token), &first).expect("answered"), Answer::Closed);
    // Moved past the bound, and the position busy: the board's own name.
    let moving = Arc::new(answers::paging::Paged::of("1.0.1.0.64", 5_000).moving(u32::MAX));
    let busy = fake::Fake::new(move |req| if req.path == "/op-at" { fake::json(503, json!({"error": "history_busy"})) } else { fake::json(200, moving.answer(&fake::frame(req), None)) });
    let Err(Halt::Refused(refused)) = whole_image_read(&fake::board(&busy), Some(&token), &first) else { panic!("the position's refusal") };
    assert_eq!((refused.status, refused.code.as_str(), &refused.body), (503, "history_busy", &json!({"error": "history_busy"})));
    assert_eq!(busy.log().iter().filter(|line| line.starts_with("POST /op-at")).count(), 1, "one frame at the position, refused");
}

/// The price read's frame and its answer (wire.md §Arrangement and §The
/// response envelope, `publish_cost`).
///
/// The frame is the `publish` frame under the read's own name, its `id` and
/// its `attest` left out and every other member as it stood, so what is
/// priced is what is sent. The answer is decoded by its seven figures — the
/// wire's own example among them — and its reads are the one sum it leaves
/// to its reader, `homes × entries + rewindow + fence`, saturating. A
/// document that is no `publish_cost` answer, one lacking a figure, and one
/// whose figure is no non-negative integer are no answer at all (the mutant
/// that reads a missing figure as zero prices an unanswered request at
/// nothing, which admits it).
#[test]
fn the_price_read_carries_the_publications_members_and_its_answer_is_seven_figures() {
    let runs = json!([{"i_start": "1.0.1.0.69.0.1.1", "origin": "1.0.1.0.69", "width": "3"}]);
    let publication = json!({"attest": {"sig": "00"}, "base": "1.0.1.0.1.2", "base_extent": "3", "doc": "1.0.1.0.1", "draft": "1.0.1.0.69", "id": "k", "op": "publish", "places": [{"ordinal": "1", "subspace": "1"}], "runs": runs, "supersede": ["1.0.1.0.1.2.1"]});
    assert_eq!(
        frames::publish_cost(publication),
        json!({"base": "1.0.1.0.1.2", "base_extent": "3", "doc": "1.0.1.0.1", "draft": "1.0.1.0.69", "op": "publish_cost", "places": [{"ordinal": "1", "subspace": "1"}], "runs": runs, "supersede": ["1.0.1.0.1.2.1"]})
    );
    // `<!-- wire: response publish_cost -->`.
    let example = json!({"as_of":9,"byte_budget":67108864,"entries":4,"fence":1613,"homes":3,"read_budget":65536,"resp":"publish_cost","rewindow":5780,"staged_bytes":2471033});
    let cost = answers::publish_cost(&example).expect("a price");
    assert_eq!(cost, answers::PublishCost { homes: 3, entries: 4, rewindow: 5_780, fence: 1_613, staged_bytes: 2_471_033, read_budget: 65_536, byte_budget: 67_108_864 });
    assert_eq!(cost.reads(), 3 * 4 + 5_780 + 1_613, "the home term beside the two the board counted whole");
    assert_eq!(answers::PublishCost { homes: u64::MAX, entries: 2, ..cost }.reads(), u64::MAX, "a sum past the integer saturates, never wraps");
    for figure in ["homes", "entries", "rewindow", "fence", "staged_bytes", "read_budget", "byte_budget"] {
        let mut lacking = example.clone();
        lacking.as_object_mut().expect("an object").remove(figure);
        assert_eq!(answers::publish_cost(&lacking), None, "no {figure}: no price");
        let mut signed = example.clone();
        signed[figure] = json!(-1);
        assert_eq!(answers::publish_cost(&signed), None, "a negative {figure}");
        let mut spelled = example.clone();
        spelled[figure] = json!("7");
        assert_eq!(answers::publish_cost(&spelled), None, "{figure} as a string");
    }
    assert_eq!(answers::publish_cost(&json!({"code": "withheld", "disposition": "permanent", "op": "publish_cost", "resp": "rejected", "site": {"addr": "1.0.1.0.69"}})), None, "a rejection is no price");
    let mut other = example.clone();
    other["resp"] = json!("count");
    assert_eq!(answers::publish_cost(&other), None, "another answer's shape");
}
