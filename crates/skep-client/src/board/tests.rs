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

/// wire.md's own request examples, spelled by the builders: each the line
/// under its `<!-- wire: request … -->` marker — `find_links_v` over one
/// span (§Link discovery reads), `find_links_ftt`'s four-set with a `from`
/// list and an `empty` type, `window_ftt`'s all-`any` four-set past a cursor
/// (and beside it, with no example of the wire's own, the mail search's
/// paged form at the start), the mailbox's mint,
/// `create_well_known_document` (§Namespace) at slot 2, whose frame
/// serializes to the example's line byte for byte, and the same op at
/// another slot, `count_v_by_home` with its `except`,
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

/// The four type constants the publication reads by, each the wire's own
/// spelling (a literal, with its line): the correspondence class the
/// publish shot's records are typed (wire.md §The publish shot and
/// head-float: "`1.1.0.1.0.1.0.3.102.1`"), the held removal (the
/// vocabulary's `3.24`), the read-with ("typed `3.71`") and the edition
/// claim ("typed `3.14`"); the retraction class, the format's fifth
/// reserved tumbler, beside them, and the mail type the paged mail search
/// asks by (the vocabulary's `3.15`).
#[test]
fn the_type_constants_are_the_wires_spellings() {
    assert_eq!(frames::T_CORRESPONDENCE, "1.1.0.1.0.1.0.3.102.1");
    assert_eq!(frames::T_HELD_REMOVAL, "1.1.0.1.0.1.0.3.24");
    assert_eq!(frames::T_READ_WITH, "1.1.0.1.0.1.0.3.71");
    assert_eq!(frames::T_EDITION, "1.1.0.1.0.1.0.3.14");
    assert_eq!(frames::T_MAIL, "1.1.0.1.0.1.0.3.15");
    assert_eq!(T_RETRACTION, "1.1.0.1.0.1.0.1.5");
    assert_eq!(frames::REGISTRY_DOCUMENT, "1.1.0.1.0.1");
    assert_eq!(frames::i_span("1.0.1.0.1.0.1.4", 2), json!({"start":"1.0.1.0.1.0.1.4","width":"0.0.0.0.0.0.0.2"}), "a slot's span: the width a displacement");
    assert_eq!(frames::end_span("1.0.1.0.1.0.1.4", 2), json!({"start":"1.0.1.0.1.0.1.4","width":"2"}), "a request end's span: the width a natural");
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
