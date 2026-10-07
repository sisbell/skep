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
    let f = frames::insert_atom("1.0.1.0.1", 1, "{}", T_ENROLL, Some("x"));
    assert_eq!(f["deposit"], T_ENROLL);
    assert_eq!(f["id"], "x");
    assert_eq!(f["at"]["ordinal"], "1");
    let r = Rejection::of(&json!({"code":"credential_refused","detail":"content_session","disposition":"permanent","op":"make_link","resp":"rejected"})).unwrap();
    assert_eq!(r.token(), "credential_refused:content_session");
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
