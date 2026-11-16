//! The admission frame's signature, checked where both of its halves are
//! linked (REG-4.67, REG-4.73, REG-1.86; AUTH-1.11): `skep-identity` frames
//! a registration request's members under the registration tag and links no
//! signature library, `skep-registry` parses the request's body and knows
//! no key, and `skep-signature` verifies — so the reader's whole walk, a
//! body parsed, its frame re-built from the members, its signer found among
//! its enrolments and the one signature verified under that key, stands
//! here, in a crate that links all three, as the session layer verifies a
//! handshake's frame.
//!
//! What it pins: a request verifies under its signer's key over the frame
//! its members re-build, and under no other frame — one for another door,
//! under another freshness value, of another shape or enrolment, or under
//! another tag — nor under another key.

use skep_identity::{
    enrolled_signer, encode_enroll, framed, parse_enroll, thread_key, AdmissionFrame, DoorId,
    Enrollment, Fingerprint, Freshness, PublicKey, ENTRY_TAG, KEY_TAG, REALM_TAG,
    REGISTRATION_TAG, SESSION_TAG,
};
use skep_registry::{
    encode_registration, parse_registration, BoardCarriesOn, Fresh, Hex64, HexDigits,
    RegistrationBody, RegistrationKind, RequestMembers, Vouch,
};
use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

const REALM: &str = "9f2a6c1d3e5b7a90c2d4e6f8a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9e1f2c41d";

fn signer(n: u8) -> HybridSigner {
    HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[n; 32]).expect("tag 1")
}

fn enrolment(keys: &[(u8, bool)]) -> String {
    let entries: Vec<Enrollment> = keys
        .iter()
        .map(|&(n, anchor)| Enrollment::new(signer(n).public_key().clone(), anchor, None).expect("no label"))
        .collect();
    encode_enroll(&entries)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A signature's bytes from its hex, either case; `None` for a string that
/// is not whole bytes of hex.
fn unhex(s: &str) -> Option<Vec<u8>> {
    let digits: Option<Vec<u8>> = s.chars().map(|c| c.to_digit(16).map(|d| d as u8)).collect();
    let digits = digits?;
    (digits.len() % 2 == 0).then(|| digits.chunks(2).map(|pair| pair[0] * 16 + pair[1]).collect())
}

/// The registry's own door, and a freshness value.
fn door() -> String {
    format!("realm:{REALM} door:1.1.0.1")
}

const FRESH: &str = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";

/// A request as an applicant's client composes it: the device key (seed 1)
/// signs the frame over the door, the freshness value, the row's own
/// address and the enrolments — the node account's, and for a fresh request
/// the board root's — each of which enrols the device key.
fn request(kind: RegistrationKind) -> RegistrationBody {
    let device = signer(1);
    let node = enrolment(&[(1, false), (2, true), (3, true)]);
    let board = enrolment(&[(4, true), (1, false), (5, true)]);
    let shape = kind.row().ordinal_path();
    let door = door();
    let frame = AdmissionFrame {
        door: &door,
        fresh: FRESH,
        shape: &shape,
        node: &node,
        board: (kind == RegistrationKind::Fresh).then_some(board.as_str()),
    };
    let signature = HexDigits::new(hex(&device.sign(&frame.to_bytes()))).expect("hex");
    let signer = Hex64::new(Fingerprint::of(device.public_key()).to_hex()).expect("a fingerprint");
    let fresh = Hex64::new(FRESH).expect("64 lowercase hex");
    match kind {
        RegistrationKind::Fresh => {
            RegistrationBody::Fresh(Fresh { door, fresh, shape, node, board, signer, signature })
        }
        RegistrationKind::BoardCarriesOn => RegistrationBody::BoardCarriesOn(BoardCarriesOn {
            door,
            fresh,
            shape,
            node,
            signer,
            signature,
        }),
        other => panic!("{other:?} is no request"),
    }
}

/// Why a reader does not honor a request's signature.
#[derive(Debug, PartialEq, Eq)]
enum Unverified {
    /// An enrolment the request carries is no enrolment record.
    Enrolment,
    /// No enrolment, or not every one, enrols the `signer`.
    Signer,
    /// `signature` is not whole bytes of hex.
    Hex,
    /// The signature does not verify over the frame under the signer's key.
    Signature,
}

/// THE READER's WALK over a parsed request: its enrolments parsed, its
/// `signer` found as a key every enrolment present enrols, its frame
/// re-built from the members, and its `signature` verified under that key —
/// the key's own signature-algorithm row naming the rule, the frame's tag
/// inside the framed bytes.
fn verify_request(request: &RequestMembers<'_>) -> Result<PublicKey, Unverified> {
    let node = parse_enroll(request.node.as_bytes()).map_err(|_| Unverified::Enrolment)?;
    let board = match request.board {
        Some(board) => Some(parse_enroll(board.as_bytes()).map_err(|_| Unverified::Enrolment)?),
        None => None,
    };
    let enrolments: Vec<&[Enrollment]> =
        std::iter::once(node.as_slice()).chain(board.as_deref()).collect();
    let signer = Fingerprint::parse_hex(request.signer.as_str()).ok_or(Unverified::Signer)?;
    let key = enrolled_signer(&signer, &enrolments).ok_or(Unverified::Signer)?;
    let frame = AdmissionFrame {
        door: request.door,
        fresh: request.fresh.as_str(),
        shape: request.shape,
        node: request.node,
        board: request.board,
    };
    let sig = unhex(request.signature.as_str()).ok_or(Unverified::Hex)?;
    skep_signature::verify(key.sig_alg_row().tag, key, &frame.to_bytes(), &sig)
        .map_err(|_| Unverified::Signature)?;
    Ok(key.clone())
}

/// A request's body through the wire and back: encoded, parsed under its
/// own kind, and read as a request.
fn through_the_parse(body: &RegistrationBody) -> RegistrationBody {
    let text = encode_registration(body, None);
    parse_registration(body.kind(), text.as_bytes()).expect("a canonical request").body
}

/// REG-4.67, REG-4.73 — A REQUEST VERIFIES OVER THE FRAME ITS MEMBERS
/// RE-BUILD: a request of either kind, encoded and parsed back, verifies
/// under its `signer`'s key — the device key every enrolment present enrols
/// — with no copy of the frame carried: the frame's fields are the body's
/// members, and the body's `door` and `fresh` are in their forms.
#[test]
fn a_request_verifies_under_its_signers_key_over_the_frame_its_members_rebuild() {
    for kind in [RegistrationKind::Fresh, RegistrationKind::BoardCarriesOn] {
        let parsed = through_the_parse(&request(kind));
        let members = parsed.request().expect("a request");
        assert_eq!(verify_request(&members).as_ref(), Ok(signer(1).public_key()), "{kind:?}");
        assert_eq!(members.shape, kind.row().ordinal_path(), "{kind:?}: the shape is its row's");
        assert_eq!(members.board.is_some(), kind == RegistrationKind::Fresh);
        let door = DoorId::parse(members.door).expect("the door identifier's one spelling");
        assert_eq!((door.to_string(), door.door.to_string()), (self::door(), "1.1.0.1".into()));
        assert!(Freshness::parse(members.fresh.as_str()).is_some(), "the freshness value's form");
        let fields = members.frame_fields();
        let fields: Vec<&[u8]> = fields.iter().map(|f| f.as_bytes()).collect();
        let frame = AdmissionFrame {
            door: members.door,
            fresh: members.fresh.as_str(),
            shape: members.shape,
            node: members.node,
            board: members.board,
        };
        assert_eq!(
            frame.to_bytes(),
            framed(REGISTRATION_TAG, &fields),
            "{kind:?}: the body's frame fields are the frame's"
        );
    }
}

/// A fresh request with one member replaced, re-typed where the replacement
/// drops or adds `board`.
fn altered(alter: impl FnOnce(&mut Fresh)) -> RegistrationBody {
    let RegistrationBody::Fresh(mut fresh) = request(RegistrationKind::Fresh) else {
        panic!("a fresh request")
    };
    alter(&mut fresh);
    RegistrationBody::Fresh(fresh)
}

/// REG-4.74, REG-4.84, REG-4.104 — A PAYLOAD FRAMED FOR ANOTHER DOOR, OR
/// REPLAYED UNDER ANOTHER FRESHNESS VALUE, DOES NOT VERIFY: the signature a
/// device key made over one frame verifies over no frame that differs in
/// its door — another realm, another account, a fork term, a second space
/// between terms — in its freshness value, in its shape, or in an
/// enrolment; and a fresh request re-typed board-carries-on, its `board`
/// dropped by a transcribing hand, does not verify either.
#[test]
fn a_payload_framed_over_another_door_or_freshness_value_does_not_verify() {
    let other_realm = REALM.replace("9f2a", "9f2b");
    let other_fresh = FRESH.replace("5e5e", "5e5f");
    let cases: Vec<(&str, RegistrationBody)> = vec![
        ("another realm", altered(|r| r.door = format!("realm:{other_realm} door:1.1.0.1"))),
        ("another account", altered(|r| r.door = format!("realm:{REALM} door:1.2.0.1"))),
        (
            "a fork term this lineage does not carry",
            altered(|r| r.door = format!("realm:{REALM} fork:1.1.0.1.0.1.0.2.9 door:1.1.0.1")),
        ),
        ("a second space", altered(|r| r.door = format!("realm:{REALM}  door:1.1.0.1"))),
        ("another freshness value", altered(|r| r.fresh = Hex64::new(other_fresh).expect("hex"))),
        ("the other request row's shape", altered(|r| r.shape = "3.54.1.2".into())),
        ("a parent row's shape", altered(|r| r.shape = "3.54.1".into())),
        ("another node enrolment", altered(|r| r.node = enrolment(&[(1, false), (2, true)]))),
        ("another board enrolment", altered(|r| r.board = enrolment(&[(1, false), (4, true)]))),
        ("the two enrolments swapped", altered(|r| std::mem::swap(&mut r.node, &mut r.board))),
    ];
    for (what, body) in cases {
        let parsed = through_the_parse(&body);
        let members = parsed.request().expect("a request");
        assert_eq!(verify_request(&members), Err(Unverified::Signature), "{what}");
    }
    // A fresh request's signature under a board-carries-on body: the frame
    // lacks the board field the signature covers.
    let RegistrationBody::Fresh(fresh) = request(RegistrationKind::Fresh) else {
        panic!("a fresh request")
    };
    for shape in [fresh.shape.clone(), "3.54.1.2".to_owned()] {
        let retyped = RegistrationBody::BoardCarriesOn(BoardCarriesOn {
            door: fresh.door.clone(),
            fresh: fresh.fresh.clone(),
            shape: shape.clone(),
            node: fresh.node.clone(),
            signer: fresh.signer.clone(),
            signature: fresh.signature.clone(),
        });
        let parsed = through_the_parse(&retyped);
        let members = parsed.request().expect("a request");
        assert_eq!(verify_request(&members), Err(Unverified::Signature), "re-typed, shape {shape}");
    }
    // The control: the unaltered request, through the same walk, verifies.
    let parsed = through_the_parse(&altered(|_| {}));
    assert!(verify_request(&parsed.request().expect("a request")).is_ok());
}

/// AUTH-1.11, AUTH-1.15, REG-1.86 — THE TAG AND THE KEY ARE INSIDE THE
/// CHECK: the same five fields framed under another declared tag do not
/// verify, so a signature over a request is no session's and no entry's; a
/// signature another key made does not verify under the signer's; a
/// `signer` no enrolment names, and one only the node enrolment names, is
/// refused before any verify; and a `signature` that is not whole bytes of
/// hex, or not the key's width, is refused.
#[test]
fn the_signature_verifies_under_the_registration_tag_and_the_enrolled_signer_alone() {
    let RegistrationBody::Fresh(fresh) = request(RegistrationKind::Fresh) else {
        panic!("a fresh request")
    };
    let device = signer(1);
    let fields: Vec<&[u8]> =
        [&fresh.door, fresh.fresh.as_str(), &fresh.shape, &fresh.node, &fresh.board]
            .map(|f| f.as_bytes())
            .to_vec();
    let sig = unhex(fresh.signature.as_str()).expect("hex");
    let verify = |frame: &[u8]| {
        skep_signature::verify(TAG_MLDSA65_ED25519, device.public_key(), frame, &sig).is_ok()
    };
    assert!(verify(&framed(REGISTRATION_TAG, &fields)), "the admission frame");
    for tag in [SESSION_TAG, ENTRY_TAG, REALM_TAG, KEY_TAG] {
        assert!(!verify(&framed(tag, &fields)), "{tag:?}: another tag's frame");
    }
    // Another key's signature over the right frame, presented under the
    // device key's fingerprint.
    let stranger = signer(9);
    let frame = framed(REGISTRATION_TAG, &fields);
    let forged = altered(|r| r.signature = HexDigits::new(hex(&stranger.sign(&frame))).expect("hex"));
    let parsed = through_the_parse(&forged);
    assert_eq!(verify_request(&parsed.request().expect("a request")), Err(Unverified::Signature));
    // A signer the enrolments do not all enrol.
    let fp = |n: u8| Hex64::new(Fingerprint::of(signer(n).public_key()).to_hex()).expect("hex");
    for (what, n) in [("no enrolment names", 9), ("only the node enrolment names", 2), ("only the board root's names", 4)] {
        let parsed = through_the_parse(&altered(|r| r.signer = fp(n)));
        assert_eq!(
            verify_request(&parsed.request().expect("a request")),
            Err(Unverified::Signer),
            "a signer {what}"
        );
    }
    // A signature in capitals is the same bytes and verifies; one of an odd
    // count of digits, and one of another width, do not.
    let capitals = altered(|r| r.signature = HexDigits::new(r.signature.as_str().to_uppercase()).expect("hex"));
    let parsed = through_the_parse(&capitals);
    assert!(verify_request(&parsed.request().expect("a request")).is_ok(), "hex of either case");
    let odd = altered(|r| r.signature = HexDigits::new(&r.signature.as_str()[1..]).expect("hex"));
    let parsed = through_the_parse(&odd);
    assert_eq!(verify_request(&parsed.request().expect("a request")), Err(Unverified::Hex));
    let short = altered(|r| r.signature = HexDigits::new(&r.signature.as_str()[2..]).expect("hex"));
    let parsed = through_the_parse(&short);
    assert_eq!(verify_request(&parsed.request().expect("a request")), Err(Unverified::Signature));
    // An enrolment that is no enrolment record is refused before the signer.
    let parsed = through_the_parse(&altered(|r| r.node = "no enrolment".into()));
    assert_eq!(verify_request(&parsed.request().expect("a request")), Err(Unverified::Enrolment));
}

/// REG-4.78, REG-4.185 — THE THREAD's KEY IS SPELLED AS A VOUCH's
/// `fingerprints` ARE: the key of a request's enrolments, each fingerprint
/// in its 64 lowercase hex, is a list a vouch's body carries entry for
/// entry, so the two compare by array equality; the same fingerprints out
/// of order or with one repeated are a vouch that parses and equals no
/// request's key, and the device key alone is another key.
#[test]
fn the_thread_key_is_the_list_a_vouch_carries() {
    let parsed = through_the_parse(&request(RegistrationKind::Fresh));
    let members = parsed.request().expect("a request");
    let node = parse_enroll(members.node.as_bytes()).expect("the node enrolment");
    let board = parse_enroll(members.board.expect("a board").as_bytes()).expect("the board root's");
    let key: Vec<String> =
        thread_key(node.iter().chain(&board)).iter().map(Fingerprint::to_hex).collect();
    assert_eq!(key.len(), 5, "six entries, the device key counted once");
    let vouch_of = |list: &[String]| {
        let body = RegistrationBody::Vouch(Vouch {
            fingerprints: list.iter().map(|f| Hex64::new(f.as_str()).expect("a fingerprint")).collect(),
            replaces: None,
        });
        let text = encode_registration(&body, None);
        let RegistrationBody::Vouch(vouch) =
            parse_registration(RegistrationKind::Vouch, text.as_bytes()).expect("a vouch").body
        else {
            panic!("a vouch")
        };
        vouch.fingerprints.iter().map(|f| f.as_str().to_owned()).collect::<Vec<String>>()
    };
    assert_eq!(vouch_of(&key), key, "a vouch of this request");
    let mut out_of_order = key.clone();
    out_of_order.swap(0, 1);
    let mut repeating = key.clone();
    repeating.push(key[0].clone());
    let device = vec![Fingerprint::of(signer(1).public_key()).to_hex()];
    for (what, list) in [("out of order", out_of_order), ("repeating", repeating), ("the device key alone", device)] {
        assert_ne!(vouch_of(&list), key, "{what}: a vouch of no request");
    }
}
