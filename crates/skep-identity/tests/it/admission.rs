//! The admission frame and its terms (AUTH-1.11; REG-4.67, REG-4.73,
//! REG-4.74, REG-4.78, REG-4.84, REG-1.86): the frame's bytes under the
//! registration tag, the door identifier's one spelling, the freshness
//! value's form, the thread's key and the signer's test. The signature over
//! the frame is checked where a signature library is linked — the daemon
//! core's suite — since this crate links none.

use crate::common;

use common::{addr, enroll_payload, fp, key};
use skep_identity::{
    enrolled_signer, framed, parse_enroll, thread_key, AdmissionFrame, DoorId, Enrollment,
    Fingerprint, Freshness, REGISTRATION_TAG, TAGS,
};

const REALM: &str = "9f2a6c1d3e5b7a90c2d4e6f8a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9e1f2c41d";

fn door() -> String {
    format!("realm:{REALM} door:1.1.0.1")
}

fn enrolment(entries: &[(u8, bool)]) -> Vec<Enrollment> {
    parse_enroll(&enroll_payload(entries)).expect("an enrolment record")
}

/// REG-4.67, AUTH-1.12 — THE FRAME IS THE REGISTRATION TAG OVER THE
/// REQUEST's MEMBERS, IN ORDER: `door`, `fresh`, `shape`, `node` and, where
/// the request carries one, `board` — each field the UTF-8 bytes of its
/// member under a four-byte big-endian length, spelled here by hand; the
/// board field left out where the board carries on, so the two kinds' frames
/// differ in their field count as in their `shape`; and a change to any one
/// field, or a byte moved across a field boundary, changes the bytes.
#[test]
fn the_frame_is_the_registration_tag_over_the_members_in_order() {
    let door = door();
    let fresh = "5e".repeat(32);
    let frame = AdmissionFrame {
        door: &door,
        fresh: &fresh,
        shape: "3.54.1.1",
        node: r#"{"type":"skep-enroll","node":true}"#,
        board: Some(r#"{"type":"skep-enroll","board":true}"#),
    };
    let by_hand = |fields: &[&str]| {
        let mut bytes = b"skep-registration-v1".to_vec();
        for field in fields {
            bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
        bytes
    };
    let five = [frame.door, frame.fresh, frame.shape, frame.node, frame.board.expect("a board")];
    assert_eq!(frame.to_bytes(), by_hand(&five));
    let fields: Vec<&[u8]> = five.iter().map(|f| f.as_bytes()).collect();
    assert_eq!(frame.to_bytes(), framed(REGISTRATION_TAG, &fields));
    let carries_on = AdmissionFrame { shape: "3.54.1.2", board: None, ..frame };
    assert_eq!(carries_on.to_bytes(), by_hand(&[frame.door, frame.fresh, "3.54.1.2", frame.node]));
    // Every field is inside the signed bytes: altering any one moves them.
    let other_door = format!("realm:{REALM} door:1.2.0.1");
    let other_fresh = "5f".repeat(32);
    let altered = [
        AdmissionFrame { door: &other_door, ..frame },
        AdmissionFrame { fresh: &other_fresh, ..frame },
        AdmissionFrame { shape: "3.54.1.2", ..frame },
        AdmissionFrame { node: "{}", ..frame },
        AdmissionFrame { board: Some("{}"), ..frame },
        AdmissionFrame { board: None, ..frame },
        AdmissionFrame { board: Some(""), ..frame },
    ];
    for other in altered {
        assert_ne!(other.to_bytes(), frame.to_bytes(), "{other:?}");
    }
    // The framing is injective: a byte moved from one field to its
    // neighbour is another frame, and so is an empty board against none.
    let moved = AdmissionFrame { door: "ab", fresh: "c", shape: "", node: "", board: None };
    let across = AdmissionFrame { door: "a", fresh: "bc", ..moved };
    assert_ne!(moved.to_bytes(), across.to_bytes());
    assert_ne!(
        AdmissionFrame { board: Some(""), ..moved }.to_bytes(),
        moved.to_bytes(),
        "an empty board field is a field"
    );
}

/// AUTH-1.11, AUTH-1.15 — the admission frame's tag is declared: in `TAGS`,
/// `skep-`-prefixed, a prefix of no other tag and no other a prefix of it,
/// so a signature over a request verifies as no session's, no entry's and
/// no record's.
#[test]
fn the_registration_tag_is_declared_and_prefix_free() {
    assert!(TAGS.contains(&REGISTRATION_TAG));
    assert_eq!(REGISTRATION_TAG.as_bytes(), b"skep-registration-v1");
    for tag in TAGS.iter().filter(|tag| **tag != REGISTRATION_TAG) {
        let (a, b) = (tag.as_bytes(), REGISTRATION_TAG.as_bytes());
        assert!(!a.starts_with(b) && !b.starts_with(a), "{tag:?}");
    }
}

/// REG-4.74 — THE DOOR IDENTIFIER's ONE SPELLING: `realm:<64 lowercase hex>
/// door:<address>` is an identifier, and so is the same with
/// `fork:<address>` between the two terms; each renders back as the string
/// it was parsed from. A second space between terms, upper-case hex, a
/// missing term, a term out of its place or given twice, a space or a term
/// around the three, a realm of another length and an address that is not
/// its own rendering are each no identifier.
#[test]
fn the_door_identifier_has_one_spelling() {
    let plain = door();
    let id = DoorId::parse(&plain).expect("realm and door");
    assert_eq!(id.realm, Fingerprint::parse_hex(REALM).expect("64 hex"));
    assert_eq!((id.fork.clone(), id.door.clone()), (None, addr(&[1, 1, 0, 1])));
    assert_eq!(id.to_string(), plain);
    let forked = format!("realm:{REALM} fork:1.1.0.1.0.1.0.2.9 door:1.1.0.7");
    let forked_id = DoorId::parse(&forked).expect("realm, fork and door");
    assert_eq!(forked_id.fork, Some(addr(&[1, 1, 0, 1, 0, 1, 0, 2, 9])));
    assert_eq!(forked_id.door, addr(&[1, 1, 0, 7]));
    assert_eq!(forked_id.to_string(), forked);
    assert_ne!(id, forked_id, "two doors");
    // The registry's own door, as the rule writes it.
    assert_eq!(DoorId::parse(&plain).map(|d| d.door.to_string()).as_deref(), Some("1.1.0.1"));
    let upper = REALM.to_uppercase();
    for bad in [
        format!("realm:{REALM}  door:1.1.0.1"),
        format!("realm:{upper} door:1.1.0.1"),
        format!("realm:{REALM}"),
        "door:1.1.0.1".to_owned(),
        format!("door:1.1.0.1 realm:{REALM}"),
        format!("realm:{REALM} door:1.1.0.1 fork:1.1.0.1.0.1.0.2.9"),
        format!("realm:{REALM} fork:1.1.0.1.0.1.0.2.9"),
        format!("realm:{REALM} fork:1.1.0.1.0.1.0.2.9 fork:1.1.0.1.0.1.0.2.9 door:1.1.0.1"),
        format!("realm:{REALM} door:1.1.0.1 door:1.1.0.1"),
        format!("realm:{REALM} realm:{REALM} door:1.1.0.1"),
        format!(" realm:{REALM} door:1.1.0.1"),
        format!("realm:{REALM} door:1.1.0.1 "),
        format!("realm:{REALM}\tdoor:1.1.0.1"),
        format!("realm:{REALM} door:1.1.0.1\n"),
        format!("realm:{} door:1.1.0.1", &REALM[..63]),
        format!("realm:{REALM}0 door:1.1.0.1"),
        format!("realm:{} door:1.1.0.1", REALM.replace('9', "g")),
        format!("realm:{REALM} door:1.01.0.1"),
        format!("realm:{REALM} door:+1.1.0.1"),
        format!("realm:{REALM} door:1.1.0"),
        format!("realm:{REALM} door:"),
        format!("realm:{REALM} door:the registry"),
        format!("realm:{REALM} fork:1.0 door:1.1.0.1"),
        format!("Realm:{REALM} door:1.1.0.1"),
        format!("realm:{REALM} https://registry.example door:1.1.0.1"),
        String::new(),
    ] {
        assert_eq!(DoorId::parse(&bad), None, "{bad:?}");
    }
}

/// REG-4.84 — THE FRESHNESS VALUE's FORM AND ITS COMPARISON: exactly 64
/// lowercase hex characters, upper-case hex and every other length refused;
/// two values are one where their spellings are, so a set of them holds
/// each once — the comparison a door's freshness set is kept by.
#[test]
fn the_freshness_value_is_64_lowercase_hex_compared_by_its_spelling() {
    let hex = "5e".repeat(32);
    let fresh = Freshness::parse(&hex).expect("64 lowercase hex");
    assert_eq!((fresh.as_str(), fresh.to_string()), (hex.as_str(), hex.clone()));
    for bad in [
        hex.to_uppercase(),
        hex[..63].to_owned(),
        format!("{hex}5"),
        format!("g{}", &hex[1..]),
        format!(" {}", &hex[1..]),
        String::new(),
    ] {
        assert_eq!(Freshness::parse(&bad), None, "{bad:?}");
    }
    let again = Freshness::parse(&hex).expect("the same value");
    let other = Freshness::parse(&"5f".repeat(32)).expect("another value");
    assert_eq!(fresh, again);
    assert_ne!(fresh, other);
    let seen: std::collections::BTreeSet<Freshness> = [fresh, again, other].into_iter().collect();
    assert_eq!(seen.len(), 2, "a value an earlier request carries is found by equality");
}

/// REG-4.78, REG-4.185 — THE THREAD's KEY: the fingerprints of every key
/// the request's enrolments name, each its 64 lowercase hex characters,
/// ascending, a repeated fingerprint once — the device key, which both
/// enrolments name, counted once — whatever order the enrolments and their
/// entries stand in. A request of other keys, and one sharing the device
/// key alone, has another key.
#[test]
fn the_thread_key_is_every_enrolled_keys_fingerprint_ascending_each_once() {
    let node = enrolment(&[(1, false), (2, true), (3, true)]);
    let board = enrolment(&[(4, true), (1, false), (5, true)]);
    let key_of_request = thread_key(node.iter().chain(&board));
    let spelled: Vec<String> = key_of_request.iter().map(Fingerprint::to_hex).collect();
    assert_eq!(spelled.len(), 5, "six entries, the device key named twice and counted once");
    for hex in &spelled {
        assert_eq!(hex.len(), 64);
        assert!(hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "{hex}");
    }
    let mut ascending = spelled.clone();
    ascending.sort();
    ascending.dedup();
    assert_eq!(spelled, ascending, "ascending in the hex's own order, each once");
    let mut expected: Vec<String> = (1..=5).map(|i| fp(i).to_hex()).collect();
    expected.sort();
    assert_eq!(spelled, expected, "the fingerprints of every key the enrolments name");
    assert!(
        (1..=5).map(fp).collect::<Vec<_>>() != key_of_request,
        "fixture: the keys' own order is not the fingerprints' ascending order"
    );
    assert_eq!(thread_key(board.iter().chain(&node)), key_of_request, "the board's entries first");
    assert_eq!(thread_key(node.iter().chain(&node)), thread_key(&node), "every entry twice");
    // The board carries on: the node enrolment's keys alone.
    assert_eq!(thread_key(&node).len(), 3);
    // A partial overlap — the device key persisting across a re-application
    // — is a different key.
    let reapplied = enrolment(&[(1, false), (6, true), (7, true)]);
    assert_ne!(thread_key(&reapplied), thread_key(&node));
    assert_eq!(thread_key(std::iter::empty::<&Enrollment>()), Vec::new(), "no enrolment, no key");
}

/// REG-1.86 — THE SIGNER IS A KEY EVERY ENROLMENT PRESENT ENROLS: the
/// device key, named by both the node enrolment and the board root's, is
/// answered as the key the frame's signature is verified under; a signer no
/// enrolment names is refused, and so is one only the node enrolment names,
/// one only the board root's names, and any signer where no enrolment is
/// given. Where the board carries on, the node enrolment alone decides.
#[test]
fn a_signer_every_enrolment_present_enrols_is_answered_its_key() {
    let node = enrolment(&[(1, false), (2, true), (3, true)]);
    let board = enrolment(&[(4, true), (1, false), (5, true)]);
    let both: [&[Enrollment]; 2] = [&node, &board];
    assert_eq!(enrolled_signer(&fp(1), &both), Some(&key(1)), "the device key");
    assert_eq!(enrolled_signer(&fp(9), &both), None, "a signer no enrolment names");
    assert_eq!(enrolled_signer(&fp(2), &both), None, "a signer only the node enrolment names");
    assert_eq!(enrolled_signer(&fp(4), &both), None, "a signer only the board root's names");
    assert_eq!(enrolled_signer(&fp(1), &[&board, &node]), Some(&key(1)), "in either order");
    let node_alone: [&[Enrollment]; 1] = [&node];
    assert_eq!(enrolled_signer(&fp(2), &node_alone), Some(&key(2)), "the board carries on");
    assert_eq!(enrolled_signer(&fp(4), &node_alone), None);
    assert_eq!(enrolled_signer(&fp(1), &[]), None, "no enrolment present");
    assert_eq!(enrolled_signer(&fp(1), &[&node, &[]]), None, "an enrolment of no key enrols none");
}
