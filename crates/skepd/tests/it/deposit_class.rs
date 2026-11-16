//! THE DEPOSIT CLASS's TYPE SET, PINNED (PUB-2.11, PUB-2.64; RES-249,
//! RES-261; the owner's ruling of 2026-09-18, seam shape S-A; the registry's
//! kinds joining with the record grade for registry records, REG-1.37 as
//! that grade re-reads it, and the registration kind's deposit-carrying
//! rows joining at their own addresses, REG-1.23).
//!
//! The insert door tests a deposit declaration's class type against a
//! BUILD-TIME set that is M5's own (`skep_arrangement::deposit_class_types`)
//! — the door's crate sits below the engine and the daemon and can read
//! neither's constants — so ENROLL and RETIRE are spelled TWICE: there, for
//! the door, and in the engine's credential pins (`t_enroll`, `t_retire`,
//! the `IDENTITY_TYPES` the fold hook classifies the pair's `make_link`
//! by); and so
//! are the registry's parsed rows — the registration's six, the BINDING and
//! the ENDPOINT: there, and in `skep_registry`'s table, which the engine's
//! ledger reads for the registry sequence's classify. A second spelling is
//! safe only while it cannot drift, and this file is what holds it:
//!
//! * the set, member for member and in order, is the pair this suite's own
//!   constants transcribe followed by the registry's parsed rows in the
//!   table's order, and holds nothing else — the CLAIM link's type, which
//!   deposits no atom, least of all, nor a registry row that carries no
//!   deposit: the registration's kind row, its parent rows `request` and
//!   `reply`, its approval;
//! * the set is prefix-free against every pin of the engine's commons ledger
//!   outside the registry (`skep_engine::types`), so no typed-link class
//!   with no atom is a member and no member reads as a pin's subtype on the
//!   daemon's prefix-recognizing write path; and its registry members are
//!   EQUAL to the ledger's own rows, and prefix-related to no other registry
//!   row but the rows a member nests under by design — its kind's and its
//!   parent's. (The ledger's own test walks its ONE list against the set, so
//!   a pin that joins later is met there; the readers are named here so the
//!   claim is also made where every spelling is in reach.)
//! * THE DAEMON HONORS WHAT THE SET SPELLS: a record declared under a member
//!   and linked under that same member (PUB-2.63) is classified by the fold
//!   as that member's kind — an enrollment enrolls, a retirement retires —
//!   and by the registry sequence as the registry's: a binding, an endpoint
//!   and a record of each registration row commit at the record grade. The
//!   fold's compare is exact equality with the daemon's constants, which no
//!   integration suite can name, so this is the equality with THEM; the
//!   value-for-value pin against the constants themselves is the codec's
//!   unit test, the one place both are in reach.

use crate::common;

use common::*;
use serde_json::Value;
use skep_address::{is_prefix, Address};
use skep_arrangement::deposit_class_types;
use skep_engine::types::{pins_outside_the_registry, t_binding, t_endpoint};
use skep_identity::{encode_retire, Fingerprint};

/// The set as the wire spells it: each member's dotted-decimal address.
fn spelled() -> Vec<String> {
    deposit_class_types().iter().map(|ty| ty.tumbler().to_string()).collect()
}

/// The registry's members of the set, as this suite's constants spell them,
/// in the table's order: the registration's six deposit-carrying rows, the
/// binding, the endpoint.
const REGISTRY_MEMBERS: [&str; 8] = [
    T_REQUEST_FRESH,
    T_REQUEST_BOARD_CARRIES_ON,
    T_REPLY_APPROVED,
    T_REPLY_REFUSED,
    T_REPLY_DENIED,
    T_VOUCH,
    T_BINDING,
    T_ENDPOINT,
];

#[test]
fn the_doors_set_is_the_atom_bearing_kinds_and_prefix_free_against_the_commons_ledger() {
    let expected: Vec<&str> = [T_ENROLL, T_RETIRE].into_iter().chain(REGISTRY_MEMBERS).collect();
    assert_eq!(
        spelled(),
        expected,
        "ENROLL, RETIRE, the registration's six deposit-carrying rows, the BINDING, the \
         ENDPOINT, and nothing else"
    );
    assert!(!spelled().iter().any(|ty| ty == T_CLAIM), "the claim link deposits no atom");
    for no_member in [T_REGISTRATION, T_REQUEST, T_REPLY, T_APPROVAL] {
        assert!(
            !spelled().iter().any(|ty| ty == no_member),
            "{no_member} carries no deposit and is never a member (REG-1.18, REG-1.23)"
        );
    }

    // The registry's members are the ledger's rows, spelled a second time —
    // and `skep_registry`'s own, which the ledger reads: each a row of the
    // table that carries deposits and a body the registry crate parses.
    let types = deposit_class_types();
    let registry_members: Vec<&Address> =
        types.iter().filter(|ty| skep_registry::row_at(ty).is_some()).collect();
    assert_eq!(registry_members.len(), REGISTRY_MEMBERS.len());
    for member in &registry_members {
        let row = skep_registry::row_at(member).expect("a registry row");
        assert!(row.carries_deposits() && row.type_value.is_some(), "{member}");
    }
    assert_eq!(*registry_members.last().expect("the endpoint"), t_endpoint());
    assert!(registry_members.contains(&t_binding()));
    assert!(registry_members.contains(&skep_registry::t_binding()));
    assert!(registry_members.contains(&skep_registry::t_endpoint()));
    for kind in skep_registry::RegistrationKind::ALL {
        assert!(
            registry_members.contains(&&kind.row().address),
            "{kind:?}: every body-bearing registration row is a member, at its own address"
        );
    }

    let ledger: [(&str, &Address); 8] = [
        ("grant", pins_outside_the_registry()[0]),
        ("edition claim", pins_outside_the_registry()[1]),
        ("endorse", pins_outside_the_registry()[2]),
        ("consumption marker", pins_outside_the_registry()[3]),
        ("journal designation", pins_outside_the_registry()[4]),
        ("rail record", pins_outside_the_registry()[5]),
        ("steward classification", pins_outside_the_registry()[6]),
        ("replaces", pins_outside_the_registry()[7]),
    ];
    for ty in deposit_class_types() {
        for (name, pin) in ledger {
            assert!(
                !is_prefix(ty.tumbler(), pin.tumbler()) && !is_prefix(pin.tumbler(), ty.tumbler()),
                "the deposit-class type {} and the {name} pin {} are prefix-related",
                ty.tumbler(),
                pin.tumbler()
            );
        }
        // …and against every registry row that is not the member itself nor
        // a row the member nests under by design — its kind's row, and its
        // parent row's (REG-1.20): the other kinds, every other subtype row.
        // No row sits beneath a member: a deposit rides a leaf.
        let above: Vec<&Address> = skep_registry::row_at(ty)
            .and_then(|row| row.of.subtype())
            .map(|subtype| {
                let parent = subtype.parent().map(|p| &p.row().address);
                std::iter::once(&subtype.kind().row().address).chain(parent).collect()
            })
            .unwrap_or_default();
        for row in skep_registry::rows() {
            if row.address == *ty {
                continue;
            }
            assert!(
                !is_prefix(ty.tumbler(), row.address.tumbler()),
                "the registry row {} sits beneath the deposit-class type {}",
                row.address.tumbler(),
                ty.tumbler()
            );
            assert_eq!(
                is_prefix(row.address.tumbler(), ty.tumbler()),
                above.contains(&&row.address),
                "the deposit-class type {} and the registry row {}",
                ty.tumbler(),
                row.address.tumbler()
            );
        }
    }
}

/// The fingerprints `key_set` lists under `field` for the claimant.
fn key_set_names(port: u16, field: &str) -> Vec<String> {
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#));
    v[field]
        .as_array()
        .unwrap_or_else(|| panic!("{field}: {v}"))
        .iter()
        .map(|e| e["fingerprint"].as_str().expect("fingerprint").to_string())
        .collect()
}

/// The pair as AUTH pins it (AUTH-5.4; PUB-2.63), both halves under ONE type:
/// the record atom's `insert` DECLARED under `ty` at the home's next free
/// position, then the `make_link` naming the atom and carrying `ty` — the
/// record signed for that deposit under the session's key (2a).
fn pair(port: u16, session: &str, atom: &str, ty: &str) -> Value {
    let atom = signed_atom(port, session, CLAIMANT_DOC1, ty, &[CLAIMANT_ACCOUNT], atom);
    let ordinal = next_content_ordinal(port, Some(session), CLAIMANT_DOC1);
    let v = op(
        port,
        Some(session),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{ty}"}}"#
        ),
    );
    let record = acked_addr(&v);
    typed_link(port, session, CLAIMANT_DOC1, &[record.as_str()], &[CLAIMANT_ACCOUNT], ty)
}

#[test]
fn the_daemon_honors_a_pair_declared_and_typed_by_the_sets_own_members() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    // The types come off M5's set and nowhere else: what the door admits is
    // what the fold is then asked to classify.
    let set = spelled();
    let (enroll, retire) = (set[0].as_str(), set[1].as_str());
    let member = |ty: &str| set.iter().find(|m| *m == ty).expect("a member of the set").as_str();
    let (binding, endpoint) = (member(T_BINDING), member(T_ENDPOINT));

    // The FIRST member is the fold's ENROLL: the key the record names joins
    // the enrolled set and signs in.
    let hired = distinct_key(91);
    let hired_fp = Fingerprint::of(&public_key_of(&hired)).to_hex();
    let device = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    expect_resp(&pair(port, &device, &enroll_atom(&[&hired]), enroll), "ack_addr");
    assert!(key_set_names(port, "enrolled").contains(&hired_fp), "the first member enrolls");
    open_signed_session(port, CLAIMANT_PRINCIPAL, &hired);

    // The SECOND member is the fold's RETIRE: the same key leaves the enrolled
    // set for the retired one.
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let record = encode_retire(&[Fingerprint::of(&public_key_of(&hired))]);
    expect_resp(&pair(port, &anchor, &json_atom(&record), retire), "ack_addr");
    assert!(!key_set_names(port, "enrolled").contains(&hired_fp), "the second member retires");
    assert!(key_set_names(port, "retired").contains(&hired_fp), "the second member retires");

    // The REST are the registry's: a binding to a registered account and an
    // endpoint, each parsed under the canonical rule and its `sig` verified
    // at the record grade, commit at the link — and so does a record of each
    // registration row, declared and linked under its own address: a
    // request of each kind and a vouch to the board's binding-writing
    // account, each answer to the request's link.
    let (node_account, _) = bootstrap_delegate(port, 93);
    let (_, v) = deposit_registry_record(port, &device, CLAIMANT_DOC1, binding, &[&node_account], &binding_body("1.2", None));
    expect_resp(&v, "ack_addr");
    let (_, v) = deposit_registry_record(port, &device, CLAIMANT_DOC1, endpoint, &[], &endpoint_body(&["https://acme.example"], None));
    expect_resp(&v, "ack_addr");
    let mut request = String::new();
    for ty in &set[2..] {
        let ty = ty.as_str();
        let (to, body) = match ty {
            T_REQUEST_FRESH | T_REQUEST_BOARD_CARRIES_ON => {
                let shape = ty.strip_prefix("1.1.0.1.0.1.0.").expect("a commons type");
                (CLAIMANT_ACCOUNT, request_body(ty, shape))
            }
            T_REPLY_APPROVED | T_REPLY_REFUSED | T_REPLY_DENIED => (request.as_str(), answer_body(ty)),
            T_VOUCH => (CLAIMANT_ACCOUNT, vouch_body(None)),
            T_BINDING | T_ENDPOINT => continue,
            other => panic!("{other}: a member of the door's set this cell deposits nothing under"),
        };
        let (_, v) = deposit_registry_record(port, &device, CLAIMANT_DOC1, ty, &[to], &body);
        let deposited = acked_addr(expect_resp(&v, "ack_addr"));
        if ty == T_REQUEST_FRESH {
            request = deposited;
        }
    }
    assert!(!request.is_empty(), "the registration's rows were deposited");
    sd.shutdown();
}
