//! THE DEPOSIT CLASS's TYPE SET, PINNED (PUB-2.11, PUB-2.64; RES-249,
//! RES-261; the owner's ruling of 2026-09-18, seam shape S-A).
//!
//! The insert door tests a deposit declaration's class type against a
//! BUILD-TIME set that is M5's own (`skep_arrangement::deposit_class_types`)
//! — the door's crate sits below the engine and the daemon and can read
//! neither's constants — so ENROLL and RETIRE are spelled TWICE: there, for
//! the door, and in the daemon's credential constants (`T_ENROLL`,
//! `T_RETIRE`), for the fold that classifies the pair's `make_link`. A
//! second spelling is safe only while it cannot drift, and this file is what
//! holds it:
//!
//! * the set, member for member and in order, is the pair this suite's own
//!   constants transcribe, and holds nothing else — the CLAIM link's type,
//!   which deposits no atom, least of all;
//! * the set is prefix-free against every pin of the engine's commons ledger
//!   (`skep_engine::types`), so no typed-link class with no atom is a member
//!   and no member reads as a pin's subtype on the daemon's prefix-recognizing
//!   write path. (The ledger's own test walks its ONE list against the set, so
//!   a pin that joins later is met there; the readers are named here so the
//!   claim is also made where all three spellings are in reach.)
//! * THE DAEMON HONORS WHAT THE SET SPELLS: a record declared under a member
//!   and linked under that same member (PUB-2.63) is classified by the fold
//!   as that member's kind — an enrollment enrolls, a retirement retires. The
//!   fold's compare is exact equality with the daemon's constants, which no
//!   integration suite can name, so this is the equality with THEM; the
//!   value-for-value pin against the constants themselves is the codec's unit
//!   test, the one place both are in reach.

use crate::common;

use common::*;
use serde_json::Value;
use skep_address::{is_prefix, Address};
use skep_arrangement::deposit_class_types;
use skep_engine::types::{
    t_consumption_marker, t_edition, t_endorse, t_grant, t_journal_designation, t_rail_record,
    t_steward_classification, t_successor_of,
};
use skep_identity::{encode_retire, Fingerprint};

/// The set as the wire spells it: each member's dotted-decimal address.
fn spelled() -> Vec<String> {
    deposit_class_types().iter().map(|ty| ty.tumbler().to_string()).collect()
}

#[test]
fn the_doors_set_is_enroll_and_retire_and_prefix_free_against_the_commons_ledger() {
    assert_eq!(spelled(), [T_ENROLL, T_RETIRE], "ENROLL then RETIRE, and nothing else");
    assert!(!spelled().iter().any(|ty| ty == T_CLAIM), "the claim link deposits no atom");

    let ledger: [(&str, &Address); 8] = [
        ("grant", t_grant()),
        ("edition claim", t_edition()),
        ("successor-of", t_successor_of()),
        ("endorse", t_endorse()),
        ("consumption marker", t_consumption_marker()),
        ("journal designation", t_journal_designation()),
        ("rail record", t_rail_record()),
        ("steward classification", t_steward_classification()),
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
/// position, then the `make_link` naming the atom and carrying `ty`.
fn pair(port: u16, session: &str, atom: &str, ty: &str) -> Value {
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
    sd.shutdown();
}
