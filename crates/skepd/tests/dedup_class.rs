//! H1 — THE EMIT / ASSERT_SUP DEDUP CELLS (PUB round 2, lane 3.3b; PUB-6.58's
//! named cell; PUB-6.25, PUB-6.26, PUB-6.27): M7's value-keyed gates run over
//! the type class FILTERED by the caller's visibility class at link-HOME
//! identity, inside the write transaction. A draft-homed incumbent is
//! invisible to a caller who cannot read the draft — its emit is a FRESH mint
//! in its own home, never an ack naming an address inside the draft's link
//! subspace — while an entitled caller acks the EARLIEST incumbent its class
//! can read. Value-identical tuples therefore coexist across the boundary,
//! and `edit_link`'s claim meets no incumbent at all.
//!
//! The reader classes are lane 3.3's: SUBTREE (a sub-account the owner
//! delegates), GRANT-HOLDER (a stranger the owner granted), NON-ENTITLED (a
//! stranger without a grant). The daemon exposes no rule registration, so the
//! SYSTEM caller at guest class is pinned at the engine's own seam
//! (`skep-engine/tests/fires.rs`), and the guest's read of the results is
//! pinned here. The dc-constraint witness cell has no gate to exercise: no
//! dc-constraint query exists in `emit` as built (see the round's report).

mod common;

use common::*;
use serde_json::Value;

/// The GRANTS class type address (COMMONS DECISION 5 — 1.1.0.1.0.1.0.3.90).
const T_GRANT: &str = "1.1.0.1.0.1.0.3.90";

/// The shipped `retired` class in the wire's endset form: the one Unary
/// idem⊤ class the open `emit` surface may write under standard genesis
/// (`[K_sup]` and `[R]` are fenced), so the tuple every cell emits is
/// `(retired, FROM, [])`.
const RETIRED_TY: &str = r#"[{"start":"1.1.0.1.0.1.0.1.3","width":"0.0.0.0.0.0.0.0.1"}]"#;

/// The ONE `from` every cell's tuple carries — a ghost element under the
/// claimant's doc 1, address-form (no occupancy) — so every emit below builds
/// the SAME I0 class and only the caller's class decides what it sees.
const FROM: &str = "1.0.1.0.1.0.3.9.1";

/// A stranger account under node 1, delegated from the bootstrap principal,
/// with its own bare session. Returns `(account, session)`.
fn stranger(port: u16, id: u64) -> (String, String) {
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let account =
        expect_resp(&v, "maybe_addr")["addr"].as_str().expect("a delegable prefix").to_string();
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{account}","new_id":{id}}}"#),
    );
    expect_resp(&v, "ack_addr");
    (account.clone(), open_session(port, id))
}

/// A sub-account delegated by the OWNER beneath the claimant's account — a
/// SUBTREE reader of every draft of the owner's (PUB-1.4). Returns
/// `(account, session)`.
fn sub_account(port: u16, owner: &str, id: u64) -> (String, String) {
    let v = op(
        port,
        Some(owner),
        &format!(r#"{{"op":"next_account_prefix","parent":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    let account =
        expect_resp(&v, "maybe_addr")["addr"].as_str().expect("a delegable prefix").to_string();
    let v = op(
        port,
        Some(owner),
        &format!(r#"{{"op":"delegate","new_prefix":"{account}","new_id":{id}}}"#),
    );
    expect_resp(&v, "ack_addr");
    (account.clone(), open_session(port, id))
}

fn create_doc(port: u16, session: &str, account: &str) -> String {
    acked_addr(&op(
        port,
        Some(session),
        &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
    ))
}

/// A principal's OWN PRIVATE HOME for its link writes: its doc 1 (the
/// mint-first home, born published) and then a second, private mint — the
/// one a bare session may write into on a claimed board (PUB-6.43).
fn own_draft(port: u16, session: &str, account: &str) -> String {
    create_doc(port, session, account);
    create_doc(port, session, account)
}

/// A private draft of the owner's under the claimant's account.
fn owner_draft(port: u16, owner: &str) -> String {
    create_doc(port, owner, CLAIMANT_ACCOUNT)
}

/// A grant link in the claimant's published home doc 1 (from the SIGNED
/// session — a write into the published world): `from` the content-prefix,
/// `to` the grantee account.
fn deposit_grant(port: u16, signed: &str, content_prefix: &str, grantee: &str) {
    acked_addr(&op(
        port,
        Some(signed),
        &format!(
            r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":["{content_prefix}"]}},"to":{{"addrs":["{grantee}"]}},"ty":{{"addrs":["{T_GRANT}"]}}}}"#
        ),
    ));
}

/// A PUBLIC link — homed in the claimant's published doc 1, from the signed
/// session — an endpoint every class can read, so `assert_sup`'s own
/// residence check never enters a cell about its dedup.
fn public_link(port: u16, signed: &str, ordinal: u64) -> String {
    let ghost = format!("{CLAIMANT_DOC1}.0.3.6.{ordinal}");
    acked_addr(&op(
        port,
        Some(signed),
        &format!(
            r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":[]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{ghost}"]}}}}"#
        ),
    ))
}

/// The tuple T `(retired, FROM, [])`, emitted into `home` by `token`; the
/// acked address.
fn emit_t(port: u16, token: &str, home: &str) -> String {
    acked_addr(&op(
        port,
        Some(token),
        &format!(r#"{{"op":"emit","home":"{home}","ty":{RETIRED_TY},"from":"{FROM}","to":[]}}"#),
    ))
}

/// The claim `old → new`, asserted from `home` by `token`; the acked address.
fn assert_sup(port: u16, token: &str, home: &str, old: &str, new: &str) -> String {
    acked_addr(&op(
        port,
        Some(token),
        &format!(r#"{{"op":"assert_sup","home":"{home}","old":"{old}","new":"{new}"}}"#),
    ))
}

/// Is `addr` inside `doc`'s LINK subspace (`doc.0.2.n`)?
fn in_link_subspace_of(addr: &str, doc: &str) -> bool {
    addr.starts_with(&format!("{doc}.0.2."))
}

fn read_link(port: u16, token: Option<&str>, a: &str) -> Value {
    let v = op(port, token, &format!(r#"{{"op":"read_link","a":"{a}"}}"#));
    expect_resp(&v, "link_value")["link"].clone()
}

/// The `emit` cell (PUB-6.25, PUB-6.26): T emitted by the OWNER into a
/// PRIVATE draft is the incumbent. The same T from a NON-ENTITLED stranger,
/// into its own home, is a FRESH mint acked in that home — never the draft's
/// link subspace. From a SUBTREE reader and from a GRANT-HOLDER — each of
/// whom can read the draft — the ack names the draft's incumbent, the
/// earliest their class can read. And the coexistence pin (cell 4): the
/// value-identical tuples stand on both sides of the boundary, each owner's
/// re-emit acking its own side's earliest incumbent, each visible to its own
/// reader and absent to the other.
#[test]
fn a_draft_homed_incumbent_dedups_only_for_callers_who_can_read_the_draft() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = owner_draft(port, &owner);

    // The incumbent: the owner's tuple, homed in its private draft.
    let incumbent = emit_t(port, &owner, &draft);
    assert!(in_link_subspace_of(&incumbent, &draft), "the incumbent is draft-homed: {incumbent}");

    // NON-ENTITLED: a stranger without a grant cannot read the draft, so its
    // emit sees no incumbent — a fresh mint, acked in ITS OWN home.
    let (b_account, b) = stranger(port, 901);
    let b_home = own_draft(port, &b, &b_account);
    let b_tuple = emit_t(port, &b, &b_home);
    assert_ne!(b_tuple, incumbent, "never an ack naming an address inside the draft");
    assert!(in_link_subspace_of(&b_tuple, &b_home), "a fresh mint in the emitter's own home: {b_tuple}");
    assert!(!in_link_subspace_of(&b_tuple, &draft));

    // SUBTREE: a sub-account the owner delegates reads the draft by the
    // subtree clause — its emit acks the draft's incumbent, the earliest its
    // class can read.
    let (sub_acct, sub) = sub_account(port, &owner, 905);
    let sub_home = own_draft(port, &sub, &sub_acct);
    assert_eq!(emit_t(port, &sub, &sub_home), incumbent, "the subtree reader acks the draft's tuple");

    // GRANT-HOLDER: a stranger the owner granted the draft reads it — its
    // emit acks the draft's incumbent too.
    let (c_account, c) = stranger(port, 902);
    let c_home = own_draft(port, &c, &c_account);
    assert_ne!(emit_t(port, &c, &c_home), incumbent, "before the grant: a stranger, fresh");
    deposit_grant(port, &signed, &draft, &c_account);
    assert_eq!(emit_t(port, &c, &c_home), incumbent, "granted: the draft's incumbent is readable, and acked");

    // COEXISTENCE (cell 4): both sides stand; each owner's re-emit acks the
    // earliest incumbent ITS class can read — the owner its draft's, the
    // stranger its own — and each tuple is readable to its own side, absent
    // to the other and to the guest (PUB-6.6).
    assert_eq!(emit_t(port, &owner, &draft), incumbent, "the owner's re-emit acks the draft's");
    assert_eq!(emit_t(port, &b, &b_home), b_tuple, "the stranger's re-emit acks its own");
    assert!(!read_link(port, Some(&owner), &incumbent).is_null(), "the owner reads its tuple");
    assert!(!read_link(port, Some(&b), &b_tuple).is_null(), "the stranger reads its tuple");
    assert!(read_link(port, Some(&b), &incumbent).is_null(), "the draft's tuple is absent to the stranger");
    assert!(read_link(port, Some(&owner), &b_tuple).is_null(), "the stranger's is absent to the owner");
    assert!(read_link(port, None, &incumbent).is_null() && read_link(port, None, &b_tuple).is_null());

    sd.shutdown();
}

/// The `assert_sup` cell (PUB-6.25): the same claim tuple over two PUBLIC
/// endpoints, incumbent draft-homed, × the classes — the non-entitled
/// stranger mints its own claim in its own home, the subtree reader and the
/// grant-holder ack the draft's.
#[test]
fn a_draft_homed_claim_dedups_only_for_callers_who_can_read_the_draft() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = owner_draft(port, &owner);
    let old = public_link(port, &signed, 1);
    let new = public_link(port, &signed, 2);

    // The incumbent claim, homed in the owner's private draft.
    let incumbent = assert_sup(port, &owner, &draft, &old, &new);
    assert!(in_link_subspace_of(&incumbent, &draft), "the claim is draft-homed: {incumbent}");

    // NON-ENTITLED: a claim of its own, in its own home.
    let (b_account, b) = stranger(port, 911);
    let b_home = own_draft(port, &b, &b_account);
    let b_claim = assert_sup(port, &b, &b_home, &old, &new);
    assert_ne!(b_claim, incumbent, "never an ack naming an address inside the draft");
    assert!(in_link_subspace_of(&b_claim, &b_home), "a fresh claim in the asserter's own home: {b_claim}");
    assert_eq!(assert_sup(port, &b, &b_home, &old, &new), b_claim, "its re-assertion acks its own");

    // SUBTREE and GRANT-HOLDER: the draft's claim is readable, and acked.
    let (sub_acct, sub) = sub_account(port, &owner, 915);
    let sub_home = own_draft(port, &sub, &sub_acct);
    assert_eq!(assert_sup(port, &sub, &sub_home, &old, &new), incumbent);
    let (c_account, c) = stranger(port, 912);
    let c_home = own_draft(port, &c, &c_account);
    deposit_grant(port, &signed, &draft, &c_account);
    assert_eq!(assert_sup(port, &c, &c_home, &old, &new), incumbent);

    // The owner's re-assertion acks the draft's claim, the earliest it reads.
    assert_eq!(assert_sup(port, &owner, &draft, &old, &new), incumbent);

    sd.shutdown();
}

/// The `edit_link` UNREACHABILITY pin (PUB-6.27): its supersession claim's
/// `new` is minted in the same transaction, so no incumbent — the owner's
/// draft-homed claim over the same original included — can exist for it, and
/// an `edit_link` ack never names an address inside a draft's link subspace.
/// This is the test that fails if the claim ever meets a store-level dedup
/// keyed on the original alone.
#[test]
fn an_edit_link_ack_never_names_an_address_inside_a_draft() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = owner_draft(port, &owner);
    let original = public_link(port, &signed, 1);
    let other = public_link(port, &signed, 2);
    // A draft-homed claim over the original — the only candidate a
    // mis-keyed dedup could ever find.
    let draft_claim = assert_sup(port, &owner, &draft, &original, &other);
    assert!(in_link_subspace_of(&draft_claim, &draft));

    let (b_account, b) = stranger(port, 921);
    let b_home = own_draft(port, &b, &b_account);
    let ghost = format!("{b_home}.0.3.6.1");
    let v = op(
        port,
        Some(&b),
        &format!(
            r#"{{"op":"edit_link","original":"{original}","d_s":"{b_home}","d_a":"{b_home}","successor":{{"from":[],"to":[],"ty":{{"addrs":["{ghost}"]}}}}}}"#
        ),
    );
    let ack = expect_resp(&v, "ack_edit");
    let successor = ack["successor"].as_str().expect("successor");
    let claim = ack["claim"].as_str().expect("claim");
    assert!(in_link_subspace_of(successor, &b_home), "the successor lands in d_s: {v}");
    assert!(in_link_subspace_of(claim, &b_home), "the claim lands in d_a: {v}");
    assert_ne!(claim, draft_claim);
    assert!(!in_link_subspace_of(claim, &draft) && !in_link_subspace_of(successor, &draft));

    // The owner's own edit from the draft lands in the draft — and its claim
    // is a fresh one beside the standing draft claim, not that claim.
    let ghost = format!("{draft}.0.3.6.2");
    let v = op(
        port,
        Some(&owner),
        &format!(
            r#"{{"op":"edit_link","original":"{original}","d_s":"{draft}","d_a":"{draft}","successor":{{"from":[],"to":[],"ty":{{"addrs":["{ghost}"]}}}}}}"#
        ),
    );
    let ack = expect_resp(&v, "ack_edit");
    assert!(in_link_subspace_of(ack["claim"].as_str().expect("claim"), &draft));
    assert_ne!(ack["claim"].as_str().expect("claim"), draft_claim);

    sd.shutdown();
}
