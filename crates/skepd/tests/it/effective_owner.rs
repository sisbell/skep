//! THE OWNER-OF-ADDRESS READ at the wire — `effective_owner(addr)`
//! (AUTH-6.37) — and `delegate`'s `new_id` bound (AUTH-6.36's clause;
//! AUTH-5.20): the drift report's (c) row 8, cell by cell.
//!
//! The read is ω UNPROJECTED — `{prefix, principal}`, the longest registered
//! prefix CONTAINING `addr` and the principal seated at it, both null
//! TOGETHER only where no registered principal's prefix contains `addr`:
//!
//! * ALLOCATED iff `prefix == addr` — a registered account answers itself;
//! * an UNALLOCATED `inc(X, 1)` answers `X`'s own prefix and principal,
//!   never none under the node;
//! * an address under no registered prefix answers both null;
//! * on `/op-at` it answers as of the position asked — the owner BEFORE a
//!   delegation at a position before it, the new seat from it on;
//! * NO SESSION: a guest and a bound principal are answered byte-identically,
//!   and nothing is withheld, a private draft's address included;
//! * the setup act's shape (AUTH-5.87): op (1)'s `not_authorized` at the
//!   holder's own `delegate` of `inc(X, 1)` → this read → the resume at op
//!   (3), driven as far as the daemon's half goes.
//!
//! The bound is a PARSE fault — `unparseable`, no code or token of its own,
//! nothing committed — and `2^53 − 1` itself is accepted.

use crate::common;

use common::*;
use serde_json::Value;

/// `2^53 − 1`: the largest integer a JSON number carries exactly.
const MAX_EXACT_ID: u64 = (1 << 53) - 1;

fn delegate_frame(new_prefix: &str, new_id: u64) -> String {
    format!(r#"{{"op":"delegate","new_prefix":"{new_prefix}","new_id":{new_id}}}"#)
}

/// `principal_prefix(id)` as the guest: the registered prefix, or `None`.
fn prefix_of(port: u16, id: u64) -> Option<String> {
    let v = op(port, None, &format!(r#"{{"op":"principal_prefix","principal":{id}}}"#));
    expect_resp(&v, "maybe_addr")["addr"].as_str().map(str::to_string)
}

/// (c) row 8, the first three cells, read as the GUEST throughout. ALLOCATED
/// iff `prefix == addr`: a seat — the claimant's account, the node — answers
/// ITSELF. An UNALLOCATED `inc(X, 1)` answers `X`'s own prefix and `X`'s own
/// principal — never none under the node — so a non-null answer alone is NOT
/// the allocation test; seated by a `delegate`, the SAME address answers
/// itself and the principal that `delegate` registered, and an unallocated
/// address beneath it then answers THAT seat, the longest containing prefix.
/// A document-tier address is a registry probe like any other — a private
/// draft's included, to a guest `doc_metadata` answers `withheld`: nothing
/// here is withheld, the owner of a withheld document being public by design
/// (PUB-8.9, which takes the owner account from `prefix`). And an address
/// under no registered prefix answers both members null, TOGETHER.
#[test]
fn a_seat_answers_itself_and_an_unallocated_first_child_answers_the_seat_above() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let x = CLAIMANT_ACCOUNT;
    let x_seat = Some((x.to_string(), CLAIMANT_PRINCIPAL));

    // A seat of its own: the prefix IS the address asked, at both tiers.
    assert_eq!(effective_owner(port, None, x), x_seat, "a registered account answers itself");
    assert_eq!(effective_owner(port, None, "1"), Some(("1".to_string(), 0)), "and so does the node");

    // `inc(X, 1)` — the board's own arithmetic names it — NOT yet delegated.
    let first_child = next_prefix_under(port, None, x);
    assert_eq!(first_child, format!("{x}.1"), "inc(X, 1) is X's first sub-account");
    let unallocated = effective_owner(port, None, &first_child);
    assert_eq!(unallocated, x_seat, "an unallocated inc(X, 1) answers X's prefix and principal");
    assert_ne!(
        unallocated.expect("never none under a seat").0,
        first_child,
        "prefix != addr: the address asked is not a seat, whatever else the answer holds"
    );
    // An unregistered SIBLING of X's answers the node's seat — never none
    // under the node.
    assert_eq!(effective_owner(port, None, "1.0.77"), Some(("1".to_string(), 0)));

    // Document-tier and element-tier addresses: the owning seat. The draft is
    // PRIVATE — the guest's `doc_metadata` of it is withheld — and the read
    // answers all the same: nothing is withheld here.
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = owner_draft(port, &owner);
    assert_withheld(&doc_metadata(port, None, &draft), &draft);
    for addr in [CLAIMANT_DOC1.to_string(), draft.clone(), format!("{draft}.0.1.1"), format!("{x}.0.999")] {
        assert_eq!(effective_owner(port, None, &addr), x_seat, "{addr} is X's");
    }

    // Seated by a `delegate`, the same address answers ITSELF…
    let held = 4_242;
    expect_resp(&op(port, Some(&owner), &delegate_frame(&first_child, held)), "ack_addr");
    assert_eq!(
        effective_owner(port, None, &first_child),
        Some((first_child.clone(), held)),
        "allocated: prefix == addr, and the principal is the one seated AT it"
    );
    // …an unallocated address beneath it answers THAT seat, not X above it…
    assert_eq!(
        effective_owner(port, None, &format!("{first_child}.1")),
        Some((first_child.clone(), held)),
        "the LONGEST registered prefix containing the address"
    );
    // …and X's own answer, and its other unallocated children's, are unmoved.
    assert_eq!(effective_owner(port, None, x), x_seat);
    assert_eq!(effective_owner(port, None, &format!("{x}.2")), x_seat);

    // Under no registered principal's prefix: both members null, TOGETHER
    // (`owner_pair` refuses a split answer, and an omitted member).
    for foreign in ["2", "2.0.7", "7.0.1.0.1"] {
        assert_eq!(effective_owner(port, None, foreign), None, "{foreign} is off this board's registry");
    }

    // The answer reports the snapshot it came from, as every read does.
    let v = op(port, None, &effective_owner_frame(x));
    assert_eq!(v["as_of"].as_u64(), Some(head_position(port)), "{v}");

    sd.shutdown();
}

/// (c) row 8, NO SESSION: the read is principal-free and session-blind. The
/// guest, the owner's BARE session, the owner's SIGNED session, a stranger's
/// session and a token the daemon never issued are answered BYTE-IDENTICALLY
/// — at a seat, at an unallocated first child, at a private draft of the
/// owner's, and off the registry — on `/op` and on `/op-at` alike. (A dead
/// token's response carries the death signal in a HEADER; the body, which is
/// the answer, is the guest's.)
#[test]
fn the_read_answers_a_guest_and_a_bound_principal_byte_identically() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let stranger = seat_stranger(port, 995);
    let draft = owner_draft(port, &bare);
    let never_issued = "0".repeat(64);
    let readers: [Option<&str>; 5] = [
        None,
        Some(bare.as_str()),
        Some(signed.as_str()),
        Some(stranger.session.as_str()),
        Some(never_issued.as_str()),
    ];

    let at = head_position(port);
    for addr in [
        CLAIMANT_ACCOUNT.to_string(),
        format!("{CLAIMANT_ACCOUNT}.1"),
        stranger.account.clone(),
        draft,
        "2.0.7".to_string(),
    ] {
        let frame = effective_owner_frame(&addr);
        let live: Vec<Vec<u8>> =
            readers.iter().map(|t| http(port, "POST", "/op", *t, frame.as_bytes()).1).collect();
        assert_eq!(json(&live[0])["resp"].as_str(), Some("effective_owner"), "{addr}: answered");
        assert!(live.iter().all(|b| *b == live[0]), "{addr}: every reader is answered alike on /op");

        let envelope = format!(r#"{{"at":{at},"frame":{frame}}}"#);
        let historical: Vec<Vec<u8>> = readers
            .iter()
            .map(|t| {
                let (st, body) = http(port, "POST", "/op-at", *t, envelope.as_bytes());
                assert_eq!(st, 200, "{addr} at {at}: {}", String::from_utf8_lossy(&body));
                body
            })
            .collect();
        assert!(
            historical.iter().all(|b| *b == historical[0]),
            "{addr}: every reader is answered alike on /op-at"
        );
        // Nothing committed in between, so the head's answer IS the answer
        // as of the head's position — `as_of` and all.
        assert_eq!(historical[0], live[0], "{addr}: /op-at at the head is /op's own answer");
    }

    sd.shutdown();
}

/// (c) row 8, SERVED ON `/op-at`, as of any committed position — through the
/// one dispatcher, the reconstructed world's own registry. As of a position
/// BEFORE a delegation the address answers the PRE-delegation owner — the
/// seat above it — and from the delegation's own position on, the new seat;
/// `as_of` stamps the position asked, never the throwaway kernel's. At
/// GENESIS the claimant's own account-to-be answers the node's seat.
#[test]
fn op_at_answers_the_owner_as_of_the_position_asked() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let x = CLAIMANT_ACCOUNT;
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let child = next_prefix_under(port, Some(&owner), x);

    let before = head_position(port);
    let held = 4_243;
    let at = acked_at(&op(port, Some(&owner), &delegate_frame(&child, held)));
    // The delegation is the ONE commit since `before` (one transaction — the
    // allocation and the registration — so the position moves by its records,
    // not by one): `before` is the last position without it, `at` the first
    // with it.
    assert!(at > before, "the delegation committed past {before}: {at}");
    assert_eq!(head_position(port), at, "and nothing else has committed since");
    // A later commit, so `at` is interior — neither 0 nor the head.
    owner_draft(port, &owner);
    assert!(at < head_position(port));

    let frame = effective_owner_frame(&child);
    let x_seat = Some((x.to_string(), CLAIMANT_PRINCIPAL));
    let new_seat = Some((child.clone(), held));
    for (position, expect, what) in [
        (before, &x_seat, "BEFORE the delegation: the pre-delegation owner, the seat above"),
        (at, &new_seat, "AT the delegation's own position: the new seat"),
        (head_position(port), &new_seat, "and at every position after it"),
    ] {
        // As the guest and as the bound owner: the read is session-blind here
        // too, and the head-set consult has no document argument to ask about.
        for token in [None, Some(owner.as_str())] {
            let v = op_at_ok(port, token, position, &frame);
            assert_eq!(&owner_pair(&v), expect, "{what} (at {position}): {v}");
            assert_eq!(v["as_of"].as_u64(), Some(position), "as_of is the position asked: {v}");
        }
    }
    assert_eq!(effective_owner(port, None, &child), new_seat, "the head agrees");

    // Genesis: before the ceremony's own `delegate`, X is an unallocated
    // account under the node — the node's seat, never none under the node.
    let v = op_at_ok(port, None, 0, &effective_owner_frame(x));
    assert_eq!(owner_pair(&v), Some(("1".to_string(), 0)), "{v}");
    assert_eq!(v["as_of"].as_u64(), Some(0));
    // Off the registry, at every position alike.
    assert_eq!(owner_pair(&op_at_ok(port, None, before, &effective_owner_frame("2.0.7"))), None);

    // History is not a place to act, and the read's frame is held to the
    // same grammar there: a bad `addr` is the `unparseable` rejection.
    let v = op_at_ok(port, None, at, r#"{"op":"effective_owner","addr":"1.0"}"#);
    assert_eq!(expect_resp(&v, "rejected")["op"].as_str(), Some("unparseable"), "{v}");

    sd.shutdown();
}

/// (c) row 8, THE SETUP ACT'S SHAPE (AUTH-5.87), the daemon's half. Op (1) is
/// the holder's own `delegate` naming `inc(X, 1)` AND NO OTHER ADDRESS under a
/// fresh id. WHERE THE ADDRESS IS ALREADY A SEAT — here an earlier run of the
/// same act; a concurrent device or a squatter is the same cell — M3 answers
/// `not_authorized` at its ownership guard and nothing commits. The act then
/// READS `effective_owner(inc(X, 1))`, TAKES `principal` WHERE
/// `prefix == inc(X, 1)`, and RESUMES AT OP (3): the mint of `X.1`'s doc 1,
/// born published, in a session AS that principal — opened with the holder's
/// device key, which opens `X.1` by reference (AUTH-4.30 (i)) — closed when
/// the act ends. The read needs no session, and the act NEVER RE-PEEKS the
/// frontier: after the refusal the peek names `inc(X, 2)`, a second space the
/// act never names.
#[test]
fn the_setup_act_meets_not_authorized_reads_the_owner_and_resumes_at_op_three() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let x = CLAIMANT_ACCOUNT;
    // The address is COMPUTED — `inc(X, 1)` — and the board's arithmetic agrees.
    let agent_space = format!("{x}.1");
    assert_eq!(next_prefix_under(port, None, x), agent_space);
    let holder = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    // AN EARLIER RUN seated it: op (1) under ITS client-minted id, its ack
    // lost with the client's persisted copy (the copy is a cache — AUTH-5.87).
    let earlier_id = 7_001_001;
    expect_resp(&op(port, Some(&holder), &delegate_frame(&agent_space, earlier_id)), "ack_addr");

    // THIS RUN: op (1) again, the same address, a FRESH id.
    let fresh_id = 7_002_002;
    let before = head_position(port);
    let v = op(port, Some(&holder), &delegate_frame(&agent_space, fresh_id));
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["op"].as_str(), Some("delegate"), "{v}");
    assert_eq!(rej["code"].as_str(), Some("not_authorized"), "M3's ownership guard: {v}");
    assert_eq!(head_position(port), before, "the refused delegate committed nothing");
    assert_eq!(prefix_of(port, fresh_id), None, "and registered nobody");
    // Never re-peek: the frontier has moved past the space the act names.
    assert_eq!(next_prefix_under(port, None, x), format!("{x}.2"));

    // THE READ — as the guest; the act needs no session for it. The
    // allocation test is the EQUALITY: `prefix` is `inc(X, 1)` itself.
    let (prefix, adopted) =
        effective_owner(port, None, &agent_space).expect("an address under X is never unowned");
    assert_eq!(prefix, agent_space, "allocated: the address is a seat of its own");
    assert_eq!(adopted, earlier_id, "and its principal is the board's to say, not the client's");
    // The cell beside it: the seat holds NO SET OF ITS OWN (AUTH-6.19's
    // empty lists) — not handed away — so the act adopts and goes on.
    let set = op(port, None, &format!(r#"{{"op":"key_set","account":"{agent_space}"}}"#));
    let set = expect_resp(&set, "key_set");
    assert_eq!(set["enrolled"].as_array().map(Vec::len), Some(0), "{set}");
    assert_eq!(set["retired"].as_array().map(Vec::len), Some(0), "{set}");

    // RESUME AT OP (3): a session AS the adopted principal, opened BY
    // REFERENCE with the holder's device key, and the home mint — the flag
    // passed affirmatively.
    let as_agent_space = open_signed_session(port, adopted, &device_key());
    let home = acked_addr(&op(port, Some(&as_agent_space), &create_frame(&agent_space, Some(true))));
    assert_eq!(home, format!("{agent_space}.0.1"), "X.1's doc 1, at its computable address");
    let meta = doc_metadata(port, None, &home);
    let meta = expect_resp(&meta, "doc_metadata");
    assert_eq!(meta["published"].as_bool(), Some(true), "born published: {meta}");
    assert_eq!(meta["owner"].as_str(), Some(agent_space.as_str()), "{meta}");
    assert_eq!(effective_owner(port, None, &home), Some((agent_space.clone(), adopted)));

    // The session op (3) opened is CLOSED when the act ends; the holder's own
    // is untouched by any of it.
    let (st, _) = http(port, "POST", "/session/close", Some(&as_agent_space), b"");
    assert_eq!(st, 204);
    assert_eq!(
        verdict(&op(port, Some(&as_agent_space), &create_frame(&agent_space, None))),
        "unauthenticated",
        "the closed session writes nothing"
    );
    owner_draft(port, &holder);

    sd.shutdown();
}

/// AUTH-6.37's residue sentence, the daemon's half: the read is served on an
/// UNCLAIMED board too — reads pass no admission gate — so before the
/// ceremony's own `delegate` the account-to-be answers the node's seat, and
/// after it, PRE-CLAIM, the account is findable by address and the read names
/// its principal.
#[test]
fn an_unclaimed_board_serves_the_read_before_and_after_the_ceremonys_delegate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    assert!(!claimed(port));

    let account = next_prefix_under(port, None, "1");
    assert_eq!(effective_owner(port, None, &account), Some(("1".to_string(), 0)));

    let boot = open_session(port, 0);
    expect_resp(&op(port, Some(&boot), &delegate_frame(&account, CLAIMANT_PRINCIPAL)), "ack_addr");
    assert!(!claimed(port), "still pre-claim");
    assert_eq!(
        effective_owner(port, None, &account),
        Some((account.clone(), CLAIMANT_PRINCIPAL)),
        "the one principal above the genesis floor, named by address"
    );

    sd.shutdown();
}

/// ITEM 2 — `delegate` REFUSES A `new_id` ABOVE `2^53 − 1` AT THE PARSE
/// (AUTH-6.36's clause; AUTH-5.20). `new_id = 2^53` is the `unparseable`
/// rejection — `malformed`, `permanent`, a `detail` naming the field; NOT
/// `credential_refused`, no token — and NOTHING COMMITS: the head, the
/// frontier and the registry stand. AT THE PARSE means ahead of every gate: a
/// frame carrying NO session is still `unparseable` past the bound, where the
/// in-range frame parses and is refused `unauthenticated` for the session it
/// lacks. And the SAME frame with `2^53 − 1` is ACCEPTED, the id carried
/// exactly on every read that answers it.
#[test]
fn delegate_refuses_a_new_id_of_two_to_the_fifty_third_at_the_parse() {
    assert_eq!(MAX_EXACT_ID, 9_007_199_254_740_991);
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let prefix = next_prefix_under(port, Some(&owner), CLAIMANT_ACCOUNT);
    let x_seat = Some((CLAIMANT_ACCOUNT.to_string(), CLAIMANT_PRINCIPAL));
    let before = head_position(port);

    for past in [MAX_EXACT_ID + 1, u64::MAX] {
        let v = op(port, Some(&owner), &delegate_frame(&prefix, past));
        let rej = expect_resp(&v, "rejected");
        assert_eq!(rej["op"].as_str(), Some("unparseable"), "a PARSE fault: {v}");
        assert_eq!(rej["code"].as_str(), Some("malformed"), "the existing vocabulary: {v}");
        assert_eq!(rej["disposition"].as_str(), Some("permanent"), "{v}");
        let detail = rej["detail"].as_str().unwrap_or_else(|| panic!("a parse fault says why: {v}"));
        assert!(detail.contains("new_id"), "naming the field: {detail}");
        assert!(detail.contains(&MAX_EXACT_ID.to_string()), "and the bound: {detail}");
        // Nothing committed.
        assert_eq!(head_position(port), before, "the head stands");
        assert_eq!(next_prefix_under(port, Some(&owner), CLAIMANT_ACCOUNT), prefix, "the frontier stands");
        assert_eq!(prefix_of(port, past), None, "no such principal is registered");
        assert_eq!(effective_owner(port, None, &prefix), x_seat, "the address is still unallocated");
    }

    // Ahead of every gate: the session gate never sees the over-bound frame.
    let v = op(port, None, &delegate_frame(&prefix, MAX_EXACT_ID + 1));
    assert_eq!(expect_resp(&v, "rejected")["op"].as_str(), Some("unparseable"), "{v}");
    let v = op(port, None, &delegate_frame(&prefix, MAX_EXACT_ID));
    assert_eq!(expect_resp(&v, "rejected")["op"].as_str(), Some("delegate"), "in range, it PARSES: {v}");
    assert_eq!(verdict(&v), "unauthenticated", "and is refused for the session it lacks: {v}");
    assert_eq!(head_position(port), before);

    // The same frame with 2^53 − 1 is accepted, and the id rides exactly.
    let v = op(port, Some(&owner), &delegate_frame(&prefix, MAX_EXACT_ID));
    assert_eq!(acked_addr(&v), prefix, "{v}");
    let at = acked_at(&v);
    assert!(at > before, "accepted, it COMMITS: {v}");
    assert_eq!(head_position(port), at, "the one commit of this vector");
    assert_eq!(prefix_of(port, MAX_EXACT_ID).as_deref(), Some(prefix.as_str()));
    let v = op(port, None, &effective_owner_frame(&prefix));
    assert_eq!(owner_pair(&v), Some((prefix.clone(), MAX_EXACT_ID)));
    assert_eq!(
        v["principal"],
        Value::from(MAX_EXACT_ID),
        "the largest admissible id is a JSON integer, exact: {v}"
    );

    sd.shutdown();
}
