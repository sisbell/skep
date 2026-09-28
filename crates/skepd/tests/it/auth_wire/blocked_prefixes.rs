//! THE BLOCKED-PREFIX LIST (AUTH-1.44, AUTH-4.36 step 4b, AUTH-4.63/4.64 item
//! 11, AUTH-4.70, AUTH-6.5) and THE TWO ACCESSORS (AUTH-4.30) — the vectors
//! RES-65 item 7 (n), RES-66 item 4 (i), RES-67 item 5 (l), RES-68 item 7 (m),
//! RES-115 and RES-140 record for the skepd lane.
//!
//! The list is CONFIG: every cell here moves it the way an operator does —
//! an issue written beside the supply file and renamed over it
//! (`issue_blocked_list`) — and never through the wire, which has no door for
//! it. The daemon looks at the file at the head of every request, so an issue
//! is in force at the first request after it.

use super::*;

/// Takedown records' version addresses, as entries cite them. The daemon
/// reads no record and knows no takedown — it echoes the address — so these
/// name nothing on the board; each is distinct so a 403 says WHICH entry
/// answered.
const RECORD_MEMBER: &str = "1.0.1.0.7.1";

const RECORD_UNDER: &str = "1.0.1.0.8.1";

const RECORD_CLAIMANT: &str = "1.0.1.0.9.1";

const RECORD_SEAT: &str = "1.0.1.0.10.1";

const RECORD_HOST: &str = "1.0.1.0.11.1";

const RECORD_NODE: &str = "1.0.1.0.12.1";

/// An OFF-BOARD host's account, lexically: `2` is no root the registry
/// assigns (REG-1.67), so it sits under no `1.N` and the off-board test —
/// the header's operator read against the board's NODE PREFIX (REG-1.69;
/// AUTH-4.36 step 4b as ruled 2026-09-18) — refuses it under any prefix.
/// The host in the registry's own global form, `1.N.0.k`, is the new
/// vector's (`the_off_board_test_runs_against_the_node_prefix…`).
const OFF_BOARD_HOST: &str = "2.0.7";

/// `local`'s GLOBAL form on the suite's board: the local `1` replaced by
/// [`NODE_PREFIX`] (REG-1.66: "egress replaces the local `1` with the
/// board's full node prefix") — the spelling the header's OPERATOR field
/// carries, since the off-board test reads it against that prefix.
fn global_form(local: &str) -> String {
    let rest = local.strip_prefix('1').expect("a local-form address begins with 1");
    format!("{NODE_PREFIX}{rest}")
}

/// [`spawn_listed`]'s board WITHOUT the claim — the pre-claim window, where
/// the list has no claimant to take as its comparand.
fn spawn_listed_unclaimed(root: &std::path::Path) -> (skepd::Skepd, std::path::PathBuf) {
    let (list, data) = listed_dirs(root);
    (spawn_with_blocked_prefixes(&data, true, Some(&list), Some(NODE_PREFIX)), list)
}

/// The exact bytes AUTH-6.5 pins for the blocked handshake.
fn prefix_blocked_body(record: &str) -> String {
    format!(r#"{{"error":"prefix_blocked","record":"{record}"}}"#)
}

/// Assert one signed handshake answers the 403 with `record` — the status,
/// the BYTES, and no death signal (a blocked handshake is a refusal with no
/// entry: nothing to close).
fn assert_blocked(port: u16, principal: u64, sk: &SigningKey, record: &str, what: &str) {
    let (st, headers, body) = signed_handshake(port, principal, sk);
    assert_eq!(st, 403, "{what}: {}", String::from_utf8_lossy(&body));
    assert_eq!(String::from_utf8(body).expect("utf-8"), prefix_blocked_body(record), "{what}");
    assert!(header(&headers, "Skepd-Session").is_none(), "{what}: /session is token-blind");
}

/// RES-65 item 7 (n), the handshake's own cells: a signed body under a
/// listed prefix answers `403 prefix_blocked` with the record's address — the
/// nonce SPENT, the same 403 under a garbage `sig` (not a 400, not a 401:
/// the signature is never reached) — while a sibling prefix's body answers
/// 200; `X.1` under listed `X` is refused (the prefix test); the address
/// carried is the LONGEST covering prefix's and a party under two entries is
/// admitted only when both are lifted; a LIFT admits.
///
/// And step 4b's POSITION (AUTH-4.36): behind the origin set and the burn,
/// ahead of the key set — so an origin refusal still precedes it and spends
/// no nonce, and an unknown principal is never told a prefix is blocked.
#[test]
fn a_listed_prefix_answers_the_403_with_its_record_after_the_burn_and_before_the_key_set() {
    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    let origin = format!("http://127.0.0.1:{port}");
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let (member_key, sibling_key) = (distinct_key(31), distinct_key(32));
    let member = keyed_member(port, &anchor, 931, &member_key);
    let sibling = keyed_member(port, &anchor, 932, &sibling_key);
    // The member's first sub-account holds no set of its own: it opens BY
    // REFERENCE against the member's, and it sits UNDER the member's prefix.
    let (under, _) = delegate_under(port, &open_session(port, 931), &member, 933);
    assert!(under.starts_with(&format!("{member}.")), "{under} sits under {member}");

    issue_blocked_list(&list, BlockedHeader::default(), &[(&member, RECORD_MEMBER)]);

    // The 403, its bytes, and the nonce SPENT: the same body again dies at
    // the burn (step 3 stands ahead of 4b) and is the ordinary 401.
    let nonce_for = |principal: u64| {
        let (st, body) =
            http(port, "GET", &format!("/challenge?principal={principal}"), None, b"");
        assert_eq!(st, 200);
        json(&body)["nonce"].as_str().expect("nonce").to_string()
    };
    let body_with = |principal: u64, nonce: &str, org: &str, sig: &str| {
        format!(
            "{{\"principal\":{principal},\"nonce\":\"{nonce}\",\"origin\":\"{org}\",\"sig\":\"{sig}\"}}"
        )
    };
    let nonce = nonce_for(931);
    let honest = body_with(931, &nonce, &origin, &sign_session(&member_key, &origin, &nonce, 931));
    let (st, headers, body) = http_full(port, "POST", "/session", None, honest.as_bytes());
    assert_eq!(st, 403, "{}", String::from_utf8_lossy(&body));
    assert_eq!(String::from_utf8(body).expect("utf-8"), prefix_blocked_body(RECORD_MEMBER));
    assert!(header(&headers, "Skepd-Session").is_none(), "a refusal with no entry: no signal");
    let (st, body) = http(port, "POST", "/session", None, honest.as_bytes());
    assert_eq!(st, 401, "the 403 SPENT the nonce: {}", String::from_utf8_lossy(&body));
    assert_eq!(String::from_utf8(body).expect("utf-8"), r#"{"error":"session_rejected"}"#);

    // A garbage `sig` — well-formed at tag 1's blob width, signing nothing —
    // and a foreign key's: the SAME 403, because no key set is read and no
    // signature verified.
    let nonce = nonce_for(931);
    let garbage = body_with(931, &nonce, &origin, &"00".repeat(3373));
    let (st, body) = http(port, "POST", "/session", None, garbage.as_bytes());
    assert_eq!(st, 403, "not a 400 and not a 401: {}", String::from_utf8_lossy(&body));
    assert_eq!(String::from_utf8(body).expect("utf-8"), prefix_blocked_body(RECORD_MEMBER));
    assert_blocked(port, 931, &distinct_key(99), RECORD_MEMBER, "a foreign key's signature");

    // Step 2 still stands AHEAD: a listed principal at a foreign origin is
    // the 401, and its nonce SURVIVES to meet the 403 at the right origin.
    let nonce = nonce_for(931);
    let evil = "https://evil.example";
    let foreign = body_with(931, &nonce, evil, &sign_session(&member_key, evil, &nonce, 931));
    let (st, _) = http(port, "POST", "/session", None, foreign.as_bytes());
    assert_eq!(st, 401, "the origin set is tested before the burn and before the block");
    let retry = body_with(931, &nonce, &origin, &sign_session(&member_key, &origin, &nonce, 931));
    let (st, _) = http(port, "POST", "/session", None, retry.as_bytes());
    assert_eq!(st, 403, "and the origin refusal spent nothing");
    // …and a principal the board does not know is never told of a block:
    // there is no account to test, so step 4's own refusal answers.
    let (st, _, body) = signed_handshake(port, 931_931, &member_key);
    assert_eq!(st, 401);
    assert_eq!(String::from_utf8(body).expect("utf-8"), r#"{"error":"session_rejected"}"#);

    // A SIBLING prefix is admitted, and its session writes.
    let sibling_token = open_signed_session(port, 932, &sibling_key);
    expect_resp(&op(port, Some(&sibling_token), &create_frame(&sibling, None)), "ack_addr");

    // `X.1` under listed `X`: refused with X's record — the prefix test.
    assert_blocked(port, 933, &member_key, RECORD_MEMBER, "the account under the listed prefix");

    // TWO covering entries: the LONGEST prefix's record answers, and lifting
    // it alone leaves the party under the other.
    issue_blocked_list(
        &list,
        BlockedHeader::default(),
        &[(&member, RECORD_MEMBER), (&under, RECORD_UNDER)],
    );
    assert_blocked(port, 933, &member_key, RECORD_UNDER, "the longest covering prefix");
    assert_blocked(port, 931, &member_key, RECORD_MEMBER, "the shorter entry's own party");
    issue_blocked_list(&list, BlockedHeader::default(), &[(&member, RECORD_MEMBER)]);
    assert_blocked(port, 933, &member_key, RECORD_MEMBER, "one of two lifted: still covered");

    // THE LIFT — an issue in which the entry is absent — admits both.
    issue_blocked_list(&list, BlockedHeader::default(), &[]);
    let member_token = open_signed_session(port, 931, &member_key);
    expect_resp(&op(port, Some(&member_token), &create_frame(&member, None)), "ack_addr");
    open_signed_session(port, 933, &member_key);

    sd.shutdown();
}

/// AUTH-4.64 item 11 — THE KILL. A live session under prefix `X`, the list
/// re-issued with an entry covering `X`: its next request of EITHER kind
/// carries `Skepd-Session: closed` on EACH route of the enumerated set, its
/// next write answers `unauthenticated` with the header on that SAME
/// response, and no `/changes` entry of it carries a position after the
/// install. ARM-BLIND (a bare binding dies as a signed one does) and BY THE
/// PREFIX TEST (a session under `X.1` dies with `X`'s entry). A sibling
/// prefix's session is untouched — its M10 session and memo intact. After
/// the LIFT the same principal's fresh handshake answers 200, and nothing
/// is resurrected.
#[test]
fn a_reissued_entry_kills_the_live_sessions_under_it_on_every_route_of_the_set() {
    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let (member_key, sibling_key) = (distinct_key(31), distinct_key(32));
    let member = keyed_member(port, &anchor, 931, &member_key);
    let sibling = keyed_member(port, &anchor, 932, &sibling_key);
    delegate_under(port, &open_session(port, 931), &member, 933);

    // One LIVE binding per route, opened before the install: a dead token is
    // closed at its first presentation, and an UNKNOWN token signals too, so
    // a binding presented twice would prove nothing about the second route.
    let live = || open_signed_session(port, 931, &member_key);
    let (on_read, on_write, on_op_at, on_changes, on_close, on_events) =
        (live(), live(), live(), live(), live(), live());
    #[cfg(feature = "observe")]
    let on_dump = live();
    let bare = open_session(port, 931);
    let under = open_signed_session(port, 933, &member_key);
    // The sibling's session holds a MEMOIZED ack — what "its M10 session and
    // memo intact" is judged against afterwards.
    let sibling_token = open_signed_session(port, 932, &sibling_key);
    let memoized = format!(r#"{{"op":"create_new_document","id":"s1","account":"{sibling}"}}"#);
    let original = op(port, Some(&sibling_token), &memoized);
    expect_resp(&original, "ack_addr");
    // The member writes while it still can.
    expect_resp(&op(port, Some(&on_write), &create_frame(&member, None)), "ack_addr");

    issue_blocked_list(&list, BlockedHeader::default(), &[(&member, RECORD_MEMBER)]);
    // The first request after the issue installs it; the head it reports is
    // the position the install stands at.
    let installed_at = head_position(port);
    // The list is CONFIG and is published nowhere: `/health.auth` keeps its
    // four members with a list in force (AUTH-6.13's negative pin).
    let auth = json(&get(port, "/health").1)["auth"].clone();
    let members: Vec<&str> = auth.as_object().expect("auth").keys().map(String::as_str).collect();
    assert_eq!(members, ["claimant", "local_trust", "origins", "signed_origins"], "{auth}");

    // The next WRITE: `unauthenticated`, the signal on that SAME response.
    let (st, headers, body) =
        http_full(port, "POST", "/op", Some(&on_write), create_frame(&member, None).as_bytes());
    assert_eq!(st, 200);
    assert_eq!(json(&body)["code"].as_str(), Some("unauthenticated"), "{:?}", json(&body));
    assert_eq!(header(&headers, "Skepd-Session"), Some("closed"));
    assert_eq!(header(&headers, "Access-Control-Expose-Headers"), Some("Skepd-Session"));
    assert_eq!(head_position(port), installed_at, "and the refused write committed nothing");

    // EACH route of the enumerated set (AUTH-4.43), a live binding apiece.
    let routes: &[(&str, &str, &str, &[u8])] = &[
        ("POST", "/op", &on_read, br#"{"op":"next_account_prefix","parent":"1"}"#),
        ("POST", "/op-at", &on_op_at, br#"{"at":0,"frame":{"op":"next_account_prefix","parent":"1"}}"#),
        ("GET", "/changes?since=0", &on_changes, b""),
        ("POST", "/session/close", &on_close, b""),
        #[cfg(feature = "observe")]
        ("GET", "/dump", &on_dump, b""),
    ];
    for &(method, path, token, body) in routes {
        let (_, headers, _) = http_full(port, method, path, Some(token), body);
        assert_eq!(
            header(&headers, "Skepd-Session"),
            Some("closed"),
            "{method} {path}: a binding under the listed prefix dies at its presentation"
        );
    }
    let (mut stream, head) = Sse::connect_with_token(port, &on_events);
    assert!(
        head.to_ascii_lowercase().contains("skepd-session: closed"),
        "/events meets the block before the stream opens: {head}"
    );

    // ARM-BLIND, and BY THE PREFIX TEST.
    assert!(presented_dead(port, &bare), "a BARE binding under the prefix dies as a signed one does");
    assert!(presented_dead(port, &under), "a session under X.1 dies with X's entry");

    // The sibling prefix is UNTOUCHED: its session lives, and M10's memo
    // still holds its ack — the ORIGINAL answer, not a second mint.
    assert!(!presented_dead(port, &sibling_token), "a sibling prefix's session is untouched");
    assert_eq!(
        op(port, Some(&sibling_token), &memoized),
        original,
        "the sibling's memoized ack replays: its M10 session and memo are intact"
    );
    stream.expect_commit(); // the dead token's stream still serves, as a guest's
    expect_resp(&op(port, Some(&sibling_token), &create_frame(&sibling, None)), "ack_addr");

    // No `/changes` entry of the killed key stands after the install.
    let member_fp = fingerprint_hex(&member_key);
    let page = json(&http(port, "GET", &format!("/changes?since={installed_at}"), Some(&anchor), b"").1);
    for entry in page["changes"].as_array().expect("changes") {
        assert_ne!(entry["key"].as_str(), Some(member_fp.as_str()), "after the install: {entry}");
    }

    // THE LIFT admits the next handshake and resurrects nothing.
    issue_blocked_list(&list, BlockedHeader::default(), &[]);
    let again = open_signed_session(port, 931, &member_key);
    expect_resp(&op(port, Some(&again), &create_frame(&member, None)), "ack_addr");
    assert!(presented_dead(port, &on_write), "a killed binding stays gone: the closed entry is no entry");

    sd.shutdown();
}

/// AUTH-4.44 and `Daemon::route`'s own rule — THE REISSUE STANDS AHEAD OF
/// DISPATCH ON EVERY REQUEST, `/events` INCLUDED: a stream opening as the
/// FIRST request after an issue installs that issue before it resolves its
/// own actor, so a covered token meets `Skepd-Session: closed` on the
/// stream's own head.
///
/// `/events` is the one route where a missed install is never corrected: a
/// stream resolves ONCE, at open, and the binding it opened under lives for
/// the connection. Put the look below dispatch — the natural place for a
/// per-request `stat`, since `Routed::EventStream` returns before `reply`
/// and a stream is not a reply — and this connect reads the PRE-issue list,
/// the stream opens with no signal, and a party the operator ordered dead
/// holds a live subscription for as long as it cares to.
///
/// The kill suite's own stream connects only after eight requests have
/// already installed the issue, and the one cell whose blocking request IS
/// its installing request drives `/session`, which goes through `reply`. So
/// this is the position neither of them puts `/events` in.
#[test]
fn a_stream_opening_first_after_an_issue_installs_it_before_it_resolves() {
    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let member_key = distinct_key(35);
    let member = keyed_member(port, &anchor, 935, &member_key);
    let live = open_signed_session(port, 935, &member_key);

    // A stream opened BEFORE the issue carries no signal — the control that
    // makes the assertion below a statement about the install rather than
    // about this token.
    let (mut before, head) = Sse::connect_with_token(port, &live);
    assert!(
        !head.to_ascii_lowercase().contains("skepd-session: closed"),
        "no entry covers this binding yet: {head}"
    );
    before.expect_commit();

    // THE ISSUE, and then NOTHING but the stream: the connect is the request
    // that notices the file moved.
    issue_blocked_list(&list, BlockedHeader::default(), &[(&member, RECORD_MEMBER)]);
    let (_after, head) = Sse::connect_with_token(port, &live);
    assert!(
        head.to_ascii_lowercase().contains("skepd-session: closed"),
        "/events installed the reissue ahead of its own resolve: {head}"
    );

    sd.shutdown();
}

/// AUTH-4.63's second trigger against AUTH-4.27's order — THE BLOCK IS AHEAD
/// OF THE BARE ARM'S PER-REQUEST CONJUNCT: a BARE binding under a listed
/// prefix, presented from an origin OUTSIDE the bare set, answers DEATH and
/// never `RequestRefused`. It is the one cell where both would refuse, and so
/// the only one that tells their order apart.
///
/// The fear is the tidy inversion — test the cheap set membership first and
/// spend the list's linear scan only where the request would otherwise be
/// admitted, a cost `covers`' own card discloses per consult. Under it this
/// presentation is "refused for this request", which the rule reserves for a
/// binding that LIVES: no signal, nothing closed, and the M10 session and its
/// memo retained for a party the operator ordered dead.
///
/// The proof that it is death and not a refusal is that a LIFT does not bring
/// it back. `the_origin_header_fences_the_bare_bind_without_killing_it` is
/// this cell's other half, on a board with no list: there the same
/// presentation must NOT kill, and `a_reissued_entry_kills…` sends no
/// `Origin` at all, so the inversion is invisible to both.
#[test]
fn the_block_outranks_a_refused_origin_and_kills_the_bare_binding() {
    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let member_key = distinct_key(36);
    let member = keyed_member(port, &anchor, 936, &member_key);
    let bare = open_session(port, 936);
    let draft = create_frame(&member, None);
    let evil = "https://evil.example";
    // The binding writes: the foreign origin alone would refuse it for THAT
    // request and leave it alive, which is what the block is about to outrank.
    expect_resp(&op(port, Some(&bare), &draft), "ack_addr");

    issue_blocked_list(&list, BlockedHeader::default(), &[(&member, RECORD_MEMBER)]);
    let (st, headers, body) =
        http_with_origin(port, "POST", "/op", Some(&bare), evil, draft.as_bytes());
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        json(&body)["code"].as_str(),
        Some("unauthenticated"),
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        header(&headers, "Skepd-Session"),
        Some("closed"),
        "the cell where BOTH would refuse answers death, never refused-for-this-request"
    );

    // …and death is permanent, which is what tells it from a request refusal:
    // after the LIFT the same token is still gone, where a binding merely
    // refused for one request would write again the moment the entry went.
    issue_blocked_list(&list, BlockedHeader::default(), &[]);
    assert!(presented_dead(port, &bare), "a killed bare binding stays gone after the lift");
    let (st, _, body) = http_full(port, "POST", "/op", Some(&bare), draft.as_bytes());
    assert_eq!(st, 200);
    assert_eq!(
        json(&body)["code"].as_str(),
        Some("unauthenticated"),
        "and it writes nothing: {}",
        String::from_utf8_lossy(&body)
    );
    // The PRINCIPAL is admitted again — the lift is a lift, not a ban.
    let fresh = open_session(port, 936);
    expect_resp(&op(port, Some(&fresh), &draft), "ack_addr");

    sd.shutdown();
}

/// THE HEADER ROWS (RES-66 item 4 (i), RES-67 item 5 (l), RES-68 item 7 (m);
/// AUTH-4.64 item 11) — the install's two INERT comparands, at the four A3
/// cells. An entry covering (a) the configured OPERATOR account (the claimant
/// where the header names none), or (b) — where that account is NOT an
/// account of this board — the board's BINDING-WRITING account (the claimant
/// where the header omits it), is ignored at install: its party's sessions
/// live and its handshakes are admitted, principal 0's with them where the
/// comparand is the claimant. Every other entry installs.
///
/// One board, one reissue per row: the header is config, and the claimant —
/// "the OLD REGISTRAR" of the two fork rows — is whoever claimed it. The
/// board is launched `--node-prefix 1.3`, so "NOT an account of this board"
/// is read against that prefix (REG-1.69; the ruled form of step 4b): the
/// lexically foreign host is off-board under it, and the seat a self-served
/// fork names is spelled in the GLOBAL form the header carries.
#[test]
fn the_headers_two_comparands_are_inert_at_the_four_lineage_cells() {
    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let (seat_key, member_key) = (distinct_key(41), distinct_key(42));
    let seat = keyed_member(port, &anchor, 941, &seat_key);
    let member = keyed_member(port, &anchor, 942, &member_key);
    let claimant = CLAIMANT_ACCOUNT;
    let zero = PRINCIPAL_ZERO;

    // THE ROOT (and every unforked self-served board): the header names
    // none, so (a) and (b) are ONE account, the claimant. An entry over it —
    // or over any prefix ABOVE it, the board's own node included — is inert;
    // a member's installs.
    let claimant_live = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let zero_live = open_signed_session(port, zero, &device_key());
    issue_blocked_list(
        &list,
        BlockedHeader::default(),
        &[(claimant, RECORD_CLAIMANT), ("1", RECORD_NODE), (&member, RECORD_MEMBER)],
    );
    assert_blocked(port, 942, &member_key, RECORD_MEMBER, "the root: a member's entry installs");
    assert!(!presented_dead(port, &claimant_live), "the root: the claimant's session lives");
    assert!(!presented_dead(port, &zero_live), "the root: principal 0's session lives");
    open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    open_signed_session(port, zero, &device_key());
    open_signed_session(port, 941, &seat_key);
    // …and a header that NAMES the claimant is the same row as one naming
    // none (RES-66 item 4 (i)): the same inert set. Named here in the LOCAL
    // form, under no `1.N`, it reads OFF-board under the ruled test, and (b)
    // — the claimant, the field omitted — is the one account (a) already
    // is; the verdicts are the row above's, by the other comparand.
    let names_the_claimant = BlockedHeader { operator: Some(claimant), binding_writer: None };
    issue_blocked_list(&list, names_the_claimant, &[(claimant, RECORD_CLAIMANT)]);
    assert!(!presented_dead(port, &claimant_live), "the root, the claimant named: it lives");
    open_signed_session(port, zero, &device_key());

    // A HOSTED TIER: the header names an OFF-BOARD host and omits the second
    // field, so (b) is LIVE and the claimant is taken in the field's place —
    // an entry over the served board's claimant is ignored, one over the
    // host's own account covers no account of this board, and a MEMBER's
    // installs and its session dies.
    issue_blocked_list(&list, BlockedHeader::default(), &[]);
    let member_live = open_signed_session(port, 942, &member_key);
    let hosted = BlockedHeader { operator: Some(OFF_BOARD_HOST), binding_writer: None };
    issue_blocked_list(
        &list,
        hosted,
        &[(claimant, RECORD_CLAIMANT), (OFF_BOARD_HOST, RECORD_HOST), (&member, RECORD_MEMBER)],
    );
    assert!(presented_dead(port, &member_live), "hosted: a member's session dies");
    assert_blocked(port, 942, &member_key, RECORD_MEMBER, "hosted: a member's entry installs");
    assert!(!presented_dead(port, &claimant_live), "hosted: the served board's claimant lives");
    assert!(!presented_dead(port, &zero_live), "hosted: principal 0's session lives");
    open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    open_signed_session(port, zero, &device_key());

    // A FORK THE COMMUNITY ITSELF SERVES: the header names the SEAT, an
    // account of the copy — in the GLOBAL form under the board's node
    // prefix, `1.3.0.k`, the form that reads ON-board — so (b) is SILENT
    // and the old claimant stays blockable (RES-66). The entry over the OLD
    // CLAIMANT installs and its sessions die, principal 0's among them (0 ↦
    // the claimant); the entry over the SEAT — spelled as the header spells
    // it, the operator being read as spelled — is ignored.
    let seat_live = open_signed_session(port, 941, &seat_key);
    let seat_global = global_form(&seat);
    let self_served = BlockedHeader { operator: Some(&seat_global), binding_writer: None };
    issue_blocked_list(
        &list,
        self_served,
        &[(claimant, RECORD_CLAIMANT), (&seat_global, RECORD_SEAT)],
    );
    assert!(presented_dead(port, &claimant_live), "fork: the old claimant's session dies");
    assert!(presented_dead(port, &zero_live), "fork: principal 0's dies with it");
    assert_blocked(port, CLAIMANT_PRINCIPAL, &device_key(), RECORD_CLAIMANT, "fork: the old claimant");
    assert_blocked(port, zero, &device_key(), RECORD_CLAIMANT, "fork: principal 0 ↦ the claimant");
    assert!(!presented_dead(port, &seat_live), "fork: the seat's session lives");
    open_signed_session(port, 941, &seat_key);

    // A FORK A THIRD PARTY SERVES: the operator off-board, the second field
    // naming the SEAT — which is exempted, and NEVER the old claimant, as
    // blockable here as on the self-served fork. The host's own entry is
    // ignored.
    let third_party =
        BlockedHeader { operator: Some(OFF_BOARD_HOST), binding_writer: Some(&seat) };
    issue_blocked_list(
        &list,
        third_party,
        &[(claimant, RECORD_CLAIMANT), (&seat, RECORD_SEAT), (OFF_BOARD_HOST, RECORD_HOST)],
    );
    assert_blocked(port, CLAIMANT_PRINCIPAL, &device_key(), RECORD_CLAIMANT, "hosted fork: the old claimant");
    assert_blocked(port, zero, &device_key(), RECORD_CLAIMANT, "hosted fork: principal 0");
    assert!(!presented_dead(port, &seat_live), "hosted fork: the seat's session lives");
    open_signed_session(port, 941, &seat_key);
    open_signed_session(port, 942, &member_key);

    sd.shutdown();
}

/// THE OFF-BOARD TEST RUNS AGAINST THE NODE PREFIX (REG-1.69; AUTH-4.36 step
/// 4b's comparand (b) as ruled 2026-09-18), never against the local root `1`
/// — under which a host's account in the registry's GLOBAL form (`1.3.0.7`:
/// every global address begins with the root, REG-1.66) read as on-board,
/// (b) went silent, and the hosted board's claimant became blockable (W2a's
/// escalation 3). ONE header — operator `1.3.0.7`, the second field omitted
/// — installed on three boards:
///
/// * `--node-prefix 1.3`: the operator is ON-BOARD, under the prefix; (b) is
///   SILENT, and the entry over the claimant — the binding-writing account —
///   is LIVE: the claimant's session dies and its handshake is the 403;
/// * `--node-prefix 1.5`: the same operator is OFF-BOARD; (b) is LIVE, and
///   the entry over the served board's claimant is INERT (and logged): its
///   session lives and its handshake is admitted, principal 0's with it;
/// * no node prefix: the daemon cannot tell, the test is OFF and every
///   operator reads as on-board — the claimant blockable, as on the first
///   board — and the install log says so once (pinned at the unit level,
///   the log being stderr).
///
/// On every board a MEMBER's entry installs: the list is in force, and only
/// the exemption moves.
#[test]
fn the_off_board_test_runs_against_the_node_prefix_and_is_off_without_one() {
    // Board `1.3`'s account `0.7`, in the registry's global form.
    const OPERATOR: &str = "1.3.0.7";
    let header = BlockedHeader { operator: Some(OPERATOR), binding_writer: None };
    for (node_prefix, claimant_blockable, what) in [
        (Some("1.3"), true, "--node-prefix 1.3: the operator on-board, (b) silent"),
        (Some("1.5"), false, "--node-prefix 1.5: the operator off-board, (b) live"),
        (None, true, "no --node-prefix: the test off, every operator on-board"),
    ] {
        let root = tempfile::tempdir().expect("tempdir");
        let (sd, list) = spawn_listed_at(root.path(), node_prefix);
        let port = sd.port();
        let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
        let member_key = distinct_key(51);
        let member = keyed_member(port, &anchor, 951, &member_key);
        let claimant_live = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        let zero_live = open_signed_session(port, PRINCIPAL_ZERO, &device_key());
        let member_live = open_signed_session(port, 951, &member_key);
        issue_blocked_list(
            &list,
            header,
            &[(CLAIMANT_ACCOUNT, RECORD_CLAIMANT), (&member, RECORD_MEMBER)],
        );
        assert!(presented_dead(port, &member_live), "{what}: a member's session dies");
        assert_blocked(port, 951, &member_key, RECORD_MEMBER, what);
        if claimant_blockable {
            assert!(presented_dead(port, &claimant_live), "{what}: the claimant's session dies");
            assert!(presented_dead(port, &zero_live), "{what}: principal 0's dies with it");
            assert_blocked(port, CLAIMANT_PRINCIPAL, &device_key(), RECORD_CLAIMANT, what);
            assert_blocked(port, PRINCIPAL_ZERO, &device_key(), RECORD_CLAIMANT, what);
        } else {
            assert!(!presented_dead(port, &claimant_live), "{what}: the served claimant lives");
            assert!(!presented_dead(port, &zero_live), "{what}: principal 0's session lives");
            open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
            open_signed_session(port, PRINCIPAL_ZERO, &device_key());
        }
        sd.shutdown();
    }
}

/// REG-1.69/1.70 — THE NODE PREFIX IS PER-DAEMON CONFIG, SUPPLIED AT EVERY
/// START AND IN NO RECORD, JOURNAL, SIDECAR OR FOLD: one board, one journal,
/// one supply file, one header — and the off-board test follows the FLAG
/// across a restart, which is how a board answers to a successor prefix.
///
/// Under `1.3` the header's operator is an account of this board, so (b) is
/// silent and the entry over the claimant is LIVE. Restarted under `1.5` —
/// the same data dir, the same list, the same recovered claimant — the
/// operator is off-board, (b) goes live, and that entry is INERT. Remember
/// the prefix anywhere and the documented reconfigure does nothing: the
/// served claimant stays blockable, or a standing block stays lifted.
///
/// The three-board table above cannot see this — each board writes its own
/// state under its own flag, so anything remembered at first start agrees
/// with the flag on every row — and it is also the one cell where BOTH
/// start-up comparands resolve live at once: the recovered claimant standing
/// as (b) because a named operator is off-board.
#[test]
fn a_restart_under_a_fresh_node_prefix_moves_the_off_board_test() {
    // Board `1.3`'s account `0.7`, in the registry's global form.
    const OPERATOR: &str = "1.3.0.7";
    let header = BlockedHeader { operator: Some(OPERATOR), binding_writer: None };
    let root = tempfile::tempdir().expect("tempdir");
    let member_key = distinct_key(37);
    {
        let (sd, list) = spawn_listed_at(root.path(), Some("1.3"));
        let port = sd.port();
        let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
        let member = keyed_member(port, &anchor, 937, &member_key);
        issue_blocked_list(
            &list,
            header,
            &[(CLAIMANT_ACCOUNT, RECORD_CLAIMANT), (&member, RECORD_MEMBER)],
        );
        // Under the board's OWN prefix the operator is on-board: (b) silent,
        // the claimant blockable, principal 0 with it.
        assert_blocked(port, CLAIMANT_PRINCIPAL, &device_key(), RECORD_CLAIMANT, "under 1.3");
        assert_blocked(port, PRINCIPAL_ZERO, &device_key(), RECORD_CLAIMANT, "under 1.3");
        assert_blocked(port, 937, &member_key, RECORD_MEMBER, "under 1.3");
        sd.shutdown();
    }

    // THE RECONFIGURE: the same root, so the same data dir and the same
    // supply file — only the flag moves.
    let (sd, _) = spawn_listed_at(root.path(), Some("1.5"));
    let port = sd.port();
    open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    open_signed_session(port, PRINCIPAL_ZERO, &device_key());
    // The MEMBER's entry is the pairing: it covers no comparand under either
    // prefix, so the list being in force is not in question — only (b) moved.
    assert_blocked(port, 937, &member_key, RECORD_MEMBER, "the list is still in force under 1.5");
    sd.shutdown();
}

/// RES-115 — THE LIST IS SUPPLIED AT EVERY START: a restart re-installs it
/// from the start-up supply, so no restart lapses a standing block — and an
/// issue made while the daemon was DOWN is the one the next start installs.
/// The two refusals beside it: a supply that is not a list STOPS the start
/// (never an empty list in its place), and a reissue that is not a list
/// installs NOTHING — the list in force stands until a good issue replaces
/// it WHOLE.
#[test]
fn a_restart_reinstalls_the_list_and_a_bad_issue_installs_nothing() {
    let root = tempfile::tempdir().expect("tempdir");
    let member_key = distinct_key(31);
    let member = {
        let (sd, list) = spawn_listed(root.path());
        let port = sd.port();
        let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
        let member = keyed_member(port, &anchor, 931, &member_key);
        issue_blocked_list(&list, BlockedHeader::default(), &[(&member, RECORD_MEMBER)]);
        assert_blocked(port, 931, &member_key, RECORD_MEMBER, "blocked before the restart");
        sd.shutdown();
        member
    };

    // The restart: the same supply, and the block holds at the FIRST request
    // — installed at open, with no reissue in between.
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    assert_blocked(port, 931, &member_key, RECORD_MEMBER, "the block holds across the restart");

    // A reissue that is not a list — torn JSON, an unknown field, an address
    // no tumbler spells — installs nothing: the block stands.
    for bad in [
        &br#"{"entries":[{"prefix":"1.0.2","#[..],
        br#"{"entries":[],"lifted":true}"#,
        br#"{"entries":[{"prefix":"1..2","record":"1.0.1.0.7.1"}]}"#,
        br#"{"operator":null,"entries":[]}"#,
        br#"[]"#,
    ] {
        issue_blocked_list_bytes(&list, bad);
        assert_blocked(port, 931, &member_key, RECORD_MEMBER, "a refused issue moves nothing");
    }
    // …and the next GOOD issue replaces the list whole.
    issue_blocked_list(&list, BlockedHeader::default(), &[]);
    open_signed_session(port, 931, &member_key);
    sd.shutdown();

    // An issue made while the daemon is DOWN is what the next start installs.
    issue_blocked_list(&list, BlockedHeader::default(), &[(&member, RECORD_UNDER)]);
    let (sd, list) = spawn_listed(root.path());
    assert_blocked(sd.port(), 931, &member_key, RECORD_UNDER, "the start-up supply's current issue");
    sd.shutdown();

    // A supply that is NOT a list stops the start: `DaemonError`, not a
    // daemon serving an empty list the standing records do not support.
    issue_blocked_list_bytes(&list, b"not a list");
    let mut opts = skepd::AuthOptions::default();
    opts.blocked_supply_path = Some(list.clone());
    let refused = skepd::Daemon::open_with(root.path().join("data"), opts);
    assert!(
        matches!(refused, Err(skepd::DaemonError::BlockedPrefixes(_))),
        "a malformed start-up supply refuses the open"
    );
    let mut opts = skepd::AuthOptions::default();
    opts.blocked_supply_path = Some(root.path().join("no-such-file.json"));
    let refused = skepd::Daemon::open_with(root.path().join("data"), opts);
    assert!(
        matches!(refused, Err(skepd::DaemonError::BlockedPrefixes(_))),
        "and so does a supply that is not there"
    );
}

/// RES-115's RUNTIME half, on the accident the operator is likeliest to have:
/// the supply file DELETED while the daemon runs. Its identity moved, so the
/// channel looks — and the read fails, which installs NOTHING (the list is
/// replaced WHOLE or not at all), so an absent file is NO LIFT: a lift of
/// everything is an ISSUE, the explicit empty list.
///
/// The bad-bytes cells above fail inside the supply's parse; a deletion fails
/// one layer earlier, at the open, and stamps no file where they stamp one —
/// so "no file, no blocks", the natural reading, lifts every standing
/// takedown at the next request and passes every one of those cells.
///
/// And the channel is not stuck by the accident: the next good issue installs,
/// so the operator's own lift still works afterwards.
#[test]
fn deleting_the_supply_installs_nothing_and_the_list_in_force_stands() {
    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let member_key = distinct_key(34);
    let member = keyed_member(port, &anchor, 934, &member_key);
    let live = open_signed_session(port, 934, &member_key);

    issue_blocked_list(&list, BlockedHeader::default(), &[(&member, RECORD_MEMBER)]);
    assert!(presented_dead(port, &live), "the entry is in force");
    assert_blocked(port, 934, &member_key, RECORD_MEMBER, "the entry is in force");

    std::fs::remove_file(&list).expect("remove the supply");
    assert_blocked(port, 934, &member_key, RECORD_MEMBER, "the file gone: the block stands");
    // The second look rules out a first request that happened not to reach
    // the channel, and pins that the refusal is remembered without the list
    // moving under it.
    assert_blocked(port, 934, &member_key, RECORD_MEMBER, "…and at the next look too");

    // The next GOOD issue installs: the failed look stopped nothing.
    issue_blocked_list(&list, BlockedHeader::default(), &[]);
    open_signed_session(port, 934, &member_key);

    sd.shutdown();
}

/// RES-115 and AUTH-4.36 step 4b together, at the ONE install the reissue
/// cells cannot reach: the START-UP install reads the claimant the canonical
/// rebuild has just recovered, so an entry over the claimant is INERT again
/// after a restart. Installed without it — the "there is no fold yet at open"
/// reading — comparand (a) is absent, `covers` answers nobody, the entry goes
/// LIVE, and the board's owner is locked out of their own board on every
/// restart, principal 0 with it: the cell REG-4.198 rules out, appearing at
/// the moment nobody is watching.
///
/// The member's entry is the PAIRING that makes the claimant's admission mean
/// anything: the same install put it in force, so the claimant being admitted
/// is not merely a list that failed to install at all.
#[test]
fn a_restart_installs_the_list_against_the_recovered_claimant() {
    let root = tempfile::tempdir().expect("tempdir");
    let member_key = distinct_key(33);
    {
        let (sd, list) = spawn_listed(root.path());
        let port = sd.port();
        let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
        let member = keyed_member(port, &anchor, 933, &member_key);
        issue_blocked_list(
            &list,
            BlockedHeader::default(),
            &[(CLAIMANT_ACCOUNT, RECORD_CLAIMANT), (&member, RECORD_MEMBER)],
        );
        assert_blocked(port, 933, &member_key, RECORD_MEMBER, "before the restart: the member");
        open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        sd.shutdown();
    }

    let (sd, _) = spawn_listed(root.path());
    let port = sd.port();
    open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    // Principal 0 is the second witness of the same comparand: it maps to the
    // claimant on both accessors (AUTH-4.30), so it is exempt with it.
    open_signed_session(port, PRINCIPAL_ZERO, &device_key());
    assert_blocked(port, 933, &member_key, RECORD_MEMBER, "the restart installed the list");
    sd.shutdown();
}

/// RES-65 item 4's residue and item 3's, in the window no other listed board
/// is in: UNCLAIMED. The header names none and there is NO CLAIMANT to take in
/// its place, so there is no comparand and every entry STANDS AS ISSUED — over
/// the very account the ceremony would have claimed with, which is what makes
/// the residue a residue. It reaches its own prefix and no other, so the kill
/// is by coverage and not by a list merely being in force.
///
/// And the BARE ARM is untouched by the list (AUTH-4.37): a bare bind naming a
/// covered principal is admitted as written — never the 403, which the signed
/// arm alone answers — and `resolve`'s arm-blind kill is what ends it, at the
/// first presentation.
///
/// The claimed-board contrast for the same entry is
/// [`the_headers_two_comparands_are_inert_at_the_four_lineage_cells`], where
/// the claimant IS the comparand and the entry over it is inert. It cannot be
/// run on this board: the ceremony must be the board's first delegate, and
/// this cell has already spent that address.
#[test]
fn an_unclaimed_board_has_no_comparand_so_every_entry_stands_as_issued() {
    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed_unclaimed(root.path());
    let port = sd.port();
    assert!(!claimed(port), "the pre-claim window");

    let (covered, covered_session) = bootstrap_delegate(port, 961);
    let (_, sibling_session) = bootstrap_delegate(port, 962);
    assert_eq!(covered, CLAIMANT_ACCOUNT, "the first delegate takes the claimant's address");

    issue_blocked_list(&list, BlockedHeader::default(), &[(&covered, RECORD_CLAIMANT)]);
    assert!(presented_dead(port, &covered_session), "no claimant, no comparand: the entry stands");
    assert!(!presented_dead(port, &sibling_session), "and it reaches its own prefix and no other");

    let (st, headers, body) =
        http_full(port, "POST", "/session", None, br#"{"principal":961}"#);
    assert_eq!(st, 200, "the bare arm reads no list: {}", String::from_utf8_lossy(&body));
    assert!(header(&headers, "Skepd-Session").is_none(), "/session is token-blind");
    let fresh = json(&body)["session"].as_str().expect("session").to_string();
    assert!(presented_dead(port, &fresh), "…and the fresh binding dies at its first presentation");

    sd.shutdown();
}

/// AUTH-4.30 (i) — `key_subject` walks to the nearest keyed account above:
/// a device key of `X` opens a SIGNED session AS an unseeded `X.2` (200), AS
/// `X.1`, and AS `X.2.7` two levels down — and each writes, its testimony
/// the key that opened it. The session authenticates against `X`'s set and
/// is re-resolved per request, so a RETIREMENT AT `X` kills it at its next
/// presentation (`Skepd-Session: closed`), exactly as it kills `X`'s own.
#[test]
fn a_key_of_the_holder_opens_its_unseeded_accounts_and_a_retirement_at_the_holder_kills_them() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let accounts = by_reference_accounts(port);
    let device_fp = fingerprint_hex(&device_key());

    let as_x1 = open_signed_session(port, accounts.x1, &device_key());
    let as_x2 = open_signed_session(port, accounts.x2, &device_key());
    let as_x2_7 = open_signed_session(port, accounts.x2_7, &device_key());
    // A token that WRITES, as the account it names: the home mint of X.2,
    // testified under the holder's key.
    let minted = op(port, Some(&as_x2), &create_frame(&accounts.x2_account, None));
    let at = acked_at(&minted);
    let page = json(&http(port, "GET", &format!("/changes?since={}", at - 1), Some(&as_x2), b"").1);
    let entry = page["changes"]
        .as_array()
        .expect("changes")
        .iter()
        .find(|e| e["at"].as_u64() == Some(at))
        .unwrap_or_else(|| panic!("the mint's own entry: {page}"))
        .clone();
    assert_eq!(entry["key"].as_str(), Some(device_fp.as_str()), "the opening key testifies");
    // A key NO set above holds opens nothing: the walk chose X's set, and
    // the signature is verified against it.
    let (st, _, _) = signed_handshake(port, accounts.x2, &distinct_key(77));
    assert_eq!(st, 401, "a key outside the holder's set");
    // `key_set` answers the unseeded account its OWN, EMPTY set — never the
    // set that opens it (AUTH-6.19).
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{}"}}"#, accounts.x2_account));
    assert_eq!(v["enrolled"].as_array().map(Vec::len), Some(0), "{v}");

    // The retirement at X, from X's anchor session.
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let ordinal = next_content_ordinal(port, Some(&anchor), CLAIMANT_DOC1);
    let retire = record_atom(port, &anchor, ordinal, &retire_atom(&[&device_fp]), T_RETIRE);
    expect_resp(&deposit(port, &anchor, &retire, T_RETIRE), "ack_addr");
    for (what, token) in [("X.1", &as_x1), ("X.2", &as_x2), ("X.2.7", &as_x2_7)] {
        assert!(presented_dead(port, token), "a retirement at X kills the session as {what}");
    }
    // The anchor still opens them: the set, not the key, is what they share.
    open_signed_session(port, accounts.x2, &anchor_key());

    sd.shutdown();
}

/// E2's THIRD TRIGGER (RES-128 C-4, RES-140; conformance T-E2(12)): a session
/// opened by reference DIES at the genesis of the account it acts as, or of
/// any account between it and the set it authenticated against — a genesis
/// at `X.2` kills the session as `X.2` AND the one as `X.2.7`, `closed` at
/// the next presentation — while the GIVER's session as `X`, and a session
/// as `X.1` that the genesis is not above, are untouched. No code of its
/// own: `key_subject` is re-run per request and now answers `X.2`.
#[test]
fn a_genesis_kills_the_sessions_opened_by_reference_at_and_beneath_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let accounts = by_reference_accounts(port);
    let giver = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let as_x1 = open_signed_session(port, accounts.x1, &device_key());
    let as_x2 = open_signed_session(port, accounts.x2, &device_key());
    let as_x2_7 = open_signed_session(port, accounts.x2_7, &device_key());

    // THE HANDOFF: X.2's genesis, homed in its registry — X's doc 1 — under
    // a FRESH key (the latch refuses one the set above holds), from X's
    // anchor session.
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let recipient_key = distinct_key(52);
    let recipient =
        hire(port, &anchor, CLAIMANT_DOC1, &accounts.x2_account, accounts.x2, &recipient_key);

    assert!(presented_dead(port, &as_x2), "the session as X.2 dies at X.2's genesis");
    assert!(presented_dead(port, &as_x2_7), "and the one as X.2.7: X.2 now stands between");
    assert!(!presented_dead(port, &giver), "the giver's session as X is untouched");
    assert!(!presented_dead(port, &as_x1), "and one as X.1, which the genesis is not above");
    assert!(!presented_dead(port, &recipient), "the recipient's own session lives");

    // The door has moved with the set: X's key opens neither any more, and
    // the RECIPIENT's opens both — at a handed-off account's children the
    // nearest keyed account above is the recipient's (RES-154).
    for p in [accounts.x2, accounts.x2_7] {
        let (st, _, body) = signed_handshake(port, p, &device_key());
        assert_eq!(st, 401, "the giver's key no longer opens {p}");
        assert_eq!(String::from_utf8(body).expect("utf-8"), r#"{"error":"session_rejected"}"#);
        open_signed_session(port, p, &recipient_key);
    }

    sd.shutdown();
}

/// THE BLOCKED-PREFIX COMPARAND IS `session_account`'s, never `key_subject`'s
/// (AUTH-4.30 (ii)): an entry over exactly `X.1` still covers a session as
/// `X.1` — whose set is `X`'s, which the entry does not cover — at the
/// handshake and at the kill alike; and REACH IS BY COVER, never by descent
/// (AUTH-4.70): the entry over `X.1` reaches neither `X` nor `X.2`.
#[test]
fn an_entry_over_exactly_the_agent_space_covers_it_whosever_set_opens_it() {
    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    let accounts = by_reference_accounts(port);
    let x1_account = format!("{CLAIMANT_ACCOUNT}.1");
    let as_x = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let as_x1 = open_signed_session(port, accounts.x1, &device_key());
    let as_x2 = open_signed_session(port, accounts.x2, &device_key());

    issue_blocked_list(&list, BlockedHeader::default(), &[(&x1_account, RECORD_UNDER)]);

    assert!(presented_dead(port, &as_x1), "the live session as X.1 is covered by its OWN account");
    assert_blocked(port, accounts.x1, &device_key(), RECORD_UNDER, "a handshake as X.1");
    assert!(!presented_dead(port, &as_x), "the entry over X.1 does not reach X");
    assert!(!presented_dead(port, &as_x2), "nor its sibling X.2");
    open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    open_signed_session(port, accounts.x2, &device_key());

    sd.shutdown();
}

/// AUTH-4.62 item 1 — the 401 body is BYTE-IDENTICAL across the thirteen
/// arms, and the 403 sits OUTSIDE them by status. Driven here are the arms
/// `every_handshake_failure_answers_the_same_401_bytes` does not reach: the
/// RETIRED key, the MIS-SIGNED body (an enrolled key over other bytes), the
/// bare bind where DISALLOWED (ENFORCING), principal 0 on an UNCLAIMED board,
/// and the thirteenth — a principal whose KEY SUBJECT's set is EMPTY, which
/// since the walk is the OWN-ADDRESS TERMINUS: a never-keyed top-level
/// delegate, and an unseeded account under never-keyed ancestors, where no
/// account above holds a set and step 5 refuses at the account's own
/// address. (Expiry needs the 60 s TTL and is pinned at `handshake` itself.)
#[test]
fn the_thirteen_401_arms_stay_byte_identical_and_the_403_stands_outside_them() {
    const REJECTED: &str = r#"{"error":"session_rejected"}"#;
    let rejected = |what: &str, (st, headers, body): (u16, Vec<(String, String)>, Vec<u8>)| {
        assert_eq!(st, 401, "{what}");
        assert_eq!(String::from_utf8(body).expect("utf-8"), REJECTED, "{what}: the one code");
        assert!(header(&headers, "Skepd-Session").is_none(), "{what}: /session is token-blind");
    };

    // Principal 0 on an UNCLAIMED board: no claimant, so nothing to sign
    // with — exactly as an unknown principal (E6).
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let sd = spawn_unclaimed(dir.path());
        rejected(
            "principal 0 on an unclaimed board",
            signed_handshake(sd.port(), PRINCIPAL_ZERO, &device_key()),
        );
        sd.shutdown();
    }
    // The bare bind where DISALLOWED: ENFORCING.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let sd = spawn_configured(dir.path(), false);
        claim_board(sd.port());
        let body = format!("{{\"principal\":{CLAIMANT_PRINCIPAL}}}");
        rejected(
            "a bare bind on an ENFORCING board",
            http_full(sd.port(), "POST", "/session", None, body.as_bytes()),
        );
        sd.shutdown();
    }

    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    let origin = format!("http://127.0.0.1:{port}");
    let p = CLAIMANT_PRINCIPAL;

    // THE THIRTEENTH ARM, at the own-address terminus: a never-keyed
    // top-level delegate, and an unseeded account beneath it — the walk
    // finds no keyed account above, answers the account's OWN address, and
    // step 5 refuses its empty set.
    let (never_keyed, never_keyed_session) = bootstrap_delegate(port, 961);
    delegate_under(port, &never_keyed_session, &never_keyed, 962);
    rejected("a never-keyed top-level delegate", signed_handshake(port, 961, &device_key()));
    rejected(
        "an unseeded account under never-keyed ancestors",
        signed_handshake(port, 962, &device_key()),
    );

    // MIS-SIGNED: an ENROLLED key, over bytes that are not this body's.
    let (st, body) = http(port, "GET", &format!("/challenge?principal={p}"), None, b"");
    assert_eq!(st, 200);
    let nonce = json(&body)["nonce"].as_str().expect("nonce").to_string();
    let sig = sign_session(&device_key(), &origin, &"ab".repeat(32), p);
    let body = format!(
        "{{\"principal\":{p},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"sig\":\"{sig}\"}}"
    );
    rejected("an enrolled key's signature over other bytes", http_full(port, "POST", "/session", None, body.as_bytes()));

    // The RETIRED key.
    let anchor = open_signed_session(port, p, &anchor_key());
    let device_fp = fingerprint_hex(&device_key());
    let ordinal = next_content_ordinal(port, Some(&anchor), CLAIMANT_DOC1);
    let retire = record_atom(port, &anchor, ordinal, &retire_atom(&[&device_fp]), T_RETIRE);
    expect_resp(&deposit(port, &anchor, &retire, T_RETIRE), "ack_addr");
    rejected("a retired key", signed_handshake(port, p, &device_key()));

    // THE 403 — outside the thirteen BY STATUS, its shape pinned: exactly
    // two members, `error` and the one public datum `record`, no `detail`.
    let member_key = distinct_key(31);
    let member = keyed_member(port, &anchor, 931, &member_key);
    issue_blocked_list(&list, BlockedHeader::default(), &[(&member, RECORD_MEMBER)]);
    let (st, _, body) = signed_handshake(port, 931, &member_key);
    assert_eq!(st, 403);
    assert_eq!(String::from_utf8(body.clone()).expect("utf-8"), prefix_blocked_body(RECORD_MEMBER));
    let shape = json(&body);
    let members: Vec<&str> = shape.as_object().expect("an object").keys().map(String::as_str).collect();
    assert_eq!(members, ["error", "record"], "one public datum beside the name: {shape}");
    // …and the 401 beside it is unmoved by a list being in force.
    rejected("a foreign key, under a list in force", signed_handshake(port, p, &distinct_key(98)));

    sd.shutdown();
}
