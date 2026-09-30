//! THE ANCHOR GATE'S HANDOFF EXCEPTION AT SLOT (6) (AUTH-3.21; RES-165, 170,
//! 171, 172, 175) — the conformance pack's §2.4 table BY TERMINUS, row by row —
//! THE SEAT CARVE's one input (AUTH-3.15; RES-195), and THE
//! CONTENT-SCOPED SESSION (AUTH-6.2–6.4, AUTH-4.39, AUTH-3.44; RES-63 item 7).
//!
//! A genesis is a record landed in its REGISTRY's doc 1 and an enroll-typed
//! deposit naming the account it seeds. Every cell below lands the record
//! from a session the publish gate admits — SIGNED for its deposit under that
//! session's key (the record grade, 2a: the daemon verifies the record's own
//! `sig` at the deposit, at the grade the act needs, so a record an ANCHOR
//! session is to commit is landed from the anchor's) — and then judges the
//! DEPOSIT, which is the credential path's and the one slot (6) reads. The
//! cells are chosen so the address test is what decides them: where a cell
//! COMMITS from a device session, the set that opens the account holds an
//! ANCHOR, so the same deposit read a handoff would have been refused.

use super::*;

const CONTENT_SESSION: &str = "credential_refused:content_session";

const SIGNED_SESSION_REQUIRED: &str = "credential_refused:signed_session_required";

/// §2.4 rows 5, 6 and 7, and AUTH-3.44's order across (6) and (7): under an
/// ANCHORED `X`, a genesis at `X.2` is `X`'s HANDOFF — refused
/// `anchor_session_required` from a device session and from a bare one (the
/// specific token masks slot (7)'s), committed from an ANCHOR session of the
/// set that opens the account; a TOP-LEVEL account's own genesis enters NO
/// cone — slot (6) is silent, so `X`'s device session commits it and `X`'s
/// BARE session meets slot (7), `signed_session_required`, still LAST on a
/// claimed board; and an ANCHORLESS giver's handoff stays device-grade.
#[test]
fn a_handoff_is_anchor_grade_wherever_the_set_that_opens_the_account_holds_an_anchor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let device = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    delegate_under(port, &bare, CLAIMANT_ACCOUNT, 951); // X.1, the held agent space
    let (x2, _) = delegate_under(port, &bare, CLAIMANT_ACCOUNT, 952);
    assert_eq!(x2, format!("{CLAIMANT_ACCOUNT}.2"));

    // ROW 5 — a by-reference descendant of S = X that is neither a hire's nor
    // a spawn's address: X's HANDOFF, and X's set holds the ceremony's anchor.
    // The record is anchor-grade, so the anchor signs it; the DEPOSIT is what
    // each hand is judged on.
    let record = land_record(port, &anchor, CLAIMANT_DOC1, &fresh_member(61), T_ENROLL, &x2);
    for (hand, token) in [("a device session", &device), ("a bare session", &bare)] {
        let v = enroll_for(port, token, CLAIMANT_DOC1, &record, &x2);
        assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "{hand}'s genesis at X.2: {v}");
    }
    assert_eq!(enrolled_count(port, &x2), 0, "a refused handoff commits nothing");
    // …and an ANCHOR session's commits: the same record, the same frame.
    expect_resp(&enroll_for(port, &anchor, CLAIMANT_DOC1, &record, &x2), "ack_addr");
    assert_eq!(enrolled_count(port, &x2), 1, "the recipient's key, latched");

    // ROW 6 — a top-level account's own genesis enters NO cone: no keyed
    // ACCOUNT stands above it, its registry being the claimant's doc 1 by the
    // bootstrap tier's rule and not by descent. Slot (6) is silent, so the
    // bare session's plant dies at slot (7) — the generic token, LAST — where
    // the same session's handoff above died at (6); and the device session,
    // no anchor of X's, commits it.
    let (member, _) = bootstrap_delegate(port, 961);
    let member_key = distinct_key(62);
    let record =
        land_record(port, &device, CLAIMANT_DOC1, &enroll_atom(&[&member_key]), T_ENROLL, &member);
    let v = enroll_for(port, &bare, CLAIMANT_DOC1, &record, &member);
    assert_eq!(verdict(&v), SIGNED_SESSION_REQUIRED, "a bare genesis in no cone meets (7): {v}");
    expect_resp(&enroll_for(port, &device, CLAIMANT_DOC1, &record, &member), "ack_addr");

    // ROW 7 — the same act under an ANCHORLESS giver stays device-grade
    // (AUTH-5.16's standing price): the member's set is its one device key.
    let giver = open_signed_session(port, 961, &member_key);
    let member_doc1 = create_doc(port, &giver, &member);
    reserve_agent_space(port, &giver, &member, 9611);
    let (handed, _) = delegate_under(port, &giver, &member, 9612);
    let record = land_record(port, &giver, &member_doc1, &fresh_member(63), T_ENROLL, &handed);
    expect_resp(&enroll_for(port, &giver, &member_doc1, &record, &handed), "ack_addr");
    assert_eq!(enrolled_count(port, &handed), 1);

    sd.shutdown();
}

/// §2.4 rows 1, 2 and 5 down one chain, each measured at the walk's TERMINUS
/// (RES-172). `Y = X.2` is handed to a recipient whose set holds an ANCHOR and
/// who works from a DEVICE session throughout:
///
/// * `inc(Y, 1)` ITSELF — the agents' home — is a HANDOFF (`Y` is not
///   bootstrap-tier, so the fold honors the genesis and slot (6) is reached):
///   `anchor_session_required`;
/// * a child of `inc(Y, 1)` is a HIRE — device-grade, COMMITS;
/// * a genesis beneath that AGENT — which stands at `inc(inc(Y, 1), 1)`
///   beneath its own nearest keyed ancestor `Y`, and holds an anchor of its
///   own — is a SPAWN: device-grade, COMMITS, its first sub-account included;
/// * and the terminus is read ALONE: the WORKER that spawn keyed stands at no
///   agent's position, so a genesis beneath it is the worker's own HANDOFF,
///   graded at the worker's set — an agent further up the chain is not read.
#[test]
fn a_hire_and_a_spawn_are_device_grade_and_the_agents_home_itself_is_a_handoff() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    delegate_under(port, &bare, CLAIMANT_ACCOUNT, 951);
    let (y, _) = delegate_under(port, &bare, CLAIMANT_ACCOUNT, 952);
    // The handoff of Y, from X's anchor session: the recipient's paper and
    // device keys.
    let x_anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let (r_paper, r_device) = (distinct_key(61), distinct_key(62));
    let record = land_record(
        port,
        &x_anchor,
        CLAIMANT_DOC1,
        &enroll_atom_flagged(&[(&r_paper, true), (&r_device, false)]),
        T_ENROLL,
        &y,
    );
    expect_resp(&enroll_for(port, &x_anchor, CLAIMANT_DOC1, &record, &y), "ack_addr");
    let r = open_signed_session(port, 952, &r_device);
    let r_anchor = open_signed_session(port, 952, &r_paper);
    let y_doc1 = create_doc(port, &r, &y);

    // ROW 5 — the agents' home itself. Its record is anchor-grade — the
    // recipient's PAPER signs it, and commits it at the end — and the
    // device session's deposit of it is what this row judges.
    let (home, _) = delegate_under(port, &r, &y, 9521);
    assert_eq!(home, format!("{y}.1"));
    let home_record = land_record(port, &r_anchor, &y_doc1, &fresh_member(63), T_ENROLL, &home);
    let v = enroll_for(port, &r, &y_doc1, &home_record, &home);
    assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "the agents' home is a handoff: {v}");

    // ROW 1 — THE HIRE. The home holds no set, so a session AS it opens by
    // reference against Y's (AUTH-4.30 (i)) — under the recipient's DEVICE
    // key, no anchor of Y's — and the hire's registry is the home's doc 1.
    let as_home = open_signed_session(port, 9521, &r_device);
    let home_doc1 = create_doc(port, &as_home, &home);
    let agent = next_prefix_under(port, Some(&as_home), &home);
    assert_eq!(agent, format!("{home}.1"));
    // THE LAYOUT'S FIFTH VECTOR, its second half (RES-64 item 8; (c) row 1):
    // the hire's `delegate` from the HOLDER's own session AS `Y` is
    // `not_authorized` and commits nothing. R's keys OPEN `Y.1` by reference,
    // but the principal bound to a session as `Y` does not OWN it — the
    // agents' home is its own seat — so M3's ownership guard answers. The SAME
    // frame from the session as `Y.1` acks.
    let hire_delegate = format!(r#"{{"op":"delegate","new_prefix":"{agent}","new_id":95211}}"#);
    let before = head_position(port);
    let v = op(port, Some(&r), &hire_delegate);
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["op"].as_str(), Some("delegate"), "{v}");
    assert_eq!(rej["code"].as_str(), Some("not_authorized"), "the holder's session as Y: {v}");
    assert_eq!(head_position(port), before, "the refused delegate committed nothing");
    assert_eq!(next_prefix_under(port, None, &home), agent, "and seated nobody");
    assert_eq!(acked_addr(&op(port, Some(&as_home), &hire_delegate)), agent);
    let (g_paper, g_device) = (distinct_key(64), distinct_key(65));
    let record = land_record(
        port,
        &as_home,
        &home_doc1,
        &enroll_atom_flagged(&[(&g_paper, true), (&g_device, false)]),
        T_ENROLL,
        &agent,
    );
    expect_resp(&enroll_for(port, &as_home, &home_doc1, &record, &agent), "ack_addr");

    // ROW 2 — THE SPAWN, beneath the agent, from the agent's DEVICE session:
    // its first sub-account, which beneath any account that is no agent is
    // that account's agents' home and a handoff.
    let g = open_signed_session(port, 95_211, &g_device);
    let agent_doc1 = create_doc(port, &g, &agent);
    let (worker, _) = delegate_under(port, &g, &agent, 952_111);
    assert_eq!(worker, format!("{agent}.1"));
    let (w_paper, w_device) = (distinct_key(66), distinct_key(67));
    let record = land_record(
        port,
        &g,
        &agent_doc1,
        &enroll_atom_flagged(&[(&w_paper, true), (&w_device, false)]),
        T_ENROLL,
        &worker,
    );
    expect_resp(&enroll_for(port, &g, &agent_doc1, &record, &worker), "ack_addr");

    // THE TERMINUS, ALONE. The worker is keyed and stands at `inc(agent, 1)`
    // beneath its own nearest keyed ancestor, the agent — no agent's
    // position — so what lies beneath it is measured at the WORKER: its own
    // handoff, anchor-grade, its set holding an anchor — the worker's PAPER
    // signs the record, and its device session's deposit is judged.
    let w = open_signed_session(port, 952_111, &w_device);
    let w_anchor = open_signed_session(port, 952_111, &w_paper);
    let worker_doc1 = create_doc(port, &w, &worker);
    let (below, _) = delegate_under(port, &w, &worker, 9_521_111);
    let record = land_record(port, &w_anchor, &worker_doc1, &fresh_member(68), T_ENROLL, &below);
    let v = enroll_for(port, &w, &worker_doc1, &record, &below);
    assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "measured at the worker alone: {v}");
    expect_resp(&enroll_for(port, &w_anchor, &worker_doc1, &record, &below), "ack_addr");

    // …and the recipient's PAPER hands the agents' home away, as a device
    // session could not.
    expect_resp(&enroll_for(port, &r_anchor, &y_doc1, &home_record, &home), "ack_addr");

    sd.shutdown();
}

/// §2.4 rows 3 and 4 — THE SEAT CARVE, and AUTH-3.15's ONE INPUT: the
/// list header's SECOND field, compared with the claimant. Where it names an
/// account that is NOT the claimant — the SEAT of a forked lineage — a
/// genesis into that account's DIRECT CHILD is an ADMISSION, device-grade;
/// `inc(seat, 1)` itself, the seat's own first sub-account, stays a HANDOFF; and
/// with no header, or one naming the claimant, the carve is SILENT. The field
/// is config, read per request: re-issue it and the carve moves with it.
#[test]
fn the_seat_carve_admits_into_the_seats_direct_child_and_is_silent_without_the_header() {
    let root = tempfile::tempdir().expect("tempdir");
    let (sd, list) = spawn_listed(root.path());
    let port = sd.port();
    let device = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    // T — a top-level account whose set holds an ANCHOR, working from a
    // DEVICE session throughout.
    let (t, _) = bootstrap_delegate(port, 941);
    let (t_paper, t_device) = (distinct_key(41), distinct_key(42));
    let record = land_record(
        port,
        &device,
        CLAIMANT_DOC1,
        &enroll_atom_flagged(&[(&t_paper, true), (&t_device, false)]),
        T_ENROLL,
        &t,
    );
    expect_resp(&enroll_for(port, &device, CLAIMANT_DOC1, &record, &t), "ack_addr");
    let seat = open_signed_session(port, 941, &t_device);
    let t_anchor = open_signed_session(port, 941, &t_paper);
    let t_doc1 = create_doc(port, &seat, &t);
    let (t1, _) = delegate_under(port, &seat, &t, 9411);
    let (t2, _) = delegate_under(port, &seat, &t, 9412);
    let (t3, _) = delegate_under(port, &seat, &t, 9413);
    // The header's SECOND field alone: the carve reads it as issued, whatever
    // the first says of the operator.
    fn header(binding_writer: Option<&str>) -> BlockedHeader<'_> {
        BlockedHeader { operator: None, binding_writer }
    }

    // SILENT: no header, and a header whose second field names the CLAIMANT
    // — on an unforked lineage the two are one account. T.2 is T's handoff.
    let t2_record = land_record(port, &seat, &t_doc1, &fresh_member(43), T_ENROLL, &t2);
    for silent in [header(None), header(Some(CLAIMANT_ACCOUNT))] {
        issue_blocked_list(&list, silent, &[]);
        let v = enroll_for(port, &seat, &t_doc1, &t2_record, &t2);
        assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "the carve is silent: {v}");
    }
    // ROW 3 — THE CARVE: the field names T, which is not the claimant, and
    // the same deposit is an ADMISSION.
    issue_blocked_list(&list, header(Some(&t)), &[]);
    expect_resp(&enroll_for(port, &seat, &t_doc1, &t2_record, &t2), "ack_addr");
    // The seat's own first sub-account is no admission. At a TOP-LEVEL seat the
    // fold refuses it first: `inc(B, 1)` of a bootstrap-tier account takes no
    // genesis (AUTH-2.62), slot (3) ahead of slot (6).
    let t1_record = land_record(port, &seat, &t_doc1, &fresh_member(44), T_ENROLL, &t1);
    let v = enroll_for(port, &seat, &t_doc1, &t1_record, &t1);
    assert_eq!(verdict(&v), "credential_refused:not_genesis_registry", "{v}");

    // ROW 4 — so the cell slot (6) ITSELF answers is a seat that is not
    // bootstrap-tier: T.3, admitted into under the carve with an anchored set
    // of its own, then named the seat in its turn.
    let (q_paper, q_device) = (distinct_key(45), distinct_key(46));
    let record = land_record(
        port,
        &seat,
        &t_doc1,
        &enroll_atom_flagged(&[(&q_paper, true), (&q_device, false)]),
        T_ENROLL,
        &t3,
    );
    expect_resp(&enroll_for(port, &seat, &t_doc1, &record, &t3), "ack_addr");
    let q = open_signed_session(port, 9413, &q_device);
    let q_doc1 = create_doc(port, &q, &t3);
    let (q1, _) = delegate_under(port, &q, &t3, 94_131);
    let (q2, _) = delegate_under(port, &q, &t3, 94_132);
    let q1_record = land_record(port, &q, &q_doc1, &fresh_member(47), T_ENROLL, &q1);
    let q2_record = land_record(port, &q, &q_doc1, &fresh_member(48), T_ENROLL, &q2);
    // While T is the seat the carve reaches T's DIRECT children and no
    // deeper: T.3's own child is T.3's handoff.
    let v = enroll_for(port, &q, &q_doc1, &q2_record, &q2);
    assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "beneath the seat's child: {v}");
    issue_blocked_list(&list, header(Some(&t3)), &[]);
    let v = enroll_for(port, &q, &q_doc1, &q1_record, &q1);
    assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "inc(seat, 1) stays a handoff: {v}");
    expect_resp(&enroll_for(port, &q, &q_doc1, &q2_record, &q2), "ack_addr");
    // …and T, the seat no longer, is a giver again: its device session is
    // refused where its paper commits — the record its paper signed.
    let (t4, _) = delegate_under(port, &seat, &t, 9414);
    let t4_record = land_record(port, &t_anchor, &t_doc1, &fresh_member(49), T_ENROLL, &t4);
    let v = enroll_for(port, &seat, &t_doc1, &t4_record, &t4);
    assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "the carve moved with the header: {v}");
    expect_resp(&enroll_for(port, &t_anchor, &t_doc1, &t4_record, &t4), "ack_addr");

    sd.shutdown();
}

/// THE SEIZED CLASS (RES-155; AUTH-5.89) — the walk ENDS AT SLOT (6). A thief
/// holding one DEVICE key of `X`'s set writes, from a session as `X`, one
/// genesis for the person's own content-bearing topic `X.2`, homed in `X`'s
/// doc 1 and naming fresh keys of its own: ω passes, the fold previews it
/// `Honored(Genesis)`, the latch finds the keys disjoint — and the anchor
/// gate refuses it, `X`'s set holding an anchor. Nor does a device key the
/// thief ENROLS for itself climb past it (AUTH-3.65's thief-enrolled row).
/// Nothing is taken: `X.2` holds no set, the person's by-reference session
/// there lives and still reads its draft, and the thief's key opens nothing.
#[test]
fn a_stolen_device_key_cannot_seize_a_subdivision_the_walk_ends_at_slot_6() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let accounts = by_reference_accounts(port);
    let topic = &accounts.x2_account;
    // The person's topic: its home, and a draft filed from a session AS it.
    let person = open_signed_session(port, accounts.x2, &device_key());
    create_doc(port, &person, topic);
    let draft = create_doc(port, &person, topic);
    expect_resp(&insert_text(port, &person, &draft, 1, "mine"), "ack_addr");

    let thief = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let thief_key = distinct_key(91);
    let record =
        land_record(port, &thief, CLAIMANT_DOC1, &enroll_atom(&[&thief_key]), T_ENROLL, topic);
    let v = enroll_for(port, &thief, CLAIMANT_DOC1, &record, topic);
    assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "the seizure: {v}");
    // The climb: a device-flagged enrollment at X is device-grade and
    // commits, and the session that key opens is no anchor's either.
    let climber = distinct_key(92);
    let own = land_record(
        port,
        &thief,
        CLAIMANT_DOC1,
        &enroll_atom(&[&climber]),
        T_ENROLL,
        CLAIMANT_ACCOUNT,
    );
    expect_resp(&deposit(port, &thief, &own, T_ENROLL), "ack_addr");
    let climbed = open_signed_session(port, CLAIMANT_PRINCIPAL, &climber);
    let v = enroll_for(port, &climbed, CLAIMANT_DOC1, &record, topic);
    assert_eq!(verdict(&v), ANCHOR_SESSION_REQUIRED, "the thief-enrolled key: {v}");

    assert_eq!(enrolled_count(port, topic), 0, "the topic holds no set: nothing was seeded");
    assert!(!presented_dead(port, &person), "the person's session as the topic lives");
    assert_eq!(text_of(port, Some(&person), &draft, 1, 4), "mine", "and reads its draft");
    let (st, _, _) = signed_handshake(port, accounts.x2, &thief_key);
    assert_eq!(st, 401, "the thief's key opens nothing");

    sd.shutdown();
}

/// RES-63 item 7, the HANDSHAKE's cells (AUTH-6.2–6.4): a SCOPED body opens
/// (200, the base's two members — the scope is not echoed); a wrong `scope`
/// value or type is `400 malformed_session_request` AHEAD of the burn, so the
/// nonce SURVIVES and the same nonce then opens; `scope` on the BARE body is
/// the 400; a v1 signature over a scoped body is the one 401 — and a v2
/// signature over an UNSCOPED body likewise: each layout verifies under its
/// own tag only. `/health.auth` gains no field.
#[test]
fn a_scoped_body_opens_under_the_v2_bytes_and_a_scope_fault_spends_no_nonce() {
    const REJECTED: &str = r#"{"error":"session_rejected"}"#;
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let p = CLAIMANT_PRINCIPAL;
    let origin = format!("http://127.0.0.1:{port}");
    let post = |body: &str| http_full(port, "POST", "/session", None, body.as_bytes());
    let malformed = |what: &str, (st, _, body): (u16, Vec<(String, String)>, Vec<u8>)| {
        assert_eq!(st, 400, "{what}: {}", String::from_utf8_lossy(&body));
        assert_eq!(json(&body)["error"].as_str(), Some("malformed_session_request"), "{what}");
    };
    let rejected = |what: &str, (st, _, body): (u16, Vec<(String, String)>, Vec<u8>)| {
        assert_eq!(st, 401, "{what}");
        assert_eq!(String::from_utf8(body).expect("utf-8"), REJECTED, "{what}: the one code");
    };

    // A WRONG SCOPE — every other value, type and case — signed exactly as
    // it says (so nothing but the field is at fault): the 400, and the nonce
    // survives every one of them…
    let nonce = challenge(port, p);
    for bad in [r#""full""#, r#""Content""#, r#""""#, "null", "true", "1", r#"["content"]"#] {
        let said = bad.trim_matches('"');
        let sig = sign_session_scoped(&device_key(), &origin, &nonce, p, said);
        let body = format!(
            "{{\"principal\":{p},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"scope\":{bad},\"sig\":\"{sig}\"}}"
        );
        malformed(&format!("scope {bad}"), post(&body));
    }
    // …and `scope` on the BARE body, the one admitted value included.
    malformed("scope on the bare body", post(&format!("{{\"principal\":{p},\"scope\":\"content\"}}")));
    // …so THE SAME NONCE then opens: the scoped body, signed under v2.
    let sig = sign_session_scoped(&device_key(), &origin, &nonce, p, "content");
    let (st, _, body) = post(&scoped_session_body(p, &nonce, &origin, &sig));
    assert_eq!(st, 200, "a scoped body opens: {}", String::from_utf8_lossy(&body));
    let opened = json(&body);
    let members: Vec<&str> =
        opened.as_object().expect("an object").keys().map(String::as_str).collect();
    assert_eq!(members, ["principal", "session"], "the base's answer, no scope echoed: {opened}");
    // The opening spent it, as any opening does.
    rejected("a spent nonce", post(&scoped_session_body(p, &nonce, &origin, &sig)));

    // A v1 SIGNATURE OVER A SCOPED BODY is the one 401 — a failure of the
    // credential, so its nonce is spent: the right signature cannot follow.
    let nonce = challenge(port, p);
    let v1 = sign_session(&device_key(), &origin, &nonce, p);
    rejected("a v1 signature over a scoped body", post(&scoped_session_body(p, &nonce, &origin, &v1)));
    let v2 = sign_session_scoped(&device_key(), &origin, &nonce, p, "content");
    rejected("and its nonce is spent", post(&scoped_session_body(p, &nonce, &origin, &v2)));
    // …and a v2 signature never opens an UNSCOPED body.
    let nonce = challenge(port, p);
    let v2 = sign_session_scoped(&device_key(), &origin, &nonce, p, "content");
    let unscoped = format!(
        "{{\"principal\":{p},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"sig\":\"{v2}\"}}"
    );
    rejected("a v2 signature over an unscoped body", post(&unscoped));

    // `/health.auth` says nothing of a scope, a content session being open.
    let health = json(&get(port, "/health").1);
    let auth: Vec<&str> =
        health["auth"].as_object().expect("auth").keys().map(String::as_str).collect();
    assert_eq!(auth, ["claimant", "local_trust", "origins", "signed_origins"], "{health}");

    sd.shutdown();
}

/// RES-63 item 7, the WRITE PATH's cells (AUTH-4.39, AUTH-3.44 slot (6)): a
/// content session's enrol and retirement answer `content_session`; so does
/// an ANCHOR key's content session's anchor act — ahead of the anchor gate,
/// the key not consulted; its content insert, publish and grant LAND, read
/// and testified as a full session's are; and `/session/close` is the 204.
/// THE ORDER, pinned on one anchor-flagged record: `content_session`, then
/// `anchor_session_required` — and slots (3)–(5) still AHEAD of both, a
/// content session's retry of a committed act answering the head's preview
/// token. A refusal is request-refused on a LIVE entry: no death signal.
#[test]
fn a_content_session_writes_content_and_deposits_no_credential() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let p = CLAIMANT_PRINCIPAL;
    let content = open_content_session(port, p, &device_key());
    let paper_content = open_content_session(port, p, &anchor_key());
    let device = open_signed_session(port, p, &device_key());
    let device_fp = fingerprint_hex(&device_key());

    // CONTENT LANDS. A declared deposit into the published home — the write
    // a bare session is refused — testified under the key that opened the
    // session, the scope being nowhere in the record.
    let ordinal = next_content_ordinal(port, Some(&content), CLAIMANT_DOC1);
    let v = op(port, Some(&content), &insert_frame(CLAIMANT_DOC1, ordinal, "z", true));
    let at = acked_at(&v);
    let page = json(&http(port, "GET", &format!("/changes?since={}", at - 1), Some(&content), b"").1);
    let entry = page["changes"]
        .as_array()
        .expect("changes")
        .iter()
        .find(|e| e["at"].as_u64() == Some(at))
        .unwrap_or_else(|| panic!("the insert's own entry: {page}"))
        .clone();
    assert_eq!(entry["key"].as_str(), Some(device_fp.as_str()), "the opening key testifies");
    assert!(entry.get("scope").is_none(), "the scope is in no record: {entry}");
    // A private draft, its bytes, and the session's own draft visibility.
    let draft = create_doc(port, &content, CLAIMANT_ACCOUNT);
    expect_resp(&insert_text(port, &content, &draft, 1, "abcde"), "ack_addr");
    assert_eq!(text_of(port, Some(&content), &draft, 1, 5), "abcde");
    assert_withheld(&op(port, None, &read1_frame(&draft)), &draft);
    // A GRANT — a non-credential `make_link` into the published home.
    let (stranger, _) = bootstrap_delegate(port, 961);
    deposit_grant(port, &content, CLAIMANT_DOC1, &draft, Some(&stranger));
    // THE SHOT — a published edition minted and published into.
    let edition = published_edition(port, &content);
    shot(port, &content, &edition, None, None, &[run(&draft, &format!("{draft}.0.1.1"), 2)]);

    // A DEVICE ENROL and a RETIREMENT — each previewed Honored, each
    // device-grade, each committed below by a FULL device session.
    let enrol = land_record(port, &content, CLAIMANT_DOC1, &fresh_member(71), T_ENROLL, CLAIMANT_ACCOUNT);
    let retire = land_record(
        port,
        &content,
        CLAIMANT_DOC1,
        &retire_atom(&[&fingerprint_hex(&distinct_key(71))]),
        T_RETIRE,
        CLAIMANT_ACCOUNT,
    );
    // AN ANCHOR ACT — an anchor-flagged enrollment.
    let anchor_act = land_record(
        port,
        &content,
        CLAIMANT_DOC1,
        &enroll_atom_flagged(&[(&distinct_key(72), true)]),
        T_ENROLL,
        CLAIMANT_ACCOUNT,
    );

    for (whose, token) in [("a device key's", &content), ("an anchor key's", &paper_content)] {
        for (act, record, ty) in [
            ("enrol", &enrol, T_ENROLL),
            ("anchor enrol", &anchor_act, T_ENROLL),
        ] {
            let (st, headers, body) = http_full(
                port,
                "POST",
                "/op",
                Some(token),
                deposit_frame(None, record, ty).as_bytes(),
            );
            assert_eq!(st, 200);
            assert_eq!(verdict(&json(&body)), CONTENT_SESSION, "{whose} content session's {act}");
            assert!(
                header(&headers, "Skepd-Session").is_none(),
                "{whose} content session's {act}: refused for this request, nothing died"
            );
        }
    }
    assert_eq!(enrolled_count(port, CLAIMANT_ACCOUNT), 2, "the ceremony's two keys, unmoved");

    // THE ORDER at slot (6), on the anchor act: the scope's token first,
    // then the anchor gate's — a FULL device session meets the second.
    assert_eq!(verdict(&deposit(port, &device, &anchor_act, T_ENROLL)), ANCHOR_SESSION_REQUIRED);
    // The full session commits the device enrol; the retirement of that key
    // is then a live act, which the content session is refused and the full
    // session commits.
    expect_resp(&deposit(port, &device, &enrol, T_ENROLL), "ack_addr");
    assert_eq!(verdict(&deposit(port, &content, &retire, T_RETIRE)), CONTENT_SESSION);
    // Slots (3)–(5) stand AHEAD: the content session's retry of the act the
    // full session committed answers the head's preview token.
    assert_eq!(
        verdict(&deposit(port, &content, &enrol, T_ENROLL)),
        "credential_refused:nothing_changed",
        "the preview token masks the scope's"
    );
    expect_resp(&deposit(port, &device, &retire, T_RETIRE), "ack_addr");

    // The content sessions outlived every refusal, and CLOSE as any session
    // does: the bare 204, the token then dead.
    for token in [&content, &paper_content] {
        assert!(!presented_dead(port, token), "a refusal is not a death");
        let (st, headers, body) = http_full(port, "POST", "/session/close", Some(token), b"");
        assert_eq!((st, body.len()), (204, 0), "close on a content session");
        assert!(header(&headers, "Skepd-Session").is_none(), "a live close carries no signal");
        assert!(presented_dead(port, token), "and the token is closed");
    }

    sd.shutdown();
}

/// RES-63 item 7's CLAIM cell. The claim link is credential-typed, so the
/// ceremony's step 5 runs on a FULL session: a content session's claim — on
/// an UNCLAIMED board, where the fold previews it Honored — answers
/// `content_session`, the board stays unclaimed, and the full session's
/// claim then lands.
#[test]
fn a_content_sessions_claim_is_refused_and_the_board_stays_unclaimed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    let key = distinct_key(11);
    let partial = seed_partial(port, CLAIMANT_PRINCIPAL, &[(&key, false)]);

    let content = open_content_session(port, CLAIMANT_PRINCIPAL, &key);
    let v = claim_deposit(port, &content, &partial.doc1, &partial.account);
    assert_eq!(verdict(&v), CONTENT_SESSION, "a content session's claim: {v}");
    assert!(!claimed(port), "a refused claim commits nothing");

    let full = open_signed_session(port, CLAIMANT_PRINCIPAL, &key);
    expect_resp(&claim_deposit(port, &full, &partial.doc1, &partial.account), "ack_addr");
    assert!(claimed(port));
    // Once claimed the fold's own verdict stands AHEAD of the scope's.
    let v = claim_deposit(port, &content, &partial.doc1, &partial.account);
    assert_eq!(verdict(&v), "credential_refused:already_claimed", "slot (3) before (6): {v}");

    sd.shutdown();
}
