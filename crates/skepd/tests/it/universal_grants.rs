//! THE ANY-PRINCIPAL DISCOVERY READ at the wire — `universal_grants`
//! (PUB-8.47; RES-224, RES-231, RES-264, RES-273, RES-298): the grant fold's
//! LIVE universal set, handed to a bound principal as one read — one row per
//! COVERED content prefix with the issuers who granted it to every principal,
//! in prefix order — and EMPTY for the guest, cell by cell:
//!
//! * an empty board answers zero rows; one universal grant (an empty `to`,
//!   `from` a document the issuer owns) answers one row `(prefix, [issuer])`;
//!   two prefixes answer two rows in PREFIX order, whatever the deposit order;
//!   a repeated grant is one index entry and one row;
//! * the GUEST is answered EMPTY on a board with universal grants — an
//!   answer, never a refusal — and a bare principal, a signed one and a
//!   stranger are answered the same rows, byte-identically;
//! * RES-231's cell: a keyed principal's grant whose `from` names a
//!   STRANGER's document is ADMITTED — it stands in the fold, `/dump`'s
//!   `grants` section lists it — and is NO row: the two are disjoint;
//! * RES-264's cell: an agent `X.1`'s grant with `from` = `X`, its hirer's
//!   prefix, WIDER than its own account, is served at `X.1` — the agent's
//!   own account — and grouped there with the agent's every other share
//!   served at `X.1`;
//! * RES-298's cell, THE COMPARE IS ω's: the hirer's share over its
//!   REGISTERED sub-account `X.1` is ADMITTED — it stands in the fold — and
//!   is NO row: `X` ω-owns nothing beneath `X.1`, a granter and not the
//!   owner, so every served row carries exactly ONE issuer, the registry's
//!   `effective_owner` of its prefix;
//! * RES-298's named residue, pinned and not repaired: a share over an
//!   UNALLOCATED sub-prefix `X.2` is served `(X.2, [X])` — ω answers `X`
//!   there — until `X.2` is delegated, and is gone at the next read after;
//! * a withdrawn grant's row is gone at the next read; on `/op-at`, as of a
//!   position before the withdrawal, it is present, `as_of` the position
//!   asked — and the guest is empty at every position.
//!
//! Nothing here decides what is SERVED: the daemon applies the same live set
//! itself at serve (`read_surface.rs` pins that half). This read decides what
//! a client may DISPLAY, and hands it the set the fold answers from.

use crate::common;

use common::*;

/// A grant-typed record in `home_doc1` from the issuer's SIGNED session,
/// `from` the given address and `to` EMPTY (the ANY-PRINCIPAL form), with
/// the position it committed at. A `from` naming an earlier grant's own
/// address is that grant's REVOCATION (PUB-5.13, PUB-5.15).
fn grant_at(port: u16, signed: &str, home_doc1: &str, from: &str) -> (String, u64) {
    let v = op(
        port,
        Some(signed),
        &format!(
            r#"{{"op":"make_link","home":"{home_doc1}","from":{{"addrs":["{from}"]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{T_GRANT}"]}}}}"#
        ),
    );
    (acked_addr(&v), acked_at(&v))
}

/// Tumbler order over dotted-decimal addresses — the order the rows come in.
fn tumbler_key(addr: &str) -> Vec<u64> {
    addr.split('.').map(|c| c.parse().expect("a component")).collect()
}

/// One expected row, `(prefix, issuers)`.
fn r(prefix: &str, issuers: &[&str]) -> (String, Vec<String>) {
    (prefix.to_string(), issuers.iter().map(|i| i.to_string()).collect())
}

/// `rows`, sorted into prefix order with each issuer list in address order —
/// what the read is expected to serve for that set of `(prefix, issuers)`.
fn in_prefix_order(mut rows: Vec<(String, Vec<String>)>) -> Vec<(String, Vec<String>)> {
    for (_, issuers) in &mut rows {
        issuers.sort_by_key(|i| tumbler_key(i));
    }
    rows.sort_by_key(|(p, _)| tumbler_key(p));
    rows
}

/// The dump's `grants` section entry for `grant` — the fold's operative set
/// rendered — asserting it stands ADMITTED with the given `content_prefix`
/// and `issuer` (and no grantee: the ANY-PRINCIPAL form).
fn assert_admitted(port: u16, grant: &str, content_prefix: &str, issuer: &str) {
    let dump = dump_text(port, None, None);
    let key = format!("\"{grant}\": ");
    let at = dump.find(&key).unwrap_or_else(|| panic!("{grant} is no record of the fold's operative set"));
    let entry = &dump[at..];
    let end = entry.find('}').expect("the entry closes");
    let entry = &entry[..end];
    assert!(entry.contains(&format!("\"content_prefix\": \"{content_prefix}\"")), "{grant}: {entry}");
    assert!(entry.contains(&format!("\"issuer\": \"{issuer}\"")), "{grant}: {entry}");
    assert!(entry.contains("\"grantee\": none"), "the ANY-PRINCIPAL form: {entry}");
}

/// The SHAPE (RES-224): the live universal set, one row per content prefix
/// with the issuers who granted it, in PREFIX order — never deposit order —
/// and `as_of` the snapshot's. An empty board answers zero rows; one grant
/// answers one row; a repeated grant is one index entry, so one row and one
/// issuer; an ACCOUNT-rung share over the issuer's own account is a row at the
/// account, ahead of its documents.
#[test]
fn the_read_serves_the_live_set_one_row_per_prefix_in_prefix_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let x = CLAIMANT_ACCOUNT;
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);

    // An empty board: the shape, and nothing in it.
    let v = op(port, Some(&bare), &universal_grants_frame());
    assert!(grant_rows(&v).is_empty(), "no universal grant stands: {v}");
    assert_eq!(v["as_of"].as_u64(), Some(head_position(port)), "{v}");

    // Two private drafts of X's; the LATER one granted FIRST.
    let d1 = owner_draft(port, &bare);
    let d2 = owner_draft(port, &bare);
    assert!(tumbler_key(&d1) < tumbler_key(&d2), "{d1} sorts before {d2}");
    deposit_grant(port, &signed, CLAIMANT_DOC1, &d2, None);
    assert_eq!(universal_grants(port, Some(&bare)), vec![r(&d2, &[x])]);
    deposit_grant(port, &signed, CLAIMANT_DOC1, &d1, None);
    assert_eq!(
        universal_grants(port, Some(&bare)),
        in_prefix_order(vec![r(&d2, &[x]), r(&d1, &[x])]),
        "prefix order, not deposit order"
    );
    // A repeated grant over d1: the index is a set, so one row and one issuer.
    deposit_grant(port, &signed, CLAIMANT_DOC1, &d1, None);
    assert_eq!(universal_grants(port, Some(&bare)), in_prefix_order(vec![r(&d1, &[x]), r(&d2, &[x])]));
    // The account rung: X's share over its own account, inside its own space
    // — served unchanged, a row of its own ahead of the documents under it.
    deposit_grant(port, &signed, CLAIMANT_DOC1, x, None);
    let rows = universal_grants(port, Some(&bare));
    assert_eq!(rows, in_prefix_order(vec![r(x, &[x]), r(&d1, &[x]), r(&d2, &[x])]));
    assert_eq!(rows[0].0, x, "the account's row leads: {rows:?}");

    // The answer reports the snapshot it came from, as every read does.
    let v = op(port, Some(&bare), &universal_grants_frame());
    assert_eq!(v["as_of"].as_u64(), Some(head_position(port)), "{v}");

    sd.shutdown();
}

/// THE GUEST IS OUTSIDE (PUB-5.109): on a board with universal grants
/// standing, a request with no token — or a dead one — is answered EMPTY
/// under the read's own tag, never refused. Every BOUND principal — the
/// issuer's bare session, its signed session, a stranger — is answered the
/// same rows, byte-identically: the set is a board population, not the
/// requester's. On `/op-at` at the head, the same.
#[test]
fn the_guest_is_answered_empty_and_every_bound_principal_the_same_rows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let stranger = seat_stranger(port, 995);
    let draft = owner_draft(port, &bare);
    deposit_grant(port, &signed, CLAIMANT_DOC1, &draft, None);
    let expect = vec![r(&draft, &[CLAIMANT_ACCOUNT])];
    let never_issued = "0".repeat(64);
    let frame = universal_grants_frame();

    // The guest, and a token the daemon never issued (a guest by class).
    for token in [None, Some(never_issued.as_str())] {
        let v = op(port, token, &frame);
        assert!(grant_rows(&v).is_empty(), "the guest is handed nothing: {v}");
        assert_eq!(v["as_of"].as_u64(), Some(head_position(port)), "an answer, stamped: {v}");
    }
    // Every bound principal: the rows, and the bytes.
    let bound = [bare.as_str(), signed.as_str(), stranger.session.as_str()];
    let live: Vec<Vec<u8>> =
        bound.iter().map(|t| http(port, "POST", "/op", Some(*t), frame.as_bytes()).1).collect();
    assert_eq!(grant_rows(&json(&live[0])), expect, "the issuer's bare session");
    assert!(live.iter().all(|b| *b == live[0]), "every bound principal is answered alike on /op");
    assert_eq!(universal_grants(port, Some(&stranger.session)), expect, "a stranger, too");

    // `/op-at` at the head: the bound alike, and equal to `/op`'s own answer;
    // the guest empty there too.
    let at = head_position(port);
    let envelope = format!(r#"{{"at":{at},"frame":{frame}}}"#);
    let historical: Vec<Vec<u8>> = bound
        .iter()
        .map(|t| {
            let (st, body) = http(port, "POST", "/op-at", Some(*t), envelope.as_bytes());
            assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
            body
        })
        .collect();
    assert!(historical.iter().all(|b| *b == historical[0]), "alike on /op-at");
    assert_eq!(historical[0], live[0], "/op-at at the head is /op's own answer");
    assert!(grant_rows(&op_at_ok(port, None, at, &frame)).is_empty(), "the guest, on /op-at");

    sd.shutdown();
}

/// RES-231's cell — THE READ IS FOLD-FILTERED, NEVER RAW. A keyed stranger B
/// writes ONE grant-typed link into its OWN doc 1 whose `from` names X's
/// private draft and whose `to` is empty. The record is ADMITTED — B's home,
/// B's ω, born published; a GRANT by PUB-5.15's test — and it enters the
/// fold's universal index: `/dump`'s `grants` section lists it. Served RAW it
/// would be a row telling every principal "B made X's draft readable to the
/// board"; served COVERED, B's account and X's draft are DISJOINT and the row
/// is DROPPED — to X, to B, to anyone — while B's share over B's OWN draft,
/// and X's over X's, are rows.
#[test]
fn a_strangers_record_over_a_strangers_document_stands_admitted_and_is_no_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let x = CLAIMANT_ACCOUNT;
    let x_signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let x_bare = open_session(port, CLAIMANT_PRINCIPAL);
    let x_draft = owner_draft(port, &x_bare);
    // B, a stranger under the node, KEYED — hired by the claimant into the
    // claimant's doc 1, the genesis registry of a node-parented account —
    // so B's signed session can deposit into B's own published doc 1.
    let b = seat_stranger(port, 995);
    let b_key = distinct_key(95);
    let b_signed = hire(port, &x_signed, CLAIMANT_DOC1, &b.account, 995, &b_key);
    assert!(!x_draft.starts_with(&format!("{}.", b.account)), "{x_draft} is not under {}", b.account);

    // B's record over X's document: admitted, in the fold, and NO row.
    let stray = deposit_grant(port, &b_signed, &b.doc1, &x_draft, None);
    assert_admitted(port, &stray, &x_draft, &b.account);
    for token in [&x_bare, &b.session, &x_signed] {
        assert!(
            universal_grants(port, Some(token)).is_empty(),
            "a stranger's document named by a stranger's record is no row"
        );
    }
    // The controls: B over B's own draft is a row; X over X's own draft is a
    // row; and the stray record still contributes nothing beside them.
    let b_draft = create_doc(port, &b.session, &b.account);
    let own = deposit_grant(port, &b_signed, &b.doc1, &b_draft, None);
    assert_admitted(port, &own, &b_draft, &b.account);
    assert_eq!(universal_grants(port, Some(&x_bare)), vec![r(&b_draft, &[b.account.as_str()])]);
    deposit_grant(port, &x_signed, CLAIMANT_DOC1, &x_draft, None);
    assert_eq!(
        universal_grants(port, Some(&b.session)),
        in_prefix_order(vec![r(&x_draft, &[x]), r(&b_draft, &[b.account.as_str()])]),
        "X's draft is granted by X alone; B's record over it names no row"
    );
    assert_admitted(port, &stray, &x_draft, &b.account);

    sd.shutdown();
}

/// RES-264's cell — THE SERVED ROW CARRIES THE COVERED PREFIX. An agent
/// `X.1`, seated in X's agent space and speaking through a session opened by
/// reference with the holder's device key (AUTH-4.30 (i)), privashes its work
/// with `from` = `X` — its hirer's prefix, WIDER than its own account — and
/// `to` empty. The record is admitted at the ACCOUNT rung and the index stores
/// `(X, [X.1])`, which `/dump` shows; the read serves `(X.1, [X.1])` — the
/// agent's OWN account, every document `X.1` owns, exactly what the fold
/// answers `true` for — and NOT `X`. Rows GROUP at the served prefix: the
/// agent's own share over `X.1` adds nothing. And THE COMPARE IS ω's
/// (RES-298): X's share over `X.1` — inside X's account by address, `X.1`'s
/// by ω, the sub-account being REGISTERED — stands ADMITTED in the fold and
/// is NO row, X a granter there and not the owner, so the row keeps its ONE
/// issuer. X's share over X itself is a row at X, ahead of it; the agent's
/// draft a row after; and every served row carries one issuer, the
/// registry's `effective_owner` of its prefix.
#[test]
fn an_agents_share_over_its_hirers_prefix_is_served_at_the_agents_own_account() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let x = CLAIMANT_ACCOUNT;
    let holder = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);

    // Seat the agent at X.1 — the computed agent space — under a fresh id,
    // and open its session by reference with the holder's device key.
    let x1 = next_prefix_under(port, None, x);
    assert_eq!(x1, format!("{x}.1"), "the agent space is inc(X, 1)");
    let agent_id = 7_001_001;
    expect_resp(
        &op(port, Some(&holder), &format!(r#"{{"op":"delegate","new_prefix":"{x1}","new_id":{agent_id}}}"#)),
        "ack_addr",
    );
    let agent = open_signed_session(port, agent_id, &device_key());
    let x1_doc1 = acked_addr(&op(port, Some(&agent), &create_frame(&x1, Some(true))));
    assert_eq!(x1_doc1, format!("{x1}.0.1"), "X.1's doc 1, born published");

    // The share over the HIRER's prefix: stored at X, served at X.1.
    let wide = deposit_grant(port, &agent, &x1_doc1, x, None);
    assert_admitted(port, &wide, x, &x1);
    let rows = universal_grants(port, Some(&bare));
    assert_eq!(rows, vec![r(&x1, &[&x1])], "served at the agent's own account");
    assert!(rows.iter().all(|(p, _)| p != x), "never the stored prefix");

    // Grouping at the served prefix: the agent's own share over X.1 adds no
    // row and no issuer…
    deposit_grant(port, &agent, &x1_doc1, &x1, None);
    assert_eq!(universal_grants(port, Some(&bare)), vec![r(&x1, &[&x1])]);
    // …and X's share over X.1 is NO row (RES-298): inside X's account by
    // address, X.1's by ω — X.1 is registered — so the record stands ADMITTED
    // in the fold, the index holds X beside X.1 there, and no served row
    // names X at X.1: a granter, not the owner.
    let parent = deposit_grant(port, &holder, CLAIMANT_DOC1, &x1, None);
    assert_admitted(port, &parent, &x1, x);
    let rows = universal_grants(port, Some(&bare));
    assert_eq!(rows, vec![r(&x1, &[&x1])], "the hirer's share beneath its registered sub-account is no row");
    assert!(
        rows.iter().all(|(p, issuers)| p != &x1 || issuers.iter().all(|i| i != x)),
        "no served row names X at X.1: {rows:?}"
    );
    // X's share over X is a row of its own at X, ahead; the agent's draft a
    // row of its own after X.1.
    deposit_grant(port, &holder, CLAIMANT_DOC1, x, None);
    let agent_draft = create_doc(port, &agent, &x1);
    deposit_grant(port, &agent, &x1_doc1, &agent_draft, None);
    let rows = universal_grants(port, Some(&agent));
    assert_eq!(rows, in_prefix_order(vec![r(x, &[x]), r(&x1, &[&x1]), r(&agent_draft, &[&x1])]));
    // Face equals fold, row by row: ONE issuer, and it is the seat the
    // registry's own `effective_owner` answers for the served prefix.
    for (prefix, issuers) in &rows {
        assert_eq!(issuers.len(), 1, "one issuer per served row: {rows:?}");
        let seat = effective_owner(port, None, prefix).map(|(seat, _)| seat);
        assert_eq!(seat.as_ref(), Some(&issuers[0]), "ω of {prefix} is the row's one issuer");
    }
    // The guest still: nothing.
    assert!(universal_grants(port, None).is_empty());

    sd.shutdown();
}

/// RES-298's NAMED RESIDUE, pinned as a fact and not repaired. ω answers `X`
/// for an UNALLOCATED sub-prefix of X's — `X.2`, before any delegation seats
/// it (AUTH-6.37) — so X's share over `X.2`, admitted at the ACCOUNT rung (the
/// ladder reads the address alone, registered or not), is served as stored,
/// `(X.2, [X])`: a row covering ∅, no document existing beneath it. Seating
/// the SIBLING `X.1` moves nothing. Seating `X.2` moves ω to `X.2`, and the
/// row is GONE at the next read while the record stands admitted in the fold
/// — the parent cell, reached by a delegation and not by a deposit. `/op-at`
/// reads ONE position, the registry with the index: as of a position before
/// the delegation the row stands, and from the delegation on it is gone.
#[test]
fn an_unallocated_sub_prefix_is_served_until_it_is_delegated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let x = CLAIMANT_ACCOUNT;
    let holder = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let frame = universal_grants_frame();

    // X.2, UNALLOCATED — nothing is delegated under X yet, not even its elder
    // sibling — and ω answers X's own seat for it.
    let x2 = format!("{x}.2");
    assert_eq!(next_prefix_under(port, None, x), format!("{x}.1"), "no delegation under X yet");
    assert_eq!(effective_owner(port, None, &x2), Some((x.to_string(), CLAIMANT_PRINCIPAL)));

    // SERVED: the share is admitted, stored `(X.2, [X])`, and served as stored.
    let early = deposit_grant(port, &holder, CLAIMANT_DOC1, &x2, None);
    assert_admitted(port, &early, &x2, x);
    let row = vec![r(&x2, &[x])];
    assert_eq!(universal_grants(port, Some(&bare)), row, "ω answers X at the unallocated X.2");

    // The SIBLING's delegation moves nothing: ω of X.2 is X still.
    let (x1, _) = delegate_under(port, &bare, x, 7_002_001);
    assert_eq!(x1, format!("{x}.1"));
    assert_eq!(universal_grants(port, Some(&bare)), row, "X.1's seat is not X.2's");
    let before = head_position(port);

    // GONE: X.2 seated, ω moves to it, and the row drops at the next read —
    // the record unmoved in the fold, as the parent cell's is.
    let (seated, _) = delegate_under(port, &bare, x, 7_002_002);
    assert_eq!(seated, x2, "the next delegable prefix under X is X.2");
    assert_eq!(effective_owner(port, None, &x2).map(|(seat, _)| seat), Some(x2.clone()));
    assert!(universal_grants(port, Some(&bare)).is_empty(), "gone at the read after the delegation");
    assert_admitted(port, &early, &x2, x);

    // History: the compare reads the registry OF the position asked.
    let at_before = op_at_ok(port, Some(&bare), before, &frame);
    assert_eq!(grant_rows(&at_before), row, "before the delegation, the row stands: {at_before}");
    let at_head = op_at_ok(port, Some(&bare), head_position(port), &frame);
    assert!(grant_rows(&at_head).is_empty(), "from the delegation on, gone: {at_head}");

    sd.shutdown();
}

/// REVOCATION IS IMMEDIATE, AND HISTORY KEEPS THE ROW. A universal grant's
/// row stands at the next read and is GONE at the read after the issuer's
/// revoking record (`from` the grant's own address). On `/op-at`: before the
/// grant, empty; at the grant's position and up to the revocation, present;
/// from the revocation on, gone — `as_of` the position asked every time, and
/// the guest empty at every position. A re-grant is a fresh row, and a blind
/// retry of the revoke — a record naming the withdrawn grant again — is of
/// neither kind and moves nothing (PUB-5.15).
#[test]
fn a_withdrawn_grants_row_is_gone_at_the_next_read_and_stands_on_op_at_before_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let x = CLAIMANT_ACCOUNT;
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = owner_draft(port, &bare);
    let row = vec![r(&draft, &[x])];
    let frame = universal_grants_frame();

    let before = head_position(port);
    let (grant, at_grant) = grant_at(port, &signed, CLAIMANT_DOC1, &draft);
    assert_eq!(universal_grants(port, Some(&bare)), row, "present at the next read");
    let (_, at_revoke) = grant_at(port, &signed, CLAIMANT_DOC1, &grant);
    assert!(before < at_grant && at_grant < at_revoke);
    assert!(universal_grants(port, Some(&bare)).is_empty(), "gone at the read after the revocation");

    // Every position probed is one a response handed out: `before` (the
    // head before the grant), the two acks' own `at`, and the head.
    for (position, expect, what) in [
        (before, Vec::new(), "before the grant"),
        (at_grant, row.clone(), "at the grant's own position, before the revocation"),
        (at_revoke, Vec::new(), "at the revocation"),
        (head_position(port), Vec::new(), "at the head"),
    ] {
        let v = op_at_ok(port, Some(&bare), position, &frame);
        assert_eq!(grant_rows(&v), expect, "{what} ({position}): {v}");
        assert_eq!(v["as_of"].as_u64(), Some(position), "as_of is the position asked: {v}");
        let v = op_at_ok(port, None, position, &frame);
        assert!(grant_rows(&v).is_empty(), "the guest, {what}: {v}");
        assert_eq!(v["as_of"].as_u64(), Some(position), "{v}");
    }

    // A re-grant is a fresh row; a blind retry of the revoke names a withdrawn
    // grant — of neither kind, entering no index and lifting nothing.
    grant_at(port, &signed, CLAIMANT_DOC1, &draft);
    assert_eq!(universal_grants(port, Some(&bare)), row, "re-granted");
    grant_at(port, &signed, CLAIMANT_DOC1, &grant);
    assert_eq!(universal_grants(port, Some(&bare)), row, "the retry of the revoke moves nothing");

    sd.shutdown();
}
