//! The change feed as THE MIRROR'S WHOLE INPUT (wire v7.11; signed ops —
//! the design record §7.3 (i), D12, D25, r6-2a): one end-to-end walk over
//! every kind of row, Π and the claim boundary read off the feed alone, the
//! attest store's crash honesty and its keep below the reclaim floor, and
//! D12 on a record deposit's rows — its two above the claim, its atom below
//! it, where nothing is signed, and an atom past the record cap, which is no
//! record. The seeded flow, the feed readers, the per-kind term checks and
//! the reclaim helpers are the parent's.

use std::collections::BTreeMap;

use skep_identity::{canonical_record, Enrollment, Fingerprint, MAX_RECORD_BYTES};

use super::*;

/// The whole feed from the floor as `token` (`None` = the guest), one page
/// — the boards here are far under the page cap.
fn all_entries(port: u16, token: Option<&str>) -> Vec<Value> {
    let v = changes_ok(port, token, "since=0&limit=4096");
    assert_eq!(v["more"], Value::Bool(false), "one page holds the whole feed: {v}");
    v["changes"].as_array().expect("changes").clone()
}

/// The entry at `at` among `entries`.
fn entry_at(entries: &[Value], at: u64) -> &Value {
    entries
        .iter()
        .find(|e| e["at"].as_u64() == Some(at))
        .unwrap_or_else(|| panic!("no entry at {at} in {entries:?}"))
}

/// The fingerprint hex a seed carrier's hybrid key enrols under — what a
/// signed session's unsigned writes testify as their `key`.
fn fingerprint_of(sk: &skep_signature::Seed) -> String {
    Fingerprint::of(&public_key_of(sk)).to_hex()
}

/// THE FEED IS THE MIRROR'S WHOLE INPUT (wire v7.11; the design record
/// §7.3 (i), D12, D25, r6-2a): one end-to-end walk over the wire on a
/// claimed board, every kind of row the fence names —
///
/// * a signed-session `publish` presenting `attest`: its row carries
///   `attest` byte-equal to the request's (the `alg` token, the `sig` hex),
///   `placed` and `base_extent` exactly as `doc_metadata` serves them for
///   the member, and NO `key`;
/// * a signed-session `insert` presenting none: `key` the fingerprint, no
///   `attest`;
/// * a bare draft mint: `key: "bare"`; the head writer's rows: `key:
///   "system"`, the publish with its terms;
/// * a `delegate`: `new_prefix` and `new_id` equal to the ack's and to
///   `effective_owner`'s answer; a `make_link`: `link` equal to its
///   `ack_addr`;
/// * a credential record deposit above the claim (lane D's signed form):
///   its ATOM row with `key` — the daemon's testimony of the writing
///   session (as7-E2 (a); SO-I7 (e)) — and its LINK row, the one the
///   record's `sig` signs, without; neither with `attest`; the ceremony's
///   rows below the claim: `key` served, no `attest` —
///
/// and the same page byte-identical across a restart (PUB-8.26) with every
/// new member.
#[test]
fn the_feed_is_the_mirrors_whole_input() {
    let dir = tempfile::tempdir().expect("tempdir");
    let before_restart: Vec<u8>;
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        let device_fp = fingerprint_of(&device_key());
        let at_of = |e: &Value| e["at"].as_u64().expect("at");

        // A `delegate` from the bootstrap principal: the minted pair.
        let boot = open_session(port, 0);
        let prefix = next_prefix_under(port, Some(&boot), "1");
        let v = op(
            port,
            Some(&boot),
            &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
        );
        let (delegate_at, delegate_addr) = (acked_at(&v), acked_addr(&v));

        // A credential record deposit ABOVE the claim, lane D's signed form:
        // the hire of principal 1 — the record's atom, signed at the record
        // grade, then the enroll link the daemon verifies the `sig` at.
        let hire_from = head(port);
        let _agent = hire(port, &signed, CLAIMANT_DOC1, &prefix, 1, &distinct_key(1));
        let hire_rows = changes_ok(port, Some(&signed), &format!("since={hire_from}"))["changes"]
            .as_array()
            .expect("changes")
            .clone();
        assert_eq!(hire_rows.len(), 2, "the hire is two writes: {hire_rows:?}");

        // A signed `publish` presenting `attest` over doc 1's whole extent,
        // posted AS COMPOSED so the request's own member is in hand.
        let extent = content_extent(port, None, CLAIMANT_DOC1);
        let runs = shot_runs(port, Some(&signed), CLAIMANT_DOC1, 1, extent);
        let frame = publish_frame(CLAIMANT_DOC1, Some((CLAIMANT_DOC1, extent)), None, &runs);
        let sent: Value =
            serde_json::from_str(&attach_attest(port, &signed, &frame)).expect("a JSON frame");
        assert!(sent["attest"].is_object(), "the suite's signer signed the shot: {sent}");
        let v = op_as_written(port, Some(&signed), &sent.to_string());
        let (publish_at, member) = (acked_at(&v), acked_addr(&v));

        // A signed-session `insert` presenting none — a private draft's own
        // edit, and the draft's mint before it, both outside the checked set.
        let v = op_as_written(port, Some(&signed), &create_frame(CLAIMANT_ACCOUNT, None));
        let (draft_at, draft) = (acked_at(&v), acked_addr(&v));
        let v = op_as_written(port, Some(&signed), &insert_frame(&draft, 1, "x", false));
        let insert_at = acked_at(&v);

        // A bare draft mint, and a bare `make_link` into it.
        let bare = open_session(port, CLAIMANT_PRINCIPAL);
        let v = op(port, Some(&bare), &create_frame(CLAIMANT_ACCOUNT, None));
        let (bare_mint_at, bare_doc) = (acked_at(&v), acked_addr(&v));
        let v = op(
            port,
            Some(&bare),
            &link_frame(&bare_doc, r#"{"addrs":[]}"#, r#"{"addrs":[]}"#, &ghost_ty(&bare_doc, 1)),
        );
        let (link_at, link_addr) = (acked_at(&v), acked_addr(&v));

        // THE WALK, as the claimant — whose class sees every row above but
        // the system account's two private draft writes.
        let entries = all_entries(port, Some(&signed));
        let mut want_ats: Vec<u64> = CEREMONY_ATS.to_vec();
        want_ats.push(H1_PUBLISH_AT);
        want_ats.push(delegate_at);
        want_ats.extend(hire_rows.iter().map(at_of));
        want_ats.extend([publish_at, draft_at, insert_at, bare_mint_at, link_at]);
        assert_eq!(entries.iter().map(at_of).collect::<Vec<_>>(), want_ats);
        for e in &entries {
            assert_terms_by_op(e, "the walk");
        }
        // `attest` rides exactly one row, the shot's; `key` is absent on
        // exactly the signed rows — the shot's and the deposit's LINK row
        // (as7-E2 (a): the atom row keeps its `key`).
        let attested: Vec<u64> =
            entries.iter().filter(|e| e.get("attest").is_some()).map(at_of).collect();
        assert_eq!(attested, vec![publish_at], "attest rides the marker-signed row alone");
        let signed_ats: Vec<u64> = vec![at_of(&hire_rows[1]), publish_at];
        let keyless: Vec<u64> =
            entries.iter().filter(|e| e.get("key").is_none()).map(at_of).collect();
        assert_eq!(keyless, signed_ats, "key is absent on the signed rows and served on every other");

        // The signed publish.
        let e = entry_at(&entries, publish_at);
        assert_eq!(e["op"].as_str(), Some("publish"));
        assert_eq!(e["docs"], serde_json::json!([member]));
        assert_eq!(e["attest"], sent["attest"], "byte-equal to the request's: {e}");
        let md = doc_metadata(port, None, &member);
        assert_eq!(e["placed"], md["placed"], "the count, as the member read serves it: {e}");
        assert_eq!(e["base_extent"], md["base_extent"], "the base extent, as the member read serves it: {e}");
        assert_eq!(e["placed"].as_str(), Some(extent.to_string().as_str()), "Σ width of the runs");
        assert_eq!(e["base_extent"].as_str(), Some(extent.to_string().as_str()), "the extent the shot named");

        // The signed-session writes that presented none: the fingerprint.
        for (what, at) in [("the draft's mint", draft_at), ("the draft's insert", insert_at)] {
            let e = entry_at(&entries, at);
            assert_eq!(e["key"].as_str(), Some(device_fp.as_str()), "{what}: {e}");
            assert_absent(e, &["attest"], what);
        }

        // The bare session's writes.
        assert_eq!(entry_at(&entries, bare_mint_at)["key"].as_str(), Some("bare"));
        let e = entry_at(&entries, link_at);
        assert_eq!(e["key"].as_str(), Some("bare"));
        assert_eq!(e["link"].as_str(), Some(link_addr.as_str()), "the minted link, the ack's: {e}");

        // The head writer's row every class sees: `H.1`'s publish, with the
        // shot's terms as `doc_metadata` serves them for the member.
        let e = entry_at(&entries, H1_PUBLISH_AT);
        assert_eq!((e["key"].as_str(), e["op"].as_str()), (Some("system"), Some("publish")));
        let md = doc_metadata(port, None, HEAD_MEMBER_1);
        assert_eq!(e["placed"], md["placed"], "H.1's count: {e}");
        assert_eq!(e["base_extent"], md["base_extent"], "H.1's base extent: {e}");
        assert_absent(e, &["attest"], "the head writer's row");

        // The delegate: the pair is the ack's, and ω's.
        let e = entry_at(&entries, delegate_at);
        assert_eq!(e["new_prefix"].as_str(), Some(delegate_addr.as_str()));
        assert_eq!(delegate_addr, prefix, "the ack names the prefix the request asked");
        assert_eq!(e["new_id"].as_u64(), Some(1));
        assert_eq!(
            effective_owner(port, None, &prefix),
            Some((prefix.clone(), 1)),
            "ω at the head agrees with the row"
        );
        assert_eq!(e["key"].as_str(), Some("bare"));

        // The record deposit's two rows (D26; e-Q2 re-cut at the atom row,
        // as7-E2 (a)): the atom's insert carries `key` — the daemon's
        // testimony of the writing session — and no `attest`; its credential
        // link, the position the record's `sig` signs, carries neither; the
        // link row names its link.
        let (atom_row, link_row) = (&hire_rows[0], &hire_rows[1]);
        assert_eq!(atom_row["op"].as_str(), Some("insert"), "{atom_row}");
        assert_eq!(atom_row["docs"], serde_json::json!([CLAIMANT_DOC1]));
        assert_eq!(atom_row["key"].as_str(), Some(device_fp.as_str()), "the atom row's key: {atom_row}");
        assert_absent(atom_row, &["attest"], "the record's atom");
        assert_terms_by_op(atom_row, "the record's atom");
        assert_eq!(link_row["op"].as_str(), Some("make_link"), "{link_row}");
        assert_absent(link_row, &["key", "attest"], "the record's link");
        assert_terms_by_op(link_row, "the record's link");
        assert!(
            link_row["link"].as_str().is_some_and(|l| l.starts_with(&format!("{CLAIMANT_DOC1}.0.2."))),
            "the enroll link, minted in the registry's link subspace: {link_row}"
        );

        // The ceremony's rows below the claim: `key` served, no `attest`.
        for at in CEREMONY_ATS {
            let e = entry_at(&entries, at);
            assert!(e["key"].is_string(), "a ceremony row serves its key: {e}");
            assert_absent(e, &["attest"], "a ceremony row");
        }
        let e = entry_at(&entries, CEREMONY_ATS[0]);
        assert_eq!(
            (e["new_prefix"].as_str(), e["new_id"].as_u64()),
            (Some(CLAIMANT_ACCOUNT), Some(CLAIMANT_PRINCIPAL)),
            "the ceremony's delegate: {e}"
        );
        assert_eq!(
            entry_at(&entries, CEREMONY_ATS[2])["key"].as_str(),
            Some("bare"),
            "the genesis record's atom, unsigned below the claim, from a bare session"
        );
        assert!(entry_at(&entries, CEREMONY_ATS[3])["link"].is_string(), "the genesis link");
        let claim = entry_at(&entries, CLAIM_POSITION);
        assert_eq!(
            claim["key"].as_str(),
            Some(device_fp.as_str()),
            "the claim, from the signed device session, unjudged at the record grade: {claim}"
        );
        assert!(claim["link"].is_string(), "the claim link's address rides its row: {claim}");

        before_restart = changes_raw(port, Some(&bare), "since=0&limit=4096").1;
        sd.shutdown();
    }

    // DETERMINISM PER CLASS across a restart (PUB-8.26), every member included.
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    assert_eq!(
        changes_raw(port, Some(&bare), "since=0&limit=4096").1,
        before_restart,
        "the same query answers byte-identically across a restart"
    );
    sd.shutdown();
}

/// Π FROM THE FEED ALONE (AUTH-6.36 consumer (1); r6-2a, m3): a walk of
/// `/changes` from the floor, paging, taking every `delegate` row's pair,
/// equals `effective_owner`'s answer for every minted prefix at the head —
/// the mirror recipe's ω derivation from the board's own records, never the
/// node registry.
#[test]
fn pi_from_the_feed_alone_is_effective_owners_answer_for_every_minted_prefix() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let boot = open_session(port, 0);
    let (a, s_a) = delegate_under(port, &boot, "1", 1);
    let (b, _) = delegate_under(port, &boot, "1", 2);
    let (a1, _) = delegate_under(port, &s_a, &a, 3);

    // THE MIRROR RECIPE: page from the floor, `delegate` rows alone.
    let mut pi: BTreeMap<String, u64> = BTreeMap::new();
    let mut since = 0;
    loop {
        let page = changes_ok(port, None, &format!("since={since}&limit=3"));
        for e in page["changes"].as_array().expect("changes") {
            if e["op"].as_str() == Some("delegate") {
                let prefix = e["new_prefix"].as_str().expect("a delegate row names its prefix");
                let id = e["new_id"].as_u64().expect("…and the principal it seated");
                assert!(pi.insert(prefix.to_string(), id).is_none(), "one row per mint: {e}");
            }
        }
        if !page["more"].as_bool().expect("more") {
            break;
        }
        since = page["last"].as_u64().expect("last");
    }
    let want: BTreeMap<String, u64> =
        [(CLAIMANT_ACCOUNT.to_string(), CLAIMANT_PRINCIPAL), (a.clone(), 1), (b.clone(), 2), (a1.clone(), 3)]
            .into_iter()
            .collect();
    assert_eq!(pi, want, "Π off the feed is every account the board minted, with its principal");
    for (prefix, id) in &pi {
        assert_eq!(
            effective_owner(port, None, prefix),
            Some((prefix.clone(), *id)),
            "ω at the head agrees with the feed's pair for {prefix}"
        );
    }
    // ω over an address BENEATH a prefix is the longest of Π's prefixes —
    // the derivation a mirror makes from these rows, checked against the
    // board's own: a document under A.1 is A.1's, not A's.
    assert_eq!(effective_owner(port, None, &format!("{a1}.0.1")), Some((a1.clone(), 3)));
    assert_eq!(effective_owner(port, None, &format!("{a}.0.9")), Some((a.clone(), 1)));
    sd.shutdown();
}

/// THE BOUNDARY FROM THE FEED ALONE (the design record §5.2's owed read):
/// the claim link's address, as `find_links` answers it, equals the `link`
/// of exactly one `make_link` row, whose `at` is the claim's position —
/// `H.1`'s own — so a reader maps the link to its commit position off the
/// feed, with no `H.1` to name it.
#[test]
fn the_claim_boundary_is_read_off_the_feed_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let claim_at = board_term(port).expect("H.1").log_position;
    assert_eq!(claim_at, CLAIM_POSITION);

    let claims = addrs_of(&op(port, None, &class_scan_frame("find_links_ftt", T_CLAIM)));
    assert_eq!(claims.len(), 1, "one claim link on the board: {claims:?}");
    let entries = all_entries(port, None);
    let rows: Vec<&Value> = entries
        .iter()
        .filter(|e| e["op"].as_str() == Some("make_link"))
        .filter(|e| e["link"].as_str() == Some(claims[0].as_str()))
        .collect();
    assert_eq!(rows.len(), 1, "exactly one make_link row names the claim link: {entries:?}");
    assert_eq!(rows[0]["at"].as_u64(), Some(claim_at), "…at the claim's position: {}", rows[0]);
    sd.shutdown();
}

/// ABSENCE IS A VERDICT, SO THE STORE IS HONEST — above the floor: a lost or
/// torn `feed-attest.log` is rebuilt at open from the journal's markers
/// (`Kernel::attestation_at`) and the feed serves the SAME `attest` bytes;
/// with `commits.log` lost beside it, the rows come back bare and the slot
/// rides the bare row — the journal's own fact beside the lost testimony.
#[test]
fn a_lost_or_torn_attest_store_is_rebuilt_from_the_journal_and_serves_the_same_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path().join("feed-attest.log");
    let (before, signed_ats, attests) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        let (a1, attest1) = signed_ghost_link(port, &signed, 1);
        let (a2, attest2) = signed_ghost_link(port, &signed, 2);
        let bare = open_session(port, CLAIMANT_PRINCIPAL);
        expect_resp(&op(port, Some(&bare), &create_frame(CLAIMANT_ACCOUNT, None)), "ack_addr");
        let before = changes_raw(port, Some(&bare), "since=0&limit=4096").1;
        // The store's own lines: `{"alg":T,"at":N,"sig":"<hex>"}`, one per
        // attested position, the tag and the blob as the marker holds them.
        let lines = attest_store_lines(dir.path());
        assert_eq!(lines.keys().copied().collect::<Vec<_>>(), vec![a1, a2]);
        for (at, attest) in [(a1, &attest1), (a2, &attest2)] {
            let (alg, sig) = &lines[&at];
            assert_eq!(*alg, u64::from(FIXTURE_TAG));
            assert_eq!(sig, attest["sig"].as_str().expect("sig"));
            let slot = sd.daemon().attestation_at(Seq(at)).expect("a boundary").expect("filled");
            assert_eq!(*sig, hex(slot.sig()), "the line mirrors the marker");
        }
        sd.shutdown();
        (before, vec![a1, a2], vec![attest1, attest2])
    };
    let judge = |ctx: &str| {
        let sd = spawn(dir.path());
        let port = sd.port();
        let bare = open_session(port, CLAIMANT_PRINCIPAL);
        assert_eq!(
            changes_raw(port, Some(&bare), "since=0&limit=4096").1,
            before,
            "{ctx}: the feed serves the same bytes, attest included"
        );
        assert_eq!(
            attest_store_lines(dir.path()).keys().copied().collect::<Vec<_>>(),
            signed_ats,
            "{ctx}: the store is rebuilt whole"
        );
        sd.shutdown();
    };
    // Deleted after commit: rebuilt from the journal.
    std::fs::remove_file(&store).expect("lose the store");
    judge("the store deleted");
    // Torn: the last line cut into, truncated at open, its position re-derived.
    let len = std::fs::metadata(&store).expect("metadata").len();
    let fh = std::fs::OpenOptions::new().write(true).open(&store).expect("open");
    fh.set_len(len.saturating_sub(37)).expect("tear the tail");
    drop(fh);
    judge("the store torn");
    // The testimony gone too: bare rows, the slot riding them.
    std::fs::remove_file(dir.path().join("commits.log")).expect("lose the testimony");
    std::fs::remove_file(&store).expect("lose the store");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let entries = all_entries(port, Some(&bare));
    for (at, attest) in signed_ats.iter().zip(&attests) {
        let e = entry_at(&entries, *at);
        assert!(e["op"].is_null() && e["key"].is_null(), "a bare row: {e}");
        assert_eq!(e["attest"], *attest, "the slot is the journal's fact, served on the bare row: {e}");
    }
    for e in entries.iter().filter(|e| !signed_ats.contains(&e["at"].as_u64().expect("at"))) {
        assert_absent(e, &["attest"], "a bare row whose marker is empty");
    }
    sd.shutdown();
}

/// ABSENCE IS A VERDICT — at and below the floor (BW-01): after a
/// reclamation drops `commits.log`'s entries below the floor,
/// `feed-attest.log` still holds its line there (the file read directly:
/// no route serves a below-floor position, e-Q1), and the row AT the floor
/// — whose marker the journal refuses `Reclaimed`, the segment holding it
/// gone — serves its slot off the kept line; with the line lost, that row
/// renders `attest: null`, LOST, never absent, and still no `key`.
#[test]
fn the_attest_store_keeps_below_the_floor_and_serves_a_lost_slot_at_the_floor_as_null() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path().join("feed-attest.log");
    let (early_at, last_at, last_attest) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let doc = seed_flow(port);
        let s1 = open_session(port, 1);
        let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        let (early_at, _) = signed_ghost_link(port, &signed, 1);
        rotate_a_segment(port, &s1, &doc);
        let (last_at, last_attest) = signed_ghost_link(port, &signed, 2);
        assert_eq!(last_at, head(port), "the signed write is the head");
        sd.shutdown();
        (early_at, last_at, last_attest)
    };
    reclaim_below_the_head(dir.path(), last_at);

    // The store kept: the line below the floor survives in the file, and
    // the row at the floor serves its slot off the kept line.
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let bare = open_session(port, CLAIMANT_PRINCIPAL);
        let (st, body) = changes_raw(port, Some(&bare), "since=0");
        assert_eq!(st, 410, "{}", text(&body));
        let floor = json(&body)["floor"].as_u64().expect("floor");
        assert_eq!(floor, last_at, "the floor is the checkpoint's own position, the head");
        assert!(early_at < floor);
        let commits = std::fs::read_to_string(dir.path().join("commits.log")).expect("commits.log");
        assert!(
            !commits.contains(&format!("{{\"at\":{early_at},")),
            "commits.log dropped the early signed write's entry: {commits}"
        );
        let lines = attest_store_lines(dir.path());
        assert!(lines.contains_key(&early_at), "the store KEEPS its line below the floor: {lines:?}");
        assert!(lines.contains_key(&last_at), "…and the line at the floor: {lines:?}");
        assert!(
            matches!(sd.daemon().attestation_at(Seq(last_at)), Err(skepd::HistoryError::Reclaimed { .. })),
            "the journal refuses the marker at the floor: its segment is reclaimed"
        );
        let page = changes_ok(port, Some(&bare), &format!("since={}", floor - 1));
        let e = entry_at(page["changes"].as_array().expect("changes"), last_at);
        assert_eq!(e["attest"], last_attest, "the row at the floor serves its slot off the kept line: {e}");
        assert_absent(e, &["key"], "a signed row");
        sd.shutdown();
    }
    // The store lost: the journal refuses the slot, nothing is rebuilt, and
    // the row — recorded signed — renders LOST.
    {
        std::fs::remove_file(&store).expect("lose the store");
        let sd = spawn(dir.path());
        let port = sd.port();
        let bare = open_session(port, CLAIMANT_PRINCIPAL);
        let page = changes_ok(port, Some(&bare), &format!("since={}", last_at - 1));
        let e = entry_at(page["changes"].as_array().expect("changes"), last_at);
        assert!(
            e.get("attest").is_some_and(Value::is_null),
            "recorded signed, the store silent, the journal refusing: attest is null — LOST, never absent: {e}"
        );
        assert_absent(e, &["key"], "the entry IS signed; only its hand is out of reach");
        assert!(attest_store_lines(dir.path()).is_empty(), "nothing was rebuilt: the journal refused the slot");
        sd.shutdown();
    }
}

/// D12 ON A RECORD DEPOSIT'S TWO ROWS — e-Q2 RE-CUT AT THE ATOM ROW (SO-I7
/// (e); round 7's as7-E2 ARM (a), owner 2026-10-01): the atom's `insert`
/// ALWAYS carries `key`, the daemon's testimony of the writing session, and
/// no `attest`; the credential `make_link` that names it — the one position
/// the record's own `sig` signs, at the record grade — carries neither. A
/// record deposited ABOVE the claim carrying NO `sig` lands NOWHERE: refused
/// at its `insert`, `record_sig_required`, PERMANENT (bu7-E1 ARM (a); SO-I4),
/// the journal unmoved — e-Q2's "a sig-less record's atom keeps its `key`"
/// has no population on a conforming daemon. And THE ORPHAN ATOM (the
/// register's SO-I7 *Test:* line, l7-R3): a record with a GARBAGE `sig` —
/// well-formed, the row's width, verifying under nothing — passes the
/// narrowed exemption (it parses, into doc 1), its link is refused
/// `attestation_invalid:signature`, and the atom's row keeps the one
/// asserted hand, `key`, with no `attest` — D12's audit diagnostic.
#[test]
fn the_atom_row_carries_key_the_link_row_none_a_sig_less_record_is_refused_and_an_orphan_keeps_its_hand() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let device_fp = fingerprint_of(&device_key());
    let boot = open_session(port, 0);
    let (a, _) = delegate_under(port, &boot, "1", 1);

    let from = head(port);
    hire(port, &signed, CLAIMANT_DOC1, &a, 1, &distinct_key(1));
    let rows = changes_ok(port, Some(&signed), &format!("since={from}"))["changes"]
        .as_array()
        .expect("changes")
        .clone();
    assert_eq!(rows.len(), 2, "the atom's insert and its link: {rows:?}");
    assert_eq!((rows[0]["op"].as_str(), rows[1]["op"].as_str()), (Some("insert"), Some("make_link")));
    assert_eq!(rows[0]["key"].as_str(), Some(device_fp.as_str()), "the atom row's key: {}", rows[0]);
    assert_absent(&rows[0], &["attest"], "a record deposit's atom row");
    assert_absent(&rows[1], &["key", "attest"], "a record deposit's link row");
    for row in &rows {
        assert_terms_by_op(row, "a record deposit's row");
    }

    // The sig-less record: refused at its insert, nothing landed.
    let (b, _) = delegate_under(port, &boot, "1", 2);
    let ordinal = next_content_ordinal(port, Some(&signed), CLAIMANT_DOC1);
    let atom = enroll_atom(&[&distinct_key(2)]);
    let before = head(port);
    let v = op_as_written(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{T_ENROLL}"}}"#
        ),
    );
    assert_eq!(verdict(&v), "credential_refused:record_sig_required", "{v}");
    assert_eq!(v["disposition"].as_str(), Some("permanent"), "{v}");
    assert_eq!(head(port), before, "no orphan: the journal's position is unmoved");

    // The orphan: a garbage `sig` of the row's width — the atom lands exempt,
    // its link is refused, and its row keeps the daemon's one asserted hand.
    let entries = [Enrollment::new(public_key_of(&distinct_key(2)), false, None).expect("no label")];
    let garbage = json_atom(&canonical_record(&entries, Some(&hex(&[0xab; 3373]))));
    let (ack, e) = feed_entry_as_written(
        port,
        &signed,
        "an orphan atom: a record with a garbage sig",
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{garbage}}}],"deposit":"{T_ENROLL}"}}"#
        ),
    );
    let v = typed_link(port, &signed, CLAIMANT_DOC1, &[&acked_addr(&ack)], &[&b], T_ENROLL);
    assert_eq!(verdict(&v), "credential_refused:attestation_invalid:signature", "{v}");
    assert_eq!(e["key"].as_str(), Some(device_fp.as_str()), "the orphan's row keeps its hand: {e}");
    assert_absent(&e, &["attest"], "the orphan atom's row");
    sd.shutdown();
}

/// Π FROM A FEED WITH BARE `delegate` ROWS (SO-I5 (e); round 7's as7-F3 —
/// bare feed rows served from the journal): with `commits.log` gone, every
/// position comes back BARE, and a bare `delegate` row still carries its
/// `op` and its pair — `new_prefix`, `new_id` — answered from the journal's
/// own records, so the mirror recipe's Π over the bare feed equals
/// `effective_owner`'s answer for every minted prefix, as it does over the
/// recorded one (`pi_from_the_feed_alone_is_effective_owners_answer_for_every_minted_prefix`).
#[test]
fn pi_from_a_feed_with_bare_delegate_rows_is_effective_owners_answer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let prefixes = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let boot = open_session(port, 0);
        let (a, s_a) = delegate_under(port, &boot, "1", 1);
        let (b, _) = delegate_under(port, &boot, "1", 2);
        let (a1, _) = delegate_under(port, &s_a, &a, 3);
        sd.shutdown();
        vec![(CLAIMANT_ACCOUNT.to_string(), CLAIMANT_PRINCIPAL), (a, 1), (b, 2), (a1, 3)]
    };
    // The testimony gone: the open re-covers every position as bare, the
    // journal answering each row's class and terms.
    std::fs::remove_file(dir.path().join("commits.log")).expect("delete the testimony");
    let sd = spawn(dir.path());
    let port = sd.port();
    let mut pi: BTreeMap<String, u64> = BTreeMap::new();
    let mut since = 0;
    loop {
        let page = changes_ok(port, None, &format!("since={since}&limit=3"));
        for e in page["changes"].as_array().expect("changes") {
            assert!(e["docs"].is_null() && e["key"].is_null() && e["time"].is_null(), "bare: {e}");
            if e["op"].as_str() == Some("delegate") {
                let prefix = e["new_prefix"].as_str().expect("a bare delegate row names its prefix");
                let id = e["new_id"].as_u64().expect("…and the principal it seated");
                assert!(pi.insert(prefix.to_string(), id).is_none(), "one row per mint: {e}");
            }
        }
        if !page["more"].as_bool().expect("more") {
            break;
        }
        since = page["last"].as_u64().expect("last");
    }
    let want: BTreeMap<String, u64> = prefixes.into_iter().collect();
    assert_eq!(pi, want, "Π off the bare feed is every account the board minted, with its principal");
    for (prefix, id) in &pi {
        assert_eq!(effective_owner(port, None, prefix), Some((prefix.clone(), *id)), "ω agrees for {prefix}");
    }
    sd.shutdown();
}

/// AT OR BELOW THE CLAIM NOTHING IS SIGNED (A5; `record_deposit_carries_sig`:
/// "the ceremony's own record, `sig` or not, keeps its row's `key`"): on an
/// UNCLAIMED board a declared enrolment atom whose record CARRIES a `sig` —
/// the record grade's shape, a hybrid blob in hex — lands, and its row serves
/// the session's `key` with no `attest`. The ceremony's own records carry no
/// `sig`, so every other row below the claim keeps its `key` whatever this arm
/// says; above the claim the same shape drops it
/// (`both_rows_of_a_record_deposit_carry_neither_key_nor_attest_and_a_sig_less_atom_keeps_its_key`).
#[test]
fn below_the_claim_a_record_carrying_a_sig_keeps_its_rows_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    ceremony_before_the_claim(port);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let entries = [Enrollment::new(public_key_of(&distinct_key(3)), false, None).expect("no label")];
    let carrying = json_atom(&canonical_record(&entries, Some(&hex(&[0xab; 3373]))));
    let ordinal = next_content_ordinal(port, Some(&signed), CLAIMANT_DOC1);
    let (_, e) = feed_entry(
        port,
        &signed,
        "a record carrying a sig, below the claim",
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{carrying}}}],"deposit":"{T_ENROLL}"}}"#
        ),
    );
    assert_eq!(
        e["key"].as_str(),
        Some(fingerprint_of(&device_key()).as_str()),
        "nothing is signed below the claim: {e}"
    );
    assert_absent(&e, &["attest"], "a row below the claim");
    sd.shutdown();
}

/// A RECORD ATOM PAST THE RECORD CAP IS NO RECORD (AUTH-1.18; the narrowed
/// exemption's one parse, `declared_record_atom`, as7-E1 ARM (a)): above
/// the claim, a declared enrolment atom spelling a canonical record WITH a
/// `sig` but past `MAX_RECORD_BYTES` parses as no record — the parse refuses
/// it `too_large` at its own head, as the read refuses its link — so the
/// exemption does not reach it and it takes the entry check like any insert
/// (s2's third case): unattested, `attestation_required`; attested, it
/// commits SIGNED, its row carrying `attest` and no `key`. The same shape
/// under the cap is the record deposit's own atom, exempt, its row serving
/// its `key`
/// (`the_atom_row_carries_key_the_link_row_none_a_sig_less_record_is_refused_and_an_orphan_keeps_its_hand`).
#[test]
fn above_the_claim_a_record_atom_past_the_cap_takes_the_entry_check() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    // Thirty-one label-free tag-1 entries and a tag-1 `sig` member spell
    // 124,589 + 6,755 = 131,344 bytes, past the 131,072 the cap admits.
    let entries: Vec<Enrollment> = (100u8..131)
        .map(|n| Enrollment::new(public_key_of(&distinct_key(n)), false, None).expect("no label"))
        .collect();
    let record = canonical_record(&entries, Some(&hex(&[0xab; 3373])));
    assert!(record.len() > MAX_RECORD_BYTES, "fixture: past the cap");
    let past = json_atom(&record);
    let ordinal = next_content_ordinal(port, Some(&signed), CLAIMANT_DOC1);
    let frame = format!(
        r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{past}}}],"deposit":"{T_ENROLL}"}}"#
    );
    let v = op_as_written(port, Some(&signed), &frame);
    assert_eq!(
        verdict(&v),
        "credential_refused:attestation_required",
        "an atom past the cap is no record: unattested, the check's (1): {v}"
    );
    let (_, e) = feed_entry(port, &signed, "a record atom past the cap, attested", &frame);
    assert!(e["attest"].is_object(), "attested: committed SIGNED, its row carrying attest: {e}");
    assert_absent(&e, &["key"], "a marker-signed row");
    sd.shutdown();
}
