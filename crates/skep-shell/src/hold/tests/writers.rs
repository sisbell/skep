//! The writer a drafts row names, as each write's answer records it.
//!
//! It is skep #1000's record. Over the fake board the suite checks that a
//! write through the one path stands out at its board across its dial, under
//! its session's key, and is
//! let go once its answer is noted, a read standing out never; that a held
//! burst the walk sends again under its dial id is recorded under the page's
//! `id` and the session the walk sent it under, never the dial id nor the
//! session that held it; that a landing the resend's read found records its
//! burst and no writer; and that one principal's record names no session of
//! another's, its drafts read waiting on no write of another's, while a
//! library write's note and a shot's record their session and no burst. The
//! feed's half — a row read before its write's answer is noted — is the feed
//! suite's (`feed/tests.rs`).

use super::*;

/// Returns the keys of principal 1's writes out at the ground's board.
fn writes_out(holds: &Holds) -> Vec<Option<String>> {
    holds.lock("b-1").principals.get(&1).map(|ph| ph.writes_out.values().cloned().collect()).unwrap_or_default()
}

/// Opens a writer of `principal`'s, acting as `account`, at the board.
///
/// It is a session as the shell opens one, its key in the ground's store.
fn writer_of(g: &Ground, principal: u64, account: &str, token: &str) -> Arc<SessionEntry> {
    let open = Open { token: Token::parse(&token.repeat(16)).unwrap(), facts: writer_facts_as(&g.store, principal, account), opened_at: 0 };
    let session = g.sessions.register(&g.entry, open, &mut NoSupplements);
    g.holds.open_session(&session);
    session
}

/// Checks that a write stands out across its dial and a read never.
///
/// A burst through `Holds::send` stands out at its board under its session's
/// key while its dial is out — the fake's look as `/op` records the send —
/// and is let go once its answer is noted, its writer recorded at the ack's
/// `at` with the page's `id`; a read through the same path stands out never
/// (the mutant that marks no write lets a drafts read send a row before its
/// writer is noted; the one that marks a read holds a drafts read waiting on
/// an answer that names no row).
#[test]
fn a_write_stands_out_across_its_dial_and_a_read_never() {
    let g = ground();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let look = {
        let (holds, seen) = (Arc::clone(&g.holds), Arc::clone(&seen));
        move || seen.lock().unwrap().push(writes_out(&holds))
    };
    *g.fake.at_send.lock().unwrap() = Some(Box::new(look));
    let ack = g.holds.send(&g.session, with_id(insert(DOC, json!(["a"]), g.fake.head()), "b-1"), None).answered().unwrap();
    g.fake.op_rejected.next(1, json!({"resp": "delivery", "items": [], "as_of": 50}));
    g.holds.send(&g.session, json!({"op": "doc_metadata", "doc": DOC}), None).answered().unwrap();
    *g.fake.at_send.lock().unwrap() = None;
    assert_eq!(*seen.lock().unwrap(), [vec![Some(g.own_key())], vec![]], "the burst stood out across its dial under its key, the read never");
    assert!(writes_out(&g.holds).is_empty(), "the burst let go once its answer was noted");
    let at = ack["at"].as_u64().expect("an ack");
    assert_eq!(g.holds.written(&g.session, at), Some(Written { by: Some(g.session.reference.clone()), burst: Some("b-1".into()) }), "its writer, and the page's `id`");
}

/// Checks that a resent burst names the page's `id` and the walk's session.
///
/// A burst with the `id` `b-1` is held under the ground's session; that
/// session leaves and another writer of the principal's opens, the only one
/// the walk can send under. The probe sends the line again under its dial
/// id, `shell:` and hex, and its ack is recorded under `b-1` and the second
/// session — never the dial id, and never the session that held it (the
/// mutant that records the dialed copy's `id` names a burst the page never
/// sent; the one that records the holding session names a writer whose dial
/// the board never answered).
#[test]
fn a_resent_burst_is_recorded_under_the_pages_id_and_the_session_the_walk_sent_it_under() {
    let g = ground();
    g.hold(&with_id(insert(DOC, json!(["a"]), g.fake.head()), "b-1"), "unreachable", false);
    assert!(g.sessions.close(&g.session.reference).is_some(), "the session that held the line leaves the table");
    let walker = writer_of(&g, 1, "1.0.1", "8e");
    g.holds.probe("b-1");
    let dialed = g.fake.sends.lock().unwrap().last().cloned().expect("the line was sent again");
    assert!(dialed["id"].as_str().is_some_and(|id| id.starts_with("shell:")), "sent under its dial id: {dialed}");
    let at = g.fake.head();
    let written = Some(Written { by: Some(walker.reference.clone()), burst: Some("b-1".into()) });
    assert_eq!(g.holds.written(&walker, at), written, "the page's `id`, and the session the walk sent it under");
}

/// Checks that a landing the read found records its burst and no writer.
///
/// A burst with the `id` `b-1` has its first dial's answer lost; its own row
/// stands on the board at the position the fake would have acked, and its
/// values at its site, so the probe's read finds it landed and keeps it, sent
/// once: the record there names `b-1` and no session, no answer having named
/// the dial that landed it (the mutant that records the walk's session names
/// a writer the shell never heard from; the one that records nothing leaves a
/// `changes` read after the landing no way to name the page's burst).
#[test]
fn a_landing_the_read_found_records_its_burst_and_no_writer() {
    let g = ground();
    g.fake.op_lost_at.store(1, Ordering::SeqCst);
    *g.fake.text.lock().unwrap() = "a".into();
    let held = g.holds.send(&g.session, with_id(insert(DOC, json!(["a"]), g.fake.head()), "b-1"), None).answered().unwrap();
    assert_eq!(held["resp"], "held", "{held}");
    let at = g.fake.next_at.load(Ordering::SeqCst);
    *g.fake.rows.lock().unwrap() = vec![json!({"at": at, "op": "insert", "key": g.own_key(), "docs": [DOC]})];
    g.holds.probe("b-1");
    assert!(g.lines().is_empty() && g.fake.sends() == 1, "kept at its landing, sent once");
    assert_eq!(g.holds.written(&g.session, at), Some(Written { by: None, burst: Some("b-1".into()) }), "its burst, and no writer");
}

/// Checks that one principal's record names no session of another's.
///
/// A writer of principal 2's insert is acked through the one path: its
/// record names it, principal 1's lookup at that position answers none, and
/// principal 1's drafts read of the row names no writer and waits not at
/// all, though principal 2's next write stands out (the mutant that keys the
/// record by position board-wide hands principal 1's page a live session
/// reference of another principal's, which stands in for that session's
/// token). A merge row's write and a shot of principal 1's record their
/// session and no burst.
#[test]
fn a_principals_record_names_no_session_of_anothers() {
    let g = ground();
    let other = writer_of(&g, 2, "1.0.2", "8e");
    let ack = g.holds.send(&other, insert("1.0.2.0.1", json!(["c"]), g.fake.head()), None).answered().unwrap();
    let at = ack["at"].as_u64().expect("an ack");
    assert_eq!(g.holds.written(&other, at), Some(Written { by: Some(other.reference.clone()), burst: None }), "its own principal's record names it");
    assert_eq!(g.holds.written(&g.session, at), None, "principal 1's lookup names no session of principal 2's");
    let out = g.holds.write_out(&other);
    let row = json!({"at": at, "op": "insert", "key": other.key().map(|key| key.to_hex()), "docs": ["1.0.2.0.1"]});
    let started = Instant::now();
    assert_eq!(g.holds.writers("b-1", 1, &[row]), [None], "no writer of another principal's named");
    assert!(started.elapsed() < WRITER_WAIT / 2, "principal 1's read waits on no write of principal 2's: {:?}", started.elapsed());
    drop(out);
    g.holds.note_arranged(&g.session, DOC, 70);
    g.holds.note_shot(&g.session, 71);
    for at in [70, 71] {
        assert_eq!(g.holds.written(&g.session, at), Some(Written { by: Some(g.session.reference.clone()), burst: None }), "at {at}: its session, no burst");
    }
}
