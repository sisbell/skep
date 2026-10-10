use super::*;

/// A refusal is a status AND a name together: the body is built through
/// `obj`, the sorting device (byte-deterministic whatever backs
/// serde_json's map) and the status comes from the same table the name
/// does, so the wire.md pairing is checked rather than repeated.
#[test]
fn refusals_pair_their_status_with_their_name() {
    let r = refuse(TransportError::PayloadTooLarge, Some("too big"));
    assert_eq!(r.status, 413);
    assert_eq!(
        String::from_utf8(r.bytes().to_vec()).expect("json"),
        r#"{"detail":"too big","error":"payload_too_large"}"#
    );
    let r =
        refuse_with(TransportError::BeyondHead, vec![("head", Value::Number(12u64.into()))]);
    assert_eq!(r.status, 400);
    assert_eq!(
        String::from_utf8(r.bytes().to_vec()).expect("json"),
        r#"{"error":"beyond_head","head":12}"#
    );
}

/// wire.md §HTTP status codes, BOTH columns — the discipline
/// [`code_name`](crate::codec) already gives M10's sixty rejection
/// codes. The table is transcribed by hand for the reason
/// [`crate::fuzz_support::TRANSPORT_ERRORS`] is: one read out of the
/// code under test would agree with whatever that code says.
///
/// Four of these — `internal_panic`, `history_io`, `history_corrupt`,
/// `no_journal` — are reachable from no test in the tree (three need
/// at-rest journal damage, one cannot arise under this daemon's
/// `Fsync` configuration), so their spelling and their status are
/// watched here and nowhere else.
#[test]
fn every_transport_error_pairs_its_documented_name_with_its_documented_status() {
    let table: Vec<(TransportError, &'static str, u16)> = vec![
        (TransportError::MalformedSessionRequest, "malformed_session_request", 400),
        (TransportError::MalformedChallenge, "malformed_challenge", 400),
        (TransportError::MalformedOpAt, "malformed_op_at", 400),
        (TransportError::WriteAtHistory, "write_at_history", 400),
        (TransportError::BeyondHead, "beyond_head", 400),
        (TransportError::NotAPosition, "not_a_position", 400),
        (TransportError::MalformedAt, "malformed_at", 400),
        (TransportError::MalformedChanges, "malformed_changes", 400),
        (TransportError::MalformedHttp, "malformed_http", 400),
        (TransportError::NoSuchEndpoint, "no_such_endpoint", 404),
        (TransportError::MethodNotAllowed, "method_not_allowed", 405),
        (TransportError::HistoryReclaimed, "history_reclaimed", 410),
        (TransportError::PayloadTooLarge, "payload_too_large", 413),
        (TransportError::InternalPanic, "internal_panic", 500),
        (TransportError::HistoryIo, "history_io", 500),
        (TransportError::HistoryCorrupt, "history_corrupt", 500),
        (TransportError::NoJournal, "no_journal", 500),
        (TransportError::HistoryBusy, "history_busy", 503),
        (TransportError::ScanBusy, "scan_busy", 503),
        (TransportError::WriteBusy, "write_busy", 503),
        (TransportError::MalformedBlob, "malformed_blob", 400),
        (TransportError::UploadRefused, "upload_refused", 403),
        (TransportError::NoUpload, "no_upload", 404),
        (TransportError::UploadHeld, "upload_held", 409),
        (TransportError::UploadOffset, "upload_offset", 409),
        (TransportError::UploadLength, "upload_length", 400),
        (TransportError::DepositRefused, "deposit_refused", 507),
        (TransportError::BlobIo, "blob_io", 500),
        (TransportError::IndexRebuilding, "index_rebuilding", 503),
        (TransportError::UploadBusy, "upload_busy", 503),
        (TransportError::NoValue, "no_value", 404),
        (TransportError::NotACell, "not_a_cell", 404),
        (TransportError::UnknownCellSchema, "unknown_cell_schema", 404),
        (TransportError::BlindCell, "blind_cell", 404),
        (TransportError::BlobMissing, "blob_missing", 404),
        (TransportError::BlobDamaged, "blob_damaged", 404),
        (TransportError::FetchBusy, "fetch_busy", 503),
    ];
    for &(err, name, status) in &table {
        assert_eq!(err.name(), name, "wire name drifted for {err:?}");
        assert_eq!(err.status(), status, "{name} must be answered with {status}");
        assert!(reason_phrase(status).is_some(), "{name}'s {status} has no reason phrase");
        // The one builder every refusal goes through takes both from
        // the error, so the pairing a client dispatches on is checked
        // where it is produced rather than only where it is declared.
        let r = refuse(err, None);
        assert_eq!(r.status, status, "{name}: the reply's status");
        let body: Value = serde_json::from_slice(r.bytes()).expect("json");
        assert_eq!(body["error"].as_str(), Some(name), "{name}: the reply's body");
        // The fuzz oracle's list is the other hand transcription of
        // this column; a name in one and not the other is a drift.
        assert!(
            crate::fuzz_support::TRANSPORT_ERRORS.contains(&name),
            "{name} is answerable but absent from the fuzz oracle's list"
        );
    }
    // Both transcriptions of wire.md's error column, measured against
    // each other. A NEW variant is caught by the compiler at `name`
    // and `status`; this catches one that reaches the wire without
    // reaching either list. The `+ 2` is the handshake's PAIR, neither
    // a `TransportError` variant — both are built at their own site per
    // AUTH-6.5, [`refuse_handshake`]: `session_rejected`, the 401, and
    // `prefix_blocked`, the 403 that is its one exception. The oracle's
    // list names both because wire.md's error column does; no fuzz
    // daemon is supplied a blocked-prefix list, so the second is a name
    // no fuzz target is answered today.
    for handshake_name in ["session_rejected", "prefix_blocked"] {
        assert!(
            crate::fuzz_support::TRANSPORT_ERRORS.contains(&handshake_name),
            "{handshake_name} is answerable but absent from the fuzz oracle's list"
        );
    }
    #[cfg(feature = "observe")]
    assert_eq!(
        table.len() + 2,
        crate::fuzz_support::TRANSPORT_ERRORS.len(),
        "the two hand transcriptions of wire.md's error column disagree in length"
    );
}

/// The statuses answered outside [`TransportError`] have their phrases
/// too: the handshake's pair, built at its own site, and the success
/// replies' 204 and 200.
#[test]
fn every_status_outside_the_transport_errors_has_a_reason_phrase() {
    use crate::auth::session::SessionRejected;
    let record = crate::codec::wire_address("1.0.1.0.7.1").expect("a record's address");
    let rejected = refuse_handshake(&HandshakeRefusal::Rejected(SessionRejected));
    let blocked = refuse_handshake(&HandshakeRefusal::Blocked { record });
    for status in [rejected.status, blocked.status, Reply::preflight().status, 200] {
        assert!(reason_phrase(status).is_some(), "{status} has no reason phrase");
    }
}

/// The blob family's preflight names the four methods the family
/// dispatches and keeps the other two headers the common preflight
/// carries; the common preflight is unchanged — the wire of every other
/// path byte-identical to before the family.
#[test]
fn the_blob_preflight_names_the_familys_methods_and_the_common_one_is_unmoved() {
    let common = Reply::preflight();
    let blob = Reply::preflight_blob();
    assert_eq!(common.headers[0], ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"));
    assert_eq!(
        blob.headers[0],
        ("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
    );
    assert_eq!(common.headers[1..], blob.headers[1..]);
    assert_eq!(blob.status, 204);
    assert!(blob.body.is_none());
}

/// The fetch's preflight names its two methods and keeps the other two
/// headers the common preflight carries; the fetch's refusals: M10's
/// rejection in M10's envelope under the code's status, the store's
/// two carrying the blob the cell names, the halt's face, every other
/// step's token under its status.
#[test]
fn the_fetch_preflight_and_each_refusals_status_and_body() {
    let fetch = Reply::preflight_fetch();
    assert_eq!(fetch.headers[0], ("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS"));
    assert_eq!(fetch.headers[1..], Reply::preflight().headers[1..]);
    assert_eq!((fetch.status, fetch.body.is_none()), (204, true));
    let home = crate::codec::wire_address("1.0.1.0.2").expect("a document");
    let withheld = Rejection::classified(
        OpKind::RetrieveI,
        RejectCode::Withheld,
        Some(FaultSite { addr: Some(home), ..FaultSite::default() }),
    );
    let r = refuse_fetch(FetchRefusal::Rejected(withheld));
    assert_eq!(r.status, 403);
    assert_eq!(
        String::from_utf8(r.bytes().to_vec()).expect("json"),
        r#"{"code":"withheld","disposition":"reorder","op":"retrieve_i","resp":"rejected","site":{"addr":"1.0.1.0.2"}}"#
    );
    let unregistered =
        Rejection::classified(OpKind::RetrieveI, RejectCode::DocNotRegistered, None);
    assert_eq!(refuse_fetch(FetchRefusal::Rejected(unregistered)).status, 404);
    let shape = Rejection::classified(OpKind::RetrieveI, RejectCode::TooManyItems, None);
    assert_eq!(refuse_fetch(FetchRefusal::Rejected(shape)).status, 400);
    let named = NamedBlob { hash: "ab".repeat(32), size: 5 };
    let r = refuse_fetch(FetchRefusal::BlobMissing(named.clone()));
    assert_eq!(r.status, 404);
    assert_eq!(
        String::from_utf8(r.bytes().to_vec()).expect("json"),
        format!(r#"{{"error":"blob_missing","hash":"{}","size":5}}"#, "ab".repeat(32))
    );
    let r = refuse_fetch(FetchRefusal::BlobDamaged(named));
    assert_eq!(r.status, 404);
    assert!(String::from_utf8_lossy(r.bytes()).contains(r#""error":"blob_damaged""#));
    let r = refuse_fetch(FetchRefusal::UnknownCellSchema);
    let body: Value = serde_json::from_slice(r.bytes()).expect("json");
    assert_eq!(body["detail"].as_str(), Some(UNKNOWN_CELL_SCHEMA_FACE));
    assert_eq!(refuse_fetch(FetchRefusal::Busy).status, 503);
    assert_eq!(refuse_fetch(FetchRefusal::Shape("i: x".into())).status, 400);
    assert_eq!(refuse_fetch(FetchRefusal::BlindCell).status, 404);
    assert_eq!(refuse_fetch(FetchRefusal::NoValue).status, 404);
    assert_eq!(refuse_fetch(FetchRefusal::NotACell).status, 404);
}

/// The `scan_busy` refusal's exact body: a transport refusal (no `resp`,
/// no `code`) at 503, naming the op it refused beside the detail — the
/// bytes wire.md shows.
#[test]
fn scan_busy_names_the_op_in_a_transport_refusal() {
    let r = refuse_scan_busy(OpKind::CountFtt);
    assert_eq!(r.status, 503);
    assert_eq!(
        String::from_utf8(r.bytes().to_vec()).expect("json"),
        r#"{"detail":"all class-scan permits are in use; retry shortly","error":"scan_busy","op":"count_ftt"}"#
    );
}

/// The `write_busy` refusal's exact body (the write permit pool): a
/// transport refusal in `scan_busy`'s shape — no `resp`, no `code` — at
/// 503, naming the op it refused beside the detail — the bytes wire.md
/// shows for a write past the pool.
#[test]
fn write_busy_names_the_op_in_a_transport_refusal() {
    let r = refuse_write_busy(OpKind::Insert);
    assert_eq!(r.status, 503);
    assert_eq!(
        String::from_utf8(r.bytes().to_vec()).expect("json"),
        r#"{"detail":"all write permits are in use; retry shortly","error":"write_busy","op":"insert"}"#
    );
}

/// The body and the type naming it travel together: a bodiless reply
/// writes no content headers at all, and a bodied one writes both —
/// which is what makes "a 204 that silently drops its bytes" and
/// "`Content-Type:` with nothing after it" unconstructible rather than
/// merely unwritten.
#[test]
fn a_bodiless_reply_writes_no_content_headers() {
    let pre = Reply::preflight();
    assert!(pre.body.is_none(), "the preflight names no body");
    assert!(pre.bytes().is_empty());
    let json = Reply::json(200, obj(vec![("ok", Value::Bool(true))]));
    let body = json.body.as_ref().expect("a JSON reply names its body");
    assert_eq!(body.content_type, "application/json");
    assert_eq!(body.bytes, br#"{"ok":true}"#);
}

/// The preflight advertises exactly the header
/// [`read_request`](crate::server::http::read_request) reads.
/// The allow-list is one joined `&'static str`, so the header's name
/// necessarily appears in it as text rather than as the constant; this
/// is what keeps the two one decision. A header the preflight omits is
/// one a browser will not send, and that failure appears only
/// cross-origin, where this suite's own TCP clients never look.
#[test]
fn the_preflight_advertises_the_session_header_the_reader_reads() {
    let pre = Reply::preflight();
    let allow = pre
        .headers
        .iter()
        .find(|(k, _)| *k == "Access-Control-Allow-Headers")
        .map(|&(_, v)| v)
        .expect("the preflight names its allowed headers");
    assert!(allow.contains(SESSION_HEADER), "{allow} must name {SESSION_HEADER}");
}
