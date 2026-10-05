//! MEDIA LANE D — THE FETCH over the wire (`media.md` Op inventory 3; the
//! register M-I2 (a)–(d), (g), M-I3 (b), M-I7 (a), (b); the ruled v1 cut,
//! whole-file serving): `GET /blob?i=` and `HEAD /blob?i=` serve a picture's
//! whole file by the I-address of its cell, gated by the read's own
//! predicate, checked against the cell before the first byte, under a permit
//! pool, the requester re-resolved mid-stream; the blind document's cell is
//! named and served no byte; every refusal is a reply of the route's own.
//!
//! Each test names the register's clause it holds: M-I2 (a) GATED BY THE
//! READ's PREDICATE; M-I2 (g) THE ENTITLEMENT RE-RESOLVED MID-STREAM; M-I3
//! (b) THE BYTES SERVED ARE THE BYTES THE CELL NAMES; M-I7 (a) THE BYTES
//! INERT AT THE FETCH; M-I7 (b) BOUNDED BY A POOL, NEVER A QUEUE.

use std::path::Path;
use std::time::Duration;

use serde_json::Value;

use crate::common;
use crate::media::{seed_pre_fence_draft, unknown_schema_value};
use common::*;

/// The fetch's wire, as the fixture pins it.
fn fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/it/fixtures/media/fetch.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("read fetch.json")).expect("JSON")
}

/// The I-address of content ordinal `n` in document `doc`.
fn i_at(doc: &str, n: u64) -> String {
    format!("{doc}.0.1.{n}")
}

/// A fetch answer's body as the rejection document it carries.
fn body_json(body: &[u8]) -> Value {
    json(body)
}

/// The I-address the cell lands at for published member `member` — the read
/// by identity as `token` over the member and its EDITION (its trunk),
/// since a `publish` re-inserts a draft's cell as FRESH identity in the
/// edition's own I-space (PUB-2.40), which the member version arranges: the
/// published I-address a guest fetches is the edition's, never the private
/// draft's. The first position holding a value is the cell's.
fn cell_i(port: u16, token: &str, member: &str) -> String {
    let edition = member.rsplit_once('.').map(|(h, _)| h.to_string()).unwrap_or_default();
    for probe in [member.to_string(), edition] {
        if probe.is_empty() {
            continue;
        }
        let fr = op(port, Some(token), &format!(r#"{{"doc":"{probe}","op":"content_frontier"}}"#));
        let frontier: u64 = match expect_resp(&fr, "frontier")["next"].as_str() {
            Some(n) => n.parse().expect("a count"),
            None => continue,
        };
        let v = op(
            port,
            Some(token),
            &format!(
                r#"{{"op":"retrieve_i","spans":[{{"start":"{}","width":"{}"}}]}}"#,
                i_at(&probe, 1),
                frontier.max(1)
            ),
        );
        if let Some(it) = expect_resp(&v, "i_delivery")["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|it| !it["value"].is_null())
        {
            return it["at"].as_str().expect("an address").to_string();
        }
    }
    panic!("no cell found at or under the edition of {member}")
}

/// THE SHAPE (step 0) and THE GATE's rejection statuses (step 2): a
/// malformed `i` is `400 malformed_blob`; the M10 read-by-identity's
/// rejection rides M10's own envelope under the HTTP status its code takes
/// on this byte route — `withheld` a draft to a guest is 403, an
/// unregistered document 404, a non-element `i` a shape 400 — the body the
/// `{"resp":"rejected"}` document, never a transport `{"error"}`.
#[test]
fn the_shape_and_the_gates_rejection_take_their_statuses() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let fx = fixture();
    assert_eq!(fx["path"].as_str(), Some(BLOB_FETCH));
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    // Step 0: the query's own shape — absent, empty, unparseable, wrong name.
    for (q, why) in
        [("", "absent"), ("i=", "empty"), ("i=1..2", "unparseable"), ("x=1.1", "wrong name")]
    {
        let raw = format!(
            "GET {BLOB_FETCH}?{q} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        let (bytes, _) = fetch_bytes(port, &raw);
        let (st, _, body) = parse_response(&bytes, why);
        assert_eq!(st, 400, "{why}: {}", String::from_utf8_lossy(&body));
        assert_eq!(body_json(&body)["error"].as_str(), Some("malformed_blob"), "{why}");
    }
    // A document address names no element position: a shape refusal.
    let (st, _, body) = fetch(port, Some(&owner), CLAIMANT_DOC1);
    assert_eq!(
        (st, body_json(&body)["error"].as_str()),
        (400, Some("malformed_blob")),
        "a document is no element"
    );
    // An unregistered element under the owner's own account: the read by
    // identity holds no value there, so the fetch is `no_value`, not a
    // registration refusal — the gate is the read, which mints nothing.
    let (st, _, body) = fetch(port, Some(&owner), &i_at("1.0.1.0.99", 1));
    assert_eq!(
        (st, body_json(&body)["error"].as_str()),
        (404, Some("no_value")),
        "{}",
        String::from_utf8_lossy(&body)
    );
    // A draft's cell withheld to the guest and to a stranger: 403 withheld,
    // for GET and HEAD alike, the body M10's — no Content-Range, no ETag.
    let bytes = b"the owner's private picture";
    put_whole(port, &owner, bytes);
    let draft = owner_draft(port, &owner);
    assert_eq!(insert_cell(port, &owner, &draft, bytes, bytes.len() as u64), "ok");
    let i = i_at(&draft, 1);
    let stranger = seat_stranger(port, 971);
    for token in [None, Some(stranger.session.as_str())] {
        for head in [false, true] {
            let (st, headers, body) = fetch_full(port, head, token, &i, &[]);
            assert_eq!(st, 403, "{head} {token:?}: {}", String::from_utf8_lossy(&body));
            if head {
                assert!(body.is_empty(), "a HEAD refusal carries no body");
            } else {
                assert_eq!(body_json(&body)["code"].as_str(), Some("withheld"), "{token:?}");
                assert_eq!(
                    body_json(&body)["site"]["addr"].as_str(),
                    Some(draft.as_str()),
                    "the home"
                );
            }
            assert!(
                header(&headers, "ETag").is_none() && header(&headers, "Content-Range").is_none()
            );
            assert_eq!(header(&headers, "Cache-Control"), Some("no-store"), "class-varying");
            assert_eq!(header(&headers, "Vary"), Some("Skepd-Session"));
        }
    }
    sd.shutdown();
}

/// M-I2 (a), M-I3 (b) — THE OWNER's AND THE GRANTEE's FETCH: the draft's
/// cell, admitted to the owner and to a grantee the owner shared it with,
/// answers 200 with the file whole — the bytes the cell names, byte for byte
/// the bytes PUT — and the gate is the same predicate the read takes. A
/// `no_value` position and a `not_a_cell` value each answer their 404.
#[test]
fn the_owner_and_the_grantee_fetch_the_whole_file_and_absences_are_named() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bytes = seeded_bytes(20_000, 7);
    put_whole(port, &owner, &bytes);
    let draft = owner_draft(port, &owner);
    assert_eq!(insert_cell(port, &owner, &draft, &bytes, bytes.len() as u64), "ok");
    expect_resp(&insert_text(port, &owner, &draft, 2, "plain words"), "ack_addr");
    let i = i_at(&draft, 1);
    // The owner: the whole file.
    let (st, headers, body) = fetch(port, Some(&owner), &i);
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(body, bytes, "the bytes the cell names, byte for byte");
    assert_eq!(
        header(&headers, "Content-Length").and_then(|v| v.parse::<usize>().ok()),
        Some(bytes.len())
    );
    // The grantee: shared the draft, admitted the same.
    let grantee = seat_stranger(port, 972);
    let grantee_signed =
        hire(port, &signed, CLAIMANT_DOC1, &grantee.account, 972, &distinct_key(72));
    deposit_grant(port, &signed, CLAIMANT_DOC1, &draft, Some(&grantee.account));
    let (st, _, body) = fetch(port, Some(&grantee_signed), &i);
    assert_eq!((st, &body), (200, &bytes), "the grantee reads the shared picture");
    // no_value: a position the draft never minted (the prose "plain words"
    // placed eleven per-byte values at 2.., so 99 is safely past the extent).
    let (st, _, body) = fetch(port, Some(&owner), &i_at(&draft, 99));
    assert_eq!((st, body_json(&body)["error"].as_str()), (404, Some("no_value")));
    // not_a_cell: the first prose position.
    let (st, _, body) = fetch(port, Some(&owner), &i_at(&draft, 2));
    assert_eq!((st, body_json(&body)["error"].as_str()), (404, Some("not_a_cell")));
    sd.shutdown();
}

/// M-I7 (a) — A PUBLISHED PICTURE TO THE GUEST: the cell published into an
/// edition is fetched by the guest, 200, every header the fetch promises
/// present and every one it must not carry absent; `HEAD` is that head and
/// no body; a `Range` header is IGNORED (the whole file, 200, no 206, no
/// Content-Range).
#[test]
fn a_published_picture_is_served_to_the_guest_with_every_header() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bytes = seeded_bytes(5_000, 11);
    put_whole(port, &owner, &bytes);
    let draft = owner_draft(port, &owner);
    assert_eq!(insert_cell(port, &owner, &draft, &bytes, bytes.len() as u64), "ok");
    let edition = published_edition(port, &signed);
    let member = acked_addr(&op(
        port,
        Some(&signed),
        &publish_frame(&edition, None, Some(&draft), &[run(&draft, &i_at(&draft, 1), 1)]),
    ));
    let i = cell_i(port, &owner, &member);
    let fx = fixture();
    let (st, headers, body) = fetch(port, None, &i);
    assert_eq!(
        st,
        200,
        "the guest reads the published picture: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(body, bytes);
    assert_eq!(header(&headers, "Content-Type"), fx["content_type"].as_str());
    assert_eq!(
        header(&headers, "Content-Length").and_then(|v| v.parse::<usize>().ok()),
        Some(bytes.len())
    );
    assert_eq!(header(&headers, "X-Content-Type-Options"), Some("nosniff"));
    assert_eq!(header(&headers, "Content-Security-Policy"), Some("sandbox"));
    assert_eq!(header(&headers, "Cache-Control"), Some("no-store"));
    assert_eq!(header(&headers, "Vary"), Some("Skepd-Session"));
    assert_eq!(header(&headers, "Access-Control-Allow-Origin"), Some("*"));
    assert_eq!(header(&headers, "Connection"), Some("close"));
    assert!(header(&headers, "ETag").is_none() && header(&headers, "Content-Range").is_none());
    assert!(header(&headers, "Last-Modified").is_none());
    // HEAD: the same head, no body.
    let (st, headers, body) = fetch_head(port, None, &i);
    assert_eq!(st, 200);
    assert_eq!(
        header(&headers, "Content-Length").and_then(|v| v.parse::<usize>().ok()),
        Some(bytes.len()),
        "HEAD declares the length"
    );
    assert!(body.is_empty(), "HEAD carries no body");
    assert_eq!(header(&headers, "Content-Type"), fx["content_type"].as_str());
    // A Range header is ignored: the whole file, 200, never 206.
    let (st, headers, rbody) = fetch_full(port, false, None, &i, &[("Range", "bytes=0-10")]);
    assert_eq!((st, &rbody), (200, &bytes), "Range is ignored: the whole file");
    assert!(header(&headers, "Content-Range").is_none());
    sd.shutdown();
}

/// M-I3 (b) — THE FILE CHECKED AGAINST THE CELL: a picture whose file is
/// gone from the store is `blob_missing`; one whose file is the wrong bytes
/// under the right name, or the wrong length, is `blob_damaged` — each
/// carrying `hash` and `size`, the cell's own, and no byte served.
#[test]
fn a_missing_or_damaged_file_is_named_and_no_byte_is_served() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let bytes = b"a picture whose file the store loses";
    put_whole(port, &owner, bytes);
    let draft = owner_draft(port, &owner);
    assert_eq!(insert_cell(port, &owner, &draft, bytes, bytes.len() as u64), "ok");
    let i = i_at(&draft, 1);
    let hex_name = blob_hex(bytes);
    let path = dir.path().join("blobs").join("blake3").join(&hex_name);
    // The file gone: blob_missing, with the cell's hash and size.
    std::fs::remove_file(&path).expect("remove the blob file");
    let (st, _, body) = fetch(port, Some(&owner), &i);
    assert_eq!((st, body_json(&body)["error"].as_str()), (404, Some("blob_missing")));
    assert_eq!(body_json(&body)["hash"].as_str(), Some(hex_name.as_str()));
    assert_eq!(body_json(&body)["size"].as_u64(), Some(bytes.len() as u64));
    // The wrong bytes under the right name, same length: blob_damaged.
    let mut wrong = bytes.to_vec();
    wrong[0] ^= 0xff;
    std::fs::write(&path, &wrong).expect("plant wrong bytes");
    let (st, _, body) = fetch(port, Some(&owner), &i);
    assert_eq!(
        (st, body_json(&body)["error"].as_str()),
        (404, Some("blob_damaged")),
        "wrong bytes"
    );
    // The wrong length: blob_damaged before any byte is hashed.
    std::fs::write(&path, b"short").expect("plant a short file");
    let (st, _, body) = fetch(port, Some(&owner), &i);
    assert_eq!(
        (st, body_json(&body)["error"].as_str()),
        (404, Some("blob_damaged")),
        "wrong length"
    );
    sd.shutdown();
}

/// The blind kind at the fetch: a blind document's cell — placed in a draft
/// (the door admits it, no deposit) — is `blind_cell` at the fetch, 404,
/// with no file, lease or index entry read; a value naming a media kind
/// under no schema this build reads is `unknown_cell_schema` (seeded through
/// a pre-fence draft, as the door refuses one at its own insert).
#[test]
fn a_blind_cell_is_named_and_an_unknown_schema_halts() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A pre-fence draft holding a value naming the picture kind under no
    // pinned schema — the door would refuse one at an insert.
    let halt = {
        let sd = spawn(dir.path());
        sd.shutdown();
        seed_pre_fence_draft(
            dir.path(),
            CLAIMANT_PRINCIPAL,
            CLAIMANT_ACCOUNT,
            unknown_schema_value().as_bytes(),
        )
    };
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    // A blind cell in the owner's draft: admitted, served no byte.
    let draft = owner_draft(port, &owner);
    expect_resp(
        &op(port, Some(&owner), &atom_frame(&draft, 1, &blind_cell_of(&[0xcd; 32]))),
        "ack_addr",
    );
    let (st, _, body) = fetch(port, Some(&owner), &i_at(&draft, 1));
    assert_eq!(
        (st, body_json(&body)["error"].as_str()),
        (404, Some("blind_cell")),
        "{}",
        String::from_utf8_lossy(&body)
    );
    // The pre-fence halt value: unknown_cell_schema.
    let (st, _, body) = fetch(port, Some(&owner), &i_at(&halt, 1));
    assert_eq!((st, body_json(&body)["error"].as_str()), (404, Some("unknown_cell_schema")));
    sd.shutdown();
}

/// M-I7 (b) — BOUNDED BY A POOL: with every fetch permit held through the
/// test hook, a fetch of a published picture — past its gate and
/// classification — is `503 fetch_busy`, retry-class; a permit released, it
/// is served.
#[test]
fn the_fetch_pool_bounds_the_route() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bytes = b"a small published picture";
    put_whole(port, &owner, bytes);
    let draft = owner_draft(port, &owner);
    assert_eq!(insert_cell(port, &owner, &draft, bytes, bytes.len() as u64), "ok");
    let edition = published_edition(port, &signed);
    let member = acked_addr(&op(
        port,
        Some(&signed),
        &publish_frame(&edition, None, Some(&draft), &[run(&draft, &i_at(&draft, 1), 1)]),
    ));
    let i = cell_i(port, &owner, &member);
    let held: Vec<_> = std::iter::repeat_with(|| sd.daemon().try_hold_fetch_permit())
        .take_while(Option::is_some)
        .flatten()
        .collect();
    assert_eq!(
        held.len(),
        fixture()["pool"].as_u64().unwrap() as usize,
        "the pool's whole count held"
    );
    let (st, _, body) = fetch(port, None, &i);
    assert_eq!(
        (st, body_json(&body)["error"].as_str()),
        (503, Some("fetch_busy")),
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert!(body_json(&body)["detail"].as_str().is_some_and(|d| d.contains("retry")));
    drop(held);
    let (st, _, body) = fetch(port, None, &i);
    assert_eq!(st, 200, "a released permit serves: {}", String::from_utf8_lossy(&body));
    assert_eq!(body.as_slice(), bytes);
    sd.shutdown();
}

/// M-I2 (g) — THE ENTITLEMENT RE-RESOLVED MID-STREAM, THE TIME INTERVAL: a
/// fetch held between chunks by the seam, its session closed and the media
/// clock advanced past the time interval, is cut by a RESET at the next
/// re-check — the whole file never delivered. REPORTED: the bytes received
/// before the cut.
#[test]
fn a_closed_session_cuts_the_stream_at_the_time_interval() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    // A file of several chunks, under the byte interval, so only the clock
    // can make the re-check due.
    let bytes = seeded_bytes(200_000, 13);
    put_whole(port, &owner, &bytes);
    let draft = owner_draft(port, &owner);
    assert_eq!(insert_cell(port, &owner, &draft, &bytes, bytes.len() as u64), "ok");
    let i = i_at(&draft, 1);
    skepd::Daemon::hold_the_fetch_stream();
    let mut stream = FetchStream::open(port, Some(&owner), &i);
    stream.read_until_body(4096, Duration::from_secs(10));
    // Close the session, move the clock past the time interval, release.
    close_session(port, &owner);
    let interval = fixture()["recheck_interval_ms"].as_u64().unwrap();
    sd.daemon().advance_media_clock_ms(interval + 1);
    skepd::Daemon::release_the_fetch_stream();
    let end = stream.read_to_end();
    let got = stream.body().len();
    assert!(got < bytes.len(), "the whole file was NOT delivered: {got} of {}", bytes.len());
    assert_ne!(end, StreamEnd::Eof, "the stream is cut, not cleanly closed at the full length");
    println!("time interval: {got} of {} bytes delivered before the cut ({end:?})", bytes.len());
    sd.shutdown();
}

/// M-I2 (g), s6-E1 (a) — THE BYTE INTERVAL: a fetch whose session is closed
/// while the stream runs is cut at the byte interval — the clock unmoved, so
/// only the bytes written could make the re-check due — short of a file
/// larger than that interval. REPORTED: the bytes received.
#[test]
fn a_closed_session_cuts_the_stream_at_the_byte_interval() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let interval = fixture()["recheck_bytes"].as_u64().unwrap();
    // A file past the byte interval by one chunk.
    let bytes = seeded_bytes(interval as usize + 64 * 1024, 17);
    put_whole(port, &owner, &bytes);
    let draft = owner_draft(port, &owner);
    assert_eq!(insert_cell(port, &owner, &draft, &bytes, bytes.len() as u64), "ok");
    let i = i_at(&draft, 1);
    skepd::Daemon::hold_the_fetch_stream();
    let mut stream = FetchStream::open(port, Some(&owner), &i);
    stream.read_until_body(4096, Duration::from_secs(10));
    // Close the session and release: the clock unmoved, the re-check becomes
    // due only once the byte interval's worth has been written.
    close_session(port, &owner);
    skepd::Daemon::release_the_fetch_stream();
    let end = stream.read_to_end();
    let got = stream.body().len();
    assert!(got < bytes.len(), "the whole file was NOT delivered: {got} of {}", bytes.len());
    assert_ne!(end, StreamEnd::Eof, "the stream is cut, not cleanly closed at the full length");
    assert!(
        got <= interval as usize + 128 * 1024,
        "cut at the byte interval, not far past it: {got} of {}",
        bytes.len()
    );
    println!("byte interval: {got} of {} bytes delivered before the cut ({end:?})", bytes.len());
    sd.shutdown();
}

/// THE FETCH's OPS ON `/op-at` (wire.md §Reading history): `retrieve_i` and
/// `content_frontier` are reads, so each answers as of a committed position —
/// the live answer on `/op` and the historical one at the head agree — and
/// `content_frontier` answers a draft's frontier to its owner, `withheld` to
/// a guest, `doc_not_registered` for an unregistered document.
#[test]
fn retrieve_i_and_content_frontier_live_and_as_of_a_position() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = draft_with(port, &owner, "abc");
    let i = i_at(&draft, 1);
    // retrieve_i, live.
    let live = op(
        port,
        Some(&owner),
        &format!(r#"{{"op":"retrieve_i","spans":[{{"start":"{i}","width":"3"}}]}}"#),
    );
    let items = expect_resp(&live, "i_delivery")["items"].as_array().expect("items").clone();
    assert_eq!(items.len(), 3, "one item per position");
    assert_eq!(items[0]["value"]["content"].as_str(), Some("a"), "the first byte: {live}");
    assert_eq!(items[0]["at"].as_str(), Some(i.as_str()));
    // content_frontier, live: three values placed, the frontier is four.
    let fr = op(port, Some(&owner), &format!(r#"{{"doc":"{draft}","op":"content_frontier"}}"#));
    assert_eq!(expect_resp(&fr, "frontier")["next"].as_str(), Some("4"), "{fr}");
    // As of the head: the same answers, through /op-at (common's own helper,
    // the (status, document) pair).
    let head = head_position(port);
    let (st, hist) = op_at(
        port,
        Some(&owner),
        head,
        &format!(r#"{{"op":"retrieve_i","spans":[{{"start":"{i}","width":"3"}}]}}"#),
    );
    assert_eq!((st, hist["resp"].as_str()), (200, Some("i_delivery")));
    assert_eq!(hist["items"], Value::Array(items), "the historical read agrees with the live one");
    let (st, hist) =
        op_at(port, Some(&owner), head, &format!(r#"{{"doc":"{draft}","op":"content_frontier"}}"#));
    assert_eq!((st, hist["next"].as_str()), (200, Some("4")), "the frontier as of the head");
    // content_frontier's gate: withheld to a guest, doc_not_registered for none.
    let g = op(port, None, &format!(r#"{{"doc":"{draft}","op":"content_frontier"}}"#));
    assert_withheld(&g, &draft);
    let u = op(port, Some(&owner), r#"{"doc":"1.0.1.0.99","op":"content_frontier"}"#);
    assert_eq!(verdict(&u), "doc_not_registered", "{u}");
    sd.shutdown();
}
