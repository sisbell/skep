//! THE WRITE's FENCE: every answer's exact bytes, written onto a real
//! loopback socket and read back to the writer's close, and held equal to
//! what the same call writes into a `Vec` — the in-process run.

use std::io::{self, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};

use super::*;

/// What `write` puts on the wire: written onto a loopback socket and read
/// back to the close, and held equal to what it writes into a `Vec`.
fn written(write: impl Fn(&mut dyn Write) -> io::Result<()>) -> Vec<u8> {
    let mut in_process = Vec::new();
    write(&mut in_process).expect("the write into a Vec");
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("a loopback port");
    let mut peer = TcpStream::connect(listener.local_addr().expect("the port's address")).expect("the peer connects");
    let (mut stream, _) = listener.accept().expect("the peer is accepted");
    write(&mut stream).expect("the write onto the socket");
    drop(stream);
    let mut wire = Vec::new();
    peer.read_to_end(&mut wire).expect("read to the writer's close");
    assert_eq!(wire, in_process, "the socket carries what the Vec holds");
    wire
}

/// A caller's headers: the dev provider's origin pair.
fn headers() -> Vec<(String, String)> {
    vec![("Access-Control-Allow-Origin".into(), "http://localhost:5173".into()), ("Vary".into(), "Origin".into())]
}

/// T6: one whole response is, byte for byte, its status line with the
/// reason, the caller's headers in the order given, the content type where
/// one is named, the body's length, `Cache-Control: no-store` and
/// `Connection: close`, a blank line, and the body.
#[test]
fn t6_a_response_is_its_status_line_its_headers_in_order_its_length_and_the_close() {
    let refused = written(|w| write_response(w, 403, &headers(), Some("text/plain; charset=utf-8"), b"refused: origin\n"));
    assert_eq!(
        String::from_utf8_lossy(&refused),
        "HTTP/1.1 403 Forbidden\r\nAccess-Control-Allow-Origin: http://localhost:5173\r\nVary: Origin\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 16\r\nCache-Control: no-store\r\nConnection: close\r\n\r\nrefused: origin\n"
    );
    let empty = written(|w| write_response(w, 204, &headers(), None, b""));
    assert_eq!(
        String::from_utf8_lossy(&empty),
        "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: http://localhost:5173\r\nVary: Origin\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
    );
}

/// T6: the head alone with no length known — a body streamed after it —
/// has no `Content-Length` line, and nothing follows its blank line.
#[test]
fn t6_a_head_with_no_length_has_no_content_length_line() {
    let head = written(|w| write_head(w, 200, &headers(), Some("application/octet-stream"), None));
    assert_eq!(
        String::from_utf8_lossy(&head),
        "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: http://localhost:5173\r\nVary: Origin\r\nContent-Type: application/octet-stream\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
    );
}

/// T6: each status the dev provider answers carries its reason phrase, and
/// any other carries `OK` — in the status line as in the table.
#[test]
fn t6_each_status_carries_its_reason_and_any_other_is_ok() {
    for (status, phrase) in [(200, "OK"), (204, "No Content"), (400, "Bad Request"), (403, "Forbidden"), (404, "Not Found"), (413, "Payload Too Large"), (201, "OK"), (500, "OK")] {
        assert_eq!(reason(status), phrase, "{status}");
        let line = written(|w| write_head(w, status, &[], None, None));
        assert!(line.starts_with(format!("HTTP/1.1 {status} {phrase}\r\n").as_bytes()), "{}", String::from_utf8_lossy(&line));
    }
}

/// One whole response is flushed behind its body: a buffered writer holds
/// none of it back.
#[test]
fn a_whole_response_is_flushed_behind_its_body() {
    let mut buffered = BufWriter::new(Vec::new());
    write_response(&mut buffered, 200, &[], Some("application/json"), b"{}").expect("the write");
    assert!(buffered.get_ref().ends_with(b"\r\n\r\n{}"), "{}", String::from_utf8_lossy(buffered.get_ref()));
}
