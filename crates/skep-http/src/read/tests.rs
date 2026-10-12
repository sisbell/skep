//! THE READ's FENCE. Every case is read twice and the two answers held
//! equal: over a real loopback socket pair — a thread sends the case's
//! writes with a pause after each, then closes its sending half — and over
//! [`Writes`], the same writes handed to the reader one read apiece, the
//! in-process equivalent. The equal answers show the scripted reads are the
//! socket's own; the scripted run is the one that holds a read's boundary
//! where a case turns on one, which a socket on a busy machine may
//! coalesce away.

use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use super::*;

/// Caps no case below meets unless it means to.
const ROOMY: Limits = Limits { max_head: 1024, max_body: 1024 };

/// The pause after each write on the socket, so that on a quiet machine the
/// reader meets the case's writes one at a time; the answers are held equal
/// to the scripted run's whatever a busy one coalesces.
const PAUSE: Duration = Duration::from_millis(20);

/// THE PEER's WRITES, read as a socket reads them when each has landed
/// before the next: a read answers at most its buffer from the oldest write
/// not yet consumed and never reaches into the next one; after the last
/// write, `Ok(0)` — the peer's close — or the error the case ends on, once.
struct Writes {
    pending: VecDeque<Vec<u8>>,
    then: Option<io::Error>,
}

impl Writes {
    /// The writes, then the peer's close. A write of no bytes sends
    /// nothing, as on a socket.
    fn closing(writes: &[&[u8]]) -> Writes {
        Writes { pending: writes.iter().filter(|w| !w.is_empty()).map(|w| w.to_vec()).collect(), then: None }
    }

    /// The writes, then a read that fails with `error`.
    fn failing(writes: &[&[u8]], error: io::Error) -> Writes {
        Writes { then: Some(error), ..Writes::closing(writes) }
    }
}

impl Read for Writes {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(write) = self.pending.front_mut() else {
            return self.then.take().map_or(Ok(0), Err);
        };
        let n = write.len().min(buf.len());
        buf[..n].copy_from_slice(&write[..n]);
        write.drain(..n);
        if write.is_empty() {
            self.pending.pop_front();
        }
        Ok(n)
    }
}

/// The same writes over a real loopback socket pair: a thread connects,
/// sends each write with a [`PAUSE`] after it and closes its sending half;
/// this side accepts and reads, under a deadline no case waits out.
fn over_socket(writes: &[&[u8]], limits: Limits) -> Result<Option<Request>, Refused> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("a loopback port");
    let addr = listener.local_addr().expect("the port's address");
    let writes: Vec<Vec<u8>> = writes.iter().map(|w| w.to_vec()).collect();
    let peer = thread::spawn(move || {
        let mut stream = TcpStream::connect(addr).expect("the peer connects");
        for write in &writes {
            // A refusal may end the read before the last write lands: that
            // write's failure is the case's own, not the suite's.
            if stream.write_all(write).is_err() {
                return;
            }
            thread::sleep(PAUSE);
        }
        let _ = stream.shutdown(Shutdown::Write);
    });
    let (mut stream, _) = listener.accept().expect("the peer is accepted");
    stream.set_read_timeout(Some(Duration::from_secs(30))).expect("a read deadline");
    let answer = read_request(&mut stream, limits);
    peer.join().expect("the peer's thread");
    answer
}

/// One case's answer: read over the socket and over the scripted writes,
/// the two held equal.
fn answer(writes: &[&[u8]], limits: Limits) -> Result<Option<Request>, Refused> {
    let scripted = read_request(&mut Writes::closing(writes), limits);
    assert_eq!(over_socket(writes, limits), scripted, "the socket's read and the scripted read answer alike");
    scripted
}

/// The refusal that says `words`.
fn malformed(words: &str) -> Result<Option<Request>, Refused> {
    Err(Refused::Malformed(words.to_string()))
}

/// A head `len` bytes long with no terminator in it: a request line and one
/// header, `X-Pad`, padded with `a`.
fn unterminated(len: usize) -> Vec<u8> {
    let mut head = b"GET / HTTP/1.1\r\nX-Pad: ".to_vec();
    head.resize(len, b'a');
    head
}

/// T1: a GET with no body reads its method, its path, its query split at
/// the FIRST `?`, its headers in the order sent, each trimmed, and an empty
/// body; `header` finds a name case-insensitively, the first of two, and
/// `query_value` the first member named. A target with no `?` has no
/// query, and `HTTP/1.0` is read as `HTTP/1.1` is.
#[test]
fn t1_a_get_reads_its_line_and_its_headers_in_order_with_no_body() {
    let get = b"GET /bridge/events?provider=abc&x=1&provider=def?g HTTP/1.1\r\nHost: 127.0.0.1:8742\r\nOrigin: http://localhost:5173\r\nX-Twice: one\r\nx-twice:  two \r\n\r\n";
    let req = answer(&[get], ROOMY).expect("read").expect("a request");
    let pairs = |pairs: &[(&str, &str)]| -> Vec<(String, String)> { pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect() };
    let expected = Request {
        method: "GET".into(),
        path: "/bridge/events".into(),
        query: Some("provider=abc&x=1&provider=def?g".into()),
        headers: pairs(&[("Host", "127.0.0.1:8742"), ("Origin", "http://localhost:5173"), ("X-Twice", "one"), ("x-twice", "two")]),
        body: Vec::new(),
    };
    assert_eq!(req, expected);
    assert_eq!(req.header("HOST"), Some("127.0.0.1:8742"), "a name is read case-insensitively");
    assert_eq!(req.header("x-TWICE"), Some("one"), "the first of a name sent twice");
    assert_eq!(req.header("Cookie"), None);
    assert_eq!(req.query_value("provider"), Some("abc"), "the first member named");
    assert_eq!(req.query_value("x"), Some("1"));
    assert_eq!(req.query_value("g"), None, "a `?` past the first is the query's own");
    let bare = answer(&[b"GET /bridge/log HTTP/1.0\r\n\r\n"], ROOMY).expect("read").expect("a request");
    assert_eq!(bare.path, "/bridge/log");
    assert_eq!(bare.query, None);
    assert!(bare.headers.is_empty() && bare.body.is_empty(), "{bare:?}");
}

/// T2: a POST whose body arrives SPLIT — the head's write carrying the
/// body's first bytes, the rest a later write with bytes past the declared
/// length behind it — reads the whole body, cut to its `Content-Length`;
/// a head's write holding more than the body is cut the same.
#[test]
fn t2_a_body_split_across_writes_is_read_whole_and_cut_to_its_length() {
    let head_and_some = b"POST /bridge/op HTTP/1.1\r\nContent-Length: 11\r\n\r\nhello";
    let req = answer(&[head_and_some, b" worldPAST THE LENGTH"], ROOMY).expect("read").expect("a request");
    assert_eq!(req.method, "POST");
    assert_eq!(req.body, b"hello world");
    let req = answer(&[b"POST /bridge/op HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcdef"], ROOMY).expect("read").expect("a request");
    assert_eq!(req.body, b"abc");
}

/// The head's terminator split across two writes is found where it
/// straddles them: the scan resumes three bytes back, never at the old end.
#[test]
fn a_terminator_split_across_writes_is_found_across_the_seam() {
    let whole = b"GET /bridge/shapes HTTP/1.1\r\nHost: h\r\n\r\n";
    for seam in 1..4 {
        let (first, second) = whole.split_at(whole.len() - seam);
        let req = answer(&[first, second], ROOMY).expect("read").expect("a request");
        assert_eq!((req.path.as_str(), req.header("Host")), ("/bridge/shapes", Some("h")), "the last {seam} byte(s) of the terminator in the second write");
    }
}

/// T3: the three closes — before any byte, `None`, a port probe answered
/// with nothing; inside the head and inside the body, each refused in its
/// own words.
#[test]
fn t3_a_close_before_any_byte_is_none_and_one_inside_the_head_or_the_body_is_refused() {
    assert_eq!(answer(&[], ROOMY), Ok(None));
    assert_eq!(answer(&[b"GET /bridge/log HTTP/1.1\r\nHost: h\r\n"], ROOMY), malformed("the connection closed inside the request head"));
    assert_eq!(answer(&[b"POST /bridge/op HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc"], ROOMY), malformed("the connection closed inside the request body"));
}

/// A read that FAILS — a socket's deadline passing, a reset: before any
/// byte, `None`, as a close is; inside the head or the body, refused in the
/// error's own words after `read: `. Scripted alone, since a socket's error
/// words are its platform's.
#[test]
fn a_failed_read_is_none_before_any_byte_and_refused_in_its_own_words_after() {
    let failing = |writes: &[&[u8]]| read_request(&mut Writes::failing(writes, io::Error::new(ErrorKind::TimedOut, "the deadline passed")), ROOMY);
    assert_eq!(failing(&[]), Ok(None));
    assert_eq!(failing(&[b"GET /bridge/log HT"]), malformed("read: the deadline passed"));
    assert_eq!(failing(&[b"POST /bridge/op HTTP/1.1\r\nContent-Length: 4\r\n\r\nab"]), malformed("read: the deadline passed"));
}

/// T4: every refusal of the subset in its words, one case apiece: a head
/// past `max_head` with no terminator in it — where a head of exactly
/// `max_head` bytes, still unterminated, reads on to its terminator, the
/// cap being passed only when exceeded; a head not UTF-8; a request line
/// with no target, with no version, with a version neither 1.1 nor 1.0 or
/// a token past it; a method not in uppercase; a header line with no
/// colon; `Content-Length` twice; a `Content-Length` not all digits, empty,
/// or past `usize`; and a `Transfer-Encoding`.
#[test]
fn t4_every_refusal_of_the_subset_is_said_in_its_words() {
    let capped = Limits { max_head: 32, max_body: 1024 };
    let read_on = answer(&[&unterminated(32), b"\r\n\r\n"], capped).expect("a head at the cap reads on").expect("a request");
    assert_eq!(read_on.header("X-Pad"), Some("aaaaaaaaa"));
    assert_eq!(answer(&[&unterminated(33)], capped), malformed("the request head exceeds the 32-byte cap"));
    let refused = |head: &[u8], words: &str| assert_eq!(answer(&[head], ROOMY), malformed(words), "{}", String::from_utf8_lossy(head));
    refused(b"GET /\xff HTTP/1.1\r\n\r\n", "the request head is not UTF-8");
    refused(b"GET\r\n\r\n", "the request line lacks a target");
    refused(b"GET /bridge/log\r\n\r\n", "the request line lacks an HTTP version");
    refused(b"GET /bridge/log HTTP/2.0\r\n\r\n", "a malformed request line");
    refused(b"GET /bridge/log HTTP/1.1 extra\r\n\r\n", "a malformed request line");
    refused(b"get /bridge/log HTTP/1.1\r\n\r\n", "a malformed method token");
    refused(b"GET /bridge/log HTTP/1.1\r\nHost h\r\n\r\n", "a malformed header line `Host h`");
    refused(b"POST /bridge/op HTTP/1.1\r\nContent-Length: 1\r\ncontent-length: 1\r\n\r\nx", "Content-Length given twice");
    refused(b"POST /bridge/op HTTP/1.1\r\nContent-Length: 1x\r\n\r\n", "a bad Content-Length `1x`");
    refused(b"POST /bridge/op HTTP/1.1\r\nContent-Length: \r\n\r\n", "a bad Content-Length ``");
    refused(b"POST /bridge/op HTTP/1.1\r\nContent-Length: 99999999999999999999999\r\n\r\n", "a bad Content-Length `99999999999999999999999`");
    refused(b"POST /bridge/op HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", "chunked request bodies are unsupported; send Content-Length");
}

/// T5: the body's cap is the CALLER's, and inclusive: a declared length one
/// past it is `TooLarge` with that cap echoed — at the head, before any of
/// the body is waited for, as none follows here — and a declared length AT
/// it is read whole; a cap of nothing admits no body but an empty one.
#[test]
fn t5_a_body_past_the_callers_cap_is_too_large_and_one_at_it_is_read() {
    let sixteen = Limits { max_head: 1024, max_body: 16 };
    assert_eq!(answer(&[b"POST /bridge/op HTTP/1.1\r\nContent-Length: 17\r\n\r\n"], sixteen), Err(Refused::TooLarge { declared: 17, cap: 16 }));
    let at_cap = answer(&[b"POST /bridge/op HTTP/1.1\r\nContent-Length: 16\r\n\r\n0123456789abcdef"], sixteen).expect("read").expect("a request");
    assert_eq!(at_cap.body, b"0123456789abcdef");
    let nothing = Limits { max_head: 1024, max_body: 0 };
    assert_eq!(answer(&[b"POST /bridge/op HTTP/1.1\r\nContent-Length: 1\r\n\r\nx"], nothing), Err(Refused::TooLarge { declared: 1, cap: 0 }));
    let empty = answer(&[b"POST /bridge/op HTTP/1.1\r\nContent-Length: 0\r\n\r\n"], nothing).expect("read").expect("a request");
    assert!(empty.body.is_empty());
}
