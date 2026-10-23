//! The log the page's gate reads: the page's calls and the shell's dials.
//!
//! As the dev provider record §3.4 and the structure record §6.3's class 5
//! draw it — "every call the page made reached the provider, and the
//! provider's dials to the daemon were these" — it holds one entry per call
//! the page made — its name, its bytes in and out, its time and whether it
//! answered a result or a refusal — and one per dial the shell made — the
//! method, the path, the status, the sizes, the time — in one sequence, so
//! a driver reads which calls caused which dials. No token, no header and
//! no body is kept: the dial's record is the request line's two words and
//! the answer's status, which is what a count needs and nothing a capture
//! could use. [`ShellDialer`] is the one `Dialer` every board of the shell
//! dials through — `PlainHttp` behind the record — so no dial escapes the
//! log, and the shell's stop is its one door: once the stop stands no dial
//! is made at all. The log is bounded: it keeps the latest
//! [`MAX_LOG_ENTRIES`], and a call under a name the bridge does not spell
//! is kept by its length, never its bytes.

use std::collections::VecDeque;
use std::fmt;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use skep_client::dial::{DialError, Dialer, Headers, Method, PlainHttp, Request, RequestHead, Response, StreamedResponse};
use skep_client::Origin;

/// How a logged call was answered, as its entry's `outcome` spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CallOutcome {
    /// The call's result.
    Result,
    /// A refusal.
    Refused,
    /// The bytes of a stream: `fetch`'s.
    Stream,
    /// A refusal the transport's own seam armed, answered without the shell.
    Canned,
}

impl CallOutcome {
    /// Returns the outcome as the log spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            CallOutcome::Result => "result",
            CallOutcome::Refused => "refused",
            CallOutcome::Stream => "stream",
            CallOutcome::Canned => "canned",
        }
    }
}

impl fmt::Display for CallOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The most entries the log keeps: the latest 2^16.
///
/// The oldest is dropped as each new one comes. A scenario the page's gate
/// runs before it reads the log is hundreds to a few thousand calls and
/// dials, so the log keeps every entry of one many times over; an entry is
/// a handful of short members, under a kilobyte held, so the log's bill
/// stays under 64 MiB however long the shell runs. Every entry's `seq`
/// counts on past the bound, so a reader sees where the kept entries start
/// by the first `seq` it reads.
const MAX_LOG_ENTRIES: usize = 1 << 16;

/// The log: its latest entries in arrival order.
///
/// It keeps 2^16 of them, the oldest dropped as each new one comes, each
/// numbered by its place in the whole sequence.
#[derive(Debug, Default)]
pub struct Log {
    entries: Mutex<Entries>,
}

/// The entries kept, and the number the next one takes.
#[derive(Debug, Default)]
struct Entries {
    kept: VecDeque<Value>,
    next_seq: u64,
}

impl Log {
    /// Returns an empty log.
    pub fn new() -> Log {
        Log::default()
    }

    /// Places one entry, numbered and stamped under the lock that places it.
    ///
    /// Its `seq` is its place in the whole sequence, so the order the
    /// entries are read in is the order they were numbered in; the oldest is
    /// dropped where the log holds [`MAX_LOG_ENTRIES`] already.
    ///
    /// # Panics
    ///
    /// Panics where the log's lock is poisoned.
    fn push(&self, mut entry: Value) {
        let mut entries = self.entries.lock().expect("the log's lock");
        entry["seq"] = Value::from(entries.next_seq);
        entries.next_seq += 1;
        entry["at_ms"] = Value::from(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0));
        if entries.kept.len() == MAX_LOG_ENTRIES {
            entries.kept.pop_front();
        }
        entries.kept.push_back(entry);
    }

    /// Records one call the page made.
    ///
    /// `call` is its name — one of the bridge's spellings (`CALLS`), and
    /// `'static`, so the bytes of a page's request cannot reach the log; a
    /// name of no call is `Log::unknown_call`'s, kept by its length alone —
    /// `bytes_in` the call's arguments and `bytes_out` its answer, each
    /// counted as compact JSON — a stream's `bytes_out` the bytes its body
    /// yielded — `elapsed` its time, `outcome` how it was answered.
    pub fn call(&self, call: &'static str, bytes_in: usize, bytes_out: usize, elapsed: Duration, outcome: CallOutcome) {
        self.push(json!({
            "kind": "call",
            "call": call,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "ms": elapsed.as_millis() as u64,
            "outcome": outcome.as_str(),
        }));
    }

    /// Records one call the page made under a name the bridge does not spell.
    ///
    /// Its refusal is `unknown_call`; it is kept as `<unknown>` with the
    /// name's length in bytes and never the name: the page chooses those
    /// bytes, and the log keeps what a count needs.
    pub(crate) fn unknown_call(&self, name_bytes: usize, bytes_in: usize, bytes_out: usize, elapsed: Duration) {
        self.push(json!({
            "kind": "call",
            "call": "<unknown>",
            "name_bytes": name_bytes,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "ms": elapsed.as_millis() as u64,
            "outcome": CallOutcome::Refused.as_str(),
        }));
    }

    /// Records one dial the shell made.
    ///
    /// It keeps the method and the path (its query cut off — a query names
    /// positions, addresses, a principal and a page's options, but the
    /// record keeps the route alone), the status answered or none where the
    /// transport refused, the sizes and the time. Private to the dialer's
    /// file, so [`ShellDialer`] alone writes one, and every dial the log
    /// keeps is one the shell made.
    fn dial(&self, method: Method, path: &str, status: Option<u16>, bytes_in: usize, bytes_out: usize, elapsed: Duration) {
        let route = path.split('?').next().unwrap_or(path);
        self.push(json!({
            "kind": "dial",
            "method": method.as_str(),
            "path": route,
            "status": status,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "ms": elapsed.as_millis() as u64,
        }));
    }

    /// Returns every entry kept, in order.
    ///
    /// # Panics
    ///
    /// Panics where the log's lock is poisoned.
    pub fn entries(&self) -> Vec<Value> {
        self.entries.lock().expect("the log's lock").kept.iter().cloned().collect()
    }

    /// Returns how many dials the log holds.
    ///
    /// # Panics
    ///
    /// Panics where the log's lock is poisoned.
    #[cfg(test)]
    fn dials(&self) -> usize {
        self.entries.lock().expect("the log's lock").kept.iter().filter(|e| e["kind"] == "dial").count()
    }

    /// Returns how many calls the log holds.
    ///
    /// # Panics
    ///
    /// Panics where the log's lock is poisoned.
    #[cfg(test)]
    fn calls(&self) -> usize {
        self.entries.lock().expect("the log's lock").kept.iter().filter(|e| e["kind"] == "call").count()
    }
}

/// The one dialer of the shell: `PlainHttp` behind the log and the stop.
///
/// `PlainHttp` writes no `Origin` header, so the daemon's bare set is met
/// by the shell and never by the page; it stands behind the dial log and
/// behind the shell's stop: once [`ShellDialer::stop`] is called
/// (`Shell::shutdown`), every dial is refused as one that made no
/// connection, recorded nowhere since none was made, so every loop that
/// dials — a feed read to a board's head, the library's drain beneath it —
/// ends at its next exchange, whatever a board answers. Cloned into every
/// board; one record, one stop.
#[derive(Debug, Clone)]
pub struct ShellDialer {
    inner: PlainHttp,
    log: Arc<Log>,
    stopping: Arc<AtomicBool>,
}

impl ShellDialer {
    /// Returns the plain arm behind `log`, dialing until [`ShellDialer::stop`].
    pub fn new(log: Arc<Log>) -> ShellDialer {
        ShellDialer { inner: PlainHttp::new(), log, stopping: Arc::new(AtomicBool::new(false)) }
    }

    /// Stops the dialer: the stop `Shell::shutdown` makes.
    ///
    /// From the call on, this dialer and every clone of it refuse every dial
    /// as one that made no connection.
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }

    /// Returns the refusal of a dial once the stop stands.
    ///
    /// It is a connection never made, which `hold`'s table reads as a burst
    /// that did not leave.
    fn stop_refusal(&self) -> Option<DialError> {
        self.stopping.load(Ordering::SeqCst).then(|| DialError::Connect("the shell is stopping: no dial is made".into()))
    }
}

impl Dialer for ShellDialer {
    fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, DialError> {
        if let Some(refused) = self.stop_refusal() {
            return Err(refused);
        }
        let started = Instant::now();
        let answer = self.inner.exchange(origin, req);
        let (status, out) = match &answer {
            Ok(r) => (Some(r.status), r.body.len()),
            Err(_) => (None, 0),
        };
        self.log.dial(req.method, &req.path, status, req.body.len(), out, started.elapsed());
        answer
    }

    fn stream(
        &self,
        origin: &Origin,
        head: &RequestHead,
        body: &mut dyn Read,
        on_interim: &mut dyn FnMut(&Headers),
    ) -> Result<StreamedResponse, DialError> {
        if let Some(refused) = self.stop_refusal() {
            return Err(refused);
        }
        let started = Instant::now();
        let answer = self.inner.stream(origin, head, body, on_interim);
        let status = answer.as_ref().ok().map(|r| r.status);
        let declared = head.content_length.unwrap_or(0) as usize;
        self.log.dial(head.method, &head.path, status, declared, 0, started.elapsed());
        answer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that the log numbers calls and dials in arrival order.
    ///
    /// A dial's path loses its query, and the counts read each kind.
    #[test]
    fn the_log_numbers_calls_and_dials_in_order() {
        let log = Log::new();
        log.call("boards", 2, 40, Duration::from_millis(3), CallOutcome::Result);
        log.dial(Method::Get, "/changes?since=4&limit=1", Some(200), 0, 120, Duration::from_millis(1));
        log.call("op", 50, 0, Duration::from_millis(9), CallOutcome::Refused);
        log.call("fetch", 30, 9, Duration::from_millis(2), CallOutcome::Stream);
        log.call("op", 30, 9, Duration::ZERO, CallOutcome::Canned);
        let entries = log.entries();
        assert_eq!(entries.len(), 5);
        assert_eq!((entries[0]["seq"].as_u64(), entries[1]["seq"].as_u64(), entries[2]["seq"].as_u64()), (Some(0), Some(1), Some(2)));
        assert_eq!((entries[1]["method"].as_str(), entries[1]["path"].as_str()), (Some("GET"), Some("/changes")));
        assert_eq!(entries[1]["status"], 200);
        let outcomes: Vec<&str> = entries.iter().filter_map(|e| e["outcome"].as_str()).collect();
        assert_eq!(outcomes, ["result", "refused", "stream", "canned"]);
        assert_eq!((log.calls(), log.dials()), (4, 1));
        assert!(entries.iter().all(|e| e["at_ms"].as_u64().is_some()));
    }

    /// Checks that an outcome displays as the log spells it.
    ///
    /// The four are four keys a transport counts its calls by.
    #[test]
    fn an_outcome_displays_as_the_log_spells_it() {
        let outcomes = [CallOutcome::Result, CallOutcome::Refused, CallOutcome::Stream, CallOutcome::Canned];
        for outcome in outcomes {
            assert_eq!(outcome.to_string(), outcome.as_str());
        }
        assert_eq!(outcomes.into_iter().collect::<std::collections::HashSet<_>>().len(), outcomes.len());
    }

    /// Checks that entries placed from many threads are numbered by place.
    ///
    /// Placed at once, every `seq` is its index in the order `entries` reads.
    #[test]
    fn concurrent_entries_are_numbered_by_their_place() {
        let log = Log::new();
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    for _ in 0..2_000 {
                        log.call("op", 1, 1, Duration::ZERO, CallOutcome::Result);
                    }
                });
            }
        });
        let entries = log.entries();
        assert_eq!(entries.len(), 16_000);
        let misplaced = entries.iter().enumerate().filter(|(i, e)| e["seq"].as_u64() != Some(*i as u64)).count();
        assert_eq!(misplaced, 0, "an entry's seq is its place");
    }

    /// Checks that the dialer records a dial no board answers all the same.
    ///
    /// The record keeps its method, its route without the query, no status,
    /// the body's size in and none out, and neither the token its header
    /// carries nor the body it sent (the mutants that record an answered dial
    /// alone, or keep the query, or count no body).
    #[test]
    fn the_dialers_record_keeps_the_route_and_sizes_answered_or_not() {
        let log = Arc::new(Log::new());
        let port = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
        let origin = Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        let token = "9f".repeat(16);
        let body = format!("{{\"op\":\"insert\",\"token\":\"{token}\"}}");
        let req = Request::post("/op?x=1", body.clone().into_bytes()).header("Skepd-Session", &token);
        assert!(ShellDialer::new(Arc::clone(&log)).exchange(&origin, &req).is_err(), "no board answers at a released port");
        let entries = log.entries();
        assert_eq!(entries.len(), 1, "the unanswered dial is recorded: {entries:?}");
        let entry = &entries[0];
        assert_eq!((entry["kind"].as_str(), entry["method"].as_str(), entry["path"].as_str()), (Some("dial"), Some("POST"), Some("/op")), "{entry}");
        assert!(entry["status"].is_null(), "{entry}");
        assert_eq!((entry["bytes_in"].as_u64(), entry["bytes_out"].as_u64()), (Some(body.len() as u64), Some(0)), "{entry}");
        let kept = entry.to_string();
        assert!(!kept.contains(&token) && !kept.contains("Skepd-Session") && !kept.contains("insert"), "{kept}");
    }

    /// Checks that the dialer records a streamed dial as an exchange is.
    ///
    /// A streamed dial — `/events` and `/blob` go out so — no board answers
    /// keeps its method, its route without the query, no status, the body
    /// its head declares in and none out — never the token its header
    /// carries nor the address its query names (the mutants that drop the
    /// streamed record, or count no declared body).
    #[test]
    fn the_dialers_streamed_record_keeps_the_route_and_sizes() {
        let log = Arc::new(Log::new());
        let port = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
        let origin = Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        let token = "9f".repeat(16);
        let head = RequestHead { method: Method::Get, path: "/blob?i=1.0.1.0.1.0.1.1".into(), headers: vec![("Skepd-Session".into(), token.clone())], content_length: Some(7) };
        let streamed = ShellDialer::new(Arc::clone(&log)).stream(&origin, &head, &mut std::io::empty(), &mut |_| {});
        assert!(streamed.is_err(), "no board answers at a released port");
        let entries = log.entries();
        assert_eq!(entries.len(), 1, "the unanswered stream is recorded: {entries:?}");
        let entry = &entries[0];
        assert_eq!((entry["kind"].as_str(), entry["method"].as_str(), entry["path"].as_str(), entry["status"].is_null()), (Some("dial"), Some("GET"), Some("/blob"), true), "{entry}");
        assert_eq!((entry["bytes_in"].as_u64(), entry["bytes_out"].as_u64()), (Some(7), Some(0)), "{entry}");
        let kept = entry.to_string();
        assert!(!kept.contains(&token) && !kept.contains("Skepd-Session") && !kept.contains("1.0.1.0.1"), "{kept}");
    }

    /// Checks that the dialer's record of an answered dial keeps its status.
    ///
    /// It keeps the board's status and the bytes its answer carried: an
    /// exchange answered `200` with five bytes is recorded `200` and five
    /// out, and a stream answered `200` and dropped unread `200` and none
    /// out — its body the reader's, never counted at the dial (the mutants
    /// that record an answer's size as none, or a stream's status as none).
    #[test]
    fn the_dialers_record_of_an_answered_dial_keeps_its_status_and_size() {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let origin = Origin::parse(&format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port())).unwrap();
        let board = std::thread::spawn(move || {
            for stream in listener.incoming().take(2) {
                let mut stream = stream.unwrap();
                let mut head = BufReader::new(stream.try_clone().unwrap());
                while head.read_line(&mut String::new()).unwrap() > 2 {}
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello").unwrap();
            }
        });
        let log = Arc::new(Log::new());
        let dialer = ShellDialer::new(Arc::clone(&log));
        assert_eq!(dialer.exchange(&origin, &Request::get("/health")).unwrap().body, b"hello");
        let head = RequestHead { method: Method::Get, path: "/blob?i=1.0.1.0.1.0.1.1".into(), headers: Vec::new(), content_length: None };
        drop(dialer.stream(&origin, &head, &mut std::io::empty(), &mut |_| {}).unwrap());
        board.join().unwrap();
        let records: Vec<(String, Option<u64>, Option<u64>)> =
            log.entries().iter().map(|e| (e["path"].as_str().unwrap_or("?").to_string(), e["status"].as_u64(), e["bytes_out"].as_u64())).collect();
        assert_eq!(records, [("/health".to_string(), Some(200), Some(5)), ("/blob".to_string(), Some(200), Some(0))]);
    }

    /// Checks that the stop dials nothing.
    ///
    /// Once a clone of the shell's dialer is stopped, an exchange and a
    /// stream through the dialer itself at a board listening — its backlog
    /// would take the connection — are each refused as connections never
    /// made, at once, the log recording none and the board never asked (the
    /// mutant that dials past the stop connects through the backlog and
    /// waits out the read bound, and a board that answers without end holds
    /// the shell's stop for good; the one whose clone stops alone leaves
    /// every other board of the shell dialing).
    #[test]
    fn a_stopped_dialer_makes_no_connection() {
        let log = Arc::new(Log::new());
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = Origin::parse(&format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port())).unwrap();
        let dialer = ShellDialer::new(Arc::clone(&log));
        dialer.clone().stop();
        let started = Instant::now();
        assert!(matches!(dialer.exchange(&origin, &Request::get("/health")), Err(DialError::Connect(_))));
        let head = RequestHead { method: Method::Get, path: "/events".into(), headers: Vec::new(), content_length: None };
        assert!(matches!(dialer.stream(&origin, &head, &mut std::io::empty(), &mut |_| {}), Err(DialError::Connect(_))));
        assert!(started.elapsed() < Duration::from_secs(1), "refused at once, not after {:?}", started.elapsed());
        assert!(log.entries().is_empty(), "no dial was made, so none is recorded: {:?}", log.entries());
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock), "the board was never asked");
    }

    /// Checks that the log is bounded.
    ///
    /// Past [`MAX_LOG_ENTRIES`] the oldest go, the latest [`MAX_LOG_ENTRIES`]
    /// kept in order, their `seq` counting on — so the first kept says where
    /// the kept entries start (the mutant that keeps every entry grows the
    /// log for the shell's life; the one that renumbers from the kept
    /// entries hides the drop).
    #[test]
    fn the_log_keeps_its_latest_entries() {
        let log = Log::new();
        for _ in 0..MAX_LOG_ENTRIES + 10 {
            log.call("probe", 2, 2, Duration::ZERO, CallOutcome::Result);
        }
        let entries = log.entries();
        assert_eq!(entries.len(), MAX_LOG_ENTRIES);
        assert_eq!((entries[0]["seq"].as_u64(), entries[MAX_LOG_ENTRIES - 1]["seq"].as_u64()), (Some(10), Some(MAX_LOG_ENTRIES as u64 + 9)));
    }

    /// Checks that a call the bridge does not spell is kept by its length.
    ///
    /// The name's length is kept and never its bytes, whatever the page sent.
    #[test]
    fn an_unknown_call_is_kept_by_its_length() {
        let log = Log::new();
        let name = "x".repeat(64 * 1024);
        log.unknown_call(name.len(), 2, 40, Duration::ZERO);
        let entry = &log.entries()[0];
        assert_eq!((entry["call"].as_str(), entry["name_bytes"].as_u64(), entry["outcome"].as_str()), (Some("<unknown>"), Some(64 * 1024), Some("refused")), "{entry}");
        assert!(entry.to_string().len() < 256, "the name is not kept: {} bytes", entry.to_string().len());
    }
}
