//! THE LOG the page's gate reads (the dev provider record §3.4; the
//! structure record §6.3's class 5 — "every call the page made reached the
//! provider, and the provider's dials to the daemon were these"): one entry
//! per CALL the page made — its name, its bytes in and out, its time and
//! whether it answered a result or a refusal — and one per DIAL the shell
//! made — the method, the path, the status, the sizes, the time — in one
//! sequence, so a driver reads which calls caused which dials. NO TOKEN, NO
//! HEADER AND NO BODY is kept: the dial's record is the request line's two
//! words and the answer's status, which is what a count needs and nothing a
//! capture could use. [`LoggingDialer`] is the one `Dialer` every board of
//! the shell dials through — `PlainHttp` behind the record — so no dial
//! escapes the log.

use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use skep_client::dial::{DialError, Dialer, Headers, Method, PlainHttp, Request, RequestHead, Response, StreamedResponse};
use skep_client::Origin;

/// How a CALL the log records was answered, as its entry's `outcome`
/// spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// The outcome as the log spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            CallOutcome::Result => "result",
            CallOutcome::Refused => "refused",
            CallOutcome::Stream => "stream",
            CallOutcome::Canned => "canned",
        }
    }
}

/// The log: the entries in arrival order, each numbered by its place.
#[derive(Debug, Default)]
pub struct Log {
    entries: Mutex<Vec<Value>>,
}

impl Log {
    /// An empty log.
    pub fn new() -> Log {
        Log::default()
    }

    /// One entry placed, numbered and stamped under the lock that places
    /// it: its `seq` is its index, so the order the entries are read in is
    /// the order they were numbered in.
    fn push(&self, mut entry: Value) {
        let mut entries = self.entries.lock().expect("the log's lock");
        entry["seq"] = Value::from(entries.len() as u64);
        entry["at_ms"] = Value::from(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0));
        entries.push(entry);
    }

    /// One CALL the page made: `call` its name, `bytes_in` the request's
    /// body, `bytes_out` the answer's, `elapsed` its time, `outcome` how it
    /// was answered.
    pub fn call(&self, call: &str, bytes_in: usize, bytes_out: usize, elapsed: Duration, outcome: CallOutcome) {
        self.push(json!({
            "kind": "call",
            "call": call,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "ms": elapsed.as_millis() as u64,
            "outcome": outcome.as_str(),
        }));
    }

    /// One DIAL the shell made: the method and the path (its query cut off
    /// — a query may name a position and nothing else, but the record keeps
    /// the route alone), the status answered or the transport's refusal,
    /// the sizes and the time. Made by [`LoggingDialer`] alone, so every
    /// dial is the shell's own.
    pub(crate) fn dial(&self, method: Method, path: &str, status: Option<u16>, bytes_in: usize, bytes_out: usize, elapsed: Duration) {
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

    /// Every entry, in order.
    pub fn entries(&self) -> Vec<Value> {
        self.entries.lock().expect("the log's lock").clone()
    }

    /// How many dials the log holds.
    #[cfg(test)]
    pub fn dials(&self) -> usize {
        self.entries.lock().expect("the log's lock").iter().filter(|e| e["kind"] == "dial").count()
    }

    /// How many calls the log holds.
    #[cfg(test)]
    pub fn calls(&self) -> usize {
        self.entries.lock().expect("the log's lock").iter().filter(|e| e["kind"] == "call").count()
    }
}

/// THE ONE DIALER of the shell: `PlainHttp` — which writes no `Origin`
/// header, so the daemon's bare set is met by the shell and never by the
/// page — behind the dial log. Cloned into every board; one record.
#[derive(Debug, Clone)]
pub struct LoggingDialer {
    inner: PlainHttp,
    log: Arc<Log>,
}

impl LoggingDialer {
    /// The plain arm behind `log`.
    pub fn new(log: Arc<Log>) -> LoggingDialer {
        LoggingDialer { inner: PlainHttp::new(), log }
    }
}

impl Dialer for LoggingDialer {
    fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, DialError> {
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

    /// The entries are numbered in arrival order, a dial's path loses its
    /// query, and the counts read each kind.
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

    /// Entries placed from many threads at once are numbered by their
    /// place: every `seq` is its index in the order `entries` reads.
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
}
