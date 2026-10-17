//! A fake board for this crate's unit tests.
//!
//! It is a [`Dialer`] answering each request by a closure the test writes,
//! keeping every request it serves beside the origin it was dialed at — so
//! a test pins what a composition sends, in what order, and what it makes
//! of each answer, with no daemon. A suite that needs the daemon itself
//! drives it through `tests/it`.

use std::sync::{Arc, Mutex};

use serde_json::Value;

use crate::board::Board;
use crate::dial::{DialError, Dialer, Headers, Request, RequestHead, Response, StreamedResponse};
use crate::origin::Origin;

/// The test's answer to one request.
type Reply = Box<dyn Fn(&Request) -> Response + Send + Sync>;

/// The fake: its answer, and every request it served, in order.
pub(crate) struct Fake {
    reply: Reply,
    pub(crate) sent: Mutex<Vec<(Origin, Request)>>,
}

impl Fake {
    /// Returns a fake answering each request by `reply`.
    pub(crate) fn new(reply: impl Fn(&Request) -> Response + Send + Sync + 'static) -> Arc<Fake> {
        Arc::new(Fake { reply: Box::new(reply), sent: Mutex::new(Vec::new()) })
    }

    /// Returns a fake that serves no request.
    ///
    /// Any request panics naming itself — the proof that a path makes no
    /// read.
    pub(crate) fn unread() -> Arc<Fake> {
        Fake::new(|req| panic!("this path makes no read, and it sent {} {}", req.method.as_str(), req.path))
    }

    /// Returns one line per request served, in order.
    ///
    /// Each is `METHOD path`, and for `/op` and `/op-at` the frame's `op`
    /// after it — the line `tests/it`'s recording dialer writes.
    ///
    /// # Panics
    ///
    /// Panics where the lock on the served requests is poisoned.
    pub(crate) fn log(&self) -> Vec<String> {
        let sent = self.sent.lock().unwrap();
        sent.iter()
            .map(|(_, req)| {
                let mut line = format!("{} {}", req.method.as_str(), req.path);
                if req.path == "/op" || req.path == "/op-at" {
                    line.push(' ');
                    line.push_str(frame(req)["op"].as_str().unwrap_or("?"));
                }
                line
            })
            .collect()
    }
}

impl Dialer for Fake {
    fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, DialError> {
        self.sent.lock().unwrap().push((origin.clone(), req.clone()));
        Ok((self.reply)(req))
    }

    fn stream(
        &self,
        _origin: &Origin,
        _head: &RequestHead,
        _body: &mut dyn std::io::Read,
        _on_interim: &mut dyn FnMut(&Headers),
    ) -> Result<StreamedResponse, DialError> {
        unreachable!("no read of a board streams")
    }
}

/// Returns the origin a fake board is dialed at.
///
/// # Panics
///
/// Panics if `http://127.0.0.1:8642` is not a canonical origin; it is one,
/// so the `expect` never fires.
pub(crate) fn origin() -> Origin {
    Origin::parse("http://127.0.0.1:8642").expect("a canonical origin")
}

/// Returns a board dialed at [`origin`] over `fake`.
pub(crate) fn board(fake: &Arc<Fake>) -> Board {
    Board::new(origin(), fake.clone())
}

/// Returns an answer of `status` carrying `body` as JSON.
pub(crate) fn json(status: u16, body: Value) -> Response {
    Response { status, headers: Headers::default(), body: body.to_string().into_bytes() }
}

/// Returns a `200` whose head carries the death signal (wire.md §Sessions).
pub(crate) fn closed() -> Response {
    Response { status: 200, headers: Headers(vec![("Skepd-Session".into(), "closed".into())]), body: b"{}".to_vec() }
}

/// Returns the frame a request carries.
///
/// It is an `/op` body whole, an `/op-at` body's inner `frame`, `Null` for a
/// request that carries none.
pub(crate) fn frame(req: &Request) -> Value {
    let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
    if req.path == "/op-at" {
        body["frame"].clone()
    } else {
        body
    }
}
