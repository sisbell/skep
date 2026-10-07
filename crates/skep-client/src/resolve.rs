//! The registry walk over this crate's one dialer (`client.md` §1.1's
//! dependency paragraph; RULED, owner 2026-10-04, ps3-2 and ps3-3): this crate
//! implements `skep_resolve::Transport` over its `Dialer`, so the shell dials
//! the board the registry names and never one the serving board's word names
//! (P25), and no cycle forms and no second trait is minted. The registry
//! answers the BOARD and never an account's set: the reader's verifier takes
//! no key set from it (`verify`'s row).

use std::sync::Arc;

use skep_address::Address;
use skep_resolve::{BoardError, GuestCost, Method, Resolution, SystemResolver, Transport, TransportError, Transports};

use crate::dial::{Dialer, Request};
use crate::origin::{NotCanonical, Origin};

/// `skep_resolve::Transport` over one `Dialer` at one origin.
pub struct DialerTransport {
    dialer: Arc<dyn Dialer>,
    origin: Origin,
}

impl std::fmt::Debug for DialerTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DialerTransport({})", self.origin)
    }
}

impl DialerTransport {
    /// The transport for `origin` through `dialer`.
    pub fn new(dialer: Arc<dyn Dialer>, origin: Origin) -> DialerTransport {
        DialerTransport { dialer, origin }
    }
}

impl Transport for DialerTransport {
    fn exchange(&self, method: Method, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        let method = match method {
            Method::Get => crate::dial::Method::Get,
            Method::Post => crate::dial::Method::Post,
        };
        let req = Request { method, path: path.to_string(), headers: Vec::new(), body: body.to_vec() };
        let resp = self.dialer.exchange(&self.origin, &req).map_err(|e| match e {
            crate::dial::DialError::NotHeld(s) => TransportError::NotHeld(s),
            crate::dial::DialError::Resolve(s) => TransportError::Resolve(s),
            crate::dial::DialError::Connect(s) | crate::dial::DialError::Timeout(s) => TransportError::Connect(s),
            crate::dial::DialError::Response(s) => TransportError::Response(s),
            crate::dial::DialError::TooLarge { cap } => TransportError::TooLarge { cap },
            other => TransportError::Io(other.to_string()),
        })?;
        Ok((resp.status, resp.body))
    }
}

/// The resolver's `Origin` as this crate's, where the two grammars agree —
/// both reproduce the daemon's (AUTH-4.2) — and [`NotCanonical`] where they
/// diverge.
impl TryFrom<&skep_resolve::Origin> for Origin {
    type Error = NotCanonical;

    fn try_from(o: &skep_resolve::Origin) -> Result<Origin, NotCanonical> {
        o.as_str().parse()
    }
}

/// A `Dial` for `skep_resolve::Mirror` over `dialer`: the shipped dial's
/// shape, this crate's transport behind it.
pub fn dial(dialer: Arc<dyn Dialer>) -> impl Fn(&skep_resolve::Origin) -> Result<Box<dyn Transport>, TransportError> {
    move |o: &skep_resolve::Origin| {
        let origin = Origin::try_from(o).map_err(|_| TransportError::Response(format!("{o} is not a canonical origin here")))?;
        Ok(Box::new(DialerTransport::new(dialer.clone(), origin)) as Box<dyn Transport>)
    }
}

/// THE GUEST-READING RESOLVE over the registry board at `registry`: a reader
/// with no mirror (REG-3.24, REG-3.33), its verdicts UNDETERMINABLE HERE —
/// `resolve(prefix)` → the board's endpoint as a named state, priced.
pub fn guest_resolve(dialer: Arc<dyn Dialer>, registry: &Origin, prefix: &Address) -> Result<(Resolution, GuestCost), BoardError> {
    let board = skep_resolve::Board::new(Box::new(DialerTransport::new(dialer, registry.clone())));
    skep_resolve::guest_resolve(&board, prefix, &SystemResolver, &Transports::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The resolver's origin converts where the two grammars agree, its text
    /// kept byte for byte.
    #[test]
    fn a_resolver_origin_converts_to_this_crates() {
        for text in ["http://127.0.0.1:8642", "https://board.example", "http://[::1]:8642"] {
            let theirs = skep_resolve::Origin::parse(text).expect("canonical to the resolver");
            assert_eq!(Origin::try_from(&theirs).map(|o| o.as_str().to_string()), Ok(text.to_string()));
        }
    }

    /// The transport is this crate's one dialer and adds nothing (P25): the
    /// resolver's request reaches the dialer at the transport's own origin —
    /// method, path and body as the resolver framed them, no header added —
    /// and the dialer's status and body come back as they were answered.
    #[test]
    fn the_transport_carries_the_resolvers_request_to_its_own_origin() {
        use crate::board::fake::Fake;
        use crate::dial::{Headers, Response};
        let fake = Fake::new(|_| Response { status: 418, headers: Headers(vec![("X-Board".into(), "registry".into())]), body: b"teapot".to_vec() });
        let registry = Origin::parse("https://registry.example").unwrap();
        let transport = DialerTransport::new(fake.clone(), registry.clone());
        assert_eq!(transport.exchange(Method::Post, "/op", br#"{"op":"health"}"#), Ok((418, b"teapot".to_vec())));
        assert_eq!(transport.exchange(Method::Get, "/health", b""), Ok((418, b"teapot".to_vec())));
        let sent = fake.sent.lock().unwrap();
        let expected = [
            Request { method: crate::dial::Method::Post, path: "/op".into(), headers: Vec::new(), body: br#"{"op":"health"}"#.to_vec() },
            Request { method: crate::dial::Method::Get, path: "/health".into(), headers: Vec::new(), body: Vec::new() },
        ];
        assert_eq!(sent.iter().map(|(origin, _)| origin).collect::<Vec<_>>(), [&registry, &registry]);
        assert_eq!(sent.iter().map(|(_, req)| req.clone()).collect::<Vec<_>>(), expected);
    }
}
