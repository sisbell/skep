//! THE ADMISSION (the dev provider record §3.2; ruled P-4): the provider's
//! session is AMBIENT to any page in the person's browser that can reach
//! its port — "a page on any site the developer has open can POST to
//! `127.0.0.1:8742`" — so EVERY request is checked before any dial: the
//! peer is loopback (the socket's address); `Host` names the listen
//! address; `Origin` equals the ONE page origin the provider was started
//! for, exactly (a missing `Origin` on a non-preflight request is refused —
//! the page always sends one, and a `curl` from the gate passes the
//! header); and THE PER-RUN SECRET — the page carries it from its URL's
//! `?provider=` query and echoes it in the [`SECRET_HEADER`] on every call;
//! on the event stream alone it rides the URL's [`SECRET_QUERY`], since an
//! `EventSource` can send no custom header (unverified here). The secret
//! is named apart from a token: it admits a page to the provider and
//! grants nothing at the board. A refusal names the failed check and no
//! dial was made. The preflight (`OPTIONS`) is answered for the one origin
//! alone and carries no secret: a browser sends none on it.

use std::net::SocketAddr;

use super::http::Request;

/// The header the page echoes the secret in.
pub const SECRET_HEADER: &str = "Skep-Provider";

/// The query key the page's URL carries the secret under, and the event
/// stream's URL repeats.
pub const SECRET_QUERY: &str = "provider";

/// The one page origin, the secret, and the listen authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    pub page_origin: String,
    pub secret: String,
    /// `127.0.0.1:<port>` — what `Host` must name.
    pub host: String,
}

/// Which check a request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    Peer,
    Host,
    Origin,
    Secret,
}

impl Check {
    /// The check's name, as the refusal's body names it.
    pub fn name(self) -> &'static str {
        match self {
            Check::Peer => "peer",
            Check::Host => "host",
            Check::Origin => "origin",
            Check::Secret => "secret",
        }
    }
}

impl Admission {
    /// The preflight: the peer and the one origin.
    pub fn preflight(&self, req: &Request, peer: Option<SocketAddr>) -> Result<(), Check> {
        self.peer(peer)?;
        self.origin(req)
    }

    /// EVERY OTHER REQUEST: the peer, the host, the origin, the secret — in
    /// the header, or on the event stream's route in the query.
    pub fn admit(&self, req: &Request, peer: Option<SocketAddr>, secret_in_query: bool) -> Result<(), Check> {
        self.peer(peer)?;
        match req.header("Host") {
            Some(h) if h.eq_ignore_ascii_case(&self.host) => {}
            _ => return Err(Check::Host),
        }
        self.origin(req)?;
        let presented = req.header(SECRET_HEADER).or_else(|| secret_in_query.then(|| req.query_value(SECRET_QUERY)).flatten());
        match presented {
            Some(s) if s == self.secret => Ok(()),
            _ => Err(Check::Secret),
        }
    }

    fn peer(&self, peer: Option<SocketAddr>) -> Result<(), Check> {
        match peer {
            Some(a) if a.ip().is_loopback() => Ok(()),
            _ => Err(Check::Peer),
        }
    }

    fn origin(&self, req: &Request) -> Result<(), Check> {
        match req.header("Origin") {
            Some(o) if o == self.page_origin => Ok(()),
            _ => Err(Check::Origin),
        }
    }
}
