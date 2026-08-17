//! The HTTP side of the adapter: skepd speaks one request per connection
//! with `Connection: close` on every response (wire.md §Transport), so a
//! client is a `TcpStream`, one written-out request, and a read to EOF.
//! Connect/read/write timeouts make a dead or hung daemon a fast, clear
//! failure instead of a stall — every error string names the daemon
//! address, because these surface verbatim as `isError` tool results.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// A dead local daemon answers `connection refused` instantly; this bounds
/// the pathological cases (unroutable address, filtered port).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-call read/write bound. A skepd op is milliseconds even under fsync;
/// ten seconds is headroom, not an expected wait.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// One skepd endpoint: host, port, and the authority string for the `Host`
/// header and error messages.
pub struct Http {
    host: String,
    port: u16,
    authority: String,
}

/// Parse `SKEPD_URL`: `http://host[:port]` and nothing else — the daemon
/// speaks plain HTTP on loopback, so any other scheme or a path is a
/// configuration mistake worth refusing at startup.
pub fn parse_url(url: &str) -> Result<Http, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("'{url}': only http:// URLs are supported"))?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, p),
        None => (rest, ""),
    };
    if !path.is_empty() {
        return Err(format!("'{url}': the daemon address takes no path"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            (h, p.parse::<u16>().map_err(|_| format!("'{url}': '{p}' is not a port"))?)
        }
        None => (authority, 80),
    };
    // Bracketed IPv6 sheds its brackets for the resolver.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(format!("'{url}': missing host"));
    }
    Ok(Http { host: host.to_string(), port, authority: authority.to_string() })
}

impl Http {
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// One exchange: write the request, read to EOF (the daemon closes),
    /// return (status, body). `Err` means skepd was not reached or did not
    /// answer — the one condition the MCP side reports as `isError`.
    pub fn request(
        &self,
        method: &str,
        path: &str,
        session: Option<&str>,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), String> {
        let addr = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| self.fail("resolve", e))?
            .next()
            .ok_or_else(|| self.fail("resolve", "no addresses"))?;
        let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
            .map_err(|e| self.fail("connect", e))?;
        stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(|e| self.fail("socket", e))?;
        stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(|e| self.fail("socket", e))?;
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.authority
        );
        if let Some(tok) = session {
            req.push_str(&format!("Skepd-Session: {tok}\r\n"));
        }
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ));
        stream
            .write_all(req.as_bytes())
            .and_then(|()| stream.write_all(body))
            .map_err(|e| self.fail("write", e))?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).map_err(|e| self.fail("read", e))?;
        parse_response(&raw).map_err(|e| self.fail("response", e))
    }

    fn fail(&self, what: &str, e: impl std::fmt::Display) -> String {
        format!("skepd at http://{}: {what}: {e}", self.authority)
    }
}

/// Split status and body out of one complete HTTP response. The daemon
/// always sends `Content-Length`; checking it catches a connection that
/// broke mid-body, which would otherwise surface as mysteriously truncated
/// JSON.
fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| String::from("no header terminator"))?;
    let head =
        std::str::from_utf8(&raw[..sep]).map_err(|_| String::from("non-UTF-8 response head"))?;
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| String::from("malformed status line"))?;
    let mut content_length: Option<usize> = None;
    for line in head.split("\r\n").skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("Content-Length") {
                content_length = v.trim().parse().ok();
            }
        }
    }
    let mut body = raw[sep + 4..].to_vec();
    if let Some(cl) = content_length {
        if body.len() < cl {
            return Err(format!("truncated body ({} of {cl} bytes)", body.len()));
        }
        body.truncate(cl);
    }
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_forms() {
        let h = parse_url("http://127.0.0.1:8642").expect("default form");
        assert_eq!(h.authority(), "127.0.0.1:8642");
        let h = parse_url("http://localhost").expect("portless form");
        assert_eq!((h.host.as_str(), h.port), ("localhost", 80));
        let h = parse_url("http://127.0.0.1:8642/").expect("bare trailing slash");
        assert_eq!(h.port, 8642);
        for bad in [
            "https://127.0.0.1:8642",
            "127.0.0.1:8642",
            "http://",
            "http://:8642",
            "http://127.0.0.1:notaport",
            "http://127.0.0.1:8642/op",
        ] {
            assert!(parse_url(bad).is_err(), "'{bad}' must not parse");
        }
    }

    #[test]
    fn response_parse() {
        let (st, body) =
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").expect("parse");
        assert_eq!((st, body.as_slice()), (200, &b"{}"[..]));
        assert!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{}").is_err(),
            "a short body is a broken connection, not an answer"
        );
        assert!(parse_response(b"garbage").is_err());
    }
}
