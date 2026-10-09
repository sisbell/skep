//! The HTTP side of the adapter: skepd speaks one request per connection
//! with `Connection: close` on every response (wire.md §Transport), so a
//! client is a `TcpStream`, one written-out request, and a read to the
//! daemon's close. Each exchange is bounded three ways — `IO_TIMEOUT`
//! bounds silence, a per-direction deadline bounds slowness, an answer cap
//! bounds size — so a dead, hung, paced or boundless peer ends in a clear
//! failure within a stated bound, never a stall or a memory bill. Every
//! error string names the daemon's origin, because these surface verbatim
//! as `isError` tool results.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// A dead local daemon answers `connection refused` instantly; this bounds
/// the pathological cases (unroutable address, filtered port).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The SILENCE bound: how long the answer's read waits for a byte, and the
/// request's write for the socket to take one; any byte renews it. A skepd
/// op is milliseconds even under fsync; ten seconds is headroom, not an
/// expected wait.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// The deadline on one direction of an exchange — the request out, or the
/// answer in — checked between socket calls: the answer's realized bound is
/// this plus one `IO_TIMEOUT`, a read in flight running to its socket
/// timeout, and the request's this plus one `WRITE_POLL`. Only this bounds
/// SLOWNESS: a peer that paces a byte per nine seconds renews `IO_TIMEOUT`
/// for as long as it likes, and this adapter is one thread. Never shorter
/// than an honest skepd's own bound: it reads a request, and writes an
/// answer, under its `TRANSFER_DEADLINE` plus one thirty-second socket
/// timeout (`server/http.rs`) — sixty seconds, after which it has abandoned
/// the transfer itself — and its handler's silence before the answer's
/// first byte is held to one `IO_TIMEOUT` already, or the read fails on
/// that bound first. Ten and sixty make seventy, so this cuts nothing skepd
/// would finish sending.
const TRANSFER_DEADLINE: Duration = Duration::from_secs(70);

/// How long the request's write sleeps while its socket takes no more, the
/// send buffer full: the granularity of its two bounds. An honest skepd
/// takes a request as fast as it reads, so an exchange pays this at most
/// once per refill of a send buffer of 128 KiB or more — 64 ms all told
/// for a frame at the 8 MiB cap, and nothing for one that fits the buffer.
const WRITE_POLL: Duration = Duration::from_millis(1);

/// The most bytes one answer may hold, head and body: skep-client's
/// `MAX_ANSWER_BYTES`, the frame routes' 8 MiB request cap with room for
/// the head (wire.md §Transport). skepd caps no `/op` answer — a
/// `retrieve_v` renders every delivered position's value, and one atom
/// copied to many positions renders as many times — so this is the
/// adapter's own bound on what a board can make it hold. An answer past it
/// is read no further; the agent narrows its request.
const MAX_ANSWER_BYTES: usize = 8 * 1024 * 1024 + 64 * 1024;

/// The method of one exchange — a type of its own, as skep-client's and
/// skep-resolve's dialers give it, so the method and the path, both text
/// on the request line, cannot trade places in a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    Get,
    Post,
}

impl Method {
    /// The method as the request line spells it.
    fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }
}

/// The daemon's origin, ready to dial: host, port, and the authority
/// (`host[:port]`) the `Host` header and error messages carry.
#[derive(Debug)]
pub struct Http {
    host: String,
    port: u16,
    authority: String,
}

impl Http {
    /// Parse `SKEPD_URL` as the daemon's origin: `http://host[:port]`, a
    /// bare trailing `/` allowed. The daemon speaks plain HTTP on loopback,
    /// so another scheme, a path, a port that is no `u16` or an empty host
    /// is a configuration mistake refused here, at startup. The host's own
    /// text is not checked: one that does not resolve fails the first
    /// exchange instead, at its `resolve:` step, naming the origin.
    pub fn parse(url: &str) -> Result<Http, String> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| format!("'{url}': only http:// URLs are supported"))?;
        let (authority, path) = match rest.split_once('/') {
            Some((a, p)) => (a, p),
            None => (rest, ""),
        };
        if !path.is_empty() {
            return Err(format!("'{url}': the daemon's origin takes no path"));
        }
        let (host, port) = match authority.rsplit_once(':') {
            // A colon inside the brackets is the IPv6 literal's own, not a
            // port's: `[::1]` takes the default port.
            Some((h, p)) if !p.ends_with(']') => {
                (h, p.parse::<u16>().map_err(|_| format!("'{url}': '{p}' is not a port"))?)
            }
            _ => (authority, 80),
        };
        // Bracketed IPv6 sheds its brackets for the resolver.
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() {
            return Err(format!("'{url}': missing host"));
        }
        Ok(Http { host: host.to_string(), port, authority: authority.to_string() })
    }

    /// The origin's authority as `SKEPD_URL` spelled it (`host[:port]`,
    /// brackets kept): the `Host` header's value, and the origin every
    /// error names.
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// One exchange: write the request, `headers` riding after `Host` and
    /// `Connection: close`, read to the daemon's close — each direction
    /// under `TRANSFER_DEADLINE`, the answer under `MAX_ANSWER_BYTES` — and
    /// return (status, body) whatever the status — what a status means is
    /// the caller's to judge, route by route. `Err` means skepd was not
    /// reached or did not answer within those bounds; its message names the
    /// origin and the failed step and never quotes the request, whose
    /// headers can carry a credential. It dials the first address `host`
    /// resolves to, and no other. `path` and each header's name and value
    /// go into the head as given: keeping CR and LF out of them is the
    /// caller's obligation, unchecked here. `daemon.rs` discharges it: its
    /// paths and header name are constants, and its one header value is a
    /// `Token`.
    pub fn exchange(
        &self,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
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
        let method = method.as_str();
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.authority
        );
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ));
        let deadline = Instant::now() + TRANSFER_DEADLINE;
        write_bounded(&mut stream, head.as_bytes(), deadline)
            .and_then(|()| write_bounded(&mut stream, body, deadline))
            .map_err(|e| self.fail("write", e))?;
        let raw = read_bounded(&mut stream, Instant::now() + TRANSFER_DEADLINE)
            .map_err(|e| self.fail("read", e))?;
        parse_response(&raw).map_err(|e| self.fail("response", e))
    }

    fn fail(&self, what: &str, e: impl std::fmt::Display) -> String {
        format!("skepd at http://{}: {what}: {e}", self.authority)
    }
}

/// `write_all` under `deadline`, the socket non-blocking for the length of
/// it. A blocking `write` cannot be held to a deadline checked between
/// calls: on BSD stacks the write timeout bounds each wait inside one call,
/// not the call, so a peer that keeps draining — however slowly — keeps one
/// call running until it has written everything it was handed. Non-blocking,
/// a call takes what fits at once, and this loop holds both bounds itself:
/// `IO_TIMEOUT` with no byte taken, `deadline` in all, each to within one
/// `WRITE_POLL`.
fn write_bounded(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    stream.set_nonblocking(true)?;
    let mut taken = Instant::now();
    while !bytes.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            let late = "request not taken within the transfer deadline";
            return Err(io::Error::new(io::ErrorKind::TimedOut, late));
        }
        if now >= taken + IO_TIMEOUT {
            let quiet = "request not taken: the peer stopped draining";
            return Err(io::Error::new(io::ErrorKind::TimedOut, quiet));
        }
        match stream.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                bytes = &bytes[n..];
                taken = Instant::now();
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(WRITE_POLL),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    stream.set_nonblocking(false)
}

/// The answer, to the daemon's close, under `deadline` and
/// `MAX_ANSWER_BYTES`: a peer that paces its bytes, or sends past the cap,
/// is refused rather than read for as long, or as far, as it likes. `raw`
/// never passes the cap and one read adds at most a chunk, so the sum
/// below cannot wrap.
fn read_bounded(stream: &mut TcpStream, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        if Instant::now() >= deadline {
            let late = "answer not delivered within the transfer deadline";
            return Err(io::Error::new(io::ErrorKind::TimedOut, late));
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(raw),
            Ok(n) if raw.len() + n > MAX_ANSWER_BYTES => {
                let past =
                    format!("answer past the {MAX_ANSWER_BYTES}-byte cap; narrow the request");
                return Err(io::Error::new(io::ErrorKind::InvalidData, past));
            }
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// Split status and body out of one complete HTTP response, recognized whole
/// or refused: the status line opens `HTTP/1.` (as skep-client's
/// `parse_head` requires), and `Content-Length` appears exactly once, as
/// `1*DIGIT` (the rule skepd's own reader holds requests to). skepd sends
/// exactly that on every answer this adapter asks for. The length is what
/// tells a connection that broke mid-body from a whole answer, so a head
/// that cannot state it is a failure, never relayed as skepd's document.
/// Bytes past the stated length are no part of the answer and are dropped.
fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| String::from("no header terminator"))?;
    let head =
        std::str::from_utf8(&raw[..sep]).map_err(|_| String::from("non-UTF-8 response head"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    if !status_line.starts_with("HTTP/1.") {
        return Err(String::from("not an HTTP/1.x status line"));
    }
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| String::from("malformed status line"))?;
    let mut content_length: Option<usize> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        if !name.trim().eq_ignore_ascii_case("Content-Length") {
            continue;
        }
        let value = value.trim();
        let digits = !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
        if content_length.is_some() || !digits {
            return Err(String::from("Content-Length repeated or not 1*DIGIT"));
        }
        content_length =
            Some(value.parse().map_err(|_| String::from("Content-Length past usize"))?);
    }
    let cl = content_length.ok_or_else(|| String::from("no Content-Length"))?;
    let body = &raw[sep + 4..];
    if body.len() < cl {
        return Err(format!("truncated body ({} of {cl} bytes)", body.len()));
    }
    Ok((status, body[..cl].to_vec()))
}

#[cfg(test)]
mod tests;
