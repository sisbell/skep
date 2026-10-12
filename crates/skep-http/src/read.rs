//! THE READ: one request off the caller's stream — the head to its
//! terminator under [`Limits::max_head`], the request line and the header
//! lines parsed, the body to its `Content-Length` under
//! [`Limits::max_body`] — or the [`Refused`] the caller answers with.

use std::io::Read;

/// One request: the method, the path, the query, the headers and the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The method token as sent: one or more uppercase ASCII letters.
    pub method: String,
    /// The request target up to its first `?` — the whole target where it
    /// has none.
    pub path: String,
    /// The target after its first `?`, undecoded, or `None` where it has
    /// none.
    pub query: Option<String>,
    /// Every header line in the order sent, its name and its value trimmed;
    /// a name sent twice is held twice.
    pub headers: Vec<(String, String)>,
    /// The body: exactly the `Content-Length` declared, empty where none
    /// was.
    pub body: Vec<u8>,
}

impl Request {
    /// The first header named `name`, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The query member `key`'s value, where the query names one — the
    /// first, where it names several — undecoded.
    pub fn query_value(&self, key: &str) -> Option<&str> {
        self.query.as_deref()?.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == key).then_some(v)
        })
    }
}

/// A request refused at the HTTP layer: the subset's refusal, or a body
/// past the cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The request is outside the subset, or the connection closed or
    /// failed inside it: the words say which.
    Malformed(String),
    /// The declared body is past the caller's cap: refused at the head,
    /// before the reader waits on any of the body.
    TooLarge {
        /// The `Content-Length` the request declared.
        declared: usize,
        /// The caller's cap, [`Limits::max_body`].
        cap: usize,
    },
}

/// THE CAPS a request is read under: the caller's configuration, so the
/// subset holds no value of either and this type has no default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The head's cap, in bytes, judged before each read: a head still
    /// without its terminator once more than this has arrived is refused,
    /// and the read that completes a head may carry it past the cap.
    pub max_head: usize,
    /// The body's cap, in bytes, inclusive: a declared `Content-Length`
    /// above it is [`Refused::TooLarge`], and one at it is read.
    pub max_body: usize,
}

/// THE READ: the head to its terminator under the cap, the body to its
/// `Content-Length` under its cap; `None` for a clean close before any
/// byte, or a read that fails before one — a port probe, a program's own
/// wake connect at its stop. `stream` is the caller's connection, a
/// `TcpStream` for both callers, though any `Read` serves.
pub fn read_request<R: Read + ?Sized>(stream: &mut R, limits: Limits) -> Result<Option<Request>, Refused> {
    let Limits { max_head, max_body } = limits;
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut scanned = 0usize;
    let head_end = loop {
        if let Some(i) = buf[scanned..].windows(4).position(|w| w == b"\r\n\r\n") {
            break scanned + i;
        }
        scanned = buf.len().saturating_sub(3);
        if buf.len() > max_head {
            return Err(Refused::Malformed(format!("the request head exceeds the {max_head}-byte cap")));
        }
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) if buf.is_empty() => return Ok(None),
            Ok(0) => return Err(Refused::Malformed("the connection closed inside the request head".into())),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) if buf.is_empty() => return Ok(None),
            Err(e) => return Err(Refused::Malformed(format!("read: {e}"))),
        }
    };
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| Refused::Malformed("the request head is not UTF-8".into()))?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().ok_or_else(|| Refused::Malformed("the request line lacks a target".into()))?.to_string();
    let version = parts.next().ok_or_else(|| Refused::Malformed("the request line lacks an HTTP version".into()))?;
    if parts.next().is_some() || (version != "HTTP/1.1" && version != "HTTP/1.0") {
        return Err(Refused::Malformed("a malformed request line".into()));
    }
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(Refused::Malformed("a malformed method token".into()));
    }
    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| Refused::Malformed(format!("a malformed header line `{line}`")))?;
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("Content-Length") {
            if content_length.is_some() {
                return Err(Refused::Malformed("Content-Length given twice".into()));
            }
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Refused::Malformed(format!("a bad Content-Length `{value}`")));
            }
            content_length = Some(value.parse().map_err(|_| Refused::Malformed(format!("a bad Content-Length `{value}`")))?);
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            return Err(Refused::Malformed("chunked request bodies are unsupported; send Content-Length".into()));
        }
        headers.push((name.to_string(), value.to_string()));
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (target, None),
    };
    let declared = content_length.unwrap_or(0);
    if declared > max_body {
        return Err(Refused::TooLarge { declared, cap: max_body });
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < declared {
        let mut chunk = [0u8; 8192];
        match stream.read(&mut chunk) {
            Ok(0) => return Err(Refused::Malformed("the connection closed inside the request body".into())),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(Refused::Malformed(format!("read: {e}"))),
        }
    }
    body.truncate(declared);
    Ok(Some(Request { method, path, query, headers, body }))
}

#[cfg(test)]
mod tests;
