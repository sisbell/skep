//! THE WRITE: one answer on the caller's stream — the status line, the
//! caller's headers in order, the content type and length where known,
//! `Cache-Control: no-store` and `Connection: close`, then the body.

use std::io::{self, Write};

/// The reason phrase for the statuses the dev provider answers, and `OK`
/// for any other: the phrase is informational, and a client reads the
/// code.
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "OK",
    }
}

/// THE HEAD of a response: the status, every header given, the content
/// type where one is named, the length where the body's is known,
/// `Cache-Control: no-store` and `Connection: close`. No flush: a caller
/// streaming the body after it flushes when the body is written.
pub fn write_head<W: Write + ?Sized>(stream: &mut W, status: u16, headers: &[(String, String)], content_type: Option<&str>, content_length: Option<usize>) -> io::Result<()> {
    let mut head = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(ct) = content_type {
        head.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    if let Some(n) = content_length {
        head.push_str(&format!("Content-Length: {n}\r\n"));
    }
    head.push_str("Cache-Control: no-store\r\nConnection: close\r\n\r\n");
    stream.write_all(head.as_bytes())
}

/// ONE WHOLE RESPONSE: the head with the body's length, then the body,
/// flushed.
pub fn write_response<W: Write + ?Sized>(stream: &mut W, status: u16, headers: &[(String, String)], content_type: Option<&str>, body: &[u8]) -> io::Result<()> {
    write_head(stream, status, headers, content_type, Some(body.len()))?;
    stream.write_all(body)?;
    stream.flush()
}

#[cfg(test)]
mod tests;
