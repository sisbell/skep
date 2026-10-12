//! THE FORM's BODY, decoded: `application/x-www-form-urlencoded`, what a
//! browser's `<form method="post">` sends — the record's `{`, `"`, `:` and
//! spaces percent-encoded and a textarea's line breaks sent as CRLF, as the
//! provisioning record §8 item 5 knows browsers (UNVERIFIED HERE). Decoded
//! strictly: the fields in the order sent, `+` a space, `%XX` the byte it
//! names, and a `%` that two hex digits do not follow REFUSED rather than
//! passed through, so no field reaches a check as bytes other than the
//! browser meant. Every other byte is kept as given, a CR and an LF among
//! them. A value stays BYTES: the record field reaches `parse_enroll` as
//! sent, whose `not_utf8` is the verdict on bytes that are not text. The
//! claim page's query, `invite=<code>`, is the same encoding and is read
//! through the same decoder.

use std::fmt;

/// A decoded form: its fields in the order sent, each name and value the
/// bytes it decodes to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Form {
    fields: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Form {
    /// The value of the first field named `name` — the first, where the
    /// form names one twice — or `None` where it names none.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.fields().iter().find(|(n, _)| n == name.as_bytes()).map(|(_, v)| v.as_slice())
    }

    /// Every field, in the order sent.
    pub fn fields(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.fields
    }
}

/// A body the decoder refuses: the `%` at byte `at` of the body is not
/// followed by two hex digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadEscape {
    /// The `%`'s offset in the body, in bytes from 0.
    pub at: usize,
}

impl fmt::Display for BadEscape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the `%` at byte {} is not followed by two hex digits", self.at)
    }
}

/// THE DECODE: `body` split at each `&` and each part at its first `=` —
/// a part with no `=` is a name with an empty value, an empty part
/// (`a=1&&b=2`) no field at all — and each side unescaped.
pub fn decode(body: &[u8]) -> Result<Form, BadEscape> {
    let mut fields = Vec::new();
    let mut start = 0;
    for part in body.split(|&b| b == b'&') {
        if !part.is_empty() {
            let (name, value, value_at) = match part.iter().position(|&b| b == b'=') {
                Some(i) => (&part[..i], &part[i + 1..], start + i + 1),
                None => (part, &part[part.len()..], start + part.len()),
            };
            fields.push((unescape(name, start)?, unescape(value, value_at)?));
        }
        start += part.len() + 1;
    }
    Ok(Form { fields })
}

/// One side of a field unescaped; `offset` is where it starts in the body,
/// which the refusal counts from.
fn unescape(bytes: &[u8], offset: usize) -> Result<Vec<u8>, BadEscape> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => match (bytes.get(i + 1).copied().and_then(hex), bytes.get(i + 2).copied().and_then(hex)) {
                (Some(hi), Some(lo)) => {
                    out.push(hi << 4 | lo);
                    i += 3;
                }
                _ => return Err(BadEscape { at: offset + i }),
            },
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// A hex digit's value, in either case.
fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
