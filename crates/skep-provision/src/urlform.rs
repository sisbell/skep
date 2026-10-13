//! THE FORM's BODY, decoded: `application/x-www-form-urlencoded`, what a
//! browser's `<form method="post">` sends — the record's `{`, `"`, `:` and
//! spaces percent-encoded and a textarea's line breaks sent as CRLF, as the
//! provisioning record §8 item 5 knows browsers (UNVERIFIED HERE). Decoded
//! strictly: the fields in the order sent, `+` a space, `%XX` the byte it
//! names, and a `%` that two hex digits do not follow REFUSED rather than
//! passed through, so no field reaches a check as bytes other than the
//! browser meant. Every other byte is kept as given, a CR and an LF among
//! them. A value stays BYTES: the record field reaches `parse_enroll` as
//! sent, whose `not_utf8` is the verdict on bytes that are not text. AT
//! MOST [`MAX_FIELDS`] FIELDS, the most any page of this site posts: a body
//! naming more is no form of this site's, and is refused before its next
//! field is copied, so a decoded form holds no more bytes than were sent.
//! The claim page's query, `invite=<code>`, is the same encoding and is read
//! through the same decoder.

use std::fmt;

/// THE FIELDS' CAP: three — the claim form's named controls, the most any
/// page of this site posts (the sign-up form posts one; the claim page's
/// query carries one). A body naming more is no form of this site's,
/// refused before its fourth field is copied: uncapped, every `a&` of a
/// body would be a field — a 48-byte pair in a list grown by doubling and a
/// one-byte allocation — some 19 MB for a body at the pages' cap, 48 times
/// what was sent, and as many times over as connections are open.
const MAX_FIELDS: usize = 3;

/// A decoded form: its fields in the order sent, each name and value the
/// bytes it decodes to.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Form {
    fields: Vec<(Vec<u8>, Vec<u8>)>,
}

/// The count of fields alone: a form carries a record, an invite code or an
/// address, none of them a log line's.
impl fmt::Debug for Form {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Form").field("fields", &self.fields.len()).finish()
    }
}

impl Form {
    /// The value of the first field named `name` — the first, where the
    /// form names one twice — or `None` where it names none.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.fields().iter().find(|(n, _)| n == name.as_bytes()).map(|(_, v)| v.as_slice())
    }

    /// Every field, in the order sent.
    fn fields(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.fields
    }
}

/// A body the decoder refuses: the `%` at byte `at` of the body is not
/// followed by two hex digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadEscape {
    /// The `%`'s offset in the body, in bytes from 0.
    at: usize,
}

impl fmt::Display for BadEscape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the `%` at byte {} is not followed by two hex digits", self.at)
    }
}

impl std::error::Error for BadEscape {}

/// A body the decoder refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormRefused {
    /// A `%` that two hex digits do not follow.
    Escape(BadEscape),
    /// More than [`MAX_FIELDS`] fields: no form of this site's.
    TooManyFields,
}

/// A bad escape, as `?` meets it.
impl From<BadEscape> for FormRefused {
    fn from(e: BadEscape) -> FormRefused {
        FormRefused::Escape(e)
    }
}

impl fmt::Display for FormRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormRefused::Escape(e) => write!(f, "{e}"),
            FormRefused::TooManyFields => write!(f, "the body names more than {MAX_FIELDS} fields"),
        }
    }
}

impl std::error::Error for FormRefused {}

/// THE DECODE: `body` split at each `&` and each part at its first `=` —
/// a part with no `=` is a name with an empty value, an empty part
/// (`a=1&&b=2`) no field at all — and each side unescaped; a part past the
/// [`MAX_FIELDS`]th field refused, whatever its shape, before it is copied.
pub fn decode(body: &[u8]) -> Result<Form, FormRefused> {
    let mut fields = Vec::new();
    let mut start = 0;
    for part in body.split(|&b| b == b'&') {
        if !part.is_empty() {
            if fields.len() == MAX_FIELDS {
                return Err(FormRefused::TooManyFields);
            }
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
