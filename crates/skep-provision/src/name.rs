//! A BOARD's NAME, the first of the post's two person-made fields — the
//! board's one label under the suffix, `<name>.skep.host` — judged in process
//! before any docker run (the provisioning record §2.1; Q6 (a)): lowercased
//! first (a DNS name is case-insensitive, as this crate knows DNS —
//! UNVERIFIED HERE), then `[a-z0-9-]` alone, 1 to 63 bytes, no hyphen at
//! either end (a hostname label's limits, as the provisioning record §8
//! item 6 knows them — UNVERIFIED HERE). The alphabet is the daemon's own
//! origin grammar narrowed to one label:
//! `SKEPD_ORIGIN=https://<name>.<suffix>` must parse at the daemon, whose
//! host admits lowercase letters, digits, `.` and `-` (the client's
//! `host_is_canonical` reproduces it). Anything else is D-4's second clause.
//! The post's other field, the person's record, is `record`'s.

use std::fmt;

/// THE LABEL's BOUND: a name is at most 63 bytes, one DNS label's limit as
/// the provisioning record §8 item 6 knows hostnames (UNVERIFIED HERE).
const MAX_NAME_BYTES: usize = 63;

/// A board's name, in the grammar: lowercase, one label of `[a-z0-9-]`, 1
/// to [`MAX_NAME_BYTES`] bytes, no hyphen at either end. Every docker call,
/// the snippet and the origin are built from one — so no value a person
/// typed reaches an argv unless it is a label, and none begins with `-`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

/// Why a name field is no name — each D-4's second clause; the log names
/// the reason and never the field, which may hold anything a person typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameRefused {
    /// The field is empty.
    Empty,
    /// The field is longer than [`MAX_NAME_BYTES`].
    TooLong,
    /// A byte outside `[a-z0-9-]` once lowercased — a dot, an underscore, a
    /// space, anything not ASCII, or bytes that are not text at all.
    NotALabel,
    /// A hyphen begins or ends it.
    Hyphen,
}

impl fmt::Display for NameRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NameRefused::Empty => "the name is empty",
            NameRefused::TooLong => "the name is longer than one label's 63 bytes",
            NameRefused::NotALabel => "the name holds a character outside letters, digits and hyphens",
            NameRefused::Hyphen => "the name begins or ends with a hyphen",
        })
    }
}

impl std::error::Error for NameRefused {}

impl Name {
    /// THE GRAMMAR over the name field's bytes: lowercased, then one label.
    pub fn parse(field: &[u8]) -> Result<Name, NameRefused> {
        let text = std::str::from_utf8(field).map_err(|_| NameRefused::NotALabel)?;
        let name = text.to_ascii_lowercase();
        if name.is_empty() {
            return Err(NameRefused::Empty);
        }
        if name.len() > MAX_NAME_BYTES {
            return Err(NameRefused::TooLong);
        }
        if !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return Err(NameRefused::NotALabel);
        }
        if name.starts_with('-') || name.ends_with('-') {
            return Err(NameRefused::Hyphen);
        }
        Ok(Name(name))
    }

    /// A NAME AS THIS SERVICE WROTE IT — a snippet's stem, a labelled volume:
    /// `text` in the grammar AS IT STANDS, never lowercased. A file or a
    /// volume spelled as no name is spelled — `Upper`, `Dave` — was made by
    /// no post of this service, and folding it would name another board's.
    pub fn exact(text: &str) -> Option<Name> {
        Name::parse(text.as_bytes()).ok().filter(|name| name.as_str() == text)
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The board's host under `suffix`: `<name>.<suffix>` — the label the
    /// serving run carries and the host the snippet routes.
    pub fn host(&self, suffix: &str) -> String {
        format!("{}.{suffix}", self.0)
    }

    /// THE PUBLIC ORIGIN, `https://<name>.<suffix>`: the origin both run
    /// lines set as `SKEPD_ORIGIN` and never a loopback one (AUTH-4.57 (b)),
    /// and the one the reply relays — never the sidecar's dialed origin.
    pub fn origin(&self, suffix: &str) -> String {
        format!("https://{}", self.host(suffix))
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests;
