//! A BOARD's NAME, the first of the post's two person-made fields — the
//! board's one label under the suffix, `<name>.skep.host` — judged in process
//! before any docker run (the provisioning record §2.1; Q6 (a)): lowercased
//! first (a DNS name is case-insensitive, as this crate knows DNS —
//! UNVERIFIED HERE), then `[a-z0-9-]` alone, at most 63 bytes, no hyphen at
//! either end (a hostname label's limits, as the provisioning record §8
//! item 6 knows them — UNVERIFIED HERE). The alphabet is the daemon's own
//! origin grammar narrowed to one label:
//! `SKEPD_ORIGIN=https://<name>.<suffix>` must parse at the daemon, whose
//! host admits lowercase letters, digits, `.` and `-` (the client's
//! `host_is_canonical` reproduces it). And the label is one DOCKER TAKES AS
//! A NAME ALONE, as this crate knows Docker (UNVERIFIED HERE): two bytes at
//! least, Docker's own floor for a container's name and a volume's; none
//! of the names every container's hosts file answers, which never reach
//! the board; and never hex digits alone, which a container command reads
//! as the prefix of another container's ID. Anything else is D-4's second
//! clause. The post's other field, the person's record, is `record`'s.

use std::fmt;

use crate::domain::Domain;

/// THE LABEL's BOUND: a name is at most 63 bytes, one DNS label's limit as
/// the provisioning record §8 item 6 knows hostnames (UNVERIFIED HERE).
const MAX_NAME_BYTES: usize = 63;

/// THE NAME's FLOOR: two bytes — Docker's own floor for a container's name
/// and a volume's, a letter or digit and then one or more of letters,
/// digits, `_`, `.` and `-` (as this crate knows Docker — UNVERIFIED HERE):
/// a one-byte name passes every look and is refused at `docker volume
/// create`, every time.
const MIN_NAME_BYTES: usize = 2;

/// THE NAMES EVERY CONTAINER's HOSTS FILE ANSWERS: Docker writes them into
/// each container's `/etc/hosts`, which a resolver reads before the bridge's
/// DNS (as this crate knows Docker — UNVERIFIED HERE) — so the health
/// sidecar's `http://localhost:8642` dials the sidecar itself, a board under
/// one never pairs, and Caddy would dial itself for its snippet.
const HOSTS_FILE_NAMES: [&str; 7] = ["localhost", "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters"];

/// A board's name, in the grammar: lowercase, one label of `[a-z0-9-]`,
/// [`MIN_NAME_BYTES`] to [`MAX_NAME_BYTES`] bytes, no hyphen at either end,
/// none of [`HOSTS_FILE_NAMES`], and not hex digits alone. Every docker
/// call, the snippet and the origin are built from one — so no value a
/// person typed reaches an argv unless it is a label, none begins with
/// `-`, and none is, to Docker, another container's ID.
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
    /// Out of the alphabet: a byte outside `[a-z0-9-]` once lowercased — a
    /// dot, an underscore, a space, anything not ASCII, or bytes that are
    /// not text at all.
    OutOfTheAlphabet,
    /// A hyphen begins or ends it.
    HyphenAtEitherEnd,
    /// Fewer than [`MIN_NAME_BYTES`]: no container or volume of Docker's can
    /// carry it.
    TooShort,
    /// One of [`HOSTS_FILE_NAMES`]: a container's own hosts file answers it,
    /// and the bridge's DNS never does.
    HostsFileName,
    /// Hex digits alone: where no container carries it, a container command
    /// reads it as the prefix of a container's ID.
    HexDigitsAlone,
}

impl fmt::Display for NameRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NameRefused::Empty => "the name is empty",
            NameRefused::TooLong => "the name is longer than one label's 63 bytes",
            NameRefused::OutOfTheAlphabet => "the name holds a character outside letters, digits and hyphens",
            NameRefused::HyphenAtEitherEnd => "the name begins or ends with a hyphen",
            NameRefused::TooShort => "the name is one character, too short for a Docker name",
            NameRefused::HostsFileName => "the name is one every container's hosts file answers, which never reaches the board",
            NameRefused::HexDigitsAlone => "the name is hex digits alone, which Docker reads as a container's ID",
        })
    }
}

impl std::error::Error for NameRefused {}

impl Name {
    /// THE GRAMMAR over the name field's bytes: lowercased, then one label
    /// Docker takes as a name alone. Where two faults hold, the first of
    /// these speaks: bytes that are not text (`OutOfTheAlphabet`), an empty
    /// field, more than [`MAX_NAME_BYTES`], a byte outside `[a-z0-9-]`
    /// (`OutOfTheAlphabet`), a hyphen at either end, fewer than
    /// [`MIN_NAME_BYTES`], one of [`HOSTS_FILE_NAMES`], hex digits alone —
    /// so 64 bytes with an underscore are `TooLong`, and `a` is `TooShort`.
    pub fn parse(field: &[u8]) -> Result<Name, NameRefused> {
        let text = std::str::from_utf8(field).map_err(|_| NameRefused::OutOfTheAlphabet)?;
        let name = text.to_ascii_lowercase();
        if name.is_empty() {
            return Err(NameRefused::Empty);
        }
        if name.len() > MAX_NAME_BYTES {
            return Err(NameRefused::TooLong);
        }
        if !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return Err(NameRefused::OutOfTheAlphabet);
        }
        if name.starts_with('-') || name.ends_with('-') {
            return Err(NameRefused::HyphenAtEitherEnd);
        }
        if name.len() < MIN_NAME_BYTES {
            return Err(NameRefused::TooShort);
        }
        if HOSTS_FILE_NAMES.contains(&name.as_str()) {
            return Err(NameRefused::HostsFileName);
        }
        // A container's ID is 64 lowercase hex digits, and a container
        // command reads a name no container carries as the unique prefix of
        // one's ID: a name of hex digits alone would have `docker rm -f
        // <name>` — the cleanup's, the sweep's, the operator's — remove
        // another board's run, or the proxy, where this board's own run
        // never stood.
        if name.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(NameRefused::HexDigitsAlone);
        }
        Ok(Name(name))
    }

    /// A NAME AS THIS SERVICE WROTE IT — a snippet's stem, a labelled volume:
    /// `text` in the grammar AS WRITTEN, never lowercased. A file or a
    /// volume spelled as no name is spelled — `Upper`, `Dave` — was made by
    /// no post of this service, and folding it would name another board's.
    pub fn exact(text: &str) -> Option<Name> {
        Name::parse(text.as_bytes()).ok().filter(|name| name.as_str() == text)
    }

    /// The name as text.
    fn as_str(&self) -> &str {
        &self.0
    }

    /// The board's host under `suffix`: `<name>.<suffix>` — the label the
    /// serving run carries and the host the snippet routes, a [`Name`] under
    /// a [`Domain`], each held to its grammar by its type.
    pub fn host(&self, suffix: &Domain) -> String {
        format!("{}.{suffix}", self.0)
    }

    /// THE PUBLIC ORIGIN, `https://<name>.<suffix>`: the origin both run
    /// lines set as `SKEPD_ORIGIN` and never a loopback one (AUTH-4.57 (b)),
    /// and the one the reply relays — never the sidecar's dialed origin.
    pub fn origin(&self, suffix: &Domain) -> String {
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
