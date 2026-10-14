//! A DOMAIN, as `--suffix` takes one — the domain every board's name is
//! under, `<name>.<suffix>` — held to THE GRAMMAR ([`domain_ok`]): lowercase
//! letters, digits, dots and hyphens, its labels non-empty and none beginning
//! or ending with a hyphen, the daemon's origin grammar for the host it
//! closes. So a board's public origin, `https://<name>.<suffix>`
//! (AUTH-4.57 (b)), parses at the daemon, and the snippet, the status URL
//! and the invite link take a suffix unchanged: it holds no character the
//! Caddyfile or a URL reads as its own. ITS VALUE ([`Domain`]) is the
//! grammar's one door — a suffix is one only once [`Domain::parse`] admits
//! it — and this module holds the value and its grammar alone, so no other
//! module can make one any other way.

use std::fmt;

/// THE GRAMMAR's ALPHABET IN WORDS, for a refusal to name: kept beside
/// [`domain_ok`], which admits these four kinds of byte and no other.
pub const DOMAIN_ALPHABET_IN_WORDS: &str = "lowercase letters, digits, dots and hyphens";

/// THE GRAMMAR: non-empty, lowercase letters, digits, dots and hyphens
/// alone — the alphabet [`DOMAIN_ALPHABET_IN_WORDS`] names — its labels
/// non-empty and none beginning or ending with a hyphen.
fn domain_ok(text: &str) -> bool {
    let labels_ok = text.split('.').all(|l| !l.is_empty() && !l.starts_with('-') && !l.ends_with('-'));
    !text.is_empty() && labels_ok && text.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

/// A DOMAIN BY THE GRAMMAR: [`Domain::parse`] is the only way to one, so a
/// host, an origin, a snippet or a URL built on one takes it unchanged. It
/// is no secret — the serving line names it, and every page shows it — so
/// its `Debug` and its `Display` show it whole.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Domain(String);

impl Domain {
    /// `text` as a domain, where the grammar admits it.
    pub fn parse(text: &str) -> Option<Domain> {
        domain_ok(text).then(|| Domain(text.to_owned()))
    }

    /// The domain as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The domain as written, for the hosts and URLs that format it in place.
impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests;
