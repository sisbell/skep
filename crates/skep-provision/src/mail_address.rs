//! A mail address, as the two files and the follow-up mail's header take it.
//!
//! The two files that keep one are the sign-up file (`signups`) and the
//! invite file (`invites`), and the header is `sender`'s. The address rule
//! ([`address_ok`]) is the minimum those need, and no more: one `@` with a
//! non-empty side each way, at most 254 bytes, ASCII alone, no control
//! character, no whitespace, none of RFC 5322's specials but `@` and `.` — so
//! an address is one line's one field, shows the owner every byte it holds as
//! itself, and is one header's one recipient in the form a `To:` carries
//! without SMTPUTF8. It checks no domain and sends nothing. Its words, for a
//! refusal to name, are [`address_rule`]'s, built beside it from the bound
//! and the specials it reads.
//!
//! Its value ([`MailAddress`]) is the rule's one door: every address that
//! comes in — the three flags that take one, `--reply-to`, `--from` and
//! `--address`, and the sign-up field — is one only once
//! [`MailAddress::parse`] admits it; and this module holds the value and its
//! rule alone, so no other module can make one any other way.

use std::fmt;

/// An address's byte bound: 254.
///
/// It is the longest a mail path carries, as this crate knows mail
/// (unverified here).
const MAX_ADDRESS_BYTES: usize = 254;

/// Returns whether `address` keeps the address rule.
///
/// The rule: one `@` with a non-empty side each way, at most
/// [`MAX_ADDRESS_BYTES`] bytes, ASCII alone, no control character, no
/// whitespace, and none of the [`SPECIALS`]. ASCII alone, because past it
/// a terminal may draw a character as another or as nothing — a bidi
/// control (`skep-client`'s `render_inert` disarms them), a zero-width
/// character, a soft hyphen, a tag character, another script's letter in a
/// Latin one's shape — so a line of the sign-up file would show the owner
/// other bytes than it holds, and the invite would go where the owner never
/// meant it; and a `To:` holding one needs SMTPUTF8 of the relay, which this
/// program neither asks for nor checks.
fn address_ok(address: &str) -> bool {
    let Some((local, domain)) = address.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && address.len() <= MAX_ADDRESS_BYTES
        && address.is_ascii()
        && !address.chars().any(|c| c.is_control() || c.is_whitespace() || SPECIALS.contains(&c))
}

/// RFC 5322's specials but `@` and `.`.
///
/// Any of them lets a `To:` header name a second recipient
/// (`me@x.example,root`, under the mailer's `-t`) or read the address as
/// other than one. Read by the rule ([`address_ok`]) and by its words
/// ([`address_rule`]) alike.
const SPECIALS: [char; 11] = ['(', ')', '<', '>', '[', ']', ':', ';', '\\', ',', '"'];

/// An address by the rule.
///
/// [`MailAddress::parse`] is the only way to one, so a value of this type is
/// one line's one field and one header's one recipient. Its `Debug` shows
/// none of it: an address is never a log line's.
#[derive(Clone, PartialEq, Eq)]
pub struct MailAddress(String);

impl MailAddress {
    /// Parses `text` as an address, where the rule admits it.
    pub fn parse(text: &str) -> Option<MailAddress> {
        address_ok(text).then(|| MailAddress(text.to_owned()))
    }

    /// Returns the address as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Nothing of the address: a `{:?}` can carry none of it.
impl fmt::Debug for MailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MailAddress(…)")
    }
}

/// Returns the rule in words, for a refusal to name.
///
/// It is kept here beside [`address_ok`], its bound and its specials read
/// from the constants the rule reads, so a change to the rule is made in one
/// place and its words with it.
pub fn address_rule() -> String {
    let specials: Vec<String> = SPECIALS.iter().map(char::to_string).collect();
    format!("one @ with a side each way, at most {MAX_ADDRESS_BYTES} bytes, ASCII alone, no space, no control character, none of {}", specials.join(" "))
}

#[cfg(test)]
mod tests;
