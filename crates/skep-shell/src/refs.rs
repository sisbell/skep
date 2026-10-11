//! THE REFERENCE REGISTRY's NAMES (`client.md` §4b.1, THE PIN; tp2-6): a
//! board reference and a session reference are OPAQUE NAMES the shell
//! issues — "a NAME, NOT A CREDENTIAL — it grants nothing by itself, every
//! `op` checked as UNTRUSTED as if it were absent; valid only inside this
//! shell instance, never derived from the token, never persisted by the
//! page; it dies with the token or the shell's restart". So a name is
//! minted from OS entropy at the moment it is issued, carries nothing of
//! the origin or the token it stands for, and a name this process never
//! issued matches nothing: the shell answers THE PIN's stale-reference
//! refusal for it. The two kinds wear different prefixes, so a session
//! reference handed where a board's is expected matches nothing either.

use skep_client::sign::fresh_bytes;

/// The entropy in one name, in bytes: ninety-six bits, so two names of one
/// process never collide and a name is never guessed.
const NAME_BYTES: usize = 12;

/// A fresh BOARD reference: `b-` and twenty-four lowercase hex.
pub fn board_name() -> String {
    format!("b-{}", hex(&fresh_bytes(NAME_BYTES)))
}

/// A fresh SESSION reference: `s-` and twenty-four lowercase hex.
pub fn session_name() -> String {
    format!("s-{}", hex(&fresh_bytes(NAME_BYTES)))
}

/// A fresh MOMENT id: `m-` and twenty-four lowercase hex — the `id` a
/// `moment` event carries and `answer`/`cancel` name.
pub fn moment_name() -> String {
    format!("m-{}", hex(&fresh_bytes(NAME_BYTES)))
}

/// Lowercase hex of `bytes` — the one spelling every name takes.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name is its prefix and twenty-four lowercase hex; two names differ;
    /// the three kinds wear three prefixes.
    #[test]
    fn a_name_is_a_prefixed_fresh_hex_string() {
        let (b, s, m) = (board_name(), session_name(), moment_name());
        for (name, prefix) in [(&b, "b-"), (&s, "s-"), (&m, "m-")] {
            assert!(name.starts_with(prefix), "{name}");
            let tail = &name[2..];
            assert_eq!(tail.len(), 24, "{name}");
            assert!(tail.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)), "{name}");
        }
        assert_ne!(board_name(), b);
        assert_ne!(session_name(), s);
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    }
}
