//! THE REFERENCE REGISTRY's NAMES (`client.md` §4b.1, THE PIN; tp2-6): a
//! board reference and a session reference are OPAQUE NAMES the shell
//! issues — "a NAME, NOT A CREDENTIAL — it grants nothing by itself, every
//! `op` checked as UNTRUSTED as if it were absent; valid only inside this
//! shell instance, never derived from the token, never persisted by the
//! page; it dies with the token or the shell's restart". So a reference is
//! minted from OS entropy at the moment it is issued, carries nothing of
//! the origin or the token it stands for, and a reference this process
//! never issued matches nothing: the shell answers THE PIN's stale-reference
//! refusal for it. The two kinds wear different prefixes, so a session
//! reference handed where a board's is expected matches nothing either. A
//! board reference names one board, its [`BoardEntry`]: minted with the
//! entry, and read beside its board whole.

use std::fmt;
use std::sync::Arc;

use skep_client::sign::fresh_bytes;
use skep_client::Board;

/// The entropy in one reference or moment id, in bytes: ninety-six bits, so
/// two of one process never collide and none is ever guessed.
const REFERENCE_BYTES: usize = 12;

/// ONE BOARD OF THE SHELL: the board dialed through the shell's one dialer —
/// its `dialed()` the board's origin — under the opaque reference minted for
/// it, the name the page holds; the pair the shell, the board's feed thread,
/// its holds and every session that stands at it read whole.
pub struct BoardEntry {
    pub reference: String,
    pub board: Arc<Board>,
}

impl BoardEntry {
    /// `board` under a fresh board reference.
    pub fn new(board: Board) -> BoardEntry {
        BoardEntry { reference: board_reference(), board: Arc::new(board) }
    }
}

impl fmt::Debug for BoardEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BoardEntry({}, {})", self.reference, self.board.dialed())
    }
}

/// A fresh BOARD reference: `b-` and twenty-four lowercase hex — minted for
/// a [`BoardEntry`] alone.
fn board_reference() -> String {
    format!("b-{}", hex(&fresh_bytes(REFERENCE_BYTES)))
}

/// A fresh SESSION reference: `s-` and twenty-four lowercase hex.
pub fn session_reference() -> String {
    format!("s-{}", hex(&fresh_bytes(REFERENCE_BYTES)))
}

/// A fresh MOMENT id: `m-` and twenty-four lowercase hex — the `id` a
/// `moment` event carries and `answer`/`cancel` name.
pub fn moment_id() -> String {
    format!("m-{}", hex(&fresh_bytes(REFERENCE_BYTES)))
}

/// Lowercase hex of `bytes` — the one spelling every reference and moment id
/// takes.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reference or a moment id is its prefix and twenty-four lowercase
    /// hex; two differ; the three kinds wear three prefixes.
    #[test]
    fn a_reference_is_a_prefixed_fresh_hex_string() {
        let (b, s, m) = (board_reference(), session_reference(), moment_id());
        for (minted, prefix) in [(&b, "b-"), (&s, "s-"), (&m, "m-")] {
            assert!(minted.starts_with(prefix), "{minted}");
            let tail = &minted[2..];
            assert_eq!(tail.len(), 24, "{minted}");
            assert!(tail.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)), "{minted}");
        }
        assert_ne!(board_reference(), b);
        assert_ne!(session_reference(), s);
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    }

    /// A board's entry takes a fresh board reference beside its board, so two
    /// entries over one origin take two: a reference names one entry, never
    /// its origin; the entry prints its reference and its board's origin.
    #[test]
    fn a_boards_entry_takes_a_fresh_reference_beside_its_board() {
        let origin = skep_client::Origin::parse("http://127.0.0.1:9").unwrap();
        let entry = || BoardEntry::new(Board::new(origin.clone(), skep_client::PlainHttp::new()));
        let (one, two) = (entry(), entry());
        assert!(one.reference.starts_with("b-") && one.reference != two.reference, "{} {}", one.reference, two.reference);
        assert_eq!((one.board.dialed(), two.board.dialed()), (&origin, &origin));
        assert_eq!(format!("{one:?}"), format!("BoardEntry({}, {origin})", one.reference));
    }
}
