//! The reference registry's names (`client.md` §4b.1, the pin).
//!
//! A board reference and a session reference are opaque names the shell
//! issues — "a name, not a credential — it grants nothing by itself, every
//! `op` checked as untrusted as if it were absent; valid only inside this
//! shell instance, never derived from the token, never persisted by the
//! page; it dies with the token or the shell's restart". So a reference is
//! minted from OS entropy at the moment it is issued, carries nothing of
//! the origin or the token it stands for, and a reference this process
//! never issued matches nothing: the shell answers a board reference with
//! `unknown_board`, and a session reference with the pin's stale-reference
//! refusal, `session_ended` — or, where the reference names a session this
//! run ended, or one of another run of the shell, with `session_died` and
//! the reason (`shell`'s `session` lookup). For that a session reference
//! names THE RUN that minted it: each shell opened mints one run id
//! ([`run_id`], eight lowercase hex from OS entropy, held by its session
//! table), and a session reference is `s-`, the run's eight hex, `-` and
//! twenty-four lowercase hex of its own ([`session_reference`]), so a
//! shell that restarted under a page can tell a reference of its earlier
//! run from one it never issued ([`session_run`]; skep #625). A board
//! reference and a moment id carry no run: `b-` or `m-` and twenty-four
//! hex. The three kinds wear different prefixes, so a session reference
//! handed where a board's is expected matches nothing either. A board
//! reference names one board, its [`BoardEntry`]: minted with the entry,
//! and read beside its board whole.

use std::fmt;
use std::sync::Arc;

use skep_client::sign::fresh_bytes;
use skep_client::Board;

/// The entropy in one reference or moment id, in bytes: ninety-six bits.
///
/// At that width two of one process never collide and none is ever guessed.
const REFERENCE_BYTES: usize = 12;

/// The entropy in a run id, in bytes: thirty-two bits, eight hex.
///
/// A run id tells one run of the shell from another under one page, never
/// a session from a session: two runs of one machine do not collide in
/// practice, and a collision costs a `session_ended` where `session_died`
/// was owed.
const RUN_BYTES: usize = 4;

/// One board of the shell, under the opaque reference minted for it.
///
/// The board is dialed through the shell's one dialer — its `dialed()` the
/// board's origin — and the reference is the name the page holds: the pair
/// the shell, the board's feed thread, its holds and every session that
/// stands at it read whole.
pub struct BoardEntry {
    pub reference: String,
    pub board: Arc<Board>,
}

impl BoardEntry {
    /// Returns the entry of `board` under a fresh board reference.
    pub fn new(board: Board) -> BoardEntry {
        BoardEntry { reference: board_reference(), board: Arc::new(board) }
    }
}

impl fmt::Debug for BoardEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BoardEntry({}, {})", self.reference, self.board.dialed())
    }
}

/// Returns a fresh board reference: `b-` and twenty-four lowercase hex.
///
/// It is minted for a [`BoardEntry`] alone.
fn board_reference() -> String {
    format!("b-{}", hex(&fresh_bytes(REFERENCE_BYTES)))
}

/// Returns a fresh run id: eight lowercase hex.
///
/// It is minted once per shell opened, by its session table, and names the
/// run in every session reference the table mints.
pub fn run_id() -> String {
    hex(&fresh_bytes(RUN_BYTES))
}

/// Returns a fresh session reference under `run`: `s-`, the run's eight
/// hex, `-`, and twenty-four lowercase hex.
pub fn session_reference(run: &str) -> String {
    format!("s-{run}-{}", hex(&fresh_bytes(REFERENCE_BYTES)))
}

/// Returns the run a well-formed session reference names.
///
/// It is the eight hex between the prefix and the reference's own
/// twenty-four, and `None` for a reference of any other form — the old
/// form's, a board reference, any text — which no run of the shell minted.
pub fn session_run(reference: &str) -> Option<&str> {
    let (run, own) = reference.strip_prefix("s-")?.split_once('-')?;
    (run.len() == 2 * RUN_BYTES && own.len() == 2 * REFERENCE_BYTES && is_hex(run) && is_hex(own)).then_some(run)
}

/// Returns a fresh moment id: `m-` and twenty-four lowercase hex.
///
/// It is the `id` a `moment` event carries and `answer`/`cancel` name.
pub fn moment_id() -> String {
    format!("m-{}", hex(&fresh_bytes(REFERENCE_BYTES)))
}

/// Returns the lowercase hex of `bytes`.
///
/// It is the one spelling every reference and moment id takes.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Returns whether `text` is lowercase hex throughout: the one spelling.
fn is_hex(text: &str) -> bool {
    text.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that a reference or a moment id is a prefixed fresh hex string.
    ///
    /// A board reference and a moment id are their prefix and twenty-four
    /// lowercase hex; a session reference is `s-`, the run's eight hex, `-`
    /// and twenty-four of its own, and names its run; two differ; the three
    /// kinds wear three prefixes.
    #[test]
    fn a_reference_is_a_prefixed_fresh_hex_string() {
        let run = run_id();
        assert!(run.len() == 8 && is_hex(&run), "{run}");
        let (b, s, m) = (board_reference(), session_reference(&run), moment_id());
        for (minted, prefix) in [(&b, "b-"), (&m, "m-")] {
            assert!(minted.starts_with(prefix), "{minted}");
            let tail = &minted[2..];
            assert_eq!(tail.len(), 24, "{minted}");
            assert!(is_hex(tail), "{minted}");
        }
        assert!(s.starts_with(&format!("s-{run}-")), "{s}");
        let own = &s[11..];
        assert!(own.len() == 24 && is_hex(own), "{s}");
        assert_eq!(session_run(&s), Some(run.as_str()), "a session reference names its run");
        assert_ne!(board_reference(), b);
        assert_ne!(session_reference(&run), s);
        assert_ne!(run_id(), run);
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    }

    /// Checks that a reference of another form names no run.
    ///
    /// The old form (`s-` and twenty-four hex), a board reference, a run of
    /// the wrong width, uppercase hex, an own part of the wrong width and
    /// plain text each name none: a reference this run or another never
    /// minted is answered `session_ended`, never a death of another run.
    #[test]
    fn a_reference_of_another_form_names_no_run() {
        let own = "0".repeat(24);
        for text in [
            format!("s-{own}"),
            format!("b-{own}"),
            format!("s-0123456-{own}"),
            format!("s-012345678-{own}"),
            format!("s-0123ABCD-{own}"),
            format!("s-01234567-{}", "0".repeat(23)),
            format!("s-01234567-{own}x"),
            "s-gone".to_string(),
            String::new(),
        ] {
            assert_eq!(session_run(&text), None, "{text}");
        }
        assert_eq!(session_run(&format!("s-01234567-{own}")), Some("01234567"));
    }

    /// Checks that a board's entry takes a fresh board reference.
    ///
    /// The reference stands beside its board, so two entries over one origin
    /// take two: a reference names one entry, never its origin; the entry
    /// prints its reference and its board's origin.
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
