//! `skep session` (`client.md` §2.2): a CONTENT-scoped signed session
//! opened with the store's key, its token printed live and what it is
//! joined to on the board's record said beside it — the principal, the
//! account, the board and the key that testifies each write under it;
//! `--close -` ends the token in `SKEP_SESSION` where it is set — stdin then
//! unread — else the one read from stdin, never one from argv (AUTH-4.53),
//! and names the board it asked, and the token it ended where the variable
//! answered.

use std::io::{self, Read};

use skep_client::board::{Scope, Token};
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::halt::Halt;
use skep_client::store::{KeySelector, KeyStore, Purpose};
use skep_client::Origin;

use super::{board_of, data, key_named, principal_or_bound, select_key, store_of, talk, Stop};
use crate::args::{session_env, CommandLine, Usage};

/// Where `--close -` took the token it ends: `SKEP_SESSION` where it is set,
/// else stdin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    Variable,
    Stdin,
}

/// What a close the board answered "already dead" says, naming `origin`,
/// the board asked: the death signal rode its 204, whoever ended the token —
/// and a board that never issued the token answers the very same 204, the
/// unknown token resolved a guest's and its close idempotent (AUTH-4.47).
/// The board's name is the one fact on the line that tells a close sent to
/// the wrong board from a token ended, and the token such a close names
/// stands LIVE at the board that issued it (AUTH-4.53).
fn already_dead_at(origin: &Origin) -> String {
    format!(
        "was already dead at {origin} (the death signal rode its 204): a restart, a retirement, a block, a genesis at the account or an \
         earlier close ended it — or {origin} never issued it, which answers the same"
    )
}

pub fn session(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    if let Some(close) = c.value("--close") {
        // THE TOKEN IS NEVER AN ARGV VALUE (§2.2; AUTH-4.53; §9 item 29).
        if close != "-" {
            return Err(Usage("--close takes `-` and ends the token in SKEP_SESSION where it is set — stdin then unread — else the one read from stdin; a token given as a flag value is refused — a command line is world-readable and outlives the run in shell history".into()).into());
        }
        // The token: SKEP_SESSION's where it is set, judged by its own
        // reader as every setting is (a value given badly is exit 2); else
        // stdin's bytes, judged whole — bytes that are no token, and a read
        // stdin refuses, are a state the read came to (exit 3), never a
        // usage refusal, which is the command line's shape alone (§2.3).
        let (token, source) = match session_env()? {
            Some(token) => (token, Source::Variable),
            None => {
                let mut bytes = Vec::new();
                io::stdin().read_to_end(&mut bytes).map_err(|e| Halt::face("the token could not be read from stdin", e.to_string(), "pipe the token in, or set SKEP_SESSION"))?;
                let token = std::str::from_utf8(&bytes).ok().and_then(Token::parse).ok_or_else(|| {
                    Halt::face(
                        "the bytes read from stdin are not a session token",
                        "a session token is 32 lowercase hex, as `skep session` printed it",
                        "pipe the token `skep session` printed, and nothing beside it",
                    )
                })?;
                (token, Source::Stdin)
            }
        };
        let already_dead = board.session_close(&token)?.already_dead;
        // Where the variable answered, the close says so whatever came of
        // it: a token piped beside the variable stands unread and LIVE, and
        // the person who piped it reads its fate in no line of this run
        // (AUTH-4.53: a live token is the principal's content capability).
        // Read from stdin, the token ended is the one piped, and a close
        // that ended it says nothing. Every line names the board asked.
        let origin = board.dialed();
        match (source, already_dead) {
            (Source::Variable, false) => talk(format!("the token in SKEP_SESSION is ended at {origin}; stdin was not read")),
            (Source::Variable, true) => talk(format!("the token in SKEP_SESSION {}; stdin was not read", already_dead_at(origin))),
            (Source::Stdin, true) => talk(format!("the token read from stdin {}", already_dead_at(origin))),
            (Source::Stdin, false) => {}
        }
        return Ok(());
    }
    // The plaintext non-loopback WARNING, ahead of everything a signed
    // session needs (AUTH-4.53; §9 item 23: a warning, never a refusal).
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let store = store_of(c)?;
    let given = c.principal()?;
    let key_file = c.key_file()?;
    let principal = principal_or_bound(given, &store, &board)?;
    let key = select_key(key_file.as_deref(), &store, &board, principal, Purpose::Sign)?;
    let signer = store.signer(&KeySelector::Path(&key.path))?;
    // CONTENT scope only (§9 item 45; RES-63); the token handed out LIVE,
    // written while the session still owns its end: a token stdout refused
    // is closed by the session's drop, never left live with nobody holding
    // it. Printed, its end is the holder's — and the line beside it names
    // what the board's record joins the token to: the principal the
    // one-binding test chose and the account it seats, the board, and the
    // key the store's lookup chose, whose fingerprint testifies each write
    // under it (AUTH-4.48).
    let session = handshake(&board, Scope::Content, &*signer, principal, Site::Session)?;
    let account = session.account().to_string();
    data(session.token().as_str())?;
    session.into_token();
    talk(format!(
        "the token is a CONTENT session for principal {principal} at account {account}, opened at {} by key {} — the board testifies each \
         write under it by that fingerprint (AUTH-4.48): it reads, holds its draft visibility and writes content; a credential act under it \
         answers content_session. It is live until `skep session --close -`, the key's retirement, or a daemon restart (AUTH-4.53: a \
         captured token is this principal's content capability for that long)",
        board.dialed(),
        key_named(&key)
    ));
    Ok(())
}
