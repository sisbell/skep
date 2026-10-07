//! `skep session` (`client.md` §2.2): a CONTENT-scoped signed session
//! opened with the store's key, its token printed live; `--close -` ends a
//! token read from stdin or `SKEP_SESSION`, never from argv (AUTH-4.53).

use std::io::{self, Read};

use skep_client::board::{Scope, Token};
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::halt::Halt;
use skep_client::store::{KeySelector, KeyStore, Purpose};

use super::{board_of, data, principal_or_bound, select_key, store_of, talk, Stop};
use crate::args::{session_env, CommandLine, Usage};

pub fn session(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    if let Some(close) = c.value("--close") {
        // THE TOKEN IS NEVER AN ARGV VALUE (§2.2; AUTH-4.53; §9 item 29).
        if close != "-" {
            return Err(Usage("--close takes `-` and reads the token from stdin (or SKEP_SESSION); a token given as a flag value is refused — a command line is world-readable and outlives the run in shell history".into()).into());
        }
        // The token's bytes, judged whole: bytes that are not text are no
        // token, and a read stdin refuses is a halt carrying its error —
        // never a usage refusal, which is the flag's shape alone (§2.3).
        let bytes = match session_env()? {
            Some(t) => t.into_bytes(),
            None => {
                let mut bytes = Vec::new();
                io::stdin().read_to_end(&mut bytes).map_err(|e| Halt::face("the token could not be read from stdin", e.to_string(), "pipe the token in, or set SKEP_SESSION"))?;
                bytes
            }
        };
        let Some(token) = std::str::from_utf8(&bytes).ok().and_then(Token::parse) else {
            return Err(Usage("the token read is not a session token (32 lowercase hex)".into()).into());
        };
        if board.session_close(&token)?.already_dead {
            talk("the token was already dead (the death signal rode the 204): a restart, a retirement, a block, a genesis at the account, or an earlier close ended it");
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
    // it. Printed, its end is the holder's.
    let session = handshake(&board, Scope::Content, &*signer, principal, Site::Session)?;
    data(session.token().as_str())?;
    session.into_token();
    talk("the token reads, holds its draft visibility and writes content; a credential act under it answers content_session. It is live until `skep session --close -`, the key's retirement, or a daemon restart (AUTH-4.53: a captured token is this principal's content capability for that long)");
    Ok(())
}
