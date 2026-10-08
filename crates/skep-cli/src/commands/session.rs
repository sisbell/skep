//! `skep session` (`client.md` §2.2): a CONTENT-scoped signed session
//! opened with the store's key, its token printed live; `--close -` ends
//! the token in `SKEP_SESSION` where it is set — stdin then unread — else
//! the one read from stdin, never one from argv (AUTH-4.53).

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
            return Err(Usage("--close takes `-` and ends the token in SKEP_SESSION where it is set — stdin then unread — else the one read from stdin; a token given as a flag value is refused — a command line is world-readable and outlives the run in shell history".into()).into());
        }
        // The token: SKEP_SESSION's where it is set, judged by its own
        // reader as every setting is (a value given badly is exit 2); else
        // stdin's bytes, judged whole — bytes that are no token, and a read
        // stdin refuses, are a state the read came to (exit 3), never a
        // usage refusal, which is the command line's shape alone (§2.3).
        let token = match session_env()? {
            Some(token) => token,
            None => {
                let mut bytes = Vec::new();
                io::stdin().read_to_end(&mut bytes).map_err(|e| Halt::face("the token could not be read from stdin", e.to_string(), "pipe the token in, or set SKEP_SESSION"))?;
                std::str::from_utf8(&bytes).ok().and_then(Token::parse).ok_or_else(|| {
                    Halt::face(
                        "the bytes read from stdin are not a session token",
                        "a session token is 32 lowercase hex, as `skep session` printed it",
                        "pipe the token `skep session` printed, and nothing beside it",
                    )
                })?
            }
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
