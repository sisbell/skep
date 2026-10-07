//! `skep session` (`client.md` §2.2): a CONTENT-scoped signed session
//! opened with the store's key, its token printed live; `--close -` ends a
//! token read from stdin or `SKEP_SESSION`, never from argv (AUTH-4.53).

use std::io::{self, Read};

use skep_client::board::{Scope, Token};
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::store::{KeySelector, KeyStore, Purpose};

use super::{board_of, data, halt, principal_or_bound, select_key, store_of, talk, usage};
use crate::args::{session_env, Command, Usage};

pub fn session(c: &Command) -> i32 {
    let board = match board_of(c) {
        Ok(b) => b,
        Err(u) => return usage(u),
    };
    if let Some(close) = c.value("--close", None) {
        // THE TOKEN IS NEVER AN ARGV VALUE (§2.2; AUTH-4.53; §9 item 29).
        if close != "-" {
            return usage(Usage("--close takes `-` and reads the token from stdin (or SKEP_SESSION); a token given as a flag value is refused — a command line is world-readable and outlives the run in shell history".into()));
        }
        let mut text = String::new();
        let token = match session_env() {
            Some(t) => t,
            None => {
                if io::stdin().read_to_string(&mut text).is_err() {
                    return usage(Usage("the token could not be read from stdin".into()));
                }
                text
            }
        };
        let Some(token) = Token::parse(&token) else { return usage(Usage("the token read is not a session token (32 lowercase hex)".into())) };
        return match board.session_close(&token) {
            Err(h) => halt(h),
            Ok(answer) => {
                if answer.already_dead {
                    talk("the token was already dead (the death signal rode the 204): a restart, a retirement, a block, a genesis at the account, or an earlier close ended it");
                }
                0
            }
        };
    }
    // The plaintext non-loopback WARNING, ahead of everything a signed
    // session needs (AUTH-4.53; §9 item 23: a warning, never a refusal).
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    let given = match c.principal() {
        Ok(p) => p,
        Err(u) => return usage(u),
    };
    let principal = match principal_or_bound(given, &store, &board) {
        Ok(p) => p,
        Err(h) => return halt(h),
    };
    let key = match select_key(c, &store, &board, principal, Purpose::Sign) {
        Ok(k) => k,
        Err(h) => return halt(h),
    };
    let signer = match store.signer(&KeySelector::Path(&key.path)) {
        Ok(s) => s,
        Err(e) => return halt(e.into()),
    };
    // CONTENT scope only (§9 item 45; RES-63); the token handed out LIVE.
    let session = match handshake(&board, Scope::Content, &*signer, principal, Site::Session) {
        Ok(s) => s,
        Err(h) => return halt(h),
    };
    talk("the token reads, holds its draft visibility and writes content; a credential act under it answers content_session. It is live until `skep session --close -`, the key's retirement, or a daemon restart (AUTH-4.53: a captured token is this principal's content capability for that long)");
    data(session.into_token().as_str());
    0
}
