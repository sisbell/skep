//! THE SESSION TABLE and THE DEATH SIGNAL's ARM (`client.md` §4b.1's
//! `session` row; §4b.2's `session-died`). The table holds every session
//! this shell opened for the page — the token, which never leaves this
//! process, under the opaque reference the page holds (`refs`) — and the
//! FACTS a death's arm is derived from: the principal, the account, the
//! kind (bare, or signed content-scoped), the key that opened it and the
//! account whose set it authenticated against. The two openings are here
//! too, so the shell's `session` call and the restart arm's silent re-open
//! (AUTH-5.31) share one: the BARE bind as the claimant on the permissive
//! board, and the SIGNED content-scoped handshake behind AUTH-5.65's
//! pre-check, each refusal under the armed name the row spells — `no_key`,
//! `origin_state`, `retired`, `not_enrolled`, `busy`, `blocked`,
//! `unreachable`.
//!
//! THE ARM (`session-died(session, reason)`, "ONE ARM PER E2 TRIGGER,
//! derived by the shell from public reads"): a bare session on a board now
//! ENFORCING died at the FLIP; a signed session whose key now stands in
//! the retired list died at a RETIREMENT — AUTH-5.28's own-hand arm where
//! this store's key wrote it, AUTH-5.77's where another did, the hand named
//! by its position and label off the admitted record read; a session
//! opened BY REFERENCE whose acted-as account now holds a set of its own
//! died at a GENESIS (the SEEDED arm); else the shell re-opens where it
//! holds a key — `403 prefix_blocked` is the BLOCK's arm, a session that
//! opens is the RESTART arm re-opened silently, and a board that does not
//! answer is said so. The page's own `close` is its own arm.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use skep_client::board::{KeySetAnswer, Opened, Scope, SessionBody, Token};
use skep_client::ceremony::handshake::{handshake_prechecked, Site};
use skep_client::derive::records::{credential_records, Hand};
use skep_client::derive::{origin_arm, precheck, KeyDiagnosis, Mode};
use skep_client::halt::Halt;
use skep_client::sheet::render_inert;
use skep_client::store::{FileStore, KeySelector, KeyStore, Purpose, StoreError};
use skep_client::Board;
use skep_identity::Fingerprint;

use crate::refusal::Refusal;

/// A session's kind: the bare bind, or the signed content-scoped handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bare,
    Content,
}

impl Kind {
    /// The kind as the bridge spells it.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Bare => "bare",
            Kind::Content => "content",
        }
    }
}

/// The facts a session was opened with — what its death's arm reads.
#[derive(Debug, Clone)]
pub struct Facts {
    pub principal: u64,
    /// `principal_prefix(principal)`, where the board answered one.
    pub account: Option<String>,
    pub kind: Kind,
    /// The key that opened a signed session.
    pub fingerprint: Option<Fingerprint>,
    /// The account whose set the signed session authenticated against —
    /// the account itself, or the nearest above it that holds a set.
    pub set_account: Option<String>,
}

impl Facts {
    /// Whether the session opened BY REFERENCE — against a set above its
    /// own account.
    pub fn by_reference(&self) -> bool {
        matches!((&self.account, &self.set_account), (Some(a), Some(s)) if a != s)
    }
}

/// One session this shell holds for the page.
#[derive(Debug)]
pub struct SessionEntry {
    /// The reference the page holds.
    pub reference: String,
    /// The board reference it stands at.
    pub board: String,
    /// The token — this process's alone.
    pub token: Token,
    pub facts: Facts,
}

/// The table, by reference.
#[derive(Debug, Default)]
pub struct Sessions {
    map: Mutex<HashMap<String, Arc<SessionEntry>>>,
}

impl Sessions {
    /// No session.
    pub fn new() -> Sessions {
        Sessions::default()
    }

    /// `entry` under its reference.
    pub fn insert(&self, entry: Arc<SessionEntry>) {
        self.map.lock().expect("the sessions' lock").insert(entry.reference.clone(), entry);
    }

    /// The session `reference` names, where this shell holds one.
    pub fn get(&self, reference: &str) -> Option<Arc<SessionEntry>> {
        self.map.lock().expect("the sessions' lock").get(reference).cloned()
    }

    /// The session removed, where it stood.
    pub fn remove(&self, reference: &str) -> Option<Arc<SessionEntry>> {
        self.map.lock().expect("the sessions' lock").remove(reference)
    }

    /// Every session at `board`, in no order.
    pub fn on_board(&self, board: &str) -> Vec<Arc<SessionEntry>> {
        self.map.lock().expect("the sessions' lock").values().filter(|e| e.board == board).cloned().collect()
    }

    /// Every session, in no order.
    pub fn all(&self) -> Vec<Arc<SessionEntry>> {
        self.map.lock().expect("the sessions' lock").values().cloned().collect()
    }

    /// How many sessions stand.
    pub fn len(&self) -> usize {
        self.map.lock().expect("the sessions' lock").len()
    }

    /// Whether none stands.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A session opened: the token and its facts.
pub struct Open {
    pub token: Token,
    pub facts: Facts,
}

/// THE BARE BIND as `principal` (`client.md` §4b.4; AUTH-4.26): honoured on
/// the unclaimed and the CLAIMED-PERMISSIVE board from this loopback peer,
/// which sends no `Origin`; refused on ENFORCING with the board's one 401,
/// carried verbatim.
pub fn open_bare(board: &Board, principal: u64) -> Result<Open, Refusal> {
    let token = match board.session_open(SessionBody::Bare { principal }).map_err(Refusal::of)? {
        Opened::Token(t) => t,
        Opened::Rejected => {
            return Err(Refusal::Board(skep_client::Refused {
                status: 401,
                code: "session_rejected".into(),
                detail: None,
                op: None,
                body: json!({"error": "session_rejected"}),
            }))
        }
        Opened::Blocked { record } => return Err(Refusal::Blocked(skep_client::Blocked { record, named_by: board.dialed().as_str().to_string(), ground: None })),
    };
    let account = board.principal_prefix(principal).map_err(Refusal::of)?;
    Ok(Open { token, facts: Facts { principal, account, kind: Kind::Bare, fingerprint: None, set_account: None } })
}

/// THE SIGNED CONTENT-SCOPED HANDSHAKE as `principal` with the store's key
/// for (this board, the principal) — §3.5's lookup — behind AUTH-5.65's
/// pre-check, each refusal under the armed name the `session` row spells.
pub fn open_signed(board: &Board, store: &FileStore, principal: u64) -> Result<Open, Refusal> {
    let health = board.health().map_err(Refusal::of)?;
    let key = match store.select(&KeySelector::Board { origin: board.dialed(), principal: Some(principal) }, Purpose::Sign) {
        Ok(key) => key,
        Err(StoreError::NoSelection { keys }) => {
            return Err(Refusal::of_named("no_key", skep_client::store::arm4_face(store, &keys, Mode::of(&health))));
        }
        Err(e) => return Err(Refusal::of_named("store_unreadable", e.into())),
    };
    let signer = store.signer(&KeySelector::Path(&key.path)).map_err(|e| Refusal::of_named("store_unreadable", e.into()))?;
    if let Err(h) = origin_arm(board.signed(), &health) {
        return Err(Refusal::of_named("origin_state", h));
    }
    let pre = precheck(board, principal, &key.fingerprint).map_err(|h| Refusal::of_named("not_registered", h))?;
    let own = [(key.fingerprint, key.public.clone())];
    match pre.diagnosis {
        KeyDiagnosis::Enrolled { .. } => {}
        KeyDiagnosis::Retired { .. } => {
            let h = skep_client::ceremony::handshake::key_face(board, &pre.walk, &key.fingerprint, &own, Site::Session).expect_err("a retired key is faced");
            return Err(Refusal::of_named("retired", h));
        }
        KeyDiagnosis::Neither => {
            let h = skep_client::ceremony::handshake::key_face(board, &pre.walk, &key.fingerprint, &own, Site::Session).expect_err("a key in neither list is faced");
            return Err(Refusal::of_named("not_enrolled", h));
        }
    }
    let session = handshake_prechecked(board, Scope::Content, &*signer, &pre, Site::Session).map_err(|h| Refusal::of_named("busy", h))?;
    let facts = Facts {
        principal,
        account: Some(session.account().to_string()),
        kind: Kind::Content,
        fingerprint: Some(session.fingerprint()),
        set_account: Some(pre.walk.set_account.clone()),
    };
    Ok(Open { token: session.into_token(), facts })
}

/// Why a session died, and — on the restart arm under a key this store
/// holds — the session re-opened silently in its place.
pub struct Death {
    pub reason: Value,
    pub reopened: Option<Open>,
}

/// The page's own `close`: its own arm.
pub fn closed() -> Death {
    Death { reason: json!({"arm": "closed"}), reopened: None }
}

/// THE ARM for a death signal met on `entry`'s token (the module doc), the
/// reads made now; `store` where the shell holds a key store for the
/// restart arm's re-open.
pub fn reason(board: &Board, store: Option<&FileStore>, entry: &SessionEntry) -> Death {
    let none = |reason: Value| Death { reason, reopened: None };
    let health = match board.health() {
        Ok(h) => h,
        Err(h) => return none(json!({"arm": "unreachable", "text": h.to_string()})),
    };
    let mode = Mode::of(&health);
    let facts = &entry.facts;
    if facts.kind == Kind::Bare {
        if mode == Mode::Enforcing {
            return none(json!({"arm": "mode", "mode": mode.name()}));
        }
        return none(json!({"arm": "restart", "reopened": false}));
    }
    // A signed session: the retirement, read off the set it authenticated
    // against and the admitted record read.
    if let (Some(fp), Some(set_account)) = (facts.fingerprint, facts.set_account.as_deref()) {
        if let Ok(KeySetAnswer::Set(set)) = board.key_set(set_account) {
            if set.retired(&fp).is_some() {
                let own: Vec<(Fingerprint, skep_identity::PublicKey)> =
                    store.and_then(|s| s.device_keys().ok()).into_iter().flatten().map(|k| (k.fingerprint, k.public)).collect();
                let records = credential_records(board, set_account, &own).ok();
                let retirement = records.as_ref().and_then(|r| r.retirement_of(&fp));
                let (hand, position, label, own_hand) = match retirement.map(|rec| (&rec.hand, rec.position)) {
                    Some((Hand::Key(hand), position)) => {
                        let label = records.as_ref().and_then(|r| r.label_of(hand)).map(|l| render_inert(&l));
                        let own_hand = own.iter().any(|(f, _)| f == hand);
                        (Some(hand.to_string()), position, label, own_hand)
                    }
                    Some((Hand::Bare, position)) => (Some("bare".to_string()), position, None, false),
                    _ => (None, None, None, false),
                };
                return none(json!({
                    "arm": "retired",
                    "fingerprint": fp.to_string(),
                    "own": own_hand,
                    "hand": hand,
                    "position": position,
                    "label": label,
                }));
            }
        }
        // The seeded arm: a session by reference whose acted-as account now
        // holds a set of its own.
        if facts.by_reference() {
            if let Some(account) = facts.account.as_deref() {
                if let Ok(KeySetAnswer::Set(set)) = board.key_set(account) {
                    if !set.is_empty() {
                        let writer = set.enrolled.first().map(|e| e.fingerprint.to_string());
                        return none(json!({"arm": "seeded", "account": account, "as_of": set.as_of, "writer": writer}));
                    }
                }
            }
        }
    }
    // The restart arm, or the block met at the re-open.
    let Some(store) = store else { return none(json!({"arm": "restart", "reopened": false})) };
    match open_signed(board, store, facts.principal) {
        Ok(open) => Death { reason: json!({"arm": "restart", "reopened": true}), reopened: Some(open) },
        Err(Refusal::Blocked(b)) => none(json!({"arm": "blocked", "record": b.record, "ground": b.ground})),
        Err(other) => none(json!({"arm": "restart", "reopened": false, "refused": other.name()})),
    }
}

/// A refusal the board's own refusal is, where the halt family carries one.
pub fn board_refusal(h: Halt) -> Refusal {
    Refusal::of(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table holds a session by its reference, lists a board's, and
    /// forgets a removed one; a session by reference is one whose set is
    /// above its account.
    #[test]
    fn the_table_holds_sessions_by_reference_and_by_board() {
        let sessions = Sessions::new();
        let token = Token::parse(&"9f".repeat(16)).unwrap();
        let facts = Facts { principal: 1, account: Some("1.0.1.1".into()), kind: Kind::Content, fingerprint: None, set_account: Some("1.0.1".into()) };
        assert!(facts.by_reference());
        sessions.insert(Arc::new(SessionEntry { reference: "s-1".into(), board: "b-1".into(), token: token.clone(), facts: facts.clone() }));
        sessions.insert(Arc::new(SessionEntry { reference: "s-2".into(), board: "b-2".into(), token, facts: Facts { set_account: Some("1.0.1.1".into()), ..facts } }));
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions.on_board("b-1").len(), 1);
        assert!(!sessions.get("s-2").unwrap().facts.by_reference());
        assert!(sessions.remove("s-1").is_some());
        assert!(sessions.get("s-1").is_none());
        assert_eq!(Kind::Bare.name(), "bare");
        assert_eq!(closed().reason["arm"], "closed");
    }
}
