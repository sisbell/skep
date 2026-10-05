//! THE ONE FIRST-SIGNED-SESSION COMPOSITION (`client.md` §1.1's
//! `first_session`; §4c.2's closing paragraph is its home; P28): every site
//! that owes AUTH-5.90 (iii)'s pinned order runs it — `bind` with the
//! content-scoped session it opens for this alone (§2.2), the claim's own
//! tail (§4.1 S5a–S5b), and the later lane's `enroll`, `retire`, `rotate` and
//! the recovery's anchor session. TWO STATES AND NOT ONE ACT, each resuming
//! by READING as P4 requires and NEITHER KEYED ON THE OTHER'S OUTCOME:
//!
//! 1. THE DOC-1 MINT at the account's computable address (AUTH-2.109), the
//!    flag affirmative — an account's FIRST mint, outside the publish class
//!    with any flag and taking no `attest` (the daemon's `publish_class`
//!    doc; PUB-8.21; AUTH RES-182) — RESUMED BY THE DOC-1 READ THERE.
//! 2. THE SETUP ACT, AUTH-5.87's ops (1) and (3) at `inc(account, 1)`, ONLY
//!    WHERE `key_set(account)` IS ITSELF NON-EMPTY (the rule's own binding
//!    class; a topic or an agent space holds no set and reserves no agent
//!    space — AUTH-6.19's signal read at the account itself, P17): op (1) the
//!    `delegate` of `inc(account, 1)` AND NO OTHER ADDRESS under a
//!    client-minted random `new_id` (AUTH-5.20) PERSISTED BEFORE THE FRAME as
//!    a binding line (§4.3's persist-first rule, P4's one named exception),
//!    resumed by `principal_prefix(new_id)` (AUTH-5.19); `not_authorized` ⇒
//!    the address is already a seat: read `effective_owner(inc(account, 1))`,
//!    take `principal` WHERE `prefix` equals it, NEVER re-peek the frontier;
//!    op (3) the mint of `inc(account, 1)`'s doc 1 in a session AS that
//!    account — opened by reference with `key`, which stands in the
//!    account's set (AUTH-4.30 (i)) — idempotent by reading, THE SESSION
//!    CLOSED WHEN THE ACT ENDS (AUTH RES-95). Op (3)'s key is pre-checked
//!    FIRST, among the reads ahead of any frame, and where it stands in
//!    neither list the setup state is sent NOT AT ALL, op (1) included (P13).
//!
//! EVERY READ IS PRINCIPAL-FREE AND MADE AHEAD OF THE SESSION, so a caller
//! learns which acts are owed before it opens one and opens none where none
//! is (`bind`'s two arms). THE DOC-1 READ ALONE IS NOT THE SELECTOR: it is
//! the first state's own resume read. The COPY — AUTH-5.87's
//! account-creation sentence — is the DOOR's and not this composition's.

use skep_identity::Fingerprint;

use crate::board::{acked_addr, frames, Answer, Board, KeySetAnswer, Rejection, Scope};
use crate::ceremony::handshake::{handshake, Session, Site};
use crate::derive::{doc_1_of, first_child, principal_of, walk_to_set, KeyDiagnosis};
use crate::halt::Halt;
use crate::origin::Origin;
use crate::sign::{fresh_principal_id, Signer};
use crate::store::{Binding, FileStore, KeyStore};

/// THE READS, all principal-free, taken ahead of any session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstSessionReads {
    pub account: String,
    /// `doc_1_of(account)`.
    pub home: String,
    /// The first state's resume read: the home stands.
    pub home_present: bool,
    /// The class test: `key_set(account)` itself is non-empty.
    pub set_nonempty: bool,
    /// `inc(account, 1)`.
    pub space: String,
    /// `effective_owner(space).principal` where `prefix == space` — the seat
    /// allocated, or none.
    pub space_seat: Option<u64>,
    /// The agents' home stands at `space.0.1`.
    pub space_home_present: bool,
    /// A `new_id` an earlier run persisted for this space, where the store
    /// holds one.
    pub persisted_new_id: Option<u64>,
    /// Whether the given key stands enrolled in the set that opens the space
    /// — op (3)'s pre-check (P13); `None` where the setup state is not owed.
    pub key_opens_space: Option<KeyDiagnosis>,
}

impl FirstSessionReads {
    /// Whether the home mint is owed.
    pub fn mint_owed(&self) -> bool {
        !self.home_present
    }

    /// Whether the setup act is owed: the account holds a set of its own and
    /// either op (1) or op (3) stands undone.
    pub fn setup_owed(&self) -> bool {
        self.set_nonempty && (self.space_seat.is_none() || !self.space_home_present)
    }

    /// Whether ANY act is owed — `bind`'s selector (§2.2): nothing owed ⇒
    /// no session is opened.
    pub fn anything_owed(&self) -> bool {
        self.mint_owed() || self.setup_owed()
    }
}

/// Whether `doc` stands — the doc-1 resume read (AUTH-2.109; AUTH-5.56
/// boundary 2): `retrieve_doc_v_span_set` answers a span set, or
/// `doc_not_registered`.
pub fn document_present(board: &Board, doc: &str) -> Result<bool, Halt> {
    match board.op(None, &frames::span_set(doc))? {
        Answer::Closed => Ok(false),
        Answer::Document(v) => match Rejection::of(&v) {
            None => Ok(true),
            Some(r) if r.code == "doc_not_registered" => Ok(false),
            Some(r) => Err(r.refused(&v)),
        },
    }
}

impl FirstSessionReads {
    /// Take the reads for `account`, `key` the key op (3)'s session would
    /// open under; `store` where a persisted `new_id` may stand.
    pub fn take(board: &Board, account: &str, key: &Fingerprint, store: Option<&FileStore>, origin: &Origin) -> Result<FirstSessionReads, Halt> {
        let home = doc_1_of(account);
        let home_present = document_present(board, &home)?;
        let set_nonempty = match board.key_set(account)? {
            KeySetAnswer::Set(s) => !s.enrolled.is_empty(),
            KeySetAnswer::NotAnAccount => {
                return Err(Halt::face(
                    format!("{account} is not an account on this board"),
                    "`key_set` answered `not_an_account` (AUTH-6.19)",
                    "check the account address",
                ))
            }
        };
        let space = first_child(account);
        let space_seat = principal_of(board, &space)?;
        let space_home_present = document_present(board, &doc_1_of(&space))?;
        let persisted_new_id = match store {
            Some(store) => store.all_bindings().ok().and_then(|lines| {
                lines.into_iter().rev().find_map(|b| match b {
                    Binding::Enrolment { origin: o, account: a, principal, .. } if &o == origin && a == space => Some(principal),
                    _ => None,
                })
            }),
            None => None,
        };
        let key_opens_space = if set_nonempty {
            // AUTH-4.30 (i): the space opens BY REFERENCE to the set that
            // opens its account — its own set is empty at birth, and before
            // op (1) it is no account at all (`not_an_account`), so the walk
            // starts at the space once it is seated and at the account
            // before, reaching the same set either way.
            let from = if space_seat.is_some() { space.as_str() } else { account };
            let walk = walk_to_set(board, from)?;
            Some(KeyDiagnosis::of(&walk.set, key))
        } else {
            None
        };
        Ok(FirstSessionReads {
            account: account.to_string(),
            home,
            home_present,
            set_nonempty,
            space,
            space_seat,
            space_home_present,
            persisted_new_id,
            key_opens_space,
        })
    }
}

/// What the composition did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstSessionDone {
    /// The home minted here (false where it already stood).
    pub minted_home: bool,
    /// The agents' home's seat, where the setup act ran or stood done.
    pub space_seat: Option<u64>,
    /// The agents' home minted here.
    pub minted_space_home: bool,
    /// The setup state was NOT sent: op (3)'s key stands in neither list of
    /// the set that opens the space (P13), the diagnosis handed back.
    pub setup_skipped: Option<KeyDiagnosis>,
    /// Op (1) answered `not_authorized` at an account whose first child was
    /// already seeded: the act STOPPED and no agents' home is created
    /// (AUTH-5.90 (iii)'s permanent fact).
    pub setup_stopped_seeded: bool,
    /// Warnings a caller prints — a store that could not persist the line.
    pub warnings: Vec<String>,
}

/// THE COMPOSITION over `reads` the caller took ahead of `session`; `key`
/// the session's own key, which op (3) opens under; `store` for the
/// persist-first line (a read-only one degrades to a warning, §3.7).
pub fn first_session(
    board: &Board,
    reads: &FirstSessionReads,
    session: &Session,
    key: &dyn Signer,
    store: Option<&FileStore>,
) -> Result<FirstSessionDone, Halt> {
    let mut done = FirstSessionDone {
        minted_home: false,
        space_seat: reads.space_seat,
        minted_space_home: false,
        setup_skipped: None,
        setup_stopped_seeded: false,
        warnings: Vec::new(),
    };
    // (1) THE DOC-1 MINT, resumed by the doc-1 read.
    if !document_present(board, &reads.home)? {
        let v = match session.op(board, &frames::create_home(&reads.account, Some(&format!("first-session.mint.{}", reads.account))))? {
            Answer::Closed => return Err(closed()),
            Answer::Document(v) => v,
        };
        match Rejection::of(&v) {
            None => done.minted_home = true,
            Some(r) if r.detail.as_deref() == Some("mint_home_public") => {
                return Err(Halt::face("the home mint was refused as a draft", r.token(), "this client passes `published: true`; this is its own fault"))
            }
            Some(r) => return Err(r.refused(&v)),
        }
    }
    // (2) THE SETUP ACT, where the account holds a set of its own.
    if !reads.set_nonempty {
        return Ok(done);
    }
    if reads.space_seat.is_some() && reads.space_home_present {
        return Ok(done);
    }
    // Op (3)'s key, settled FIRST (P13): in neither list ⇒ nothing sent.
    match reads.key_opens_space {
        Some(KeyDiagnosis::Enrolled { .. }) => {}
        other => {
            done.setup_skipped = Some(other.unwrap_or(KeyDiagnosis::Neither));
            return Ok(done);
        }
    }
    // Op (1): the seat — read, resumed, or delegated under a persisted id.
    let seat = match reads.space_seat {
        Some(seat) => seat,
        None => delegate_space(board, reads, session, key, store, &mut done)?,
    };
    if done.setup_stopped_seeded {
        return Ok(done);
    }
    done.space_seat = Some(seat);
    // Op (3): the mint of the space's doc 1 in a session AS the space, the
    // key opening it by reference; idempotent by reading; closed at the end.
    if !document_present(board, &doc_1_of(&reads.space))? {
        let as_space = handshake(board, Scope::Content, key, seat, Site::Setup)?;
        let outcome = as_space.op(board, &frames::create_home(&reads.space, Some(&format!("first-session.space-mint.{}", reads.space))));
        let _ = as_space.close(board);
        match outcome? {
            Answer::Closed => return Err(closed()),
            Answer::Document(v) => match Rejection::of(&v) {
                None => done.minted_space_home = true,
                Some(r) if r.code == "not_owner" || r.code == "not_an_account" => {
                    return Err(Halt::face(
                        format!("the agents' home at {} is not this seat's to mint", reads.space),
                        format!("{}: op (1) did not land as read (AUTH-5.87's own resume)", r.token()),
                        "re-run: S5a's resume reads the seat again",
                    ))
                }
                Some(r) => return Err(r.refused(&v)),
            },
        }
    }
    Ok(done)
}

fn closed() -> Halt {
    Halt::face(
        "the session ended during the first signed session's acts",
        "the board answered `Skepd-Session: closed`",
        "re-run: both states resume by reading (AUTH-5.87; AUTH-2.109)",
    )
}

/// Op (1): `delegate(inc(account, 1), new_id)` under a persisted id.
fn delegate_space(
    board: &Board,
    reads: &FirstSessionReads,
    session: &Session,
    key: &dyn Signer,
    store: Option<&FileStore>,
    done: &mut FirstSessionDone,
) -> Result<u64, Halt> {
    // The persisted id, read back (AUTH-5.19): `principal_prefix(new_id)` ⇒
    // the delegate committed; else the SAME id is sent.
    let new_id = match reads.persisted_new_id {
        Some(id) => {
            if board.principal_prefix(id)?.as_deref() == Some(reads.space.as_str()) {
                return Ok(id);
            }
            id
        }
        None => {
            let id = fresh_principal_id();
            // PERSIST-FIRST (§4.3; AUTH-5.20): the line BEFORE the frame.
            if let Some(store) = store {
                let line = Binding::Enrolment {
                    origin: board.dialed.clone(),
                    principal: id,
                    account: reads.space.clone(),
                    fingerprint: key.fingerprint(),
                };
                if let Err(e) = store.bind(&line) {
                    done.warnings.push(format!("the agents' home's binding line could not be written ({e}); record it yourself: {}", line.line()));
                }
            }
            id
        }
    };
    let v = match session.op(board, &frames::delegate(&reads.space, new_id, Some(&format!("first-session.delegate.{}", reads.space))))? {
        Answer::Closed => return Err(closed()),
        Answer::Document(v) => v,
    };
    if acked_addr(&v).is_some() {
        return Ok(new_id);
    }
    let Some(r) = Rejection::of(&v) else {
        return Err(Halt::face("the delegate answered a shape this client does not know", v.to_string(), "this is a fault in this client or the board"));
    };
    match r.code.as_str() {
        // The address is ALREADY A SEAT: read the seat, never re-peek the
        // frontier (AUTH-5.87).
        "not_authorized" => match principal_of(board, &reads.space)? {
            Some(seat) => {
                // Correct the persisted line to the read principal.
                if let Some(store) = store {
                    let line = Binding::Enrolment {
                        origin: board.dialed.clone(),
                        principal: seat,
                        account: reads.space.clone(),
                        fingerprint: key.fingerprint(),
                    };
                    if let Err(e) = store.bind(&line) {
                        done.warnings.push(format!("the corrected binding line could not be written ({e}); record it yourself: {}", line.line()));
                    }
                }
                // AUTH-5.90 (iii): a first child already SEEDED by another
                // party is a permanent fact — the act stops where its set is
                // not the account's own.
                match board.key_set(&reads.space)? {
                    KeySetAnswer::Set(s) if !s.enrolled.is_empty() => {
                        done.setup_stopped_seeded = true;
                        done.space_seat = Some(seat);
                    }
                    _ => {}
                }
                Ok(seat)
            }
            None => Err(Halt::face(
                format!("`delegate` of {} was refused `not_authorized` and the address has no seat", reads.space),
                "ω answers the seat above an unallocated address; this contradiction is this client's to report",
                "re-run; the setup act resumes by reading",
            )),
        },
        "duplicate_id" => Err(Halt::face(
            "the client-minted principal id is already registered",
            format!("{}: `new_id` {new_id} collided", r.token()),
            "re-run: a FRESH id is minted (AUTH-5.20), never a resume onto the colliding one",
        )),
        "claim_first" => Err(Halt::face("the board is unclaimed", "claim_first on the agents' home's delegate: the claim did not land", "re-run `skep claim`")),
        _ => Err(r.refused(&v)),
    }
}
