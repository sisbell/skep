//! The one first-signed-session composition.
//!
//! It is `client.md` §1.1's `first_session`, its home §4c.2's closing
//! paragraph (P28): every site that owes AUTH-5.90 (iii)'s pinned order runs
//! it — `bind` with the content-scoped session it opens for this alone
//! (§2.2), the claim's own tail (§4.1 S5a–S5b), and `enroll`, `retire`,
//! `rotate` and the recovery's anchor session. Two states and not one act,
//! each resuming by reading as P4 requires and neither keyed on the other's
//! outcome:
//!
//! 1. The doc-1 mint at the account's computable address (AUTH-2.109), the
//!    flag affirmative — an account's first mint, which from this signed
//!    session is publish-class whatever its flag (PUB-6.43's exemption is
//!    the bare session's alone; PUB-8.21) and so carries the `attest` over
//!    the empty body, signed by the session's own key ([`home_frame`]) —
//!    resumed by the doc-1 read there.
//! 2. The setup act, AUTH-5.87's ops (1) and (3) at `inc(account, 1)`, only
//!    where `key_set(account)` itself enrolls a key (the rule's own binding
//!    class; a topic or an agent space holds no set and reserves no agent
//!    space — AUTH-6.19's signal read at the account itself, P17): op (1) the
//!    `delegate` of `inc(account, 1)` and no other address under a
//!    client-minted random `new_id` (AUTH-5.20) persisted before the frame as
//!    a binding line (§4.3's persist-first rule, P4's one named exception),
//!    resumed by `principal_prefix(new_id)` (AUTH-5.19); `not_authorized` ⇒
//!    the address is already a seat: read `effective_owner(inc(account, 1))`,
//!    take `principal` where `prefix` equals it, never re-peek the frontier;
//!    op (3) the mint of `inc(account, 1)`'s doc 1 in a session as that
//!    account — opened by reference with `key`, which stands in the
//!    account's set (AUTH-4.30 (i)), the mint attested under `key` as the
//!    doc-1 mint is — idempotent by reading, the session closed when the
//!    act ends (AUTH RES-95). Op (3)'s key is pre-checked
//!    first, among the reads ahead of any frame, and where it is not
//!    enrolled there — retired, or in neither list — the setup state is sent
//!    not at all, op (1) included (P13).
//!
//! Every read of [`FirstSessionReads`] is principal-free and made ahead of
//! the session, so a caller learns which acts are owed before it opens one
//! and opens none where none is (`bind`'s two arms). The doc-1 read alone is
//! not the selector: it is the first state's own resume read. The copy —
//! AUTH-5.87's account-creation sentence — is the door's and not this
//! composition's.
//!
//! Op (1)'s persist-first `delegate` is `delegate_persisted`, the one form
//! of §4.3's rule, which the handoff's beat (a) runs too (§4c.2 G2: "the
//! same rule, the same form, not a second one").

use serde_json::Value;
use skep_identity::{entry_body_empty, ContentFreeOp, DocTerm, Fingerprint};

use super::attest_member;
use crate::address::{doc_1_of, first_child, parse_address};
use crate::board::{acked_addr, frames, Answer, Board, KeySetAnswer, Rejection, Scope};
use crate::ceremony::handshake::{handshake, Session, Site};
use crate::derive::{principal_of, walk_to_set, KeyDiagnosis};
use crate::halt::Halt;
use crate::sign::{fresh_principal_id, Signer};
use crate::store::{Binding, FileStore, KeyStore};

/// The reads, all principal-free, taken ahead of any session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstSessionReads {
    /// The account the reads are of.
    pub account: String,
    /// `doc_1_of(account)`.
    pub home: String,
    /// The first state's resume read: the home stands.
    pub home_present: bool,
    /// The class test: `key_set(account)` itself enrolls a key.
    pub set_nonempty: bool,
    /// `inc(account, 1)` — the agent space (AUTH-5.87).
    pub agent_space: String,
    /// The principal seated at the agent space where it is a seat, else none.
    ///
    /// A seat is where `effective_owner`'s `prefix ==` it (AUTH-6.37).
    pub agent_space_principal: Option<u64>,
    /// The agent space's home stands.
    ///
    /// The home is its doc 1 at `agent_space.0.1` (AUTH-5.87, "and its
    /// home").
    pub agent_space_home_present: bool,
    /// A `new_id` an earlier run persisted for the agent space.
    ///
    /// It is `None` where the store holds none.
    pub persisted_new_id: Option<u64>,
    /// Op (3)'s pre-check (P13) of the given key.
    ///
    /// It is the key's diagnosis at the set that opens the agent space;
    /// `None` where the account holds no set of its own.
    pub key_opens_agent_space: Option<KeyDiagnosis>,
}

impl FirstSessionReads {
    /// Returns whether the home mint is owed.
    pub fn mint_owed(&self) -> bool {
        !self.home_present
    }

    /// Returns whether the setup act is owed.
    ///
    /// It is owed where the account holds a set of its own and either op (1)
    /// or op (3) stands undone.
    pub fn setup_owed(&self) -> bool {
        self.set_nonempty && (self.agent_space_principal.is_none() || !self.agent_space_home_present)
    }

    /// Returns whether any act is owed — `bind`'s selector (§2.2).
    ///
    /// Nothing owed ⇒ no session is opened.
    pub fn anything_owed(&self) -> bool {
        self.mint_owed() || self.setup_owed()
    }
}

/// Returns whether `doc` stands — the doc-1 resume read.
///
/// AUTH-2.109; AUTH-5.56 boundary 2: `retrieve_doc_v_span_set` answers a
/// span set, or `doc_not_registered`.
///
/// # Errors
///
/// Any other rejection is the board's refusal; otherwise
/// [`Board::guest`]'s errors.
pub fn document_present(board: &Board, doc: &str) -> Result<bool, Halt> {
    let v = board.guest(&frames::span_set(doc))?;
    match Rejection::of(&v) {
        None => Ok(true),
        Some(r) if r.key() == "doc_not_registered" => Ok(false),
        Some(r) => Err(r.refused(&v)),
    }
}

impl FirstSessionReads {
    /// Takes the reads for `account`.
    ///
    /// `key` is the key op (3)'s session would open under; `store` where a
    /// persisted `new_id` may stand.
    ///
    /// # Errors
    ///
    /// `account` answering `not_an_account` halts, as do the reads' own
    /// errors.
    pub fn take(board: &Board, account: &str, key: &Fingerprint, store: Option<&FileStore>) -> Result<FirstSessionReads, Halt> {
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
        let agent_space = first_child(account);
        let agent_space_principal = principal_of(board, &agent_space)?;
        let agent_space_home_present = document_present(board, &doc_1_of(&agent_space))?;
        let persisted_new_id = persisted(board, store, &agent_space);
        let key_opens_agent_space = if set_nonempty {
            // AUTH-4.30 (i): the agent space opens by reference to the set
            // that opens its account — its own set is empty at birth, and
            // before op (1) it is no account at all (`not_an_account`), so
            // the walk starts at the agent space once it is seated and at the
            // account before, reaching the same set either way.
            let from = if agent_space_principal.is_some() { agent_space.as_str() } else { account };
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
            agent_space,
            agent_space_principal,
            agent_space_home_present,
            persisted_new_id,
            key_opens_agent_space,
        })
    }
}

/// What the composition did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstSessionDone {
    /// The home minted here (false where it already stood).
    pub minted_home: bool,
    /// The principal seated at the agent space — op (1).
    ///
    /// It stands where the agent space is a seat: read so ahead of the act,
    /// or found or made so by op (1).
    pub agent_space_principal: Option<u64>,
    /// The agent space's home minted here — op (3).
    pub minted_agent_space_home: bool,
    /// The setup state was not sent: op (3)'s key is not enrolled there.
    ///
    /// The key stands retired, or in neither list, of the set that opens the
    /// agent space (P13); the diagnosis is handed back.
    pub setup_skipped: Option<KeyDiagnosis>,
    /// Op (1) answered `not_authorized` at an already-seeded first child.
    ///
    /// The act stopped and no agents' home is created (AUTH-5.90 (iii)'s
    /// permanent fact).
    pub setup_stopped_seeded: bool,
    /// Warnings a caller prints — a store that could not persist the line.
    pub warnings: Vec<String>,
}

/// Returns the `new_id` a persist-first line cached for `account` at `board`.
///
/// It is read where the store holds one, under the origin the board dials,
/// the one [`delegate_persisted`] writes every such line under. The line is
/// a cache and never a source (§4.3): the seat itself is read off the board,
/// so a store whose bindings cannot be read answers none, and the delegate
/// goes out under a fresh `new_id`.
pub(crate) fn persisted(board: &Board, store: Option<&FileStore>, account: &str) -> Option<u64> {
    store.and_then(|s| s.persisted_new_id(board.dialed(), account).ok().flatten())
}

/// Runs the composition over `reads` the caller took ahead of `session`.
///
/// `key` is the session's own key, which the two home mints are attested
/// under and op (3) opens under; `store` for the persist-first line (a
/// read-only one degrades to a warning, §3.7).
///
/// # Errors
///
/// The doc-1 mint's halts ([`mint_home`]); op (1)'s — the persist-first
/// delegate's, and the no-seat contradiction; op (3)'s handshake, the
/// session closed, `not_owner` or `not_an_account` faced, and any other
/// refusal; and the reads' errors.
pub fn first_session(
    board: &Board,
    reads: &FirstSessionReads,
    session: &Session<'_>,
    key: &dyn Signer,
    store: Option<&FileStore>,
) -> Result<FirstSessionDone, Halt> {
    let mut done = FirstSessionDone {
        minted_home: false,
        agent_space_principal: reads.agent_space_principal,
        minted_agent_space_home: false,
        setup_skipped: None,
        setup_stopped_seeded: false,
        warnings: Vec::new(),
    };
    // (1) The doc-1 mint, resumed by the doc-1 read.
    done.minted_home = mint_home(board, reads, session, key)?;
    // (2) The setup act, where the account holds a set of its own.
    if !reads.set_nonempty {
        return Ok(done);
    }
    if reads.agent_space_principal.is_some() && reads.agent_space_home_present {
        return Ok(done);
    }
    // Op (3)'s key, settled first (P13): not enrolled ⇒ nothing sent.
    match reads.key_opens_agent_space {
        Some(KeyDiagnosis::Enrolled { .. }) => {}
        other => {
            done.setup_skipped = Some(other.unwrap_or(KeyDiagnosis::Neither));
            return Ok(done);
        }
    }
    // Op (1): the agent space's principal — read, resumed, or delegated
    // under a persisted `new_id`.
    let principal = match reads.agent_space_principal {
        Some(principal) => principal,
        None => delegate_agent_space(board, reads, session, key, store, &mut done)?,
    };
    if done.setup_stopped_seeded {
        return Ok(done);
    }
    done.agent_space_principal = Some(principal);
    // Op (3): the mint of the agent space's home in a session as the agent
    // space, the key opening it by reference and attesting the mint;
    // idempotent by reading; closed at the end.
    if !document_present(board, &doc_1_of(&reads.agent_space))? {
        let as_agent_space = handshake(board, Scope::Content, key, principal, Site::Setup)?;
        let id = format!("first-session.space-mint.{}", reads.agent_space);
        let outcome = home_frame(board, &as_agent_space, &reads.agent_space, key, &id).and_then(|frame| as_agent_space.op(&frame));
        let _ = as_agent_space.close();
        match outcome? {
            Answer::Closed => return Err(closed()),
            Answer::Document(v) => match Rejection::of(&v) {
                None => done.minted_agent_space_home = true,
                Some(r) if matches!(r.key(), "not_owner" | "not_an_account") => {
                    return Err(Halt::face(
                        format!("the home of the agent space {} is not this session's to mint", reads.agent_space),
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

/// Runs the first state alone — the doc-1 mint by its own resume read.
///
/// It never runs the setup state: the recovery's R3 on the answer "an
/// agent's" (`client.md` §4a.2 R3), where R4's containment insert homes in
/// the agent's doc 1 too, while AUTH-5.87 excludes an agent's account by
/// name ("an agent holds no agent space; its first child is its first
/// worker") so ops (1) and (3) would delegate the agent's first child from
/// the owner's anchor session, permanently. The mint is attested under
/// `signer`, the session's own key ([`home_frame`]). It answers whether the
/// home was minted here.
///
/// # Errors
///
/// [`home_frame`]'s halts; `mint_home_public` and an `attestation_*` refusal
/// are faced as this client's own fault; the session closed, any other
/// refusal and the reads' errors halt.
pub fn mint_home(board: &Board, reads: &FirstSessionReads, session: &Session<'_>, signer: &dyn Signer) -> Result<bool, Halt> {
    if document_present(board, &reads.home)? {
        return Ok(false);
    }
    let frame = home_frame(board, session, &reads.account, signer, &format!("first-session.mint.{}", reads.account))?;
    let v = match session.op(&frame)? {
        Answer::Closed => return Err(closed()),
        Answer::Document(v) => v,
    };
    match Rejection::of(&v) {
        None => Ok(true),
        Some(r) if r.key() == "mint_home_public" => {
            Err(Halt::face("the home mint was refused as a draft", r.token(), "this client passes `published: true`; this is its own fault"))
        }
        Some(r) if r.key().starts_with("attestation_") => Err(Halt::face(
            "the board judged the home mint's attest and refused",
            format!("{}: the frame this client composed did not verify under the set that opens the account as of the base, or the board had no head", r.token()),
            "this is this client's frame and never your act; `board_unavailable` is a reorder — retry once the head is written",
        )),
        Some(r) => Err(r.refused(&v)),
    }
}

/// Returns the home mint's frame for `account` under `session`, attested.
///
/// It is `frames::create_home` — the flag affirmative — carrying the `attest`
/// a first mint from a signed session owes (PUB-6.43; PUB-8.21): the entry
/// signature over the empty body, the frame's `account` the session's own
/// and its `doc` the account the home lands in, signed by `signer`, the
/// session's key — as the daemon composes the frame it verifies. The
/// bare-session mints (the claim's S2, the hosted arm's H3) take no `attest`
/// and never come here.
///
/// # Errors
///
/// A board with no `H.1` yet halts, nothing sent; an address that does not
/// parse is this client's frame; and the term read's own errors.
pub(crate) fn home_frame(board: &Board, session: &Session<'_>, account: &str, signer: &dyn Signer, id: &str) -> Result<Value, Halt> {
    let Some(term) = board.board_term()? else {
        return Err(Halt::face(
            format!("this board has no H.1 yet, so the home of {account} cannot be minted from this session"),
            "a home mint from a signed session carries an `attest` naming `H.1`'s pair as its board term, and the board answers no head",
            "retry once the board has written its head; nothing was written",
        ));
    };
    let frame_fault = || Halt::face("the home mint's frame could not be composed", "an address of the mint did not parse", "this is this client's frame; nothing was written");
    let own = parse_address(session.account()).ok_or_else(frame_fault)?;
    let parent = parse_address(account).ok_or_else(frame_fault)?;
    let mut frame = frames::create_home(account, Some(id));
    frame["attest"] = attest_member(term, &own, DocTerm::One(&parent), &entry_body_empty(ContentFreeOp::CreateNewDocument), signer);
    Ok(frame)
}

fn closed() -> Halt {
    Halt::face(
        "the session ended during the first signed session's acts",
        "the board answered `Skepd-Session: closed`",
        "re-run: both states resume by reading (AUTH-5.87; AUTH-2.109)",
    )
}

/// Runs op (1): `delegate(inc(account, 1), new_id)` by the persist-first form.
///
/// What is its own is the seeded stop and the no-seat contradiction.
///
/// # Errors
///
/// The no-seat contradiction — `not_authorized` at an address that is no
/// seat; [`delegate_persisted`]'s halts; and the `key_set` read's.
fn delegate_agent_space(
    board: &Board,
    reads: &FirstSessionReads,
    session: &Session<'_>,
    key: &dyn Signer,
    store: Option<&FileStore>,
    done: &mut FirstSessionDone,
) -> Result<u64, Halt> {
    let id = format!("first-session.delegate.{}", reads.agent_space);
    match delegate_persisted(board, session, store, reads.persisted_new_id, &reads.agent_space, &key.fingerprint(), &id, &mut done.warnings)? {
        Delegated::Committed { principal, .. } => Ok(principal),
        Delegated::Seated(principal) => {
            // AUTH-5.90 (iii): a first child already seeded by another party
            // is a permanent fact — the act stops where its set is not the
            // account's own.
            match board.key_set(&reads.agent_space)? {
                KeySetAnswer::Set(s) if !s.enrolled.is_empty() => {
                    done.setup_stopped_seeded = true;
                    done.agent_space_principal = Some(principal);
                }
                _ => {}
            }
            Ok(principal)
        }
        Delegated::NotAuthorized => Err(Halt::face(
            format!("`delegate` of {} was refused `not_authorized` and the address has no seat", reads.agent_space),
            "ω answers the seat above an unallocated address; this contradiction is this client's to report",
            "re-run; the setup act resumes by reading",
        )),
    }
}

/// What the persist-first `delegate` answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Delegated {
    /// The `delegate` stands committed under `principal`, its `new_id`.
    ///
    /// It was `sent` by this call, or found committed by the persisted
    /// `new_id`'s read-back (AUTH-5.19).
    Committed { principal: u64, sent: bool },
    /// `not_authorized` at an address already a seat.
    ///
    /// The principal seated there is read off `effective_owner` (AUTH-6.37),
    /// the persisted line corrected to it.
    Seated(u64),
    /// `not_authorized` at an address that is no seat: the site faces it.
    NotAuthorized,
}

/// Sends the persist-first `delegate` of `address` (AUTH-5.20; AUTH-5.19).
///
/// It is §4.3's rule, P4's one named exception, in its one form: the
/// persisted `new_id` read back by `principal_prefix` — this address ⇒
/// committed; no address ⇒ the delegate never landed, the same `new_id`
/// sent again; another address ⇒ the `new_id` is spent and a fresh one is
/// minted, never a resume onto it — a fresh `new_id` persisted as a binding
/// line before the frame (`key` the line's fingerprint; a store that cannot
/// append is a warning carrying the line, §3.7); `not_authorized` resolved
/// by the seat's own read and never a re-peek of the frontier (AUTH-5.87).
/// `id` is the frame's AUTH-5.6 per-session id.
///
/// # Errors
///
/// `duplicate_id` faced, and `claim_first`; the session closed; an answer
/// of a shape this client does not know; any other refusal, the board's;
/// and the reads' errors.
#[allow(clippy::too_many_arguments)]
pub(crate) fn delegate_persisted(
    board: &Board,
    session: &Session<'_>,
    store: Option<&FileStore>,
    persisted_new_id: Option<u64>,
    address: &str,
    key: &Fingerprint,
    id: &str,
    warnings: &mut Vec<String>,
) -> Result<Delegated, Halt> {
    let mut persist = |principal: u64| {
        let Some(store) = store else { return };
        let line = Binding::Enrollment { origin: board.dialed().clone(), principal, account: address.to_string(), fingerprint: *key };
        if let Err(w) = store.bind(&line) {
            warnings.push(w.to_string());
        }
    };
    let new_id = match persisted_new_id {
        Some(spent_or_sent) => match board.principal_prefix(spent_or_sent)? {
            Some(seated) if seated == address => return Ok(Delegated::Committed { principal: spent_or_sent, sent: false }),
            None => spent_or_sent,
            Some(_) => {
                let fresh = fresh_principal_id();
                persist(fresh);
                fresh
            }
        },
        None => {
            let fresh = fresh_principal_id();
            persist(fresh);
            fresh
        }
    };
    let v = match session.op(&frames::delegate(address, new_id, Some(id)))? {
        Answer::Closed => return Err(closed()),
        Answer::Document(v) => v,
    };
    if acked_addr(&v).is_some() {
        return Ok(Delegated::Committed { principal: new_id, sent: true });
    }
    let Some(r) = Rejection::of(&v) else {
        return Err(Halt::face("the delegate answered a shape this client does not know", v.to_string(), "this is a fault in this client or the board"));
    };
    match r.key() {
        "not_authorized" => match principal_of(board, address)? {
            Some(principal) => {
                persist(principal);
                Ok(Delegated::Seated(principal))
            }
            None => Ok(Delegated::NotAuthorized),
        },
        "duplicate_id" => Err(Halt::face(
            "the client-minted principal id is already registered",
            format!("{}: `new_id` {new_id} collided", r.token()),
            "re-run: the read-back finds the id registered to another address, and a FRESH id is minted (AUTH-5.20), never a resume onto the colliding one",
        )),
        "claim_first" => Err(Halt::face(
            "the board is unclaimed",
            format!("claim_first at the delegate of {address}: the board admits the claim ceremony's own shape alone until the claim lands (AUTH-3.82)"),
            "re-run `skep claim`",
        )),
        _ => Err(r.refused(&v)),
    }
}
