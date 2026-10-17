//! The claim (`client.md` §4): AUTH-5.55 as a state machine.
//!
//! It is P4, one state per AUTH-5.56 boundary, every state resumed by
//! reading the board (§4.4: no claim journal) — and, in its child `hosted`,
//! the hosted arm (§4.5; AUTH-5.55 step 8), every session bare, no `Person`
//! call anywhere.

use std::path::PathBuf;

use skep_identity::{Enrollment, Fingerprint};

use super::say;
use crate::address::doc_1_of;
use crate::board::{acked_addr, frames, Answer, Board, KeySetAnswer, Rejection, Scope, SessionBody, Opened, Token, T_CLAIM};
use crate::ceremony::backup::{backup_moment, BackupOptions, Venue};
use crate::ceremony::deposit::{deposit, Deposit, DepositKind, DepositOutcome};
use crate::ceremony::first_session::{document_present, first_session, FirstSessionReads};
use crate::ceremony::handshake::{handshake, handshake_prechecked, Site};
use crate::derive::{precheck, principal_of, Mode};
use crate::halt::Halt;
use crate::person::{Person, Public, Question};
use crate::sheet::Facts;
use crate::sign::Signer;
use crate::store::{arm4_face, Binding, FileStore, KeyFacts, KeySelector, KeyStore, Purpose, StoreError};

mod hosted;

pub use hosted::{hosted, HostedOutcome, HostedReply};

/// The notebook arm's inputs.
#[derive(Debug, Clone)]
pub struct NotebookOptions {
    /// `--principal`; recommend default 1 (§9 item 9).
    pub principal: Option<u64>,
    /// `--name`: the display name (S9).
    ///
    /// It is a changeable label, never the device's name `keygen` fixed;
    /// held, the write deferred.
    pub display_name: Option<String>,
    /// `--anchor-out`, once per anchor.
    pub anchor_out: Vec<PathBuf>,
    /// `--paper`.
    pub paper: bool,
    /// The machine's host name, for the anchor boxes' per-run default.
    ///
    /// The default is §4.2 step 2's.
    pub host_name: String,
    /// The date, for the same per-run default.
    pub date: String,
}

/// What the notebook walk answers at S10.
///
/// It holds the account, its principal and the device key's fingerprint,
/// and what the walk retained — the binding line (the origin dialed beside
/// the account and the principal, §3.5), the agent space, the warnings, the
/// display name held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claimed {
    /// The claimed account.
    pub account: String,
    /// The account's principal.
    pub principal: u64,
    /// The device key's fingerprint.
    pub fingerprint: Fingerprint,
    /// The agent space's address, where it is a seat.
    ///
    /// The first session found it one or made it one.
    pub agent_space: Option<String>,
    /// The binding line the walk retained.
    pub binding_line: String,
    /// The warnings the walk raised.
    pub warnings: Vec<String>,
    /// The display name collected and held — no write (S9).
    pub display_name: Option<String>,
}

/// What `claim` answers: the board this store's, or another's (§4.3).
///
/// A fresh claim answers `Ours`; on a board already claimed the answer is
/// §4.3's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// The board is this store's, the tail finished.
    ///
    /// The message is the same whether the tail was found done or finished
    /// now.
    Ours(Claimed),
    /// "claimed by ⟨claimant⟩; no key in this store is bound to it" — exit 0.
    Stranger { claimant: String },
}

/// Returns the pre-claim residue halt (§4.4; the no-delegate-twice halt).
fn residue_halt(next: &str) -> Halt {
    Halt::face(
        format!("this board carries pre-claim residue — re-genesis before claiming (next_account_prefix answers {next}, past 1.0.2)"),
        "more than one principal stands above the genesis floor, so the claim refuses `claim_residue` from every hand and \
         the board is claimable by nobody (PUB-6.63; wire.md §Credential refusals); the retry that delegates again is the \
         one that makes it so, so this client delegates nothing",
        "stop the daemon, remove its data directory, start it fresh, and run `skep claim` again",
    )
}

/// Says S0′'s statements: the pre-install ones and the unclaimed window.
///
/// The pre-install statements are AUTH-5.55 step 0's (AUTH RES-97: both
/// rendered before step 1 all the same); the unclaimed window is step 1's.
fn statements_s0(person: &mut dyn Person, local_trust: bool) {
    let reader_clause = if local_trust {
        "; and local means the machine this board runs on: while local trust is on, anything running on it can bare-bind as you here — writing as you, and reading every draft you have already written, with no mint at all"
    } else {
        ""
    };
    say(
        person,
        "AUTH-5.85",
        format!(
            "every edit to this page, including what you later remove, is kept — this notebook's history is permanent, and it is \
             local: no mirror holds it and this board can never be made public; the records this page holds (your keys, your \
             claim, the grants you issue) stand as records of their own, so removing the text one names does not remove it: the \
             record stays in force, and the version you removed it from remains readable{reader_clause}."
        ),
    );
    say(
        person,
        "AUTH-5.74",
        "this notebook is local forever; public work happens in an org — and the venue that names as the place public work \
         happens is not reachable on any board today, and this board can never become one when they open.",
    );
    say(
        person,
        "AUTH-5.55 step 1",
        "until the claim commits this board is UNCLAIMED: anything that can reach this port can take this board permanently — \
         finish now, and do not expose this machine while the ceremony is open. What a party that claims mid-span costs you is \
         two printed anchors, a delegated account and the whole ceremony.",
    );
}

/// Returns the store's device key for this walk.
///
/// §2.2 `claim`: `--dir` alone, `--key` not consulted; §3.5's lookup: the
/// binding for (board, N), else the lone device key, else arm 4's fork —
/// its public facts, and its signer from the store that holds its seed
/// (§3a).
///
/// # Errors
///
/// Arm 4's fork where the store selects no key; the store's other refusals
/// and its signer's, as halts.
fn device_key(store: &FileStore, board: &Board, principal: u64, mode: Mode) -> Result<(KeyFacts, Box<dyn Signer>), Halt> {
    match store.select(&KeySelector::Board { origin: board.dialed(), principal: Some(principal) }, Purpose::Sign) {
        Ok(key) => {
            let signer = store.signer(&KeySelector::Path(&key.path))?;
            Ok((key, signer))
        }
        Err(StoreError::NoSelection { keys }) => Err(arm4_face(store, &keys, mode)),
        Err(e) => Err(e.into()),
    }
}

/// Runs the notebook walk, S0–S10.
///
/// # Errors
///
/// A halt at the state that meets it, in the walk's order. On a claimed
/// board, the tail's halts. S0: the reads, and the residue halt where
/// `next_account_prefix` answers other than `1.0.1` or `1.0.2`; the device
/// key's selection, arm 4's fork included. S1: the bare bind refused or
/// blocked, the delegate closed or refused, or a resumed account with no
/// seat. S2: the owner's bare bind refused or blocked, and the mint closed
/// or refused. S3/S4: `not_an_account`, a key set that is not this
/// store's, an abandoned backup moment and the genesis deposit's halts. S5:
/// the pre-check and the handshake, the claim closed, an answer of a shape
/// this client does not know, a foreign claimant, `claim_residue`,
/// `claimant_keyless` and any other refusal. S5a–S5b: the first session's
/// halts. S8: a claim that did not flip the board.
///
/// # Panics
///
/// Panics if `Enrollment::new` refuses a label the anchor box or `keygen`
/// admitted; both admit only labels it takes, so neither `expect` fires.
pub fn notebook(board: &Board, store: &FileStore, person: &mut dyn Person, opts: &NotebookOptions) -> Result<ClaimOutcome, Halt> {
    // S0 probe: the pair, the mode, the residue fact.
    let health = board.health()?;
    let mode = Mode::of(&health);
    let local_trust = health.local_trust();
    if let Some(claimant) = health.claimant() {
        return tail_or_stranger(board, store, person, opts, claimant.to_string(), local_trust);
    }
    let principal = opts.principal.unwrap_or(1);
    let next = board.next_account_prefix("1")?.unwrap_or_default();
    let (account, resumed) = match next.as_str() {
        "1.0.1" => ("1.0.1".to_string(), false),
        "1.0.2" => ("1.0.1".to_string(), true),
        other => return Err(residue_halt(other)),
    };
    // The device key, from `--dir` alone.
    let (key, device) = device_key(store, board, principal, mode)?;
    let device_fp = key.fingerprint;
    let device_public = key.public.clone();
    let device_label = key.label.clone();

    // S0′ statements before step 1 (RES-97).
    statements_s0(person, local_trust);

    // S1 bare-0 → delegate, or the resume over the delegated account by
    // address (AUTH-5.56 boundary 1 as RES-118 amends it).
    let principal = if resumed {
        match principal_of(board, &account)? {
            Some(p) => {
                say(person, "AUTH-5.56", format!("resuming over the delegated account {account} (principal {p}) by reading — nothing is delegated again"));
                p
            }
            None => return Err(residue_halt("1.0.2")),
        }
    } else {
        let boot = bare_session(board, 0, &health)?;
        let v = match board.op(Some(&boot), &frames::delegate(&account, principal, Some("claim.delegate")))? {
            Answer::Closed => return Err(Halt::face("the bootstrap session ended", "closed at the delegate", "re-run `skep claim`; the walk resumes by reading")),
            Answer::Document(v) => v,
        };
        if acked_addr(&v).is_none() {
            let r = Rejection::of(&v).map(|r| r.token()).unwrap_or_else(|| v.to_string());
            return Err(Halt::face(format!("the first delegate was refused: {r}"), "AUTH-5.55 step 1's delegate from principal 0", "re-run `skep claim`; a `claim_first` here is impossible by AUTH-3.82 and is surfaced verbatim"));
        }
        let _ = board.session_close(&boot);
        principal
    };
    let facts = Facts { account: account.clone(), principal, origin: board.signed().clone() };

    // S2 owner-bare → mint, idempotent by reading (boundary 2).
    let owner_bare = bare_session(board, principal, &health)?;
    let home = doc_1_of(&account);
    if !document_present(board, &home)? {
        let v = match board.op(Some(&owner_bare), &frames::create_home(&account, Some("claim.mint")))? {
            Answer::Closed => return Err(Halt::face("the owner's bare session ended at the mint", "closed", "re-run `skep claim`")),
            Answer::Document(v) => v,
        };
        if acked_addr(&v).is_none() {
            let r = Rejection::of(&v).map(|r| r.token()).unwrap_or_else(|| v.to_string());
            return Err(Halt::face(format!("the home mint was refused: {r}"), "AUTH-5.55 step 2", "re-run `skep claim`"));
        }
    }

    // S3/S4: owed where the genesis has not landed — `key_set(account)`
    // empty ⇒ S4 owed; holding this store's fingerprint ⇒ S5 owed; holding
    // keys that are not this store's ⇒ S4's own fork.
    let set = match board.key_set(&account)? {
        KeySetAnswer::Set(s) => s,
        KeySetAnswer::NotAnAccount => return Err(Halt::face(format!("{account} is not an account"), "`key_set` answered `not_an_account`", "re-genesis the board")),
    };
    if !set.is_empty() && set.enrolled(&device_fp).is_none() {
        return Err(Halt::face(
            format!("account {account} already holds a key set and it is not this store's"),
            "a genesis landed in the window: an earlier run of this walk whose store is gone, or another hand's partial (the \
             board is still unclaimed, so this is no foreign claim)",
            "if you hold THAT run's anchor sheets the act is AUTH-5.56 boundary 4's — the resume claim signed by an imported \
             paper anchor — and NO COMMAND IN THIS VERSION PERFORMS IT; otherwise re-genesis (stop the daemon, remove its data \
             directory, start it fresh) and run `skep claim` again — never a fresh `delegate`",
        ));
    }
    if set.is_empty() {
        // S3 names → backup moment. The device label shown, not re-asked.
        say(
            person,
            "AUTH-5.42",
            format!(
                "the device key for this board is `{}` ({device_fp}), named at `skep keygen` — its name is public, permanent, uncorrectable, and the byline on every write this key makes",
                device_label.as_deref().map(crate::sheet::render_inert).unwrap_or_else(|| "(no label)".into())
            ),
        );
        let backup = backup_moment(
            person,
            &Venue::Notebook { facts: facts.clone() },
            &BackupOptions {
                labels: Vec::new(),
                destinations: opts.anchor_out.clone(),
                paper: opts.paper,
                store: Some(store.root().to_path_buf()),
                host_name: opts.host_name.clone(),
                date: opts.date.clone(),
            },
        )
        .map_err(|h| abandonment_face(h, &account, principal))?;
        // S4 genesis: one atom, declared, from N's bare session; at or below
        // the claim no `sig`.
        let mut entries = Vec::new();
        for a in &backup.anchors {
            entries.push(Enrollment::new(a.public.clone(), true, Some(a.label.as_str().to_string())).expect("a label the box admitted"));
        }
        entries.push(Enrollment::new(device_public.clone(), false, device_label.clone()).expect("a label keygen admitted"));
        let outcome = deposit(
            board,
            &owner_bare,
            &Deposit { home: &home, subject: &account, kind: DepositKind::Enroll(entries), hand: None, id: "claim.genesis" },
        )?;
        if let DepositOutcome::Committed { reason } = &outcome {
            say(person, "AUTH-5.17", format!("the genesis stands: {reason}"));
        }
    }

    // S5 claim (signed, full): the pre-check first (both reads live), the
    // challenge, the claim link.
    let pre = precheck(board, principal, &device_fp)?;
    let signed = handshake_prechecked(board, Scope::Full, &*device, &pre, Site::Claim)?;
    let claim_frame = frames::make_link(&home, &[&account], &[], T_CLAIM, Some("claim.claim"));
    let v = match signed.op(&claim_frame)? {
        Answer::Closed => return Err(Halt::face("the signed session ended at the claim", "closed", "re-run `skep claim`")),
        Answer::Document(v) => v,
    };
    if acked_addr(&v).is_none() {
        let r = Rejection::of(&v).ok_or_else(|| Halt::face("the claim answered a shape this client does not know", v.to_string(), "this is a fault in this client or the board"))?;
        match r.key() {
            "already_claimed" => {
                // AUTH-5.17: reconcile off the claimant.
                let h = board.health()?;
                match h.claimant() {
                    Some(c) if c == account => {}
                    Some(c) => return Err(foreign_claimant(c)),
                    None => return Err(r.refused(&v)),
                }
            }
            "claim_residue" => return Err(residue_halt("past 1.0.2")),
            "claimant_keyless" => {
                return Err(Halt::face("the genesis did not land", "claimant_keyless at the claim: S4 is still owed", "re-run `skep claim`; the walk resumes from S4 by reading"))
            }
            _ => return Err(r.refused(&v)),
        }
    }
    // S5a–S5b: the agent-space act in this session, after the claim commits.
    say(person, "AUTH-5.87", "creating your account also creates a space for your agents beneath it, and its home");
    let reads = FirstSessionReads::take(board, &account, &device_fp, Some(store))?;
    let done = first_session(board, &reads, &signed, &*device, Some(store))?;
    let mut warnings = done.warnings.clone();
    // S7 close the owner's bare session (idempotent 204; dead at the flip
    // into enforcing, alive in claimed-permissive).
    let _ = board.session_close(&owner_bare);
    // S8 verify the flip.
    let after = board.health()?;
    if after.claimant() != Some(account.as_str()) {
        return Err(Halt::face("the claim did not flip the board", format!("/health.auth.claimant is {:?}", after.claimant()), "re-run `skep claim`"));
    }
    if after.signed_origins().is_empty() {
        warnings.push("warning: this board is claimed with no configured origin — signed_origins is empty and every signed session will be refused until the daemon is relaunched with `--origin` (wire.md §The claim ceremony and credentials)".into());
    }
    if after.local_trust() {
        warnings.push("the board is CLAIMED-PERMISSIVE (--local-trust on): any loopback party may still write drafts as any principal, with `key: \"bare\"` as the tell; the publish class is shut to bare sessions".into());
    }
    // S9 name: collected and held; the write deferred.
    let display_name = s9_name(person, opts)?;
    // S10 retain: the binding, the close, the three facts.
    let line = Binding::Enrollment { origin: board.dialed().clone(), principal, account: account.clone(), fingerprint: device_fp };
    if let Err(w) = store.bind(&line) {
        warnings.push(w.to_string());
    }
    let _ = signed.close();
    Ok(ClaimOutcome::Ours(Claimed {
        account,
        principal,
        fingerprint: device_fp,
        agent_space: done.agent_space_principal.map(|_| reads.agent_space.clone()),
        binding_line: line.to_string(),
        warnings,
        display_name,
    }))
}

/// Collects S9's display name, with its one distinguishing line.
///
/// The write is deferred in v1 (AUTH-5.55 step 9; RES-62 item 10 pick B).
///
/// # Errors
///
/// None: an abandoned ask answers no name.
fn s9_name(person: &mut dyn Person, opts: &NotebookOptions) -> Result<Option<String>, Halt> {
    let display_name = match &opts.display_name {
        Some(n) => Some(n.clone()),
        None => {
            say(person, "AUTH-5.55 step 9", "your display name is a LABEL, changeable later, and never an identity — unlike the device name, which is permanent and the byline on every write that key makes (R44; AUTH-5.3)");
            let answer = person.ask(Public(Question { text: "display name (leave empty to skip): ".into() })).ok();
            answer.filter(|n| !n.trim().is_empty())
        }
    };
    if let Some(n) = &display_name {
        say(person, "AUTH-5.55 step 9", format!("display name `{}` collected and HELD: no doc-1 write is made in this version — the write returns when the display-name record's form is pinned", crate::sheet::render_inert(n)));
    }
    Ok(display_name)
}

fn foreign_claimant(claimant: &str) -> Halt {
    Halt::face(
        format!("another hand claimed this board: {claimant}"),
        "the claim is irreversible (I6, AUTH-2.101), so this account and this board are gone and no act on this board \
         recovers either (AUTH-5.15's foreign-claimant arm)",
        "a FRESH board, claimed before it is exposed",
    )
}

/// Returns S3's abandonment exit: the two things the person now holds.
///
/// The exit is §4.1 S3's.
fn abandonment_face(h: Halt, account: &str, principal: u64) -> Halt {
    match h {
        Halt::Halt(face) => Halt::face(
            format!("{} — the claim stops before its genesis", face.state),
            format!(
                "{}; account {account} (principal {principal}) is delegated and recoverable residue: a re-run resumes over it by \
                 reading. (i) Any anchor files written or sheets printed name a real delegated account and open nothing, ever — \
                 destroy them, or keep them plainly marked dead, and never file them beside a live pair (their per-run token tells \
                 them apart). (ii) The unclaimed window is now true indefinitely: the daemon is still running and still unclaimed.",
                face.cause
            ),
            "stop the daemon, or finish the walk now by re-running `skep claim`",
        ),
        other => other,
    }
}

/// Opens a bare session for `principal`.
///
/// # Errors
///
/// The 401 with its two causes faced (§4.1 S1); a `403 prefix_blocked` as
/// [`Halt::Blocked`], its ground unread; and [`Board::session_open`]'s
/// errors.
fn bare_session(board: &Board, principal: u64, health: &crate::board::Health) -> Result<Token, Halt> {
    match board.session_open(SessionBody::Bare { principal })? {
        Opened::Token(t) => Ok(t),
        Opened::Rejected => Err(Halt::face(
            format!("the bare bind as principal {principal} was refused"),
            format!(
                "/health reads claimant {:?}, local_trust {}: either the board is claimed, or you dialed it through a published \
                 port — on an unclaimed board the bare bind reduces to the peer being loopback (AUTH-4.14; AUTH-4.26)",
                health.claimant(),
                health.local_trust()
            ),
            "run `skep claim` where the daemon's loopback is reachable — natively, or as the sidecar in its network namespace",
        )),
        Opened::Blocked { record } => Err(Halt::Blocked(crate::halt::Blocked { record, named_by: board.dialed().as_str().to_string(), ground: None })),
    }
}

/// Runs S0's ours test and the tail (§4.3).
///
/// `key_set(claimant)` holds this store's fingerprint ⇒ the run resumes at
/// the tail in a content-scoped session; otherwise the stranger message,
/// exit 0.
///
/// # Errors
///
/// In order: the claimant's `key_set` read and the store's key list; the
/// seat read, and a claimant with no seat, faced; the store's signer; the
/// content-scoped handshake; the first session's reads and halts; then the
/// `/health` read and the store's binding lookup.
fn tail_or_stranger(board: &Board, store: &FileStore, person: &mut dyn Person, opts: &NotebookOptions, claimant: String, local_trust: bool) -> Result<ClaimOutcome, Halt> {
    let set = match board.key_set(&claimant)? {
        KeySetAnswer::Set(s) => s,
        KeySetAnswer::NotAnAccount => return Ok(ClaimOutcome::Stranger { claimant }),
    };
    let keys = store.device_keys()?;
    let Some(ours) = keys.iter().find(|k| set.enrolled(&k.fingerprint).is_some()) else {
        return Ok(ClaimOutcome::Stranger { claimant });
    };
    let Some(principal) = principal_of(board, &claimant)? else {
        return Err(Halt::face(format!("{claimant} has no seat"), "`effective_owner` answered no allocated seat for the claimant", "this is a board fault"));
    };
    let fingerprint = ours.fingerprint;
    let device = store.signer(&KeySelector::Path(&ours.path))?;
    say(person, "§4.3", format!("this board is already yours (claimant {claimant}, principal {principal}); finishing whatever of the tail is unfinished"));
    let session = handshake(board, Scope::Content, &*device, principal, Site::Tail)?;
    say(person, "AUTH-5.87", "creating your account also creates a space for your agents beneath it, and its home");
    let reads = FirstSessionReads::take(board, &claimant, &fingerprint, Some(store))?;
    let done = first_session(board, &reads, &session, &*device, Some(store))?;
    let mut warnings = done.warnings.clone();
    let after = board.health()?;
    if after.signed_origins().is_empty() {
        warnings.push("warning: signed_origins is empty — every signed session will be refused until the daemon is relaunched with `--origin`".into());
    }
    if local_trust {
        warnings.push("the board is CLAIMED-PERMISSIVE: any loopback party may still write drafts as any principal".into());
    }
    let display_name = s9_name(person, opts)?;
    let line = Binding::Enrollment { origin: board.dialed().clone(), principal, account: claimant.clone(), fingerprint };
    let bound = store.enrollment_for(board.dialed(), principal)?.is_some_and(|(_, fp)| fp == fingerprint);
    if !bound {
        if let Err(w) = store.bind(&line) {
            warnings.push(w.to_string());
        }
    }
    let _ = session.close();
    Ok(ClaimOutcome::Ours(Claimed {
        account: claimant,
        principal,
        fingerprint,
        agent_space: done.agent_space_principal.map(|_| reads.agent_space.clone()),
        binding_line: line.to_string(),
        warnings,
        display_name,
    }))
}
