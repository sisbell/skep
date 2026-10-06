//! THE CLAIM (`client.md` §4): AUTH-5.55 as a state machine — P4, one state
//! per AUTH-5.56 boundary, every state RESUMED BY READING the board (§4.4;
//! RULED: the claim journal retired) — and, in its child `hosted`, the
//! hosted arm (§4.5; AUTH-5.55 step 8), every session bare, no `Person` call
//! anywhere.

use std::path::PathBuf;

use skep_identity::{Enrollment, Fingerprint};

use super::say;
use crate::address::doc_1_of;
use crate::board::{acked_addr, frames, Answer, Board, KeySetAnswer, Rejection, Scope, SessionBody, Opened, Token, T_CLAIM};
use crate::ceremony::backup::{backup_moment, BackupOptions, Venue};
use crate::ceremony::deposit::{deposit, Deposit, DepositKind, DepositOutcome, Grade};
use crate::ceremony::first_session::{document_present, first_session, FirstSessionReads};
use crate::ceremony::handshake::{handshake, handshake_prechecked, Site};
use crate::derive::{precheck, principal_of, Mode};
use crate::halt::Halt;
use crate::person::{Person, Public, Question};
use crate::sheet::Facts;
use crate::store::{arm4_face, store_halt, Binding, FileStore, KeySelector, KeyStore, Purpose, StoreError};

mod hosted;

pub use hosted::{hosted, HostedOutcome, HostedReply};

/// The notebook arm's inputs.
#[derive(Debug, Clone)]
pub struct NotebookOptions {
    /// `--principal`; RECOMMEND default 1 (§9 item 9).
    pub principal: Option<u64>,
    /// `--name`, held; the write deferred (S9).
    pub name: Option<String>,
    /// `--anchor-out`, once per anchor.
    pub anchor_out: Vec<PathBuf>,
    /// `--paper`.
    pub paper: bool,
    pub host: String,
    pub date: String,
}

/// The three facts and what the walk retained (S10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claimed {
    pub account: String,
    pub principal: u64,
    pub fingerprint: Fingerprint,
    /// The agent space's address, where the setup act ran or stood done.
    pub agent_space: Option<String>,
    pub binding_line: String,
    pub warnings: Vec<String>,
    /// The display name collected and HELD — no write (S9).
    pub display_name: Option<String>,
}

/// §4.3: what `claim` answers on a claimed board.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// The board is this store's — the tail finished, the same message
    /// whether found done or finished now.
    Ours(Claimed),
    /// "claimed by ⟨claimant⟩; no key in this store is bound to it" — exit 0.
    Stranger { claimant: String },
}

/// The pre-claim residue halt (§4.4; the NO-DELEGATE-TWICE halt KEPT).
fn residue_halt(next: &str) -> Halt {
    Halt::face(
        format!("this board carries pre-claim residue — re-genesis before claiming (next_account_prefix answers {next}, past 1.0.2)"),
        "more than one principal stands above the genesis floor, so the claim refuses `claim_residue` from every hand and \
         the board is claimable by nobody (PUB-6.63; wire.md §Credential refusals); the retry that delegates again is the \
         one that makes it so, so this client delegates nothing",
        "stop the daemon, remove its data directory, start it fresh, and run `skep claim` again",
    )
}

/// S0′: the pre-install statements (AUTH-5.55 step 0; AUTH RES-97: both
/// rendered before step 1 all the same) and the unclaimed window (step 1).
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

/// The store's device key for this walk (§2.2 `claim`: `--dir` alone, `--key`
/// not consulted; §3.5's lookup): the binding for (board, N), else the lone
/// device key, else arm 4's fork.
fn device_key(store: &FileStore, board: &Board, principal: u64, mode: Mode, local_trust: bool) -> Result<(PathBuf, crate::sheet::KeyFile), Halt> {
    match store.select(&KeySelector::Binding { origin: &board.dialed, principal: Some(principal) }, Purpose::Sign) {
        Ok(sel) => Ok((sel.path, sel.file)),
        Err(StoreError::NoSelection { keys }) => Err(arm4_face(store, &keys, mode, local_trust)),
        Err(e) => Err(store_halt(e)),
    }
}

/// THE NOTEBOOK WALK, S0–S10.
pub fn notebook(board: &Board, store: &FileStore, person: &mut dyn Person, opts: &NotebookOptions) -> Result<ClaimOutcome, Halt> {
    // S0 PROBE: the pair, the mode, the residue fact.
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
    let (_key_path, key_file) = device_key(store, board, principal, mode, local_trust)?;
    let device = key_file.signer();
    let device_fp = key_file.fingerprint;
    let device_public = key_file.public.clone();
    let device_label = key_file.label.clone();

    // S0′ STATEMENTS before step 1 (RES-97).
    statements_s0(person, local_trust);

    // S1 BARE-0 → DELEGATE, or the resume over the delegated account by
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
    let facts = Facts { account: account.clone(), principal, origin: board.signed.clone() };

    // S2 OWNER-BARE → MINT, idempotent by reading (boundary 2).
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
    // EMPTY ⇒ S4 owed; holding this store's fingerprint ⇒ S5 owed; holding
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
        // S3 NAMES → BACKUP MOMENT. The device label shown, not re-asked.
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
                host: opts.host.clone(),
                date: opts.date.clone(),
            },
        )
        .map_err(|h| abandonment_face(h, &account, principal))?;
        // S4 GENESIS: one atom, declared, from N's bare session; at or below
        // the claim no `sig`.
        let mut entries = Vec::new();
        for a in &backup.anchors {
            entries.push(Enrollment::new(a.public.clone(), true, Some(a.label.as_str().to_string())).expect("a label the box admitted"));
        }
        entries.push(Enrollment::new(device_public.clone(), false, device_label.clone()).expect("a label keygen admitted"));
        let outcome = deposit(
            board,
            &owner_bare,
            &Deposit { home: &home, subject: &account, kind: DepositKind::Enroll(entries), grade: Grade::Anchor, hand: None, id: "claim.genesis" },
        )?;
        if let DepositOutcome::Committed { reason } = &outcome {
            say(person, "AUTH-5.17", format!("the genesis stands: {reason}"));
        }
    }

    // S5 CLAIM (SIGNED, FULL): the pre-check first (both reads live), the
    // challenge, the claim link.
    let pre = precheck(board, principal, &device_fp)?;
    let signed = handshake_prechecked(board, Scope::Full, &device, principal, &pre, Site::Claim)?;
    let claim_frame = frames::make_link(&home, &[&account], &[], T_CLAIM, Some("claim.claim"));
    let v = match signed.op(board, &claim_frame)? {
        Answer::Closed => return Err(Halt::face("the signed session ended at the claim", "closed", "re-run `skep claim`")),
        Answer::Document(v) => v,
    };
    if acked_addr(&v).is_none() {
        let r = Rejection::of(&v).ok_or_else(|| Halt::face("the claim answered a shape this client does not know", v.to_string(), "this is a fault in this client or the board"))?;
        match r.detail.as_deref().unwrap_or("") {
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
    let reads = FirstSessionReads::take(board, &account, &device_fp, Some(store), &board.dialed)?;
    let done = first_session(board, &reads, &signed, &device, Some(store))?;
    let mut warnings = done.warnings.clone();
    // S7 CLOSE the bare sessions (idempotent 204; dead at the flip into
    // ENFORCING, alive in CLAIMED-PERMISSIVE).
    let _ = board.session_close(&owner_bare);
    // S8 VERIFY the flip.
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
    // S9 NAME: collected and held; the write deferred.
    let display_name = s9_name(person, opts)?;
    // S10 RETAIN: the binding, the close, the three facts.
    let line = Binding::Enrollment { origin: board.dialed.clone(), principal, account: account.clone(), fingerprint: device_fp };
    if let Err(e) = store.bind(&line) {
        warnings.push(format!("the store could not be appended ({e}); record this binding line yourself: {}", line.line()));
    }
    let _ = signed.close(board);
    Ok(ClaimOutcome::Ours(Claimed {
        account,
        principal,
        fingerprint: device_fp,
        agent_space: done.space_seat.map(|_| reads.space.clone()),
        binding_line: line.line(),
        warnings,
        display_name,
    }))
}

/// S9: the display name, with its one distinguishing line; the write
/// deferred in v1 (AUTH-5.55 step 9; RES-62 item 10 pick B).
fn s9_name(person: &mut dyn Person, opts: &NotebookOptions) -> Result<Option<String>, Halt> {
    let name = match &opts.name {
        Some(n) => Some(n.clone()),
        None => {
            say(person, "AUTH-5.55 step 9", "your display name is a LABEL, changeable later, and never an identity — unlike the device name, which is permanent and the byline on every write that key makes (R44; AUTH-5.3)");
            let answer = person.ask(Public(Question { text: "display name (leave empty to skip): ".into() })).ok();
            answer.filter(|n| !n.trim().is_empty())
        }
    };
    if let Some(n) = &name {
        say(person, "AUTH-5.55 step 9", format!("display name `{}` collected and HELD: no doc-1 write is made in this version — the write returns when the display-name record's form is pinned", crate::sheet::render_inert(n)));
    }
    Ok(name)
}

fn foreign_claimant(claimant: &str) -> Halt {
    Halt::face(
        format!("another hand claimed this board: {claimant}"),
        "the claim is irreversible (I6, AUTH-2.101), so this account and this board are gone and no act on this board \
         recovers either (AUTH-5.15's foreign-claimant arm)",
        "a FRESH board, claimed before it is exposed",
    )
}

/// S3's abandonment exit: the two things the person now holds (§4.1 S3).
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

/// A bare session for `principal`; the 401's two causes faced (§4.1 S1).
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
        Opened::Blocked { record } => Err(Halt::Blocked(crate::halt::Blocked { record, named_by: board.dialed.as_str().to_string(), ground: None })),
    }
}

/// S0's OURS test and the tail (§4.3): `key_set(claimant)` holds this
/// store's fingerprint ⇒ the run RESUMES AT THE TAIL in a CONTENT-scoped
/// session; otherwise the stranger message, exit 0.
fn tail_or_stranger(board: &Board, store: &FileStore, person: &mut dyn Person, opts: &NotebookOptions, claimant: String, local_trust: bool) -> Result<ClaimOutcome, Halt> {
    let set = match board.key_set(&claimant)? {
        KeySetAnswer::Set(s) => s,
        KeySetAnswer::NotAnAccount => return Ok(ClaimOutcome::Stranger { claimant }),
    };
    let keys = store.list().map_err(store_halt)?;
    let Some(ours) = keys.iter().find(|k| !k.anchor && set.enrolled(&k.fingerprint).is_some()) else {
        return Ok(ClaimOutcome::Stranger { claimant });
    };
    let Some(principal) = principal_of(board, &claimant)? else {
        return Err(Halt::face(format!("{claimant} has no seat"), "`effective_owner` answered no allocated seat for the claimant", "this is a board fault"));
    };
    let file = store.load(&ours.path).map_err(store_halt)?;
    let device = file.signer();
    say(person, "§4.3", format!("this board is already yours (claimant {claimant}, principal {principal}); finishing whatever of the tail is unfinished"));
    let session = handshake(board, Scope::Content, &device, principal, Site::Tail)?;
    say(person, "AUTH-5.87", "creating your account also creates a space for your agents beneath it, and its home");
    let reads = FirstSessionReads::take(board, &claimant, &file.fingerprint, Some(store), &board.dialed)?;
    let done = first_session(board, &reads, &session, &device, Some(store))?;
    let mut warnings = done.warnings.clone();
    let after = board.health()?;
    if after.signed_origins().is_empty() {
        warnings.push("warning: signed_origins is empty — every signed session will be refused until the daemon is relaunched with `--origin`".into());
    }
    if local_trust {
        warnings.push("the board is CLAIMED-PERMISSIVE: any loopback party may still write drafts as any principal".into());
    }
    let display_name = s9_name(person, opts)?;
    let line = Binding::Enrollment { origin: board.dialed.clone(), principal, account: claimant.clone(), fingerprint: file.fingerprint };
    let bound = store.enrollment_for(&board.dialed, principal).map_err(store_halt)?.is_some_and(|(_, fp)| fp == file.fingerprint);
    if !bound {
        if let Err(e) = store.bind(&line) {
            warnings.push(format!("the store could not be appended ({e}); record this binding line yourself: {}", line.line()));
        }
    }
    let _ = session.close(board);
    Ok(ClaimOutcome::Ours(Claimed {
        account: claimant,
        principal,
        fingerprint: file.fingerprint,
        agent_space: done.space_seat.map(|_| reads.space.clone()),
        binding_line: line.line(),
        warnings,
        display_name,
    }))
}
