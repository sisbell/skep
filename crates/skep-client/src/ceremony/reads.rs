//! R0's READS (`client.md` §4a.2 R0), the head every recovery-family walk
//! shares — `recover`'s two arms, `retire` and `rotate` — in R0's own order:
//! the ORIGIN ARM first (AUTH-5.24), the mode (AUTH-5.86), `principal_prefix`
//! (AUTH-5.67 (2)), `key_set` AT THE SET THE WALK REACHES (AUTH-5.21;
//! AUTH-4.30 (i)), the account's own doc 1 (`first_session`'s first state's
//! resume read), and THE ADMITTED READ once, PRICED before the first face
//! (AUTH-5.68; §9 item 50). The halts are R0's: `claimant == null` ⇒ `skep
//! claim`; the terminus EMPTY ⇒ the never-keyed face; an account that opens
//! BY REFERENCE ⇒ at a walk that ENROLLS, the halt naming where the act is
//! made (AUTH-6.37; the twin of `not_holder_retirement`'s redirect,
//! AUTH-3.56). The A4 cell (AUTH-5.60 step 4's table; AUTH RES-174's rider)
//! is derived here too, off the pair and the origin dialed, for the report's
//! and the operator sentence's sake.

use skep_identity::{Fingerprint, PublicKey};

use crate::board::{Board, Health};
use crate::ceremony::first_session::document_present;
use crate::derive::records::{credential_records, Records};
use crate::derive::{doc_1_of, origin_arm, parent_account, principal_of, walk_to_set, Mode, Walk};
use crate::halt::Halt;
use crate::person::{Person, Public, Statement};

/// AUTH-5.60 step 4's A4 cell, as the recovering party stands in it:
/// SERVED, a LOOPBACK-BOUND notebook, a BIND-OVERRIDE notebook — and, by
/// AUTH RES-174's rider, a party recovering at an account another party
/// gave them, routed to the served row's instrument with the GIVER as the
/// operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum A4Cell {
    Served,
    LoopbackNotebook,
    BindOverrideNotebook,
    HandoffRecipient { giver: String },
}

impl A4Cell {
    /// The cell off `/health`'s pair and the origin dialed (§4a.2 R6): a
    /// loopback dial with only loopback origins configured is the
    /// loopback-bound notebook; a loopback dial with a configured
    /// non-loopback origin is the bind-override notebook; any other dial is
    /// a served board. An account that hangs beneath another account's set
    /// — a handoff's recipient — takes the rider.
    pub fn of(board: &Board, health: &Health, account: &str, walk: &Walk) -> A4Cell {
        if let Some(parent) = parent_account(account) {
            if !walk.set.is_empty() && walk.set_account == account {
                let giver = walk_to_set(board, &parent).map(|w| w.set_account).unwrap_or(parent);
                return A4Cell::HandoffRecipient { giver };
            }
        }
        if board.dialed.names_loopback_host() {
            let overridden = health.origins().iter().any(|o| crate::origin::Origin::parse(o).is_some_and(|x| !x.names_loopback_host()));
            return if overridden { A4Cell::BindOverrideNotebook } else { A4Cell::LoopbackNotebook };
        }
        A4Cell::Served
    }

    pub fn name(&self) -> String {
        match self {
            A4Cell::Served => "a SERVED board".into(),
            A4Cell::LoopbackNotebook => "a LOOPBACK-BOUND notebook".into(),
            A4Cell::BindOverrideNotebook => "a BIND-OVERRIDE notebook".into(),
            A4Cell::HandoffRecipient { giver } => format!("a handed-off subdivision at {giver}'s board"),
        }
    }
}

/// R0's answer.
#[derive(Debug, Clone)]
pub struct Reads {
    pub health: Health,
    pub mode: Mode,
    /// `principal_prefix(n)` — the account A.
    pub account: String,
    pub principal: u64,
    /// AUTH-5.21's walk from A.
    pub walk: Walk,
    /// The principal seated at the set account — the one a session there
    /// is opened as (A's own where A holds its own set).
    pub set_principal: u64,
    /// A's own doc 1 and whether it stands.
    pub home: String,
    pub home_present: bool,
    /// The admitted read at the set account, made once.
    pub records: Records,
    pub cell: A4Cell,
}

fn say(person: &mut dyn Person, rule: &'static str, text: impl Into<String>) {
    person.say(Public(Statement { rule, text: text.into() }));
}

/// R0, in its order. `enrolls` names a walk whose act is an ENROLLMENT
/// (recover's device arm, rotate), which halts at an account that opens by
/// reference; a retirement is REDIRECTED to the set account instead.
pub fn r0(board: &Board, person: &mut dyn Person, principal: u64, enrolls: bool, own: &[(Fingerprint, PublicKey)]) -> Result<Reads, Halt> {
    let health = board.health()?;
    // The ORIGIN ARM first (AUTH-5.24; AUTH-5.65).
    origin_arm(&board.signed, &health)?;
    let mode = Mode::of(&health);
    if mode == Mode::Unclaimed {
        // AUTH-5.60 step 1's LOST-with-no-volume arm; AUTH-5.72's notebook arm.
        return Err(Halt::face(
            "no board here recovers: this board is UNCLAIMED",
            "`/health.auth.claimant` is null — a fresh board, on which no account of yours exists; a lost notebook with no volume \
             copy is a fresh board and nothing carries (AUTH-5.60 step 1; AUTH-5.72's notebook arm)",
            "run `skep claim` on this board",
        ));
    }
    let Some(account) = board.principal_prefix(principal)? else {
        return Err(Halt::face(
            format!("principal {principal} is not a registered account on this board"),
            "`principal_prefix` answered null (AUTH-5.65's cell; AUTH-5.22: a mistyped principal is faced at import, before any signature)",
            "check the principal number and the board",
        ));
    };
    let walk = walk_to_set(board, &account)?;
    if walk.terminus_empty() {
        return Err(Halt::face(
            format!("no key set opens {account}: the walk from it reached no set"),
            "AUTH-5.25 (ii)'s never-keyed state: `key_set` is empty at the account and at every account above it",
            "no retry clears this; at a board you claimed, the claim's genesis did not land — re-run `skep claim`",
        ));
    }
    let set_principal = match principal_of(board, &walk.set_account)? {
        Some(p) => p,
        None => principal,
    };
    if walk.by_reference() && enrolls {
        // AUTH-6.37; the enrollment-side twin of `not_holder_retirement`'s
        // redirect (AUTH-3.56).
        return Err(Halt::face(
            format!("{account} opens by reference and holds no keys of its own, so no key is enrolled AT it"),
            format!(
                "`key_set({account})` is empty and the set that opens it stands at {} (AUTH-4.30 (i); every unseeded account answers empty by law, AUTH-6.19)",
                walk.set_account
            ),
            format!("make the act at {} — principal {set_principal} — where the set that opens it stands (AUTH-6.37)", walk.set_account),
        ));
    }
    let home = doc_1_of(&account);
    let home_present = document_present(board, &home)?;
    // THE ADMITTED READ, once, priced here (§4a.2 R0; §1.1's cost).
    say(
        person,
        "AUTH-5.68 (cost)",
        format!(
            "reading the credential records of {} over its two residence addresses — a discovery, then per record two frames \
             and a bisection over /op-at (at most log2 of the head's {} positions each); this read is made once and held for the walk",
            walk.set_account,
            health.log_position()
        ),
    );
    let records = credential_records(board, &walk.set_account, own)?;
    say(person, "AUTH-5.68 (cost)", format!("read {} credential records at {}", records.records.len(), walk.set_account));
    let cell = A4Cell::of(board, &health, &account, &walk);
    Ok(Reads { health, mode, account, principal, walk, set_principal, home, home_present, records, cell })
}

/// An account's own doc 1 (`first_session`'s first state's resume read,
/// taken at R0 so R3's call has it).
pub fn home_of(board: &Board, account: &str) -> Result<(String, bool), Halt> {
    let home = doc_1_of(account);
    let present = document_present(board, &home)?;
    Ok((home, present))
}
