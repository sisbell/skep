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
//! is derived here too — the venue off the pair and the origin dialed, the
//! rider's giver off its own walk — for the report's and the operator
//! sentence's sake.

use skep_identity::{Fingerprint, PublicKey};

use super::say;
use crate::address::{doc_1_of, parent_account};
use crate::board::{Board, Health};
use crate::ceremony::first_session::document_present;
use crate::derive::records::{credential_records, Records};
use crate::derive::{origin_arm, principal_of, walk_to_set, Mode, Walk};
use crate::halt::Halt;
use crate::person::Person;

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
    /// The cell `account` stands in (§4a.2 R6): an account that hangs beneath
    /// another account's set — a handoff's recipient — takes RES-174's rider,
    /// the GIVER read by AUTH-5.21's walk from the account above (a fault of
    /// that read halts, never a guessed giver); every other account stands in
    /// its board's [`A4Cell::venue`].
    pub fn of(board: &Board, health: &Health, account: &str, walk: &Walk) -> Result<A4Cell, Halt> {
        if let Some(parent) = parent_account(account) {
            if !walk.set.is_empty() && walk.set_account == account {
                let giver = walk_to_set(board, &parent)?.set_account;
                return Ok(A4Cell::HandoffRecipient { giver });
            }
        }
        Ok(A4Cell::venue(board, health))
    }

    /// The board's VENUE, off `/health`'s pair and the origin dialed, no read
    /// made: a loopback dial with only loopback origins configured is the
    /// loopback-bound notebook; a loopback dial with a configured
    /// non-loopback origin is the bind-override notebook; any other dial is a
    /// served board.
    pub fn venue(board: &Board, health: &Health) -> A4Cell {
        if board.dialed().names_loopback_host() {
            let overridden = health.origins().iter().any(|o| crate::origin::Origin::parse(o).is_some_and(|x| !x.names_loopback_host()));
            return if overridden { A4Cell::BindOverrideNotebook } else { A4Cell::LoopbackNotebook };
        }
        A4Cell::Served
    }

    /// The board is the person's own — a notebook, loopback-bound or
    /// bind-override, whose volume copy is theirs to take; a recipient's
    /// board is never their own.
    pub fn own_board(&self) -> bool {
        matches!(self, A4Cell::LoopbackNotebook | A4Cell::BindOverrideNotebook)
    }
}

/// R0's answer: what the walks after it act on.
#[derive(Debug, Clone)]
pub struct Reads {
    /// `principal_prefix(n)` — the account A.
    pub account: String,
    /// AUTH-5.21's walk from A.
    pub walk: Walk,
    /// The principal seated at the set account — the one a session there
    /// is opened as (A's own where A holds its own set).
    pub set_principal: u64,
    /// A's own doc 1 — the home `recover`'s retirements are written to.
    pub home: String,
    /// The admitted read at the set account, made once.
    pub records: Records,
    pub cell: A4Cell,
}

/// The credential act the walk over R0's reads makes at the account it
/// read — what R0 decides by at an account that opens BY REFERENCE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Act {
    /// An ENROLLMENT (`recover`'s two arms, `rotate`): no key is enrolled AT
    /// an account that opens by reference, so R0 halts there naming where
    /// the act is made (AUTH-6.37).
    Enrollment,
    /// A RETIREMENT (`retire`): REDIRECTED to the set account, where the key
    /// stands as that account's own (`not_holder_retirement`'s redirect,
    /// AUTH-3.56).
    Retirement,
}

/// R0, in its order, for a walk whose act is `act`.
pub fn r0(board: &Board, person: &mut dyn Person, principal: u64, act: Act, own: &[(Fingerprint, PublicKey)]) -> Result<Reads, Halt> {
    let health = board.health()?;
    // The ORIGIN ARM first (AUTH-5.24; AUTH-5.65).
    origin_arm(board.signed(), &health)?;
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
    if walk.by_reference() && act == Act::Enrollment {
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
    // A's own doc 1, read in R0's order: a home the board will not answer for
    // halts here, ahead of the import. The walk that mints it reads it again
    // where it acts (`FirstSessionReads`).
    document_present(board, &home)?;
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
    let cell = A4Cell::of(board, &health, &account, &walk)?;
    Ok(Reads { account, walk, set_principal, home, records, cell })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::board::fake::Fake;
    use crate::origin::Origin;

    fn health(origins: &[&str]) -> Health {
        let body = json!({"auth": {"claimant": "1.0.1", "local_trust": false, "origins": origins, "signed_origins": origins}, "log_position": 9});
        Health { raw: body.to_string().into_bytes(), body }
    }

    /// AUTH-5.60 step 4's venue, off `/health`'s pair and the origin dialed
    /// with NO read: a loopback dial with loopback origins alone is the
    /// loopback-bound notebook, one with a configured non-loopback origin
    /// beside them the bind-override notebook, and any other dial a SERVED
    /// board; a notebook is the person's own board, a served board and a
    /// recipient's never.
    #[test]
    fn the_venue_is_a_notebook_only_where_the_board_is_dialed_on_loopback() {
        let venue = |dialed: &str, origins: &[&str]| A4Cell::venue(&Board::new(Origin::parse(dialed).unwrap(), Fake::unread()), &health(origins));
        let loopback = ["http://127.0.0.1:8642", "http://localhost:8642", "http://[::1]:8642"];
        let overridden = [&loopback[..], &["https://board.example"]].concat();
        for dialed in ["http://127.0.0.1:8642", "http://[::1]:8642"] {
            assert_eq!(venue(dialed, &loopback), A4Cell::LoopbackNotebook, "{dialed}");
            assert_eq!(venue(dialed, &overridden), A4Cell::BindOverrideNotebook, "{dialed}");
        }
        for dialed in ["https://board.example", "http://10.0.0.7:8642", "http://board.example:8642"] {
            for origins in [&loopback[..], &overridden[..]] {
                assert_eq!(venue(dialed, origins), A4Cell::Served, "{dialed} with {origins:?}");
            }
        }
        let cells = [A4Cell::LoopbackNotebook, A4Cell::BindOverrideNotebook, A4Cell::Served, A4Cell::HandoffRecipient { giver: "1.0.1".into() }];
        assert_eq!(cells.iter().map(A4Cell::own_board).collect::<Vec<_>>(), [true, true, false, false]);
    }
}
