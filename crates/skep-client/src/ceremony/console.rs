//! The registrar's console: the queue answered (REG-4.107, REG-4.108).
//!
//! A registry's door has a queue on its board — requests written on
//! admitted homes — and this walk is the hand that answers it, under a key
//! of the binding-writing account's own set: the queue read and its triage
//! (`queue`), and the three answers with the approval's whole write list
//! (`answer`).
//!
//! **The door** ([`Door`]). The binding-writing account is the board's
//! claimant, and the door's identifier is one readable string, `realm:<64
//! hex> door:<address>` (REG-4.74): the realm the fingerprint of the key
//! set the claimant's genesis record enrolls, read off the board as a
//! mirror's realm check reads it, and the account in full form. No read
//! publishes a board's node prefix, so the full form is the registry
//! root's, whose prefix is `1.1` by rule (REG-1.69): this console is a root
//! door's, and a depth door's is its own lane's.
//!
//! **The policy** is the door's well-known document 5, read by `policy`:
//! each term from the version the rule names — the intake homes from the
//! version standing at a request's own position, the approval's hand, the
//! collection interval and a denial's grounds from the version standing at
//! the act. A door with no policy standing admits no request and writes no
//! approval and no denial (REG-4.139).
//!
//! **The two hands** ([`Hand`]; REG-4.108). An approval is a keyed act in
//! the registrar's own set, by one of two hands the policy's `approval`
//! term names: an officer's signed session, or, under open admission alone,
//! an unattended console that is a labeled registrar device key
//! ([`auto_round`]). Both make the same writes. A refusal — the failed
//! re-check's answer — is written by the approval's own hand; a denial is
//! an officer's alone. Approval is built at an open door: at an
//! invitation-only or an n-vouches door it is refused, naming the mode.
//!
//! **The approval's order, and its resume** (REG-4.123 steps 1 to 3). One
//! ordered act, each write preceded by the read that finds an earlier
//! run's:
//!
//! 1. *The mint.* The node account is `delegate`d at the board's next
//!    top-level address from the session of the principal that mints such
//!    accounts, opened by reference under the console's own key
//!    (REG-4.110) — its `new_id` on disk before the frame
//!    (`delegate_persisted`; REG-4.109). Its genesis is the request's `node`
//!    enrolment, verbatim, written from the registrar's own signed session
//!    into its own doc 1 (REG-4.95 step 2). With the genesis, the approval
//!    link, from the genesis to the request.
//! 2. *The binding.* The next prefix by next-form, read off the bindings
//!    alone (REG-2.3), bound to the account; then the read-back, through
//!    the resolver's own walk, until it finds that account at the prefix
//!    bound (REG-2.16) — a pass that loses a race takes the next prefix.
//! 3. *The reply.* The approved answer: the prefix once, the node account's
//!    pair alone at the root, the collection interval copied from the
//!    policy version standing, the disposition and that version's address
//!    (REG-4.90, REG-4.91).
//!
//! The order is the spec's for its residue: a genesis'd account no binding
//! names is safe, and is what a resume finds and binds. A run that stops
//! anywhere resumes by reading, and never mints, binds or replies twice:
//! before the mint, always, a genesis naming the request's node
//! fingerprints in the registrar's doc 1 (REG-4.86), and an account this
//! store's persist-first line names that holds no key; before the approval
//! link, the link itself; before the binding, a binding that holds the
//! account; before the reply, an answer on the thread. Every write of a run
//! carries an idempotency id no other act of it carries.
//!
//! **Two consoles at one request** (REG-4.86). An officer's console and the
//! unattended one are two hands of one registrar, and may take one request
//! in the same interval. The registration is the FIRST genesis by journal
//! order naming the request's node keys: the read-back's pass reads the
//! genesis registry again, and a console that finds another's genesis
//! ahead of its own sends no answer and retires the binding it wrote —
//! "so one request has one reply, on the thread the winner answers". Every
//! answer — approved, refused or denied — is written only after the thread
//! is read again and found unanswered. A run that leaves a request so
//! answers [`Outcome::Yielded`].

mod answer;
mod queue;

use std::sync::Arc;

pub use answer::{approve, deny, Approval, Denial, Outcome, Refusal, Yielded};
pub use queue::{
    collected, enrolment_shape, read_queue, request_shape, shape_named, ApprovalLink, PassedOver, Queue, Request, RequestKey, State, Thread, ThreadAnswer, Verdict, MAX_ENROLMENTS, MAX_ENROLMENT_KEYS,
    MAX_LABEL_BYTES,
};

use skep_identity::DoorId;
use skep_registry::{Admission, ApprovalHand};

use super::say;
use crate::address::{doc_1_of, parse_address};
use crate::board::Board;
use crate::ceremony::policy::NoPolicy;
use crate::dial::Dialer;
use crate::halt::Halt;
use crate::person::Person;
use crate::resolve::root_hint;
use crate::sign::Signer;
use crate::store::FileStore;

/// The registry root's node prefix (REG-1.69).
///
/// A daemon started at this prefix is the registry's own board, and its
/// accounts' full form opens with it: the door account `1.0.1` is
/// `1.1.0.1` in the door's identifier (REG-4.74).
pub const ROOT_NODE_PREFIX: &str = "1.1";

/// The tier a root door binds prefixes of: `1.N` (REG-1.86 (c)).
pub(crate) const ROOT_TIER: &str = "1";

/// The first prefix a root door allocates: `1.2`, `1.1` being the
/// registry's own board.
pub(crate) const FIRST_ROOT_PREFIX: u64 = 2;

/// The hand a console act is written by (REG-4.108).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hand {
    /// An officer's signed session: a person is present.
    Officer,
    /// The unattended console, a labeled registrar device key.
    Unattended,
}

/// A registry's door, as its console reads it off the board.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Door {
    /// The binding-writing account, in the board's own form: its claimant.
    pub account: String,
    /// That account's doc 1: the home of every binding, answer and
    /// approval link the console writes.
    pub home: String,
    /// The door's identifier (REG-4.74).
    pub id: DoorId,
}

impl Door {
    /// Reads the door of the board `board` dials.
    ///
    /// The claimant and the realm are read as a guest through `dialer`, by
    /// the read a mirror's realm check makes (`resolve::root_hint`), which
    /// pages the board's feed no further than its claim.
    ///
    /// # Errors
    ///
    /// `root_hint`'s halts — an unclaimed board has no realm and no door —
    /// and a claimant whose address is not an account of this board's own
    /// node, faced as the board's fault.
    pub fn read(board: &Board, dialer: Arc<dyn Dialer>) -> Result<Door, Halt> {
        let (hint, genesis) = root_hint(dialer, board.dialed(), &[], None)?;
        let account = genesis.claimant.to_string();
        let full = account.strip_prefix("1.0.").map(|rest| format!("{ROOT_NODE_PREFIX}.0.{rest}")).and_then(|full| parse_address(&full));
        let Some(full) = full else {
            return Err(Halt::face(
                format!("the board's claimant, {account}, is no account of its own node"),
                "a door's binding-writing account is an account of the board it is on, `1.0.<n>` in that board's own form (REG-2.4)",
                "this is a fault in the board; nothing was written",
            ));
        };
        Ok(Door { home: doc_1_of(&account), account, id: DoorId { realm: hint.realm().genesis, fork: None, door: full } })
    }
}

/// A console: who acts, on which board, with which key and store.
pub struct Console<'a> {
    /// The board the door is on.
    pub board: &'a Board,
    /// The console's key store: the persist-first lines of the accounts it
    /// delegates are kept there (REG-4.109).
    pub store: &'a FileStore,
    /// The console's key: a key of the binding-writing account's own set.
    pub signer: &'a dyn Signer,
    /// The registrar's own principal: the one seated at the door account.
    pub principal: u64,
    /// The hand that acts.
    pub hand: Hand,
    /// The dialer the door's realm and the read-back are read through: a
    /// registry mirror's (`resolve::mirror_dialer`).
    pub dialer: Arc<dyn Dialer>,
}

/// Returns the halt a door with no policy standing comes to.
pub(crate) fn no_policy(no: &NoPolicy) -> Halt {
    Halt::face(
        no.to_string(),
        "a door with no policy standing is shut: no request is admitted, no approval and no denial is written (REG-4.139)",
        "publish the door's policy — `skep set-policy <file>` — and run this again; nothing was written",
    )
}

/// Why the unattended hand does not act at a door, where it does not.
///
/// It acts only where the policy standing is open admission naming the
/// `auto` hand (REG-4.108): `None` there, and otherwise the reason, in this
/// console's words.
pub fn unattended_withheld(queue: &Queue) -> Option<String> {
    let standing = match queue.policy.standing() {
        Ok(standing) => standing,
        Err(no) => return Some(no.to_string()),
    };
    match (standing.policy.approval_hand(), &standing.policy.admission) {
        (Some(ApprovalHand::Unattended), Admission::Open) => None,
        (None, _) => Some(format!("the policy standing, {}, names no approval hand this console knows (`approval` is `{}`): no approval is written under it", standing.version.address, crate::sheet::render_inert(&standing.policy.approval))),
        (_, admission) => Some(format!(
            "the policy standing, {}, is `{}` admission approved by `{}`: the unattended hand approves only at an open door whose `approval` is `auto`, and otherwise the hand is an officer's",
            standing.version.address,
            admission.as_str(),
            crate::sheet::render_inert(&standing.policy.approval)
        )),
    }
}

/// One pass of the unattended hand over the queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Round {
    /// What the pass did, one outcome a request it answered, in order.
    pub acts: Vec<Outcome>,
    /// Why the hand acted on nothing, where the policy withholds it.
    pub withheld: Option<String>,
    /// Whether the pass ended at `stop`, between two acts.
    pub stopped: bool,
    /// The requests still waiting when the pass ended.
    pub waiting: usize,
}

/// Runs one pass of the unattended hand: every waiting request answered.
///
/// The queue is read; where the policy standing does not open the
/// unattended hand ([`unattended_withheld`]) nothing is written and the
/// reason is answered. Otherwise each waiting request, in journal order,
/// is approved where it passes the re-check and refused where it fails it
/// — never denied: a denial is an officer's. `stop` is asked between two
/// requests and never inside one: an act under way runs to its end.
///
/// **Precondition.** `console.hand` is [`Hand::Unattended`].
///
/// # Errors
///
/// The reads' halts, and the first halt an act comes to; a hand that is not
/// the unattended one is this client's caller's fault.
pub fn auto_round(console: &Console<'_>, person: &mut dyn Person, stop: &dyn Fn() -> bool) -> Result<Round, Halt> {
    if console.hand != Hand::Unattended {
        return Err(Halt::face("this console is not the unattended hand", "a pass over the queue is the unattended console's act", "this is this client's frame; nothing was written"));
    }
    let door = Door::read(console.board, console.dialer.clone())?;
    let queue = read_queue(console.board, None, &door)?;
    let mut round = Round { acts: Vec::new(), withheld: unattended_withheld(&queue), stopped: false, waiting: queue.waiting().count() };
    if round.withheld.is_some() {
        return Ok(round);
    }
    for thread in queue.waiting() {
        if stop() {
            round.stopped = true;
            break;
        }
        say(person, "REG-4.108", format!("the request {} is answered by the unattended hand", thread.request.link));
        round.acts.push(answer::answer(console, person, &door, &queue, &thread.request.link)?);
        round.waiting = round.waiting.saturating_sub(1);
    }
    Ok(round)
}

/// The test seam inside the approval: a hold between the mint and the
/// binding.
///
/// Compiled only under `test-hooks`. Where `SKEP_TEST_HOLD_APPROVAL` names
/// a directory, the approval writes a file `held` there once its mint is
/// done and waits until a file `release` stands beside it: a suite sends
/// the process a signal while it is held, and sees the act run to its end.
#[cfg(feature = "test-hooks")]
pub(crate) mod hooks {
    /// Holds the approval where the variable names a directory.
    pub(crate) fn hold_after_the_mint() {
        let Some(dir) = std::env::var_os("SKEP_TEST_HOLD_APPROVAL").map(std::path::PathBuf::from) else { return };
        if std::fs::write(dir.join("held"), b"held\n").is_err() {
            return;
        }
        while !dir.join("release").exists() {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}
