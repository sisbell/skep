//! The labels of the keys another device holds (skep #869).
//!
//! A hand whose key this shell's store does not hold goes by the label the
//! account's credential records give it, and by its fingerprint alone where
//! no verified record gives one (`client.md` §4b.2's `held` event).
//! [`Holds::recorded_label`] answers that label, off the reads a board's
//! hold keeps for each account.
//!
//! **Only a verified label.** A label comes from an admission of the
//! signature-filtered table (`skep_client::verify::filtered_table`; REG-3.39,
//! the signed-ops design record §4.5's table paragraph), never from a record
//! the board merely serves, so a planted enrollment names nothing. An
//! admission outlives its key's retirement, so a device since retired keeps
//! its name on the rows it wrote. The table judges a genesis under its
//! delegator's set (that paragraph's clause (a)), which one account's records
//! do not hold: a read takes the claimant's account, the accounts above the
//! session's key set's, top-down, and the set's own ([`accounts_read`]), and
//! [`admitted_labels`] orders them as the journal does and keeps the
//! admissions of the set's own account. Below the retention floor no order
//! crosses accounts (that paragraph's clause (d)), so a delegated account's
//! record read position-free leaves every label of its table unnamed; the
//! claimant's own records order among themselves.
//!
//! **One read, kept.** A read is made outside the board's lock, at most once
//! per hands read, and kept by the account it was made for. A key no kept
//! read names is read again only at a row past the kept read's head: an
//! enrollment precedes every row its key wrote, so a read at or past a row
//! has seen that row's key, and a key it does not name stays unnamed. A
//! session with no key set, the keyless session, reads nothing.
//!
//! **What a read costs (SP-23).** It is one `credential_records` per account
//! on the chain, the depth of the session's key set beneath its node: a claim
//! link, the two discovery reads of the account's records, and for each
//! record its `read_link`, its atom's read through its home's I→V inversion,
//! its hand and the bisection for its position, at most 2·⌈log₂ head⌉ + 3
//! `/op-at` probes (AUTH-5.68).
//!
//! **A read that fails** — a board not answering, a busy history, the death
//! signal at one of its token-free reads — names no label and ends no
//! session, and what an earlier read gave stands (SP-14). Its cause is said
//! in the shell's own window once per change, and once more as a read next
//! succeeds (SP-11).

use std::collections::HashMap;
use std::iter;

use skep_client::address::{parent_account, parse_address};
use skep_client::derive::records::{credential_records, Records};
use skep_client::sheet::render_inert;
use skep_client::store::KeyFacts;
use skep_client::verify::filtered_table;
use skep_identity::{BoardTerm, Fingerprint, PublicKey};

use super::Holds;
use crate::sessions::{SessionEntry, SessionKind};

/// One account's key labels, as a board's hold keeps them.
#[derive(Debug, Default)]
pub(super) struct AccountLabels {
    /// What the newest read that succeeded gave, where one has.
    read: Option<LabelsRead>,
    /// The cause last said of a read that failed, until a read succeeds.
    failing: Option<String>,
}

/// What one read of an account's credential records gave.
#[derive(Debug)]
struct LabelsRead {
    /// The labels the verified records give, by fingerprint.
    labels: HashMap<String, String>,
    /// The lowest head its accounts were read at.
    ///
    /// A record at or below it, the read has seen.
    head: u64,
}

impl AccountLabels {
    /// Returns whether a read is owed for `key`, named at a row at `at`.
    ///
    /// One is owed where no read succeeded, or where the kept one does not
    /// name `key` and the row stands past its head.
    fn owes_read(&self, key: &str, at: Option<u64>) -> bool {
        self.read.as_ref().is_none_or(|read| !read.labels.contains_key(key) && at.is_some_and(|at| at > read.head))
    }

    /// Returns a kept read naming `key` as `label`, made at `head`.
    ///
    /// It is the suites' seam: the fake board serves no credential record.
    #[cfg(test)]
    pub(super) fn naming(key: &str, label: &str, head: u64) -> AccountLabels {
        AccountLabels { read: Some(LabelsRead { labels: HashMap::from([(key.to_string(), label.to_string())]), head }), failing: None }
    }
}

impl Holds {
    /// Returns the label the account's verified records give `key`, inert.
    ///
    /// `key`, a fingerprint this store does not hold, is named at a row at
    /// `at`, and `listed` is what this store's listing gave, tried first at
    /// a signed record's hand. The account is the session's key set's (the
    /// keyless session holds none, and reads nothing). A read is made
    /// (the module's doc) where [`AccountLabels::owes_read`] says and
    /// `read_made`, the caller's for one hands read, stands unset. Nothing
    /// is held across it: the board's lock is taken for the look and the
    /// keeping alone.
    pub(super) fn recorded_label(&self, session: &SessionEntry, key: &str, at: Option<u64>, listed: &[KeyFacts], read_made: &mut bool) -> Option<String> {
        let SessionKind::Signed { set_account, .. } = &session.facts.kind else { return None };
        let owed = self.lock(&session.board_reference).labels.get(set_account).is_none_or(|kept| kept.owes_read(key, at));
        if owed && !std::mem::replace(read_made, true) {
            self.read_labels(session, set_account, listed);
        }
        let board_hold = self.lock(&session.board_reference);
        let label = board_hold.labels.get(set_account)?.read.as_ref()?.labels.get(key)?;
        Some(render_inert(label))
    }

    /// Reads `account`'s labels and keeps them, or says why it could not.
    ///
    /// A read of an older head than the one kept, a slower thread's, is
    /// dropped. A failure leaves the kept read standing, and its cause and
    /// the first success after it are each said once (the module's doc).
    fn read_labels(&self, session: &SessionEntry, account: &str, listed: &[KeyFacts]) {
        let answered = self.labels_off_the_board(session, account, listed);
        let mut board_hold = self.lock(&session.board_reference);
        let kept = board_hold.labels.entry(account.to_string()).or_default();
        match answered {
            Ok(read) => {
                if kept.failing.take().is_some() {
                    self.say(format_args!("account {account}'s credential records read again: another device's key is named by its recorded label"));
                }
                if kept.read.as_ref().is_none_or(|standing| standing.head <= read.head) {
                    kept.read = Some(read);
                }
            }
            Err(cause) => {
                if kept.failing.as_deref() != Some(cause.as_str()) {
                    self.say(format_args!("account {account}'s credential records could not be read to name another device's key ({cause}); the key is named by its fingerprint until they read"));
                    kept.failing = Some(cause);
                }
            }
        }
    }

    /// Makes one read of `account`'s labels at the session's board.
    ///
    /// The board names its claimant first — a board naming none trusts no
    /// genesis, so no record can be verified there and none is read — and
    /// the head read that follows feeds the board's state
    /// ([`Holds::signing_term`]).
    ///
    /// # Errors
    ///
    /// Returns the cause of the first read that failed, in the words the
    /// shell's own window says it in.
    fn labels_off_the_board(&self, session: &SessionEntry, account: &str, listed: &[KeyFacts]) -> Result<LabelsRead, String> {
        let health = session.board.health().map_err(|h| h.to_string())?;
        let Some(claimant) = health.claimant() else { return Ok(LabelsRead { labels: HashMap::new(), head: health.log_position() }) };
        let term = self.signing_term(session).map_err(|refused| refused.to_string())?;
        let own: Vec<(Fingerprint, PublicKey)> = listed.iter().map(|key| (key.fingerprint, key.public.clone())).collect();
        let reads = accounts_read(claimant, account).iter().map(|reading| credential_records(&session.board, reading, &own).map_err(|h| h.to_string())).collect::<Result<Vec<Records>, String>>()?;
        let head = reads.iter().map(|read| read.head).min().unwrap_or_else(|| health.log_position());
        Ok(LabelsRead { labels: admitted_labels(reads, account, claimant, term), head })
    }
}

/// Returns the accounts one read of `account`'s labels takes, in its order.
///
/// They are the claimant's, every account above `account`, top-down, and
/// `account` itself, each once.
pub(super) fn accounts_read(claimant: &str, account: &str) -> Vec<String> {
    let mut above: Vec<String> = iter::successors(Some(account.to_string()), |a| parent_account(a)).collect();
    above.retain(|a| a != claimant);
    above.push(claimant.to_string());
    above.reverse();
    above
}

/// Returns the labels the signature-filtered table gives `account`'s keys.
///
/// `reads` are the [`accounts_read`] reads, the claimant's first, and `term`
/// is `H.1`'s pair, the record frame's term. The records are ordered as the
/// journal holds them: by position, the position-free first, which lie below
/// the floor beneath every positioned record, the claimant's in the read's
/// own order. A delegated account's record read position-free leaves every
/// label unnamed, no order crossing accounts below the floor (the module's
/// doc). Each admission of `account` carrying a label names its key, a key
/// since retired among them.
pub(super) fn admitted_labels(reads: Vec<Records>, account: &str, claimant: &str, term: Option<BoardTerm>) -> HashMap<String, String> {
    let orderable = reads.iter().filter(|read| read.account != claimant).all(|read| read.records.iter().all(|record| record.position.is_some()));
    let subject = match parse_address(account) {
        Some(subject) if orderable => subject,
        _ => return HashMap::new(),
    };
    let (head, floor, claim_entry) = (reads.iter().map(|read| read.head).min().unwrap_or(0), reads.iter().find_map(|read| read.floor), reads.iter().find_map(|read| read.claim_entry));
    let mut records: Vec<_> = reads.into_iter().flat_map(|read| read.records).collect();
    records.sort_by_key(|record| record.position);
    let merged = Records { account: account.to_string(), records, head, floor, claim_entry, claimed: true };
    let table = filtered_table(&merged, Some(claimant), term);
    table.admissions(&subject).iter().filter_map(|admission| Some((admission.fingerprint.to_hex(), admission.label.clone()?))).collect()
}
