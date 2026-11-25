//! The faces of a landing's faults.
//!
//! Each composes the face a step's refusal carries: the board's head owed
//! before the shot ([`head_owed`]); an act standing with its record
//! unwritten ([`record_owed`]), for an [`Unwritten`] reason and a journal's
//! [`Unfit`] check; a draft landing's write answered from the board's memo
//! of an earlier landing that stands no more ([`memo_landing_gone`]); a
//! board refusal of this library's own frame ([`own_fault`]); and an answer
//! of a shape this client cannot read ([`shape_face`]).

use serde_json::Value;
use skep_address::Address;

use crate::board::Rejection;
use crate::halt::Halt;
use crate::merge::reads::Refusal;
use crate::merge::record::RecordLanding;

/// Faces a claimed board whose head is owed, met before the shot (SP-14).
///
/// Nothing of the landing is written: the shot, its first write, could not
/// be signed.
pub(super) fn head_owed(cause: String) -> Halt {
    Halt::face(
        "this board has no H.1 yet, so the merge cannot land",
        cause,
        "retry once the board has written its head; nothing was written",
    )
}

/// Faces a draft landing's write answered from the board's memo of an
/// earlier landing that stands no more in `into` as this composition's.
///
/// The acknowledgment names `at`, the position of an earlier call's write
/// under the same id in this session, which the board answered without
/// running anything (wire.md §Correlation and idempotency), and the draft
/// as it stands holds no landing of this composition there
/// (`Writer::land_into_draft`, the end-to-end check). Nothing was written.
pub(super) fn memo_landing_gone(into: &Address, at: u64) -> Halt {
    Halt::face(
        format!("this session landed this merge in {into} at position {at} already, and that landing no longer stands there as this composition's"),
        format!("the board answered the landing's write from its memo of that earlier write under the same id, running nothing; since it, the landing was taken back, another landing took its mark, it placed another composition's list of the same head and sides, or the board reclaimed position {at} with no record of it standing — nothing was written"),
        "compose the merge again and land it: a composition reads the board as it stands, and its writes carry ids of their own",
    )
}

/// Why an act's record is not written, the act standing.
///
/// The record is a landing's, an undo's or a withdrawal's last step, so
/// the member or the draft already holds what the act wrote; the face says
/// so, and why the record is not.
pub(in crate::merge) enum Unwritten {
    /// The account's journal is not found: the board refused its find, a
    /// class scan, busy on every bounded reissue (the `journal` module's
    /// doc).
    Busy,
    /// The journal cannot take the record, for the check it fails.
    Journal(Address, Unfit),
    /// Any other refusal or fault stopped the record's step: one of its
    /// reads or writes unanswered or refused, which the face's cause names.
    Stopped,
}

impl Unwritten {
    /// Returns why the record is not written, as a face's state says it.
    pub(in crate::merge) fn reason(&self) -> String {
        match self {
            Unwritten::Busy => {
                "the board was too busy to find the account's merge journal".to_string()
            }
            Unwritten::Journal(journal, unfit) => unfit.reason(journal),
            Unwritten::Stopped => {
                "a read or a write of the record went unanswered, or was refused".to_string()
            }
        }
    }

    /// Returns when `resume` writes the record, as a face's act says it.
    fn remedy(&self) -> &'static str {
        match self {
            Unwritten::Busy => "once the board is less busy, or with a journal named",
            Unwritten::Journal(..) => {
                "with a journal this account can write, or with none for its own"
            }
            Unwritten::Stopped => "once the board answers the record's reads and writes",
        }
    }
}

/// Why a journal cannot take a merge record: the check it fails.
///
/// A record's atom goes into its journal as a plain insert, so the journal
/// is a draft the merger's account owns, readable and registered at this
/// board (the merge record's decision 7). A journal named is checked before
/// an act's first write (`Writer::check_journal`; P13), which faces the
/// first three and answers a published one [`Refusal::PublishedJournal`];
/// one the record's step finds failing a check leaves the act standing with
/// its record unwritten ([`Unwritten::Journal`]). The checks run in the
/// board's order for the atom: the read's answer, then the owner, then the
/// published bit.
#[derive(Clone, Copy)]
pub(in crate::merge) enum Unfit {
    /// It answers `withheld`: this merger may not read it.
    Withheld,
    /// It answers `doc_not_registered`.
    Unregistered,
    /// It is another account's, so the atom is refused `not_owner`
    /// (wire.md §Identity, ownership).
    Foreign,
    /// It is published, so the atom is refused `published_target` (wire.md
    /// §The version-chain refusals).
    Published,
}

impl Unfit {
    /// Returns what the check found of `journal`, as a face's state says it.
    pub(super) fn reason(self, journal: &Address) -> String {
        match self {
            Unfit::Withheld => {
                format!("the journal {journal} is not readable to this merger (withheld)")
            }
            Unfit::Unregistered => {
                format!("the journal {journal} is not registered at this board (doc_not_registered)")
            }
            Unfit::Foreign => format!("the journal {journal} is another account's"),
            Unfit::Published => format!("the journal {journal} is published"),
        }
    }
}

/// Faces a landing that stands with its record unwritten.
///
/// The member or the draft holds the merge and the record is not written,
/// for `why` — the account's journal not found, its find refused busy, or a
/// journal that cannot take the record ([`Unfit`]): `resume` writes it once
/// the board answers the find, or into a journal the merger can write, told
/// the draft for a draft landing, since one told no draft refuses a fresh
/// draft's landing that has no record, [`Refusal::LandingBegun`], writing
/// nothing.
pub(super) fn record_owed(landed: &RecordLanding, why: &Unwritten, cause: String) -> Halt {
    let (at, act) = match landed {
        RecordLanding::Member { member, .. } => (member, format!("resume {}: it finds the member holding the merge and writes the record", why.remedy())),
        RecordLanding::Draft { draft, .. } => (draft, format!("resume naming {draft} {}: it finds the draft holding the merge and writes the record", why.remedy())),
    };
    Halt::face(
        format!("the merge stands at {at}, and its record is not written: {}", why.reason()),
        cause,
        act,
    )
}

/// Faces a board refusal of this library's own frame (A-288's own-bug class).
///
/// It is nothing a person can act on.
pub(in crate::merge) fn own_fault(what: &str, r: &Rejection) -> Refusal {
    own_fault_face(format!("the board refused {what}"), format!("{}: the frame this library composed is wrong in substance — its base, its runs, its home or its attest", r.token()))
}

/// Returns this library's own fault, faced.
///
/// There is no user-facing act to offer.
pub(crate) fn own_fault_face(state: impl Into<String>, cause: impl Into<String>) -> Refusal {
    Refusal::Halt(Halt::face(state, cause, "this is a fault in this library, not in your keys or your act; nothing further was written"))
}

/// Faces an answer without the shape the write's ack promises.
pub(crate) fn shape_face(op: &str, v: &Value) -> Halt {
    Halt::face(
        format!("`{op}` answered a document this client cannot read"),
        crate::halt::clipped(&v.to_string(), 200).to_string(),
        "this board is not speaking the wire this client expects",
    )
}
