//! The merge's landing — the merge record's §1.5.
//!
//! The landing is the one `publish` of the merged list from the head with
//! its signed body, then the claim's read and the record in the journal with
//! its public link, each step idempotent by reading first (P4, P14); the
//! draft landing, ONE `set_arrangement` of the merged list into the draft
//! (the landing lane's rulings R1, R4, R5; skep #764); and [`resume`], the
//! residue walk that completes what a lost acknowledgment left, writing
//! nothing twice.
//!
//! **The order, and what each step reads first.** The cap: `counts.m`
//! against the shot's run cap before any frame (decision 13; P13). The shot:
//! the trunk's next member, then the head's daughters, read for a member
//! whose first `placed` positions already hold M — else one `publish` from
//! the head, its body every copied run's bytes re-read through the side that
//! holds them and every window signed by address, re-asked once under the
//! same per-session `id` where the acknowledgment was lost. The frame and
//! its body go through the publication composition's request builder
//! (`crate::publication::Request`) BARE — no `links`, `retract` or
//! `read_with` entry, no place beside any run, the document form — the
//! merge's one delta from a publication (the link-sets design §5.5: "the
//! walk's base the `base` it holds"), so a request carrying no deposit
//! signs today's body byte for byte through the one body builder. A daughter in
//! the acknowledgment is reported at once ([`Landed::AsDaughter`]): the head
//! moved under the merge, the library never re-runs, the embedder does with
//! `retries` one higher (decision 17). The record: the merger's current
//! record for the key, read by the landing itself as the composition reads
//! the prior records (the merge record's §1.5 (ii), §1.3's step 7) — the
//! links of the kind to each side of the key, kept to the merger's own
//! doc 1, the newest there — standing where it names this landing's member
//! or draft; else the journal found or minted, the atom appended at its
//! end, the link from the merger's doc 1 to the member and every side
//! besides the head under the kind, the record naming that newest record in
//! `replaces` (P20: a later record from the same home names the one it
//! replaces). A newer record of the key — an undo's, a withdrawal's, a
//! landing of it elsewhere — replaces this landing's, so a landing after it
//! writes its own. The composition's `Merged::prior` is what the
//! composition saw, under the reader's currency, and never the landing's
//! answer: a composition kept across a take-back, or one made before its
//! own landing, lands by the board as it stands.
//!
//! **The head, before any write.** Each write of the landing — the shot,
//! the stage, the draft's one write, the record's journal, atom and link —
//! is preceded by the board's head (`Board::board_head`; SP-14): `H.1`'s pair,
//! which the shot and the record's link sign over, or none on a board no
//! one has claimed, which takes them without an `attest`. A claimed board
//! serving no head record halts the landing at the first write it would
//! make, with nothing sent: the record's link could not be signed, so no
//! write before it is begun — before the shot or the stage the merge has
//! not landed, and before the record the landing stands and the residue
//! walk writes the record once the head is written. The head is read after
//! the read-first steps, so a [`resume`] that finds nothing landed answers
//! with no head read. The board's own `attestation_invalid:board_unavailable`
//! at the shot or the record's link — a head owed past that read — is faced
//! the same, never as this library's fault.
//!
//! **The draft landing is one write.** M is sent whole as one
//! `set_arrangement` of the draft (wire.md §Arrangement), TYPED against the
//! one position the merge was composed at — `Merged::as_of`, the position
//! every read of the composition was made at (skep #762) — so an edit made
//! to the draft after the merge was composed is refused `arrangement_moved`
//! with nothing changed, and the draft holds M or what it held, never a
//! state between. The frame carries the head the merge composed on with
//! its extent AS READ (`head`), the same pair as the base to record where
//! the board records a base for the draft — read off the draft's
//! `doc_metadata` at that position; a baseless draft and a fork get none,
//! so the library never sends a `base` the board refuses `no_base_to_record`
//! (N4) — and the merge the draft is to carry (`merge`, every side but the
//! draft itself). The board re-records the base on the head and sets the
//! marker in the same commit (R4); a newer version published since the
//! compose is not refused: the write lands against the head it composed on
//! and the ack names the trunk's current head as `head_moved`, which the
//! landing carries out (R5, "land and tell"). The write is sent where the
//! draft already holds M too, so the base and the marker are recorded. With
//! no draft named ([`Landing::Draft`]'s `into` none), a fresh draft is
//! staged from the head first — `stage {from: the head}`, two commits, the
//! state between a plain staged draft (R3) — and the write is typed against
//! the stage's own position; where the merger's newest record for the key,
//! read before the stage, names a draft landing, that landing is reported
//! and nothing is staged. The record follows, its draft landing's position
//! the write's `at`. The draft landing's per-session ids share one stem
//! naming the key, the draft and the position the write is typed against —
//! `<stem>.draft`, then the record's `<stem>.record` and `<stem>.link` —
//! and the stage's is `<key>@<P>.stage`, P the composition's position, or
//! `<key>@<P>~<link>.stage` where a record of the key stands in the
//! merger's doc 1, `<link>` the newest one's, which the landing's record
//! will replace: the board answers a second call over one composition from
//! its ids, and a landing composed after a take-back, landed into another
//! draft, or landed fresh again after its own landing was taken back, is a
//! write of its own. The shot's are the key's: `<key>.publish`,
//! `<key>.record`, `<key>.link`.
//!
//! **The claim, as this wire admits it.** The record's step (i) files
//! `assert_sup{home: the merger's doc 1, old: the daughter, new: the member}`
//! over two version members. The wire's `assert_sup` takes resident links
//! alone as its endpoints — wire.md §Links (writes): "a link named by
//! address", `endpoint_not_resident` for "an address no link occupies" — and
//! a version member is no link, so the claim the record spells is refused by
//! the daemon as built, ahead of any transaction. This build therefore makes
//! the claim's read, `in_claims{y: the daughter, view: active}`, recording a
//! claim another writer filed, and sends no `assert_sup`. What states the
//! supersession on this wire is the record's own public link from the
//! merger's doc 1 to the member and the daughter under the merge kind, which
//! a reader at the daughter finds by `find_links_ftt{ty, to}`. A claim over
//! version members is the wire's to admit, not a frame this library sends.

use serde_json::{json, Value};
use skep_address::Address;
use skep_identity::{
    entry_body_make_link, entry_frame, unit_span, BoardTerm, DocTerm, EntryBody, EntrySlot,
    LinkSlots,
};

use crate::address::{doc_1_of, document_of, parse_address};
use crate::board::{
    acked_addr, acked_at, acked_head_moved, answers, frames, Answer, Board, BoardHead, Rejection,
    Token,
};
use crate::halt::{Halt, Refused};
use crate::publication::{self, Piece};
use crate::sign::{sig_hex, Signer};

use super::compose::Run;
use super::journal;
use super::reads::{
    comps, daughter_of, first_difference, is_trunk_member, next_trunk_member, position_of,
    runs_of, values_for, Family, Merged, Reader, Refusal, Role, Side,
};
use super::record::{read_record, records_of, Record, RecordLanding};

/// The most bytes a shot's signed body may run to.
///
/// It is the frame routes' request-body cap, 8 MiB (wire.md §HTTP status
/// codes, `413 payload_too_large`), the parity the daemon holds a shot's
/// body to. The body is composed through the publication's request
/// builder and measured against it; a body past it is refused by name.
pub const SHOT_BODY_BUDGET: usize = 8 * 1024 * 1024;

/// The merger: a signed session's facts and its hand.
///
/// The facts are the session's token, the account it acts as, and the
/// signer it was opened with (the merge record's §7, "What it reads
/// through"). They are taken as facts, never as the ceremony's own session
/// type, which this module does not name: the embedder opens the session
/// with a content scope through the handshake and lends its token, its
/// account and its signer here.
#[derive(Clone, Copy)]
pub struct Merger<'a> {
    /// The signed session's token — what every write presents.
    pub token: &'a Token,
    /// The account the session acts as, `principal_prefix(principal)`.
    ///
    /// The record link's home is its doc 1.
    pub account: &'a str,
    /// The signer the session was opened with.
    ///
    /// It is the shot's and the record link's hand.
    pub signer: &'a dyn Signer,
}

/// How a merge lands (the merge record's §7, `Landing`).
///
/// It is the shot from the head, or the draft landing into a staging draft.
pub enum Landing<'a> {
    /// One `publish` from the head with M as the runs (§1.5).
    ///
    /// The claim's read and the record follow it.
    Shot {
        /// The merger's signed session and hand.
        merger: Merger<'a>,
        /// The staging draft whose fresh text the shot re-inserts.
        ///
        /// The caller names it where the merger typed any; a draft side's
        /// is named without asking where M holds its fresh text.
        draft: Option<Address>,
        /// The merge journal the record goes to.
        ///
        /// The account's default where `None` — the journal its first
        /// record went to, or a private one minted (decision 7).
        journal: Option<Address>,
    },
    /// M set as the whole arrangement of a draft in one `set_arrangement`.
    ///
    /// The write is typed against the position the merge was composed at
    /// (the module's doc); the record follows, with `landed` the draft — no
    /// claim: the person's own shot is the claim's moment (decision 16).
    Draft {
        /// The merger's signed session and hand.
        merger: Merger<'a>,
        /// The draft M is landed into.
        ///
        /// `None` lands it in a FRESH draft staged from the head the merge
        /// was composed on (R3): `stage {from: the head}`, then the write
        /// typed against the stage's position, the base the stage recorded
        /// re-recorded on the head — unless the merger's newest record for
        /// the key, read at the landing, names a draft landing, which is
        /// reported with nothing staged.
        into: Option<Address>,
        /// The merge journal, or the account's default.
        journal: Option<Address>,
    },
}

/// What a landing answered (the merge record's §7, `Landed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Landed {
    /// The merge landed on the trunk.
    ///
    /// It carries the member, the shot's position, the claims standing at
    /// the daughters, the record's public link, and the retries the record
    /// carries.
    Member {
        /// The merged member, `D.h+1`.
        address: Address,
        /// The shot's commit position.
        ///
        /// Where the member already stood and the feed holds no row of its
        /// mint, it is the highest `as_of` the reads answered.
        position: u64,
        /// The supersession claims standing at the daughters, as read.
        claims: Vec<Address>,
        /// The record's public link.
        ///
        /// It is the one written, homed in the merger's doc 1, or the one
        /// already standing for this key and landing.
        record: Address,
        /// `Options::retries`, as written into the record.
        retries: u32,
    },
    /// The head moved under the merge; the shot landed as its daughter.
    ///
    /// Reported, never a success; the embedder re-runs with the new head and
    /// `retries` one higher (decision 17).
    AsDaughter {
        /// The daughter minted.
        address: Address,
        /// The shot's commit position.
        ///
        /// Where the daughter already stood and the feed holds no row of its
        /// mint, it is the highest `as_of` the reads answered.
        position: u64,
    },
    /// M landed into a draft.
    ///
    /// It carries the draft — the one named, or the fresh one staged — the
    /// write's position, the record's public link, and the newer head where
    /// the board told one.
    Draft {
        /// The draft.
        into: Address,
        /// The `set_arrangement`'s commit position, the write's `at`.
        ///
        /// Where the landing was found standing — a `resume` that found the
        /// draft holding M, a fresh landing the merger's newest record for
        /// the key names — it is the position that landing recorded.
        position: u64,
        /// The record's public link.
        record: Address,
        /// The trunk's current head, where it is no longer the head the
        /// merge was composed on (R5, "land and tell").
        ///
        /// The write landed all the same, recorded on the head it composed
        /// on; the embedder tells that a newer version stands, and a merge
        /// composed again on it includes it. `None` where the head used is
        /// the trunk's, and where the landing was found standing.
        head_moved: Option<Address>,
    },
}

impl<'a> Landing<'a> {
    fn merger(&self) -> Merger<'a> {
        match self {
            Landing::Shot { merger, .. } | Landing::Draft { merger, .. } => *merger,
        }
    }

    fn journal(&self) -> Option<&Address> {
        match self {
            Landing::Shot { journal, .. } | Landing::Draft { journal, .. } => journal.as_ref(),
        }
    }
}

/// Lands a composed merge (the merge record's §7, `land`).
///
/// The shot is followed by the claim's read and the record, the draft
/// landing by the record alone, each step read first — the draft's one
/// write under a per-session id the board answers again — so a second call
/// over the same `merged` in one session writes nothing twice. A merge
/// composed again after an undo or a withdrawal lands as a write of its
/// own, in the same session or another: its ids name the position it was
/// composed at, and the take-back's record leaves no record standing for
/// it, so it writes its own. With no draft named, the merger's newest
/// record for the key is read before anything is staged, whatever the
/// composition saw: a draft landing it names is the answer, in any session;
/// a take-back's record leaves the key open, so the same `merged` landed
/// again stages a draft of its own, the stage's id naming that record.
///
/// # Errors
///
/// In this order:
///
/// - [`Refusal::OverCap`], before any frame;
/// - the reads' refusals, for a member already holding M, for the merger's
///   newest record for the key where no draft is named, or for the draft's
///   `doc_metadata` at the position the write is typed against;
/// - a claimed board serving no head record, as [`Refusal::Halt`] naming
///   `H.1`, before the first write the landing would make — the shot, the
///   stage, the draft's one write or the record's first — with nothing
///   sent; and the `H.1` and `/health` reads' halts (SP-14);
/// - the shot's: the value reads' refusals, [`Refusal::WindowWithheld`],
///   [`Refusal::NeedsSignedSession`], [`Refusal::NoSuchDocument`], the
///   board's `not_owner` naming the draft side as [`Refusal::UnownedDraft`],
///   `already_published` and `publication_over_budget` verbatim as
///   [`Refusal::Halt`] (never the library's fault),
///   `attestation_invalid:board_unavailable` faced as the head the board
///   owes, nothing landed, and a lost acknowledgment as the dialer's halt
///   after one re-ask, for [`resume`] to complete — or the draft landing's: the
///   stage's refusals where a fresh draft is staged ([`Refusal::Unreadable`]
///   and [`Refusal::NoSuchDocument`] naming the head), then the one write's
///   — `arrangement_moved` as the board's verdict, [`Refusal::Halt`] with
///   `Refused` naming the draft that changed after the merge was composed
///   and that nothing was merged; [`Refusal::ForkBaseMoved`];
///   [`Refusal::BaseNotInChain`]; [`Refusal::WindowWithheld`];
///   [`Refusal::NeedsSignedSession`]; [`Refusal::NoSuchDocument`] naming
///   the draft; `source_not_registered`, `no_base_to_record` and
///   `base_extent_too_large` as the library's own faults, since it names
///   the head and the extent the merge read, and a base only where the
///   draft records one at the position the write is typed against — and a
///   lost acknowledgment as the dialer's halt, with no re-ask;
/// - the claim's and the record's reads' refusals, then the record's
///   writes': [`Refusal::NeedsSignedSession`], and at its link
///   `attestation_invalid:board_unavailable` faced as the head the board
///   owes, the landing standing for [`resume`] to record.
///
/// At any step the library's own faults, the board's other refusals
/// verbatim, transport halts and the death signal are [`Refusal::Halt`].
///
/// # Panics
///
/// Panics if a landing that shoots answers none; the walk with `shoot` on
/// answers one on every path, so the `expect` never fires.
pub fn land(board: &Board, merged: &Merged, landing: Landing<'_>) -> Result<Landed, Refusal> {
    walk(board, merged, landing, true)
        .map(|landed| landed.expect("a landing that shoots answers a landing"))
}

/// Completes a landing whose acknowledgment was lost — the residue walk.
///
/// Where the shot landed and its acknowledgment was lost, the walk (the
/// merge record's §1.5, P14) finds the member whose first `placed`
/// positions equal M — the trunk's next member, else a daughter of the
/// head, which it reports as [`Landed::AsDaughter`] — or the draft already
/// holding M, read as it stands, with the position its marker carries, and
/// completes the record, after the claim's read for the trunk's member,
/// writing nothing twice; `None` where nothing landed, with nothing
/// written. A fresh landing names no draft to read: the merger's newest
/// record for the key, read now, is its answer where it names a draft
/// landing, else `None`. The board's head is read only before the record's
/// writes, so a walk that finds nothing landed answers `None` whatever the
/// head.
///
/// # Errors
///
/// As [`land`]'s but the shot's, the stage's and the draft's write's, which
/// it never sends.
pub fn resume(
    board: &Board,
    merged: &Merged,
    landing: Landing<'_>,
) -> Result<Option<Landed>, Refusal> {
    walk(board, merged, landing, false)
}

/// Runs the landing's steps, each read first.
///
/// They are the shot, the claim's read and the record, or the draft landing
/// and the record. `shoot` is whether a landing not found standing is made.
///
/// # Errors
///
/// As [`land`]'s, or as [`resume`]'s with `shoot` off.
fn walk(
    board: &Board,
    merged: &Merged,
    landing: Landing<'_>,
    shoot: bool,
) -> Result<Option<Landed>, Refusal> {
    let (m, cap) = (merged.composed.counts.m, merged.cap);
    if m > cap {
        return Err(Refusal::OverCap { runs: m, cap });
    }
    let merger = landing.merger();
    let writer = Writer::new(board, merger);
    match &landing {
        Landing::Shot { draft, .. } => {
            let (member, position) = match writer.standing_member(merged)? {
                Standing::Trunk(member, at) => (member, at),
                Standing::Daughter(address, position) => {
                    return Ok(Some(Landed::AsDaughter { address, position }))
                }
                Standing::Absent => {
                    if !shoot {
                        return Ok(None);
                    }
                    let (address, position) = writer.publish(merged, draft.as_ref())?;
                    if !is_trunk_member(&merged.inputs.doc, &address) {
                        return Ok(Some(Landed::AsDaughter { address, position }));
                    }
                    (address, position)
                }
            };
            let claims = writer.claims_standing(merged, &member)?;
            let landed = RecordLanding::Member { member: member.clone(), position };
            let newest = writer.newest_record(merged)?;
            let record = match newest.naming(&landed) {
                Some(link) => link.clone(),
                None => {
                    let stem = merged.key.text();
                    let journal = landing.journal();
                    writer.write_landing_record(merged, landed, &claims, &newest, &stem, journal)?
                }
            };
            Ok(Some(Landed::Member {
                address: member,
                position,
                claims,
                record,
                retries: merged.inputs.options.retries,
            }))
        }
        Landing::Draft { into, .. } => {
            // The draft and the position the write is typed against: the
            // merge's one position for a draft named; for a fresh draft,
            // the stage's own position — unless the merger's newest record
            // for the key, read here from the board, names a draft landing,
            // which is the answer. The stage and the one write write no
            // record, so that read is the record step's too.
            let (into, as_of, newest) = match into {
                Some(into) => (into.clone(), merged.as_of, None),
                None => {
                    let newest = writer.newest_record(merged)?;
                    if let Some(standing) = newest.draft_landing() {
                        return Ok(Some(standing));
                    }
                    if !shoot {
                        return Ok(None);
                    }
                    let (fresh, at) = writer.stage(merged, &newest)?;
                    (fresh, at, Some(newest))
                }
            };
            // The stem of the landing's per-session ids: the key, the draft
            // and the position the write is typed against, so the board
            // answers a second call over one composition from its ids, and a
            // landing composed after a take-back, into another draft, or into
            // the fresh draft a stage after a take-back mints, is a write of
            // its own.
            let stem = format!("{}:{into}@{as_of}", merged.key.text());
            let Some((position, head_moved)) =
                writer.land_into_draft(merged, &into, as_of, &stem, shoot)?
            else {
                return Ok(None);
            };
            let landed = RecordLanding::Draft { draft: into.clone(), position };
            let newest = match newest {
                Some(newest) => newest,
                None => writer.newest_record(merged)?,
            };
            let record = match newest.naming(&landed) {
                Some(link) => link.clone(),
                None => {
                    let journal = landing.journal();
                    writer.write_landing_record(merged, landed, &[], &newest, &stem, journal)?
                }
            };
            Ok(Some(Landed::Draft { into, position, record, head_moved }))
        }
    }
}

/// Whether a member already holds the merge.
enum Standing {
    /// No member of the head's reach holds M.
    Absent,
    /// The trunk's next member holds M, minted at this position.
    ///
    /// Where the feed holds no row of the mint, the position is the reads'
    /// highest `as_of`.
    Trunk(Address, u64),
    /// A daughter of the head holds M: the shot landed under a moved head.
    Daughter(Address, u64),
}

/// What one member of the chain holds against M.
enum Holds {
    /// Not registered.
    Nothing,
    /// Another arrangement, or one this reader cannot read.
    Other,
    /// M over its first `placed` positions, minted at this position.
    ///
    /// Where the feed holds no row of the mint, the position is the reads'
    /// highest `as_of`.
    Merged(u64),
}

/// The merger's newest record for the key, as the landing read it.
///
/// Only [`Writer::newest_record`] builds one, from the board, so what a
/// landing finds standing and what the record it writes replaces are the
/// board's state at the landing (P20), never what the composition saw.
/// Empty where no record of the key stands in the merger's doc 1.
struct Newest(Option<(Address, Record)>);

impl Newest {
    /// Returns the newest record's link: what a record written now replaces.
    fn link(&self) -> Option<&Address> {
        self.0.as_ref().map(|(link, _)| link)
    }

    /// Returns the newest record's link where it names `landed`.
    ///
    /// It does where both land in the same member, or both in the same
    /// draft, whatever either's position. An undo's or a withdrawal's
    /// record names no landing and a landing of the key elsewhere names
    /// another, so either leaves nothing standing for `landed`.
    fn naming(&self, landed: &RecordLanding) -> Option<&Address> {
        let (link, record) = self.0.as_ref()?;
        let same = match (record.landed.as_ref()?, landed) {
            (RecordLanding::Member { member: a, .. }, RecordLanding::Member { member: b, .. }) => {
                a == b
            }
            (RecordLanding::Draft { draft: a, .. }, RecordLanding::Draft { draft: b, .. }) => {
                a == b
            }
            _ => false,
        };
        same.then_some(link)
    }

    /// Returns the draft landing the newest record names, found standing.
    ///
    /// It is a fresh landing's answer with nothing staged: the draft, the
    /// position the record names and the record's link, with no newer head
    /// told. `None` where the newest names no draft landing or none stands.
    fn draft_landing(&self) -> Option<Landed> {
        let (link, record) = self.0.as_ref()?;
        let Some(RecordLanding::Draft { draft, position }) = &record.landed else {
            return None;
        };
        Some(Landed::Draft {
            into: draft.clone(),
            position: *position,
            record: link.clone(),
            head_moved: None,
        })
    }
}

/// The landing's writer: the merger and a reader under its token.
///
/// The undo and the withdrawal (the `undo` module) write through it too:
/// the head's pre-check, the one write and the record are theirs as the
/// landing's.
pub(super) struct Writer<'a> {
    pub(super) board: &'a Board,
    pub(super) merger: Merger<'a>,
    pub(super) reader: Reader<'a>,
}

impl<'a> Writer<'a> {
    /// Returns a writer over `board` as `merger`, its reader under the
    /// merger's token.
    pub(super) fn new(board: &'a Board, merger: Merger<'a>) -> Writer<'a> {
        Writer { board, merger, reader: Reader::new(board, Some(merger.token)) }
    }
}

impl Writer<'_> {
    /// Finds the member that already holds M, the shot's read-first.
    ///
    /// It reads the trunk's next member, then — where that is another's —
    /// the head's daughters in order until the first absent.
    ///
    /// # Errors
    ///
    /// A member's reads' refusals, as `holds` answers them; a head or a
    /// daughter whose address cannot be spelled, as the library's own fault.
    fn standing_member(&self, merged: &Merged) -> Result<Standing, Refusal> {
        let head = &merged.inputs.head;
        let next = next_trunk_member(head).ok_or_else(|| {
            own_fault_face(
                "the head's next member cannot be spelled",
                format!("{head} has no component to count on"),
            )
        })?;
        match self.holds(merged, &next)? {
            Holds::Merged(at) => return Ok(Standing::Trunk(next, at)),
            Holds::Nothing => return Ok(Standing::Absent),
            Holds::Other => {}
        }
        for k in 1u64.. {
            let daughter = daughter_of(head, k).ok_or_else(|| {
                own_fault_face(
                    "a daughter's address cannot be spelled",
                    format!("{head} extended by {k}"),
                )
            })?;
            match self.holds(merged, &daughter)? {
                Holds::Merged(at) => return Ok(Standing::Daughter(daughter, at)),
                Holds::Nothing => return Ok(Standing::Absent),
                Holds::Other => {}
            }
        }
        Ok(Standing::Absent)
    }

    /// Returns whether `member` holds M over its first `placed` positions.
    ///
    /// # Errors
    ///
    /// The member's reads' refusals but `withheld`, a `doc_not_registered`
    /// on its metadata and a member too fragmented to image, which answer as
    /// what it holds; an `image` run that is no content I-address; the feed
    /// walk's halts.
    fn holds(&self, merged: &Merged, member: &Address) -> Result<Holds, Refusal> {
        let meta = match self.reader.metadata(member, None) {
            Ok(m) => m,
            Err(Refusal::NoSuchDocument(_)) => return Ok(Holds::Nothing),
            Err(Refusal::Unreadable(_)) => return Ok(Holds::Other),
            Err(e) => return Err(e),
        };
        let Some(placed) = meta.placed else { return Ok(Holds::Other) };
        let image = match self.reader.image(member, None, 1, placed) {
            Ok(runs) => runs,
            Err(Refusal::Unreadable(_)) | Err(Refusal::TooFragmented { .. }) => {
                return Ok(Holds::Other)
            }
            Err(e) => return Err(e),
        };
        let actual = runs_of(&image)?;
        let expected: Vec<(Run, Family)> = merged
            .composed
            .runs
            .iter()
            .map(|p| p.run.clone())
            .zip(merged.families.iter().copied())
            .collect();
        if first_difference(&expected, &actual, &merged.inputs.doc).is_some() {
            return Ok(Holds::Other);
        }
        let at = position_of(self.board, Some(self.merger.token), member)?
            .unwrap_or_else(|| self.reader.as_of());
        Ok(Holds::Merged(at))
    }

    /// Sends the shot, answering the member minted and the ack's position.
    ///
    /// The frame and its body go through the publication's request builder
    /// with no member and no place — every copied run's values re-read
    /// through the side that holds them, every window by address, the base
    /// group the head and its extent as read — then the frame with its
    /// `attest` and its id, one re-ask under the same id on a lost
    /// acknowledgment.
    ///
    /// # Errors
    ///
    /// The head's refusal and halts ([`Writer::signing_term`]), read before
    /// the values, nothing sent; [`Refusal::WindowWithheld`],
    /// [`Refusal::NeedsSignedSession`] and [`Refusal::NoSuchDocument`] as the
    /// board answers them; `not_owner` naming the draft side as
    /// [`Refusal::UnownedDraft`], `already_published` and
    /// `publication_over_budget` as the board's refusal verbatim, never this
    /// library's fault, and `attestation_invalid:board_unavailable` faced as
    /// the head the board owes; the value reads' refusals; the attest's
    /// fault; a body past [`SHOT_BODY_BUDGET`], a run with no address, a
    /// window of width 0, and the board's refusal of the frame's substance —
    /// the shot's own table, a place's or a deposit's token, which this frame
    /// never carries — as the library's own faults; an answer of a shape
    /// this client does not know, faced; the death signal; a dial fault after
    /// the one re-ask; the board's other refusals verbatim.
    fn publish(&self, merged: &Merged, draft: Option<&Address>) -> Result<(Address, u64), Refusal> {
        let term = self.signing_term(&head_owed)?;
        let doc = &merged.inputs.doc;
        let head = &merged.inputs.head;
        let draft_side = merged.inputs.sides.iter().find_map(|s| match s {
            Side::Draft { at, .. } => Some(at.clone()),
            _ => None,
        });
        let fresh = merged.families.contains(&Family::DraftNative);
        let draft = draft.cloned().or(if fresh { draft_side } else { None });
        let mut runs = Vec::with_capacity(merged.composed.runs.len());
        let mut pieces = Vec::with_capacity(merged.composed.runs.len());
        for (placed, family) in merged.composed.runs.iter().zip(&merged.families) {
            let run = &placed.run;
            let i_start = run
                .address_at(0)
                .ok_or_else(|| own_fault_face("a run of M names no address", format!("{run:?}")))?;
            runs.push(publication::Run::new(run.origin.clone(), run.i_start, run.width));
            match family {
                Family::Window => {
                    if run.width == 0 {
                        return Err(own_fault_face("a window of width 0", format!("{run:?}")));
                    }
                    pieces.push(Piece::Window { start: i_start, width: run.width });
                }
                Family::Own | Family::DraftNative => {
                    let items = values_for(
                        &self.reader,
                        &merged.maps,
                        placed.side.map(|s| s.0 as usize),
                        run,
                    )?;
                    pieces.push(Piece::Values(items));
                }
            }
        }
        // THE REQUEST BUILDER, bare: the merge's delta from a publication is
        // no member and no place, in either list.
        let n = runs.len();
        let request = publication::Request {
            doc: Some(doc.clone()),
            mint: None,
            claim: false,
            base: Some((head.clone(), merged.head_extent)),
            draft: draft.clone(),
            also: Vec::new(),
            runs,
            places: vec![None; n],
            also_places: Vec::new(),
            stray_records: vec![0; n],
            pieces,
            entries: Vec::new(),
            retract: Vec::new(),
            read_with: Vec::new(),
            unspellable: Vec::new(),
            counterparts: Vec::new(),
            id: format!("{}.publish", merged.key.text()),
            count: publication::Count::default(),
            price: publication::Price::default(),
            as_of: self.reader.as_of(),
        };
        let body = request.body();
        if body.as_bytes().len() > SHOT_BODY_BUDGET {
            return Err(own_fault_face("the shot's body cannot be composed", format!("the merged list's values pass what one shot's body may carry ({SHOT_BODY_BUDGET} bytes)")));
        }
        let attest = self.attest(term, doc, &body)?;
        let frame = request.frame(attest);
        // A lost acknowledgment is re-asked once under the same id in the same
        // session (§1.5: the per-session idempotency key), else `resume`.
        let answer = match self.board.op(Some(self.merger.token), &frame) {
            Err(Halt::Dial(_)) => self.board.op(Some(self.merger.token), &frame)?,
            other => other?,
        };
        let v = match answer {
            Answer::Closed => return Err(closed("publishing the merge").into()),
            Answer::Document(v) => v,
        };
        if let (Some(addr), Some(at)) = (acked_addr(&v), acked_at(&v)) {
            let member = parse_address(addr).ok_or_else(|| shape_face("publish", &v))?;
            return Ok((member, at));
        }
        let Some(r) = Rejection::of(&v) else { return Err(shape_face("publish", &v).into()) };
        let site = r.site().addr.as_deref().and_then(parse_address);
        Err(match r.key() {
            "withheld" => Refusal::WindowWithheld(site.unwrap_or_else(|| doc.clone())),
            "signed_session_required" => Refusal::NeedsSignedSession,
            "doc_not_registered" => Refusal::NoSuchDocument(doc.clone()),
            // The publication's own refusals of the shot: the unowned draft
            // side named, the twin fence's member and the budget's detail
            // verbatim.
            "not_owner" if site.is_some() && site == draft => match site.clone() {
                Some(draft) => Refusal::UnownedDraft { draft },
                None => own_fault("the shot", &r),
            },
            "already_published" | "publication_over_budget" => Refusal::Halt(r.refused(&v)),
            "base_superseded"
            | "base_not_in_chain"
            | "base_extent_too_large"
            | "bad_run"
            | "dangling_source"
            | "source_not_registered"
            | "not_owner"
            | "too_many_runs"
            | "too_many_values"
            | "private_source_versionless"
            | "kept_place_moved"
            | "stray_place_unrecorded"
            | "link_home_refused"
            | "old_refused"
            | "duplicate_original"
            | "read_with_in_links"
            | "retract_refused"
            | "read_with_refused"
            | "malformed" => own_fault("the shot", &r),
            // The board's state, never this library's frame (a reorder).
            "attestation_invalid:board_unavailable" => head_owed(format!(
                "{}: the board refused the shot, serving no head record (`H.1`) to verify its signature over — a head the board owes, never this library's frame",
                r.token()
            ))
            .into(),
            k if k.starts_with("attestation_") => own_fault("the shot's attest", &r),
            _ => Refusal::Halt(r.refused(&v)),
        })
    }

    /// Returns the claim's read: the active claims whose `new` is the member.
    ///
    /// They are read at each daughter — what another writer filed; this wire
    /// admits none over version members (the module's doc).
    ///
    /// # Errors
    ///
    /// The `in_claims` read's refusal at a daughter.
    fn claims_standing(&self, merged: &Merged, member: &Address) -> Result<Vec<Address>, Refusal> {
        let mut out = Vec::new();
        let member = member.to_string();
        for side in &merged.inputs.sides {
            let Side::Member(daughter) = side else { continue };
            let v =
                self.reader.answered(daughter, &frames::in_claims(&daughter.to_string()), None)?;
            for claim in answers::claims(&v) {
                if claim.active && claim.new == member {
                    if let Some(a) = parse_address(&claim.claim) {
                        out.push(a);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Returns the record's read: the merger's newest record for the key.
    ///
    /// It is the merger's current record for the key (the merge record's
    /// §1.5 (ii), read first as §1.3's step 7 reads; §4's currency, newest
    /// per key), read by the landing from the board. It is found as the
    /// composition's prior records are, by the links of the kind to each
    /// side of the key, and kept to the merger's own home, its doc 1, where
    /// a link's ordinal is the order it was minted in: the newest there is
    /// the record. A record of the key in another account's home is never
    /// the merger's — its landing is another's, and a record names in
    /// `replaces` one from its own home (P20). It stands for a landing it
    /// names ([`Newest::naming`]); one naming no landing or another — an
    /// undo's or a withdrawal's, or a landing of the key elsewhere —
    /// replaced the record of this landing.
    ///
    /// # Errors
    ///
    /// A halt reading the links or a record.
    fn newest_record(&self, merged: &Merged) -> Result<Newest, Refusal> {
        let home = doc_1_of(self.merger.account);
        let newest = records_of(&self.reader, &merged.inputs.kind, &merged.key)?
            .into_iter()
            .filter(|(link, _)| document_of(&link.to_string()).as_deref() == Some(home.as_str()))
            .max_by_key(|(link, _)| comps(link));
        Ok(Newest(newest))
    }

    /// Writes a landing's record, answering its link's address.
    ///
    /// The record is the composition's with `landed` and `claims` filled
    /// and `replaces` the link of `newest`, the merger's newest record for
    /// the key as the landing read it — none where none stands (P20). It is
    /// written through [`Writer::write_record`] under `stem` — the key's
    /// text for the shot, and for a draft landing the key's with the draft
    /// and the position its write is typed against — the link's first end
    /// the landed address, and a head owed at its writes faced as the
    /// landing standing with its record unwritten ([`record_owed`]).
    ///
    /// # Errors
    ///
    /// [`Writer::write_record`]'s.
    fn write_landing_record(
        &self,
        merged: &Merged,
        landed: RecordLanding,
        claims: &[Address],
        newest: &Newest,
        stem: &str,
        journal: Option<&Address>,
    ) -> Result<Address, Refusal> {
        let target = match &landed {
            RecordLanding::Member { member, .. } => member.clone(),
            RecordLanding::Draft { draft, .. } => draft.clone(),
        };
        let mut record = merged.record.clone();
        record.landed = Some(landed.clone());
        record.claims = claims.to_vec();
        record.replaces = newest.link().cloned();
        let owed = |cause: String| record_owed(&landed, cause);
        self.write_record(&merged.inputs.kind, &record, &target, stem, journal, &owed)
    }

    /// Writes `record` under `kind`, answering its link's address.
    ///
    /// The board's head is read first, then the journal found or minted, the
    /// atom appended at its end as a plain insert, and the public link made
    /// from the merger's doc 1 to `target` — the landed address, or the
    /// draft an undo or a withdrawal names — and every side of the record
    /// besides its head under the kind, attested over `H.1`'s pair. The two
    /// writes carry the per-session ids `<stem>.record` and `<stem>.link`;
    /// `owed` is the face a head owed meets at either, the act standing
    /// with its record unwritten.
    ///
    /// # Errors
    ///
    /// The head's refusal and halts ([`Writer::signing_term`]), the act
    /// standing and nothing of the record sent; the journal's halts
    /// ([`journal::of`]); the extent read's refusal; a journal that is
    /// published, full or another account's, a doc 1 this session does not
    /// own, a doc 1 or an account this client cannot spell, and an attest the
    /// board refuses, as the library's own faults, but
    /// `attestation_invalid:board_unavailable` at the link, faced as the head
    /// the board owes with the act standing; an answer of a shape this
    /// client does not know, faced; [`Refusal::NeedsSignedSession`] at the
    /// link; the death signal; the board's other refusals verbatim.
    pub(super) fn write_record(
        &self,
        kind: &Address,
        record: &Record,
        target: &Address,
        stem: &str,
        journal: Option<&Address>,
        owed: &dyn Fn(String) -> Halt,
    ) -> Result<Address, Refusal> {
        let term = self.signing_term(owed)?;
        let journal = journal::of(self.board, &self.merger, kind, journal.cloned())?;
        let text = record.to_value().to_string();
        let ordinal = self.reader.extent(&journal, None)?.checked_add(1).ok_or_else(|| {
            own_fault_face(
                "the journal is full",
                format!("{journal} answered an extent with no ordinal after it"),
            )
        })?;
        // Typed against the state the extent was read at (skep #442): the
        // reader's highest `as_of`, which that read just raised.
        let v = self.answered_write(
            &frames::insert_plain_atom(
                &journal.to_string(),
                ordinal,
                &text,
                self.reader.as_of(),
                Some(&format!("{stem}.record")),
            ),
            "appending the record",
        )?;
        let atom = match acked_addr(&v) {
            Some(a) => parse_address(a).ok_or_else(|| shape_face("insert", &v))?,
            None => {
                let Some(r) = Rejection::of(&v) else {
                    return Err(shape_face("insert", &v).into());
                };
                return Err(match r.key() {
                    "published_target" => own_fault_face("the journal is not a draft", format!("{}: the merge journal {journal} is published, and a record is appended as a plain insert into a draft", r.token())),
                    "not_owner" => own_fault_face("the journal is not this account's", format!("{}: {journal} is owned by another account", r.token())),
                    _ => Refusal::Halt(r.refused(&v)),
                });
            }
        };
        // The link from doc 1: the atom's unit span to the target and every
        // side of the record besides its head, typed the kind (§4, "Its
        // home").
        let home_text = doc_1_of(self.merger.account);
        let home = parse_address(&home_text).ok_or_else(|| {
            own_fault_face("the account's doc 1 cannot be spelled", home_text.clone())
        })?;
        let mut to: Vec<Address> = vec![target.clone()];
        for side in record.sides.iter().filter(|s| s.role() != Role::Head) {
            if !to.contains(side.address()) {
                to.push(side.address().clone());
            }
        }
        let from_spans = [unit_span(&atom)];
        let to_spans: Vec<_> = to.iter().map(unit_span).collect();
        let ty_spans = [unit_span(kind)];
        let body = entry_body_make_link(LinkSlots {
            from: EntrySlot(&from_spans),
            to: EntrySlot(&to_spans),
            ty: EntrySlot(&ty_spans),
        });
        let attest = self.attest(term, &home, &body)?;
        let atom_text = atom.to_string();
        let to_text: Vec<String> = to.iter().map(ToString::to_string).collect();
        let to_refs: Vec<&str> = to_text.iter().map(String::as_str).collect();
        let mut frame = frames::make_link(
            &home_text,
            &[&atom_text],
            &to_refs,
            &kind.to_string(),
            Some(&format!("{stem}.link")),
        );
        if let Some(a) = attest {
            frame["attest"] = a;
        }
        let v = self.answered_write(&frame, "linking the record")?;
        if let Some(link) = acked_addr(&v) {
            return parse_address(link).ok_or_else(|| shape_face("make_link", &v).into());
        }
        let Some(r) = Rejection::of(&v) else { return Err(shape_face("make_link", &v).into()) };
        Err(match r.key() {
            "not_owner" => own_fault_face(
                "this session does not own its doc 1",
                format!("{}: the record's link is homed in the merger's own doc 1", r.token()),
            ),
            "signed_session_required" => Refusal::NeedsSignedSession,
            // The board's state, never this library's frame (a reorder).
            "attestation_invalid:board_unavailable" => owed(format!(
                "{}: the board refused the record's link from doc 1, serving no head record (`H.1`) to verify its signature over — a head the board owes, never this library's frame",
                r.token()
            ))
            .into(),
            k if k.starts_with("attestation_") => own_fault("the record link's attest", &r),
            _ => Refusal::Halt(r.refused(&v)),
        })
    }

    /// Returns the current record naming `draft` as landed in.
    ///
    /// It is read through the links of `kind` to the draft, each record's
    /// atom through its journal, keeping the records whose `landed` is the
    /// draft, and answering the newest of them by its link's address, with
    /// that link; a record whose journal the merger may not read is no
    /// candidate. `None` where none stands: the undo's and the withdrawal's
    /// record is then not written (the `undo` module's doc).
    ///
    /// # Errors
    ///
    /// The link read's refusal at the draft; a halt reading a record.
    pub(super) fn landed_record(
        &self,
        kind: &Address,
        draft: &Address,
    ) -> Result<Option<Record>, Refusal> {
        let v = self.reader.answered(
            draft,
            &frames::find_links_ftt(&kind.to_string(), &draft.to_string()),
            None,
        )?;
        let mut newest: Option<(Address, Record)> = None;
        for link in answers::addrs(&v) {
            let Some(link) = parse_address(link) else { continue };
            let Some(record) = read_record(&self.reader, &link)? else { continue };
            let lands_here =
                matches!(&record.landed, Some(RecordLanding::Draft { draft: d, .. }) if d == draft);
            if !lands_here {
                continue;
            }
            if newest.as_ref().is_none_or(|(l, _)| comps(&link) > comps(l)) {
                newest = Some((link, record));
            }
        }
        Ok(newest.map(|(link, mut record)| {
            record.link = Some(link);
            record
        }))
    }

    /// Stages a fresh draft from the head, answering it and its position.
    ///
    /// It is `stage {from: the head the merge composed on}` (R3) under the
    /// per-session id `<key>@<P>.stage`, P the position the merge was
    /// composed at, or `<key>@<P>~<link>.stage` where `newest`, the
    /// merger's newest record for the key, stands — `<link>` its link, the
    /// record the landing's own will replace. A retry of the same landing
    /// reads the same newest record, so it is answered its stage again; one
    /// composed after a take-back stages afresh, and so does the same
    /// composition landed again after its landing was taken back, whose
    /// newest record is the take-back's. The board mints a private draft of
    /// the merger's account holding the head by identity and records the
    /// head as its base, so the write that follows re-records that base on
    /// the same head. The board's head is read first: the stage begins a
    /// landing whose record's link signs over it (the module's doc).
    ///
    /// # Errors
    ///
    /// The head's refusal and halts ([`Writer::signing_term`]), nothing
    /// sent; [`Refusal::Unreadable`] and [`Refusal::NoSuchDocument`] naming
    /// the head, as the board's `withheld` and `source_not_registered` on the
    /// stage's source; an answer of a shape this client does not know,
    /// faced; the death signal; a dial fault; the board's other refusals
    /// verbatim — `mint_home_first` among them.
    fn stage(&self, merged: &Merged, newest: &Newest) -> Result<(Address, u64), Refusal> {
        self.signing_term(&head_owed)?;
        let head = &merged.inputs.head;
        let id = match newest.link() {
            None => format!("{}@{}.stage", merged.key.text(), merged.as_of),
            Some(link) => format!("{}@{}~{link}.stage", merged.key.text(), merged.as_of),
        };
        let frame = frames::stage(&head.to_string(), Some(&id));
        let v = self.answered_write(&frame, "staging a fresh draft")?;
        if let (Some(addr), Some(at)) = (acked_addr(&v), acked_at(&v)) {
            let fresh = parse_address(addr).ok_or_else(|| shape_face("stage", &v))?;
            return Ok((fresh, at));
        }
        let Some(r) = Rejection::of(&v) else { return Err(shape_face("stage", &v).into()) };
        Err(match r.key() {
            "withheld" => Refusal::Unreadable(head.clone()),
            "source_not_registered" => Refusal::NoSuchDocument(head.clone()),
            _ => Refusal::Halt(r.refused(&v)),
        })
    }

    /// Lands M into the draft in one write, answering its position and the
    /// newer head where the board told one.
    ///
    /// The one frame is `set_arrangement` (the module's doc): M's runs,
    /// typed against `as_of` — the merge's one position for a draft named,
    /// the stage's position for a fresh one — with the head the merge
    /// composed on and its extent as read, the same pair as the base to
    /// record where the draft's `doc_metadata`, read at `as_of`, records a
    /// base, and the merge's sides but the draft itself; its id
    /// `<stem>.draft`, `stem` naming the key, the draft and `as_of`, which
    /// the board answers again in the same session for the same composition.
    /// It is sent where the draft already holds M too, so the base and the
    /// marker are recorded, and only after the board's head is read: the
    /// record's link that follows signs over it (the module's doc). With
    /// `shoot` off nothing is sent: the draft is read as it stands, and
    /// holding M it answers the position its marker carries for this merge's
    /// head — else the read's `as_of` — or `None` where it holds another
    /// list.
    ///
    /// # Errors
    ///
    /// The draft's reads' refusals — a draft that did not exist at `as_of`,
    /// faced, naming the way out; the head's refusal and halts
    /// ([`Writer::signing_term`]), nothing sent; the board's
    /// `arrangement_moved` as its verdict, [`Refusal::Halt`] with the
    /// `Refused` re-said to the draft that changed after the merge was
    /// composed and nothing merged; [`Refusal::ForkBaseMoved`] and
    /// [`Refusal::BaseNotInChain`], the two refusals a person meets;
    /// [`Refusal::WindowWithheld`] where a run names an origin the merger may
    /// not read; [`Refusal::NeedsSignedSession`];
    /// [`Refusal::NoSuchDocument`] naming the draft; a run with no address
    /// and the board's refusal of the frame's substance — the head and the
    /// extent the merge read and the base the draft records at `as_of`
    /// (`source_not_registered`, `no_base_to_record`,
    /// `base_extent_too_large`), a run's origin (`source_not_registered`,
    /// `bad_run`, `dangling_source`, `too_many_runs`), the draft's standing
    /// (`published_target`, `not_owner`) — as the library's own faults; an
    /// answer of a shape this client does not know, faced; the death signal;
    /// a dial fault; the board's other refusals verbatim.
    fn land_into_draft(
        &self,
        merged: &Merged,
        into: &Address,
        as_of: u64,
        stem: &str,
        shoot: bool,
    ) -> Result<Option<(u64, Option<Address>)>, Refusal> {
        let head = &merged.inputs.head;
        let target: Vec<Run> = merged.composed.runs.iter().map(|p| p.run.clone()).collect();
        if !shoot {
            // The residue walk: the draft as it stands, read first.
            let meta = self.reader.metadata(into, None)?;
            let current = runs_of(&self.reader.imaged(into, None)?.runs)?;
            let as_own: Vec<(Run, Family)> =
                target.iter().cloned().map(|r| (r, Family::Own)).collect();
            if first_difference(&as_own, &current, &merged.inputs.doc).is_some() {
                return Ok(None);
            }
            let position = meta
                .merge
                .as_ref()
                .filter(|m| m.head == head.to_string())
                .and_then(|m| m.at)
                .unwrap_or_else(|| self.reader.as_of());
            return Ok(Some((position, None)));
        }
        // The base to record: the head's pair, only where the board records
        // a base for the draft at the position the write is typed against
        // (N4) — a baseless draft and a fork get none.
        let meta = match self.reader.metadata(into, Some(as_of)) {
            Ok(meta) => meta,
            Err(Refusal::NoSuchDocument(_)) => {
                return Err(Halt::face(
                    format!("{into} did not exist at position {as_of}, the position this merge was composed at"),
                    "the merge reads every draft it uses at one board position and types its landing against it, so the draft it lands into must stand there: a draft minted after the composition changed after it",
                    "run the merge again naming the draft, or land it in a fresh draft (`into` none; the command's --new)",
                )
                .into())
            }
            Err(e) => return Err(e),
        };
        let head_text = head.to_string();
        let pair = Some((head_text.as_str(), merged.head_extent));
        let base = if meta.base.is_some() { pair } else { None };
        let runs: Vec<Value> = target
            .iter()
            .map(|r| {
                let i_start = r
                    .address_at(0)
                    .ok_or_else(|| own_fault_face("a run of M names no address", format!("{r:?}")))?;
                Ok(frames::shot_run(&r.origin.to_string(), &i_start.to_string(), r.width))
            })
            .collect::<Result<_, Refusal>>()?;
        let sides: Vec<String> = merged
            .inputs
            .sides
            .iter()
            .map(|s| s.address())
            .filter(|s| *s != into)
            .map(ToString::to_string)
            .collect();
        let side_refs: Vec<&str> = sides.iter().map(String::as_str).collect();
        let id = format!("{stem}.draft");
        let frame = frames::set_arrangement(
            &into.to_string(),
            &runs,
            as_of,
            pair,
            base,
            Some(&side_refs),
            Some(&id),
        );
        // The head before the one write: the record's link signs over it.
        self.signing_term(&head_owed)?;
        let v = self.answered_write(&frame, "landing the merge in the draft")?;
        if let Some(at) = acked_at(&v) {
            let head_moved = match acked_head_moved(&v) {
                Some(h) => Some(parse_address(h).ok_or_else(|| shape_face("set_arrangement", &v))?),
                None => None,
            };
            return Ok(Some((at, head_moved)));
        }
        let Some(r) = Rejection::of(&v) else {
            return Err(shape_face("set_arrangement", &v).into());
        };
        let site = r.site().addr.as_deref().and_then(parse_address);
        Err(match r.key() {
            "withheld" => Refusal::WindowWithheld(site.unwrap_or_else(|| into.clone())),
            "signed_session_required" => Refusal::NeedsSignedSession,
            "doc_not_registered" => Refusal::NoSuchDocument(into.clone()),
            // The draft changed after the merge was composed — another
            // hand's edit past the one position the merge read it at, a race
            // and never this client's fault: the board's verdict, its words
            // the person's, and nothing was merged (the one write wipes
            // nothing).
            "arrangement_moved" => {
                let current = v["site"]["current"].as_u64();
                Refusal::Halt(Halt::Refused(Refused {
                    status: 200,
                    code: r.code().to_string(),
                    detail: Some(format!(
                        "{into} changed after the merge was composed{} — nothing was merged; run the merge again, which reads the draft as it stands",
                        match current {
                            Some(c) => format!(" (composed at position {as_of}, the draft changed at {c})"),
                            None => format!(" at position {as_of}"),
                        }
                    )),
                    op: r.op().map(str::to_string),
                    body: v.clone(),
                }))
            }
            "fork_base_moved" => Refusal::ForkBaseMoved {
                fork: into.clone(),
                source: site.unwrap_or_else(|| into.clone()),
                head: head.clone(),
            },
            "base_not_in_chain" => Refusal::BaseNotInChain { into: into.clone(), head: head.clone() },
            // The head and its extent are the merge's own reads — a member
            // registered for good, whose count never falls (PUB-2.43) — the
            // base is sent only where the draft records one at the position
            // the write is typed against, and every run was composed from
            // the merge's images: a refusal of them is its own fault.
            "no_base_to_record"
            | "base_extent_too_large"
            | "source_not_registered"
            | "published_target"
            | "not_owner"
            | "bad_run"
            | "dangling_source"
            | "too_many_runs"
            | "malformed" => own_fault("the draft landing", &r),
            _ => Refusal::Halt(r.refused(&v)),
        })
    }

    /// Sends one write under the merger's token.
    ///
    /// Its answer is the response document.
    ///
    /// # Errors
    ///
    /// The death signal under the token, faced; otherwise [`Board::op`]'s
    /// errors.
    pub(super) fn answered_write(&self, frame: &Value, during: &str) -> Result<Value, Refusal> {
        match self.board.op(Some(self.merger.token), frame)? {
            Answer::Closed => Err(closed(during).into()),
            Answer::Document(v) => Ok(v),
        }
    }

    /// Returns the term the act's signed writes sign over (SP-14).
    ///
    /// It is `H.1`'s pair, or `None` on a board no one has claimed, which
    /// takes the shot and the record's link without an `attest`
    /// (`Board::board_head`). Every write of a landing, an undo or a
    /// withdrawal reads it first (the module's doc); `owed` is the face a
    /// claimed board serving no head record meets — [`head_owed`] before an
    /// act's first write, [`record_owed`] where a landing stands with its
    /// record all that is left to write.
    ///
    /// # Errors
    ///
    /// A claimed board serving no head record, faced by `owed`, with nothing
    /// sent; `Board::board_head`'s halts, a head record that stands and
    /// cannot be read among them.
    pub(super) fn signing_term(
        &self,
        owed: &dyn Fn(String) -> Halt,
    ) -> Result<Option<BoardTerm>, Refusal> {
        let claimant = match self.board.board_head()? {
            BoardHead::Term(term) => return Ok(Some(term)),
            BoardHead::Unclaimed => return Ok(None),
            BoardHead::Owed { claimant } => claimant,
        };
        Err(owed(format!("the board names {claimant} its claimant and serves no head record (`H.1`), and the shot and the record's link sign over that record's pair (signed ops), so no write of the act is sent before the board writes it")).into())
    }

    /// Returns the `attest` member over `body`.
    ///
    /// It is for a write whose `doc` row is `doc`: the entry frame under
    /// `term` — `H.1`'s pair as [`Writer::signing_term`] read it — the
    /// merger's account and the row, signed by the merger's signer (signed
    /// ops; `skep_identity::entry_frame`, the one composer). `None` where
    /// `term` is none: a board no one has claimed, which drops the member
    /// unread.
    ///
    /// # Errors
    ///
    /// A merger's account this client cannot spell, as the library's own
    /// fault.
    pub(super) fn attest(
        &self,
        term: Option<BoardTerm>,
        doc: &Address,
        body: &EntryBody,
    ) -> Result<Option<Value>, Refusal> {
        let Some(term) = term else { return Ok(None) };
        let account = parse_address(self.merger.account).ok_or_else(|| {
            own_fault_face(
                "the merger's account cannot be spelled",
                self.merger.account.to_string(),
            )
        })?;
        let alg = self.merger.signer.public_key().alg().to_string();
        let bytes = entry_frame(&alg, term, &account, DocTerm::One(doc), body);
        Ok(Some(json!({"alg": alg, "sig": sig_hex(&self.merger.signer.sign(&bytes))})))
    }
}

/// Returns the death signal under the session, faced.
pub(super) fn closed(during: &str) -> Halt {
    Halt::face(
        format!("the session ended while {during}"),
        "the board answered `Skepd-Session: closed` (wire.md §Sessions)",
        "open a session again and resume: every step of the landing resumes by reading",
    )
}

/// Faces a claimed board whose head is owed, met before the landing's first
/// write (SP-14).
///
/// Nothing of the landing is written: the record's link could not be
/// signed, so no write before it is begun.
pub(super) fn head_owed(cause: String) -> Halt {
    Halt::face(
        "this board has no H.1 yet, so the merge cannot land",
        cause,
        "retry once the board has written its head; nothing was written",
    )
}

/// Faces a claimed board whose head is owed, met at the record of a landing
/// that stands (SP-14).
///
/// The member or the draft holds the merge and the record's link is not
/// written: `resume` writes it once the board has written its head, told
/// the draft for a draft landing, since a fresh draft's landing is
/// otherwise found by its record alone.
fn record_owed(landed: &RecordLanding, cause: String) -> Halt {
    let (at, act) = match landed {
        RecordLanding::Member { member, .. } => (member, "resume once the board has written its head: it finds the member holding the merge and writes the record".to_string()),
        RecordLanding::Draft { draft, .. } => (draft, format!("resume naming {draft} once the board has written its head: it finds the draft holding the merge and writes the record")),
    };
    Halt::face(
        format!("the merge stands at {at}, and its record's link is not written: this board has no H.1 yet"),
        cause,
        act,
    )
}

/// Faces a board refusal of this library's own frame (A-288's own-bug class).
///
/// It is nothing a person can act on.
pub(super) fn own_fault(what: &str, r: &Rejection) -> Refusal {
    own_fault_face(format!("the board refused {what}"), format!("{}: the frame this library composed is wrong in substance — its base, its runs, its home or its attest", r.token()))
}

/// Returns this library's own fault, faced.
///
/// There is no user-facing act to offer.
pub(super) fn own_fault_face(state: impl Into<String>, cause: impl Into<String>) -> Refusal {
    Refusal::Halt(Halt::face(state, cause, "this is a fault in this library, not in your keys or your act; nothing further was written"))
}

/// Faces an answer without the shape the write's ack promises.
pub(super) fn shape_face(op: &str, v: &Value) -> Halt {
    Halt::face(
        format!("`{op}` answered a document this client cannot read"),
        crate::halt::clipped(&v.to_string(), 200).to_string(),
        "this board is not speaking the wire this client expects",
    )
}
