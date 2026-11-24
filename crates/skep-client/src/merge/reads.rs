//! The merge's reads — the merge record's §1.3 in its order.
//!
//! Beside them stands what they build: [`compose`], which reads the head,
//! the base and every side as run lists, composes them through the core and
//! writes nothing; the conversion of an `image` answer's runs to the core's,
//! each origin the bare document ([`origin_of`]); [`head_of`], the
//! feed-walk fallback for a bare document's head member; the read of the
//! correspondence records of every origin among a past state's runs, each
//! in its owner's own account, which a comparison by identity maps both its
//! texts through too (`history::records`), and [`mapped_image`], a state's
//! image mapped through them at its own spelling — what the restore and the
//! take-backs send, so words a publication made public since come back as
//! the published words they became and a member's own words as themselves
//! — with [`mapped`], the same mapping over the core's runs; the read of
//! the person's own origins' records alone, the twin fence's; and
//! [`Refusal`], every refusal a read or a landing can meet.
//!
//! The reads, in the record's order (§1.3): the document's metadata; each
//! side's line of recorded bases, walked to the trunk; the head's extent;
//! the head imaged whole, then the base, derived from where those lines
//! end — the head's own image where the base is the head, else imaged
//! whole; each side imaged whole; the shared material joined by the core
//! over the lists; the values where the value rule has work, read through
//! the side that holds them; and the prior records for the key, so a
//! standing record is known before anything is written (§3, idempotence).
//! Every `image` past the run budget is re-asked in halves and the parts
//! re-joined by I-adjacency (§8: "a region past the budget can be asked in
//! parts"), every value read past the delivery budget or the dialer's
//! answer cap likewise.
//!
//! **The base, from the records** (the owner's ruling of 2026-11-02: a
//! version tree takes a daughter's parent from the base the board recorded,
//! never from its address). A side's line starts at its ANCHOR: a member's
//! is itself; a fork side's where the board records it standing — the BASE
//! the board records for it where it records one, `doc_metadata`'s `base`,
//! the member or the bare document another account's `stage` copied into
//! it, moved to the head by each landing into it (the owner's ruling of
//! 2026-11-19; skep #1106), else its SOURCE, `doc_metadata`'s `source`, the
//! member or the bare document a `version` minted it sharing (the
//! fork-source design record, arm A; the merge record's case (j)); a draft
//! side's the BASE the board records for it — `doc_metadata`'s `base`, the
//! member or the bare document it was staged from, moved to the member each
//! publication it rendered minted (wire.md §Namespace, `stage`). From the
//! anchor the line climbs the bases the board recorded, each hop below the
//! trunk read off its own `doc_metadata` — its `shot_base`, the base
//! its shot was made against, else its `source`, the member a `version`
//! snapshotted into it — until it ends at the document itself or at a trunk
//! member, where the address is the record: a shot naming the head lands on
//! the trunk and one naming any other base lands as that base's daughter,
//! save one naming the bare document once a member stands, which lands
//! under the first member, `D.1.k`, recorded against `D`
//! (`skep-arrangement`'s `shot_admission`). A hop the board records no
//! parent for is refused ([`Refusal::HopUnrecorded`]), never taken from its
//! address, and a parent the minting rule cannot have recorded is the
//! board's fault, faced. The base is the document itself where any side's
//! line ends there — a side begun before the document's first version — its
//! image the document's own arrangement from before that version, read with
//! `own` where the trunk's `own_count` is above 0 and not read at all at 0
//! (PUB-2.66); else it is the earliest trunk member the head and the
//! lines end at, the nearest common ancestor on the trunk. The lines are
//! walked before the head's extent, and the base is never the caller's to
//! know: a base the caller names is checked against the derived one beside
//! every side and refused where it disagrees, and one named beside a fork
//! side is refused unread.
//!
//! **One state, fenced at the head** (skep #762, #1144; the owner's ruling
//! of 2026-11-22). The record describes a state the
//! board held at ONE board position P, never one an edit landing between two
//! reads composed, and a composition reads it at the HEAD, rebuilding no
//! past state. What can change while it reads — the head, a side that is a
//! trunk member, which can take a deposit, the draft and each fork — is
//! FENCED: its `doc_metadata` is read before any `image` and again after the
//! images and the values, a fork's and a draft's opening fence the read its
//! anchor and its state come off, and P is the highest `as_of` the opening
//! fences answered. A side whose closing fence answers another `arranged_at`
//! — the position its text last changed at, which every placement, removal,
//! reorder, shot and snapshot into it moves — or another recorded base or
//! source, which move without it, is refused [`Refusal::SideMoved`], nothing
//! written, the way on to compose again: every opening fence came before
//! every closing one, so each side fenced held at P the state its image was
//! read in. What cannot change is read at the head with no fence: a member
//! below the head and each hop of a side's line are published versions, the
//! same at every position, and the document's own arrangement from before
//! its first version stands once a version does. Every VALUE is read at the
//! head ([`values_of`]): a member's by its V-ordinals, which a version never
//! moves and the head moves only by deposits past its extent; a draft's or a
//! fork's by the I-addresses its image served, a value at an I-address being
//! written once — so a value read needs no past state whenever it is made,
//! and the shot reads each holder's values in as few reads as the budgets
//! allow. The record carries P for its draft side (§4: "for a draft read at
//! N") and each fork's and draft's state as of P — its `arranged_at`, off the
//! one answer its anchor is read from (skep #770) — the result carries P as
//! its `as_of`, and the draft landing is typed against P, so an edit to the
//! draft after P is refused `arrangement_moved`. A composition whose draft
//! side names a position reads as of it instead — the trunk, the head, the
//! draft, each fork and each side that is a trunk member, each image and
//! anchor — the members that cannot change at the head, and fences nothing:
//! P is the position named. A verification reads every metadata and image as
//! of one position, its draft side's, else the `as_of` of its first read,
//! made at the head, and its values at the head ([`record::verify`]). A
//! position the board does not answer is refused by name — its history
//! reclaimed ([`Refusal::HistoryReclaimed`]), past the board's head
//! ([`Refusal::BeyondHead`]) or inside one commit ([`Refusal::NotAPosition`])
//! — never read at the head instead; where it is the position a merge record
//! names, [`record::verify`] answers for it (skep #761). The prior records'
//! lookup after the shape's reads reads the journal, at the head.
//!
//! A side whose base the library cannot read — a member of another
//! document or the bare document itself, a fork in the document's own
//! tree, a draft of an account other than the trunk owner's, a draft the
//! board records no base for, a fork it records neither a base nor a source
//! for, or one whose base, else source, lies in another document (decision
//! 15) — refuses before the first `image`, as does a fork of the trunk
//! owner's own account, whose draft is
//! the draft side and never a fork ([`Refusal::ForkOfOwner`]), a side whose
//! line passes a hop the board records no parent for, and a side begun
//! before the document's first version where the board serves no
//! `own_count`, its base an arrangement this board does not count
//! ([`Refusal::BareSource`]); a side the reader may not read refuses at its
//! own read. A run a readable side windows from a document the reader may
//! not read is answered whole by `image` and `compare`; a member's value
//! read masks it at its own position (`retrieve_v`; wire.md §The read
//! predicate, "a delivery masks per run") and a read by identity of a
//! draft's or a fork's words refuses it whole (`retrieve_i`), each naming
//! that document, so it refuses where a value is read
//! ([`Refusal::Unreadable`]); the value rule switched off reads no value of
//! it. A `withheld` or a `doc_not_registered` at a read of several
//! documents — the join's `compare`, the read by identity — names the
//! document the board's `site.addr` names, and one naming none this client
//! parses is the board's refusal verbatim, [`Refusal::Halt`], never one of
//! the read's documents in its place (SP-18).
//!
//! The reads go through [`Board::op`] under the caller's token, or with no
//! token where none is given, and through [`Board::op_at`] for a read as of
//! a position, whose `history_busy` is retried a bounded number of times
//! (§7, "What it reads through"); the feed walk goes through
//! [`Board::changes`]. Nothing here writes.
//!
//! **The session's end.** Every read and write of the merge, the restore
//! and the take-backs that meets the death signal under the caller's token
//! answers [`Refusal::SessionEnded`] (wire.md §Sessions), carrying the face
//! that names the step it met and the way on that the act it stopped
//! leaves — a landing resumed, a take-back whose write stands left as it
//! is, every other act run again — so an embedder ends its session on the
//! arm, never on the words. The reader and the writer are each built for
//! one act's way on (`OnEnd`), and the one constructor composes the face
//! (`session_ended`). A read that presented no token cannot meet the
//! signal: one that does is the board's or the transport's fault,
//! [`Refusal::Halt`], as [`Board`] faces it.

use serde_json::Value;
use skep_address::Address;

use crate::address::parse_address;
use crate::board::{Board, ChangesAnswer, ChangesQuery, Token};

use super::record::{self, Record, SideAt};

use readings::Readings;

mod addresses;
mod correspondence;
mod inputs;
mod join;
mod reader;
mod readings;
mod refusal;

pub use addresses::origin_of;
pub(crate) use addresses::runs_of;
pub(super) use addresses::{
    comps, content_prefix, daughter_of, is_trunk_member, last_component, next_trunk_member,
    version_components,
};
pub use correspondence::{mapped, mapped_image};
pub(crate) use correspondence::{owners_records, records_of};
pub use inputs::{Family, Inputs, Merged, Role, Side};
pub(super) use join::{check_join, first_difference, first_word_difference};
pub(crate) use reader::{session_ended, OnEnd, Reader};
pub(super) use readings::{check_shape, fence, read_shape, values_for, values_of, Reading};
pub(super) use refusal::stretches;
pub use refusal::{NoUndo, Refusal};

/// The most runs one shot may name.
///
/// It is the wire's list cap, `MAX_WIRE_LIST` = 4,096 elements per request
/// array, which the shot's `runs` is parsed through (the merge record's §8,
/// "The three caps, read at the pin"). A merged list past it is refused
/// with the count, never split (decision 13).
pub const SHOT_RUN_CAP: usize = 1 << 12;

/// The most sides one merge composes besides the head.
///
/// Every list the core walks is numbered by its one-byte [`SideIx`], the
/// head's `0` and each side's its place after it. A merge of more sides is
/// refused by name before any read.
///
/// [`SideIx`]: super::SideIx
pub(super) const MAX_SIDES: usize = u8::MAX as usize;

/// The most items one `retrieve_v` delivers.
///
/// It is `MAX_DELIVERY_ITEMS`, 131,072 (wire.md §Rejection codes,
/// `too_many_items`): a value read wider than it is made in parts.
pub(super) const MAX_DELIVERY_ITEMS: u64 = 1 << 17;

/// How many times a `history_busy` on a read at a position is retried.
///
/// Past them the read is [`Refusal::HistoryBusy`] (§7: "retry with backoff,
/// bounded"). A composition naming no position, and a landing into a draft
/// with a recorded base or by a shot, read at the head and never meet it;
/// a landing into a draft with none reads the past states its rows' walk
/// needs (the `landings` module's doc).
const HISTORY_BUSY_RETRIES: u32 = 4;

// ── compose ───────────────────────────────────────────────────────────────

/// Composes a merge from the board, writing nothing.
///
/// It makes §1.3's reads in order, the core's walk and the prior records'
/// read for the key (the merge record's §7, `compose`) — all but step 6's,
/// the shot's bytes, which the landing reads.
///
/// `token` is the caller's — `None` reads as a guest, which reads public
/// members alone. The shape is read at the head, each side that can change
/// fenced, or as of the position its draft side names (the module's doc),
/// and stands at one board position P, which the result carries as `as_of`
/// and as the record's draft side position, so a verifier reads the draft
/// and its recorded base as this composition did (§4: "for a draft read at
/// N") and the landing types its write against it. The result carries M
/// with each run's family, the gap report, the counts (`counts.m` against
/// [`SHOT_RUN_CAP`], carried, not refused here), the record the landing
/// would write, and the standing record for the key where one is current.
///
/// # Errors
///
/// A base named beside a fork side, [`Refusal::ForkBaseNamed`], before any
/// read — a fork's base is the board's to serve (the fork-source design
/// record, decision 8); then `read_shape`'s — more than 255 sides besides
/// the head among them, faced before any read; a fork of the trunk owner's
/// own account, [`Refusal::ForkOfOwner`], after the trunk's metadata alone;
/// a hop the board records no parent for, [`Refusal::HopUnrecorded`]; a
/// named base the sides' recorded bases do not derive,
/// [`Refusal::DraftBaseDisagrees`] or [`Refusal::NamedBaseDisagrees`]; a
/// side begun before the document's first version on a board serving no
/// `own_count`, [`Refusal::BareSource`]; a side that can change that changed
/// while it was read, [`Refusal::SideMoved`] naming it, nothing written, and
/// a board serving no `arranged_at` to fence a side by, faced; a draft side
/// named at a position the board does not answer,
/// [`Refusal::HistoryReclaimed`], [`Refusal::BeyondHead`] or
/// [`Refusal::NotAPosition`], and [`Refusal::HistoryBusy`] past the bounded
/// retries — a composition naming no position meets none of the four — then
/// the prior records' reads' refusals, which `record::current` answers.
pub fn compose(board: &Board, token: Option<&Token>, inputs: &Inputs) -> Result<Merged, Refusal> {
    if let Some(base) = &inputs.base {
        if let Some(fork) = inputs.sides.iter().find_map(|s| match s {
            Side::Fork(f) => Some(f),
            _ => None,
        }) {
            return Err(Refusal::ForkBaseNamed { fork: fork.clone(), base: base.clone() });
        }
    }
    let reader = Reader::new(board, token, OnEnd::Rerun);
    let readings = read_shape(
        &reader,
        Reading::Composing,
        &inputs.doc,
        &inputs.head,
        inputs.base.clone(),
        &inputs.sides,
        &inputs.options,
    )?;
    let Readings { at, base, maps, head_extent, owner, composed, families, arranged, .. } =
        readings;
    // The record's sides: the head, then each side — a draft at P, the one
    // position it was read at, and a fork and a draft with their states.
    let mut sides: Vec<SideAt> = vec![SideAt::Member { at: inputs.head.clone(), role: Role::Head }];
    sides.extend(
        inputs
            .sides
            .iter()
            .zip(arranged)
            .map(|(side, arranged_at)| SideAt::of(side, at, arranged_at)),
    );
    let record = Record {
        doc: inputs.doc.clone(),
        base,
        sides,
        landed: None,
        claims: Vec::new(),
        runs: composed.counts,
        retries: inputs.options.retries,
        gaps: composed.gaps.clone(),
        values: composed.values.clone(),
        answers: Vec::new(),
        replaces: None,
        by: record::by(),
        link: None,
    };
    // The key is the record's own, so the two never disagree.
    let key = record.key();
    // Step 7: the prior records, the trunk owner's account's current over
    // another's, found through the sides but the head — the journal's reads,
    // at the head: they raise the reader's running `as_of` past P, which
    // nothing below reads. The prior stands beside the record, never in its
    // `replaces`: it can be another account's record, which no landing of
    // the merger's replaces, and the landing names what its record replaces
    // from its own read (P20).
    let head = Some(&inputs.head);
    let prior = record::current_among(&reader, &inputs.kind, &key, Some(&owner), head)?;
    Ok(Merged {
        inputs: inputs.clone(),
        composed,
        families,
        key,
        cap: SHOT_RUN_CAP,
        record,
        // P explicitly — never the reader's highest `as_of`, which the
        // closing fences and the prior records' reads at the head raised.
        as_of: at,
        prior,
        head_extent,
        maps,
    })
}

// ── the feed-walk fallback ────────────────────────────────────────────────

/// Returns the head member of bare document `doc` by walking its change feed.
///
/// The walk is the fallback the merge record's §1.3 step 1 describes, "read
/// backwards to the last `publish` row": no single read answers a bare
/// document's head member (unverified-here 7), so the last `publish` row
/// under `doc` whose minted member is a trunk member names it; a daughter's
/// row never does. `None` for a document with no member, or one whose head
/// member's `publish` row is below the feed's retention floor.
///
/// The walk is paged from the floor up under `under=doc`, so its cost is the
/// document's own rows; an embedder that knows the head names it instead.
///
/// # Errors
///
/// The feed walk's: a transport fault, [`Refusal::Halt`]; the death signal
/// under the token, [`Refusal::SessionEnded`], the walk run again on a new
/// session.
pub fn head_of(
    board: &Board,
    token: Option<&Token>,
    doc: &Address,
) -> Result<Option<Address>, Refusal> {
    let mut head: Option<Address> = None;
    feed_rows(&Reader::new(board, token, OnEnd::Rerun), &doc.to_string(), false, 0, |row| {
        if row["op"].as_str() != Some("publish") {
            return;
        }
        if let Some(member) = row["docs"]
            .as_array()
            .and_then(|d| d.first())
            .and_then(Value::as_str)
            .and_then(parse_address)
        {
            if is_trunk_member(doc, &member) {
                head = Some(member);
            }
        }
    })?;
    Ok(head)
}

/// Returns the commit position of the `publish` row that minted `member`.
///
/// It is read off the member's own rows of the feed, through `reader`;
/// `None` where the feed no longer holds it.
///
/// # Errors
///
/// [`feed_rows`]'s.
pub(super) fn position_of(reader: &Reader<'_>, member: &Address) -> Result<Option<u64>, Refusal> {
    let mut at = None;
    let text = member.to_string();
    feed_rows(reader, &text, false, 0, |row| {
        if at.is_none()
            && row["op"].as_str() == Some("publish")
            && row["docs"].as_array().and_then(|d| d.first()).and_then(Value::as_str)
                == Some(text.as_str())
        {
            at = row["at"].as_u64();
        }
    })?;
    Ok(at)
}

/// The rows a walk of the drafts supplement asks each page for.
///
/// It is the wire's most (wire.md §The change feed, Paging: `limit`'s
/// maximum 4096). A draft's own rows carry no `attest`, so a page of them
/// stays far inside the page byte budget; a page that would pass it is
/// refused with the `limit` that fits, which the walk asks again at.
const DRAFTS_PAGE: u64 = 1 << 12;

/// Walks every row of the feed under `under` past `since`, oldest first.
///
/// The walk runs from `since` to the head, 0 walking from the floor: the
/// retention floor restarts the walk at the floor, a page past the byte
/// budget is re-asked at the limit that fits. With `drafts` the walk is the
/// supplement's, `drafts=true` — the rows naming a draft the token's class
/// may read, which is where a draft's own `set_arrangement` rows are
/// (wire.md §The change feed, Narrowings) — asked [`DRAFTS_PAGE`] rows a
/// page; without it the published stream's, the member rows a head or a
/// mint position is read off, whose signed rows the wire's default page
/// holds. The pages are read through `reader`'s board under its token.
///
/// # Errors
///
/// The feed's halts, [`Refusal::Halt`]: a transport fault, and the death
/// signal on a walk that presents no token, the board's fault; the death
/// signal under the token, [`Refusal::SessionEnded`], faced for `reader`'s
/// act.
pub(super) fn feed_rows(
    reader: &Reader<'_>,
    under: &str,
    drafts: bool,
    mut since: u64,
    mut each: impl FnMut(&Value),
) -> Result<(), Refusal> {
    let mut limit = drafts.then_some(DRAFTS_PAGE);
    loop {
        let query = ChangesQuery { since, under: Some(under), drafts, limit };
        match reader.board.changes(reader.token, &query)? {
            ChangesAnswer::Page(page) => {
                for row in &page.changes {
                    each(row);
                }
                if !page.more {
                    return Ok(());
                }
                since = page.last;
            }
            ChangesAnswer::HistoryReclaimed { floor } => {
                // The page is `(since, head]`, so the oldest answerable
                // position is reached from the one below it.
                let next = floor.map_or(since + 1, |f| f.saturating_sub(1));
                if next <= since {
                    return Ok(());
                }
                since = next;
            }
            ChangesAnswer::TooLarge { fits } => limit = Some(fits),
            ChangesAnswer::Closed => {
                return Err(session_ended("walking the change feed", reader.on_end))
            }
        }
    }
}
