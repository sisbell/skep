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
//! the base, derived from where those lines end, imaged whole; the head and
//! each side imaged whole; the shared material joined by the core over the
//! lists; the values where the value rule has work, read through the side
//! that holds them; and the prior records for the key, so a standing record
//! is known before anything is written (§3, idempotence). Every `image`
//! past the run budget is re-asked in halves and the parts re-joined by
//! I-adjacency (§8: "a region past the budget can be asked in parts"),
//! every `retrieve_v` past the delivery budget likewise.
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
//! trunk read at P off its own `doc_metadata` — its `shot_base`, the base
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
//! `own` at P where the trunk's `own_count` is above 0 and not read at all
//! at 0 (PUB-2.66); else it is the earliest trunk member the head and the
//! lines end at, the nearest common ancestor on the trunk. The lines are
//! walked before the head's extent, and the base is never the caller's to
//! know: a base the caller names is checked against the derived one beside
//! every side and refused where it disagrees, and one named beside a fork
//! side is refused unread.
//!
//! **One position for everything** (skep #762; the landing lane's ruling).
//! Every frame a shape's reads send is answered at ONE board position P:
//! the position the draft side names where it names one, else the `as_of`
//! of the shape's first read, the document's `doc_metadata`, made at the
//! head. Every later read — a fork's anchor, a draft's base, each hop of a
//! side's line, the head's extent and image, the base's image, each side's
//! image, the values read through the sides, the join's `compare` — goes
//! through `/op-at` at P, so
//! the record describes a state the board held at one moment and never one
//! that an edit landing between two reads composed; the record carries P
//! for its draft side (§4: "for a draft read at N") and each fork's and
//! draft's state as of P — the position its text last changed at,
//! `doc_metadata`'s `arranged_at`, off the one answer its anchor is read
//! from (skep #770) — the result carries P as its `as_of`, and the draft
//! landing is typed against P. A P the board
//! does not answer is refused by name — its history reclaimed
//! ([`Refusal::HistoryReclaimed`]), past the board's head
//! ([`Refusal::BeyondHead`]) or inside one commit
//! ([`Refusal::NotAPosition`]) — never read at the head instead; where P is
//! the position a merge record names, [`record::verify`] answers for it
//! (skep #761). The prior records' lookup after the shape's reads reads the
//! journal, not a draft, and stays at the head. A side whose base the
//! library cannot read — a member of another document or the bare document
//! itself, a fork in the document's own tree, a draft of an account other
//! than the trunk owner's, a draft the board records no base for, a fork it
//! records neither a base nor a source for, or one whose base, else source,
//! lies in another document (decision 15) — refuses before the first
//! `image`, as does a fork of the trunk owner's own account, whose draft is
//! the draft side and never a fork ([`Refusal::ForkOfOwner`]), a side whose
//! line passes a hop the board records no parent for, and a side begun
//! before the document's first version where the board serves no
//! `own_count`, its base an arrangement this board does not count
//! ([`Refusal::BareSource`]); a side the reader may not read refuses at its
//! own read. A run a readable side windows from a document the reader may
//! not read is answered whole by `image` and `compare` and masked by
//! `retrieve_v` (wire.md §The read predicate, "a delivery masks per run"),
//! so it refuses where a value is read, naming that document
//! ([`Refusal::Unreadable`]); the value rule switched off reads no value of
//! it.
//!
//! The reads go through [`Board::op`] under the caller's token, or with no
//! token where none is given, for the first read and the journal's, and
//! [`Board::op_at`] for every read at P, whose `history_busy` is retried a
//! bounded number of times (§7, "What it reads through"); the feed walk
//! goes through [`Board::changes`]. Nothing here writes.
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
pub(super) use join::{check_join, first_difference};
pub(crate) use reader::{session_ended, OnEnd, Reader};
pub(super) use readings::{check_shape, read_shape, values_for};
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
/// bounded").
const HISTORY_BUSY_RETRIES: u32 = 4;

// ── compose ───────────────────────────────────────────────────────────────

/// Composes a merge from the board, writing nothing.
///
/// It makes §1.3's reads in order, the core's walk and the prior records'
/// read for the key (the merge record's §7, `compose`) — all but step 6's,
/// the shot's bytes, which the landing reads.
///
/// `token` is the caller's — `None` reads as a guest, which reads public
/// members alone. Every read of the shape is made at one board position P
/// (the module's doc), which the result carries as `as_of` and as the
/// record's draft side position, so a verifier reads the draft and its
/// recorded base as this composition did (§4: "for a draft read at N") and
/// the landing types its write against it. The result carries M with each
/// run's family, the gap report, the counts (`counts.m` against
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
/// `own_count`, [`Refusal::BareSource`] — then the prior records' reads'
/// refusals, which `record::current` answers.
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
    let mut record = Record {
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
    // another's — the journal's reads, at the head: they raise the reader's
    // running `as_of` past P, which nothing below reads.
    let prior = record::current_among(&reader, &inputs.kind, &key, Some(&owner))?;
    record.replaces = prior.as_ref().and_then(|p| p.link.clone());
    Ok(Merged {
        inputs: inputs.clone(),
        composed,
        families,
        key,
        cap: SHOT_RUN_CAP,
        record,
        // P explicitly — never the reader's highest `as_of`, which the prior
        // records' reads at the head just raised.
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

/// Walks every row of the feed under `under` past `since`, oldest first.
///
/// The walk runs from `since` to the head, 0 walking from the floor: the
/// retention floor restarts the walk at the floor, a page past the byte
/// budget is re-asked at the limit that fits. With `drafts` the walk is the
/// supplement's, `drafts=true` — the rows naming a draft the token's class
/// may read, which is where a draft's own `set_arrangement` rows are
/// (wire.md §The change feed, Narrowings); without it the published
/// stream's, the member rows a head or a mint position is read off. The
/// pages are read through `reader`'s board under its token.
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
    let mut limit = None;
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
