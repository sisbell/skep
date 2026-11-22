//! The shape's reads in order (the merge record's §1.3), then the core's walk.
//!
//! [`read_shape`] makes them at the one position P — each side's line of
//! recorded bases, the base derived from where the lines end, the head and
//! the sides imaged — and composes the lists through the core, the values
//! read through the sides that hold them ([`values_for`]). The rules they
//! keep are the `reads` module's doc.

use std::cell::RefCell;

use skep_address::Address;

use crate::address::parse_address;
use crate::halt::Halt;
use crate::merge::compose::{compose_runs, Composed, Item, Options, Run, SideIx};

use super::addresses::{
    account_of, address_parent, comps, content_prefix, in_chain, is_trunk_member, last_component,
    runs_of, trunk_of,
};
use super::inputs::{Family, Side};
use super::reader::{Imaged, Reader};
use super::refusal::Refusal;
use super::MAX_SIDES;

// ── the value mapping (the fragment model) ────────────────────────────────

/// Returns where the positions of `run` stand among the sides' images.
///
/// Each stretch is `(the image's index, the V-ordinal it begins at, its
/// width)` — the image at `prefer` asked first, then the others in order —
/// so a sub-run of a run a side holds is read at that side's own V-ordinals
/// (`ordinal_of`'s mapping), and a shared identity at whichever side holds
/// it.
///
/// # Errors
///
/// A position no image holds is the library's own fault: the core places
/// only positions some side gave it.
pub(in crate::merge) fn locate(
    maps: &[Imaged],
    prefer: Option<usize>,
    run: &Run,
) -> Result<Vec<(usize, u64, u64)>, Halt> {
    let prefix = content_prefix(&run.origin);
    let order: Vec<usize> =
        prefer.into_iter().chain((0..maps.len()).filter(|i| Some(*i) != prefer)).collect();
    let mut out = Vec::new();
    let mut pos = run.i_start;
    let end = run.reach();
    while pos < end {
        let found = order.iter().find_map(|&i| {
            maps[i]
                .runs
                .iter()
                .find(|r| r.prefix == prefix && r.first <= pos && pos - r.first < r.width)
                .map(|r| (i, r))
        });
        let Some((i, r)) = found else {
            return Err(Halt::face(
                format!("no side holds the position {prefix}.{pos}"),
                "the merged list names a position none of the images read holds — a fault in this client's composition",
                "this is this client's fault; nothing was written",
            ));
        };
        let stretch = (end - pos).min(r.first + r.width - pos);
        out.push((i, r.ordinal + (pos - r.first), stretch));
        pos += stretch;
    }
    Ok(out)
}

/// Reads the values of `run`'s positions through the sides that hold them.
///
/// The sides are found by [`locate`], `prefer` asked first.
///
/// # Errors
///
/// [`locate`]'s fault; [`Reader::values`]'s errors.
pub(in crate::merge) fn values_for(
    reader: &Reader<'_>,
    maps: &[Imaged],
    prefer: Option<usize>,
    run: &Run,
) -> Result<Vec<Item>, Refusal> {
    let mut out = Vec::with_capacity(run.width as usize);
    for (i, ordinal, width) in locate(maps, prefer, run)? {
        out.extend(reader.values(&maps[i].doc, maps[i].at, ordinal, width)?);
    }
    Ok(out)
}

// ── the shape's reads ─────────────────────────────────────────────────────

/// Everything the reads of one shape yield.
///
/// `compose` and `verify` both build on it.
pub(in crate::merge) struct Readings {
    /// The one position P every read but the first was made at (the
    /// `reads` module's doc): the draft side's named position, else the first
    /// read's `as_of`.
    pub(in crate::merge) at: u64,
    /// The base: a member, or the document itself where a side was begun
    /// before its first version — derived from the sides' lines of recorded
    /// bases, a named one checked against it (the `reads` module's doc).
    pub(in crate::merge) base: Address,
    /// The base's image: the document's own arrangement where the base is
    /// the document itself.
    pub(in crate::merge) base_image: Imaged,
    /// The head's and each side's image, in side order.
    pub(in crate::merge) maps: Vec<Imaged>,
    /// The head's content extent as read.
    pub(in crate::merge) head_extent: u64,
    /// The trunk's owner account.
    pub(in crate::merge) owner: String,
    /// The core's result.
    pub(in crate::merge) composed: Composed,
    /// Each run of M's family.
    pub(in crate::merge) families: Vec<Family>,
    /// Each side's `arranged_at` at P, in side order.
    ///
    /// A fork's and a draft's come off the one `doc_metadata` its anchor was
    /// read from, `None` where the board keeps none; a member's is `None`,
    /// its address its state.
    pub(in crate::merge) arranged: Vec<Option<u64>>,
}

/// Makes the reads of §1.3 in order, then the core's walk.
///
/// The reads are the document's metadata; for each side in order, a fork's or a
/// draft's own metadata for its anchor and its state — a fork's anchor the base
/// the board records for it, else the source it was born sharing
/// ([`fork_anchor`]); a draft's the base the board records for it; each one's
/// state its `arranged_at`, carried in side order beside the readings
/// (`Readings::arranged`) — then the metadata of each hop of its line of
/// recorded bases below the trunk ([`recorded_line`]); the head's extent; the
/// base imaged — the document's own arrangement where the base is the document,
/// read only where its `own_count` is above 0; the head and each side imaged;
/// the composition with the values read through the sides. The first read is
/// made at the position the draft side names, else at the head, and every later
/// read at the one position P that read answered (the `reads` module's doc): a
/// draft at a position names P; else P is the first read's `as_of`, and an edit
/// landing on any side between two reads changes nothing the reads answer.
///
/// The base is derived from where the lines end ([`derived_base`]). A base
/// handed in is checked against it beside every side: beside a fork side it
/// is the record's own at `verify`, never a caller's ([`compose`] refuses
/// one), and one the lines do not derive is faced — the fork's recorded
/// base moved since the record with its text unmoved, or the record,
/// written before a fork side's state was kept, names none, the fork's
/// state having matched before the reads (`record::verify`); beside a draft
/// side, or beside member sides alone — a caller's or the
/// record's — it is refused by name ([`Refusal::DraftBaseDisagrees`],
/// [`Refusal::NamedBaseDisagrees`]): naming the base never moves what the
/// merge composes against.
///
/// # Errors
///
/// In this order:
///
/// - a head that is no trunk member of `doc`, faced;
/// - two drafts, [`Refusal::TwoDrafts`];
/// - more sides besides the head than [`MAX_SIDES`], faced;
/// - a member that is no member of `doc`'s chain — of another document, the
///   bare document itself, an address within a member — and a fork in
///   `doc`'s own tree — `doc` itself, a member of its chain or an address
///   within either — [`Refusal::BaseUnknown`];
/// - the metadata read's refusals — at the named position,
///   [`Reader::read`]'s faults of a position included — and an answer
///   naming no `as_of`, faced;
/// - the first side, in side order, that is a draft of an account other
///   than the trunk owner's, [`Refusal::BaseUnknown`], or a fork of the
///   trunk owner's own account, [`Refusal::ForkOfOwner`] — every side
///   judged so before any side's own read;
/// - for each side in order: at a fork or a draft its metadata read's
///   refusals at P — [`Reader::read`]'s faults of a position included,
///   [`Refusal::HistoryReclaimed`] among them — the side unreadable,
///   [`Refusal::Unreadable`]; a fork the board records neither a base nor
///   a source for or a draft it records no base for, or one whose anchor —
///   a fork's recorded base, else its source; a draft's recorded base —
///   lies in another document, [`Refusal::BaseUnknown`]; then its line's —
///   each hop's metadata read's refusals at P, a hop the board records no
///   parent for, [`Refusal::HopUnrecorded`], a parent that contradicts the
///   hop's address, faced;
/// - the head's extent read's refusals;
/// - a named base the lines do not derive: beside a fork side — the
///   record's, at `verify` — faced, naming both bases, beside a draft side
///   [`Refusal::DraftBaseDisagrees`], beside member sides alone
///   [`Refusal::NamedBaseDisagrees`];
/// - a base that is the document itself where the trunk's metadata carried
///   no `own_count`, [`Refusal::BareSource`] naming the first side whose
///   line ends there — every refusal so far decided before any `image`;
/// - then each image and value read's own refusals — a run a readable side
///   windows from a document the reader may not read,
///   [`Refusal::Unreadable`] naming that document where the value rule
///   reads its values — and an `image` run that is no content I-address.
///
/// [`compose`]: super::compose
pub(in crate::merge) fn read_shape(
    reader: &Reader<'_>,
    doc: &Address,
    head: &Address,
    base: Option<Address>,
    sides: &[Side],
    options: &Options,
) -> Result<Readings, Refusal> {
    let last = check_shape(doc, head, sides)?;
    // Step 1: the document and the head. THE ONE POSITION P (skep #762): the
    // draft side's named position, else the `as_of` of this first read,
    // made at the head; every read after it is made at P.
    let named = sides.iter().find_map(Side::position);
    let (meta, meta_as_of) = reader.metadata_read(doc, named)?;
    let at = match named.or(meta_as_of) {
        Some(at) => at,
        None => {
            return Err(Halt::face(
                "`doc_metadata` answered no `as_of`",
                format!("the read of {doc} named no position (wire.md §The response envelope: every response names where it sits)"),
                "this board is not speaking the wire this client expects; nothing was written",
            )
            .into())
        }
    };
    // The owner, in side order: a draft side is the trunk owner's account's,
    // and a fork side another account's — the owner's own draft is the
    // draft side, its words re-minted, never a fork's windows onto it.
    for side in sides {
        match side {
            Side::Draft { at, .. } if account_of(at).as_deref() != Some(meta.owner.as_str()) => {
                return Err(Refusal::BaseUnknown(side.clone()));
            }
            Side::Fork(fork) if account_of(fork).as_deref() == Some(meta.owner.as_str()) => {
                return Err(Refusal::ForkOfOwner { fork: fork.clone() });
            }
            Side::Draft { .. } | Side::Fork(_) | Side::Member(_) => {}
        }
    }
    // Each side's line, in side order: its anchor — a fork's the base the
    // board records for it, else its source; a draft's the base the board
    // records for it; a member's itself — then the bases recorded up from it
    // to the trunk, every read at P. A fork's and a draft's state comes off
    // the one `doc_metadata` its anchor is read from.
    let mut ends: Vec<LineEnd> = Vec::with_capacity(sides.len());
    let mut arranged: Vec<Option<u64>> = Vec::with_capacity(sides.len());
    for side in sides {
        let (anchor, state) = match side {
            Side::Fork(fork) => fork_anchor(reader, doc, side, fork, at)?,
            Side::Draft { at: draft, .. } => draft_base(reader, doc, side, draft, at)?,
            Side::Member(m) => (m.clone(), None),
        };
        ends.push(recorded_line(reader, doc, side, &anchor, at)?);
        arranged.push(state);
    }
    let (head_extent, head_as_of) = reader.span_set(head, Some(at))?;
    // Step 2: the base, derived from where the lines end; a named one
    // checked against it beside every side — beside a draft never against
    // the draft's recorded base itself, which a daughter's staging makes a
    // different member.
    let derived = derived_base(head, sides, &ends);
    let served = match &derived {
        Derived::Document { .. } => doc.clone(),
        Derived::Member(member) => member.clone(),
    };
    if let Some(named) = base {
        if named != served {
            // Beside a fork the named base is a record's (`compose` refuses
            // a caller's unread), and its fork's state matched before the
            // reads (`record::verify`): the fork's recorded base moved with
            // its text unmoved, or the record, written before the states
            // were kept, names none.
            return Err(if sides.iter().any(|s| matches!(s, Side::Fork(_))) {
                Halt::face(
                    format!("the record names the base {named}, and the board's records now derive {served} for its fork side"),
                    "a fork's base is derived from where the board records it standing — its recorded base, which a landing into a staged fork moves, else its source — and the fork's recorded base moved since the record, or the record, written before a fork side's state was kept, names none",
                    "this record cannot be checked against its fork as it stands, or it is not one this library would write against this board; nothing was read at another position and nothing was written",
                )
                .into()
            } else if let Some(side) = sides.iter().find(|s| matches!(s, Side::Draft { .. })) {
                Refusal::DraftBaseDisagrees { side: side.clone(), named, served }
            } else {
                Refusal::NamedBaseDisagrees { named, served }
            });
        }
    }
    // The base's image: at the document itself, its own arrangement from
    // before its first version, counted by the trunk's `own_count` read at P
    // and read at P only where that count is above 0.
    let base_image = match derived {
        Derived::Member(member) => reader.imaged(&member, Some(at))?,
        Derived::Document { side, hop } => {
            let Some(count) = meta.own_count else {
                return Err(Refusal::BareSource {
                    side: side.clone(),
                    source: doc.clone(),
                    hop: hop.cloned(),
                });
            };
            reader.imaged_own(doc, at, count)?
        }
    };
    let base = served;
    // Step 3: the head, then each side — every image at P, the head's
    // included, so the values read through the images are read at P too.
    let (head_runs, head_imaged_as_of) =
        reader.image_read(head, Some(at), 1, head_extent, false)?;
    let mut maps = vec![Imaged {
        doc: head.clone(),
        own: false,
        at: Some(at),
        extent: head_extent,
        runs: head_runs,
        as_of: head_as_of.max(head_imaged_as_of),
    }];
    for side in sides {
        maps.push(reader.imaged(side.address(), Some(at))?);
    }
    // Steps 4 and 5: the join and the walk, the values through the sides.
    let base_runs = runs_of(&base_image.runs)?;
    let mut side_runs = Vec::with_capacity(maps.len());
    for (ix, m) in (0..=last).zip(&maps) {
        side_runs.push((SideIx(ix), runs_of(&m.runs)?));
    }
    let fault: RefCell<Option<Refusal>> = RefCell::new(None);
    let values = |side: SideIx, run: &Run| -> Option<Vec<Item>> {
        match values_for(reader, &maps, Some(side.0 as usize), run) {
            Ok(items) => Some(items),
            Err(e) => {
                fault.borrow_mut().get_or_insert(e);
                None
            }
        }
    };
    let composed = compose_runs(&base_runs, doc, &side_runs, None, options, &values);
    if let Some(e) = fault.into_inner() {
        return Err(e);
    }
    let families = composed.runs.iter().map(|p| family_of(&p.run.origin, doc, sides)).collect();
    Ok(Readings {
        at,
        base,
        base_image,
        maps,
        head_extent,
        owner: meta.owner,
        composed,
        families,
        arranged,
    })
}

/// Checks a shape's sides before any read.
///
/// It answers the last side's one-byte number. The checks are
/// [`read_shape`]'s first refusals, in its order: a head that is
/// no trunk member of `doc`, two drafts, more sides than [`MAX_SIDES`], a
/// member that is no member of `doc`'s chain and a fork in `doc`'s own
/// tree. A verifier makes them before it reads a fork's state.
///
/// # Errors
///
/// As [`read_shape`]'s first four.
pub(in crate::merge) fn check_shape(doc: &Address, head: &Address, sides: &[Side]) -> Result<u8, Refusal> {
    if !is_trunk_member(doc, head) {
        return Err(Halt::face(
            format!("{head} is not a trunk member of {doc}"),
            "the head is the document's latest trunk member, `D.h`",
            "name the head member, or read it with `head_of`",
        )
        .into());
    }
    if sides.iter().filter(|s| matches!(s, Side::Draft { .. })).count() > 1 {
        return Err(Refusal::TwoDrafts);
    }
    // Every list the walk is given is numbered by its one-byte `SideIx`, the
    // head's 0 and each side's its place after it: `last` is the last side's.
    let Ok(last) = u8::try_from(sides.len()) else {
        return Err(Halt::face(
            format!(
                "this merge names {} sides besides the head, past the {MAX_SIDES} one merge composes",
                sides.len()
            ),
            "a merge numbers every list it composes by one byte, the head's first",
            "merge fewer sides at a time; nothing was read or written",
        )
        .into());
    };
    for side in sides {
        match side {
            // A draft's anchor is read off the board after the trunk's own
            // metadata (`read_shape`).
            Side::Draft { .. } => {}
            // A fork lies outside the trunk's own tree: `doc` itself, a
            // member of its chain or an address within either is none. Its
            // anchor is read off the board as a draft's is.
            Side::Fork(fork) => {
                if trunk_of(fork).as_ref() == Some(doc) {
                    return Err(Refusal::BaseUnknown(side.clone()));
                }
            }
            Side::Member(m) => {
                if m == doc || !in_chain(doc, m) {
                    return Err(Refusal::BaseUnknown(side.clone()));
                }
            }
        }
    }
    Ok(last)
}

/// Reads where the board records a fork side standing: the fork's anchor.
///
/// It is the fork's `doc_metadata` `base` where the board records one — a
/// document another account's `stage` minted: the member or the bare
/// document it was staged from, or the base it inherited as an alternative,
/// moved to the head by each landing into it (wire.md §Namespace, `stage`)
/// — else its `source`, the member or the bare document a `version` minted
/// it sharing (the fork-source design record, arm A). A recorded base is
/// where the draft now stands, so it is never passed over for the source
/// (the owner's ruling of 2026-11-19; skep #1106). Both are read off the
/// one `doc_metadata` at the one position `at`, and the one taken is the
/// anchor where it is `doc` itself or a member of its chain (the merge
/// record's case (j)): the two checks in order — present, of this
/// document's chain. An anchor that is `doc` itself is a fork taken before
/// its first version, whose line ends there at once ([`recorded_line`]).
/// Beside it is the fork's state, the same answer's `arranged_at`, which
/// the record keeps for the fork side ([`SideAt::Fork`]).
///
/// # Errors
///
/// [`Reader::metadata`]'s errors on the fork — the fork unreadable,
/// [`Refusal::Unreadable`]; a fork the board records neither a base nor a
/// source for — one `fork` or `create_new_document` minted — or one whose
/// recorded base, else source, lies in another document — a staged fork
/// published as an edition of its own among them, its base moved to that
/// edition's member — [`Refusal::BaseUnknown`].
///
/// [`SideAt::Fork`]: super::record::SideAt::Fork
fn fork_anchor(
    reader: &Reader<'_>,
    doc: &Address,
    side: &Side,
    fork: &Address,
    at: u64,
) -> Result<(Address, Option<u64>), Refusal> {
    let meta = reader.metadata(fork, Some(at))?;
    match meta.base.or(meta.source).as_deref().and_then(parse_address) {
        Some(anchor) if in_chain(doc, &anchor) => Ok((anchor, meta.arranged_at)),
        _ => Err(Refusal::BaseUnknown(side.clone())),
    }
}

/// Reads the base the board records for a draft side: the draft's anchor.
///
/// It is the draft's `doc_metadata` `base` (wire.md §Namespace, `stage`;
/// §The response envelope): the member or the bare document the draft was
/// staged from, moved to the member each publication of the draft itself
/// minted and never by a merge's shot that names the draft, which keeps it
/// (`keep_base`; skep #944) — read as [`fork_anchor`] reads a fork's, never
/// the caller's to know — and it is the draft's anchor where it is `doc`
/// itself or a member of its chain: the two checks in order — recorded, of
/// this document's chain. The read is at the one position `at`, as the
/// draft's image is (wire.md §Reading history): the base that stood when
/// the draft was read, which a publication of the draft may have moved
/// since, so a record's side composes against the base its merge composed
/// against. The merge's base is then derived up the bases recorded from it
/// ([`recorded_line`]), so a draft staged from a daughter `D.k.m` merges
/// with the head over `D.k`, the base that daughter was published against,
/// and one staged from `D` itself, or whose publication landed as version
/// 1's daughter, over `D`'s own arrangement. Beside it is the draft's
/// state, the same answer's `arranged_at` ([`SideAt::Draft`]).
///
/// # Errors
///
/// [`Reader::metadata`]'s errors on the draft — the draft unreadable,
/// [`Refusal::Unreadable`]; a draft the board records no base for — never
/// staged, or minted by `fork` or `create_new_document` — or one whose
/// recorded base lies in another document, [`Refusal::BaseUnknown`].
///
/// [`SideAt::Draft`]: super::record::SideAt::Draft
fn draft_base(
    reader: &Reader<'_>,
    doc: &Address,
    side: &Side,
    draft: &Address,
    at: u64,
) -> Result<(Address, Option<u64>), Refusal> {
    let meta = reader.metadata(draft, Some(at))?;
    match meta.base.as_deref().and_then(parse_address) {
        Some(base) if in_chain(doc, &base) => Ok((base, meta.arranged_at)),
        _ => Err(Refusal::BaseUnknown(side.clone())),
    }
}

/// Where a side's line of recorded bases ends ([`recorded_line`]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum LineEnd {
    /// The document itself: the side was begun before its first version.
    Document {
        /// The member on the line whose recorded base is the document;
        /// `None` where the side's anchor is the document.
        hop: Option<Address>,
    },
    /// A trunk member, where the address is the record.
    Trunk(Address),
}

/// Walks a side's line of recorded bases from its anchor to where it meets
/// the trunk (the `reads` module's doc).
///
/// `anchor` is the side's own address for a member; a fork's recorded base,
/// else its source; a draft's recorded base. Each hop below the trunk is
/// read at the one position `at`, its recorded parent the hop's
/// `doc_metadata` `shot_base` — the base its shot was made against (wire.md
/// §The response envelope, the shot terms) — else its `source`, the member
/// an owned `version` snapshotted into it. The line ends at `doc` itself,
/// or at a trunk member with nothing read: a trunk member `D.k+1` was
/// minted against `D.k`, a shot naming the head landing on the trunk and
/// one naming another base landing as that base's daughter
/// (`skep-arrangement`'s `shot_admission`), so on the trunk the address is
/// the record. A recorded parent is the hop's address parent, or `doc`
/// itself for a hop under `doc`'s first member — a shot naming the bare
/// document once a member stands lands there — so each hop strips a version
/// component or reaches `doc`, and the walk ends.
///
/// # Errors
///
/// [`Reader::metadata`]'s errors on a hop — [`Refusal::Unreadable`] naming
/// it among them — each answered as itself, never as a hop with no record
/// (SP-14); a hop the board records no parent for,
/// [`Refusal::HopUnrecorded`] — a parent is never taken from an address
/// (the owner's ruling of 2026-11-02); a parent that is no address, or one
/// the minting rule cannot have recorded, faced as the board's fault.
fn recorded_line(
    reader: &Reader<'_>,
    doc: &Address,
    side: &Side,
    anchor: &Address,
    at: u64,
) -> Result<LineEnd, Refusal> {
    let mut hop = anchor.clone();
    let mut bare_hop = None;
    loop {
        if hop == *doc {
            return Ok(LineEnd::Document { hop: bare_hop });
        }
        if is_trunk_member(doc, &hop) {
            return Ok(LineEnd::Trunk(hop));
        }
        let meta = reader.metadata(&hop, Some(at))?;
        let Some(recorded) = meta.shot_base.or(meta.source) else {
            return Err(Refusal::HopUnrecorded { side: side.clone(), hop });
        };
        let parent = parse_address(&recorded).ok_or_else(|| {
            Halt::face(
                format!("the board records `{recorded}` as the base {hop} was published against"),
                "a recorded base (`doc_metadata`'s `shot_base` or `source`) is an address",
                "this is a board fault; nothing was written",
            )
        })?;
        let under = address_parent(&hop);
        let beside_first = parent == *doc
            && under
                .as_ref()
                .is_some_and(|u| is_trunk_member(doc, u) && last_component(u) == Some(1));
        if under.as_ref() != Some(&parent) && !beside_first {
            return Err(Halt::face(
                format!("the board records {parent} as the base {hop} was published against"),
                format!("a member lies under the base its shot or its `version` named — under {doc}'s first member where that base is {doc} itself — and {hop} does not lie under {parent}"),
                "this is a board fault, its records contradicting its own minting rule; nothing was written",
            )
            .into());
        }
        if parent == *doc {
            bare_hop = Some(hop);
        }
        hop = parent;
    }
}

/// The base the sides' lines derive with the head ([`derived_base`]): the
/// base's address and how its image is read, from one value.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Derived<'s> {
    /// The document itself, its own arrangement from before its first
    /// version imaged: `side` is the first side whose line ends there, and
    /// `hop` the member on that line recorded against the document, where
    /// the side's anchor is not the document itself.
    Document {
        /// The first side whose line ends at the document.
        side: &'s Side,
        /// The member on its line recorded against the document.
        hop: Option<&'s Address>,
    },
    /// A trunk member, imaged as it stands.
    Member(Address),
}

/// Returns the base the sides' lines derive with the head (the `reads`
/// module's doc), `ends` parallel to `sides`.
///
/// It is the document itself where any line ends there, the document's own
/// arrangement from before its first version being the one state every
/// side then descends from; else the earliest trunk member among the head
/// and the lines' ends — the nearest common ancestor on the trunk, every
/// member of which was minted against the one before it, as [`base_of`]
/// of two trunk members answers.
///
/// [`base_of`]: crate::merge::base_of
fn derived_base<'s>(head: &Address, sides: &'s [Side], ends: &'s [LineEnd]) -> Derived<'s> {
    let mut base = head;
    for (side, end) in sides.iter().zip(ends) {
        match end {
            LineEnd::Document { hop } => return Derived::Document { side, hop: hop.as_ref() },
            LineEnd::Trunk(member) => {
                if comps(member) < comps(base) {
                    base = member;
                }
            }
        }
    }
    Derived::Member(base.clone())
}

/// Returns a run's family by its origin.
///
/// It is the trunk's own, a draft side's, or a window.
fn family_of(origin: &Address, doc: &Address, sides: &[Side]) -> Family {
    if origin == doc {
        Family::Own
    } else if sides.iter().any(|s| matches!(s, Side::Draft { at, .. } if at == origin)) {
        Family::DraftNative
    } else {
        Family::Window
    }
}
