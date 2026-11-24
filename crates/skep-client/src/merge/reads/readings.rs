//! The shape's reads in order (the merge record's §1.3), then the core's walk.
//!
//! [`read_shape`] makes them as the act it serves reads them ([`Reading`]) —
//! each side's line of recorded bases, the base derived from where the lines
//! end, the head and the sides imaged, each side that can change fenced
//! where a composition reads it at the head — and composes the lists through
//! the core, the values read at the head through the sides that hold them
//! ([`values_for`], [`values_of`]), the dedup's in one walk's reads
//! together ([`compose_with_values`]). The rules they keep are the `reads`
//! module's doc.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};

use skep_address::Address;

use crate::address::parse_address;
use crate::board::answers::{ArrangedAt, Metadata};
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

/// One stretch of a run's positions, where an image holds it.
struct Stretch<'m> {
    /// The image's index among the sides' images.
    image: usize,
    /// The V-ordinal it begins at in that image.
    ordinal: u64,
    /// The I-address prefix the image served it under.
    prefix: &'m str,
    /// Its first position's last component.
    first: u64,
    /// The positions it holds.
    width: u64,
}

/// Returns where the positions of `run` stand among the sides' images.
///
/// Each stretch is a run of positions one image holds, with the V-ordinal it
/// begins at there and the I-address the image served it at — the image at
/// `prefer` asked first, then the others in order — so a sub-run of a run a
/// side holds is read at that side's own V-ordinals (`ordinal_of`'s
/// mapping), and a shared identity at whichever side holds it.
///
/// # Errors
///
/// A position no image holds is the library's own fault: the core places
/// only positions some side gave it.
fn locate<'m>(maps: &'m [Imaged], prefer: Option<usize>, run: &Run) -> Result<Vec<Stretch<'m>>, Halt> {
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
        let width = (end - pos).min(r.first + r.width - pos);
        out.push(Stretch {
            image: i,
            ordinal: r.ordinal + (pos - r.first),
            prefix: &r.prefix,
            first: pos,
            width,
        });
        pos += width;
    }
    Ok(out)
}

/// Reads the values of `run`'s positions through the sides that hold them.
///
/// It is [`values_of`] of the one run.
///
/// # Errors
///
/// As [`values_of`]'s.
pub(in crate::merge) fn values_for(
    reader: &Reader<'_>,
    doc: &Address,
    maps: &[Imaged],
    prefer: Option<usize>,
    run: &Run,
) -> Result<Vec<Item>, Refusal> {
    Ok(values_of(reader, doc, maps, &[(prefer, run)])?.pop().unwrap_or_default())
}

/// Reads the values of several runs at the head, one list a run.
///
/// Each `(prefer, run)` is found among the images by [`locate`], the image at
/// `prefer` asked first, and every stretch is read by the image that holds
/// it, each holder's stretches in as few reads as the budgets allow: a
/// member of `doc`'s chain — the head, a member side — by its V-ordinals
/// ([`Reader::values_by_ordinal`]), which hold the same words at every
/// position, a version never changing and the head only gaining deposits
/// past its extent; a draft or a fork by the I-addresses its image served
/// ([`Reader::values_by_identity`]), since either can change once read and a
/// value at an I-address is written once. No value is read as of a past
/// position, whatever position the image was read at.
///
/// # Errors
///
/// [`locate`]'s fault; the holders' reads' errors.
pub(in crate::merge) fn values_of(
    reader: &Reader<'_>,
    doc: &Address,
    maps: &[Imaged],
    runs: &[(Option<usize>, &Run)],
) -> Result<Vec<Vec<Item>>, Refusal> {
    let located: Vec<Vec<Stretch<'_>>> =
        runs.iter().map(|(prefer, run)| locate(maps, *prefer, run)).collect::<Result<_, _>>()?;
    // Each holder's stretches, as (the run's place, the stretch's place).
    let mut holders: BTreeMap<usize, Vec<(usize, usize)>> = BTreeMap::new();
    for (k, stretches) in located.iter().enumerate() {
        for (j, s) in stretches.iter().enumerate() {
            holders.entry(s.image).or_default().push((k, j));
        }
    }
    let mut values: Vec<Vec<Vec<Item>>> =
        located.iter().map(|stretches| vec![Vec::new(); stretches.len()]).collect();
    for (image, held) in &holders {
        let holder = &maps[*image].doc;
        let read = if in_chain(doc, holder) {
            let spans: Vec<(u64, u64)> =
                held.iter().map(|&(k, j)| (located[k][j].ordinal, located[k][j].width)).collect();
            reader.values_by_ordinal(holder, &spans)?
        } else {
            let spans: Vec<(&str, u64, u64)> = held
                .iter()
                .map(|&(k, j)| (located[k][j].prefix, located[k][j].first, located[k][j].width))
                .collect();
            reader.values_by_identity(holder, &spans)?
        };
        for (&(k, j), items) in held.iter().zip(read) {
            values[k][j] = items;
        }
    }
    Ok(values.into_iter().map(|stretches| stretches.concat()).collect())
}

// ── the shape's reads ─────────────────────────────────────────────────────

/// Which act a shape's reads serve, and so how they are made.
///
/// Where each read is made is the `reads` module's doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::merge) enum Reading {
    /// A composition's: at the head, each side that can change fenced.
    ///
    /// Where its draft side names a position, every side that can change is
    /// read as of it instead, and every member that cannot at the head.
    Composing,
    /// A verification's: every image and metadata read as of one position.
    ///
    /// It is the record's draft side's, else the position its first read
    /// answered.
    Verifying,
}

/// Where a shape's reads are made, once its first read has answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Positions {
    /// At the head, each side that can change fenced.
    Live,
    /// Each side that can change as of the position, the members that
    /// cannot at the head.
    Named(u64),
    /// Every image and metadata as of the position.
    Recorded(u64),
}

impl Positions {
    /// Returns where a side that can change is read.
    ///
    /// It is the head, a trunk member, a draft or a fork, and the trunk's
    /// own arrangement read beside them.
    fn changing(self) -> Option<u64> {
        match self {
            Positions::Live => None,
            Positions::Named(at) | Positions::Recorded(at) => Some(at),
        }
    }

    /// Returns where a member that cannot change is read.
    ///
    /// It is a hop below the trunk, a daughter, or a base below the head.
    fn fixed(self) -> Option<u64> {
        match self {
            Positions::Live | Positions::Named(_) => None,
            Positions::Recorded(at) => Some(at),
        }
    }
}

/// What a fence reads of a side that can change.
///
/// It is the position the side's text last changed at, and where the board
/// records it standing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Standing {
    /// Its `arranged_at`.
    arranged_at: Option<u64>,
    /// Its recorded base.
    base: Option<String>,
    /// Its source.
    source: Option<String>,
}

impl Standing {
    /// Returns what a fence's `doc_metadata` answer `meta` says.
    fn of(meta: &Metadata) -> Standing {
        Standing {
            arranged_at: meta.arranged_at.position(),
            base: meta.base.clone(),
            source: meta.source.clone(),
        }
    }
}

/// A side that can change, as its opening fence read it.
struct Fence {
    /// The side's address.
    doc: Address,
    /// What the fence read of it.
    standing: Standing,
    /// The answer's `as_of`.
    as_of: u64,
}

/// Reads `doc`'s `doc_metadata` at the head as a fence.
///
/// It answers the metadata and its `as_of` (the `reads` module's doc, the
/// fences). The answer carries an `arranged_at`, a position or `null`: the
/// fence holds a document unchanged by it.
///
/// # Errors
///
/// [`Reader::metadata_read`]'s; an answer naming no `as_of`, and one that
/// carries no `arranged_at` — an older board, whose answer cannot tell a side
/// unchanged — faced, nothing written.
pub(in crate::merge) fn fence(reader: &Reader<'_>, doc: &Address) -> Result<(Metadata, u64), Refusal> {
    let (meta, as_of) = reader.metadata_read(doc, None)?;
    let Some(as_of) = as_of else { return Err(no_as_of(doc).into()) };
    if meta.arranged_at == ArrangedAt::Unserved {
        return Err(Halt::face(
            format!("the board serves no `arranged_at` for {doc}"),
            "a merge reads each side that can change at the head and holds it to one state by the position its text last changed at, `doc_metadata`'s `arranged_at`, read before its image and again after it (wire.md §The response envelope), and this board's answer carries no such member — an older board",
            "this board cannot hold the merge to one state, so nothing was merged and nothing was written",
        )
        .into());
    }
    Ok((meta, as_of))
}

/// Faces a read of `doc` whose answer named no position.
fn no_as_of(doc: &Address) -> Halt {
    Halt::face(
        "`doc_metadata` answered no `as_of`",
        format!("the read of {doc} named no position (wire.md §The response envelope: every response names where it sits)"),
        "this board is not speaking the wire this client expects; nothing was written",
    )
}

/// Everything the reads of one shape yield.
///
/// `compose` and `verify` both build on it.
pub(in crate::merge) struct Readings {
    /// The position P the shape stands at (the `reads` module's doc).
    ///
    /// For a composition at the head, it is the highest `as_of` its opening
    /// fences answered; else the draft side's named position, or a
    /// verification's first read's `as_of`.
    pub(in crate::merge) at: u64,
    /// The base: a member, or the document itself where a side was begun
    /// before its first version — derived from the sides' lines of recorded
    /// bases, a named one checked against it (the `reads` module's doc).
    pub(in crate::merge) base: Address,
    /// The base's image: the document's own arrangement where the base is
    /// the document itself, the head's own image where the base is the head.
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
    /// read from — at a composition at the head, its opening fence — `None`
    /// where the board keeps none; a member's is `None`, its address its
    /// state.
    pub(in crate::merge) arranged: Vec<Option<u64>>,
}

/// Makes the reads of §1.3 in order, then the core's walk.
///
/// The reads are the document's metadata; for each side in order, a fork's
/// or a draft's own metadata for its anchor and its state — a fork's anchor
/// the base the board records for it, else the source it was born sharing
/// ([`fork_anchor`]); a draft's the base the board records for it
/// ([`draft_base`]); each one's state its `arranged_at`, carried in side
/// order beside the readings (`Readings::arranged`) — then the metadata of
/// each hop of its line of recorded bases below the trunk
/// ([`recorded_line`]); the head's extent; the head imaged; the base imaged
/// — the head's own image where the base is the head, the document's own
/// arrangement where the base is the document, read only where its
/// `own_count` is above 0; each side imaged; the composition with the
/// values read through the sides, the dedup's together
/// ([`compose_with_values`]).
///
/// Where they are made is `reading`'s (the `reads` module's doc). A
/// composition whose sides name no position reads at the head and FENCES
/// each side that can change — the head, a side that is a trunk member, the
/// draft, a fork — with its `doc_metadata` read before any image and again
/// after the images and the values: a fork's and a draft's opening fence is
/// the read its anchor and its state come off, a member's and the head's
/// follow the sides', and P is the highest `as_of` they answered. Each side
/// fenced must answer its closing fence as it answered its opening one — its
/// `arranged_at`, its recorded base and its source — so it held, at P, the
/// state its image was read in. A composition whose draft side names a
/// position reads the trunk, every side that can change and its anchor as of
/// it, every member that cannot change — a hop, a daughter, a base below the
/// head — at the head, and fences nothing: P is the position named. A
/// verification reads every metadata and image as of P, the record's draft
/// side's position, else the `as_of` of the trunk's metadata, read at the
/// head. Every value is read at the head.
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
/// - the trunk's metadata read's refusals — as of a position,
///   [`Reader::read`]'s faults of a position included — and an answer
///   naming no `as_of`, faced;
/// - the first side, in side order, that is a draft of an account other
///   than the trunk owner's, [`Refusal::BaseUnknown`], or a fork of the
///   trunk owner's own account, [`Refusal::ForkOfOwner`] — every side
///   judged so before any side's own read;
/// - for each side in order: at a fork or a draft its metadata read's
///   refusals — as of a position, [`Reader::read`]'s faults of a position
///   included, [`Refusal::HistoryReclaimed`] among them; at the head, a
///   fence's faults — the side unreadable, [`Refusal::Unreadable`]; a fork
///   the board records neither a base nor a source for or a draft it
///   records no base for, or one whose anchor — a fork's recorded base,
///   else its source; a draft's recorded base — lies in another document,
///   [`Refusal::BaseUnknown`]; at a trunk member read at the head its
///   fence's refusals; then its line's — each hop's metadata read's
///   refusals, a hop the board records no parent for,
///   [`Refusal::HopUnrecorded`], a parent that contradicts the hop's
///   address, faced;
/// - at the head, the head's fence's refusals — a fence answer naming no
///   `as_of`, or carrying no `arranged_at`, faced as a board this client
///   cannot hold to one state;
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
///   reads its values — and an `image` run that is no content I-address;
/// - at the head, a side whose closing fence answers otherwise than its
///   opening one, [`Refusal::SideMoved`] naming it, the first in fence
///   order, and the closing fences' own refusals.
///
/// [`compose`]: super::compose
pub(in crate::merge) fn read_shape(
    reader: &Reader<'_>,
    reading: Reading,
    doc: &Address,
    head: &Address,
    base: Option<Address>,
    sides: &[Side],
    options: &Options,
) -> Result<Readings, Refusal> {
    let last = check_shape(doc, head, sides)?;
    // Step 1: the document, at the position a draft side names, else at
    // the head (skep #762).
    let named = sides.iter().find_map(Side::position);
    let (meta, meta_as_of) = reader.metadata_read(doc, named)?;
    let positions = match (reading, named) {
        (Reading::Composing, None) => {
            meta_as_of.ok_or_else(|| no_as_of(doc))?;
            Positions::Live
        }
        (Reading::Composing, Some(at)) => Positions::Named(at),
        (Reading::Verifying, _) => {
            Positions::Recorded(named.or(meta_as_of).ok_or_else(|| no_as_of(doc))?)
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
    // to the trunk. A fork's and a draft's state comes off the one
    // `doc_metadata` its anchor is read from: at the head, its opening
    // fence. A side that is a trunk member can take a deposit, so at the
    // head it is fenced too.
    let live = positions == Positions::Live;
    let mut fences: Vec<Fence> = Vec::new();
    let mut opened = |reader: &Reader<'_>, side: &Address| -> Result<Metadata, Refusal> {
        if !live {
            return reader.metadata(side, positions.changing());
        }
        let (meta, as_of) = fence(reader, side)?;
        fences.push(Fence { doc: side.clone(), standing: Standing::of(&meta), as_of });
        Ok(meta)
    };
    let mut ends: Vec<LineEnd> = Vec::with_capacity(sides.len());
    let mut arranged: Vec<Option<u64>> = Vec::with_capacity(sides.len());
    for side in sides {
        let (anchor, state) = match side {
            Side::Fork(fork) => {
                let meta = opened(reader, fork)?;
                (fork_anchor(doc, side, &meta)?, meta.arranged_at.position())
            }
            Side::Draft { at: draft, .. } => {
                let meta = opened(reader, draft)?;
                (draft_base(doc, side, &meta)?, meta.arranged_at.position())
            }
            Side::Member(m) => {
                if live && is_trunk_member(doc, m) {
                    opened(reader, m)?;
                }
                (m.clone(), None)
            }
        };
        ends.push(recorded_line(reader, doc, side, &anchor, positions.fixed())?);
        arranged.push(state);
    }
    // The head's fence, the last of them: P is where they stand.
    if live {
        opened(reader, head)?;
    }
    let at = match positions {
        Positions::Live => fences.iter().map(|f| f.as_of).max().unwrap_or_default(),
        Positions::Named(at) | Positions::Recorded(at) => at,
    };
    let (head_extent, head_as_of) = reader.span_set(head, positions.changing())?;
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
    // The document's own arrangement from before its first version is
    // counted by the trunk's `own_count`, read with the trunk.
    let own_count = match &derived {
        Derived::Member(_) => None,
        Derived::Document { side, hop } => match meta.own_count {
            Some(count) => Some(count),
            None => {
                return Err(Refusal::BareSource {
                    side: (*side).clone(),
                    source: doc.clone(),
                    hop: hop.cloned(),
                })
            }
        },
    };
    // Step 3: the head, the base, then each side.
    let (head_runs, head_imaged_as_of) =
        reader.image_read(head, positions.changing(), 1, head_extent, false)?;
    let head_image = Imaged {
        doc: head.clone(),
        own: false,
        at: positions.changing(),
        extent: head_extent,
        runs: head_runs,
        as_of: head_as_of.max(head_imaged_as_of),
    };
    // The base's image: the head's own where the base is the head; at the
    // document itself its own arrangement, read only where its count is
    // above 0.
    let base_image = match (derived, own_count) {
        (Derived::Member(member), _) if member == *head => head_image.clone(),
        (Derived::Member(member), _) => reader.imaged(&member, positions.fixed())?,
        (Derived::Document { .. }, count) => {
            reader.imaged_own(doc, positions.changing(), count.unwrap_or_default())?
        }
    };
    let base = served;
    let mut maps = vec![head_image];
    for side in sides {
        let read_at = match side {
            Side::Member(m) if !is_trunk_member(doc, m) => positions.fixed(),
            Side::Member(_) | Side::Draft { .. } | Side::Fork(_) => positions.changing(),
        };
        maps.push(reader.imaged(side.address(), read_at)?);
    }
    // Steps 4 and 5: the join and the walk, the values through the sides.
    let base_runs = runs_of(&base_image.runs)?;
    let mut side_runs = Vec::with_capacity(maps.len());
    for (ix, m) in (0..=last).zip(&maps) {
        side_runs.push((SideIx(ix), runs_of(&m.runs)?));
    }
    let composed = compose_with_values(reader, doc, &maps, &base_runs, &side_runs, options)?;
    // The closing fences: each side that can change, read again after its
    // image and its values, must stand as it stood before them.
    for fenced in &fences {
        let standing = Standing::of(&fence(reader, &fenced.doc)?.0);
        if standing != fenced.standing {
            return Err(Refusal::SideMoved {
                side: fenced.doc.clone(),
                at,
                before: fenced.standing.arranged_at,
                after: standing.arranged_at,
            });
        }
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

/// Composes `base` and `sides` through the core, the values the value rule
/// compares read at the head through the sides that hold them ([`values_of`]).
///
/// With the retype off, the dedup alone reads values, and which runs it
/// reads is the walk's and never the values': the gaps it compares and their
/// groups are the same whatever bytes they hold, and so is every walk the
/// core makes again under a chosen order. So the walk is made once answering
/// every run with no items, noting the runs it asks; those runs are read
/// together, each holder's in as few reads as the budgets allow, and the
/// walk is made again answering from them — two reads for a merge of two
/// sides whatever its shared spots, where a read a run would make one a run.
/// A walk that asks no run is the composition. With the retype on, which
/// runs the walk reads depends on the values read before them, so each run
/// is read as the walk asks it, as it is where the reads together are
/// refused.
///
/// # Errors
///
/// The value reads' first refusal in the order the walk asks them: the
/// reads together refused, the runs are read again one at a time, so the
/// refusal is that run's.
fn compose_with_values(
    reader: &Reader<'_>,
    doc: &Address,
    maps: &[Imaged],
    base: &[Run],
    sides: &[(SideIx, Vec<Run>)],
    options: &Options,
) -> Result<Composed, Refusal> {
    let fault: RefCell<Option<Refusal>> = RefCell::new(None);
    let one_at_a_time = |side: SideIx, run: &Run| -> Option<Vec<Item>> {
        match values_for(reader, doc, maps, Some(side.0 as usize), run) {
            Ok(items) => Some(items),
            Err(e) => {
                fault.borrow_mut().get_or_insert(e);
                None
            }
        }
    };
    let composed = if options.dedup && !options.retype {
        let asked: RefCell<Vec<(SideIx, Run)>> = RefCell::new(Vec::new());
        let noting = |side: SideIx, run: &Run| -> Option<Vec<Item>> {
            asked.borrow_mut().push((side, run.clone()));
            Some(Vec::new())
        };
        let first = compose_runs(base, doc, sides, None, options, &noting);
        let mut asked = asked.into_inner();
        let mut seen = HashSet::new();
        asked.retain(|key| seen.insert(key.clone()));
        if asked.is_empty() {
            first
        } else {
            let pairs: Vec<(Option<usize>, &Run)> = asked
                .iter()
                .map(|(side, run)| (Some(side.0 as usize), run))
                .collect();
            match values_of(reader, doc, maps, &pairs) {
                Ok(read) => {
                    let held: HashMap<(SideIx, Run), Vec<Item>> =
                        asked.into_iter().zip(read).collect();
                    let answered = |side: SideIx, run: &Run| match held.get(&(side, run.clone())) {
                        Some(items) => Some(items.clone()),
                        None => one_at_a_time(side, run),
                    };
                    compose_runs(base, doc, sides, None, options, &answered)
                }
                Err(_) => compose_runs(base, doc, sides, None, options, &one_at_a_time),
            }
        }
    } else {
        compose_runs(base, doc, sides, None, options, &one_at_a_time)
    };
    match fault.into_inner() {
        Some(e) => Err(e),
        None => Ok(composed),
    }
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

/// Returns where the board records a fork side standing: the fork's anchor.
///
/// It is read off the fork's `doc_metadata`, `meta`: the fork's `base`
/// where the board records one — a document another
/// account's `stage` minted: the member or the bare document it was staged
/// from, or the base it inherited as an alternative, moved to the head by
/// each landing into it (wire.md §Namespace, `stage`) — else its `source`,
/// the member or the bare document a `version` minted it sharing (the
/// fork-source design record, arm A). A recorded base is where the draft now
/// stands, so it is never passed over for the source (the owner's ruling of
/// 2026-11-19; skep #1106). Both are read off the one `doc_metadata` — at a
/// composition at the head, the fork's opening fence — and the one taken is
/// the anchor where it is `doc` itself or a member of its chain (the merge
/// record's case (j)): the two checks in order — present, of this
/// document's chain. An anchor that is `doc` itself is a fork taken before
/// its first version, whose line ends there at once ([`recorded_line`]).
/// Beside it is the fork's state, the same answer's `arranged_at`, which the
/// record keeps for the fork side ([`SideAt::Fork`]).
///
/// # Errors
///
/// A fork the board records neither a base nor a source for — one `fork` or
/// `create_new_document` minted — or one whose recorded base, else source,
/// lies in another document — a staged fork published as an edition of its
/// own among them, its base moved to that edition's member —
/// [`Refusal::BaseUnknown`].
///
/// [`SideAt::Fork`]: super::record::SideAt::Fork
fn fork_anchor(doc: &Address, side: &Side, meta: &Metadata) -> Result<Address, Refusal> {
    match meta.base.as_deref().or(meta.source.as_deref()).and_then(parse_address) {
        Some(anchor) if in_chain(doc, &anchor) => Ok(anchor),
        _ => Err(Refusal::BaseUnknown(side.clone())),
    }
}

/// Returns the base the board records for a draft side: the draft's anchor.
///
/// It is read off the draft's `doc_metadata`, `meta`: the draft's `base`
/// (wire.md §Namespace, `stage`; §The response
/// envelope): the member or the bare document the draft was staged from,
/// moved to the member each publication of the draft itself minted and never
/// by a merge's shot that names the draft, which keeps it (`keep_base`; skep
/// #944) — read as [`fork_anchor`] reads a fork's, never the caller's to
/// know — and it is the draft's anchor where it is `doc` itself or a member
/// of its chain: the two checks in order — recorded, of this document's
/// chain. It is read where the draft's image is (wire.md §Reading history):
/// at a composition at the head, the draft's opening fence, which its
/// closing fence holds the draft to; as of a position, the base that stood
/// there, which a publication of the draft may have moved since, so a
/// record's side composes against the base its merge composed against. The
/// merge's base is then derived up the bases recorded from it
/// ([`recorded_line`]), so a draft staged from a daughter `D.k.m` merges with
/// the head over `D.k`, the base that daughter was published against, and
/// one staged from `D` itself, or whose publication landed as version 1's
/// daughter, over `D`'s own arrangement. Beside it is the draft's state, the
/// same answer's `arranged_at` ([`SideAt::Draft`]).
///
/// # Errors
///
/// A draft the board records no base for — never staged, or minted by
/// `fork` or `create_new_document` — or one whose recorded base lies in
/// another document, [`Refusal::BaseUnknown`].
///
/// [`SideAt::Draft`]: super::record::SideAt::Draft
fn draft_base(doc: &Address, side: &Side, meta: &Metadata) -> Result<Address, Refusal> {
    match meta.base.as_deref().and_then(parse_address) {
        Some(base) if in_chain(doc, &base) => Ok(base),
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
/// read at the head, or as of `at` where a verification reads, its recorded
/// parent the hop's `doc_metadata` `shot_base` — the base its shot was made
/// against (wire.md §The response envelope, the shot terms) — else its
/// `source`, the member an owned `version` snapshotted into it: a hop is a
/// published member, whose recorded parent never changes. The line ends at
/// `doc` itself, or at a trunk member with nothing read: a trunk member
/// `D.k+1` was minted against `D.k`, a shot naming the head landing on the
/// trunk and one naming another base landing as that base's daughter
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
    at: Option<u64>,
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
        let meta = reader.metadata(&hop, at)?;
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
