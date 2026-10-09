//! THE `publish` BODY — the cell [`entry_body_publish`] spells, and
//! [`PublishBody`] builds piece by piece under a byte budget — in a module of
//! its own for one reason: the builder's fields are private HERE. No code
//! outside this file can construct a [`PublishBody`] but through
//! [`PublishBody::within`], or grow one but through [`PublishBody::push`] and
//! [`PublishBody::window`], so the standing invariant its card states — never
//! past its budget, never short of a piece it was offered — rests on the code
//! in this file alone, not on every function the frame's grammar holds. The
//! rows it writes through — the value-sequence row, the address-list row and
//! the window row — are the parent's, stated there with the frame's other
//! rows.
//!
//! The body — the design record §2.5's `publish` cell as ruled — is three
//! parts, in order:
//!
//! * `be64(placed)` — the positions the client placed, Σ width of its runs,
//!   and so how many of the MINTED MEMBER's positions (the version the shot
//!   mints) the segments below spell;
//! * then those positions as SEGMENTS, in V-order — THE RUNS THE CLIENT
//!   PLACED IN THE ADDRESS FORM, the SHOT's address form (l6-A4), classed by
//!   value and by address at the minted member (fam2-Q's arm A) as
//!   [`ShotSegmentPiece`]'s card states — each opening with ONE CLASS BYTE:
//!   `0x02` a VALUE STRETCH, the maximal run of consecutive positions the
//!   commit COPIES IN, as one value-sequence row; `0x01` a WINDOW, one run
//!   onto ANOTHER document's I-space, which the commit keeps as a reference,
//!   as one window row. The segments are the runs AS THE MINTED MEMBER'S
//!   ARRANGEMENT HOLDS THEM, maximally merged (M5's run-list merges
//!   I-adjacent runs of one origin), so two I-adjacent windows are one
//!   segment and a stretch never meets a stretch;
//! * then the BASE GROUP, one length-delimited group: EMPTY (`be32(0)`) where
//!   the shot has no base — the birth bit — else the base MEMBER's address as
//!   an address-list row of one element (the optional-address row's own
//!   spelling of a present address, so the body takes no new form) followed
//!   by `be64(base_extent)` — [`push_base`] over a [`ShotBase`].
//!
//! THE BASE IS SIGNED, its member and its extent both (V, fam1-Q part (1),
//! with bu7-E2 ARM (a), owner 2026-10-01; the member re-pinned in place under
//! `skep-entry-v1` by l6-A3, as the frame's other re-pins are). The signer
//! and the daemon read the two off the request's own `base` and
//! `base_extent`. A verifier holding the MINTED MEMBER and no request
//! composes the same bytes: it DERIVES the base member from the minted
//! member's address — a trunk member `D.k+1` was minted against `D.k`, a
//! daughter `X.m` against `X`, a birth version against the memberless
//! document, or against nothing where the group is EMPTY — reads `placed`
//! and `base_extent` where D25's (c′) journals them, in M5's placing record,
//! and reads the minted member's first `placed` positions, spelling a stretch
//! from the values there and a window from the run the member holds. So the
//! derivation feeds the preimage: it answers how a verifier finds the
//! member, never whether the signature covers it. A re-submission of a
//! signed shot naming ANOTHER base — the trunk's current head, say — spells
//! another group and verifies under no key, while a replayed shot naming the
//! base it signed verifies as it did and names a base its own commit left no
//! longer the head, so the store's rule mints that base's daughter, never
//! the trunk's next. The address is the client's own, so the frame stays
//! POSITION-FREE.
//!
//! Every segment is self-delimiting behind its class byte and carries at
//! least one position — a stretch its count of values, a window its width —
//! so the segments end exactly where the positions they carry reach the
//! leading `be64(placed)`, and the base group is what follows them: the body
//! is uniquely decodable from its front, whatever the group's own bytes. The
//! group needs no marker of its own; its first byte is its `be32` length's
//! high byte, a zero — which no class byte is — only while the group is
//! shorter than 16 MiB, and the count, not that byte, ends the segments.

use core::fmt;
use core::num::NonZeroU64;

use skep_address::Address;

use super::{address_bytes, push_address_list, push_window, EntryBody, Grammar, ValueSequence};
use crate::framing::{delimited_len, push_delimited};

/// The `publish` body's segment CLASS bytes: a WINDOW, a run held BY
/// ADDRESS, and a VALUE STRETCH, positions held BY VALUE. The slot row's
/// form byte is neither, and the two rows never meet in one body.
const SEGMENT_WINDOW: u8 = 0x01;
const SEGMENT_VALUE_STRETCH: u8 = 0x02;

/// One piece the `publish` body's SEGMENTS are built from — a piece of the
/// shot's ADDRESS FORM (l6-A4), taken in V-order: one position the commit
/// copies in, by its value, or one window onto another document's I-space, by
/// its address. The pieces are not the segments: consecutive values make ONE
/// value stretch, and each window makes a segment of its own. `Copy`, as the
/// slices it borrows are: a view of the caller's piece, never an owner of it.
///
/// The classing is the minted member's: a run whose origin is that member's
/// own trunk — the shot document's own I-space placed by reference, or the
/// staging draft's text re-inserted as fresh identity under that trunk — is
/// read out as [`ShotSegmentPiece::Value`]s, one per position; a run whose
/// origin is any other document is one [`ShotSegmentPiece::Window`]. Which of
/// a shot's runs is which, and where two I-adjacent windows become one, is
/// M5's to say (`skep-arrangement`'s `Shot::address_form`); this crate spells
/// what it is handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShotSegmentPiece<'a> {
    /// One position the commit COPIES IN — its value, read at the minted
    /// member.
    Value(&'a [u8]),
    /// A WINDOW — one run onto another document's I-space, kept by the
    /// commit as a reference: its I-start and its width, as the minted
    /// member's arrangement holds the run, clipped to the client's placed
    /// positions.
    Window {
        /// The run's first I-address.
        start: &'a Address,
        /// The run's width — at least one position, as every run's is, which
        /// its type, `NonZeroU64`, holds.
        width: NonZeroU64,
    },
}

/// THE SHOT'S BASE as the `publish` body spells it (V; bu7-E2): the MEMBER
/// the staged draft was copied from — the trunk head for the ordinary shot, a
/// pinned member for the daughter shot, the memberless document itself for a
/// shot into a document between its mint and its birth version — and the
/// EXTENT of it the copy took. The request's own `base` and `base_extent`,
/// which M5's `Shot::base` carries as `Base { member, extent }`; a verifier
/// holding the minted member derives the member from that member's address
/// and reads the extent off `doc_metadata`. `Copy`, as the address it borrows
/// is: a view of the caller's base, never an owner of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShotBase<'a> {
    /// The member (or memberless document) the draft was copied from.
    pub member: &'a Address,
    /// The content positions of `member` the copy took.
    pub extent: u64,
}

/// THE BASE GROUP, onto `out`: ONE length-delimited group — EMPTY (`be32(0)`)
/// where the shot has no base, the birth bit — else the base member's address
/// as an address-list row of one element (the optional-address row's own
/// spelling of a present address: the form byte, `be64(1)`, the address
/// delimited) followed by `be64(base_extent)`. So an absent group is four
/// bytes and a present one `4 + 1 + 8 + 4 + len(address) + 8`. It needs no
/// marker of its own: the segments before it end where the positions they
/// carry reach the body's leading `be64(placed)` (the module doc), and the
/// group is what follows them.
fn push_base(out: &mut Vec<u8>, base: Option<ShotBase<'_>>) {
    let mut group = Vec::new();
    if let Some(ShotBase { member, extent }) = base {
        push_address_list(&mut group, [member]);
        group.extend_from_slice(&extent.to_be_bytes());
    }
    push_delimited(out, &group);
}

/// THE `publish` BODY, under the `publish` token: `be64(placed)`, then the
/// body's segments built from `pieces` in the order given — each run of
/// consecutive values ONE value stretch, its class byte and one value-sequence
/// row; each window its class byte and one window row — then the base group
/// over `base`, the shot's [`ShotBase`] or `None` in the birth shape. It is
/// [`PublishBody`] under a budget no body reaches: over pieces a budget
/// admits, the two build one body.
///
/// PRECONDITIONS — every value and every window's start spelling is shorter
/// than 2^32 bytes, as [`entry_body_insert`](super::entry_body_insert)'s
/// values are, and so is the base group ([`PublishBody::within`]'s
/// PRECONDITION); and the positions the pieces cover sum below 2^64 — the
/// count's width. A caller breaking one PANICS, naming the obligation.
pub fn entry_body_publish<'a>(
    pieces: impl IntoIterator<Item = ShotSegmentPiece<'a>>,
    base: Option<ShotBase<'_>>,
) -> EntryBody {
    PublishBody::within(usize::MAX, base)
        .and_then(|empty| {
            pieces.into_iter().try_fold(empty, |body, piece| match piece {
                ShotSegmentPiece::Value(value) => body.push(value),
                ShotSegmentPiece::Window { start, width } => body.window(start, width),
            })
        })
        .expect(
            "a budget of usize::MAX refuses neither the body of no segments nor a piece past it \
             — a saturated length never passes it — so the refusal named here is a caller's \
             broken precondition",
        )
        .finish()
}

/// A `publish` BODY built one piece at a time under a byte BUDGET — for the
/// verifier that re-composes a shot's body off its own store, where each
/// value arrives by a read that can fail and a body past the budget must be
/// REFUSED rather than built. [`PublishBody::within`], [`PublishBody::push`]
/// and [`PublishBody::window`] measure the budget in the body's own layout
/// and NAME what they refuse ([`PublishRefusal`]), so no caller restates that
/// layout, or the count's arithmetic, to learn which refusal it met; the
/// caller keeps its walk, its own answer for a value it could not read and
/// for each refusal, and collects nothing ahead of the build.
///
/// Its standing INVARIANT is the one the budget exists for: the body built so
/// far, its leading count and the base group [`PublishBody::finish`]
/// appends included, never passes `budget` bytes — [`PublishBody::within`],
/// the type's one constructor, establishes it, refusing a budget the body of
/// no segments already passes, and each of its two growth sites,
/// [`PublishBody::push`] and [`PublishBody::window`], keeps it or refuses, so
/// `finish` never answers a body past its budget.
///
/// A refusal CONSUMES the builder, at a push and at a window alike, and the
/// type is not `Clone` — the compile-time check beside it holds that — so the
/// only body that can be finished is one that took EVERY piece it was
/// offered, in order. A body that skipped a piece, or stopped short of one,
/// would be the preimage of a different, shorter publish: every other member
/// of the frame is fixed for one principal's publishes into one trunk under
/// one key, so a signature made for that publish would verify over it.
/// [`entry_body_publish`] is this builder under a budget no body reaches, so
/// over pieces the budget admits the two build one body.
///
/// Consecutive values join ONE stretch — the row opened by the first of them
/// and closed by the next window or by `finish` — so a stretch is always
/// maximal, whatever run boundaries the caller walked them in; windows are
/// taken as given, one segment each, and are the minted member's own maximal
/// runs by the caller's obligation ([`ShotSegmentPiece`]).
#[derive(Debug)]
pub struct PublishBody {
    bytes: Vec<u8>,
    /// The open value stretch — the segment the latest values joined, still
    /// taking values until a window or `finish` closes it.
    stretch: Option<ValueSequence>,
    /// The positions the pieces so far cover — the leading count, written
    /// back at `finish`.
    placed: u64,
    /// The base group `finish` appends, spelled at `within` so its bytes
    /// count against the budget from the start.
    base_group: Vec<u8>,
    budget: usize,
}

impl PublishBody {
    /// A body of no segments yet — the leading count's eight bytes, and the
    /// base group held for `finish` — whose [`PublishBody::push`] and
    /// [`PublishBody::window`] admit no piece that would carry the FINISHED
    /// body past `budget` bytes; else [`PublishRefusal::PastBudget`], where
    /// that body of no segments passes the budget already. `base` is the
    /// shot's ([`ShotBase`]): `None` in the birth shape, the EMPTY group.
    ///
    /// A budget the body of no segments passes is REFUSED, as a push or a
    /// window refuses a piece, because it is an input's doing as much as a
    /// caller's: the base group holds the base MEMBER's address (V; bu7-E2),
    /// which the shot's author names, at a length the author chooses, so
    /// whether a budget holds the body of no segments depends on the shot.
    /// Constructed past its own budget, the builder would finish to an
    /// over-budget body no push or window had refused — the one body the type
    /// exists to refuse rather than build.
    ///
    /// PRECONDITION — the base group is shorter than 2^32 bytes: the member's
    /// spelling and the twenty-one bytes the group puts around it (the
    /// address-list row's form byte, `be64` count and `be32` length, then
    /// `be64(extent)`) together. A longer group PANICS, naming the
    /// obligation, whatever the budget: it is spelled before it is measured.
    pub fn within(
        budget: usize,
        base: Option<ShotBase<'_>>,
    ) -> Result<PublishBody, PublishRefusal> {
        let bytes = 0u64.to_be_bytes().to_vec();
        let mut base_group = Vec::new();
        push_base(&mut base_group, base);
        if bytes.len() + base_group.len() > budget {
            return Err(PublishRefusal::PastBudget);
        }
        Ok(PublishBody { bytes, stretch: None, placed: 0, base_group, budget })
    }

    /// What the body would measure if finished now: the bytes down, and the
    /// group `finish` appends.
    fn finished_len(&self) -> usize {
        self.bytes.len() + self.base_group.len()
    }

    /// Append `value` as the body's next position — joining the open value
    /// stretch, or opening one after a window or at the body's start — and
    /// hand the builder back; else the cause ([`PublishRefusal`]) and the
    /// builder GONE: a body that refused a piece can be neither continued
    /// nor finished. [`PublishRefusal::Unspellable`] where the positions
    /// placed would pass 2^64 − 1, the count's width; else
    /// [`PublishRefusal::PastBudget`] where the finished body would pass its
    /// budget. No value is free — an empty one costs its length prefix, and
    /// the first of a stretch its class byte and count besides — so a budget
    /// admits at most a quarter as many values as it has bytes, whatever the
    /// values hold.
    ///
    /// PRECONDITION — as [`entry_body_publish`]'s: `value` is shorter than
    /// 2^32 bytes, else PANICS; under any budget below that bound, this
    /// refuses such a value first.
    #[must_use = "push takes the builder: the body goes on in the one it returns"]
    pub fn push(mut self, value: &[u8]) -> Result<PublishBody, PublishRefusal> {
        let placed = self.placed.checked_add(1).ok_or(PublishRefusal::Unspellable)?;
        let opening: usize = if self.stretch.is_some() { 0 } else { 1 + 8 };
        let cost = opening.saturating_add(delimited_len(value.len()));
        if self.finished_len().saturating_add(cost) > self.budget {
            return Err(PublishRefusal::PastBudget);
        }
        let mut stretch = match self.stretch.take() {
            Some(stretch) => stretch,
            None => {
                self.bytes.push(SEGMENT_VALUE_STRETCH);
                ValueSequence::open(&mut self.bytes)
            }
        };
        stretch.push(&mut self.bytes, value);
        self.stretch = Some(stretch);
        self.placed = placed;
        Ok(self)
    }

    /// Append a WINDOW — the run from `start` of `width` positions, held by
    /// address — closing any open value stretch first, and hand the builder
    /// back; else the cause and the builder GONE, as after a refused push:
    /// [`PublishRefusal::Unspellable`] where the positions placed would pass
    /// 2^64 − 1, then [`PublishRefusal::PastBudget`]. `width` is a
    /// [`NonZeroU64`] because a run holds at least one position: a window of
    /// none is no call this method can be given. A window costs its class
    /// byte, its start's delimited spelling and eight bytes of width, whatever
    /// its width.
    ///
    /// PRECONDITION — `start`'s spelling is shorter than 2^32 bytes, else
    /// PANICS; under any budget below that bound, this refuses such a start
    /// first.
    #[must_use = "window takes the builder: the body goes on in the one it returns"]
    pub fn window(
        mut self,
        start: &Address,
        width: NonZeroU64,
    ) -> Result<PublishBody, PublishRefusal> {
        let placed = self.placed.checked_add(width.get()).ok_or(PublishRefusal::Unspellable)?;
        let start = address_bytes(start);
        let cost = 1usize.saturating_add(delimited_len(start.len())).saturating_add(8);
        if self.finished_len().saturating_add(cost) > self.budget {
            return Err(PublishRefusal::PastBudget);
        }
        if let Some(stretch) = self.stretch.take() {
            stretch.close(&mut self.bytes);
        }
        self.bytes.push(SEGMENT_WINDOW);
        push_window(&mut self.bytes, &start, width.get());
        self.placed = placed;
        Ok(self)
    }

    /// The body, under the `publish` token: the count of positions the
    /// pieces this builder took cover, the segments built from them in the
    /// order pushed — the open stretch closed — then the base group; never
    /// past its budget, by the standing invariant.
    pub fn finish(self) -> EntryBody {
        let PublishBody { mut bytes, stretch, placed, base_group, .. } = self;
        if let Some(stretch) = stretch {
            stretch.close(&mut bytes);
        }
        bytes[..8].copy_from_slice(&placed.to_be_bytes());
        bytes.extend_from_slice(&base_group);
        EntryBody { grammar: Grammar::Publish, bytes }
    }
}

/// [`PublishBody`] is not `Clone`, and this block stops compiling the moment
/// it is: a copy taken before a push would outlive that push's refusal, and
/// finish to the shorter body the refusal exists to forbid. The `_` below is
/// inferred while the blanket impl is the only one that applies; a `Clone`
/// type meets the second as well, and the path is ambiguous.
const _: fn() = || {
    trait AmbiguousIfClone<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    #[allow(dead_code)]
    struct IsClone;
    impl<T: Clone> AmbiguousIfClone<IsClone> for T {}
    let _ = <PublishBody as AmbiguousIfClone<_>>::check;
};

/// Why [`PublishBody`] refused — at its construction
/// ([`PublishBody::within`]), the body of no segments already past the
/// budget, or at a piece, the builder GONE with it, as every refusal after
/// construction leaves it — NAMED, because a caller answers the two
/// differently: a body PAST ITS BUDGET is the one the builder exists to
/// refuse rather than build; a count past the body's leading `be64` names
/// positions no store holds. What each is answered is the caller's: a
/// refusal reaches no wire from here. A window of no positions is no cause
/// here: a window's width is a [`NonZeroU64`], so no such piece can be
/// offered.
///
/// The causes are tested in ONE order, the count first, then the budget — so
/// a piece the body could not spell at any budget is never answered as past
/// this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublishRefusal {
    /// The FINISHED body — its leading count and its base group included —
    /// would pass the builder's budget.
    PastBudget,
    /// The positions placed would pass 2^64 − 1, the most the body's leading
    /// `be64(placed)` spells.
    Unspellable,
}

/// Prose, never a wire vocabulary: each caller answers a refusal in its own
/// terms.
impl fmt::Display for PublishRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PublishRefusal::PastBudget => "the finished body would pass its budget",
            PublishRefusal::Unspellable => "the positions placed would pass 2^64 - 1",
        })
    }
}

impl std::error::Error for PublishRefusal {}
