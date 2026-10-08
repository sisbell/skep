//! THE STATE EVENT's TEN ARMS (`client.md` §4b.2's `index(board, session?,
//! state)`; §4e.5): the search index's own state, as a TYPED enum — every
//! arm carries what the design names for it (a position, a count of units,
//! a limit in bytes, a range, a version) and NEVER a UI string: the words
//! are the UX's, keyed off the arm. "THE STATE IS THE PAIR's" (§4e.5): a
//! session's state is composed from the published index's `stats()` and that
//! principal's supplement's, the guest form's from the published index's
//! alone, so `widening` reaches no face without that principal's session and
//! no supplement's count reaches the guest face (`search.md` §4 (iii)). The
//! composition is [`State::compose`] over one [`Part`] per index the face
//! searches, in the ORDER this module fixes — the design names the arms and
//! not their precedence, so the order below is the build's, stated once:
//!
//! 1. no part — the guest form over a board the shell holds no index for —
//!    is `None`;
//! 2. a part FACED as a newer skep's file is `NewerSkep`, the pair unusable;
//! 3. a part still BUILDING — the first build or a rebuild, the whole
//!    published board read from the floor — is `Building`;
//! 4. a part WIDENING — R90's fetch running over a range — is `Widening`;
//! 5. a part past the ceiling — `seen > 0` — is `PastTheCeiling`;
//! 6. a range whose bare-row count stands withholds `complete`: `Unplaced`;
//! 7. a part that met `history_reclaimed` at this open and kept its file is
//!    `ResumedFromTheFloor`;
//! 8. a part whose file states a floor is `AtTheFloor`;
//! 9. else `Complete`, `as_of` the lowest `held` over the pair's ranges.
//!
//! `Busy` is composed by no part: the consumer answers it where a second
//! process holds the feeder's lock (`search.md` §5.6, RULED refuse for v1).
//! Nothing in any arm names a file, a path or a principal's directory.

use skep_address::Address;
use skep_search::{ChainAt, Header, Revision, Stats};

/// A range of a feed, as the state names it: the board's whole feed — the
/// published index's one range — or the prefix a widening named as `under=`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Range {
    /// The board's whole feed.
    Board,
    /// An account's or a document's prefix.
    Under(Address),
}

impl Range {
    /// The range a header record's `under` names.
    pub fn of(under: Option<&Address>) -> Range {
        match under {
            None => Range::Board,
            Some(prefix) => Range::Under(prefix.clone()),
        }
    }
}

/// What a rebuild cannot restore (§4b.2's `building.lost`), keyed to the two
/// rebuilds that remain (`search.md` §5.4): a DAMAGED file, and a DIVERGED
/// history — "this board's history no longer extends the one this index was
/// built from at ⟨held⟩", the file moved aside with its pair as the
/// evidence. The documents below the floor and the revoked grants' holdings
/// are what either loses; the words are the UX's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lost {
    /// The file failed its own checks — `what` the check the crate named.
    Damaged {
        /// The check that refused the file.
        what: String,
    },
    /// The board's history no longer extends the one the index was built
    /// from at `held`: `beyond_head`, a different chain, or an `H.k` found
    /// different, gone or superseded (ITEM 1 (a)'s riders).
    Diverged {
        /// The saved pair the face names.
        held: ChainAt,
    },
}

/// Why the file is a newer skep's (§4b.2's `newer_skep {v}`; `search.md`
/// §5.1): its `v`, or its tokenizer revision — faced, searched not, never
/// overwritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Newer {
    /// The header's `v` is above the one this skep writes.
    Version {
        /// The version the header names.
        v: u64,
    },
    /// The index was cut under a tokenizer revision newer than this skep's.
    Tokenizer {
        /// The revision the header names.
        revision: Revision,
    },
}

/// THE TEN ARMS (`client.md` §4b.2), typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// No index for this board: the guest form over a board the one line
    /// does not name, or an UNCLAIMED board, which has no `H.1` and no
    /// directory (`search.md` §5.2).
    None,
    /// The first build or a rebuild, the whole published board read from the
    /// floor (§4e.2): the position reached and the units indexed so far;
    /// `lost` what the rebuild cannot restore, where this is a rebuild;
    /// `aside` where an index naming another board, or another principal's
    /// class, was set aside under its own name and this board's built fresh
    /// (`search.md` §5.4, ITEM 1b (c)).
    Building {
        /// The feed position the build has reached.
        position: u64,
        /// The units indexed so far.
        units: usize,
        /// What a rebuild cannot restore, where this is one.
        lost: Option<Lost>,
        /// Whether a misplaced file was set aside before this build.
        aside: bool,
    },
    /// R90's fetch running over a range — C-134's PINNED "local index built
    /// before sign-in — widening".
    Widening {
        /// The range being fetched.
        range: Range,
    },
    /// C-134's PINNED "complete as of this class": every range indexed
    /// through `as_of`; the floor stated where known.
    Complete {
        /// The lowest `held` position over the pair's ranges.
        as_of: u64,
        /// The board's reclaim floor, where an answer carried one.
        floor: Option<u64>,
    },
    /// The index BEGAN at a reclaim floor above the board's first entry — a
    /// rebuild, or a board older than its retention — so its completeness
    /// is the floor's: the residue line's input (foundations §2.1).
    AtTheFloor {
        /// The floor the index is complete from.
        floor: u64,
    },
    /// `at_the_floor`'s sibling (`search.md` §5.4, ITEM 1 RULED (a)): the
    /// index met `history_reclaimed` at open and its file was KEPT, each
    /// range resumed from `floor` — complete from there, a document written
    /// only between the old `held` and the floor searched as last read, or
    /// absent.
    ResumedFromTheFloor {
        /// The floor the ranges resumed from.
        floor: u64,
        /// The saved pair the ranges held before the resume.
        held: ChainAt,
    },
    /// A bare row's change could not be placed on `range` — testimony lost
    /// to a crash names no document — so `complete` is WITHHELD while the
    /// count stands; the act that exists is the refresh (`search.md` §5.4).
    Unplaced {
        /// The range the bare rows arrived on.
        range: Range,
        /// How many changes on it could not be placed.
        count: u64,
    },
    /// The crate's typed refusal past its stated limit (`search.md` §7.4):
    /// `held` and `seen` in UNITS, `limit` in BYTES; `seen` persisted in the
    /// file so the arm composes after a restart as before it.
    PastTheCeiling {
        /// The units the index holds.
        held: usize,
        /// The units offered past the ceiling and refused.
        seen: u64,
        /// The ceiling, in bytes of text.
        limit: u64,
    },
    /// The index file was written by a newer skep than this one, or at a
    /// newer tokenizer revision: faced, searched not, never overwritten
    /// (`search.md` §5.1; the key file's disposition, `client.md` §3.2).
    NewerSkep {
        /// Which of the two.
        v: Newer,
    },
    /// A second shell on the same data directory finding the feeder's lock
    /// held: its search is REFUSED, the state saying search is busy in
    /// another window (`search.md` §5.6, RULED refuse for v1) — and the
    /// resume's `history_busy` left pending past its retries, retried at the
    /// next poll.
    Busy,
}

/// One index of the pair a face searches, as the composition reads it:
/// faced as a newer skep's, or live with its facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part<'a> {
    /// The file is a newer skep's — faced and left.
    Faced(Newer),
    /// A live index.
    Index(Facts<'a>),
}

/// The facts of one live index the composition reads (`search.md` §1.4's
/// `stats`, the header's ranges, and the consumer's own flags).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts<'a> {
    /// The live counts, the ceiling and `seen`.
    pub stats: Stats,
    /// The header: the ranges with their `held` and bare-row counts, the
    /// floor.
    pub header: &'a Header,
    /// The position a build in progress has reached, where one runs.
    pub building: Option<u64>,
    /// The range a widening in progress fetches, where one runs.
    pub widening: Option<Range>,
    /// The floor the ranges resumed from at this open, and the pair they held
    /// before it, where the open met `history_reclaimed` and kept the file.
    pub resumed: Option<(u64, ChainAt)>,
    /// What this build cannot restore, where it is a rebuild.
    pub lost: Option<Lost>,
    /// Whether a misplaced file was set aside before this build.
    pub aside: bool,
}

impl State {
    /// THE COMPOSITION over the pair's parts, in the module doc's order: the
    /// guest form's one part, a session's two.
    pub fn compose(parts: &[Part<'_>]) -> State {
        if parts.is_empty() {
            return State::None;
        }
        let mut live = Vec::with_capacity(parts.len());
        for part in parts {
            match part {
                Part::Faced(newer) => return State::NewerSkep { v: newer.clone() },
                Part::Index(facts) => live.push(facts),
            }
        }
        if let Some(facts) = live.iter().find(|f| f.building.is_some()) {
            return State::Building {
                position: facts.building.unwrap_or(0),
                units: live.iter().map(|f| f.stats.units).sum(),
                lost: facts.lost.clone(),
                aside: facts.aside,
            };
        }
        if let Some(range) = live.iter().find_map(|f| f.widening.clone()) {
            return State::Widening { range };
        }
        if let Some(facts) = live.iter().find(|f| f.stats.seen > 0) {
            return State::PastTheCeiling {
                held: facts.stats.units,
                seen: facts.stats.seen,
                limit: facts.stats.ceiling,
            };
        }
        for facts in &live {
            if let Some(range) = facts.header.ranges.iter().find(|r| r.bare_rows > 0) {
                return State::Unplaced { range: Range::of(range.under.as_ref()), count: range.bare_rows };
            }
        }
        if let Some((floor, held)) = live.iter().find_map(|f| f.resumed) {
            return State::ResumedFromTheFloor { floor, held };
        }
        if let Some(floor) = live.iter().filter_map(|f| f.header.floor).find(|f| *f > 0) {
            return State::AtTheFloor { floor };
        }
        let as_of = live.iter().flat_map(|f| f.header.ranges.iter().map(|r| r.held.position)).min().unwrap_or(0);
        let floor = live.iter().find_map(|f| f.header.floor);
        State::Complete { as_of, floor }
    }
}
