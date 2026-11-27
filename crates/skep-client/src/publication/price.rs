//! THE PRICE (the link-sets design §5.6; wire.md §The publish shot and
//! head-float, the in-lock reads' budget): the request priced against every
//! cap BEFORE the act.
//!
//! Six terms, each a [`Term`] with how far it passes its cap. Two are the
//! request's own shape, judged here with no read, since a frame past
//! either does not parse and so cannot be priced: THE LISTS — `runs`,
//! `places`, `links`, `retract`, `read_with` and the `originals` rider,
//! each against the codec's wire-list cap, 4,096 — and THE BODY — the
//! signed body against the frame routes' request-body cap, 8 MiB. Four are
//! judged against THE BOARD's numbers, and the board is asked for them
//! (`publish_cost`, wire.md §Arrangement, answered as [`PublishCost`]):
//! THE VALUES — the distinct draft-native positions, counted here off the
//! request, against the board's `position_budget`; THE UNITS — the atoms
//! and whole runs of single bytes those positions would be staged as,
//! which only the stored values tell and so the board counts, against its
//! `unit_budget`, the two the store refuses a shot `too_many_values` past;
//! and THE IN-LOCK READS and THE STAGED BYTES, what the board prices the
//! request at by the function its own `publication_over_budget` refusal
//! reads, against the `read_budget` and `byte_budget` it answers beside
//! them. This library sums neither figure and keeps no copy of any of the
//! four budgets: a price costs one read of the board, and where the board
//! cannot be asked there is no price.
//!
//! The verdict is DATA — which term, by how much — and the caller refuses
//! the act on it with the caps' lines, which are the copy's; past a cap the
//! act that exists is a narrower request. Where a list or the body passes
//! its cap the board is not asked — such a frame does not parse — and the
//! price judges neither the values nor the units and carries no reads and
//! no bytes beside the terms passed.
//!
//! The board's price is read off a state no lock holds, so the board may
//! move between it and the send: a refusal the board answers after its own
//! price admitted the request is a race, and the send's budget arm says so.

use skep_address::Address;

use super::enumerate::MAX_WIRE_LIST;
use super::Run;
use crate::board::PublishCost;

/// The frame routes' request-body cap, 8 MiB, the parity the daemon holds a
/// signed body to.
pub const REQUEST_BODY_BYTES: usize = 8 * 1024 * 1024;

/// One term of the price.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Term {
    /// The `runs` list against the wire-list cap.
    Runs,
    /// The `places` list against the wire-list cap.
    Places,
    /// The `links` list against the wire-list cap.
    Links,
    /// The `retract` list against the wire-list cap.
    Retract,
    /// The `read_with` list against the wire-list cap.
    ReadWith,
    /// The `originals` rider against the wire-list cap.
    Originals,
    /// The signed body against the request-body cap.
    Body,
    /// The distinct draft-native positions against the board's positions
    /// budget.
    Values,
    /// The units the board counts the re-insert as against its units
    /// budget. The board stops counting at the first unit past the budget,
    /// so the amount past is one: a floor, never how many units the draft
    /// holds.
    Units,
    /// The in-lock reads against the board's reads budget.
    Reads,
    /// The staged bytes against the board's transaction budget.
    Bytes,
}

/// The request's own shape: what the price reads off the request alone.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Shape {
    /// Each list's length: `runs`, `places`, `links`, `retract`,
    /// `read_with`, `originals`.
    pub lists: [usize; 6],
    /// The signed body's bytes.
    pub body: usize,
    /// The distinct draft-native positions: counted here, and judged
    /// against the board's `position_budget` once the board has answered.
    pub values: u64,
}

impl Shape {
    /// Returns every term the shape passes with no read of the board — a
    /// list or the body past the cap a frame must be inside to parse — with
    /// how far past.
    ///
    /// The values are no term of it: the budget they are held to is the
    /// board's to state ([`Price::of`]).
    pub fn over(&self) -> Vec<(Term, u64)> {
        let mut over = Vec::new();
        for (term, n) in [Term::Runs, Term::Places, Term::Links, Term::Retract, Term::ReadWith, Term::Originals].into_iter().zip(self.lists) {
            if n > MAX_WIRE_LIST {
                over.push((term, (n - MAX_WIRE_LIST) as u64));
            }
        }
        if self.body > REQUEST_BODY_BYTES {
            over.push((Term::Body, (self.body - REQUEST_BODY_BYTES) as u64));
        }
        over
    }
}

/// The price.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Price {
    /// Each list's length: `runs`, `places`, `links`, `retract`, `read_with`,
    /// `originals`.
    pub lists: [usize; 6],
    /// The signed body's bytes.
    pub body: usize,
    /// The distinct draft-native positions.
    pub values: u64,
    /// The units the board counted the re-insert as; zero where the board
    /// was not asked.
    pub units: u64,
    /// The in-lock reads, as the board priced them; zero where the board
    /// was not asked.
    pub reads: usize,
    /// The staged bytes, as the board priced them; zero where the board was
    /// not asked.
    pub bytes: u64,
    /// Every term past its cap, with how far past.
    pub over: Vec<(Term, u64)>,
}

impl Price {
    /// Whether the request is within every cap.
    pub fn admits(&self) -> bool {
        self.over.is_empty()
    }

    /// Returns the price of a request of `shape` the board prices at `cost`.
    ///
    /// The lists and the body are judged against this library's two caps,
    /// and every other term against the budget the board answered for it,
    /// whatever number that is: the shape's distinct positions against
    /// `position_budget`, the board's units against `unit_budget`, its
    /// reads ([`PublishCost::reads`]) against `read_budget`, its staged
    /// bytes against `byte_budget`. `None` is a request the board was not
    /// asked about, a list or its body already past a cap: its values and
    /// its units are judged against nothing, there being no budget to hold
    /// them to.
    pub fn of(shape: &Shape, cost: Option<&PublishCost>) -> Price {
        let mut over = shape.over();
        let (mut units, mut reads, mut bytes) = (0u64, 0u64, 0u64);
        if let Some(cost) = cost {
            (units, reads, bytes) = (cost.units, cost.reads(), cost.staged_bytes);
            for (term, figure, budget) in [
                (Term::Values, shape.values, cost.position_budget),
                (Term::Units, units, cost.unit_budget),
                (Term::Reads, reads, cost.read_budget),
                (Term::Bytes, bytes, cost.byte_budget),
            ] {
                if figure > budget {
                    over.push((term, figure - budget));
                }
            }
        }
        Price { lists: shape.lists, body: shape.body, values: shape.values, units, reads: usize::try_from(reads).unwrap_or(usize::MAX), bytes, over }
    }
}

/// Returns the distinct positions the draft-native runs name — the store's
/// count of the positions a shot re-inserts, a position two runs name
/// counted once — over every named draft: the positions of two drafts are
/// distinct addresses, so each draft's are counted on its own chain and
/// summed. The board states the budget they are held to; how many units
/// they are staged as it counts itself, off the stored values.
pub fn distinct_draft_positions(runs: &[Run], drafts: &[Address]) -> u64 {
    let mut total = 0u64;
    for draft in drafts {
        let mut ranges: Vec<(u64, u64)> = runs.iter().filter(|r| r.origin == *draft).map(|r| (r.i_start, r.reach())).collect();
        ranges.sort_unstable();
        let mut cursor = 0u64;
        for (lo, hi) in ranges {
            let lo = lo.max(cursor);
            if hi > lo {
                total += hi - lo;
                cursor = hi;
            }
        }
    }
    total
}
