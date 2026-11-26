//! THE PRICE (the link-sets design §5.6; wire.md §The publish shot and
//! head-float, the in-lock reads' budget): the request priced against every
//! cap BEFORE the act.
//!
//! Five terms, each a [`Term`] with how far it passes its cap. Three are
//! the request's own shape, judged here with no read: THE LISTS — `runs`,
//! `places`, `links`, `retract`, `read_with` and the `originals` rider,
//! each against the codec's wire-list cap, 4,096; THE BODY — the signed
//! body against the frame routes' request-body cap, 8 MiB; THE VALUES — the
//! distinct draft-native positions against the shot's re-insert budget.
//! Two are THE BOARD's, and the board is asked for them: THE IN-LOCK READS
//! and THE STAGED BYTES are what the board prices the request at
//! (`publish_cost`, wire.md §Arrangement — the function its own
//! `publication_over_budget` refusal reads), answered with the two budgets
//! it holds them to ([`PublishCost`]). This library sums neither and keeps
//! no copy of either budget: a price costs one read of the board, and
//! where the board cannot be asked there is no price.
//!
//! The verdict is DATA — which term, by how much — and the caller refuses
//! the act on it with the caps' lines, which are the copy's; past a cap the
//! act that exists is a narrower request. Where a list, the body or the
//! values pass their cap the board is not asked — a frame past the list cap
//! or the body cap does not parse — and the price carries no reads and no
//! bytes beside the terms passed.
//!
//! The board's price is read off a state no lock holds, so the board may
//! move between it and the send: a refusal the board answers after its own
//! price admitted the request is a race, and the send's budget arm says so.

use skep_address::Address;

use super::enumerate::MAX_WIRE_LIST;
use super::Run;
use crate::board::PublishCost;

/// The shot's re-insert budget: M5's `MAX_REINSERTED_VALUES`, the distinct
/// draft-native positions.
pub const MAX_REINSERTED_VALUES: u64 = 1 << 17;

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
    /// The distinct draft-native positions against the re-insert budget.
    Values,
    /// The in-lock reads against the board's reads budget.
    Reads,
    /// The staged bytes against the board's transaction budget.
    Bytes,
}

/// The request's own shape, as the price judges it with no read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Shape {
    /// Each list's length: `runs`, `places`, `links`, `retract`,
    /// `read_with`, `originals`.
    pub lists: [usize; 6],
    /// The signed body's bytes.
    pub body: usize,
    /// The distinct draft-native positions.
    pub values: u64,
}

impl Shape {
    /// Returns every term of the shape past its cap, with how far past.
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
        if self.values > MAX_REINSERTED_VALUES {
            over.push((Term::Values, self.values - MAX_REINSERTED_VALUES));
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
    /// The shape's three terms are judged against this library's caps, and
    /// the board's two against the budgets the board answered with them:
    /// the reads ([`PublishCost::reads`]) against `read_budget`, the staged
    /// bytes against `byte_budget`. `None` is a request the board was not
    /// asked about, its shape already past a cap.
    pub fn of(shape: &Shape, cost: Option<&PublishCost>) -> Price {
        let mut over = shape.over();
        let (mut reads, mut bytes) = (0u64, 0u64);
        if let Some(cost) = cost {
            (reads, bytes) = (cost.reads(), cost.staged_bytes);
            if reads > cost.read_budget {
                over.push((Term::Reads, reads - cost.read_budget));
            }
            if bytes > cost.byte_budget {
                over.push((Term::Bytes, bytes - cost.byte_budget));
            }
        }
        Price { lists: shape.lists, body: shape.body, values: shape.values, reads: usize::try_from(reads).unwrap_or(usize::MAX), bytes, over }
    }
}

/// Returns the distinct positions the draft-native runs name — the store's
/// re-insert count, a position two runs name counted once — over every
/// named draft: the positions of two drafts are distinct addresses, so each
/// draft's are counted on its own chain and summed.
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
