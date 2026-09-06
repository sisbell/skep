//! §Request-side values of the PUBLISH SHOT (PUB-2.33, PUB-8.1): the
//! client-supplied I-address runs with the origin each windows, the base the
//! staged draft was taken from, and the whole shot — the composite's
//! arrangement input, taken FROM THE CLIENT and never read off any draft's
//! arrangement at commit.
//!
//! Three values rather than loose arguments, for the reason [`crate::VPos`]
//! and [`crate::VSpec`] are values: the pieces of a shot travel together, and
//! a `base` handed over without the extent its copy took would be a base the
//! composite cannot compose against (PUB-2.42).

use skep_address::{Address, Nat};

use crate::run::Run;

/// One client-supplied run of a publish shot (PUB-2.33 as amended,
/// PUB-8.1): the arrangement the shooting client rendered and the person
/// confirmed, one I-run at a time, in arrangement order.
///
/// `origin` is the DOCUMENT the run windows — the document its I-addresses
/// were minted under, a version member projecting to its document
/// (PUB-2.15). It is what the source gate is asked about (PUB-6.23) and
/// what decides the run's family in the member (PUB-2.40): the shot
/// document's own I-space stays by reference, the staging draft's is
/// re-inserted as fresh identity, any other document's stays a window. The
/// composite CHECKS it against the run's start — a run whose stated origin
/// is not the document that minted its addresses is refused `BadRun`
/// (`PublishError`) — so the field is the client's statement of intent, and
/// a mistaken one is told rather than silently re-derived.
///
/// `run` is the I-run: a content element start and a width ≥ 1, built
/// through [`Run::new`], the one foreign constructor — so a shot cannot name
/// a zero-width run or a start that is not a full element position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShotRun {
    /// The document the run windows (its origin, PUB-2.15-projected).
    pub origin: Address,
    /// The I-run itself.
    pub run: Run,
}

/// The base a staged draft was taken from (PUB-2.37): the MEMBER the
/// stager's `copy` named as its source — the trunk head for the ordinary
/// shot, an older member for the daughter shot — or the document itself
/// while it has no member yet (a published document between its birth and
/// its first shot, PUB-2.66's memberless reading), together with how many of
/// its content positions the copy TOOK.
///
/// `extent` is what lets the composite honor PUB-2.42's deposit cell against
/// a whole-arrangement supply: a published member's arrangement changes only
/// by exempt deposits appended at fresh positions (PUB-2.43), so the
/// positions of `member` past `extent` are exactly the deposits the render
/// post-dates, and the composite carries them into the new member unchanged
/// (PUB-2.45). A pinned base never grows, so for a daughter shot the extent
/// equals the base's current count and nothing is appended. An extent past
/// the base's current count is a request defect (`BaseExtentTooLarge`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Base {
    /// The member (or memberless document) the draft was copied from.
    pub member: Address,
    /// The content positions of `member` the copy took — the extent the
    /// staged arrangement accounts for.
    pub extent: Nat,
}

/// One publish shot (PUB-2.33): the next member of the document's chain,
/// born published, in one commit.
///
/// `base` absent is the BIRTH VERSION (PUB-2.34): the chain's first member,
/// admitted only while the chain is empty. `draft` names the staging draft
/// whose native runs are re-inserted as fresh identity under the document's
/// own I-space (PUB-2.40, PUB-2.41); absent, no run is draft-native and every
/// run is placed by reference. `runs` is the WHOLE arrangement the client
/// rendered (PUB-2.33 as amended); the composite appends the base's
/// post-render deposits after it (PUB-2.42, PUB-2.45).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shot {
    /// The member the draft was staged from, with the extent the copy took;
    /// absent for the birth version.
    pub base: Option<Base>,
    /// The staging draft, whose runs are re-inserted as fresh identity.
    pub draft: Option<Address>,
    /// The client-rendered arrangement, in order.
    pub runs: Vec<ShotRun>,
}
