//! The marshaled [`Response`] — consolidated by shape; every acknowledged
//! write carries the committed `Seq` and every read answer the snapshot `Seq`
//! (ASN-0134 A1/A2/V1), while a rejection carries neither.

use skep_address::{Address, Nat, SpanSet};
use skep_arrangement::Run;
use skep_discovery::{OrphanReport, SupClaim, Window};
use skep_kernel::Seq;
use skep_links::{Endset, Invalid, Link};
use skep_retrieval::{CompareReport, Deletions, Delivery};

use crate::reject::Rejection;

/// One row of the audit-view edition-claim lookup (PUB-8.46, PUB round 2,
/// lane 3.4 §2): a link of the edition-claim class whose `to` slot denotes
/// the target document, ADMITTED to the class and UNSUPERSEDED, with its
/// retraction stated rather than hidden — the client's PUB-3.19 admission
/// test runs over the `home` this row carries (one `doc_metadata` read of it),
/// and nowhere in the engine.
///
/// `active` is M7's active-view membership: `false` names a claim the home
/// has nullified (retracted), which the audit view still lists (PUB-8.46,
/// PUB-6.32). `to` is the claim's `to` endset as deposited, so a client can
/// tell a whole-document claim from one denoting a version of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditionClaim {
    /// The claim link's address.
    pub claim: Address,
    /// The link's home document — the EDITION.
    pub home: Address,
    /// The `to` endset, denoting the target.
    pub to: Endset,
    /// `true` unless the home has nullified the claim (the retraction).
    pub active: bool,
}

/// A document's birth version — the opening member `D.1` of its version
/// chain, with the extent PUB-3.19's edition test images over (PUB-8.12).
///
/// One value rather than two fields, because the two are one fact: a document
/// whose chain has no member has neither, and a document with one has both.
/// `extent` is that member's arranged content count, which a version never
/// changes (PUB-2.50), so it is the base extent a client measures an edition
/// against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BirthVersion {
    /// The chain's opening member, `D.1`.
    pub addr: Address,
    /// That member's arranged content count.
    pub extent: Nat,
}

/// The marshaled response. Every variant but [`Response::Rejected`] carries
/// one coordinate — `at` on the three acknowledging shapes, `as_of` on every
/// read answer — and what a client does with the pair is [the two
/// coordinates](crate#the-two-coordinates).
///
/// A rejection carries none: it names the operation it refused and how, not a
/// position. So a client tracking the frontier across a refusal asks
/// [`Operation::log_position`] or reissues.
///
/// [`Operation::log_position`]: crate::Operation::log_position
///
/// `Debug + PartialEq + Eq`, because the caller who holds one cannot supply
/// them (both trait and type are foreign to it) and every use of an answer
/// wants them: a transport logging what it is about to marshal, a test
/// asserting the shape an operation produced, a harness diagnosing the shape
/// it did not expect. Every payload carries all three, M6's [`DeliveryItem`]
/// by a hand-written `Debug` that reports its value's byte length and never
/// its bytes.
///
/// [`DeliveryItem`]: skep_retrieval::DeliveryItem
///
/// Not `Clone`, and not for a bound's sake — every payload clones. Nothing
/// needs to duplicate an answer: the one thing that outlives its request is
/// the small [`CommittedAck`] a committed write yields, which the retry memo
/// holds in place of the whole `Response` (§7). Not `Hash`, which M1's
/// `Address` does not carry.
///
/// `#[must_use]` on the type rather than on `execute`, so it holds for every
/// producer: a `Response` that is built and dropped is a request that was
/// executed — possibly committed — and never answered, which is exactly the
/// silence the never-silent contract forbids.
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    /// delete/copy/rearrange — committed at `at` (A7).
    Ack { at: Seq },
    /// create/insert/version/makelink/emit/nullify/sup/fork/delegate/node.
    AckAddr { addr: Address, at: Seq },
    /// editlink: the successor link and its supersession claim.
    AckEdit { successor: Address, claim: Address, at: Seq },
    /// RETRIEVEV delivery.
    Delivery { items: Delivery, as_of: Seq },
    /// vspan/vspanset/project.
    SpanSet { set: SpanSet, as_of: Seq },
    /// origins/docs-containing/findlinks.
    Addrs { addrs: Vec<Address>, as_of: Seq },
    /// next-account-prefix / principal-prefix (`None` = absent/ineligible).
    MaybeAddr { addr: Option<Address>, as_of: Seq },
    /// count_v / count_ftt.
    Count { n: usize, as_of: Seq },
    /// window_v / window_ftt.
    Page { window: Window, as_of: Seq },
    /// RETRIEVEENDSETS pairs.
    Endsets { pairs: Vec<(usize, Endset)>, as_of: Seq },
    /// V→I image.
    Runs { runs: Vec<Run>, as_of: Seq },
    /// discoverable_from.
    Bool { val: bool, as_of: Seq },
    /// readlink (`None` = ⊥).
    LinkValue { link: Option<Link>, as_of: Seq },
    /// followlink — the one response carrying a `Result` in-band, by design:
    /// ⟨⟩ ≠ ⊥ is a defined FOLLOWLINK answer (§2); `Invalid` is a query
    /// result, not a lifecycle failure, and is never lowered to a
    /// [`Rejection`].
    Follow { result: Result<SpanSet, Invalid>, as_of: Seq },
    /// SHOWDELETIONS report.
    Deletions { rep: Deletions, as_of: Seq },
    /// COMPARE report.
    Compare { rep: CompareReport, as_of: Seq },
    /// delete_orphans preview.
    Orphans { report: OrphanReport, as_of: Seq },
    /// in_claims / out_claims.
    Claims { claims: Vec<SupClaim>, as_of: Seq },
    /// doc_metadata (PUB-8.12): the publication state a client's own
    /// admission tests need, and nothing else. `doc` is the trunk document
    /// the argument projects to (a version member names its document's
    /// state); `owner` is M3's effective owner account, CARRIED rather than
    /// recomputed client-side because ω is the store's word (`None` is
    /// unreachable for a registered document and stands only so the shape
    /// never invents an account); `birth` is the [`BirthVersion`] of a
    /// document whose chain has a member, absent for one with none.
    DocMetadata {
        doc: Address,
        published: bool,
        owner: Option<Address>,
        birth: Option<BirthVersion>,
        as_of: Seq,
    },
    /// edition_claims (PUB-8.46): the audit-view lookup of the edition-claim
    /// class over `target`, unsuperseded, retracted-or-not stated, homed
    /// where the caller can read (PUB-6.13).
    EditionClaims { claims: Vec<EditionClaim>, as_of: Seq },
    /// The never-silent surface: every failure of a parsed `Op` (Invariants).
    Rejected(Rejection),
}

/// What a committed write acknowledges — ANY of the three acknowledging
/// shapes, of which [`Response::Ack`] is only the barest — and the ONLY thing
/// a lost acknowledgment can duplicate, so the only thing the idempotency
/// cache holds (§1 step (d), §7). Cheap to `Clone` (`Seq` is `Copy`,
/// `Address` is a tumbler), which is what lets the memo be replayed without
/// cloning a `Response`.
///
/// The three shapes are the three acknowledging `Response` variants, and the
/// correspondence is stated in one place — [`Response::as_ack`] and the
/// `From` impl below — so a new acknowledging shape is a compile error at
/// `as_ack` rather than a memo silently dropped.
#[derive(Clone)]
pub(crate) enum CommittedAck {
    /// [`Response::Ack`].
    At { at: Seq },
    /// [`Response::AckAddr`].
    Addr { addr: Address, at: Seq },
    /// [`Response::AckEdit`].
    Edit { successor: Address, claim: Address, at: Seq },
}

impl From<CommittedAck> for Response {
    fn from(ack: CommittedAck) -> Response {
        match ack {
            CommittedAck::At { at } => Response::Ack { at },
            CommittedAck::Addr { addr, at } => Response::AckAddr { addr, at },
            CommittedAck::Edit { successor, claim, at } => {
                Response::AckEdit { successor, claim, at }
            }
        }
    }
}

impl Response {
    /// The committed-write acknowledgment this response carries, if it is
    /// one — `None` for every read answer and every rejection, neither of
    /// which may be replayed from the memo (a cached read replays a stale
    /// snapshot; a Reorder/Retry reissue MUST re-execute).
    ///
    /// EXHAUSTIVE match with NO `_` arm: a newly added `Response` variant
    /// fails to compile here, beside the catalogue it joins, and must be
    /// classified as acknowledging or not before it can ship.
    pub(crate) fn as_ack(&self) -> Option<CommittedAck> {
        match self {
            Response::Ack { at } => Some(CommittedAck::At { at: *at }),
            Response::AckAddr { addr, at } => {
                Some(CommittedAck::Addr { addr: addr.clone(), at: *at })
            }
            Response::AckEdit { successor, claim, at } => Some(CommittedAck::Edit {
                successor: successor.clone(),
                claim: claim.clone(),
                at: *at,
            }),
            Response::Delivery { .. }
            | Response::SpanSet { .. }
            | Response::Addrs { .. }
            | Response::MaybeAddr { .. }
            | Response::Count { .. }
            | Response::Page { .. }
            | Response::Endsets { .. }
            | Response::Runs { .. }
            | Response::Bool { .. }
            | Response::LinkValue { .. }
            | Response::Follow { .. }
            | Response::Deletions { .. }
            | Response::Compare { .. }
            | Response::Orphans { .. }
            | Response::Claims { .. }
            | Response::DocMetadata { .. }
            | Response::EditionClaims { .. }
            | Response::Rejected(_) => None,
        }
    }
}
