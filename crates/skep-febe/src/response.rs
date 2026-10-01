//! The marshaled [`Response`] — consolidated by shape; every acknowledged
//! write carries the committed `Seq` and every read answer the snapshot `Seq`
//! (ASN-0134 A1/A2/V1), while a rejection carries neither.

use std::collections::BTreeSet;

use skep_address::{Address, Nat, SpanSet};
use skep_arrangement::{Run, ShotTerms};
use skep_discovery::{OrphanReport, SupClaim, Window};
use skep_kernel::Seq;
use skep_links::{Endset, Invalid, Link};
use skep_namespace::PrincipalId;
use skep_retrieval::{CompareReport, Deletions, Delivery};

use crate::reject::Rejection;

/// One row of the audit-view edition-claim lookup (PUB-8.46, PUB round 2,
/// lane 3.4 §2): a link of the edition-claim class whose `to` slot OVERLAPS
/// the target's subtree, UNSUPERSEDED, with its retraction stated rather
/// than hidden — the client's PUB-3.19 admission test runs over the `home`
/// this row carries (one `doc_metadata` read of it), and nowhere in the
/// engine.
///
/// Overlap is WIDER than denotation, so a row is no promise that `to` names
/// the target: asking about a document yields the claims on it AND on its
/// versions, and a `to` slot spanning the subtree may denote no address in
/// it at all. `to` is the endset AS DEPOSITED, which is what lets a client
/// tell those cases apart for itself.
///
/// `active` is M7's active-view membership: `false` names a claim the home
/// has nullified (retracted), which the audit view still lists (PUB-8.46,
/// PUB-6.32).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EditionClaim {
    /// The claim link's address.
    pub claim: Address,
    /// The link's home document — the EDITION.
    pub home: Address,
    /// The `to` endset AS DEPOSITED: it overlaps the target's subtree and
    /// need not denote the target.
    pub to: Endset,
    /// `true` unless the home has nullified the claim (the retraction).
    pub active: bool,
}

/// A document's birth version — the opening member `D.1` of its version
/// chain, with the extent PUB-3.19's edition test images over (PUB-8.12).
///
/// One value rather than two fields, because the two are one fact: a document
/// whose chain has no member has neither, and a document with one has both.
/// `extent` is that member's BIRTH CONTENT (PUB-3.19 as RES-276 reads it; the
/// owner's D2): the content it was minted with, the leading runs of its
/// arrangement, which a deposit never grows. It is NOT the member's arranged
/// content count — a birth version is the head until a second member exists,
/// and a head's arrangement takes every declared deposit (PUB-2.66) — so it
/// is served frozen at the mint, the same at every later position, and is
/// the birth extent a client measures an edition against, with nothing to
/// subtract.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BirthVersion {
    /// The chain's opening member, `D.1`.
    pub addr: Address,
    /// The content count that member was BORN with; a deposit is no part of it.
    pub extent: Nat,
}

/// One row of the ANY-PRINCIPAL DISCOVERY READ (PUB-8.47; RES-224), as a
/// client is served it: a COVERED content prefix and the issuers whose live
/// universal grants cover it, each an address. OWNED rather than borrowed,
/// because an answer outlives the snapshot it was read from.
///
/// M10 builds one only by narrowing the world's [`UniversalIndexRow`]s by
/// the compare [`Op::UniversalGrants`] states, so every issuer listed ω-owns
/// the prefix beside it, and the set a client is handed is the set the
/// fold's `grant_exists` answers from (RES-231, RES-264, RES-273, RES-298).
/// Rows come in prefix order. `issuers` is a SET — address order and no
/// repeat are its type's — which the codec renders as the list RES-224's
/// shape rules: one row per content prefix with the issuers who granted it.
/// In practice it holds exactly ONE: ω is a function, and every issuer the
/// fold indexes is a seat ω answers itself at (the obligation
/// [`UniversalIndexRow`] states).
///
/// [`UniversalIndexRow`]: crate::UniversalIndexRow
/// [`Op::UniversalGrants`]: crate::Op::UniversalGrants
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UniversalGrant {
    /// The covered content prefix — a document or an account address.
    pub prefix: Address,
    /// The issuing accounts, each ω-owning `prefix` — a set, so it iterates
    /// in address order and holds no issuer twice.
    pub issuers: BTreeSet<Address>,
}

/// The marshaled response. Every variant but [`Response::Rejected`] carries
/// one coordinate — `at` on the three acknowledging shapes, `as_of` on every
/// read answer, which [`Response::as_of`] reads off whichever shape it is —
/// and what a client does with the pair is [the two
/// coordinates](crate#the-two-coordinates).
///
/// A rejection carries none: it names the operation it refused and how, not a
/// position. So a client tracking the committed head across a refusal asks
/// [`OperationSurface::log_position`] or reissues.
///
/// [`OperationSurface::log_position`]: crate::OperationSurface::log_position
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
/// holds in place of the whole `Response` (§7). Not `Hash`, on five payload
/// leaves that lack it: M6's [`DeliveryItem`], [`Deletions`] and [`CorrPair`],
/// and M7's [`Invalid`] and [`Link`]. M1's `Address` is NOT among them — it
/// carries a hand-written `Hash`, identity being the tumbler — which is why
/// [`EditionClaim`], [`BirthVersion`] and [`UniversalGrant`] have one.
///
/// [`Deletions`]: skep_retrieval::Deletions
/// [`CorrPair`]: skep_retrieval::CorrPair
/// [`Invalid`]: skep_links::Invalid
/// [`Link`]: skep_links::Link
///
/// `#[must_use]` on the type rather than on `execute`, so it holds for every
/// producer: a `Response` that is built and dropped is a request that was
/// executed — possibly committed — and never answered, which is exactly the
/// silence the never-silent contract forbids. Not `#[non_exhaustive]`, for
/// [`Op`]'s reason.
///
/// [`Op`]: crate::Op
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    /// delete/copy/rearrange — committed at `at` (A7).
    Ack { at: Seq },
    /// A write acknowledged with one ADDRESS (A7). What `addr` names is the
    /// op's: the document minted (create_new_document, fork); the document
    /// `version` minted — the next member of the source's chain where the
    /// caller owns the source, a fresh document in the caller's own account
    /// where it does not (PUB-2.14); the chain member `publish` appended
    /// (PUB-2.37); the account delegated (delegate); the node admitted
    /// (register_node); the I-address of the first value placed (insert, whose
    /// values M5 places as ONE run from there); the record (make_link, with or
    /// without its `replaces` link); the tuple (emit), the retraction
    /// (nullify) or the claim (assert_sup) deposited. `at` is the coordinate
    /// the write committed at — save that those last three may instead answer,
    /// on a DEDUP HIT, the incumbent this principal can read (PUB-6.25,
    /// PUB-6.26): nothing commits, and `at` is then the coordinate of the base
    /// the incumbent was found in ([the two
    /// coordinates](crate#the-two-coordinates)).
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
    /// effective_owner (AUTH-6.37): ω UNPROJECTED — `(prefix, principal)`,
    /// the LONGEST registered prefix containing the address asked and the
    /// principal seated at it, off ONE walk of M3's registry. ONE optional
    /// value rather than two optional fields, because the two are one fact
    /// (the [`BirthVersion`] shape, and for its reason): they are M3's own
    /// registry ENTRY, so a prefix without its principal is not something
    /// this shape can say, and `None` — no registered principal's prefix
    /// contains the address — takes both TOGETHER. The address asked is a
    /// SEAT of its own iff `prefix` equals it; any other prefix names the
    /// nearest seat above it. For an ACCOUNT address that equality is the
    /// allocation test (AUTH-5.87) — allocating an account seats it, a
    /// `delegate` baptizing the prefix and registering its principal at once
    /// — and `Some` alone never is. At every other tier it says nothing about
    /// allocation: a document, an element and a node `register_node` admitted
    /// are allocated and seated nowhere.
    EffectiveOwner { owner: Option<(Address, PrincipalId)>, as_of: Seq },
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
    /// in_claims / out_claims: SUPERSESSION claims (M8's [`SupClaim`]) on one
    /// link's lineage — the EDITION claims are [`Response::EditionClaims`]'s.
    Claims { claims: Vec<SupClaim>, as_of: Seq },
    /// doc_metadata (PUB-8.12): the publication state a client's own
    /// admission tests need, and — since the signed-ops design record's D25,
    /// arm (c′) — the shot terms a verifier of a member's entry signature
    /// needs. `doc` is the trunk document the argument projects to (a
    /// version member names its document's state); `owner` is M3's effective
    /// owner account, CARRIED rather than recomputed client-side because ω is
    /// the store's word (`None` is unreachable for a registered document and
    /// stands only so the shape never invents an account); `birth` is the
    /// [`BirthVersion`] of a document whose chain has a member, absent for
    /// one with none; `terms` are the [`ShotTerms`] of THE ADDRESS NAMED —
    /// the count the shot that minted that member placed and the base extent
    /// its copy took — answered for a version member the shot minted, and
    /// absent otherwise: for the trunk document itself, for a birth version an
    /// owned `version` minted, and for a member minted before the record
    /// carried them.
    DocMetadata {
        doc: Address,
        published: bool,
        owner: Option<Address>,
        birth: Option<BirthVersion>,
        terms: Option<ShotTerms>,
        as_of: Seq,
    },
    /// edition_claims (PUB-8.46): the audit-view lookup of the edition-claim
    /// class over `target`, unsuperseded, retracted-or-not stated, homed
    /// where the caller can read (PUB-6.13), in LINK-ADDRESS order — the
    /// order the class is answered in, preserved through the home filter, so
    /// dropping a row never reorders its neighbours.
    EditionClaims { claims: Vec<EditionClaim>, as_of: Seq },
    /// universal_grants (PUB-8.47): the fold's live ANY-PRINCIPAL set as a
    /// client may DISPLAY it — one row per COVERED content prefix with the
    /// issuers who granted it, in prefix order, each row fold-filtered
    /// ([`UniversalGrant`]); EMPTY where the requester is the guest
    /// (PUB-5.109), an answer and never a refusal, and the same rows for
    /// every bound principal. Nothing here decides what is SERVED — the
    /// daemon applies the same live set itself at serve — so the answer
    /// changes what a client shows and never what it can read.
    UniversalGrants { rows: Vec<UniversalGrant>, as_of: Seq },
    /// The never-silent surface: every failure of a parsed `Op` (Invariants).
    Rejected(Rejection),
}

/// What a committed write acknowledges — ANY of the three acknowledging
/// shapes, of which [`Response::Ack`] is only the barest — and the ONLY thing
/// a lost acknowledgment can duplicate, so the only thing the retry memo
/// holds (§1 step (d), §7). Small — a `Seq` and at most two addresses
/// — which is what lets the memo hold and replay it in place of a whole
/// `Response`. Small is not free: cloning an `Address` allocates, which is
/// the cost `to_ack`'s prefix names.
///
/// The three shapes are the three acknowledging `Response` variants, and the
/// correspondence is stated in one place — [`Response::to_ack`] and the
/// `From` impl below — so a new acknowledging shape is a compile error at
/// `to_ack` rather than a memo silently dropped.
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
    /// The SNAPSHOT coordinate a read answer reports (A2/V1): `Some` for every
    /// read shape, `None` for the three acknowledgments — which carry the `at`
    /// they committed at — and for a rejection, which reports no position.
    /// What a client compares it against is [the two
    /// coordinates](crate#the-two-coordinates).
    ///
    /// EXHAUSTIVE with no `_` arm: a newly added shape fails to compile here,
    /// beside the catalogue it joins, until it is classified as a read answer
    /// or not — so a transport that stamps, logs or compares positions asks
    /// this one method rather than matching every read shape of its own.
    pub fn as_of(&self) -> Option<Seq> {
        // One catalogue, written here and in `as_of_mut`: the coordinate law
        // over every read (`every_read_reports_the_committed_head_as_its_as_of`)
        // asks both of every read shape, and counts the shapes it visits, so
        // the two cannot come to classify a shape differently.
        match self {
            Response::Delivery { as_of, .. }
            | Response::SpanSet { as_of, .. }
            | Response::Addrs { as_of, .. }
            | Response::MaybeAddr { as_of, .. }
            | Response::EffectiveOwner { as_of, .. }
            | Response::Count { as_of, .. }
            | Response::Page { as_of, .. }
            | Response::Endsets { as_of, .. }
            | Response::Runs { as_of, .. }
            | Response::Bool { as_of, .. }
            | Response::LinkValue { as_of, .. }
            | Response::Follow { as_of, .. }
            | Response::Deletions { as_of, .. }
            | Response::Compare { as_of, .. }
            | Response::Orphans { as_of, .. }
            | Response::Claims { as_of, .. }
            | Response::DocMetadata { as_of, .. }
            | Response::EditionClaims { as_of, .. }
            | Response::UniversalGrants { as_of, .. } => Some(*as_of),
            Response::Ack { .. }
            | Response::AckAddr { .. }
            | Response::AckEdit { .. }
            | Response::Rejected(_) => None,
        }
    }

    /// [`Response::as_of`], mutable — for a front door that answers off a
    /// kernel of its own and restamps the position the answer is OF (skepd's
    /// historical door, whose throwaway kernel counts from 0). `None`
    /// wherever `as_of` is, so an acknowledgment's `at` and a rejection are
    /// never restamped.
    pub fn as_of_mut(&mut self) -> Option<&mut Seq> {
        match self {
            Response::Delivery { as_of, .. }
            | Response::SpanSet { as_of, .. }
            | Response::Addrs { as_of, .. }
            | Response::MaybeAddr { as_of, .. }
            | Response::EffectiveOwner { as_of, .. }
            | Response::Count { as_of, .. }
            | Response::Page { as_of, .. }
            | Response::Endsets { as_of, .. }
            | Response::Runs { as_of, .. }
            | Response::Bool { as_of, .. }
            | Response::LinkValue { as_of, .. }
            | Response::Follow { as_of, .. }
            | Response::Deletions { as_of, .. }
            | Response::Compare { as_of, .. }
            | Response::Orphans { as_of, .. }
            | Response::Claims { as_of, .. }
            | Response::DocMetadata { as_of, .. }
            | Response::EditionClaims { as_of, .. }
            | Response::UniversalGrants { as_of, .. } => Some(as_of),
            Response::Ack { .. }
            | Response::AckAddr { .. }
            | Response::AckEdit { .. }
            | Response::Rejected(_) => None,
        }
    }

    /// The committed-write acknowledgment this response carries, if it is
    /// one — `None` for every read answer and every rejection, neither of
    /// which may be replayed from the memo (a memoized read replays a stale
    /// snapshot; a Reorder/Retry reissue MUST re-execute). It builds an
    /// OWNED ack, cloning the acknowledged addresses, which is the work its
    /// `to_` prefix names (C-CONV).
    ///
    /// EXHAUSTIVE match with NO `_` arm: a newly added `Response` variant
    /// fails to compile here, beside the catalogue it joins, and must be
    /// classified as acknowledging or not before it can ship.
    pub(crate) fn to_ack(&self) -> Option<CommittedAck> {
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
            | Response::EffectiveOwner { .. }
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
            | Response::UniversalGrants { .. }
            | Response::Rejected(_) => None,
        }
    }
}
