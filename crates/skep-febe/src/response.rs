//! The marshaled [`Response`], consolidated by shape.
//!
//! Every acknowledged write carries a committed `Seq` and every read answer
//! the snapshot `Seq` (ASN-0134 A1/A2/V1), while a rejection carries neither.

use std::collections::BTreeSet;

use skep_address::{Address, Nat, SpanSet};
use skep_arrangement::{Run, ShotTerms};
use skep_content::Val;
use skep_discovery::{OrphanReport, SupClaim, Window};
use skep_kernel::Seq;
use skep_links::{Endset, Invalid, Link};
use skep_namespace::PrincipalId;
use skep_retrieval::{CompareReport, Deletions, Delivery};

use crate::reject::Rejection;

/// One position of the read by identity's answer (AUTH-6.38–6.40).
///
/// It is an item of [`Response::IDelivery`]: the I-address asked and the
/// value M4 holds at it — an entry's own, or the one byte at a position
/// inside a stretch, owned as a one-byte `Val` — or `None` — a position the
/// document never minted, or a link position, M4 holding content-subspace
/// elements alone. Its own shape and not M6's [`DeliveryItem`]: that one
/// names no content position's address — only a link position's `Ref`
/// carries one — and has no absent arm, its positions being the
/// arrangement's, where these are the request's. A value, with the
/// response's derives; `Debug` renders the value by its byte length, as M4's
/// `Val` does, never a byte.
///
/// [`DeliveryItem`]: skep_retrieval::DeliveryItem
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IItem {
    /// The I-address asked.
    pub at: Address,
    /// The value at it, as M4 holds it; `None` where none is.
    pub value: Option<Val>,
}

/// One row of the audit-view edition-claim lookup (PUB-8.46).
///
/// It is a link of the edition-claim class whose `to` slot overlaps the
/// target's subtree, unsuperseded, with its retraction stated rather than
/// hidden — the client's PUB-3.19 admission test runs over the `home` this
/// row carries (one `doc_metadata` read of it), and nowhere in the engine.
///
/// Overlap is wider than denotation, so a row is no promise that `to` names
/// the target: asking about a document yields the claims on it and on its
/// versions, and a `to` slot spanning the subtree may denote no address in
/// it at all. `to` is the endset as deposited, which is what lets a client
/// tell those cases apart for itself.
///
/// `active` is M7's active-view membership: `false` names a claim the home
/// has nullified (retracted), which the audit view still lists (PUB-8.46,
/// PUB-6.32).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EditionClaim {
    /// The claim link's address.
    pub claim: Address,
    /// The link's home document — the edition.
    pub home: Address,
    /// The `to` endset, as deposited.
    ///
    /// It overlaps the target's subtree and need not denote the target.
    pub to: Endset,
    /// `true` unless the home has nullified the claim (the retraction).
    pub active: bool,
}

/// A document's birth version: the opening member `D.1` of its version chain.
///
/// It comes with the extent PUB-3.19's edition test images over (PUB-8.12).
/// One value rather than two fields, because the two are one fact: a document
/// whose chain has no member has neither, and a document with one has both.
/// `extent` is that member's birth content (PUB-3.19 as RES-276 reads it;
/// R2-kickoff D2): the content it was minted with, the leading runs of its
/// arrangement, which a deposit never grows. It is not the member's arranged
/// content count — a birth version is the head until a second member exists,
/// and a head's arrangement takes every declared deposit (PUB-2.66) — so it
/// is served frozen at the mint, the same at every later position, and is
/// the birth extent a client measures an edition against, with nothing to
/// subtract.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BirthVersion {
    /// The chain's opening member, `D.1`.
    pub addr: Address,
    /// The content count that member was born with; a deposit is no part of it.
    pub extent: Nat,
}

/// One row of the any-principal discovery read (PUB-8.47; RES-224).
///
/// It is a covered content prefix and the issuers whose live universal grants
/// cover it, each an address, as a client is served it. Owned rather than
/// borrowed, because an answer outlives the snapshot it was read from.
///
/// M10 builds one only by narrowing the world's [`UniversalIndexRow`]s by
/// the compare [`Op::UniversalGrants`] states, so every issuer listed ω-owns
/// the prefix beside it, and the set a client is handed is the set the
/// fold's `grant_exists` answers from (RES-231, RES-264, RES-273, RES-298).
/// Rows come in prefix order. `issuers` is a set — address order and no
/// repeat are its type's — which the codec renders as the list RES-224's
/// shape rules: one row per content prefix with the issuers who granted it.
/// In practice it holds exactly one: ω is a function, and every issuer the
/// fold indexes is a seat ω answers itself at (the obligation
/// [`UniversalIndexRow`] states).
///
/// [`UniversalIndexRow`]: crate::UniversalIndexRow
/// [`Op::UniversalGrants`]: crate::Op::UniversalGrants
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UniversalGrant {
    /// The covered content prefix — a document or an account address.
    pub prefix: Address,
    /// The issuing accounts, each ω-owning `prefix`.
    ///
    /// They are a set, so it iterates in address order and holds no issuer
    /// twice.
    pub issuers: BTreeSet<Address>,
}

/// When a minted address's position committed: the daemon's testimony.
///
/// It rides the two reads that answer an address's age beside the position
/// the world keeps for it — [`Response::LinkValue`]'s and
/// [`Response::DocMetadata`]'s `time` — and it is the transport's to fill
/// ([`Response::mint_mut`]): M10 answers the position off the world, and the
/// daemon that holds the change feed and reads the time document adds the
/// clock, since a timestamp is transport metadata and never substrate state
/// (wire.md §The change feed). `millis` is unix milliseconds; `source` says
/// which testimony it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MintTime {
    /// The commit's wall-clock unix milliseconds.
    pub millis: u64,
    /// Where the reading came from.
    pub source: TimeSource,
}

/// Which testimony a [`MintTime`] is: the feed's line, or the hour record.
///
/// The wire spells it as `time_from`: `"feed"` where the change feed holds
/// the position's own line, exact to the minute; `"anchor"` where it does
/// not and the newest hourly `skep-time` record at or below the position
/// answers instead, exact to the hour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimeSource {
    /// The change feed's recorded `time` for the position itself.
    Feed,
    /// The newest hourly time record at or below the position.
    Anchor,
}

/// The marshaled response.
///
/// Every variant but [`Response::Rejected`] carries one coordinate — `at` on
/// the three acknowledging shapes, `as_of` on every read answer, which
/// [`Response::as_of`] reads off whichever shape it is — and what a client
/// does with the pair is [the two coordinates](crate#the-two-coordinates).
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
/// the small `CommittedAck` an acknowledged write yields, which the retry memo
/// holds in place of the whole `Response` (§7). Not `Hash`, on six payload
/// leaves that lack it: the content store's `Val`, which an [`IItem`]
/// carries; M6's [`DeliveryItem`], [`Deletions`] and [`CorrPair`]; and M7's
/// [`Invalid`] and [`Link`]. M1's `Address` is not among them — it carries a
/// hand-written `Hash`, identity being the tumbler — which is why
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
    /// delete/copy/reinstate/rearrange — committed at `at` (A7).
    Ack { at: Seq },
    /// A write acknowledged with one address (A7).
    ///
    /// What `addr` names is the op's: the document minted
    /// (create_new_document, fork); the document `version` minted — the next
    /// member of the source's chain where the caller owns the source, a fresh
    /// document in the caller's own account where it does not (PUB-2.14); the
    /// chain member `publish` appended (PUB-2.37); the account delegated
    /// (delegate); the node admitted (register_node); the I-address of the
    /// first value placed (insert, whose values M5 places as one run from
    /// there); the record (make_link, with or without its `replaces` link);
    /// the tuple (emit), the retraction (nullify) or the claim (assert_sup)
    /// deposited. `at` is the coordinate the write committed at — save that
    /// those last three may instead answer, on a dedup hit, the incumbent this
    /// principal can read (PUB-6.25, PUB-6.26): nothing commits, and `at` is
    /// then the coordinate of the base the incumbent was found in ([the two
    /// coordinates](crate#the-two-coordinates)).
    AckAddr { addr: Address, at: Seq },
    /// editlink: the successor link and its supersession claim.
    AckEdit { successor: Address, claim: Address, at: Seq },
    /// RETRIEVEV delivery.
    Delivery { items: Delivery, as_of: Seq },
    /// RETRIEVEI, the read by identity (AUTH-6.38–6.40).
    ///
    /// One [`IItem`] per I-position of every span, in span order, the value
    /// as M4 holds it or `None`. Its own shape, not [`Response::Delivery`]'s,
    /// for the reason [`IItem`] states.
    IDelivery { items: Vec<IItem>, as_of: Seq },
    /// The content-frontier read's answer: `next`, the next unminted ordinal.
    ///
    /// It is the document's next unminted content ordinal — its mint count
    /// plus one, save on the ghost home document, whose content chain starts
    /// past its five ghost positions.
    Frontier { next: Nat, as_of: Seq },
    /// vspan/vspanset/project.
    SpanSet { set: SpanSet, as_of: Seq },
    /// origins/docs-containing/findlinks.
    Addrs { addrs: Vec<Address>, as_of: Seq },
    /// next-account-prefix / principal-prefix (`None` = absent/ineligible).
    MaybeAddr { addr: Option<Address>, as_of: Seq },
    /// effective_owner (AUTH-6.37): ω unprojected, as `(prefix, principal)`.
    ///
    /// It is the longest registered prefix containing the address asked and
    /// the principal seated at it, off one walk of M3's registry. One optional
    /// value rather than two optional fields, because the two are one fact
    /// (the [`BirthVersion`] shape, and for its reason): they are M3's own
    /// registry entry, so a prefix without its principal is not something
    /// this shape can say, and `None` — no registered principal's prefix
    /// contains the address — takes both together. The address asked is a
    /// seat of its own iff `prefix` equals it; any other prefix names the
    /// nearest seat above it. For an account address that equality is the
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
    /// readlink (`None` = ⊥), with the link's age.
    ///
    /// `at` is the position of the commit that minted the link, kept in the
    /// world by M3's position map and answered where the link is — `None`
    /// where the link reads as absent (never deposited, or homed where the
    /// caller may not read, PUB-6.6, the two indistinguishable), and where
    /// a build before the map minted it. `time` is the transport's testimony
    /// of when that position committed ([`MintTime`]), filled through
    /// [`Response::mint_mut`] and `None` until it is, or where no testimony
    /// holds a reading.
    LinkValue { link: Option<Link>, at: Option<Seq>, time: Option<MintTime>, as_of: Seq },
    /// followlink, the one response carrying a `Result` in-band, by design.
    ///
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
    /// in_claims / out_claims: supersession claims on one link's lineage.
    ///
    /// They are M8's [`SupClaim`]s; the edition claims are
    /// [`Response::EditionClaims`]'s.
    Claims { claims: Vec<SupClaim>, as_of: Seq },
    /// doc_metadata (PUB-8.12): publication state, shot terms and fork source.
    ///
    /// It carries the publication state a client's own admission tests need,
    /// and — per signed-ops D25 — the shot terms a verifier of a member's
    /// entry signature needs. `doc` is the trunk document the argument
    /// projects to (a version member names its document's state); `owner` is
    /// M3's effective owner account, carried rather than recomputed
    /// client-side because ω is the store's word (`None` is unreachable for a
    /// registered document and stands only so the shape never invents an
    /// account); `birth` is the [`BirthVersion`] of a document whose chain
    /// has a member, absent for one with none; `terms` are the [`ShotTerms`]
    /// of the address named — the count the shot that minted that member
    /// placed and the base extent its copy took — answered for a version
    /// member the shot minted, and absent otherwise: for the trunk document
    /// itself, and for a member an owned `version` minted, a birth version
    /// among them. `source` is the fork source of the address named (the
    /// fork-source design record): the member or bare document whose
    /// arrangement a `version` snapshotted into it — answered for every
    /// document a `version` minted, an owned member and a cross-owner fork
    /// alike, and absent for every other: a trunk no `version` minted, a shot
    /// member, a `fork`-minted or created document. It is served to every
    /// reader of the address named and gated by nothing of the source's: an
    /// address is not secret, and the fork's readers already hold the
    /// source's I-addresses through `image`. `at` is the position of the
    /// commit that minted the ADDRESS NAMED — a member answers its own mint,
    /// the one member of this shape that does not project to the document —
    /// kept in the world by M3's position map, and `None` where a build
    /// before the map minted it; `time` is the transport's testimony of when
    /// that position committed ([`MintTime`]), filled through
    /// [`Response::mint_mut`]. Both are served to whoever may read the
    /// address named, as `source` is.
    DocMetadata {
        /// The trunk document the argument projects to.
        doc: Address,
        /// Whether that trunk document is published.
        published: bool,
        /// The trunk's effective owner account, as ω answers it.
        owner: Option<Address>,
        /// The trunk's birth version, absent while its chain has no member.
        birth: Option<BirthVersion>,
        /// The shot terms of the address named, where a shot minted it.
        terms: Option<ShotTerms>,
        /// Where a `version` minted the address named, its fork source.
        source: Option<Address>,
        /// The position of the commit that minted the address named.
        at: Option<Seq>,
        /// The transport's testimony of when `at` committed.
        time: Option<MintTime>,
        /// The coordinate of the snapshot the answer was read from.
        as_of: Seq,
    },
    /// edition_claims (PUB-8.46): the audit-view edition-claim lookup.
    ///
    /// It is the lookup of the edition-claim class over `target`,
    /// unsuperseded, retracted-or-not stated, homed where the caller can read
    /// (PUB-6.13), in link-address order — the order the class is answered
    /// in, preserved through the home filter, so dropping a row never
    /// reorders its neighbours.
    EditionClaims { claims: Vec<EditionClaim>, as_of: Seq },
    /// universal_grants (PUB-8.47): the fold's live any-principal set.
    ///
    /// It is that set as a client may display it — one row per covered
    /// content prefix with the issuers who granted it, in prefix order, each
    /// row fold-filtered ([`UniversalGrant`]); empty where the requester is
    /// the guest (PUB-5.109), an answer and never a refusal, and the same
    /// rows for every bound principal. Nothing here decides what is *served*
    /// — the daemon applies the same live set itself at serve — so the answer
    /// changes what a client shows and never what it can read.
    UniversalGrants { rows: Vec<UniversalGrant>, as_of: Seq },
    /// The never-silent surface: every failure of a parsed `Op` (Invariants).
    Rejected(Rejection),
}

/// A write's acknowledgment: any of the three acknowledging shapes.
///
/// It is the only thing a lost acknowledgment can duplicate, so the only
/// thing the retry memo holds (§1 step (d), §7) — the acknowledgment of a
/// write that committed, or of one answered with the incumbent it
/// deduplicated against — and [`Response::Ack`] is only the barest of its
/// shapes. Small — a `Seq` and at most two addresses — which is what lets
/// the memo hold and replay it in place of a whole `Response`. Small is not
/// free: cloning an `Address` allocates, which is the cost `to_ack`'s prefix
/// names.
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
    /// Returns the snapshot coordinate a read answer reports (A2/V1).
    ///
    /// `Some` for every read shape, `None` for the three acknowledgments —
    /// which carry an `at` of their own — and for a rejection, which reports
    /// no position. What a client compares it against is [the two
    /// coordinates](crate#the-two-coordinates).
    ///
    /// Exhaustive with no `_` arm: a newly added shape fails to compile here,
    /// beside the catalogue it joins, until it is classified as a read answer
    /// or not — so a transport that stamps, logs or compares positions asks
    /// this one method rather than matching every read shape of its own.
    pub fn as_of(&self) -> Option<Seq> {
        // One catalogue, written here and in `as_of_mut`: the coordinate law
        // (`every_read_reports_the_committed_head_as_its_as_of`) asks both of
        // nineteen of the twenty-one read shapes — every one but the read by
        // identity's and the content frontier's — and counts the shapes it
        // visits, so the two cannot come to classify one of those nineteen
        // differently.
        match self {
            Response::Delivery { as_of, .. }
            | Response::IDelivery { as_of, .. }
            | Response::Frontier { as_of, .. }
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

    /// Returns [`Response::as_of`]'s coordinate, mutable, for restamping.
    ///
    /// It is for a front door that answers off a kernel of its own and
    /// restamps the position the answer is *of* (skepd's historical door,
    /// whose throwaway kernel counts from 0). `None` wherever `as_of` is, so
    /// an acknowledgment's `at` and a rejection are never restamped.
    pub fn as_of_mut(&mut self) -> Option<&mut Seq> {
        match self {
            Response::Delivery { as_of, .. }
            | Response::IDelivery { as_of, .. }
            | Response::Frontier { as_of, .. }
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

    /// Returns the minted position an age read answered, and its time slot.
    ///
    /// It is the transport's door for dating the two reads that answer an
    /// address's age — [`Response::LinkValue`] and [`Response::DocMetadata`]
    /// — the shape [`Response::as_of_mut`] has, for the reason it has it:
    /// which shapes carry an age is M10's classification, asked here rather
    /// than restated at the handler. `Some` where the answer carries a
    /// position, with the slot the caller fills from the testimony it holds
    /// (the change feed's line, the hour record); `None` for every other
    /// shape, and for an age read whose position is unknown, which carries
    /// no time either. M10 itself never fills the slot: a timestamp is the
    /// transport's testimony, never the world's.
    pub fn mint_mut(&mut self) -> Option<(Seq, &mut Option<MintTime>)> {
        match self {
            Response::LinkValue { at: Some(at), time, .. }
            | Response::DocMetadata { at: Some(at), time, .. } => Some((*at, time)),
            _ => None,
        }
    }

    /// Returns this response's committed-write acknowledgment, if it is one.
    ///
    /// `None` for every read answer and every rejection, neither of which may
    /// be replayed from the memo (a memoized read replays a stale snapshot; a
    /// Reorder/Retry reissue must re-execute). It builds an owned ack,
    /// cloning the acknowledged addresses, which is the work its `to_` prefix
    /// names (C-CONV).
    ///
    /// Exhaustive match with no `_` arm: a newly added `Response` variant
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
            | Response::IDelivery { .. }
            | Response::Frontier { .. }
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
