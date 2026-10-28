//! The typed rejections of M5's operations (§Errors).
//!
//! Each variant names one verdict and says what it means; that is the whole
//! job of this file.
//!
//! **Which error wins** when several conditions fail at once is a property of
//! the operation, not of the enum: it is stated on each op of
//! [`Vstream`](crate::Vstream), which is where a caller reads it and where the
//! integration suite pins it. Declaration order here carries no contract.

use std::error::Error;
use std::fmt;

use skep_address::Address;
use skep_content::ContentError;
use skep_namespace::MintError;

/// INSERT rejection (ASN-0116; §3).
///
/// `NotContentSubspace`: `at.subspace ≠ s_C`. `OutOfBounds`: `at.ordinal ∉
/// [1, n_C + 1]` of the arrangement the insert lands in — the named
/// document's, or, for a declared deposit into a published chain with a
/// head, the head's ([`deposit_surface`](crate::deposit_surface)). (The two
/// split the interface document's `BadPosition` into precise verdicts,
/// aligned with DELETE's granularity, so M10 gets a self-describing
/// rejection.) `NotOwner` carries the document that failed the ω check.
///
/// `PublishedTarget` is the version-chain model's in-place advance refusal
/// (PUB-2.11; PUB-kickoff D2b): the target's document (a version member
/// projects to it, PUB-2.15) is published, and this insert is not the one
/// exemption: an insert declared under a type the deposit class holds
/// (PUB-2.64; RES-249, RES-261) and deposit-shaped (PUB-2.59, PUB-2.61,
/// PUB-9.13's declared horn). The face, verbatim from PUB-2.11's table:
/// "⟨D⟩ is published — it advances by versions. Stage your change in a
/// draft, then publish it as the next version."
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InsertError {
    /// `doc` is not a registered document.
    DocNotRegistered,
    /// The caller is not `doc`'s effective owner (ω); carries `doc`.
    NotOwner(Address),
    /// `doc`'s document is published and this insert is not the exemption.
    PublishedTarget,
    /// `at` is not in the content subspace `s_C`.
    NotContentSubspace,
    /// `at.ordinal` is outside `[1, n_C + 1]` of the arrangement landed in.
    OutOfBounds,
    /// `values` is empty.
    EmptyContent,
    /// A content mint was refused.
    Mint(MintError),
    /// A content write was refused.
    Content(ContentError),
}

/// COPY rejection (ASN-0118; §5).
///
/// Destination `at` gets the same `NotContentSubspace`/`OutOfBounds` split as
/// INSERT; per-spec guards are `SourceNotRegistered`, `NotOrdinalVSpan`
/// (fails [`is_ordinal_vspan`](crate::is_ordinal_vspan) — the lossless
/// narrowing of Conflicts #7, and named for the predicate a caller runs to
/// pre-validate), `SourceNotContentSubspace` (content-residence,
/// `span.start().get(1) ≠ s_C`), `EmptySource` (registered-but-content-empty
/// source, ASN-0118 enabled(COPY)), `DanglingSource` (a resolved run start
/// ∉ dom(C) — S3★), `TooManyRuns` (the placement exceeds
/// [`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS), or the specs' run-list walk
/// would exceed [`MAX_COPY_RESOLVE_STEPS`](crate::MAX_COPY_RESOLVE_STEPS) —
/// one verdict for both, a run budget the caller meets by splitting the
/// copy, as M7's `SlotTooLarge` is one for a slot's two budgets), and
/// `EmptyResult` (net placement empty after clipping). `NotOwner` carries the
/// destination document, which is the only one COPY gates.
///
/// Why the residence and referential guards exist — what each protects, and
/// what widening it would oblige — and which document `NotOwner` names are
/// stated on [`Vstream::copy`](crate::Vstream::copy). An argument about an
/// invariant belongs with the operation that keeps it, so a widening reads
/// one statement rather than two that must be edited in step.
///
/// `PublishedTarget` is PUB-2.11's refusal on the destination (copy-into is
/// an in-place edit); the sources are not gated here — by ownership or by
/// publication — and their readability is the caller's
/// ([`Vstream::copy`](crate::Vstream::copy)). Same face as
/// [`InsertError::PublishedTarget`]; no deposit exemption — only a declared
/// `insert` rides it (PUB-2.59).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CopyError {
    /// The destination `doc` is not a registered document.
    DocNotRegistered,
    /// The caller is not the destination's effective owner (ω); carries it.
    NotOwner(Address),
    /// The destination's document is published; copy-into edits in place.
    PublishedTarget,
    /// `at` is not in the content subspace `s_C`.
    NotContentSubspace,
    /// `at.ordinal` is outside the destination's `[1, n_C + 1]`.
    OutOfBounds,
    /// A spec's source is not a registered document.
    SourceNotRegistered,
    /// A spec's source arranges no content.
    EmptySource,
    /// A spec's span fails [`is_ordinal_vspan`](crate::is_ordinal_vspan).
    NotOrdinalVSpan,
    /// A spec's span does not lie in the content subspace `s_C`.
    SourceNotContentSubspace,
    /// A resolved run's start holds no value in the content store.
    DanglingSource,
    /// The placement, or the walk resolving the specs, exceeds its budget.
    TooManyRuns,
    /// Nothing survives clipping: the net placement is empty.
    EmptyResult,
}

/// REINSTATE rejection (the replacement act's record).
///
/// REINSTATE is the write by identity — `retrieve_i`'s twin as COPY is
/// `retrieve_v`'s. Destination `at` gets INSERT's
/// `NotContentSubspace`/`OutOfBounds` split and `PublishedTarget` is
/// PUB-2.11's refusal on the destination, as COPY's; `NotOwner` carries the
/// destination, the only document the op gates. Per run, the shot's own
/// verdicts on a client-supplied run: `BadRun` (its start is no content
/// element, or the document the client's `origin` projects to is not the
/// trunk of the document that minted it — address arithmetic, disclosing
/// nothing), `SourceNotRegistered` (that origin document is not registered),
/// `DanglingSource` (an address the run names holds no value — every address
/// probed, as the shot probes a by-reference run, the run being the client's
/// I-extent and no arrangement's), `TooManyRuns` (the placement exceeds
/// [`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS)), and `EmptyResult` (`runs`
/// is empty). Which wins is stated on
/// [`Vstream::reinstate`](crate::Vstream::reinstate). No `Withheld`: the
/// origins' readability is the caller's, as COPY's sources' is, discharged
/// at M10's door.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReinstateError {
    /// The destination `doc` is not a registered document.
    DocNotRegistered,
    /// The caller is not the destination's effective owner (ω); carries it.
    NotOwner(Address),
    /// The destination's document is published; a re-placement edits in place.
    PublishedTarget,
    /// `at` is not in the content subspace `s_C`.
    NotContentSubspace,
    /// `at.ordinal` is outside the destination's `[1, n_C + 1]`.
    OutOfBounds,
    /// A supplied run is not a content run of its stated origin.
    BadRun,
    /// A run's origin document is not a registered document.
    SourceNotRegistered,
    /// An address a supplied run names holds no stored value.
    DanglingSource,
    /// The placement exceeds [`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS).
    TooManyRuns,
    /// `runs` is empty.
    EmptyResult,
}

/// DELETE rejection (ASN-0117; §4).
///
/// A delete is refused unless the doc is registered, the caller is its
/// owner, its document is not published (`PublishedTarget` — PUB-2.11's
/// refusal, the face of [`InsertError::PublishedTarget`]), `subspace(p) =
/// s_C`, `p` is arranged (`ordinal ∈ [1, n_C]`), the range is contained
/// (`ordinal + width − 1 ≤ n_C`), and `width ≥ 1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeleteError {
    /// `doc` is not a registered document.
    DocNotRegistered,
    /// The caller is not `doc`'s effective owner (ω); carries `doc`.
    NotOwner(Address),
    /// `doc`'s document is published: a delete is an in-place edit.
    PublishedTarget,
    /// `p` is not in the content subspace `s_C`.
    NotContentSubspace,
    /// `p.ordinal` names no arranged content position.
    NotArranged,
    /// The range overruns the arranged content: `ordinal + width − 1 > n_C`.
    OutOfBounds,
    /// `width` is zero.
    EmptyWidth,
}

/// REARRANGE rejection (ASN-0119/0084 R-PRE; §6).
///
/// A rearrange is refused unless the document is registered, the caller is
/// its owner, the document is not published (`PublishedTarget` — PUB-2.11's
/// refusal, the face of [`InsertError::PublishedTarget`]), there are 3 or 4
/// cuts, strictly ascending, all subspace s_C, CS5 lower bound `1 ≤ ord(c₀)`
/// and upper bound `ord(c_last) ≤ n_C + 1` hold (both `OutOfBounds`), and
/// the content subspace is non-empty (`EmptyContentSubspace`, R-PRE(ii)).
/// Whether that last verdict can be reached past the ones before it is
/// [`Vstream::rearrange`](crate::Vstream::rearrange)'s to say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RearrangeError {
    /// `doc` is not a registered document.
    DocNotRegistered,
    /// The caller is not `doc`'s effective owner (ω); carries `doc`.
    NotOwner(Address),
    /// `doc`'s document is published: a re-arrangement is an in-place edit.
    PublishedTarget,
    /// `cuts` holds neither three cuts nor four.
    BadCutCount,
    /// The cuts' ordinals are not strictly ascending.
    NotAscending,
    /// A cut is not in the content subspace `s_C`.
    NotContentSubspace,
    /// The first cut's ordinal is below 1, or the last's past `n_C + 1`.
    OutOfBounds,
    /// The content subspace is empty.
    EmptyContentSubspace,
}

/// CREATENEWVERSION rejection (ASN-0123; §7).
///
/// `NodeTierCrossOwner`: the P-tier excludes a node-tier cross-owner fork —
/// rejected explicitly before any mint rather than surfacing obliquely as
/// `Mint(NotAnAccount)`.
///
/// The version-chain model's two refusals (PUB-kickoff D2b), both exact of
/// the own-source arm (PUB-2.14 — the cross-owner branch mints in the
/// caller's account off the source default plus the flag and is never
/// refused by either):
///
/// * `PrivateSourceVersionless` — PUB-2.9: the source the caller owns is
///   private, whatever the flag; private documents are versionless, private
///   history being the pool. One code; the face splits on the flag the
///   caller sent (PUB-8.3, RES-43) — absent or `false`: "⟨D⟩ is private —
///   private documents are versionless. Mint a sibling draft to hold the
///   alternative; the version chain is publication's own."; `true`: "⟨D⟩ is
///   private — publishing means minting a separate edition: select what to
///   publish and it is minted published-born, your draft re-windowing it;
///   private documents are versionless."
/// * `PrivateVersionOfPublished` — PUB-2.7: the source is published and the
///   resolved state is private (the explicit `false` arm alone — absent
///   inherits published and is legal, PUB-2.8). The face names both acts
///   (RES-189): "⟨D⟩ is published — its versions are published. To keep a
///   private copy of it, mint a sibling draft to hold it; the version chain
///   is publication's own. To change what the world reads, stage your change
///   in a draft, then publish it as the next version."
///
/// Both read the source's document (PUB-2.15): a version member is judged
/// as its trunk is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionError {
    /// `source` is not a registered document.
    SourceNotRegistered,
    /// `principal` names no registered principal.
    NotAPrincipal,
    /// A cross-owner fork whose forker's prefix is not a registered account.
    NodeTierCrossOwner,
    /// The owned source is private: private documents are versionless.
    PrivateSourceVersionless,
    /// The owned source is published and the resolved state is private.
    PrivateVersionOfPublished,
    /// The identity mint was refused.
    Mint(MintError),
}

/// PUBLISH rejection (PUB-2.33, PUB-8.1): the shot's verdicts.
///
/// Which one wins when several apply is stated on
/// [`Vstream::publish`](crate::Vstream::publish) and only there.
///
/// Below, `doc` is the address the shot names and *the document* is the one
/// it projects to (PUB-2.15): registration and ω are judged on the address
/// named, and publication, the chain and the base on the document — the
/// shot is the document's, whichever member names it.
///
/// * `DocNotRegistered` / `NotOwner(doc)` — the registration and ω of the
///   address named; the payload is that address. `NotOwner` carries the
///   DRAFT's document instead where `draft` is named and the caller does not
///   own the document it projects to — the link-sets design §5.7's
///   unowned-draft edge, asked right after the draft's registration and
///   ahead of every readability question; the records a publication keeps
///   are homed in the draft, so the shot refuses a draft the caller does not
///   own, readable or not.
/// * `SourceNotRegistered` — the base, the document the draft projects to
///   (PUB-2.15), or a run's origin document is not a registered document.
/// * `BadRun` — a supplied run is not a content run of its stated origin:
///   its start is not a content element, or its origin document — the trunk
///   (PUB-2.15) of the document that minted it — is not the document the
///   client's `origin` projects to. Address arithmetic on the request alone;
///   it discloses nothing about what exists.
/// * `BaseNotInChain` — `base` names a document that is neither the document
///   nor a member of its chain (PUB-2.37: a shot lands under its own base).
/// * `BaseSuperseded` — the base is absent, or names the document itself,
///   while the document already has a member: the birth shape (PUB-2.34) and
///   the memberless base (PUB-2.66) both name the document's own pre-chain
///   arrangement, which the chain has superseded; name the member the draft
///   was staged from.
/// * `BaseExtentTooLarge` — `base.extent` exceeds the base's current content
///   count: the render claims to have seen more than the member holds.
/// * `PrivateSourceVersionless` — the document is private: private documents
///   are versionless (PUB-2.9), and a shot appends a version. One code with
///   `version`'s own (the wire's `private_source_versionless`); the face is
///   PUB-2.9's `true` arm, the intent being publication: "⟨D⟩ is private —
///   publishing means minting a separate edition: select what to publish
///   and it is minted published-born, your draft re-windowing it; private
///   documents are versionless."
/// * `Withheld(origin_doc)` — the source gate (PUB-6.23, PUB-8.1's second
///   constraint) refused a run: the payload is the origin document
///   (PUB-8.4's `site.addr`) of the first supplied run, in run order, that
///   the base does not already arrange — carried-ness is judged run by run
///   (PUB-6.24), not per origin document — whose origin document is not the
///   shot's own document and which the shooter may not read.
/// * `DanglingSource` — an I-address a run names has no stored value
///   (S3★): a by-reference run whose I-extent M4 does not hold whole, or a
///   draft-native run whose bytes are not all there to re-insert.
/// * `TooManyRuns` — the member's placement exceeds
///   [`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS), the budget COPY, REINSTATE
///   and the shot share; a shot cannot be split to meet it.
/// * `TooManyValues` — the values the shot re-inserts
///   ([`Shot::reinserted_values`](crate::Shot::reinserted_values): the
///   distinct positions the draft-native runs name) exceed
///   [`MAX_REINSERTED_VALUES`](crate::MAX_REINSERTED_VALUES): each such value
///   is re-inserted as fresh identity, two staged records apiece where every
///   value is an atom, and two for a whole run of single-byte values.
///   Arithmetic on the request alone, it discloses nothing about what
///   exists; a shot cannot be split to meet it. Its own verdict and not
///   `TooManyRuns`'s, since the re-inserted values are I-adjacent and
///   coalesce: a shot refused here may place a single run.
/// * `Mint` / `Content` — the identity mint, a content mint, or a content
///   write refused (M3/M4's own boundary refusals; defensive).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublishError {
    /// `doc`, the address the shot names, is not a registered document.
    DocNotRegistered,
    /// The caller is not the effective owner (ω) of `doc`, or of the draft
    /// the shot names; carries the document that failed.
    NotOwner(Address),
    /// The base, the draft's document or a run's origin is not registered.
    SourceNotRegistered,
    /// A supplied run is not a content run of its stated origin.
    BadRun,
    /// The base is neither the document nor a member of its chain.
    BaseNotInChain,
    /// The base is absent or the document itself, and a member exists.
    BaseSuperseded,
    /// `base.extent` exceeds the base's current content count.
    BaseExtentTooLarge,
    /// The document is private: private documents are versionless.
    PrivateSourceVersionless,
    /// The source gate refused a run; carries that run's origin document.
    Withheld(Address),
    /// An I-address a supplied run names has no stored value.
    DanglingSource,
    /// The placement exceeds [`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS).
    TooManyRuns,
    /// The values the shot re-inserts exceed `MAX_REINSERTED_VALUES`.
    TooManyValues,
    /// The identity mint or a content mint was refused.
    Mint(MintError),
    /// A content write was refused.
    Content(ContentError),
}

/// Link-seating rejection (ASN-0047 CL-OWN/CL-UNIQ; §8).
///
/// `NotLinkAddress` — `link` is not a full element position
/// `doc·0·s_L·ordinal`, the shape a seated run's start must have;
/// `NotHomeLink` — `origin(link) ≠ doc` (via M1's `document_of`);
/// `AlreadySeated` — the link is already inside the doc's link-run
/// I-extents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeatError {
    /// `link` is not a full element position in the link subspace `s_L`.
    NotLinkAddress,
    /// `origin(link)` is not `doc`.
    NotHomeLink,
    /// `link` is already seated in `doc`'s link subspace.
    AlreadySeated,
}

// `?`-desugaring conversions the in-closure mint/write calls depend on:
// `allocate_for_placement`'s `mint_content(home)?` and `stage_write(…)?`, and
// `allocate_stretch_for_placement`'s `mint_content_range(home, n)?` and
// `stage_stretch(…)?` — whose `EmptyStretch` and `Overlap` ride the same
// `From<ContentError>` as `AlreadyStored` — the two steps INSERT and the shot
// share, whose bound (`E: From<MintError> + From<ContentError>`) these impls
// discharge — the shot's own `mint_version(…)?`, and VERSION's
// `mint_version`/`mint_document … ?`.

impl From<MintError> for InsertError {
    fn from(e: MintError) -> Self {
        InsertError::Mint(e)
    }
}

impl From<ContentError> for InsertError {
    fn from(e: ContentError) -> Self {
        InsertError::Content(e)
    }
}

impl From<MintError> for VersionError {
    fn from(e: MintError) -> Self {
        VersionError::Mint(e)
    }
}

impl From<MintError> for PublishError {
    fn from(e: MintError) -> Self {
        PublishError::Mint(e)
    }
}

impl From<ContentError> for PublishError {
    fn from(e: ContentError) -> Self {
        PublishError::Content(e)
    }
}

impl fmt::Display for PublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublishError::DocNotRegistered => {
                f.write_str("publish: doc is not a registered document")
            }
            PublishError::NotOwner(_) => {
                f.write_str("publish: the caller is not the document's effective owner (ω)")
            }
            PublishError::SourceNotRegistered => f.write_str(
                "publish: the base, the draft, or a run's origin is not a registered document",
            ),
            PublishError::BadRun => f.write_str(
                "publish: a supplied run is not a content run of its stated origin",
            ),
            PublishError::BaseNotInChain => f.write_str(
                "publish: the base is neither the document nor a member of its chain",
            ),
            PublishError::BaseSuperseded => f.write_str(
                "publish: the document already has a member, so its own pre-chain arrangement is no base — name the member the draft was staged from",
            ),
            PublishError::BaseExtentTooLarge => f.write_str(
                "publish: the base extent exceeds the base's current content count",
            ),
            PublishError::PrivateSourceVersionless => f.write_str(
                "publish: the document is private — publishing means minting a separate edition; private documents are versionless (PUB-2.9)",
            ),
            PublishError::Withheld(_) => f.write_str(
                "publish: a supplied run windows an origin the shooter may not read (withheld)",
            ),
            PublishError::DanglingSource => f.write_str(
                "publish: a supplied run names an I-address with no stored value (S3★)",
            ),
            PublishError::TooManyRuns => {
                f.write_str("publish: the placement exceeds the per-transaction run budget")
            }
            PublishError::TooManyValues => f.write_str(
                "publish: the values the shot re-inserts from its draft exceed the per-transaction re-insert budget",
            ),
            // This layer only — the inner message is the `source`.
            PublishError::Mint(_) => f.write_str("publish: an identity or content mint failed"),
            PublishError::Content(_) => f.write_str("publish: a content write was rejected"),
        }
    }
}
impl Error for PublishError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            PublishError::Mint(e) => Some(e),
            PublishError::Content(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for InsertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InsertError::DocNotRegistered => f.write_str("insert: doc is not a registered document"),
            InsertError::NotOwner(_) => {
                f.write_str("insert: the caller is not the document's effective owner (ω)")
            }
            InsertError::PublishedTarget => f.write_str(
                "insert: the document is published — it advances by versions; stage the change in a draft, then publish it as the next version (an undeclared insert, one declared under a type the deposit class does not hold, and a declared insert at any position but a fresh content one are each an in-place edit)",
            ),
            InsertError::NotContentSubspace => {
                f.write_str("insert: at.subspace is not the content subspace s_C")
            }
            InsertError::OutOfBounds => {
                f.write_str("insert: at.ordinal is outside the valid insertion range [1, n_C + 1]")
            }
            InsertError::EmptyContent => f.write_str("insert: values is empty"),
            // The wrapping variants describe this layer only; the inner
            // message is reachable through `source`, and a reporter that
            // walks the `source` chain would otherwise print it twice.
            InsertError::Mint(_) => f.write_str("insert: content mint failed"),
            InsertError::Content(_) => f.write_str("insert: content write rejected"),
        }
    }
}
impl Error for InsertError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            InsertError::Mint(e) => Some(e),
            InsertError::Content(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for CopyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CopyError::DocNotRegistered => "copy: doc is not a registered document",
            CopyError::NotOwner(_) => {
                "copy: the caller is not the destination document's effective owner (ω)"
            }
            CopyError::PublishedTarget => {
                "copy: the destination document is published — it advances by versions; stage the change in a draft, then publish it as the next version"
            }
            CopyError::NotContentSubspace => "copy: at.subspace is not the content subspace s_C",
            CopyError::OutOfBounds => {
                "copy: at.ordinal is outside the valid insertion range [1, n_C + 1]"
            }
            CopyError::SourceNotRegistered => "copy: a spec's source is not a registered document",
            CopyError::EmptySource => "copy: a spec's source content subspace is empty",
            CopyError::NotOrdinalVSpan => {
                "copy: a spec's span is not an ordinal-level depth-2 V-span"
            }
            CopyError::SourceNotContentSubspace => {
                "copy: a spec's span does not lie in the content subspace s_C"
            }
            CopyError::DanglingSource => {
                "copy: a resolved run start is not present in the content store (S3★)"
            }
            CopyError::TooManyRuns => {
                "copy: the placement, or the run-list walk resolving its specs, exceeds the per-transaction run budget"
            }
            CopyError::EmptyResult => "copy: the net placement is empty after clipping",
        })
    }
}
impl Error for CopyError {}

impl fmt::Display for ReinstateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ReinstateError::DocNotRegistered => "reinstate: doc is not a registered document",
            ReinstateError::NotOwner(_) => {
                "reinstate: the caller is not the destination document's effective owner (ω)"
            }
            ReinstateError::PublishedTarget => {
                "reinstate: the destination document is published — it advances by versions; stage the change in a draft, then publish it as the next version"
            }
            ReinstateError::NotContentSubspace => {
                "reinstate: at.subspace is not the content subspace s_C"
            }
            ReinstateError::OutOfBounds => {
                "reinstate: at.ordinal is outside the valid insertion range [1, n_C + 1]"
            }
            ReinstateError::BadRun => {
                "reinstate: a supplied run is not a content run of its stated origin"
            }
            ReinstateError::SourceNotRegistered => {
                "reinstate: a run's origin is not a registered document"
            }
            ReinstateError::DanglingSource => {
                "reinstate: a supplied run names an I-address with no stored value (S3★)"
            }
            ReinstateError::TooManyRuns => {
                "reinstate: the placement exceeds the per-transaction run budget"
            }
            ReinstateError::EmptyResult => "reinstate: runs is empty",
        })
    }
}
impl Error for ReinstateError {}

impl fmt::Display for DeleteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DeleteError::DocNotRegistered => "delete: doc is not a registered document",
            DeleteError::NotOwner(_) => {
                "delete: the caller is not the document's effective owner (ω)"
            }
            DeleteError::PublishedTarget => {
                "delete: the document is published — it advances by versions; stage the change in a draft, then publish it as the next version"
            }
            DeleteError::NotContentSubspace => "delete: p.subspace is not the content subspace s_C",
            DeleteError::NotArranged => "delete: p.ordinal names no arranged content position",
            DeleteError::OutOfBounds => "delete: the range overruns the arranged content (ordinal + width − 1 > n_C)",
            DeleteError::EmptyWidth => "delete: width must be ≥ 1",
        })
    }
}
impl Error for DeleteError {}

impl fmt::Display for RearrangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RearrangeError::DocNotRegistered => "rearrange: doc is not a registered document",
            RearrangeError::NotOwner(_) => {
                "rearrange: the caller is not the document's effective owner (ω)"
            }
            RearrangeError::PublishedTarget => {
                "rearrange: the document is published — it advances by versions; stage the change in a draft, then publish it as the next version"
            }
            RearrangeError::BadCutCount => "rearrange: exactly 3 or 4 cuts are required",
            RearrangeError::NotAscending => "rearrange: cut ordinals must be strictly ascending",
            RearrangeError::NotContentSubspace => {
                "rearrange: every cut must lie in the content subspace s_C"
            }
            RearrangeError::OutOfBounds => {
                "rearrange: cuts must satisfy 1 ≤ ord(c₀) and ord(c_last) ≤ n_C + 1"
            }
            RearrangeError::EmptyContentSubspace => {
                "rearrange: the content subspace is empty (R-PRE ii)"
            }
        })
    }
}
impl Error for RearrangeError {}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionError::SourceNotRegistered => {
                f.write_str("version: the source is not a registered document")
            }
            VersionError::NotAPrincipal => f.write_str("version: the caller id names no principal"),
            VersionError::NodeTierCrossOwner => f.write_str(
                "version: a cross-owner fork requires an account-tier forker (P-tier, ASN-0123)",
            ),
            VersionError::PrivateSourceVersionless => f.write_str(
                "version: the source is private — private documents are versionless; mint a sibling draft to hold the alternative, the version chain is publication's own (PUB-2.9)",
            ),
            VersionError::PrivateVersionOfPublished => f.write_str(
                "version: the source is published — its versions are published; to keep a private copy mint a sibling draft, and to change what the world reads stage the change in a draft and publish it as the next version (PUB-2.7)",
            ),
            // This layer only — the mint's own message is the `source`.
            VersionError::Mint(_) => f.write_str("version: identity mint failed"),
        }
    }
}
impl Error for VersionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            VersionError::Mint(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for SeatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SeatError::NotLinkAddress => {
                "seat: link is not a full element position in the link subspace s_L"
            }
            SeatError::NotHomeLink => "seat: origin(link) is not this document (CL-OWN)",
            SeatError::AlreadySeated => "seat: the link is already seated in this document (CL-UNIQ)",
        })
    }
}
impl Error for SeatError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{doc1, t};

    #[test]
    fn wrapping_errors_name_their_own_layer_and_delegate_the_cause() {
        // The terse `Display` on the wrapping variants is affordable only
        // because the cause is reachable through `source`, so a reporter
        // walking the `source` chain prints it exactly once. That chain is the
        // whole justification, and it is what this pins.
        let cause = MintError::HomeNotRegistered;
        let insert_mint = InsertError::Mint(cause);
        assert_eq!(insert_mint.to_string(), "insert: content mint failed");
        // Compared against the inner error's own message, never against M3's
        // literal text: M3 may reword freely, and the claim here is that the
        // cause arrives, not what it says.
        assert_eq!(
            insert_mint
                .source()
                .expect("the mint failure is the cause")
                .to_string(),
            cause.to_string()
        );

        let version_mint = VersionError::Mint(cause);
        assert_eq!(version_mint.to_string(), "version: identity mint failed");
        assert_eq!(
            version_mint
                .source()
                .expect("the mint failure is the cause")
                .to_string(),
            cause.to_string()
        );

        let refusal = ContentError::AlreadyStored(t(&[1, 0, 1, 0, 1, 0, 1, 1]));
        let insert_write = InsertError::Content(refusal.clone());
        assert_eq!(insert_write.to_string(), "insert: content write rejected");
        assert_eq!(
            insert_write
                .source()
                .expect("the write refusal is the cause")
                .to_string(),
            refusal.to_string()
        );

        // The unwrapped verdicts are the end of the `source` chain: they
        // describe themselves and wrap nothing.
        assert!(InsertError::EmptyContent.source().is_none());
        assert!(VersionError::NotAPrincipal.source().is_none());
        assert!(CopyError::EmptyResult.source().is_none());
        assert!(ReinstateError::DanglingSource.source().is_none());
        assert!(InsertError::PublishedTarget.source().is_none());
        assert!(VersionError::PrivateSourceVersionless.source().is_none());
        assert!(VersionError::PrivateVersionOfPublished.source().is_none());

        // The shot's wrappers take the same discipline as INSERT's.
        let publish_mint = PublishError::Mint(cause);
        assert_eq!(publish_mint.to_string(), "publish: an identity or content mint failed");
        assert_eq!(
            publish_mint
                .source()
                .expect("the mint failure is the cause")
                .to_string(),
            cause.to_string()
        );
        let publish_write = PublishError::Content(refusal.clone());
        assert_eq!(
            publish_write
                .source()
                .expect("the write refusal is the cause")
                .to_string(),
            refusal.to_string()
        );
        assert!(PublishError::Withheld(doc1()).source().is_none());
        assert!(PublishError::BaseSuperseded.source().is_none());
    }

    #[test]
    fn the_version_chain_refusals_name_the_act_that_clears_them() {
        // PUB-2.11's table pins the faces; the store's Display is the
        // operator-facing line, and what it must carry is the same act — the
        // next version by way of a draft — so a log line read without the
        // wire's face still points at the remedy rather than at nothing.
        for line in [
            InsertError::PublishedTarget.to_string(),
            CopyError::PublishedTarget.to_string(),
            ReinstateError::PublishedTarget.to_string(),
            DeleteError::PublishedTarget.to_string(),
            RearrangeError::PublishedTarget.to_string(),
        ] {
            assert!(line.contains("published"), "{line}");
            assert!(line.contains("next version"), "{line}");
        }
        // INSERT's line also names each of the three things the one exemption
        // needs — a declaration, its type one the deposit class holds, a
        // fresh content position — since a published document refuses an
        // insert lacking any one of them.
        let insert_line = InsertError::PublishedTarget.to_string();
        for condition in ["undeclared", "deposit class", "fresh content"] {
            assert!(insert_line.contains(condition), "{condition}: {insert_line}");
        }
        assert!(VersionError::PrivateSourceVersionless.to_string().contains("versionless"));
        assert!(VersionError::PrivateVersionOfPublished.to_string().contains("sibling draft"));
    }
}
