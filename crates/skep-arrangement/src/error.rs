//! §Errors — the typed rejections of M5's op surface. Each variant names one
//! verdict and says what it means; that is the whole job of this file.
//!
//! WHICH ERROR WINS when several conditions fail at once is a property of the
//! operation, not of the enum: it is stated on each op of
//! [`Vstream`](crate::Vstream), which is where a caller reads it and where the
//! integration suite pins it. Declaration order here carries no contract.

use std::error::Error;
use std::fmt;

use skep_address::Address;
use skep_content::ContentError;
use skep_namespace::MintError;

/// INSERT rejection (ASN-0116; §3). `NotContentSubspace`: `at.subspace ≠
/// s_C`. `OutOfBounds`: `at.ordinal ∉ [1, n_C + 1]`. (The interface
/// document's former `BadPosition` was split into these two precise
/// verdicts, aligned with DELETE's granularity, so M10 gets a
/// self-describing rejection.) `NotOwner` carries the document that failed
/// the ω check.
///
/// `PublishedTarget` is the version-chain model's in-place advance refusal
/// (PUB-2.11; owner ruling D2b): the target's DOCUMENT (a version member
/// projects to it, PUB-2.15) is PUBLISHED, and this insert is not an
/// admitted deposit — one DECLARED deposit-shaped (PUB-2.59, PUB-2.61,
/// PUB-9.13's DECLARED horn), which is the one exemption. The face, verbatim
/// from PUB-2.11's table: "⟨D⟩ is published — it advances by versions. Stage
/// your change in a draft, then publish it as the next version."
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InsertError {
    DocNotRegistered,
    NotOwner(Address),
    PublishedTarget,
    NotContentSubspace,
    OutOfBounds,
    EmptyContent,
    Mint(MintError),
    Content(ContentError),
}

/// COPY rejection (ASN-0118; §5). Destination `at` gets the same
/// `NotContentSubspace`/`OutOfBounds` split as INSERT; per-spec guards are
/// `SourceNotRegistered`, `NotOrdinalVSpan` (fails
/// [`is_ordinal_vspan`](crate::is_ordinal_vspan) — the lossless narrowing of
/// Conflicts #7, and named for the predicate a caller runs to pre-validate),
/// `SourceNotContentSubspace` (content-residence,
/// `span.start().get(1) ≠ s_C`), `EmptySource` (registered-but-content-empty
/// source, ASN-0118 enabled(COPY)), `DanglingSource` (a resolved run start
/// ∉ dom(C) — S3★), `TooManyRuns` (the placement exceeds
/// [`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS)), and `EmptyResult` (net
/// placement empty after clipping). `NotOwner` carries the DESTINATION
/// document, which is the only one COPY gates.
///
/// Why the residence and referential guards exist — what each protects, and
/// what widening it would oblige — and which document `NotOwner` names are
/// stated on [`Vstream::copy`](crate::Vstream::copy). An argument about an
/// invariant belongs with the operation that keeps it, so a widening reads
/// one statement rather than two that must be edited in step.
///
/// `PublishedTarget` is PUB-2.11's refusal on the DESTINATION (copy-into is
/// the reading surface's own mutation class); the sources stay unrestricted.
/// Same face as [`InsertError::PublishedTarget`]; no deposit exemption —
/// only a declared `insert` rides it (PUB-2.59).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CopyError {
    DocNotRegistered,
    NotOwner(Address),
    PublishedTarget,
    NotContentSubspace,
    OutOfBounds,
    SourceNotRegistered,
    EmptySource,
    NotOrdinalVSpan,
    SourceNotContentSubspace,
    DanglingSource,
    TooManyRuns,
    EmptyResult,
}

/// DELETE rejection (ASN-0117; §4): the doc is registered, the caller is its
/// owner, its document is not published (`PublishedTarget` — PUB-2.11's
/// refusal, the face of [`InsertError::PublishedTarget`]), `subspace(p) =
/// s_C`, `p` is arranged (`ordinal ∈ [1, n_C]`), the range is contained
/// (`ordinal + width − 1 ≤ n_C`), and `width ≥ 1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeleteError {
    DocNotRegistered,
    NotOwner(Address),
    PublishedTarget,
    NotContentSubspace,
    NotArranged,
    OutOfBounds,
    EmptyWidth,
}

/// REARRANGE rejection (ASN-0119/0084 R-PRE; §6): the document is not
/// published (`PublishedTarget` — PUB-2.11's refusal, the face of
/// [`InsertError::PublishedTarget`]), 3 or 4 cuts, strictly ascending, all
/// subspace s_C, CS5 lower bound `1 ≤ ord(c₀)` and upper bound
/// `ord(c_last) ≤ n_C + 1` (both `OutOfBounds`), content subspace non-empty
/// (R-PRE(ii); with ascending in-bounds cuts an empty subspace always trips
/// `OutOfBounds` first, so `EmptyContentSubspace` is defensive completeness
/// against the cited R-PRE rather than a reachable verdict).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RearrangeError {
    DocNotRegistered,
    NotOwner(Address),
    PublishedTarget,
    BadCutCount,
    NotAscending,
    NotContentSubspace,
    OutOfBounds,
    EmptyContentSubspace,
}

/// CREATENEWVERSION rejection (ASN-0123; §7). `NodeTierCrossOwner`: the
/// P-tier excludes a node-tier cross-owner fork — rejected explicitly before
/// any mint rather than surfacing obliquely as `Mint(NotAnAccount)`.
///
/// The version-chain model's two refusals (owner ruling D2b), both EXACT OF
/// THE OWN-SOURCE ARM (PUB-2.14 — the cross-owner branch mints in the
/// caller's account off the source default plus the flag and is never
/// refused by either):
///
/// * `PrivateSourceVersionless` — PUB-2.9: the source the caller OWNS is
///   PRIVATE, whatever the flag; private documents are versionless, private
///   history being the pool. ONE code; the FACE splits on the flag the
///   caller SENT (PUB-8.3, RES-43) — absent or `false`: "⟨D⟩ is private —
///   private documents are versionless. Mint a sibling draft to hold the
///   alternative; the version chain is publication's own."; `true`: "⟨D⟩ is
///   private — publishing means minting a separate edition: select what to
///   publish and it is minted published-born, your draft re-windowing it;
///   private documents are versionless."
/// * `PrivateVersionOfPublished` — PUB-2.7: the source is PUBLISHED and the
///   RESOLVED state is private (the explicit `false` arm alone — absent
///   inherits published and is legal, PUB-2.8). The face names both acts
///   (RES-189): "⟨D⟩ is published — its versions are published. To keep a
///   private copy of it, mint a sibling draft to hold it; the version chain
///   is publication's own. To change what the world reads, stage your change
///   in a draft, then publish it as the next version."
///
/// Both read the source's DOCUMENT (PUB-2.15): a version member is judged
/// as its trunk is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionError {
    SourceNotRegistered,
    NotAPrincipal,
    NodeTierCrossOwner,
    PrivateSourceVersionless,
    PrivateVersionOfPublished,
    Mint(MintError),
}

/// Link-seating rejection (ASN-0047 CL-OWN/CL-UNIQ; §8): `NotLinkAddress` —
/// `link` is not a full element position `doc·0·s_L·ordinal`, the shape a
/// seated run's start must have; `NotHomeLink` — `origin(link) ≠ doc` (via
/// M1's `document_of`); `AlreadySeated` — the link is already inside the
/// doc's link-run I-extents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeatError {
    NotLinkAddress,
    NotHomeLink,
    AlreadySeated,
}

// `?`-desugaring conversions the in-closure mint/write calls depend on
// (INSERT: `mint_content(doc)?`, `stage_write(…)?`; VERSION:
// `mint_version`/`mint_document … ?`).

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

impl fmt::Display for InsertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InsertError::DocNotRegistered => f.write_str("insert: doc is not a registered document"),
            InsertError::NotOwner(_) => {
                f.write_str("insert: the caller is not the document's effective owner (ω)")
            }
            InsertError::PublishedTarget => f.write_str(
                "insert: the document is published — it advances by versions; stage the change in a draft, then publish it as the next version (an undeclared or non-fresh deposit is an in-place edit)",
            ),
            InsertError::NotContentSubspace => {
                f.write_str("insert: at.subspace is not the content subspace s_C")
            }
            InsertError::OutOfBounds => {
                f.write_str("insert: at.ordinal is outside the valid insertion range [1, n_C + 1]")
            }
            InsertError::EmptyContent => f.write_str("insert: values is empty"),
            // The wrapping variants describe THIS layer only; the inner
            // message is reachable through `source`, and a reporter that
            // walks the chain would otherwise print it twice.
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
            CopyError::TooManyRuns => "copy: the placement exceeds the per-transaction run budget",
            CopyError::EmptyResult => "copy: the net placement is empty after clipping",
        })
    }
}
impl Error for CopyError {}

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
    use crate::testutil::t;

    #[test]
    fn wrapping_errors_name_their_own_layer_and_delegate_the_cause() {
        // The terse `Display` on the wrapping variants is affordable only
        // because the cause is reachable through `source`, so a reporter
        // walking the chain prints it exactly once. That chain is the whole
        // justification, and it is what this pins.
        let cause = MintError::HomeNotRegistered;
        let insert_mint = InsertError::Mint(cause);
        assert_eq!(insert_mint.to_string(), "insert: content mint failed");
        // Compared against the inner error's OWN message, never against M3's
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

        let refusal = ContentError::AlreadyPresent(t(&[1, 0, 1, 0, 1, 0, 1, 1]));
        let insert_write = InsertError::Content(refusal.clone());
        assert_eq!(insert_write.to_string(), "insert: content write rejected");
        assert_eq!(
            insert_write
                .source()
                .expect("the write refusal is the cause")
                .to_string(),
            refusal.to_string()
        );

        // The unwrapped verdicts are the end of the chain: they describe
        // themselves and wrap nothing.
        assert!(InsertError::EmptyContent.source().is_none());
        assert!(VersionError::NotAPrincipal.source().is_none());
        assert!(CopyError::EmptyResult.source().is_none());
        assert!(InsertError::PublishedTarget.source().is_none());
        assert!(VersionError::PrivateSourceVersionless.source().is_none());
        assert!(VersionError::PrivateVersionOfPublished.source().is_none());
    }

    #[test]
    fn the_version_chain_refusals_name_the_act_that_clears_them() {
        // PUB-2.11's table pins the FACES; the store's Display is the
        // operator-facing line, and what it must carry is the same act — the
        // next version by way of a draft — so a log line read without the
        // wire's face still points at the remedy rather than at nothing.
        for line in [
            InsertError::PublishedTarget.to_string(),
            CopyError::PublishedTarget.to_string(),
            DeleteError::PublishedTarget.to_string(),
            RearrangeError::PublishedTarget.to_string(),
        ] {
            assert!(line.contains("published"), "{line}");
            assert!(line.contains("next version"), "{line}");
        }
        assert!(VersionError::PrivateSourceVersionless.to_string().contains("versionless"));
        assert!(VersionError::PrivateVersionOfPublished.to_string().contains("sibling draft"));
    }
}
