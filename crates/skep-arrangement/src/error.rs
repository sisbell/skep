//! §Errors — the typed rejections of M5's op surface. Each variant names one
//! verdict and says what it means; that is the whole job of this file.
//!
//! WHICH ERROR WINS when several conditions fail at once is a property of the
//! operation, not of the enum: it is stated on each op in
//! [`ops`](crate::Vstream), which is where a caller reads it and where the
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InsertError {
    DocNotRegistered,
    NotOwner(Address),
    NotContentSubspace,
    OutOfBounds,
    EmptyContent,
    Mint(MintError),
    Content(ContentError),
}

/// COPY rejection (ASN-0118; §5). Destination `at` gets the same
/// `NotContentSubspace`/`OutOfBounds` split as INSERT; per-spec guards are
/// `SourceNotRegistered`, `BadSpan` (fails
/// [`is_ordinal_vspan`](crate::is_ordinal_vspan) — the lossless narrowing of
/// Conflicts #7), `SourceNotContentSubspace`
/// (content-residence, `span.start().get(1) ≠ s_C`), `EmptySource`
/// (registered-but-content-empty source, ASN-0118 enabled(COPY)),
/// `DanglingSource` (a resolved run start ∉ dom(C) — S3★), and
/// `EmptyResult` (net placement empty after clipping). `NotOwner` gates the
/// DESTINATION doc only — reading source spans stays unrestricted:
/// transclusion of anyone's content is the point of the medium.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CopyError {
    DocNotRegistered,
    NotOwner(Address),
    NotContentSubspace,
    OutOfBounds,
    SourceNotRegistered,
    EmptySource,
    BadSpan,
    SourceNotContentSubspace,
    DanglingSource,
    EmptyResult,
}

/// DELETE rejection (ASN-0117; §4): the doc is registered, the caller is its
/// owner, `subspace(p) = s_C`, `p` is arranged (`ordinal ∈ [1, n_C]`), the
/// range is contained (`ordinal + width − 1 ≤ n_C`), and `width ≥ 1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeleteError {
    DocNotRegistered,
    NotOwner(Address),
    NotContentSubspace,
    NotArranged,
    OutOfBounds,
    EmptyWidth,
}

/// REARRANGE rejection (ASN-0119/0084 R-PRE; §6): 3 or 4 cuts, strictly
/// ascending, all subspace s_C, CS5 lower bound `1 ≤ ord(c₀)` and upper
/// bound `ord(c_last) ≤ n_C + 1` (both `OutOfBounds`), content subspace
/// non-empty (R-PRE(ii); with ascending in-bounds cuts an empty subspace
/// always trips `OutOfBounds` first, so `EmptyContentSubspace` is defensive
/// completeness against the cited R-PRE rather than a reachable verdict).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RearrangeError {
    DocNotRegistered,
    NotOwner(Address),
    BadCutCount,
    NotAscending,
    NotContentSubspace,
    OutOfBounds,
    EmptyContentSubspace,
}

/// CREATENEWVERSION rejection (ASN-0123; §7). `NodeTierCrossOwner`: the
/// P-tier excludes a node-tier cross-owner fork — rejected explicitly before
/// any mint rather than surfacing obliquely as `Mint(NotAnAccount)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionError {
    SourceNotRegistered,
    NotAPrincipal,
    NodeTierCrossOwner,
    Mint(MintError),
}

/// Link-seating rejection (ASN-0047 CL-OWN/CL-UNIQ; §8): `NotHomeLink` —
/// `origin(link) ≠ doc` (via M1's `document_of`); `AlreadySeated` — the link
/// is already inside the doc's link-run I-extents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeatError {
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
            CopyError::NotContentSubspace => "copy: at.subspace is not the content subspace s_C",
            CopyError::OutOfBounds => {
                "copy: at.ordinal is outside the valid insertion range [1, n_C + 1]"
            }
            CopyError::SourceNotRegistered => "copy: a spec's source is not a registered document",
            CopyError::EmptySource => "copy: a spec's source content subspace is empty",
            CopyError::BadSpan => "copy: a spec's span is not an ordinal-level depth-2 V-span",
            CopyError::SourceNotContentSubspace => {
                "copy: a spec's span does not lie in the content subspace s_C"
            }
            CopyError::DanglingSource => {
                "copy: a resolved run start is not present in the content store (S3★)"
            }
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
                f.write_str("version: d_src is not a registered document")
            }
            VersionError::NotAPrincipal => f.write_str("version: the caller id names no principal"),
            VersionError::NodeTierCrossOwner => f.write_str(
                "version: a cross-owner fork requires an account-tier forker (P-tier, ASN-0123)",
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
            SeatError::NotHomeLink => "seat: origin(link) is not this document (CL-OWN)",
            SeatError::AlreadySeated => "seat: the link is already seated in this document (CL-UNIQ)",
        })
    }
}
impl Error for SeatError {}
