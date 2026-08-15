//! §Public interface — the request/result value types of the query surface:
//! the four-set descriptor request ([`SlotSpec`]/[`FourSet`]), the windowing
//! pair ([`Cursor`]/[`Window`]), the lineage and survival reports
//! ([`SupClaim`]/[`OrphanReport`]), and the one typed rejection
//! ([`QueryError`]). M8 journals nothing, so none of these serialize.

use std::error::Error;
use std::fmt;

use skep_address::Address;
use skep_links::Endset;

/// Per-slot request component for the four-set descriptor query — the
/// three-way distinction the conjunction needs (ASN-0121).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotSpec {
    /// ∗ / NOSPECS — the unit: drops out of the conjunction (FL-WILD).
    Any,
    /// ∅ constrained-empty — the zero: annihilates the whole result (FL-EMP).
    Empty,
    /// Populated address-spans (M7's readable [`Endset`]); MUST be NON-EMPTY —
    /// an empty `Endset` is normalized onto the `Empty`/zero path (M7 forbids
    /// an empty `match_links` endset).
    Spans(Endset),
}

/// The four-set descriptor `q = (H, F, G, Θ)` (ASN-0121). `home` is matched
/// against `home(a)` — an M1 `document_of` address projection — NOT a slot
/// and NOT an arrangement-presence test (ASN-0132 CN-STAB: a reverse-orphaned
/// link still satisfies a home-bounded query).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FourSet {
    pub home: SlotSpec,
    pub from: SlotSpec,
    pub to: SlotSpec,
    pub ty: SlotSpec,
}

/// Windowing cursor (ASN-0108 W2/W3): `None` = ⊥ (start); `Some(a)` = resume
/// strictly past `a`. The cursor is a permanent link ADDRESS — the whole
/// continuation is this value, held by the client; there is no server
/// iterator and no cached list.
pub type Cursor = Option<Address>;

/// One window of an enumeration (ASN-0108): `batch` in ascending address
/// order; `next` resumes (the ≺-max of the batch, else the cursor unchanged);
/// `exhausted` — a batch shorter than `n` — is the terminal signal (W9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Window {
    pub batch: Vec<Address>,
    pub next: Cursor,
    pub exhausted: bool,
}

/// One supersession claim from the archival lineage (ASN-0125 EL11b), read
/// off M7's FLIPPED storage convention: `old` = the FROM slot (superseded),
/// `new` = the TO slot (superseding). `home` is the pure M1 `document_of`
/// attribution (EL8b); `active` is M7's `is_active(claim)` — a claim may be
/// disclosed from the Audit view yet itself nullified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupClaim {
    pub claim: Address,
    pub old: Address,
    pub new: Address,
    pub home: Address,
    pub active: bool,
}

/// The pre-edit survival report (ASN-0117): the links the proposed DELETE
/// would drop from `d` — the PER-DOCUMENT orphan set over the ACTIVE view (a
/// nullified link that lost its last witness in `d` is NOT reported). The
/// global-ghost / LP17 escalation is M6 territory, not computed here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrphanReport {
    pub orphaned: Vec<Address>,
}

/// The one typed rejection of the query surface. The first three arise on the
/// region/pointwise families; the last three only on the `delete_orphans`
/// preview, mirroring M5's `DeleteError` granularity so the rejection is
/// actionable (`OutOfBounds` deliberately folds M5's `NotArranged` +
/// `OutOfBounds` — jointly equivalent under the width ≥ 1 guard, §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryError {
    /// `d` is not a registered document (M3) — distinct from a
    /// registered-but-empty `d`, which yields a defined empty result.
    DocNotRegistered,
    /// `a ∉ dom(L)` — or, on `project` only, an out-of-range slot (M7's
    /// `followlink` conflates the two; the `BadSlot` split is deferred).
    NotALink,
    /// The region is not content-subspace, ordinal-level, depth-2 V-spans
    /// (`start[1] = s_C = 1`, `width[1] = 0`) — rejected up front so M5's
    /// silent clipping never turns the request into a different query.
    BadRegion,
    /// `delete_orphans`: `p.subspace ≠ s_C` (mirror of M5's variant).
    NotContentSubspace,
    /// `delete_orphans`: `width = 0` (mirror of M5's variant).
    EmptyWidth,
    /// `delete_orphans`: out-of-range `(p, width)` — folds M5's `NotArranged`
    /// (start beyond the arranged run) and `OutOfBounds` (range overrun).
    OutOfBounds,
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            QueryError::DocNotRegistered => "query: d is not a registered document",
            QueryError::NotALink => "query: the address is not a resident link (or the slot is out of range)",
            QueryError::BadRegion => {
                "query: the region is not content-subspace ordinal-level depth-2 V-spans"
            }
            QueryError::NotContentSubspace => {
                "delete-orphans: p.subspace is not the content subspace s_C"
            }
            QueryError::EmptyWidth => "delete-orphans: width must be ≥ 1",
            QueryError::OutOfBounds => {
                "delete-orphans: the range is outside the arranged content (p < 1 or p + width > n_C + 1)"
            }
        })
    }
}
impl Error for QueryError {}
