//! §Public interface — the plain values the reads take and return: the
//! windowing pair ([`Cursor`]/[`Window`]), the lineage and survival reports
//! ([`SupClaim`]/[`OrphanReport`]), and the two typed rejections
//! ([`QueryError`] for the query surface, [`OrphanError`] for the
//! delete-orphan preview). M8 journals nothing, so none of these serialize.
//! The four-set request, whose slots carry the descriptor family's logic,
//! lives with that family in `descriptor`.

use std::error::Error;
use std::fmt;

use skep_address::Address;

/// Windowing cursor (ASN-0108 W2/W3): `None` = ⊥ (start); `Some(a)` = resume
/// strictly past `a`. The whole continuation is this value, held by the
/// client; there is no server iterator and no cached list.
///
/// In ordinary use `a` is the ≺-max of a previous batch — a permanent link
/// address — but the windowing operations require nothing of it: any
/// `Address` resumes, because the cut is by key rather than by lookup. Each
/// states that where a caller meets it.
pub type Cursor = Option<Address>;

/// One window of an enumeration (ASN-0108). A plain record: its fields are
/// public and independent, and a caller may build one freely.
///
/// The windowing operations RETURN values that satisfy these relations,
/// where `n′ = max(n, 1)` is what the `n` asked for is clamped to (W9):
///
/// * `batch` is the first `min(n′, k)` links, in ascending address order, of
///   the read's answer strictly past the cursor, `k` being how many remain —
///   so it never holds more than `n′`;
/// * `next` is the ≺-max of the batch, or the cursor unchanged if the batch
///   is empty;
/// * `exhausted` holds iff `batch.len() < n′`, the terminal signal.
///
/// They are stated against `n′`, not the `n` asked for: at `n = 0` a window
/// holds at most one link, and an empty one reports exhaustion — the terminal
/// signal the clamp exists to keep. They are postconditions of
/// [`crate::window_v_on`]/[`crate::window_ftt_on`], not properties of this
/// type.
///
/// A PASS — windows drained from `None` to `exhausted`, each at its own
/// state — returns every link that matches throughout it, under one
/// predicate held fixed, exactly once (W4/W5). A link that begins to match
/// during the pass is returned only if it sorts past the cursor at the
/// moment it begins to match. Link addresses grow within a home but not
/// across homes, so a link minted mid-pass in a home that sorts behind the
/// cursor is not returned by that pass.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Window {
    pub batch: Vec<Address>,
    pub next: Cursor,
    pub exhausted: bool,
}

/// One supersession claim from the archival lineage (ASN-0125 EL11b): `old`
/// is the link it records as superseded and `new` the link it records as
/// superseding. Which stored slot holds which endpoint is M7's convention,
/// stated on its `assert_sup`; this record carries the endpoints and never
/// the slots. `home` is the pure M1 `document_of` attribution (EL8b).
///
/// `active` is the CLAIM's own — M7's `is_active(claim)`, so a claim may be
/// disclosed from the Audit view yet itself nullified. `old` and `new` carry
/// no such flag: they are the addresses the claim names, read out as
/// recorded, and either may itself be a nullified link.
///
/// A plain record: its fields are public and a caller may build one freely,
/// so none of the relations above is a property of this type. They are
/// postconditions of the reads that return one: a claim
/// [`crate::in_claims_on`] returns for `y` has `old = y`, one
/// [`crate::out_claims_on`] returns for `x` has `new = x`, and each has
/// `old`/`new` the superseded and superseding links its stored tuple records,
/// `home = document_of(claim)` and `active = is_active(claim)` at the read's
/// snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
///
/// A plain record: `orphaned` is public and a caller may build one freely.
/// A report RETURNED by [`crate::delete_orphans_on`] carries it in ascending
/// address order — the same permanent key every enumeration here reads out
/// by, and a postcondition of that function rather than a property of this
/// type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OrphanReport {
    pub orphaned: Vec<Address>,
}

/// The typed rejection of the QUERY surface — the region family and the
/// pointwise pair. Exactly these five arise on the surface as a whole, so a
/// caller matching the whole surface — as M10's lowering does — writes no
/// unreachable arm. Each read states which of them it raises, and a match
/// over one read's result carries the rest as unreachable arms. The
/// delete-orphan preview refuses on its own preconditions and carries its
/// own [`OrphanError`].
///
/// The last two are M8's own BUDGET refusals, and they are refusals rather
/// than truncations for the reason every read here exists: a short answer
/// silently drops links, and a caller cannot tell a short answer from a true
/// one. Each is permanent for the request that drew it (M10 lowers both as
/// `Permanent`); whether a caller can reshape its way past one depends on
/// the read:
///
/// * a region-family `ImageTooLarge` splits: the budgets are per call, so
///   the region can be asked in parts, down to single positions, and the
///   parts recomposed by UNION — a count by counting the union, never by
///   adding counts. A single position is refused only over a reading surface
///   of more than `MAX_IMAGE_RUNS²` content runs;
/// * a pointwise `ImageTooLarge` — a fact about `d`'s runs and `a`'s
///   coverage — and an `EndsetsTooLarge` over one position do not: those
///   questions cannot be answered through this surface at this state.
///
/// **The exhaustiveness is promised, not merely current.** A downstream match
/// over these variants is a COMPLETENESS check — M10 must give every refusal
/// a wire code, and a variant added here has to fail that build rather than
/// fall into a catch-all arm that ships some default. That is what a caller
/// buys by matching without `_`, and it is why this enum is not sealed; the
/// suite matches it from outside the crate so the promise is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryError {
    /// `d` is not a registered document (M3) — distinct from a
    /// registered-but-empty `d`, which yields a defined empty result.
    DocNotRegistered,
    /// `a ∉ dom(L)`. Two further cases answer the same. On both pointwise
    /// reads, a link homed in a document the reader may not read — absent to
    /// them (PUB-6.6), so it answers exactly as a non-link does. On
    /// [`crate::project_on`] alone, an out-of-range slot, which M7's
    /// `followlink` does not tell from a non-link (the `BadSlot` split is
    /// deferred).
    NotALink,
    /// Some span of the region is not the shape [`crate::content_vspan`]
    /// builds — rejected up front so M5's silent clipping never turns the
    /// request into a different query. A caller that builds its region
    /// through that constructor cannot provoke this.
    BadRegion,
    /// The read would materialize or join more arrangement I-runs than
    /// [`crate::MAX_IMAGE_RUNS`] admits, or exceed the product its own join is
    /// held to: the square for the run-list walk behind the region family and
    /// for the touch test of a link's whole coverage, and
    /// [`crate::MAX_ANSWER_SPANS`] for the projection. Each of the three reads
    /// that hold it counts the runs its own work multiplies, which the
    /// constant states. The runs are the side of a join the request supplies;
    /// what they are joined against is the world's.
    ImageTooLarge,
    /// The RETRIEVEENDSETS answer would carry more spans than
    /// [`crate::MAX_ANSWER_SPANS`] — the pairs the store hands back, not
    /// anything the request names, so a caller cannot reshape its way past
    /// it. [`crate::project_on`]'s product is held at the same number and
    /// raises `ImageTooLarge` instead, which is why that constant is the
    /// ANSWER's and not this variant's: two reads, two words, one budget.
    EndsetsTooLarge,
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            QueryError::DocNotRegistered => "query: d is not a registered document",
            QueryError::NotALink => "query: the address is not a resident link (or the slot is out of range)",
            QueryError::BadRegion => {
                "query: the region is not content-subspace ordinal-level depth-2 V-spans"
            }
            QueryError::ImageTooLarge => {
                "query: the arrangement runs the request would materialize or walk, or the product of the join against them, are past this read's budget"
            }
            QueryError::EndsetsTooLarge => {
                "query: the endsets touching the region are past the answer's span budget"
            }
        })
    }
}
impl Error for QueryError {}

/// The typed rejection of the `delete_orphans` preview: five verdicts, four
/// drawn from the seven of M5's `DeleteError`, at M5's own granularity, so
/// the refusal is actionable, and one M8's own. `OutOfBounds` folds M5's
/// `NotArranged` and `OutOfBounds` into one ([`crate::delete_orphans_on`]
/// states where the two vocabularies label one refusal differently). Of M5's
/// other two, `NotOwner` is absent by decision — the preview takes no
/// `Caller`, so ownership is not its word to speak — and `PublishedTarget` is
/// absent and OPEN: a published `d` is one M5 refuses and the preview answers
/// about, a gap [`crate::delete_orphans_on`] states rather than a rule it
/// keeps. `ImageTooLarge` is the one M5 has no word for, because DELETE stabs
/// nothing: what it prices is the preview's own work.
///
/// Exhaustively matchable from outside the crate, and promised so, for the
/// reason [`QueryError`] states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrphanError {
    /// `d` is not a registered document (M3). A registered-but-empty `d` is
    /// refused too, but for its request's shape — `NotContentSubspace` off
    /// `s_C`, then `EmptyWidth` at width 0, and `OutOfBounds` otherwise,
    /// since `n_C = 0` admits no range — so what this variant buys a caller
    /// is WHICH fault is named, as M5's DELETE likewise refuses every request
    /// on an empty document.
    DocNotRegistered,
    /// `p.subspace ≠ s_C` (mirror of M5's variant).
    NotContentSubspace,
    /// `width = 0` (mirror of M5's variant).
    EmptyWidth,
    /// Out-of-range `(p, width)` — folds M5's `NotArranged` (start outside
    /// the arranged content) and `OutOfBounds` (range overrun).
    OutOfBounds,
    /// The runs the preview's two stabs would join are past
    /// [`crate::MAX_IMAGE_RUNS`] — the query surface's run budget
    /// ([`QueryError::ImageTooLarge`]), held on the preview's own work and named
    /// as the query surface names it. [`crate::delete_orphans_on`] states which
    /// runs it counts, and so which documents and ranges it refuses.
    ImageTooLarge,
}

impl fmt::Display for OrphanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OrphanError::DocNotRegistered => "delete-orphans: d is not a registered document",
            OrphanError::NotContentSubspace => {
                "delete-orphans: p.subspace is not the content subspace s_C"
            }
            OrphanError::EmptyWidth => "delete-orphans: width must be ≥ 1",
            OrphanError::OutOfBounds => {
                "delete-orphans: the range is outside the arranged content (p < 1 or p + width > n_C + 1)"
            }
            OrphanError::ImageTooLarge => {
                "delete-orphans: the runs the preview would stab are past the run budget"
            }
        })
    }
}
impl Error for OrphanError {}
