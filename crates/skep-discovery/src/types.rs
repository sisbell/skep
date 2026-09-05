//! §Public interface — the request/result value types of the query surface:
//! the four-set descriptor request ([`SlotSpec`]/[`FourSet`], which reads its
//! own slots), the windowing pair ([`Cursor`]/[`Window`]), the lineage and
//! survival reports ([`SupClaim`]/[`OrphanReport`]), and the two typed
//! rejections ([`QueryError`] for the query surface, [`OrphanError`] for the
//! delete-orphan preview). M8 journals nothing, so none of these serialize.

use std::error::Error;
use std::fmt;

use skep_address::Address;
use skep_links::Endset;

use crate::helpers::home_of;
use crate::{FROM, TO, TYPE};

/// Per-slot request component for the four-set descriptor query — the
/// three-way distinction the conjunction needs (ASN-0121).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum SlotSpec {
    /// ∗ / NOSPECS — the unit: drops out of the conjunction (FL-WILD), and so
    /// the default: an unstated slot constrains nothing.
    #[default]
    Any,
    /// ∅ constrained-empty — the zero: annihilates the whole result (FL-EMP).
    Empty,
    /// Populated address-spans (M7's readable [`Endset`]). An EMPTY `Endset`
    /// is accepted and read as [`SlotSpec::Empty`] — the same zero
    /// ([`FourSet::is_unsatisfiable`] answers for both), so M7's `match_links`
    /// is never handed an empty constraint.
    Spans(Endset),
}

/// The four-set descriptor `q = (H, F, G, Θ)` (ASN-0121). `home` is matched
/// against `home(a)` — an M1 `document_of` address projection — NOT a slot
/// and NOT an arrangement-presence test (ASN-0132 CN-STAB: a reverse-orphaned
/// link still satisfies a home-bounded query).
///
/// `Eq`/`Hash` are REPRESENTATIONAL, not semantic: [`SlotSpec::Empty`] and a
/// `Spans` naming nothing are one query — [`FourSet::is_unsatisfiable`]
/// answers for both — and two distinct values, so a map keyed on a descriptor
/// holds two entries for that one query. A missed hit, never a wrong answer;
/// the semantic test is `is_unsatisfiable`, which reads the slots rather than
/// their spelling.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FourSet {
    pub home: SlotSpec,
    pub from: SlotSpec,
    pub to: SlotSpec,
    pub ty: SlotSpec,
}

impl FourSet {
    /// `(∗,∗,∗,∗)` — the UNIT descriptor (FL-WILD): every slot wildcard, so
    /// it matches the whole addressable slice. The counterpart to the zero
    /// [`FourSet::is_unsatisfiable`] answers for, and the base a narrowed
    /// query is built from: `FourSet { from: …, ..FourSet::any() }` names
    /// only the slots it constrains, so no slot is left at something other
    /// than the wildcard by accident.
    pub fn any() -> FourSet {
        FourSet {
            home: SlotSpec::Any,
            from: SlotSpec::Any,
            to: SlotSpec::Any,
            ty: SlotSpec::Any,
        }
    }

    /// FL-EMP: does some slot carry the zero — an explicit
    /// [`SlotSpec::Empty`], or a `Spans` that names nothing? Such a descriptor
    /// matches no link whatever the other slots say.
    ///
    /// This is what separates the two zeros ASN-0132 keeps apart: a `0` from
    /// [`crate::count_ftt_on`] over a satisfiable descriptor asserts that no
    /// addressable link satisfies `q` (CN-ZERO), while a `0` over an
    /// unsatisfiable one says only that the REQUEST names nothing. Same
    /// number, different assertion — and this answers the second off the
    /// descriptor's own slots, with no store read at all.
    pub fn is_unsatisfiable(&self) -> bool {
        [&self.home, &self.from, &self.to, &self.ty]
            .into_iter()
            .any(|s| match s {
                SlotSpec::Any => false,
                SlotSpec::Empty => true,
                SlotSpec::Spans(e) => e.is_empty(),
            })
    }

    /// The constrained LINK slots as M7's AND-of-ORs takes them (FL-WILD: an
    /// `Any` slot is omitted, never handed over as an empty constraint), or
    /// `None` when the descriptor is unsatisfiable.
    ///
    /// The zero and the constraint list are answered together because they
    /// are read off the same four slots: a slot carrying `Empty` has no
    /// endset to hand M7, so a list built without first asking
    /// [`FourSet::is_unsatisfiable`] would drop that slot exactly as it drops
    /// `Any` and silently widen the query. Every endset in a `Some` list is
    /// non-empty.
    ///
    /// ORDERED SMALLEST FIRST, which is a cost decision and not a semantic
    /// one: M7 drives one whole-store scan with the FIRST constraint and
    /// narrows the survivors with the rest, at `|query spans| × |slot spans|`
    /// per link tested, so the conjunct that pays the store-sized factor
    /// should be the cheapest one to test. An AND is order-free, so this
    /// moves work and never the answer — and the sort is stable, so equal
    /// spellings keep FROM/TO/TYPE order and one descriptor still names one
    /// constraint list.
    pub(crate) fn link_constraints(&self) -> Option<Vec<(usize, &Endset)>> {
        if self.is_unsatisfiable() {
            return None;
        }
        let mut constraints = Vec::new();
        for (slot, spec) in [(FROM, &self.from), (TO, &self.to), (TYPE, &self.ty)] {
            if let SlotSpec::Spans(e) = spec {
                constraints.push((slot, e)); // e non-empty: a satisfiable descriptor has no empty Spans
            }
        }
        constraints.sort_by_key(|(_, e)| e.len());
        Some(constraints)
    }

    /// `athome(a, H)` — ASN-0121/0132's residence test, the companion of
    /// `touch`: does the home slot admit the link at `a`? `Any` admits every
    /// link (FL-WILD); a `Spans` admits those whose `home(a)` its coverage
    /// names — an ADDRESS projection, never an arrangement-presence test
    /// (CN-STAB: a reverse-orphaned link still satisfies a home-bounded
    /// query); and the zero admits none, which is FL-EMP for the home slot.
    ///
    /// Crate-internal because it reads `home(a)` unconditionally, which every
    /// LINK address has: the addresses reaching it come off M7's
    /// `match_links` and are keys of the link store by construction.
    pub(crate) fn at_home(&self, a: &Address) -> bool {
        match &self.home {
            SlotSpec::Any => true,
            SlotSpec::Empty => false,
            SlotSpec::Spans(h) => h.covers(home_of(a).tumbler()),
        }
    }
}

/// `FourSet::default()` IS [`FourSet::any()`] — the unit descriptor, so
/// `FourSet { from: …, ..Default::default() }` reads as the wildcard base it
/// is. The domain name carries the doc; this is the std spelling of it.
impl Default for FourSet {
    fn default() -> FourSet {
        FourSet::any()
    }
}

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
/// The windowing operations RETURN values with three relations among those
/// fields — `batch` in ascending address order; `next` the ≺-max of the
/// batch, else the cursor unchanged; `exhausted` iff the batch is shorter
/// than the `n` asked for, which is the terminal signal (W9). Those are
/// postconditions of `window_v_on`/`window_ftt_on`, so a value that came
/// from either holds them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Window {
    pub batch: Vec<Address>,
    pub next: Cursor,
    pub exhausted: bool,
}

/// One supersession claim from the archival lineage (ASN-0125 EL11b), read
/// off M7's FLIPPED storage convention: `old` = the FROM slot (superseded),
/// `new` = the TO slot (superseding). `home` is the pure M1 `document_of`
/// attribution (EL8b).
///
/// `active` is the CLAIM's own — M7's `is_active(claim)`, so a claim may be
/// disclosed from the Audit view yet itself nullified. `old` and `new` carry
/// no such flag: they are the addresses the claim names, read out as
/// recorded, and either may itself be a nullified link.
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

/// The typed rejection of the QUERY surface — the region and pointwise
/// families. Exactly these five can arise there, so a caller matching them
/// exhaustively writes no unreachable arm; the delete-orphan preview refuses
/// on its own preconditions and carries its own [`OrphanError`].
///
/// The last two are M8's own BUDGET refusals, and they are refusals rather
/// than truncations for the reason every read here exists: a short answer
/// silently drops links, and a caller cannot tell a short answer from a true
/// one. A caller past a budget splits the request.
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
    /// `a ∉ dom(L)` — or, on `project` only, an out-of-range slot (M7's
    /// `followlink` conflates the two; the `BadSlot` split is deferred).
    NotALink,
    /// Some span of the region is not the shape [`crate::content_vspan`]
    /// builds — rejected up front so M5's silent clipping never turns the
    /// request into a different query. A caller that builds its region
    /// through that constructor cannot provoke this.
    BadRegion,
    /// The request names more arrangement I-runs than
    /// [`crate::MAX_IMAGE_RUNS`]: a region whose image is past the budget, or
    /// — on the two pointwise reads, where the runs are `ran(M(d))` — a `d`
    /// whose whole arrangement is. The runs are the side of a join the
    /// request supplies; what they are joined against is the world's.
    ImageTooLarge,
    /// The RETRIEVEENDSETS answer would carry more spans than
    /// [`crate::MAX_ENDSET_SPANS`]. The one budget here priced on what the
    /// store hands back rather than on what the request names.
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
                "query: the arrangement runs the request would materialize are past the run budget"
            }
            QueryError::EndsetsTooLarge => {
                "query: the endsets touching the region are past the answer's span budget"
            }
        })
    }
}
impl Error for QueryError {}

/// The typed rejection of the `delete_orphans` preview: four verdicts drawn
/// from M5's `DeleteError` at M5's own granularity, so the refusal is
/// actionable. `OutOfBounds` folds M5's `NotArranged` and `OutOfBounds` into
/// one (§6 states where the two vocabularies label one refusal differently),
/// and M5's `NotOwner` has no counterpart here at all — the preview takes no
/// `Caller`, so ownership is not its word to speak.
///
/// Exhaustively matchable from outside the crate, and promised so, for the
/// reason [`QueryError`] states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrphanError {
    /// `d` is not a registered document (M3). A registered-but-empty `d` is
    /// refused too, but for range — `EmptyWidth` at width 0 and
    /// `OutOfBounds` otherwise, since `n_C = 0` admits no range — so what
    /// this variant buys a caller is WHICH fault is named, as M5's DELETE
    /// likewise refuses every request on an empty document.
    DocNotRegistered,
    /// `p.subspace ≠ s_C` (mirror of M5's variant).
    NotContentSubspace,
    /// `width = 0` (mirror of M5's variant).
    EmptyWidth,
    /// Out-of-range `(p, width)` — folds M5's `NotArranged` (start outside
    /// the arranged content) and `OutOfBounds` (range overrun).
    OutOfBounds,
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
        })
    }
}
impl Error for OrphanError {}
