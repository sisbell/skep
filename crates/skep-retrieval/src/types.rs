//! §Public interface — the request and result value types, under the stated
//! derive policy (the marshaling seam M10 codes against).
//!
//! Every M6-owned request/result type here is a plain all-`pub`-field value
//! carrying **`Clone + Debug + PartialEq + Eq`**, plus `Serialize` wherever
//! its leaves carry it. Two departures from the plain derive, each for a
//! reason its own leaf gives:
//!
//! * [`DeliveryItem`]'s `Debug` is hand-written, because M4's `Val` has none
//!   — blobs never render into logs, which is M4's decision. M6 is in the
//!   same position M4 put its own [`ContentWrite`] in, and keeps the
//!   discipline the same way: the item renders its payload's byte LENGTH and
//!   never its bytes, so the difficulty is absorbed here rather than exported
//!   to every caller that wants to log, `expect` or `assert_eq!` a delivery.
//! * [`CorrPair`]/[`CompareReport`] have no `Serialize`, because M5's `VPos`
//!   has none. They are destructure-and-marshal values M10 writes out
//!   **field-by-field** — every leaf serializes individually, `VPos`'s
//!   `pub Nat` fields included.
//!
//! NOTHING here derives `Deserialize`, and that one is M6's own decision
//! rather than a leaf's: M10 constructs requests through M1's validating front
//! doors (`validate`, `Span::new`/`from_endpoints`), so an untrusted address
//! reaches M6 only as a value some M1 constructor has already admitted.
//!
//! [`Delivery`] and [`CompareReport`] are COLLECTIONS, and behave like std's:
//! `len`/`is_empty`/`iter`/`as_slice`, `IntoIterator` owned and borrowed,
//! `FromIterator`, and `Default` for the empty answer each genuinely returns.
//! A reader walks an answer without naming its representation, which the
//! orphan rule would otherwise forbid a consumer from arranging for itself.
//! Not `Extend`: these are answers produced whole, never grown in place, and
//! the narrower promise is the honest one.
//!
//! [`ContentWrite`]: skep_content::ContentWrite

use std::fmt;

use serde::Serialize;
use skep_address::{Address, Nat, Span};
use skep_arrangement::VPos;
use skep_content::Val;

/// One document + one ordinal-level V-span of depth ≥ 2 — RETRIEVEV's
/// ordered, single-span idiom (ASN-0115: the spec-set is the ORDERED
/// `&[Spec]`; per-spec order is denotational, R5). Depth-COMPATIBILITY
/// (`#start == 2`) is consulting-state, not well-formedness, so a deeper
/// start is an admissible spec that resolves to ⟨⟩. The SET-shaped
/// operations (COMPARE, FINDDOCSCONTAINING) use [`RegionSpec`] instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Spec {
    pub doc: Address,
    pub span: Span,
}

/// One document + a finite set of V-spans — one member of the spec-set the
/// two SET-shaped operations take: COMPARE (content only; the `(dᵢ, Sᵢ)` of
/// ASN-0122's `ρ`) and FINDDOCSCONTAINING (FD-CONVEX wants multi-span). Both
/// take `&[RegionSpec]`.
///
/// It SPECIFIES part of a region; it is not one. The region `R_Σ(ρ)` is what
/// the spec-set denotes once each span is clipped against the document's
/// current arrangement — the thing COMPARE's report is confined to (X12 R1),
/// and the thing an empty resolution yields none of.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RegionSpec {
    pub doc: Address,
    pub spans: Vec<Span>,
}

/// One delivered item per active V-position (ASN-0115 R3 exactness): a
/// content position delivers its stored value (an `Arc` clone — cheap, never
/// a byte copy); a link position delivers the address-as-reference and never
/// reads M4.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum DeliveryItem {
    Content(Val),
    Ref(Address),
}

/// Renders a content item by its payload's BYTE LENGTH and a link item by its
/// address (M1's dotted decimal) — never a payload byte, which is the whole of
/// M4's reason for withholding `Debug` from `Val` and is kept here by hand
/// because a derive could not. Shape: `Content(n bytes)` / `Ref(c₁.….c_#t)`.
impl fmt::Debug for DeliveryItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeliveryItem::Content(v) => write!(f, "Content({} bytes)", v.len()),
            DeliveryItem::Ref(a) => write!(f, "Ref({a})"),
        }
    }
}

/// RETRIEVEV's result: per-spec concatenation in submitted order,
/// ascending-V within each spec, no merge, no dedup, no global sort
/// (ASN-0115 R3/R5/R8). `Default` is the empty delivery, which is the exact
/// answer to an empty spec-set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Delivery(pub Vec<DeliveryItem>);

impl Delivery {
    /// The delivered items, in delivery order.
    pub fn as_slice(&self) -> &[DeliveryItem] {
        &self.0
    }

    /// How many items were delivered — one per active V-position (R3).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether nothing was delivered: an empty spec-set, or one whose spans
    /// all resolved empty (R6).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrowed items in delivery order — the iterator `&Delivery` walks.
    pub fn iter(&self) -> std::slice::Iter<'_, DeliveryItem> {
        self.0.iter()
    }
}

impl IntoIterator for Delivery {
    type Item = DeliveryItem;
    type IntoIter = std::vec::IntoIter<DeliveryItem>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Delivery {
    type Item = &'a DeliveryItem;
    type IntoIter = std::slice::Iter<'a, DeliveryItem>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Collect AS GIVEN: the order a delivery is collected in IS its delivery
/// order (R5/R8 — no merge, no dedup, no sort).
impl FromIterator<DeliveryItem> for Delivery {
    fn from_iter<I: IntoIterator<Item = DeliveryItem>>(it: I) -> Delivery {
        Delivery(it.into_iter().collect())
    }
}

/// SHOWDELETIONS' result (ASN-0075): each half is the deduped,
/// Tumbler-ordered set of I-addresses deleted-from-one document yet
/// current-in-the-other — the existing I-addresses themselves (D-IDENT),
/// never copies, T1-orderable (D-ORD). `Default` is the two-empty-halves
/// answer two registered-empty documents genuinely yield.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Deletions {
    /// `DeletedFromAWithB` — `DELETED(a, d_a) ∧ CURRENT(a, d_b)`.
    pub deleted_from_a_with_b: Vec<Address>,
    /// `DeletedFromBWithA` — `DELETED(a, d_b) ∧ CURRENT(a, d_a)`.
    pub deleted_from_b_with_a: Vec<Address>,
}

/// One COMPARE correspondence (ASN-0122): the two feet resolve to one shared
/// I-address run of `width` positions — slot 1 drawn from operand ρ₁, slot 2
/// from ρ₂ (X12). NOT `Serialize` (derive policy above): it carries M5's
/// `VPos`, which is not, so M10 marshals this field-by-field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorrPair {
    pub d1: Address,
    pub u1: VPos,
    pub d2: Address,
    pub u2: VPos,
    /// How many consecutive positions the two feet share — at least ONE in
    /// every reported pair, since a correspondence is emitted only for a
    /// non-empty I-overlap. So expanding a pair into its `width` position
    /// pairs (X10) is a faithful re-reading of the report: no pair vanishes
    /// under the expansion.
    pub width: Nat,
}

/// COMPARE's result: the complete, sound correspondence relation in one
/// deterministic presentation (ASN-0122 R1–R3; finer-than-maximal — X12 R4's
/// canonical form is not required). NOT `Serialize` — see [`CorrPair`].
/// `Default` is the empty report two regions that share no address yield.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompareReport(pub Vec<CorrPair>);

impl CompareReport {
    /// The reported correspondences, in presentation order.
    pub fn as_slice(&self) -> &[CorrPair] {
        &self.0
    }

    /// How many correspondences were reported.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the two regions share no address at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrowed correspondences in presentation order — the iterator
    /// `&CompareReport` walks.
    pub fn iter(&self) -> std::slice::Iter<'_, CorrPair> {
        self.0.iter()
    }
}

impl IntoIterator for CompareReport {
    type Item = CorrPair;
    type IntoIter = std::vec::IntoIter<CorrPair>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a CompareReport {
    type Item = &'a CorrPair;
    type IntoIter = std::slice::Iter<'a, CorrPair>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Collect AS GIVEN — the presentation order is [`Query::compare`]'s to fix
/// (X12 R3), not this constructor's to impose.
///
/// [`Query::compare`]: crate::Query::compare
impl FromIterator<CorrPair> for CompareReport {
    fn from_iter<I: IntoIterator<Item = CorrPair>>(it: I) -> CompareReport {
        CompareReport(it.into_iter().collect())
    }
}
