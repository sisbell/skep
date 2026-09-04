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
//! [`ContentWrite`]: skep_content::ContentWrite

use std::fmt;

use serde::Serialize;
use skep_address::{Address, Nat, Span};
use skep_arrangement::VPos;
use skep_content::Val;

/// One document + one ordinal-level depth-2 V-span — RETRIEVEV's ordered,
/// single-span idiom (ASN-0115: the spec-set is the ORDERED `&[Spec]`;
/// per-spec order is denotational, R5). The SET-shaped operations (COMPARE,
/// FINDDOCSCONTAINING) use [`Region`] instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Spec {
    pub doc: Address,
    pub span: Span,
}

/// One document + a finite V-region (set of spans) — the shared
/// "(document, span-set)" idiom for the two SET-shaped operations: COMPARE
/// (content only; the unordered set ASN-0122's `ρ` is) and FINDDOCSCONTAINING
/// (FD-CONVEX wants multi-span). Both take `&[Region]`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Region {
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
/// (ASN-0115 R3/R5/R8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Delivery(pub Vec<DeliveryItem>);

/// SHOWDELETIONS' result (ASN-0075): each half is the deduped,
/// Tumbler-ordered set of I-addresses deleted-from-one document yet
/// current-in-the-other — the existing I-addresses themselves (D-IDENT),
/// never copies, T1-orderable (D-ORD).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Deletions {
    /// Deleted from `d_a` ∧ current in `d_b`.
    pub a_with_b: Vec<Address>,
    /// Deleted from `d_b` ∧ current in `d_a`.
    pub b_with_a: Vec<Address>,
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
    pub width: Nat,
}

/// COMPARE's result: the complete, sound correspondence relation in
/// deterministic canonical order (ASN-0122 R1–R3; finer-than-maximal — X12 R4
/// is not required). NOT `Serialize` — see [`CorrPair`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompareReport(pub Vec<CorrPair>);
