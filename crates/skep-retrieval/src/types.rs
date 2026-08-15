//! §Public interface — the request and result value types, under the stated
//! derive policy (the marshaling seam M10 codes against).
//!
//! Every M6-owned request/result type here is a plain all-`pub`-field value
//! deriving **`Clone + PartialEq + Eq + Serialize`** — and nothing more. No
//! `Debug` on any type carrying `Address`/`Span`/`Val` (the declared policy;
//! `Val` carries no `Debug` at all, so `DeliveryItem` could not derive it
//! anyway). No `Deserialize` anywhere: M10 constructs requests through M1's
//! validating front doors (`validate`, `Span::new`/`from_endpoints`), never
//! by deserializing untrusted addresses. The two exceptions are
//! [`CorrPair`]/[`CompareReport`]: they carry M5's `VPos`, which declares no
//! serde or equality derives, so M6 declares none on them — they are
//! move-only, destructure-only values M10 marshals **field-by-field** (every
//! leaf still serializes individually, `VPos`'s `pub Nat` fields included).

use serde::Serialize;
use skep_address::{Address, Nat, Span};
use skep_arrangement::VPos;
use skep_content::Val;

/// One document + one ordinal-level depth-2 V-span — RETRIEVEV's ordered,
/// single-span idiom (ASN-0115: the spec-set is the ORDERED `&[Spec]`;
/// per-spec order is denotational, R5). The SET-shaped operations (COMPARE,
/// FINDDOCSCONTAINING) use [`Region`] instead.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Spec {
    pub doc: Address,
    pub span: Span,
}

/// One document + a finite V-region (set of spans) — the shared
/// "(document, span-set)" idiom for the two SET-shaped operations: COMPARE
/// (content only; the unordered set ASN-0122's `ρ` is) and FINDDOCSCONTAINING
/// (FD-CONVEX wants multi-span). Both take `&[Region]`.
#[derive(Clone, PartialEq, Eq, Serialize)]
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

/// RETRIEVEV's result: per-spec concatenation in submitted order,
/// ascending-V within each spec, no merge, no dedup, no global sort
/// (ASN-0115 R3/R5/R8).
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Delivery(pub Vec<DeliveryItem>);

/// SHOWDELETIONS' result (ASN-0075): each half is the deduped,
/// Tumbler-ordered set of I-addresses deleted-from-one document yet
/// current-in-the-other — the existing I-addresses themselves (D-IDENT),
/// never copies, T1-orderable (D-ORD).
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Deletions {
    /// Deleted from `d_a` ∧ current in `d_b`.
    pub a_with_b: Vec<Address>,
    /// Deleted from `d_b` ∧ current in `d_a`.
    pub b_with_a: Vec<Address>,
}

/// One COMPARE correspondence (ASN-0122): the two feet resolve to one shared
/// I-address run of `width` positions — slot 1 drawn from operand ρ₁, slot 2
/// from ρ₂ (X12). NO DERIVES (deliberate, derive policy above): carries M5's
/// `VPos`, whose as-given declaration names no equality/serde derives, so
/// this is a move-only, destructure-only value M10 marshals field-by-field.
pub struct CorrPair {
    pub d1: Address,
    pub u1: VPos,
    pub d2: Address,
    pub u2: VPos,
    pub width: Nat,
}

/// COMPARE's result: the complete, sound correspondence relation in
/// deterministic canonical order (ASN-0122 R1–R3; finer-than-maximal — X12 R4
/// is not required). NO DERIVES — see [`CorrPair`].
pub struct CompareReport(pub Vec<CorrPair>);
