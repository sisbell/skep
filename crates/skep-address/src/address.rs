//! §B/§C — validation, classification, field & containment projection, and
//! decomposition (ASN-0045; ASN-0034: T4/T4b, T6, T7).

use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

use crate::tumbler::{nat_is_zero, Nat, Tumbler};

/// The hierarchical level of a T4-valid address: zeros = 0/1/2/3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Level {
    Node,
    Account,
    Document,
    Element,
}

/// Total classification of an arbitrary carrier tumbler (ASN-0045): the four
/// levels plus the disjoint `Invalid` tag. A five-way sum, not four booleans:
/// Partition (exactly-one-level) and Off-Domain Vacuity hold *by construction*
/// because a function is single-valued and `Invalid` is a disjoint tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Class {
    Node,
    Account,
    Document,
    Element,
    Invalid,
}

/// The Partition embedding (`Class = Level ⊎ {Invalid}`): every level is a
/// class; only the classifier can answer `Invalid`.
impl From<Level> for Class {
    fn from(level: Level) -> Class {
        match level {
            Level::Node => Class::Node,
            Level::Account => Class::Account,
            Level::Document => Class::Document,
            Level::Element => Class::Element,
        }
    }
}

/// The four T4-validity clauses (T4): no leading zero (`t₁ ≠ 0`), no trailing
/// zero (`t_{#t} ≠ 0`), no adjacent zeros, and `zeros(t) ≤ 3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum T4Clause {
    LeadingZero,
    TrailingZero,
    AdjacentZeros,
    OverDepth,
}

impl fmt::Display for T4Clause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            T4Clause::LeadingZero => "LeadingZero",
            T4Clause::TrailingZero => "TrailingZero",
            T4Clause::AdjacentZeros => "AdjacentZeros",
            T4Clause::OverDepth => "OverDepth",
        })
    }
}

/// [`validate`] rejection: the violated T4 clause(s) ONLY — it does NOT carry
/// the rejected `Tumbler` (interface contract: a caller that needs the input
/// back must clone before calling).
///
/// OPEN DECISION (design: "first-failure vs full-set"): carries the **full
/// set** of violated clauses, each at most once, in `T4Clause` declaration
/// order — the conservative, information-preserving reading of "clause(s)"
/// (clauses co-occur: `[0]` violates both `LeadingZero` and `TrailingZero`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct T4Error {
    clauses: Vec<T4Clause>,
}

impl T4Error {
    /// The violated clauses, in `T4Clause` declaration order, each at most
    /// once — read-only, so a rejection can only be raised by the validator
    /// that found the violations, never assembled by a caller.
    pub fn clauses(&self) -> &[T4Clause] {
        &self.clauses
    }
}

impl fmt::Display for T4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tumbler is not T4-valid; violated clause(s):")?;
        for (i, c) in self.clauses.iter().enumerate() {
            if i > 0 {
                write!(f, ",")?;
            }
            write!(f, " {c}")?;
        }
        Ok(())
    }
}
impl Error for T4Error {}

/// The T4 reading of a carrier tumbler: how many separators it has, and which
/// clauses it violates. Four projections hang off one reading — the count, the
/// verdict, the class, and the admission — so none of them decides admission
/// again on its own.
struct T4Scan {
    zeros: usize,
    clauses: Vec<T4Clause>,
}

impl T4Scan {
    /// The level this reading admits, or `None` when a clause was violated —
    /// the one place T4 admission and level determination are decided
    /// together, so [`classify`] and the `level` an [`Address`] carries cannot
    /// disagree.
    fn admitted_level(&self) -> Option<Level> {
        self.clauses.is_empty().then(|| level_of_zeros(self.zeros))
    }
}

/// One fused left-to-right O(#t) scan with O(1) carried state (design §2):
/// the separator count plus all four T4 clauses in a single pass — a *scan,
/// not a parse*, cheap because it streams, not because the input is bounded.
/// The count is `usize`, unbounded per T0(b): garbage with hundreds of zeros
/// classifies Invalid, never wraps, never faults. No early exit — `zeros(t)`
/// must report the true count.
fn t4_scan(t: &Tumbler) -> T4Scan {
    let comps = t.comps();
    let mut zero_count = 0usize;
    let mut adjacent_zeros = false;
    let mut prev_zero = false;
    for c in comps {
        if nat_is_zero(c) {
            if prev_zero {
                adjacent_zeros = true;
            }
            zero_count += 1;
            prev_zero = true;
        } else {
            prev_zero = false;
        }
    }
    let mut clauses = Vec::new();
    if nat_is_zero(&comps[0]) {
        clauses.push(T4Clause::LeadingZero);
    }
    if nat_is_zero(&comps[comps.len() - 1]) {
        clauses.push(T4Clause::TrailingZero);
    }
    if adjacent_zeros {
        clauses.push(T4Clause::AdjacentZeros);
    }
    if zero_count > 3 {
        clauses.push(T4Clause::OverDepth);
    }
    T4Scan {
        zeros: zero_count,
        clauses,
    }
}

/// Separator (zero-component) count of a **carrier** tumbler — what T4's
/// `zeros(t) ≤ 3` clause reads, and what a caller holding a tumbler that may
/// not be an address needs (a span endpoint, a displacement, a V-spec whose
/// zero-freeness is being checked).
///
/// NOT the way to ask an `Address` for its level. `level_of_zeros` is the one
/// place the count↔level map lives, and an `Address` has already been through
/// it: [`Address::level`] is that answer, carried on the value, in the level
/// vocabulary, with no second pass. `zeros(a.tumbler()) == 1` is
/// `a.level() == Level::Account` spelled in the implementation's terms — the
/// spelling that goes silently wrong if the encoding ever moves, because
/// nothing at the call site relates the numeral to the level.
///
/// UNBOUNDED per T0(b): `usize`, never `u8` (a fixed-width counter could wrap
/// a 259-zero count to 3 and mis-read garbage as Element).
pub fn zeros(t: &Tumbler) -> usize {
    t4_scan(t).zeros
}

/// T4 well-formedness: all four clauses hold. The depth ceiling and every
/// T6/T7 field-read rest entirely on the `zeros ≤ 3` clause checked here —
/// the only thing stopping a four-separator tumbler from being read as a
/// phantom fifth level.
pub fn is_t4_valid(t: &Tumbler) -> bool {
    t4_scan(t).admitted_level().is_some()
}

fn level_of_zeros(z: usize) -> Level {
    match z {
        0 => Level::Node,
        1 => Level::Account,
        2 => Level::Document,
        3 => Level::Element,
        _ => unreachable!("T4-valid tumblers have zeros ≤ 3"),
    }
}

/// Total classifier (ASN-0045): never faults; garbage yields `Class::Invalid`
/// — bare, no clause (the total form needs only the tag; diagnostics belong
/// to [`validate`]). Membership of the level in {0,1,2,3} comes from the
/// arithmetic bound `zeros ≤ 3`, never from a level-name bijection.
pub fn classify(t: &Tumbler) -> Class {
    t4_scan(t)
        .admitted_level()
        .map_or(Class::Invalid, Class::from)
}

/// Admission constructor — the validate-and-classify front door, one fused
/// scan (design §2). CONSUMES `t`; on the error path the input is dropped and
/// [`T4Error`] carries only the violated clause(s) — clone before calling if
/// you need the rejected tumbler back.
pub fn validate(t: Tumbler) -> Result<Address, T4Error> {
    let scan = t4_scan(&t);
    let admitted = scan.admitted_level();
    match admitted {
        Some(level) => Ok(Address { tumbler: t, level }),
        None => Err(T4Error {
            clauses: scan.clauses,
        }),
    }
}

/// A T4-valid, classified tumbler — the recommended hybrid representation.
///
/// INVARIANT: every `Address` is T4-valid. Discharged at each mint site:
/// *checked* by [`validate`] and [`crate::elem_addr`], *preserved* by
/// [`parent`], [`document_of`], and [`crate::checked_inc`], and *re-checked*
/// at the deserialization boundary (the validating `Deserialize` routes
/// through `validate` and re-derives `level`).
///
/// `level` is a **derived constant** on an immutable value — a standing fact,
/// never a stale-able cache (ASN-0045 level stability). Serde: serializes as
/// its **bare tumbler** (`level` is never persisted; journal entries stay
/// flat tumblers exactly as the data model prescribes) and deserializes
/// through `validate`, so a stored level can never disagree with
/// [`classify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "Tumbler", try_from = "Tumbler")]
pub struct Address {
    tumbler: Tumbler,
    level: Level,
}

/// Identity is the tumbler (T3): `level` is a function of it and cannot
/// disagree, so hashing the tumbler alone is consistent with `Eq` — and says
/// in the impl what identity an `Address` has, which a derive would leave to
/// the field list.
impl Hash for Address {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.tumbler.hash(state);
    }
}

/// An address renders as its tumbler — dotted decimal (T3): `level` is
/// derived and never shown, because the tumbler already determines it.
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.tumbler.fmt(f)
    }
}

/// The tumbler order (T1), delegating to `Tumbler::cmp` — `level` plays no
/// part (it is a function of the tumbler and cannot disagree). Lets M3's
/// frontier comparisons and M8's identity-ordered cursors order addresses
/// directly, with no `.tumbler()` detour.
impl Ord for Address {
    fn cmp(&self, other: &Address) -> std::cmp::Ordering {
        self.tumbler.cmp(&other.tumbler)
    }
}

/// Delegates to [`Ord`] (Ord/PartialOrd consistency).
impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Address) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Serialization shadow: an `Address` journals as its bare, flat `Tumbler`.
impl From<Address> for Tumbler {
    fn from(a: Address) -> Tumbler {
        a.tumbler
    }
}

/// Deserialization mint path (the serde `try_from` shadow): re-validates and
/// re-derives `level` — no unguarded mint on journal replay.
impl TryFrom<Tumbler> for Address {
    type Error = T4Error;
    fn try_from(t: Tumbler) -> Result<Address, T4Error> {
        validate(t)
    }
}

impl Address {
    /// The underlying flat tumbler — the storage/journal key form.
    pub fn tumbler(&self) -> &Tumbler {
        &self.tumbler
    }

    /// The derived hierarchical level (ASN-0045 level stability) — the
    /// standing answer to every level question about this address: which level
    /// it is, whether it is one of a set of levels, whether it agrees with
    /// another address's. Nothing holding an `Address` needs to count
    /// separators to ask any of them; [`zeros`] is for carrier tumblers that
    /// have never been through the classifier.
    pub fn level(&self) -> Level {
        self.level
    }

    /// 0-based index of the `n`-th separator (zero) component, `n` 1-based to
    /// match the field numbering; `None` when fewer than `n` separators
    /// exist. `n ≥ 1` is the caller's obligation — `n = 0` is not a question
    /// about a 1-based numbering, and the debug assertion says so rather than
    /// letting it wrap into a `None` that reads as "no such separator". The
    /// single spelling of "where does a field begin" — every field projection
    /// and every truncation below reads through it. Recomputed on demand and
    /// allocation-free: `#t` is small, and the design defers any parsed-field
    /// hint until a containment path proves hot.
    fn separator(&self, n: usize) -> Option<usize> {
        debug_assert!(n >= 1, "separator numbering is 1-based");
        self.tumbler
            .comps()
            .iter()
            .enumerate()
            .filter(|&(_, c)| nat_is_zero(c))
            .map(|(i, _)| i)
            .nth(n - 1)
    }

    /// The field between the `n`-th separator (1-based) and the next
    /// separator or the end; `None` when fewer than `n` separators exist
    /// (T4b: present-or-absent is encoded by `Option`, never a sentinel).
    fn field(&self, n: usize) -> Option<&[Nat]> {
        let start = self.separator(n)? + 1;
        let end = self.separator(n + 1).unwrap_or(self.tumbler.len());
        Some(&self.tumbler.comps()[start..end])
    }

    /// T4b `N` — always present: the components before the first separator.
    pub fn node_field(&self) -> &[Nat] {
        let comps = self.tumbler.comps();
        &comps[..self.separator(1).unwrap_or(comps.len())]
    }

    /// T4b `U` — `Some` iff zeros ≥ 1.
    pub fn account_field(&self) -> Option<&[Nat]> {
        self.field(1)
    }

    /// T4b `D` — `Some` iff zeros ≥ 2 (the full document field, version
    /// components included).
    pub fn document_field(&self) -> Option<&[Nat]> {
        self.field(2)
    }

    /// T4b `E` — `Some` iff zeros = 3 (T4 caps zeros at 3, so ≥ 3 ⟺ = 3);
    /// nonempty for a valid address (no trailing zero).
    pub fn element_field(&self) -> Option<&[Nat]> {
        self.field(3)
    }

    /// `element_field[0]` (T7): which subspace the element sits in —
    /// [`content_subspace`] or [`link_subspace`], disjoint by `1 < 2` at this
    /// position, so nothing has to enforce the separation. The index is total:
    /// T4's no-trailing-zero clause makes a present element field nonempty. A
    /// borrow into the address's own components, like every other field
    /// projection: routing an element is a comparison, and a comparison need
    /// not allocate.
    pub fn subspace(&self) -> Option<&Nat> {
        self.element_field().map(|e| &e[0])
    }

    /// The `N·0·U·0·D` component prefix — where a document's subtree begins;
    /// `None` when zeros < 2. The address form is [`document_of`]; this is
    /// the same knowledge without the mint, for callers that only compare.
    fn document_prefix(&self) -> Option<&[Nat]> {
        let comps = self.tumbler.comps();
        match self.level {
            Level::Node | Level::Account => None,
            Level::Document => Some(comps),
            Level::Element => Some(
                &comps[..self
                    .separator(3)
                    .expect("an Element address has three separators")],
            ),
        }
    }
}

/// T7's **content** subspace: the numeral `1` at `element_field[0]` (the
/// spec's *text* subspace, and the system's content subspace — M4's store,
/// M5's content runs, the content side of M6/M7 routing). M1 owns T7, so the
/// numeral that decides content-from-link is named here rather than restated
/// wherever an element is routed.
pub fn content_subspace() -> Nat {
    Nat::from(1u32)
}

/// T7's **link** subspace: the numeral `2` at `element_field[0]`. The two
/// subspaces are named values rather than a closed sum because T7 leaves the
/// link subspace open to further subdivision — an element field T4b admits
/// may carry a numeral matching neither.
pub fn link_subspace() -> Nat {
    Nat::from(2u32)
}

/// T6(a): `N(a) = N(b)` — decidable from the two addresses alone
/// (`tumbleraccounteq`-style truncate-and-compare; the basis of
/// coordination-free operation).
pub fn same_node(a: &Address, b: &Address) -> bool {
    a.node_field() == b.node_field()
}

/// T6(b): zeros ≥ 1 on BOTH ∧ N, U equal. FIELD-ABSENCE ⇒ NO: if either
/// operand lacks an account field the answer is `false` — never
/// `None == None ⇒ true` (two Node addresses do NOT report "same account").
pub fn same_account(a: &Address, b: &Address) -> bool {
    match (a.account_field(), b.account_field()) {
        (Some(ua), Some(ub)) => same_node(a, b) && ua == ub,
        _ => false,
    }
}

/// T6(c): zeros ≥ 2 on BOTH ∧ N, U, D equal (field-absence ⇒ NO).
pub fn same_document(a: &Address, b: &Address) -> bool {
    match (a.document_field(), b.document_field()) {
        (Some(da), Some(db)) => same_account(a, b) && da == db,
        _ => false,
    }
}

/// T6(d): zeros ≥ 2 on BOTH ∧ `a` lies under `b`'s document prefix
/// `N·0·U·0·D` (field-absence ⇒ NO). This is the *containment* projection:
/// the document field records who allocated under whom, NOT what was copied
/// from what — derivation history is a separate version graph (M3/M5),
/// explicitly not M1's.
pub fn under_document(a: &Address, b: &Address) -> bool {
    if !matches!(a.level(), Level::Document | Level::Element) {
        return false; // zeros ≥ 2 is required on BOTH operands; this is a's side
    }
    match b.document_prefix() {
        // A predicate compares; it does not mint. Reading the prefix in place
        // costs one slice comparison and no allocation, which is what makes
        // "decidable from the two addresses alone" cheap as well as true.
        Some(p) => a.tumbler().comps().starts_with(p),
        None => false, // b's side: zeros(b) < 2
    }
}

/// §C — the longest T4-valid proper prefix: drop the last component and, if
/// that exposes a trailing separator, drop it too (at most a two-component
/// peel — a valid address has no adjacent zeros). A *single structural peel*,
/// NOT a guaranteed level-coarsening (a full content element peels to its
/// subspace-base, still Element-class) and NOT the derivation parent. `None`
/// only for a single-component node. The peel cannot empty the prefix: T4's
/// no-leading-zero clause makes `comps[0]` nonzero, so the separator drop
/// cannot fire at `end = 1` and at least one component always survives.
/// Minted through [`validate`] — the one gate for the Address validity
/// invariant; the `expect` states why it opens.
pub fn parent(a: &Address) -> Option<Address> {
    let comps = a.tumbler().comps();
    if comps.len() == 1 {
        return None;
    }
    let mut end = comps.len() - 1; // drop the last component
    if nat_is_zero(&comps[end - 1]) {
        end -= 1; // an exposed trailing separator goes too
    }
    let prefix = Tumbler::from_vec(comps[..end].to_vec());
    Some(validate(prefix).expect("a peeled prefix of a T4-valid address is T4-valid"))
}

/// §C — the origin **Document** address: the zeros = 2 prefix `N·0·U·0·D`
/// (the FULL document field, version components included). `None` when
/// `zeros(a) < 2`; a Document input returns itself. The one-call
/// level-coarsening M6's SHOWORIGIN attribution needs — address
/// *construction* stays in M1, so M6 never reassembles from raw
/// `document_field()` components. Preserves the validity invariant.
pub fn document_of(a: &Address) -> Option<Address> {
    match a.level() {
        // zeros = 2: already the Document — nothing to truncate.
        Level::Document => Some(a.clone()),
        // zeros < 2 has no document prefix and zeros = 3 truncates at the
        // third separator; both answers come from the one projector.
        _ => {
            let prefix = Tumbler::from_vec(a.document_prefix()?.to_vec());
            Some(
                validate(prefix)
                    .expect("the zeros=2 prefix of a T4-valid address is a valid Document"),
            )
        }
    }
}

/// §C — `t_{#t}`: the local sibling index at the current field. Total on the
/// carrier (tumblers are nonempty, T0).
///
/// Which field is current decides what the component means, and that is the
/// caller's knowledge, not the tumbler's: it is the element ordinal only for
/// a FULL element position `doc·0·subspace·ordinal`. On a subspace *base*
/// `doc·0·subspace` the last component is the subspace id (TA7a, the same
/// hazard [`crate::shift`] carries); on a versioned document it is the
/// version component. A caller after an element ordinal reads it from a
/// verified element position — [`Address::element_field`], or the
/// [`crate::ElemPos`] packaging that holds `subspace` and `ordinal` apart.
pub fn ordinal(t: &Tumbler) -> &Nat {
    t.comps().last().expect("T0: tumblers are nonempty")
}
