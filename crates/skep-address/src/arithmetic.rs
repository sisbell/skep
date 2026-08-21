//! §D/§E — position arithmetic and the ordinal-only shift (ASN-0034: ⊕/⊖,
//! `inc`, TA-MTO/TA-RC/TA-LC, TA5a, TS1–TS5, TA7a, D0–D2).
//!
//! Implemented straight from the constructive definitions — deliberately NOT
//! a port of the reference mantissa arithmetic, whose recorded defects are the
//! silent digit-overflow wrap in `tumbleradd` and the fatal fixed `NPLACES`
//! length bound (T0(a)/T0(b) forbid both). ⊕'s prefix-from-first /
//! tail-from-second asymmetry is *not* a defect — it is the spec-mandated
//! three-region semantics (TA-MTO/TA-RC) — so the semantics are kept and only
//! the fixed-width representation is dropped.

use std::error::Error;
use std::fmt;

use crate::address::{validate, Address, Level};
use crate::tumbler::{is_prefix, nat_is_zero, Nat, Pos, Tumbler};

/// First nonzero index (1-based) — the level at which a displacement acts;
/// the shared kernel of `⊕`, the ordinal shift, and the span-length
/// convention (a named primitive, not inline recomputation). `None` iff
/// `Zero(w)`.
pub fn action_point(w: &Tumbler) -> Option<Pos> {
    w.comps().iter().position(|c| !nat_is_zero(c)).map(|i| i + 1)
}

/// The clause that puts a displacement outside `⊕`'s domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddDomain {
    /// `¬Pos(w)` — the displacement has no action point.
    ZeroDisplacement,
    /// `actionPoint(w) > #a` — it acts at a position past `#a`, the start's
    /// last.
    ActionPointTooDeep,
}

/// `⊕`'s domain, decided in one place: the action point `k` at which `a ⊕ w`
/// acts, or the clause that puts `w` outside it. Two askers — [`add`], and
/// `Span::new`, because T12 *is* this domain. `Span::reach` applies `⊕`
/// unguarded, and that is sound only while the span constructor admits
/// exactly what `add` accepts; asking here is what makes "exactly"
/// structural rather than a promise repeated in two comments.
pub(crate) fn add_domain(a: &Tumbler, w: &Tumbler) -> Result<Pos, AddDomain> {
    let k = action_point(w).ok_or(AddDomain::ZeroDisplacement)?;
    if k > a.len() {
        return Err(AddDomain::ActionPointTooDeep);
    }
    Ok(k)
}

/// Last nonzero index, else `#t` if all-zero. For T4-valid `t`, `sig(t) = #t`
/// (TA5-SigValid) — its own operation precisely so `inc(·, 0)` (which
/// advances `sig`) is never conflated with the action-point-driven
/// arithmetic.
pub fn sig(t: &Tumbler) -> Pos {
    t.comps()
        .iter()
        .rposition(|c| !nat_is_zero(c))
        .map_or(t.len(), |i| i + 1)
}

/// [`add`] (`⊕`) precondition failure: `¬Pos(w) ∨ actionPoint(w) > #a`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddPrecond;

impl fmt::Display for AddPrecond {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("⊕ precondition failed: requires Pos(w) and actionPoint(w) ≤ #a")
    }
}
impl Error for AddPrecond {}

/// `⊕` — precondition `Pos(w) ∧ actionPoint(w) ≤ #a`, else `Err(AddPrecond)`.
/// With `k = actionPoint(w)`: copy `a₁..a_{k-1}`, set `a_k + w_k`, take
/// `w_{k+1..}` as the tail — result length `#w`; the common case touches one
/// component, with no carry. **Many-to-one** (TA-MTO/TA-RC): the start's
/// structure past `k` is discarded, so a start cannot be recovered from
/// result-plus-displacement in general.
pub fn add(a: &Tumbler, w: &Tumbler) -> Result<Tumbler, AddPrecond> {
    let k = add_domain(a, w).map_err(|_| AddPrecond)?;
    let (ac, wc) = (a.comps(), w.comps());
    let mut out: Vec<Nat> = Vec::with_capacity(wc.len());
    out.extend_from_slice(&ac[..k - 1]);
    out.push(&ac[k - 1] + &wc[k - 1]);
    out.extend_from_slice(&wc[k..]);
    Ok(Tumbler::from_vec(out))
}

/// Zero-padded component at 0-based `i` — ⊖'s working view of an operand.
fn padded_comp<'t>(t: &'t Tumbler, i: usize, zero: &'t Nat) -> &'t Nat {
    t.comps().get(i).unwrap_or(zero)
}

/// [`sub`] (`⊖`) precondition failure: `a < w` (`⊖` requires `a ≥ w`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubPrecond;

impl fmt::Display for SubPrecond {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("⊖ precondition failed: requires a ≥ w")
    }
}
impl Error for SubPrecond {}

/// `⊖` — precondition `a ≥ w`, else `Err(SubPrecond)`. Zero-pad both to
/// `L = max(#a, #w)`, find the zero-padded divergence, emit zeros before it,
/// the difference at it, and `a`'s padded tail after; if padded-equal, the
/// all-zero tumbler of length `L`. The result may be a (non-address) Zero
/// tumbler — legal carrier output (TA6 quarantine: no address validation
/// here).
pub fn sub(a: &Tumbler, w: &Tumbler) -> Result<Tumbler, SubPrecond> {
    if a < w {
        return Err(SubPrecond);
    }
    let l = a.len().max(w.len());
    let zero = Nat::from(0u32);
    let padded_divergence = (0..l).find(|&i| padded_comp(a, i, &zero) != padded_comp(w, i, &zero));
    match padded_divergence {
        None => Ok(Tumbler::from_vec(vec![zero; l])),
        Some(d) => {
            let mut out: Vec<Nat> = Vec::with_capacity(l);
            out.resize(d, Nat::from(0u32));
            // a ≥ w puts the larger component on a's side at the divergence,
            // so this ℕ subtraction cannot underflow.
            out.push(padded_comp(a, d, &zero) - padded_comp(w, d, &zero));
            for i in (d + 1)..l {
                out.push(padded_comp(a, i, &zero).clone());
            }
            Ok(Tumbler::from_vec(out))
        }
    }
}

/// `inc` — pure, total for `k ≥ 0`: `k = 0` advances `sig(t)` (next peer,
/// length-preserving); `k > 0` appends `k−1` zeros then a `1`, extending the
/// sequence by `k` positions (`k = 1` mints a same-zeros-level peer/version,
/// `k = 2` descends one zeros-level, `k ≥ 3` always breaks T4 — hence the
/// gate). M1 supplies the pure value tool; the durable frontier that uses it
/// is M3's.
///
/// `k` is a LENGTH, not a bound: the result carries `#t + k` components, so
/// this is the one operation here whose allocation is sized by an argument
/// rather than by its operand. Every caller passes a literal (M3's `b_C`/`b_L`
/// pass 2) or routes through [`checked_inc`], whose gate caps it at 2 — a `k`
/// derived from input would be an allocation the input sizes, and would yield
/// nothing usable either, since the gate refuses every `k ≥ 3`.
#[must_use = "inc returns the advanced tumbler; it does not modify `t`"]
pub fn inc(t: &Tumbler, k: usize) -> Tumbler {
    let mut out = t.comps().to_vec();
    if k == 0 {
        out[sig(t) - 1] += Nat::from(1u32); // 0-based position named by sig
    } else {
        out.extend(std::iter::repeat_with(|| Nat::from(0u32)).take(k - 1));
        out.push(Nat::from(1u32));
    }
    Tumbler::from_vec(out)
}

/// TA5a gate predicate (T10a) — **the minting producer (M3) must consult this
/// before minting**: true for `k ∈ {0, 1}` always, for `k = 2` iff
/// `zeros(t) ≤ 2` — a valid address's level IS its separator count, so this
/// is read off the level the `Address` already carries (`≤ 2` ⟺ not
/// Element-level) — never for `k ≥ 3` (adjacent zeros would be appended).
/// Correctness is owed here; *enforcement* — and the frontier the gate guards
/// — is M3's obligation: an allocator that skips it emits T4-invalid
/// addresses and breaks the level determination GlobalUniqueness rests on.
pub fn inc_preserves_t4(t: &Address, k: usize) -> bool {
    match k {
        0 | 1 => true,
        2 => t.level() != Level::Element,
        _ => false,
    }
}

/// [`checked_inc`]: the TA5a gate refused — `inc_preserves_t4(t, k)` is false.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateViolation;

impl fmt::Display for GateViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TA5a gate violation: inc would not preserve T4-validity")
    }
}
impl Error for GateViolation {}

/// `inc` + TA5a gate + reclassify — an `Address` mint site: the advanced
/// tumbler is minted through [`validate`], the one gate for the validity
/// invariant, and the `expect` states why it opens.
///
/// The gate is consulted BEFORE [`inc`], so a `k` outside its domain is
/// refused as a value, in constant time and without allocating — which is
/// what makes this, and not `inc`, the door a caller may hand a `k` it
/// derived from input.
pub fn checked_inc(t: &Address, k: usize) -> Result<Address, GateViolation> {
    if !inc_preserves_t4(t, k) {
        return Err(GateViolation);
    }
    let next = inc(t.tumbler(), k);
    Ok(validate(next).expect("TA5a gate passed ⇒ inc preserves T4"))
}

/// `b ⊖ a`, returned only when the round-trip `a ⊕ (b ⊖ a) = b` is guaranteed
/// (D0–D2: `a < b`, `divergence(a, b) ≤ #a`, `#a ≤ #b`); otherwise `None` —
/// store endpoints, don't recompute.
///
/// Past D0 and D2, D1's divergence clause IS "`a` is not a prefix of `b`":
/// with `#a ≤ #b` established, the divergence exceeds `#a` exactly when every
/// shared component agrees, which is [`is_prefix`]. That case is what the gate
/// exists for — there `b ⊖ a` would not round-trip.
pub fn displacement(a: &Tumbler, b: &Tumbler) -> Option<Tumbler> {
    if a >= b {
        return None; // D0: a < b
    }
    if a.len() > b.len() {
        return None; // D2: #a ≤ #b
    }
    if is_prefix(a, b) {
        return None; // D1: past D0/D2, divergence > #a ⟺ a is a prefix of b
    }
    Some(sub(b, a).expect("a < b ⇒ b ≥ a"))
}

/// §E — the ordinal-only shift `v ⊕ δ(n, #v)`: advance the LAST component by
/// `n`. Order-preserving on same-length operands (TS1), injective (TS2),
/// additively composing (TS3), strict and amount-monotone for `n ≥ 1`
/// (TS4/TS5) — what lets the I-stream stay sorted and distinct under shift.
/// **Total for `n ≥ 0`**: the source's OrdinalDisplacement is stated for
/// `n ≥ 1` (`δ(0, ·)` is Zero and fails `Pos(w)`), and M1 extends the function
/// at `0` with the identity displacement — so the caller owes nothing at the
/// amount and there is no refusal channel for it.
///
/// PRIMITIVE serving two obligations. The first is the §E ordinal advance,
/// and it carries the TA7a hazard: the last component is the ordinal only
/// for a FULL element position `doc·0·subspace·ordinal`; a raw shift of a
/// subspace *base* `doc·0·subspace` (whose last component IS the subspace id)
/// silently advances content → link. Hold a verified full element position, or
/// use [`shift_ordinal`], which makes the mis-shift unrepresentable for
/// callers that go through it. (OPEN DECISION resolved to the documented
/// default: `shift` stays public-but-annotated rather than crate-private —
/// the un-violable property is the wrapper's, not the whole API's.) The
/// second obligation is the reach convention, where the operand is an
/// arbitrary carrier tumbler and no ordinal is meant at all; that one is
/// `next_at_length`, and the hazard above does not reach it.
#[must_use = "shift returns the advanced tumbler; it does not modify `v`"]
pub fn shift(v: &Tumbler, n: &Nat) -> Tumbler {
    let mut out = v.comps().to_vec();
    *out.last_mut().expect("T0: tumblers are nonempty") += n;
    Tumbler::from_vec(out)
}

/// The least tumbler of the same length strictly above `t` — the REACH
/// convention, which every half-open interval built from a single point
/// uses: `subtree_of`'s capture of `t`'s subtree, `cover`'s unit spans, and
/// `hull`'s tight upper end. Strictly greater (TS4) and length-preserving,
/// so WF always fires on `(t, next_at_length(t))`.
///
/// Distinct from an ordinal advance in what it means, not in what it
/// computes: the operand here is an arbitrary carrier prefix or a point-set
/// maximum, and the position advanced is `#t` because that is where the
/// half-open bound belongs — no element position is assumed, so no subspace
/// can be crossed.
pub(crate) fn next_at_length(t: &Tumbler) -> Tumbler {
    shift(t, &Nat::from(1u32))
}

/// A full element position with the subspace stripped into structural context
/// — the packaging that closes the TA7a hazard for callers that use it.
/// Models exactly the 2-component element field `subspace·ordinal`; T4b
/// admits element fields of ANY length ≥ 1, so [`elem_addr`] is NOT the only
/// element-construction path — longer element fields are minted via
/// `Tumbler::new(..)` + `validate`.
///
/// Identity is the content, like every other value in this crate: two
/// positions naming the same document, subspace and ordinal are the same
/// position, and [`elem_addr`] is injective on its guarded domain, so equal
/// positions materialize to equal addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElemPos {
    pub doc: Address,
    pub subspace: Nat,
    pub ordinal: Nat,
}

/// [`elem_addr`] rejection — guards checked in declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElemError {
    DocNotDocument,
    SubspaceZero,
    OrdinalZero,
}

impl fmt::Display for ElemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ElemError::DocNotDocument => "elem_addr: doc is not a Document-level address",
            ElemError::SubspaceZero => "elem_addr: subspace must be ≥ 1 (adjacent zeros otherwise)",
            ElemError::OrdinalZero => "elem_addr: ordinal must be ≥ 1 (trailing zero otherwise)",
        })
    }
}
impl Error for ElemError {}

/// Mints `doc·0·subspace·ordinal` — an `Address` mint site guarding the
/// validity invariant: requires `doc.level() == Document`, `subspace ≥ 1`
/// (else adjacent zeros after the separator), `ordinal ≥ 1` (else a trailing
/// zero). The constructed tumbler is minted through [`validate`], the one
/// gate for the validity invariant, and the `expect` states why it opens.
/// Guards run in `ElemError` declaration order.
///
/// CONSUMES `p`, like every other admission door here: its components move
/// into the minted address, and on the error path the position is dropped —
/// clone before calling if you need it back.
pub fn elem_addr(p: ElemPos) -> Result<Address, ElemError> {
    if p.doc.level() != Level::Document {
        return Err(ElemError::DocNotDocument);
    }
    if nat_is_zero(&p.subspace) {
        return Err(ElemError::SubspaceZero);
    }
    if nat_is_zero(&p.ordinal) {
        return Err(ElemError::OrdinalZero);
    }
    let mut comps = p.doc.tumbler().comps().to_vec();
    comps.push(Nat::from(0u32));
    comps.push(p.subspace);
    comps.push(p.ordinal);
    Ok(validate(Tumbler::from_vec(comps))
        .expect("doc·0·subspace·ordinal under all three guards is T4-valid"))
}

/// Subspace-safe ordinal shift: `ordinal += n` ONLY — the subspace is
/// structural context and untouched, so the TA7a content→link mis-shift is
/// unrepresentable through this wrapper. Pure `ElemPos → ElemPos`, consuming
/// the position it advances: the document and subspace travel through
/// untouched rather than being copied out of a loan. Validity is re-discharged
/// when the position is materialized by [`elem_addr`].
#[must_use = "shift_ordinal consumes the position and returns the advanced one"]
pub fn shift_ordinal(mut p: ElemPos, n: &Nat) -> ElemPos {
    p.ordinal += n;
    p
}
