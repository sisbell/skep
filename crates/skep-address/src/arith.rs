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

use crate::address::{validate, zeros, Address, Level};
use crate::error::{AddPrecond, GateViolation, SubPrecond};
use crate::tumbler::{nat_is_zero, Nat, Pos, Tumbler};

/// First nonzero index (1-based) — the level at which a displacement acts;
/// the shared kernel of `⊕`, the ordinal shift, and the span-length
/// convention (a named primitive, not inline recomputation). `None` iff
/// `Zero(w)`.
pub fn action_point(w: &Tumbler) -> Option<Pos> {
    w.comps().iter().position(|c| !nat_is_zero(c)).map(|i| i + 1)
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

/// `⊕` — precondition `Pos(w) ∧ actionPoint(w) ≤ #a`, else `Err(AddPrecond)`.
/// With `k = actionPoint(w)`: copy `a₁..a_{k-1}`, set `a_k + w_k`, take
/// `w_{k+1..}` as the tail — result length `#w`; the common case touches one
/// component, with no carry. **Many-to-one** (TA-MTO/TA-RC): the start's
/// structure below `k` is discarded, so a start cannot be recovered from
/// result-plus-displacement in general.
pub fn add(a: &Tumbler, w: &Tumbler) -> Result<Tumbler, AddPrecond> {
    let k = action_point(w).ok_or(AddPrecond)?;
    if k > a.len() {
        return Err(AddPrecond);
    }
    let (ac, wc) = (a.comps(), w.comps());
    let mut out: Vec<Nat> = Vec::with_capacity(wc.len());
    out.extend_from_slice(&ac[..k - 1]);
    out.push(&ac[k - 1] + &wc[k - 1]);
    out.extend_from_slice(&wc[k..]);
    Ok(Tumbler::from_vec(out))
}

/// Zero-padded component at 0-based `i` — ⊖'s working view of an operand.
fn padded<'t>(t: &'t Tumbler, i: usize, zero: &'t Nat) -> &'t Nat {
    t.comps().get(i).unwrap_or(zero)
}

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
    let zpd = (0..l).find(|&i| padded(a, i, &zero) != padded(w, i, &zero));
    match zpd {
        None => Ok(Tumbler::from_vec(vec![zero; l])),
        Some(d) => {
            let mut out: Vec<Nat> = Vec::with_capacity(l);
            out.resize(d, Nat::from(0u32));
            // a ≥ w puts the larger component on a's side at the divergence,
            // so this ℕ subtraction cannot underflow.
            out.push(padded(a, d, &zero) - padded(w, d, &zero));
            for i in (d + 1)..l {
                out.push(padded(a, i, &zero).clone());
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
pub fn inc(t: &Tumbler, k: usize) -> Tumbler {
    let mut out = t.comps().to_vec();
    if k == 0 {
        let i = sig(t) - 1; // 0-based position named by sig
        let bumped = &out[i] + &Nat::from(1u32);
        out[i] = bumped;
    } else {
        out.extend(std::iter::repeat_with(|| Nat::from(0u32)).take(k - 1));
        out.push(Nat::from(1u32));
    }
    Tumbler::from_vec(out)
}

/// TA5a gate predicate (T10a) — **the minting producer (M3) must consult this
/// before minting**: true for `k ∈ {0, 1}` always, for `k = 2` iff
/// `zeros(t) ≤ 2`, never for `k ≥ 3` (adjacent zeros would be appended).
/// Correctness is owed here; *enforcement* — and the frontier the gate guards
/// — is M3's obligation: an allocator that skips it emits T4-invalid
/// addresses and breaks the level determination GlobalUniqueness rests on.
pub fn inc_preserves_t4(t: &Address, k: usize) -> bool {
    match k {
        0 | 1 => true,
        2 => zeros(t.tumbler()) <= 2,
        _ => false,
    }
}

/// `inc` + TA5a gate + reclassify — an `Address` mint site (validity
/// preserved; routed through [`validate`] defensively).
pub fn checked_inc(t: &Address, k: usize) -> Result<Address, GateViolation> {
    if !inc_preserves_t4(t, k) {
        return Err(GateViolation);
    }
    let next = inc(t.tumbler(), k);
    Ok(validate(next).expect("TA5a gate passed ⇒ inc preserves T4"))
}

/// The first index (1-based) at which two tumblers cease to agree: the least
/// shared-position `k` with `aₖ ≠ bₖ`, or `#shorter + 1` when every shared
/// component agrees (the prefix case). The un-padded sibling of ⊖'s
/// zero-padded divergence, and the one helper [`displacement`]'s D1 gate
/// cannot be built without.
fn divergence(a: &Tumbler, b: &Tumbler) -> Pos {
    let (ac, bc) = (a.comps(), b.comps());
    let shared = ac.len().min(bc.len());
    (0..shared)
        .find(|&i| ac[i] != bc[i])
        .map_or(shared + 1, |i| i + 1)
}

/// `b ⊖ a`, returned only when the round-trip `a ⊕ (b ⊖ a) = b` is guaranteed
/// (D0–D2: `a < b`, `divergence(a, b) ≤ #a`, `#a ≤ #b`); otherwise `None` —
/// store endpoints, don't recompute. The divergence gate is load-bearing
/// precisely through the prefix case: a proper-prefix `a` has
/// `divergence = #a + 1 > #a` and is correctly excluded (there `b ⊖ a` would
/// not round-trip).
pub fn displacement(a: &Tumbler, b: &Tumbler) -> Option<Tumbler> {
    if a >= b {
        return None; // D0: a < b
    }
    if a.len() > b.len() {
        return None; // D2: #a ≤ #b
    }
    if divergence(a, b) > a.len() {
        return None; // D1: divergence ≤ #a
    }
    Some(sub(b, a).expect("a < b ⇒ b ≥ a"))
}

/// §E — the ordinal-only shift `v ⊕ δ(n, #v)`: advance the LAST component by
/// `n`. Order-preserving on same-length operands (TS1), injective (TS2),
/// additively composing (TS3), strict and amount-monotone for `n ≥ 1`
/// (TS4/TS5) — what lets the I-stream stay sorted and distinct under shift.
/// Precondition `n ≥ 1` (OrdinalDisplacement); `shift(v, 0) = v` is the
/// explicit total extension (identity displacement).
///
/// PRIMITIVE — TA7a hazard: the last component is the ordinal only for a FULL
/// element position `doc·0·subspace·ordinal`; a raw shift of a subspace
/// *base* `doc·0·subspace` (whose last component IS the subspace id) silently
/// advances text → link. Hold a verified full element position, or use
/// [`shift_ordinal`], which makes the mis-shift unrepresentable for callers
/// that go through it. (OPEN DECISION resolved to the documented default:
/// `shift` stays public-but-annotated rather than crate-private — the
/// un-violable property is the wrapper's, not the whole API's.)
pub fn shift(v: &Tumbler, n: &Nat) -> Tumbler {
    let mut out = v.comps().to_vec();
    let last = out.len() - 1;
    let bumped = &out[last] + n;
    out[last] = bumped;
    Tumbler::from_vec(out)
}

/// A full element position with the subspace stripped into structural context
/// — the packaging that closes the TA7a hazard for callers that use it.
/// Models exactly the 2-component element field `subspace·ordinal`; T4b
/// admits element fields of ANY length ≥ 1, so [`elem_addr`] is NOT the only
/// element-construction path — longer element fields are minted via
/// `Tumbler::new(..)` + `validate`.
#[derive(Debug, Clone)]
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
/// zero); the constructed tumbler is routed through [`validate`] defensively.
/// Guards run in `ElemError` declaration order.
pub fn elem_addr(p: &ElemPos) -> Result<Address, ElemError> {
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
    comps.push(p.subspace.clone());
    comps.push(p.ordinal.clone());
    Ok(validate(Tumbler::from_vec(comps))
        .expect("doc·0·subspace·ordinal under all three guards is T4-valid"))
}

/// Subspace-safe ordinal shift: `ordinal += n` ONLY — the subspace is
/// structural context and untouched, so the TA7a text→link mis-shift is
/// unrepresentable through this wrapper. Pure `ElemPos → ElemPos`; validity
/// is re-discharged when the position is materialized by [`elem_addr`].
pub fn shift_ordinal(p: &ElemPos, n: &Nat) -> ElemPos {
    ElemPos {
        doc: p.doc.clone(),
        subspace: p.subspace.clone(),
        ordinal: &p.ordinal + n,
    }
}
