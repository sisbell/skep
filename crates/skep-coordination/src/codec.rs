//! §Internal 4 — the def byte format (PR-ENC): a deterministic, decidable,
//! INJECTIVE serialization of the signed term `(Γ_D, body)` — `body` the
//! compact pre-`Reg`-expansion syntactic body — as a length-prefixed envelope
//! (varint length · param context · body), so "the run is exactly what the
//! parse consumed" is a one-line check. n = 1: one `Val` at one content
//! address (Conflicts §2).
//!
//! The codec refuses to encode `Sort::Tup` in a parameter context (Codom-only
//! at encode time as well as at registration — `Tup` has no tag at all), and
//! treats a reserved-range `VarId` (`≥ EXPANSION_NAME_BASE`) in decoded input
//! as malformed — the range is not encodable, so stored defs cannot smuggle
//! expansion names. Varints are minimal-form-checked on decode, so decode is
//! a function with ≤ 1 valid parse per byte string.

use skep_address::{validate, Address, Nat, Span, Tumbler};
use skep_links::Endset;

use crate::ast::{Atom, Dom, Lit, Prim, Term, TypeKey, TypeRef, VarId, EXPANSION_NAME_BASE};
use crate::value::Sort;

/// Decode failure — surfaced as `RegisterError::ParseFailed` (and, for an
/// ever-registered start, the permanent poisoned memo entry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed;

/// Decode nesting cap — a defensive bound on hand-forged input; hand-authored
/// compact bodies sit far below it.
const MAX_DEPTH: u32 = 1024;

// ─────────────────────────────── encoding ───────────────────────────────

/// Encode the signed term. `Err(v)` names a `Tup`-sorted parameter (the codec
/// refusal; `define_predicate` pre-rejects, so this is the backstop).
pub(crate) fn encode(params: &[(VarId, Sort)], body: &Term) -> Result<Vec<u8>, VarId> {
    let mut payload = Vec::new();
    w_varint(&mut payload, params.len() as u64);
    for (v, s) in params {
        if *s == Sort::Tup {
            return Err(v.clone());
        }
        w_varid(&mut payload, v);
        payload.push(sort_tag(*s));
    }
    w_term(&mut payload, body);
    let mut out = Vec::with_capacity(payload.len() + 10);
    w_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(&payload);
    Ok(out)
}

fn w_varint(b: &mut Vec<u8>, mut x: u64) {
    loop {
        let byte = (x & 0x7f) as u8;
        x >>= 7;
        if x == 0 {
            b.push(byte);
            return;
        }
        b.push(byte | 0x80);
    }
}

fn w_varid(b: &mut Vec<u8>, v: &VarId) {
    w_varint(b, v.0 as u64);
}

fn sort_tag(s: Sort) -> u8 {
    match s {
        Sort::Bool => 1,
        Sort::Addr => 2,
        Sort::AddrSet => 3,
        Sort::OptAddr => 4,
        Sort::AddrSeq => 5,
        Sort::Map => 6,
        Sort::Nat => 7,
        Sort::OptNat => 8,
        // Codom-only: Tup deliberately has no tag (unencodable).
        Sort::Tup => unreachable!("encode refuses Sort::Tup before tagging"),
    }
}

fn w_nat(b: &mut Vec<u8>, n: &Nat) {
    let bytes = n.to_bytes_be();
    w_varint(b, bytes.len() as u64);
    b.extend_from_slice(&bytes);
}

fn w_tumbler(b: &mut Vec<u8>, t: &Tumbler) {
    w_varint(b, t.len() as u64);
    for i in 1..=t.len() {
        w_nat(b, t.get(i));
    }
}

fn w_addr(b: &mut Vec<u8>, a: &Address) {
    w_tumbler(b, a.tumbler());
}

fn w_span(b: &mut Vec<u8>, s: &Span) {
    w_tumbler(b, s.start());
    w_tumbler(b, s.width());
}

fn w_endset(b: &mut Vec<u8>, e: &Endset) {
    w_varint(b, e.len() as u64);
    for s in e.spans() {
        w_span(b, s);
    }
}

fn w_typeref(b: &mut Vec<u8>, tr: &TypeRef) {
    match tr {
        TypeRef::Concrete(TypeKey(e)) => {
            b.push(1);
            w_endset(b, e);
        }
        TypeRef::ClassVar(v) => {
            b.push(2);
            w_varid(b, v);
        }
    }
}

fn w_term(b: &mut Vec<u8>, t: &Term) {
    match t {
        Term::Var(v) => {
            b.push(1);
            w_varid(b, v);
        }
        Term::Lit(l) => {
            b.push(2);
            match l {
                Lit::True => b.push(1),
                Lit::False => b.push(2),
                Lit::Nat(n) => {
                    b.push(3);
                    w_nat(b, n);
                }
                Lit::Addr(a) => {
                    b.push(4);
                    w_addr(b, a);
                }
                Lit::BotAddr => b.push(5),
                Lit::BotNat => b.push(6),
            }
        }
        Term::Atom(a) => {
            b.push(3);
            w_atom(b, a);
        }
        Term::Prim(p) => {
            b.push(4);
            w_prim(b, p);
        }
        Term::And(x, y) => {
            b.push(5);
            w_term(b, x);
            w_term(b, y);
        }
        Term::Or(x, y) => {
            b.push(6);
            w_term(b, x);
            w_term(b, y);
        }
        Term::Not(x) => {
            b.push(7);
            w_term(b, x);
        }
        Term::Implies(x, y) => {
            b.push(8);
            w_term(b, x);
            w_term(b, y);
        }
        Term::Iff(x, y) => {
            b.push(9);
            w_term(b, x);
            w_term(b, y);
        }
        Term::Forall { var, dom, body } => {
            b.push(10);
            w_varid(b, var);
            w_dom(b, dom);
            w_term(b, body);
        }
        Term::Exists { var, dom, body } => {
            b.push(11);
            w_varid(b, var);
            w_dom(b, dom);
            w_term(b, body);
        }
        Term::Let { var, bound, body } => {
            b.push(12);
            w_varid(b, var);
            w_term(b, bound);
            w_term(b, body);
        }
        Term::IfSome { opt, var, then_, else_ } => {
            b.push(13);
            w_term(b, opt);
            w_varid(b, var);
            w_term(b, then_);
            w_term(b, else_);
        }
        Term::Count(d) => {
            b.push(14);
            w_dom(b, d);
        }
        Term::MaxT1(d) => {
            b.push(15);
            w_dom(b, d);
        }
        Term::MinT1(d) => {
            b.push(16);
            w_dom(b, d);
        }
        Term::BigUnion { dom, var, body } => {
            b.push(17);
            w_dom(b, dom);
            w_varid(b, var);
            w_term(b, body);
        }
        Term::Reflect(d) => {
            b.push(18);
            w_dom(b, d);
        }
        Term::Ref { addr, args } => {
            b.push(19);
            w_addr(b, addr);
            w_varint(b, args.len() as u64);
            for a in args {
                w_term(b, a);
            }
        }
    }
}

fn w_atom(b: &mut Vec<u8>, a: &Atom) {
    match a {
        Atom::IsK(tr, e) => {
            b.push(1);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::Members(tr) => {
            b.push(2);
            w_typeref(b, tr);
        }
        Atom::TargetsOf(tr, e) => {
            b.push(3);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::IsFiltered(tr, e) => {
            b.push(4);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::Succs(tr, e) => {
            b.push(5);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::Chain(tr, e) => {
            b.push(6);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::Tip(tr, e) => {
            b.push(7);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::IsInChain(tr, x, y) => {
            b.push(8);
            w_typeref(b, tr);
            w_term(b, x);
            w_term(b, y);
        }
        Atom::SourcesTo(tr, e) => {
            b.push(9);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::TargetOf(tr, e) => {
            b.push(10);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::TargetsKeyed(e) => {
            b.push(11);
            w_term(b, e);
        }
        Atom::Age(tr, e) => {
            b.push(12);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::Stale(tr, e) => {
            b.push(13);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::IsDoc(e) => {
            b.push(14);
            w_term(b, e);
        }
        Atom::TupAddr(v) => {
            b.push(15);
            w_varid(b, v);
        }
        Atom::TupAddrsF(v) => {
            b.push(16);
            w_varid(b, v);
        }
        Atom::TupAddrsG(v) => {
            b.push(17);
            w_varid(b, v);
        }
        Atom::InCoverageF(e, v) => {
            b.push(18);
            w_term(b, e);
            w_varid(b, v);
        }
        Atom::InCoverageG(e, v) => {
            b.push(19);
            w_term(b, e);
            w_varid(b, v);
        }
    }
}

fn w_dom(b: &mut Vec<u8>, d: &Dom) {
    match d {
        Dom::MembersDom(tr) => {
            b.push(1);
            w_typeref(b, tr);
        }
        Dom::ActiveSlice(tr) => {
            b.push(2);
            w_typeref(b, tr);
        }
        Dom::AuditSlice(tr) => {
            b.push(3);
            w_typeref(b, tr);
        }
        Dom::LinkDom => b.push(4),
        Dom::Reg => b.push(5),
        Dom::Filter { dom, var, pred } => {
            b.push(6);
            w_dom(b, dom);
            w_varid(b, var);
            w_term(b, pred);
        }
        Dom::SetTerm(t) => {
            b.push(7);
            w_term(b, t);
        }
    }
}

fn w_prim(b: &mut Vec<u8>, p: &Prim) {
    match p {
        Prim::AddrEq(x, y) => w_prim2(b, 1, x, y),
        Prim::Prefix(x, y) => w_prim2(b, 2, x, y),
        Prim::T1Lt(x, y) => w_prim2(b, 3, x, y),
        Prim::SetMem(x, y) => w_prim2(b, 4, x, y),
        Prim::SetEq(x, y) => w_prim2(b, 5, x, y),
        Prim::IsEmpty(x) => {
            b.push(6);
            w_term(b, x);
        }
        Prim::Elems(x) => {
            b.push(7);
            w_term(b, x);
        }
        Prim::NatEq(x, y) => w_prim2(b, 8, x, y),
        Prim::NatLe(x, y) => w_prim2(b, 9, x, y),
        Prim::NatAdd(x, y) => w_prim2(b, 10, x, y),
        Prim::MapGet(m, tr) => {
            b.push(11);
            w_term(b, m);
            w_typeref(b, tr);
        }
        Prim::Def(x) => {
            b.push(12);
            w_term(b, x);
        }
    }
}

fn w_prim2(b: &mut Vec<u8>, tag: u8, x: &Term, y: &Term) {
    b.push(tag);
    w_term(b, x);
    w_term(b, y);
}

// ─────────────────────────────── decoding ───────────────────────────────

/// Decode a stored def `Val`'s bytes: envelope length must match exactly and
/// the payload must be fully consumed ("the run is exactly what the parse
/// consumed").
pub(crate) fn decode(bytes: &[u8]) -> Result<(Vec<(VarId, Sort)>, Term), Malformed> {
    let mut r = Rd { b: bytes, i: 0 };
    let len = r.varint()? as usize;
    if bytes.len() - r.i != len {
        return Err(Malformed);
    }
    let n_params = r.varint()? as usize;
    if n_params > len {
        return Err(Malformed); // cheap bound against absurd counts
    }
    let mut params = Vec::with_capacity(n_params);
    for _ in 0..n_params {
        let v = r.varid()?;
        let s = r.sort()?;
        params.push((v, s));
    }
    let body = r.term(0)?;
    if r.i != bytes.len() {
        return Err(Malformed);
    }
    Ok((params, body))
}

struct Rd<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Rd<'a> {
    fn u8(&mut self) -> Result<u8, Malformed> {
        let x = *self.b.get(self.i).ok_or(Malformed)?;
        self.i += 1;
        Ok(x)
    }

    /// Minimal-form LEB128 (a non-minimal encoding is rejected, so decode is
    /// injective on its accepted domain).
    fn varint(&mut self) -> Result<u64, Malformed> {
        let mut x: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            if shift == 63 && (byte & 0x7e) != 0 {
                return Err(Malformed); // overflow past u64
            }
            if shift > 63 {
                return Err(Malformed);
            }
            x |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                if byte == 0 && shift != 0 {
                    return Err(Malformed); // non-minimal (trailing zero limb)
                }
                return Ok(x);
            }
            shift += 7;
        }
    }

    /// A `VarId` from stored content: the reserved expansion range is not
    /// encodable input (PR-ENC's body-binder disjointness).
    fn varid(&mut self) -> Result<VarId, Malformed> {
        let x = self.varint()?;
        if x >= u64::from(EXPANSION_NAME_BASE) {
            return Err(Malformed);
        }
        Ok(VarId(x as u32))
    }

    fn sort(&mut self) -> Result<Sort, Malformed> {
        Ok(match self.u8()? {
            1 => Sort::Bool,
            2 => Sort::Addr,
            3 => Sort::AddrSet,
            4 => Sort::OptAddr,
            5 => Sort::AddrSeq,
            6 => Sort::Map,
            7 => Sort::Nat,
            8 => Sort::OptNat,
            // No Tup tag: the Codom-only invariant holds at parse time.
            _ => return Err(Malformed),
        })
    }

    fn nat(&mut self) -> Result<Nat, Malformed> {
        let len = self.varint()? as usize;
        if self.i + len > self.b.len() {
            return Err(Malformed);
        }
        let bytes = &self.b[self.i..self.i + len];
        self.i += len;
        if bytes.is_empty() || (bytes.len() > 1 && bytes[0] == 0) {
            return Err(Malformed); // canonical big-endian only
        }
        Ok(Nat::from_bytes_be(bytes))
    }

    fn tumbler(&mut self) -> Result<Tumbler, Malformed> {
        let n = self.varint()? as usize;
        if n == 0 || n > self.b.len() {
            return Err(Malformed);
        }
        let mut comps = Vec::with_capacity(n);
        for _ in 0..n {
            comps.push(self.nat()?);
        }
        Tumbler::new(comps).map_err(|_| Malformed)
    }

    fn addr(&mut self) -> Result<Address, Malformed> {
        validate(self.tumbler()?).map_err(|_| Malformed)
    }

    fn span(&mut self) -> Result<Span, Malformed> {
        let start = self.tumbler()?;
        let width = self.tumbler()?;
        Span::new(start, width).map_err(|_| Malformed)
    }

    fn endset(&mut self) -> Result<Endset, Malformed> {
        let n = self.varint()? as usize;
        if n > self.b.len() {
            return Err(Malformed);
        }
        let mut spans = Vec::with_capacity(n);
        for _ in 0..n {
            spans.push(self.span()?);
        }
        Ok(Endset::from_spans(spans))
    }

    fn typeref(&mut self) -> Result<TypeRef, Malformed> {
        Ok(match self.u8()? {
            1 => TypeRef::Concrete(TypeKey(self.endset()?)),
            2 => TypeRef::ClassVar(self.varid()?),
            _ => return Err(Malformed),
        })
    }

    fn term(&mut self, depth: u32) -> Result<Term, Malformed> {
        if depth > MAX_DEPTH {
            return Err(Malformed);
        }
        let d = depth + 1;
        Ok(match self.u8()? {
            1 => Term::Var(self.varid()?),
            2 => Term::Lit(match self.u8()? {
                1 => Lit::True,
                2 => Lit::False,
                3 => Lit::Nat(self.nat()?),
                4 => Lit::Addr(self.addr()?),
                5 => Lit::BotAddr,
                6 => Lit::BotNat,
                _ => return Err(Malformed),
            }),
            3 => Term::Atom(self.atom(d)?),
            4 => Term::Prim(self.prim(d)?),
            5 => Term::And(self.arc_term(d)?, self.arc_term(d)?),
            6 => Term::Or(self.arc_term(d)?, self.arc_term(d)?),
            7 => Term::Not(self.arc_term(d)?),
            8 => Term::Implies(self.arc_term(d)?, self.arc_term(d)?),
            9 => Term::Iff(self.arc_term(d)?, self.arc_term(d)?),
            10 => Term::Forall { var: self.varid()?, dom: self.arc_dom(d)?, body: self.arc_term(d)? },
            11 => Term::Exists { var: self.varid()?, dom: self.arc_dom(d)?, body: self.arc_term(d)? },
            12 => Term::Let { var: self.varid()?, bound: self.arc_term(d)?, body: self.arc_term(d)? },
            13 => Term::IfSome {
                opt: self.arc_term(d)?,
                var: self.varid()?,
                then_: self.arc_term(d)?,
                else_: self.arc_term(d)?,
            },
            14 => Term::Count(self.arc_dom(d)?),
            15 => Term::MaxT1(self.arc_dom(d)?),
            16 => Term::MinT1(self.arc_dom(d)?),
            17 => Term::BigUnion { dom: self.arc_dom(d)?, var: self.varid()?, body: self.arc_term(d)? },
            18 => Term::Reflect(self.arc_dom(d)?),
            19 => {
                let addr = self.addr()?;
                let n = self.varint()? as usize;
                if n > self.b.len() {
                    return Err(Malformed);
                }
                let mut args = Vec::with_capacity(n);
                for _ in 0..n {
                    args.push(self.arc_term(d)?);
                }
                Term::Ref { addr, args }
            }
            _ => return Err(Malformed),
        })
    }

    fn arc_term(&mut self, depth: u32) -> Result<std::sync::Arc<Term>, Malformed> {
        Ok(std::sync::Arc::new(self.term(depth)?))
    }

    fn arc_dom(&mut self, depth: u32) -> Result<std::sync::Arc<Dom>, Malformed> {
        Ok(std::sync::Arc::new(self.dom(depth)?))
    }

    fn atom(&mut self, d: u32) -> Result<Atom, Malformed> {
        Ok(match self.u8()? {
            1 => Atom::IsK(self.typeref()?, self.arc_term(d)?),
            2 => Atom::Members(self.typeref()?),
            3 => Atom::TargetsOf(self.typeref()?, self.arc_term(d)?),
            4 => Atom::IsFiltered(self.typeref()?, self.arc_term(d)?),
            5 => Atom::Succs(self.typeref()?, self.arc_term(d)?),
            6 => Atom::Chain(self.typeref()?, self.arc_term(d)?),
            7 => Atom::Tip(self.typeref()?, self.arc_term(d)?),
            8 => Atom::IsInChain(self.typeref()?, self.arc_term(d)?, self.arc_term(d)?),
            9 => Atom::SourcesTo(self.typeref()?, self.arc_term(d)?),
            10 => Atom::TargetOf(self.typeref()?, self.arc_term(d)?),
            11 => Atom::TargetsKeyed(self.arc_term(d)?),
            12 => Atom::Age(self.typeref()?, self.arc_term(d)?),
            13 => Atom::Stale(self.typeref()?, self.arc_term(d)?),
            14 => Atom::IsDoc(self.arc_term(d)?),
            15 => Atom::TupAddr(self.varid()?),
            16 => Atom::TupAddrsF(self.varid()?),
            17 => Atom::TupAddrsG(self.varid()?),
            18 => Atom::InCoverageF(self.arc_term(d)?, self.varid()?),
            19 => Atom::InCoverageG(self.arc_term(d)?, self.varid()?),
            _ => return Err(Malformed),
        })
    }

    fn dom(&mut self, depth: u32) -> Result<Dom, Malformed> {
        if depth > MAX_DEPTH {
            return Err(Malformed);
        }
        let d = depth + 1;
        Ok(match self.u8()? {
            1 => Dom::MembersDom(self.typeref()?),
            2 => Dom::ActiveSlice(self.typeref()?),
            3 => Dom::AuditSlice(self.typeref()?),
            4 => Dom::LinkDom,
            5 => Dom::Reg,
            6 => Dom::Filter { dom: self.arc_dom(d)?, var: self.varid()?, pred: self.arc_term(d)? },
            7 => Dom::SetTerm(self.arc_term(d)?),
            _ => return Err(Malformed),
        })
    }

    fn prim(&mut self, d: u32) -> Result<Prim, Malformed> {
        Ok(match self.u8()? {
            1 => Prim::AddrEq(self.arc_term(d)?, self.arc_term(d)?),
            2 => Prim::Prefix(self.arc_term(d)?, self.arc_term(d)?),
            3 => Prim::T1Lt(self.arc_term(d)?, self.arc_term(d)?),
            4 => Prim::SetMem(self.arc_term(d)?, self.arc_term(d)?),
            5 => Prim::SetEq(self.arc_term(d)?, self.arc_term(d)?),
            6 => Prim::IsEmpty(self.arc_term(d)?),
            7 => Prim::Elems(self.arc_term(d)?),
            8 => Prim::NatEq(self.arc_term(d)?, self.arc_term(d)?),
            9 => Prim::NatLe(self.arc_term(d)?, self.arc_term(d)?),
            10 => Prim::NatAdd(self.arc_term(d)?, self.arc_term(d)?),
            11 => Prim::MapGet(self.arc_term(d)?, self.typeref()?),
            12 => Prim::Def(self.arc_term(d)?),
            _ => return Err(Malformed),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn v(x: u32) -> VarId {
        VarId::new(x).expect("test var below the watershed")
    }

    fn tum(comps: &[u32]) -> Tumbler {
        Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")
    }

    fn ad(comps: &[u32]) -> Address {
        validate(tum(comps)).expect("T4-valid")
    }

    /// decode ∘ encode = id on a body exercising every recursive family —
    /// PR-ENC's round-trip (injectivity witness on this input).
    #[test]
    fn roundtrip_identity() {
        let key = TypeKey(skep_links::enc(&[ad(&[9, 0, 9, 0, 9, 0, 9, 1])]));
        let body = Term::Exists {
            var: v(1),
            dom: Arc::new(Dom::Filter {
                dom: Arc::new(Dom::LinkDom),
                var: v(2),
                pred: Arc::new(Term::Prim(Prim::AddrEq(
                    Arc::new(Term::Var(v(2))),
                    Arc::new(Term::Lit(Lit::Addr(ad(&[1, 0, 1, 0, 1, 0, 1, 3])))),
                ))),
            }),
            body: Arc::new(Term::And(
                Arc::new(Term::Atom(Atom::IsK(
                    TypeRef::Concrete(key.clone()),
                    Arc::new(Term::Var(v(1))),
                ))),
                Arc::new(Term::Forall {
                    var: v(3),
                    dom: Arc::new(Dom::Reg),
                    body: Arc::new(Term::Prim(Prim::Def(Arc::new(Term::Prim(Prim::MapGet(
                        Arc::new(Term::Atom(Atom::TargetsKeyed(Arc::new(Term::Var(v(1)))))),
                        TypeRef::ClassVar(v(3)),
                    )))))),
                }),
            )),
        };
        let params = vec![(v(7), Sort::Addr), (v(8), Sort::Nat)];
        let bytes = encode(&params, &body).expect("Codom-only params encode");
        let (p2, b2) = decode(&bytes).expect("round trip parses");
        assert_eq!(p2, params);
        assert_eq!(b2, body);
    }

    /// The codec refuses `Sort::Tup` in a parameter context (Codom-only at
    /// encode time — ASN-0130 SignedTerm).
    #[test]
    fn encode_refuses_tup_param() {
        let params = vec![(v(1), Sort::Tup)];
        assert_eq!(encode(&params, &Term::Lit(Lit::True)), Err(v(1)));
    }

    /// A reserved-range `VarId` in stored content is not a valid parse
    /// (PR-ENC's reserved supply): craft it via the crate-internal
    /// constructor path.
    #[test]
    fn decode_rejects_reserved_range_varid() {
        let reserved = VarId(EXPANSION_NAME_BASE);
        let body = Term::Var(reserved);
        let bytes = encode(&[], &body).expect("encode does not police body vars");
        assert_eq!(decode(&bytes), Err(Malformed));
    }

    /// Trailing bytes are a parse failure ("fully consumed").
    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = encode(&[], &Term::Lit(Lit::True)).expect("encodes");
        bytes.push(0);
        assert_eq!(decode(&bytes), Err(Malformed));
    }
}
