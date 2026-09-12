//! §Internal 4 — the def byte format (PR-ENC): a deterministic, decidable,
//! INJECTIVE serialization of the signed term `(Γ_D, body)` — `body` the
//! compact pre-`Reg`-expansion syntactic body — as a length-prefixed envelope
//! (varint length · param context · body), so "the run is exactly what the
//! parse consumed" is a one-line check. n = 1: one `Val` at one content
//! address (Conflicts §2).
//!
//! The codec refuses to encode `Sort::Tup` in a parameter context (Codom-only
//! at encode time as well as at registration — `Tup` has no tag at all), and
//! decodes a variable name through `VarId::new`, so a reserved-range name
//! (`≥ EXPANSION_NAME_BASE`) in stored content is malformed and stored defs
//! cannot smuggle expansion names. Varints are minimal-form-checked on
//! decode, so decode is a function with ≤ 1 valid parse per byte string.

use skep_address::{validate, Address, Nat, Span, Tumbler};
use skep_links::Endset;

use crate::ast::{Atom, Dom, Lit, Prim, Term, TypeKey, TypeRef, VarId};
use crate::value::{SignedTerm, Sort};

/// Decode failure — surfaced as `RegisterError::ParseFailed` (and, for an
/// ever-registered start, the permanent poisoned memo entry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed;

/// Decode nesting cap — a defensive bound on hand-forged input; hand-authored
/// compact bodies sit far below it.
const MAX_DEPTH: u32 = 1024;

/// The tag table — the ONE statement of the format's discriminants, read by
/// the encoder and the decoder alike. Each family numbers its own
/// constructors from 1 in declaration order; a term tag and an atom tag may
/// coincide, since a tag is only ever read where its family is expected.
mod tag {
    pub mod sort {
        pub const BOOL: u8 = 1;
        pub const ADDR: u8 = 2;
        pub const ADDR_SET: u8 = 3;
        pub const OPT_ADDR: u8 = 4;
        pub const ADDR_SEQ: u8 = 5;
        pub const MAP: u8 = 6;
        pub const NAT: u8 = 7;
        pub const OPT_NAT: u8 = 8;
        // Codom-only: `Tup` deliberately has no tag (unencodable).
    }

    pub mod typeref {
        pub const CONCRETE: u8 = 1;
        pub const CLASS_VAR: u8 = 2;
    }

    pub mod lit {
        pub const TRUE: u8 = 1;
        pub const FALSE: u8 = 2;
        pub const NAT: u8 = 3;
        pub const ADDR: u8 = 4;
        pub const BOT_ADDR: u8 = 5;
        pub const BOT_NAT: u8 = 6;
    }

    pub mod term {
        pub const VAR: u8 = 1;
        pub const LIT: u8 = 2;
        pub const ATOM: u8 = 3;
        pub const PRIM: u8 = 4;
        pub const AND: u8 = 5;
        pub const OR: u8 = 6;
        pub const NOT: u8 = 7;
        pub const IMPLIES: u8 = 8;
        pub const IFF: u8 = 9;
        pub const FORALL: u8 = 10;
        pub const EXISTS: u8 = 11;
        pub const LET: u8 = 12;
        pub const IF_SOME: u8 = 13;
        pub const COUNT: u8 = 14;
        pub const MAX_T1: u8 = 15;
        pub const MIN_T1: u8 = 16;
        pub const BIG_UNION: u8 = 17;
        pub const REFLECT: u8 = 18;
        pub const REF: u8 = 19;
    }

    pub mod atom {
        pub const IS_K: u8 = 1;
        pub const MEMBERS: u8 = 2;
        pub const TARGETS_OF: u8 = 3;
        pub const IS_FILTERED: u8 = 4;
        pub const SUCCS: u8 = 5;
        pub const CHAIN: u8 = 6;
        pub const TIP: u8 = 7;
        pub const IS_IN_CHAIN: u8 = 8;
        pub const SOURCES_TO: u8 = 9;
        pub const TARGET_OF: u8 = 10;
        pub const TARGETS_KEYED: u8 = 11;
        pub const AGE: u8 = 12;
        pub const STALE: u8 = 13;
        pub const IS_DOC: u8 = 14;
        pub const TUP_ADDR: u8 = 15;
        pub const TUP_ADDRS_F: u8 = 16;
        pub const TUP_ADDRS_G: u8 = 17;
        pub const IN_COVERAGE_F: u8 = 18;
        pub const IN_COVERAGE_G: u8 = 19;
    }

    pub mod dom {
        pub const MEMBERS_DOM: u8 = 1;
        pub const ACTIVE_SLICE: u8 = 2;
        pub const AUDIT_SLICE: u8 = 3;
        pub const LINK_DOM: u8 = 4;
        pub const REG: u8 = 5;
        pub const FILTER: u8 = 6;
        pub const SET_TERM: u8 = 7;
    }

    pub mod prim {
        pub const ADDR_EQ: u8 = 1;
        pub const PREFIX: u8 = 2;
        pub const T1_LT: u8 = 3;
        pub const SET_MEM: u8 = 4;
        pub const SET_EQ: u8 = 5;
        pub const IS_EMPTY: u8 = 6;
        pub const ELEMS: u8 = 7;
        pub const NAT_EQ: u8 = 8;
        pub const NAT_LE: u8 = 9;
        pub const NAT_ADD: u8 = 10;
        pub const MAP_GET: u8 = 11;
        pub const DEF: u8 = 12;
    }
}

// ─────────────────────────────── encoding ───────────────────────────────

/// Encode the signed term. `Err(v)` names a `Tup`-sorted parameter (the codec
/// refusal — unreachable from `define_predicate`, whose `TypedTerm` is
/// Codom-only by type; the codec keeps its own invariant regardless).
pub(crate) fn encode(t: &SignedTerm) -> Result<Vec<u8>, VarId> {
    let mut payload = Vec::new();
    w_varint(&mut payload, t.params.len() as u64);
    for (v, s) in &t.params {
        if *s == Sort::Tup {
            return Err(v.clone());
        }
        w_varid(&mut payload, v);
        payload.push(sort_tag(*s));
    }
    w_term(&mut payload, &t.body);
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
    w_varint(b, u64::from(v.index()));
}

fn sort_tag(s: Sort) -> u8 {
    match s {
        Sort::Bool => tag::sort::BOOL,
        Sort::Addr => tag::sort::ADDR,
        Sort::AddrSet => tag::sort::ADDR_SET,
        Sort::OptAddr => tag::sort::OPT_ADDR,
        Sort::AddrSeq => tag::sort::ADDR_SEQ,
        Sort::Map => tag::sort::MAP,
        Sort::Nat => tag::sort::NAT,
        Sort::OptNat => tag::sort::OPT_NAT,
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
    for c in t {
        w_nat(b, c);
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
            b.push(tag::typeref::CONCRETE);
            w_endset(b, e);
        }
        TypeRef::ClassVar(v) => {
            b.push(tag::typeref::CLASS_VAR);
            w_varid(b, v);
        }
    }
}

fn w_term(b: &mut Vec<u8>, t: &Term) {
    use tag::term::*;
    match t {
        Term::Var(v) => {
            b.push(VAR);
            w_varid(b, v);
        }
        Term::Lit(l) => {
            b.push(LIT);
            match l {
                Lit::True => b.push(tag::lit::TRUE),
                Lit::False => b.push(tag::lit::FALSE),
                Lit::Nat(n) => {
                    b.push(tag::lit::NAT);
                    w_nat(b, n);
                }
                Lit::Addr(a) => {
                    b.push(tag::lit::ADDR);
                    w_addr(b, a);
                }
                Lit::BotAddr => b.push(tag::lit::BOT_ADDR),
                Lit::BotNat => b.push(tag::lit::BOT_NAT),
            }
        }
        Term::Atom(a) => {
            b.push(ATOM);
            w_atom(b, a);
        }
        Term::Prim(p) => {
            b.push(PRIM);
            w_prim(b, p);
        }
        Term::And(x, y) => {
            b.push(AND);
            w_term(b, x);
            w_term(b, y);
        }
        Term::Or(x, y) => {
            b.push(OR);
            w_term(b, x);
            w_term(b, y);
        }
        Term::Not(x) => {
            b.push(NOT);
            w_term(b, x);
        }
        Term::Implies(x, y) => {
            b.push(IMPLIES);
            w_term(b, x);
            w_term(b, y);
        }
        Term::Iff(x, y) => {
            b.push(IFF);
            w_term(b, x);
            w_term(b, y);
        }
        Term::Forall { var, dom, body } => {
            b.push(FORALL);
            w_varid(b, var);
            w_dom(b, dom);
            w_term(b, body);
        }
        Term::Exists { var, dom, body } => {
            b.push(EXISTS);
            w_varid(b, var);
            w_dom(b, dom);
            w_term(b, body);
        }
        Term::Let { var, bound, body } => {
            b.push(LET);
            w_varid(b, var);
            w_term(b, bound);
            w_term(b, body);
        }
        Term::IfSome { opt, var, then_, else_ } => {
            b.push(IF_SOME);
            w_term(b, opt);
            w_varid(b, var);
            w_term(b, then_);
            w_term(b, else_);
        }
        Term::Count(d) => {
            b.push(COUNT);
            w_dom(b, d);
        }
        Term::MaxT1(d) => {
            b.push(MAX_T1);
            w_dom(b, d);
        }
        Term::MinT1(d) => {
            b.push(MIN_T1);
            w_dom(b, d);
        }
        Term::BigUnion { dom, var, body } => {
            b.push(BIG_UNION);
            w_dom(b, dom);
            w_varid(b, var);
            w_term(b, body);
        }
        Term::Reflect(d) => {
            b.push(REFLECT);
            w_dom(b, d);
        }
        Term::Ref { addr, args } => {
            b.push(REF);
            w_addr(b, addr);
            w_varint(b, args.len() as u64);
            for a in args {
                w_term(b, a);
            }
        }
    }
}

fn w_atom(b: &mut Vec<u8>, a: &Atom) {
    use tag::atom::*;
    match a {
        Atom::IsK(tr, e) => {
            b.push(IS_K);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::Members(tr) => {
            b.push(MEMBERS);
            w_typeref(b, tr);
        }
        Atom::TargetsOf(tr, e) => {
            b.push(TARGETS_OF);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::IsFiltered(tr, e) => {
            b.push(IS_FILTERED);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::Succs(tr, e) => {
            b.push(SUCCS);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::Chain(tr, e) => {
            b.push(CHAIN);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::Tip(tr, e) => {
            b.push(TIP);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::IsInChain(tr, x, y) => {
            b.push(IS_IN_CHAIN);
            w_typeref(b, tr);
            w_term(b, x);
            w_term(b, y);
        }
        Atom::SourcesTo(tr, e) => {
            b.push(SOURCES_TO);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::TargetOf(tr, e) => {
            b.push(TARGET_OF);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::TargetsKeyed(e) => {
            b.push(TARGETS_KEYED);
            w_term(b, e);
        }
        Atom::Age(tr, e) => {
            b.push(AGE);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::Stale(tr, e) => {
            b.push(STALE);
            w_typeref(b, tr);
            w_term(b, e);
        }
        Atom::IsDoc(e) => {
            b.push(IS_DOC);
            w_term(b, e);
        }
        Atom::TupAddr(v) => {
            b.push(TUP_ADDR);
            w_varid(b, v);
        }
        Atom::TupAddrsF(v) => {
            b.push(TUP_ADDRS_F);
            w_varid(b, v);
        }
        Atom::TupAddrsG(v) => {
            b.push(TUP_ADDRS_G);
            w_varid(b, v);
        }
        Atom::InCoverageF(e, v) => {
            b.push(IN_COVERAGE_F);
            w_term(b, e);
            w_varid(b, v);
        }
        Atom::InCoverageG(e, v) => {
            b.push(IN_COVERAGE_G);
            w_term(b, e);
            w_varid(b, v);
        }
    }
}

fn w_dom(b: &mut Vec<u8>, d: &Dom) {
    use tag::dom::*;
    match d {
        Dom::MembersDom(tr) => {
            b.push(MEMBERS_DOM);
            w_typeref(b, tr);
        }
        Dom::ActiveSlice(tr) => {
            b.push(ACTIVE_SLICE);
            w_typeref(b, tr);
        }
        Dom::AuditSlice(tr) => {
            b.push(AUDIT_SLICE);
            w_typeref(b, tr);
        }
        Dom::LinkDom => b.push(LINK_DOM),
        Dom::Reg => b.push(REG),
        Dom::Filter { dom, var, pred } => {
            b.push(FILTER);
            w_dom(b, dom);
            w_varid(b, var);
            w_term(b, pred);
        }
        Dom::SetTerm(t) => {
            b.push(SET_TERM);
            w_term(b, t);
        }
    }
}

fn w_prim(b: &mut Vec<u8>, p: &Prim) {
    use tag::prim::*;
    match p {
        Prim::AddrEq(x, y) => w_prim2(b, ADDR_EQ, x, y),
        Prim::Prefix(x, y) => w_prim2(b, PREFIX, x, y),
        Prim::T1Lt(x, y) => w_prim2(b, T1_LT, x, y),
        Prim::SetMem(x, y) => w_prim2(b, SET_MEM, x, y),
        Prim::SetEq(x, y) => w_prim2(b, SET_EQ, x, y),
        Prim::IsEmpty(x) => {
            b.push(IS_EMPTY);
            w_term(b, x);
        }
        Prim::Elems(x) => {
            b.push(ELEMS);
            w_term(b, x);
        }
        Prim::NatEq(x, y) => w_prim2(b, NAT_EQ, x, y),
        Prim::NatLe(x, y) => w_prim2(b, NAT_LE, x, y),
        Prim::NatAdd(x, y) => w_prim2(b, NAT_ADD, x, y),
        Prim::MapGet(m, tr) => {
            b.push(MAP_GET);
            w_term(b, m);
            w_typeref(b, tr);
        }
        Prim::Def(x) => {
            b.push(DEF);
            w_term(b, x);
        }
    }
}

fn w_prim2(b: &mut Vec<u8>, t: u8, x: &Term, y: &Term) {
    b.push(t);
    w_term(b, x);
    w_term(b, y);
}

// ─────────────────────────────── decoding ───────────────────────────────

/// Decode a stored def `Val`'s bytes to the signed term: envelope length must
/// match exactly and the payload must be fully consumed ("the run is exactly
/// what the parse consumed").
pub(crate) fn decode(bytes: &[u8]) -> Result<SignedTerm, Malformed> {
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
    Ok(SignedTerm { params, body })
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

    /// A `VarId` from stored content, through the public constructor: the
    /// reserved expansion range is not encodable input (PR-ENC's
    /// body-binder disjointness).
    fn varid(&mut self) -> Result<VarId, Malformed> {
        let x = self.varint()?;
        u32::try_from(x).ok().and_then(VarId::new).ok_or(Malformed)
    }

    fn sort(&mut self) -> Result<Sort, Malformed> {
        use tag::sort::*;
        Ok(match self.u8()? {
            BOOL => Sort::Bool,
            ADDR => Sort::Addr,
            ADDR_SET => Sort::AddrSet,
            OPT_ADDR => Sort::OptAddr,
            ADDR_SEQ => Sort::AddrSeq,
            MAP => Sort::Map,
            NAT => Sort::Nat,
            OPT_NAT => Sort::OptNat,
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
        use tag::typeref::*;
        Ok(match self.u8()? {
            CONCRETE => TypeRef::Concrete(TypeKey(self.endset()?)),
            CLASS_VAR => TypeRef::ClassVar(self.varid()?),
            _ => return Err(Malformed),
        })
    }

    fn term(&mut self, depth: u32) -> Result<Term, Malformed> {
        use tag::term::*;
        if depth > MAX_DEPTH {
            return Err(Malformed);
        }
        let d = depth + 1;
        Ok(match self.u8()? {
            VAR => Term::Var(self.varid()?),
            LIT => Term::Lit(match self.u8()? {
                tag::lit::TRUE => Lit::True,
                tag::lit::FALSE => Lit::False,
                tag::lit::NAT => Lit::Nat(self.nat()?),
                tag::lit::ADDR => Lit::Addr(self.addr()?),
                tag::lit::BOT_ADDR => Lit::BotAddr,
                tag::lit::BOT_NAT => Lit::BotNat,
                _ => return Err(Malformed),
            }),
            ATOM => Term::Atom(self.atom(d)?),
            PRIM => Term::Prim(self.prim(d)?),
            AND => Term::And(self.arc_term(d)?, self.arc_term(d)?),
            OR => Term::Or(self.arc_term(d)?, self.arc_term(d)?),
            NOT => Term::Not(self.arc_term(d)?),
            IMPLIES => Term::Implies(self.arc_term(d)?, self.arc_term(d)?),
            IFF => Term::Iff(self.arc_term(d)?, self.arc_term(d)?),
            FORALL => Term::Forall { var: self.varid()?, dom: self.arc_dom(d)?, body: self.arc_term(d)? },
            EXISTS => Term::Exists { var: self.varid()?, dom: self.arc_dom(d)?, body: self.arc_term(d)? },
            LET => Term::Let { var: self.varid()?, bound: self.arc_term(d)?, body: self.arc_term(d)? },
            IF_SOME => Term::IfSome {
                opt: self.arc_term(d)?,
                var: self.varid()?,
                then_: self.arc_term(d)?,
                else_: self.arc_term(d)?,
            },
            COUNT => Term::Count(self.arc_dom(d)?),
            MAX_T1 => Term::MaxT1(self.arc_dom(d)?),
            MIN_T1 => Term::MinT1(self.arc_dom(d)?),
            BIG_UNION => Term::BigUnion { dom: self.arc_dom(d)?, var: self.varid()?, body: self.arc_term(d)? },
            REFLECT => Term::Reflect(self.arc_dom(d)?),
            REF => {
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
        use tag::atom::*;
        Ok(match self.u8()? {
            IS_K => Atom::IsK(self.typeref()?, self.arc_term(d)?),
            MEMBERS => Atom::Members(self.typeref()?),
            TARGETS_OF => Atom::TargetsOf(self.typeref()?, self.arc_term(d)?),
            IS_FILTERED => Atom::IsFiltered(self.typeref()?, self.arc_term(d)?),
            SUCCS => Atom::Succs(self.typeref()?, self.arc_term(d)?),
            CHAIN => Atom::Chain(self.typeref()?, self.arc_term(d)?),
            TIP => Atom::Tip(self.typeref()?, self.arc_term(d)?),
            IS_IN_CHAIN => Atom::IsInChain(self.typeref()?, self.arc_term(d)?, self.arc_term(d)?),
            SOURCES_TO => Atom::SourcesTo(self.typeref()?, self.arc_term(d)?),
            TARGET_OF => Atom::TargetOf(self.typeref()?, self.arc_term(d)?),
            TARGETS_KEYED => Atom::TargetsKeyed(self.arc_term(d)?),
            AGE => Atom::Age(self.typeref()?, self.arc_term(d)?),
            STALE => Atom::Stale(self.typeref()?, self.arc_term(d)?),
            IS_DOC => Atom::IsDoc(self.arc_term(d)?),
            TUP_ADDR => Atom::TupAddr(self.varid()?),
            TUP_ADDRS_F => Atom::TupAddrsF(self.varid()?),
            TUP_ADDRS_G => Atom::TupAddrsG(self.varid()?),
            IN_COVERAGE_F => Atom::InCoverageF(self.arc_term(d)?, self.varid()?),
            IN_COVERAGE_G => Atom::InCoverageG(self.arc_term(d)?, self.varid()?),
            _ => return Err(Malformed),
        })
    }

    fn dom(&mut self, depth: u32) -> Result<Dom, Malformed> {
        use tag::dom::*;
        if depth > MAX_DEPTH {
            return Err(Malformed);
        }
        let d = depth + 1;
        Ok(match self.u8()? {
            MEMBERS_DOM => Dom::MembersDom(self.typeref()?),
            ACTIVE_SLICE => Dom::ActiveSlice(self.typeref()?),
            AUDIT_SLICE => Dom::AuditSlice(self.typeref()?),
            LINK_DOM => Dom::LinkDom,
            REG => Dom::Reg,
            FILTER => Dom::Filter { dom: self.arc_dom(d)?, var: self.varid()?, pred: self.arc_term(d)? },
            SET_TERM => Dom::SetTerm(self.arc_term(d)?),
            _ => return Err(Malformed),
        })
    }

    fn prim(&mut self, d: u32) -> Result<Prim, Malformed> {
        use tag::prim::*;
        Ok(match self.u8()? {
            ADDR_EQ => Prim::AddrEq(self.arc_term(d)?, self.arc_term(d)?),
            PREFIX => Prim::Prefix(self.arc_term(d)?, self.arc_term(d)?),
            T1_LT => Prim::T1Lt(self.arc_term(d)?, self.arc_term(d)?),
            SET_MEM => Prim::SetMem(self.arc_term(d)?, self.arc_term(d)?),
            SET_EQ => Prim::SetEq(self.arc_term(d)?, self.arc_term(d)?),
            IS_EMPTY => Prim::IsEmpty(self.arc_term(d)?),
            ELEMS => Prim::Elems(self.arc_term(d)?),
            NAT_EQ => Prim::NatEq(self.arc_term(d)?, self.arc_term(d)?),
            NAT_LE => Prim::NatLe(self.arc_term(d)?, self.arc_term(d)?),
            NAT_ADD => Prim::NatAdd(self.arc_term(d)?, self.arc_term(d)?),
            MAP_GET => Prim::MapGet(self.arc_term(d)?, self.typeref()?),
            DEF => Prim::Def(self.arc_term(d)?),
            _ => return Err(Malformed),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::ast::fixture::every_former;

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
        let key = TypeKey(skep_links::enc(&[ad(&[1, 1, 0, 1, 0, 1, 0, 1, 1])]));
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
        let signed = SignedTerm { params: vec![(v(7), Sort::Addr), (v(8), Sort::Nat)], body };
        let bytes = encode(&signed).expect("Codom-only params encode");
        assert_eq!(decode(&bytes), Ok(signed));
    }

    /// decode ∘ encode = id over EVERY former, atom, prim, domain, literal
    /// and type position, and every encodable sort in Γ_D — so a tag the two
    /// halves read differently, anywhere in the table, fails here.
    #[test]
    fn roundtrip_every_former() {
        let signed = every_former();
        let bytes = encode(&signed).expect("Codom-only params encode");
        assert_eq!(decode(&bytes), Ok(signed));
    }

    /// The codec refuses `Sort::Tup` in a parameter context (Codom-only at
    /// encode time — ASN-0130 SignedTerm).
    #[test]
    fn encode_refuses_tup_param() {
        let signed = SignedTerm { params: vec![(v(1), Sort::Tup)], body: Term::Lit(Lit::True) };
        assert_eq!(encode(&signed), Err(v(1)));
    }

    /// A reserved-range `VarId` in stored content is not a valid parse
    /// (PR-ENC's reserved supply): the first expansion name, minted through
    /// the crate-private constructor, must not survive a round trip.
    #[test]
    fn decode_rejects_reserved_range_varid() {
        let signed = SignedTerm { params: vec![], body: Term::Var(VarId::expansion(0)) };
        let bytes = encode(&signed).expect("encode does not police body vars");
        assert_eq!(decode(&bytes), Err(Malformed));
    }

    /// Trailing bytes are a parse failure ("fully consumed").
    #[test]
    fn decode_rejects_trailing_bytes() {
        let signed = SignedTerm { params: vec![], body: Term::Lit(Lit::True) };
        let mut bytes = encode(&signed).expect("encodes");
        bytes.push(0);
        assert_eq!(decode(&bytes), Err(Malformed));
    }
}
