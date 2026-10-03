//! A signed term spelling every former, atom, prim, domain, literal and type
//! position, with every encodable sort in Γ_D — the input the codec's round
//! trip and the walks' agreement are checked on. It need not type-check: the
//! codec and the walks are structural. Beside it, the unit tests' two
//! builders, [`v`] and [`a`]. Test builds only.

use std::sync::Arc;

use skep_address::{validate, Address, Nat, Tumbler};
use skep_links::enc;

use crate::ast::{ArcDom, ArcTerm, Atom, Dom, Lit, Prim, Term, TypeKey, TypeRef, VarId};
use crate::value::{SignedTerm, Sort};

/// A variable below the reserved expansion range.
pub(crate) fn v(x: u32) -> VarId {
    VarId::new(x).expect("test var below the watershed")
}

/// An address from its components, which must spell a T4-valid tumbler.
pub(crate) fn a(comps: &[u32]) -> Address {
    validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty"))
        .expect("T4-valid")
}

fn at(t: Term) -> ArcTerm {
    Arc::new(t)
}

fn ad(x: Dom) -> ArcDom {
    Arc::new(x)
}

pub(crate) fn every_former() -> SignedTerm {
    let concrete = TypeRef::Concrete(TypeKey(enc(&[a(&[1, 1, 0, 1, 0, 1, 0, 1, 1])])));
    let class_var = TypeRef::ClassVar(v(9));
    let x = || Term::Var(v(1));
    let y = || Term::Var(v(2));
    let lits = [
        Lit::True,
        Lit::False,
        Lit::Nat(Nat::from(7u32)),
        // A natural past one byte: the codec's length-prefixed
        // big-endian limbs, not a single-byte special case.
        Lit::Nat(Nat::from(1u64 << 40)),
        Lit::Addr(a(&[1, 0, 1, 0, 1, 0, 1, 3])),
        Lit::BotAddr,
        Lit::BotNat,
    ]
    .into_iter()
    .map(Term::Lit);
    let atoms = [
        Atom::IsK(concrete.clone(), at(x())),
        Atom::Members(class_var.clone()),
        Atom::TargetsOf(concrete.clone(), at(x())),
        Atom::IsFiltered(concrete.clone(), at(x())),
        Atom::Succs(concrete.clone(), at(x())),
        Atom::Chain(concrete.clone(), at(x())),
        Atom::Tip(concrete.clone(), at(x())),
        Atom::IsInChain(concrete.clone(), at(x()), at(y())),
        Atom::SourcesTo(concrete.clone(), at(x())),
        Atom::TargetOf(concrete.clone(), at(x())),
        Atom::TargetsKeyed(at(x())),
        Atom::Age(concrete.clone(), at(x())),
        Atom::Stale(concrete.clone(), at(x())),
        Atom::IsDoc(at(x())),
        Atom::TupAddr(v(3)),
        Atom::TupAddrsF(v(3)),
        Atom::TupAddrsG(v(3)),
        Atom::InCoverageF(at(x()), v(3)),
        Atom::InCoverageG(at(x()), v(3)),
    ]
    .into_iter()
    .map(Term::Atom);
    let prims = [
        Prim::AddrEq(at(x()), at(y())),
        Prim::Prefix(at(x()), at(y())),
        Prim::T1Lt(at(x()), at(y())),
        Prim::SetMem(at(x()), at(y())),
        Prim::SetEq(at(x()), at(y())),
        Prim::IsEmpty(at(x())),
        Prim::Elems(at(x())),
        Prim::NatEq(at(x()), at(y())),
        Prim::NatLe(at(x()), at(y())),
        Prim::NatAdd(at(x()), at(y())),
        Prim::MapGet(at(x()), class_var.clone()),
        Prim::Def(at(x())),
    ]
    .into_iter()
    .map(Term::Prim);
    let formers = [
        Term::Or(at(x()), at(y())),
        Term::Not(at(x())),
        Term::Implies(at(x()), at(y())),
        Term::Iff(at(x()), at(y())),
        Term::Forall { var: v(5), dom: ad(Dom::MembersDom(concrete.clone())), body: at(x()) },
        Term::Exists { var: v(5), dom: ad(Dom::ActiveSlice(concrete.clone())), body: at(x()) },
        Term::Let { var: v(6), bound: at(x()), body: at(y()) },
        // Every sibling position holds a DISTINCT subterm, so a walk or a
        // codec half that transposes two of them cannot round-trip.
        Term::IfSome { opt: at(x()), var: v(7), then_: at(y()), else_: at(Term::Lit(Lit::False)) },
        Term::Count(ad(Dom::AuditSlice(class_var))),
        Term::MaxT1(ad(Dom::LinkDom)),
        Term::MinT1(ad(Dom::Reg)),
        Term::BigUnion {
            dom: ad(Dom::Filter { dom: ad(Dom::LinkDom), var: v(4), pred: at(x()) }),
            var: v(8),
            body: at(y()),
        },
        Term::Reflect(ad(Dom::SetTerm(at(x())))),
        Term::Ref { addr: a(&[1, 0, 1, 0, 1, 0, 1, 4]), args: vec![at(x()), at(y())] },
    ];
    // `And` is the spine, so it is spelled by the fold itself.
    let body = lits
        .chain(atoms)
        .chain(prims)
        .chain(formers)
        .reduce(|l, r| Term::And(at(l), at(r)))
        .expect("nonempty");
    let params = vec![
        (v(1), Sort::Bool),
        (v(2), Sort::Addr),
        (v(3), Sort::AddrSet),
        (v(4), Sort::OptAddr),
        (v(5), Sort::AddrSeq),
        (v(6), Sort::Map),
        (v(7), Sort::Nat),
        (v(8), Sort::OptNat),
    ];
    SignedTerm { params, body }
}
