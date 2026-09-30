use std::sync::Arc;

use super::*;
use crate::fixture::every_former;

fn v(x: u32) -> VarId {
    VarId::new(x).expect("test var below the watershed")
}

fn a(comps: &[u32]) -> Address {
    validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty"))
        .expect("T4-valid")
}

/// decode ∘ encode = id on a body exercising every recursive family —
/// PR-ENC's round-trip (injectivity witness on this input).
#[test]
fn roundtrip_is_identity_on_every_recursive_family() {
    let key = TypeKey(skep_links::enc(&[a(&[1, 1, 0, 1, 0, 1, 0, 1, 1])]));
    let body = Term::Exists {
        var: v(1),
        dom: Arc::new(Dom::Filter {
            dom: Arc::new(Dom::LinkDom),
            var: v(2),
            pred: Arc::new(Term::Prim(Prim::AddrEq(
                Arc::new(Term::Var(v(2))),
                Arc::new(Term::Lit(Lit::Addr(a(&[1, 0, 1, 0, 1, 0, 1, 3])))),
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
fn roundtrip_is_identity_on_every_former() {
    let signed = every_former();
    let bytes = encode(&signed).expect("Codom-only params encode");
    assert_eq!(decode(&bytes), Ok(signed));
}

/// The codec refuses `Sort::Tup` in a parameter context (Codom-only at
/// encode time — ASN-0130 SignedTerm).
#[test]
fn encode_refuses_tup_param() {
    let signed = SignedTerm { params: vec![(v(1), Sort::Tup)], body: Term::Lit(Lit::True) };
    assert_eq!(encode(&signed), Err(UnencodableTup(v(1))));
}

/// A reserved-range `VarId` in stored content is not a valid parse
/// (PR-ENC's reserved supply): the first expansion name, minted through
/// the crate-private constructor, must not survive a round trip.
#[test]
fn decode_refuses_a_reserved_range_varid() {
    let signed = SignedTerm { params: vec![], body: Term::Var(VarId::expansion(0)) };
    let bytes = encode(&signed).expect("encode does not police body vars");
    assert_eq!(decode(&bytes), Err(Malformed));
}

/// Trailing bytes are a parse failure ("fully consumed").
#[test]
fn decode_refuses_trailing_bytes() {
    let signed = SignedTerm { params: vec![], body: Term::Lit(Lit::True) };
    let mut bytes = encode(&signed).expect("encodes");
    bytes.push(0);
    assert_eq!(decode(&bytes), Err(Malformed));
}

/// A length prefix no input can satisfy is `Malformed`, never a panic:
/// a closed `Lit::Nat` whose byte-length varint reads `u64::MAX` — a
/// well-formed 13-byte envelope (`0` params, `LIT`, `NAT`, the nine
/// `0xff` limbs and the final `0x01`) around one hostile length.
#[test]
fn decode_refuses_an_absurd_length_prefix() {
    let mut bytes = vec![13, 0, tag::term::LIT, tag::lit::NAT];
    bytes.extend([0xff; 9]);
    bytes.push(0x01);
    assert_eq!(decode(&bytes), Err(Malformed));
}

/// The format is one artifact — the closed `True` is exactly these four
/// bytes, `¬True` these five, `Nat(5)` these six — and every departure
/// from the canonical spelling is `Malformed`: a non-minimal varint at
/// either length position, a natural with a leading zero or with no
/// bytes, an unknown tag in either family, an envelope the input cannot
/// fill. So no two byte strings decode to one term.
#[test]
fn decode_refuses_every_non_canonical_spelling() {
    let closed_true = SignedTerm { params: vec![], body: Term::Lit(Lit::True) };
    assert_eq!(encode(&closed_true).expect("encodes"), vec![3, 0, 2, 1]);
    let not_true = SignedTerm { params: vec![], body: Term::Not(Arc::new(Term::Lit(Lit::True))) };
    assert_eq!(encode(&not_true).expect("encodes"), vec![4, 0, 7, 2, 1]);
    let five = SignedTerm { params: vec![], body: Term::Lit(Lit::Nat(Nat::from(5u32))) };
    assert_eq!(decode(&[5, 0, 2, 3, 1, 5]), Ok(five));
    let malformed: [&[u8]; 7] = [
        &[4, 0x80, 0x00, 2, 1],    // a non-minimal parameter count
        &[0x83, 0x00, 0, 2, 1],    // a non-minimal envelope length
        &[6, 0, 2, 3, 2, 0x00, 5], // a natural with a leading zero
        &[4, 0, 2, 3, 0],          // a natural with no bytes
        &[2, 0, 99],               // an unknown term tag
        &[5, 1, 1, 9, 2, 1],       // an unknown sort tag
        &[9, 0, 2, 1],             // an envelope the input cannot fill
    ];
    for bytes in malformed {
        assert_eq!(decode(bytes), Err(Malformed), "{bytes:?}");
    }
}

/// The two varint OVERFLOW refusals, which the minimal-form check cannot
/// reach: a tenth limb whose bits fall off the top of a `u64`
/// (`shift == 63` with any bit but the lowest set), and an eleventh limb
/// at all (`shift > 63`). Neither is a trailing ZERO limb, so
/// `decode_refuses_every_non_canonical_spelling`'s cases leave both
/// unwatched, and `decode_refuses_an_absurd_length_prefix`'s nine `0xff`s
/// plus `0x01` exercise the first guard's ACCEPT path rather than its
/// refusal.
///
/// Each respells the envelope length `3` of the canonical closed `True`,
/// so what the first guard keeps is PR-ENC's INJECTIVITY: `2u64 << 63` is
/// a legal shift evaluating to 0, so without that guard the ten-limb
/// string decodes to the very term the four-byte one does. The second
/// guard keeps `<< 70` — a shift past the type's width, and a panic —
/// from being reached at all. Both are def-codec fuzz-corpus seeds.
#[test]
fn decode_refuses_a_varint_whose_limbs_overflow_a_u64() {
    let closed_true = SignedTerm { params: vec![], body: Term::Lit(Lit::True) };
    assert_eq!(encode(&closed_true).expect("encodes"), vec![3, 0, 2, 1]);
    // Ten limbs: the tenth contributes `2 << 63` = 0 — the same length,
    // a different byte string.
    let mut overflowing = vec![0x83];
    overflowing.extend([0x80; 8]);
    overflowing.extend([0x02, 0, 2, 1]);
    assert_eq!(decode(&overflowing), Err(Malformed));
    // Eleven limbs: the tenth is a legal high bit, the eleventh a shift
    // past `u64`'s width.
    let mut past_width = vec![0x83];
    past_width.extend([0x80; 8]);
    past_width.extend([0x81, 0x00, 0, 2, 1]);
    assert_eq!(decode(&past_width), Err(Malformed));
}

/// The nesting cap at its boundary: a body `MAX_DEPTH` formers deep
/// decodes, one deeper is `Malformed`.
#[test]
fn decode_caps_nesting_at_max_depth() {
    let nested = |n: usize| {
        let mut t = Term::Lit(Lit::True);
        for _ in 0..n {
            t = Term::Not(Arc::new(t));
        }
        SignedTerm { params: vec![], body: t }
    };
    let at_cap = nested(MAX_DEPTH as usize);
    assert_eq!(decode(&encode(&at_cap).expect("encodes")), Ok(at_cap));
    let past = nested(MAX_DEPTH as usize + 1);
    assert_eq!(decode(&encode(&past).expect("encodes")), Err(Malformed));
}

/// The DOMAIN family has its own recursion through `Rd::dom`, and
/// [`Rd::enter`] is its only door: a `Dom::Filter` chain descends to the
/// innermost domain BEFORE any `pred` is read, so nothing in the term
/// family bounds the descent. A body of 2¹⁵ `count(L_dom)` leaves is
/// 2¹⁶ − 1 term formers beside 2¹⁵ domain formers — within the budget
/// were the domains charged nothing, `Malformed` when they are charged
/// like every other former — and halving the leaves halves all three
/// counts, so the refusal is the budget's and not the shape's. The chain
/// then pins the nesting boundary on the same family: at the cap it
/// decodes, one level deeper it does not.
///
/// On the ASCENT a filter's `pred` sits at the level its inner domain
/// occupied, so the term door co-fires there; it is the descent, and the
/// stack it spends, that only this family's door bounds.
#[test]
fn decode_charges_the_domain_family_and_caps_its_nesting() {
    // A balanced `And` tree whose every leaf is `count(L_dom)`: L − 1
    // `And`s, L `Count`s, and L domain formers beside them.
    let leaves = |l: u32| {
        let mut t = Term::Count(Arc::new(Dom::LinkDom));
        for _ in 0..l.trailing_zeros() {
            t = Term::And(Arc::new(t.clone()), Arc::new(t));
        }
        SignedTerm { params: vec![], body: t }
    };
    let past = leaves(1 << 15);
    assert_eq!(decode(&encode(&past).expect("encodes")), Err(Malformed));
    // Halving the leaves halves all three counts, so the same body is
    // within the budget with the domains charged — the refusal above is
    // the budget's, not the shape's.
    let within = leaves(1 << 14);
    assert_eq!(decode(&encode(&within).expect("encodes")), Ok(within));

    // `Count` at 0, filter k at k, the innermost `L_dom` at n + 1.
    let filters = |n: usize| {
        let mut d = Dom::LinkDom;
        for _ in 0..n {
            d = Dom::Filter {
                dom: Arc::new(d),
                var: v(1),
                pred: Arc::new(Term::Lit(Lit::True)),
            };
        }
        SignedTerm { params: vec![], body: Term::Count(Arc::new(d)) }
    };
    let at_cap = filters(MAX_DEPTH as usize - 1);
    assert_eq!(decode(&encode(&at_cap).expect("encodes")), Ok(at_cap));
    let deeper = filters(MAX_DEPTH as usize);
    assert_eq!(decode(&encode(&deeper).expect("encodes")), Err(Malformed));
}

/// The node budget at its boundary, on a body that is shallow and wide:
/// a balanced `And` tree of 2¹⁵ leaves (2¹⁶ − 1 nodes, 16 formers deep)
/// decodes, and one of 2¹⁶ leaves (2¹⁷ − 1 nodes) is `Malformed` — a
/// well-formed run three times the budget in bytes, refused at the
/// budget rather than built to its end.
#[test]
fn decode_caps_nodes_at_max_term_nodes() {
    let balanced = |leaves: u32| {
        let mut t = Term::Lit(Lit::True);
        for _ in 0..leaves.trailing_zeros() {
            t = Term::And(Arc::new(t.clone()), Arc::new(t));
        }
        SignedTerm { params: vec![], body: t }
    };
    let within = balanced(1 << 15);
    assert_eq!(decode(&encode(&within).expect("encodes")), Ok(within));
    let past = balanced(1 << 16);
    assert_eq!(decode(&encode(&past).expect("encodes")), Err(Malformed));
}

/// The budget counts the PAYLOAD a node carries, not the node alone: a
/// closed `Lit::Nat` is two formers whatever its magnitude, and one of
/// 2¹⁶ limbs is `Malformed` while one of 2¹⁴ limbs decodes — so the
/// natural's limbs are refused at the budget rather than allocated first.
#[test]
fn decode_charges_a_literal_s_payload_against_the_node_budget() {
    let nat = |limbs: usize| SignedTerm {
        params: vec![],
        body: Term::Lit(Lit::Nat(Nat::from_bytes_be(&vec![1u8; limbs * 8]))),
    };
    let within = nat(1 << 14);
    assert_eq!(decode(&encode(&within).expect("encodes")), Ok(within));
    assert_eq!(decode(&encode(&nat(1 << 16)).expect("encodes")), Err(Malformed));
}

/// A count the input chooses — here an endset's span count, at four bytes
/// of input per ~48 bytes of `Span` — is charged against the budget
/// BEFORE it sizes anything, so it can size nothing past the budget's
/// remainder: a hundred spans decode, four thousand are `Malformed`.
#[test]
fn decode_charges_an_endset_s_spans_against_the_node_budget() {
    let members = |spans: u32| {
        let e = Endset::from_spans((0..spans).flat_map(|i| {
            skep_links::enc(&[a(&[1, 1, 0, 1, 0, 1, 0, 1, i + 1])]).spans().cloned().collect::<Vec<_>>()
        }));
        SignedTerm {
            params: vec![],
            body: Term::Atom(Atom::Members(TypeRef::Concrete(TypeKey(e)))),
        }
    };
    let within = members(100);
    assert_eq!(decode(&encode(&within).expect("encodes")), Ok(within));
    assert_eq!(decode(&encode(&members(4000)).expect("encodes")), Err(Malformed));
}
