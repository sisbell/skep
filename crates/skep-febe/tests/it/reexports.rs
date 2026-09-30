//! The re-export rule, checked from where a dependent stands: a request is
//! assembled, and every response payload named, through `skep_febe` alone.
//!
//! It lives in the integration binary because only here does
//! `use skep_febe::*` see exactly what a dependent sees — the crate's public
//! paths and nothing else. A re-export narrowed to a private import fails to
//! compile here, as it would in every dependent that names it; a unit test
//! inside the crate would still reach the private import through
//! `use super::*` and pass.

use skep_febe::*;

/// The re-export rule as a check rather than a comment: a request is
/// assembled through `skep_febe` alone — the M1 constructors and the
/// failures they answer with, since a `Result` whose error cannot be named
/// is one a caller can only `unwrap`, and one `Op` per upstream module the
/// block covers. Nothing here names an upstream crate, so a re-export
/// dropped from the request half of the block fails to compile.
#[test]
fn a_request_is_built_spelling_one_crate() {
    let doc: Result<Tumbler, EmptySequence> = Tumbler::new([1u32, 0, 1, 0, 1].map(Nat::from));
    let doc: Result<Address, T4Error> = validate(doc.expect("nonempty"));
    let doc = doc.expect("T4-valid");

    // `Op::Emit`'s `from` and `Op::Nullify`'s `target` are element
    // addresses, which is the constructor this reaches for.
    let elem: Result<Address, ElemError> = elem_addr(ElemPos {
        doc: doc.clone(),
        subspace: Nat::from(1u32),
        ordinal: Nat::from(1u32),
    });
    assert!(elem.is_ok());

    // A V-span, as every M5/M6/M8 region argument carries.
    let span: Result<Span, T12Clause> = Span::new(
        Tumbler::new([1u32, 1].map(Nat::from)).expect("nonempty"),
        Tumbler::new([0u32, 1].map(Nat::from)).expect("nonempty"),
    );
    assert!(span.is_ok());
    assert_ne!(SpanSet::singleton(span.expect("well formed")), SpanSet::empty());

    // The one refusal a caller meets before any request is assembled.
    let empty: Result<Tumbler, EmptySequence> = Tumbler::new([]);
    assert!(empty.is_err(), "an empty component sequence is no tumbler");

    let span = Span::new(
        Tumbler::new([1u32, 1].map(Nat::from)).expect("nonempty"),
        Tumbler::new([0u32, 1].map(Nat::from)).expect("nonempty"),
    )
    .expect("well formed");
    let at = VPos { subspace: Nat::from(1u32), ordinal: Nat::from(1u32) };
    let vspec = VSpec { source: doc.clone(), span: span.clone() };
    let q = FourSet {
        home: SlotSpec::Spans(enc([&doc])),
        from: SlotSpec::Any,
        to: SlotSpec::Any,
        ty: SlotSpec::Any,
    };
    let cur: Cursor = None;

    // The slot numbering `Op::FollowLink` and `Op::Project` index into,
    // and `FaultSite::slot` reports an EDITLINK successor fault back in.
    const { assert!(FROM < TO && TO < TYPE, "the slot numbering runs FROM, TO, TYPE") };

    // One request per upstream module, so a re-export dropped from any
    // group is a compile error rather than a dependency an external
    // caller silently acquires.
    let ops: Vec<Op> = vec![
        // M4 (`Val`), M5 (`VPos`, `Deposit`)
        Op::Insert {
            doc: doc.clone(),
            at: at.clone(),
            values: vec![Val::new(vec![1u8])],
            deposit: Deposit::Undeclared,
        },
        Op::Copy { doc: doc.clone(), at, specs: vec![vspec.clone()] },                      // M5
        Op::RetrieveV { specs: vec![Spec { doc: doc.clone(), span: span.clone() }] },       // M6
        Op::Compare {
            rho1: vec![RegionSpec { doc: doc.clone(), spans: vec![span] }],
            rho2: vec![],
        },
        Op::FindLinksFtt { q: q.clone() }, // M8
        Op::WindowFtt { q, cur, n: 1 },
        Op::MakeLink {
            home: doc.clone(),
            from: SlotArg::Resolve(vec![vspec.clone()]), // M7
            to: SlotArg::Addrs(vec![doc.clone()]),
            ty: SlotArg::Resolve(vec![vspec.clone()]),
            replaces: None,
        },
        Op::Emit { home: doc.clone(), ty: Endset::empty(), from: doc.clone(), to: vec![] },
        Op::InClaims { y: doc.clone(), view: View::Active },
        Op::FollowLink { a: doc.clone(), slot: FROM },
        Op::Project { a: doc.clone(), slot: TYPE, d: doc.clone() },
        Op::Delegate { new_prefix: doc.tumbler().clone(), new_id: PrincipalId(1) }, // M3
        Op::EditLink {
            original: doc.clone(),
            successor: SuccessorSpec {
                from: vec![vspec],
                to: vec![],
                ty: SlotArg::Addrs(vec![doc.clone()]),
            },
            d_s: doc.clone(),
            d_a: doc,
        },
    ];
    assert_eq!(ops.len(), 13, "one request per upstream module, and then some");

    // The REQUEST itself, all three fields (signed ops): the idempotency
    // key, the op, and the attestation that rides beside `id` — built
    // through M2's one constructor, whose refusal is nameable here too,
    // so a re-export dropped from the request's third field, or from its
    // error, fails this build rather than an external caller's.
    let attest: Result<Attestation, AttestationError> = Attestation::new(1, vec![0xA5]);
    let attest = attest.expect("a non-zero tag over a non-empty blob is an attestation");
    let requests: Vec<Request> = ops
        .into_iter()
        .map(|op| Request { id: Some(ReqId(b"r".to_vec())), op, attest: Some(attest.clone()) })
        .collect();
    assert_eq!(requests.len(), 13, "every op rides a request with its two companions");

    // The two budgets a request is held to — one M10's, one M7's — read
    // off the same crate, since a caller that checks both before sending
    // should not have to spell two.
    const { assert!(MAX_REQ_ID_BYTES > 0 && MAX_SLOT_SPANS > 0) };
}

/// The same rule on the answer side. Several response payloads have no
/// public constructor — they are what a store hands back — so this names
/// them rather than building them, which is the compile-time check the
/// rule actually needs. A re-export dropped from the response half of the
/// block fails here, and its cost is the dependency this crate exists to
/// spare an external caller.
#[test]
fn a_response_payload_is_named_spelling_one_crate() {
    let _: Option<Seq> = None; // M2 — the coordinate on every answer
    let _: Option<Run> = None; // M5 — `Response::Runs`
    let _: Option<Link> = None; // M7 — `Response::LinkValue`
    let _: Option<Invalid> = None; // M7 — `Response::Follow`'s in-band Err
    let _: Option<Window> = None; // M8 — `Response::Page`
    let _: Option<OrphanReport> = None;
    let _: Option<SupClaim> = None; // M8 — `Response::Claims`
    let _: Option<Delivery> = None; // M6 — `Response::Delivery`…
    let _: Option<DeliveryItem> = None; // …and what is inside it
    let _: Option<CompareReport> = None; // M6 — `Response::Compare`…
    let _: Option<CorrPair> = None; // …and what is inside it
    let _: Option<Deletions> = None; // M6 — `Response::Deletions`
    // The two M6 shapes a `FaultSite` carries: M10's own rejection type
    // is unreadable without them.
    let _: Option<Operand> = None;
    let _: Option<SpanFault> = None;
}
