use super::*;
use skep_address::{validate, Nat, Span, Tumbler};
use skep_discovery::SlotSpec;

fn tum(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")
}
fn addr(comps: &[u32]) -> Address {
    validate(tum(comps)).unwrap_or_else(|_| panic!("T4-valid test address"))
}
fn sp() -> Span {
    Span::new(tum(&[1, 1]), tum(&[0, 1])).unwrap_or_else(|_| panic!("well-formed test span"))
}
fn vpos() -> VPos {
    VPos { subspace: Nat::from(1u32), ordinal: Nat::from(1u32) }
}
fn vs() -> VSpec {
    VSpec { source: addr(&[1, 0, 1, 0, 1]), span: sp() }
}
fn q() -> FourSet {
    FourSet { home: SlotSpec::Any, from: SlotSpec::Any, to: SlotSpec::Any, ty: SlotSpec::Any }
}
fn doc() -> Address {
    addr(&[1, 0, 1, 0, 1])
}

/// Every variant, paired with its documented partition side (§1's
/// `is_read` grouping): `(op, is_read)`. Crate-visible: the dispatch
/// tables' agreement with this partition is checked against the same
/// fixture, in `operation/tests.rs`, and the write door's three pairing laws
/// in `operation/door.rs`.
pub(crate) fn all_ops() -> Vec<(Op, bool)> {
    vec![
        (Op::CreateNewDocument { account: addr(&[1, 0, 1]), published: None }, false),
        (Op::Delegate { new_prefix: tum(&[1, 0, 1]), new_id: PrincipalId(1) }, false),
        (Op::RegisterNode { addr: tum(&[1, 1]) }, false),
        (Op::Fork { published: None }, false),
        (Op::NextAccountPrefix { parent: addr(&[1]) }, true),
        (Op::PrincipalPrefix { id: PrincipalId(1) }, true),
        (Op::EffectiveOwner { addr: addr(&[1, 0, 1, 1]) }, true),
        (Op::DocMetadata { doc: doc() }, true),
        (
            Op::Insert {
                doc: doc(),
                at: vpos(),
                values: vec![Val::new(vec![1u8])],
                deposit: Deposit::Undeclared,
            },
            false,
        ),
        (Op::Delete { doc: doc(), p: vpos(), width: Nat::from(1u32) }, false),
        (Op::Copy { doc: doc(), at: vpos(), specs: vec![vs()] }, false),
        (Op::Rearrange { doc: doc(), cuts: vec![vpos()] }, false),
        (Op::Version { d_src: doc(), published: None }, false),
        (
            Op::Publish { doc: doc(), shot: Shot { base: None, draft: None, runs: vec![] } },
            false,
        ),
        (
            Op::MakeLink {
                home: doc(),
                from: SlotArg::Resolve(vec![vs()]),
                to: SlotArg::Addrs(vec![doc()]),
                ty: SlotArg::Resolve(vec![vs()]),
                replaces: None,
            },
            false,
        ),
        (Op::Emit { home: doc(), ty: Endset::empty(), from: doc(), to: vec![] }, false),
        (Op::Nullify { home: doc(), target: doc() }, false),
        (Op::AssertSup { home: doc(), old: doc(), new: doc() }, false),
        (
            Op::EditLink {
                original: doc(),
                successor: SuccessorSpec { from: vec![vs()], to: vec![vs()], ty: SlotArg::Addrs(vec![doc()]) },
                d_s: doc(),
                d_a: doc(),
            },
            false,
        ),
        (Op::ReadLink { a: doc() }, true),
        (Op::FollowLink { a: doc(), slot: 1 }, true),
        (Op::RetrieveV { specs: vec![Spec { doc: doc(), span: sp() }] }, true),
        (Op::RetrieveDocVSpan { doc: doc() }, true),
        (Op::RetrieveDocVSpanSet { doc: doc() }, true),
        (Op::ShowOrigin { doc: doc(), span: sp() }, true),
        (Op::ShowDeletions { d_a: doc(), d_b: doc() }, true),
        (
            Op::Compare {
                rho1: vec![RegionSpec { doc: doc(), spans: vec![sp()] }],
                rho2: vec![],
            },
            true,
        ),
        (Op::FindDocsContaining { regions: vec![RegionSpec { doc: doc(), spans: vec![sp()] }] }, true),
        (Op::Image { d: doc(), region: vec![sp()] }, true),
        (Op::FindLinksV { d: doc(), region: vec![sp()] }, true),
        (Op::FindLinksFtt { q: q() }, true),
        (Op::CountV { d: doc(), region: vec![sp()] }, true),
        (Op::CountFtt { q: q() }, true),
        (Op::WindowV { d: doc(), region: vec![sp()], cur: None, n: 1 }, true),
        (Op::WindowFtt { q: q(), cur: None, n: 1 }, true),
        (Op::RetrieveEndsets { d: doc(), region: vec![sp()] }, true),
        (Op::Project { a: doc(), slot: 1, d: doc() }, true),
        (Op::DiscoverableFrom { a: doc(), d: doc() }, true),
        (Op::DeleteOrphans { d: doc(), p: vpos(), width: Nat::from(1u32) }, true),
        (Op::InClaims { y: doc(), view: View::Active }, true),
        (Op::OutClaims { x: doc(), view: View::Active }, true),
        (Op::EditionClaims { target: doc() }, true),
        (Op::UniversalGrants, true),
    ]
}

/// §1: the read/write partition is exhaustive and two-sided
/// (`is_write == !is_read`), with 28 reads and 15 writes (the publish
/// shot joining the fourteen of the design, lane 3.2; the doc-metadata
/// read and the edition-claim lookup joining the twenty-four reads,
/// lane 3.4; the owner-of-address read the twenty-seventh, AUTH-6.37;
/// the any-principal discovery read the twenty-eighth, PUB-8.47).
#[test]
fn partition_matches_the_design_grouping() {
    let ops = all_ops();
    assert_eq!(ops.len(), 43);
    let reads = ops.iter().filter(|(_, r)| *r).count();
    assert_eq!(reads, 28);
    for (op, expect_read) in &ops {
        assert_eq!(op.is_read(), *expect_read);
        assert_eq!(op.is_write(), !*expect_read);
    }
}

/// `Op::kind` is injective over the variants and never yields
/// `Unparseable`. Injectivity is read off a [`HashSet`], which is the
/// same shape a transport keying per-operation counters uses, so the
/// `Hash` a caller depends on is exercised here rather than merely
/// derived.
///
/// [`HashSet`]: std::collections::HashSet
#[test]
fn kind_is_injective_and_never_unparseable() {
    let mut seen = std::collections::HashSet::new();
    for (op, _) in all_ops() {
        let kind = op.kind();
        assert_ne!(kind, OpKind::Unparseable);
        assert!(seen.insert(kind), "{kind:?} is produced by two variants");
    }
    assert_eq!(seen.len(), 43);
}

/// [`SuccessorSpec`] is a VALUE, and the comparison macros are what a
/// caller writes with one — a harness pinning a built successor against a
/// parsed one, a client rendering the successor a slot-localized
/// `IllFormedSpec` refused. `assert_eq!`/`assert_ne!` require `Debug` on
/// both operands, so the derive a caller depends on is exercised here
/// rather than merely written.
#[test]
fn a_successor_spec_is_a_value_the_comparison_macros_accept() {
    let spec = |ordinal: u32| SuccessorSpec {
        from: vec![vs()],
        to: vec![],
        ty: SlotArg::Addrs(vec![addr(&[1, 0, 1, 0, ordinal])]),
    };
    assert_eq!(spec(1), spec(1), "a rebuilt successor is the same successor");
    assert_ne!(spec(1), spec(2), "…and one with another type slot is a different one");
    assert_eq!(spec(1).clone(), spec(1), "a clone is the same successor too");
}

/// PUB-6.4: the doc-argument list runs in DECLARATION order across an
/// op's lists and by index within each — `d_a` before `d_b`, ρ₁'s regions
/// before ρ₂'s, the dual row's `d` alone (PUB-6.8) — and a read that
/// names no document to withhold (the FTT family, the raw link reads,
/// the lineage probes, the namespace reads) answers the empty list, as
/// every write does.
#[test]
fn doc_arguments_run_in_declaration_order() {
    let d1 = addr(&[1, 0, 1, 0, 1]);
    let d2 = addr(&[1, 0, 1, 0, 2]);
    let d3 = addr(&[1, 0, 1, 0, 3]);
    let op = Op::ShowDeletions { d_a: d1.clone(), d_b: d2.clone() };
    assert_eq!(op.doc_arguments(), vec![&d1, &d2]);
    let op = Op::Compare {
        rho1: vec![RegionSpec { doc: d2.clone(), spans: vec![sp()] }],
        rho2: vec![
            RegionSpec { doc: d3.clone(), spans: vec![] },
            RegionSpec { doc: d1.clone(), spans: vec![] },
        ],
    };
    assert_eq!(op.doc_arguments(), vec![&d2, &d3, &d1]);
    let op = Op::Project { a: d1.clone(), slot: 1, d: d3.clone() };
    assert_eq!(op.doc_arguments(), vec![&d3], "the dual row consults `d`, never the link");
    // Lane 3.4: the two publication reads that take a document each consult
    // that one document — the H1 row's "target unreadable ⟹ withheld".
    let op = Op::DocMetadata { doc: d2.clone() };
    assert_eq!(op.doc_arguments(), vec![&d2]);
    let op = Op::EditionClaims { target: d3.clone() };
    assert_eq!(
        op.doc_arguments(),
        vec![&d3],
        "the target is a named document, not a probe key"
    );
    // AUTH-6.37: the owner-of-address read has NO document argument — its
    // `addr` is a registry probe — so the consult is never asked about it
    // and nothing is withheld, whatever the address names.
    let op = Op::EffectiveOwner { addr: d1.clone() };
    assert!(
        op.doc_arguments().is_empty(),
        "a DOCUMENT address asked about is still a probe, never a doc-argument"
    );
    // PUB-8.47: the any-principal discovery read takes no argument, so
    // there is nothing to consult; its rows are fold-filtered at its arm.
    assert!(Op::UniversalGrants.doc_arguments().is_empty());
    for (op, is_read) in all_ops() {
        let names_a_document = !op.doc_arguments().is_empty();
        let expects = is_read
            && !matches!(
                op,
                Op::NextAccountPrefix { .. }
                    | Op::PrincipalPrefix { .. }
                    | Op::EffectiveOwner { .. }
                    | Op::ReadLink { .. }
                    | Op::FollowLink { .. }
                    | Op::FindLinksFtt { .. }
                    | Op::CountFtt { .. }
                    | Op::WindowFtt { .. }
                    | Op::InClaims { .. }
                    | Op::OutClaims { .. }
                    | Op::UniversalGrants
            );
        assert_eq!(names_a_document, expects, "{:?}: the doc-argument row", op.kind());
    }
}

/// PUB-6.23 / PUB-6.24 / PUB-6.4, lane 3.3c: the source-argument list
/// runs in DECLARATION order — `copy`'s specs by index, `version`'s
/// `d_src`, and the two link writes' RESOLVE-form slots in the wire's
/// declared order `from`, `to`, `ty` with specs by index inside a slot —
/// while an ADDRESS-FORM slot is ungated and names nothing. Exactly the
/// four source-reading writes answer a non-empty list; `fork`, every other
/// write and every read answer the empty one.
#[test]
fn source_arguments_run_in_declaration_order_and_skip_address_form_slots() {
    let d1 = addr(&[1, 0, 1, 0, 1]);
    let d2 = addr(&[1, 0, 1, 0, 2]);
    let d3 = addr(&[1, 0, 1, 0, 3]);
    let spec = |d: &Address| VSpec { source: d.clone(), span: sp() };

    let op = Op::Copy { doc: d1.clone(), at: vpos(), specs: vec![spec(&d2), spec(&d3)] };
    assert_eq!(op.source_arguments(), vec![&d2, &d3], "copy: each spec's source, by index");
    let op = Op::Version { d_src: d2.clone(), published: None };
    assert_eq!(op.source_arguments(), vec![&d2]);
    let op = Op::MakeLink {
        home: d1.clone(),
        from: SlotArg::Resolve(vec![spec(&d3)]),
        to: SlotArg::Addrs(vec![d2.clone()]),
        ty: SlotArg::Resolve(vec![spec(&d2), spec(&d1)]),
        replaces: Some(d3.clone()),
    };
    assert_eq!(
        op.source_arguments(),
        vec![&d3, &d2, &d1],
        "make_link: from, then ty — the address-form `to` and the `replaces` member name \
         no source"
    );
    let op = Op::EditLink {
        original: d1.clone(),
        successor: SuccessorSpec {
            from: vec![spec(&d3)],
            to: vec![spec(&d2)],
            ty: SlotArg::Addrs(vec![d1.clone()]),
        },
        d_s: d1.clone(),
        d_a: d1.clone(),
    };
    assert_eq!(
        op.source_arguments(),
        vec![&d3, &d2],
        "edit_link: the successor's slots in order"
    );

    for (op, is_read) in all_ops() {
        let reads_a_source = !op.source_arguments().is_empty();
        let expects = !is_read
            && matches!(
                op,
                Op::Copy { .. } | Op::Version { .. } | Op::MakeLink { .. } | Op::EditLink { .. }
            );
        assert_eq!(reads_a_source, expects, "{:?}: the source-reading-writes row", op.kind());
    }
}
