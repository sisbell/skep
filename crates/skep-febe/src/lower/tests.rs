use super::*;
use crate::reject::Disposition;
use skep_address::{validate, Nat, Tumbler};
use skep_retrieval::{Operand, SpanFault};

/// The standard test document address.
fn doc() -> skep_address::Address {
    validate(Tumbler::new([1u32, 0, 1, 0, 1].map(Nat::from)).expect("nonempty"))
        .unwrap_or_else(|_| panic!("T4-valid"))
}

/// §5 nested-error rule: wrappers recurse into the leaf's own impl.
#[test]
fn wrappers_recurse() {
    let (code, site) = CreateDocumentError::Mint(MintError::NotAnAccount).lower();
    assert_eq!(code, RejectCode::NotAnAccount);
    assert!(site.is_none());
    let (code, _) = InsertError::Mint(MintError::HomeNotRegistered).lower();
    assert_eq!(code, RejectCode::HomeNotRegistered);
    let (code, _) = MakeLinkError::Seat(SeatError::AlreadySeated).lower();
    assert_eq!(code, RejectCode::AlreadySeated);
    let (code, _) = PublishError::Mint(MintError::SourceNotRegistered).lower();
    assert_eq!(code, RejectCode::SourceNotRegistered);
    let (code, _) = PublishError::Content(ContentError::AlreadyStored(
        Tumbler::new([1u32].map(Nat::from)).expect("nonempty"),
    ))
    .lower();
    assert_eq!(code, RejectCode::Content);
}

/// §5's nested-error rule as a LAW over every wrapper: each wrapper variant
/// lowers exactly as the leaf it wraps — code and site — for EVERY leaf of
/// that leaf's enum, so no wrapper arm can be the constant its one sampled
/// leaf happens to lower to (a `Gate` corruption lowered as a registration
/// code would lose its operator detail and advise a reorder).
#[test]
fn every_wrapper_lowers_as_the_leaf_it_wraps_for_every_leaf() {
    for leaf in [
        MintError::HomeNotRegistered,
        MintError::SourceNotRegistered,
        MintError::NotAnAccount,
        MintError::Gate(skep_address::GateViolation),
    ] {
        for (wrapper, lowered) in [
            ("CreateDocumentError::Mint", CreateDocumentError::Mint(leaf).lower()),
            ("InsertError::Mint", InsertError::Mint(leaf).lower()),
            ("VersionError::Mint", VersionError::Mint(leaf).lower()),
            ("PublishError::Mint", PublishError::Mint(leaf).lower()),
            ("MakeLinkError::Mint", MakeLinkError::Mint(leaf).lower()),
            ("EmitError::Mint", EmitError::Mint(leaf).lower()),
            ("NullifyError::Mint", NullifyError::Mint(leaf).lower()),
            ("AssertSupError::Mint", AssertSupError::Mint(leaf).lower()),
            ("EditLinkError::Mint", EditLinkError::Mint(leaf).lower()),
        ] {
            assert_eq!(lowered, leaf.lower(), "{wrapper}({leaf:?})");
        }
    }
    for leaf in [SeatError::NotLinkAddress, SeatError::NotHomeLink, SeatError::AlreadySeated] {
        let lowered = MakeLinkError::Seat(leaf).lower();
        assert_eq!(lowered, leaf.lower(), "MakeLinkError::Seat({leaf:?})");
    }
    let content = || {
        ContentError::AlreadyStored(Tumbler::new([1u32].map(Nat::from)).expect("nonempty"))
    };
    let lowered = InsertError::Content(content()).lower();
    assert_eq!(lowered, content().lower(), "InsertError::Content");
    let lowered = PublishError::Content(content()).lower();
    assert_eq!(lowered, content().lower(), "PublishError::Content");
}

/// §5: `Content(ContentError)` collapses wholesale to `Content`
/// (Permanent), discarding M4's structure — the flagged best-effort.
#[test]
fn content_error_collapses_wholesale() {
    let e = InsertError::Content(ContentError::AlreadyStored(
        Tumbler::new([1u32].map(Nat::from)).expect("nonempty"),
    ));
    let (code, site) = e.lower();
    assert_eq!(code, RejectCode::Content);
    assert!(site.is_none());
    assert_eq!(code.disposition(), Disposition::Permanent);
}

/// §5: M6's variant-carried localization survives into the site — `index`
/// and `fault` from RETRIEVEV's spec fault, `operand`/`region`/`index` from
/// COMPARE's, and `addr` from a multi-document `DocNotRegistered(Address)` —
/// and `slot`, which only M10's successor guard fills, stays empty.
#[test]
fn m6_faults_thread_their_site() {
    let (code, site) =
        RetrieveError::MalformedSpec { index: 3, fault: SpanFault::StartTooShallow }.lower();
    assert_eq!(code, RejectCode::MalformedSpan);
    let site = site.expect("localized");
    assert_eq!(site.index, Some(3));
    assert!(matches!(site.fault, Some(SpanFault::StartTooShallow)));
    assert!(site.operand.is_none() && site.region.is_none() && site.addr.is_none());
    assert!(site.slot.is_none(), "a slot localizes an M10 successor fault, never an M6 one");

    let (code, site) = CompareError::MalformedSpan {
        operand: Operand::Second,
        region: 1,
        index: 2,
        fault: SpanFault::NotLevelUniform,
    }
    .lower();
    assert_eq!(code, RejectCode::MalformedSpan);
    let site = site.expect("localized");
    assert!(matches!(site.operand, Some(Operand::Second)));
    assert_eq!(site.region, Some(1));
    assert_eq!(site.index, Some(2));

    let (code, site) = FindError::DocNotRegistered(doc()).lower();
    assert_eq!(code, RejectCode::DocNotRegistered);
    assert_eq!(site.expect("localized").addr, Some(doc()));
}

/// PUB-8.4/PUB-8.5, at the lowering: the shot's `withheld` carries the
/// withheld document in `site.addr` and NOTHING else — the code, the
/// `reorder` disposition, and the site; `detail` stays empty. The
/// shape is what `wire.md` pins and `tests/publish.rs` reads back over
/// the wire; this is where it is decided.
#[test]
fn withheld_names_the_document_and_carries_no_detail() {
    let rej = lower_txn(
        OpKind::Publish,
        TxnError::Rejected(PublishError::Withheld(doc())),
    );
    assert_eq!(rej.code, RejectCode::Withheld);
    assert_eq!(rej.disposition, Disposition::Reorder, "a later grant is the one filling event");
    assert_eq!(rej.site.expect("the withheld document rides the site").addr, Some(doc()));
    assert!(rej.detail.is_none(), "PUB-8.5: detail is ABSENT on this code, always");
}

/// Ownership ruling (2026-08-16): every gated write enum's
/// `NotOwner(Address)` lowers to the `NotOwner` code with the failing
/// address threaded into `site.addr`.
#[test]
fn not_owner_threads_the_failing_address() {
    for (code, site) in [
        InsertError::NotOwner(doc()).lower(),
        CopyError::NotOwner(doc()).lower(),
        DeleteError::NotOwner(doc()).lower(),
        RearrangeError::NotOwner(doc()).lower(),
        PublishError::NotOwner(doc()).lower(),
        MakeLinkError::NotOwner(doc()).lower(),
        EmitError::NotOwner(doc()).lower(),
        NullifyError::NotOwner(doc()).lower(),
        AssertSupError::NotOwner(doc()).lower(),
        EditLinkError::NotOwner(doc()).lower(),
    ] {
        assert_eq!(code, RejectCode::NotOwner);
        assert_eq!(site.expect("localized").addr, Some(doc()));
        assert_eq!(code.disposition(), Disposition::Permanent);
    }
}

/// §5: M2's transaction-level outcomes take M10's own codes, each with
/// the disposition its remedy calls for, and a typed `Rejected(E)`
/// lowers verbatim through the store's own impl.
#[test]
fn txn_errors_carry_their_remedy() {
    let rej = lower_txn::<InsertError>(
        OpKind::Insert,
        TxnError::Durability(std::io::Error::other("disk gone")),
    );
    assert_eq!(rej.code, RejectCode::Durability);
    assert_eq!(rej.disposition, Disposition::Retry);
    assert!(rej.detail.as_deref().is_some_and(|d| d.contains("disk gone")));

    // Unencodable: its own code, never Malformed — the frame the client
    // presented parsed, and the records M2 refused are the store's.
    let rej = lower_txn::<InsertError>(
        OpKind::Insert,
        TxnError::Unencodable("record too large".into()),
    );
    assert_eq!(rej.code, RejectCode::TxnUnencodable);
    assert_eq!(
        rej.disposition,
        Disposition::Permanent,
        "a record M2 cannot journal must never be advertised as retryable"
    );
    assert!(rej.detail.as_deref().is_some_and(|d| d.contains("record too large")));

    // OverBudget: its own code (the records all encode — only the
    // transaction is too big), Permanent per the 2026-08-21 ruling, with
    // the accounted size and the split remedy threaded for the operator.
    let rej = lower_txn::<InsertError>(OpKind::Insert, TxnError::OverBudget { bytes: 99 });
    assert_eq!(rej.code, RejectCode::TxnOverBudget);
    assert_eq!(rej.disposition, Disposition::Permanent);
    assert!(rej.detail.as_deref().is_some_and(|d| d.contains("99") && d.contains("split")));

    let rej = lower_txn::<InsertError>(OpKind::Insert, TxnError::Poisoned);
    assert_eq!(rej.code, RejectCode::Poisoned);
    assert_eq!(rej.disposition, Disposition::Halt);

    let rej = lower_txn(OpKind::Insert, TxnError::Rejected(InsertError::EmptyContent));
    assert_eq!(rej.code, RejectCode::EmptyContent);
    assert_eq!(rej.disposition, Disposition::Permanent);
}

/// §5: M8's fieldless `DocNotRegistered` lowers with no site — unlike
/// M6's — and the as-built fence/split variants map to their documented
/// nearest leaves.
#[test]
fn m8_lowers_with_no_site_and_as_built_variants_take_near_leaves() {
    let (code, site) = QueryError::DocNotRegistered.lower();
    assert_eq!(code, RejectCode::DocNotRegistered);
    assert!(site.is_none());
    let (code, _) = EmitError::SupersessionClass.lower();
    assert_eq!(code, RejectCode::DcViolation);
    let (code, _) = CopyError::SourceNotContentSubspace.lower();
    assert_eq!(code, RejectCode::NotContentSubspace);
}

// ─────────────── the nested-error rule as a law, not examples ───────────

/// The variant's own name, as its `Debug` spells it, up to whatever
/// punctuation its payload starts with.
fn variant_name<E: std::fmt::Debug>(e: &E) -> String {
    let rendered = format!("{e:?}");
    rendered.split(['(', ' ', '{']).next().unwrap_or_default().to_string()
}

/// The §5 rule for one flat variant: it lowers to the leaf of its own name,
/// read off its `Debug` ([`variant_name`]).
fn same_name<E: Lower + std::fmt::Debug>(e: E) {
    let name = variant_name(&e);
    let (code, _) = e.lower();
    assert_eq!(
        name,
        format!("{code:?}"),
        "a flat variant lowers to the same-named leaf (§5); {name} lowered to {code:?}"
    );
}

/// The exceptions, and the whole list of them: a flat variant whose
/// documented leaf is NOT its own name. Asserting the names differ is
/// what keeps this a list of deviations — a variant that stops deviating
/// belongs with the mechanical ones above.
fn deviates<E: Lower>(name: &str, e: E, expected: RejectCode) {
    let (code, _) = e.lower();
    assert_eq!(code, expected, "{name} lowers to the documented near leaf");
    assert_ne!(
        name,
        format!("{code:?}"),
        "{name} no longer deviates — move it to the same-named list"
    );
}

/// §5's mechanical claim over the whole table rather than a sample of it:
/// EVERY flat variant of EVERY upstream error enum lowers to the leaf
/// with its own name, and the seven documented deviations are the only
/// ones. Wrapper variants belong to `wrappers_recurse`.
#[test]
fn flat_variants_lower_to_the_same_named_code() {
    // ── M3 (namespace) ──
    same_name(MintError::HomeNotRegistered);
    same_name(MintError::SourceNotRegistered);
    same_name(MintError::NotAnAccount);
    same_name(MintError::Gate(skep_address::GateViolation));
    same_name(CreateDocumentError::NotOwner);
    same_name(DelegateError::NotValid);
    same_name(DelegateError::NotAccountTier);
    same_name(DelegateError::TooDeep);
    same_name(DelegateError::DelegatorUnknown);
    same_name(DelegateError::NotAncestor);
    same_name(DelegateError::NotAuthorized);
    same_name(DelegateError::NotTopDown);
    same_name(DelegateError::NotFresh);
    same_name(DelegateError::DuplicateId);
    same_name(DelegateError::ParentNotRegistered);
    same_name(DelegateError::NotNextForm);
    same_name(RegisterNodeError::NotValid);
    same_name(RegisterNodeError::NotNode);
    same_name(RegisterNodeError::TooDeep);
    same_name(RegisterNodeError::NotFresh);
    same_name(RegisterNodeError::NotDescendantOfBootstrap);

    // ── M4 (content) — the wholesale collapse, Open build decision 8.
    //    M4's variant set is feature-dependent and `#[non_exhaustive]`,
    //    which the collapse makes moot: whatever the variant, the code is
    //    `Content`.
    deviates(
        "AlreadyStored",
        ContentError::AlreadyStored(Tumbler::new([1u32].map(Nat::from)).expect("nonempty")),
        RejectCode::Content,
    );

    // ── M5 (arrangement) ──
    same_name(SeatError::NotLinkAddress);
    same_name(SeatError::NotHomeLink);
    same_name(SeatError::AlreadySeated);
    same_name(InsertError::DocNotRegistered);
    same_name(InsertError::NotOwner(doc()));
    same_name(InsertError::PublishedTarget);
    same_name(InsertError::NotContentSubspace);
    same_name(InsertError::OutOfBounds);
    same_name(InsertError::EmptyContent);
    same_name(CopyError::DocNotRegistered);
    same_name(CopyError::NotOwner(doc()));
    same_name(CopyError::PublishedTarget);
    same_name(CopyError::NotContentSubspace);
    same_name(CopyError::OutOfBounds);
    same_name(CopyError::SourceNotRegistered);
    same_name(CopyError::EmptySource);
    same_name(CopyError::NotOrdinalVSpan);
    same_name(CopyError::DanglingSource);
    same_name(CopyError::TooManyRuns);
    same_name(CopyError::EmptyResult);
    // As-built M5 split the source-residence guard out; the design's
    // union carries no same-named leaf.
    deviates(
        "SourceNotContentSubspace",
        CopyError::SourceNotContentSubspace,
        RejectCode::NotContentSubspace,
    );
    same_name(DeleteError::DocNotRegistered);
    same_name(DeleteError::NotOwner(doc()));
    same_name(DeleteError::PublishedTarget);
    same_name(DeleteError::NotContentSubspace);
    same_name(DeleteError::NotArranged);
    same_name(DeleteError::OutOfBounds);
    same_name(DeleteError::EmptyWidth);
    same_name(RearrangeError::DocNotRegistered);
    same_name(RearrangeError::NotOwner(doc()));
    same_name(RearrangeError::PublishedTarget);
    same_name(RearrangeError::BadCutCount);
    same_name(RearrangeError::NotAscending);
    same_name(RearrangeError::NotContentSubspace);
    same_name(RearrangeError::OutOfBounds);
    same_name(RearrangeError::EmptyContentSubspace);
    same_name(VersionError::SourceNotRegistered);
    same_name(VersionError::NotAPrincipal);
    same_name(VersionError::NodeTierCrossOwner);
    same_name(VersionError::PrivateSourceVersionless);
    same_name(VersionError::PrivateVersionOfPublished);
    // The publish shot (lane 3.2): every flat verdict same-named, the
    // withheld one threading its document through the site.
    same_name(PublishError::DocNotRegistered);
    same_name(PublishError::NotOwner(doc()));
    same_name(PublishError::SourceNotRegistered);
    same_name(PublishError::BadRun);
    same_name(PublishError::BaseNotInChain);
    same_name(PublishError::BaseSuperseded);
    same_name(PublishError::BaseExtentTooLarge);
    same_name(PublishError::PrivateSourceVersionless);
    same_name(PublishError::Withheld(doc()));
    same_name(PublishError::DanglingSource);
    same_name(PublishError::TooManyRuns);
    same_name(PublishError::TooManyValues);

    // ── M7 (links) ──
    same_name(MakeLinkError::HomeNotRegistered);
    same_name(MakeLinkError::NotOwner(doc()));
    same_name(MakeLinkError::IllFormedSpec);
    same_name(MakeLinkError::SlotTooLarge);
    same_name(MakeLinkError::EmptyTypeResolution);
    same_name(MakeLinkError::RetractionClass);
    // The `[K_sup]` sole-writer fence, on both enums that carry it.
    deviates(
        "SupersessionClass",
        MakeLinkError::SupersessionClass,
        RejectCode::DcViolation,
    );
    // …and the `replaces` class's, the same leaf on both enums.
    deviates("ReplacesClass", MakeLinkError::ReplacesClass, RejectCode::DcViolation);
    same_name(EmitError::HomeNotRegistered);
    same_name(EmitError::NotOwner(doc()));
    same_name(EmitError::NotRegistered);
    same_name(EmitError::RetractionClass);
    same_name(EmitError::ShapeViolation);
    same_name(EmitError::NonAddressDenotingType);
    same_name(EmitError::SlotTooLarge);
    deviates("SupersessionClass", EmitError::SupersessionClass, RejectCode::DcViolation);
    deviates("ReplacesClass", EmitError::ReplacesClass, RejectCode::DcViolation);
    same_name(NullifyError::HomeNotRegistered);
    same_name(NullifyError::NotOwner(doc()));
    same_name(NullifyError::BadTarget);
    same_name(AssertSupError::HomeNotRegistered);
    same_name(AssertSupError::NotOwner(doc()));
    same_name(AssertSupError::EndpointNotResident);
    same_name(AssertSupError::SelfSupersession);
    same_name(EditLinkError::OriginalNotResident);
    same_name(EditLinkError::HomeNotRegistered);
    same_name(EditLinkError::NotOwner(doc()));
    same_name(EditLinkError::SlotTooLarge);
    same_name(EditLinkError::IllFormedSuccessor);
    same_name(EditLinkError::DcViolation);

    // ── M6 (retrieval) ──
    same_name(RetrieveError::DocNotRegistered(doc()));
    // `MalformedSpan` covers RETRIEVEV's differently-named fault (§5).
    deviates(
        "MalformedSpec",
        RetrieveError::MalformedSpec { index: 0, fault: SpanFault::NotOrdinalLevel },
        RejectCode::MalformedSpan,
    );
    same_name(RetrieveError::TooManyItems);
    same_name(ExtentError::DocNotRegistered);
    same_name(OriginError::DocNotRegistered);
    same_name(OriginError::NoSuchSubspace);
    same_name(OriginError::EmptySubspace);
    same_name(OriginError::DepthIncompatible);
    same_name(OriginError::RangeNotPresent);
    same_name(OriginError::MalformedSpan(SpanFault::NotLevelUniform));
    same_name(DeletionsError::DocNotRegistered(doc()));
    same_name(CompareError::DocNotRegistered(doc()));
    same_name(CompareError::NotContentSubspace {
        operand: Operand::First,
        region: 0,
        index: 0,
    });
    same_name(CompareError::MalformedSpan {
        operand: Operand::First,
        region: 0,
        index: 0,
        fault: SpanFault::StartNotZeroFree,
    });
    same_name(CompareError::TooManyBlocks { operand: Operand::First });
    same_name(CompareError::TooManyPairs);
    same_name(FindError::DocNotRegistered(doc()));
    same_name(FindError::MalformedSpan {
        region: 0,
        index: 0,
        fault: SpanFault::StartTooShallow,
    });
    same_name(FindError::TooMuchCoverage);

    // ── M8 (discovery) ──
    same_name(QueryError::DocNotRegistered);
    same_name(QueryError::NotALink);
    same_name(QueryError::BadRegion);
    same_name(QueryError::ImageTooLarge);
    same_name(QueryError::EndsetsTooLarge);
    same_name(OrphanError::DocNotRegistered);
    same_name(OrphanError::NotContentSubspace);
    same_name(OrphanError::EmptyWidth);
    same_name(OrphanError::OutOfBounds);
    same_name(OrphanError::ImageTooLarge);
}
