use super::*;

/// §5 disposition table: the explicit Halt/Retry/Reorder rows.
#[test]
fn the_explicit_rows_advise_halt_retry_and_reorder() {
    assert_eq!(RejectCode::Poisoned.disposition(), Disposition::Halt);
    assert_eq!(RejectCode::Durability.disposition(), Disposition::Retry);
    for code in [
        RejectCode::BadTarget,
        RejectCode::DocNotRegistered,
        RejectCode::HomeNotRegistered,
        RejectCode::SourceNotRegistered,
        RejectCode::NotAnAccount,
        RejectCode::OriginalNotResident,
        RejectCode::EndpointNotResident,
        RejectCode::ParentNotRegistered,
        RejectCode::Withheld,
    ] {
        assert_eq!(code.disposition(), Disposition::Reorder);
    }
}

/// §5: the named-`Permanent` codes (invariant-forced or recovery-steering)
/// and the conservative state-dependent bucket all land `Permanent`.
#[test]
fn invariant_forced_and_state_dependent_codes_are_permanent() {
    for code in [
        RejectCode::NotRegistered,
        RejectCode::NotFresh,
        RejectCode::Gate,
        RejectCode::TxnOverBudget,
        RejectCode::TxnUnencodable,
        RejectCode::NotNextForm,
        RejectCode::NotArranged,
        RejectCode::OutOfBounds,
        RejectCode::EmptySource,
        RejectCode::EmptyContentSubspace,
        RejectCode::RangeNotPresent,
        RejectCode::EmptySubspace,
        RejectCode::DelegatorUnknown,
        RejectCode::NotAPrincipal,
        RejectCode::NotOwner,
        RejectCode::Unauthenticated,
        RejectCode::Malformed,
        RejectCode::PublishedTarget,
        RejectCode::PrivateVersionOfPublished,
        RejectCode::PrivateSourceVersionless,
        RejectCode::BadRun,
        RejectCode::BaseNotInChain,
        RejectCode::BaseSuperseded,
        RejectCode::BaseExtentTooLarge,
    ] {
        assert_eq!(code.disposition(), Disposition::Permanent);
    }
}

/// §5: `Gate` carries the fixed operator-condition detail, and it is the
/// only code that does — exclusivity over the whole domain, since a
/// standing detail added to a second code changes what every client sees
/// for that code, and changes rejection identity with it (`Eq` compares
/// `detail`). The neighbouring policy, [`RejectCode::disposition`], is
/// checked over the same domain by [`ALL_CODES`].
#[test]
fn gate_detail_is_fixed_and_exclusive() {
    let gate = Rejection::classified(OpKind::CreateNewDocument, RejectCode::Gate, None);
    assert_eq!(gate.detail.as_deref(), Some(GATE_DETAIL));
    for code in ALL_CODES {
        if code == RejectCode::Gate {
            continue;
        }
        assert!(
            Rejection::classified(OpKind::CreateNewDocument, code, None).detail.is_none(),
            "{code:?} carries a standing detail; `fixed_detail` says Gate is the only one"
        );
    }
}

/// A rejection is a std error: boxable as `Box<dyn Error + Send + Sync>`
/// (C-GOOD-ERR), and rendered with the op/code/disposition a `{}` log line
/// needs, the detail appended when one was threaded. Its codec-side twin,
/// `ParseError`, is checked beside it in `codec`.
#[test]
fn a_rejection_is_a_std_error() {
    fn boxed(
        e: impl std::error::Error + Send + Sync + 'static,
    ) -> Box<dyn std::error::Error + Send + Sync> {
        Box::new(e)
    }

    let rej = Rejection::classified(OpKind::Insert, RejectCode::Durability, None)
        .with_detail("disk gone".into());
    let line = rej.to_string();
    assert!(line.contains("Insert") && line.contains("Durability"));
    assert!(line.contains("Retry"), "the advisory hint belongs in the line: {line}");
    assert!(line.ends_with("disk gone"));
    assert_eq!(boxed(rej).to_string(), line);

    let bare = Rejection::classified(OpKind::Insert, RejectCode::NotOwner, None).to_string();
    assert!(bare.contains("NotOwner") && !bare.ends_with(':'));
}

/// A rejection is a VALUE: it clones, and it compares over all six
/// fields — `detail` included, since a message an operator reads is part
/// of the answer, and `io_kind` included, since a full volume and a
/// refused entropy read are different answers to the daemon (the
/// operations design §1.1 m1). And it keys a map, as the classification
/// vocabulary alone does, which is the shape a transport tallying refusals
/// reaches for; the impls have to be here, because a consumer cannot add
/// them.
#[test]
fn a_rejection_is_a_value_and_keys_a_map() {
    use std::collections::{HashMap, HashSet};

    let site = FaultSite { slot: Some(crate::FROM), index: Some(1), ..FaultSite::default() };
    let rej = Rejection {
        op: OpKind::EditLink,
        code: RejectCode::IllFormedSpec,
        disposition: Disposition::Permanent,
        site: Some(site),
        detail: None,
        io_kind: None,
    };
    assert_eq!(rej.clone(), rej, "a clone is the same answer");
    assert_ne!(
        rej.clone().with_detail("successor slot from".into()),
        rej,
        "a threaded message is part of what the client was told"
    );
    let elsewhere = Rejection {
        site: Some(FaultSite { slot: Some(crate::TO), index: Some(1), ..FaultSite::default() }),
        ..rej.clone()
    };
    assert_ne!(elsewhere, rej, "the same index in another slot is another fault");

    // m1: the I/O kind is part of the value too. Two rejections differing
    // in nothing but the kind are two answers, a clone carries the kind,
    // and the two hash apart — so a daemon keying its once-per-condition
    // state by the whole rejection tells a full volume from another
    // failure of the same code.
    let full = Rejection::classified(OpKind::Insert, RejectCode::Durability, None)
        .with_detail("no space left on device".into())
        .with_io_kind(std::io::ErrorKind::StorageFull);
    let other_kind = Rejection { io_kind: Some(std::io::ErrorKind::Other), ..full.clone() };
    let no_kind = Rejection { io_kind: None, ..full.clone() };
    assert_eq!(full.clone().io_kind, Some(std::io::ErrorKind::StorageFull), "a clone carries it");
    assert_ne!(full, other_kind, "the kind is part of the answer the daemon reads");
    assert_ne!(full, no_kind, "…and so is its absence");
    let by_kind: HashSet<Rejection> =
        [full.clone(), other_kind, no_kind, full].into_iter().collect();
    assert_eq!(by_kind.len(), 3, "the three kinds are three keys; the repeat is one");

    let mut per_code: HashMap<RejectCode, u64> = HashMap::new();
    for code in [RejectCode::NotOwner, RejectCode::Durability, RejectCode::NotOwner] {
        *per_code.entry(code).or_default() += 1;
    }
    assert_eq!(per_code[&RejectCode::NotOwner], 2);
    assert_eq!(per_code.len(), 2);

    // A WHOLE rejection keys a map too, and hashes consistently with the
    // five-field equality above: the same refusal met twice is one key,
    // and `rej`/`elsewhere` — which differ only in the site's slot — are
    // two. Keying by the composite is what a transport tallying
    // per-`(op, code)` or deduping repeated refusals reaches for, and
    // only this crate can supply the impl.
    let mut tally: HashMap<Rejection, u64> = HashMap::new();
    for r in [rej.clone(), elsewhere.clone(), rej.clone()] {
        *tally.entry(r).or_default() += 1;
    }
    assert_eq!(tally[&rej], 2, "the same refusal met twice is one key");
    assert_eq!(tally[&elsewhere], 1);
    assert_eq!(tally.len(), 2, "a fault in another slot is another key");

    let advised: HashSet<Disposition> = ALL_CODES.iter().map(|c| c.disposition()).collect();
    assert_eq!(advised.len(), 4, "every disposition is the advice of some code");
}

// ────────────── the disposition table over its whole domain ─────────────

/// The §5 table read off the design rather than off the code: an
/// EXHAUSTIVE match with no `_` arm, so every code's advice is a
/// deliberate row here even where the production lookup reaches it
/// through the designed catch-all.
///
/// A newly added [`RejectCode`] lands in TWO places in this file: here,
/// and in [`ALL_CODES`].
fn documented_disposition(c: RejectCode) -> Disposition {
    match c {
        // The kernel stopped.
        RejectCode::Poisoned => Disposition::Halt,
        // The one transient fault: the I/O may succeed next time.
        RejectCode::Durability => Disposition::Retry,
        // Registration/residence: the referent may yet arrive, so a
        // client that raced its own prerequisite may reissue.
        RejectCode::BadTarget
        | RejectCode::DocNotRegistered
        | RejectCode::HomeNotRegistered
        | RejectCode::SourceNotRegistered
        | RejectCode::NotAnAccount
        | RejectCode::OriginalNotResident
        | RejectCode::EndpointNotResident
        | RejectCode::ParentNotRegistered => Disposition::Reorder,
        // The source gate's withheld: a later grant is the one event
        // that fills it, in every cell (PUB-8.4, PUB-8.6).
        RejectCode::Withheld => Disposition::Reorder,
        // Everything else: reissuing the identical request cannot help.
        RejectCode::Unauthenticated
        | RejectCode::Malformed
        | RejectCode::TxnUnencodable
        | RejectCode::TxnOverBudget
        | RejectCode::NotRegistered
        | RejectCode::NotOwner
        | RejectCode::Gate
        | RejectCode::DelegatorUnknown
        | RejectCode::DuplicateId
        | RejectCode::NotAncestor
        | RejectCode::NotAuthorized
        | RejectCode::NotAccountTier
        | RejectCode::NotTopDown
        | RejectCode::NotNextForm
        | RejectCode::NotValid
        | RejectCode::NotNode
        | RejectCode::TooDeep
        | RejectCode::NotDescendantOfBootstrap
        | RejectCode::NotFresh
        | RejectCode::EmptyContent
        | RejectCode::Content
        | RejectCode::EmptySource
        | RejectCode::NotOrdinalVSpan
        | RejectCode::DanglingSource
        | RejectCode::TooManyRuns
        | RejectCode::TooManyValues
        | RejectCode::EmptyResult
        | RejectCode::NotArranged
        | RejectCode::OutOfBounds
        | RejectCode::EmptyWidth
        | RejectCode::BadCutCount
        | RejectCode::NotAscending
        | RejectCode::EmptyContentSubspace
        | RejectCode::NotAPrincipal
        | RejectCode::NodeTierCrossOwner
        | RejectCode::NotLinkAddress
        | RejectCode::NotHomeLink
        | RejectCode::AlreadySeated
        | RejectCode::NotContentSubspace
        // The version-chain refusals: publication never transitions,
        // so no reissue lands (PUB-8.3's permanent class).
        | RejectCode::PublishedTarget
        | RejectCode::PrivateVersionOfPublished
        | RejectCode::PrivateSourceVersionless
        // The publish shot's four request-shape refusals (lane 3.2).
        | RejectCode::BadRun
        | RejectCode::BaseNotInChain
        | RejectCode::BaseSuperseded
        | RejectCode::BaseExtentTooLarge
        | RejectCode::IllFormedSpec
        | RejectCode::SlotTooLarge
        | RejectCode::EmptyTypeResolution
        | RejectCode::ShapeViolation
        | RejectCode::RetractionClass
        | RejectCode::NonAddressDenotingType
        | RejectCode::SelfSupersession
        | RejectCode::IllFormedSuccessor
        | RejectCode::DcViolation
        | RejectCode::NoSuchSubspace
        | RejectCode::EmptySubspace
        | RejectCode::DepthIncompatible
        | RejectCode::RangeNotPresent
        | RejectCode::MalformedSpan
        | RejectCode::TooManyBlocks
        | RejectCode::TooManyPairs
        | RejectCode::TooMuchCoverage
        | RejectCode::TooManyItems
        | RejectCode::NotALink
        | RejectCode::BadRegion
        | RejectCode::ImageTooLarge
        | RejectCode::EndsetsTooLarge => Disposition::Permanent,
    }
}

/// Every code, in declaration order — the domain the policy is total
/// over. A newly added code lands here and in
/// [`documented_disposition`].
const ALL_CODES: [RejectCode; 79] = [
    RejectCode::Unauthenticated,
    RejectCode::Malformed,
    RejectCode::Durability,
    RejectCode::TxnUnencodable,
    RejectCode::TxnOverBudget,
    RejectCode::Poisoned,
    RejectCode::HomeNotRegistered,
    RejectCode::DocNotRegistered,
    RejectCode::SourceNotRegistered,
    RejectCode::ParentNotRegistered,
    RejectCode::NotRegistered,
    RejectCode::OriginalNotResident,
    RejectCode::EndpointNotResident,
    RejectCode::NotOwner,
    RejectCode::NotAnAccount,
    RejectCode::Gate,
    RejectCode::DelegatorUnknown,
    RejectCode::DuplicateId,
    RejectCode::NotAncestor,
    RejectCode::NotAuthorized,
    RejectCode::NotAccountTier,
    RejectCode::NotTopDown,
    RejectCode::NotNextForm,
    RejectCode::NotValid,
    RejectCode::NotNode,
    RejectCode::TooDeep,
    RejectCode::NotDescendantOfBootstrap,
    RejectCode::NotFresh,
    RejectCode::EmptyContent,
    RejectCode::Content,
    RejectCode::EmptySource,
    RejectCode::NotOrdinalVSpan,
    RejectCode::DanglingSource,
    RejectCode::TooManyRuns,
    RejectCode::TooManyValues,
    RejectCode::EmptyResult,
    RejectCode::NotArranged,
    RejectCode::OutOfBounds,
    RejectCode::EmptyWidth,
    RejectCode::BadCutCount,
    RejectCode::NotAscending,
    RejectCode::EmptyContentSubspace,
    RejectCode::NotAPrincipal,
    RejectCode::NodeTierCrossOwner,
    RejectCode::NotLinkAddress,
    RejectCode::NotHomeLink,
    RejectCode::AlreadySeated,
    RejectCode::NotContentSubspace,
    RejectCode::PublishedTarget,
    RejectCode::PrivateVersionOfPublished,
    RejectCode::PrivateSourceVersionless,
    RejectCode::Withheld,
    RejectCode::BadRun,
    RejectCode::BaseNotInChain,
    RejectCode::BaseSuperseded,
    RejectCode::BaseExtentTooLarge,
    RejectCode::IllFormedSpec,
    RejectCode::SlotTooLarge,
    RejectCode::EmptyTypeResolution,
    RejectCode::ShapeViolation,
    RejectCode::RetractionClass,
    RejectCode::NonAddressDenotingType,
    RejectCode::BadTarget,
    RejectCode::SelfSupersession,
    RejectCode::IllFormedSuccessor,
    RejectCode::DcViolation,
    RejectCode::NoSuchSubspace,
    RejectCode::EmptySubspace,
    RejectCode::DepthIncompatible,
    RejectCode::RangeNotPresent,
    RejectCode::MalformedSpan,
    RejectCode::TooManyBlocks,
    RejectCode::TooManyPairs,
    RejectCode::TooMuchCoverage,
    RejectCode::TooManyItems,
    RejectCode::NotALink,
    RejectCode::BadRegion,
    RejectCode::ImageTooLarge,
    RejectCode::EndsetsTooLarge,
];

/// §5: the policy is a TOTAL function off the flat code, and the advice
/// it gives for every code in [`ALL_CODES`] is the advice the design's
/// table documents — not merely the advice the catch-all happens to
/// produce.
#[test]
fn the_disposition_table_deviates_only_where_documented() {
    for code in ALL_CODES {
        assert_eq!(
            code.disposition(),
            documented_disposition(code),
            "{code:?} is advised against the design's §5 table"
        );
    }
}

/// [`ALL_CODES`] is the domain the law above quantifies over, so it must
/// hold every code exactly once.
#[test]
fn all_codes_lists_each_code_once() {
    for (i, a) in ALL_CODES.iter().enumerate() {
        for b in &ALL_CODES[i + 1..] {
            assert_ne!(a, b, "{a:?} is listed twice");
        }
    }
}
