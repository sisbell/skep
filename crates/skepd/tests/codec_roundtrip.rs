//! Codec contract tests, transport-only: every `Op` variant round-trips
//! through the canonical encoding, every `Response` shape marshals
//! deterministically, and the wire name tables (op names, rejection codes)
//! are pinned so a rename upstream cannot silently change the protocol.

use std::path::Path;

use serde_json::Value;
use skep_address::{validate, Address, Nat, Span, SpanSet, Tumbler};
use skep_arrangement::{Run, VPos, VSpec};
use skep_content::Val;
use skep_discovery::{FourSet, OrphanReport, SlotSpec, SupClaim, Window};
use skep_febe::{
    Codec, Disposition, FaultSite, Op, OpKind, ParseError, RejectCode, Rejection, ReqId, Request,
    Response, SlotArg, SuccessorSpec,
};
use skep_kernel::Seq;
use skep_links::{Endset, Invalid, Link, View, MAX_SLOT_SPANS};
use skep_namespace::PrincipalId;
use skep_retrieval::{
    CompareReport, CorrPair, Deletions, Delivery, DeliveryItem, RegionSpec, Spec, SpanFault,
};
use skepd::JsonCodec;

// ── fixture vocabulary ──

fn t(comps: &[u64]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty component list")
}

fn a(comps: &[u64]) -> Address {
    validate(t(comps)).expect("T4-valid test address")
}

fn n(x: u64) -> Nat {
    Nat::from(x)
}

fn sp(start: &[u64], width: &[u64]) -> Span {
    Span::new(t(start), t(width)).expect("well-formed test span")
}

fn vp(s: u64, o: u64) -> VPos {
    VPos { subspace: n(s), ordinal: n(o) }
}

fn d1() -> Address {
    a(&[1, 0, 1, 0, 1])
}

fn d2() -> Address {
    a(&[1, 0, 1, 0, 2])
}

fn d3() -> Address {
    a(&[1, 0, 1, 0, 3])
}

fn link1() -> Address {
    a(&[1, 0, 1, 0, 1, 0, 2, 1])
}

fn link2() -> Address {
    a(&[1, 0, 1, 0, 1, 0, 2, 2])
}

fn cspan(ord: u64, w: u64) -> Span {
    sp(&[1, ord], &[0, w])
}

fn vs(source: Address, ord: u64, w: u64) -> VSpec {
    VSpec { source, span: cspan(ord, w) }
}

fn ispan() -> Span {
    sp(&[1, 0, 1, 0, 1, 0, 1, 1], &[0, 0, 0, 0, 0, 0, 0, 5])
}

fn q_all() -> FourSet {
    FourSet { home: SlotSpec::Any, from: SlotSpec::Any, to: SlotSpec::Any, ty: SlotSpec::Any }
}

fn rq(id: Option<&str>, op: Op) -> Request {
    Request { id: id.map(|s| ReqId(s.as_bytes().to_vec())), op }
}

/// Unwrap a parse, naming the frame as well as the fault — which
/// `Result::expect` cannot do, since it sees only the error.
fn parse_ok(codec: &JsonCodec, frame: &[u8]) -> Request {
    codec.parse(frame).unwrap_or_else(|e| {
        panic!("frame failed to parse ({e}): {}", String::from_utf8_lossy(frame))
    })
}

/// Every `Op` variant at least once; both `SlotArg` forms on make_link's
/// slots (wire v5) and on the successor type slot, both cursor states, all
/// three slot-constraint forms, and all four value write forms (per-byte
/// runs, a UTF-8 atom, a non-UTF-8 run, a non-UTF-8 atom).
fn all_requests() -> Vec<Request> {
    vec![
        rq(Some("idem-1"), Op::CreateNewDocument { account: a(&[1, 0, 1]) }),
        rq(None, Op::Delegate { new_prefix: t(&[1, 0, 2]), new_id: PrincipalId(2) }),
        rq(None, Op::RegisterNode { addr: t(&[1, 1]) }),
        rq(None, Op::Fork),
        rq(None, Op::NextAccountPrefix { parent: a(&[1]) }),
        rq(None, Op::PrincipalPrefix { id: PrincipalId(2) }),
        rq(
            None,
            Op::Insert {
                doc: d1(),
                at: vp(1, 1),
                // Canonical: ["hi",{"atom":"atom!"},{"hex":"ff"},{"atom_hex":"00ff"}]
                values: vec![
                    Val::new(vec![b'h']),
                    Val::new(vec![b'i']),
                    Val::new(b"atom!".to_vec()),
                    Val::new(vec![0xffu8]),
                    Val::new(vec![0u8, 255]),
                ],
            },
        ),
        rq(None, Op::Delete { doc: d1(), p: vp(1, 3), width: n(2) }),
        rq(None, Op::Copy { doc: d1(), at: vp(1, 6), specs: vec![vs(d2(), 1, 5)] }),
        rq(None, Op::Rearrange { doc: d1(), cuts: vec![vp(1, 1), vp(1, 3), vp(1, 6)] }),
        rq(None, Op::Version { d_src: d1() }),
        rq(
            None,
            Op::MakeLink {
                home: d1(),
                from: SlotArg::Resolve(vec![vs(d1(), 1, 5)]),
                to: SlotArg::Resolve(vec![vs(d2(), 1, 6)]),
                ty: SlotArg::Resolve(vec![vs(d3(), 1, 1)]),
            },
        ),
        // Wire v5: mixed slots — a link-to-link addrs TO and a ghost
        // subspace-3 name typing the link.
        rq(
            None,
            Op::MakeLink {
                home: d1(),
                from: SlotArg::Resolve(vec![vs(d1(), 1, 5)]),
                to: SlotArg::Addrs(vec![link1()]),
                ty: SlotArg::Addrs(vec![a(&[1, 0, 1, 0, 3, 0, 3, 6, 1])]),
            },
        ),
        // Wire v5: empty addrs FROM/TO are expressible (the store's type
        // floor, not the codec, rejects an empty ty).
        rq(
            None,
            Op::MakeLink {
                home: d1(),
                from: SlotArg::Addrs(vec![]),
                to: SlotArg::Addrs(vec![]),
                ty: SlotArg::Addrs(vec![a(&[1, 0, 1, 0, 3, 0, 3, 6, 2])]),
            },
        ),
        rq(
            None,
            Op::Emit {
                home: d1(),
                ty: Endset::from_spans([sp(&[1, 1, 0, 1, 0, 1, 0, 1, 4], &[0, 0, 0, 0, 0, 0, 0, 0, 1])]),
                from: d1(),
                to: vec![d2()],
            },
        ),
        rq(None, Op::Nullify { home: d1(), target: link1() }),
        rq(None, Op::AssertSup { home: d1(), old: link1(), new: link2() }),
        rq(
            None,
            Op::EditLink {
                original: link1(),
                successor: SuccessorSpec {
                    from: vec![vs(d2(), 1, 5)],
                    to: vec![vs(d2(), 6, 2)],
                    ty: SlotArg::Addrs(vec![a(&[1, 0, 1, 0, 3, 0, 2, 1])]),
                },
                d_s: d2(),
                d_a: d1(),
            },
        ),
        rq(
            None,
            Op::EditLink {
                original: link1(),
                successor: SuccessorSpec {
                    from: vec![vs(d2(), 1, 5)],
                    to: vec![],
                    ty: SlotArg::Resolve(vec![vs(d3(), 1, 1)]),
                },
                d_s: d2(),
                d_a: d1(),
            },
        ),
        rq(None, Op::ReadLink { a: link1() }),
        rq(None, Op::FollowLink { a: link1(), slot: 2 }),
        rq(None, Op::RetrieveV { specs: vec![Spec { doc: d1(), span: cspan(1, 11) }] }),
        rq(None, Op::RetrieveDocVSpan { doc: d1() }),
        rq(None, Op::RetrieveDocVSpanSet { doc: d1() }),
        rq(None, Op::ShowOrigin { doc: d1(), span: cspan(1, 5) }),
        rq(None, Op::ShowDeletions { d_a: d1(), d_b: d2() }),
        rq(
            None,
            Op::Compare {
                rho1: vec![RegionSpec { doc: d1(), spans: vec![cspan(1, 5)] }],
                rho2: vec![RegionSpec { doc: d2(), spans: vec![cspan(1, 5)] }],
            },
        ),
        rq(
            None,
            Op::FindDocsContaining {
                regions: vec![RegionSpec { doc: d1(), spans: vec![cspan(1, 5)] }],
            },
        ),
        rq(None, Op::Image { d: d1(), region: vec![cspan(1, 5)] }),
        rq(None, Op::FindLinksV { d: d1(), region: vec![cspan(1, 5)] }),
        rq(
            None,
            Op::FindLinksFtt {
                q: FourSet {
                    home: SlotSpec::Any,
                    from: SlotSpec::Spans(Endset::from_spans([ispan()])),
                    to: SlotSpec::Any,
                    ty: SlotSpec::Empty,
                },
            },
        ),
        rq(None, Op::CountV { d: d1(), region: vec![cspan(1, 5)] }),
        rq(None, Op::CountFtt { q: q_all() }),
        rq(None, Op::WindowV { d: d1(), region: vec![cspan(1, 5)], cur: None, n: 16 }),
        rq(None, Op::WindowFtt { q: q_all(), cur: Some(link1()), n: 16 }),
        rq(None, Op::RetrieveEndsets { d: d1(), region: vec![cspan(1, 5)] }),
        rq(None, Op::Project { a: link1(), slot: 2, d: d2() }),
        rq(None, Op::DiscoverableFrom { a: link1(), d: d1() }),
        rq(None, Op::DeleteOrphans { d: d1(), p: vp(1, 3), width: n(2) }),
        rq(None, Op::InClaims { y: link1(), view: View::Active }),
        rq(None, Op::OutClaims { x: link2(), view: View::Audit }),
        // The third documented view (wire.md §Value encodings), so all
        // three ride the canonical round trip and not just two.
        rq(None, Op::InClaims { y: link2(), view: View::Default }),
    ]
}

const OP_NAMES: [&str; 38] = [
    "create_new_document",
    "delegate",
    "register_node",
    "fork",
    "next_account_prefix",
    "principal_prefix",
    "insert",
    "delete",
    "copy",
    "rearrange",
    "version",
    "make_link",
    "emit",
    "nullify",
    "assert_sup",
    "edit_link",
    "read_link",
    "follow_link",
    "retrieve_v",
    "retrieve_doc_v_span",
    "retrieve_doc_v_span_set",
    "show_origin",
    "show_deletions",
    "compare",
    "find_docs_containing",
    "image",
    "find_links_v",
    "find_links_ftt",
    "count_v",
    "count_ftt",
    "window_v",
    "window_ftt",
    "retrieve_endsets",
    "project",
    "discoverable_from",
    "delete_orphans",
    "in_claims",
    "out_claims",
];

/// parse ∘ marshal_request is the identity on canonical frames, for every
/// variant; and the emitted op-name set is exactly the documented 38.
#[test]
fn every_op_round_trips_canonically() {
    let codec = JsonCodec;
    let mut seen: Vec<String> = Vec::new();
    for req in all_requests() {
        let bytes = codec.marshal_request(&req);
        let parsed = parse_ok(&codec, &bytes);
        let bytes2 = codec.marshal_request(&parsed);
        assert_eq!(
            bytes,
            bytes2,
            "round-trip not a fixpoint for {}",
            String::from_utf8_lossy(&bytes)
        );
        let v: Value = serde_json::from_slice(&bytes).expect("canonical frame is JSON");
        seen.push(v["op"].as_str().expect("op tag").to_string());
    }
    seen.sort();
    seen.dedup();
    let mut expected: Vec<&str> = OP_NAMES.to_vec();
    expected.sort();
    assert_eq!(seen, expected, "op-name coverage drifted");
}

/// The idempotency id rides the frame and survives the round trip.
#[test]
fn request_id_round_trips() {
    let codec = JsonCodec;
    let req = rq(Some("key-9"), Op::Fork);
    let parsed = parse_ok(&codec, &codec.marshal_request(&req));
    assert_eq!(parsed.id, Some(ReqId(b"key-9".to_vec())));
}

/// Every non-rejected `Response` shape, built fresh on each call so
/// determinism can be checked across two independent constructions
/// (`Response` derives no `Clone`, deliberately).
fn all_responses() -> Vec<(&'static str, Response)> {
    vec![
        ("ack", Response::Ack { at: Seq(7) }),
        ("ack_addr", Response::AckAddr { addr: a(&[1, 0, 1, 0, 1, 0, 1, 1]), at: Seq(7) }),
        (
            "ack_edit",
            Response::AckEdit {
                successor: link2(),
                claim: a(&[1, 0, 1, 0, 1, 0, 2, 3]),
                at: Seq(7),
            },
        ),
        (
            "delivery",
            Response::Delivery {
                items: Delivery(vec![
                    DeliveryItem::Content(Val::new(vec![b'h'])),
                    DeliveryItem::Content(Val::new(vec![b'i'])),
                    DeliveryItem::Content(Val::new(b"hello".to_vec())),
                    DeliveryItem::Content(Val::new(vec![0u8, 255])),
                    DeliveryItem::Ref(link1()),
                ]),
                as_of: Seq(9),
            },
        ),
        (
            "span_set",
            Response::SpanSet { set: [ispan()].into_iter().collect::<SpanSet>(), as_of: Seq(9) },
        ),
        ("addrs", Response::Addrs { addrs: vec![link1()], as_of: Seq(9) }),
        ("maybe_addr", Response::MaybeAddr { addr: Some(a(&[1, 0, 2])), as_of: Seq(9) }),
        ("maybe_addr_none", Response::MaybeAddr { addr: None, as_of: Seq(9) }),
        ("count", Response::Count { n: 2, as_of: Seq(9) }),
        (
            "page",
            Response::Page {
                window: Window { batch: vec![link1()], next: Some(link1()), exhausted: true },
                as_of: Seq(9),
            },
        ),
        (
            "endsets",
            Response::Endsets {
                pairs: vec![(1, Endset::from_spans([cspan(1, 5)]))],
                as_of: Seq(9),
            },
        ),
        (
            "runs",
            Response::Runs {
                runs: vec![Run::new(a(&[1, 0, 1, 0, 1, 0, 1, 1]), n(5))
                    .expect("element-level run fixture")],
                as_of: Seq(9),
            },
        ),
        ("bool", Response::Bool { val: true, as_of: Seq(9) }),
        (
            "link_value",
            Response::LinkValue {
                link: Some(
                    Link::new([
                        Endset::from_spans([ispan()]),
                        Endset::from_spans([sp(
                            &[1, 0, 1, 0, 2, 0, 1, 1],
                            &[0, 0, 0, 0, 0, 0, 0, 6],
                        )]),
                        Endset::from_spans([sp(
                            &[1, 0, 1, 0, 3, 0, 1, 1],
                            &[0, 0, 0, 0, 0, 0, 0, 1],
                        )]),
                    ])
                    .expect("arity-3 link fixture"),
                ),
                as_of: Seq(9),
            },
        ),
        ("link_value_null", Response::LinkValue { link: None, as_of: Seq(9) }),
        (
            "follow",
            Response::Follow {
                result: Ok([ispan()].into_iter().collect::<SpanSet>()),
                as_of: Seq(9),
            },
        ),
        ("follow_invalid", Response::Follow { result: Err(Invalid), as_of: Seq(9) }),
        (
            "deletions",
            Response::Deletions {
                rep: Deletions { deleted_from_a_with_b: vec![a(&[1, 0, 1, 0, 1, 0, 1, 1])], deleted_from_b_with_a: vec![] },
                as_of: Seq(9),
            },
        ),
        (
            "compare",
            Response::Compare {
                rep: CompareReport(vec![CorrPair {
                    d1: d1(),
                    u1: vp(1, 1),
                    d2: d2(),
                    u2: vp(1, 3),
                    width: n(5),
                }]),
                as_of: Seq(9),
            },
        ),
        (
            "orphans",
            Response::Orphans { report: OrphanReport { orphaned: vec![link1()] }, as_of: Seq(9) },
        ),
        (
            "claims",
            Response::Claims {
                claims: vec![SupClaim {
                    claim: a(&[1, 0, 1, 0, 1, 0, 2, 3]),
                    old: link1(),
                    new: link2(),
                    home: d1(),
                    active: true,
                }],
                as_of: Seq(9),
            },
        ),
        (
            "rejected",
            Response::Rejected(Rejection {
                op: OpKind::Insert,
                code: RejectCode::Unauthenticated,
                disposition: Disposition::Permanent,
                site: None,
                detail: None,
            }),
        ),
        (
            "rejected_site",
            Response::Rejected(Rejection {
                op: OpKind::RetrieveV,
                code: RejectCode::MalformedSpan,
                disposition: Disposition::Permanent,
                site: Some(FaultSite {
                    index: Some(1),
                    fault: Some(SpanFault::NotOrdinalLevel),
                    ..FaultSite::default()
                }),
                detail: None,
            }),
        ),
        (
            "rejected_unparseable",
            JsonCodec.unparseable(ParseError { detail: Some("unknown op 'frobnicate'".into()) }),
        ),
    ]
}

/// Marshal determinism: same value twice → byte-equal; two independent
/// constructions of the same value → byte-equal; and every shape name is
/// distinct where it should be.
#[test]
fn every_response_shape_marshals_deterministically() {
    let codec = JsonCodec;
    let first = all_responses();
    let second = all_responses();
    assert_eq!(first.len(), second.len());
    for ((name_a, resp_a), (name_b, resp_b)) in first.iter().zip(second.iter()) {
        assert_eq!(name_a, name_b);
        let one = codec.marshal(resp_a);
        assert_eq!(one, codec.marshal(resp_a), "double marshal differs for {name_a}");
        assert_eq!(one, codec.marshal(resp_b), "independent construction differs for {name_a}");
        // Every marshaled response is itself valid JSON with a resp tag.
        let v: Value = serde_json::from_slice(&one).expect("marshal emits JSON");
        assert!(v["resp"].is_string(), "{name_a} lacks a resp tag");
    }
}

/// The rejection codes wire.md documents: every backtick-quoted
/// snake_case token in §Rejection codes. Harvested from the arbiter rather
/// than restated, because a third hand transcription would drift the same
/// way the table below already did.
///
/// The section ends at the next heading of ANY level, not at the next
/// top-level one: §Credential refusals follows it and spells out the
/// DETAIL tokens `credential_refused` carries (`already_claimed`,
/// `mint_home_first`, `malformed_payload:<sub>`, …). Those are not codes,
/// no `RejectCode` row can pin them, and reading them as codes would make
/// this harvest measure the table against the wrong list.
fn documented_reject_codes() -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/wire.md");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let after = text
        .split_once("### Rejection codes")
        .expect("wire.md names its rejection-code section")
        .1;
    let end = [after.find("\n### "), after.find("\n## ")]
        .into_iter()
        .flatten()
        .min()
        .expect("the section ends at the next heading");
    let section = &after[..end];
    let mut out: Vec<String> = section
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|t| {
            !t.is_empty()
                && t.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
        .map(str::to_string)
        .collect();
    out.sort();
    out.dedup();
    // The harvest must not go vacuous if the section's prose is reshaped:
    // an empty list would make the check below pass by finding nothing.
    assert!(out.len() > 50, "harvested only {} codes; wire.md's section shape changed", out.len());
    out
}

/// The full `RejectCode` wire-name table — all 64 codes, pinned.
/// `code_name` is exhaustive over the enum, so the compiler forces a new
/// variant to be NAMED; this forces the name to be the one wire.md
/// publishes, and the harvest above forces the table to hold every code
/// the document lists save the one the daemon originates itself.
#[test]
fn reject_code_names_are_pinned() {
    let table: [(RejectCode, &str); 64] = [
        (RejectCode::Unauthenticated, "unauthenticated"),
        (RejectCode::Malformed, "malformed"),
        (RejectCode::Durability, "durability"),
        (RejectCode::TxnUnencodable, "txn_unencodable"),
        (RejectCode::TxnOverBudget, "txn_over_budget"),
        (RejectCode::Poisoned, "poisoned"),
        (RejectCode::HomeNotRegistered, "home_not_registered"),
        (RejectCode::DocNotRegistered, "doc_not_registered"),
        (RejectCode::SourceNotRegistered, "source_not_registered"),
        (RejectCode::ParentNotRegistered, "parent_not_registered"),
        (RejectCode::NotRegistered, "not_registered"),
        (RejectCode::OriginalNotResident, "original_not_resident"),
        (RejectCode::EndpointNotResident, "endpoint_not_resident"),
        (RejectCode::NotOwner, "not_owner"),
        (RejectCode::NotAnAccount, "not_an_account"),
        (RejectCode::Gate, "gate"),
        (RejectCode::DelegatorUnknown, "delegator_unknown"),
        (RejectCode::DuplicateId, "duplicate_id"),
        (RejectCode::NotAncestor, "not_ancestor"),
        (RejectCode::NotAuthorized, "not_authorized"),
        (RejectCode::NotAccountTier, "not_account_tier"),
        (RejectCode::NotTopDown, "not_top_down"),
        (RejectCode::NotNextForm, "not_next_form"),
        (RejectCode::NotValid, "not_valid"),
        (RejectCode::NotNode, "not_node"),
        (RejectCode::TooDeep, "too_deep"),
        (RejectCode::NotDescendantOfBootstrap, "not_descendant_of_bootstrap"),
        (RejectCode::NotFresh, "not_fresh"),
        (RejectCode::EmptyContent, "empty_content"),
        (RejectCode::Content, "content"),
        (RejectCode::EmptySource, "empty_source"),
        (RejectCode::NotOrdinalVSpan, "not_ordinal_vspan"),
        (RejectCode::DanglingSource, "dangling_source"),
        (RejectCode::TooManyRuns, "too_many_runs"),
        (RejectCode::EmptyResult, "empty_result"),
        (RejectCode::NotArranged, "not_arranged"),
        (RejectCode::OutOfBounds, "out_of_bounds"),
        (RejectCode::EmptyWidth, "empty_width"),
        (RejectCode::BadCutCount, "bad_cut_count"),
        (RejectCode::NotAscending, "not_ascending"),
        (RejectCode::EmptyContentSubspace, "empty_content_subspace"),
        (RejectCode::NotAPrincipal, "not_a_principal"),
        (RejectCode::NodeTierCrossOwner, "node_tier_cross_owner"),
        (RejectCode::NotLinkAddress, "not_link_address"),
        (RejectCode::NotHomeLink, "not_home_link"),
        (RejectCode::AlreadySeated, "already_seated"),
        (RejectCode::NotContentSubspace, "not_content_subspace"),
        (RejectCode::IllFormedSpec, "ill_formed_spec"),
        (RejectCode::SlotTooLarge, "slot_too_large"),
        (RejectCode::EmptyTypeResolution, "empty_type_resolution"),
        (RejectCode::ShapeViolation, "shape_violation"),
        (RejectCode::RetractionClass, "retraction_class"),
        (RejectCode::NonAddressDenotingType, "non_address_denoting_type"),
        (RejectCode::BadTarget, "bad_target"),
        (RejectCode::SelfSupersession, "self_supersession"),
        (RejectCode::IllFormedSuccessor, "ill_formed_successor"),
        (RejectCode::DcViolation, "dc_violation"),
        (RejectCode::NoSuchSubspace, "no_such_subspace"),
        (RejectCode::EmptySubspace, "empty_subspace"),
        (RejectCode::DepthIncompatible, "depth_incompatible"),
        (RejectCode::RangeNotPresent, "range_not_present"),
        (RejectCode::MalformedSpan, "malformed_span"),
        (RejectCode::NotALink, "not_a_link"),
        (RejectCode::BadRegion, "bad_region"),
    ];
    let codec = JsonCodec;
    for (code, name) in table {
        let resp = Response::Rejected(Rejection {
            op: OpKind::Insert,
            code,
            disposition: Disposition::Permanent,
            site: None,
            detail: None,
        });
        let v: Value = serde_json::from_slice(&codec.marshal(&resp)).expect("json");
        assert_eq!(v["code"].as_str(), Some(name), "wire name drifted for {code:?}");
    }
    // The harvest reads prose, so it cannot tell a code from a word the
    // prose quotes while describing one. These three are every such word
    // §Rejection codes carries, each with the reason it is not a table
    // error and where it IS watched:
    //
    // * `credential_refused` — a code, but the DAEMON's own, built by
    //   `daemon_rejected` rather than lowered from `RejectCode`, which has
    //   no such variant (wire.md: "the auth work's one new code"). Its
    //   wire shape is asserted end to end in `tests/auth_wire.rs`.
    // * `permanent` — a disposition, pinned by
    //   `every_disposition_marshals_and_diagnostics_are_omitted_when_absent`.
    // * `detail` — the rejection envelope's own field, pinned by that same
    //   test's presence rules.
    //
    // Named rather than filtered by shape, and each required below to
    // still appear in the section, so an exemption cannot outlive the
    // sentence that earns it. A FOURTH word appearing here should fail
    // this test: the right answer is to read the new sentence and decide
    // whether it names a code, not to widen the list to quiet it.
    const NOT_TABLE_ROWS: [&str; 3] = ["credential_refused", "detail", "permanent"];
    // Every other code the document lists must be pinned here. The reverse
    // is deliberately NOT asserted: `slot_too_large` is a name `code_name`
    // can emit that wire.md v6.1 assigns no code to — a guarantee question,
    // not a table error (see the boundary note).
    let documented = documented_reject_codes();
    let pinned: std::collections::HashSet<&str> = table.iter().map(|&(_, n)| n).collect();
    for name in &documented {
        assert!(
            pinned.contains(name.as_str()) || NOT_TABLE_ROWS.contains(&name.as_str()),
            "wire.md documents rejection code '{name}', which this table does not pin"
        );
    }
    for name in NOT_TABLE_ROWS {
        assert!(
            documented.iter().any(|d| d == name),
            "'{name}' is exempted from the table, but §Rejection codes no longer quotes it"
        );
    }
}

/// The four dispositions and the diagnostic-field presence rules.
#[test]
fn every_disposition_marshals_and_diagnostics_are_omitted_when_absent() {
    let codec = JsonCodec;
    let table = [
        (Disposition::Permanent, "permanent"),
        (Disposition::Reorder, "reorder"),
        (Disposition::Retry, "retry"),
        (Disposition::Halt, "halt"),
    ];
    for (disp, name) in table {
        let resp = Response::Rejected(Rejection {
            op: OpKind::Delete,
            code: RejectCode::OutOfBounds,
            disposition: disp,
            site: None,
            detail: None,
        });
        let v: Value = serde_json::from_slice(&codec.marshal(&resp)).expect("json");
        assert_eq!(v["disposition"].as_str(), Some(name));
        // Diagnostic options are OMITTED when absent, not null.
        assert!(v.get("site").is_none());
        assert!(v.get("detail").is_none());
    }
    // …and present when carried, including the full site field set.
    let resp = Response::Rejected(Rejection {
        op: OpKind::Compare,
        code: RejectCode::DocNotRegistered,
        disposition: Disposition::Reorder,
        site: Some(FaultSite {
            operand: Some(skep_retrieval::Operand::Second),
            region: Some(0),
            slot: Some(skep_febe::FROM),
            index: Some(2),
            fault: Some(SpanFault::StartTooShallow),
            addr: Some(d2()),
        }),
        detail: Some("d2 not registered".into()),
    });
    let v: Value = serde_json::from_slice(&codec.marshal(&resp)).expect("json");
    assert_eq!(v["site"]["operand"].as_str(), Some("second"));
    assert_eq!(v["site"]["region"].as_u64(), Some(0));
    assert_eq!(v["site"]["slot"].as_u64(), Some(skep_febe::FROM as u64));
    assert_eq!(v["site"]["index"].as_u64(), Some(2));
    assert_eq!(v["site"]["fault"].as_str(), Some("start_too_shallow"));
    assert_eq!(v["site"]["addr"].as_str(), Some("1.0.1.0.2"));
    assert_eq!(v["detail"].as_str(), Some("d2 not registered"));
}

/// wire.md §Value encodings: "Span sets and endsets are JSON arrays of
/// spans, ORDER PRESERVED VERBATIM" — the rule `Endset::from_spans` states
/// upstream too ("stored exactly as given, never canonicalized at rest").
/// Every endset fixture in this suite carries exactly one span, so nothing
/// watched the sequence: a sort, a merge of the two adjacent spans, or a
/// dedup of the repeated one would pass every test and silently change
/// what a client reads back from `read_link` and what an addrs-form `ty`
/// denotes.
#[test]
fn an_endset_round_trips_its_spans_in_the_order_given() {
    let codec = JsonCodec;
    // Descending, then two adjacent (mergeable), then a repeat: the three
    // shapes a canonicalizer touches.
    let frame = br#"{"op":"emit","home":"1.0.1.0.1","from":"1.0.1.0.1","to":[],"ty":[{"start":"1.9","width":"0.1"},{"start":"1.1","width":"0.1"},{"start":"1.2","width":"0.1"},{"start":"1.1","width":"0.1"}]}"#;
    let canon: Value =
        serde_json::from_slice(&codec.marshal_request(&parse_ok(&codec, frame))).expect("json");
    let expect: Value = serde_json::from_str(
        r#"[{"start":"1.9","width":"0.1"},{"start":"1.1","width":"0.1"},{"start":"1.2","width":"0.1"},{"start":"1.1","width":"0.1"}]"#,
    )
    .expect("json");
    assert_eq!(canon["ty"], expect, "an endset keeps the order and the multiplicity given");
}

/// Lenient parse, canonical emit: integer naturals, uppercase hex, shuffled
/// field order, and the empty slot-constraint normalization all read; the
/// canonical form is what comes back out.
#[test]
fn lenient_forms_parse_and_re_emit_canonically() {
    let codec = JsonCodec;
    // Integer nats and shuffled fields.
    let lenient =
        br#"{"values":["hi"],"doc":"1.0.1.0.1","op":"insert","at":{"subspace":1,"ordinal":1}}"#;
    let parsed = parse_ok(&codec, lenient);
    let canon: Value = serde_json::from_slice(&codec.marshal_request(&parsed)).expect("json");
    assert_eq!(canon["at"]["subspace"].as_str(), Some("1"), "canonical nats are strings");
    // Uppercase hex reads; canonical output is lowercase.
    let hexed = br#"{"op":"insert","doc":"1.0.1.0.1","at":{"subspace":"1","ordinal":"1"},"values":[{"hex":"00FF"}]}"#;
    let parsed = parse_ok(&codec, hexed);
    let canon: Value = serde_json::from_slice(&codec.marshal_request(&parsed)).expect("json");
    assert_eq!(canon["values"][0]["hex"].as_str(), Some("00ff"));
    // Empty slot-constraint array normalizes onto "empty".
    let ftt = br#"{"op":"count_ftt","q":{"home":[],"from":"any","to":"any","ty":"any"}}"#;
    let parsed = parse_ok(&codec, ftt);
    let canon: Value = serde_json::from_slice(&codec.marshal_request(&parsed)).expect("json");
    assert_eq!(canon["q"]["home"].as_str(), Some("empty"));
    // A beyond-u64 natural rides the string form.
    let wide = br#"{"op":"delete","doc":"1.0.1.0.1","p":{"subspace":"1","ordinal":"1"},"width":"18446744073709551616"}"#;
    let parsed = parse_ok(&codec, wide);
    let canon: Value = serde_json::from_slice(&codec.marshal_request(&parsed)).expect("json");
    assert_eq!(canon["width"].as_str(), Some("18446744073709551616"));
    // An absent `cur` is ⊥, exactly as an explicit null is (wire.md §Value
    // encodings: "An absent `cur` field means `null`") — the one accessor
    // whose absence is not a missing field. Both doc examples spell it out,
    // so no frame in this suite had ever omitted it.
    let bare = br#"{"op":"window_v","d":"1.0.1.0.1","region":[{"start":"1.1","width":"0.5"}],"n":16}"#;
    let with_null = br#"{"op":"window_v","cur":null,"d":"1.0.1.0.1","region":[{"start":"1.1","width":"0.5"}],"n":16}"#;
    assert_eq!(
        codec.marshal_request(&parse_ok(&codec, bare)),
        codec.marshal_request(&parse_ok(&codec, with_null)),
        "an absent cursor is the same request as an explicit null one"
    );
}

/// Wire v2 write forms: `"str"`/`{"hex"}` mint one single-byte value per
/// byte, `{"atom"}`/`{"atom_hex"}` mint one composite value; mixed arrays
/// concatenate in order; the canonical form coalesces maximal per-byte runs
/// and renders one-byte atoms per-byte; empty per-byte forms are vacuous and
/// empty atoms are inexpressible.
#[test]
fn value_write_forms_round_trip() {
    let codec = JsonCodec;
    let frame = |values: &str| {
        format!(
            r#"{{"op":"insert","doc":"1.0.1.0.1","at":{{"subspace":"1","ordinal":"1"}},"values":{values}}}"#
        )
    };
    let vals = |req: &Request| match &req.op {
        Op::Insert { values, .. } => values.clone(),
        _ => panic!("insert expected"),
    };
    let canon = |req: &Request| -> Value {
        serde_json::from_slice::<Value>(&codec.marshal_request(req)).expect("canonical is JSON")
            ["values"]
            .clone()
    };
    let jv = |s: &str| serde_json::from_str::<Value>(s).expect("expectation is JSON");

    // "str": one single-byte value per UTF-8 byte ("hé" = 'h' + 2 bytes of 'é').
    let parsed = parse_ok(&codec, frame(r#"["hé"]"#).as_bytes());
    let values = vals(&parsed);
    assert_eq!(values.len(), 3);
    assert!(values.iter().all(|v| v.as_bytes().len() == 1));
    assert_eq!(canon(&parsed), jv(r#"["hé"]"#));

    // {"hex"}: per-byte as well; a non-UTF-8 run re-marshals on the hex path.
    let parsed = parse_ok(&codec, frame(r#"[{"hex":"00ff"}]"#).as_bytes());
    let values = vals(&parsed);
    assert_eq!(values.len(), 2);
    assert_eq!(canon(&parsed), jv(r#"[{"hex":"00ff"}]"#));

    // {"atom"}: ONE composite value; {"atom_hex"}: one composite of raw bytes.
    let parsed = parse_ok(&codec, frame(r#"[{"atom":"hello"}]"#).as_bytes());
    let values = vals(&parsed);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].as_bytes(), b"hello");
    assert_eq!(canon(&parsed), jv(r#"[{"atom":"hello"}]"#));
    let parsed = parse_ok(&codec, frame(r#"[{"atom_hex":"00ff"}]"#).as_bytes());
    let values = vals(&parsed);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].as_bytes(), &[0x00, 0xff]);
    assert_eq!(canon(&parsed), jv(r#"[{"atom_hex":"00ff"}]"#));

    // Mixed arrays concatenate in order and are canonical as given.
    let parsed = parse_ok(&codec, frame(r#"["ab",{"atom":"cd"},"ef"]"#).as_bytes());
    assert_eq!(vals(&parsed).len(), 5);
    assert_eq!(canon(&parsed), jv(r#"["ab",{"atom":"cd"},"ef"]"#));

    // Adjacent per-byte elements canonicalize onto one maximal run…
    let parsed = parse_ok(&codec, frame(r#"["ab","cd"]"#).as_bytes());
    assert_eq!(canon(&parsed), jv(r#"["abcd"]"#));
    // …and a one-byte atom IS a single-byte value (granularity distinguishes
    // only multi-byte payloads), canonicalizing onto the per-byte form.
    let parsed = parse_ok(&codec, frame(r#"[{"atom":"x"}]"#).as_bytes());
    assert_eq!(canon(&parsed), jv(r#"["x"]"#));

    // Empty per-byte forms contribute zero values (the store still rejects a
    // zero-total insert; that verdict is the store's, not the parse's).
    let parsed = parse_ok(&codec, frame(r#"["",{"hex":""}]"#).as_bytes());
    assert!(vals(&parsed).is_empty());
    assert_eq!(canon(&parsed), jv("[]"));

    // Zero-byte atoms and multi-key objects are parse failures.
    for bad in [
        r#"[{"atom":""}]"#,
        r#"[{"atom_hex":""}]"#,
        r#"[{"atom":"a","hex":"00"}]"#,
        r#"[{}]"#,
    ] {
        assert!(codec.parse(frame(bad).as_bytes()).is_err(), "{bad} must not parse");
    }
}

/// The delivery marshal is injective across granularity: N per-byte values
/// and one N-byte composite render differently, so a client always knows
/// which world it is looking at.
#[test]
fn delivery_marshal_distinguishes_granularity() {
    let codec = JsonCodec;
    let per_byte = Response::Delivery {
        items: Delivery(
            b"hello".iter().map(|&b| DeliveryItem::Content(Val::new(vec![b]))).collect(),
        ),
        as_of: Seq(9),
    };
    let atom = Response::Delivery {
        items: Delivery(vec![DeliveryItem::Content(Val::new(b"hello".to_vec()))]),
        as_of: Seq(9),
    };
    let per_bytes = codec.marshal(&per_byte);
    let atom_bytes = codec.marshal(&atom);
    assert_ne!(per_bytes, atom_bytes, "granularity must survive the marshal");
    let v: Value = serde_json::from_slice(&per_bytes).expect("json");
    assert_eq!(v["items"], serde_json::from_str::<Value>(r#"[{"content":"hello"}]"#).unwrap());
    let v: Value = serde_json::from_slice(&atom_bytes).expect("json");
    assert_eq!(v["items"], serde_json::from_str::<Value>(r#"[{"atom":"hello"}]"#).unwrap());
}

/// Delivery runs coalesce maximally and are judged UTF-8 on the whole
/// concatenation; refs and atoms break runs; non-UTF-8 takes the hex paths.
#[test]
fn delivery_runs_coalesce_and_split() {
    let codec = JsonCodec;
    let c = |b: u8| DeliveryItem::Content(Val::new(vec![b]));
    let items_of = |resp: &Response| -> Value {
        serde_json::from_slice::<Value>(&codec.marshal(resp)).expect("json")["items"].clone()
    };
    // 'é' arrives as two per-byte values; the run is one valid-UTF-8 item.
    let utf8 =
        Response::Delivery { items: Delivery(vec![c(b'h'), c(0xc3), c(0xa9)]), as_of: Seq(9) };
    assert_eq!(items_of(&utf8), serde_json::from_str::<Value>(r#"[{"content":"hé"}]"#).unwrap());
    // An invalid concatenation renders the WHOLE run as hex.
    let raw = Response::Delivery { items: Delivery(vec![c(0xc3), c(0x28)]), as_of: Seq(9) };
    assert_eq!(items_of(&raw), serde_json::from_str::<Value>(r#"[{"hex":"c328"}]"#).unwrap());
    // Refs and atoms break runs; a non-UTF-8 composite is atom_hex.
    let mixed = Response::Delivery {
        items: Delivery(vec![
            c(b'a'),
            DeliveryItem::Ref(link1()),
            c(b'b'),
            DeliveryItem::Content(Val::new(vec![0u8, 255])),
            c(b'c'),
        ]),
        as_of: Seq(9),
    };
    let expect: Value = serde_json::from_str(
        r#"[{"content":"a"},{"ref":"1.0.1.0.1.0.2.1"},{"content":"b"},{"atom_hex":"00ff"},{"content":"c"}]"#,
    )
    .unwrap();
    assert_eq!(items_of(&mixed), expect);
}

/// wire.md §Value encodings: a zero-width span is "rejected at parse" — so
/// a frame carrying one is answered on the PARSE channel, with a detail
/// naming the span, never admitted for a store to judge later under some
/// other code. Every op shape that carries a span is checked, since each
/// reaches `p_span` by its own path.
#[test]
fn a_zero_width_span_is_refused_at_parse() {
    let codec = JsonCodec;
    let frames: [&[u8]; 4] = [
        br#"{"op":"retrieve_v","specs":[{"doc":"1.0.1.0.1","span":{"start":"1.1","width":"0.0"}}]}"#,
        br#"{"op":"show_origin","doc":"1.0.1.0.1","span":{"start":"1.1","width":"0.0"}}"#,
        br#"{"op":"image","d":"1.0.1.0.1","region":[{"start":"1.1","width":"0.0"}]}"#,
        br#"{"op":"emit","home":"1.0.1.0.1","from":"1.0.1.0.1","to":[],"ty":[{"start":"1.1","width":"0.0"}]}"#,
    ];
    for frame in frames {
        // `Request` derives no Debug, so `expect_err` cannot apply; match.
        let err = match codec.parse(frame) {
            Err(e) => e,
            Ok(_) => {
                panic!("a zero-width span must not parse: {}", String::from_utf8_lossy(frame))
            }
        };
        let detail = err.detail.expect("a parse failure names what failed");
        assert!(
            detail.contains("ill-formed span"),
            "the detail must localize the span, not something else: {detail}"
        );
    }
}

/// Never-silent applied to typos: unknown ops, unknown fields, missing
/// fields, malformed addresses, and non-object frames all fail parse with a
/// detail message. The make_link slot grammar is exactly two forms: the
/// tagged `{"resolve"}` object belongs to edit_link's successor `ty` alone,
/// and addrs names must be T4-valid addresses.
#[test]
fn every_malformed_frame_fails_parse_with_a_detail() {
    let codec = JsonCodec;
    let bad: [&[u8]; 12] = [
        b"not json at all",
        br#"["op","fork"]"#,
        br#"{"op":"frobnicate"}"#,
        br#"{"op":"fork","surprise":1}"#,
        br#"{"op":"version"}"#,
        br#"{"op":"version","d_src":"0.1"}"#,
        br#"{"op":"insert","doc":"1.0.1.0.1","at":{"subspace":"1","ordinal":"1"},"values":[true]}"#,
        br#"{"op":"make_link","home":"1.0.1.0.1","from":[],"to":[],"ty":{"resolve":[]}}"#,
        br#"{"op":"make_link","home":"1.0.1.0.1","from":[],"to":[],"ty":{"addrs":["0.1"]}}"#,
        // Signed and fractional numbers where the wire says "non-negative
        // integer": a slot index, a natural width, and a page size. Each
        // wraps rather than merely differing if the parse is ever widened
        // to `as_i64()`.
        br#"{"op":"follow_link","a":"1.0.1.0.1.0.2.1","slot":-1}"#,
        br#"{"op":"delete","doc":"1.0.1.0.1","p":{"subspace":"1","ordinal":"1"},"width":-1}"#,
        br#"{"op":"window_v","d":"1.0.1.0.1","region":[{"start":"1.1","width":"0.5"}],"cur":null,"n":2.5}"#,
    ];
    for frame in bad {
        let err = match codec.parse(frame) {
            Err(e) => e,
            Ok(_) => panic!("frame must not parse: {}", String::from_utf8_lossy(frame)),
        };
        assert!(err.detail.is_some(), "parse failure must carry a detail");
    }
}

/// `marshal_request`'s stated precondition, at the boundary: a `Request`
/// past the wire caps marshals fine and produces a frame `parse` refuses.
///
/// The caps are the parse side's trust-boundary obligation and this
/// direction does not re-check them — one check, one owner — so the
/// round-trip promise is conditional, and this is where that condition is
/// a fact rather than a sentence. `MAX_SLOT_SPANS` is M7's published
/// per-slot budget, which the codec adopts verbatim as its list cap.
#[test]
fn an_over_cap_request_marshals_to_a_frame_parse_refuses() {
    let codec = JsonCodec;
    let spans = |n: usize| Endset::from_spans((0..n).map(|_| ispan()));

    // At the cap the promise holds in full.
    let at_cap = rq(
        None,
        Op::FindLinksFtt {
            q: FourSet {
                home: SlotSpec::Any,
                from: SlotSpec::Spans(spans(MAX_SLOT_SPANS)),
                to: SlotSpec::Any,
                ty: SlotSpec::Any,
            },
        },
    );
    let bytes = codec.marshal_request(&at_cap);
    assert_eq!(
        codec.marshal_request(&parse_ok(&codec, &bytes)),
        bytes,
        "a request at the cap round-trips"
    );

    // One past it, the marshal still succeeds — and the parse refuses it.
    let over = rq(
        None,
        Op::FindLinksFtt {
            q: FourSet {
                home: SlotSpec::Any,
                from: SlotSpec::Spans(spans(MAX_SLOT_SPANS + 1)),
                to: SlotSpec::Any,
                ty: SlotSpec::Any,
            },
        },
    );
    let bytes = codec.marshal_request(&over);
    let err = match codec.parse(&bytes) {
        Err(e) => e,
        Ok(_) => panic!("an over-cap frame must not parse"),
    };
    let detail = err.detail.expect("a parse failure names what failed");
    assert!(detail.contains("wire cap"), "the refusal names the cap: {detail}");
}
