//! `skep/docs/wire.md` is tested, not decorative: every fenced JSON example
//! annotated `<!-- wire: request <op> -->` must parse and be canonical,
//! every `<!-- wire: response <name> -->` block must equal the marshal of
//! the corresponding fixture here, every `<!-- wire: op_at <name> -->`
//! block must be the strict history envelope around a canonical read frame,
//! and every `<!-- wire: error <name> -->` block must equal its
//! transport-error fixture. Coverage is asserted both ways — an op or
//! response shape missing from the doc fails, and a doc marker without a
//! fixture fails.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;
use skep_address::{validate, Address, Nat, Span, SpanSet, Tumbler};
use skep_arrangement::{Run, VPos};
use skep_content::Val;
use skep_discovery::{GoOn, LinkRow, OrphanReport, SupClaim, Window};
use skep_febe::{
    BirthVersion, Codec, Disposition, EditionClaim, FaultSite, IItem, Marker, MintTime, OpKind,
    ParseError, RejectCode, Rejection, Response, ShotTerms, TimeSource, UniversalGrant,
};
use skep_kernel::Seq;
use skep_links::{Endset, Invalid, Link};
use skep_namespace::PrincipalId;
use skep_retrieval::{
    CompareReport, CorrPair, Deletions, Delivery, DeliveryItem, Flagged, LineNumbers, SpanFault,
};
use skepd::JsonCodec;

fn wire_md() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/wire.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// (kind, name, json body) for every marked fenced block.
fn blocks() -> Vec<(String, String, String)> {
    let text = wire_md();
    let mut out = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let Some(rest) = line.trim().strip_prefix("<!-- wire:") else { continue };
        let rest = rest.trim().trim_end_matches("-->").trim();
        let mut parts = rest.split_whitespace();
        let kind = parts.next().expect("marker kind").to_string();
        let name = parts.next().expect("marker name").to_string();
        while let Some(l) = lines.peek() {
            if l.trim().is_empty() {
                lines.next();
            } else {
                break;
            }
        }
        let fence = lines.next().unwrap_or_else(|| panic!("no fence after marker '{name}'"));
        assert!(fence.trim().starts_with("```"), "marker '{name}' not followed by a fence");
        let mut body = String::new();
        for l in lines.by_ref() {
            if l.trim().starts_with("```") {
                break;
            }
            body.push_str(l);
            body.push('\n');
        }
        out.push((kind, name, body));
    }
    assert!(!out.is_empty(), "wire.md carries no marked examples");
    out
}

const OP_NAMES: [&str; 54] = [
    "create_new_document",
    "delegate",
    "register_node",
    "fork",
    "create_well_known_document",
    "next_account_prefix",
    "principal_prefix",
    "effective_owner",
    "doc_metadata",
    "insert",
    "delete",
    "copy",
    "reinstate",
    "rearrange",
    "set_arrangement",
    "edit",
    "version",
    "stage",
    "publish",
    "make_link",
    "emit",
    "nullify",
    "assert_sup",
    "edit_link",
    "read_link",
    "follow_link",
    "retrieve_v",
    "retrieve_i",
    "content_frontier",
    "retrieve_doc_v_span",
    "retrieve_doc_v_span_set",
    "line_numbers",
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
    "count_v_by_home",
    "find_links_v_history",
    "retrieve_endsets",
    "project",
    "discoverable_from",
    "delete_orphans",
    "in_claims",
    "out_claims",
    "edition_claims",
    "universal_grants",
    "publish_cost",
];

/// Every request example parses, is canonical (re-marshal equals the doc
/// value), is tagged with the marker's own op name — and every op appears.
#[test]
fn doc_request_examples_are_canonical_and_complete() {
    let codec = JsonCodec;
    let mut seen: Vec<String> = Vec::new();
    for (kind, name, body) in blocks() {
        if kind != "request" {
            continue;
        }
        let req = codec
            .parse(body.as_bytes())
            .unwrap_or_else(|e| panic!("doc request '{name}' does not parse: {:?}", e.detail));
        let canonical: Value =
            serde_json::from_slice(&codec.marshal_request(&req)).expect("canonical is JSON");
        let doc: Value = serde_json::from_str(&body).expect("doc block is JSON");
        assert_eq!(canonical, doc, "doc request '{name}' is not in canonical form");
        assert_eq!(canonical["op"].as_str(), Some(name.as_str()), "marker/op mismatch");
        seen.push(name);
    }
    seen.sort();
    seen.dedup();
    let mut expected: Vec<&str> = OP_NAMES.to_vec();
    expected.sort();
    assert_eq!(seen, expected, "every op must carry at least one doc example");
}

// ── the response fixtures behind the doc's examples ──

fn t(comps: &[u64]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty component list")
}

fn a(comps: &[u64]) -> Address {
    validate(t(comps)).expect("T4-valid doc-example address")
}

fn n(x: u64) -> Nat {
    Nat::from(x)
}

fn sp(start: &[u64], width: &[u64]) -> Span {
    Span::new(t(start), t(width)).expect("well-formed doc-example span")
}

fn link1() -> Address {
    a(&[1, 0, 1, 0, 1, 0, 2, 1])
}

fn ispan() -> Span {
    sp(&[1, 0, 1, 0, 1, 0, 1, 1], &[0, 0, 0, 0, 0, 0, 0, 5])
}

/// The line read's documented answer, every number flagged where `masked`.
fn line_numbers(masked: bool) -> LineNumbers {
    let start = VPos { subspace: n(1), ordinal: n(3) };
    LineNumbers {
        positions: vec![Flagged { number: n(2), masked }],
        lines: vec![Some(Flagged { number: start, masked }), None],
        count: Flagged { number: n(2), masked },
    }
}

fn fixture(name: &str) -> Response {
    match name {
        "ack" => Response::Ack { at: Seq(7), head_moved: None },
        // The landing's tell (skep #764): a `set_arrangement` composed on
        // `1.0.1.0.1.2` after `1.0.1.0.1.3` was published lands and names
        // the trunk's current head.
        "ack_head_moved" => Response::Ack { at: Seq(14), head_moved: Some(a(&[1, 0, 1, 0, 1, 3])) },
        "ack_addr" => Response::AckAddr { addr: a(&[1, 0, 1, 0, 1, 0, 1, 1]), at: Seq(7), committed: true, head_moved: None },
        // A write that found its work done (skep #1043): the mailbox standing
        // at `1.0.1.0.2`, answered at the head the call was judged at.
        "ack_addr_committed_nothing" => {
            Response::AckAddr { addr: a(&[1, 0, 1, 0, 2]), at: Seq(9), committed: false, head_moved: None }
        }
        // The tell beside the address: an `edit` that minted in the draft
        // `1.0.1.0.64` and named a head the trunk has moved past.
        "ack_addr_head_moved" => Response::AckAddr {
            addr: a(&[1, 0, 1, 0, 64, 0, 1, 3]),
            at: Seq(14),
            committed: true,
            head_moved: Some(a(&[1, 0, 1, 0, 1, 3])),
        },
        "ack_edit" => Response::AckEdit {
            successor: a(&[1, 0, 1, 0, 1, 0, 2, 2]),
            claim: a(&[1, 0, 1, 0, 1, 0, 2, 3]),
            at: Seq(7),
        },
        // Five per-byte values coalesce into one content item (the text
        // discipline's common case); the ref breaks the run.
        "delivery" => Response::Delivery {
            items: Delivery(
                b"hello"
                    .iter()
                    .map(|&b| DeliveryItem::Content(Val::new(vec![b])))
                    .chain([DeliveryItem::Ref(link1())])
                    .collect(),
            ),
            as_of: Seq(9),
        },
        // A composite value is its own atom item, never coalesced with the
        // per-byte run beside it.
        "delivery_atom" => Response::Delivery {
            items: Delivery(vec![
                DeliveryItem::Content(Val::new(vec![b'h'])),
                DeliveryItem::Content(Val::new(vec![b'i'])),
                DeliveryItem::Content(Val::new(b"chunk".to_vec())),
            ]),
            as_of: Seq(9),
        },
        // The withheld arm (v7.4, lane 3.3, §4): a readable per-byte run, then
        // a masked run at its own position — one item, never coalesced.
        "delivery_withheld" => Response::Delivery {
            items: Delivery(vec![
                DeliveryItem::Content(Val::new(vec![b'a'])),
                DeliveryItem::Withheld { origin: a(&[1, 0, 1, 0, 64]), width: n(3) },
            ]),
            as_of: Seq(9),
        },
        // The read by identity (AUTH-6.38–6.40): one item per I-position
        // asked — a content value at the first, and the null a position the
        // document never minted takes — never coalesced across positions.
        "i_delivery" => Response::IDelivery {
            items: vec![
                IItem { at: a(&[1, 0, 1, 0, 1, 0, 1, 1]), value: Some(Val::new(vec![b'h'])) },
                IItem { at: a(&[1, 0, 1, 0, 1, 0, 1, 2]), value: None },
            ],
            as_of: Seq(9),
        },
        // The content-frontier read: `next`, the next unminted content
        // ordinal, a natural as every count rides the wire.
        "frontier" => Response::Frontier { next: n(5), as_of: Seq(9) },
        // The line read, asked position 3 and lines 2 and 9 of `a\nb\n`:
        // line 2, a start at position 3 beside a line that names none, and
        // two lines — and the same numbers to a reader who may not read the
        // run at the first position, every one flagged.
        "line_numbers" => Response::LineNumbers { numbers: line_numbers(false), as_of: Seq(9) },
        "line_numbers_masked" => {
            Response::LineNumbers { numbers: line_numbers(true), as_of: Seq(9) }
        }
        "span_set" => {
            Response::SpanSet { set: [ispan()].into_iter().collect::<SpanSet>(), as_of: Seq(9) }
        }
        "addrs" => Response::Addrs { addrs: vec![link1()], as_of: Seq(9) },
        "maybe_addr" => Response::MaybeAddr { addr: Some(a(&[1, 0, 2])), as_of: Seq(9) },
        "maybe_addr_none" => Response::MaybeAddr { addr: None, as_of: Seq(9) },
        // The owner-of-address answer (AUTH-6.37): ω's pair — the claimant's
        // seat and the principal at it — and the both-null answer an address
        // under no registered prefix takes.
        "effective_owner" => Response::EffectiveOwner {
            owner: Some((a(&[1, 0, 1]), PrincipalId(900))),
            as_of: Seq(9),
        },
        "effective_owner_none" => Response::EffectiveOwner { owner: None, as_of: Seq(9) },
        "count" => Response::Count { n: 2, as_of: Seq(9) },
        "page" => Response::Page {
            window: Window { batch: vec![link1()], next: Some(link1()), exhausted: true },
            as_of: Seq(9),
        },
        // The count by home: two homes' rows in address order, the walk
        // ended under its budget.
        "homes" => Response::Homes {
            homes: vec![(a(&[1, 0, 1, 0, 1]), 2), (a(&[1, 0, 1, 0, 64]), 1)],
            exhausted: true,
            as_of: Seq(9),
        },
        // The retracted-links read: an active row beside a retracted one,
        // the window of two full, its cursor the second row's address.
        "links" => Response::Links {
            links: vec![
                LinkRow { a: link1(), at: Some(Seq(5)), retracted_at: None },
                LinkRow { a: a(&[1, 0, 1, 0, 1, 0, 2, 2]), at: Some(Seq(6)), retracted_at: Some(Seq(8)) },
            ],
            next: Some(a(&[1, 0, 1, 0, 1, 0, 2, 2])),
            exhausted: false,
            as_of: Seq(9),
        },
        "endsets" => Response::Endsets {
            pairs: vec![(1, Endset::from_spans([sp(&[1, 1], &[0, 5])]))],
            as_of: Seq(9),
        },
        "runs" => Response::Runs {
            runs: vec![
                Run::new(a(&[1, 0, 1, 0, 1, 0, 1, 1]), n(5)).expect("element-level run fixture")
            ],
            as_of: Seq(9),
        },
        // An image cut short at the run budget: the page's runs under
        // `ispans` and the go-on beside them — the next ordinal, the
        // arrangement read and its position.
        "image_page" => Response::ImagePage {
            runs: vec![
                Run::new(a(&[1, 0, 1, 0, 1, 0, 1, 1]), n(5)).expect("element-level run fixture")
            ],
            next: GoOn { at: n(6), surface: a(&[1, 0, 1, 0, 1]), arranged_at: Some(Seq(7)) },
            as_of: Seq(9),
        },
        "bool" => Response::Bool { val: true, as_of: Seq(9) },
        "link_value" => Response::LinkValue {
            link: Some(
                Link::new([
                    Endset::from_spans([ispan()]),
                    Endset::from_spans([sp(&[1, 0, 1, 0, 64, 0, 1, 1], &[0, 0, 0, 0, 0, 0, 0, 6])]),
                    Endset::from_spans([sp(&[1, 0, 1, 0, 65, 0, 1, 1], &[0, 0, 0, 0, 0, 0, 0, 1])]),
                ])
                .expect("arity-3 link fixture"),
            ),
            at: Some(Seq(7)),
            time: Some(MintTime { millis: 1_786_838_400_047, source: TimeSource::Feed }),
            as_of: Seq(9),
        },
        "link_value_null" => Response::LinkValue { link: None, at: None, time: None, as_of: Seq(9) },
        "follow" => Response::Follow {
            result: Ok([ispan()].into_iter().collect::<SpanSet>()),
            as_of: Seq(9),
        },
        "follow_invalid" => Response::Follow { result: Err(Invalid), as_of: Seq(9) },
        "deletions" => Response::Deletions {
            rep: Deletions {
                deleted_from_a_with_b: vec![a(&[1, 0, 1, 0, 1, 0, 1, 1])],
                deleted_from_b_with_a: vec![],
            },
            as_of: Seq(9),
        },
        "compare" => Response::Compare {
            rep: CompareReport(vec![CorrPair {
                d1: a(&[1, 0, 1, 0, 1]),
                u1: VPos { subspace: n(1), ordinal: n(1) },
                d2: a(&[1, 0, 1, 0, 64]),
                u2: VPos { subspace: n(1), ordinal: n(3) },
                width: n(5),
            }]),
            as_of: Seq(9),
        },
        "orphans" => {
            Response::Orphans { report: OrphanReport { orphaned: vec![link1()] }, as_of: Seq(9) }
        }
        "claims" => Response::Claims {
            claims: vec![SupClaim {
                claim: a(&[1, 0, 1, 0, 1, 0, 2, 3]),
                old: link1(),
                new: a(&[1, 0, 1, 0, 1, 0, 2, 2]),
                home: a(&[1, 0, 1, 0, 1]),
                active: true,
            }],
            as_of: Seq(9),
        },
        // A born document with a birth version and its base extent
        // (PUB-8.12), asked of the birth version `D.1` itself, which the shot
        // minted from the memberless document taken at three positions,
        // placing five: its shot terms beside the document's state (D25's
        // (c′)), the base its shot recorded that document, its arrangement
        // last changed by that shot.
        "doc_metadata" => Response::DocMetadata {
            doc: a(&[1, 0, 1, 0, 1]),
            published: true,
            owner: Some(a(&[1, 0, 1])),
            birth: Some(BirthVersion { addr: a(&[1, 0, 1, 0, 1, 1]), extent: n(5) }),
            terms: Some(ShotTerms {
                placed: n(5),
                base_extent: Some(n(3)),
                base: Some(a(&[1, 0, 1, 0, 1])),
            }),
            source: None,
            source_copied: None,
            base: None,
            base_copied: None,
            merge: None,
            own_count: n(5),
            arranged_at: Some(Seq(7)),
            at: Some(Seq(7)),
            time: Some(MintTime { millis: 1_786_838_400_047, source: TimeSource::Feed }),
            as_of: Seq(9),
        },
        // A private draft the staging act minted off the birth version above
        // (B3-S10): no chain member and no shot terms, its `source` the member
        // copied and `source_copied` the five positions the copy took, its
        // `base` that member and `base_copied` the same five, its arrangement
        // last changed by the stage that minted it.
        "doc_metadata_unborn" => Response::DocMetadata {
            doc: a(&[1, 0, 1, 0, 64]),
            published: false,
            owner: Some(a(&[1, 0, 1])),
            birth: None,
            terms: None,
            source: Some(a(&[1, 0, 1, 0, 1, 1])),
            source_copied: Some(n(5)),
            base: Some(a(&[1, 0, 1, 0, 1, 1])),
            base_copied: Some(n(5)),
            merge: None,
            own_count: n(5),
            arranged_at: Some(Seq(8)),
            at: Some(Seq(8)),
            time: Some(MintTime { millis: 1_786_838_400_052, source: TimeSource::Anchor }),
            as_of: Seq(9),
        },
        // A cross-owner FORK (the fork-source design record's arm A): a
        // private document of another account, minted by `version` off the
        // member `1.0.1.0.1.1`, which it was born sharing — its `source`, the
        // five positions its copy took its `source_copied`. Its own chain has
        // no member and no shot minted it, so the other per-member facts are
        // null — the base among them: a `version` records none. A build
        // before the position map minted it, so the board keeps neither its
        // mint position nor the position its arrangement last changed at.
        "doc_metadata_fork" => Response::DocMetadata {
            doc: a(&[1, 0, 2, 0, 1]),
            published: false,
            owner: Some(a(&[1, 0, 2])),
            birth: None,
            terms: None,
            source: Some(a(&[1, 0, 1, 0, 1, 1])),
            source_copied: Some(n(5)),
            base: None,
            base_copied: None,
            merge: None,
            own_count: n(5),
            arranged_at: None,
            at: None,
            time: None,
            as_of: Seq(9),
        },
        // The staged draft above after a merge's landing (the landing lane;
        // skep #764): a `set_arrangement` composed on version 2 at six
        // positions moved its base there and put the marker beside it — the
        // one side merged, the head at the extent read, the landing's
        // position — its `source_copied` the five its stage copied, its
        // `own_count` the seven positions the landing left it holding, and
        // its `arranged_at` the landing's own position.
        "doc_metadata_marked" => Response::DocMetadata {
            doc: a(&[1, 0, 1, 0, 64]),
            published: false,
            owner: Some(a(&[1, 0, 1])),
            birth: None,
            terms: None,
            source: Some(a(&[1, 0, 1, 0, 1, 1])),
            source_copied: Some(n(5)),
            base: Some(a(&[1, 0, 1, 0, 1, 2])),
            base_copied: Some(n(6)),
            merge: Some(Marker {
                sides: vec![a(&[1, 0, 1, 0, 1, 1, 1])],
                head: a(&[1, 0, 1, 0, 1, 2]),
                head_copied: n(6),
                at: Seq(14),
            }),
            own_count: n(7),
            arranged_at: Some(Seq(14)),
            at: Some(Seq(8)),
            time: Some(MintTime { millis: 1_786_838_400_052, source: TimeSource::Anchor }),
            as_of: Seq(15),
        },
        "edition_claims" => Response::EditionClaims {
            claims: vec![EditionClaim {
                claim: a(&[1, 0, 1, 0, 67, 0, 2, 1]),
                home: a(&[1, 0, 1, 0, 67]),
                to: Endset::from_spans([sp(&[1, 0, 1, 0, 1], &[0, 0, 0, 0, 1])]),
                active: true,
            }],
            as_of: Seq(9),
        },
        // The any-principal discovery read (PUB-8.47): one served row — the
        // claimant's draft, granted to every principal by the claimant — and
        // the guest's empty answer under the same tag.
        "universal_grants" => Response::UniversalGrants {
            rows: vec![UniversalGrant {
                prefix: a(&[1, 0, 1, 0, 64]),
                issuers: BTreeSet::from([a(&[1, 0, 1])]),
            }],
            as_of: Seq(9),
        },
        "universal_grants_empty" => Response::UniversalGrants { rows: Vec::new(), as_of: Seq(9) },
        // The price of a publication: the five figures, a member each, the
        // two budgets beside them.
        "publish_cost" => Response::PublishCost {
            price: skep_links::ReadPrice { homes: 3, entries: 4, rewindow: 5_780, fence: 1_613, staged_bytes: 2_471_033 },
            as_of: Seq(9),
        },
        "rejected" => Response::Rejected(Rejection {
            op: OpKind::Insert,
            code: RejectCode::Unauthenticated,
            disposition: Disposition::Permanent,
            site: None,
            detail: None,
            io_kind: None,
        }),
        "rejected_site" => Response::Rejected(Rejection {
            op: OpKind::RetrieveV,
            code: RejectCode::MalformedSpan,
            disposition: Disposition::Permanent,
            site: Some(FaultSite {
                index: Some(1),
                fault: Some(SpanFault::NotOrdinalLevel),
                ..FaultSite::default()
            }),
            detail: None,
            io_kind: None,
        }),
        // A paged image's continuation of a draft written since its page
        // was read: the code, permanent, the document under the site.
        "rejected_page_moved" => Response::Rejected(Rejection {
            op: OpKind::Image,
            code: RejectCode::PageMoved,
            disposition: Disposition::Permanent,
            site: Some(FaultSite { addr: Some(a(&[1, 0, 1, 0, 64])), ..FaultSite::default() }),
            detail: None,
            io_kind: None,
        }),
        "rejected_unparseable" => {
            JsonCodec.unparseable(ParseError {
                detail: Some("unknown op 'frobnicate'".into()),
                site: None,
            })
        }
        other => panic!("doc marker 'response {other}' has no fixture in wire_doc.rs"),
    }
}

/// The 30 response shapes every client must decode; each must appear as a
/// doc marker (variant markers like `follow_invalid` are extra coverage).
const REQUIRED_SHAPES: [&str; 30] = [
    "ack",
    "ack_addr",
    "ack_edit",
    "delivery",
    "i_delivery",
    "frontier",
    "line_numbers",
    "span_set",
    "addrs",
    "maybe_addr",
    "effective_owner",
    "count",
    "page",
    "homes",
    "links",
    "endsets",
    "runs",
    "image_page",
    "bool",
    "link_value",
    "follow",
    "deletions",
    "compare",
    "orphans",
    "claims",
    "doc_metadata",
    "edition_claims",
    "universal_grants",
    "publish_cost",
    "rejected",
];

/// The prose between `from` and the first of `until` after it, with every
/// whitespace run collapsed — so a re-wrap of a paragraph moves no pin.
/// Searched from the first occurrence of `after` (`""` is the top), so a
/// caller can skip past a section whose entries share the form it is after.
fn prose_after(after: &str, from: &str, until: &[&str]) -> String {
    let text = wire_md();
    let base = text.find(after).unwrap_or_else(|| panic!("wire.md no longer carries {after:?}"));
    let text = &text[base..];
    let start = text.find(from).unwrap_or_else(|| panic!("wire.md no longer carries {from:?}"));
    let rest = &text[start + from.len()..];
    let end = until.iter().filter_map(|u| rest.find(u)).min().unwrap_or(rest.len());
    rest[..end].split_whitespace().collect::<Vec<_>>().join(" ")
}

fn prose(from: &str, until: &[&str]) -> String {
    prose_after("", from, until)
}

/// One op's row of §Operations: from its bold name to the next row or heading.
/// Searched from §Operations, since a shape's entry under §The response
/// envelope opens with the same bold name where the shape and the op share
/// one (`effective_owner`, `universal_grants`).
fn op_row(name: &str) -> String {
    prose_after("\n## Operations", &format!("\n**`{name}`** —"), &["\n**`", "\n### ", "\n## "])
}

/// The `new_id` bound is ONE number in two places — the `delegate` row and
/// the codec's parse (AUTH-6.36's clause; AUTH-5.20) — so the number is READ
/// out of the row and handed to the codec: the doc's own bound parses, one
/// past it does not. And §Value encodings' integer note, which once said a
/// principal id approaching 2^53 was "unreachable in practice" — the OPPOSITE
/// of the bound — says it of positions and counts alone, and points here.
#[test]
fn doc_new_id_bound_is_the_codecs_own() {
    let row = op_row("delegate");
    assert!(row.contains("2^53 − 1"), "the delegate row states the bound: {row}");
    let bound: u64 = row
        .split('`')
        .skip(1)
        .step_by(2)
        .find(|t| t.len() > 1 && t.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or_else(|| panic!("the delegate row spells the bound as a literal: {row}"))
        .parse()
        .expect("the literal is a u64");
    assert_eq!(bound, (1u64 << 53) - 1, "the literal IS 2^53 − 1");
    let codec = JsonCodec;
    let frame = |id: u64| format!(r#"{{"new_id":{id},"new_prefix":"1.0.2","op":"delegate"}}"#);
    assert!(codec.parse(frame(bound).as_bytes()).is_ok(), "the doc's own bound is admitted");
    assert!(codec.parse(frame(bound + 1).as_bytes()).is_err(), "one past it is a parse fault");
    for fact in ["`unparseable`", "no code or token of its own", "nothing commits"] {
        assert!(row.contains(fact), "the delegate row says {fact:?}: {row}");
    }

    let note = prose("**Machine-bounded integers**", &["\n**Spans**"]);
    assert!(
        !note.contains("principal count"),
        "the integer note no longer calls a principal id unreachable: {note}"
    );
    assert!(
        note.contains("`delegate` refuses a `new_id` above 2^53 − 1 at the parse"),
        "the integer note states the bound: {note}"
    );
}

/// THE STORE'S OWN CODE FOR THE SYSTEM ACCOUNT'S WELL-KNOWN CREATION
/// (`RejectCode::SystemAccountNoWellKnown`): §Rejection codes tables
/// `system_account_no_well_known` among the namespace's codes, between
/// `not_an_account` and `gate`, and its row says whose refusal it is, that
/// it is permanent, and that the daemon's door answers the credential
/// family's token of the same name first, so no daemon request reaches it
/// today. The code's wire name is pinned in skep-core's `codec_roundtrip.rs`
/// and its disposition in skep-febe's `reject/tests.rs`; the door's token
/// has its own bullet under §Credential refusals, pinned below. This pins
/// that the table carries the code.
#[test]
fn doc_tables_the_stores_system_account_no_well_known_code() {
    let codes = prose("\n### Rejection codes", &["\n### The version-chain refusals"]);
    for fact in [
        "Namespace/authority: `not_owner`, `not_an_account`, `system_account_no_well_known` (the STORE's own refusal of a well-known creation that names the system account, which creates none",
        "its slots are its own table, seeded at genesis — permanent, no state admits the request",
        "the daemon's door answers `credential_refused:system_account_no_well_known` first, whoever asks and at every slot (§Credential refusals), so no daemon request reaches it today",
        "it answers a caller that reaches the store without that door), `gate` (M3's inc gate",
    ] {
        assert!(codes.contains(fact), "§Rejection codes says {fact:?}");
    }
}

/// The owner-of-address row (AUTH-6.37) carries the facts a client builds
/// on, each in the row itself: the one allocation test, the both-null
/// answer, no session, and `/op-at`.
#[test]
fn doc_owner_of_address_row_states_the_allocation_test() {
    let row = op_row("effective_owner");
    for fact in [
        "iff `prefix` equals the address you asked",
        "`null` TOGETHER",
        "there is no document argument",
        "NO session is needed",
        "nothing is withheld",
        "served on `/op-at` too",
    ] {
        assert!(row.contains(fact), "the effective_owner row says {fact:?}: {row}");
    }
}

/// THE WELL-KNOWN CREATION (the mailbox design §2, §3; REG-4.131):
/// §Namespace's `create_well_known_document` row states the well-known
/// documents it creates — the mailbox at 2, private, and the bio at 3, the
/// link page at 4 and the account's policy document at 5, each published
/// and empty, its owner's alone, once — that `slot` is required, its answer,
/// the first words of a published slot's document by an ordinary
/// publication, the signature a published slot's creation carries on a
/// claimed board and the address it names, what an `attest` at slot 2 meets,
/// what a second call is answered — saying it committed nothing — and what
/// its `at` is, the member the op does not take, its refusals by token in
/// their order, and that mail needs no mailbox document; its two request
/// examples are the slot-2 frame and the attested slot-5 frame, byte for
/// byte; §Credential refusals carries the system account's token in a
/// bullet of its own — whoever asks, at every slot, on claimed and
/// unclaimed boards alike — names the op in `mint_home_first`'s cell, and
/// a minting `publish` beside it, puts a published slot's creation among
/// the board-state gate's inputs and the mailbox's outside it; and §The
/// change feed lists the op among the mints whose row names the minted
/// document. The mailbox the board creates with the home page is said
/// where a reader looks for it: the `create_new_document` row's rule, its
/// one ack and its one signature; the well-known row's slot 2, answered
/// standing, and its mail paragraph, a stranger answered `withheld`
/// wherever a home stands; and the change feed's `[home, mailbox]` row, its
/// kept `attest` and its `drafts=true` page. The daemon's answers are
/// pinned in skep-core's and skep-febe's suites and in `well_known.rs` and
/// `mailbox.rs`; this pins that the contract says so.
#[test]
fn doc_states_the_well_known_creation_its_slots_its_refusals_and_its_feed_row() {
    let row = op_row("create_well_known_document");
    for fact in [
        "CREATE ONE OF THE ACCOUNT'S WELL-KNOWN DOCUMENTS",
        "the address `<account>.0.<slot>`. `slot` is REQUIRED, a number",
        "| `2` | the account's MAILBOX — `1.0.1.0.2` for the account `1.0.1` | PRIVATE |",
        "| `3` | the account's BIO | PUBLISHED |",
        "| `4` | the account's LINK PAGE | PUBLISHED |",
        "| `5` | the account's POLICY DOCUMENT | PUBLISHED |",
        "The slot fixes the document's state, and no member of the request changes it",
        "Each is created EMPTY",
        "is the account OWNER's ALONE and is created ONCE",
        "→ `ack_addr` (the document's address)",
        "takes its FIRST WORDS by an ordinary publication",
        "a `publish` naming the document as `doc` lands its first version, `<account>.0.<slot>.1`",
        "ON A CLAIMED BOARD the creation at slot 3, 4 or 5 is PUBLISH-CLASS",
        "its `doc` THE SLOT DOCUMENT's OWN ADDRESS, `<account>.0.<slot>`",
        "a frame signed for one slot verifies at no other",
        "never framed under `create_new_document`'s token",
        "The creation at slot 2 is never publish-class",
        "admitted from a bare session on a claimed board as `stage` is",
        "sent at slot 2 is no unknown field: it is ADMITTED AND DROPPED",
        "The op takes no `published`",
        "No creation moves a count",
        "is answered `ack_addr` with the SAME `addr` and commits nothing",
        "carries `\"committed\": false`, which the creation's acknowledgment never does",
        "Its `at` is the position the call was JUDGED at",
        "The test is per slot",
        "a request with no `slot`, or with a `slot` that names none of the four — `1`, `6`, `63`, `64`, a string — is `malformed`",
        "`credential_refused:system_account_no_well_known`, whoever asks and at every slot",
        "`credential_refused:mint_home_first` at every slot",
        "`credential_refused:claim_first`",
        "`credential_refused:signed_session_required` from a bare session, `credential_refused:attestation_required` with no `attest`, `credential_refused:attestation_invalid:signature`",
        "`not_owner`",
        "`not_an_account`",
        "MAIL NEEDS NO MAILBOX DOCUMENT",
    ] {
        assert!(row.contains(fact), "the create_well_known_document row says {fact:?}: {row}");
    }
    assert!(!row.contains("names the account and no slot"), "the row no longer says the op names no slot");
    // The row's two examples, byte for byte: the mailbox's frame, and the
    // policy document's with its `attest`.
    let examples: Vec<String> = blocks()
        .into_iter()
        .filter(|(kind, name, _)| kind == "request" && name == "create_well_known_document")
        .map(|(_, _, body)| body.trim().to_string())
        .collect();
    assert_eq!(
        examples,
        [
            r#"{"account":"1.0.1","op":"create_well_known_document","slot":2}"#,
            r#"{"account":"1.0.1","attest":{"alg":"mldsa65-ed25519","sig":"00"},"op":"create_well_known_document","slot":5}"#,
        ],
        "the row's request examples"
    );
    for example in &examples {
        assert!(row.contains(example.as_str()), "the example stands in the op's own row: {example}");
    }
    let refusals = prose("\n### Credential refusals", &["\n## Operations"]);
    for fact in [
        "* `system_account_no_well_known` — a `create_well_known_document`",
        "at EVERY `slot`",
        "it has no well-known document to create",
        "its number 5 holds no document, ever",
        "Refused WHOEVER ASKS",
        "on claimed and unclaimed boards alike: it stands in the MINT class",
        "a `fork`, a `version` or a `stage` by a principal whose account's space has never held a document; a `create_well_known_document` (§Namespace) by the owner of the `account` it names, at any `slot`, where that account holds no document",
        "and a `publish` at its mint form (`mint: true`, §The publish shot and head-float) by the owner of the `account` it names, where that account holds no document",
        "becomes the account's doc 1 and creates its mailbox in the same commit",
        "a `create_well_known_document` by the account's owner at a slot whose document is created PUBLISHED — the bio's (3), the link page's (4), the policy document's (5)",
        "the mailbox's creation (`create_well_known_document` at slot 2, the one slot whose document is private)",
    ] {
        assert!(refusals.contains(fact), "§Credential refusals says {fact:?}");
    }
    assert!(!refusals.contains("`create_well_known_document`, private always"), "§Credential refusals no longer calls the creation private always");
    let envelope = prose("\n## The response envelope", &["\n## Rejections"]);
    assert!(
        envelope.contains("`create_well_known_document` that found its slot's document standing"),
        "§The response envelope names the creation's second call by its slot"
    );
    let feed = prose("\n## The change feed", &["\n## The other endpoints"]);
    assert!(
        feed.contains("the **minted** document for `create_new_document`/`fork`/`version`/`stage`/`create_well_known_document`"),
        "§The change feed lists the well-known creation among the mints"
    );
    // The mailbox the board creates with the home page (the mailbox design
    // §3): the create's row, the slot-2 call's answer, the mail paragraph
    // and the feed's row and exemption say so.
    let create = op_row("create_new_document");
    for fact in [
        "An account's first mint also creates the account's MAILBOX, `<account>.0.2`, private and empty, in the same commit",
        "the ack names the home, and `doc_metadata` dates both at the ack's `at`",
        "The account's first mint also creates its mailbox, document 2; no mint by this op creates any other of them",
        "the commit's `attest` signs the home's act alone",
    ] {
        assert!(create.contains(fact), "the create_new_document row says {fact:?}: {create}");
    }
    assert!(!create.contains("this op never mints one"), "the create row no longer says it mints no well-known document");
    for fact in [
        "The MAILBOX the board creates itself: an account's first `create_new_document` creates it in the same commit as the home page",
        "the board creates it with the account's home page, in the same commit",
        "`doc_not_registered` only for one that has none",
    ] {
        assert!(row.contains(fact), "the create_well_known_document row says {fact:?}: {row}");
    }
    assert!(!row.contains("a client creates it just before the first of them"), "no client creates the mailbox");
    for fact in [
        "an account's first `create_new_document` or `fork` naming the home FIRST, then the MAILBOX its commit created, `[home, mailbox]`",
        "a `create_new_document` or `fork` row reduced from `[home, mailbox]` to `[home]`, which KEEP their `attest`",
        "An account's first-mint row names its mailbox, a draft, so the account holder's `drafts=true` page carries it",
    ] {
        assert!(feed.contains(fact), "§The change feed says {fact:?}");
    }
}

/// The registrar's gate (REG-2.1) as the contract states it. `register_node`'s
/// row says the op is the registrar's alone — the claimant account's own
/// principal in a signed session, under any key of its set — and names each
/// refused caller's answer by its token, the store's codes behind the gate;
/// §Credential refusals carries the gate in a paragraph of its own, with
/// `not_registrar`'s class and the sessions the claimant's own keys open
/// that it refuses, and holds the op's own arm of the board-state gate on
/// the claimed side and its name on the unclaimed one; and §Identity's modes
/// carry the one write a signed session is not admitted for the asking. The
/// daemon's answers are pinned in `auth_wire/gates.rs`, `register.rs` and
/// `authz.rs`; this pins that the contract says so.
#[test]
fn doc_states_register_nodes_gate_and_each_refused_callers_answer() {
    let row = op_row("register_node");
    for fact in [
        "It is THE REGISTRAR's ALONE (REG-2.1)",
        "the CLAIMANT account's own principal in a SIGNED session",
        "under any key of that account's set, from a full session or a content-scoped one",
        "a guest, `unauthenticated`",
        "on an UNCLAIMED board, `credential_refused:claim_first`, bare and signed sessions alike",
        "a BARE session `credential_refused:signed_session_required`, whatever its principal",
        "a SIGNED session that is not the registrar's `credential_refused:not_registrar`",
        "stand behind the gate: the registrar alone is answered them",
        "The op takes no `attest`",
    ] {
        assert!(row.contains(fact), "the register_node row says {fact:?}: {row}");
    }
    let refusals = prose("\n### Credential refusals", &["\n## Operations"]);
    for fact in [
        "**The registrar's gate** (`credential_refused`; REG-2.1)",
        "under ANY key of that account's enrolled set",
        "on an UNCLAIMED board, `claim_first`",
        "from a BARE session on a claimed board, `signed_session_required`",
        "`not_registrar` — from a SIGNED session on a claimed board that is not the registrar's",
        "the gate reads the principal the session names, never the key set that opened it",
        "PERMANENT like the family's: a session's principal is fixed at its open and a board's claimant never changes",
        "A guest answers `unauthenticated` ahead of all three",
        "ONE write is judged by none of this and takes the arm below, from every session: `register_node`",
        "claimed, `register_node` alone — THE REGISTRAR'S ARM (REG-2.1; the registrar's gate, above)",
        "every other write refuses, `register_node` among them",
    ] {
        assert!(refusals.contains(fact), "§Credential refusals says {fact:?}");
    }
    let modes = prose("\n### Identity — modes, principals, credentials", &["\n### The read predicate"]);
    for fact in [
        "bare writes landing in the published world and a bare `register_node` still refuse (`signed_session_required`)",
        "`register_node` is the board's REGISTRAR's alone",
        "a signed session of anyone else is refused `not_registrar`",
    ] {
        assert!(modes.contains(fact), "§Identity's modes say {fact:?}");
    }
}

/// The any-principal discovery row (PUB-8.47) carries the facts a client
/// builds on, each in the row itself: no argument, prefix order, empty for
/// a guest, the served prefix the COVERED one and never the stored prefix,
/// and `/op-at`. And the envelope lists the shape with its tested examples,
/// as it lists `effective_owner`'s — the list whole, no shape documented
/// under its op alone.
#[test]
fn doc_universal_grants_row_states_the_covered_prefix_and_the_guests_empty_answer() {
    let row = op_row("universal_grants");
    for fact in [
        "takes no argument",
        "in prefix order",
        "empty for a guest",
        "the served prefix is the covered one",
        "never the stored prefix",
        "served on `/op-at`",
    ] {
        assert!(row.contains(fact), "the universal_grants row says {fact:?}: {row}");
    }
    let envelope = prose("\n## The response envelope", &["\n## Rejections"]);
    for shape in REQUIRED_SHAPES {
        if shape == "rejected" {
            continue; // its own section
        }
        assert!(
            envelope.contains(&format!("**`{shape}`** —")),
            "§The response envelope lists `{shape}`"
        );
    }
}

/// The line read's row states its rule, its masking and its refusals.
///
/// §Content & provenance reads' `line_numbers` row carries what a client
/// builds on: the three questions, the two optional lists and their cap, the
/// rule that counts a line and the end of a document, the positions it
/// answers and the two it refuses by index, the `null` a line that names
/// none takes, the masking and its flag, the one walk and its refusal, and
/// `/op-at`. The cap is one number in two places, so it is read out of the
/// row and handed to the codec: a list of that many entries parses and one
/// more does not. §The read predicate lists the read among the masked ones,
/// §Rejection codes gives it the walk refusal, and head-float names it. The
/// daemon's answers are pinned in `line_numbers.rs`; this pins that the
/// contract says so.
#[test]
fn doc_states_the_line_read_its_rule_its_masking_and_its_refusals() {
    let row = op_row("line_numbers");
    for fact in [
        "THE LINE READ: `doc`'s line numbers, and no text",
        "the line each of `positions` lies on, the position each of `lines` starts at, and the document's line count, which is always answered",
        "absent, `null` and `[]` are one request",
        "`malformed` under the op `unparseable`",
        "→ `line_numbers`, one item for each entry, in request order",
        "A LINE BREAK is a content position whose value is the single byte `0x0A`",
        "never an atom, whatever its bytes",
        "Line 1 starts at position 1, and line N one position past line break N − 1",
        "a document that ENDS in a line break has NO empty last line",
        "An empty document has no line, and the link subspace has none",
        "A position is answered from 1 to ONE PAST THE END",
        "one outside the content subspace is `not_content_subspace`",
        "one at ordinal 0 or further past the end is `range_not_present`",
        "`site.index` its place in `positions`, the first faulty one in request order speaking",
        "is answered `null` in its place",
        "unreadable is `withheld`, unregistered is `doc_not_registered`",
        "a bare published address answers its trunk head",
        "a run whose origin you may not read counts NO line break",
        "each carries `masked`, `true` where such a run lies at or before what it numbers",
        "A position inside such a run is on the line the run starts on",
        "YOUR VIEW and never a name",
        "walks the document's runs ONCE, whatever its two lists hold",
        "refused whole (`too_many_items`, §Rejection codes)",
        "Served on `/op-at` as every read is, numbering the document as it stood",
    ] {
        assert!(row.contains(fact), "the line_numbers row says {fact:?}: {row}");
    }
    let cap = figure_after(&row, "`MAX_SLOT_SPANS` = ");
    let codec = JsonCodec;
    let frame = |entries: usize| {
        let lines = vec![r#""1""#; entries].join(",");
        format!(r#"{{"doc":"1.0.1.0.1","lines":[{lines}],"op":"line_numbers"}}"#)
    };
    assert!(codec.parse(frame(cap).as_bytes()).is_ok(), "a list at the row's own cap is admitted");
    assert!(codec.parse(frame(cap + 1).as_bytes()).is_err(), "one entry past it is a parse fault");

    let masked =
        prose("How a masked read answers:", &["\nThe two publication reads take the consult too"]);
    assert!(
        masked.contains("**A line read masks per run too**: `line_numbers` counts NO line break of a run you may not read"),
        "§The read predicate lists the line read among the masked reads: {masked}"
    );
    let codes = prose("\n### Rejection codes", &["\n### The version-chain refusals"]);
    for fact in [
        "`range_not_present` (also a line read's listed position at ordinal 0 or more than one past its document's end, never clipped",
        "a line read answers `too_many_items` where its document holds more content runs than that",
        "no narrower request passes",
    ] {
        assert!(codes.contains(fact), "§Rejection codes says {fact:?}");
    }
    let float =
        prose("**Head-float** (PUB-2.49, PUB-2.50, PUB-2.53).", &["\n**The deposit cell**"]);
    assert!(
        float.contains("`retrieve_v`, `line_numbers`, `retrieve_doc_v_span`"),
        "head-float names the read: {float}"
    );
    let shape = prose("\n**`line_numbers`** — line_numbers", &["\n**`span_set`**"]);
    for fact in [
        "`positions` is one `{line, masked}` for each position asked",
        "`lines` one `{start, masked}` for each line asked",
        "or `null`, in the line's own place, where the number names no line of the document",
        "`count` is `{n, masked}`, the document's line count, always present",
    ] {
        assert!(shape.contains(fact), "the line_numbers shape says {fact:?}: {shape}");
    }
}

/// THE RECORD GRADE'S PROSE (signed ops, 2a): §The claim ceremony and
/// credentials states the record's own signature — the `record` grammar's
/// five rows by name, in order, the home's account as the frame's `account`,
/// the grade the hand signs at, and the verify at the deposit's `make_link`
/// — and §Credential refusals states the record deposit's one refusal
/// beside the entry grade's, the record-grade causes of
/// `attestation_invalid`, and the credential deposit's `replaces` fence,
/// each in the section a client reads for it. The daemon's tokens are
/// pinned end to end in `signed_ops.rs`; this pins that the contract says
/// so.
#[test]
fn doc_states_the_record_grade_beside_the_entry_grade() {
    let ceremony = prose("\n### The claim ceremony and credentials", &["\n### Correlation"]);
    for fact in [
        "**The record's own signature — the record grade**",
        "`framed(\"skep-entry-v1\", [alg, board, account, doc, \"record\", body])`",
        "`account` the HOME's account",
        "(1) the link's TYPE address",
        "(2) the link's `to` slot",
        "(3) the `replaces` row",
        "(4) the LINEAGE row",
        "(5) the SIG-LESS CANONICAL RECORD",
        "`from` is no row",
        "THE GRADE THE ACT NEEDS",
        "VERIFIES it at that `make_link`",
        "the ceremony's own genesis record carries no `sig`",
    ] {
        assert!(ceremony.contains(fact), "§The claim ceremony and credentials says {fact:?}");
    }
    let refusals = prose("\n### Credential refusals", &["\n## Operations"]);
    for fact in [
        "THE RECORD CARRIES NO `sig` AT ALL",
        "answered at the deposit's `make_link`",
        "the same causes over the record's `sig`",
        "the anchors alone where the act is anchor-grade",
        "`replaces_not_credential`",
        "`replaces` row is EMPTY by kind",
        "still claimed, THE RECORD GRADE",
    ] {
        assert!(refusals.contains(fact), "§Credential refusals says {fact:?}");
    }
    let links = prose("\n### Links (writes)", &["\n### Links (raw reads)"]);
    assert!(
        links.contains("and no `replaces` member (`replaces_not_credential`"),
        "§Links (writes) fences the member on a credential-typed make_link"
    );
}

/// THE LINK-SETS ROWS' CONTRACT (lane S0; the commons seeding round,
/// 2026-10-27): §Credential refusals carries the correspondence class's
/// sole-writer fence beside the `replaces` one — the class, the token, ONE
/// writer (the `publish` shot's own record class; nothing deposits one by
/// itself), PERMANENT, who it answers, the parent outside it and its
/// `nullify`'s refusal — and §Links (writes) glosses the slots by ORDINAL and
/// ROLE in the standing rule's words (the one-sided link record's decision
/// 5 (a)), the keys and their order kept as sealed. The daemon's answers are
/// pinned in `vectors.rs`, `nullify_class.rs` and skep-core's own suite;
/// this pins that the contract says so.
#[test]
fn doc_states_the_correspondence_fence_and_the_slots_ordinal_and_role_reading() {
    let refusals = prose("\n### Credential refusals", &["\n## Operations"]);
    for fact in [
        "The `replaces` class — `replaces_not_standalone`",
        "The correspondence class — `correspondence_not_standalone`",
        "`1.1.0.1.0.1.0.3.102.1`",
        "the `publish` shot's own record class",
        "nothing deposits one by itself",
        "the parent `counterpart` `1.1.0.1.0.1.0.3.102` is no member",
        "PERMANENT. It answers the owner of every home the write names",
        "Its `nullify` is refused `nullify_audit_view`",
    ] {
        assert!(refusals.contains(fact), "§Credential refusals says {fact:?}");
    }
    let links = prose("\n### Links (writes)", &["\n### Links (raw reads)"]);
    for fact in [
        "glossed by ORDINAL and ROLE",
        "slot 1 (`from`) holds what a link brings of its own",
        "slot 2 (`to`) holds what it is about",
        "a one-sided link leaves empty the slot it has no content for",
        "a MARK",
        "has an empty `from` and its matter in `to`",
        "The claim `3.3` stands as built",
        "The keys `from`/`to`/`ty` and their order stay as every signed row seals them",
    ] {
        assert!(links.contains(fact), "§Links (writes) says {fact:?}");
    }
}

/// THE DEPOSITS AND THE SIGNED BODY (the link-sets design §5.7; lane S3):
/// §Arrangement's `publish` names the target's two forms and the three
/// lists with their end forms; §The publish shot and head-float states the
/// one commit's order, the plan's validation with its skips, the deposit
/// rows of the signed body and the memo ahead of the admission; §Rejection
/// codes carries the six tokens with their details; §Links (writes) the
/// `retract` entry's class cell; §Correlation and idempotency the memo's
/// place; §The change feed the row's homes. The daemon's answers are
/// pinned in `publish.rs` and `signed_ops.rs`; this pins that the contract
/// says so.
#[test]
fn doc_states_the_deposits_their_body_and_their_tokens() {
    let arrangement = prose("\n### Arrangement (document editing)", &["\n### Media"]);
    for fact in [
        "THE TARGET takes one of two forms",
        "`claim: true` rides either form and writes the edition claim",
        "refused `claim_refused` (`detail` `member_stands`, `site.addr` the edition, nothing committed)",
        "THE DEPOSITS, four",
        "THE MEMBER-POSITION",
        "A V-spec is admitted in no entry",
        "DEPOSIT ROWS (§The publish shot and head-float, the deposits)",
    ] {
        assert!(arrangement.contains(fact), "§Arrangement says {fact:?}");
    }
    let shot = prose("\n### The publish shot and head-float", &["\n### Credential refusals"]);
    for fact in [
        "**The deposits**",
        "homed in the edition the commit mints OR names",
        "THE PLAN, read on",
        "RETRACTED is SKIPPED",
        "standing in a published home of yours is SKIPPED",
        "A skipped entry has no",
        "answered from the retry memo BEFORE the admission judges it",
        "| `link_home_refused`, `old_refused`, `duplicate_original`, `read_with_in_links`, `retract_refused`, `read_with_refused` | permanent | `index` = the entry in its own list |",
        "| `supersede_refused` | permanent | `index` = the entry in `supersede`; at `head_moved`, `index` = 0 and `addr` = the trunk's head |",
        "| `claim_refused` | permanent | `addr` = the edition |",
    ] {
        assert!(shot.contains(fact), "§The publish shot and head-float says {fact:?}");
    }
    let codes = prose("\n### Rejection codes", &["\n### The version-chain refusals"]);
    for token in ["`link_home_refused`", "`old_refused`", "`duplicate_original`", "`read_with_in_links`", "`retract_refused`", "`read_with_refused`", "`supersede_refused`", "`claim_refused`"] {
        assert!(codes.contains(token), "§Rejection codes carries {token}");
    }
    assert!(codes.contains("`site.addr` the edition, `detail` member_stands"), "§Rejection codes states the claim refusal's site and detail");
    let links = prose("\n### Links (writes)", &["\n### Links (raw reads)"]);
    assert!(links.contains("refused `retract_refused` with the class as its"), "§Links (writes) states the retract entry's class cell");
    let memo = prose("\n### Correlation and idempotency", &["\n### HTTP status codes"]);
    assert!(memo.contains("the memo is read BEFORE the write is judged"), "§Correlation states the memo's place");
    let feed = prose("\n## The change feed", &["\n## The other endpoints"]);
    assert!(feed.contains("then every other home the commit's"), "§The change feed states the row's homes");
}

/// THE PRIVATE RIDER (the link-sets design §5.7 (vi′); skep #894):
/// §Arrangement's `publish` names `originals` beside `retract` — one entry
/// per original of a retracted formatting mark, `{old, rest?}`, no deposit,
/// outside the signed preimage; §The publish shot and head-float places
/// the originals' writes in the one commit after the deposits and ahead of
/// the re-window, the fresh mark ahead of the retraction, states the
/// plan's (4′) with its nine causes and the skip, and keeps the rider out
/// of the signed groups; §Rejection codes carries the token with its
/// details and its row; §Links (writes) states the rider's class cell;
/// §The change feed names the ended original's home. The daemon's answers
/// are pinned in `publish.rs`; this pins that the contract says so.
#[test]
fn doc_states_the_private_rider_and_its_token() {
    let arrangement = prose("\n### Arrangement (document editing)", &["\n### Media"]);
    for fact in [
        "THE DEPOSITS, four",
        "beside it THE PRIVATE RIDER `originals`, no deposit and no term of the count, outside the signed preimage as `draft` is",
        "`{old, rest?}`, `old` the original's address",
        "the original's words NO COPY OF IT HAS EVER COVERED, in the I-span form",
        "writing first, over a rest, a fresh mark of the original's type over exactly those words",
        "refused `original_refused` by entry",
    ] {
        assert!(arrangement.contains(fact), "§Arrangement says {fact:?}");
    }
    let shot = prose("\n### The publish shot and head-float", &["\n### Credential refusals"]);
    for fact in [
        "then THE ORIGINALS the private rider `originals` ends, in declared order, each at its own home",
        "the fresh mark of the original's type first, seated as any draft formatting is, then the original's retraction, `nullify`'s tuple, unseated — then the re-window",
        "(4′) each `originals` entry — THE PRIVATE RIDER beside `retract`",
        "(`original_refused`: absent, not_owner, public), once (duplicate at the second)",
        "(not_content_span, too_large)",
        "(fenced_type)",
        "(rest_outside)",
        "a mark of THIS request's `retract` list, as sent (unclaimed)",
        "never an arbitrary private retraction",
        "an original ALREADY RETRACTED is SKIPPED, the entry committing nothing, as (4) skips its target",
        "nor is the `originals` rider: its writes are private",
        "a request carrying the rider alone signs today's body byte for byte",
        "| `original_refused` | permanent | `index` = the entry in `originals` |",
    ] {
        assert!(shot.contains(fact), "§The publish shot and head-float says {fact:?}");
    }
    let codes = prose("\n### Rejection codes", &["\n### The version-chain refusals"]);
    for fact in ["`original_refused` (an entry of the originals rider", "unclaimed — no active claim of yours names the original as old and a mark of this request's retract list as new"] {
        assert!(codes.contains(fact), "§Rejection codes says {fact:?}");
    }
    let links = prose("\n### Links (writes)", &["\n### Links (raw reads)"]);
    assert!(links.contains("entry of its `originals` rider, refused `original_refused` with the same class token"), "§Links (writes) states the rider's class cell");
    let feed = prose("\n## The change feed", &["\n## The other endpoints"]);
    assert!(feed.contains("the private home of an original the `originals` rider ended"), "§The change feed names the ended original's home");
}

/// THE SUPERSESSION CLAIM A PUBLICATION CARRIES (the merge bridge lane,
/// brief A; skep #805, #806): §Arrangement's `publish` names the
/// `supersede` member — the daughters by address, each one claim homed in
/// `doc`'s trunk onto the trunk's next member, skipped where a claim of
/// yours already names it; §The publish shot and head-float sets the
/// supersede list aside from the destination's no-refusal rule and states
/// the plan's (6) with its four causes — `head_moved` first, the list
/// refused whole with the trunk's head — the claim's home and stored form,
/// the fifth kind byte and its group with the member BY TAG, the race's
/// refusal ahead of the signature check, the reads and the permanence;
/// §Rejection codes carries the token with its details; §Links (writes)
/// keeps `assert_sup` to links and names the publication the member form's
/// one writer, and the `nullify` class names the member `old`; §Link
/// discovery reads states `in_claims` over a member; §Credential refusals
/// names the merged version's claim among the class. The daemon's answers
/// are pinned in `publish.rs` and `nullify_class.rs`; this pins that the
/// contract says so.
#[test]
fn doc_states_the_supersession_claim_a_publication_carries() {
    let arrangement = prose("\n### Arrangement (document editing)", &["\n### Media"]);
    for fact in [
        "and `supersede`, THE DAUGHTERS the member takes in",
        "`old` the daughter and `new` THE MEMBER THIS COMMIT MINTS, homed in `doc`'s trunk and signed in the body as the edition claim is",
        "that member is the trunk's next, a shot off a base the trunk moved past being refused whole `supersede_refused` with `detail` `head_moved`",
        "daughter a claim of yours already names is SKIPPED, never refused",
        "`supersede` is the document form's alone",
        "A `supersede` entry is an address, the daughter's",
    ] {
        assert!(arrangement.contains(fact), "§Arrangement says {fact:?}");
    }
    let shot = prose("\n### The publish shot and head-float", &["\n### Credential refusals"]);
    for fact in [
        "THE DAUGHTERS it supersedes",
        "nothing is refused for want of a base, a shot carrying `supersede` aside",
        "the read-withs, the supersession claims, each list in its declared order",
        "(6) a `supersede` list stands only beside a shot that lands on the TRUNK",
        "the list is refused whole, ahead of every entry's own check (`supersede_refused`, `detail` `head_moved`, `site.index` 0 and `site.addr` the trunk's head)",
        "then each `supersede` entry names a REGISTERED VERSION MEMBER of `doc`'s own chain",
        "`detail` `not_member`",
        "its base (`detail` `base`)",
        "`detail` `duplicate` at the second",
        "is SKIPPED, never refused — the entry commits nothing, the publication lands",
        "homed in `doc`'s TRUNK",
        "`0x05` a supersession claim",
        "`to` ONE TAG ELEMENT, `member`",
        "**The race at a supersession claim.**",
        "that member is always the TRUNK's next",
        "a request carrying `supersede` is refused whole: `supersede_refused`, permanent, `detail` `head_moved`, `site.index` 0 and `site.addr` the trunk's head, nothing committed",
        "a signed request over the old head is answered this code with its signature unchecked, never `attestation_invalid`",
        "A shot carrying no `supersede` keeps the destination's rule and lands as the base's daughter",
        "**The permanence of a supersession claim over members**",
        "THE SUPERSESSION CLAIM's readers are `in_claims` at the daughter and `out_claims` at the member",
        "a claim per `supersede` entry",
    ] {
        assert!(shot.contains(fact), "§The publish shot and head-float says {fact:?}");
    }
    let codes = prose("\n### Rejection codes", &["\n### The version-chain refusals"]);
    for fact in [
        "`supersede_refused` (a supersede entry",
        "head_moved, a member stands and the base is not the trunk's head",
        "`site.index` 0 and `site.addr` the trunk's head",
        "not_member",
        "base, the daughter the member the shot appends to",
        "duplicate, a second entry naming one daughter",
        "links, originals, read-with and supersede entries",
    ] {
        assert!(codes.contains(fact), "§Rejection codes says {fact:?}");
    }
    let links = prose("\n### Links (writes)", &["\n### Links (raw reads)"]);
    for fact in [
        "`old` and `new` are resident LINKS",
        "has one writer, `publish`'s `supersede` entry",
        "or a version member of the owner's own chain, the daughter a publication's `supersede` entry named",
    ] {
        assert!(links.contains(fact), "§Links (writes) says {fact:?}");
    }
    let discovery = prose("\n### Link discovery reads", &["\n### Grants"]);
    assert!(discovery.contains("`in_claims{y: a daughter}` answers the claims publications deposited over it"), "§Link discovery reads states the member key");
    assert!(discovery.contains("neither a resident link nor a registered member answers `[]`"), "§Link discovery reads states the empty answer");
    let credentials = prose("\n### Credential refusals", &["\n## Operations"]);
    assert!(credentials.contains("a merged version's claim over the daughter it took in"), "§Credential refusals names the merged version's claim");
    assert!(credentials.contains("so a published merge's claim is never retractable by its owner"), "§Credential refusals states the permanence");
}

/// THE KEPT PLACES (the link-sets design §5.7; lane S2; every named draft
/// re-windowed, skep #739): §Arrangement's `publish` names the `places`
/// member — parallel to `runs`, a V-position or `null` per entry, outside
/// the signed frame, absent the shot as before — and the `also_places`
/// member, each `also` draft's own places, its shape and its refusals;
/// §The publish shot and head-float states the re-window of EVERY named
/// draft at its own places, its order, its check by membership, that no
/// `also` draft's recorded base moves, and its refusal with the entry AND
/// the draft; §Rejections states `site.addr` on the two re-window codes;
/// §Rejection codes carries the token; and §The change feed names a
/// re-windowed `also` draft on the row. The daemon's answers are pinned in
/// `publish.rs` and skep-core's suite; this pins that the contract says so.
#[test]
fn doc_states_the_kept_places_and_their_refusal() {
    let arrangement = prose("\n### Arrangement (document editing)", &["\n### Media"]);
    for fact in [
        "`places`, optional, is the draft's KEPT PLACES",
        "a list parallel to `runs` by index",
        "or of a draft `also` names which the `draft` holds by identity",
        "absent or all-`null` is the shot as before",
        "a place stands beside any run, in a request naming a `draft`, at either form",
        "`also_places`, optional, is EACH `also` DRAFT's OWN KEPT PLACES",
        "at most one entry per draft, each `draft` one `also` names",
        "a place beside a run of the rendering `draft`'s or of another `also` draft's identity is `malformed`",
        "An entry whose list is all `null` is dropped",
        "The canonical form writes `also_places` only where some entry carries a place, those entries in `also`'s order",
        "The places lie OUTSIDE the signed frame, as `draft` does",
        "`malformed`, `site.index` the entry",
    ] {
        assert!(arrangement.contains(fact), "§Arrangement says {fact:?}");
    }
    let shot = prose("\n### The publish shot and head-float", &["\n### Credential refusals"]);
    for fact in [
        "**The kept places**",
        "EVERY NAMED DRAFT RE-WINDOWED",
        "RE-WINDOWS EVERY NAMED DRAFT at its own places, after the records",
        "the rendering draft first, then each `also` draft in `also`'s order",
        "The check is by MEMBERSHIP of the named place",
        "no `also` draft's RECORDED BASE MOVES",
        "`site.index` the `runs` entry and `site.addr` THE DRAFT that no longer honours the place",
        "| `kept_place_moved` | permanent | `index` = the `runs` entry, `addr` = the draft |",
        "A request that sends no places, or `null` at every entry, in either list is the shot as before",
        "The board's own producers send none",
        "* `kept_place_moved` —",
    ] {
        assert!(shot.contains(fact), "§The publish shot and head-float says {fact:?}");
    }
    let rejections = prose("\n## Rejections", &["\n### Rejection codes"]);
    assert!(
        rejections.contains("On the publication's two re-window refusals, `kept_place_moved` and `stray_place_unrecorded`, `addr` names the draft being re-windowed"),
        "§Rejections states `site.addr` on the two re-window codes"
    );
    let codes = prose("\n### Rejection codes", &["\n### The version-chain refusals"]);
    assert!(
        codes.contains("`kept_place_moved` (the publication's re-window"),
        "§Rejection codes carries the token"
    );
    assert!(codes.contains("`site.index` the runs entry and `site.addr` that draft"), "§Rejection codes states the draft on the code");
    let feed = prose("\n## The change feed", &["\n## The other endpoints"]);
    assert!(
        feed.contains("or re-windowed it at a place its `also_places` entry carries (minting nothing in it)"),
        "§The change feed names a re-windowed `also` draft on the row"
    );
    assert!(feed.contains("`create_new_document`/`fork`/`version`/`stage`"), "§The change feed names `stage` among the mints");
}

/// The kept base (skep #944) is stated wherever the base move is.
///
/// §Arrangement's `publish` names the `keep_base` member — a flag beside
/// `draft`, outside the signed frame, written only where set, `malformed`
/// without `draft`; §The publish shot and head-float states that a shot
/// setting it moves no base and re-windows its draft as ever; §Namespace's
/// `stage` and `doc_metadata` rows and the response envelope's
/// `doc_metadata` state the base it leaves standing, the marker paragraph
/// lists it among the writes that leave the marker untouched, and §The
/// change feed says the row's member is the draft's base only where the
/// shot moved it. The daemon's answers are pinned in `publish.rs` and
/// skep-core's suite; this pins that the contract says so.
#[test]
fn doc_states_the_kept_base() {
    let arrangement = prose("\n### Arrangement (document editing)", &["\n### Media"]);
    for fact in [
        "`keep_base`, optional, is a flag",
        "leaves the draft's RECORDED BASE and its merge marker standing",
        "the canonical form writes the flag only where it is `true`",
        "`keep_base` without `draft` is `malformed` naming the member",
        "a shot keeping its draft's base signs as the same shot moving it",
    ] {
        assert!(arrangement.contains(fact), "§Arrangement says {fact:?}");
    }
    let shot = prose("\n### The publish shot and head-float", &["\n### Credential refusals"]);
    assert!(
        shot.contains("A shot setting `keep_base` (§Arrangement, `publish`) moves no base at all"),
        "§The publish shot and head-float states the kept base"
    );
    let stage = prose_after("\n### Namespace", "\n**`stage`** —", &["\n**`"]);
    assert!(stage.contains("every such `publish` but one setting `keep_base`"), "§Namespace's `stage` row states the kept base: {stage}");
    let metadata = prose_after("\n### Namespace", "\n**`doc_metadata`** —", &["\n**`"]);
    assert!(metadata.contains("without `keep_base`"), "§Namespace's `doc_metadata` row states the kept base");
    let envelope = prose("\n## The response envelope", &["\n## Rejections"]);
    for fact in [
        "a `publish` setting `keep_base` (§Arrangement, `publish`) moves neither",
        "and a `publish` setting `keep_base` among them",
    ] {
        assert!(envelope.contains(fact), "§The response envelope says {fact:?}");
    }
    let feed = prose("\n## The change feed", &["\n## The other endpoints"]);
    assert!(
        feed.contains("the draft's recorded base where the shot moved it and not where the shot set `keep_base`"),
        "§The change feed states which member is the draft's base"
    );
}

/// The contract states the marker put back (skep #870).
///
/// §Arrangement's `merge` names its optional `at`, the board's check of it
/// and its refusal; §Rejection codes
/// carries the token; the response envelope's `doc_metadata` keeps the
/// position through a take-back's undo; and §The change feed's row names
/// the position put back. The daemon's answers are pinned in
/// `set_arrangement.rs` and the stores' suites; this pins that the contract
/// says so.
#[test]
fn doc_states_the_marker_put_back() {
    let arrangement = prose("\n### Arrangement (document editing)", &["\n### Media"]);
    for fact in [
        "`at`, optional, PUTS A MARKER BACK",
        "`at` without a `base` is `malformed`, and any other `at` is `marker_not_restorable`, nothing written",
        "the merge's position (`marker_not_restorable`), then `empty_result` and each change's shape",
    ] {
        assert!(arrangement.contains(fact), "§Arrangement says {fact:?}");
    }
    let codes = prose("\n### Rejection codes", &["\n### ", "\n## "]);
    assert!(codes.contains("`marker_not_restorable` (set_arrangement whose merge names a position"), "§Rejection codes carries the token");
    let envelope = prose("\n## The response envelope", &["\n## Rejections"]);
    assert!(envelope.contains("PUT BACK as it stood by one whose `merge` names the marker's `at`"), "§The response envelope keeps the position");
    let feed = prose("\n## The change feed", &["\n## The other endpoints"]);
    assert!(feed.contains("from a merge PUT BACK (`merge.at` the landing's position)"), "§The change feed names the position put back");
}

/// THE STRAY PLACES (the link-sets design §5.7, "AND THE STRAY PLACES WITH
/// THEM"; §5.5, the counterpart first; lane F4): §Arrangement's `places`
/// names a run of either kind — the draft's, or a stray run of `doc`'s own
/// identity or of another document's words, re-composed by reference to a
/// record the caller may read, wherever homed — and stands beside any run
/// in a request naming a `draft`; §The publish shot and head-float states
/// the stray arm in either list, its record read over every record the
/// caller may read, its check, its token with the entry and the draft, and
/// the window it refuses rather than keeps; §Rejection codes carries the
/// token and its table row. The daemon's answers are pinned in `publish.rs`
/// and the stores' suites; this pins that the contract says so.
#[test]
fn doc_states_the_stray_places_and_their_refusal() {
    let arrangement = prose("\n### Arrangement (document editing)", &["\n### Media"]);
    for fact in [
        "or, for a STRAY run — a run of `doc`'s own identity, or of another published document's words the draft holds",
        "re-composed by reference to a correspondence record the caller may read, wherever homed",
        "`stray_place_unrecorded` where no record the caller may read names a stray run's identity whole",
        "a place beside an ordinary window onto another document, which no record names, is refused so, never silently kept",
        "A place in a request naming no `draft`, one outside the content subspace, or one past the runs is `malformed`, `site.index` the entry; a place stands beside any run, in a request naming a `draft`, at either form",
        "or beside a stray run it arranges",
    ] {
        assert!(arrangement.contains(fact), "§Arrangement says {fact:?}");
    }
    let shot = prose("\n### The publish shot and head-float", &["\n### Credential refusals"]);
    for fact in [
        "AND THE STRAY PLACES WITH THEM",
        "re-composes such a run BY REFERENCE to the record's `to`",
        "in `places` for the rendering draft, in a draft's `also_places` entry for a stray run that draft arranges",
        "the commit reads every correspondence record the caller may read whose `to` covers the run, wherever homed",
        "checks that the draft still arranges the record's `from` words at the place, by identity as above",
        "re-windows them there onto the record's `to` in the same transaction",
        "no identity is minted and no record written",
        "A record the caller may not read is never used",
        "A stray run no record the caller may read covers whole is refused `stray_place_unrecorded`",
        "`site.index` the `runs` entry and `site.addr` the draft being re-windowed at it",
        "a placed window is re-windowed through a record or refused, never silently kept",
        "a place in `places` stands beside any run, at either form, and whether it re-windows is the commit's to decide",
        "| `stray_place_unrecorded` | permanent | `index` = the `runs` entry, `addr` = the draft |",
        "no correspondence record the caller may read names that identity whole as its `to`, wherever homed",
        "* `stray_place_unrecorded` —",
    ] {
        assert!(shot.contains(fact), "§The publish shot and head-float says {fact:?}");
    }
    let codes = prose("\n### Rejection codes", &["\n### The version-chain refusals"]);
    assert!(codes.contains("and `stray_place_unrecorded` (the re-window's stray arm"), "§Rejection codes carries the token");
    assert!(codes.contains("that no correspondence record the caller may read names whole as its to-span, wherever homed"), "§Rejection codes states the widened read");
}

/// THE STAGED BYTES, THE PRICE's FIFTH TERM (the link-sets design §5.6, M6;
/// lane F4): §The publish shot and head-float's budget paragraph states the
/// term, its table, the transaction budget it is held to and why the body
/// cap alone does not hold it; §Rejection codes' entry carries the second
/// cause and the figure.
#[test]
fn doc_states_the_staged_bytes_term_of_the_publication_price() {
    let shot = prose("\n### The publish shot and head-float", &["\n### Credential refusals"]);
    for fact in [
        "AND THE STAGED BYTES, the price's fifth term".to_string(),
        "priced from the worst-case table off the request".to_string(),
        format!("against the kernel's transaction budget, `MAX_TXN_BYTES` = {} (64 MiB)", skep_links::ReadPrice::BYTE_BUDGET),
        "so the kernel's own `txn_over_budget` is met only by a bug or a race".to_string(),
        "`detail` naming the bound passed with its figures".to_string(),
        "a `links` entry's member-position slot is up to 4096 stored spans for 36 bytes of body".to_string(),
        "a stored span is about ten times its spelling".to_string(),
    ] {
        assert!(shot.contains(&fact), "§The publish shot and head-float says {fact:?}");
    }
    assert_eq!(skep_links::ReadPrice::BYTE_BUDGET, 64 * 1024 * 1024, "the budget as the document states it");
    let codes = prose("\n### Rejection codes", &["\n### The version-chain refusals"]);
    assert!(codes.contains("its in-lock reads and its staged bytes, `publication_over_budget`"), "§Rejection codes names the second cause");
    assert!(codes.contains(&format!("past the kernel's `MAX_TXN_BYTES` = {}", skep_links::ReadPrice::BYTE_BUDGET)), "§Rejection codes states the figure");
    assert!(shot.contains("| `publication_over_budget` | permanent | — | the request's in-lock reads are priced past `MAX_PUBLICATION_READS`, or the bytes its commit would stage past the kernel's `MAX_TXN_BYTES`"), "the table row's second cause");
}

/// THE PRICE READ. §Arrangement's `publish_cost` row and §The response
/// envelope's entry carry what a client builds on. The row: the members are
/// a `publish`'s, each parsed as `publish` parses it; no `attest`; the
/// figures are the refusal's own, by the one function, answered whether or
/// not a budget is passed; nothing is written and neither a permit nor a
/// lock is taken; the named drafts are document arguments and an
/// `originals` entry's home one by derivation; a guest is priced with no
/// homes; and the rule a client admits a request by. The entry: the five
/// figures with what each counts, the two budgets with what each is held
/// to, and that the read never answers the refusal. The entry's example is
/// a price a client admits by that rule, its two budgets the daemon's own
/// and its re-window the budget paragraph's worked figure — a draft's runs
/// and the pieces placed, summed — and the budget paragraph points a client
/// at the read. The daemon's answers are pinned in `publication_reads.rs`;
/// this pins that the contract says so.
#[test]
fn doc_states_the_price_read_whose_figures_it_answers_and_how_a_client_admits() {
    let row = op_row("publish_cost");
    for fact in [
        "a read that carries a `publish`'s members",
        "each parsed as `publish` parses it",
        "one the codec refuses as a `publish` is refused here the same, `malformed`",
        "It carries no `attest`",
        "by the function its `publication_over_budget` refusal reads",
        "answered whether or not a budget is passed",
        "It writes nothing: no position moves and the change feed gains no row",
        "it takes no write permit and no lock",
        "which the daemon prices again ahead of its own lock",
        "are document arguments",
        "one you may not read answers `withheld`, `site.addr` that draft",
        "by derivation, is the home of each `originals` entry",
        "a guest holds no account and is priced with none",
        "A client admits a request where `homes × entries + rewindow + fence` is at most `read_budget` and `staged_bytes` at most `byte_budget`",
        "keeps no copy of either budget",
    ] {
        assert!(row.contains(fact), "the publish_cost row says {fact:?}: {row}");
    }
    let entry = prose_after("\n## The response envelope", "\n**`publish_cost`** —", &["\n<!-- wire:"]);
    for fact in [
        "`homes`, your link-holding homes",
        "`entries`, the `links`, `originals`, `read_with` and `supersede` entries, summed",
        "`rewindow`, per draft the commit re-windows its content runs and the pieces its lists place, summed",
        "`fence`, one per re-inserted run",
        "`staged_bytes`, the bytes the commit would stage",
        "`read_budget`, which `homes × entries + rewindow + fence` is held to",
        "`byte_budget`, which `staged_bytes` is",
        "Each is a JSON integer",
        "the read never answers `publication_over_budget`",
    ] {
        assert!(entry.contains(fact), "§The response envelope's publish_cost entry says {fact:?}: {entry}");
    }
    let example = blocks().into_iter().find(|(kind, name, _)| kind == "response" && name == "publish_cost").map(|(_, _, body)| body).expect("the entry's example");
    let example: serde_json::Value = serde_json::from_str(&example).expect("the example is JSON");
    let figure = |member: &str| example[member].as_u64().unwrap_or_else(|| panic!("`{member}` an integer: {example}"));
    assert_eq!((figure("read_budget"), figure("byte_budget")), (skep_links::ReadPrice::BUDGET as u64, skep_links::ReadPrice::BYTE_BUDGET), "the example's budgets are the daemon's");
    let reads = figure("homes") * figure("entries") + figure("rewindow") + figure("fence");
    assert!(reads <= figure("read_budget") && figure("staged_bytes") <= figure("byte_budget"), "the example is a price a client admits: {reads} reads");
    let shot = prose("\n### The publish shot and head-float", &["\n### Credential refusals"]);
    assert_eq!((figure("rewindow"), figure("fence")), (4_167 + 1_613, 1_613), "the example's re-window and fence are the budget paragraph's worked figure");
    for fact in [
        "1,613 placed pieces in a draft of 4,167 runs, at 5,780 steps and 1,613 fence stabs",
        "`publish_cost` (§Arrangement) answers a request's five figures and the two budgets, by the function this refusal reads, to a client that asks before it sends",
    ] {
        assert!(shot.contains(fact), "§The publish shot and head-float says {fact:?}");
    }
}

/// THE ELEVEN CELLS AND THE STORED SLOT ROW (SO-I6 (a), (h); SO-I7 (f)):
/// §Credential refusals names the eleven kinds the check runs on and states
/// the frame's rows once — the stored slot row under `0x03`, its EMPTY
/// spelling, the address-list row, the pair's row, the EMPTY body — and
/// that the armed set gained no cause; each op's paragraph carries its
/// `attest` statement (the mints' EMPTY body over the parent account, the
/// well-known creation's over the slot document's own address,
/// `nullify`'s and `assert_sup`'s class constants, `edit_link`'s pair and
/// fifth row); and §The change feed states the third absence. The daemon's
/// bytes are pinned in `signed_ops.rs` and `feed_class.rs`; this pins that
/// the contract says so.
#[test]
fn doc_states_the_eleven_cells_and_the_stored_slot_row() {
    let refusals = prose("\n### Credential refusals", &["\n## Operations"]);
    for fact in [
        "publish-class write of the ELEVEN KINDS that have an entry frame",
        "`create_new_document`, `fork`, `version`, `create_well_known_document`, `insert`, `publish`, `make_link`, `emit`, `nullify`, `assert_sup`, `edit_link`",
        "`delete`, `copy`, `reinstate` and `rearrange` have no frame",
        "**The entry frame's rows**",
        "THE PAIR'S ROW, its two homes as an address-list row of two: `0x01 ‖ be64(2) ‖ be32(len) ‖ d_s ‖ be32(len) ‖ d_a`",
        "THE SLOT ROW, a link slot AS THE STORE HOLDS IT",
        "`0x03 ‖ be64(n) ‖ per span: be32(len) ‖ start ‖ be32(len) ‖ width`",
        "the EMPTY slot has one spelling, `0x03 ‖ be64(0)`",
        "THE ADDRESS-LIST ROW, `0x01 ‖ be64(n) ‖ each address be32(len) ‖ dotted decimal` — never a link slot's row",
        "THE EMPTY BODY, the three mints' and the well-known creation's: the member PRESENT and empty, `be32(0)` in the frame, each under its op's own token",
        "a mint's `doc` the parent account, the creation's THE SLOT DOCUMENT's OWN ADDRESS, `<account>.0.<slot>`",
        "the widening to the eleven kinds added no cause",
        "Every publish-class write of the eleven kinds on a claimed board is judged",
        "the op is none of the eleven kinds",
    ] {
        assert!(refusals.contains(fact), "§Credential refusals says {fact:?}");
    }
    let namespace = prose("\n### Namespace", &["\n### Identity reads"]);
    for fact in [
        "`doc` is the PARENT ACCOUNT the document lands in — `account` itself",
        "`op` `create_new_document` and `body` EMPTY",
        "`doc` the principal's own account, `op` `fork`, `body` EMPTY",
    ] {
        assert!(namespace.contains(fact), "§Namespace says {fact:?}");
    }
    let arrangement = prose("\n### Arrangement (document editing)", &["\n### Media"]);
    assert!(
        arrangement.contains("never the trunk of `d_src` — `op` `version` and `body` EMPTY"),
        "§Arrangement states the version's cell over the parent account"
    );
    let links = prose("\n### Links (writes)", &["\n### Links (raw reads)"]);
    for fact in [
        "each a SLOT ROW — the slot AS THE STORE WILL HOLD IT, its spans verbatim under `0x03`",
        "the client resolves through `image` over each source before signing",
        "the retraction class's one unit span, its reserved ghost tumbler `1.1.0.1.0.1.0.1.5`",
        "the supersedes class's one unit span, its reserved ghost tumbler `1.1.0.1.0.1.0.1.4`",
        "`doc` is THE PAIR'S ROW — `d_s` then `d_a`, the op's own order",
        "THE FIFTH ROW, the claim's `from` slot row: `original`'s one unit span",
        "the `to` slot row one unit span per address and EMPTY (`0x03 ‖ be64(0)`) at a Unary class",
    ] {
        assert!(links.contains(fact), "§Links (writes) says {fact:?}");
    }
    let feed = prose("\n## The change feed", &["\n## The other endpoints"]);
    for fact in [
        "a row whose `docs` your class REDUCES carries no `attest` member — ABSENT, not `null`",
        "ABSENT on a row whose `docs` your class REDUCES (the straddle renderings above), the third absence",
    ] {
        assert!(feed.contains(fact), "§The change feed says {fact:?}");
    }
}

/// THE MEDIA SECTION (media lane A; the fence): §Media states the cell's
/// schema row by row, the canonical rule, the designation, the cap and the
/// kind's interim address, the door's four arms with their codes in a table,
/// the P10 face's words — naming no deposit and no re-PUT — the vector set
/// by path, and the INTERIM pins; and §Rejection codes and §Credential
/// refusals each point at it. The daemon's answers are pinned end to end in
/// `media.rs`; this pins that the contract says so, and that the fixture the
/// section names pins the same three constants the section does.
#[test]
fn doc_states_the_media_cell_and_its_door() {
    let media = prose("\n### Media — the reference cell and its door", &["\n### Links (writes)"]);
    for fact in [
        "ONE REFERENCE CELL",
        "| `type` | string |",
        "| `hash` | string |",
        "| `size` | number |",
        "`parse(b)` answers a cell only where `b == encode(parse(b))`",
        "`blake3`",
        "1024 bytes",
        "`1.1.0.1.0.1.0.3.89`",
        "crates/skepd/tests/it/fixtures/media/cells.json",
        "| `published_target` | `insert` | permanent |",
        "| `credential_refused`, `detail` `unbound_cell` |",
        "| `credential_refused`, `detail` `unknown_cell_schema` |",
        "no deposit of yours here is this picture's cell as written",
        "never that none was made",
        "the face now names the deposit the cell lacks",
        "INTERIM PINS",
        "What this build does NOT carry, by name",
    ] {
        assert!(media.contains(fact), "§Media says {fact:?}");
    }
    assert!(
        !media.contains("this picture's bytes were not deposited here under your account"),
        "the face that said none was made is gone"
    );
    assert!(
        !media.contains("| `not_owner`, `site.addr` the draft | `publish` | permanent |"),
        "the draft-owner arm left the door: the shot's own admission asks it of every drafted shot"
    );
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/it/fixtures/media/cells.json"),
        )
        .expect("the vector set the section names exists"),
    )
    .expect("the vector set is JSON");
    assert_eq!(fixture["kind"].as_str(), Some("1.1.0.1.0.1.0.3.89"));
    assert_eq!(fixture["designation"].as_str(), Some("blake3"));
    assert_eq!(fixture["cap"].as_u64(), Some(1024));
    let codes = prose("\n### Rejection codes", &["\n### The version-chain refusals"]);
    assert!(codes.contains("Media (lanes A and B"), "§Rejection codes points at §Media");
    let refusals = prose("\n### Credential refusals", &["\n## Operations"]);
    assert!(
        refusals.contains("**The media door's four tokens**"),
        "§Credential refusals points at §Media"
    );
}

/// THE BLIND CELL AND THE FETCH (media lane D): §Media states the blind
/// document's cell beside the picture's — its schema row, its kind's interim
/// address, its vector set by path — the ONE classification, the door's kind
/// column (the blind cell admitted with no deposit consulted), and THE FETCH
/// in full: its path and two methods, its five-step order, the M10 gate's
/// rejection riding M10's envelope under a byte-route status, the four
/// 404 "not a file" refusals and `fetch_busy`, the content type, the inert
/// pair, the pool and the two intervals; and §HTTP status codes carries the
/// seven. The daemon's answers are pinned end to end in `blob_fetch.rs`;
/// this pins that the contract says so, and that the blind vector set the
/// section names pins the same kind and cap the section does.
#[test]
fn doc_states_the_blind_cell_and_the_fetch() {
    let media = prose("\n### Media — the reference cell and its door", &["\n### Links (writes)"]);
    for fact in [
        "**The blind document's cell (v1).**",
        "| `commitment` | string |",
        "`1.1.0.1.0.1.0.3.88`",
        "carries NO `size` and NO `hash`",
        "crates/skepd/tests/it/fixtures/media/blind-cells.json",
        "ONE CLASSIFICATION reads both kinds",
        "THE KIND COLUMN",
        "NEVER `unbound_cell` or `lease_lapsed`",
        "**THE FETCH**",
        "`GET /blob?i=<address>`",
        "`HEAD /blob?i=<address>`",
        "rides M10's own envelope",
        "`403` for `withheld`",
        "`404 no_value`",
        "`404 not_a_cell`",
        "`404 unknown_cell_schema`",
        "`404 blind_cell`",
        "`404 blob_missing`",
        "`404 blob_damaged`",
        "`503 fetch_busy`",
        "checked before its first byte",
        "`Content-Type: application/octet-stream`",
        "RE-RESOLVED MID-STREAM",
        "the fetch pool, 2",
        "1 MiB of bytes and 5 s",
        "the blind document's kind, `1.1.0.1.0.1.0.3.88`",
        "`X-Content-Type-Options: nosniff`",
        "`Content-Security-Policy: sandbox`",
    ] {
        assert!(media.contains(fact), "§Media says {fact:?}");
    }
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/it/fixtures/media/blind-cells.json"),
        )
        .expect("the blind vector set the section names exists"),
    )
    .expect("the blind vector set is JSON");
    assert_eq!(fixture["kind"].as_str(), Some("1.1.0.1.0.1.0.3.88"));
    assert_eq!(fixture["cap"].as_u64(), Some(1024));
    let statuses = prose("\n### HTTP status codes", &["\n### Determinism"]);
    for name in [
        "no_value",
        "not_a_cell",
        "unknown_cell_schema",
        "blind_cell",
        "blob_missing",
        "blob_damaged",
        "fetch_busy",
    ] {
        assert!(statuses.contains(&format!("`{name}`")), "§HTTP status codes lists {name}");
    }
}

/// THE REGISTRY SECTION (the registry's stable core): §Registry states the
/// rows with their addresses and the "Deposits" column — THE TABLE AND THE
/// CODE's AGREEING ROW FOR ROW, in the table's order and none short, a
/// row's Deposits cell saying it carries them exactly where the code's row
/// does, and each registration row named as the vocabulary names it — the
/// deposit class's members, the set's own, in its order; the bodies'
/// canonical forms, a row of the bodies' table for every body the code
/// parses and its `type` string the row's; the spec's examples IN CANONICAL
/// FORM and the spaced spelling as what the parse refuses; the cap per
/// kind; the vector sets by path; the door's policy document; the record
/// grade's reach — a deposit's two positions — the registry sequence's
/// order and its refusal table under the one code, the audit-view refusal's
/// members with the endpoint and the vouch outside, the seeding check's
/// three arms, the family's tokens and what the build does not carry; §The
/// claim ceremony and credentials points at the members, §Credential
/// refusals lists the registry's classes and points at the family,
/// §Rejection codes points at the code. The daemon's answers are pinned end
/// to end in `registry.rs`, `registration.rs` and `nullify_class.rs`; this
/// pins that the contract says so, and that the vector sets the section
/// names pin the same caps and hold the section's two examples as admitted
/// bodies.
#[test]
fn doc_states_the_registry_rows_the_bodies_and_the_refusals() {
    let head = "\n### Registry — the rows, the bodies and the record grade";
    let registry = prose(head, &["\n### Links (writes)"]);
    // The section as written, line by line, for its tables.
    let text = wire_md();
    let raw = text.split(head).nth(1).expect("the section's head stands");
    let raw = raw.split("\n### Links (writes)").next().expect("the section's end");

    // THE TABLE, ROW FOR ROW AGAINST THE CODE: every line of the table the
    // section opens with, in order, is a row of `skep_registry::rows()`.
    let table: Vec<Vec<&str>> = raw
        .split("| Address | Row | Deposits |")
        .nth(1)
        .expect("the rows' table")
        .lines()
        .skip(2)
        .take_while(|line| line.starts_with('|'))
        .map(|line| line.trim_matches('|').split(" | ").map(str::trim).collect())
        .collect();
    let rows = skep_registry::rows();
    assert_eq!(table.len(), rows.len(), "the table holds a line a row, none short and none over");
    for (line, row) in table.iter().zip(rows) {
        let [address, what, deposits] = line.as_slice() else { panic!("three cells: {line:?}") };
        assert_eq!(*address, format!("`{}`", row.address), "the table's order is the code's");
        assert_eq!(
            deposits.starts_with("on "),
            row.carries_deposits(),
            "{address}: the Deposits cell {deposits:?}"
        );
        assert_eq!(deposits.starts_with("NONE on "), !row.carries_deposits(), "{address}");
        if row.of.kind() == skep_registry::Kind::Registration {
            let name = skep_registry::definition_at(&row.address).expect("a named row").name;
            assert!(what.contains(&format!("named `{name}`")), "{address}: {what:?} names {name}");
        }
    }
    let parents: Vec<&str> =
        table.iter().filter(|line| line[1].contains("a PARENT ROW")).map(|line| line[0]).collect();
    assert_eq!(parents, ["`1.1.0.1.0.1.0.3.54.1`", "`1.1.0.1.0.1.0.3.54.2`"], "the parent rows");
    assert!(
        registry.contains(
            "| `1.1.0.1.0.1.0.3.58.1` | the policy link's OWN reading | on this row |"
        ),
        "the policy link's own reading stands as it stood"
    );

    // THE DEPOSIT CLASS's MEMBERS, as the door's own set spells them.
    let members = registry
        .split("**The deposit class's members.**")
        .nth(1)
        .and_then(|rest| rest.split("the atom-bearing kinds").next())
        .expect("the members' sentence");
    let spelled: Vec<&str> = members
        .split('`')
        .filter(|token| token.starts_with("1.1.0.1.0.1.0.3."))
        .collect();
    let door: Vec<String> =
        skep_arrangement::deposit_class_types().iter().map(|ty| ty.to_string()).collect();
    assert_eq!(spelled, door, "the section's members are the door's set, in its order");

    // THE BODIES' TABLE: a row for every body the code parses, its `type`
    // the string its registry row holds.
    let mut parsed = vec!["binding", "endpoint"];
    parsed.extend(
        skep_registry::RegistrationKind::ALL.iter().map(|k| k.row().type_value.expect("a type")),
    );
    for ty in &parsed {
        assert!(registry.contains(&format!("| `\"{ty}\"` |")), "the bodies' table has a row typed {ty}");
    }
    let bodies_rows = raw
        .split("| row | `type` | members, in order |")
        .nth(1)
        .expect("the bodies' table")
        .lines()
        .skip(2)
        .take_while(|line| line.starts_with('|'))
        .count();
    assert_eq!(bodies_rows, parsed.len(), "a row a parsed body, and no other");

    for fact in [
        "**The rows**",
        "**The deposit class's members.**",
        "**The bodies**",
        "`parse(b)` answers a record only where `b == encode(parse(b))`",
        r#"{"type":"binding","prefix":"1.5"}"#,
        r#"{"type":"endpoint","origins":["https://acme.example","https://acme.example.net","http://<acme's onion host>.onion"]}"#,
        "are what the parse REFUSES",
        r#"framed("skep-registration-v1", [door, fresh, shape, node, board])"#,
        "NO member is a JSON number but a PRINCIPAL",
        "the three TOGETHER or not at all",
        "crates/skep-registry/tests/vectors/records.json",
        "`registration.json`",
        "**The door's policy document**",
        "crates/skep-registry/tests/vectors/policy.json",
        "**The record grade for registry records**",
        "BOTH of the deposit's positions",
        "**The registry sequence and its refusals.**",
        "THE BOARD'S OWN BINDING-WRITING ACCOUNT",
        "A REQUEST'S SHAPE",
        "| `claim_first` | permanent |",
        "| `signed_session_required` | permanent |",
        "| `not_doc_one` | permanent |",
        "| `registry_form` | permanent |",
        "| `malformed_record:<cause>` | permanent |",
        "| `attestation_required` | reorder |",
        "| `attestation_invalid:<cause>` | the cause's |",
        r#"{"code":"registry_refused","detail":"registry_form","disposition":"permanent","op":"make_link","resp":"rejected"}"#,
        "**The audit-view refusal**",
        "The ENDPOINT is NOT a member",
        "THE VOUCH is NOT a member",
        "**The seeding check**",
        "**The body cap is a term of the format, per kind**",
        "64 KiB, 65,536 bytes, for a registration REQUEST of either kind, and 16 KiB, 16,384 bytes, for every other body",
        "**The family's tokens are pinned**",
        "What this build does NOT carry, by name",
        "The checked set of the write-path check is UNCHANGED",
    ] {
        assert!(registry.contains(fact), "§Registry says {fact:?}");
    }
    // No stale tally and no interim head stands in the section.
    for stale in ["twelve", "five kinds", "seven subtype", "the reserve's ordinals", "INTERIM", "four members"] {
        assert!(!registry.contains(stale), "§Registry no longer says {stale:?}");
    }
    // THE AUDIT MEMBERS: each registration row the section names as a
    // member is a request row, an answer row or the approval — never a
    // parent's or the kind's address, and never the vouch's.
    let audit = registry
        .split("**The audit-view refusal**")
        .nth(1)
        .and_then(|rest| rest.split("**The seeding check**").next())
        .expect("the audit paragraph");
    for member in ["…3.54.1.1", "…3.54.1.2", "…3.54.2.1", "…3.54.2.2", "…3.54.2.3", "…3.54.4"] {
        assert!(audit.contains(&format!("`{member}`")), "the audit paragraph names {member}");
    }
    for no_member in ["`…3.54`", "`…3.54.1`", "`…3.54.2`", "`…3.54.3`"] {
        assert!(!audit.contains(no_member), "the audit paragraph names no member at {no_member}");
    }

    let fixture = |name: &str| -> Value {
        serde_json::from_str(
            &std::fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../skep-registry/tests/vectors")
                    .join(name),
            )
            .unwrap_or_else(|e| panic!("the vector set {name} the section names exists: {e}")),
        )
        .expect("the vector set is JSON")
    };
    let records = fixture("records.json");
    assert_eq!(records["cap"].as_u64(), Some(16_384));
    assert_eq!(skep_registry::MAX_REGISTRY_RECORD_BYTES, 16_384);
    assert_eq!(skep_registry::MAX_REGISTRATION_REQUEST_BYTES, 65_536);
    let registration = fixture("registration.json");
    for kind in skep_registry::RegistrationKind::ALL {
        let ty = kind.row().type_value.expect("a type");
        assert_eq!(registration["caps"][ty].as_u64(), Some(kind.cap() as u64), "{ty}: its cap");
    }
    assert!(fixture("policy.json")["vectors"].as_array().is_some_and(|v| !v.is_empty()));
    let vectors = records["vectors"].as_array().expect("vectors");
    for example in [
        r#"{"type":"binding","prefix":"1.5"}"#,
        r#"{"type":"endpoint","origins":["https://acme.example","https://acme.example.net","http://<acme's onion host>.onion"]}"#,
    ] {
        assert!(
            vectors.iter().any(|v| v["bytes"].as_str() == Some(example) && v["parse"] == "ok"),
            "the section's example is an admitted vector: {example}"
        );
    }
    let credentials =
        prose("\n### The claim ceremony and credentials", &["\n### Correlation and idempotency"]);
    assert!(
        credentials.contains("its members stated once at §Registry under §Operations"),
        "§The claim ceremony and credentials points at the deposit class's members"
    );
    let refusals = prose("\n### Credential refusals", &["\n## Operations"]);
    for fact in [
        "the binding (`1.1.0.1.0.1.0.3.55`)",
        "the takedown record (`1.1.0.1.0.1.0.3.57`)",
        "the policy link (`1.1.0.1.0.1.0.3.58`)",
        "the registration's request rows, answer rows and approval link, each at its own address (`1.1.0.1.0.1.0.3.54.1.1`",
        "the endpoint (`1.1.0.1.0.1.0.3.56`) OUTSIDE",
        "the registration's vouch (`1.1.0.1.0.1.0.3.54.3`) OUTSIDE",
        "**The registry sequence's family**",
        "`registry_refused`",
    ] {
        assert!(refusals.contains(fact), "§Credential refusals says {fact:?}");
    }
    let codes = prose("\n### Rejection codes", &["\n### The version-chain refusals"]);
    assert!(
        codes.contains("The registry: registry refused")
            && codes.contains("§Registry under §Operations"),
        "§Rejection codes points at §Registry"
    );
}

/// THE UPLOAD (media lane B; the record's clauses, the H1 rows; the upload
/// permit pool, M-I5 (f); the FAILED index, `operations.md` §4 row 26):
/// §Media states the PUT's path family and its five method/path pairs, the
/// identifier's two carriers, the seven clauses each by number — clause (4)
/// with the partial neither the pass nor the open can remove — the eleven
/// refusals of the family with their statuses — the permit's `upload_busy`
/// and the failed index's `index_failed` among them — THE PERMIT in the
/// creation's and the resume's rows, the deposit read's members, the
/// binding's three answers at the door with `lease_lapsed` the third
/// token, the INTERIM pins the build carries — the cap, the chunk, the
/// grain, the identifier's bits, the partial's name, the lease interval
/// and the horizon, the idle and transfer bounds, the floor, the limits
/// record's default and its owed channel, the upload pool's count and the
/// two worker counts it is counted into, the failed face — and the H1
/// rows; the readiness paragraph's FAILED arm, which with the token's two
/// rows names no retry (the fence's I3 and I5); §Endpoints lists the
/// family, §Transport the family's cap, §HTTP status codes the eleven; and
/// the vector set the section names pins the same constants.
#[test]
fn doc_states_the_upload_its_pins_and_its_refusals() {
    let media = prose("\n### Media — the reference cell and its door", &["\n### Links (writes)"]);
    for fact in [
        "**The upload — the PUT**",
        "`POST /blob/upload?length=<N>`",
        "`PATCH /blob/upload/<id>?offset=<K>`",
        "`GET /blob/upload/<id>`",
        "`DELETE /blob/upload/<id>`",
        "`GET /blob/upload`",
        "`Upload-Id`",
        "(1) THE IDENTIFIER",
        "(2) THE PENDING QUOTA",
        "(3) ONE EXPIRY",
        "(4) REMOVED ON EXPIRY",
        "A partial that neither the pass nor the open can remove stays until one can, and its \
         upload answers `no_upload` all the same.",
        "(5) A STREAM CLAIMS ITS UPLOAD FIRST",
        "(6) REFUSED IS ENDED",
        "(7) FINISHED, THE LEASE TAKES OVER",
        "| 400 | `malformed_blob` |",
        "| 403 | `upload_refused` |",
        "| 404 | `no_upload` |",
        "| 409 | `upload_held` |",
        "| 409 | `upload_offset` |",
        "| 400 | `upload_length` |",
        "| 413 | `payload_too_large` |",
        "| 507 | `deposit_refused` |",
        "| 500 | `blob_io` |",
        "| 503 | `index_rebuilding` |",
        "| 503 | `index_failed` |",
        "| 503 | `upload_busy` |",
        "the eleven refusal names with their statuses above",
        "the failed face, not retried:",
        "admitted under the upload permit pool",
        "`503 upload_busy`",
        "THE PERMIT",
        "bounded by a pool, never a queue",
        "the upload pool, 4",
        "{\"base\":<bytes>,\"deposits\":[…],\"limits\":null,\"pending\":<bytes>,\"per_account\":<bytes>,\"uploads\":[…]}",
        "`credential_refused`, `detail` `lease_lapsed`",
        "a hash this principal did not deposit under its own lease",
        "NO ANSWER OF THE UPLOAD SAYS WHETHER THE FILE WAS ALREADY HERE",
        "the per-file cap, 64 MiB",
        "the chunk, 64 KiB",
        "the partial's fsync grain, 1 MiB",
        "128 bits",
        "`.upload-<identifier>`",
        "the lease interval's default, seven days",
        "the horizon, thirty days",
        "the idle bound, 30 s",
        "the transfer bound, 10 minutes",
        "the floor, 256 MiB",
        "CONSTANT HALF",
        "twice the newest checkpoint's size plus one maximal segment",
        "re-read as each checkpoint lands",
        "the cadence's byte bound",
        "AUTH-4.70",
        "takes no `Serial`",
        "crates/skepd/tests/it/fixtures/media/uploads.json",
        "**The H1 rows**",
    ] {
        assert!(media.contains(fact), "§Media says {fact:?}");
    }
    // The two worker counts the pool is counted into, read THROUGH the
    // constants: the pins passage moves with them (the ops lanes' D6, the
    // write pool's landing moved both) and never ahead of or behind them.
    for pin in [
        format!("`MIN_WORKERS`, {}", skepd::MIN_WORKERS),
        format!("`DEFAULT_WORKERS`, {}", skepd::DEFAULT_WORKERS),
    ] {
        assert!(media.contains(&pin), "§Media says {pin:?}");
    }
    let endpoints = prose("\n### Endpoints", &["\n### Transport"]);
    assert!(endpoints.contains("`POST /blob/upload`"), "§Endpoints lists the family");
    assert!(
        endpoints.contains("`PATCH /blob/upload/<id>`"),
        "§Endpoints lists the family's resume"
    );
    let transport = prose("\n### Transport", &["\n### Identity"]);
    assert!(
        transport.contains("**64 MiB** on the blob upload"),
        "§Transport names the family's cap"
    );
    let statuses = prose("\n### HTTP status codes", &["\n### Determinism"]);
    for name in [
        "malformed_blob",
        "upload_refused",
        "no_upload",
        "upload_held",
        "upload_offset",
        "upload_length",
        "deposit_refused",
        "blob_io",
        "index_rebuilding",
        "index_failed",
        "upload_busy",
    ] {
        assert!(statuses.contains(&format!("`{name}`")), "§HTTP status codes lists {name}");
    }
    // THE FAILED ARM (`operations.md` §4 row 26; PATTERNS P10): the
    // readiness paragraph says where the walk died the three readers answer
    // `index_failed` for the life of the process, the door the lease arm's
    // verdict as final, the pruner no pass, the act a restart — and neither
    // it nor the token's two rows names a retry: "retry" and "shortly"
    // absent from each.
    let readiness = media
        .split("**The readiness refusal**")
        .nth(1)
        .and_then(|rest| rest.split("**The pruner.**").next())
        .expect("the readiness paragraph");
    let failed_arm = readiness
        .split("Where the walk at open DIED")
        .nth(1)
        .expect("the FAILED arm closes the readiness paragraph");
    for fact in [
        "`503 {\"error\":\"index_failed\",\"detail\":\"…\"}`",
        "for the life of the process",
        "the lease arm's own verdict as final",
        "`lease_lapsed`",
        "`unbound_cell`",
        "the pruner runs no pass",
        "a restart",
    ] {
        assert!(failed_arm.contains(fact), "the FAILED arm says {fact:?}: {failed_arm}");
    }
    let row_cell = |table: &str, row: &str| -> String {
        table
            .split(row)
            .nth(1)
            .and_then(|rest| rest.split(" | | ").next())
            .unwrap_or_else(|| panic!("the row {row:?} and its cell"))
            .to_string()
    };
    for text in [
        row_cell(&statuses, "| 503 | `index_failed` |"),
        row_cell(&media, "| 503 | `index_failed` |"),
        failed_arm.to_string(),
    ] {
        assert!(text.contains("a restart"), "the act, a restart: {text}");
        assert!(
            !text.contains("retry") && !text.contains("shortly"),
            "no retry hint (P10) in a face of the failed index: {text}"
        );
    }
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/it/fixtures/media/uploads.json"),
        )
        .expect("the vector set the section names exists"),
    )
    .expect("the vector set is JSON");
    assert_eq!(fixture["pins"]["per_file_cap"].as_u64(), Some(64 * 1024 * 1024));
    assert_eq!(fixture["pins"]["lease_interval_ms"].as_u64(), Some(7 * 24 * 3600 * 1000));
    assert_eq!(fixture["pins"]["lease_horizon_ms"].as_u64(), Some(30 * 24 * 3600 * 1000));
    assert_eq!(fixture["pins"]["upload_pool"].as_u64(), Some(4));
    assert_eq!(fixture["pins"]["min_workers"].as_u64(), Some(skepd::MIN_WORKERS as u64));
    assert_eq!(fixture["pins"]["default_workers"].as_u64(), Some(skepd::DEFAULT_WORKERS as u64));
    assert_eq!(fixture["refusals"]["deposit_refused"].as_u64(), Some(507));
    assert_eq!(fixture["refusals"]["index_rebuilding"].as_u64(), Some(503));
    assert_eq!(fixture["refusals"]["index_failed"].as_u64(), Some(503));
    assert_eq!(fixture["refusals"]["upload_busy"].as_u64(), Some(503));
}

/// THE WALK BEHIND THE LISTENER (`operations.md` §3.3 step 2; §4 row 16;
/// the ops lanes' D9, W1's third token): §HTTP status codes carries
/// `feed_rebuilding` at 503 in the retry-class family's voice — the region
/// a lost or torn `commits.log` left uncovered, re-covered behind the
/// listener, pages below and above serving, `/events` untouched, retry
/// shortly, save after the walk's death, which no retry outlasts — and §The
/// change feed's **Rebuilding.** paragraph says the walk's shape: the
/// refusal's body, that it is retry-class as `history_busy` is, that pages
/// above and below serve, `/events` is untouched, that one rewrite lands
/// it, and that a dead walk's region stays uncovered until a restart, its
/// `detail` saying so. The daemon's answers are
/// pinned end to end in `feed_walk.rs`; this pins that the contract says so.
#[test]
fn doc_states_the_feed_walk_behind_the_listener_and_its_token() {
    let statuses = prose("\n### HTTP status codes", &["\n### Determinism"]);
    assert!(
        statuses.contains("| 503 | `feed_rebuilding` |"),
        "§HTTP status codes carries the token at 503"
    );
    let row = statuses
        .split("| 503 | `feed_rebuilding` |")
        .nth(1)
        .and_then(|rest| rest.split(" | | ").next())
        .expect("the row's cell");
    for fact in [
        "lost or torn `commits.log`",
        "behind the listener",
        "pages below and above",
        "`/events` is untouched",
        "retry shortly",
        "`history_busy`",
        "no retry succeeds before it",
    ] {
        assert!(row.contains(fact), "the row says {fact:?}: {row}");
    }
    let feed = prose("\n## The change feed", &["\n## The other endpoints"]);
    for fact in [
        "**Rebuilding.**",
        "re-covered behind the listener",
        "`503 {\"error\": \"feed_rebuilding\", \"detail\": …}`",
        "retry-class, as `history_busy` is",
        "above and below the region serve",
        "`/events` is untouched",
        "ONE rewrite",
        "Where the walk's thread dies, the region stays uncovered",
        "no retry succeeds",
    ] {
        assert!(feed.contains(fact), "§The change feed says {fact:?}");
    }
}

/// THE WRITE PERMIT POOL (`operations.md` §4 rows 25, 27; the ops lanes' D6,
/// W1's second token): §The model says a write is admitted under
/// `MAX_CONCURRENT_WRITES` (4) at once, taken before the credential lock and
/// the guard, the next refused `503 write_busy`, retry-class, nothing
/// committed; §HTTP status codes carries the token at 503 in the pool
/// family's voice — all write permits in use, the `op` carried, retry
/// shortly; and §Media's pins passage counts the pool into the worker
/// minimum — `MIN_WORKERS` one more than the SIX pools' slots together, the
/// write pool's 4 among them, the default one above it — the two counts
/// read through the constants, and the vector set pins the same two. The
/// daemon's answers are pinned end to end in `write_pool.rs`; this pins
/// that the contract says so.
#[test]
fn doc_states_the_write_permit_pool_and_its_token() {
    let model = prose("\n## The model", &["\n### Endpoints"]);
    for fact in [
        "the daemon serializes writes internally",
        "At most `MAX_CONCURRENT_WRITES` (4) write requests are admitted at once",
        "the write permit pool, taken before the credential lock and the guard",
        "the next is refused `503 write_busy`, retry-class, nothing committed",
    ] {
        assert!(model.contains(fact), "§The model says {fact:?}");
    }
    let statuses = prose("\n### HTTP status codes", &["\n### Determinism"]);
    assert!(
        statuses.contains("| 503 | `write_busy` |"),
        "§HTTP status codes carries the token at 503"
    );
    // The row's cell alone: `prose` collapses the table's whitespace, so the
    // next row opens at the first `| |` after the token's.
    let row = statuses
        .split("| 503 | `write_busy` |")
        .nth(1)
        .and_then(|rest| rest.split(" | | ").next())
        .expect("the row's cell");
    for fact in [
        "all write permits are in use",
        "past the write permit pool",
        "before the credential lock and the guard are taken",
        "nothing committed",
        "carries `op`",
        "retry shortly",
    ] {
        assert!(row.contains(fact), "the row says {fact:?}: {row}");
    }
    let media = prose("\n### Media — the reference cell and its door", &["\n### Links (writes)"]);
    for fact in
        ["six pools' slots together", "the write permit pool's 4", "`MAX_CONCURRENT_WRITES`"]
    {
        assert!(media.contains(fact), "§Media's pins say {fact:?}");
    }
    for pin in [
        format!("`MIN_WORKERS`, {}", skepd::MIN_WORKERS),
        format!("`DEFAULT_WORKERS`, {}", skepd::DEFAULT_WORKERS),
    ] {
        assert!(media.contains(&pin), "§Media's pins say {pin:?}");
    }
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/it/fixtures/media/uploads.json"),
        )
        .expect("the vector set exists"),
    )
    .expect("the vector set is JSON");
    assert_eq!(fixture["pins"]["min_workers"].as_u64(), Some(skepd::MIN_WORKERS as u64));
    assert_eq!(fixture["pins"]["default_workers"].as_u64(), Some(skepd::DEFAULT_WORKERS as u64));
    assert!(
        fixture["note"].as_str().is_some_and(|note| note.contains("fetch and write pools")),
        "the set's note counts the write pool into the minimum"
    );
}

/// Checks §Transport's largest single answer, its deadlines and head cap.
///
/// §Transport states, per route, the largest single answer a reader must
/// accept as the code bounds it today — the blob fetch at the per-file cap,
/// a feed page at the page byte budget, a frame answer in items, spans and
/// pairs and in bytes by no constant, the dump the world, the rest one
/// object — and never the kernel's per-transaction budget restated; the
/// transport's three deadlines, 30 s each, with what each bounds; and the
/// request head's cap with its refusal (`operations.md` §2.4 rows 1, 2 and
/// 12; the ops lanes' W3 and W4). The figures the test reaches are read
/// through the constants — the per-file cap, the delivery, span and pair
/// budgets, and the page budget, `skep_core::limits`'s
/// `MAX_CHANGES_PAGE_BYTES`, cross-checked against the `budget` §The change
/// feed's refusal carries — so the sentence moves with them; the three
/// deadlines (`http.rs`'s `REQUEST_READ_TIMEOUT`, `WRITE_TIMEOUT` and
/// `TRANSFER_DEADLINE`) and the head cap (`http.rs`'s `MAX_REQUEST_HEAD`,
/// whose refusal `read_request` spells) are the daemon's private
/// constants, pinned as the literals their cards spell.
#[test]
fn doc_states_the_largest_single_answer_the_three_deadlines_and_the_head_cap() {
    let transport = prose("\n### Transport", &["\n### Identity"]);
    for fact in [
        "THE LARGEST SINGLE ANSWER a reader must accept is the route's".to_string(),
        "no one figure bounds every route".to_string(),
        format!(
            "`GET /blob?i=` streams one file up to the per-file cap, **{} MiB**",
            skep_media::limits::MAX_BLOB_BYTES >> 20
        ),
        "its `Content-Length` the file's size and a RESET the one end short of it".to_string(),
        format!(
            "a `GET /changes` page carries at most **{} MiB** of marshaled entries",
            skep_core::limits::MAX_CHANGES_PAGE_BYTES >> 20
        ),
        "a page past it refused whole with `400 malformed_changes` carrying `budget` and `fits`"
            .to_string(),
        "bounded in ITEMS where it is bounded at all and in bytes by no constant of the daemon's"
            .to_string(),
        format!("a delivery at `MAX_DELIVERY_ITEMS` = {} items", skep_retrieval::MAX_DELIVERY_ITEMS),
        format!(
            "an endset or projection answer at `MAX_ANSWER_SPANS` = {} spans",
            skep_discovery::MAX_ANSWER_SPANS
        ),
        format!("a compare report at `MAX_COMPARE_PAIRS` = {} pairs", skep_retrieval::MAX_COMPARE_PAIRS),
        "each item or span as large as the value or the addresses it carries".to_string(),
        "a list answer — the links or documents found, the claims, the grant rows, the orphan preview — as long as the world makes it".to_string(),
        "`GET /dump` (`observe` builds) is the whole world at the reader's class".to_string(),
        "every other route answers one JSON object of a few members or nothing (`204`)".to_string(),
        "the deposit read's listing the requester's own deposits and standing uploads".to_string(),
    ] {
        assert!(transport.contains(&fact), "§Transport says {fact:?}");
    }
    assert!(
        !transport.contains("MAX_TXN_BYTES") && !transport.contains("per-transaction"),
        "the sentence bounds the answer, never the kernel's transaction budget restated"
    );
    let feed = prose("\n## The change feed", &["\n## The other endpoints"]);
    assert!(
        feed.contains(&format!("\"budget\": {}", skep_core::limits::MAX_CHANGES_PAGE_BYTES)),
        "the budget §Transport spells is the budget §The change feed's refusal carries"
    );
    // THE THREE DEADLINES (§2.4 row 1): `Duration::from_secs(30)` each in
    // `http.rs`, `pub(super)` — the literal, with what each bounds in the
    // cards' own terms.
    for fact in [
        "Every other exchange runs under the transport's three deadlines, 30 s each",
        "the socket's read deadline and write deadline, per call and renewed by any byte, bound SILENCE",
        "a request whose bytes stall that long is refused `400 malformed_http`",
        "an answer whose reader stops draining is dropped",
        "the transfer deadline, checked between socket calls, bounds SLOWNESS",
        "the request in (head and body) and the answer out each have 30 s of their own",
        "a request not delivered within its deadline answered `400 malformed_http` under the reply's own deadline",
        "an answer not taken within its dropped",
        "`GET /events`, once open, is written under the write deadline per event and no transfer deadline",
        "the two blob routes' streamed bodies — the upload's in, the fetch's out — run under the idle and transfer bounds above instead",
    ] {
        assert!(transport.contains(fact), "§Transport says {fact:?}");
    }
    // THE HEAD CAP (§2.4 row 2): `MAX_REQUEST_HEAD` = `64 * 1024` in
    // `http.rs`, private — the literal, and the detail `read_request`
    // formats from it.
    for fact in [
        "The request HEAD — the request line and the headers — is capped at **64 KiB**".to_string(),
        format!(
            "a longer one is refused `400 malformed_http` with the detail `request head exceeds the {}-byte cap`",
            64 * 1024
        ),
        "before the body is read; frames ride in the body, under the caps above".to_string(),
    ] {
        assert!(transport.contains(&fact), "§Transport says {fact:?}");
    }
}

/// **The image in pages, as the document states it.** §Link discovery reads'
/// `image` row says a region past the run budget is never refused for its
/// runs and answers `image_page`, names the continuation — the rest of the
/// region and the page's `next` sent back whole as `cur` — and the one
/// state a page set is of: read from `cur.surface`, a draft's refused
/// `page_moved` once written, a published document's answered from the
/// version its first page read, another arrangement or another place
/// `bad_region`; §Value encodings states the go-on's three members;
/// §The response envelope states the page's shape and why it is no `runs`;
/// and §Rejection codes lists `page_moved` and says the image read is not
/// refused for the runs its region resolves. The examples are held to the
/// codec by the marker tests; the continuation's parses to the go-on it
/// spells.
#[test]
fn doc_states_the_image_in_pages_its_continuation_and_the_one_state_of_a_page_set() {
    let row = op_row("image");
    for fact in [
        "→ `runs`; or, where the region resolves more than `MAX_IMAGE_RUNS` = 4096 runs, `image_page`",
        "NEVER REFUSED FOR THE RUNS IT RESOLVES",
        "a document in R runs is read whole in ⌈R ÷ 4096⌉ frames, each answered",
        "THE CONTINUATION is the same frame with the rest of the region and the page's `next` sent back whole as `cur`",
        "`region`'s first span begins at `cur.at`",
        "A PAGE SET IS ONE STATE, whoever reads it",
        "The continuation is read from `cur.surface`, not from wherever `d`'s readers float by then",
        "it is answered only while that document's `arranged_at` is still `cur.arranged_at`",
        "the continuation is refused `page_moved` — `site.addr` the document, `permanent`",
        "any other, and a `region` that does not begin at `cur.at`, is `bad_region`",
        "A region of several spans is paged in region order",
    ] {
        assert!(row.contains(fact), "the image row says {fact:?}: {row}");
    }
    let encodings = prose("\n## Value encodings", &["\n## The request envelope"]);
    for fact in [
        "**Go-ons** (a paged read) are `{\"at\": <nat>, \"surface\": <address>, \"arranged_at\": <position or null>}`",
        "the continuation sends it back WHOLE under `cur`",
        "The board holds no iterator here either",
    ] {
        assert!(encodings.contains(fact), "§Value encodings says {fact:?}");
    }
    let envelope = prose("\n## The response envelope", &["\n## Rejections"]);
    for fact in [
        "`ispans` is its first 4096 runs",
        "EVERY ONE WHOLE — a page ends at a run's reach, never inside one",
        "A `resp` of its own and a member of its own, never `runs` with a member beside it",
    ] {
        assert!(envelope.contains(fact), "§The response envelope says {fact:?}");
    }
    let codes = prose("\n### Rejection codes", &["\n### ", "\n## "]);
    for fact in [
        "`page_moved` (the image read's continuation of a draft or a private document written since its page was read",
        "where the image read, never refused for those runs, ends its page and names where the rest begins",
    ] {
        assert!(codes.contains(fact), "§Rejection codes says {fact:?}");
    }
    // The continuation's example carries the go-on the page's example hands
    // back, in the one form.
    let codec = JsonCodec;
    let continued = blocks().into_iter().find(|(kind, name, body)| kind == "request" && name == "image" && body.contains("\"cur\"")).expect("the continuation's example").2;
    let frame = codec.parse(continued.as_bytes()).unwrap_or_else(|e| panic!("the continuation parses: {e}"));
    let skep_febe::Op::Image { cur, region, .. } = frame.op else { panic!("an image") };
    let cur = cur.expect("the go-on");
    assert_eq!((cur.at.clone(), cur.arranged_at), (n(4097), Some(Seq(7))));
    assert_eq!(region[0].start().iter().nth(1), Some(&cur.at), "the region begins where the go-on says");
}

/// **An edit carries no landing, as the document states it.** §Arrangement's
/// `edit` row says `base` and `merge` are a landing's terms and
/// `set_arrangement`'s alone, an `edit` carrying either refused at the
/// parse with nothing written and no row, `head` the one of the three it
/// keeps; and the codec holds the document to it — its own `edit` example
/// parses, and with a `base` or a `merge` beside it is refused as an
/// unknown field, where the same members under `set_arrangement` parse.
#[test]
fn doc_states_an_edit_carries_no_landing_and_the_codec_refuses_one() {
    let row = op_row("edit");
    for fact in [
        "Of `set_arrangement`'s three optional members, below, it carries ONE: `head`",
        "`base` and `merge` are a LANDING's terms, and a landing is `set_arrangement`'s alone",
        "an `edit` frame carrying either is refused at the parse",
        "with nothing written and no row",
        "An EMPTY `changes` changes nothing and is refused `empty_result`",
        "the two terms `base` and `merge`, both `null`",
    ] {
        assert!(row.contains(fact), "the edit row says {fact:?}: {row}");
    }
    let landing = op_row("set_arrangement");
    assert!(landing.contains("a landing's terms, `base` and `merge` below, which no other frame carries"), "{landing}");
    let codec = JsonCodec;
    let example = blocks().into_iter().find(|(kind, name, _)| kind == "request" && name == "edit").expect("the edit's example").2;
    let with = |name: &str, members: &str| {
        let mut frame: Value = serde_json::from_str(&example).expect("the example is JSON");
        frame["op"] = Value::from(name);
        for (member, value) in serde_json::from_str::<Value>(members).expect("members").as_object().expect("an object") {
            frame[member] = value.clone();
        }
        if name == "set_arrangement" {
            frame["changes"] = Value::Array(Vec::new());
        }
        codec.parse(frame.to_string().as_bytes())
    };
    assert!(with("edit", "{}").is_ok(), "the document's own example parses");
    let head = r#""head":{"at":"1.0.1.0.1.2","extent":"4"}"#;
    assert!(with("edit", &format!("{{{head}}}")).is_ok(), "the head pair rides an edit");
    for (members, named) in [
        (r#"{"base":{"at":"1.0.1.0.1.2","extent":"4"}}"#.to_string(), "unknown field 'base'"),
        (format!(r#"{{{head},"merge":{{"sides":[]}}}}"#), "unknown field 'merge'"),
    ] {
        let refused = with("edit", &members).expect_err("an edit carries no landing");
        assert!(refused.detail.as_deref().is_some_and(|detail| detail.contains(named)), "{members}: {refused}");
        assert!(with("set_arrangement", &members).is_ok(), "a landing is set_arrangement's: {members}");
    }
}

/// **A paged past read is one reconstruction, and when it is let go.** §Reading
/// history says an `image` at a position that answers a page keeps the
/// state and its slot for the continuation, which rebuilds nothing and is
/// never refused `history_busy`; that the kept state is let go at the
/// read's end, when its reader begins that read again, and after
/// **`KEPT_READ_IDLE` = 10 s** with no page asked — at the next historical
/// request, before it asks for a slot. The figure is `history.rs`'s
/// crate-private constant, held by the daemon's own behaviour: a read left
/// after its first page keeps its slot half-way to the document's figure
/// and has lost it at the figure, the edge clock driven through its seam;
/// the bound to the millisecond is `history.rs`'s own unit test's.
#[test]
fn doc_states_a_paged_past_read_is_one_reconstruction_and_when_it_is_let_go() {
    use crate::common::{acked_at, draft_with, edit_frame, expect_resp, image_frame, insert_text, op, op_at_ok, open_session, spanset_frame, spawn, CLAIMANT_PRINCIPAL};

    let history = prose("\n## Reading history", &["\n## The commit stream"]);
    for fact in [
        "**A paged read is one reconstruction.**",
        "is answered from the kept state, and so on to the last page",
        "It rebuilds nothing and asks no slot, so it is never refused `history_busy`",
        "ONE reconstruction and ⌈R ÷ 4096⌉ frames",
        "holds one of the pool's slots from its first page to its last",
        "is rebuilt as every other historical read is, and answered the same page",
        "when the read ends — a page under `runs`, or a rejection the read itself answers",
        "`withheld`, decided ahead of the read (§The read predicate), reaches no kept state — when its reader sends that read's first page again",
        "**`KEPT_READ_IDLE` = 10 s**",
        "the next historical request lets an idle read go before it asks for a slot",
        "A past state does not move, so a read at a position meets no `page_moved`",
        "per request, with no answer kept, a paged `image`'s reconstruction aside (above)",
    ] {
        assert!(history.contains(fact), "§Reading history says {fact:?}");
    }
    let idle_ms = figure_after(&history, "**`KEPT_READ_IDLE` = ") as u64 * 1_000;
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = draft_with(port, &owner, &"a".repeat(2_501));
    let cuts: Vec<(u64, u64, &str)> = (2..=2_501).map(|at| (at, 0, "b")).collect();
    let at = acked_at(expect_resp(&op(port, Some(&owner), &edit_frame(&draft, &cuts, None)), "ack_addr"));
    expect_resp(&insert_text(port, &owner, &draft, 1, "since"), "ack_addr");
    // Held together, then counted: a permit dropped as it is taken returns
    // its slot to the pool.
    let free = || std::iter::from_fn(|| sd.daemon().try_hold_reconstruction_permit()).collect::<Vec<_>>().len();
    expect_resp(&op_at_ok(port, Some(&owner), at, &image_frame(&draft, 1, 5_001)), "image_page");
    assert_eq!(free(), 1, "the page's state is kept, its slot held");
    // Half-way to the figure: the time the requests themselves take, which
    // the seam's clock counts too, is far under the other half.
    sd.daemon().advance_edge_clock_ms(idle_ms / 2);
    expect_resp(&op_at_ok(port, Some(&owner), at, &spanset_frame(&draft)), "span_set");
    assert_eq!(free(), 1, "half-way to the document's figure it is kept still");
    sd.daemon().advance_edge_clock_ms(idle_ms - idle_ms / 2);
    expect_resp(&op_at_ok(port, Some(&owner), at, &spanset_frame(&draft)), "span_set");
    assert_eq!(free(), 2, "at the figure the next historical request lets it go");
    sd.shutdown();
}

/// THE RECONSTRUCTION POOL's WIDTH BESIDE THE CLASS-SCAN POOL's, AND THE
/// ROOT ROUTE AS THE GUEST READER (`operations.md` §2.4 row 8; the ops
/// lanes' W4; the sweep's row (e)): §Reading history spells the pool's
/// width as §Link discovery reads spells the class-scan pool's —
/// **`MAX_CONCURRENT_RECONSTRUCTIONS` = 2** — where `history_busy`'s
/// condition is explained, the class-scan paragraph points at it from
/// "DISJOINT from the reconstruction pool", and the endpoint table's
/// `GET /` row says of the route what §The other endpoints says: the
/// embedded GUEST READER, one self-contained HTML file, `client` builds
/// only — no longer "the embedded authoring client". The width is
/// `history.rs`'s crate-private constant, pinned as its literal and held
/// by arithmetic the test CAN reach: `MIN_WORKERS` is one more than the
/// six pools' slots together, so the figures this document spells — the
/// two widths here, and the per-document pool's ceiling and its waiting
/// slots, `MAX_CONCURRENT_REGION_READS` and `MAX_REGION_READ_WAITERS`, read
/// off §Link discovery reads as the class-scan pool's width is — and the
/// write pool's figure (§The model), with the two media pools' constants,
/// must sum to it — a pool whose constant moved without its sentence fails
/// here.
#[test]
fn doc_states_the_reconstruction_pools_width_and_the_root_route_as_the_guest_reader() {
    let history = prose("\n## Reading history", &["\n## The commit stream"]);
    for fact in [
        "Reconstruction is bounded: at most **`MAX_CONCURRENT_RECONSTRUCTIONS` = 2** run concurrently",
        "the pool's width, a daemon constant this document names as it names the class-scan pool's (§Link discovery reads)",
        "`503 {\"error\": \"history_busy\"}`",
    ] {
        assert!(history.contains(fact), "§Reading history says {fact:?}");
    }
    assert!(
        !history.contains("at most **2** run"),
        "the bare figure gave way to the constant's spelling"
    );
    let scans = prose("\n### Link discovery reads", &["\n### Grants"]);
    for fact in [
        "**`MAX_CONCURRENT_CLASS_SCANS` = 2**",
        "The pool is DISJOINT from the reconstruction pool (§Reading history, whose width `MAX_CONCURRENT_RECONSTRUCTIONS` states beside `history_busy`)",
    ] {
        assert!(scans.contains(fact), "§Link discovery reads says {fact:?}");
    }
    let model = prose("\n## The model", &["\n### Endpoints"]);
    let reconstructions = figure_after(&history, "**`MAX_CONCURRENT_RECONSTRUCTIONS` = ");
    let class_scans = figure_after(&scans, "**`MAX_CONCURRENT_CLASS_SCANS` = ");
    let region_reads = figure_after(&scans, "**`MAX_CONCURRENT_REGION_READS` = ");
    let waiters = figure_after(&scans, "**`MAX_REGION_READ_WAITERS` = ");
    let writes = figure_after(&model, "`MAX_CONCURRENT_WRITES` (");
    assert_eq!(
        reconstructions
            + class_scans
            + region_reads
            + waiters
            + writes
            + skep_media::limits::MAX_CONCURRENT_FETCHES
            + skep_media::limits::MAX_CONCURRENT_UPLOADS
            + 1,
        skepd::MIN_WORKERS,
        "the six pools' widths as the document spells them — the per-document pool's by its ceiling and its waiting slots — plus one, are `MIN_WORKERS`"
    );
    let endpoints = prose("\n### Endpoints", &["\n### Transport"]);
    let row = endpoints
        .split("| `GET /` |")
        .nth(1)
        .and_then(|rest| rest.split(" | |").next())
        .expect("the endpoint table's root-route row");
    for fact in [
        "The embedded GUEST READER, one self-contained HTML file",
        "presents no token and acts on nothing",
        "only in `client` builds — the feature is default-off",
        "§The other endpoints",
    ] {
        assert!(row.contains(fact), "the root-route row says {fact:?}: {row}");
    }
    assert!(
        !row.contains("authoring client"),
        "the row no longer calls the route an authoring client: {row}"
    );
    let other = prose("\n## The other endpoints", &["\n## A first board, end to end"]);
    for fact in [
        "it is the GUEST READER",
        "the embedded reader, one self-contained HTML file embedded in the binary at build",
        "It presents no token on any route it dials",
        "acts on nothing",
    ] {
        assert!(other.contains(fact), "§The other endpoints says {fact:?}");
    }
}

/// Checks that §Link discovery reads states the region read's bounded wait.
///
/// The ruling (the home-index record's D3 (b)) keeps the refusal and adds a
/// bounded wait before it: a region read whose document holds its width
/// waits **`REGION_READ_WAIT` = 2 ms** at most, in one of
/// **`MAX_REGION_READ_WAITERS` = 2** waiting slots across the board,
/// admitted as one of its document's permits returns and refused when the
/// wait ends; the class pool and the ceiling refuse at once, and the wait is
/// a bound and never a queue. The paragraph says each, every read is no
/// longer said to be refused at once, and §HTTP status codes' `scan_busy`
/// row names the wait at the paragraph's figure. The figures are held to the
/// daemon's constants by the scan module's own unit test, which also pins
/// the wait's behaviour.
#[test]
fn doc_states_the_region_reads_bounded_wait() {
    let scans = prose("\n### Link discovery reads", &["\n### Grants"]);
    for fact in [
        "A class scan that finds every class-scan permit in use is refused AT ONCE",
        "and so is a region read whose document has room but whose board holds its six",
        "A region read whose document holds its two region reads WAITS first, holding its worker",
        "**`REGION_READ_WAIT` = 2 ms** at most",
        "in one of **`MAX_REGION_READ_WAITERS` = 2** waiting slots across the board",
        "admitted the moment one of its document's permits returns",
        "refused where its document still holds its width when the wait ends, or where it finds \
         every waiting slot taken",
        "The wait is a bound and never a queue",
        "no order is kept among the waiting reads",
        "refuses its reader after the wait as before it",
        "A refused read costs the parse and, at its document's width, at most the wait",
        "The five figures — the three counts, the wait and the waiting slots — are daemon \
         constants this document names",
    ] {
        assert!(scans.contains(fact), "§Link discovery reads says {fact:?}");
    }
    assert!(
        !scans.contains("is refused at once with"),
        "FINDING (#658): every read is no longer refused at once: {scans}"
    );
    let wait = figure_after(&scans, "**`REGION_READ_WAIT` = ");
    let statuses = prose("\n### HTTP status codes", &["\n### Determinism"]);
    let row = statuses
        .split("| 503 | `scan_busy` |")
        .nth(1)
        .and_then(|rest| rest.split(" | | ").next())
        .expect("the scan_busy row's cell");
    let named = format!(
        "whose document still holds its two region reads after a bounded wait ({wait} ms at most)"
    );
    assert!(row.contains(&named), "the row names the wait, {named:?}: {row}");
}

/// The natural the prose spells right after `marker` — a figure read out of
/// the document, as `doc_new_id_bound_is_the_codecs_own` reads the delegate
/// row's bound.
fn figure_after(text: &str, marker: &str) -> usize {
    let at = text.find(marker).unwrap_or_else(|| panic!("wire.md no longer carries {marker:?}"));
    let rest = &text[at + marker.len()..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().unwrap_or_else(|_| panic!("no figure follows {marker:?}: {rest:.40}"))
}

/// THE `durability` FACE AND THE FEED's COMPACTION AT THE CHECKPOINT (P10:
/// no face names a retry that cannot succeed; jw-R3, jw-R4): §Rejections'
/// `retry` row says what a retry-class answer at a full volume means — the
/// operation did nothing, no reissue succeeds until the operator frees the
/// room, the operator stream names it, the person's act is to tell the
/// operator — and §Rejection codes' `durability` entry says the same of the
/// code, the disposition staying `retry`; the old "durability hiccup" is
/// gone from both. §The change feed says the feed is kept whole from
/// genesis — never compacted to the journal's reclaim floor, `/changes`
/// from 0 at any age, `410` on `/changes` for a hole alone and never for a
/// position the journal reclaimed — with the stop a rewrite failed past
/// its rename carries. The daemon's words are pinned in `changes.rs` and
/// `feed_retained.rs`; this pins that the contract says so.
#[test]
fn doc_states_the_durability_faces_words_and_the_feed_kept_whole() {
    let rejections = prose("\n## Rejections", &["\n### Rejection codes"]);
    for fact in [
        "`\"retry\"` — the operation did nothing",
        "where the cause is the volume's room",
        "NO reissue succeeds until the operator frees it",
        "the operator stream names it",
        "never to reissue blindly",
    ] {
        assert!(rejections.contains(fact), "§Rejections says {fact:?}");
    }
    assert!(!rejections.contains("hiccup"), "the retry row names no hiccup");
    let codes = prose("\n### Rejection codes", &["\n### The version-chain refusals"]);
    for fact in [
        "`durability` (the",
        "the operation did nothing — retry",
        "FULL VOLUME",
        "no retry succeeds before it",
    ] {
        assert!(codes.contains(fact), "§Rejection codes says {fact:?}");
    }
    assert!(!codes.contains("hiccup"));
    let feed = prose("\n## The change feed", &["\n## The other endpoints"]);
    for fact in [
        "The feed is kept whole from genesis",
        "never compacted to the journal's reclaim floor",
        "`GET /changes?since=0` reads a board's whole record of events from its first commit",
        "never for a position the journal has reclaimed but the feed still holds",
        "The five are KEPT WHOLE from genesis",
        "STOPS that file for the uptime",
        "fails no write",
    ] {
        assert!(feed.contains(fact), "§The change feed says {fact:?}");
    }
    assert!(!feed.contains("COMPACTED to the journal's reclaim floor"), "no feed file compacts");
}

/// THE UPLOAD SETTING, THE DEFAULT LIMIT, THE CREATION's GATE, THE REBUILD
/// WINDOW, THE PRUNER's RENAME-ASIDE AND COMPACTION, AND THE OPERATOR's
/// TOOLS (the owner's ruling on the default limit; sweep 6's rows s6-lam-a,
/// b, c, e, f, s6-op-a, b, d, g, h; the register M-I5 (b), (c), (d), (e),
/// (f), M-I6 (b), (d), (f), (h), M-I7 (e)): §Media states the setting with
/// its flag, its variable and its `/health` echo; the default per-account
/// limit's figure, its floor, its echo as `per_account` and the record that
/// overrides it; the creation's two new refusals, `floor` on no length and
/// `standing` with its face; the rebuild window's retry-class answer with
/// its code; the past-cap classification; the pruner's rename aside under the
/// arm and the compaction on its trigger; the empty resume; the H1 timing
/// rows and the K2 residue by name; the INTERIM pins each; and a subsection
/// of its own for the two tools, naming what neither writes. §The other
/// endpoints carries the `media` object beside `auth`; §Credential refusals
/// the fourth token and its class. The daemon's answers are pinned in
/// `blob_routes.rs`, `media.rs`, `pruner.rs`, `hazard.rs` and `tools.rs`;
/// this pins that the contract says so, and that the vector set names the
/// same pins. The default limit's two words — one eighth of the volume's
/// capacity, never below 256 MiB — are pinned at EACH of §Media's two sites,
/// the paragraph and the pins list, as two slices, so an edit to either
/// alone fails here.
#[test]
fn doc_states_the_upload_setting_the_default_limit_the_creations_gate_and_the_tools() {
    let media = prose("\n### Media — the reference cell and its door", &["\n### Links (writes)"]);
    for fact in [
        "**The upload setting.**",
        "`--no-uploads`",
        "SKEPD_UPLOADS=false",
        "`media.uploads`",
        "`uploads_closed`",
        "`per_account`",
        "the venue total unset",
        "| 403 | `upload_refused` | `detail` `unauthenticated`, `claim_first`, `node_tier` or `uploads_closed`",
        "`scope` `floor` AT THE CREATION",
        "`scope` `standing`",
        "the end of one of them",
        "`credential_refused`, `detail` `index_rebuilding` |",
        "| retry |",
        "the cap bounds the parse and never the classification",
        "RENAMED ASIDE",
        "the aside UNLINKED AFTER, under no arm",
        "(d) THE COMPACTION",
        "an EMPTY resume",
        "in the same time",
        "named residue",
        "the standing-uploads bound, 8",
        "the compaction trigger, four times",
        "1,024 lines",
        "**The operator's tools.**",
        "`skepd inventory --data-dir <dir> [--no-rehash]`",
        "`skepd pull --data-dir <dir> [--hash <hex>] <file>`",
        "writes nothing under `blobs/`",
        "no lease, no record, no journal entry",
        "What this build does NOT carry, by name",
    ] {
        assert!(media.contains(fact), "§Media says {fact:?}");
    }
    // THE DEFAULT LIMIT AT BOTH SITES: the paragraph that rules it (the
    // owner's ruling, in capitals there) and the pins list that carries it
    // — each slice must hold both words, so neither site can lose them
    // while the other still says them.
    let paragraph =
        prose("UNTIL A RECORD IS INSTALLED THE DAEMON's", &["\n**The upload setting.**"]);
    let pins = prose("**INTERIM PINS**", &["\nThe set's second file"]);
    for (site, text) in [("the ruling paragraph", &paragraph), ("the pins list", &pins)] {
        for words in ["one eighth of the volume's capacity", "never below 256 MiB"] {
            assert!(
                text.to_lowercase().contains(&words.to_lowercase()),
                "§Media's {site} says {words:?}: {text}"
            );
        }
    }
    assert!(
        pins.contains("the default per-account limit, one eighth of the volume's capacity read once at start and never below 256 MiB"),
        "the pins list's row, whole: {pins}"
    );
    // The upload permit pool is CARRIED (M-I5 (f)), so the list of what the
    // build does not carry no longer names it.
    let not_carried = media
        .split("What this build does NOT carry, by name")
        .nth(1)
        .and_then(|rest| rest.split("\n\n").next())
        .expect("the paragraph of what is not carried");
    assert!(
        !not_carried.contains("permit pool"),
        "the upload permit pool is carried, and the list of what is not names it still: {not_carried}"
    );
    let health = prose("\n## The other endpoints", &["\n## A first board, end to end"]);
    for fact in [
        "`media`",
        "`media.uploads`",
        "\"media\":{\"uploads\":true}",
        "`writes`",
        "`writes.halted`",
        "\"writes\":{\"halted\":false}",
    ] {
        assert!(health.contains(fact), "§The other endpoints says {fact:?}");
    }
    let refusals = prose("\n### Credential refusals", &["\n## Operations"]);
    assert!(refusals.contains("**The media door's four tokens**"), "§Credential refusals names the four");
    assert!(refusals.contains("`index_rebuilding`"), "§Credential refusals names the rebuild window's token");
    let codes = prose("\n### Rejection codes", &["\n### The version-chain refusals"]);
    assert!(codes.contains("four tokens"), "§Rejection codes counts four");
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/it/fixtures/media/uploads.json"),
        )
        .expect("the vector set exists"),
    )
    .expect("the vector set is JSON");
    assert_eq!(fixture["pins"]["max_standing_uploads"].as_u64(), Some(8));
    assert_eq!(fixture["pins"]["default_limit_share"].as_u64(), Some(8));
    assert_eq!(fixture["pins"]["default_limit_floor_bytes"].as_u64(), Some(256 * 1024 * 1024));
    assert_eq!(fixture["pins"]["compaction_trigger"].as_u64(), Some(4));
    assert_eq!(fixture["pins"]["compaction_min_lines"].as_u64(), Some(1024));
    assert_eq!(fixture["pins"]["uploads_closed_detail"].as_str(), Some("uploads_closed"));
    let cells: Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/it/fixtures/media/cells.json"),
        )
        .expect("the cell vector set exists"),
    )
    .expect("JSON");
    let past = cells["vectors"].as_array().unwrap().iter().find(|v| v["name"] == "past_the_cap").expect("the vector");
    assert_eq!(past["names_kind"].as_bool(), Some(true), "a past-cap body opening as the kind names it");
}

/// THE CELL INDEX, THE READINESS REFUSAL AND THE PRUNER (the register M-I5 (b),
/// (f), M-I6 (a), (b); the rulings ms5-R and ms5-T4): §Media states the index —
/// what it holds, the entry at commit and the walk at open, the composition
/// clause, the halt mark — the readiness token and its exactly three readers,
/// the pruner's pass with its arm, its grain, its halts, its cadence and its
/// exit — each step going on past an entry it cannot remove, its failures
/// counted — the deposit read's two figures, the own scope's two terms, the
/// binding's index-first order, the replace's aside and its deferred unlink;
/// and the status table carries the token. The daemon's answers are pinned in
/// `media.rs`, `pruner.rs`, `blob_routes.rs` and `hazard.rs`; this pins that
/// the contract says so.
#[test]
fn doc_states_the_cell_index_the_readiness_refusal_and_the_pruner() {
    let media = prose("\n### Media — the reference cell and its door", &["\n### Links (writes)"]);
    for fact in [
        "**The cell index.**",
        "ONE DERIVED INDEX SERVES THE BASE AND THE PRUNER's",
        "ENTERED AT EVERY COMMIT THAT MINTS A",
        "REBUILT WHOLE AT EVERY OPEN from the world replayed",
        "never from the retained journal alone",
        "THE COMPOSITION",
        "never installed in its place",
        "THE HALT MARK",
        "**The readiness refusal**",
        "READY FOR THE INDEX's THREE READERS AND FOR NOTHING ELSE",
        "`index_rebuilding`",
        "and the pruner's pass does",
        "**The pruner.**",
        "(a) THE EXPIRED",
        "(b) THE HALTS",
        "(c) THE UNREFERENCED FILES",
        "UNDER THE CREDENTIAL LOCK's EXCLUSIVE ARM, ONE FILE PER",
        "`blake3` alone",
        "one hour",
        "THE BINDING READS THE CELL INDEX FIRST",
        "is a REFERENCE, kept by no",
        "the principal's BASE plus its PENDING BYTES",
        "LINKED ASIDE",
        "`.retired-<hex>-<n>`",
        "THE ASIDE IS UNLINKED AFTER THE",
        "the time an answer takes is part of",
        "the readiness token, `index_rebuilding`, 503, retry-class",
        "the pruner's cadence, one hour between passes",
        "RENAMED ASIDE",
        "(d) THE COMPACTION",
        "EACH STEP GOES ON PAST AN ENTRY IT CANNOT REMOVE and leaves it for the next pass",
        "the pass's line names the step, its first failure in the store's words and how many of \
         the step's acts failed (`— the first of {n} failures`)",
        "a listing that fails ends its step",
    ] {
        assert!(media.contains(fact), "§Media says {fact:?}");
    }
    let statuses = prose("\n### HTTP status codes", &["\n### Determinism"]);
    assert!(
        statuses.contains("| 503 | `index_rebuilding` |"),
        "§HTTP status codes carries the token at 503"
    );
}

/// D23 — `/health`'s `writes` MEMBER (wire.md §The other endpoints; op-D10
/// (a)), its `conditions` MEMBER (the link-sets design §5.7, W8 (5); lane
/// S4) and the object's ORDER RULE: the section names the two members, the
/// one boolean `halted`, what the boolean means, the array's object and
/// when it clears, and the count of members a consumer is written to; its
/// example carries `"conditions":[]` and `"writes":{"halted":false}` in
/// their places; the example's top-level keys stand in the order the
/// daemon's key-sorting `obj` writes them — alphabetical, `conditions`
/// after `chain_head`, `writes` after `ok` — and a live daemon's `/health`
/// answers the same keys in the same order, `writes` false and
/// `conditions` empty on a healthy board.
#[test]
fn doc_states_the_writes_member_and_the_health_examples_keys_are_the_daemons_in_its_order() {
    let health = prose("\n## The other endpoints", &["\n## A first board, end to end"]);
    for fact in [
        "`writes` is an object with one boolean, `halted`",
        "`writes.halted` is `false` on a healthy board",
        "`conditions` is an array, EMPTY on a healthy board, else one object per system producer whose last shot was refused",
        "the published head's writer, the time writer and the registry seed",
        "Each object carries `producer` (`head`, `time` or `registry`), `act`",
        "`position` (the committed position the refused shot was to stand above",
        "`attempts` (the attempts refused since the producer last landed",
        "clears when that producer NEXT LANDS",
        "A refusal is not a halt: `writes.halted` stands beside it as before",
        r#"`{"act":"insert","attempts":3,"code":"durability","detail":"the volume is full","position":42,"producer":"head"}`"#,
        "the operator stream's standing line carries the same fact as its clause",
        "these eight members",
        "must not treat a ninth as a violation",
    ] {
        assert!(health.contains(fact), "§The other endpoints says {fact:?}");
    }
    // The example off the document's own lines: `prose` collapses the
    // section's whitespace, and the example is the one line opening on
    // the `auth` member.
    let text = wire_md();
    let section = text.find("\n## The other endpoints").expect("the section");
    let example = text[section..]
        .lines()
        .find(|line| line.starts_with("{\"auth\":"))
        .expect("the section's /health example");
    let keys = top_level_keys(example);
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "the example's keys stand in obj's alphabetical order");
    assert_eq!(
        keys,
        ["auth", "chain_head", "conditions", "head_time", "log_position", "media", "ok", "writes"],
        "the eight members, each once"
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = crate::common::spawn_unclaimed(dir.path());
    let (st, body) = crate::common::get(sd.port(), "/health");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let served = std::str::from_utf8(&body).expect("the answer is UTF-8");
    assert_eq!(top_level_keys(served), keys, "the daemon's /health carries the example's keys in its order");
    let v: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(v["writes"], serde_json::json!({"halted": false}), "a healthy board: {v}");
    assert_eq!(v["conditions"], serde_json::json!([]), "a healthy board: no condition: {v}");
    sd.shutdown();
}

/// THE FOUR STATEMENTS OF LANE S4 (the link-sets design §5.7, W8 (1), W8
/// (2), W7 (3)): §Transport states that a frame the daemon has received is
/// applied whatever became of its connection, its answer not taken dropped;
/// §Correlation and idempotency states that a re-ask under a pending
/// frame's `id` waits at the serialization lock and is answered the
/// acknowledgment from the memo, a refusal judged afresh, the `500` the one
/// gap; §The publish shot and head-float states the in-lock reads' budget
/// — the four terms, the re-window's counting the pieces its lists place,
/// the constant, the refusal ahead of the permit and the locks, its table
/// row — and the position-fenced read, the ordinals'
/// pin across commits and the frontier's galloping probe; and §Rejection
/// codes carries the budget's token with the constant. The daemon's
/// answers are pinned in `publish.rs`; this pins that the contract says so.
#[test]
fn doc_states_the_received_frame_the_pending_frame_the_reads_budget_and_the_fenced_read() {
    let transport = prose("\n### Transport", &["\n### Identity"]);
    for fact in [
        "A FRAME THE DAEMON HAS RECEIVED IS APPLIED whatever became of its connection",
        "the request is read whole, then routed, and nothing between the two looks at the socket",
        "the answer not taken is dropped as a stalled reader's is",
        "never reads the loss as the frame dropped",
    ] {
        assert!(transport.contains(fact), "§Transport says {fact:?}");
    }
    let memo = prose("\n### Correlation and idempotency", &["\n### HTTP status codes"]);
    for fact in [
        "THE `id` ANSWERS A PENDING FRAME",
        "WAITS at that lock for the first frame's turn",
        "an acknowledgment is answered from the memo, executing nothing, never a second execution queued behind the first",
        "a refusal is not memoized, so the re-ask is judged afresh",
        "a client reads the board before any re-send after a `500`",
    ] {
        assert!(memo.contains(fact), "§Correlation and idempotency says {fact:?}");
    }
    let shot = prose("\n### The publish shot and head-float", &["\n### Credential refusals"]);
    for fact in [
        "**The in-lock reads' budget**".to_string(),
        "PRICED BEFORE THE LOCK IS TAKEN".to_string(),
        "the caller's link-holding home count × (`links` entries + `originals` entries + `read_with` entries + `supersede` entries), plus, per draft the commit re-windows".to_string(),
        "its content run count and the pieces its lists place, summed".to_string(),
        "a place that cuts a run of the draft adds nothing".to_string(),
        "plus one per re-inserted run, against".to_string(),
        "a run no list places costs the re-window nothing".to_string(),
        format!("`MAX_PUBLICATION_READS` = {} (16 × `MAX_SLOT_SPANS`)", skep_links::MAX_PUBLICATION_READS),
        "ahead of the write permit, both locks and every other refusal of a publication's".to_string(),
        "the budget is conservative by design".to_string(),
        "| `publication_over_budget` | permanent | — |".to_string(),
        "**The position-fenced read**".to_string(),
        "RISE WITH COMMIT POSITION".to_string(),
        "ONE CONTIGUOUS RUN of the home's ordinals".to_string(),
        "`read_link` past the frontier answers `link_value` with a null `link` and a null `at`".to_string(),
        "a galloping probe".to_string(),
        "the in-lock reads' price stands ahead of the gate".to_string(),
    ] {
        assert!(shot.contains(&fact), "§The publish shot and head-float says {fact:?}");
    }
    assert_eq!(skep_links::MAX_PUBLICATION_READS, 16 * skep_links::MAX_SLOT_SPANS, "the constant as the document derives it");
    let codes = prose("\n### Rejection codes", &["\n### The version-chain refusals"]);
    assert!(codes.contains("`publication_over_budget` (the reads the one commit makes"), "§Rejection codes carries the token");
    assert!(
        codes.contains(&format!("`MAX_PUBLICATION_READS` = {}", skep_links::MAX_PUBLICATION_READS)),
        "§Rejection codes states the constant"
    );
}

/// The member names of one JSON object's text at its top level, in the
/// order written — read off the bytes, since a parsed map forgets the
/// order: a string met at depth one where a member name is due.
fn top_level_keys(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut keys = Vec::new();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut string_start = 0;
    let mut name_due = false;
    for (i, &b) in bytes.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
                if depth == 1 && name_due {
                    keys.push(text[string_start..i].to_string());
                    name_due = false;
                }
            }
            continue;
        }
        match b {
            b'{' => {
                depth += 1;
                name_due = depth == 1;
            }
            b'[' => depth += 1,
            b'}' | b']' => depth -= 1,
            b',' if depth == 1 => name_due = true,
            b'"' => {
                in_string = true;
                string_start = i + 1;
            }
            _ => {}
        }
    }
    keys
}

/// Every `op_at` example is the strict `{"at", "frame"}` envelope around a
/// canonical READ frame — the doc's history examples parse through the same
/// codec the daemon uses.
#[test]
fn doc_op_at_examples_are_canonical() {
    let codec = JsonCodec;
    let mut count = 0;
    for (kind, name, body) in blocks() {
        if kind != "op_at" {
            continue;
        }
        let v: Value = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("doc op_at '{name}' is not JSON: {e}"));
        let obj = v.as_object().unwrap_or_else(|| panic!("op_at '{name}' must be an object"));
        assert_eq!(obj.len(), 2, "op_at '{name}' carries exactly 'at' and 'frame': {v}");
        assert!(obj["at"].is_u64(), "op_at '{name}': 'at' is a JSON number");
        let frame = obj.get("frame").expect("op_at envelope carries 'frame'");
        let frame_bytes = serde_json::to_vec(frame).expect("frame re-serializes");
        let req = codec
            .parse(&frame_bytes)
            .unwrap_or_else(|e| panic!("doc op_at '{name}' frame does not parse: {:?}", e.detail));
        let canonical: Value =
            serde_json::from_slice(&codec.marshal_request(&req)).expect("canonical is JSON");
        assert_eq!(&canonical, frame, "op_at '{name}' frame is not in canonical form");
        count += 1;
    }
    assert!(count > 0, "wire.md documents no op_at example");
}

/// Every transport-error example equals its fixture — the bodies the
/// history endpoints refuse with. The server side of the same shapes is
/// asserted end-to-end in tests/it/history.rs.
#[test]
fn doc_error_examples_match_their_fixtures() {
    let mut seen: Vec<String> = Vec::new();
    for (kind, name, body) in blocks() {
        if kind != "error" {
            continue;
        }
        let doc: Value = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("doc error '{name}' is not JSON: {e}"));
        let expect = match name.as_str() {
            "write_at_history" => serde_json::json!({"error": "write_at_history"}),
            "beyond_head" => serde_json::json!({"error": "beyond_head", "head": 12}),
            "not_a_position" => serde_json::json!({"error": "not_a_position", "nearest": 7}),
            "history_reclaimed" => {
                serde_json::json!({"error": "history_reclaimed", "floor": 2048})
            }
            other => panic!("doc marker 'error {other}' has no fixture in wire_doc.rs"),
        };
        assert_eq!(doc, expect, "doc error '{name}' drifted from its fixture");
        seen.push(name);
    }
    for required in ["write_at_history", "beyond_head", "not_a_position", "history_reclaimed"] {
        assert!(
            seen.iter().any(|n| n == required),
            "transport error '{required}' has no documented example"
        );
    }
}

/// The commit-stream example is asserted structurally, not byte-for-byte:
/// the position in the doc is illustrative, the framing is the contract —
/// an `event: commit` line, then a `data:` line whose payload is exactly
/// `{"log_position": <number>}`, nothing else. (The daemon's emitter is a
/// single format string over the same framing.)
#[test]
fn doc_sse_examples_have_the_commit_framing() {
    let mut count = 0;
    for (kind, name, body) in blocks() {
        if kind != "sse" {
            continue;
        }
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "sse '{name}' is one event: event line + data line");
        assert_eq!(lines[0], "event: commit", "sse '{name}' event name");
        let data = lines[1]
            .strip_prefix("data: ")
            .unwrap_or_else(|| panic!("sse '{name}' lacks a 'data: ' line"));
        let v: Value = serde_json::from_str(data)
            .unwrap_or_else(|e| panic!("sse '{name}' data is not JSON: {e}"));
        let obj = v.as_object().unwrap_or_else(|| panic!("sse '{name}' data is an object"));
        assert_eq!(obj.len(), 1, "the v1 payload is the position alone: {data}");
        assert!(obj["log_position"].is_u64(), "sse '{name}': log_position is a number");
        count += 1;
    }
    assert!(count > 0, "wire.md documents no commit-stream event example");
}

/// Every response example equals the marshal of its fixture, and every
/// required shape is documented.
#[test]
fn doc_response_examples_match_the_codec() {
    let codec = JsonCodec;
    let mut names: Vec<String> = Vec::new();
    for (kind, name, body) in blocks() {
        if kind != "response" {
            continue;
        }
        let doc: Value = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("doc response '{name}' is not JSON: {e}"));
        let marshaled: Value =
            serde_json::from_slice(&codec.marshal(&fixture(&name))).expect("marshal emits JSON");
        assert_eq!(marshaled, doc, "doc response '{name}' drifted from the codec");
        names.push(name);
    }
    for required in REQUIRED_SHAPES {
        assert!(
            names.iter().any(|n| n == required),
            "response shape '{required}' has no documented example"
        );
    }
    // The other hand transcription of this list is the fuzz oracle's, which
    // judges what the DAEMON answers where this judges what wire.md
    // documents. A shape in one and not the other is a drift — and adding
    // one to the oracle is exactly what an author does to quiet it, after
    // which the shape ships undocumented and both lists pass. (A new
    // `Response` VARIANT is caught by the compiler at `j_response`, not by
    // either list; this catches a shape that reaches the wire without
    // reaching both.)
    let mut oracle: Vec<&str> = skepd::fuzz_support::RESP_SHAPES.to_vec();
    let mut required: Vec<&str> = REQUIRED_SHAPES.to_vec();
    oracle.sort();
    required.sort();
    assert_eq!(oracle, required, "the two transcriptions of wire.md's response shapes disagree");
}

/// Checks that §Sessions spells the nonce's lifetime and the store's cap.
///
/// A nonce lives `CHALLENGE_TTL_MS` — `ttl_ms` on the wire, a byte pin of
/// it — and at most `MAX_LIVE_NONCES` are live at once. Both are
/// `skep-core`'s `pub` constants, read here, so a figure that moves fails
/// here rather than leaving the document naming the old one.
#[test]
fn doc_spells_the_nonces_lifetime_and_the_stores_cap_through_their_constants() {
    use skep_core::auth::session::CHALLENGE_TTL_MS;
    use skep_core::auth::MAX_LIVE_NONCES;

    let sessions = prose("\n### Sessions", &["\n### ", "\n## "]);
    for fact in [
        format!("\"ttl_ms\":{CHALLENGE_TTL_MS}"),
        format!(
            "It lives {} seconds (`ttl_ms` is a byte pin of that constant)",
            CHALLENGE_TTL_MS / 1000
        ),
        format!(
            "At most {MAX_LIVE_NONCES} nonces are live at once; past the cap the oldest is evicted"
        ),
    ] {
        assert!(sessions.contains(&fact), "§Sessions says {fact:?}: {sessions}");
    }
}
