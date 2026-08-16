//! `skep/docs/wire.md` is tested, not decorative: every fenced JSON example
//! annotated `<!-- wire: request <op> -->` must parse and be canonical, and
//! every `<!-- wire: response <name> -->` block must equal the marshal of
//! the corresponding fixture here. Coverage is asserted both ways — an op
//! or response shape missing from the doc fails, and a doc marker without a
//! fixture fails.

use std::path::Path;

use serde_json::Value;
use skep_address::{validate, Address, Nat, Span, SpanSet, Tumbler};
use skep_arrangement::{Run, VPos};
use skep_content::Val;
use skep_discovery::{OrphanReport, SupClaim, Window};
use skep_febe::{
    Codec, Disposition, FaultSite, OpKind, ParseError, RejectCode, Rejection, Response,
};
use skep_kernel::Seq;
use skep_links::{Endset, Invalid, Link};
use skep_retrieval::{CompareReport, CorrPair, Deletions, Delivery, DeliveryItem, SpecFault};
use skepd::JsonCodec;

fn wire_md() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/wire.md");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
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

/// Every request example parses, is canonical (re-marshal equals the doc
/// value), is tagged with the marker's own op name — and all 38 ops appear.
#[test]
fn doc_request_examples_are_canonical_and_complete() {
    let codec = JsonCodec;
    let mut seen: Vec<String> = Vec::new();
    for (kind, name, body) in blocks() {
        if kind != "request" {
            continue;
        }
        let req = codec.parse(body.as_bytes()).unwrap_or_else(|e| {
            panic!("doc request '{name}' does not parse: {:?}", e.detail)
        });
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

fn fixture(name: &str) -> Response {
    match name {
        "ack" => Response::Ack { at: Seq(7) },
        "ack_addr" => Response::AckAddr { addr: a(&[1, 0, 1, 0, 1, 0, 1, 1]), at: Seq(7) },
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
        "span_set" => Response::SpanSet {
            set: [ispan()].into_iter().collect::<SpanSet>(),
            as_of: Seq(9),
        },
        "addrs" => Response::Addrs { addrs: vec![link1()], as_of: Seq(9) },
        "maybe_addr" => Response::MaybeAddr { addr: Some(a(&[1, 0, 2])), as_of: Seq(9) },
        "maybe_addr_none" => Response::MaybeAddr { addr: None, as_of: Seq(9) },
        "count" => Response::Count { n: 2, as_of: Seq(9) },
        "page" => Response::Page {
            window: Window { batch: vec![link1()], next: Some(link1()), exhausted: true },
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
        "bool" => Response::Bool { val: true, as_of: Seq(9) },
        "link_value" => Response::LinkValue {
            link: Some(
                Link::new([
                    Endset::from_spans([ispan()]),
                    Endset::from_spans([sp(&[1, 0, 1, 0, 2, 0, 1, 1], &[0, 0, 0, 0, 0, 0, 0, 6])]),
                    Endset::from_spans([sp(&[1, 0, 1, 0, 3, 0, 1, 1], &[0, 0, 0, 0, 0, 0, 0, 1])]),
                ])
                .expect("arity-3 link fixture"),
            ),
            as_of: Seq(9),
        },
        "link_value_null" => Response::LinkValue { link: None, as_of: Seq(9) },
        "follow" => Response::Follow {
            result: Ok([ispan()].into_iter().collect::<SpanSet>()),
            as_of: Seq(9),
        },
        "follow_invalid" => Response::Follow { result: Err(Invalid), as_of: Seq(9) },
        "deletions" => Response::Deletions {
            rep: Deletions { a_with_b: vec![a(&[1, 0, 1, 0, 1, 0, 1, 1])], b_with_a: vec![] },
            as_of: Seq(9),
        },
        "compare" => Response::Compare {
            rep: CompareReport(vec![CorrPair {
                d1: a(&[1, 0, 1, 0, 1]),
                u1: VPos { subspace: n(1), ordinal: n(1) },
                d2: a(&[1, 0, 1, 0, 2]),
                u2: VPos { subspace: n(1), ordinal: n(3) },
                width: n(5),
            }]),
            as_of: Seq(9),
        },
        "orphans" => Response::Orphans {
            report: OrphanReport { orphaned: vec![link1()] },
            as_of: Seq(9),
        },
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
        "rejected" => Response::Rejected(Rejection {
            op: OpKind::Insert,
            code: RejectCode::Unauthenticated,
            disposition: Disposition::Permanent,
            site: None,
            detail: None,
        }),
        "rejected_site" => Response::Rejected(Rejection {
            op: OpKind::RetrieveV,
            code: RejectCode::MalformedSpan,
            disposition: Disposition::Permanent,
            site: Some(FaultSite {
                index: Some(1),
                fault: Some(SpecFault::NotOrdinalLevel),
                ..FaultSite::default()
            }),
            detail: None,
        }),
        "rejected_unparseable" => {
            JsonCodec.unparseable(ParseError { detail: Some("unknown op 'frobnicate'".into()) })
        }
        other => panic!("doc marker 'response {other}' has no fixture in wire_doc.rs"),
    }
}

/// The 19 response shapes every client must decode; each must appear as a
/// doc marker (variant markers like `follow_invalid` are extra coverage).
const REQUIRED_SHAPES: [&str; 19] = [
    "ack",
    "ack_addr",
    "ack_edit",
    "delivery",
    "span_set",
    "addrs",
    "maybe_addr",
    "count",
    "page",
    "endsets",
    "runs",
    "bool",
    "link_value",
    "follow",
    "deletions",
    "compare",
    "orphans",
    "claims",
    "rejected",
];

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
        let marshaled: Value = serde_json::from_slice(&codec.marshal(&fixture(&name)))
            .expect("marshal emits JSON");
        assert_eq!(marshaled, doc, "doc response '{name}' drifted from the codec");
        names.push(name);
    }
    for required in REQUIRED_SHAPES {
        assert!(
            names.iter().any(|n| n == required),
            "response shape '{required}' has no documented example"
        );
    }
}
