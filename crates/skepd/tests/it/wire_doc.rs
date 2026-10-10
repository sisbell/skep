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
use skep_discovery::{OrphanReport, SupClaim, Window};
use skep_febe::{
    BirthVersion, Codec, Disposition, EditionClaim, FaultSite, IItem, OpKind, ParseError,
    RejectCode, Rejection, Response, ShotTerms, UniversalGrant,
};
use skep_kernel::Seq;
use skep_links::{Endset, Invalid, Link};
use skep_namespace::PrincipalId;
use skep_retrieval::{CompareReport, CorrPair, Deletions, Delivery, DeliveryItem, SpanFault};
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

const OP_NAMES: [&str; 45] = [
    "create_new_document",
    "delegate",
    "register_node",
    "fork",
    "next_account_prefix",
    "principal_prefix",
    "effective_owner",
    "doc_metadata",
    "insert",
    "delete",
    "copy",
    "rearrange",
    "version",
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
    "edition_claims",
    "universal_grants",
];

/// Every request example parses, is canonical (re-marshal equals the doc
/// value), is tagged with the marker's own op name — and all 45 ops appear.
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
        // The withheld arm (v7.4, lane 3.3, §4): a readable per-byte run, then
        // a masked run at its own position — one item, never coalesced.
        "delivery_withheld" => Response::Delivery {
            items: Delivery(vec![
                DeliveryItem::Content(Val::new(vec![b'a'])),
                DeliveryItem::Withheld { origin: a(&[1, 0, 1, 0, 2]), width: n(3) },
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
                d2: a(&[1, 0, 1, 0, 2]),
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
        // (c′)).
        "doc_metadata" => Response::DocMetadata {
            doc: a(&[1, 0, 1, 0, 1]),
            published: true,
            owner: Some(a(&[1, 0, 1])),
            birth: Some(BirthVersion { addr: a(&[1, 0, 1, 0, 1, 1]), extent: n(5) }),
            terms: Some(ShotTerms { placed: n(5), base_extent: Some(n(3)) }),
            as_of: Seq(9),
        },
        // A private draft with no chain member yet: birth/birth_extent null,
        // and no shot terms either.
        "doc_metadata_unborn" => Response::DocMetadata {
            doc: a(&[1, 0, 1, 0, 2]),
            published: false,
            owner: Some(a(&[1, 0, 1])),
            birth: None,
            terms: None,
            as_of: Seq(9),
        },
        "edition_claims" => Response::EditionClaims {
            claims: vec![EditionClaim {
                claim: a(&[1, 0, 1, 0, 5, 0, 2, 1]),
                home: a(&[1, 0, 1, 0, 5]),
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
                prefix: a(&[1, 0, 1, 0, 2]),
                issuers: BTreeSet::from([a(&[1, 0, 1])]),
            }],
            as_of: Seq(9),
        },
        "universal_grants_empty" => Response::UniversalGrants { rows: Vec::new(), as_of: Seq(9) },
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
        "rejected_unparseable" => {
            JsonCodec.unparseable(ParseError { detail: Some("unknown op 'frobnicate'".into()) })
        }
        other => panic!("doc marker 'response {other}' has no fixture in wire_doc.rs"),
    }
}

/// The 25 response shapes every client must decode; each must appear as a
/// doc marker (variant markers like `follow_invalid` are extra coverage).
const REQUIRED_SHAPES: [&str; 25] = [
    "ack",
    "ack_addr",
    "ack_edit",
    "delivery",
    "i_delivery",
    "frontier",
    "span_set",
    "addrs",
    "maybe_addr",
    "effective_owner",
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
    "doc_metadata",
    "edition_claims",
    "universal_grants",
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

/// THE TEN CELLS AND THE STORED SLOT ROW (SO-I6 (a), (h); SO-I7 (f)):
/// §Credential refusals names the ten kinds the check runs on and states
/// the frame's rows once — the stored slot row under `0x03`, its EMPTY
/// spelling, the address-list row, the pair's row, the EMPTY body — and
/// that the armed set gained no cause; each op's paragraph carries its
/// `attest` statement (the mints' EMPTY body over the parent account,
/// `nullify`'s and `assert_sup`'s class constants, `edit_link`'s pair and
/// fifth row); and §The change feed states the third absence. The daemon's
/// bytes are pinned in `signed_ops.rs` and `feed_class.rs`; this pins that
/// the contract says so.
#[test]
fn doc_states_the_ten_cells_and_the_stored_slot_row() {
    let refusals = prose("\n### Credential refusals", &["\n## Operations"]);
    for fact in [
        "publish-class write of the TEN KINDS that have an entry frame",
        "`delete`, `copy` and `rearrange` have no frame",
        "**The entry frame's rows**",
        "THE PAIR'S ROW, its two homes as an address-list row of two: `0x01 ‖ be64(2) ‖ be32(len) ‖ d_s ‖ be32(len) ‖ d_a`",
        "THE SLOT ROW, a link slot AS THE STORE HOLDS IT",
        "`0x03 ‖ be64(n) ‖ per span: be32(len) ‖ start ‖ be32(len) ‖ width`",
        "the EMPTY slot has one spelling, `0x03 ‖ be64(0)`",
        "THE ADDRESS-LIST ROW, `0x01 ‖ be64(n) ‖ each address be32(len) ‖ dotted decimal` — never a link slot's row",
        "THE EMPTY BODY, the three mints': the member PRESENT and empty, `be32(0)` in the frame",
        "the widening to the ten kinds added no cause",
        "Every publish-class write of the ten kinds on a claimed board is judged",
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
        "| `not_owner`, `site.addr` the draft | `publish` | permanent |",
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
/// twelve rows with their addresses and the "Deposits" column, the deposit
/// class's four members, the two bodies' canonical forms with the spec's
/// examples IN CANONICAL FORM and the spaced spelling as what the parse
/// refuses, the cap, the vector set by path, the record grade's reach — a
/// deposit's two positions — the registry sequence's order and its refusal
/// table under the one code, the audit-view refusal's three members with
/// the endpoint outside, the seeding check's three arms, the interim pins
/// and what the build does not carry; §The claim ceremony and credentials
/// points at the four members, §Credential refusals lists the registry's
/// three classes and points at the family, §Rejection codes points at the
/// code. The daemon's answers are pinned end to end in `registry.rs` and
/// `nullify_class.rs`; this pins that the contract says so, and that the
/// vector set the section names pins the same cap and holds the section's
/// two examples as admitted bodies.
#[test]
fn doc_states_the_registry_rows_the_bodies_and_the_refusals() {
    let registry = prose(
        "\n### Registry — the twelve rows, the two bodies and the record grade",
        &["\n### Links (writes)"],
    );
    for fact in [
        "| `1.1.0.1.0.1.0.3.55` | the BINDING — the registration record | on the bare ordinal (one reading) |",
        "| `1.1.0.1.0.1.0.3.56` | the ENDPOINT | on the bare ordinal (one reading); no subtype row |",
        "| `1.1.0.1.0.1.0.3.57` | the TAKEDOWN RECORD — the kind | NONE on the bare ordinal (two readings) |",
        "| `1.1.0.1.0.1.0.3.57.1` | the takedown record's own BASE reading | on this row |",
        "| `1.1.0.1.0.1.0.3.57.2` | LIFTED | on this row |",
        "| `1.1.0.1.0.1.0.3.58` | the POLICY LINK — the kind | NONE on the bare ordinal (five readings) |",
        "| `1.1.0.1.0.1.0.3.58.1` | the policy link's OWN reading | on this row |",
        "| `1.1.0.1.0.1.0.3.58.2` | the DISAVOWAL | on this row |",
        "| `1.1.0.1.0.1.0.3.58.3` | an expulsion's GROUND RECORD | on this row |",
        "| `1.1.0.1.0.1.0.3.58.4` | a succession's GROUND RECORD | on this row |",
        "| `1.1.0.1.0.1.0.3.58.5` | the ORG-CHOSEN SUCCESSION POLICY | on this row |",
        "| `1.1.0.1.0.1.0.3.59` | `successor-of` — the succession claim | on the bare ordinal (one reading) |",
        "**The deposit class's four members.**",
        "`parse(b)` answers a record only where `b == encode(parse(b))`",
        r#"{"type":"binding","prefix":"1.5"}"#,
        r#"{"type":"endpoint","origins":["https://acme.example","https://acme.example.net","http://<acme's onion host>.onion"]}"#,
        "are what the parse REFUSES",
        "16 KiB",
        "crates/skep-registry/tests/vectors/records.json",
        "**The record grade for registry records**",
        "BOTH of the deposit's positions",
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
        "**The seeding check**",
        "**INTERIM PINS**",
        "What this build does NOT carry, by name",
        "The checked set of the write-path check is UNCHANGED",
    ] {
        assert!(registry.contains(fact), "§Registry says {fact:?}");
    }
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../skep-registry/tests/vectors/records.json"),
        )
        .expect("the vector set the section names exists"),
    )
    .expect("the vector set is JSON");
    assert_eq!(fixture["cap"].as_u64(), Some(16_384));
    let vectors = fixture["vectors"].as_array().expect("vectors");
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
        credentials.contains("four members, stated once at §Registry"),
        "§The claim ceremony and credentials points at the deposit class's four members"
    );
    let refusals = prose("\n### Credential refusals", &["\n## Operations"]);
    for fact in [
        "the binding (`1.1.0.1.0.1.0.3.55`)",
        "the takedown record (`1.1.0.1.0.1.0.3.57`)",
        "the policy link (`1.1.0.1.0.1.0.3.58`)",
        "the endpoint (`1.1.0.1.0.1.0.3.56`) OUTSIDE",
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
/// permit pool, M-I5 (f)): §Media states the PUT's path family and its five
/// method/path pairs, the identifier's two carriers, the seven clauses each
/// by number, the ten refusals of the family with their statuses — the
/// permit's `upload_busy` among them — THE PERMIT in the creation's and the
/// resume's rows, the deposit read's members, the binding's three answers
/// at the door with `lease_lapsed` the third token, the INTERIM pins the
/// build carries — the cap, the chunk, the grain, the identifier's bits,
/// the partial's name, the lease interval and the horizon, the idle and
/// transfer bounds, the floor, the limits record's default and its owed
/// channel, the upload pool's count and the two worker counts it is
/// counted into — and the H1 rows; §Endpoints lists the family, §Transport
/// the family's cap, §HTTP status codes the ten; and the vector set the
/// section names pins the same constants.
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
        "| 503 | `upload_busy` |",
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
        "upload_busy",
    ] {
        assert!(statuses.contains(&format!("`{name}`")), "§HTTP status codes lists {name}");
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
    assert_eq!(fixture["refusals"]["upload_busy"].as_u64(), Some(503));
}

/// THE WALK BEHIND THE LISTENER (`operations.md` §3.3 step 2; §4 row 16;
/// the ops lanes' D9, W1's third token): §HTTP status codes carries
/// `feed_rebuilding` at 503 in the retry-class family's voice — the region
/// a lost or torn `commits.log` left uncovered, re-covered behind the
/// listener, pages below and above serving, `/events` untouched, retry
/// shortly — and §The change feed's **Rebuilding.** paragraph says the
/// walk's shape: the refusal's body, that it is retry-class as
/// `history_busy` is, that pages above and below serve, `/events` is
/// untouched, and that one rewrite lands it. The daemon's answers are
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
/// minimum — `MIN_WORKERS` one more than the FIVE pools' slots together, the
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
    for fact in [
        "five pools' slots together",
        "the write permit pool's 4",
        "`MAX_CONCURRENT_WRITES`",
    ] {
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

/// THE `durability` FACE AND THE FEED's COMPACTION AT THE CHECKPOINT (P10:
/// no face names a retry that cannot succeed; jw-R3, jw-R4): §Rejections'
/// `retry` row says what a retry-class answer at a full volume means — the
/// operation did nothing, no reissue succeeds until the operator frees the
/// room, the operator stream names it, the person's act is to tell the
/// operator — and §Rejection codes' `durability` entry says the same of the
/// code, the disposition staying `retry`; the old "durability hiccup" is
/// gone from both. §The change feed says the five feed files are compacted
/// after each checkpoint the daemon's thread lands, while serving, with the
/// stop a rewrite failed past its rename carries. The daemon's words are
/// pinned in `changes.rs`; this pins that the contract says so.
#[test]
fn doc_states_the_durability_faces_words_and_the_compaction_at_the_checkpoint() {
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
        "COMPACTED to the journal's reclaim floor",
        "after each checkpoint the daemon's own",
        "checkpoint thread lands, while serving",
        "STOPS that file for the uptime",
        "fails no write",
    ] {
        assert!(feed.contains(fact), "§The change feed says {fact:?}");
    }
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
/// same pins.
#[test]
fn doc_states_the_upload_setting_the_default_limit_the_creations_gate_and_the_tools() {
    let media = prose("\n### Media — the reference cell and its door", &["\n### Links (writes)"]);
    for fact in [
        "**The upload setting.**",
        "`--no-uploads`",
        "SKEPD_UPLOADS=false",
        "`media.uploads`",
        "`uploads_closed`",
        "one eighth of the volume's capacity",
        "never below 256 MiB",
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

/// THE CELL INDEX, THE READINESS REFUSAL AND THE PRUNER (the register
/// M-I5 (b), (f), M-I6 (a), (b); the rulings ms5-R and ms5-T4): §Media
/// states the index — what it holds, the entry at commit and the walk at
/// open, the composition clause, the halt mark — the readiness token and
/// its exactly three readers, the pruner's pass with its arm, its grain,
/// its halts and its cadence, the deposit read's two figures, the own
/// scope's two terms, the binding's index-first order, the replace's aside
/// and its deferred unlink; and the status table carries the token. The
/// daemon's answers are pinned in `media.rs`, `pruner.rs`, `blob_routes.rs`
/// and `hazard.rs`; this pins that the contract says so.
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
/// (a)) and the object's ORDER RULE: the section names the member, its one
/// boolean `halted`, what the boolean means and the count of members a
/// consumer is written to; its example carries `"writes":{"halted":false}`
/// in its place; the example's top-level keys stand in the order the
/// daemon's key-sorting `obj` writes them — alphabetical, `writes` after
/// `ok` — and a live daemon's `/health` answers the same keys in the same
/// order, `writes` false on a healthy board.
#[test]
fn doc_states_the_writes_member_and_the_health_examples_keys_are_the_daemons_in_its_order() {
    let health = prose("\n## The other endpoints", &["\n## A first board, end to end"]);
    for fact in [
        "`writes` is an object with one boolean, `halted`",
        "`writes.halted` is `false` on a healthy board",
        "these seven members",
        "must not treat an eighth as a violation",
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
        ["auth", "chain_head", "head_time", "log_position", "media", "ok", "writes"],
        "the seven members, each once"
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = crate::common::spawn_unclaimed(dir.path());
    let (st, body) = crate::common::get(sd.port(), "/health");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let served = std::str::from_utf8(&body).expect("the answer is UTF-8");
    assert_eq!(top_level_keys(served), keys, "the daemon's /health carries the example's keys in its order");
    let v: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(v["writes"], serde_json::json!({"halted": false}), "a healthy board: {v}");
    sd.shutdown();
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
