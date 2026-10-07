//! Content reads: `retrieve_contents` in each recorded shape (docs maps,
//! per-target lists, per-doc keyed replies, positions, spec sets, spans, the
//! whole document), the vspan/vspanset probes, and the observation
//! bundles. A whole-document read asks skep for everything its own extent
//! reports, never only as much as the recording says exists; and a read
//! whose recording holds an answer no shape here reaches ends inexpressible,
//! the answer named (`compared_nothing`).

use serde_json::Value;

use skep_febe::{Op, Response};
use skep_retrieval::{DeliveryItem, Spec};

use super::{
    compared_nothing, inexpressible, joint_absence, probe_state, refusal, settle_accepted,
    settle_unaccepted, Cx, Probe, Tally,
};
use crate::allowlist::Adjustments;
use crate::compare::{
    compare_content, compare_count, compare_spansets, is_collapsed_subspace_shape,
    COLLAPSED_SUBSPACE_ANALYSIS, VERSION_LINK_CARRYOVER_ANALYSIS,
};
use crate::fields::{
    as_text, expected_failure, field, has_observation_fields, locate, op_name, per_doc_replies,
    position_from_op_name, raw_spanset_of, recorded_content, recorded_spanset, span_dict,
    str_field, strings_of, verb_of, vspec_dict, Verb,
};
use crate::outcome::{Disagreement, OpOutcome};
use crate::tum::{is_link_address, link_home_docid, parse_dotted, parse_vpos, VPoint};

/// The arguments a content read carries: the document it reads, and the
/// region, spec set or position that narrows it.
const CONTENT_READS: &[&str] = &[
    "doc", "docid", "doc_label", "specset", "specs", "span", "spans", "vspan", "address", "at",
    "position",
];

/// The arguments a vspan/vspanset probe carries: the document it reads.
const EXTENT_READS: &[&str] = &["doc", "docid", "doc_label"];

/// The retrieve specs for a doc-less retrieve that follows a follow op whose
/// recorded result is a vspec — the landing the script read (policy
/// `retrieve-follow-landing`). `None` when the shape does not apply.
fn follow_landing_specs(cx: &mut Cx, index: usize, op: &Value) -> Option<Vec<Spec>> {
    if str_field(op, &["doc", "docid"]).is_some() {
        return None;
    }
    let prev = cx.ops.get(index.checked_sub(1)?)?;
    if !matches!(verb_of(prev), Some(Verb::FollowLink | Verb::Traverse)) {
        return None;
    }
    let (docid, spans) = raw_spanset_of(field(prev, &["result"])?)?;
    let docid = docid?;
    if spans.is_empty() {
        return None;
    }
    let d = cx.alpha.translate(&docid)?;
    let mut specs = Vec::new();
    for (start, w) in &spans {
        let region = parse_vpos(start)?.region(crate::tum::parse_width(w)?);
        if let Some(span) = region.span() {
            specs.push(Spec { doc: d.clone(), span });
        }
    }
    (!specs.is_empty()).then_some(specs)
}

/// A `{start, width}` dict whose components parse as dotted decimal but NOT
/// as a depth-2 V-position — the boundary corpus's nested local addresses
/// ("1.1.1" width "0.0.1"). Returns the raw component vectors for
/// [`crate::tum::deep_span`].
fn deep_span_dict(v: &Value) -> Option<(Vec<u64>, Vec<u64>)> {
    let o = v.as_object()?;
    let start = parse_dotted(o.get("start").and_then(Value::as_str)?)?;
    let width = parse_dotted(o.get("width").and_then(Value::as_str)?)?;
    (start.len() > 2 || width.len() > 2).then_some((start, width))
}

pub(super) fn h_retrieve_contents(cx: &mut Cx, index: usize, op: &Value, out: &mut OpOutcome) {
    let recorded_failure = expected_failure(op);

    // Multi-doc probe: `docs` map of name → expected strings. An id map
    // (create_documents-shaped) holds addresses, never content: set aside.
    if let Some(map) = op.get("docs").and_then(Value::as_object) {
        let mut tally = Tally::default();
        for (name, exp) in map {
            let Some(strings) = strings_of(exp) else { continue };
            if as_text(&strings).is_none() {
                continue;
            }
            let Some(doc) = cx.shadow.resolve_doc(name) else {
                tally.unaimed(format!("docs-map name `{name}` resolves to no document"));
                continue;
            };
            let label = format!("{name}: ");
            match cx.read_content(&doc) {
                Ok(items) => tally.judge(compare_content(&strings, &items, cx.alpha), &label),
                Err(code) => tally.differ(Disagreement {
                    expected: format!("{name}: contents"),
                    actual: format!("{name}: {code}"),
                }),
            }
        }
        out.adaptations.push("contents:content-subspace".into());
        let reads: Vec<&str> = CONTENT_READS.iter().copied().chain(["docs"]).collect();
        tally.settle_read(out, "content", op, &reads);
        return;
    }

    // Per-target probe list: `targets: [{doc|docid, contents}]` —
    // identity/identity_multi_document_sharing records every created
    // target's content only here.
    if let Some(entries) = op.get("targets").and_then(Value::as_array) {
        let mut tally = Tally::default();
        for e in entries {
            let docid = e
                .get("docid")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| {
                    e.get("doc").and_then(Value::as_str).and_then(|n| cx.shadow.resolve_doc(n))
                });
            let (Some(docid), Some(strings)) =
                (docid, e.get("contents").or_else(|| e.get("content")).and_then(strings_of))
            else {
                continue;
            };
            let label = format!("{docid}: ");
            match cx.read_content(&docid) {
                Ok(items) => tally.judge(compare_content(&strings, &items, cx.alpha), &label),
                Err(code) => tally.differ(Disagreement {
                    expected: format!("{docid}: contents"),
                    actual: format!("{docid}: {code}"),
                }),
            }
        }
        if tally.compared > 0 {
            out.adaptations.push("contents:content-subspace".into());
            tally.settle(out, "content");
            return;
        }
    }

    // Per-doc keyed probe (policy `contents:per-doc-keyed`): the recorded
    // per-document replies of one read (`fields::per_doc_replies`) —
    // internal/ispan_partial_overlap op 4's `source: ["CDEFG"], dest:
    // ["CDEFG"]` beside an `expected` that is prose, a snapshot's
    // `A_content`. The script's unrecorded specset is reconstructed
    // GOLDEN-side: a single recorded string that is a proper substring of
    // the doc's shadow content locates in the SHADOW and that span is read
    // from skep (policy `read-span-from-recorded-strings` — the query
    // derives from golden data only, so skep still has to deliver the right
    // bytes at those positions); everything else reads the whole document
    // and any mismatch surfaces loudly.
    let replies = per_doc_replies(op, cx.shadow);
    if !replies.is_empty() {
        let mut tally = Tally::default();
        for (name, doc, strings) in &replies {
            let Some(d) = cx.skep_doc(doc) else {
                tally.differ(Disagreement {
                    expected: format!("{name}: contents"),
                    actual: format!("{name}: {doc} never bound"),
                });
                continue;
            };
            // Reconstructed narrowing: exactly one recorded string,
            // strictly inside the shadow's content, located there.
            let narrowed = match strings.as_slice() {
                [s] if !s.is_empty()
                    && !is_link_address(s)
                    && *s != cx.shadow.text_string(doc) =>
                {
                    cx.shadow
                        .find_text(Some(doc.as_str()), s)
                        .map(|(_, ord)| (ord, s.len() as u64))
                }
                _ => None,
            };
            let items = if let Some((ord, w)) = narrowed {
                out.adaptations.push("read-span-from-recorded-strings".into());
                match VPoint::content(ord).region(w).span().map(|span| {
                    cx.rig.exec(Op::RetrieveV { specs: vec![Spec { doc: d, span }] })
                }) {
                    Some(Response::Delivery { items, .. }) => Ok(items.0),
                    Some(r) => Err(refusal(&r)),
                    None => Ok(Vec::new()),
                }
            } else {
                cx.read_content(doc)
            };
            let label = format!("{name}: ");
            match items {
                Ok(items) => tally.judge(compare_content(strings, &items, cx.alpha), &label),
                Err(code) => tally.differ(Disagreement {
                    expected: format!("{name}: contents"),
                    actual: format!("{name}: {code}"),
                }),
            }
        }
        out.adaptations.push("contents:per-doc-keyed".into());
        tally.settle(out, "content");
        return;
    }

    // Per-position probe: `positions` map of "1.3" → "C".
    if let Some(map) = op.get("positions").and_then(Value::as_object) {
        let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
            inexpressible(out, "positions probe with no document in scope".into());
            return;
        };
        let Some(d) = cx.skep_doc(&doc) else {
            out.never_bound(format!("positions probe doc {doc} never bound"));
            return;
        };
        let mut tally = Tally::default();
        for (pos, exp) in map {
            let Some(at) = parse_vpos(pos) else {
                tally.unaimed(format!("positions key `{pos}` is not a V-position"));
                continue;
            };
            let Some(want) = exp.as_str() else { continue };
            let Some(span) = at.region(1).span() else { continue };
            match cx.rig.exec(Op::RetrieveV { specs: vec![Spec { doc: d.clone(), span }] }) {
                Response::Delivery { items, .. } => {
                    // One-position comparison through the shared content
                    // comparator, so an address value goes through α
                    // (bind + element lift) like every delivered address —
                    // never compared as a rendered string.
                    if want.is_empty() && items.0.is_empty() {
                        tally.agree();
                        continue;
                    }
                    let c = compare_content(&[want.to_string()], &items.0, cx.alpha);
                    tally.judge(c, &format!("{pos}="));
                }
                r => tally.differ(Disagreement {
                    expected: format!("{pos}={want:?}"),
                    actual: format!("{pos}: {}", refusal(&r)),
                }),
            }
        }
        tally.settle_read(out, "content-positions", op, CONTENT_READS);
        return;
    }

    // The recorded reply: an array outranks prose (`fields::recorded_content`).
    let strings: Option<Vec<String>> =
        recorded_content(op, CONTENT_READS).map(|(_, strings)| strings);

    // The expectation itself may name the doc (a link-address probe's home).
    let doc_from_exp: Option<String> = strings.as_ref().and_then(|ss| {
        ss.iter().find_map(|s| link_home_docid(s)).filter(|h| cx.shadow.knows(h))
    });
    if let Some(h) = &doc_from_exp {
        cx.shadow.set_current(h);
    }

    let mut specs: Vec<Spec> = Vec::new();
    // Link-subspace reads issued as a SECOND RetrieveV, so a refusal of the
    // link side cannot void the content read (policy
    // `contents:both-subspaces`); an unoccupied link subspace delivers
    // nothing (M6 R6), and the comparison shows the expected @addr
    // undelivered. The golden doc the link read targets is kept so an empty
    // answer can be classified (a VERSION missing its source's links is the
    // carryover family).
    let mut link_specs: Vec<Spec> = Vec::new();
    let mut link_read_doc: Option<String> = None;
    if let Some(arr) = field(op, &["specset", "specs"]).and_then(Value::as_array) {
        for v in arr {
            let Some((docid, regions)) = vspec_dict(v) else {
                inexpressible(out, "retrieve spec list holds a non-vspec entry".into());
                return;
            };
            let Some(d) = cx.alpha.translate(&docid) else {
                out.never_bound(format!("retrieve doc {docid} never bound"));
                return;
            };
            for region in regions {
                if let Some(span) = region.span() {
                    specs.push(Spec { doc: d.clone(), span });
                }
            }
        }
    } else if let Some(s) = str_field(op, &["specset"]) {
        if s.contains("NOSPECS") || s == "empty" {
            out.adaptations.push("empty-specset".into());
        } else if let Some(rest) = s.strip_prefix("First ") {
            // "First N chars from each document"
            // (content/retrieve_multiple_documents).
            let n: Option<u64> =
                rest.split_whitespace().next().and_then(|t| t.parse().ok());
            if let Some(n) = n {
                out.adaptations.push("specset-from-description".into());
                let first = VPoint::content(1).region(n);
                for docid in cx.shadow.created() {
                    if let (Some(d), Some(span)) = (cx.alpha.peek_exact(docid), first.span()) {
                        specs.push(Spec { doc: d, span });
                    }
                }
            } else {
                inexpressible(out, format!("retrieve specset {s:?} not groundable"));
                return;
            }
        } else {
            inexpressible(out, format!("retrieve specset {s:?} not groundable"));
            return;
        }
    } else if let Some(v) = field(op, &["span", "spans", "vspan"]) {
        // Narrowing argument: dict span(s) or located/decorated text — the
        // partial-retrieve path (content/partial_retrieve,
        // retrieve_noncontiguous_spans).
        let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
            inexpressible(out, "retrieve with no document in scope".into());
            return;
        };
        let Some(d) = cx.skep_doc(&doc) else {
            out.never_bound(format!("retrieve doc {doc} never bound"));
            return;
        };
        let items: Vec<&Value> = match v {
            Value::Array(a) => a.iter().collect(),
            other => vec![other],
        };
        for item in items {
            if let Some(region) = span_dict(item) {
                if let Some(span) = region.span() {
                    specs.push(Spec { doc: d.clone(), span });
                }
            } else if let Some((start, width)) = deep_span_dict(item) {
                // A NESTED local V-address ("1.1.1" width "0.0.1" —
                // boundary_deep_vaddress_reads): built as an arbitrary-depth
                // tumbler span and asked of skep raw; M6's answer — empty (a
                // well-formed nested span resolves to nothing, R6) or
                // `MalformedSpan` (ruling 17) — is compared as recorded
                // (policy `deep-vaddress-span`).
                out.adaptations.push("deep-vaddress-span".into());
                match crate::tum::deep_span(&start, &width) {
                    Some(span) => specs.push(Spec { doc: d.clone(), span }),
                    None => {
                        inexpressible(
                            out,
                            format!("deep span start {start:?} width {width:?} not constructible"),
                        );
                        return;
                    }
                }
            } else if let Some(t) = item.as_str() {
                match locate(cx.shadow, Some(&doc), t) {
                    Some(l) => {
                        out.adaptations.push(l.how.tag().into());
                        if let Some(span) = l.region().span() {
                            specs.push(Spec { doc: d.clone(), span });
                        }
                    }
                    None => {
                        inexpressible(out, format!("retrieve span {t:?} not groundable"));
                        return;
                    }
                }
            }
        }
    } else if let Some(landing) = (!op_name(op).to_ascii_lowercase().starts_with("full_"))
        .then(|| follow_landing_specs(cx, index, op))
        .flatten()
    {
        // Policy `retrieve-follow-landing`: a doc-less retrieve right after
        // a follow whose recorded result names a vspec reads THOSE spans —
        // the script retrieved the link destination it had just followed
        // (links/follow_link op8), never the register. A `full_*` op is by
        // its own name a whole-document read, never a landing read
        // (round-5 item 4: insert_text_check_both_link_positions op7).
        out.adaptations.push("retrieve-follow-landing".into());
        specs = landing;
    } else {
        // Full probes aim at the doc the last CONTENT write touched, not
        // whatever the register drifted to (policy
        // `full-probe-targets-last-write`).
        let full_probe = op_name(op).to_ascii_lowercase().starts_with("full_");
        let doc = if full_probe && str_field(op, &["doc", "docid"]).is_none() {
            match cx.shadow.last_written.clone().filter(|d| cx.shadow.knows(d)) {
                Some(d) => {
                    out.adaptations.push("full-probe-targets-last-write".into());
                    cx.shadow.set_current(&d);
                    Some(d)
                }
                None => cx.doc_arg(op, out, &["doc", "docid"]),
            }
        } else {
            cx.doc_arg(op, out, &["doc", "docid"])
        };
        let Some(doc) = doc else {
            inexpressible(out, "retrieve with no document in scope".into());
            return;
        };
        let Some(d) = cx.skep_doc(&doc) else {
            out.never_bound(format!("retrieve doc {doc} never bound"));
            return;
        };
        let pos = str_field(op, &["address", "at", "position"]).and_then(parse_vpos).or_else(
            || {
                position_from_op_name(op_name(op)).inspect(|_| {
                    out.adaptations.push("position-from-op-name".into());
                })
            },
        );
        if let Some(at) = pos {
            if let Some(span) = at.region(1).span() {
                specs.push(Spec { doc: d, span });
            }
        } else {
            // Whole document: everything skep's own extent reports in the
            // content subspace (`Cx::skep_content_spans`) — never sized
            // from the recording, which would hide whatever skep holds past
            // it. The reply's SHAPE follows the golden (round-5 item 5):
            // text-only recorded contents read the CONTENT subspace only
            // (policy `contents:content-subspace` — udanax's plain
            // retrieve_contents never lists link items); a recorded reply
            // that includes a link address read BOTH subspaces — content
            // plus the link positions — and the link addresses compare
            // through α (policy `contents:both-subspaces`). One
            // evidence-driven narrowing: when the recorded TEXT is a strict
            // prefix of the shadow's (recorded-reality) content, the
            // script's specset was that much narrower — read only that many
            // positions (policy `read-scoped-to-recorded-extent`).
            let n = cx.shadow.text_len(&doc);
            let mut scoped_to: Option<u64> = None;
            let has_addr = strings
                .as_ref()
                .is_some_and(|ss| ss.iter().any(|s| is_link_address(s)));
            if let Some(ss) = &strings {
                let text_len: usize =
                    ss.iter().filter(|s| !is_link_address(s)).map(String::len).sum();
                let shadow_text = cx.shadow.text_string(&doc);
                // Bounded at 2 elements: a larger shortfall is a
                // world-construction failure that must diverge loudly, not
                // a narrower script read.
                if (text_len as u64) < n
                    && n - text_len as u64 <= 2
                    && text_len > 0
                    && shadow_text.len() >= text_len
                    && ss
                        .iter()
                        .find(|s| !is_link_address(s))
                        .is_some_and(|first| shadow_text.starts_with(first.as_str()))
                {
                    out.adaptations.push("read-scoped-to-recorded-extent".into());
                    scoped_to = Some(text_len as u64);
                }
            }
            out.adaptations.push(
                if has_addr { "contents:both-subspaces" } else { "contents:content-subspace" }
                    .to_string(),
            );
            match scoped_to {
                Some(read_n) => {
                    let read = VPoint::content(1).region(read_n);
                    specs.extend(read.span().map(|span| Spec { doc: d.clone(), span }))
                }
                None => match cx.skep_content_spans(&d) {
                    Ok(spans) => {
                        specs.extend(spans.into_iter().map(|span| Spec { doc: d.clone(), span }))
                    }
                    Err(r) => {
                        settle_unaccepted(out, recorded_failure, &r);
                        return;
                    }
                },
            }
            if has_addr {
                let n_addr = strings
                    .as_ref()
                    .map(|ss| ss.iter().filter(|s| is_link_address(s)).count() as u64)
                    .unwrap_or(0);
                let links = cx.shadow.link_count(&doc).max(n_addr);
                let link_positions = VPoint { sub: 2, ord: 1 }.region(links);
                if let Some(span) = link_positions.span() {
                    link_specs.push(Spec { doc: d, span });
                    link_read_doc = Some(doc.clone());
                }
            }
        }
    }
    let items: Vec<DeliveryItem> = if specs.is_empty() {
        // No span to read: an empty spec set, or a document whose content
        // extent skep reports empty.
        Vec::new()
    } else {
        match cx.rig.exec(Op::RetrieveV { specs }) {
            Response::Delivery { items, .. } => {
                if !settle_accepted(out, recorded_failure) {
                    return;
                }
                items.0
            }
            other => {
                settle_unaccepted(out, recorded_failure, &other);
                return;
            }
        }
    };
    // The link-subspace read, as its own call: a link-side rejection
    // localizes to the missing segment — the comparison below then shows
    // the expected @addr undelivered — instead of voiding the content read.
    let mut items = items;
    if !link_specs.is_empty() {
        match cx.rig.exec(Op::RetrieveV { specs: link_specs }) {
            Response::Delivery { items: more, .. } => {
                if more.0.is_empty() {
                    // The read FIRED and came back silent-empty (M6 R6: an
                    // unoccupied subspace degrades to an empty contribution,
                    // never an error). Say so — a note-less miss is
                    // indistinguishable from the policy not firing, which is
                    // exactly the ambiguity round 6 was misdiagnosed on. A
                    // version doc missing its source's links is the
                    // carryover family ruling 15 decided.
                    let versioned = link_read_doc
                        .as_deref()
                        .is_some_and(|g| cx.shadow.version_of.contains_key(g));
                    out.add_note(if versioned {
                        VERSION_LINK_CARRYOVER_ANALYSIS.to_string()
                    } else {
                        "link-subspace read fired and delivered no items (subspace \
                         unoccupied on the skep side)"
                            .to_string()
                    });
                }
                items.extend(more.0);
            }
            r => out.add_note(format!("link-subspace read: {}", refusal(&r))),
        }
    }
    let Some(strings) = strings else {
        compared_nothing(out, op, CONTENT_READS);
        return;
    };
    match compare_content(&strings, &items, cx.alpha) {
        Ok(()) => out.agree("content"),
        Err(d) => out.disagree("content", d),
    }
}

/// A vspan probe, or a vspanset probe when `verb` is
/// [`Verb::RetrieveVspanset`].
pub(super) fn h_retrieve_vspanset(
    cx: &mut Cx,
    op: &Value,
    out: &mut OpOutcome,
    adjustments: &Adjustments,
    verb: Verb,
) {
    let recorded = recorded_spanset(op);
    // A count of a ROLE document's spans names that document (policy
    // `vspan-count-by-role`: ispan_consolidation_bulk's
    // `source_vspan_count`).
    let role_count: Option<(&str, u64)> = op.as_object().and_then(|o| {
        o.iter().find_map(|(k, v)| Some((k.strip_suffix("_vspan_count")?, v.as_u64()?)))
    });
    let role_doc = match role_count {
        Some((role, _)) => match cx.shadow.resolve_doc(role) {
            Some(d) => {
                out.adaptations.push("vspan-count-by-role".into());
                Some(d)
            }
            None => {
                inexpressible(out, format!("`{role}_vspan_count` names no document"));
                return;
            }
        },
        None => None,
    };
    // The expectation's own docid names the document when the op omits it.
    let doc = recorded
        .as_ref()
        .and_then(|(_, d, _)| d.clone())
        .and_then(|d| cx.shadow.resolve_doc(&d))
        .or(role_doc)
        .or_else(|| cx.doc_arg(op, out, &["doc", "docid"]));
    let Some(doc) = doc else {
        inexpressible(out, "vspanset probe with no document in scope".into());
        return;
    };
    cx.shadow.set_current(&doc);
    let Some(d) = cx.skep_doc(&doc) else {
        out.never_bound(format!("vspanset of never-bound doc {doc}"));
        return;
    };
    // `poom_empty` records whether udanax's POOM — its V-space arrangement
    // of the document — held anything (policy `poom-empty`).
    let poom_empty = field(op, &["poom_empty"]).and_then(Value::as_bool);
    let recorded_failure = expected_failure(op);
    let r = if verb == Verb::RetrieveVspanset {
        cx.rig.exec(Op::RetrieveDocVSpanSet { doc: d })
    } else {
        cx.rig.exec(Op::RetrieveDocVSpan { doc: d })
    };
    let set = match r {
        Response::SpanSet { set, .. } => {
            if !settle_accepted(out, recorded_failure) {
                return;
            }
            set
        }
        other => {
            settle_unaccepted(out, recorded_failure, &other);
            return;
        }
    };
    let count = field(op, &["span_count"]).and_then(Value::as_u64).or(role_count.map(|(_, n)| n));
    if let Some(n) = count {
        match compare_count(n, set.iter().count(), adjustments, &mut out.adaptations) {
            Ok(()) => out.agree("count"),
            Err(d) => out.disagree("count", d),
        }
        return;
    }
    if let Some(empty) = poom_empty {
        out.adaptations.push("poom-empty".into());
        let spans = set.iter().count();
        if (spans == 0) == empty {
            out.agree("vspanset");
        } else {
            let want = if empty { "an empty vspanset" } else { "a nonempty vspanset" };
            let actual = format!("{spans} span(s)");
            out.disagree("vspanset", Disagreement { expected: want.into(), actual });
        }
        return;
    }
    let Some((_, _, spans)) = recorded else {
        compared_nothing(out, op, EXTENT_READS);
        return;
    };
    match compare_spansets(&spans, &set, adjustments, &mut out.adaptations) {
        Ok(()) => out.agree("vspanset"),
        Err(d) => {
            out.disagree("vspanset", d);
            if is_collapsed_subspace_shape(&spans) {
                out.note = Some(COLLAPSED_SUBSPACE_ANALYSIS.to_string());
            } else if cx.shadow.version_of.contains_key(&doc)
                && cx.shadow.link_count(&doc) > 0
                && spans.iter().all(|(s, _)| s == "1" || s.starts_with("1."))
            {
                // A VERSION's recorded content-subspace extent disagreeing
                // with skep's while the shadow (udanax's recorded reality)
                // says the version carries links is the carryover family —
                // the recorded width folds the copied links onto the tail.
                out.note = Some(VERSION_LINK_CARRYOVER_ANALYSIS.to_string());
            }
        }
    }
}

/// Observation-bundle ops (`initial_state`, `after_first_insert`,
/// `verify_empty`, …): pure probes over the doc in scope.
pub(super) fn h_observe(
    cx: &mut Cx,
    index: usize,
    op: &Value,
    out: &mut OpOutcome,
    adjustments: &Adjustments,
) {
    // docs-map / targets-list / positions bundles, and per-document
    // replies, compare several documents.
    if op.get("docs").and_then(Value::as_object).is_some()
        || op.get("targets").and_then(Value::as_array).is_some()
        || op.get("positions").and_then(Value::as_object).is_some()
        || !per_doc_replies(op, cx.shadow).is_empty()
    {
        h_retrieve_contents(cx, index, op, out);
        return;
    }
    // A probe green FAILED with no observation data recorded
    // (boundary_foreign_and_malformed_opens: probes of never-created docs
    // through validation-free opens). Never-created target → joint absence;
    // a real bound target → issue the vspanset read and reconcile the
    // recorded failure against skep's own answer.
    let recorded_failure = expected_failure(op);
    if recorded_failure.is_some() && !has_observation_fields(op) {
        if let Some(docref) = str_field(op, &["doc", "docid"]) {
            if joint_absence(cx, out, recorded_failure.as_deref(), docref) {
                return;
            }
            if let Some(d) = cx.alpha.peek_translate(docref) {
                match cx.rig.exec(Op::RetrieveDocVSpanSet { doc: d }) {
                    Response::SpanSet { .. } => {
                        settle_accepted(out, recorded_failure);
                    }
                    other => settle_unaccepted(out, recorded_failure, &other),
                }
                return;
            }
        }
        inexpressible(out, "failed probe with no resolvable document".into());
        return;
    }
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        inexpressible(out, "observation bundle with no document in scope".into());
        return;
    };
    probe_state(cx, op, out, adjustments, &doc, Probe::Bundle);
}
