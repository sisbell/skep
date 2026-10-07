//! The three searches: `find_links` (a four-set query over the images of the
//! golden's regions, deleted content reached through I-history — operator
//! ruling 10), `find_documents`, and `retrieve_endsets` (compared as
//! I-coverage — operator ruling 11).

use serde_json::Value;

use skep_discovery::{FourSet, SlotSpec};
use skep_febe::{Op, Response};
use skep_links::{enc, Endset};
use skep_retrieval::RegionSpec;

use super::{
    elem_range, inexpressible, marker_type_name, parse_set_spans, rejection_code, settle_ack,
    side_specs, Cx, SetSpan, Tally,
};
use crate::allowlist::Grants;
use crate::compare::{compare_addr_sets, compare_count};
use crate::fields::{expected_failure, field, locate, str_field, vspec_dict, DocSpans};
use crate::outcome::{OpOutcome, Status};
use crate::tum::{is_link_address, parse_dotted, vspan};

/// One query side of a find_links: golden V-space (doc, spans) pairs to be
/// imaged live, or a pre-resolved I-space endset (deleted-content reach).
enum SideSpec {
    V(Vec<DocSpans>),
    I(Endset),
}

pub(super) fn h_find_links(cx: &mut Cx, op: &Value, out: &mut OpOutcome, grants: &Grants) {
    let mut notes: Vec<String> = Vec::new();

    // `by` routing (find_links_by_target, search_by_both_endpoints…):
    // tokens split on AND; "target…" constrains TO, "source…" FROM; a token
    // may name a specific doc ("source1"). The search field (if any) feeds
    // the FIRST by-slot; role extents fill the rest.
    let by = str_field(op, &["by", "direction"]).map(str::to_ascii_lowercase);
    let mut by_from_doc: Option<String> = None;
    let mut by_to_doc: Option<String> = None;
    if let Some(b) = &by {
        for token in b.split(|c: char| !c.is_alphanumeric() && c != '_').filter(|t| !t.is_empty())
        {
            if matches!(token, "and" | "only" | "empty" | "incoming" | "outgoing") {
                continue;
            }
            if token.contains("target") {
                by_to_doc = cx
                    .shadow
                    .resolve_doc(token)
                    .or_else(|| cx.shadow.resolve_doc("target"));
            } else if token.contains("source") {
                by_from_doc = cx
                    .shadow
                    .resolve_doc(token)
                    .or_else(|| cx.shadow.resolve_doc("source"));
            }
        }
        // "incoming"/"outgoing" without source/target tokens: direction of
        // the explicit from/to fields, handled below.
    }

    // The search region: vspec array, doc reference, located text — or,
    // when the text/region lives only in DELETED content, the I-coverage
    // captured at delete time (ruling 10, policy `i-coverage-search`).
    let mut icov_tag = false;
    let search_sides: Option<SideSpec> = (|| {
        if let Some(v) = field(op, &["search", "specs", "specset", "source_specs"]) {
            if let Some(s) = v.as_str() {
                if s.contains("NOSPECS") || s == "empty" {
                    return Some(SideSpec::V(Vec::new()));
                }
                if s == "full document" || s.starts_with("entire") {
                    let d = cx.shadow.scoped()?;
                    let n = cx.shadow.text_len(&d);
                    return Some(SideSpec::V(vec![(d, vec![(1, 1, n.max(1))])]));
                }
                if let Some(l) = locate(cx.shadow, None, s) {
                    return Some(SideSpec::V(vec![(l.doc, vec![(1, l.ord, l.width)])]));
                }
                let ispans = cx.deletions.locate(s.as_bytes())?;
                icov_tag = true;
                return Some(SideSpec::I(Endset::from_spans(ispans)));
            }
            let arr = v.as_array()?;
            let vspecs: Option<Vec<_>> = arr.iter().map(vspec_dict).collect();
            return vspecs.map(SideSpec::V);
        }
        if let Some(t) = str_field(op, &["search_text", "query"]) {
            if t == "full document" || t.starts_with("entire") {
                let d = cx.shadow.scoped()?;
                let n = cx.shadow.text_len(&d);
                return Some(SideSpec::V(vec![(d, vec![(1, 1, n.max(1))])]));
            }
            if let Some(l) = locate(cx.shadow, None, t) {
                return Some(SideSpec::V(vec![(l.doc, vec![(1, l.ord, l.width)])]));
            }
            let ispans = cx.deletions.locate(t.as_bytes())?;
            icov_tag = true;
            return Some(SideSpec::I(Endset::from_spans(ispans)));
        }
        // A doc-valued search field (link_chain's `search_doc: "B"`).
        if let Some(d) =
            str_field(op, &["search_doc", "search_document"]).and_then(|s| cx.shadow.resolve_doc(s))
        {
            let n = cx.shadow.text_len(&d);
            return Some(SideSpec::V(vec![(d, vec![(1, 1, n.max(1))])]));
        }
        None
    })();
    if icov_tag {
        out.adaptations.push("i-coverage-search".into());
    }
    if str_field(op, &["search_text", "query"]).is_some() && search_sides.is_some() && !icov_tag {
        out.adaptations.push("text-located:search".into());
    }

    // Explicit from/to fields (doc names or vspec arrays).
    let explicit_side = |cx: &mut Cx, out: &mut OpOutcome, keys: &[&str]| -> Option<Vec<DocSpans>> {
        let v = field(op, keys)?;
        side_specs(cx, out, v).ok()
    };

    let whole_of = |cx: &Cx, d: &str| -> Vec<DocSpans> {
        let n = cx.shadow.text_len(d);
        if n == 0 {
            vec![(d.to_string(), Vec::new())]
        } else {
            vec![(d.to_string(), vec![(1, 1, n)])]
        }
    };

    let by_is_target = by.as_deref().is_some_and(|b| b.contains("target"));
    let by_is_both = by.as_deref().is_some_and(|b| b.contains("and") || (b.contains("source") && b.contains("target")));

    let mut from_sides: Option<SideSpec> = None;
    let mut to_sides: Option<SideSpec> = None;

    // Corpus-extension set fields (`fromset`/`toset`): explicit vspec lists.
    // An EMPTY list is the recording client's NOSPECS — no constraint on the
    // slot (policy `set-empty:unconstrained`); the legacy from/to keys keep
    // their own semantics untouched.
    for (key, slot) in [("fromset", 0usize), ("toset", 1)] {
        let Some(v) = field(op, &[key]) else { continue };
        let Some(arr) = v.as_array() else { continue };
        if arr.is_empty() {
            out.adaptations.push(format!("set-empty:unconstrained:{key}"));
            continue;
        }
        let Some(parsed) = arr.iter().map(vspec_dict).collect::<Option<Vec<DocSpans>>>() else {
            inexpressible(out, format!("find_links {key} holds a non-vspec entry"));
            return;
        };
        if slot == 0 {
            from_sides = Some(SideSpec::V(parsed));
        } else {
            to_sides = Some(SideSpec::V(parsed));
        }
    }

    if let Some(s) = explicit_side(cx, out, &["from", "source", "sources"]) {
        // `by: "target"` routes the explicit doc into the TO slot: the
        // client's `from` field named the doc it searched FROM, `by` named
        // WHICH endset it constrained (interactions/link_both_endpoints_
        // transcluded op11 searches target_origin by target — its content
        // is the link's TO coverage, never its FROM). Policy
        // `by-routes-explicit-side`.
        if by_is_target && !by_is_both && to_sides.is_none() {
            out.adaptations.push("by-routes-explicit-side".into());
            to_sides = Some(SideSpec::V(s));
        } else {
            from_sides = Some(SideSpec::V(s));
        }
    }
    if let Some(s) = explicit_side(cx, out, &["to", "target", "targets"]) {
        to_sides = Some(SideSpec::V(s));
    }
    if let Some(search) = search_sides {
        if by_is_target && to_sides.is_none() {
            to_sides = Some(search);
        } else if from_sides.is_none() {
            from_sides = Some(search);
        }
    }
    if by_is_both || (by_is_target && to_sides.is_none()) {
        if let Some(d) = &by_to_doc {
            if to_sides.is_none() {
                to_sides = Some(SideSpec::V(whole_of(cx, d)));
            }
        } else if by_is_target && to_sides.is_none() {
            if let Some(d) = cx.shadow.resolve_doc("target") {
                to_sides = Some(SideSpec::V(whole_of(cx, &d)));
            }
        }
    }
    if by_is_both || (!by_is_target && by.is_some() && from_sides.is_none()) {
        if let Some(d) = &by_from_doc {
            if from_sides.is_none() {
                from_sides = Some(SideSpec::V(whole_of(cx, d)));
            }
        }
    }
    // `via_transcluded_content: true` — the search covers exactly the
    // scoped doc's foreign-origin (copied-in) regions (policy
    // `transcluded-region-search`; links/link_chain_with_transclusion's
    // final probe searches B's transcluded portion, not its own anchors).
    if from_sides.is_none()
        && to_sides.is_none()
        && field(op, &["via_transcluded_content"]).and_then(Value::as_bool) == Some(true)
    {
        if let Some(d) = cx.shadow.scoped() {
            out.adaptations.push("transcluded-region-search".into());
            let regions = cx.transcluded_regions_golden(&d);
            let spans: Vec<(u64, u64, u64)> = regions.iter().map(|(o, w)| (1, *o, *w)).collect();
            from_sides = Some(SideSpec::V(vec![(d, spans)]));
        }
    }
    // An op that carried ANY explicit set field (even empty — NOSPECS) was a
    // fully specified client call; the bare-register aim never applies.
    let ext_sets_present =
        ["fromset", "toset", "threeset", "homespans"].iter().any(|k| op.get(*k).is_some());
    if from_sides.is_none() && to_sides.is_none() && !ext_sets_present {
        // Bare find_links: the recording client searched by the source-role
        // document when one is named (link scenarios probe "can the link be
        // found from source" — links/link_home_document_content_deleted),
        // else by the scoped document's whole current extent.
        let aim = cx
            .shadow
            .find_named_containing("source")
            .or_else(|| cx.shadow.scoped());
        if let Some(d) = aim {
            out.adaptations.push("doc-from-register".into());
            from_sides = Some(SideSpec::V(whole_of(cx, &d)));
        }
    }
    // An explicit doc field narrows the bare search to that document.
    if let Some(d) = str_field(op, &["doc", "docid"]).and_then(|s| cx.shadow.resolve_doc(s)) {
        if field(op, &["from", "source", "sources"]).is_none()
            && field(op, &["search", "specs", "specset"]).is_none()
            && str_field(op, &["search_text", "query", "search_doc"]).is_none()
        {
            from_sides = Some(SideSpec::V(whole_of(cx, &d)));
        }
    }

    // V sides image through the live arrangement; a doc whose content is
    // gone entirely falls back to its captured deletion I-spans (ruling 10)
    // — the search the golden aimed at content that still exists as
    // I-history. The clamp flag surfaces as `query-clamped-to-extent`.
    let mut clamped_any = false;
    let mut icov_any = false;
    let mut side_to_slot = |cx: &mut Cx, sides: Option<SideSpec>, notes: &mut Vec<String>| -> SlotSpec {
        match sides {
            None => SlotSpec::Any,
            Some(SideSpec::I(e)) => {
                if e.is_empty() {
                    SlotSpec::Empty
                } else {
                    SlotSpec::Spans(e)
                }
            }
            Some(SideSpec::V(list)) => {
                let mut all: Vec<skep_address::Span> = Vec::new();
                for (doc, spans) in &list {
                    if spans.is_empty() || cx.shadow.text_len(doc) == 0 {
                        let deleted = cx.deletions.ispans_of(doc);
                        if !deleted.is_empty() {
                            icov_any = true;
                            all.extend(deleted);
                        }
                        continue;
                    }
                    let (e, n, cl) = cx.image_endset(doc, spans);
                    notes.extend(n);
                    clamped_any |= cl;
                    all.extend(e.spans().cloned());
                }
                let e = Endset::from_spans(all);
                if e.is_empty() {
                    SlotSpec::Empty
                } else {
                    SlotSpec::Spans(e)
                }
            }
        }
    };
    let from = side_to_slot(cx, from_sides, &mut notes);
    let to = side_to_slot(cx, to_sides, &mut notes);
    if icov_any {
        out.adaptations.push("i-coverage-search".into());
    }
    if clamped_any {
        out.adaptations.push("query-clamped-to-extent".into());
    }

    // The type slot: `threeset` (corpus extension) first — content spans
    // image to their I-coverage, markers map through the registry, empty is
    // NOSPECS (unconstrained) — then the legacy name-based filter.
    let ty = if let Some(v) = field(op, &["threeset"]) {
        match v.as_array() {
            Some(arr) if arr.is_empty() => {
                out.adaptations.push("set-empty:unconstrained:threeset".into());
                SlotSpec::Any
            }
            Some(_) => match parse_set_spans(v) {
                Ok(sides) => {
                    let mut all: Vec<skep_address::Span> = Vec::new();
                    for (docid, spans) in &sides {
                        let mut plain: Vec<(u64, u64, u64)> = Vec::new();
                        for sp in spans {
                            match sp {
                                SetSpan::Plain(s, o, w) => plain.push((*s, *o, *w)),
                                SetSpan::Marker(comps) => match marker_type_name(comps) {
                                    Some(name) => {
                                        out.adaptations.push("threeset-marker→registry".into());
                                        out.adaptations.push("type_registry".into());
                                        match cx.rig.type_endset(name) {
                                            Some(e) => all.extend(e.spans().cloned()),
                                            None => notes.push(format!(
                                                "type `{name}` has no registry endset"
                                            )),
                                        }
                                    }
                                    None => notes.push(format!(
                                        "threeset marker {comps:?} is not a known udanax type \
                                         address"
                                    )),
                                },
                            }
                        }
                        if !plain.is_empty() {
                            let (e, n, cl) = cx.image_endset(docid, &plain);
                            notes.extend(n);
                            // The from/to clamp tag was already emitted above;
                            // tag a threeset clamp directly.
                            if cl {
                                out.adaptations.push("query-clamped-to-extent".into());
                            }
                            all.extend(e.spans().cloned());
                        }
                    }
                    let e = Endset::from_spans(all);
                    if e.is_empty() {
                        SlotSpec::Empty
                    } else {
                        SlotSpec::Spans(e)
                    }
                }
                Err(e) => {
                    inexpressible(out, format!("find_links threeset: {e}"));
                    return;
                }
            },
            None => SlotSpec::Any,
        }
    } else {
        match str_field(op, &["filter", "type", "link_type"]) {
            None | Some("none") | Some("all") | Some("") => SlotSpec::Any,
            Some(name) => {
                out.adaptations.push("type_registry".into());
                match cx.rig.type_endset(name) {
                    Some(e) => SlotSpec::Spans(e),
                    None => {
                        notes.push(format!("type `{name}` has no registry endset"));
                        SlotSpec::Empty
                    }
                }
            }
        }
    };
    let home = match field(
        op,
        &["homedocids", "homedocs", "home_docs", "homedoc", "home_doc", "home", "homespans"],
    ) {
        None => SlotSpec::Any,
        Some(v) => {
            let refs: Vec<String> = match v {
                Value::String(s) => vec![s.clone()],
                Value::Array(a) => a
                    .iter()
                    .filter_map(|x| {
                        // Strings or `{start: docid, width: "0.1"}` span
                        // dicts over global doc space
                        // (find_links_filter_by_homedocid).
                        x.as_str()
                            .map(str::to_string)
                            .or_else(|| {
                                x.get("start").and_then(Value::as_str).map(str::to_string)
                            })
                    })
                    .collect(),
                _ => Vec::new(),
            };
            let mut addrs = Vec::new();
            for r in refs {
                match cx.shadow.resolve_doc(&r).and_then(|g| cx.alpha.translate(&g)) {
                    Some(a) => addrs.push(a),
                    None => notes.push(format!("home doc {r} unresolvable")),
                }
            }
            if addrs.is_empty() {
                SlotSpec::Empty
            } else {
                SlotSpec::Spans(enc(&addrs))
            }
        }
    };
    let q = FourSet { home, from, to, ty };
    let xf = expected_failure(op);
    let r = cx.rig.exec(Op::FindLinksFtt { q });
    let addrs: Vec<skep_address::Address> = match r {
        Response::Addrs { addrs, .. } => {
            if !settle_ack(out, xf, None) {
                return;
            }
            // Harness infrastructure out BEFORE either comparator: the
            // rig's setup grant (ruling 21) answers every FROM-constrained
            // or unconstrained query over a rig account's content, and a
            // count expectation has no α-binding step to drop it in.
            addrs.into_iter().filter(|a| !cx.rig.is_infra_addr(a)).collect()
        }
        other => {
            settle_ack(out, xf, rejection_code(&other));
            return;
        }
    };
    if !notes.is_empty() {
        out.note = Some(notes.join("; "));
    }
    // Expected addresses: the standard keys, then the phase-keyed forms the
    // delete scripts use (delete_all_with_links records its results under
    // before_delete / after_delete — round-5 item 8: those ARE recorded
    // expectations, never skipped).
    const PHASE_KEYS: &[&str] = &[
        "before_delete", "after_delete", "links_before", "links_after", "before", "after",
        "found",
    ];
    let expected = field(op, &["result", "links", "expected"])
        .and_then(Value::as_array)
        .or_else(|| {
            // All-string arrays only — a phase key holding span dicts is
            // observation data for other comparators, not an address list.
            field(op, PHASE_KEYS)
                .and_then(Value::as_array)
                .filter(|a| a.iter().all(|v| v.as_str().is_some()))
        });
    let Some(expected) = expected else {
        // Count expectations: bare fields, or a `{success, count}` object
        // under a phase key.
        let n = field(op, &["expected_count", "count"]).and_then(Value::as_u64).or_else(|| {
            field(op, PHASE_KEYS)
                .and_then(|v| v.get("count").or_else(|| v.get("expected_count")))
                .and_then(Value::as_u64)
        });
        if let Some(n) = n {
            out.comparator = Some("count".into());
            match compare_count(n, addrs.len(), grants, &mut out.adaptations) {
                Ok(()) => out.status = Status::Agreed,
                Err((e, a)) => {
                    out.status = Status::Disagreed;
                    out.expected = Some(e);
                    out.actual = Some(a);
                }
            }
            return;
        }
        out.status = Status::NotCompared;
        return;
    };
    let want: Vec<String> =
        expected.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    out.comparator = Some("address-set".into());
    let rig = &*cx.rig;
    let mut adaptations = std::mem::take(&mut out.adaptations);
    let verdict =
        compare_addr_sets(&want, &addrs, cx.alpha, |a| rig.is_infra_addr(a), &mut adaptations);
    out.adaptations = adaptations;
    match verdict {
        Ok(()) => out.status = Status::Agreed,
        Err((e, a)) => {
            out.status = Status::Disagreed;
            out.expected = Some(e);
            out.actual = Some(a);
        }
    }
}

/// A bare find_documents' aim: the source-role document first (the
/// discovery scripts track "which docs contain SOURCE's content" across
/// before/after probes — spanfilade/delete_all_transcluded_content,
/// discovery/find_documents_after_delete), then the register.
fn bare_find_documents_aim(cx: &mut Cx, op: &Value, out: &mut OpOutcome) -> Option<String> {
    if str_field(op, &["doc", "docid"]).is_some() {
        return cx.doc_arg(op, out, &["doc", "docid"]);
    }
    if let Some(d) = cx.shadow.find_named_containing("source") {
        out.adaptations.push("doc-from-register".into());
        cx.shadow.set_current(&d);
        return Some(d);
    }
    cx.doc_arg(op, out, &["doc", "docid"])
}

pub(super) fn h_find_documents(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    let xf = expected_failure(op);
    let mut regions: Vec<RegionSpec> = Vec::new();
    let mut ground_failed: Option<String> = None;
    // A search text whose live location is gone: FINDDOCSCONTAINING takes
    // V-regions only, so the I-coverage reach re-locates the doc's DELETED
    // bytes in whichever doc still holds the identity live (the
    // transclusion sharer) — ruling 10's mechanism for this op.
    let relocate = |cx: &mut Cx, out: &mut OpOutcome, needle: &str| -> Option<RegionSpec> {
        let l = locate(cx.shadow, None, needle)?;
        out.adaptations.push("i-coverage-search".into());
        let d = cx.alpha.translate(&l.doc)?;
        Some(RegionSpec { doc: d, spans: vspan(1, l.ord, l.width).into_iter().collect() })
    };
    if let Some(v) = field(op, &["specset", "specs", "search", "regions"]) {
        if let Some(arr) = v.as_array() {
            for item in arr {
                let Some((docid, spans)) = vspec_dict(item) else {
                    inexpressible(out, "find_documents spec list holds a non-vspec entry".into());
                    return;
                };
                let Some(d) = cx.alpha.translate(&docid) else {
                    out.status = Status::Disagreed;
                    out.comparator = Some("alpha".into());
                    out.note = Some(format!("find_documents doc {docid} unresolvable"));
                    return;
                };
                // Clamp query spans to the live extent (policy
                // `query-clamped-to-extent`; the compared RESULT is untouched).
                let text_len = cx.shadow.text_len(&docid);
                let mut clamped = false;
                let spans: Vec<skep_address::Span> = spans
                    .iter()
                    .filter_map(|(s, o, w)| {
                        if *w == 0 {
                            return None;
                        }
                        if *s == 1 {
                            if *o > text_len {
                                clamped = true;
                                return None;
                            }
                            let end = (*o + *w - 1).min(text_len);
                            if end < *o + *w - 1 {
                                clamped = true;
                            }
                            vspan(1, *o, end + 1 - *o)
                        } else {
                            vspan(*s, *o, *w)
                        }
                    })
                    .collect();
                if clamped {
                    out.adaptations.push("query-clamped-to-extent".into());
                }
                regions.push(RegionSpec { doc: d, spans });
            }
        } else if let Some(s) = v.as_str() {
            if s.contains("NOSPECS") || s == "empty" {
                out.adaptations.push("empty-specset".into());
                // regions stays empty — udanax's NOSPECS call.
            } else {
                match locate(cx.shadow, None, s) {
                    Some(l) => {
                        out.adaptations.push(l.how.into());
                        if let (Some(d), Some(span)) =
                            (cx.alpha.translate(&l.doc), vspan(1, l.ord, l.width))
                        {
                            regions.push(RegionSpec { doc: d, spans: vec![span] });
                        }
                    }
                    None => ground_failed = Some(format!("search {s:?} not groundable")),
                }
            }
        }
    } else if let Some(qt) = str_field(op, &["query", "search_text", "text"]) {
        match locate(cx.shadow, None, qt) {
            Some(l) => {
                out.adaptations.push(l.how.into());
                let Some(d) = cx.alpha.translate(&l.doc) else {
                    out.status = Status::Disagreed;
                    out.comparator = Some("alpha".into());
                    out.note = Some(format!("find_documents doc {} unresolvable", l.doc));
                    return;
                };
                let spans = vspan(1, l.ord, l.width).into_iter().collect();
                regions.push(RegionSpec { doc: d, spans });
            }
            None => {
                ground_failed = Some(format!(
                    "query {qt:?} not found in any live document (deleted content is reachable \
                     by I-history, but FINDDOCSCONTAINING takes V-regions)"
                ))
            }
        }
    } else if let Some(sd) = str_field(op, &["search_from", "search_doc", "search_document"])
        .and_then(|s| cx.shadow.resolve_doc(s))
    {
        // A search_from field names the DOC whose content is the query
        // (discovery/insert_vs_append_docispan names its docs "insert" and
        // "append").
        cx.shadow.set_current(&sd);
        let n = cx.shadow.text_len(&sd);
        if let (Some(d), Some(span)) = (cx.alpha.translate(&sd), vspan(1, 1, n)) {
            regions.push(RegionSpec { doc: d, spans: vec![span] });
        }
    } else if let Some(doc) = bare_find_documents_aim(cx, op, out) {
        let n = cx.shadow.text_len(&doc);
        if n == 0 {
            // The aimed doc is empty: the search the script repeated was
            // over content this doc has DELETED — reach it through the doc
            // that still holds the identity live (spanfilade/
            // delete_all_transcluded_content's post-delete find_documents).
            let mut relocated = false;
            for bytes in cx.deletions.bytes_of(&doc) {
                let needle = String::from_utf8_lossy(&bytes).into_owned();
                if let Some(r) = relocate(cx, out, &needle) {
                    regions.push(r);
                    relocated = true;
                    break;
                }
            }
            if !relocated {
                if let Some(d) = cx.alpha.translate(&doc) {
                    regions.push(RegionSpec { doc: d, spans: Vec::new() });
                }
            }
        } else if let Some(d) = cx.alpha.translate(&doc) {
            regions.push(RegionSpec { doc: d, spans: vspan(1, 1, n).into_iter().collect() });
        }
    }
    if let Some(reason) = ground_failed {
        if xf.is_some() {
            out.status = Status::Agreed;
            out.comparator = Some("expected-failure".into());
            out.note = Some(format!("{reason}; golden also recorded failure"));
        } else {
            inexpressible(out, format!("find_documents {reason}"));
        }
        return;
    }
    let r = cx.rig.exec(Op::FindDocsContaining { regions });
    let addrs = match r {
        Response::Addrs { addrs, .. } => {
            if !settle_ack(out, xf, None) {
                return;
            }
            addrs
        }
        other => {
            settle_ack(out, xf, rejection_code(&other));
            return;
        }
    };
    let Some(expected) = field(op, &["result", "docs", "expected"]).and_then(Value::as_array)
    else {
        out.status = Status::NotCompared;
        return;
    };
    let want: Vec<String> =
        expected.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    out.comparator = Some("address-set".into());
    let rig = &*cx.rig;
    let mut adaptations = std::mem::take(&mut out.adaptations);
    let verdict =
        compare_addr_sets(&want, &addrs, cx.alpha, |a| rig.is_infra_addr(a), &mut adaptations);
    out.adaptations = adaptations;
    match verdict {
        Ok(()) => out.status = Status::Agreed,
        Err((e, a)) => {
            out.status = Status::Disagreed;
            out.expected = Some(e);
            out.actual = Some(a);
        }
    }
}

pub(super) fn h_endsets(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    // Link-space query: the golden's slot vspecs are addressed to the LINK
    // itself ("search": "link address space" — links/link_retrieval_via_
    // endsets). udanax renders link endsets in the link's own V-space; skep
    // returns permanent I-spans via FOLLOWLINK — widths are the shared
    // structural vocabulary, so this comparator checks per-slot width
    // multisets (a representational difference in the address base, not a
    // loosening of the widths).
    let link_space = str_field(op, &["search"]).is_some_and(|s| s.contains("link"))
        || field(op, &["from", "source"])
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(|v| v.get("docid"))
            .and_then(Value::as_str)
            .is_some_and(is_link_address);
    if link_space {
        let link_golden = str_field(op, &["link", "link_id"])
            .map(str::to_string)
            .or_else(|| {
                field(op, &["from", "source"])
                    .and_then(Value::as_array)
                    .and_then(|a| a.first())
                    .and_then(|v| v.get("docid"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .or_else(|| cx.shadow.last_link.clone());
        let Some(link_golden) = link_golden else {
            inexpressible(out, "link-space endsets with no link in scope".into());
            return;
        };
        let Some(link) = cx.alpha.translate(&link_golden) else {
            out.status = Status::Disagreed;
            out.comparator = Some("alpha".into());
            out.note = Some(format!("endsets of unresolvable link {link_golden}"));
            return;
        };
        out.adaptations.push("endsets-as-followlink".into());
        let mut tally = Tally::default();
        for (slot_keys, slot) in
            [(&["from", "source"][..], 1usize), (&["to", "target"][..], 2)]
        {
            let Some(exp) = field(op, slot_keys) else { continue };
            let Some(want_specs) = slot_vspecs(&mut tally, slot, exp) else { continue };
            let mut want: Vec<u64> =
                want_specs.iter().flat_map(|(_, spans)| spans.iter().map(|(_, _, w)| *w)).collect();
            let mut got: Vec<u64> = Vec::new();
            match cx.rig.exec(Op::FollowLink { a: link.clone(), slot }) {
                Response::Follow { result: Ok(set), .. } => {
                    for sp in set.iter() {
                        let (_, w) = crate::tum::span_strings(sp);
                        if let Some(n) = parse_dotted(&w).and_then(|c| c.last().copied()) {
                            got.push(n);
                        }
                    }
                }
                Response::Follow { result: Err(_), .. } => {}
                r => {
                    tally.differ(
                        format!("slot{slot} widths"),
                        rejection_code(&r).unwrap_or_else(|| "?".into()),
                    );
                    continue;
                }
            }
            want.sort();
            got.sort();
            if want == got {
                tally.agree();
            } else {
                tally.differ(format!("slot{slot}:{want:?}"), format!("slot{slot}:{got:?}"));
            }
        }
        tally.settle(out, "endsets-follow-widths");
        return;
    }

    // Region query: an explicit search specset (first doc's spans) or the
    // whole extent of the doc in scope.
    let (doc, region): (String, Vec<skep_address::Span>) =
        if let Some(arr) = field(op, &["search", "specs", "specset"]).and_then(Value::as_array) {
            let vspecs: Option<Vec<_>> = arr.iter().map(vspec_dict).collect();
            let Some(vspecs) = vspecs else {
                inexpressible(out, "retrieve_endsets search holds a non-vspec entry".into());
                return;
            };
            let Some((docid, spans)) = vspecs.into_iter().next() else {
                inexpressible(out, "retrieve_endsets with an empty search".into());
                return;
            };
            (docid, spans.iter().filter_map(|(s, o, w)| vspan(*s, *o, *w)).collect())
        } else {
            let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
                inexpressible(out, "retrieve_endsets with no document in scope".into());
                return;
            };
            let n = cx.shadow.text_len(&doc);
            (doc.clone(), vspan(1, 1, n).into_iter().collect())
        };
    cx.shadow.set_current(&doc);
    let Some(d) = cx.skep_doc(&doc) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("retrieve_endsets doc {doc} unresolvable"));
        return;
    };
    let xf = expected_failure(op);
    let pairs = match cx.rig.exec(Op::RetrieveEndsets { d, region }) {
        Response::Endsets { pairs, .. } => {
            if !settle_ack(out, xf, None) {
                return;
            }
            pairs
        }
        other => {
            settle_ack(out, xf, rejection_code(&other));
            return;
        }
    };
    // Per-slot comparison. FROM/TO (operator ruling 11, policy
    // `endset-coverage-translated`): the golden records udanax's RESOLVED
    // V-specs in the query doc's coordinates while skep reports the STORED
    // endset (I-spans) — so the golden's (docid, V-span)s are mapped
    // through Image to I-coverage and compared coverage-for-coverage
    // (endsets/endsets_transcluded_source: the transcluder's V-span and the
    // source-homed I-span cover the same identity). The TYPE slot keeps the
    // (origin doc, width) shape — type names live in the harness types
    // document (policy type_registry), which coverage cannot speak.
    out.adaptations.push("type_registry".into());
    out.adaptations.push("endset-coverage-translated".into());
    // The corpus extension nests the slot expectations under a `result`
    // object ({from, to, three}); the legacy shape keys them top-level. The
    // `three` slot compares through the same coverage comparator — its
    // recorded spans are content spans (A8), and skep-side registry spans
    // are already excluded as harness infrastructure.
    let exp_root: &Value = match op.get("result") {
        Some(r)
            if r.as_object().is_some_and(|o| {
                ["from", "to", "three"].iter().any(|k| o.contains_key(*k))
            }) =>
        {
            r
        }
        _ => op,
    };
    let mut tally = Tally::default();
    for (slot_keys, slot) in [
        (&["from", "source"][..], 1usize),
        (&["to", "target"][..], 2),
        (&["three"][..], 3),
    ] {
        let Some(exp) = field(exp_root, slot_keys) else { continue };
        let Some(want_specs) = slot_vspecs(&mut tally, slot, exp) else { continue };
        // Golden side → I-coverage via the live image.
        let mut want_ranges: Vec<(String, u64, u64)> = Vec::new();
        for (docid, spans) in &want_specs {
            let (e, notes, _) = cx.image_endset(docid, spans);
            for n in notes {
                out.add_note(n);
            }
            for sp in e.spans() {
                if let Some(r) = elem_range(sp) {
                    want_ranges.push((r.0, r.1, r.1 + r.2));
                }
            }
        }
        // Skep side: the recorded endset spans, infrastructure spans (the
        // types doc, the rig homes, ruling 21's grant) excluded.
        let mut got_ranges: Vec<(String, u64, u64)> = Vec::new();
        for (i, e) in &pairs {
            if *i != slot {
                continue;
            }
            for sp in e.spans() {
                if let Ok(a) = skep_address::validate(sp.start().clone()) {
                    if cx.rig.is_infra_addr(&a) {
                        continue;
                    }
                }
                if let Some(r) = elem_range(sp) {
                    got_ranges.push((r.0, r.1, r.1 + r.2));
                }
            }
        }
        let want = merge_ranges(want_ranges);
        let got = merge_ranges(got_ranges);
        if want == got {
            tally.agree();
        } else {
            tally.differ(
                format!("slot{slot}:cov{}", render_ranges(&want)),
                format!("slot{slot}:cov{}", render_ranges(&got)),
            );
        }
    }
    // TYPE slot: (origin doc, width) multiset as before.
    if let Some(want_specs) = field(op, &["type"]).and_then(|exp| slot_vspecs(&mut tally, 3, exp)) {
        let mut want: Vec<(String, u64)> = want_specs
            .iter()
            .flat_map(|(docid, spans)| spans.iter().map(|(_, _, w)| (docid.clone(), *w)))
            .collect();
        let mut got: Vec<(String, u64)> = Vec::new();
        for (i, e) in &pairs {
            if *i != 3 {
                continue;
            }
            for sp in e.spans() {
                let Ok(a) = skep_address::validate(sp.start().clone()) else { continue };
                if cx.rig.is_infra_addr(&a) {
                    continue;
                }
                let doc = skep_address::document_of(&a)
                    .map(|d| cx.alpha.render_skep(&d))
                    .unwrap_or_else(|| "?".into());
                let w = parse_dotted(&crate::tum::tum_str(sp.width()))
                    .and_then(|c| c.last().copied())
                    .unwrap_or(0);
                got.push((doc, w));
            }
        }
        want.sort();
        got.sort();
        if want == got {
            tally.agree();
        } else {
            tally.differ(format!("slot3:{want:?}"), format!("slot3:{got:?}"));
        }
    }
    tally.settle(out, "endsets-coverage");
}

/// One slot's recorded endset, read as vspec dicts. A slot expectation that
/// is not a list, or an entry that is not a vspec, is a recorded part the
/// comparison cannot aim at — tallied as such, never dropped; `None` when
/// nothing of the slot is readable.
fn slot_vspecs(tally: &mut Tally, slot: usize, exp: &Value) -> Option<Vec<DocSpans>> {
    let Some(entries) = exp.as_array() else {
        tally.unaimed(format!("slot{slot} expectation {exp} is not a vspec list"));
        return None;
    };
    let mut specs = Vec::new();
    for v in entries {
        match vspec_dict(v) {
            Some(spec) => specs.push(spec),
            None => tally.unaimed(format!("slot{slot} entry {v} is not a vspec")),
        }
    }
    if specs.is_empty() && !entries.is_empty() {
        return None;
    }
    Some(specs)
}

/// Sort and merge element ranges (prefix, lo, hi-exclusive) — the coverage
/// normal form both endsets-coverage sides reduce to.
fn merge_ranges(mut ranges: Vec<(String, u64, u64)>) -> Vec<(String, u64, u64)> {
    ranges.sort();
    let mut out: Vec<(String, u64, u64)> = Vec::new();
    for (p, lo, hi) in ranges {
        if let Some(last) = out.last_mut() {
            if last.0 == p && lo <= last.2 {
                last.2 = last.2.max(hi);
                continue;
            }
        }
        out.push((p, lo, hi));
    }
    out
}

fn render_ranges(ranges: &[(String, u64, u64)]) -> String {
    let parts: Vec<String> =
        ranges.iter().map(|(p, lo, hi)| format!("{p}.{lo}+{}", hi - lo)).collect();
    format!("[{}]", parts.join(", "))
}
