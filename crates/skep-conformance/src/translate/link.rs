//! Link creation: `create_link` in the legacy recordings, whose endsets are
//! grounded in evidence order and then by the recording scripts'
//! conventions, and in the corpus extension's explicit-set shape, whose every
//! argument is recorded.

use serde_json::Value;

use skep_arrangement::VSpec;
use skep_febe::{Op, Response, SlotArg};

use super::{
    inexpressible, marker_type_name, parse_set_spans, rejection_code, settle_ack, side_specs, Cx,
    SetSpan,
};
use crate::fields::{
    arrow_results, expect_strings, expected_failure, field, label_of, locate, note_arrow,
    parse_python_spec, str_field, vspec_dict, DocSpans,
};
use crate::outcome::{OpOutcome, Status};
use crate::tum::{link_home_docid, parse_dotted, parse_vpos, vspan};

fn to_vspecs(cx: &mut Cx, sides: &[DocSpans]) -> Result<Vec<VSpec>, String> {
    let mut specs = Vec::new();
    for (docid, spans) in sides {
        let Some(sd) = cx.alpha.translate(docid) else {
            return Err(format!("endset doc {docid} unresolvable"));
        };
        for (sub, ord, w) in spans {
            if let Some(span) = vspan(*sub, *ord, *w) {
                specs.push(VSpec { source: sd.clone(), span });
            }
        }
    }
    Ok(specs)
}

/// Forward evidence for a link endset: the first LATER recorded
/// follow/endsets/traverse result for this link id, accepted only if no
/// write op intervenes (positions recorded then are positions now).
/// Vspec-shaped results carry (doc, spans) directly; content-string results
/// are LOCATED in the shadow — `hint` narrows the search to the side's
/// known doc first, so star_hub's three follows recording the same
/// "Target document" each pin their own peripheral. `arrows` are the
/// create op's own arrow results, letting step-keyed traverse entries name
/// the link; `roles` are the create op's raw from/to strings, letting a
/// role-keyed traverse hop ({from: "A", to: "B", text} / {step: "A->B",
/// text}) pin the TO side — the hop's `text` is the LANDING content, so
/// role matching never grounds a FROM side. Empty recorded evidence
/// (`target: []`) is never used — an empty endset is not expressible to
/// MakeLink.
fn endset_evidence(
    cx: &Cx,
    from_index: usize,
    link_golden: &str,
    want_source: bool,
    hint: Option<&str>,
    arrows: &[(String, String, String)],
    roles: Option<(&str, &str)>,
) -> Option<Vec<DocSpans>> {
    let writes = ["insert", "delete", "remove", "vcopy", "copy", "pivot", "swap", "rearrange"];
    let ground = |v: &Value| -> Option<Vec<DocSpans>> {
        if let Some(arr) = v.as_array() {
            if let Some(vs) = arr.iter().map(vspec_dict).collect::<Option<Vec<_>>>() {
                return if vs.is_empty() { None } else { Some(vs) };
            }
        }
        if let Some(s) = v.as_str() {
            if let Some((Some(doc), spans)) = parse_python_spec(s) {
                let parsed: Vec<(u64, u64, u64)> = spans
                    .iter()
                    .filter_map(|(st, w)| {
                        let (sub, ord) = parse_vpos(st)?;
                        Some((sub, ord, crate::tum::parse_width(w)?))
                    })
                    .collect();
                if !parsed.is_empty() {
                    return Some(vec![(doc, parsed)]);
                }
            }
        }
        // Content strings → located spans (hint doc first).
        let ss = expect_strings(v)?;
        let mut sides: Vec<DocSpans> = Vec::new();
        for s in &ss {
            if s.is_empty() || (s.contains('.') && parse_dotted(s).is_some()) {
                return None;
            }
            let l = locate(cx.shadow, hint, s).or_else(|| locate(cx.shadow, None, s))?;
            sides.push((l.doc, vec![(1, l.ord, l.width)]));
        }
        (!sides.is_empty()).then_some(sides)
    };
    for op in &cx.ops[from_index + 1..] {
        let label = label_of(op).to_ascii_lowercase();
        if writes.iter().any(|w| label.starts_with(w)) {
            return None;
        }
        let follow_like = label.starts_with("follow")
            || label.starts_with("traverse")
            || label.contains("traversal");
        if follow_like {
            // Entry lists ({link|step, target_text|source_text|text}).
            for key in ["results", "path", "traversal", "steps", "result"] {
                let Some(entries) = field(op, &[key]).and_then(Value::as_array) else { continue };
                for e in entries {
                    let by_link = e.get("link").and_then(Value::as_str) == Some(link_golden);
                    let by_step = e
                        .get("step")
                        .and_then(Value::as_str)
                        .and_then(|s| s.split_once("->"))
                        .and_then(|(f, t)| {
                            arrows
                                .iter()
                                .find(|(af, at, _)| af == f.trim() && at == t.trim())
                                .map(|(_, _, r)| r.as_str())
                        })
                        == Some(link_golden);
                    // Role match — TO side only (see doc comment): the
                    // entry's from/to (or step "F->T" / landing step "T…")
                    // equals this create's own role strings.
                    let by_roles = !want_source
                        && roles.is_some_and(|(fr, tr)| {
                            let ef = e.get("from").and_then(Value::as_str).map(str::trim);
                            let et = e
                                .get("to")
                                .and_then(Value::as_str)
                                .and_then(|t| t.split_whitespace().next());
                            if ef == Some(fr) && et == Some(tr) {
                                return true;
                            }
                            match e.get("step").and_then(Value::as_str) {
                                Some(s) => match s.split_once("->") {
                                    Some((f, t)) => {
                                        f.trim() == fr
                                            && t.split_whitespace().next() == Some(tr)
                                    }
                                    None => s.split_whitespace().next() == Some(tr),
                                },
                                None => false,
                            }
                        });
                    if !(by_link || by_step || by_roles) {
                        continue;
                    }
                    let keys: &[&str] = if want_source {
                        &["source_text", "text"]
                    } else {
                        &["target_text", "text", "content"]
                    };
                    for k in keys {
                        if let Some(sides) = e.get(*k).and_then(ground) {
                            return Some(sides);
                        }
                    }
                }
            }
            // Plain follow with (or without — the bare-follow convention) a
            // link field.
            let mentions = str_field(op, &["link", "link_id", "id"]).map(|l| l == link_golden);
            if label.starts_with("follow") && mentions.unwrap_or(true) {
                let slot_matches = match str_field(op, &["end", "direction", "linkend", "which"]) {
                    Some(e) if e.contains("->") => !want_source,
                    Some(e) => {
                        (want_source && e.contains("source"))
                            || (!want_source && e.contains("target"))
                    }
                    None => want_source, // bare follow records the SOURCE end
                };
                if slot_matches {
                    if let Some(sides) = field(op, &["result"]).and_then(ground) {
                        return Some(sides);
                    }
                }
            }
        }
        if label.starts_with("retrieve_endsets") || label.starts_with("endsets") {
            let keys: &[&str] = if want_source { &["source", "from"] } else { &["target", "to"] };
            if let Some(arr) = field(op, keys).and_then(Value::as_array) {
                let vspecs: Option<Vec<_>> = arr.iter().map(vspec_dict).collect();
                if let Some(v) = vspecs.filter(|v| !v.is_empty()) {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// The corpus-extension create_link shape (MANIFEST-NEW recordings): explicit
/// `home` plus `fromset`/`toset`/`threeset` vspec-dict lists, every argument
/// machine-groundable. None of the legacy default-endset conventions apply:
/// an explicitly EMPTY list goes to MakeLink empty (policy
/// `explicit-empty-endset` — green accepts all three empty, A11, and skep's
/// verdict is recorded raw), and the third endset is either the udanax
/// type-marker (→ the registry name, policy `threeset-marker→registry`) or
/// real content spans (→ the TYPE endset via α, policy
/// `threeset-content-type`; green's content-span third endsets are
/// first-class, A8).
fn h_create_link_explicit(cx: &mut Cx, op: &Value, out: &mut OpOutcome, xf: Option<String>) {
    let golden = str_field(op, &["result", "link_id"]).map(str::to_string);

    // FROM / TO: α-translated V-specs; marker spans do not belong here.
    let build_side = |cx: &mut Cx, out: &mut OpOutcome, key: &str| -> Result<Option<Vec<VSpec>>, ()> {
        let Some(v) = op.get(key) else { return Ok(None) };
        let sides = match parse_set_spans(v) {
            Ok(s) => s,
            Err(e) => {
                inexpressible(out, format!("create_link {key}: {e}"));
                return Err(());
            }
        };
        if sides.is_empty() {
            out.adaptations.push("explicit-empty-endset".into());
            return Ok(Some(Vec::new()));
        }
        let mut specs = Vec::new();
        for (docid, spans) in &sides {
            let Some(d) = cx.alpha.translate(docid) else {
                out.status = Status::Disagreed;
                out.comparator = Some("alpha".into());
                out.note = Some(format!("create_link {key}: doc {docid} unresolvable"));
                return Err(());
            };
            for sp in spans {
                match sp {
                    SetSpan::Plain(s, ord, w) => {
                        if let Some(span) = vspan(*s, *ord, *w) {
                            specs.push(VSpec { source: d.clone(), span });
                        }
                    }
                    SetSpan::Marker(comps) => {
                        inexpressible(
                            out,
                            format!(
                                "create_link {key}: marker-form span {comps:?} outside the \
                                 type slot"
                            ),
                        );
                        return Err(());
                    }
                }
            }
        }
        Ok(Some(specs))
    };
    let from = match build_side(cx, out, "fromset") {
        Ok(v) => v.unwrap_or_default(),
        Err(()) => return,
    };
    let to = match build_side(cx, out, "toset") {
        Ok(v) => v.unwrap_or_default(),
        Err(()) => return,
    };

    // THREE: empty stays empty; markers map through the registry; content
    // spans translate through α as the real TYPE endset.
    let ty: Vec<VSpec> = match op.get("threeset") {
        None => {
            out.adaptations.push("default_type_jump".into());
            out.adaptations.push("type_registry".into());
            match cx.rig.type_vspec("jump") {
                Some(t) => vec![t],
                None => {
                    inexpressible(out, "type registry capacity exhausted".into());
                    return;
                }
            }
        }
        Some(v) => {
            let sides = match parse_set_spans(v) {
                Ok(s) => s,
                Err(e) => {
                    inexpressible(out, format!("create_link threeset: {e}"));
                    return;
                }
            };
            if sides.is_empty() {
                out.adaptations.push("explicit-empty-endset".into());
                Vec::new()
            } else {
                let mut specs = Vec::new();
                for (docid, spans) in &sides {
                    for sp in spans {
                        match sp {
                            SetSpan::Marker(comps) => match marker_type_name(comps) {
                                Some(name) => {
                                    out.adaptations.push("threeset-marker→registry".into());
                                    out.adaptations.push("type_registry".into());
                                    match cx.rig.type_vspec(name) {
                                        Some(t) => specs.push(t),
                                        None => {
                                            inexpressible(
                                                out,
                                                format!(
                                                    "type registry capacity exhausted for \
                                                     `{name}`"
                                                ),
                                            );
                                            return;
                                        }
                                    }
                                }
                                None => {
                                    inexpressible(
                                        out,
                                        format!(
                                            "threeset marker {comps:?} is not a known udanax \
                                             type address"
                                        ),
                                    );
                                    return;
                                }
                            },
                            SetSpan::Plain(s, ord, w) => {
                                let Some(d) = cx.alpha.translate(docid) else {
                                    out.status = Status::Disagreed;
                                    out.comparator = Some("alpha".into());
                                    out.note = Some(format!(
                                        "create_link threeset: doc {docid} unresolvable"
                                    ));
                                    return;
                                };
                                out.adaptations.push("threeset-content-type".into());
                                if let Some(span) = vspan(*s, *ord, *w) {
                                    specs.push(VSpec { source: d, span });
                                }
                            }
                        }
                    }
                }
                specs
            }
        }
    };

    // HOME: the explicit field, else the recorded result's own prefix.
    let home_golden = str_field(op, &["home", "home_doc"])
        .map(str::to_string)
        .or_else(|| golden.as_ref().and_then(|g| link_home_docid(g)));
    let Some(home_golden) = home_golden else {
        inexpressible(out, "explicit-set create_link with no home".into());
        return;
    };
    let Some(home) = cx.alpha.translate(&home_golden) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("create_link home {home_golden} unresolvable"));
        return;
    };

    // Shadow endset triples (content subspace) for the traversal registry —
    // recorded before the vecs move into the request.
    let triples = |v: &Value| -> Vec<(String, u64, u64)> {
        parse_set_spans(v)
            .unwrap_or_default()
            .iter()
            .flat_map(|(d, spans)| {
                spans
                    .iter()
                    .filter_map(|sp| match sp {
                        SetSpan::Plain(1, o, w) => Some((d.clone(), *o, *w)),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    let from_triples = op.get("fromset").map(triples).unwrap_or_default();
    let to_triples = op.get("toset").map(triples).unwrap_or_default();

    match cx.rig.exec(Op::MakeLink {
        home,
        from: SlotArg::Resolve(from),
        to: SlotArg::Resolve(to),
        ty: SlotArg::Resolve(ty),
        replaces: None,
    }) {
        Response::AckAddr { addr, .. } => {
            if !settle_ack(out, xf, None) {
                return;
            }
            cx.shadow.seat_link(&home_golden);
            cx.shadow.set_current(&home_golden);
            if let Some(g) = &golden {
                cx.alpha.bind(g, &addr);
                cx.shadow.last_link = Some(g.clone());
                cx.shadow.record_link(g, from_triples, to_triples);
                out.status = Status::Agreed;
                out.comparator = Some("address-binding".into());
            } else {
                out.status = Status::NotCompared;
            }
        }
        other => {
            settle_ack(out, xf, rejection_code(&other));
        }
    }
}

pub(super) fn h_create_link(cx: &mut Cx, index: usize, op: &Value, out: &mut OpOutcome) {
    let xf = expected_failure(op);
    // The corpus-extension explicit-set shape short-circuits every legacy
    // grounding convention — the recordings carry all arguments.
    if op.get("fromset").is_some() || op.get("toset").is_some() || op.get("threeset").is_some() {
        h_create_link_explicit(cx, op, out, xf);
        return;
    }
    // Result ids: result/results/link_id fields, or arrow keys ("A->B": link).
    let arrows = arrow_results(op);
    let goldens: Vec<String> = match field(op, &["result", "results", "link_id"]) {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => {
            a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
        }
        _ => arrows.iter().map(|(_, _, r)| r.clone()).collect(),
    };
    if goldens.len() > 1 {
        out.adaptations.push("create_links:repeat".into());
    }
    // Arrow roles carried in a note/comment value ("doc1 -> doc4" —
    // find_links_homedocids_multiple) stand in when no arrow keys exist.
    let narrow = if arrows.is_empty() { note_arrow(op) } else { None };

    // Group endsets for plural creates (star_hub, selective_removal): a
    // from/to string is a GROUP reference when its singular members exist
    // as named docs — link k then runs member-k to member-k. Detected by
    // membership, not by resolution failure: "peripherals" fuzzy-resolves
    // to peripherals1, which round 2 wrongly aimed every link at.
    let group_of = |cx: &Cx, s: &str| -> Option<String> {
        let sing = s.trim_end_matches('s');
        let m1 = cx.shadow.resolve_doc(&format!("{sing}1"));
        let m2 = cx.shadow.resolve_doc(&format!("{sing}2"));
        (m1.is_some() && m2.is_some() && m1 != m2).then(|| sing.to_string())
    };
    let from_group = str_field(op, &["from", "source"]).and_then(|s| group_of(cx, s));
    let to_group = str_field(op, &["to", "target"]).and_then(|s| group_of(cx, s));
    // The create's raw from/to strings, as role names for role-keyed
    // traverse-hop evidence (endset_evidence's `roles`).
    let roles: Option<(&str, &str)> = match (
        str_field(op, &["from", "source"]),
        str_field(op, &["to", "target"]),
    ) {
        (Some(f), Some(t)) => Some((f, t)),
        _ => None,
    };

    let count = goldens.len().max(1);
    let mut bound = 0usize;
    for k in 0..count {
        let golden = goldens.get(k).cloned();
        let arrow = arrows.get(k).cloned().or_else(|| {
            golden.as_ref().and_then(|g| {
                arrows.iter().find(|(_, _, r)| r == g).cloned()
            })
        });

        // Per-side doc hints: arrow doc, note-arrow doc, group member k,
        // explicit doc-ref string — the doc a side lives in when only a
        // doc (not a span) is known.
        let member = |cx: &Cx, g: &Option<String>| -> Option<String> {
            let g = g.as_ref()?;
            cx.shadow
                .resolve_doc(&format!("{g}{}", k + 1))
                .or_else(|| cx.shadow.resolve_doc(&format!("{g}s{}", k + 1)))
        };
        let from_doc_hint: Option<String> = arrow
            .as_ref()
            .and_then(|(f, _, _)| cx.shadow.resolve_doc(f))
            .or_else(|| narrow.as_ref().and_then(|(f, _)| cx.shadow.resolve_doc(f)))
            .or_else(|| member(cx, &from_group))
            .or_else(|| {
                if from_group.is_some() {
                    return None;
                }
                str_field(op, &["source", "from"]).and_then(|s| cx.shadow.resolve_doc(s))
            });
        let to_doc_hint: Option<String> = arrow
            .as_ref()
            .and_then(|(_, t, _)| cx.shadow.resolve_doc(t))
            .or_else(|| narrow.as_ref().and_then(|(_, t)| cx.shadow.resolve_doc(t)))
            .or_else(|| member(cx, &to_group))
            .or_else(|| {
                if to_group.is_some() {
                    return None;
                }
                str_field(op, &["target", "to"]).and_then(|s| cx.shadow.resolve_doc(s))
            });

        // FROM side, in evidence order: explicit vspec arrays; source_text
        // located (hint doc first); a from-string that is TEXT, not a doc;
        // forward evidence; the hint doc's whole extent; the scripts'
        // first-word convention on the home.
        let mut from_sides: Vec<DocSpans> = Vec::new();
        if let Some(v) = field(op, &["source", "from", "source_spans"]).filter(|v| !v.is_string())
        {
            match side_specs(cx, out, v) {
                Ok(s) => from_sides = s,
                Err(e) => {
                    inexpressible(out, format!("create_link source: {e}"));
                    return;
                }
            }
        }
        if from_sides.is_empty() {
            if let Some(t) = str_field(op, &["source_text"]) {
                match locate(cx.shadow, from_doc_hint.as_deref(), t)
                    .or_else(|| locate(cx.shadow, None, t))
                {
                    Some(l) => {
                        out.adaptations.push(format!("text-located:source_text ({})", l.how));
                        from_sides.push((l.doc, vec![(1, l.ord, l.width)]));
                    }
                    None => {
                        inexpressible(out, format!("create_link source: text {t:?} not found"));
                        return;
                    }
                }
            }
        }
        if from_sides.is_empty() && from_group.is_none() {
            if let Some(s) = str_field(op, &["source", "from"]) {
                // A bracket range ("doc1[1.2-1.4]") is a REGION description,
                // never a bare doc reference — locate wins over the fuzzy
                // doc-hint containment match.
                if from_doc_hint.is_none() || s.contains('[') {
                    if let Some(l) = locate(cx.shadow, None, s) {
                        out.adaptations.push(l.how.into());
                        from_sides.push((l.doc, vec![(1, l.ord, l.width)]));
                    }
                }
            }
        }
        // Home: the recorded result's own prefix is authoritative.
        let home_golden = golden
            .as_ref()
            .and_then(|g| link_home_docid(g))
            .or_else(|| str_field(op, &["home_doc", "home"]).and_then(|s| cx.shadow.resolve_doc(s)))
            .or_else(|| from_doc_hint.clone())
            .or_else(|| from_sides.first().map(|(d, _)| d.clone()))
            .or_else(|| cx.shadow.resolve_doc("source"))
            .or_else(|| cx.shadow.scoped());
        let Some(home_golden) = home_golden else {
            inexpressible(out, "create_link with no home document in scope".into());
            return;
        };
        if from_sides.is_empty() {
            if let Some(g) = &golden {
                if let Some(ev) = endset_evidence(
                    cx,
                    index,
                    g,
                    true,
                    from_doc_hint.as_deref(),
                    &arrows,
                    roles,
                ) {
                    out.adaptations.push("endset-evidence".into());
                    from_sides = ev;
                }
            }
        }
        // An `on`/`over`/`anchor` field describes the FROM anchor: either
        // literal text to locate, or "transcluded content"-style wording
        // that names the home doc's foreign-origin (copied-in) regions
        // (policy `endset-from-transcluded-region`; interactions/
        // link_to_transcluded_then_version, version_transcluded_linked_
        // content calibrate both forms).
        if from_sides.is_empty() {
            if let Some(anchor) = str_field(op, &["on", "over", "anchor"]) {
                if anchor.contains("transclu") {
                    let doc = golden
                        .as_ref()
                        .and_then(|g| link_home_docid(g))
                        .or_else(|| cx.shadow.scoped());
                    if let Some(doc) = doc {
                        let regions = cx.transcluded_regions_golden(&doc);
                        if !regions.is_empty() {
                            out.adaptations.push("endset-from-transcluded-region".into());
                            from_sides.push((
                                doc,
                                regions.iter().map(|(o, w)| (1, *o, *w)).collect(),
                            ));
                        }
                    }
                } else if let Some(l) =
                    locate(cx.shadow, from_doc_hint.as_deref(), anchor)
                        .or_else(|| locate(cx.shadow, None, anchor))
                {
                    out.adaptations.push(format!("text-located:on ({})", l.how));
                    from_sides.push((l.doc, vec![(1, l.ord, l.width)]));
                }
            }
        }
        if from_sides.is_empty() {
            if let Some(d) = &from_doc_hint {
                let n = cx.shadow.text_len(d);
                if n > 0 {
                    out.adaptations.push("whole-extent".into());
                    from_sides.push((d.clone(), vec![(1, 1, n)]));
                }
            }
        }
        if from_sides.is_empty() {
            let text = cx.shadow.text_string(&home_golden);
            let first_word: String =
                text.split_whitespace().next().unwrap_or_default().to_string();
            if let Some((d, ord)) = cx.shadow.find_text(Some(&home_golden), &first_word) {
                if !first_word.is_empty() {
                    out.adaptations.push("default_source_first_word".into());
                    from_sides.push((d, vec![(1, ord, first_word.len() as u64)]));
                }
            }
            if from_sides.is_empty() {
                inexpressible(out, "create_link source: nothing to ground the FROM endset".into());
                return;
            }
        }

        // TO side, same order; the tail defaults are the target-role doc's
        // whole extent, then self (a single-doc scenario self-links —
        // three_links_vspan_growth has only one document).
        let mut to_sides: Vec<DocSpans> = Vec::new();
        if let Some(v) = field(op, &["target", "to", "target_spans"]).filter(|v| !v.is_string()) {
            match side_specs(cx, out, v) {
                Ok(s) => to_sides = s,
                Err(e) => {
                    inexpressible(out, format!("create_link target: {e}"));
                    return;
                }
            }
        }
        if to_sides.is_empty() {
            if let Some(t) = str_field(op, &["target_text"]) {
                match locate(cx.shadow, to_doc_hint.as_deref(), t)
                    .or_else(|| locate(cx.shadow, None, t))
                {
                    Some(l) => {
                        out.adaptations.push(format!("text-located:target_text ({})", l.how));
                        to_sides.push((l.doc, vec![(1, l.ord, l.width)]));
                    }
                    None => {
                        inexpressible(out, format!("create_link target: text {t:?} not found"));
                        return;
                    }
                }
            }
        }
        if to_sides.is_empty() && to_group.is_none() {
            if let Some(s) = str_field(op, &["target", "to"]) {
                // Same bracket-range-over-doc-hint rule as the FROM side.
                if to_doc_hint.is_none() || s.contains('[') {
                    if let Some(l) = locate(cx.shadow, None, s) {
                        out.adaptations.push(l.how.into());
                        to_sides.push((l.doc, vec![(1, l.ord, l.width)]));
                    }
                }
            }
        }
        if to_sides.is_empty() {
            if let Some(g) = &golden {
                if let Some(ev) = endset_evidence(
                    cx,
                    index,
                    g,
                    false,
                    to_doc_hint.as_deref(),
                    &arrows,
                    roles,
                ) {
                    out.adaptations.push("endset-evidence".into());
                    to_sides = ev;
                }
            }
        }
        if to_sides.is_empty() {
            if let Some(d) = &to_doc_hint {
                let n = cx.shadow.text_len(d);
                if n > 0 {
                    out.adaptations.push("whole-extent".into());
                    to_sides.push((d.clone(), vec![(1, 1, n)]));
                }
            }
        }
        if to_sides.is_empty() {
            let tgt = cx
                .shadow
                .resolve_doc("target")
                .filter(|t| Some(t) != from_sides.first().map(|(d, _)| d))
                .filter(|t| cx.shadow.text_len(t) > 0);
            match tgt {
                Some(t) => {
                    out.adaptations.push("default_target_whole_doc".into());
                    let n = cx.shadow.text_len(&t);
                    to_sides.push((t, vec![(1, 1, n)]));
                }
                None => {
                    let n = cx.shadow.text_len(&home_golden);
                    if n > 0 {
                        out.adaptations.push("default_target_self".into());
                        to_sides.push((home_golden.clone(), vec![(1, 1, n)]));
                    } else {
                        inexpressible(
                            out,
                            "create_link target: nothing to ground the TO endset".into(),
                        );
                        return;
                    }
                }
            }
        }

        // TYPE.
        let ty_name = link_type_name(op).unwrap_or_else(|| {
            out.adaptations.push("default_type_jump".into());
            "jump".to_string()
        });
        out.adaptations.push("type_registry".into());
        let Some(ty) = cx.rig.type_vspec(&ty_name) else {
            inexpressible(out, format!("type registry capacity exhausted for `{ty_name}`"));
            return;
        };

        let from = match to_vspecs(cx, &from_sides) {
            Ok(v) => v,
            Err(e) => {
                out.status = Status::Disagreed;
                out.comparator = Some("alpha".into());
                out.note = Some(e);
                return;
            }
        };
        let to = match to_vspecs(cx, &to_sides) {
            Ok(v) => v,
            Err(e) => {
                out.status = Status::Disagreed;
                out.comparator = Some("alpha".into());
                out.note = Some(e);
                return;
            }
        };
        let Some(home) = cx.skep_doc(&home_golden) else {
            out.status = Status::Disagreed;
            out.comparator = Some("alpha".into());
            out.note = Some(format!("create_link home {home_golden} unresolvable"));
            return;
        };
        let r = cx.rig.exec(Op::MakeLink {
            home,
            from: SlotArg::Resolve(from),
            to: SlotArg::Resolve(to),
            ty: SlotArg::Resolve(vec![ty]),
            replaces: None,
        });
        match r {
            Response::AckAddr { addr, .. } => {
                cx.shadow.seat_link(&home_golden);
                cx.shadow.set_current(&home_golden);
                if let Some(g) = &golden {
                    cx.alpha.bind(g, &addr);
                    cx.shadow.last_link = Some(g.clone());
                    // The traversal registry: this link's grounded endsets
                    // (content subspace), for hop resolution from the world.
                    let flat = |sides: &[DocSpans]| -> Vec<(String, u64, u64)> {
                        sides
                            .iter()
                            .flat_map(|(d, spans)| {
                                spans
                                    .iter()
                                    .filter(|(s, _, _)| *s == 1)
                                    .map(|(_, o, w)| (d.clone(), *o, *w))
                                    .collect::<Vec<_>>()
                            })
                            .collect()
                    };
                    cx.shadow.record_link(g, flat(&from_sides), flat(&to_sides));
                }
                if let Some((f, t, rr)) = &arrow {
                    cx.shadow.arrow_links.insert((f.clone(), t.clone()), rr.clone());
                }
                bound += 1;
            }
            other => {
                settle_ack(out, xf, rejection_code(&other));
                return;
            }
        }
    }
    if !settle_ack(out, xf, None) {
        return;
    }
    if bound == 0 || goldens.is_empty() {
        out.status = Status::NotCompared;
        out.note = Some("create_link with no recorded result to bind".into());
    } else {
        out.status = Status::Agreed;
        out.comparator = Some("address-binding".into());
    }
}

/// The link type name: a `type`/`link_type` string, or a golden type vspec
/// into udanax's registry doc (client.py: local 2.2=jump, 2.3=quote,
/// 2.6=footnote, 2.6.2=margin).
fn link_type_name(op: &Value) -> Option<String> {
    if let Some(s) = str_field(op, &["type", "link_type"]) {
        if !matches!(s, "" | "none" | "all") {
            return Some(s.to_string());
        }
        return None;
    }
    let v = field(op, &["type", "typespecs"])?;
    let arr = v.as_array()?;
    for item in arr {
        let (_, spans) = vspec_dict(item)?;
        for (sub, ord, _) in spans {
            if sub == 2 {
                return Some(
                    match ord {
                        2 => "jump",
                        3 => "quote",
                        6 => "footnote",
                        _ => "margin",
                    }
                    .to_string(),
                );
            }
        }
    }
    None
}
