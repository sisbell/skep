//! Link creation: `create_link` in the legacy recordings, whose endsets are
//! grounded in evidence order and then by the recording scripts'
//! conventions, and in the corpus extension's explicit-set shape, whose every
//! argument is recorded.

use serde_json::Value;

use skep_arrangement::VSpec;
use skep_febe::Response;

use super::{
    inexpressible, marker_type_name, parse_set_spans, settle_accepted, settle_unaccepted,
    side_specs, Cx, SetSpan,
};
use crate::evidence::Effect;
use crate::fields::{
    arrow_results, as_text, expected_failure, field, locate, note_arrow, op_name,
    parse_python_spec, str_field, strings_of, verb_of, vspec_dict, DocSpans, Verb,
};
use crate::outcome::{OpOutcome, Status};
use crate::shadow::ShadowLink;
use crate::tum::{link_home_docid, parse_vpos, VPoint, VRegion};

fn to_vspecs(cx: &mut Cx, sides: &[DocSpans]) -> Result<Vec<VSpec>, String> {
    let mut specs = Vec::new();
    for (docid, spans) in sides {
        let Some(sd) = cx.alpha.translate(docid) else {
            return Err(format!("endset doc {docid} never bound"));
        };
        for region in spans {
            if let Some(span) = region.span() {
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
    index: usize,
    link_golden: &str,
    want_source: bool,
    hint: Option<&str>,
    arrows: &[(String, String, String)],
    roles: Option<(&str, &str)>,
) -> Option<Vec<DocSpans>> {
    let ground = |v: &Value| -> Option<Vec<DocSpans>> {
        if let Some(arr) = v.as_array() {
            if let Some(vs) = arr.iter().map(vspec_dict).collect::<Option<Vec<_>>>() {
                return if vs.is_empty() { None } else { Some(vs) };
            }
        }
        if let Some(s) = v.as_str() {
            if let Some((Some(doc), spans)) = parse_python_spec(s) {
                let parsed: Vec<VRegion> = spans
                    .iter()
                    .filter_map(|(st, w)| Some(parse_vpos(st)?.region(crate::tum::parse_width(w)?)))
                    .collect();
                if !parsed.is_empty() {
                    return Some(vec![(doc, parsed)]);
                }
            }
        }
        // Content strings → located spans (hint doc first).
        let ss = strings_of(v)?;
        let mut sides: Vec<DocSpans> = Vec::new();
        for s in &ss {
            if s.is_empty() || as_text(std::slice::from_ref(s)).is_none() {
                return None;
            }
            let l = locate(cx.shadow, hint, s).or_else(|| locate(cx.shadow, None, s))?;
            sides.push(l.into_side());
        }
        (!sides.is_empty()).then_some(sides)
    };
    for op in &cx.ops[index + 1..] {
        let verb = verb_of(op);
        if verb.is_some_and(Verb::writes_content) {
            return None;
        }
        if matches!(verb, Some(Verb::FollowLink | Verb::Traverse)) {
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
            if op_name(op).to_ascii_lowercase().starts_with("follow") && mentions.unwrap_or(true) {
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
        if verb == Some(Verb::RetrieveEndsets) {
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
/// answer is recorded raw), and the third endset is either the udanax
/// type-marker (→ the type name the types document holds, policy
/// `threeset-marker→types-document`) or real content spans (→ the TYPE
/// endset via α, policy
/// `threeset-content-type`; green's content-span third endsets are
/// first-class, A8).
fn h_create_link_explicit(
    cx: &mut Cx,
    op: &Value,
    out: &mut OpOutcome,
    recorded_failure: Option<String>,
) {
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
                out.never_bound(format!("create_link {key}: doc {docid} never bound"));
                return Err(());
            };
            for sp in spans {
                match sp {
                    SetSpan::Plain(region) => {
                        if let Some(span) = region.span() {
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

    // THREE: empty stays empty; markers map through the types document;
    // content spans translate through α as the real TYPE endset.
    let ty: Vec<VSpec> = match op.get("threeset") {
        None => {
            out.adaptations.push("default_type_jump".into());
            out.adaptations.push("types_document".into());
            match cx.rig.type_vspec("jump") {
                Some(t) => vec![t],
                None => {
                    inexpressible(out, "types document capacity exhausted".into());
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
                                    out.adaptations
                                        .push("threeset-marker→types-document".into());
                                    out.adaptations.push("types_document".into());
                                    match cx.rig.type_vspec(name) {
                                        Some(t) => specs.push(t),
                                        None => {
                                            inexpressible(
                                                out,
                                                format!(
                                                    "types document capacity exhausted for \
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
                            SetSpan::Plain(region) => {
                                let Some(d) = cx.alpha.translate(docid) else {
                                    out.never_bound(format!(
                                        "create_link threeset: doc {docid} never bound"
                                    ));
                                    return;
                                };
                                out.adaptations.push("threeset-content-type".into());
                                if let Some(span) = region.span() {
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

    // Shadow endset triples (content subspace) for the shadow's links, which
    // traversal hops resolve from.
    let triples = |v: &Value| -> Vec<(String, u64, u64)> {
        parse_set_spans(v)
            .unwrap_or_default()
            .iter()
            .flat_map(|(d, spans)| {
                spans
                    .iter()
                    .filter_map(|sp| match sp {
                        SetSpan::Plain(VRegion { sub: 1, ord, width }) => {
                            Some((d.clone(), *ord, *width))
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    let link = golden.as_ref().map(|g| ShadowLink {
        golden: g.clone(),
        from: op.get("fromset").map(triples).unwrap_or_default(),
        to: op.get("toset").map(triples).unwrap_or_default(),
    });

    match cx.make_link(&home_golden, [from, to, ty], link, None, Effect::of(op)) {
        Err(_) => out.never_bound(format!("create_link home {home_golden} never bound")),
        Ok(Response::AckAddr { .. }) => {
            if !settle_accepted(out, recorded_failure) {
                return;
            }
            if golden.is_some() {
                out.agree("address-binding");
            } else {
                out.status = Status::NotCompared;
            }
        }
        Ok(other) => settle_unaccepted(out, recorded_failure, &other),
    }
}

pub(super) fn h_create_link(cx: &mut Cx, index: usize, op: &Value, out: &mut OpOutcome) {
    let recorded_failure = expected_failure(op);
    // The corpus-extension explicit-set shape short-circuits every legacy
    // grounding convention — the recordings carry all arguments.
    if op.get("fromset").is_some() || op.get("toset").is_some() || op.get("threeset").is_some() {
        h_create_link_explicit(cx, op, out, recorded_failure);
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
    let arrow_in_note = if arrows.is_empty() { note_arrow(op) } else { None };

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
    let mut made = 0usize;
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
            .or_else(|| arrow_in_note.as_ref().and_then(|(f, _)| cx.shadow.resolve_doc(f)))
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
            .or_else(|| arrow_in_note.as_ref().and_then(|(_, t)| cx.shadow.resolve_doc(t)))
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
                        out.adaptations.push(format!("text-located:source_text ({})", l.how.tag()));
                        from_sides.push(l.into_side());
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
                        out.adaptations.push(l.how.tag().into());
                        from_sides.push(l.into_side());
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
            .or_else(|| cx.shadow.current());
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
                        .or_else(|| cx.shadow.current());
                    if let Some(doc) = doc {
                        let regions = cx.transcluded_regions_golden(&doc);
                        if !regions.is_empty() {
                            out.adaptations.push("endset-from-transcluded-region".into());
                            let copied_in =
                                regions.iter().map(|&(o, w)| VPoint::content(o).region(w));
                            from_sides.push((doc, copied_in.collect()));
                        }
                    }
                } else if let Some(l) =
                    locate(cx.shadow, from_doc_hint.as_deref(), anchor)
                        .or_else(|| locate(cx.shadow, None, anchor))
                {
                    out.adaptations.push(format!("text-located:on ({})", l.how.tag()));
                    from_sides.push(l.into_side());
                }
            }
        }
        if from_sides.is_empty() {
            if let Some(d) = &from_doc_hint {
                let n = cx.shadow.text_len(d);
                if n > 0 {
                    out.adaptations.push("whole-extent".into());
                    from_sides.push((d.clone(), vec![VPoint::content(1).region(n)]));
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
                    let region = VPoint::content(ord).region(first_word.len() as u64);
                    from_sides.push((d, vec![region]));
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
                        out.adaptations.push(format!("text-located:target_text ({})", l.how.tag()));
                        to_sides.push(l.into_side());
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
                        out.adaptations.push(l.how.tag().into());
                        to_sides.push(l.into_side());
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
                    to_sides.push((d.clone(), vec![VPoint::content(1).region(n)]));
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
                    to_sides.push((t, vec![VPoint::content(1).region(n)]));
                }
                None => {
                    let n = cx.shadow.text_len(&home_golden);
                    if n > 0 {
                        out.adaptations.push("default_target_self".into());
                        to_sides.push((home_golden.clone(), vec![VPoint::content(1).region(n)]));
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
        out.adaptations.push("types_document".into());
        let Some(ty) = cx.rig.type_vspec(&ty_name) else {
            inexpressible(out, format!("types document capacity exhausted for `{ty_name}`"));
            return;
        };

        let from = match to_vspecs(cx, &from_sides) {
            Ok(v) => v,
            Err(e) => {
                out.never_bound(e);
                return;
            }
        };
        let to = match to_vspecs(cx, &to_sides) {
            Ok(v) => v,
            Err(e) => {
                out.never_bound(e);
                return;
            }
        };
        // The shadow's links: this link's grounded endsets (content
        // subspace), for hop resolution from the world.
        let flat = |sides: &[DocSpans]| -> Vec<(String, u64, u64)> {
            sides
                .iter()
                .flat_map(|(d, regions)| {
                    regions
                        .iter()
                        .filter(|r| r.sub == 1)
                        .map(|r| (d.clone(), r.ord, r.width))
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        let link = golden.as_ref().map(|g| ShadowLink {
            golden: g.clone(),
            from: flat(&from_sides),
            to: flat(&to_sides),
        });
        match cx.make_link(&home_golden, [from, to, vec![ty]], link, arrow, Effect::of(op)) {
            Err(_) => {
                out.never_bound(format!("create_link home {home_golden} never bound"));
                return;
            }
            Ok(Response::AckAddr { .. }) => made += 1,
            Ok(other) => {
                settle_unaccepted(out, recorded_failure, &other);
                return;
            }
        }
    }
    if !settle_accepted(out, recorded_failure) {
        return;
    }
    if made == 0 || goldens.is_empty() {
        out.status = Status::NotCompared;
        out.note = Some("create_link with no recorded result to bind".into());
    } else {
        out.agree("address-binding");
    }
}

/// The link type name: a `type`/`link_type` string, or a golden type vspec
/// into udanax's link types document (client.py's LINK_TYPES_DOC: local
/// 2.2=jump, 2.3=quote, 2.6=footnote, 2.6.2=margin).
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
        let (_, regions) = vspec_dict(item)?;
        for r in regions {
            if r.sub == 2 {
                return Some(
                    match r.ord {
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
