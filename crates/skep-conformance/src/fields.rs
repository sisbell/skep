//! Shared field-bag parsing: the one place golden JSON fields, decorated
//! descriptions, and recorded span shapes are interpreted. Both the grounding
//! pre-pass and the live translator read through these helpers, so the two
//! passes cannot drift on what a field means.
//!
//! Decoration grammar (each form calibrated against named golden files):
//! * `"end"` / `"start"` / `"position 6"` / `"after First"` — positions
//!   (internal/insert_only_baseline, versions/version_insert_in_middle,
//!   discovery/insert_multiple_times_accumulates_docispan).
//! * `"1.1 length 3"` — span (edgecases/delete_first_char,
//!   delete_all/delete_all_incrementally).
//! * `"quick (5-9)"` / `"ABCD (1-4)"` — text with inclusive ordinal range
//!   (content/retrieve_noncontiguous_spans, edgecases/overlapping_vcopy).
//! * `"1-char span at 1.1"` — width + position (edgecases/
//!   link_zero_width_endpoints).
//! * `"just 'S'"` / `"first occurrence of 'text' (1.10-1.13)"` — quoted text
//!   (edgecases/vcopy_single_char, internal/internal_transclusion_with_link).
//! * `"source:here"` — doc-qualified text (versions/version_with_links).
//! * `"doc1[1.2-1.4]"` — doc-qualified range (subspace/
//!   insert_text_check_link_positions).
//! * `"all of B"` / `"all"` / `"full document"` — whole extent (content/
//!   nested_vcopy, spanfilade/delete_all_transcluded_content,
//!   links/overlapping_links).
//! * `"bank (first)"` / `"shared (transcluded)"` — text with a descriptive
//!   parenthetical, stripped (links/overlapping_links_different_targets,
//!   endsets/endsets_transcluded_source); `"DEF (from C)"` — the
//!   parenthetical names the document (identity/identity_partial_transclusion).

use serde_json::Value;

use crate::shadow::Shadow;
use crate::tum::{parse_dotted, parse_vpos, parse_width};

// ───────────────────────────── raw field access ────────────────────────────

pub fn field<'v>(op: &'v Value, keys: &[&str]) -> Option<&'v Value> {
    keys.iter().find_map(|k| op.get(*k)).filter(|v| !v.is_null())
}

pub fn str_field<'v>(op: &'v Value, keys: &[&str]) -> Option<&'v str> {
    field(op, keys).and_then(Value::as_str)
}

pub fn label_of(op: &Value) -> &str {
    op.get("op").and_then(Value::as_str).unwrap_or("")
}

// ─────────────────────────── span / vspec shapes ───────────────────────────

/// `{start, width}` / `{start, end}` span dict → (subspace, ord, width).
/// ARGUMENT use only — starts here are always well-formed `sub.ord` (or bare
/// ordinal) V-positions. Recorded RESULTS go through [`expect_spans_raw`],
/// which never reinterprets.
pub fn span_dict(v: &Value) -> Option<(u64, u64, u64)> {
    let o = v.as_object()?;
    let start = o.get("start").and_then(Value::as_str)?;
    let (sub, ord) = parse_vpos(start)?;
    if let Some(w) = o.get("width").and_then(Value::as_str) {
        return Some((sub, ord, parse_width(w)?));
    }
    if let Some(e) = o.get("end").and_then(Value::as_str) {
        let (esub, eord) = parse_vpos(e)?;
        if esub == sub && eord >= ord {
            return Some((sub, ord, eord - ord));
        }
    }
    None
}

/// One document side of a spec: golden docid + `(subspace, ordinal, width)`
/// span triples — the parsed shape of a vspec dict, shared by every
/// endset/search builder in the translator.
pub type DocSpans = (String, Vec<(u64, u64, u64)>);

/// A golden vspec dict `{docid, spans|span}` → (docid, [(sub, ord, w)]).
pub fn vspec_dict(v: &Value) -> Option<DocSpans> {
    let o = v.as_object()?;
    let docid = o.get("docid").and_then(Value::as_str)?.to_string();
    if let Some(spans) = o.get("spans").and_then(Value::as_array) {
        let parsed: Option<Vec<_>> = spans.iter().map(span_dict).collect();
        return Some((docid, parsed?));
    }
    if let Some(sp) = o.get("span") {
        return Some((docid, vec![span_dict(sp)?]));
    }
    None
}

// ───────────────────────── recorded-result spans (raw) ─────────────────────

/// One recorded span, kept verbatim: `(start, width)` dotted strings exactly
/// as the recording client `str()`-ed the decoded tumblers. Comparison
/// against skep is string-level after rendering skep spans the same way —
/// no reinterpretation of udanax's serialization ever happens here (the
/// two-subspace vspanset shape in the goldens is malformed and must surface
/// as recorded, not be coerced into a `sub.ord` reading).
pub type RawSpan = (String, String);

fn raw_from_dict(v: &Value) -> Option<RawSpan> {
    let o = v.as_object()?;
    let start = o.get("start").and_then(Value::as_str)?.to_string();
    if let Some(w) = o.get("width").and_then(Value::as_str) {
        return Some((start, w.to_string()));
    }
    // {start, end} results: convert to width only when both parse cleanly.
    let e = o.get("end").and_then(Value::as_str)?;
    let (sub, ord) = parse_vpos(&start)?;
    let (esub, eord) = parse_vpos(e)?;
    if esub == sub && eord >= ord {
        return Some((start, format!("0.{}", eord - ord)));
    }
    None
}

/// `"1.1-0.24"` dashed rendering (link_poom/three_links_vspan_growth).
fn raw_from_dashed(s: &str) -> Option<RawSpan> {
    let (a, b) = s.split_once('-')?;
    let (a, b) = (a.trim(), b.trim());
    parse_dotted(a)?;
    parse_dotted(b)?;
    Some((a.to_string(), b.to_string()))
}

/// client.py `str()` forms: `<VSpec in D, at S for W, …>`, `<VSpan in D at S
/// for W>`, `<Span at S for W>` — spans kept verbatim. A `<SpecSet [ … ]>`
/// wrapper (subspace/insert_text_check_both_link_positions records the
/// client's raw SpecSet repr as a follow result) unwraps to its inner specs;
/// spec segments naming a second document are dropped with the first kept —
/// the one calibrated recording holds a single VSpec.
pub fn parse_python_spec(s: &str) -> Option<(Option<String>, Vec<RawSpan>)> {
    let s = s.trim().strip_prefix('<')?.strip_suffix('>')?;
    if let Some(r) = s.strip_prefix("SpecSet ") {
        let inner = r.trim().strip_prefix('[')?.strip_suffix(']')?;
        if inner.trim().is_empty() {
            return Some((None, Vec::new()));
        }
        let mut doc: Option<String> = None;
        let mut spans: Vec<RawSpan> = Vec::new();
        // Segments are non-nested "<…>" groups.
        let mut rest = inner;
        while let Some(open) = rest.find('<') {
            let Some(close) = rest[open..].find('>') else { break };
            let seg = &rest[open..open + close + 1];
            if let Some((d, ss)) = parse_python_spec(seg) {
                match (&doc, &d) {
                    (None, _) => {
                        doc = d;
                        spans.extend(ss);
                    }
                    (Some(cur), Some(new)) if cur == new => spans.extend(ss),
                    _ => {} // second-document segment: dropped (see above)
                }
            }
            rest = &rest[open + close + 1..];
        }
        if spans.is_empty() && doc.is_none() {
            return None;
        }
        return Some((doc, spans));
    }
    let (doc, rest) = if let Some(r) = s.strip_prefix("VSpec in ") {
        let (d, tail) = r.split_once(',').map(|(d, t)| (Some(d.trim().to_string()), t))?;
        (d, tail.to_string())
    } else if let Some(r) = s.strip_prefix("VSpan in ") {
        let (d, tail) = r.split_once(" at ")?;
        (Some(d.trim().to_string()), format!(" at {tail}"))
    } else if let Some(r) = s.strip_prefix("Span at ") {
        (None, format!(" at {r}"))
    } else {
        return None;
    };
    let mut spans = Vec::new();
    for part in rest.split(',') {
        let part = part.trim();
        let Some(p) = part.strip_prefix("at ") else { continue };
        let (start, width) = p.split_once(" for ")?;
        parse_dotted(start.trim())?;
        parse_dotted(width.trim())?;
        spans.push((start.trim().to_string(), width.trim().to_string()));
    }
    Some((doc, spans))
}

/// Harvest a recorded span-set expectation in any of the goldens' shapes:
/// vspec dict, array of span dicts, array of dashed strings, array of vspec
/// dicts (flattened), `{vspans|spans: …}` wrapper, python string. Returns
/// (optional docid, raw spans). Zero-width spans are DROPPED: a span of
/// width 0 contains no address (client.py `Span.contains`: start ≤ x <
/// start+0 is unsatisfiable), so udanax's zero-span rendering of emptiness
/// (documents/retrieve_vspan_empty: "at 0 for 0") is provably the same
/// observable as skep's empty span set.
pub fn expect_spans_raw(v: &Value) -> Option<(Option<String>, Vec<RawSpan>)> {
    let zero = |w: &str| parse_dotted(w).is_some_and(|c| c.iter().all(|&x| x == 0));
    let clean = |list: Vec<RawSpan>| -> Vec<RawSpan> {
        list.into_iter().filter(|(_, w)| !zero(w)).collect()
    };
    if let Some(arr) = v.as_array() {
        if arr.is_empty() {
            return Some((None, Vec::new()));
        }
        if let Some(dicts) = arr.iter().map(raw_from_dict).collect::<Option<Vec<_>>>() {
            return Some((None, clean(dicts)));
        }
        if let Some(dashed) =
            arr.iter().map(|x| x.as_str().and_then(raw_from_dashed)).collect::<Option<Vec<_>>>()
        {
            return Some((None, clean(dashed)));
        }
        if let Some(vspecs) = arr.iter().map(vspec_raw).collect::<Option<Vec<_>>>() {
            let doc = vspecs.first().map(|(d, _)| d.clone());
            let all: Vec<RawSpan> = vspecs.into_iter().flat_map(|(_, s)| s).collect();
            return Some((doc, clean(all)));
        }
        return None;
    }
    if let Some(o) = v.as_object() {
        if let Some(rs) = raw_from_dict(v) {
            return Some((None, clean(vec![rs])));
        }
        if let Some((doc, spans)) = vspec_raw(v) {
            return Some((Some(doc), clean(spans)));
        }
        for k in ["vspans", "spans"] {
            match o.get(k) {
                Some(inner @ Value::Object(_)) => return expect_spans_raw(inner),
                Some(Value::Array(arr)) => {
                    let doc = o.get("docid").and_then(Value::as_str).map(str::to_string);
                    let dicts: Option<Vec<_>> = arr.iter().map(raw_from_dict).collect();
                    return dicts.map(|d| (doc, clean(d)));
                }
                _ => {}
            }
        }
        return None;
    }
    if let Some(s) = v.as_str() {
        let (doc, spans) = parse_python_spec(s)?;
        return Some((doc, clean(spans)));
    }
    None
}

fn vspec_raw(v: &Value) -> Option<(String, Vec<RawSpan>)> {
    let o = v.as_object()?;
    let docid = o.get("docid").and_then(Value::as_str)?.to_string();
    let spans = o.get("spans").and_then(Value::as_array)?;
    let parsed: Option<Vec<_>> = spans.iter().map(raw_from_dict).collect();
    Some((docid, parsed?))
}

/// Harvest a vspanset expectation from ANY plausible field (the goldens key
/// them result/before/after/empty_state/after_insert/…): first the standard
/// keys, then a scan of remaining fields for span-set-shaped values. Shared
/// by the translator's probes and the grounding pre-pass (whose insert-width
/// authority reads the same recorded vspansets).
pub fn harvest_spanset(op: &Value) -> Option<(String, Option<String>, Vec<RawSpan>)> {
    const ARG_KEYS: &[&str] = &[
        "op", "doc", "docid", "comment", "label", "note", "interpretation", "search", "specs",
        "specset", "link", "positions", "span", "vspan", "start", "width", "end", "text",
        "strings", "texts", "cuts", "targets", "source_span", "source", "target", "from", "to",
        "address", "at", "position",
    ];
    for k in ["result", "vspans", "vspanset", "spans", "before", "after", "expected"] {
        if let Some(v) = op.get(k) {
            if let Some((doc, spans)) = expect_spans_raw(v) {
                return Some((k.to_string(), doc, spans));
            }
        }
    }
    let o = op.as_object()?;
    for (k, v) in o {
        if ARG_KEYS.contains(&k.as_str()) {
            continue;
        }
        if looks_like_spanset(v) || v.as_str().is_some_and(|s| s.starts_with('<')) {
            if let Some((doc, spans)) = expect_spans_raw(v) {
                return Some((k.clone(), doc, spans));
            }
        }
        // An explicit empty list under a state-ish key is an empty set.
        if v.as_array().is_some_and(Vec::is_empty) && (k.contains("state") || k.contains("span")) {
            return Some((k.clone(), None, Vec::new()));
        }
    }
    None
}

/// Is this value span-set-shaped at all? (Observation-bundle detection.)
pub fn looks_like_spanset(v: &Value) -> bool {
    match v {
        Value::Array(a) => {
            !a.is_empty()
                && (a.iter().all(|x| raw_from_dict(x).is_some())
                    || a.iter().all(|x| x.as_str().is_some_and(|s| raw_from_dashed(s).is_some()))
                    || a.iter().all(|x| vspec_raw(x).is_some()))
        }
        Value::Object(o) => o.contains_key("spans") || o.contains_key("vspans"),
        _ => false,
    }
}

// ─────────────────────────── content expectations ──────────────────────────

/// The expected-content field: an array of strings, a bare string, a
/// stringified python list ("['ACBDEFGH']"), or the `{success, contents}`
/// object wrapper (edgecases/retrieve_empty_specset). The bare marker
/// `"empty"` under an `expected` key means no content
/// (delete_all/empty_document_never_filled).
pub fn expect_strings(v: &Value) -> Option<Vec<String>> {
    if let Some(arr) = v.as_array() {
        return Some(arr.iter().filter_map(|x| x.as_str().map(str::to_string)).collect());
    }
    if let Some(o) = v.as_object() {
        for k in ["contents", "content", "strings"] {
            if let Some(inner) = o.get(k) {
                return expect_strings(inner);
            }
        }
        return None;
    }
    let s = v.as_str()?;
    let t = s.trim();
    if t == "empty" {
        return Some(Vec::new());
    }
    if t.starts_with('[') && t.ends_with(']') {
        let inner = &t[1..t.len() - 1];
        if inner.trim().is_empty() {
            return Some(Vec::new());
        }
        return Some(
            inner
                .split(',')
                .map(|p| p.trim().trim_matches('\'').trim_matches('"').to_string())
                .collect(),
        );
    }
    Some(vec![s.to_string()])
}

/// Did the golden record this op as a failure? (`error` non-null and not the
/// scripts' placeholder, or an explicit failed status.)
pub fn expected_failure(op: &Value) -> Option<String> {
    if let Some(s) = str_field(op, &["status"]) {
        if matches!(s, "failed" | "error" | "rejected") {
            return Some(format!("status={s}"));
        }
        if s == "succeeded" {
            return None;
        }
    }
    match str_field(op, &["error"]) {
        Some("N/A") | Some("") | None => None,
        Some(e) => Some(e.to_string()),
    }
}

/// A recorded `result` string of the form "OPERATION_FAILED: …" marks an op
/// the RECORDING CLIENT crashed on (e.g. bert/copy_without_write_token_on_
/// target: python AttributeError) — udanax never executed it, so the harness
/// executes nothing and compares nothing.
pub fn client_side_failure(op: &Value) -> Option<&str> {
    str_field(op, &["result"]).filter(|s| s.starts_with("OPERATION_FAILED:"))
}

/// A recording-client python `repr` captured verbatim ("<VSpan in … at 0 for
/// 0>", "<SpecSet […]>"). Such a string is NEVER document content — round 3
/// seeded documents/retrieve_vspan_empty's doc with the 33-byte repr of its
/// own empty vspan because the content-probe path took the string at face
/// value. Every content-string consumer filters through this.
pub fn is_python_repr(s: &str) -> bool {
    s.starts_with('<') && s.ends_with('>')
}

// ───────────────────────────── decorated forms ─────────────────────────────

/// A located region: golden doc + 1-based content ordinal + width.
#[derive(Clone, Debug)]
pub struct Located {
    pub doc: String,
    pub ord: u64,
    pub width: u64,
    /// The grounding policy that produced it (report tag).
    pub how: &'static str,
}

/// Resolve a decorated span/text description against the shadow. `doc_hint`
/// narrows the search when the caller knows the document. Never guesses: a
/// description this grammar cannot ground returns `None` and the caller
/// classifies the op inexpressible with the text recorded.
pub fn locate(shadow: &Shadow, doc_hint: Option<&str>, desc: &str) -> Option<Located> {
    let desc = desc.trim();

    // Plain text, found verbatim — the common case; try before any grammar.
    if let Some((doc, ord)) = shadow.find_text(doc_hint, desc) {
        return Some(Located { doc, ord, width: desc.len() as u64, how: "text-located" });
    }

    // "S.O length N" (delete_first_char).
    if let Some((pos, len)) = desc.split_once(" length ") {
        if let (Some((1, ord)), Ok(w)) = (parse_vpos(pos.trim()), len.trim().parse::<u64>()) {
            let doc = doc_hint.map(str::to_string).or_else(|| shadow.scoped())?;
            return Some(Located { doc, ord, width: w, how: "span-from-description" });
        }
    }

    // "N-char span at S.O" (link_zero_width_endpoints).
    if let Some(idx) = desc.find("-char span at ") {
        let n = desc[..idx].trim().parse::<u64>().ok()?;
        let (_, ord) = parse_vpos(desc[idx + "-char span at ".len()..].trim())?;
        let doc = doc_hint.map(str::to_string).or_else(|| shadow.scoped())?;
        return Some(Located { doc, ord, width: n.max(1), how: "span-from-description" });
    }

    // "doc[A-B]" bracket range (insert_text_check_link_positions) and the
    // single-position form "doc1[1.2]" (createlink_check_text_positions) —
    // one content ordinal, width 1.
    if let Some((docref, rest)) = desc.split_once('[') {
        if let Some(range) = rest.strip_suffix(']') {
            if let Some(doc) = shadow.resolve_doc(docref.trim()) {
                if let Some((ord, w)) = ordinal_range(range) {
                    return Some(Located { doc, ord, width: w, how: "range-from-description" });
                }
                if let Some((1, ord)) = parse_vpos(range.trim()) {
                    return Some(Located { doc, ord, width: 1, how: "range-from-description" });
                }
            }
        }
    }

    // "doc:text" qualified text (version_with_links "source:here").
    if let Some((docref, text)) = desc.split_once(':') {
        if let Some(doc) = shadow.resolve_doc(docref.trim()) {
            let t = text.trim();
            if let Some((d, ord)) = shadow.find_text(Some(&doc), t) {
                return Some(Located { doc: d, ord, width: t.len() as u64, how: "text-located" });
            }
        }
    }

    // "all of B" / "all" / "full document" / "entire …" — whole extent.
    let whole = |doc: String| -> Option<Located> {
        let n = shadow.text_len(&doc);
        if n == 0 {
            return None;
        }
        Some(Located { doc, ord: 1, width: n, how: "whole-extent" })
    };
    if let Some(rest) = desc.strip_prefix("all of ") {
        if let Some(doc) = shadow.resolve_doc(rest.trim()) {
            return whole(doc);
        }
    }
    if desc == "all" || desc == "full document" || desc.starts_with("entire") {
        let doc = doc_hint.map(str::to_string).or_else(|| shadow.scoped())?;
        return whole(doc);
    }

    // Trailing parenthetical: "text (5-9)" range, "text (from C)" doc
    // qualifier, "bank (second)" occurrence selector, or descriptive junk
    // to strip ("shared (transcluded)").
    if let Some(open) = desc.rfind('(') {
        if desc.ends_with(')') {
            let head = desc[..open].trim();
            let inner = &desc[open + 1..desc.len() - 1];
            if let Some((ord, w)) = ordinal_range(inner) {
                let doc = doc_hint
                    .map(str::to_string)
                    .or_else(|| shadow.find_text(None, head).map(|(d, _)| d))
                    .or_else(|| shadow.scoped())?;
                // The explicit range is authoritative; the head text is a
                // reminder (retrieve_noncontiguous_spans "quick (5-9)").
                return Some(Located { doc, ord, width: w, how: "range-from-description" });
            }
            if let Some(docref) = inner.strip_prefix("from ") {
                if let Some(doc) = shadow.resolve_doc(docref.trim()) {
                    if let Some((d, ord)) = shadow.find_text(Some(&doc), head) {
                        return Some(Located {
                            doc: d,
                            ord,
                            width: head.len() as u64,
                            how: "text-located",
                        });
                    }
                }
            }
            // "(first)" / "(second)" / "(first, same span)" — an occurrence
            // selector, honored, not stripped: round 3 landed every
            // "bank (second)" on the FIRST occurrence, giving
            // overlapping_links_different_targets a third overlapping link.
            if let Some(n) = occurrence_of(inner) {
                if !head.is_empty() {
                    if let Some((d, ord)) = shadow.find_text_nth(doc_hint, head, n) {
                        return Some(Located {
                            doc: d,
                            ord,
                            width: head.len() as u64,
                            how: "text-located:nth-occurrence",
                        });
                    }
                    return None; // selector present but unsatisfiable
                }
            }
            if !head.is_empty() {
                if let Some((d, ord)) = shadow.find_text(doc_hint, head) {
                    return Some(Located {
                        doc: d,
                        ord,
                        width: head.len() as u64,
                        how: "text-located",
                    });
                }
            }
        }
    }

    // Quoted text anywhere: "just 'S'", "first occurrence of 'text' (…)".
    if let Some(q) = quoted(desc) {
        if let Some((d, ord)) = shadow.find_text(doc_hint, &q) {
            return Some(Located { doc: d, ord, width: q.len() as u64, how: "text-located" });
        }
    }

    None
}

/// An occurrence-selector parenthetical's ordinal: "first" → 1,
/// "first, same span" → 1, "second" → 2 … `None` for anything else.
fn occurrence_of(inner: &str) -> Option<u64> {
    let word = inner.split([',', ' ']).next()?.trim().to_ascii_lowercase();
    match word.as_str() {
        "first" => Some(1),
        "second" => Some(2),
        "third" => Some(3),
        "fourth" => Some(4),
        "fifth" => Some(5),
        _ => None,
    }
}

/// "5-9" or "1.5-1.9" inclusive ordinal range → (start ordinal, width).
fn ordinal_range(s: &str) -> Option<(u64, u64)> {
    let (a, b) = s.split_once('-')?;
    let pv = |x: &str| -> Option<u64> {
        let x = x.trim();
        match parse_dotted(x)?.as_slice() {
            [o] => Some(*o),
            [1, o] => Some(*o),
            _ => None,
        }
    };
    let (start, end) = (pv(a)?, pv(b)?);
    if end >= start && start > 0 {
        Some((start, end - start + 1))
    } else {
        None
    }
}

/// First 'single'- or "double"-quoted segment.
fn quoted(s: &str) -> Option<String> {
    for q in ['\'', '"'] {
        if let Some(i) = s.find(q) {
            if let Some(j) = s[i + 1..].find(q) {
                let inner = &s[i + 1..i + 1 + j];
                if !inner.is_empty() {
                    return Some(inner.to_string());
                }
            }
        }
    }
    None
}

/// A position description → 1-based content ordinal (grounded against the
/// shadow when relative). `None` = not a position this grammar speaks.
pub fn resolve_position(shadow: &Shadow, doc: &str, desc: &str) -> Option<(u64, u64, &'static str)> {
    let desc = desc.trim();
    if let Some((sub, ord)) = parse_vpos(desc) {
        return Some((sub, ord, "explicit-position"));
    }
    match desc {
        "end" | "append" => return Some((1, shadow.text_len(doc) + 1, "position-end")),
        "start" | "beginning" => return Some((1, 1, "position-start")),
        _ => {}
    }
    if let Some(n) = desc.strip_prefix("position ").and_then(|x| x.trim().parse::<u64>().ok()) {
        return Some((1, n, "position-from-description"));
    }
    if let Some(t) = desc.strip_prefix("after ") {
        let t = t.trim();
        if let Some((_, ord)) = shadow.find_text(Some(doc), t) {
            return Some((1, ord + t.len() as u64, "position-after-text"));
        }
        // Case-insensitive fallback: labels say "after first" for "First ".
        if let Some((_, ord, w)) = shadow.find_text_ci(doc, t) {
            return Some((1, ord + w, "position-after-text"));
        }
    }
    if let Some(t) = desc.strip_prefix("before ") {
        if let Some((_, ord)) = shadow.find_text(Some(doc), t.trim()) {
            return Some((1, ord, "position-before-text"));
        }
    }
    None
}

/// Positional probes: the first two consecutive numeric `_`-tokens in the
/// label ("text_at_1_3_before" → (1,3); "pos_1_4_after" → (1,4)).
pub fn position_from_label(label: &str) -> Option<(u64, u64)> {
    let toks: Vec<&str> = label.split('_').collect();
    for w in toks.windows(2) {
        if let (Ok(a), Ok(b)) = (w[0].parse::<u64>(), w[1].parse::<u64>()) {
            return Some((a, b));
        }
    }
    None
}

/// Label-token doc reference: `…_doc1` / `…_doc2` (subspace/
/// insert_text_check_link_positions "insert_text_doc1").
pub fn doc_from_label(label: &str) -> Option<String> {
    label
        .rsplit('_')
        .next()
        .filter(|t| t.starts_with("doc") && t[3..].parse::<u64>().is_ok())
        .map(str::to_string)
}

/// The symbolic name a create op binds: an explicit doc/name/label field, or
/// the role carried by the label itself — `create_target` names its doc
/// "target" (identity/identity_mixed_sources probes `doc: "target"` though
/// no field ever bound it), `create_doc2_and_copy` names "doc2". Generic
/// create labels (create_document, create_documents…) carry no role.
pub fn create_name_of(op: &Value) -> Option<String> {
    if let Some(s) = str_field(op, &["doc", "name", "label"]) {
        if crate::tum::parse_dotted(s).is_none() {
            return Some(s.to_string());
        }
    }
    let label = label_of(op).to_ascii_lowercase();
    let role = label.strip_prefix("create_")?;
    let role = role.split("_and_").next().unwrap_or(role);
    const GENERIC: &[&str] = &[
        "document", "documents", "doc", "docs", "version", "node", "link", "links", "chain",
        "sources", "multiple", "multiple_targets", "and", "new",
    ];
    if role.is_empty() || GENERIC.contains(&role) {
        return None;
    }
    Some(role.to_string())
}

/// An arrow spec carried in a note/comment VALUE — `note: "doc1 -> doc4"`
/// (links/find_links_homedocids_multiple) names a create_link's endset
/// roles the way arrow KEYS ("A->B": id) do elsewhere.
pub fn note_arrow(op: &Value) -> Option<(String, String)> {
    for key in ["note", "comment", "description"] {
        if let Some(s) = str_field(op, &[key]) {
            if let Some((f, t)) = s.split_once("->") {
                let (f, t) = (f.trim(), t.trim());
                // Both sides must be short bare references, not prose.
                if !f.is_empty()
                    && !t.is_empty()
                    && !f.contains(' ')
                    && !t.contains(' ')
                    && f.len() <= 16
                    && t.len() <= 16
                {
                    return Some((f.to_string(), t.to_string()));
                }
            }
        }
    }
    None
}

/// The document address a link address lives under, textually: strip the
/// final `0.2.n` local part ("1.1.0.1.0.1.0.2.1" → "1.1.0.1.0.1").
pub fn link_home_docid(link: &str) -> Option<String> {
    let comps = parse_dotted(link)?;
    if comps.len() >= 4 {
        let n = comps.len();
        if comps[n - 3] == 0 && comps[n - 2] == 2 && comps[n - 1] > 0 {
            let head: Vec<String> = comps[..n - 3].iter().map(|c| c.to_string()).collect();
            return Some(head.join("."));
        }
    }
    None
}

/// A link address in golden terms: `…·0·2·n` (a document's link subspace).
pub fn is_link_address(s: &str) -> bool {
    link_home_docid(s).is_some()
}
