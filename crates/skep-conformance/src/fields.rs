//! Shared field-bag parsing: the one place golden JSON fields, decorated
//! descriptions, recorded span shapes, recorded replies, and an op's own
//! arguments are interpreted — the verb an op's name reads as
//! (`normalize`), the document an op aims at (`aim_doc`), the content a
//! read's recording answers with (`recorded_content`) and the regions a
//! vcopy copies (`vcopy_sources`) included. Both the grounding pre-pass and
//! the play pass read through these helpers, so the two passes cannot drift
//! on what a field means. What a scenario's recorded evidence says an op DID —
//! whether it happened at all, where an insert or a vcopy landed, what a
//! delete removed — is `evidence`'s.
//!
//! Two of its grammars are modules of their own: `verb`, the verb an op's
//! name reads as, and `description`, a recorded description grounded
//! against the shadow — each item of both named through this module.

use serde_json::Value;

use crate::shadow::Shadow;
use crate::tum::{
    is_golden_address, is_link_address, link_home_docid, parse_dotted, parse_vpos, parse_width,
    VPoint, VRegion,
};

// The verb an op's name reads as: the canonical verbs, the stem table, the meta names.
mod verb;
// The description grammar: a recorded position, span, range or text, grounded in the shadow.
mod description;

pub use description::{
    locate, ordinal_range, quoted, resolve_position, Grounding, Located, PositionGrounding,
};
pub use verb::{has_observation_fields, normalize, reads_whole_content, verb_of, Verb};

// ───────────────────────────── raw field access ────────────────────────────

pub fn field<'v>(op: &'v Value, keys: &[&str]) -> Option<&'v Value> {
    keys.iter().find_map(|k| op.get(*k)).filter(|v| !v.is_null())
}

pub fn str_field<'v>(op: &'v Value, keys: &[&str]) -> Option<&'v str> {
    field(op, keys).and_then(Value::as_str)
}

/// The golden's `op` field — the recording's name for the operation, which
/// `normalize` reads a verb from and some names carry arguments in; never
/// its `label` field (a create's role, a probe's phase, a compare's
/// `<x>_vs_<y>` pair).
pub fn op_name(op: &Value) -> &str {
    op.get("op").and_then(Value::as_str).unwrap_or("")
}

/// Keys never an answer a read leaves unread, and never a document's name
/// in a roster: the op's name (`op`), which dispatch reads; its `label` — a
/// create's role, a probe's phase, a compare's `<x>_vs_<y>` pair — which
/// naming and compare pairing read; the `session` it runs under, which
/// routing reads; the recorded failure (`error`, `status`) every handler
/// settles against ([`expected_failure`]); prose (`comment`, `note`,
/// `description`, `interpretation`, `message`, `claim`, `assertion`); an
/// open's `mode`; and a verification's own judgement of itself (`match`).
pub const ANNOTATION_KEYS: &[&str] = &[
    "op", "label", "comment", "note", "description", "interpretation", "message", "claim",
    "assertion", "match", "session", "mode", "error", "status",
];

// ─────────────────────────── span / vspec shapes ───────────────────────────

/// `{start, width}` / `{start, end}` span dict → the region it names.
/// ARGUMENT use only — starts here are always well-formed `sub.ord` (or bare
/// ordinal) V-positions. Recorded RESULTS go through [`raw_spanset_of`],
/// which never reinterprets.
pub fn span_dict(v: &Value) -> Option<VRegion> {
    let o = v.as_object()?;
    let at = parse_vpos(o.get("start").and_then(Value::as_str)?)?;
    if let Some(w) = o.get("width").and_then(Value::as_str) {
        return Some(at.region(parse_width(w)?));
    }
    if let Some(e) = o.get("end").and_then(Value::as_str) {
        let end = parse_vpos(e)?;
        if end.sub == at.sub && end.ord >= at.ord {
            return Some(at.region(end.ord - at.ord));
        }
    }
    None
}

/// One document side of a spec: golden docid + its regions — the parsed
/// shape of a vspec dict, shared by every endset/search builder in the play
/// pass.
pub type DocSpans = (String, Vec<VRegion>);

/// A golden vspec dict `{docid, spans|span}` → (docid, its regions).
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

fn raw_span_dict(v: &Value) -> Option<RawSpan> {
    let o = v.as_object()?;
    let start = o.get("start").and_then(Value::as_str)?.to_string();
    if let Some(w) = o.get("width").and_then(Value::as_str) {
        return Some((start, w.to_string()));
    }
    // {start, end} results: convert to width only when both parse cleanly.
    let end = parse_vpos(o.get("end").and_then(Value::as_str)?)?;
    let at = parse_vpos(&start)?;
    if end.sub == at.sub && end.ord >= at.ord {
        return Some((start, format!("0.{}", end.ord - at.ord)));
    }
    None
}

/// `"1.1-0.24"` dashed rendering (link_poom/three_links_vspan_growth).
fn raw_span_dashed(s: &str) -> Option<RawSpan> {
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
    } else {
        let r = s.strip_prefix("Span at ")?;
        (None, format!(" at {r}"))
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

/// The span set a recorded value holds, kept raw, in any of the goldens'
/// shapes: vspec dict, array of span dicts, array of dashed strings, array
/// of vspec dicts (flattened), `{vspans|spans: …}` wrapper, python string.
/// Returns (optional docid, raw spans). Zero-width spans are DROPPED: a span of
/// width 0 contains no address (client.py `Span.contains`: start ≤ x <
/// start+0 is unsatisfiable), so udanax's zero-span rendering of emptiness
/// (documents/retrieve_vspan_empty: "at 0 for 0") is provably the same
/// observable as skep's empty span set.
pub fn raw_spanset_of(v: &Value) -> Option<(Option<String>, Vec<RawSpan>)> {
    let zero = |w: &str| parse_dotted(w).is_some_and(|c| c.iter().all(|&x| x == 0));
    let clean = |list: Vec<RawSpan>| -> Vec<RawSpan> {
        list.into_iter().filter(|(_, w)| !zero(w)).collect()
    };
    if let Some(arr) = v.as_array() {
        if arr.is_empty() {
            return Some((None, Vec::new()));
        }
        if let Some(dicts) = arr.iter().map(raw_span_dict).collect::<Option<Vec<_>>>() {
            return Some((None, clean(dicts)));
        }
        if let Some(dashed) =
            arr.iter().map(|x| x.as_str().and_then(raw_span_dashed)).collect::<Option<Vec<_>>>()
        {
            return Some((None, clean(dashed)));
        }
        if let Some(vspecs) = arr.iter().map(raw_vspec_dict).collect::<Option<Vec<_>>>() {
            let doc = vspecs.first().map(|(d, _)| d.clone());
            let all: Vec<RawSpan> = vspecs.into_iter().flat_map(|(_, s)| s).collect();
            return Some((doc, clean(all)));
        }
        return None;
    }
    if let Some(o) = v.as_object() {
        if let Some(rs) = raw_span_dict(v) {
            return Some((None, clean(vec![rs])));
        }
        if let Some((doc, spans)) = raw_vspec_dict(v) {
            return Some((Some(doc), clean(spans)));
        }
        for k in ["vspans", "spans"] {
            match o.get(k) {
                Some(inner @ Value::Object(_)) => return raw_spanset_of(inner),
                Some(Value::Array(arr)) => {
                    let doc = o.get("docid").and_then(Value::as_str).map(str::to_string);
                    let dicts: Option<Vec<_>> = arr.iter().map(raw_span_dict).collect();
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

fn raw_vspec_dict(v: &Value) -> Option<(String, Vec<RawSpan>)> {
    let o = v.as_object()?;
    let docid = o.get("docid").and_then(Value::as_str)?.to_string();
    let spans = o.get("spans").and_then(Value::as_array)?;
    let parsed: Option<Vec<_>> = spans.iter().map(raw_span_dict).collect();
    Some((docid, parsed?))
}

/// The vspanset an op records, and the key it lives under, from ANY
/// plausible field (the goldens key them result/before/after/empty_state/
/// after_insert/…): first the standard keys, then a scan of remaining fields
/// for span-set-shaped values. Shared by the play pass's probes and the
/// grounding pre-pass (whose insert-width authority reads the same recorded
/// vspansets).
pub fn recorded_spanset(op: &Value) -> Option<(String, Option<String>, Vec<RawSpan>)> {
    const ARG_KEYS: &[&str] = &[
        "op", "doc", "docid", "comment", "label", "note", "interpretation", "search", "specs",
        "specset", "link", "positions", "span", "vspan", "start", "width", "end", "text",
        "strings", "texts", "cuts", "targets", "source_span", "source", "target", "from", "to",
        "address", "at", "position",
    ];
    for k in ["result", "vspans", "vspanset", "spans", "before", "after", "expected"] {
        if let Some(v) = op.get(k) {
            if let Some((doc, spans)) = raw_spanset_of(v) {
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
            if let Some((doc, spans)) = raw_spanset_of(v) {
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

/// A `<role>_vspan_count` field — the recorded count of a ROLE document's
/// vspanset spans (internal/ispan_consolidation_bulk's `source_vspan_count`,
/// `dest_vspan_count`): the role, and the count (policy
/// `vspan-count-by-role`). The one reading both passes aim such a probe by.
pub fn role_vspan_count(op: &Value) -> Option<(&str, u64)> {
    let o = op.as_object()?;
    o.iter().find_map(|(k, v)| Some((k.strip_suffix("_vspan_count")?, v.as_u64()?)))
}

/// Is this value span-set-shaped at all? (Observation-bundle detection.)
pub fn looks_like_spanset(v: &Value) -> bool {
    match v {
        Value::Array(a) => {
            !a.is_empty()
                && (a.iter().all(|x| raw_span_dict(x).is_some())
                    || a.iter().all(|x| x.as_str().is_some_and(|s| raw_span_dashed(s).is_some()))
                    || a.iter().all(|x| raw_vspec_dict(x).is_some()))
        }
        Value::Object(o) => o.contains_key("spans") || o.contains_key("vspans"),
        _ => false,
    }
}

// ─────────────────────────── content expectations ──────────────────────────

/// The strings a recorded content value holds: an array of strings, a bare
/// string, a stringified python list ("['ACBDEFGH']"), or the `{success,
/// contents}` object wrapper (edgecases/retrieve_empty_specset). The bare marker
/// `"empty"` under an `expected` key means no content
/// (delete_all/empty_document_never_filled).
///
/// An array is a content list only when EVERY entry is a string or a link
/// item as the recording client renders one, `{link_id: X}`, which reads as
/// the link address X (links/orphaned_link_source_all_deleted's retrieve of
/// an emptied document delivers its link). An array holding span dicts is
/// a different result shape and returns `None` — reading a recorded
/// post-insert vspanset (`result: [{start,width}]`, allocation_
/// independence/all_operations_interleaved op 1) as the EMPTY content
/// expectation would fabricate a `content []` disagreement.
pub fn strings_of(v: &Value) -> Option<Vec<String>> {
    if let Some(arr) = v.as_array() {
        return arr
            .iter()
            .map(|x| x.as_str().map(str::to_string).or_else(|| link_item(x)))
            .collect();
    }
    if let Some(o) = v.as_object() {
        for k in ["contents", "content", "strings"] {
            if let Some(inner) = o.get(k) {
                return strings_of(inner);
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

/// A delivered link item as the recording client renders it — an object
/// whose one field is `link_id`, a link address — read as that address.
fn link_item(v: &Value) -> Option<String> {
    let o = v.as_object()?;
    let id = o.get("link_id").and_then(Value::as_str)?;
    (o.len() == 1 && is_link_address(id)).then(|| id.to_string())
}

/// The bytes a recorded content reply names, its strings joined — `None`
/// when any string is a golden address ([`is_golden_address`]) or a
/// recording-client python repr ("<VSpan in … at 0 for 0>", "<SpecSet
/// […]>"), neither of which is ever content-subspace bytes. Every reader of
/// recorded content as document text goes through here: round 3 seeded
/// documents/retrieve_vspan_empty's doc with the 33-byte repr of its own
/// empty vspan when one reader took the string at face value. Text that
/// merely looks dotted or bracketed — a version chain's "0123456789.1", a
/// "<b>" — is text, and is compared.
pub fn as_text(strings: &[String]) -> Option<String> {
    if strings.iter().any(|s| is_golden_address(s) || is_python_repr(s)) {
        return None;
    }
    Some(strings.concat())
}

/// A recording-client python `repr` captured verbatim: one of the four
/// forms client.py renders, which [`parse_python_spec`] reads — never text
/// that merely sits between angle brackets.
fn is_python_repr(s: &str) -> bool {
    const FORMS: &[&str] = &["<VSpan ", "<VSpec ", "<Span ", "<SpecSet "];
    s.ends_with('>') && FORMS.iter().any(|form| s.starts_with(form))
}

/// The keys a content read's recorded answer lives under, in the order they
/// are consulted. `expected_contents` precedes `expected`, which usually
/// holds prose.
pub const REPLY_KEYS: &[&str] = &[
    "result", "before", "after", "content", "contents", "sample", "remaining", "empty",
    "expected_contents", "expected", "value", "text",
];

/// The keys a write's recorded post-state lives under — a write's `text`
/// and `content` fields are its ARGUMENTS, never an answer.
pub const POST_WRITE_KEYS: &[&str] = &["remaining", "result", "expected_contents"];

/// The arguments a content read carries: the document it reads, and the
/// region, spec set or position that narrows it — never where its recorded
/// answer lives ([`recorded_content`]).
pub const CONTENT_READS: &[&str] = &[
    "doc", "docid", "doc_label", "specset", "specs", "span", "spans", "vspan", "address", "at",
    "position",
];

/// The content a read's recording answers with, and the key it lives
/// under: the first [`REPLY_KEYS`] key holding a recorded array (or a
/// `{contents}` wrapper around one); else the op's one string array under a
/// key outside `reads` and [`ANNOTATION_KEYS`] (rearrange/double_pivot's
/// `original`, `after_first`); else the first reply key holding a bare
/// string, in [`strings_of`]' forms. A bare string never outranks a
/// recorded array: `expected` usually holds prose ("Should match original
/// (ABCDE)") beside the array that is the data. Two or more such unlisted
/// arrays name no single answer, so the op has none here, and the read that
/// compares nothing names them.
pub fn recorded_content(op: &Value, reads: &[&str]) -> Option<(String, Vec<String>)> {
    for k in REPLY_KEYS {
        if let Some(v) = field(op, &[k]).filter(|v| !v.is_string()) {
            if let Some(strings) = strings_of(v) {
                return Some((k.to_string(), strings));
            }
        }
    }
    let o = op.as_object()?;
    let unlisted: Vec<(&String, Vec<String>)> = o
        .iter()
        .filter(|(k, v)| {
            v.is_array()
                && !REPLY_KEYS.contains(&k.as_str())
                && !reads.contains(&k.as_str())
                && !ANNOTATION_KEYS.contains(&k.as_str())
        })
        .filter_map(|(k, v)| Some((k, strings_of(v)?)))
        .collect();
    match unlisted.as_slice() {
        [(k, strings)] => return Some((k.to_string(), strings.clone())),
        [] => {}
        _ => return None,
    }
    REPLY_KEYS.iter().find_map(|k| {
        let v = field(op, &[k]).filter(|v| v.is_string())?;
        Some((k.to_string(), strings_of(v)?))
    })
}

/// The per-document replies of one read: two or more fields whose KEY
/// names a document — directly ("source", "dest") or before a `_content`
/// suffix ("A_content") — and whose VALUE is a string array, each the
/// recorded content of that document (internal/ispan_partial_overlap's
/// `source: ["CDEFG"], dest: ["CDEFG"]`, beside an `expected` that is
/// prose; isolation/cross_document_transclusion_isolation's snapshots). An
/// op that names its document, or records a reply under a reply key, is no
/// such read. Returned as (key, golden doc, strings) in key order; empty
/// when fewer than two fields qualify.
pub fn per_doc_replies(op: &Value, shadow: &Shadow) -> Vec<(String, String, Vec<String>)> {
    const NOT_DOCS: &[&str] =
        &["texts", "strings", "cuts", "spans", "targets", "docs", "positions"];
    if field(op, &["doc", "docid", "result", "specset", "specs", "contents", "content"]).is_some() {
        return Vec::new();
    }
    let Some(o) = op.as_object() else { return Vec::new() };
    let replies: Vec<(String, String, Vec<String>)> = o
        .iter()
        .filter(|(k, v)| {
            let k = k.as_str();
            v.is_array()
                && !ANNOTATION_KEYS.contains(&k)
                && !REPLY_KEYS.contains(&k)
                && !NOT_DOCS.contains(&k)
        })
        .filter_map(|(k, v)| {
            let strings = strings_of(v)?;
            let named = k.strip_suffix("_contents").or_else(|| k.strip_suffix("_content"));
            let doc = named.and_then(|n| shadow.resolve_doc(n)).or_else(|| shadow.resolve_doc(k))?;
            Some((k.clone(), doc, strings))
        })
        .collect();
    if replies.len() < 2 {
        return Vec::new();
    }
    replies
}

/// What kind of probe an op's recorded content is: the keys it lives under
/// differ, because a WRITE op's `text`/`content` fields are its ARGUMENTS,
/// never a post-state expectation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    /// An observation bundle (initial_state, after_first_insert…): the
    /// reply a read's recording answers with ([`recorded_content`]).
    Bundle,
    /// After a write (insert/delete/vcopy): only the post-write keys
    /// ([`POST_WRITE_KEYS`]) are expectations.
    PostWrite,
    /// One interior-typing step entry: its own `contents`/`content`.
    Step,
}

/// The arguments an observation bundle carries: the document it observes.
pub const BUNDLE_READS: &[&str] = &["doc", "docid", "doc_label"];

/// The content a probe of `kind` records, and the key it lives under — what
/// the play pass compares a document's whole content against
/// (`play::probe_state`), and the walk probes the shadow with. `None` when
/// the recording keeps none.
pub fn probed_content(op: &Value, kind: Probe) -> Option<(String, Vec<String>)> {
    let first_present = |keys: &[&str]| -> Option<(String, Vec<String>)> {
        let key = *keys.iter().find(|k| field(op, &[**k]).is_some())?;
        Some((key.to_string(), strings_of(field(op, &[key])?)?))
    };
    match kind {
        Probe::Bundle => recorded_content(op, BUNDLE_READS),
        Probe::PostWrite => first_present(POST_WRITE_KEYS),
        Probe::Step => first_present(&["contents", "content"]),
    }
}

/// The per-target replies of one read: each `targets` entry naming its
/// document — by `docid`, or a `doc` name that resolves — with the strings
/// its `contents` (or `content`) records, the content of that document
/// (identity/identity_multi_document_sharing records each created target's
/// content only here; content/multiple_vcopy_same_source each copy's).
/// Entries carrying no such pair are no reply. In entry order.
pub fn target_replies(op: &Value, shadow: &Shadow) -> Vec<(String, Vec<String>)> {
    let Some(entries) = op.get("targets").and_then(Value::as_array) else { return Vec::new() };
    entries
        .iter()
        .filter_map(|e| {
            let doc = e.get("docid").and_then(Value::as_str).map(str::to_string).or_else(|| {
                e.get("doc").and_then(Value::as_str).and_then(|n| shadow.resolve_doc(n))
            });
            let strings = e.get("contents").or_else(|| e.get("content")).and_then(strings_of);
            Some((doc?, strings?))
        })
        .collect()
}

/// Did the golden record this op as a failure? A `status` of "failed",
/// "error" or "rejected" says so, and one of "succeeded" says not —
/// whatever `error` holds; otherwise a non-null `error` other than the
/// scripts' placeholders ("N/A", "") is the recorded failure.
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

/// The RECORDING CLIENT crashed before the op reached udanax — a python
/// `AttributeError` on a session method the client lacks. The corpus records
/// that crash three ways: a `result` of "OPERATION_FAILED: …"
/// (bert/copy_without_write_token_on_target), a `result` of "FAILED: …"
/// naming the missing attribute (internal/insert_rearrange_insert_iaddress_
/// gap op 2, whose next retrieve shows the text unchanged), and an `error`
/// naming it (links/insert_text_at_link_subspace op 7). udanax never
/// executed such an op, so the harness executes nothing and compares
/// nothing. Returns the recorded message.
pub fn client_side_failure(op: &Value) -> Option<&str> {
    let missing_attribute = |s: &&str| s.contains("object has no attribute");
    str_field(op, &["result"])
        .filter(|s| {
            s.starts_with("OPERATION_FAILED:") || (s.starts_with("FAILED:") && missing_attribute(s))
        })
        .or_else(|| str_field(op, &["error"]).filter(missing_attribute))
}

// ────────────────────────────── op arguments ───────────────────────────────

/// The most a single recorded NUMBER may make the harness build: bytes for
/// one document out of no recorded bytes (`insert_loop`'s A–Z cycle, a
/// pre-pass filler or seed), or documents out of one `count`. It is skep's
/// delivery budget: every whole-document comparison here is one RETRIEVEV,
/// which skep refuses past `MAX_DELIVERY_ITEMS` values (M6), so past it the
/// number orders work no comparison can use, and the op is refused instead
/// of built.
pub const BUILD_BUDGET: u64 = skep_retrieval::MAX_DELIVERY_ITEMS as u64;

/// An op's recorded `count`: `Ok(None)` when it records none; an `Err`
/// naming the count and the budget when it is past [`BUILD_BUDGET`].
pub fn recorded_count(op: &Value) -> Result<Option<u64>, String> {
    match field(op, &["count"]).and_then(Value::as_u64) {
        Some(n) if n > BUILD_BUDGET => Err(format!(
            "recorded count {n} is past the build budget of {BUILD_BUDGET} (skep's delivery \
             budget: no comparison could read what it would build)"
        )),
        n => Ok(n),
    }
}

/// The inserted text: field, strings array, or carried by the op's name
/// (`insert_1_AAA` = ordinal 1 text AAA; `insert_A` = text A).
pub fn insert_text(op: &Value) -> Option<String> {
    if let Some(t) = str_field(op, &["text", "content", "string"]) {
        return Some(t.to_string());
    }
    if let Some(a) = field(op, &["strings", "texts"]).and_then(Value::as_array) {
        return Some(a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(""));
    }
    let name = op_name(op);
    let rest = name.strip_prefix("insert_")?;
    if let Some((ordtok, text)) = rest.split_once('_') {
        if ordtok.parse::<u64>().is_ok() {
            return Some(text.to_string());
        }
        return None; // insert_after_delete etc.: descriptive, not text
    }
    // Single trailing token: the text itself (insert_A, insert_1), unless a
    // known descriptive word.
    if rest.is_empty() || matches!(rest, "loop" | "text" | "attempt" | "all") {
        return None;
    }
    Some(rest.to_string())
}

/// `insert_all`-style distribution: a texts array of ≥ 2 entries under an
/// op name that names no single position — one text per document, never one
/// concatenated insert.
pub fn distributed_insert_texts(op: &Value) -> Option<Vec<String>> {
    let name = op_name(op).to_ascii_lowercase();
    if !(name == "insert_all" || name == "insert_each") {
        return None;
    }
    let texts: Vec<String> = field(op, &["texts", "strings"])
        .and_then(Value::as_array)?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    (texts.len() >= 2).then_some(texts)
}

/// The n most recently created docs, creation order — the targets an
/// `insert_all` distributes over (its creates immediately precede it).
pub fn distribution_targets(shadow: &Shadow, n: usize) -> Vec<String> {
    let created = shadow.created();
    let start = created.len().saturating_sub(n);
    created[start..].to_vec()
}

/// Rearrange cut ordinals from `cuts` array or cut1..cut4 / v1..v3 /
/// starta..endb keyed fields.
pub fn cuts_of(op: &Value) -> Vec<u64> {
    let parse_cut = |v: &Value| -> Option<u64> {
        if let Some(n) = v.as_u64() {
            return Some(n);
        }
        match parse_vpos(v.as_str()?) {
            Some(VPoint { sub: 1, ord }) => Some(ord),
            _ => None,
        }
    };
    if let Some(arr) = field(op, &["cuts"]).and_then(Value::as_array) {
        return arr.iter().filter_map(parse_cut).collect();
    }
    let mut cuts = Vec::new();
    for keys in [
        &["cut1", "v1", "starta"][..],
        &["cut2", "v2", "enda"][..],
        &["cut3", "v3", "startb"][..],
        &["cut4", "endb"][..],
    ] {
        match field(op, keys).and_then(parse_cut) {
            Some(c) => cuts.push(c),
            None => break,
        }
    }
    cuts
}

/// The cuts a swap's two `regions` texts name in `doc`, each found in the
/// shadow, the earlier region's first — tagged `text-located:regions`;
/// `None` unless both are found (identity/identity_through_rearrange_swap).
/// The one reading both passes swap a swap that records no cuts by.
pub fn swap_regions(
    op: &Value,
    shadow: &Shadow,
    doc: &str,
    adaptations: &mut Vec<String>,
) -> Option<Vec<u64>> {
    let regions = field(op, &["regions"]).and_then(Value::as_array)?;
    let texts: Vec<&str> = regions.iter().filter_map(Value::as_str).collect();
    let [ta, tb] = texts[..] else { return None };
    let (_, s1) = shadow.find_text(Some(doc), ta)?;
    let (_, s2) = shadow.find_text(Some(doc), tb)?;
    adaptations.push("text-located:regions".into());
    let (w1, w2) = (ta.len() as u64, tb.len() as u64);
    Some(if s1 <= s2 { vec![s1, s1 + w1, s2, s2 + w2] } else { vec![s2, s2 + w2, s1, s1 + w1] })
}

/// Does this `open_document` ask for udanax's CONFLICT_COPY — a fork of the
/// opened document into a new version — rather than a plain open? In either
/// spelling the recordings use: `conflict: "copy"`, or `copy` / `copy_mode:
/// "conflict_copy"`. The one reading both passes fork an open by.
pub fn is_conflict_copy(op: &Value) -> bool {
    str_field(op, &["conflict"]).is_some_and(|c| c == "copy")
        || str_field(op, &["copy", "copy_mode"]).is_some_and(|c| c == "conflict_copy")
}

/// A compare operand named by a top-level vspec-dict field: (field key,
/// golden docid, content-subspace (ord, width) windows).
pub type CompareOperand = (String, String, Vec<(u64, u64)>);

/// The operands a compare names by its own role-keyed vspec-dict fields
/// (policy `compare-operands-explicit`: ms_version_race's `version_a1`/
/// `original`, fanout's `dest`/`source`), its recorded answer's keys aside.
/// Exactly two make the compare explicit, its sides read from them alone.
/// The one reading both passes split a compare by.
pub fn compare_operands(op: &Value) -> Vec<CompareOperand> {
    const NOT_OPERAND: &[&str] = &["result", "pairs", "shared", "shared_spans"];
    let Some(o) = op.as_object() else { return Vec::new() };
    o.iter()
        .filter(|(k, _)| !NOT_OPERAND.contains(&k.as_str()))
        .filter_map(|(k, v)| {
            let (docid, regions) = vspec_dict(v)?;
            let windows = regions.iter().filter(|r| r.sub == 1).map(|r| (r.ord, r.width)).collect();
            Some((k.clone(), docid, windows))
        })
        .collect()
}

/// Does this `retrieve_endsets` address the LINK itself rather than a
/// document's region — a `search` naming link space, or a first
/// `from`/`source` vspec whose docid is a link address (links/
/// link_retrieval_via_endsets)? The one reading both passes split an
/// endsets query by.
pub fn endsets_in_link_space(op: &Value) -> bool {
    let first_docid = field(op, &["from", "source"])
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|v| v.get("docid"))
        .and_then(Value::as_str);
    str_field(op, &["search"]).is_some_and(|s| s.contains("link"))
        || first_docid.is_some_and(is_link_address)
}

/// A `to`/`dest` value that is a position marker, not a document reference:
/// "end", "start", "end of doc" (edgecases/vcopy_to_same_document).
pub fn is_position_marker(s: &str) -> bool {
    let t = s.trim().to_ascii_lowercase();
    t == "end" || t == "start" || t.starts_with("end of") || t.starts_with("start of")
}

/// A document roster: the op's `<name>: <golden docid>` fields, each binding
/// a name the scenario uses to a document the recording created —
/// create_sources' `source1`/`source2` (identity/identity_mixed_sources),
/// create_documents' `doc1`/`doc2` (subspace/insert_text_check_link_
/// positions), the `docs` op's `A`/`B`/`C` (isolation/cross_document_
/// transclusion_isolation). A create's own argument and result keys are no
/// names. Sorted by name.
pub fn roster(op: &Value) -> Vec<(String, String)> {
    const NOT_NAMES: &[&str] = &[
        "result", "results", "docs", "count", "texts", "type", "doc", "name", "doc_label",
        "chain",
    ];
    let Some(o) = op.as_object() else { return Vec::new() };
    let mut pairs: Vec<(String, String)> = o
        .iter()
        .filter(|(k, _)| !ANNOTATION_KEYS.contains(&k.as_str()) && !NOT_NAMES.contains(&k.as_str()))
        .filter_map(|(k, v)| {
            let id = v.as_str()?;
            let named = parse_dotted(id).is_some() && !is_link_address(id);
            named.then(|| (k.clone(), id.to_string()))
        })
        .collect();
    pairs.sort();
    pairs
}

/// One document a plural create makes, as [`documents_created`] reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatedDoc {
    /// The golden id the recording kept; `None` when it kept none, and each
    /// pass mints the document under the id it synthesizes as it goes
    /// (`Shadow::synthesize_docid`).
    pub id: Option<String>,
    /// The names the recording gives it, the first the one it is created
    /// under.
    pub names: Vec<String>,
    /// The text the op inserts into it at creation (`texts[k]`).
    pub text: Option<String>,
}

/// The documents a plural create makes ([`documents_created`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatedDocuments {
    /// The documents, in the order they are created.
    pub docs: Vec<CreatedDoc>,
    /// The op counts its documents — `results`, `count` — rather than naming
    /// them in a docs map or a roster: only a counted document carries a
    /// text, and only a counted document created empty is one an expansion
    /// plan may build.
    pub counted: bool,
}

/// The documents a `create_documents` op makes, in each shape the corpus
/// records, as both passes read it: a `docs` map of name → id, created in
/// id order; else a roster of `<name>: <docid>` fields ([`roster`]), in name
/// order; else counted — `count` documents, or as many as it records
/// `results` or `docs` names (one at least), each its `results` id, named
/// by its `docs` name or as the `k`th of its group ([`group_word`]: the
/// group's `<group>N`, with the singular `<g>N` and 0-based `<g>_k` the
/// scripts also use — "peripheral2" for group "peripherals", "target_0" in
/// identity_multi_document_sharing), and filled with its `texts` entry.
/// `Err` names a count past [`BUILD_BUDGET`]: no document is created then.
/// The one reading both passes create documents by.
pub fn documents_created(op: &Value) -> Result<CreatedDocuments, String> {
    let named = |pairs: Vec<(String, String)>| CreatedDocuments {
        docs: pairs
            .into_iter()
            .map(|(id, name)| CreatedDoc { id: Some(id), names: vec![name], text: None })
            .collect(),
        counted: false,
    };
    let mut by_id: Vec<(String, String)> = op
        .get("docs")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(n, id)| id.as_str().map(|i| (i.to_string(), n.clone())))
                .collect()
        })
        .unwrap_or_default();
    if !by_id.is_empty() {
        by_id.sort();
        return Ok(named(by_id));
    }
    let rostered = roster(op);
    if !rostered.is_empty() {
        return Ok(named(rostered.into_iter().map(|(name, id)| (id, name)).collect()));
    }
    let strings = |key: &str| -> Vec<String> {
        field(op, &[key])
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };
    let (results, names, texts) = (strings("results"), strings("docs"), strings("texts"));
    let group = group_word(op);
    let count = recorded_count(op)?
        .map(|c| c as usize)
        .unwrap_or_else(|| results.len().max(names.len()).max(1))
        .max(results.len());
    let docs = (0..count)
        .map(|k| {
            let primary =
                names.get(k).cloned().or_else(|| group.as_ref().map(|g| format!("{g}{}", k + 1)));
            let mut doc_names: Vec<String> = primary.into_iter().collect();
            if let Some(g) = &group {
                let singular = g.trim_end_matches('s');
                doc_names.push(format!("{singular}{}", k + 1));
                doc_names.push(format!("{singular}_{k}"));
            }
            let (id, text) = (results.get(k).cloned(), texts.get(k).cloned());
            CreatedDoc { id, names: doc_names, text }
        })
        .collect();
    Ok(CreatedDocuments { docs, counted: true })
}

/// Where an op's document argument points.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DocAim {
    /// An explicit document field that resolves.
    Named(String),
    /// A `…_doc<n>` token in the op's name ("insert_text_doc1").
    FromOpName(String),
    /// The current-document register, for an op that names no document.
    Register(String),
    /// An explicit document field that resolves to nothing: the reference,
    /// as recorded.
    Unresolved(String),
    /// The op names no document, and no document exists yet.
    FirstTouch,
}

/// The document an op aims at, as both passes read it: its explicit field
/// (`keys`), then a token of its name, then the current-document register —
/// the register only for a genuinely bare op, never in place of an explicit
/// reference that resolves to nothing. A document named by a field or by
/// the op's name becomes the register, mirroring the recording scripts'
/// scope.
pub fn aim_doc(shadow: &mut Shadow, op: &Value, keys: &[&str]) -> DocAim {
    if let Some(s) = str_field(op, keys) {
        return match shadow.resolve_doc(s) {
            Some(d) => {
                shadow.set_current(&d);
                DocAim::Named(d)
            }
            None => DocAim::Unresolved(s.to_string()),
        };
    }
    if let Some(d) = doc_from_op_name(op_name(op)).and_then(|name| shadow.resolve_doc(&name)) {
        shadow.set_current(&d);
        return DocAim::FromOpName(d);
    }
    match shadow.current() {
        Some(d) => DocAim::Register(d),
        None => DocAim::FirstTouch,
    }
}

/// The group word a plural create names its members with: an explicit
/// type/doc field ("peripherals" — links/star_hub_outgoing), else the role
/// the op's name carries ("create_multiple_targets" → "target").
pub fn group_word(op: &Value) -> Option<String> {
    if let Some(s) = str_field(op, &["type", "doc"]) {
        if parse_dotted(s).is_none() {
            return Some(s.to_string());
        }
    }
    let name = op_name(op).to_ascii_lowercase();
    if name.starts_with("create_") {
        for word in ["target", "source", "peripheral"] {
            if name.contains(word) {
                return Some(word.to_string());
            }
        }
    }
    None
}

/// `"A->B": "<link id>"` arrow-keyed create_link results
/// (links/multi_hop_reverse_traversal).
pub fn arrow_results(op: &Value) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    if let Some(o) = op.as_object() {
        for (k, v) in o {
            if let Some((f, t)) = k.split_once("->") {
                if let Some(r) = v.as_str() {
                    if link_home_docid(r).is_some() {
                        out.push((f.trim().to_string(), t.trim().to_string(), r.to_string()));
                    }
                }
            }
        }
    }
    out
}

/// Positional probes: the first two consecutive numeric `_`-tokens in the
/// op's name, read as subspace then ordinal ("text_at_1_3_before" → 1.3;
/// "pos_1_4_after" → 1.4).
pub fn position_from_op_name(op_name: &str) -> Option<VPoint> {
    let toks: Vec<&str> = op_name.split('_').collect();
    for w in toks.windows(2) {
        if let (Ok(sub), Ok(ord)) = (w[0].parse::<u64>(), w[1].parse::<u64>()) {
            return Some(VPoint { sub, ord });
        }
    }
    None
}

/// A doc reference carried by the op's name: `…_doc1` / `…_doc2`
/// (subspace/insert_text_check_link_positions "insert_text_doc1").
pub fn doc_from_op_name(op_name: &str) -> Option<String> {
    op_name
        .rsplit('_')
        .next()
        .filter(|t| t.starts_with("doc") && t[3..].parse::<u64>().is_ok())
        .map(str::to_string)
}

/// The symbolic name a create op binds: an explicit doc/name/label/role
/// field — versions/version_copies_what names its documents only by `role`
/// ("parent", "target") — or the role the op's name carries:
/// `create_target` names its doc "target" (identity/identity_mixed_sources
/// probes `doc: "target"` though no field ever bound it),
/// `create_doc2_and_copy` names "doc2". Generic create op names
/// (create_document, create_documents…) carry no role.
pub fn create_name_of(op: &Value) -> Option<String> {
    // `doc_label` is the corpus-extension recorder's explicit role name
    // (new-corpus files only; verified absent from the original 263).
    if let Some(s) = str_field(op, &["doc", "name", "label", "doc_label", "role"]) {
        if crate::tum::parse_dotted(s).is_none() {
            return Some(s.to_string());
        }
    }
    let name = op_name(op).to_ascii_lowercase();
    let role = name.strip_prefix("create_")?;
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

/// The addresses a create op's recording kept for the documents it made:
/// its `result` or `results` — one address, or a list of them — or a
/// `result` object holding the address under the name the op gives its
/// document ([`create_name_of`]: `create_doc2_and_copy`'s `result: {doc2:
/// "1.1.0.1.0.2", …}`, allocation_independence/all_operations_interleaved).
/// `None` when the recording kept none this grammar reads: the document is
/// then minted under a golden id the harness synthesizes
/// (`Shadow::synthesize_docid`). The one reading both passes create by.
pub fn created_addresses(op: &Value) -> Option<Vec<String>> {
    match field(op, &["result", "results"])? {
        Value::String(s) => Some(vec![s.clone()]),
        Value::Array(a) => Some(a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()),
        Value::Object(o) => {
            let id = o.get(&create_name_of(op)?)?.as_str()?;
            parse_dotted(id).is_some().then(|| vec![id.to_string()])
        }
        _ => None,
    }
}

/// The address a `create_version`'s recording kept for the version: its
/// `result`, or a `result` object's `version`.
pub fn version_result(op: &Value) -> Option<String> {
    match field(op, &["result"]) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Object(o)) => o.get("version").and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}

/// The document a `create_version` versions, as both passes read it: a
/// `from`/`source`/`of`/`original` reference that resolves, else a `doc` one
/// that does — `doc` usually names the NEW version (identity/
/// identity_through_rearrange_pivot), so only a resolving one names the
/// source — else the current-document register, tagged `doc-from-register`.
/// `None` when no document is in scope.
pub fn version_source(
    op: &Value,
    shadow: &Shadow,
    adaptations: &mut Vec<String>,
) -> Option<String> {
    str_field(op, &["from", "source", "of", "original"])
        .and_then(|s| shadow.resolve_doc(s))
        .or_else(|| str_field(op, &["doc"]).and_then(|s| shadow.resolve_doc(s)))
        .or_else(|| {
            adaptations.push("doc-from-register".into());
            shadow.current()
        })
}

/// The names a `create_version` gives the NEW version: its `doc`, `name`
/// and `label` fields — `doc` usually names the new version, never its
/// source unless it resolves ([`version_source`]). Each that is no address
/// and names no document yet comes to name the version (`Shadow::version`).
/// The one reading both passes name a version by.
pub fn version_names(op: &Value) -> Vec<&str> {
    ["doc", "name", "label"].iter().filter_map(|k| str_field(op, &[k])).collect()
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

// ────────────────────────────── vcopy sources ──────────────────────────────

/// One region an ordinary vcopy copies: the golden document, and the region
/// of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopySource {
    pub doc: String,
    pub region: VRegion,
}

/// An ordinary vcopy's source regions, read from the op's own fields
/// against the shadow alone — the one reading the play pass executes and
/// the pre-pass mirrors. In field order:
///
/// * a spec list of vspec dicts or located texts, or a single vspec dict
///   (`source: {docid, span}` — the corpus extension's fanout and depth
///   recordings);
/// * a `spans` list of span dicts (in the `from`/`source_doc` doc, else the
///   register's) or located texts;
/// * a `source_span`/`span` dict in the `from`/`source_doc` doc, else in the
///   first content-holding doc other than the destination reference;
/// * a `text`/`span` description;
/// * a `from`/`source` document (its whole current extent) or described
///   region. A description that grounds OUTSIDE its doc's live extent
///   grounded against the wrong doc — typically the register pointing at
///   the just-created empty destination — so it re-grounds against the
///   content-holding docs excluding the destination reference (policy
///   `vcopy-source-reaimed`; internal/ispan_partial_overlap's `from:
///   "positions 3-7 (CDEFG)"` with `to: "dest"`, confirmed by the recorded
///   post-state "CDEFG in both"). With no valid re-aim the original
///   grounding stands and diverges loudly.
///
/// Zero-width regions copy nothing and are dropped. The grounding policies
/// applied are pushed to `adaptations`; `Err` carries the reason the op is
/// inexpressible.
pub fn vcopy_sources(
    op: &Value,
    shadow: &Shadow,
    adaptations: &mut Vec<String>,
) -> Result<Vec<CopySource>, String> {
    let mut sources: Vec<CopySource> = Vec::new();
    let mut push = |doc: &str, region: VRegion| {
        if region.width > 0 {
            sources.push(CopySource { doc: doc.to_string(), region });
        }
    };
    let dest_ref = str_field(op, &["to", "dest", "target", "target_doc"])
        .filter(|t| !is_position_marker(t))
        .and_then(|t| shadow.resolve_doc(t))
        .unwrap_or_default();
    let named_source = str_field(op, &["from", "source_doc"]).and_then(|s| shadow.resolve_doc(s));
    let spec_items: Option<Vec<&Value>> =
        match field(op, &["specs", "specset", "source", "sources"]) {
            Some(Value::Array(a)) => Some(a.iter().collect()),
            Some(v @ Value::Object(_)) if vspec_dict(v).is_some() => Some(vec![v]),
            _ => None,
        };
    if let Some(items) = spec_items {
        for v in items {
            if let Some((docid, regions)) = vspec_dict(v) {
                for region in regions {
                    push(&docid, region);
                }
            } else if let Some(t) = v.as_str() {
                let l = locate(shadow, None, t).ok_or(format!("vcopy span {t:?} not groundable"))?;
                adaptations.push(l.how.tag().into());
                push(&l.doc, l.region());
            } else {
                return Err("vcopy spec list holds an unrecognized entry".into());
            }
        }
    } else if let Some(items) = field(op, &["spans"]).and_then(Value::as_array) {
        for v in items {
            if let Some(region) = span_dict(v) {
                if let Some(docid) = named_source.clone().or_else(|| shadow.current()) {
                    push(&docid, region);
                }
            } else if let Some(t) = v.as_str() {
                let l = locate(shadow, None, t).ok_or(format!("vcopy span {t:?} not groundable"))?;
                adaptations.push(l.how.tag().into());
                push(&l.doc, l.region());
            }
        }
    } else if let Some(region @ VRegion { sub: 1, .. }) =
        field(op, &["source_span", "span"]).and_then(span_dict)
    {
        let src = named_source
            .or_else(|| shadow.content_docs_except(&dest_ref).first().cloned())
            .ok_or("vcopy source_span with no source document")?;
        push(&src, region);
    } else if let Some(t) = str_field(op, &["text", "span"]) {
        let l = locate(shadow, named_source.as_deref(), t)
            .ok_or(format!("vcopy text {t:?} not groundable"))?;
        adaptations.push(l.how.tag().into());
        push(&l.doc, l.region());
    } else if let Some(s) = str_field(op, &["from", "source"]) {
        if let Some(from) = shadow.resolve_doc(s) {
            let n = shadow.text_len(&from);
            if n == 0 {
                return Err("vcopy from an empty document".into());
            }
            adaptations.push("whole-extent".into());
            push(&from, VPoint::content(1).region(n));
        } else if let Some(l) = locate(shadow, None, s) {
            // A described region's end, saturating: a recorded ordinal or
            // width at the top of the range lies outside every extent.
            let within =
                |c: &Located| c.ord.saturating_add(c.width) <= shadow.text_len(&c.doc) + 1;
            let l = if !within(&l) {
                match shadow.content_docs_except(&dest_ref).iter().find_map(|d| {
                    locate(shadow, Some(d.as_str()), s).filter(within)
                }) {
                    Some(re) => {
                        adaptations.push("vcopy-source-reaimed".into());
                        re
                    }
                    None => l,
                }
            } else {
                l
            };
            adaptations.push(l.how.tag().into());
            push(&l.doc, l.region());
        } else {
            return Err(format!("vcopy from {s:?}: neither a doc nor a groundable region"));
        }
    } else {
        return Err("vcopy without specs, span or text".into());
    }
    if sources.is_empty() {
        return Err("vcopy resolved to no source spans".into());
    }
    Ok(sources)
}

#[cfg(test)]
mod tests;
