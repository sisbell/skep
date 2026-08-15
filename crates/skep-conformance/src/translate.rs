//! The translator: canonical verb + fields → skep `Op`, executed and
//! compared in place. The catalogue is deliberately boring — one arm per
//! verb, exhaustive; a reader auditing "what does the harness do with
//! `vcopy`" finds one function that says so. Every adaptation policy is
//! named and recorded per-op; a label or field shape that cannot be
//! translated is classified `inexpressible` with the reason recorded —
//! never silently skipped.
//!
//! ## Adaptation policies (each recorded per-op when applied)
//!
//! * `open_document:noop` — skep has no bert/open layer (access control
//!   descoped); the op's `result` address still binds in the α-map (to the
//!   same skep doc).
//! * `open_document:conflict_copy→version` — the golden's own recorded
//!   result (a new sub-address of the source) shows CONFLICT_COPY forked a
//!   version.
//! * `close_document:noop` — no open layer, nothing to close.
//! * `type_registry` — link-type names (jump/quote/…) denote positions in a
//!   harness-created types document; udanax encoded them as vspecs into an
//!   unoccupied link subspace (unresolvable I-space). Type-slot data lying
//!   inside the types doc is harness infrastructure and is excluded from
//!   endset comparisons.
//! * `default_type_jump` — create_link without a type: the recording
//!   scripts' client always sent a typespec; jump is their default.
//! * `default_target_whole_doc` — create_link without target specs: the TO
//!   endset covers the whole current extent of the scenario's target-role
//!   document (the recording scripts' bare-link convention).
//! * `text-located:<field>` — a span was located by substring search in the
//!   golden-side shadow (source_text / delete-by-text / query).
//! * `append-at-end` — insert/vcopy without a position: appended at the
//!   current extent's end, as the recording scripts did.
//! * `position-from-label` — positional probes (`text_at_1_3_before`,
//!   `pos_1_4_after`, `link_at_2_1_after`) carry their position only in the
//!   label.
//! * `implicit_last_link` — follow_link without a link field follows the
//!   most recently created link.
//! * `account_as_delegate` / `create_node_as_delegate` — udanax account
//!   selection / sub-account minting map onto M3 delegation with a fresh
//!   principal per account.
//! * `follow_as_projection` — follow_link renders through `Op::Project`
//!   (I→V into a named document), the present-tense analog of udanax's
//!   V-spec follow; skep's raw FOLLOWLINK returns permanent I-spans, which
//!   the goldens never speak.
//! * `create_links:repeat` — a plural create with per-result binding
//!   repeats one MakeLink per recorded result.

use serde_json::Value;

use skep_address::Nat;
use skep_arrangement::{Run, VPos, VSpec};
use skep_content::Val;
use skep_discovery::{FourSet, SlotSpec};
use skep_febe::{Op, Response};
use skep_links::{enc, Endset};
use skep_retrieval::{Region, Spec};

use crate::alpha::Alpha;
use crate::compare::{
    compare_addr_sets, compare_expected_failure, compare_segments, compare_spansets,
    segments_from_delivery, segments_from_golden, Segment,
};
use crate::harness::Rig;
use crate::outcome::{OpOutcome, Status};
use crate::shadow::Shadow;
use crate::tum::{parse_dotted, parse_vpos, parse_width, vspan};

/// Allowlist grants pre-resolved for one op by the runner.
#[derive(Clone, Default)]
pub struct Grants {
    pub width_tolerance: u64,
    pub count_delta: i64,
    /// Classes whose entries match this op — a disagreement with any class
    /// present is verdict-allowlisted by the runner.
    pub classes: Vec<String>,
}

pub struct Cx<'a> {
    pub rig: &'a mut Rig,
    pub alpha: &'a mut Alpha,
    pub shadow: &'a mut Shadow,
}

// ─────────────────────────── verb normalization ────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    CreateDocument,
    OpenDocument,
    CloseDocument,
    Insert,
    Delete,
    DeleteAll,
    Vcopy,
    Pivot,
    Swap,
    Rearrange,
    CreateVersion,
    CreateLink,
    FollowLink,
    FindLinks,
    FindDocuments,
    Contents,
    Vspan,
    Vspanset,
    Endsets,
    Compare,
    Account,
    CreateNode,
    Meta,
}

impl Verb {
    pub fn name(self) -> &'static str {
        match self {
            Verb::CreateDocument => "create_document",
            Verb::OpenDocument => "open_document",
            Verb::CloseDocument => "close_document",
            Verb::Insert => "insert",
            Verb::Delete => "delete",
            Verb::DeleteAll => "delete_all",
            Verb::Vcopy => "vcopy",
            Verb::Pivot => "pivot",
            Verb::Swap => "swap",
            Verb::Rearrange => "rearrange",
            Verb::CreateVersion => "create_version",
            Verb::CreateLink => "create_link",
            Verb::FollowLink => "follow_link",
            Verb::FindLinks => "find_links",
            Verb::FindDocuments => "find_documents",
            Verb::Contents => "retrieve_contents",
            Verb::Vspan => "retrieve_vspan",
            Verb::Vspanset => "retrieve_vspanset",
            Verb::Endsets => "retrieve_endsets",
            Verb::Compare => "compare_versions",
            Verb::Account => "account",
            Verb::CreateNode => "create_node",
            Verb::Meta => "meta",
        }
    }
}

/// The meta/diagnostic labels (per the brief): executed nothing, compared
/// nothing, counted separately.
const META: &[&str] = &[
    "snapshot", "dump_state", "verify", "setup", "analysis", "note", "summary",
    "initial_state", "final_state",
];

/// Longest-matching verb stem, checked in table order (specific before
/// general — `vspanset` before `vspan`, `delete_all` before `delete`).
const STEMS: &[(&str, Verb)] = &[
    ("create_node", Verb::CreateNode),
    ("create_documents", Verb::CreateDocument),
    ("create_document", Verb::CreateDocument),
    ("create_doc", Verb::CreateDocument),
    ("create_sources", Verb::CreateDocument),
    ("create_target", Verb::CreateDocument),
    ("create_multiple_targets", Verb::CreateDocument),
    ("open_document", Verb::OpenDocument),
    ("close_document", Verb::CloseDocument),
    ("create_version", Verb::CreateVersion),
    ("version", Verb::CreateVersion),
    ("create_links", Verb::CreateLink),
    ("create_link", Verb::CreateLink),
    ("makelink", Verb::CreateLink),
    ("insert", Verb::Insert),
    ("append", Verb::Insert),
    ("delete_all", Verb::DeleteAll),
    ("remove_all", Verb::DeleteAll),
    ("delete", Verb::Delete),
    ("remove", Verb::Delete),
    ("vcopy", Verb::Vcopy),
    ("copy", Verb::Vcopy),
    ("pivot", Verb::Pivot),
    ("swap", Verb::Swap),
    ("rearrange", Verb::Rearrange),
    ("follow_link", Verb::FollowLink),
    ("follow_links", Verb::FollowLink),
    ("traverse", Verb::FollowLink),
    ("reverse_traversal", Verb::FollowLink),
    ("find_links", Verb::FindLinks),
    ("links_", Verb::FindLinks),
    ("links", Verb::FindLinks),
    ("find_documents", Verb::FindDocuments),
    ("find_docs", Verb::FindDocuments),
    ("docs", Verb::FindDocuments),
    ("retrieve_vspanset", Verb::Vspanset),
    ("vspanset", Verb::Vspanset),
    ("retrieve_vspan", Verb::Vspan),
    ("vspan", Verb::Vspan),
    ("retrieve_endsets", Verb::Endsets),
    ("endsets", Verb::Endsets),
    ("retrieve_contents", Verb::Contents),
    ("retrieve", Verb::Contents),
    ("contents", Verb::Contents),
    ("content", Verb::Contents),
    ("text_at", Verb::Contents),
    ("pos_", Verb::Contents),
    ("link_at", Verb::Contents),
    ("full_text", Verb::Contents),
    ("full_content", Verb::Contents),
    ("compare", Verb::Compare),
    ("comparisons", Verb::Compare),
    ("account", Verb::Account),
];

/// Normalize a label to a canonical verb: meta list, then the stem table,
/// then a field-shape fallback for pure state-probe labels (a `result` of
/// span dicts reads as a vspanset probe; of link addresses as an unfiltered
/// find_links; of plain strings as a contents probe). `None` ⇒
/// inexpressible.
pub fn normalize(label: &str, op: &Value) -> Option<Verb> {
    let l = label.to_ascii_lowercase();
    if META.iter().any(|m| l == *m || l.starts_with(&format!("{m}_"))) {
        return Some(Verb::Meta);
    }
    for (stem, verb) in STEMS {
        if l.starts_with(stem) {
            return Some(*verb);
        }
    }
    // Shape fallback for unknown probe labels.
    if let Some(res) = op.get("result") {
        if let Some(arr) = res.as_array() {
            if !arr.is_empty() && arr.iter().all(|v| span_dict(v).is_some()) {
                return Some(Verb::Vspanset);
            }
            if !arr.is_empty()
                && arr.iter().all(|v| v.as_str().is_some_and(is_link_address))
            {
                return Some(Verb::FindLinks);
            }
            if arr.iter().all(|v| v.as_str().is_some()) {
                return Some(Verb::Contents);
            }
        }
        if res.is_object() && (res.get("spans").is_some() || res.get("vspans").is_some()) {
            return Some(Verb::Vspanset);
        }
    }
    None
}

/// A link address in golden terms: `…·0·2·n` (a document's link subspace).
fn is_link_address(s: &str) -> bool {
    match parse_dotted(s) {
        Some(c) if c.len() >= 3 => c[c.len() - 3] == 0 && c[c.len() - 2] == 2,
        _ => false,
    }
}

// ───────────────────────────── field helpers ───────────────────────────────

fn field<'v>(op: &'v Value, keys: &[&str]) -> Option<&'v Value> {
    keys.iter().find_map(|k| op.get(*k)).filter(|v| !v.is_null())
}

fn str_field<'v>(op: &'v Value, keys: &[&str]) -> Option<&'v str> {
    field(op, keys).and_then(Value::as_str)
}

/// `{start, width}` or `{start, end}` span dict → (subspace, ord, width).
fn span_dict(v: &Value) -> Option<(u64, u64, u64)> {
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

/// A golden vspec dict `{docid, spans: [...]}` → (docid, [(sub, ord, w)]).
fn vspec_dict(v: &Value) -> Option<(String, Vec<(u64, u64, u64)>)> {
    let o = v.as_object()?;
    let docid = o.get("docid").and_then(Value::as_str)?.to_string();
    let spans = o.get("spans").and_then(Value::as_array)?;
    let parsed: Option<Vec<_>> = spans.iter().map(span_dict).collect();
    Some((docid, parsed?))
}

/// client.py `str()` forms: `<VSpec in D, at S for W, …>`, `<VSpan in D at S
/// for W>`, `<Span at S for W>` — some goldens recorded these verbatim.
fn parse_python_spec(s: &str) -> Option<(Option<String>, Vec<(u64, u64, u64)>)> {
    let s = s.trim().strip_prefix('<')?.strip_suffix('>')?;
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
        let (sub, ord) = parse_vpos(start.trim())?;
        let w = parse_width(width.trim())?;
        spans.push((sub, ord, w));
    }
    if spans.is_empty() {
        None
    } else {
        Some((doc, spans))
    }
}

/// The expected-content field: an array of strings, a bare string, or a
/// stringified python list ("['ACBDEFGH']").
fn expect_strings(v: &Value) -> Option<Vec<String>> {
    if let Some(arr) = v.as_array() {
        return Some(arr.iter().filter_map(|x| x.as_str().map(str::to_string)).collect());
    }
    let s = v.as_str()?;
    let t = s.trim();
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

/// The expected-spans field, in any of the golden's shapes. Returns
/// (optional docid, spans as (start, width) dotted strings).
fn expect_spans(v: &Value) -> Option<(Option<String>, Vec<(String, String)>)> {
    let render = |list: &[(u64, u64, u64)]| -> Vec<(String, String)> {
        list.iter().map(|(s, o, w)| (format!("{s}.{o}"), format!("0.{w}"))).collect()
    };
    if let Some(arr) = v.as_array() {
        let dicts: Option<Vec<_>> = arr.iter().map(span_dict).collect();
        if let Some(d) = dicts {
            return Some((None, render(&d)));
        }
        // A list of vspec dicts — flatten (single-doc callers only).
        let vspecs: Option<Vec<_>> = arr.iter().map(vspec_dict).collect();
        if let Some(vs) = vspecs {
            let doc = vs.first().map(|(d, _)| d.clone());
            let all: Vec<_> = vs.into_iter().flat_map(|(_, s)| s).collect();
            return Some((doc, render(&all)));
        }
        if arr.is_empty() {
            return Some((None, Vec::new()));
        }
        return None;
    }
    if let Some(o) = v.as_object() {
        if let Some((s, ord, w)) = span_dict(v) {
            return Some((None, render(&[(s, ord, w)])));
        }
        if let Some((doc, spans)) = vspec_dict(v) {
            return Some((Some(doc), render(&spans)));
        }
        for k in ["vspans", "spans"] {
            if let Some(arr) = o.get(k).and_then(Value::as_array) {
                let dicts: Option<Vec<_>> = arr.iter().map(span_dict).collect();
                let doc = o.get("docid").and_then(Value::as_str).map(str::to_string);
                return dicts.map(|d| (doc, render(&d)));
            }
        }
        return None;
    }
    if let Some(s) = v.as_str() {
        let (doc, spans) = parse_python_spec(s)?;
        return Some((doc, render(&spans)));
    }
    None
}

/// Did the golden record this op as a failure? (`error` non-null and not the
/// scripts' "N/A" placeholder, or an explicit failed status.)
fn expected_failure(op: &Value) -> Option<String> {
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

/// Resolve a document reference field to a golden docid (address string or
/// symbolic role), with the most-recently-created doc as the recording
/// scripts' implicit default.
fn doc_ref(cx: &Cx, op: &Value, keys: &[&str]) -> Option<String> {
    if let Some(s) = str_field(op, keys) {
        return cx.shadow.resolve_doc(s);
    }
    cx.shadow.created.last().cloned()
}

fn skep_doc(cx: &mut Cx, golden: &str) -> Option<skep_address::Address> {
    cx.alpha.translate(golden)
}

/// Note a rejection (or an unexpected shape) against an op expected to
/// succeed.
fn fail_response(out: &mut OpOutcome, comparator: &str, expected: &str, r: &Response) {
    out.status = Status::Disagreed;
    out.comparator = Some(comparator.to_string());
    out.expected = Some(expected.to_string());
    out.actual = Some(match r {
        Response::Rejected(rej) => format!("Rejected({:?})", rej.code),
        _ => "unexpected response shape".to_string(),
    });
}

fn inexpressible(out: &mut OpOutcome, reason: String) {
    out.status = Status::Inexpressible;
    out.note = Some(reason);
}

fn rejection_code(r: &Response) -> Option<String> {
    match r {
        Response::Rejected(rej) => Some(format!("{:?}", rej.code)),
        _ => None,
    }
}

fn vpos(sub: u64, ord: u64) -> VPos {
    VPos { subspace: Nat::from(sub), ordinal: Nat::from(ord) }
}

/// Shared post-execution verdict for ops whose only comparable aspect is
/// success/failure: reconcile skep's accept/reject with the golden's
/// recorded expectation.
fn settle_ack(out: &mut OpOutcome, xf: Option<String>, rejected: Option<String>) -> bool {
    match (xf, rejected) {
        (None, None) => true, // both succeeded — caller continues
        (Some(_), Some(code)) => {
            out.status = Status::Agreed;
            out.comparator = Some("expected-failure".into());
            out.note = Some(format!("both sides failed (skep: {code})"));
            false
        }
        (None, Some(code)) => {
            out.status = Status::Disagreed;
            out.comparator = Some("rejection".into());
            out.expected = Some("success (golden recorded no error)".into());
            out.actual = Some(format!("Rejected({code})"));
            false
        }
        (Some(err), None) => {
            out.status = Status::Disagreed;
            out.comparator = Some("expected-failure".into());
            let (e, a) = match compare_expected_failure(&err, None) {
                Err(pair) => pair,
                Ok(()) => unreachable!("None rejection with recorded error always disagrees"),
            };
            out.expected = Some(e);
            out.actual = Some(a);
            false
        }
    }
}

// ────────────────────────────── the catalogue ──────────────────────────────

/// Translate, execute, and compare one golden operation. Exactly one
/// `OpOutcome` per op, whatever happens.
pub fn run_op(cx: &mut Cx, index: usize, op: &Value, grants: &Grants) -> OpOutcome {
    let label = op.get("op").and_then(Value::as_str).unwrap_or("").to_string();
    let mut out = OpOutcome::new(index, &label);
    if label.is_empty() {
        inexpressible(&mut out, "operation has no `op` label".into());
        return out;
    }
    let Some(verb) = normalize(&label, op) else {
        let keys: Vec<&str> = op.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        inexpressible(&mut out, format!("label `{label}` (fields {keys:?}) has no canonical verb"));
        return out;
    };
    out.verb = verb.name().to_string();
    match verb {
        Verb::Meta => out.status = Status::Meta,
        Verb::CreateDocument => h_create_document(cx, op, &mut out),
        Verb::OpenDocument => h_open_document(cx, op, &mut out),
        Verb::CloseDocument => {
            out.adaptations.push("close_document:noop".into());
            out.status = Status::NotCompared;
        }
        Verb::Insert => h_insert(cx, op, &mut out, grants),
        Verb::Delete => h_delete(cx, op, &mut out, false),
        Verb::DeleteAll => h_delete(cx, op, &mut out, true),
        Verb::Vcopy => h_vcopy(cx, op, &mut out),
        Verb::Pivot => h_pivot_swap(cx, op, &mut out, true),
        Verb::Swap => h_pivot_swap(cx, op, &mut out, false),
        Verb::Rearrange => {
            let n = field(op, &["cuts"]).and_then(Value::as_array).map(|a| a.len());
            match n {
                Some(3) => h_pivot_swap(cx, op, &mut out, true),
                Some(4) => h_pivot_swap(cx, op, &mut out, false),
                _ => inexpressible(&mut out, "rearrange without a 3- or 4-cut list".into()),
            }
        }
        Verb::CreateVersion => h_create_version(cx, op, &mut out),
        Verb::CreateLink => h_create_link(cx, op, &mut out),
        Verb::FollowLink => h_follow_link(cx, op, &mut out, grants),
        Verb::FindLinks => h_find_links(cx, op, &mut out),
        Verb::FindDocuments => h_find_documents(cx, op, &mut out),
        Verb::Contents => h_contents(cx, op, &mut out, &label),
        Verb::Vspan => h_vspanset(cx, op, &mut out, grants, false),
        Verb::Vspanset => h_vspanset(cx, op, &mut out, grants, true),
        Verb::Endsets => h_endsets(cx, op, &mut out),
        Verb::Compare => h_compare(cx, op, &mut out),
        Verb::Account => h_account(cx, op, &mut out),
        Verb::CreateNode => h_create_node(cx, op, &mut out),
    }
    out
}

fn h_create_document(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    let name = str_field(op, &["doc", "name"])
        .filter(|s| !crate::alpha::looks_like_address(s))
        .map(str::to_string);
    let goldens: Vec<String> = match field(op, &["result", "results"]) {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        _ => Vec::new(),
    };
    let xf = expected_failure(op);
    if goldens.is_empty() {
        // Nothing to bind; still execute one create so scenario document
        // counting stays honest, and note the unbindable result.
        let r = cx.rig.exec(Op::CreateNewDocument { account: cx.rig.current_account.clone() });
        if settle_ack(out, xf, rejection_code(&r)) {
            out.status = Status::NotCompared;
            out.note = Some("create_document with no recorded result to bind".into());
        }
        return;
    }
    for (i, golden) in goldens.iter().enumerate() {
        let r = cx.rig.exec(Op::CreateNewDocument { account: cx.rig.current_account.clone() });
        match r {
            Response::AckAddr { addr, .. } => {
                cx.alpha.bind(golden, &addr);
                cx.shadow.create_doc(golden, if i == 0 { name.as_deref() } else { None });
            }
            other => {
                if !settle_ack(out, xf.clone(), rejection_code(&other)) {
                    return;
                }
            }
        }
    }
    if !settle_ack(out, xf, None) {
        return;
    }
    out.status = Status::Agreed;
    out.comparator = Some("address-binding".into());
}

fn h_open_document(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    let Some(doc) = doc_ref(cx, op, &["doc", "docid", "document"]) else {
        inexpressible(out, "open_document without a resolvable doc".into());
        return;
    };
    let conflict_copy = str_field(op, &["conflict"]).is_some_and(|c| c == "copy")
        || str_field(op, &["copy", "copy_mode"]).is_some_and(|c| c == "conflict_copy");
    let result = str_field(op, &["result"]).map(str::to_string);
    if conflict_copy {
        out.adaptations.push("open_document:conflict_copy→version".into());
        let Some(src) = skep_doc(cx, &doc) else {
            out.status = Status::Disagreed;
            out.comparator = Some("alpha".into());
            out.note = Some(format!("open_document(conflict=copy) of unresolvable doc {doc}"));
            return;
        };
        match cx.rig.exec(Op::Version { d_src: src }) {
            Response::AckAddr { addr, .. } => {
                if let Some(g) = &result {
                    cx.alpha.bind(g, &addr);
                    cx.shadow.version(&doc, g);
                }
                out.status = Status::Agreed;
                out.comparator = Some("address-binding".into());
            }
            other => fail_response(out, "rejection", "version address (CONFLICT_COPY)", &other),
        }
        return;
    }
    out.adaptations.push("open_document:noop".into());
    // The open result names the same document — bind the alias so both
    // spellings translate.
    if let Some(g) = &result {
        if let Some(a) = skep_doc(cx, &doc) {
            cx.alpha.bind(g, &a);
        }
    }
    out.status = Status::NotCompared;
}

fn h_insert(cx: &mut Cx, op: &Value, out: &mut OpOutcome, grants: &Grants) {
    let Some(doc) = doc_ref(cx, op, &["doc", "docid"]) else {
        inexpressible(out, "insert with no document in scope".into());
        return;
    };
    // Text: field, strings array, or the wrapper-label form insert_<n>_<TEXT>.
    let text: Option<String> = str_field(op, &["text", "content", "string"])
        .map(str::to_string)
        .or_else(|| {
            field(op, &["strings", "texts"])
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(""))
        })
        .or_else(|| {
            let label = op.get("op").and_then(Value::as_str)?;
            let rest = label.strip_prefix("insert_")?;
            let (_ord, text) = rest.split_once('_')?;
            out.adaptations.push("args-from-label".into());
            Some(text.to_string())
        });
    let Some(text) = text else {
        inexpressible(out, "insert without text".into());
        return;
    };
    let (sub, ord) = match str_field(op, &["address", "at", "position", "vaddr"]) {
        Some(p) => match parse_vpos(p) {
            Some(x) => x,
            None => {
                inexpressible(out, format!("insert position `{p}` is not a V-position"));
                return;
            }
        },
        None => {
            // Wrapper labels insert_<n>_<TEXT> carry the ordinal in the label.
            let from_label = op
                .get("op")
                .and_then(Value::as_str)
                .and_then(|l| l.strip_prefix("insert_"))
                .and_then(|r| r.split_once('_'))
                .and_then(|(o, _)| o.parse::<u64>().ok());
            match from_label {
                Some(o) => (1, o),
                None => {
                    out.adaptations.push("append-at-end".into());
                    (1, cx.shadow.text_len(&doc) + 1)
                }
            }
        }
    };
    let Some(d) = skep_doc(cx, &doc) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("insert into unresolvable doc {doc}"));
        return;
    };
    let xf = expected_failure(op);
    let values: Vec<Val> = text.bytes().map(|b| Val::new(vec![b])).collect();
    let r = cx.rig.exec(Op::Insert { doc: d, at: vpos(sub, ord), values });
    if !settle_ack(out, xf, rejection_code(&r)) {
        return;
    }
    if sub == 1 {
        cx.shadow.insert(&doc, ord, text.as_bytes());
    }
    // Some wrapper forms record the post-insert vspanset as the result.
    if let Some(res) = field(op, &["result"]) {
        if let Some((_, spans)) = expect_spans(res) {
            let Some(d2) = skep_doc(cx, &doc) else { return };
            match cx.rig.exec(Op::RetrieveDocVSpanSet { doc: d2 }) {
                Response::SpanSet { set, .. } => {
                    out.comparator = Some("vspanset".into());
                    match compare_spansets(&spans, &set, grants.width_tolerance) {
                        Ok(()) => out.status = Status::Agreed,
                        Err((e, a)) => {
                            out.status = Status::Disagreed;
                            out.expected = Some(e);
                            out.actual = Some(a);
                        }
                    }
                }
                other => fail_response(out, "vspanset", "post-insert vspanset", &other),
            }
            return;
        }
        out.status = Status::NotCompared;
        out.note = Some("insert result in a shape the harness does not compare".into());
        return;
    }
    out.status = Status::NotCompared;
}

fn h_delete(cx: &mut Cx, op: &Value, out: &mut OpOutcome, all: bool) {
    let Some(doc) = doc_ref(cx, op, &["doc", "docid"]) else {
        inexpressible(out, "delete with no document in scope".into());
        return;
    };
    let xf = expected_failure(op);
    let (sub, ord, width) = if all {
        let n = cx.shadow.text_len(&doc);
        if n == 0 {
            out.adaptations.push("delete_all:empty-noop".into());
            out.status = Status::NotCompared;
            out.note = Some("document already empty; nothing to delete".into());
            return;
        }
        (1, 1, n)
    } else if let Some(t) = str_field(op, &["text"]) {
        match cx.shadow.find_text(Some(&doc), t) {
            Some((_, ord)) => {
                out.adaptations.push("text-located:text".into());
                (1, ord, t.len() as u64)
            }
            None => {
                if xf.is_some() {
                    out.status = Status::Agreed;
                    out.comparator = Some("expected-failure".into());
                    out.note =
                        Some("delete-by-text not locatable; golden also recorded failure".into());
                } else {
                    inexpressible(out, format!("delete text {t:?} not found in {doc}"));
                }
                return;
            }
        }
    } else if let Some(sp) = field(op, &["span", "vspan"]).and_then(span_dict) {
        sp
    } else if let Some(start) = str_field(op, &["start", "address", "at"]) {
        let Some((sub, ord)) = parse_vpos(start) else {
            inexpressible(out, format!("delete start `{start}` is not a V-position"));
            return;
        };
        let width = if let Some(w) = str_field(op, &["width"]).and_then(parse_width) {
            w
        } else if let Some(e) = str_field(op, &["end"]) {
            match parse_dotted(e).as_deref() {
                Some([0, w]) => *w,
                Some([esub, eord]) if *esub == sub && *eord >= ord => eord - ord,
                _ => {
                    inexpressible(out, format!("delete end `{e}` unintelligible"));
                    return;
                }
            }
        } else if let Some(n) = field(op, &["count"]).and_then(Value::as_u64) {
            n
        } else {
            inexpressible(out, "delete without width/end/count".into());
            return;
        };
        (sub, ord, width)
    } else {
        inexpressible(out, "delete without text/span/start".into());
        return;
    };
    let Some(d) = skep_doc(cx, &doc) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("delete in unresolvable doc {doc}"));
        return;
    };
    let r = cx.rig.exec(Op::Delete { doc: d, p: vpos(sub, ord), width: Nat::from(width) });
    if !settle_ack(out, xf, rejection_code(&r)) {
        return;
    }
    if sub == 1 {
        cx.shadow.delete(&doc, ord, width);
    }
    out.status = Status::NotCompared;
}

fn h_vcopy(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    // Source spec(s): explicit vspec dicts, or a text located in the shadow.
    let mut specs: Vec<VSpec> = Vec::new();
    let mut copied: Vec<u8> = Vec::new();
    let mut src_doc: Option<String> = None;
    if let Some(arr) = field(op, &["specs", "specset", "source", "sources"]).and_then(Value::as_array)
    {
        for v in arr {
            let Some((docid, spans)) = vspec_dict(v) else {
                inexpressible(out, "vcopy spec list holds a non-vspec entry".into());
                return;
            };
            let Some(sd) = skep_doc(cx, &docid) else {
                out.status = Status::Disagreed;
                out.comparator = Some("alpha".into());
                out.note = Some(format!("vcopy source doc {docid} unresolvable"));
                return;
            };
            src_doc.get_or_insert(docid.clone());
            for (sub, ord, w) in spans {
                let Some(span) = vspan(sub, ord, w) else { continue };
                copied.extend(cx.shadow.slice(&docid, ord, w));
                specs.push(VSpec { source: sd.clone(), span });
            }
        }
    } else if let Some(t) = str_field(op, &["text", "span"]) {
        let from = str_field(op, &["from", "source_doc"])
            .and_then(|s| cx.shadow.resolve_doc(s));
        match cx.shadow.find_text(from.as_deref(), t) {
            Some((docid, ord)) => {
                out.adaptations.push("text-located:text".into());
                let w = t.len() as u64;
                let Some(sd) = skep_doc(cx, &docid) else {
                    out.status = Status::Disagreed;
                    out.comparator = Some("alpha".into());
                    out.note = Some(format!("vcopy source doc {docid} unresolvable"));
                    return;
                };
                let Some(span) = vspan(1, ord, w) else {
                    inexpressible(out, "vcopy of empty text".into());
                    return;
                };
                copied = cx.shadow.slice(&docid, ord, w);
                src_doc = Some(docid);
                specs.push(VSpec { source: sd, span });
            }
            None => {
                inexpressible(out, format!("vcopy text {t:?} not found in any document"));
                return;
            }
        }
    } else {
        inexpressible(out, "vcopy without specs or text".into());
        return;
    }
    // Destination doc + position. `to` may be a doc reference or the
    // position markers "end"/"start" (destination = the source doc then).
    let to_raw = str_field(op, &["to", "dest", "target"]);
    let dest: Option<String> = match to_raw {
        Some("end") | Some("start") => src_doc.clone(),
        Some(s) => cx.shadow.resolve_doc(s),
        None => doc_ref(cx, op, &["doc", "docid"]),
    };
    let Some(dest) = dest else {
        inexpressible(out, "vcopy without a resolvable destination".into());
        return;
    };
    let ord = match str_field(op, &["address", "at", "position"]) {
        Some(p) => match parse_vpos(p) {
            Some((1, o)) => o,
            _ => {
                inexpressible(out, format!("vcopy position `{p}` is not a content V-position"));
                return;
            }
        },
        None => {
            if to_raw == Some("start") {
                1
            } else {
                out.adaptations.push("append-at-end".into());
                cx.shadow.text_len(&dest) + 1
            }
        }
    };
    let Some(d) = skep_doc(cx, &dest) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("vcopy destination {dest} unresolvable"));
        return;
    };
    let xf = expected_failure(op);
    let r = cx.rig.exec(Op::Copy { doc: d, at: vpos(1, ord), specs });
    if !settle_ack(out, xf, rejection_code(&r)) {
        return;
    }
    cx.shadow.insert(&dest, ord, &copied);
    out.status = Status::NotCompared;
}

fn h_pivot_swap(cx: &mut Cx, op: &Value, out: &mut OpOutcome, pivot: bool) {
    let Some(doc) = doc_ref(cx, op, &["doc", "docid"]) else {
        inexpressible(out, "rearrange with no document in scope".into());
        return;
    };
    let parse_cut = |v: &Value| -> Option<u64> {
        if let Some(n) = v.as_u64() {
            return Some(n);
        }
        match parse_vpos(v.as_str()?) {
            Some((1, o)) => Some(o),
            _ => None,
        }
    };
    let mut cuts: Vec<u64> = Vec::new();
    if let Some(arr) = field(op, &["cuts"]).and_then(Value::as_array) {
        for v in arr {
            match parse_cut(v) {
                Some(c) => cuts.push(c),
                None => {
                    inexpressible(out, "rearrange cut is not a content position".into());
                    return;
                }
            }
        }
    } else if pivot {
        for k in [["v1", "start"], ["v2", "pivot"], ["v3", "end"]] {
            match field(op, &k).and_then(parse_cut) {
                Some(c) => cuts.push(c),
                None => break,
            }
        }
    } else if let Some(regions) = field(op, &["regions"]).and_then(Value::as_array) {
        // Two texts to exchange, located in the shadow.
        let texts: Vec<&str> = regions.iter().filter_map(Value::as_str).collect();
        if texts.len() == 2 {
            let a = cx.shadow.find_text(Some(&doc), texts[0]);
            let b = cx.shadow.find_text(Some(&doc), texts[1]);
            if let (Some((_, s1)), Some((_, s2))) = (a, b) {
                out.adaptations.push("text-located:regions".into());
                let (w1, w2) = (texts[0].len() as u64, texts[1].len() as u64);
                let (s1, e1, s2, e2) = if s1 <= s2 {
                    (s1, s1 + w1, s2, s2 + w2)
                } else {
                    (s2, s2 + w2, s1, s1 + w1)
                };
                cuts = vec![s1, e1, s2, e2];
            }
        }
    } else {
        for k in [["starta"], ["enda"], ["startb"], ["endb"]] {
            match field(op, &k).and_then(parse_cut) {
                Some(c) => cuts.push(c),
                None => break,
            }
        }
    }
    let want = if pivot { 3 } else { 4 };
    if cuts.len() != want {
        inexpressible(out, format!("rearrange needs {want} cuts, could derive {}", cuts.len()));
        return;
    }
    let Some(d) = skep_doc(cx, &doc) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("rearrange in unresolvable doc {doc}"));
        return;
    };
    let xf = expected_failure(op);
    let r = cx.rig.exec(Op::Rearrange {
        doc: d,
        cuts: cuts.iter().map(|&c| vpos(1, c)).collect(),
    });
    if !settle_ack(out, xf, rejection_code(&r)) {
        return;
    }
    if pivot {
        cx.shadow.pivot(&doc, cuts[0], cuts[1], cuts[2]);
    } else {
        cx.shadow.swap(&doc, cuts[0], cuts[1], cuts[2], cuts[3]);
    }
    out.status = Status::NotCompared;
}

fn h_create_version(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    let Some(src) = doc_ref(cx, op, &["from", "doc", "source", "of"]) else {
        inexpressible(out, "create_version with no source document".into());
        return;
    };
    let golden = match field(op, &["result"]) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Object(o)) => o.get("version").and_then(Value::as_str).map(str::to_string),
        _ => None,
    };
    let Some(d_src) = skep_doc(cx, &src) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("version of unresolvable doc {src}"));
        return;
    };
    let xf = expected_failure(op);
    let r = cx.rig.exec(Op::Version { d_src });
    match r {
        Response::AckAddr { addr, .. } => {
            if !settle_ack(out, xf, None) {
                return;
            }
            if let Some(g) = &golden {
                cx.alpha.bind(g, &addr);
                cx.shadow.version(&src, g);
                out.status = Status::Agreed;
                out.comparator = Some("address-binding".into());
            } else {
                out.status = Status::NotCompared;
                out.note = Some("create_version with no recorded result to bind".into());
            }
        }
        other => {
            settle_ack(out, xf, rejection_code(&other));
        }
    }
}

fn h_create_link(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    // Endset assembly. Explicit vspec lists translate directly; strings are
    // located in the shadow; a missing target falls to the whole-doc policy.
    let collect = |cx: &mut Cx,
                       out: &mut OpOutcome,
                       v: Option<&Value>,
                       text_key: &str,
                       text: Option<&str>|
     -> Result<(Vec<VSpec>, Option<String>), String> {
        let mut specs = Vec::new();
        let mut first_doc = None;
        if let Some(arr) = v.and_then(Value::as_array) {
            for item in arr {
                let Some((docid, spans)) = vspec_dict(item) else {
                    return Err("endset list holds a non-vspec entry".into());
                };
                let Some(sd) = cx.alpha.translate(&docid) else {
                    return Err(format!("endset doc {docid} unresolvable"));
                };
                first_doc.get_or_insert(docid);
                for (sub, ord, w) in spans {
                    if let Some(span) = vspan(sub, ord, w) {
                        specs.push(VSpec { source: sd.clone(), span });
                    }
                }
            }
            return Ok((specs, first_doc));
        }
        let text = v.and_then(Value::as_str).or(text);
        if let Some(t) = text {
            match cx.shadow.find_text(None, t) {
                Some((docid, ord)) => {
                    out.adaptations.push(format!("text-located:{text_key}"));
                    let sd = cx
                        .alpha
                        .translate(&docid)
                        .ok_or_else(|| format!("endset doc {docid} unresolvable"))?;
                    let span = vspan(1, ord, t.len() as u64)
                        .ok_or_else(|| "empty endset text".to_string())?;
                    specs.push(VSpec { source: sd, span });
                    first_doc = Some(docid);
                }
                None => return Err(format!("endset text {t:?} not found")),
            }
        }
        Ok((specs, first_doc))
    };

    let (from, from_doc) = match collect(
        cx,
        out,
        field(op, &["source", "from"]),
        "source_text",
        str_field(op, &["source_text"]),
    ) {
        Ok(x) => x,
        Err(e) => {
            inexpressible(out, format!("create_link source: {e}"));
            return;
        }
    };
    let (mut to, _) = match collect(
        cx,
        out,
        field(op, &["target", "to"]),
        "target_text",
        str_field(op, &["target_text"]),
    ) {
        Ok(x) => x,
        Err(e) => {
            inexpressible(out, format!("create_link target: {e}"));
            return;
        }
    };
    if to.is_empty() {
        // Policy default_target_whole_doc: whole current extent of the
        // target-role document (when one exists and has content).
        if let Some(tgt) = cx.shadow.resolve_doc("target").filter(|t| Some(t) != from_doc.as_ref())
        {
            let n = cx.shadow.text_len(&tgt);
            if n > 0 {
                if let (Some(sd), Some(span)) = (cx.alpha.translate(&tgt), vspan(1, 1, n)) {
                    out.adaptations.push("default_target_whole_doc".into());
                    to.push(VSpec { source: sd, span });
                }
            }
        }
    }
    let home_golden = str_field(op, &["home_doc", "home"])
        .and_then(|s| cx.shadow.resolve_doc(s))
        .or(from_doc)
        .or_else(|| cx.shadow.created.first().cloned());
    let Some(home_golden) = home_golden else {
        inexpressible(out, "create_link with no home document in scope".into());
        return;
    };
    let Some(home) = skep_doc(cx, &home_golden) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("create_link home {home_golden} unresolvable"));
        return;
    };
    let ty_name = str_field(op, &["type", "link_type"]).unwrap_or_else(|| {
        out.adaptations.push("default_type_jump".into());
        "jump"
    });
    out.adaptations.push("type_registry".into());
    let Some(ty) = cx.rig.type_vspec(ty_name) else {
        inexpressible(out, format!("type registry capacity exhausted for `{ty_name}`"));
        return;
    };

    let goldens: Vec<String> = match field(op, &["result", "results"]) {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => {
            if a.len() > 1 {
                out.adaptations.push("create_links:repeat".into());
            }
            a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
        }
        _ => Vec::new(),
    };
    let xf = expected_failure(op);
    let count = goldens.len().max(1);
    for i in 0..count {
        let r = cx.rig.exec(Op::MakeLink {
            home: home.clone(),
            from: from.clone(),
            to: to.clone(),
            ty: vec![ty.clone()],
        });
        match r {
            Response::AckAddr { addr, .. } => {
                cx.shadow.seat_link(&home_golden);
                if let Some(g) = goldens.get(i) {
                    cx.alpha.bind(g, &addr);
                    cx.shadow.last_link = Some(g.clone());
                }
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
    if goldens.is_empty() {
        out.status = Status::NotCompared;
        out.note = Some("create_link with no recorded result to bind".into());
    } else {
        out.status = Status::Agreed;
        out.comparator = Some("address-binding".into());
    }
}

/// Resolve a link-slot name to M7's positional index (FROM=1, TO=2, TYPE=3).
fn slot_of(name: &str) -> Option<usize> {
    match name {
        "source" | "sources" | "from" => Some(1),
        "target" | "targets" | "to" => Some(2),
        "type" => Some(3),
        _ => None,
    }
}

fn h_follow_link(cx: &mut Cx, op: &Value, out: &mut OpOutcome, grants: &Grants) {
    out.adaptations.push("follow_as_projection".into());
    let label = op.get("op").and_then(Value::as_str).unwrap_or("");
    let slot = str_field(op, &["end", "direction", "linkend", "which"])
        .and_then(slot_of)
        .or_else(|| {
            // follow_links_to_targets / follow_links_source and friends carry
            // the slot in the label.
            if label.contains("source") {
                Some(1)
            } else if label.contains("target") {
                Some(2)
            } else if label.contains("type") {
                Some(3)
            } else {
                None
            }
        })
        .unwrap_or_else(|| {
            out.adaptations.push("default-slot:target".into());
            2
        });
    let link_golden = str_field(op, &["link", "link_id", "id"])
        .filter(|s| crate::alpha::looks_like_address(s))
        .map(str::to_string)
        .or_else(|| {
            out.adaptations.push("implicit_last_link".into());
            cx.shadow.last_link.clone()
        });
    let Some(link_golden) = link_golden else {
        inexpressible(out, "follow_link with no link in scope".into());
        return;
    };
    let Some(link) = cx.alpha.translate(&link_golden) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("follow of unresolvable link {link_golden}"));
        return;
    };
    let Some(expected) = field(op, &["result", "content", "contents", "expected", "spans"]) else {
        out.status = Status::NotCompared;
        out.note = Some("follow_link with nothing recorded to compare".into());
        return;
    };
    // One projection per document; a rejection is evidence, not a crash.
    let project = |cx: &mut Cx, d: &skep_address::Address| -> Result<skep_address::SpanSet, String> {
        match cx.rig.exec(Op::Project { a: link.clone(), slot, d: d.clone() }) {
            Response::SpanSet { set, .. } => Ok(set),
            r => Err(rejection_code(&r).unwrap_or_else(|| "unexpected response".into())),
        }
    };

    // Shape 1: vspec dicts (possibly several docs) — compare spans per doc.
    let as_vspecs: Option<Vec<(String, Vec<(u64, u64, u64)>)>> = expected
        .as_array()
        .and_then(|arr| arr.iter().map(vspec_dict).collect());
    if let Some(vspecs) = as_vspecs {
        if !vspecs.is_empty() {
            out.comparator = Some("projection".into());
            let mut fails: Vec<(String, String)> = Vec::new();
            for (docid, spans) in vspecs {
                let Some(d) = cx.alpha.translate(&docid) else {
                    fails.push((format!("{docid}: spans"), format!("{docid}: unresolvable")));
                    continue;
                };
                let want: Vec<(String, String)> = spans
                    .iter()
                    .map(|(s, o, w)| (format!("{s}.{o}"), format!("0.{w}")))
                    .collect();
                match project(cx, &d) {
                    Ok(set) => {
                        if let Err((e, a)) = compare_spansets(&want, &set, grants.width_tolerance) {
                            fails.push((format!("{docid}: {e}"), format!("{docid}: {a}")));
                        }
                    }
                    Err(code) => fails.push((format!("{docid}: spans"), format!("{docid}: {code}"))),
                }
            }
            if fails.is_empty() {
                out.status = Status::Agreed;
            } else {
                out.status = Status::Disagreed;
                out.expected = Some(fails.iter().map(|f| f.0.clone()).collect::<Vec<_>>().join(" | "));
                out.actual = Some(fails.iter().map(|f| f.1.clone()).collect::<Vec<_>>().join(" | "));
            }
            return;
        }
    }
    // Shape 2: python VSpec string.
    if let Some(s) = expected.as_str() {
        if let Some((Some(docid), spans)) = parse_python_spec(s) {
            let want: Vec<(String, String)> =
                spans.iter().map(|(s, o, w)| (format!("{s}.{o}"), format!("0.{w}"))).collect();
            out.comparator = Some("projection".into());
            let target = cx.alpha.translate(&docid);
            let projected = match target {
                Some(d) => project(cx, &d),
                None => Err("unresolvable".to_string()),
            };
            match projected {
                Ok(set) => match compare_spansets(&want, &set, grants.width_tolerance) {
                    Ok(()) => out.status = Status::Agreed,
                    Err((e, a)) => {
                        out.status = Status::Disagreed;
                        out.expected = Some(e);
                        out.actual = Some(a);
                    }
                },
                Err(code) => {
                    out.status = Status::Disagreed;
                    out.expected = Some(format!("{docid}: spans"));
                    out.actual = Some(format!("{docid}: {code}"));
                }
            }
            return;
        }
    }
    // Shape 3: strings (endset CONTENT) or the empty list. Project into
    // every scenario document; retrieve the projected spans; compare text.
    let Some(strings) = expect_strings(expected) else {
        inexpressible(out, "follow_link expectation in an unrecognized shape".into());
        return;
    };
    let mut segs_actual: Vec<Segment> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for docid in cx.shadow.all_docs() {
        let Some(d) = cx.alpha.peek(&docid) else { continue };
        match project(cx, &d) {
            Ok(set) => {
                if set.iter().next().is_none() {
                    continue;
                }
                let specs: Vec<Spec> =
                    set.iter().map(|sp| Spec { doc: d.clone(), span: sp.clone() }).collect();
                match cx.rig.exec(Op::RetrieveV { specs }) {
                    Response::Delivery { items, .. } => {
                        segs_actual.extend(segments_from_delivery(&items.0, cx.alpha));
                    }
                    r => errors.push(format!(
                        "{docid}: retrieve {}",
                        rejection_code(&r).unwrap_or_else(|| "?".into())
                    )),
                }
            }
            Err(code) => errors.push(format!("{docid}: {code}")),
        }
    }
    let segs_expected = segments_from_golden(&strings, cx.alpha);
    out.comparator = Some("projection-content".into());
    match compare_segments(&segs_expected, &segs_actual) {
        Ok(()) if errors.is_empty() => out.status = Status::Agreed,
        Ok(()) => {
            out.status = Status::Disagreed;
            out.note = Some(format!("projection errors: {}", errors.join("; ")));
        }
        Err((e, a)) => {
            out.status = Status::Disagreed;
            out.expected = Some(e);
            out.actual = Some(a);
            if !errors.is_empty() {
                out.note = Some(format!("projection errors: {}", errors.join("; ")));
            }
        }
    }
}

/// Resolve a list of golden vspecs to one I-space endset through Op::Image
/// (the sanctioned V→I surface). Rejections contribute nothing and are
/// returned as notes.
fn image_endset(
    cx: &mut Cx,
    vspecs: &[(String, Vec<(u64, u64, u64)>)],
) -> (Endset, Vec<String>) {
    let mut spans = Vec::new();
    let mut notes = Vec::new();
    for (docid, list) in vspecs {
        let Some(d) = cx.alpha.translate(docid) else {
            notes.push(format!("{docid}: unresolvable"));
            continue;
        };
        let region: Vec<skep_address::Span> =
            list.iter().filter_map(|(s, o, w)| vspan(*s, *o, *w)).collect();
        if region.is_empty() {
            continue;
        }
        match cx.rig.exec(Op::Image { d, region }) {
            Response::Runs { runs, .. } => spans.extend(runs.iter().map(Run::iextent)),
            r => notes.push(format!(
                "{docid}: image {}",
                rejection_code(&r).unwrap_or_else(|| "?".into())
            )),
        }
    }
    (Endset::from_spans(spans), notes)
}

/// A find-links filter field: vspec dicts, a doc reference (whole extent),
/// or a text to locate.
fn filter_vspecs(
    cx: &mut Cx,
    out: &mut OpOutcome,
    v: &Value,
) -> Option<Vec<(String, Vec<(u64, u64, u64)>)>> {
    if let Some(arr) = v.as_array() {
        return arr.iter().map(vspec_dict).collect();
    }
    let s = v.as_str()?;
    if let Some(docid) = cx.shadow.resolve_doc(s) {
        let n = cx.shadow.text_len(&docid);
        if n == 0 {
            return Some(vec![(docid, vec![])]);
        }
        return Some(vec![(docid, vec![(1, 1, n)])]);
    }
    let (docid, ord) = cx.shadow.find_text(None, s)?;
    out.adaptations.push("text-located:search".into());
    Some(vec![(docid, vec![(1, ord, s.len() as u64)])])
}

fn h_find_links(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    let mut notes: Vec<String> = Vec::new();
    let mut slot = |cx: &mut Cx, out: &mut OpOutcome, v: Option<&Value>| -> SlotSpec {
        match v {
            None => SlotSpec::Any,
            Some(val) => match filter_vspecs(cx, out, val) {
                Some(vs) => {
                    let (e, n) = image_endset(cx, &vs);
                    notes.extend(n);
                    if e.is_empty() {
                        SlotSpec::Empty
                    } else {
                        SlotSpec::Spans(e)
                    }
                }
                None => {
                    notes.push("filter field unintelligible; constrained to nothing".into());
                    SlotSpec::Empty
                }
            },
        }
    };
    let from = slot(cx, out, field(op, &["search", "source", "sources", "from", "specs"]));
    let to = slot(cx, out, field(op, &["target", "targets", "to"]));
    let ty = match str_field(op, &["filter", "type", "link_type"]) {
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
    };
    let home = match field(op, &["homedocs", "homedocids", "home_docs", "homedoc", "home_doc", "home"]) {
        None => SlotSpec::Any,
        Some(v) => {
            let refs: Vec<String> = match v {
                Value::String(s) => vec![s.clone()],
                Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
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
    if !notes.is_empty() {
        out.note = Some(notes.join("; "));
    }
    let Some(expected) = field(op, &["result", "links", "expected"]).and_then(Value::as_array)
    else {
        out.status = Status::NotCompared;
        return;
    };
    let want: Vec<String> =
        expected.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    out.comparator = Some("address-set".into());
    let rig = &*cx.rig;
    match compare_addr_sets(&want, &addrs, cx.alpha, |a| rig.is_types_addr(a)) {
        Ok(()) => out.status = Status::Agreed,
        Err((e, a)) => {
            out.status = Status::Disagreed;
            out.expected = Some(e);
            out.actual = Some(a);
        }
    }
}

fn h_find_documents(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    let xf = expected_failure(op);
    let mut regions: Vec<Region> = Vec::new();
    if let Some(arr) = field(op, &["specset", "specs", "search", "regions"]).and_then(Value::as_array)
    {
        for v in arr {
            let Some((docid, spans)) = vspec_dict(v) else {
                inexpressible(out, "find_documents spec list holds a non-vspec entry".into());
                return;
            };
            let Some(d) = cx.alpha.translate(&docid) else {
                out.status = Status::Disagreed;
                out.comparator = Some("alpha".into());
                out.note = Some(format!("find_documents doc {docid} unresolvable"));
                return;
            };
            let spans: Vec<skep_address::Span> =
                spans.iter().filter_map(|(s, o, w)| vspan(*s, *o, *w)).collect();
            regions.push(Region { doc: d, spans });
        }
    } else if let Some(qt) = str_field(op, &["query", "text"]) {
        match cx.shadow.find_text(None, qt) {
            Some((docid, ord)) => {
                out.adaptations.push("text-located:query".into());
                let Some(d) = cx.alpha.translate(&docid) else {
                    out.status = Status::Disagreed;
                    out.comparator = Some("alpha".into());
                    out.note = Some(format!("find_documents doc {docid} unresolvable"));
                    return;
                };
                let spans = vspan(1, ord, qt.len() as u64).into_iter().collect();
                regions.push(Region { doc: d, spans });
            }
            None => {
                if xf.is_some() {
                    out.status = Status::Agreed;
                    out.comparator = Some("expected-failure".into());
                    out.note = Some("query text not locatable; golden also recorded failure".into());
                } else {
                    inexpressible(out, format!("find_documents query {qt:?} not found"));
                }
                return;
            }
        }
    } else if let Some(doc) = doc_ref(cx, op, &["doc", "docid"]) {
        let n = cx.shadow.text_len(&doc);
        if let (Some(d), Some(span)) = (cx.alpha.translate(&doc), vspan(1, 1, n.max(0))) {
            regions.push(Region { doc: d, spans: vec![span] });
        } else if n == 0 {
            if let Some(d) = cx.alpha.translate(&doc) {
                regions.push(Region { doc: d, spans: vec![] });
            }
        }
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
    match compare_addr_sets(&want, &addrs, cx.alpha, |a| rig.is_types_addr(a)) {
        Ok(()) => out.status = Status::Agreed,
        Err((e, a)) => {
            out.status = Status::Disagreed;
            out.expected = Some(e);
            out.actual = Some(a);
        }
    }
}

/// Positional probes: the first two consecutive numeric `_`-tokens in the
/// label ("text_at_1_3_before" → (1,3); "pos_1_4_after" → (1,4)).
fn position_from_label(label: &str) -> Option<(u64, u64)> {
    let toks: Vec<&str> = label.split('_').collect();
    for w in toks.windows(2) {
        if let (Ok(a), Ok(b)) = (w[0].parse::<u64>(), w[1].parse::<u64>()) {
            return Some((a, b));
        }
    }
    None
}

fn h_contents(cx: &mut Cx, op: &Value, out: &mut OpOutcome, label: &str) {
    let xf = expected_failure(op);
    let mut specs: Vec<Spec> = Vec::new();
    if let Some(arr) = field(op, &["specset", "specs"]).and_then(Value::as_array) {
        for v in arr {
            let Some((docid, spans)) = vspec_dict(v) else {
                inexpressible(out, "retrieve spec list holds a non-vspec entry".into());
                return;
            };
            let Some(d) = cx.alpha.translate(&docid) else {
                out.status = Status::Disagreed;
                out.comparator = Some("alpha".into());
                out.note = Some(format!("retrieve doc {docid} unresolvable"));
                return;
            };
            for (s, o, w) in spans {
                if let Some(span) = vspan(s, o, w) {
                    specs.push(Spec { doc: d.clone(), span });
                }
            }
        }
    } else {
        let Some(doc) = doc_ref(cx, op, &["doc", "docid"]) else {
            inexpressible(out, "retrieve with no document in scope".into());
            return;
        };
        let Some(d) = skep_doc(cx, &doc) else {
            out.status = Status::Disagreed;
            out.comparator = Some("alpha".into());
            out.note = Some(format!("retrieve doc {doc} unresolvable"));
            return;
        };
        let pos = str_field(op, &["address", "at", "position"])
            .and_then(parse_vpos)
            .or_else(|| {
                position_from_label(label).map(|p| {
                    out.adaptations.push("position-from-label".into());
                    p
                })
            });
        if let Some((sub, ord)) = pos {
            if let Some(span) = vspan(sub, ord, 1) {
                specs.push(Spec { doc: d, span });
            }
        } else {
            // Whole document: the content run plus the link run — udanax's
            // "retrieve the full vspanset" idiom, which is how link
            // addresses show up inside contents results.
            let n = cx.shadow.text_len(&doc);
            if let Some(span) = vspan(1, 1, n) {
                specs.push(Spec { doc: d.clone(), span });
            }
            let l = cx.shadow.link_count(&doc);
            if let Some(span) = vspan(2, 1, l) {
                specs.push(Spec { doc: d, span });
            }
        }
    }
    let expected = field(
        op,
        &["result", "before", "after", "content", "contents", "expected", "value", "text"],
    );
    let items: Vec<skep_retrieval::DeliveryItem> = if specs.is_empty() {
        Vec::new() // empty document, nothing to ask for
    } else {
        match cx.rig.exec(Op::RetrieveV { specs }) {
            Response::Delivery { items, .. } => {
                if !settle_ack(out, xf, None) {
                    return;
                }
                items.0
            }
            other => {
                settle_ack(out, xf, rejection_code(&other));
                return;
            }
        }
    };
    let Some(expected) = expected else {
        out.status = Status::NotCompared;
        return;
    };
    let Some(strings) = expect_strings(expected) else {
        inexpressible(out, "retrieve expectation in an unrecognized shape".into());
        return;
    };
    let want = segments_from_golden(&strings, cx.alpha);
    let got = segments_from_delivery(&items, cx.alpha);
    out.comparator = Some("content".into());
    match compare_segments(&want, &got) {
        Ok(()) => out.status = Status::Agreed,
        Err((e, a)) => {
            out.status = Status::Disagreed;
            out.expected = Some(e);
            out.actual = Some(a);
        }
    }
}

fn h_vspanset(cx: &mut Cx, op: &Value, out: &mut OpOutcome, grants: &Grants, full_set: bool) {
    let expected = field(op, &["result", "vspans", "spans", "before", "after", "expected"])
        .and_then(expect_spans);
    // The expectation's own docid names the document when the op omits it.
    let doc = expected
        .as_ref()
        .and_then(|(d, _)| d.clone())
        .and_then(|d| cx.shadow.resolve_doc(&d))
        .or_else(|| doc_ref(cx, op, &["doc", "docid"]));
    let Some(doc) = doc else {
        inexpressible(out, "vspanset probe with no document in scope".into());
        return;
    };
    let Some(d) = skep_doc(cx, &doc) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("vspanset of unresolvable doc {doc}"));
        return;
    };
    let xf = expected_failure(op);
    let r = if full_set {
        cx.rig.exec(Op::RetrieveDocVSpanSet { doc: d })
    } else {
        cx.rig.exec(Op::RetrieveDocVSpan { doc: d })
    };
    let set = match r {
        Response::SpanSet { set, .. } => {
            if !settle_ack(out, xf, None) {
                return;
            }
            set
        }
        other => {
            settle_ack(out, xf, rejection_code(&other));
            return;
        }
    };
    let Some((_, spans)) = expected else {
        out.status = Status::NotCompared;
        out.note = Some("vspanset probe with no comparable expectation".into());
        return;
    };
    out.comparator = Some("vspanset".into());
    match compare_spansets(&spans, &set, grants.width_tolerance) {
        Ok(()) => out.status = Status::Agreed,
        Err((e, a)) => {
            out.status = Status::Disagreed;
            out.expected = Some(e);
            out.actual = Some(a);
        }
    }
}

fn h_endsets(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    // Region: an explicit search specset (first doc's spans) or the whole
    // extent of the doc in scope.
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
        } else if field(op, &["search"]).is_some_and(|v| v.is_string()) {
            inexpressible(
                out,
                "retrieve_endsets search is descriptive text, not a spec".into(),
            );
            return;
        } else {
            let Some(doc) = doc_ref(cx, op, &["doc", "docid"]) else {
                inexpressible(out, "retrieve_endsets with no document in scope".into());
                return;
            };
            let n = cx.shadow.text_len(&doc);
            (doc.clone(), vspan(1, 1, n).into_iter().collect())
        };
    let Some(d) = skep_doc(cx, &doc) else {
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
    // Structural comparison per slot: the multiset of (origin document,
    // element width) each side's endsets cover. Golden endsets are V-specs;
    // skep endsets are recorded I-extents — origin doc + width is the shape
    // both sides speak. Type-slot spans inside the harness types document
    // are excluded (policy type_registry — they encode the type NAME, which
    // the golden encodes as an unresolvable link-subspace spec).
    out.adaptations.push("type_registry".into());
    out.comparator = Some("endsets-structural".into());
    let mut fails: Vec<(String, String)> = Vec::new();
    for (slot_keys, slot) in
        [(&["from", "source"][..], 1usize), (&["to", "target"][..], 2), (&["type"][..], 3)]
    {
        let Some(exp) = field(op, slot_keys) else { continue };
        let mut want: Vec<(String, u64)> = Vec::new();
        if let Some(arr) = exp.as_array() {
            for v in arr {
                if let Some((docid, spans)) = vspec_dict(v) {
                    for (_, _, w) in spans {
                        want.push((docid.clone(), w));
                    }
                }
            }
        }
        let mut got: Vec<(String, u64)> = Vec::new();
        for (i, e) in &pairs {
            if *i != slot {
                continue;
            }
            for sp in e.spans() {
                let Ok(a) = skep_address::validate(sp.start().clone()) else { continue };
                if cx.rig.is_types_addr(&a) {
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
        if want != got {
            fails.push((format!("slot{slot}:{want:?}"), format!("slot{slot}:{got:?}")));
        }
    }
    if fails.is_empty() {
        out.status = Status::Agreed;
    } else {
        out.status = Status::Disagreed;
        out.expected = Some(fails.iter().map(|f| f.0.clone()).collect::<Vec<_>>().join(" | "));
        out.actual = Some(fails.iter().map(|f| f.1.clone()).collect::<Vec<_>>().join(" | "));
    }
}

fn h_compare(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    // The two documents, as referenced by the golden (names or addresses).
    let (ref_a, ref_b): (String, String) = if let Some(docs) =
        field(op, &["docs", "documents"]).and_then(Value::as_array)
    {
        let refs: Vec<String> = docs.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
        match refs.as_slice() {
            [a, b] => (a.clone(), b.clone()),
            _ => {
                inexpressible(out, "compare needs exactly two documents".into());
                return;
            }
        }
    } else if let (Some(a), Some(b)) =
        (str_field(op, &["doc_a", "a"]), str_field(op, &["doc_b", "b"]))
    {
        (a.to_string(), b.to_string())
    } else {
        ("original".to_string(), "version".to_string())
    };
    let (Some(ga), Some(gb)) = (cx.shadow.resolve_doc(&ref_a), cx.shadow.resolve_doc(&ref_b))
    else {
        inexpressible(out, format!("compare documents `{ref_a}`/`{ref_b}` unresolvable"));
        return;
    };
    let (Some(da), Some(db)) = (cx.alpha.translate(&ga), cx.alpha.translate(&gb)) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some("compare over unresolvable documents".into());
        return;
    };
    let whole = |cx: &Cx, g: &str, d: &skep_address::Address| -> Region {
        let n = cx.shadow.text_len(g);
        Region { doc: d.clone(), spans: vspan(1, 1, n).into_iter().collect() }
    };
    let rho1 = vec![whole(cx, &ga, &da)];
    let rho2 = vec![whole(cx, &gb, &db)];
    let xf = expected_failure(op);
    let rep = match cx.rig.exec(Op::Compare { rho1, rho2 }) {
        Response::Compare { rep, .. } => {
            if !settle_ack(out, xf, None) {
                return;
            }
            rep
        }
        other => {
            settle_ack(out, xf, rejection_code(&other));
            return;
        }
    };
    // Normalize skep's pairs to (ordA, ordB, width) triples, then coalesce
    // adjacent runs exactly as client.py's collapse_sharedspans did on the
    // recording side (the golden is already collapsed; symmetric treatment).
    let nat_u64 = |n: &Nat| -> u64 { n.to_string().parse().unwrap_or(u64::MAX) };
    let a_str = crate::tum::addr_str(&da);
    let b_str = crate::tum::addr_str(&db);
    let mut triples: Vec<(u64, u64, u64)> = Vec::new();
    let mut foreign: Vec<String> = Vec::new();
    for p in rep.0 {
        let (d1, d2) = (crate::tum::addr_str(&p.d1), crate::tum::addr_str(&p.d2));
        let (o1, o2, w) = (nat_u64(&p.u1.ordinal), nat_u64(&p.u2.ordinal), nat_u64(&p.width));
        if nat_u64(&p.u1.subspace) != 1 || nat_u64(&p.u2.subspace) != 1 {
            continue;
        }
        if d1 == a_str && d2 == b_str {
            triples.push((o1, o2, w));
        } else if d1 == b_str && d2 == a_str {
            triples.push((o2, o1, w));
        } else {
            foreign.push(format!("({d1},{d2})"));
        }
    }
    triples.sort();
    let mut merged: Vec<(u64, u64, u64)> = Vec::new();
    for t in triples {
        if let Some(last) = merged.last_mut() {
            if last.0 + last.2 == t.0 && last.1 + last.2 == t.1 {
                last.2 += t.2;
                continue;
            }
        }
        merged.push(t);
    }
    let Some(shared) = field(op, &["shared", "result", "pairs"]).and_then(Value::as_array) else {
        out.status = Status::NotCompared;
        return;
    };
    let mut want: Vec<(u64, u64, u64)> = Vec::new();
    for item in shared {
        let Some(o) = item.as_object() else { continue };
        let sa = o.get(&ref_a).and_then(span_dict);
        let sb = o.get(&ref_b).and_then(span_dict);
        if let (Some((_, oa, wa)), Some((_, ob, _))) = (sa, sb) {
            want.push((oa, ob, wa));
        }
    }
    want.sort();
    out.comparator = Some("correspondence".into());
    if want == merged && foreign.is_empty() {
        out.status = Status::Agreed;
    } else {
        out.status = Status::Disagreed;
        out.expected = Some(format!("{want:?}"));
        let mut act = format!("{merged:?}");
        if !foreign.is_empty() {
            act.push_str(&format!(" + foreign docs {foreign:?}"));
        }
        out.actual = Some(act);
    }
}

fn h_account(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    out.adaptations.push("account_as_delegate".into());
    let Some(acct) = str_field(op, &["account", "acctid", "id"]) else {
        inexpressible(out, "account op without an account field".into());
        return;
    };
    let existing = cx.alpha.peek(acct);
    match cx.rig.switch_account(existing) {
        Ok(a) => {
            cx.alpha.bind(acct, &a);
            out.status = Status::NotCompared;
        }
        Err(e) => {
            out.status = Status::Disagreed;
            out.comparator = Some("account".into());
            out.expected = Some(format!("account context {acct}"));
            out.actual = Some(e);
        }
    }
}

fn h_create_node(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    out.adaptations.push("create_node_as_delegate".into());
    let Some(parent_golden) = str_field(op, &["account", "acctid", "parent"]) else {
        inexpressible(out, "create_node without an account field".into());
        return;
    };
    let Some(parent) = cx.alpha.translate(parent_golden) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("create_node under unresolvable account {parent_golden}"));
        return;
    };
    let xf = expected_failure(op);
    match cx.rig.delegate_under(&parent, false) {
        Ok(sub) => {
            if !settle_ack(out, xf, None) {
                return;
            }
            if let Some(g) = str_field(op, &["result"]) {
                cx.alpha.bind(g, &sub);
                out.status = Status::Agreed;
                out.comparator = Some("address-binding".into());
            } else {
                out.status = Status::NotCompared;
            }
        }
        Err(e) => {
            settle_ack(out, xf, Some(e));
        }
    }
}

