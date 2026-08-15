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
//!   descoped); the op's `result` address still binds in the α-map.
//! * `open_document:conflict_copy→version` — the golden's own recorded
//!   result (a new sub-address of the source) shows CONFLICT_COPY forked.
//! * `close_document:noop` — no open layer, nothing to close.
//! * `client-error:no-op` — the golden result is "OPERATION_FAILED: …", a
//!   RECORDING-CLIENT crash; udanax never executed the op, so neither does
//!   the harness.
//! * `type_registry` — link-type names denote positions in a
//!   harness-created types document; udanax encoded them as vspecs into an
//!   unoccupied link subspace (unresolvable I-space). Type-slot data inside
//!   the types doc is harness infrastructure, excluded from comparisons.
//! * `default_type_jump` — create_link without a type: the recording
//!   scripts' default.
//! * `default_source_first_word` / `default_target_whole_doc` /
//!   `default_target_self` — bare create_link endset conventions, evidence
//!   first (see `endset_evidence`), then the scripts' defaults
//!   (links/link_retrieval_via_endsets pins first-word; links/follow_link
//!   pins evidence-target).
//! * `endset-evidence` — a bare link endset recovered from a LATER recorded
//!   follow/endsets result for the same link, accepted only when no write
//!   intervenes.
//! * `text-located:*` / `span-from-description` / `range-from-description`
//!   / `whole-extent` — decorated-description grounding (fields::locate).
//! * `position-end` / `position-from-description` / `position-after-text` /
//!   `position-from-label` — position grounding.
//! * `doc-from-label` / `doc-from-register` — document scope grounding
//!   (the current-document register mirrors the recording scripts' implicit
//!   scope).
//! * `implied-create:first-touch` — an op needed a document before any
//!   create; one is created, exactly as the recording script must have.
//! * `expansion-plan` — the op executed a pre-pass reconstruction plan
//!   (create_chain / setup / vcopy_multiple / create_and_transclude).
//! * `implicit_last_link` / `default-slot:source` — follow_link without a
//!   link/end field: the most recent link, the SOURCE end (pinned by
//!   isolation/insert_text_does_not_affect_links_in_same_document, whose
//!   bare follow recorded the source spans).
//! * `follow_as_projection` — follow_link renders through `Op::Project`
//!   (I→V into a document); skep's raw FOLLOWLINK returns permanent
//!   I-spans, which the goldens never speak.
//! * `account_as_delegate` / `create_node_as_delegate` — udanax account
//!   selection / sub-account minting map onto M3 delegation.
//! * `create_links:repeat` — a plural create repeats one MakeLink per
//!   recorded result.
//! * `alpha-bind-from-result:N` — N unbound golden result addresses were
//!   bound to skep response addresses positionally (the α-map's sanctioned
//!   move; a wrong pairing surfaces later as a double-bind finding).
//! * `contents:content-subspace` — whole-document retrieves read the
//!   CONTENT subspace only, matching udanax's retrieve_contents (its
//!   recorded results never include link-subspace items).

use std::collections::BTreeMap;

use serde_json::Value;

use skep_address::Nat;
use skep_arrangement::{Run, VPos, VSpec};
use skep_content::Val;
use skep_discovery::{FourSet, SlotSpec};
use skep_febe::{Op, Response};
use skep_links::{enc, Endset};
use skep_retrieval::{DeliveryItem, Region, Spec};

use crate::alpha::Alpha;
use crate::compare::{
    collapsed_subspace_shape, compare_addr_sets, compare_content, compare_count,
    compare_expected_failure, compare_spansets, COLLAPSED_SUBSPACE_ANALYSIS,
};
use crate::fields::{
    self, client_side_failure, doc_from_label, expect_spans_raw, expect_strings, expected_failure,
    field, label_of, link_home_docid, locate, parse_python_spec, position_from_label,
    resolve_position, span_dict, str_field, vspec_dict, DocSpans, RawSpan,
};
use crate::ground::{arrow_results, cuts_of, delete_region, insert_text, SetupStep};
use crate::harness::Rig;
use crate::outcome::{OpOutcome, Status};
use crate::shadow::Shadow;
use crate::tum::{parse_dotted, parse_vpos, vspan};

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
    /// The whole scenario, for bounded forward-evidence scans.
    pub ops: &'a [Value],
    /// Pre-pass expansion plans, keyed by op index.
    pub plans: &'a BTreeMap<usize, Vec<SetupStep>>,
}

// ─────────────────────────── verb normalization ────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    CreateDocument,
    CreateDocuments,
    CreateChain,
    Setup,
    OpenDocument,
    CloseDocument,
    Insert,
    InsertLoop,
    InteriorTyping,
    Delete,
    DeleteAll,
    Vcopy,
    Pivot,
    Swap,
    Rearrange,
    CreateVersion,
    CreateLink,
    FollowLink,
    Traverse,
    FindLinks,
    FindDocuments,
    Contents,
    Vspan,
    Vspanset,
    Endsets,
    Compare,
    Account,
    CreateNode,
    Observe,
    Meta,
}

impl Verb {
    pub fn name(self) -> &'static str {
        match self {
            Verb::CreateDocument => "create_document",
            Verb::CreateDocuments => "create_documents",
            Verb::CreateChain => "create_chain",
            Verb::Setup => "setup",
            Verb::OpenDocument => "open_document",
            Verb::CloseDocument => "close_document",
            Verb::Insert => "insert",
            Verb::InsertLoop => "insert_loop",
            Verb::InteriorTyping => "interior_typing",
            Verb::Delete => "delete",
            Verb::DeleteAll => "delete_all",
            Verb::Vcopy => "vcopy",
            Verb::Pivot => "pivot",
            Verb::Swap => "swap",
            Verb::Rearrange => "rearrange",
            Verb::CreateVersion => "create_version",
            Verb::CreateLink => "create_link",
            Verb::FollowLink => "follow_link",
            Verb::Traverse => "traverse",
            Verb::FindLinks => "find_links",
            Verb::FindDocuments => "find_documents",
            Verb::Contents => "retrieve_contents",
            Verb::Vspan => "retrieve_vspan",
            Verb::Vspanset => "retrieve_vspanset",
            Verb::Endsets => "retrieve_endsets",
            Verb::Compare => "compare_versions",
            Verb::Account => "account",
            Verb::CreateNode => "create_node",
            Verb::Observe => "observe",
            Verb::Meta => "meta",
        }
    }
}

/// The meta/diagnostic labels (per the brief): executed nothing, compared
/// nothing, counted separately — UNLESS the op carries observation data
/// (a vspanset/contents bundle), in which case it is an [`Verb::Observe`]
/// probe (internal/interior_typing_two_characters's `initial_state`).
const META: &[&str] = &[
    "snapshot", "dump_state", "verify", "setup", "analysis", "note", "summary", "initial_state",
    "final_state",
];

/// Longest-matching verb stem, checked in table order (specific before
/// general — `vspanset` before `vspan`, `delete_all` before `delete`).
const STEMS: &[(&str, Verb)] = &[
    ("create_node", Verb::CreateNode),
    ("create_chain", Verb::CreateChain),
    ("create_and_transclude", Verb::Vcopy),
    ("create_documents", Verb::CreateDocuments),
    ("create_document", Verb::CreateDocument),
    ("create_doc", Verb::CreateDocument),
    ("create_sources", Verb::CreateDocuments),
    ("create_target", Verb::CreateDocument),
    ("create_multiple_targets", Verb::CreateDocuments),
    ("open_document", Verb::OpenDocument),
    ("close_document", Verb::CloseDocument),
    ("create_version", Verb::CreateVersion),
    ("version", Verb::CreateVersion),
    ("create_links", Verb::CreateLink),
    ("create_link", Verb::CreateLink),
    ("makelink", Verb::CreateLink),
    ("interior_typing", Verb::InteriorTyping),
    ("insert_loop", Verb::InsertLoop),
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
    ("reverse_traversal", Verb::Traverse),
    ("traverse", Verb::Traverse),
    ("follow_links", Verb::Traverse),
    ("follow_link", Verb::FollowLink),
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

/// Does the op carry observation data (a probe bundle)?
fn has_observation_fields(op: &Value) -> bool {
    let Some(o) = op.as_object() else { return false };
    for (k, v) in o {
        match k.as_str() {
            "vspanset" | "vspans" | "contents" | "content" | "positions" | "docs" => return true,
            "result" | "before" | "after" | "empty" => {
                if expect_strings(v).is_some() || fields::looks_like_spanset(v) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Normalize a label to a canonical verb: meta list (with the
/// observation-bundle escape), then the stem table, then a field-shape
/// fallback for pure state-probe labels. `None` ⇒ inexpressible.
pub fn normalize(label: &str, op: &Value) -> Option<Verb> {
    let l = label.to_ascii_lowercase();
    if l == "setup" {
        return Some(Verb::Setup);
    }
    if META.iter().any(|m| l == *m || l.starts_with(&format!("{m}_"))) {
        return Some(if has_observation_fields(op) { Verb::Observe } else { Verb::Meta });
    }
    for (stem, verb) in STEMS {
        if l.starts_with(stem) {
            return Some(*verb);
        }
    }
    if !arrow_results(op).is_empty() {
        return Some(Verb::CreateLink);
    }
    // Shape fallback for unknown probe labels.
    if let Some(res) = op.get("result") {
        if fields::looks_like_spanset(res) {
            return Some(Verb::Vspanset);
        }
        if let Some(arr) = res.as_array() {
            if !arr.is_empty() && arr.iter().all(|v| v.as_str().is_some_and(fields::is_link_address))
            {
                return Some(Verb::FindLinks);
            }
            if arr.iter().all(|v| v.as_str().is_some()) {
                return Some(Verb::Contents);
            }
        }
    }
    if has_observation_fields(op) {
        return Some(Verb::Observe);
    }
    None
}

// ───────────────────────────── small shared bits ───────────────────────────

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

impl Cx<'_> {
    /// The op's document argument: explicit field, label token, then the
    /// current-document register. Creates a first-touch document when the
    /// scenario has none yet (mirrored by the grounding pre-pass).
    fn doc_arg(&mut self, op: &Value, out: &mut OpOutcome, keys: &[&str]) -> Option<String> {
        if let Some(s) = str_field(op, keys) {
            if let Some(d) = self.shadow.resolve_doc(s) {
                return Some(d);
            }
        }
        if let Some(name) = doc_from_label(label_of(op)) {
            if let Some(d) = self.shadow.resolve_doc(&name) {
                out.adaptations.push("doc-from-label".into());
                return Some(d);
            }
        }
        if let Some(d) = self.shadow.scoped() {
            out.adaptations.push("doc-from-register".into());
            return Some(d);
        }
        let id = self.shadow.synthesize_docid();
        match self.rig.exec(Op::CreateNewDocument { account: self.rig.current_account.clone() }) {
            Response::AckAddr { addr, .. } => {
                out.adaptations.push("implied-create:first-touch".into());
                self.alpha.bind(&id, &addr);
                self.shadow.create_doc(&id, None);
                Some(id)
            }
            _ => None,
        }
    }

    fn skep_doc(&mut self, golden: &str) -> Option<skep_address::Address> {
        self.alpha.translate(golden)
    }

    /// Execute one reconstruction step (lead-in or expansion plan): the same
    /// op surface the scenarios use, mirrored into the shadow.
    pub fn exec_setup_step(&mut self, s: &SetupStep) -> Result<(), String> {
        match s {
            SetupStep::Insert { doc, bytes } => {
                let d = self.skep_doc(doc).ok_or_else(|| format!("setup insert: {doc} unbound"))?;
                let at = self.shadow.text_len(doc) + 1;
                let values: Vec<Val> = bytes.iter().map(|b| Val::new(vec![*b])).collect();
                match self.rig.exec(Op::Insert { doc: d, at: vpos(1, at), values }) {
                    Response::AckAddr { .. } => {
                        self.shadow.insert(doc, at, bytes);
                        Ok(())
                    }
                    r => Err(format!(
                        "setup insert into {doc}: {}",
                        rejection_code(&r).unwrap_or_else(|| "?".into())
                    )),
                }
            }
            SetupStep::Copy { doc, src, ord, width } => {
                let d = self.skep_doc(doc).ok_or_else(|| format!("setup copy: {doc} unbound"))?;
                let sd = self.skep_doc(src).ok_or_else(|| format!("setup copy: {src} unbound"))?;
                let span = vspan(1, *ord, *width)
                    .ok_or_else(|| "setup copy: empty span".to_string())?;
                let at = self.shadow.text_len(doc) + 1;
                let bytes = self.shadow.slice(src, *ord, *width);
                match self.rig.exec(Op::Copy {
                    doc: d,
                    at: vpos(1, at),
                    specs: vec![VSpec { source: sd, span }],
                }) {
                    Response::Ack { .. } => {
                        self.shadow.insert(doc, at, &bytes);
                        Ok(())
                    }
                    r => Err(format!(
                        "setup copy into {doc}: {}",
                        rejection_code(&r).unwrap_or_else(|| "?".into())
                    )),
                }
            }
        }
    }

    /// Whole-document CONTENT-subspace delivery (policy
    /// `contents:content-subspace` — udanax's retrieve_contents results
    /// never include link-subspace items).
    fn read_content(&mut self, doc: &str) -> Result<Vec<DeliveryItem>, String> {
        let n = self.shadow.text_len(doc);
        let Some(span) = vspan(1, 1, n) else { return Ok(Vec::new()) };
        let d = self.skep_doc(doc).ok_or_else(|| format!("{doc} unresolvable"))?;
        match self.rig.exec(Op::RetrieveV { specs: vec![Spec { doc: d, span }] }) {
            Response::Delivery { items, .. } => Ok(items.0),
            r => Err(rejection_code(&r).unwrap_or_else(|| "unexpected response".into())),
        }
    }

    /// V→I image of a set of golden spans in one doc (the sanctioned V→I
    /// surface for building query endsets).
    fn image_endset(&mut self, docid: &str, spans: &[(u64, u64, u64)]) -> (Endset, Vec<String>) {
        let mut notes = Vec::new();
        let Some(d) = self.alpha.translate(docid) else {
            notes.push(format!("{docid}: unresolvable"));
            return (Endset::from_spans(std::iter::empty()), notes);
        };
        let region: Vec<skep_address::Span> =
            spans.iter().filter_map(|(s, o, w)| vspan(*s, *o, *w)).collect();
        if region.is_empty() {
            return (Endset::from_spans(std::iter::empty()), notes);
        }
        match self.rig.exec(Op::Image { d, region }) {
            Response::Runs { runs, .. } => {
                (Endset::from_spans(runs.iter().map(Run::iextent)), notes)
            }
            r => {
                notes.push(format!(
                    "{docid}: image {}",
                    rejection_code(&r).unwrap_or_else(|| "?".into())
                ));
                (Endset::from_spans(std::iter::empty()), notes)
            }
        }
    }
}

// ────────────────────────────── the catalogue ──────────────────────────────

/// Translate, execute, and compare one golden operation. Exactly one
/// `OpOutcome` per op, whatever happens.
pub fn run_op(cx: &mut Cx, index: usize, op: &Value, grants: &Grants) -> OpOutcome {
    let label = label_of(op).to_string();
    let mut out = OpOutcome::new(index, &label);
    if label.is_empty() {
        inexpressible(&mut out, "operation has no `op` label".into());
        return out;
    }
    // Recording-client crash: udanax never saw the op.
    if let Some(msg) = client_side_failure(op) {
        out.adaptations.push("client-error:no-op".into());
        out.status = Status::NotCompared;
        out.note = Some(format!("recording client failed before reaching udanax: {msg}"));
        return out;
    }
    let Some(verb) = normalize(&label, op) else {
        let keys: Vec<&str> =
            op.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        inexpressible(&mut out, format!("label `{label}` (fields {keys:?}) has no canonical verb"));
        return out;
    };
    out.verb = verb.name().to_string();
    match verb {
        Verb::Meta => out.status = Status::Meta,
        Verb::Observe => h_observe(cx, op, &mut out, grants),
        Verb::Setup => h_setup(cx, index, &mut out),
        Verb::CreateDocument => h_create_document(cx, op, &mut out),
        Verb::CreateDocuments => h_create_documents(cx, op, &mut out),
        Verb::CreateChain => h_create_chain(cx, index, op, &mut out),
        Verb::OpenDocument => h_open_document(cx, op, &mut out),
        Verb::CloseDocument => {
            out.adaptations.push("close_document:noop".into());
            out.status = Status::NotCompared;
        }
        Verb::Insert => h_insert(cx, op, &mut out, grants),
        Verb::InsertLoop => h_insert_loop(cx, op, &mut out, grants),
        Verb::InteriorTyping => h_interior_typing(cx, op, &mut out, grants),
        Verb::Delete => h_delete(cx, op, &mut out, grants, false),
        Verb::DeleteAll => h_delete(cx, op, &mut out, grants, true),
        Verb::Vcopy => h_vcopy(cx, index, op, &mut out, grants),
        Verb::Pivot => h_pivot_swap(cx, op, &mut out, true),
        Verb::Swap => h_pivot_swap(cx, op, &mut out, false),
        Verb::Rearrange => {
            let n = cuts_of(op).len();
            match n {
                3 => h_pivot_swap(cx, op, &mut out, true),
                4 => h_pivot_swap(cx, op, &mut out, false),
                k => inexpressible(&mut out, format!("rearrange needs 3 or 4 cuts, could derive {k}")),
            }
        }
        Verb::CreateVersion => h_create_version(cx, op, &mut out),
        Verb::CreateLink => h_create_link(cx, index, op, &mut out),
        Verb::FollowLink => h_follow_link(cx, op, &mut out, grants),
        Verb::Traverse => h_traverse(cx, op, &mut out, grants),
        Verb::FindLinks => h_find_links(cx, op, &mut out, grants),
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

// ── creation ────────────────────────────────────────────────────────────────

fn h_create_document(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    let name = str_field(op, &["doc", "name", "label"])
        .filter(|s| parse_dotted(s).is_none())
        .map(str::to_string);
    let goldens: Vec<String> = match field(op, &["result", "results"]) {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        _ => vec![cx.shadow.synthesize_docid()],
    };
    let xf = expected_failure(op);
    for (i, golden) in goldens.iter().enumerate() {
        if cx.shadow.knows(golden) {
            // Implied-created earlier (grounding); bind name and move on.
            if let (0, Some(n)) = (i, &name) {
                cx.shadow.bind_name(n, golden);
            }
            cx.shadow.set_current(golden);
            continue;
        }
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

fn h_create_documents(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    let xf = expected_failure(op);
    // docs map {name: id} — created in id order.
    if let Some(map) = op.get("docs").and_then(Value::as_object) {
        let mut by_id: Vec<(String, String)> = map
            .iter()
            .filter_map(|(n, id)| id.as_str().map(|i| (i.to_string(), n.clone())))
            .collect();
        if !by_id.is_empty() {
            by_id.sort();
            for (id, n) in by_id {
                create_one(cx, out, &id, Some(&n));
            }
            let _ = settle_ack(out, xf, None);
            if out.status == Status::NotCompared {
                out.status = Status::Agreed;
                out.comparator = Some("address-binding".into());
            }
            return;
        }
    }
    // doc1/doc2 keyed fields.
    let mut keyed: Vec<(String, String)> = op
        .as_object()
        .map(|o| {
            o.iter()
                .filter(|(k, _)| k.starts_with("doc") && k[3..].parse::<u64>().is_ok())
                .filter_map(|(k, v)| v.as_str().map(|id| (k.clone(), id.to_string())))
                .collect()
        })
        .unwrap_or_default();
    if !keyed.is_empty() {
        keyed.sort();
        for (k, id) in keyed {
            create_one(cx, out, &id, Some(&k));
        }
        let _ = settle_ack(out, xf, None);
        if out.status == Status::NotCompared {
            out.status = Status::Agreed;
            out.comparator = Some("address-binding".into());
        }
        return;
    }
    let results: Vec<String> = field(op, &["results"])
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let names: Vec<String> = field(op, &["docs"])
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let texts: Vec<String> = field(op, &["texts"])
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let group = str_field(op, &["type", "doc"]).map(str::to_string);
    let count = field(op, &["count"])
        .and_then(Value::as_u64)
        .map(|c| c as usize)
        .unwrap_or_else(|| results.len().max(names.len()).max(1))
        .max(results.len());
    for k in 0..count {
        let id = results.get(k).cloned().unwrap_or_else(|| cx.shadow.synthesize_docid());
        let name =
            names.get(k).cloned().or_else(|| group.as_ref().map(|t| format!("{t}{}", k + 1)));
        create_one(cx, out, &id, name.as_deref());
        if let Some(t) = texts.get(k) {
            if let Some(d) = cx.skep_doc(&id) {
                let values: Vec<Val> = t.bytes().map(|b| Val::new(vec![b])).collect();
                if let Response::AckAddr { .. } =
                    cx.rig.exec(Op::Insert { doc: d, at: vpos(1, 1), values })
                {
                    cx.shadow.insert(&id, 1, t.as_bytes());
                }
            }
        }
    }
    let _ = settle_ack(out, xf, None);
    if out.status == Status::NotCompared {
        out.status = Status::Agreed;
        out.comparator = Some("address-binding".into());
    }
}

fn create_one(cx: &mut Cx, out: &mut OpOutcome, id: &str, name: Option<&str>) {
    if cx.shadow.knows(id) {
        if let Some(n) = name {
            cx.shadow.bind_name(n, id);
        }
        cx.shadow.set_current(id);
        return;
    }
    match cx.rig.exec(Op::CreateNewDocument { account: cx.rig.current_account.clone() }) {
        Response::AckAddr { addr, .. } => {
            cx.alpha.bind(id, &addr);
            cx.shadow.create_doc(id, name);
        }
        other => fail_response(out, "rejection", "document creation", &other),
    }
}

fn h_create_chain(cx: &mut Cx, index: usize, op: &Value, out: &mut OpOutcome) {
    let Some(map) = op.get("docs").and_then(Value::as_object) else {
        inexpressible(out, "create_chain without a docs map".into());
        return;
    };
    let mut by_id: Vec<(String, String)> = map
        .iter()
        .filter_map(|(n, id)| id.as_str().map(|i| (i.to_string(), n.clone())))
        .collect();
    by_id.sort();
    for (id, n) in &by_id {
        create_one(cx, out, id, Some(n));
    }
    if out.status == Status::Disagreed {
        return;
    }
    run_plan(cx, index, out);
}

fn h_setup(cx: &mut Cx, index: usize, out: &mut OpOutcome) {
    if cx.plans.contains_key(&index) {
        run_plan(cx, index, out);
    } else {
        out.status = Status::Meta;
        out.note = Some("setup description not parseable; treated as meta".into());
    }
}

/// Execute the pre-pass expansion plan attached to this op.
fn run_plan(cx: &mut Cx, index: usize, out: &mut OpOutcome) {
    let Some(plan) = cx.plans.get(&index).cloned() else {
        out.status = Status::NotCompared;
        out.note = Some("no expansion plan derived; nothing executed".into());
        return;
    };
    out.adaptations.push(format!("expansion-plan:{}", plan.len()));
    for step in &plan {
        // Copies/inserts target docs the plan may create implicitly.
        let (SetupStep::Copy { doc, .. } | SetupStep::Insert { doc, .. }) = step;
        if !cx.shadow.knows(doc) {
            create_one(cx, out, doc, None);
        }
        if let Err(e) = cx.exec_setup_step(step) {
            out.status = Status::Disagreed;
            out.comparator = Some("expansion-plan".into());
            out.expected = Some("reconstructed setup executes".into());
            out.actual = Some(e);
            return;
        }
    }
    out.status = Status::NotCompared;
}

fn h_open_document(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid", "document"]) else {
        inexpressible(out, "open_document without a resolvable doc".into());
        return;
    };
    let conflict_copy = str_field(op, &["conflict"]).is_some_and(|c| c == "copy")
        || str_field(op, &["copy", "copy_mode"]).is_some_and(|c| c == "conflict_copy");
    let result = str_field(op, &["result"]).map(str::to_string);
    if conflict_copy {
        out.adaptations.push("open_document:conflict_copy→version".into());
        let Some(src) = cx.skep_doc(&doc) else {
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
        if let Some(a) = cx.skep_doc(&doc) {
            cx.alpha.bind(g, &a);
        }
    }
    cx.shadow.set_current(&doc);
    out.status = Status::NotCompared;
}

fn h_create_version(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    // Source: an explicit from/source/of that RESOLVES; a `doc` field only
    // when it resolves to an existing doc (identity_through_rearrange_pivot
    // uses `doc` for the NEW version's name); else the register.
    let explicit = str_field(op, &["from", "source", "of", "original"])
        .and_then(|s| cx.shadow.resolve_doc(s));
    let via_doc_field = str_field(op, &["doc"]).and_then(|s| cx.shadow.resolve_doc(s));
    let src = explicit.or(via_doc_field).or_else(|| {
        out.adaptations.push("doc-from-register".into());
        cx.shadow.scoped()
    });
    let Some(src) = src else {
        inexpressible(out, "create_version with no source document".into());
        return;
    };
    let golden = match field(op, &["result"]) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Object(o)) => o.get("version").and_then(Value::as_str).map(str::to_string),
        _ => None,
    };
    let Some(d_src) = cx.skep_doc(&src) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("version of unresolvable doc {src}"));
        return;
    };
    let xf = expected_failure(op);
    match cx.rig.exec(Op::Version { d_src }) {
        Response::AckAddr { addr, .. } => {
            if !settle_ack(out, xf, None) {
                return;
            }
            if let Some(g) = &golden {
                cx.alpha.bind(g, &addr);
                cx.shadow.version(&src, g);
                // A non-address doc/name/label field names the NEW version.
                for key in ["doc", "name", "label"] {
                    if let Some(n) = str_field(op, &[key]) {
                        if parse_dotted(n).is_none() && cx.shadow.resolve_doc(n).is_none() {
                            cx.shadow.bind_name(n, g);
                        }
                    }
                }
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

// ── content writes ──────────────────────────────────────────────────────────

fn h_insert(cx: &mut Cx, op: &Value, out: &mut OpOutcome, grants: &Grants) {
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        inexpressible(out, "insert with no document in scope".into());
        return;
    };
    let Some(text) = insert_text(op) else {
        inexpressible(out, "insert without text".into());
        return;
    };
    if str_field(op, &["text"]).is_none() && label_of(op).starts_with("insert_") {
        out.adaptations.push("args-from-label".into());
    }
    let (sub, ord) = match str_field(op, &["address", "at", "position", "vaddr"]) {
        Some(p) => match resolve_position(cx.shadow, &doc, p) {
            Some((s, o, how)) => {
                if how != "explicit-position" {
                    out.adaptations.push(how.into());
                }
                (s, o)
            }
            None => {
                inexpressible(out, format!("insert position `{p}` is not groundable"));
                return;
            }
        },
        None => {
            // insert_<n>_<TEXT> labels carry the sequence number, not a
            // position; those and bare inserts append.
            out.adaptations.push("position-end".into());
            (1, cx.shadow.text_len(&doc) + 1)
        }
    };
    let Some(d) = cx.skep_doc(&doc) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("insert into unresolvable doc {doc}"));
        return;
    };
    let xf = expected_failure(op);
    let values: Vec<Val> = text.bytes().map(|b| Val::new(vec![b])).collect();
    let r = cx.rig.exec(Op::Insert { doc: d, at: vpos(sub, ord), values });
    // Shadow mirrors the RECORDED reality regardless of skep's verdict, so
    // later translations stay grounded in what udanax saw.
    if sub == 1 {
        cx.shadow.insert(&doc, ord, text.as_bytes());
    }
    if !settle_ack(out, xf, rejection_code(&r)) {
        return;
    }
    probe_state(cx, op, out, grants, &doc, Probe::PostWrite);
}

fn h_insert_loop(cx: &mut Cx, op: &Value, out: &mut OpOutcome, grants: &Grants) {
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        inexpressible(out, "insert_loop with no document in scope".into());
        return;
    };
    let Some(count) = field(op, &["count"]).and_then(Value::as_u64) else {
        inexpressible(out, "insert_loop without a count".into());
        return;
    };
    // The recorded sample (edgecases/many_small_inserts) shows A–Z cycling,
    // one insert per character, appended.
    out.adaptations.push("insert-loop:a-z-cycle".into());
    let Some(d) = cx.skep_doc(&doc) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("insert_loop into unresolvable doc {doc}"));
        return;
    };
    for k in 0..count {
        let b = b'A' + (k % 26) as u8;
        let at = cx.shadow.text_len(&doc) + 1;
        let r = cx.rig.exec(Op::Insert {
            doc: d.clone(),
            at: vpos(1, at),
            values: vec![Val::new(vec![b])],
        });
        cx.shadow.insert(&doc, at, &[b]);
        if let Some(code) = rejection_code(&r) {
            out.status = Status::Disagreed;
            out.comparator = Some("rejection".into());
            out.expected = Some(format!("insert {} of {count} succeeds", k + 1));
            out.actual = Some(format!("Rejected({code})"));
            return;
        }
    }
    probe_state(cx, op, out, grants, &doc, Probe::PostWrite);
}

fn h_interior_typing(cx: &mut Cx, op: &Value, out: &mut OpOutcome, grants: &Grants) {
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        inexpressible(out, "interior_typing with no document in scope".into());
        return;
    };
    let Some(results) = field(op, &["results"]).and_then(Value::as_array) else {
        inexpressible(out, "interior_typing without a results list".into());
        return;
    };
    out.adaptations.push("expansion-plan:interior-typing".into());
    let Some(d) = cx.skep_doc(&doc) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("interior_typing into unresolvable doc {doc}"));
        return;
    };
    let mut fails: Vec<(String, String)> = Vec::new();
    for r in results {
        let (Some(ch), Some(pos)) =
            (r.get("char").and_then(Value::as_str), r.get("position").and_then(Value::as_str))
        else {
            continue;
        };
        let Some((1, ord, _)) = resolve_position(cx.shadow, &doc, pos) else { continue };
        let resp = cx.rig.exec(Op::Insert {
            doc: d.clone(),
            at: vpos(1, ord),
            values: ch.bytes().map(|b| Val::new(vec![b])).collect(),
        });
        cx.shadow.insert(&doc, ord, ch.as_bytes());
        if let Some(code) = rejection_code(&resp) {
            fails.push((format!("insert '{ch}' at {pos}"), format!("Rejected({code})")));
            continue;
        }
        // Per-step probes: vspanset + contents recorded per character.
        let mut step = OpOutcome::new(out.index, &out.label);
        probe_state(cx, r, &mut step, grants, &doc, Probe::Step);
        if step.status == Status::Disagreed {
            fails.push((
                format!("step '{ch}': {}", step.expected.unwrap_or_default()),
                step.actual.unwrap_or_default(),
            ));
        }
    }
    if fails.is_empty() {
        out.status = Status::Agreed;
        out.comparator = Some("state-probe".into());
    } else {
        out.status = Status::Disagreed;
        out.comparator = Some("state-probe".into());
        out.expected = Some(fails.iter().map(|f| f.0.clone()).collect::<Vec<_>>().join(" | "));
        out.actual = Some(fails.iter().map(|f| f.1.clone()).collect::<Vec<_>>().join(" | "));
    }
}

fn h_delete(cx: &mut Cx, op: &Value, out: &mut OpOutcome, grants: &Grants, all: bool) {
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
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
    } else if let Some((ord, w)) = delete_region(cx.shadow, &doc, op) {
        if str_field(op, &["span", "vspan", "text"]).is_some_and(|s| span_dict(&Value::String(s.into())).is_none())
        {
            out.adaptations.push("span-from-description".into());
        }
        (1, ord, w)
    } else if let Some(start) = str_field(op, &["start", "address", "at"]) {
        // A link-subspace delete (delete_middle_link_check_gap_closure).
        match parse_vpos(start) {
            Some((sub, ord)) if sub != 1 => {
                let w = str_field(op, &["width"]).and_then(crate::tum::parse_width).unwrap_or(1);
                (sub, ord, w)
            }
            _ => {
                inexpressible(out, format!("delete start `{start}` is not groundable"));
                return;
            }
        }
    } else {
        if xf.is_some() {
            out.status = Status::Agreed;
            out.comparator = Some("expected-failure".into());
            out.note = Some("delete region not groundable; golden also recorded failure".into());
            return;
        }
        inexpressible(out, "delete without a groundable region".into());
        return;
    };
    let Some(d) = cx.skep_doc(&doc) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("delete in unresolvable doc {doc}"));
        return;
    };
    let r = cx.rig.exec(Op::Delete { doc: d, p: vpos(sub, ord), width: Nat::from(width) });
    if sub == 1 {
        cx.shadow.delete(&doc, ord, width);
    }
    if !settle_ack(out, xf, rejection_code(&r)) {
        return;
    }
    probe_state(cx, op, out, grants, &doc, Probe::PostWrite);
}

fn h_vcopy(cx: &mut Cx, index: usize, op: &Value, out: &mut OpOutcome, grants: &Grants) {
    // Pre-pass expansion plans cover the macro forms (vcopy_multiple /
    // vcopy_all / vcopy_from_both / vcopy_to_multiple / create_and_
    // transclude): fillers as inserts, shared regions as real copies.
    if cx.plans.contains_key(&index) {
        // vcopy_to_multiple / create_and_transclude bind their target ids.
        if let Some(targets) = field(op, &["targets"]).and_then(Value::as_array) {
            for t in targets {
                let id = t.as_str().or_else(|| t.get("docid").and_then(Value::as_str));
                if let Some(id) = id {
                    create_one(cx, out, id, None);
                }
            }
        }
        run_plan(cx, index, out);
        if out.status == Status::Disagreed {
            return;
        }
        // Per-target contents expectations (vcopy_to_multiple) compare here.
        if let Some(targets) = field(op, &["targets"]).and_then(Value::as_array) {
            let mut fails: Vec<(String, String)> = Vec::new();
            for t in targets {
                let (Some(id), Some(exp)) = (
                    t.get("docid").and_then(Value::as_str),
                    t.get("contents").and_then(expect_strings),
                ) else {
                    continue;
                };
                match cx.read_content(id) {
                    Ok(items) => {
                        if let Err((e, a)) = compare_content(&exp, &items, cx.alpha) {
                            fails.push((format!("{id}: {e}"), format!("{id}: {a}")));
                        }
                    }
                    Err(code) => fails.push((format!("{id}: contents"), format!("{id}: {code}"))),
                }
            }
            if !fails.is_empty() {
                out.status = Status::Disagreed;
                out.comparator = Some("content".into());
                out.expected =
                    Some(fails.iter().map(|f| f.0.clone()).collect::<Vec<_>>().join(" | "));
                out.actual =
                    Some(fails.iter().map(|f| f.1.clone()).collect::<Vec<_>>().join(" | "));
            } else if targets.iter().any(|t| t.get("contents").is_some()) {
                out.status = Status::Agreed;
                out.comparator = Some("content".into());
            }
        }
        return;
    }

    // Source spec(s): explicit vspec dicts, span dicts, located texts.
    let mut specs: Vec<VSpec> = Vec::new();
    let mut copied: Vec<u8> = Vec::new();
    let mut src_doc: Option<String> = None;
    if let Some(arr) =
        field(op, &["specs", "specset", "source", "sources"]).and_then(Value::as_array)
    {
        for v in arr {
            if let Some((docid, spans)) = vspec_dict(v) {
                let Some(sd) = cx.alpha.translate(&docid) else {
                    out.status = Status::Disagreed;
                    out.comparator = Some("alpha".into());
                    out.note = Some(format!("vcopy source doc {docid} unresolvable"));
                    return;
                };
                src_doc.get_or_insert(docid.clone());
                for (sub, ord, w) in spans {
                    if let Some(span) = vspan(sub, ord, w) {
                        if sub == 1 {
                            copied.extend(cx.shadow.slice(&docid, ord, w));
                        }
                        specs.push(VSpec { source: sd.clone(), span });
                    }
                }
            } else if let Some(t) = v.as_str() {
                match locate(cx.shadow, None, t) {
                    Some(l) => {
                        if !vcopy_push_located(cx, out, l, &mut specs, &mut copied, &mut src_doc) {
                            return;
                        }
                    }
                    None => {
                        inexpressible(out, format!("vcopy span {t:?} not groundable"));
                        return;
                    }
                }
            } else {
                inexpressible(out, "vcopy spec list holds an unrecognized entry".into());
                return;
            }
        }
    } else if let Some(arr) = field(op, &["spans"]).and_then(Value::as_array) {
        for v in arr {
            if let Some((sub, ord, w)) = span_dict(v) {
                let hint = str_field(op, &["from", "source_doc"])
                    .and_then(|s| cx.shadow.resolve_doc(s))
                    .or_else(|| cx.shadow.scoped());
                let Some(docid) = hint else { continue };
                let Some(sd) = cx.alpha.translate(&docid) else { continue };
                if let Some(span) = vspan(sub, ord, w) {
                    if sub == 1 {
                        copied.extend(cx.shadow.slice(&docid, ord, w));
                    }
                    src_doc.get_or_insert(docid.clone());
                    specs.push(VSpec { source: sd, span });
                }
            } else if let Some(t) = v.as_str() {
                match locate(cx.shadow, None, t) {
                    Some(l) => {
                        if !vcopy_push_located(cx, out, l, &mut specs, &mut copied, &mut src_doc) {
                            return;
                        }
                    }
                    None => {
                        inexpressible(out, format!("vcopy span {t:?} not groundable"));
                        return;
                    }
                }
            }
        }
    } else if let Some((1, ord, w)) = field(op, &["source_span", "span"]).and_then(span_dict) {
        let src = str_field(op, &["from", "source_doc"])
            .and_then(|s| cx.shadow.resolve_doc(s))
            .or_else(|| {
                let dest_hint = str_field(op, &["to", "dest", "target", "target_doc"])
                    .and_then(|s| cx.shadow.resolve_doc(s))
                    .unwrap_or_default();
                cx.shadow.content_docs_except(&dest_hint).first().cloned()
            });
        let Some(src) = src else {
            inexpressible(out, "vcopy source_span with no source document".into());
            return;
        };
        let Some(sd) = cx.alpha.translate(&src) else {
            out.status = Status::Disagreed;
            out.comparator = Some("alpha".into());
            out.note = Some(format!("vcopy source doc {src} unresolvable"));
            return;
        };
        if let Some(span) = vspan(1, ord, w) {
            copied.extend(cx.shadow.slice(&src, ord, w));
            src_doc = Some(src);
            specs.push(VSpec { source: sd, span });
        }
    } else if let Some(t) = str_field(op, &["text", "span"]) {
        let from = str_field(op, &["from", "source_doc"]).and_then(|s| cx.shadow.resolve_doc(s));
        match locate(cx.shadow, from.as_deref(), t) {
            Some(l) => {
                if !vcopy_push_located(cx, out, l, &mut specs, &mut copied, &mut src_doc) {
                    return;
                }
            }
            None => {
                inexpressible(out, format!("vcopy text {t:?} not groundable"));
                return;
            }
        }
    } else if let Some(from) =
        str_field(op, &["from", "source"]).and_then(|s| cx.shadow.resolve_doc(s))
    {
        // `from: <doc>` with no span: the whole current extent.
        let n = cx.shadow.text_len(&from);
        if let (Some(sd), Some(span)) = (cx.alpha.translate(&from), vspan(1, 1, n)) {
            out.adaptations.push("whole-extent".into());
            copied.extend(cx.shadow.slice(&from, 1, n));
            src_doc = Some(from);
            specs.push(VSpec { source: sd, span });
        } else {
            inexpressible(out, "vcopy from an empty document".into());
            return;
        }
    } else {
        inexpressible(out, "vcopy without specs, span or text".into());
        return;
    }
    if specs.is_empty() {
        inexpressible(out, "vcopy resolved to no source spans".into());
        return;
    }

    // Destination doc + position. `to` may be a doc reference or the
    // position markers "end"/"start" (destination = the source doc then).
    let to_raw = str_field(op, &["to", "dest", "target", "target_doc"]);
    let dest: Option<String> = match to_raw {
        Some("end") | Some("start") => src_doc.clone(),
        Some(s) => cx.shadow.resolve_doc(s),
        None => cx.doc_arg(op, out, &["doc", "docid"]),
    };
    let Some(dest) = dest else {
        inexpressible(out, "vcopy without a resolvable destination".into());
        return;
    };
    let ord = match str_field(op, &["address", "at", "position"]) {
        Some(p) => match resolve_position(cx.shadow, &dest, p) {
            Some((1, o, _)) => o,
            _ => {
                inexpressible(out, format!("vcopy position `{p}` is not groundable"));
                return;
            }
        },
        None => {
            if to_raw == Some("start") {
                1
            } else {
                out.adaptations.push("position-end".into());
                cx.shadow.text_len(&dest) + 1
            }
        }
    };
    let Some(d) = cx.skep_doc(&dest) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("vcopy destination {dest} unresolvable"));
        return;
    };
    let xf = expected_failure(op);
    let r = cx.rig.exec(Op::Copy { doc: d, at: vpos(1, ord), specs });
    cx.shadow.insert(&dest, ord, &copied);
    if !settle_ack(out, xf, rejection_code(&r)) {
        return;
    }
    probe_state(cx, op, out, grants, &dest, Probe::PostWrite);
}

/// Push one located vcopy source region: resolve its doc, record the copied
/// bytes and the V-spec. `false` = unresolvable doc (outcome written).
fn vcopy_push_located(
    cx: &mut Cx,
    out: &mut OpOutcome,
    l: fields::Located,
    specs: &mut Vec<VSpec>,
    copied: &mut Vec<u8>,
    src_doc: &mut Option<String>,
) -> bool {
    let Some(sd) = cx.alpha.translate(&l.doc) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("vcopy source doc {} unresolvable", l.doc));
        return false;
    };
    out.adaptations.push(l.how.into());
    if let Some(span) = vspan(1, l.ord, l.width) {
        copied.extend(cx.shadow.slice(&l.doc, l.ord, l.width));
        src_doc.get_or_insert(l.doc.clone());
        specs.push(VSpec { source: sd, span });
    }
    true
}

fn h_pivot_swap(cx: &mut Cx, op: &Value, out: &mut OpOutcome, pivot: bool) {
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        inexpressible(out, "rearrange with no document in scope".into());
        return;
    };
    let mut cuts = cuts_of(op);
    if cuts.is_empty() && !pivot {
        // Two texts to exchange, located in the shadow.
        if let Some(regions) = field(op, &["regions"]).and_then(Value::as_array) {
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
        }
    }
    let want = if pivot { 3 } else { 4 };
    if cuts.len() != want {
        inexpressible(out, format!("rearrange needs {want} cuts, could derive {}", cuts.len()));
        return;
    }
    let Some(d) = cx.skep_doc(&doc) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("rearrange in unresolvable doc {doc}"));
        return;
    };
    let xf = expected_failure(op);
    let r = cx
        .rig
        .exec(Op::Rearrange { doc: d, cuts: cuts.iter().map(|&c| vpos(1, c)).collect() });
    if pivot {
        cx.shadow.pivot(&doc, cuts[0], cuts[1], cuts[2]);
    } else {
        cx.shadow.swap(&doc, cuts[0], cuts[1], cuts[2], cuts[3]);
    }
    if !settle_ack(out, xf, rejection_code(&r)) {
        return;
    }
    out.status = Status::NotCompared;
}

// ── links ───────────────────────────────────────────────────────────────────

/// One endset side resolved to golden (doc, spans) pairs.
fn side_specs(cx: &mut Cx, out: &mut OpOutcome, v: &Value) -> Result<Vec<DocSpans>, String> {
    if let Some(arr) = v.as_array() {
        let mut sides = Vec::new();
        for item in arr {
            if let Some((docid, spans)) = vspec_dict(item) {
                sides.push((docid, spans));
            } else if let Some(s) = item.as_str() {
                sides.extend(side_specs(cx, out, &Value::String(s.to_string()))?);
            } else {
                return Err("endset list holds an unrecognized entry".into());
            }
        }
        return Ok(sides);
    }
    let Some(s) = v.as_str() else { return Err("endset field in an unrecognized shape".into()) };
    // A doc reference → whole current extent (bidirectional_explicit_links
    // `from: "A"` — the round-1 mistake of text-searching the LETTER A is
    // exactly what this branch prevents).
    if let Some(doc) = cx.shadow.resolve_doc(s) {
        let n = cx.shadow.text_len(&doc);
        if n == 0 {
            return Err(format!("doc {s} is empty"));
        }
        out.adaptations.push("whole-extent".into());
        return Ok(vec![(doc, vec![(1, 1, n)])]);
    }
    match locate(cx.shadow, None, s) {
        Some(l) => {
            out.adaptations.push(l.how.into());
            Ok(vec![(l.doc, vec![(1, l.ord, l.width)])])
        }
        None => Err(format!("endset text {s:?} not found")),
    }
}

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

/// Forward evidence for a bare link endset: the first LATER recorded
/// follow/endsets result for this link id, accepted only if no write op
/// intervenes (positions recorded then are positions now).
fn endset_evidence(
    cx: &Cx,
    from_index: usize,
    link_golden: &str,
    want_source: bool,
) -> Option<Vec<DocSpans>> {
    let writes = ["insert", "delete", "remove", "vcopy", "copy", "pivot", "swap", "rearrange"];
    for op in &cx.ops[from_index + 1..] {
        let label = label_of(op).to_ascii_lowercase();
        if writes.iter().any(|w| label.starts_with(w)) {
            return None;
        }
        let mentions = str_field(op, &["link", "link_id", "id"]).map(|l| l == link_golden);
        if label.starts_with("follow") && mentions.unwrap_or(true) {
            let slot_matches = match str_field(op, &["end", "direction", "linkend", "which"]) {
                Some(e) => {
                    (want_source && e.contains("source")) || (!want_source && e.contains("target"))
                }
                None => want_source, // bare follow records the SOURCE end
            };
            if slot_matches {
                if let Some(arr) = field(op, &["result"]).and_then(Value::as_array) {
                    let vspecs: Option<Vec<_>> = arr.iter().map(vspec_dict).collect();
                    if let Some(v) = vspecs.filter(|v| !v.is_empty()) {
                        return Some(v);
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

fn h_create_link(cx: &mut Cx, index: usize, op: &Value, out: &mut OpOutcome) {
    let xf = expected_failure(op);
    // Result ids: result/results fields, or arrow keys ("A->B": link).
    let arrows = arrow_results(op);
    let goldens: Vec<String> = match field(op, &["result", "results"]) {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => {
            a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
        }
        _ => arrows.iter().map(|(_, _, r)| r.clone()).collect(),
    };
    if goldens.len() > 1 {
        out.adaptations.push("create_links:repeat".into());
    }

    // Group endsets for plural creates (star_hub, selective_removal):
    // link k runs from group-member k (or the recorded home) to the
    // target-role doc (or per-k members of a target group).
    let from_group = str_field(op, &["from", "source"])
        .filter(|s| cx.shadow.resolve_doc(s).is_none())
        .map(|s| s.trim_end_matches('s').to_string());
    let to_group = str_field(op, &["to", "target"])
        .filter(|s| cx.shadow.resolve_doc(s).is_none())
        .map(|s| s.trim_end_matches('s').to_string());

    let count = goldens.len().max(1);
    let mut bound = 0usize;
    for k in 0..count {
        let golden = goldens.get(k).cloned();
        let arrow = arrows.get(k).cloned().or_else(|| {
            golden.as_ref().and_then(|g| {
                arrows.iter().find(|(_, _, r)| r == g).cloned()
            })
        });

        // FROM side.
        let mut from_sides: Vec<DocSpans> = Vec::new();
        let explicit_from = field(op, &["source", "from"]).filter(|v| !v.is_string() || {
            v.as_str().is_some_and(|s| cx.shadow.resolve_doc(s).is_some() || locate(cx.shadow, None, s).is_some())
        });
        if let Some((f, _, _)) = &arrow {
            if let Some(doc) = cx.shadow.resolve_doc(f) {
                let n = cx.shadow.text_len(&doc);
                if n > 0 {
                    out.adaptations.push("whole-extent".into());
                    from_sides.push((doc, vec![(1, 1, n)]));
                }
            }
        }
        if from_sides.is_empty() {
            if let Some(v) = explicit_from {
                match side_specs(cx, out, v) {
                    Ok(s) => from_sides = s,
                    Err(e) => {
                        inexpressible(out, format!("create_link source: {e}"));
                        return;
                    }
                }
            }
        }
        if from_sides.is_empty() {
            if let Some(t) = str_field(op, &["source_text"]) {
                match locate(cx.shadow, None, t) {
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
        if from_sides.is_empty() {
            if let Some(g) = from_group.as_ref() {
                if let Some(doc) = cx.shadow.resolve_doc(&format!("{g}{}", k + 1)) {
                    let n = cx.shadow.text_len(&doc);
                    if n > 0 {
                        out.adaptations.push("whole-extent".into());
                        from_sides.push((doc, vec![(1, 1, n)]));
                    }
                }
            }
        }
        // Home: the recorded result's own prefix is authoritative.
        let home_golden = golden
            .as_ref()
            .and_then(|g| link_home_docid(g))
            .or_else(|| str_field(op, &["home_doc", "home"]).and_then(|s| cx.shadow.resolve_doc(s)))
            .or_else(|| from_sides.first().map(|(d, _)| d.clone()))
            .or_else(|| cx.shadow.resolve_doc("source"))
            .or_else(|| cx.shadow.scoped());
        let Some(home_golden) = home_golden else {
            inexpressible(out, "create_link with no home document in scope".into());
            return;
        };
        if from_sides.is_empty() {
            // Evidence, then the scripts' first-word convention.
            if let Some(g) = &golden {
                if let Some(ev) = endset_evidence(cx, index, g, true) {
                    out.adaptations.push("endset-evidence".into());
                    from_sides = ev;
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
            }
            if from_sides.is_empty() {
                inexpressible(out, "create_link source: nothing to ground the FROM endset".into());
                return;
            }
        }

        // TO side.
        let mut to_sides: Vec<DocSpans> = Vec::new();
        if let Some((_, t, _)) = &arrow {
            if let Some(doc) = cx.shadow.resolve_doc(t) {
                let n = cx.shadow.text_len(&doc);
                if n > 0 {
                    to_sides.push((doc, vec![(1, 1, n)]));
                }
            }
        }
        if to_sides.is_empty() {
            if let Some(v) = field(op, &["target", "to"]).filter(|v| {
                !v.is_string()
                    || v.as_str().is_some_and(|s| {
                        cx.shadow.resolve_doc(s).is_some() || locate(cx.shadow, None, s).is_some()
                    })
            }) {
                match side_specs(cx, out, v) {
                    Ok(s) => to_sides = s,
                    Err(e) => {
                        inexpressible(out, format!("create_link target: {e}"));
                        return;
                    }
                }
            }
        }
        if to_sides.is_empty() {
            if let Some(t) = str_field(op, &["target_text"]) {
                match locate(cx.shadow, None, t) {
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
        if to_sides.is_empty() {
            if let Some(g) = to_group.as_ref() {
                let member = cx
                    .shadow
                    .resolve_doc(&format!("{g}{}", k + 1))
                    .or_else(|| cx.shadow.resolve_doc(g));
                if let Some(doc) = member {
                    let n = cx.shadow.text_len(&doc);
                    if n > 0 {
                        to_sides.push((doc, vec![(1, 1, n)]));
                    }
                }
            }
        }
        if to_sides.is_empty() {
            if let Some(g) = &golden {
                if let Some(ev) = endset_evidence(cx, index, g, false) {
                    out.adaptations.push("endset-evidence".into());
                    to_sides = ev;
                }
            }
        }
        if to_sides.is_empty() {
            // The target-role doc's whole extent; a single-doc scenario
            // self-links (three_links_vspan_growth has only one document).
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
        let r = cx.rig.exec(Op::MakeLink { home, from, to, ty: vec![ty] });
        match r {
            Response::AckAddr { addr, .. } => {
                cx.shadow.seat_link(&home_golden);
                cx.shadow.set_current(&home_golden);
                if let Some(g) = &golden {
                    cx.alpha.bind(g, &addr);
                    cx.shadow.last_link = Some(g.clone());
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

/// Resolve a link-slot name to M7's positional index (FROM=1, TO=2, TYPE=3).
fn slot_of(name: &str) -> Option<usize> {
    if name.contains("source") || name == "from" {
        return Some(1);
    }
    if name.contains("target") || name == "to" {
        return Some(2);
    }
    if name.contains("type") {
        return Some(3);
    }
    None
}

fn h_follow_link(cx: &mut Cx, op: &Value, out: &mut OpOutcome, grants: &Grants) {
    out.adaptations.push("follow_as_projection".into());
    let label = label_of(op);
    let slot = str_field(op, &["end", "direction", "linkend", "which"])
        .and_then(|e| {
            if e.contains("->") {
                // "direction": "A->B" follows the link forward: TARGET end.
                Some(2)
            } else {
                slot_of(e)
            }
        })
        .or_else(|| {
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
            // Bare follow records the SOURCE end (pinned by isolation/
            // insert_text_does_not_affect_links_in_same_document, whose
            // recorded before/after results are the source spans).
            out.adaptations.push("default-slot:source".into());
            1
        });
    let link_golden = str_field(op, &["link", "link_id", "id"])
        .filter(|s| fields::is_link_address(s))
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
    follow_compare(cx, out, grants, &link, slot, expected);
}

/// Project a link slot and compare against a recorded expectation (vspec
/// dicts, a python VSpec string, or endset-content strings).
fn follow_compare(
    cx: &mut Cx,
    out: &mut OpOutcome,
    grants: &Grants,
    link: &skep_address::Address,
    slot: usize,
    expected: &Value,
) {
    let project = |cx: &mut Cx, d: &skep_address::Address| -> Result<skep_address::SpanSet, String> {
        match cx.rig.exec(Op::Project { a: link.clone(), slot, d: d.clone() }) {
            Response::SpanSet { set, .. } => Ok(set),
            r => Err(rejection_code(&r).unwrap_or_else(|| "unexpected response".into())),
        }
    };

    // Shape 1: vspec dicts (possibly several docs) — compare spans per doc.
    let as_vspecs: Option<Vec<DocSpans>> =
        expected.as_array().and_then(|arr| arr.iter().map(vspec_dict).collect());
    if let Some(vspecs) = as_vspecs {
        if !vspecs.is_empty() {
            out.comparator = Some("projection".into());
            let mut fails: Vec<(String, String)> = Vec::new();
            for (docid, spans) in vspecs {
                let Some(d) = cx.alpha.translate(&docid) else {
                    fails.push((format!("{docid}: spans"), format!("{docid}: unresolvable")));
                    continue;
                };
                let want: Vec<RawSpan> = spans
                    .iter()
                    .map(|(s, o, w)| (format!("{s}.{o}"), format!("0.{w}")))
                    .collect();
                match project(cx, &d) {
                    Ok(set) => {
                        if let Err((e, a)) = compare_spansets(&want, &set, grants.width_tolerance) {
                            fails.push((format!("{docid}: {e}"), format!("{docid}: {a}")));
                        }
                    }
                    Err(code) => {
                        fails.push((format!("{docid}: spans"), format!("{docid}: {code}")))
                    }
                }
            }
            if fails.is_empty() {
                out.status = Status::Agreed;
            } else {
                out.status = Status::Disagreed;
                out.expected =
                    Some(fails.iter().map(|f| f.0.clone()).collect::<Vec<_>>().join(" | "));
                out.actual =
                    Some(fails.iter().map(|f| f.1.clone()).collect::<Vec<_>>().join(" | "));
            }
            return;
        }
    }
    // Shape 2: python VSpec string.
    if let Some(s) = expected.as_str() {
        if let Some((Some(docid), spans)) = parse_python_spec(s) {
            out.comparator = Some("projection".into());
            let target = cx.alpha.translate(&docid);
            let projected = match target {
                Some(d) => project(cx, &d),
                None => Err("unresolvable".to_string()),
            };
            match projected {
                Ok(set) => match compare_spansets(&spans, &set, grants.width_tolerance) {
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
    let mut items_actual: Vec<DeliveryItem> = Vec::new();
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
                    Response::Delivery { items, .. } => items_actual.extend(items.0),
                    r => errors.push(format!(
                        "{docid}: retrieve {}",
                        rejection_code(&r).unwrap_or_else(|| "?".into())
                    )),
                }
            }
            Err(code) => errors.push(format!("{docid}: {code}")),
        }
    }
    out.comparator = Some("projection-content".into());
    match compare_content(&strings, &items_actual, cx.alpha) {
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

/// Traversal macros: reverse_traversal / traverse_* / follow_links_* —
/// per-entry link follows with optional per-hop find_links checks. An op in
/// this family without a step list is a single follow (follow_links_target).
fn h_traverse(cx: &mut Cx, op: &Value, out: &mut OpOutcome, grants: &Grants) {
    let label = label_of(op).to_ascii_lowercase();
    let entries = field(op, &["path", "traversal", "results", "steps"])
        .and_then(Value::as_array)
        .or_else(|| {
            // A `result`/`results` list of step OBJECTS is a traversal; a
            // list of strings/vspecs is a single follow's expectation.
            field(op, &["result", "results"])
                .and_then(Value::as_array)
                .filter(|a| a.iter().all(|v| v.is_object() && vspec_dict(v).is_none()))
        });
    let Some(entries) = entries else {
        h_follow_link(cx, op, out, grants);
        return;
    };
    let reverse = label.contains("reverse");
    let default_slot = if label.contains("source") || reverse { 1 } else { 2 };
    out.adaptations.push("follow_as_projection".into());
    let mut fails: Vec<(String, String)> = Vec::new();
    let mut compared = 0usize;
    for entry in entries {
        let Some(e) = entry.as_object() else { continue };
        // links_found: 0 — a hop asserting no incoming/outgoing links.
        if let Some(n) = e.get("links_found").and_then(Value::as_u64) {
            let at = e.get("at").and_then(Value::as_str).and_then(|s| cx.shadow.resolve_doc(s));
            if let Some(atdoc) = at {
                compared += 1;
                let count = find_links_into(cx, &atdoc, reverse);
                if count as u64 != n {
                    fails.push((format!("{atdoc}: {n} links"), format!("{atdoc}: {count}")));
                }
            }
            continue;
        }
        // The link this hop follows.
        let link_golden: Option<String> = e
            .get("link")
            .and_then(Value::as_str)
            .filter(|s| fields::is_link_address(s))
            .map(str::to_string)
            .or_else(|| {
                let step = e.get("step").and_then(Value::as_str)?;
                let (f, t) = step.split_once("->")?;
                cx.shadow.arrow_links.get(&(f.trim().to_string(), t.trim().to_string())).cloned()
            })
            .or_else(|| {
                let f = e.get("from").and_then(Value::as_str)?.trim();
                let t = e.get("to").and_then(Value::as_str)?;
                let t = t.split_whitespace().next().unwrap_or(t).trim();
                cx.shadow.arrow_links.get(&(f.to_string(), t.to_string())).cloned()
            })
            .or_else(|| {
                // reverse_traversal: at X, the link ARRIVING from
                // found_link_from — the arrow (from, X).
                let at = e.get("at").and_then(Value::as_str)?.trim();
                let from = e.get("found_link_from").and_then(Value::as_str)?.trim();
                cx.shadow.arrow_links.get(&(from.to_string(), at.to_string())).cloned()
            });
        let Some(link_golden) = link_golden else {
            fails.push(("hop link".into(), "no link resolvable for this hop".into()));
            continue;
        };
        let Some(link) = cx.alpha.translate(&link_golden) else {
            fails.push((link_golden.clone(), "unresolvable link".into()));
            continue;
        };
        let (slot, expected) = if let Some(t) = e.get("target_text") {
            (2, t)
        } else if let Some(t) = e.get("source_text") {
            (1, t)
        } else if let Some(t) = e.get("text") {
            (default_slot, t)
        } else if let Some(t) = e.get("result") {
            (default_slot, t)
        } else {
            continue;
        };
        let mut hop = OpOutcome::new(out.index, &out.label);
        follow_compare(cx, &mut hop, &Grants::default(), &link, slot, expected);
        compared += 1;
        if hop.status == Status::Disagreed {
            fails.push((
                format!("{link_golden}: {}", hop.expected.unwrap_or_default()),
                hop.actual.unwrap_or_else(|| hop.note.unwrap_or_default()),
            ));
        }
    }
    out.comparator = Some("traversal".into());
    if compared == 0 && fails.is_empty() {
        out.status = Status::NotCompared;
        out.note = Some("traversal entries carried nothing comparable".into());
    } else if fails.is_empty() {
        out.status = Status::Agreed;
    } else {
        out.status = Status::Disagreed;
        out.expected = Some(fails.iter().map(|f| f.0.clone()).collect::<Vec<_>>().join(" | "));
        out.actual = Some(fails.iter().map(|f| f.1.clone()).collect::<Vec<_>>().join(" | "));
    }
}

/// Links whose TO (reverse) / FROM (forward) endset touches `doc`'s extent.
fn find_links_into(cx: &mut Cx, doc: &str, reverse: bool) -> usize {
    let n = cx.shadow.text_len(doc);
    let (e, _) = cx.image_endset(doc, &[(1, 1, n.max(1))]);
    let spec = if e.is_empty() { SlotSpec::Empty } else { SlotSpec::Spans(e) };
    let q = if reverse {
        FourSet { home: SlotSpec::Any, from: SlotSpec::Any, to: spec, ty: SlotSpec::Any }
    } else {
        FourSet { home: SlotSpec::Any, from: spec, to: SlotSpec::Any, ty: SlotSpec::Any }
    };
    match cx.rig.exec(Op::FindLinksFtt { q }) {
        Response::Addrs { addrs, .. } => addrs.len(),
        _ => 0,
    }
}

fn h_find_links(cx: &mut Cx, op: &Value, out: &mut OpOutcome, grants: &Grants) {
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

    // The search region: vspec array, doc reference, located text.
    let search_sides: Option<Vec<DocSpans>> = (|| {
        if let Some(v) = field(op, &["search", "specs", "specset", "source_specs"]) {
            if let Some(s) = v.as_str() {
                if s.contains("NOSPECS") || s == "empty" {
                    return Some(Vec::new());
                }
                if s == "full document" || s.starts_with("entire") {
                    let d = cx.shadow.scoped()?;
                    let n = cx.shadow.text_len(&d);
                    return Some(vec![(d, vec![(1, 1, n.max(1))])]);
                }
                let l = locate(cx.shadow, None, s)?;
                return Some(vec![(l.doc, vec![(1, l.ord, l.width)])]);
            }
            let arr = v.as_array()?;
            let vspecs: Option<Vec<_>> = arr.iter().map(vspec_dict).collect();
            return vspecs;
        }
        if let Some(t) = str_field(op, &["search_text", "query"]) {
            if t == "full document" || t.starts_with("entire") {
                let d = cx.shadow.scoped()?;
                let n = cx.shadow.text_len(&d);
                return Some(vec![(d, vec![(1, 1, n.max(1))])]);
            }
            let l = locate(cx.shadow, None, t)?;
            return Some(vec![(l.doc, vec![(1, l.ord, l.width)])]);
        }
        None
    })();
    if str_field(op, &["search_text", "query"]).is_some() && search_sides.is_some() {
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

    let mut from_sides: Option<Vec<DocSpans>> = None;
    let mut to_sides: Option<Vec<DocSpans>> = None;

    if let Some(s) = explicit_side(cx, out, &["from", "source", "sources"]) {
        from_sides = Some(s);
    }
    if let Some(s) = explicit_side(cx, out, &["to", "target", "targets"]) {
        to_sides = Some(s);
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
                to_sides = Some(whole_of(cx, d));
            }
        } else if by_is_target && to_sides.is_none() {
            if let Some(d) = cx.shadow.resolve_doc("target") {
                to_sides = Some(whole_of(cx, &d));
            }
        }
    }
    if by_is_both || (!by_is_target && by.is_some() && from_sides.is_none()) {
        if let Some(d) = &by_from_doc {
            if from_sides.is_none() {
                from_sides = Some(whole_of(cx, d));
            }
        }
    }
    if from_sides.is_none() && to_sides.is_none() {
        // Bare find_links: the recording client searched by the scoped
        // document's whole current extent (orphaned_link_discovery_by_
        // link_id records [] precisely because the deleted source extent
        // resolves to nothing).
        if let Some(d) = cx.shadow.scoped() {
            out.adaptations.push("doc-from-register".into());
            from_sides = Some(whole_of(cx, &d));
        }
    }
    // An explicit doc field narrows the bare search to that document.
    if let Some(d) = str_field(op, &["doc", "docid"]).and_then(|s| cx.shadow.resolve_doc(s)) {
        if field(op, &["from", "source", "sources"]).is_none()
            && field(op, &["search", "specs", "specset"]).is_none()
            && str_field(op, &["search_text", "query"]).is_none()
        {
            from_sides = Some(whole_of(cx, &d));
        }
    }

    let side_to_slot = |cx: &mut Cx, sides: Option<Vec<DocSpans>>, notes: &mut Vec<String>| -> SlotSpec {
        match sides {
            None => SlotSpec::Any,
            Some(list) => {
                let mut all: Vec<skep_address::Span> = Vec::new();
                for (doc, spans) in &list {
                    if spans.is_empty() {
                        continue;
                    }
                    let (e, n) = cx.image_endset(doc, spans);
                    notes.extend(n);
                    all.extend(e.spans().cloned());
                }
                let e = Endset::from_spans(all.into_iter());
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
    let home = match field(op, &["homedocids", "homedocs", "home_docs", "homedoc", "home_doc", "home"])
    {
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
    let expected = field(op, &["result", "links", "expected"]).and_then(Value::as_array);
    let Some(expected) = expected else {
        if let Some(n) = field(op, &["expected_count", "count"]).and_then(Value::as_u64) {
            out.comparator = Some("count".into());
            match compare_count(n, grants.count_delta, addrs.len()) {
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
        compare_addr_sets(&want, &addrs, cx.alpha, |a| rig.is_types_addr(a), &mut adaptations);
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

fn h_find_documents(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    let xf = expected_failure(op);
    let mut regions: Vec<Region> = Vec::new();
    let mut ground_failed: Option<String> = None;
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
                let spans: Vec<skep_address::Span> =
                    spans.iter().filter_map(|(s, o, w)| vspan(*s, *o, *w)).collect();
                regions.push(Region { doc: d, spans });
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
                            regions.push(Region { doc: d, spans: vec![span] });
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
                regions.push(Region { doc: d, spans });
            }
            None => ground_failed = Some(format!("query {qt:?} not found")),
        }
    } else if let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) {
        let n = cx.shadow.text_len(&doc);
        if let Some(d) = cx.alpha.translate(&doc) {
            regions.push(Region { doc: d, spans: vspan(1, 1, n).into_iter().collect() });
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
        compare_addr_sets(&want, &addrs, cx.alpha, |a| rig.is_types_addr(a), &mut adaptations);
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

// ── content reads ───────────────────────────────────────────────────────────

const CONTENT_EXPECT_KEYS: &[&str] = &[
    "result", "before", "after", "content", "contents", "sample", "remaining", "empty",
    "expected", "value", "text",
];

fn h_contents(cx: &mut Cx, op: &Value, out: &mut OpOutcome, label: &str) {
    let xf = expected_failure(op);

    // Multi-doc probe: `docs` map of name → expected strings.
    if let Some(map) = op.get("docs").and_then(Value::as_object) {
        let mut fails: Vec<(String, String)> = Vec::new();
        for (name, exp) in map {
            let (Some(doc), Some(strings)) =
                (cx.shadow.resolve_doc(name), expect_strings(exp))
            else {
                continue;
            };
            // An id map (create_documents-shaped), not a content probe.
            if strings.iter().any(|s| s.contains('.') && parse_dotted(s).is_some()) {
                continue;
            }
            match cx.read_content(&doc) {
                Ok(items) => {
                    if let Err((e, a)) = compare_content(&strings, &items, cx.alpha) {
                        fails.push((format!("{name}: {e}"), format!("{name}: {a}")));
                    }
                }
                Err(code) => fails.push((format!("{name}: contents"), format!("{name}: {code}"))),
            }
        }
        out.adaptations.push("contents:content-subspace".into());
        out.comparator = Some("content".into());
        if fails.is_empty() {
            out.status = Status::Agreed;
        } else {
            out.status = Status::Disagreed;
            out.expected = Some(fails.iter().map(|f| f.0.clone()).collect::<Vec<_>>().join(" | "));
            out.actual = Some(fails.iter().map(|f| f.1.clone()).collect::<Vec<_>>().join(" | "));
        }
        return;
    }

    // Per-position probe: `positions` map of "1.3" → "C".
    if let Some(map) = op.get("positions").and_then(Value::as_object) {
        let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
            inexpressible(out, "positions probe with no document in scope".into());
            return;
        };
        let Some(d) = cx.skep_doc(&doc) else {
            out.status = Status::Disagreed;
            out.comparator = Some("alpha".into());
            out.note = Some(format!("positions probe doc {doc} unresolvable"));
            return;
        };
        let mut fails: Vec<(String, String)> = Vec::new();
        for (pos, exp) in map {
            let (Some((sub, ord)), Some(want)) = (parse_vpos(pos), exp.as_str()) else { continue };
            let Some(span) = vspan(sub, ord, 1) else { continue };
            match cx.rig.exec(Op::RetrieveV { specs: vec![Spec { doc: d.clone(), span }] }) {
                Response::Delivery { items, .. } => {
                    let got: String = items
                        .0
                        .iter()
                        .map(|it| match it {
                            DeliveryItem::Content(v) => {
                                String::from_utf8_lossy(v.as_bytes()).into_owned()
                            }
                            DeliveryItem::Ref(a) => format!("@{}", cx.alpha.render_skep(a)),
                        })
                        .collect();
                    if got != want {
                        fails.push((format!("{pos}={want:?}"), format!("{pos}={got:?}")));
                    }
                }
                r => fails.push((
                    format!("{pos}={want:?}"),
                    format!("{pos}: {}", rejection_code(&r).unwrap_or_else(|| "?".into())),
                )),
            }
        }
        out.comparator = Some("content-positions".into());
        if fails.is_empty() {
            out.status = Status::Agreed;
        } else {
            out.status = Status::Disagreed;
            out.expected = Some(fails.iter().map(|f| f.0.clone()).collect::<Vec<_>>().join(" | "));
            out.actual = Some(fails.iter().map(|f| f.1.clone()).collect::<Vec<_>>().join(" | "));
        }
        return;
    }

    let expected = field(op, CONTENT_EXPECT_KEYS);
    let strings: Option<Vec<String>> = expected.and_then(expect_strings);

    // The expectation itself may name the doc (a link-address probe's home).
    let doc_from_exp: Option<String> = strings.as_ref().and_then(|ss| {
        ss.iter().find_map(|s| link_home_docid(s)).filter(|h| cx.shadow.knows(h))
    });
    if let Some(h) = &doc_from_exp {
        cx.shadow.set_current(h);
    }

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
                for docid in cx.shadow.all_docs() {
                    if let (Some(d), Some(span)) = (cx.alpha.peek(&docid), vspan(1, 1, n)) {
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
            out.status = Status::Disagreed;
            out.comparator = Some("alpha".into());
            out.note = Some(format!("retrieve doc {doc} unresolvable"));
            return;
        };
        let items: Vec<&Value> = match v {
            Value::Array(a) => a.iter().collect(),
            other => vec![other],
        };
        for item in items {
            if let Some((s, o, w)) = span_dict(item) {
                if let Some(span) = vspan(s, o, w) {
                    specs.push(Spec { doc: d.clone(), span });
                }
            } else if let Some(t) = item.as_str() {
                match locate(cx.shadow, Some(&doc), t) {
                    Some(l) => {
                        out.adaptations.push(l.how.into());
                        if let Some(span) = vspan(1, l.ord, l.width) {
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
    } else {
        let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
            inexpressible(out, "retrieve with no document in scope".into());
            return;
        };
        let Some(d) = cx.skep_doc(&doc) else {
            out.status = Status::Disagreed;
            out.comparator = Some("alpha".into());
            out.note = Some(format!("retrieve doc {doc} unresolvable"));
            return;
        };
        let pos = str_field(op, &["address", "at", "position"]).and_then(parse_vpos).or_else(
            || {
                position_from_label(label).map(|p| {
                    out.adaptations.push("position-from-label".into());
                    p
                })
            },
        );
        if let Some((sub, ord)) = pos {
            if let Some(span) = vspan(sub, ord, 1) {
                specs.push(Spec { doc: d, span });
            }
        } else {
            // Whole document: the CONTENT subspace only (policy
            // `contents:content-subspace`).
            out.adaptations.push("contents:content-subspace".into());
            let n = cx.shadow.text_len(&doc);
            if let Some(span) = vspan(1, 1, n) {
                specs.push(Spec { doc: d, span });
            }
        }
    }
    let items: Vec<DeliveryItem> = if specs.is_empty() {
        Vec::new() // empty document / empty specset: nothing to ask for
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
    let Some(strings) = strings else {
        out.status = Status::NotCompared;
        return;
    };
    out.comparator = Some("content".into());
    match compare_content(&strings, &items, cx.alpha) {
        Ok(()) => out.status = Status::Agreed,
        Err((e, a)) => {
            out.status = Status::Disagreed;
            out.expected = Some(e);
            out.actual = Some(a);
        }
    }
}

/// Harvest a vspanset expectation from ANY plausible field (the goldens key
/// them result/before/after/empty_state/after_insert/…): first the standard
/// keys, then a scan of remaining fields for span-set-shaped values.
fn harvest_spanset(op: &Value) -> Option<(String, Option<String>, Vec<RawSpan>)> {
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
        if fields::looks_like_spanset(v) || v.as_str().is_some_and(|s| s.starts_with('<')) {
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

fn h_vspanset(cx: &mut Cx, op: &Value, out: &mut OpOutcome, grants: &Grants, full_set: bool) {
    let harvested = harvest_spanset(op);
    // The expectation's own docid names the document when the op omits it.
    let doc = harvested
        .as_ref()
        .and_then(|(_, d, _)| d.clone())
        .and_then(|d| cx.shadow.resolve_doc(&d))
        .or_else(|| cx.doc_arg(op, out, &["doc", "docid"]));
    let Some(doc) = doc else {
        inexpressible(out, "vspanset probe with no document in scope".into());
        return;
    };
    cx.shadow.set_current(&doc);
    let Some(d) = cx.skep_doc(&doc) else {
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
    if let Some(n) = field(op, &["span_count"]).and_then(Value::as_u64) {
        out.comparator = Some("count".into());
        let actual = set.iter().count();
        match compare_count(n, grants.count_delta, actual) {
            Ok(()) => out.status = Status::Agreed,
            Err((e, a)) => {
                out.status = Status::Disagreed;
                out.expected = Some(e);
                out.actual = Some(a);
            }
        }
        return;
    }
    let Some((_, _, spans)) = harvested else {
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
            if collapsed_subspace_shape(&spans) {
                out.note = Some(COLLAPSED_SUBSPACE_ANALYSIS.to_string());
            }
        }
    }
}

fn h_endsets(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
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
            .is_some_and(fields::is_link_address);
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
        out.comparator = Some("endsets-follow-widths".into());
        let mut fails: Vec<(String, String)> = Vec::new();
        for (slot_keys, slot) in
            [(&["from", "source"][..], 1usize), (&["to", "target"][..], 2)]
        {
            let Some(exp) = field(op, slot_keys).and_then(Value::as_array) else { continue };
            let mut want: Vec<u64> = Vec::new();
            for v in exp {
                if let Some((_, spans)) = vspec_dict(v) {
                    want.extend(spans.iter().map(|(_, _, w)| *w));
                }
            }
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
                    fails.push((
                        format!("slot{slot} widths"),
                        rejection_code(&r).unwrap_or_else(|| "?".into()),
                    ));
                    continue;
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

// ── compare ─────────────────────────────────────────────────────────────────

/// A shared-span pair side: bare `{start,width}`, `{docid, span}`, or
/// `{docid, spans:[…]}` — returns (optional docid, ord, width), content
/// subspace only.
fn pair_side(v: &Value) -> Option<(Option<String>, u64, u64)> {
    if let Some((sub, ord, w)) = span_dict(v) {
        if sub == 1 {
            return Some((None, ord, w));
        }
        return None;
    }
    let o = v.as_object()?;
    let docid = o.get("docid").and_then(Value::as_str).map(str::to_string);
    if let Some(sp) = o.get("span") {
        let (sub, ord, w) = span_dict(sp)?;
        if sub == 1 {
            return Some((docid, ord, w));
        }
        return None;
    }
    if let Some(arr) = o.get("spans").and_then(Value::as_array) {
        let (sub, ord, w) = arr.first().and_then(span_dict)?;
        if sub == 1 {
            return Some((docid, ord, w));
        }
    }
    None
}

/// One recorded shared-span pair → (A-side, B-side), oriented by docid
/// match first, then key-name match against the two doc references, then
/// the source/dest role convention.
fn orient_pair(
    item: &Value,
    ga: &str,
    gb: &str,
    ref_a: &str,
    ref_b: &str,
) -> Option<((u64, u64), (u64, u64))> {
    let o = item.as_object()?;
    let sides: Vec<(String, (Option<String>, u64, u64))> = o
        .iter()
        .filter_map(|(k, v)| pair_side(v).map(|s| (k.clone(), s)))
        .collect();
    if sides.len() < 2 {
        return None;
    }
    let score_a = |k: &str, doc: &Option<String>| -> i32 {
        if doc.as_deref() == Some(ga) {
            return 3;
        }
        if k == ref_a || k.contains(ref_a) || ref_a.contains(k) {
            return 2;
        }
        if matches!(k, "a" | "source" | "original" | "doc1" | "first") {
            return 1;
        }
        0
    };
    let score_b = |k: &str, doc: &Option<String>| -> i32 {
        if doc.as_deref() == Some(gb) {
            return 3;
        }
        if k == ref_b || k.contains(ref_b) || ref_b.contains(k) {
            return 2;
        }
        if matches!(k, "b" | "dest" | "target" | "version" | "doc2" | "second") {
            return 1;
        }
        0
    };
    let mut best: Option<(usize, usize, i32)> = None;
    for (i, (ki, (di, _, _))) in sides.iter().enumerate() {
        for (j, (kj, (dj, _, _))) in sides.iter().enumerate() {
            if i == j {
                continue;
            }
            let s = score_a(ki, di) + score_b(kj, dj);
            if best.is_none_or(|(_, _, bs)| s > bs) {
                best = Some((i, j, s));
            }
        }
    }
    let (i, j, _) = best?;
    let (_, (_, oa, wa)) = &sides[i];
    let (_, (_, ob, _)) = &sides[j];
    Some(((*oa, *wa), (*ob, *wa)))
}

fn run_compare_pair(
    cx: &mut Cx,
    out: &mut OpOutcome,
    ga: &str,
    gb: &str,
    ref_a: &str,
    ref_b: &str,
    shared: &[Value],
) -> Option<()> {
    let (Some(da), Some(db)) = (cx.alpha.translate(ga), cx.alpha.translate(gb)) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some("compare over unresolvable documents".into());
        return None;
    };
    let whole = |cx: &Cx, g: &str, d: &skep_address::Address| -> Region {
        let n = cx.shadow.text_len(g);
        Region { doc: d.clone(), spans: vspan(1, 1, n).into_iter().collect() }
    };
    let rho1 = vec![whole(cx, ga, &da)];
    let rho2 = vec![whole(cx, gb, &db)];
    let rep = match cx.rig.exec(Op::Compare { rho1, rho2 }) {
        Response::Compare { rep, .. } => rep,
        other => {
            fail_response(out, "correspondence", "a compare report", &other);
            return None;
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
    let mut want: Vec<(u64, u64, u64)> = Vec::new();
    for item in shared {
        if let Some(((oa, wa), (ob, _))) = orient_pair(item, ga, gb, ref_a, ref_b) {
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
    Some(())
}

fn h_compare(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    // Per-source comparison list (content/vcopy_from_multiple_documents
    // `comparisons`): entries {source: name, shared: […]} against the
    // destination doc.
    if let Some(entries) = field(op, &["results", "comparisons"]).and_then(Value::as_array) {
        if entries.iter().all(|e| e.get("shared").is_some()) && !entries.is_empty() {
            let dest = cx
                .shadow
                .resolve_doc("target")
                .or_else(|| cx.shadow.scoped());
            let Some(dest) = dest else {
                inexpressible(out, "comparisons with no destination doc in scope".into());
                return;
            };
            let mut fails: Vec<(String, String)> = Vec::new();
            for e in entries {
                let Some(srcname) = e.get("source").and_then(Value::as_str) else { continue };
                let Some(src) = cx.shadow.resolve_doc(srcname) else { continue };
                let shared: Vec<Value> =
                    e.get("shared").and_then(Value::as_array).cloned().unwrap_or_default();
                let mut sub = OpOutcome::new(out.index, &out.label);
                run_compare_pair(cx, &mut sub, &dest, &src, "target", "source", &shared);
                if sub.status == Status::Disagreed {
                    fails.push((
                        format!("{srcname}: {}", sub.expected.unwrap_or_default()),
                        sub.actual.unwrap_or_else(|| sub.note.unwrap_or_default()),
                    ));
                }
            }
            out.comparator = Some("correspondence".into());
            if fails.is_empty() {
                out.status = Status::Agreed;
            } else {
                out.status = Status::Disagreed;
                out.expected =
                    Some(fails.iter().map(|f| f.0.clone()).collect::<Vec<_>>().join(" | "));
                out.actual =
                    Some(fails.iter().map(|f| f.1.clone()).collect::<Vec<_>>().join(" | "));
            }
            return;
        }
    }

    // The two documents, as referenced by the golden (names or addresses).
    let (ref_a, ref_b): (String, String) = if let Some(docs) =
        field(op, &["docs", "documents", "comparing"]).and_then(Value::as_array)
    {
        let refs: Vec<String> =
            docs.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
        match refs.as_slice() {
            [a, b] => (a.clone(), b.clone()),
            _ => {
                inexpressible(out, "compare needs exactly two documents".into());
                return;
            }
        }
    } else if let (Some(a), Some(b)) = (
        str_field(op, &["doc_a", "doc1", "a"]),
        str_field(op, &["doc_b", "doc2", "b"]),
    ) {
        (a.to_string(), b.to_string())
    } else {
        ("original".to_string(), "version".to_string())
    };
    let shared: Vec<Value> = field(op, &["shared", "result", "pairs", "shared_spans"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    // Resolve refs; fall back to the docids carried inside the shared items
    // (identity_through_rearrange_pivot's "rearranged"/"original_version").
    let docids_in_items: Vec<String> = shared
        .iter()
        .filter_map(Value::as_object)
        .flat_map(|o| o.values())
        .filter_map(|v| v.get("docid").and_then(Value::as_str).map(str::to_string))
        .collect();
    let resolve_side = |cx: &Cx, r: &str, idx: usize| -> Option<String> {
        cx.shadow
            .resolve_doc(r)
            .or_else(|| docids_in_items.get(idx).cloned().filter(|d| cx.shadow.knows(d)))
    };
    let (ga, gb) = match (resolve_side(cx, &ref_a, 0), resolve_side(cx, &ref_b, 1)) {
        (Some(a), Some(b)) => (a, b),
        // One side resolvable and the items carry no second docid: the
        // script compared the document WITH ITSELF (internal/
        // insert_only_baseline's source/dest pairs over one doc).
        (Some(a), None) | (None, Some(a)) if docids_in_items.iter().all(|d| d == &a) => {
            out.adaptations.push("compare:self".into());
            (a.clone(), a)
        }
        _ => {
            inexpressible(out, format!("compare documents `{ref_a}`/`{ref_b}` unresolvable"));
            return;
        }
    };
    if shared.is_empty() && field(op, &["shared", "result", "pairs"]).is_none() {
        // Count-only expectation (insert_only_baseline `shared_span_pairs`)
        // or nothing to compare.
        if field(op, &["shared_span_pairs"]).and_then(Value::as_u64).is_none() {
            out.status = Status::NotCompared;
            return;
        }
    }
    if run_compare_pair(cx, out, &ga, &gb, &ref_a, &ref_b, &shared).is_none() {
        return;
    }
    // shared_span_pairs count check rides on top when present and the span
    // list was absent.
    if let (Some(n), true) =
        (field(op, &["shared_span_pairs"]).and_then(Value::as_u64), shared.is_empty())
    {
        if out.status == Status::Disagreed && out.expected.as_deref() == Some("[]") {
            // Re-judge as a count comparison.
            let actual = out.actual.as_deref().unwrap_or("").matches('(').count();
            out.comparator = Some("count".into());
            if actual as u64 == n {
                out.status = Status::Agreed;
                out.expected = None;
                out.actual = None;
            } else {
                out.expected = Some(format!("{n} shared pairs"));
                out.actual = Some(format!("{actual} shared pairs"));
            }
        }
    }
}

// ── accounts ────────────────────────────────────────────────────────────────

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

// ── observation bundles & post-write probes ─────────────────────────────────

/// What kind of probe an op's extra fields represent — the key sets differ
/// because a WRITE op's `text`/`content` fields are its ARGUMENTS, never a
/// post-state expectation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// Observation bundle (initial_state, after_first_insert…): full
    /// harvest.
    Bundle,
    /// After a write (insert/delete/vcopy): only result/remaining-style
    /// keys are expectations.
    PostWrite,
    /// One interior-typing step entry: its own vspanset/contents fields.
    Step,
}

/// A state probe: compare whatever vspanset/contents data the op (or one
/// interior-typing step) carries against the doc's live state.
fn probe_state(cx: &mut Cx, op: &Value, out: &mut OpOutcome, grants: &Grants, doc: &str, kind: Probe) {
    let mut compared = false;
    let mut fails: Vec<(String, String)> = Vec::new();

    // Vspanset-shaped expectation.
    let harvested = match kind {
        Probe::Step => op
            .get("vspanset")
            .and_then(expect_spans_raw)
            .map(|(d, s)| ("vspanset".to_string(), d, s)),
        _ => harvest_spanset(op),
    };
    if let Some((_, docid, spans)) = harvested {
        let target =
            docid.and_then(|d| cx.shadow.resolve_doc(&d)).unwrap_or_else(|| doc.to_string());
        if let Some(d) = cx.skep_doc(&target) {
            match cx.rig.exec(Op::RetrieveDocVSpanSet { doc: d }) {
                Response::SpanSet { set, .. } => {
                    compared = true;
                    if let Err((e, a)) = compare_spansets(&spans, &set, grants.width_tolerance) {
                        if collapsed_subspace_shape(&spans) {
                            out.note = Some(COLLAPSED_SUBSPACE_ANALYSIS.to_string());
                        }
                        fails.push((format!("vspanset {e}"), a));
                    }
                }
                r => fails
                    .push(("vspanset".into(), rejection_code(&r).unwrap_or_else(|| "?".into()))),
            }
        }
    }

    // Contents expectation.
    let content_keys: &[&str] = match kind {
        Probe::Step => &["contents", "content"],
        Probe::PostWrite => &["remaining", "result", "expected_contents"],
        Probe::Bundle => &[
            "result", "before", "after", "content", "contents", "sample", "remaining", "empty",
            "expected_contents",
        ],
    };
    if let Some(strings) = field(op, content_keys).and_then(expect_strings) {
        // Address strings are never content-subspace bytes (a create-like
        // result); skip rather than fabricate a comparison.
        let addr_like =
            strings.iter().any(|s| s.contains('.') && parse_dotted(s).is_some());
        if !addr_like {
            match cx.read_content(doc) {
                Ok(items) => {
                    compared = true;
                    if let Err((e, a)) = compare_content(&strings, &items, cx.alpha) {
                        fails.push((format!("content {e}"), a));
                    }
                }
                Err(code) => fails.push(("content".into(), code)),
            }
        }
    }

    if !compared && fails.is_empty() {
        out.status = Status::NotCompared;
        return;
    }
    out.comparator = Some("state-probe".into());
    if fails.is_empty() {
        out.status = Status::Agreed;
    } else {
        out.status = Status::Disagreed;
        out.expected = Some(fails.iter().map(|f| f.0.clone()).collect::<Vec<_>>().join(" | "));
        out.actual = Some(fails.iter().map(|f| f.1.clone()).collect::<Vec<_>>().join(" | "));
    }
}

/// Observation-bundle ops (`initial_state`, `after_first_insert`,
/// `verify_empty`, …): pure probes over the doc in scope.
fn h_observe(cx: &mut Cx, op: &Value, out: &mut OpOutcome, grants: &Grants) {
    // docs-map bundles compare several documents.
    if op.get("docs").and_then(Value::as_object).is_some() {
        h_contents(cx, op, out, label_of(op));
        return;
    }
    if op.get("positions").and_then(Value::as_object).is_some() {
        h_contents(cx, op, out, label_of(op));
        return;
    }
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        inexpressible(out, "observation bundle with no document in scope".into());
        return;
    };
    probe_state(cx, op, out, grants, &doc, Probe::Bundle);
}
