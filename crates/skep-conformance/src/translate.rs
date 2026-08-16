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
//! * `slot-from-evidence-doc` — a bare follow whose recorded result names a
//!   document: the slot whose projection lands in that document is the one
//!   the script followed (the golden's own result disambiguates the end).
//! * `follow_as_projection` — follow_link renders through `Op::Project`
//!   (I→V into a document); skep's raw FOLLOWLINK returns permanent
//!   I-spans, which the goldens never speak.
//! * `i-coverage-search` — a search aimed at content the shadow knows was
//!   deleted (or at a doc whose current extent no longer covers the
//!   recorded region) is built from I-coverage captured at delete time —
//!   ruling 10: deleted content stays findable via I-history, never by
//!   loosening V-queries.
//! * `query-clamped-to-extent` — a recorded SEARCH region wider than the
//!   doc's live extent is intersected with it before imaging (udanax's
//!   sparse V tolerated fat query spans; the golden's RESULT is still
//!   compared untouched).
//! * `delete-span-from-post-state` / `delete-span-widened-boundary` — a
//!   text-located delete span corrected by the recorded post-delete content
//!   (diff pins exactly what udanax removed), or widened by the flanking
//!   space that convention shows the scripts deleted.
//! * `vcopy-dest-from-evidence` — a dest-less vcopy aimed at the doc whose
//!   later probe shows the copied bytes embedded, instead of the register.
//! * `endset-evidence` (extended) — also refines whole-extent doc-ref
//!   endsets from later follow results (vspec-shaped or content strings),
//!   so stored links carry the extents the scripts actually made.
//! * `golden-duplicate-result` — the golden's expected list names one
//!   address twice (a recording defect); compared as a set, the dedup
//!   tagged so the defect stays visible.
//! * `empty-as-absent` — an expected-empty position probe agreeing with a
//!   skep absence rejection (both encode "nothing there").
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
//! * `contents:both-subspaces` — a retrieve whose recorded result lists a
//!   link address alongside text read the link subspace too, as a second
//!   RetrieveV so a link-side absence localizes; the link addresses compare
//!   through α (the version scenarios' whole-document retrieves surfaced
//!   the copied link). The reply's shape follows the golden.
//! * `full-probe-targets-last-write` — a `full_text_*`/`full_content_*`
//!   probe reads the doc the last CONTENT write touched, never a follow
//!   landing and never the drifted register
//!   (subspace/insert_text_check_both_link_positions op7).
//! * `by-routes-explicit-side` — find_links `by: "target"` routes the
//!   explicit from-doc into the TO slot: the field named the doc searched
//!   FROM, `by` named the endset constrained
//!   (interactions/link_both_endpoints_transcluded op11).
//! * `delete-text-from-label` — a bare `delete_A` op's removed text comes
//!   from its label, post-state-diff first
//!   (iaddress_allocation/delete_does_not_affect_next_insert).
//! * `read-scoped-to-recorded-extent` — a whole-document retrieve read only
//!   as many content positions as the golden's reply carries, when the
//!   shadow (the recorded reality) holds more — the script's specset was
//!   narrower than the doc (createnewversion_text_vs_links reads 33 of 34).
//! * `retrieve-follow-landing` — a doc-less retrieve right after a follow
//!   whose recorded result names a vspec reads THOSE spans (links/
//!   follow_link op8 retrieves the link destination, not the register).
//! * `render-by-identity` — operator ruling 11: a followed endset renders
//!   bytes once per RECORDED I-span, in span order, from whichever live
//!   arrangement speaks for each portion — never once per projected
//!   occurrence (shared content used to render "DEF" as "DEFEFDEF").
//! * `endset-coverage-translated` — operator ruling 11: retrieve_endsets
//!   compares the golden's (docid, V-span) endsets mapped through Image to
//!   I-coverage against skep's recorded endset spans — coverage equality,
//!   not coordinate equality (udanax resolved into the query doc's V-space).
//! * `traverse-hops-from-world` — traversal hop links resolve from the
//!   harness's link registry (every created link's endsets), never by text
//!   re-search; `links_found` lists compare against a real FindLinksFtt.
//! * `insert-all:distributed` — an `insert_all` texts array fills one
//!   created document per text, in creation order.
//! * `insert-aim-from-recorded-vspanset` — a doc-less insert re-aims at the
//!   doc whose next recorded vspanset shows the width grew by this insert
//!   (insert_vspace_mapping: the register held the version snapshot).
//! * `insert-padded-to-recorded-vspanset:+N` — the recorded vspanset width
//!   is the authority for how much the script inserted; the field text is
//!   padded (with spaces) to match, never the comparison adjusted. DECLINED
//!   when links seated between the insert and the probe explain the surplus
//!   — that is udanax's version link carryover (see
//!   `VERSION_LINK_CARRYOVER_ANALYSIS`), and padding would fabricate a
//!   ghost content byte (createnewversion_text_vs_links' own retrieve
//!   delivers 33 text chars plus the link marker for its recorded 0.34).
//! * `vcopy-source-reaimed` — a from-description that grounded OUTSIDE its
//!   doc's live extent (the register pointing at the just-created empty
//!   destination) re-grounds against the content-holding docs excluding the
//!   destination; the recorded post-state confirms the span
//!   (internal/ispan_partial_overlap's "positions 3-7 (CDEFG)").
//! * `contents:per-doc-keyed` — `<docname>: [strings]` fields are the
//!   recorded per-document replies of one retrieve (ispan_partial_overlap's
//!   `source:/dest:` arrays; the `expected` string alongside is prose).
//! * `read-span-from-recorded-strings` — a per-doc-keyed reply that is a
//!   proper substring of the doc's shadow content locates in the SHADOW
//!   (golden-side data only) and that span is read from skep — the script's
//!   unrecorded specset reconstructed without consulting skep's answer.
//! * `delete-noop-from-post-state` — the recorded post-delete content
//!   equals the pre-delete content byte-for-byte: udanax removed nothing,
//!   so neither does the harness (delete_all_with_links' whole-doc remove).
//! * `endset-from-transcluded-region` — a create_link `on:` field naming
//!   transcluded content grounds the endset to the home document's
//!   foreign-origin (copied-in) regions, read from the live V→I image.
//! * `transcluded-region-search` — a find_links `via_transcluded_content`
//!   query searches exactly the scoped doc's foreign-origin regions.
//! * `vcopy-cover-from-comparisons` / `vcopy-embed-plan` /
//!   `vcopy-span-from-comparison` / `vcopy-prefix-from-comparison` —
//!   grounding-pre-pass reconstructions of append-shaped vcopys from the
//!   scenario's own probes and recorded comparison pairs (the round-4
//!   unrecorded-prefix cluster); surfaced in the groundings list and
//!   executed as expansion plans.
//!
//! ## Round-7 policies (the 34-scenario corpus extension)
//!
//! * `session-route:<label>` — the op carried a `session` field and executed
//!   under that label's account session (label→account bound by `account`
//!   ops; two labels on one account share its session).
//! * `session-label-implicit-bind` — an op used a session label no `account`
//!   op had bound; it bound to the then-current account.
//! * `connect:session` — green's `connect` opens a TCP session; skep
//!   sessions open at account binding, so the op executes nothing.
//! * `open-noop-vs-recorded-failure` — green REFUSED the open (bert
//!   enforcement / account gating, manifest A1/A2); skep has no open layer
//!   to refuse with, so the recorded failure is surfaced as a raw
//!   divergence, never absorbed into the open no-op.
//! * `joint-absence` — the golden recorded a failure against an object that
//!   was never created (green's OPEN validates nothing, A7); the reference
//!   has no α-image, so there is nothing to address on skep either — both
//!   systems refuse, compared as agreement via the expected-failure
//!   comparator (α's never-bound finding is deliberately not emitted: the
//!   absence IS the expected answer).
//! * `explicit-empty-endset` — a create_link `fromset`/`toset`/`threeset`
//!   recorded as an EMPTY list is passed to MakeLink empty (green accepts
//!   all three, A11); the default-endset conventions never substitute.
//! * `threeset-marker→registry` — a threeset span at the udanax type-marker
//!   local address `1.0.2.X` (client.py's LINK_TYPES encoding) denotes the
//!   registry type name (2.2 jump / 2.3 quote / 2.6 footnote / 2.6.2
//!   margin) — the same `type_registry` mapping the name-based path uses.
//! * `threeset-content-type` — a threeset carrying real content spans
//!   becomes the link's TYPE endset via α (green's content-span third
//!   endsets are first-class, A8).
//! * `set-empty:unconstrained` — an EMPTY `fromset`/`toset`/`threeset` on a
//!   find_links is the recording client's NOSPECS: no constraint on that
//!   slot (create_link's empty means empty; the query's empty means any).
//! * `compare-operands-explicit` — a compare op's two operands read from its
//!   own role-keyed vspec-dict fields (ms_version_race's `version_a1`/
//!   `original`), never from the original/version convention.
//! * `deep-vaddress-span` — a span dict at a NESTED local address ("1.1.1")
//!   is built as an arbitrary-depth tumbler span and asked of skep raw;
//!   M6's answer (empty, or a depth/absence rejection) is compared as
//!   recorded (boundary_deep_vaddress_reads).
//! * `raw wire request codes` are inexpressible by construction: skep's
//!   surface is typed `Op`s; unknown-code handling lives in the transport's
//!   `OpKind::Unparseable`, which a library harness cannot reach.

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
    VERSION_LINK_CARRYOVER_ANALYSIS,
};
use crate::fields::{
    self, client_side_failure, create_name_of, doc_from_label, expect_spans_raw, expect_strings,
    expected_failure, field, harvest_spanset, label_of, link_home_docid, locate, note_arrow,
    parse_python_spec, position_from_label, resolve_position, span_dict, str_field, vspec_dict,
    DocSpans, RawSpan,
};
use crate::ground::{
    arrow_results, cuts_of, delete_is_noop, distributed_insert_texts, distribution_targets,
    insert_aim_from_probe, insert_pad_width, insert_text, next_content_probe, resolve_delete_span,
    SetupStep,
};
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
    Connect,
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
            Verb::Connect => "connect",
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
    ("connect", Verb::Connect),
    // The new-corpus checkpoint op: vspanset+contents bundle, or a bare
    // failed probe of a never-created doc (error field only).
    ("probe", Verb::Observe),
];

/// Does the op carry observation data (a probe bundle)?
fn has_observation_fields(op: &Value) -> bool {
    let Some(o) = op.as_object() else { return false };
    for (k, v) in o {
        match k.as_str() {
            "vspanset" | "vspans" | "contents" | "content" | "positions" | "docs" | "targets" => {
                return true
            }
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
    // Keep any resolution note already attached (doc_arg's unresolvable-
    // reference detail) alongside the classification reason.
    out.note = Some(match out.note.take() {
        Some(n) => format!("{reason}; {n}"),
        None => reason,
    });
}

fn rejection_code(r: &Response) -> Option<String> {
    match r {
        Response::Rejected(rej) => Some(format!("{:?}", rej.code)),
        _ => None,
    }
}

/// Policy `joint-absence`: the golden recorded a FAILURE against a document
/// reference that was never created in this scenario (green's OPEN validates
/// nothing — A7 — so its scripts could aim ops at garbage docids and fail at
/// first use). The reference has no α-image, so there is nothing to address
/// on skep either: both systems refuse the object, compared as agreement.
/// Peek only — α's never-bound finding is deliberately not emitted, because
/// the absence IS the expected answer here, not a translation the harness
/// needed and missed. Returns `true` when the outcome was written.
fn joint_absence(cx: &Cx, out: &mut OpOutcome, xf: &Option<String>, docref: &str) -> bool {
    if xf.is_none() || cx.shadow.knows(docref) || cx.alpha.peek_translate(docref).is_some() {
        return false;
    }
    out.adaptations.push("joint-absence".into());
    out.status = Status::Agreed;
    out.comparator = Some("expected-failure".into());
    out.note = Some(format!(
        "golden recorded failure and `{docref}` was never created — no α-image, nothing to \
         address on skep; both systems refuse the object"
    ));
    true
}

fn vpos(sub: u64, ord: u64) -> VPos {
    VPos { subspace: Nat::from(sub), ordinal: Nat::from(ord) }
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
    /// current-document register — the register ONLY for genuinely bare ops
    /// (round-3 discipline): an explicit reference that resolves also aims
    /// the register (mirroring the recording scripts' scope), and one that
    /// does NOT resolve is surfaced instead of silently mis-aiming a probe
    /// at whatever the register held. Creates a first-touch document when
    /// the scenario has none yet (mirrored by the grounding pre-pass).
    fn doc_arg(&mut self, op: &Value, out: &mut OpOutcome, keys: &[&str]) -> Option<String> {
        if let Some(s) = str_field(op, keys) {
            if let Some(d) = self.shadow.resolve_doc(s) {
                self.shadow.set_current(&d);
                return Some(d);
            }
            out.note = Some(format!("document reference `{s}` resolves to nothing"));
            return None;
        }
        if let Some(name) = doc_from_label(label_of(op)) {
            if let Some(d) = self.shadow.resolve_doc(&name) {
                out.adaptations.push("doc-from-label".into());
                self.shadow.set_current(&d);
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
            SetupStep::Link { from, to, golden } => {
                let sides = |cx: &mut Cx, list: &[(String, u64, u64)]| -> Result<Vec<VSpec>, String> {
                    let mut specs = Vec::new();
                    for (doc, ord, w) in list {
                        let sd = cx
                            .skep_doc(doc)
                            .ok_or_else(|| format!("setup link: {doc} unbound"))?;
                        let span = vspan(1, *ord, *w)
                            .ok_or_else(|| "setup link: empty span".to_string())?;
                        specs.push(VSpec { source: sd, span });
                    }
                    Ok(specs)
                };
                let f = sides(self, from)?;
                let t = sides(self, to)?;
                let home_golden = golden
                    .as_ref()
                    .and_then(|g| link_home_docid(g))
                    .or_else(|| from.first().map(|(d, _, _)| d.clone()))
                    .ok_or_else(|| "setup link: no home".to_string())?;
                let home = self
                    .skep_doc(&home_golden)
                    .ok_or_else(|| format!("setup link: home {home_golden} unbound"))?;
                // The scripts' default type (policy default_type_jump).
                let ty = self
                    .rig
                    .type_vspec("jump")
                    .ok_or_else(|| "setup link: type registry exhausted".to_string())?;
                match self.rig.exec(Op::MakeLink { home, from: f, to: t, ty: vec![ty] }) {
                    Response::AckAddr { addr, .. } => {
                        self.shadow.seat_link(&home_golden);
                        self.shadow.set_current(&home_golden);
                        if let Some(g) = golden {
                            self.alpha.bind(g, &addr);
                            self.shadow.last_link = Some(g.clone());
                            self.shadow.record_link(g, from.clone(), to.clone());
                        }
                        Ok(())
                    }
                    r => Err(format!(
                        "setup link in {home_golden}: {}",
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

    /// V→I image of a set of golden QUERY spans in one doc (the sanctioned
    /// V→I surface for building query endsets). Content-subspace spans are
    /// clamped to the doc's live extent first — udanax's sparse V tolerated
    /// recorded search spans wider than the content
    /// (find_links_homedocids_multiple queries width 25 over a 20-char doc)
    /// while skep's dense Image rejects them; clamping the QUERY (never a
    /// compared result) is policy `query-clamped-to-extent`, reported via
    /// the returned flag.
    fn image_endset(
        &mut self,
        docid: &str,
        spans: &[(u64, u64, u64)],
    ) -> (Endset, Vec<String>, bool) {
        let mut notes = Vec::new();
        let mut clamped = false;
        let Some(d) = self.alpha.translate(docid) else {
            notes.push(format!("{docid}: unresolvable"));
            return (Endset::from_spans(std::iter::empty()), notes, clamped);
        };
        let text_len = self.shadow.text_len(docid);
        let region: Vec<skep_address::Span> = spans
            .iter()
            .filter_map(|(s, o, w)| {
                if *w == 0 {
                    return None;
                }
                let (o, w) = if *s == 1 {
                    if *o > text_len {
                        clamped = true;
                        return None;
                    }
                    let end = (*o + *w - 1).min(text_len);
                    if end < *o + *w - 1 {
                        clamped = true;
                    }
                    (*o, end + 1 - *o)
                } else {
                    (*o, *w)
                };
                vspan(*s, o, w)
            })
            .collect();
        if region.is_empty() {
            return (Endset::from_spans(std::iter::empty()), notes, clamped);
        }
        match self.rig.exec(Op::Image { d, region }) {
            Response::Runs { runs, .. } => {
                (Endset::from_spans(runs.iter().map(Run::iextent)), notes, clamped)
            }
            r => {
                notes.push(format!(
                    "{docid}: image {}",
                    rejection_code(&r).unwrap_or_else(|| "?".into())
                ));
                (Endset::from_spans(std::iter::empty()), notes, clamped)
            }
        }
    }

    /// The whole-content V→I image of one golden doc as
    /// (I-prefix, I-ordinal, width, V-start) rows, V order — the raw
    /// material for identity rendering and transcluded-region detection.
    fn image_rows(&mut self, docid: &str) -> Vec<(String, u64, u64, u64)> {
        let n = self.shadow.text_len(docid);
        let (Some(d), Some(span)) = (self.alpha.peek(docid), vspan(1, 1, n)) else {
            return Vec::new();
        };
        let Response::Runs { runs, .. } = self.rig.exec(Op::Image { d, region: vec![span] })
        else {
            return Vec::new();
        };
        let mut rows = Vec::new();
        let mut v = 1u64;
        for run in &runs {
            let w: u64 = run.width().to_string().parse().unwrap_or(0);
            if let Some((p, lo, rw)) = elem_range(&run.iextent()) {
                rows.push((p, lo, rw, v));
            }
            v += w;
        }
        rows
    }

    /// The scoped doc's foreign-origin (transcluded) content regions, as
    /// golden (ordinal, width) V-ranges — a run whose I-prefix does not lie
    /// under the doc's own skep address arrived by COPY.
    fn transcluded_regions_golden(&mut self, docid: &str) -> Vec<(u64, u64)> {
        let Some(own) = self.alpha.peek(docid) else { return Vec::new() };
        let own_prefix = crate::tum::addr_str(&own);
        self.image_rows(docid)
            .into_iter()
            .filter(|(p, _, _, _)| {
                !(p.starts_with(&format!("{own_prefix}.")) || p == &own_prefix)
            })
            .map(|(_, _, w, v)| (v, w))
            .collect()
    }

    /// Ruling 11's follow rendering (policy `render-by-identity`): the
    /// RECORDED endset from `Op::FollowLink`, rendered as bytes ONCE per
    /// I-span in span order — each portion read from the first live
    /// arrangement (creation order) that still speaks for it. Portions no
    /// arrangement holds render nothing (udanax's orphan follows recorded
    /// empty; live-only keeps that agreement) and are counted in the note.
    fn render_recorded_endset(
        &mut self,
        link: &skep_address::Address,
        slot: usize,
    ) -> Result<(String, Vec<String>), String> {
        let set = match self.rig.exec(Op::FollowLink { a: link.clone(), slot }) {
            Response::Follow { result: Ok(set), .. } => set,
            Response::Follow { result: Err(_), .. } => {
                return Ok((String::new(), vec!["followlink: invalid slot".into()]))
            }
            r => return Err(rejection_code(&r).unwrap_or_else(|| "unexpected response".into())),
        };
        // Index every doc's live V→I rows once.
        let docs = self.shadow.all_docs();
        let mut world: Vec<(String, Vec<(String, u64, u64, u64)>)> = Vec::new();
        for docid in &docs {
            if self.shadow.text_len(docid) == 0 {
                continue;
            }
            let rows = self.image_rows(docid);
            if !rows.is_empty() {
                world.push((docid.clone(), rows));
            }
        }
        let mut notes = Vec::new();
        let mut rendered_bytes: Vec<u8> = Vec::new();
        let mut missing = 0u64;
        for isp in set.iter() {
            let Some((p, lo, w)) = elem_range(isp) else {
                notes.push("non-element endset span skipped".into());
                continue;
            };
            let mut buf: Vec<Option<u8>> = vec![None; w as usize];
            for (docid, rows) in &world {
                if buf.iter().all(Option::is_some) {
                    break;
                }
                let Some(d) = self.alpha.peek(docid) else { continue };
                for (rp, rlo, rw, v) in rows {
                    if rp != &p {
                        continue;
                    }
                    let a = (*rlo).max(lo);
                    let b = (rlo + rw).min(lo + w);
                    if a >= b {
                        continue;
                    }
                    let off = (a - lo) as usize;
                    let len = (b - a) as usize;
                    if buf[off..off + len].iter().all(Option::is_some) {
                        continue;
                    }
                    let Some(span) = vspan(1, v + (a - rlo), b - a) else { continue };
                    let items = match self
                        .rig
                        .exec(Op::RetrieveV { specs: vec![Spec { doc: d.clone(), span }] })
                    {
                        Response::Delivery { items, .. } => items.0,
                        r => {
                            notes.push(format!(
                                "{docid}: retrieve {}",
                                rejection_code(&r).unwrap_or_else(|| "?".into())
                            ));
                            continue;
                        }
                    };
                    let mut k = off;
                    for it in items {
                        if k >= off + len {
                            break;
                        }
                        if let DeliveryItem::Content(val) = it {
                            for byte in val.as_bytes() {
                                if k >= off + len {
                                    break;
                                }
                                if buf[k].is_none() {
                                    buf[k] = Some(*byte);
                                }
                                k += 1;
                            }
                        } else {
                            k += 1; // a link ref is never endset text
                        }
                    }
                }
            }
            for slot_byte in &buf {
                match slot_byte {
                    Some(b) => rendered_bytes.push(*b),
                    None => missing += 1,
                }
            }
        }
        if missing > 0 {
            notes.push(format!(
                "{missing} recorded endset element(s) have no live arrangement (deleted \
                 everywhere); rendered without them"
            ));
        }
        Ok((String::from_utf8_lossy(&rendered_bytes).into_owned(), notes))
    }
}

/// A contiguous element-level span as (prefix components, first ordinal,
/// width) — sound exactly for the single-I-extent shape `Run::iextent` and
/// recorded content endset spans carry. `None` for coarser spans.
fn elem_range(s: &skep_address::Span) -> Option<(String, u64, u64)> {
    let w = crate::tum::span_elem_width(s)?;
    let st = s.start();
    let n = st.len();
    if n < 2 {
        return None;
    }
    let last: u64 = st.get(n).to_string().parse().ok()?;
    let prefix: Vec<String> = (1..n).map(|i| st.get(i).to_string()).collect();
    Some((prefix.join("."), last, w))
}

// ────────────────────────────── the catalogue ──────────────────────────────

/// Translate, execute, and compare one golden operation. Exactly one
/// `OpOutcome` per op, whatever happens.
pub fn run_op(cx: &mut Cx, index: usize, op: &Value, grants: &Grants) -> OpOutcome {
    let label = label_of(op).to_string();
    let mut out = OpOutcome::new(index, &label);
    if label.is_empty() {
        // A recorder ANNOTATION entry ({note: "…"} with no op at all,
        // ms_create_race) is commentary, not an operation — meta. Anything
        // else without a label stays inexpressible.
        let annotation_only = op.as_object().is_some_and(|o| {
            !o.is_empty()
                && o.keys().all(|k| matches!(k.as_str(), "note" | "comment" | "description"))
        });
        if annotation_only {
            out.verb = Verb::Meta.name().to_string();
            out.status = Status::Meta;
            out.note = str_field(op, &["note", "comment", "description"]).map(str::to_string);
            return out;
        }
        inexpressible(&mut out, "operation has no `op` label".into());
        return out;
    }
    // Raw wire request codes (prov_request_surface): green's dispatch-table
    // probe. skep's surface is typed `Op`s — an unknown code is the
    // TRANSPORT's `OpKind::Unparseable`, unreachable from the library
    // harness — so the op is inexpressible by construction, code recorded.
    if label == "raw_request" {
        let code = field(op, &["code"]).and_then(Value::as_u64);
        inexpressible(
            &mut out,
            format!(
                "raw wire request code {} has no counterpart on skep's typed Op surface \
                 (unknown-code handling is the transport's OpKind::Unparseable)",
                code.map(|c| c.to_string()).unwrap_or_else(|| "?".into())
            ),
        );
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
    // Multi-session routing: an op carrying a `session` label executes under
    // that label's account session (policy `session-route`). `account` binds
    // labels itself and `connect`/meta execute nothing, so they skip routing;
    // ops without the field leave the working session untouched, so
    // single-session scenarios are undisturbed.
    if !matches!(verb, Verb::Account | Verb::Connect | Verb::Meta) {
        if let Some(sess) = str_field(op, &["session"]) {
            match cx.rig.route_session(sess) {
                Ok(implicit) => {
                    out.adaptations.push(format!("session-route:{sess}"));
                    if implicit {
                        out.adaptations.push("session-label-implicit-bind".into());
                    }
                }
                Err(e) => {
                    out.status = Status::Disagreed;
                    out.comparator = Some("session".into());
                    out.expected = Some(format!("op executes under session {sess}"));
                    out.actual = Some(e);
                    return out;
                }
            }
        }
    }
    match verb {
        Verb::Meta => out.status = Status::Meta,
        Verb::Observe => h_observe(cx, index, op, &mut out, grants),
        Verb::Setup => h_setup(cx, index, &mut out),
        Verb::CreateDocument => h_create_document(cx, op, &mut out),
        Verb::CreateDocuments => h_create_documents(cx, index, op, &mut out),
        Verb::CreateChain => h_create_chain(cx, index, op, &mut out),
        Verb::OpenDocument => h_open_document(cx, op, &mut out),
        Verb::CloseDocument => {
            out.adaptations.push("close_document:noop".into());
            out.status = Status::NotCompared;
        }
        Verb::Insert => h_insert(cx, index, op, &mut out, grants),
        Verb::InsertLoop => h_insert_loop(cx, op, &mut out, grants),
        Verb::InteriorTyping => h_interior_typing(cx, op, &mut out, grants),
        Verb::Delete => h_delete(cx, index, op, &mut out, grants, false),
        Verb::DeleteAll => h_delete(cx, index, op, &mut out, grants, true),
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
        Verb::Contents => h_contents(cx, index, op, &mut out, &label),
        Verb::Vspan => h_vspanset(cx, op, &mut out, grants, false),
        Verb::Vspanset => h_vspanset(cx, op, &mut out, grants, true),
        Verb::Endsets => h_endsets(cx, op, &mut out),
        Verb::Compare => h_compare(cx, op, &mut out),
        Verb::Account => h_account(cx, op, &mut out),
        Verb::CreateNode => h_create_node(cx, op, &mut out),
        Verb::Connect => {
            // Green's `connect` opens a TCP session; skep sessions open when
            // an `account` op binds the label — nothing to execute here.
            out.adaptations.push("connect:session".into());
            out.status = Status::NotCompared;
        }
    }
    out
}

// ── creation ────────────────────────────────────────────────────────────────

fn h_create_document(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    let name = create_name_of(op);
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

fn h_create_documents(cx: &mut Cx, index: usize, op: &Value, out: &mut OpOutcome) {
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
    // Role-keyed fields: doc1/doc2, source1/source2, targetN — any
    // `<role><n>` key holding a dotted docid (identity_mixed_sources).
    let mut keyed: Vec<(String, String)> = op
        .as_object()
        .map(|o| {
            o.iter()
                .filter(|(k, _)| crate::ground::keyed_role(k))
                .filter_map(|(k, v)| {
                    let id = v.as_str()?;
                    parse_dotted(id)?;
                    Some((k.clone(), id.to_string()))
                })
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
    let group = crate::ground::group_word(op);
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
        if let Some(g) = &group {
            let singular = g.trim_end_matches('s');
            cx.shadow.bind_name(&format!("{singular}{}", k + 1), &id);
            cx.shadow.bind_name(&format!("{singular}_{k}"), &id);
        }
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
    // World-construction plans (create_multiple_targets): the pre-pass
    // covered each created-empty doc's probed content with real copies.
    if cx.plans.contains_key(&index) {
        run_plan(cx, index, out);
        if out.status == Status::Disagreed {
            return;
        }
        out.status = Status::NotCompared;
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
        if let SetupStep::Copy { doc, .. } | SetupStep::Insert { doc, .. } = step {
            if !cx.shadow.knows(doc) {
                create_one(cx, out, doc, None);
            }
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
    // Green REFUSED this open (bert enforcement / account gating — manifest
    // A1/A2, recorded only in the multisession/boundary corpus); skep has no
    // open layer to refuse with. The divergence is real and surfaces raw
    // (policy `open-noop-vs-recorded-failure`) — never absorbed into the
    // no-op.
    if let Some(err) = expected_failure(op) {
        out.adaptations.push("open-noop-vs-recorded-failure".into());
        out.status = Status::Disagreed;
        out.comparator = Some("expected-failure".into());
        out.expected = Some(format!("failure: {err:?}"));
        out.actual =
            Some("skep has no bert/open layer (access control descoped); nothing rejected".into());
        return;
    }
    // The open result names the same document — bind the alias so both
    // spellings translate. Peek, not translate: green's OPEN validates
    // nothing (A7), so an open of a never-created doc succeeds there and has
    // no α-image here — that absence is noted, not an α-finding (the later
    // probe's recorded failure meets it as joint absence).
    if let Some(g) = &result {
        match cx.alpha.peek_translate(&doc) {
            Some(a) => cx.alpha.bind(g, &a),
            None => {
                out.note = Some(format!(
                    "open of `{doc}` (never created; green's OPEN validates nothing) — \
                     result not bindable"
                ));
            }
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
    let xf = expected_failure(op);
    if joint_absence(cx, out, &xf, &src) {
        return; // green failed versioning a never-created doc (boundary A7)
    }
    let Some(d_src) = cx.skep_doc(&src) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some(format!("version of unresolvable doc {src}"));
        return;
    };
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

fn h_insert(cx: &mut Cx, index: usize, op: &Value, out: &mut OpOutcome, grants: &Grants) {
    // insert_all + texts: one text per created doc, creation order (policy
    // `insert-all:distributed`; mirrors the grounding pre-pass exactly).
    if let Some(texts) = distributed_insert_texts(op) {
        out.adaptations.push("insert-all:distributed".into());
        let docs = distribution_targets(cx.shadow, texts.len());
        for (docid, t) in docs.iter().zip(&texts) {
            let Some(d) = cx.skep_doc(docid) else {
                out.status = Status::Disagreed;
                out.comparator = Some("alpha".into());
                out.note = Some(format!("insert_all target {docid} unresolvable"));
                return;
            };
            let at = cx.shadow.text_len(docid) + 1;
            let values: Vec<Val> = t.bytes().map(|b| Val::new(vec![b])).collect();
            let r = cx.rig.exec(Op::Insert { doc: d, at: vpos(1, at), values });
            cx.shadow.insert(docid, at, t.as_bytes());
            if let Some(code) = rejection_code(&r) {
                out.status = Status::Disagreed;
                out.comparator = Some("rejection".into());
                out.expected = Some(format!("insert_all into {docid} succeeds"));
                out.actual = Some(format!("Rejected({code})"));
                return;
            }
        }
        out.status = Status::NotCompared;
        return;
    }
    let Some(mut doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        inexpressible(out, "insert with no document in scope".into());
        return;
    };
    let Some(mut text) = insert_text(op) else {
        inexpressible(out, "insert without text".into());
        return;
    };
    if str_field(op, &["text"]).is_none() && label_of(op).starts_with("insert_") {
        out.adaptations.push("args-from-label".into());
    }
    // Doc-less insert re-aim from the next recorded vspanset probe (policy
    // `insert-aim-from-recorded-vspanset`; mirrors the grounding pre-pass).
    if str_field(op, &["doc", "docid"]).is_none() && doc_from_label(label_of(op)).is_none() {
        if let Some(d2) = insert_aim_from_probe(cx.ops, index, cx.shadow, &doc, &text) {
            out.adaptations.push("insert-aim-from-recorded-vspanset".into());
            cx.shadow.set_current(&d2);
            doc = d2;
        }
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
            // position; those and bare inserts append — unless the op's own
            // recorded post-state shows the text embedded mid-document,
            // which pins the position exactly (policy
            // `insert-position-from-post-state`; interleaved_insert_delete's
            // insert_2 "BBB" turns "AA" into "ABBBA").
            match crate::ground::insert_pos_from_post_state(op, cx.shadow, &doc, &text) {
                Some(o) => {
                    out.adaptations.push("insert-position-from-post-state".into());
                    (1, o)
                }
                None => {
                    out.adaptations.push("position-end".into());
                    (1, cx.shadow.text_len(&doc) + 1)
                }
            }
        }
    };
    // Recorded-vspanset width authority (policy `insert-padded-to-recorded-
    // vspanset`; mirrors the grounding pre-pass byte-for-byte).
    if sub == 1
        && (str_field(op, &["address", "at", "position", "vaddr"]).is_none()
            || cx.shadow.text_len(&doc) == 0)
    {
        let new_len = cx.shadow.text_len(&doc) + text.len() as u64;
        if let Some(pad) = insert_pad_width(cx.ops, index, cx.shadow, &doc, new_len) {
            out.adaptations.push(format!("insert-padded-to-recorded-vspanset:+{pad}"));
            text.push_str(&" ".repeat(pad as usize));
        }
    }
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

fn h_delete(cx: &mut Cx, index: usize, op: &Value, out: &mut OpOutcome, grants: &Grants, all: bool) {
    let Some(doc) = cx.doc_arg(op, out, &["doc", "docid"]) else {
        inexpressible(out, "delete with no document in scope".into());
        return;
    };
    // Policy `delete-noop-from-post-state`: the recorded post-delete content
    // equals the pre-delete content — udanax removed nothing (client-crash
    // family), so the harness executes nothing and later probes compare
    // against the intact document honestly.
    if delete_is_noop(cx.shadow, cx.ops, index, &doc) {
        out.adaptations.push("delete-noop-from-post-state".into());
        out.status = Status::NotCompared;
        let mut note = String::from(
            "recorded post-delete content equals pre-delete content; udanax removed nothing \
             from the content subspace",
        );
        // Adjudication analysis (round-5 item 8, delete_all_with_links):
        // when the SAME recording later reports the doc's links unfindable
        // (find_links count 0 / empty) while its content probe still reads
        // the full text, udanax's whole-document remove split the
        // subspaces — content intact, link-subspace occupancy removed.
        // Skep cannot reproduce that split without violating the ruled
        // subspace-confinement invariant (udanax-no-subspace-confinement,
        // adjudication/decisions.md ruling 2), so the harness keeps the
        // content no-op and leaves the later link-findability divergence
        // raw for adjudication.
        let links_vanish = cx.shadow.link_count(&doc) > 0
            && cx.ops[index + 1..].iter().any(|later| {
                let l = label_of(later).to_ascii_lowercase();
                if !(l.starts_with("find_links") || l.starts_with("links")) {
                    return false;
                }
                ["result", "links", "expected", "before_delete", "after_delete", "before",
                 "after"]
                .iter()
                .any(|k| {
                    let Some(v) = later.get(*k) else { return false };
                    v.as_array().is_some_and(|a| a.is_empty())
                        || v.get("count").and_then(Value::as_u64) == Some(0)
                })
            });
        if links_vanish {
            note.push_str(
                "; ANALYSIS: this recording's later find_links expects the home link \
                 unfindable (count 0) while the content probe still reads the full text — \
                 udanax's remove deleted link-subspace occupancy only; skep cannot reproduce \
                 the split without violating the ruled subspace-confinement invariant \
                 (decisions.md ruling 2), so the link-findability divergence downstream is \
                 left raw for adjudication",
            );
        }
        out.note = Some(note);
        return;
    }
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
    } else if let Some((ord, w, how)) = resolve_delete_span(cx.shadow, cx.ops, index, &doc, op) {
        if how != "explicit" {
            out.adaptations.push(how.into());
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
    // I-coverage capture (ruling 10): image the doomed content region while
    // the arrangement still speaks for it, so later searches can reach it
    // through I-history.
    if sub == 1 {
        let bytes = cx.shadow.slice(&doc, ord, width);
        cx.rig.capture_deletion(&doc, &d, ord, bytes);
    }
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

    // Source spec(s): explicit vspec dicts, span dicts, located texts. The
    // corpus extension records a SINGLE vspec dict (`source: {docid, span}`,
    // fanout/depth recordings) — normalized to a one-item list here.
    let mut specs: Vec<VSpec> = Vec::new();
    let mut copied: Vec<u8> = Vec::new();
    let mut src_doc: Option<String> = None;
    let spec_items: Option<Vec<&Value>> =
        match field(op, &["specs", "specset", "source", "sources"]) {
            Some(Value::Array(a)) => Some(a.iter().collect()),
            Some(v @ Value::Object(_)) if vspec_dict(v).is_some() => Some(vec![v]),
            _ => None,
        };
    if let Some(arr) = spec_items {
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
    } else if let Some(s) = str_field(op, &["from", "source"]) {
        if let Some(from) = cx.shadow.resolve_doc(s) {
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
        } else if let Some(l) = locate(cx.shadow, None, s) {
            // A described region, not a doc ("positions 1-4 (Orig)" —
            // edgecases/vcopy_to_same_document). A grounding that lands
            // OUTSIDE its doc's live extent grounded against the wrong doc —
            // typically the register pointing at the just-created empty
            // destination — and the script's copy can only have read a doc
            // that holds the span: re-ground against the content-holding
            // docs excluding the dest reference (policy
            // `vcopy-source-reaimed`; internal/ispan_partial_overlap's
            // `from: "positions 3-7 (CDEFG)"` with `to: "dest"`, confirmed
            // by the recorded post-state "CDEFG in both"). No valid re-aim
            // keeps the original grounding and its loud divergence.
            let l = if l.ord + l.width > cx.shadow.text_len(&l.doc) + 1 {
                let dest_ref = str_field(op, &["to", "dest", "target", "target_doc"])
                    .filter(|t| !crate::ground::is_position_marker(t))
                    .and_then(|t| cx.shadow.resolve_doc(t))
                    .unwrap_or_default();
                match cx.shadow.content_docs_except(&dest_ref).iter().find_map(|d| {
                    locate(cx.shadow, Some(d.as_str()), s)
                        .filter(|c| c.ord + c.width <= cx.shadow.text_len(&c.doc) + 1)
                }) {
                    Some(re) => {
                        out.adaptations.push("vcopy-source-reaimed".into());
                        re
                    }
                    None => l,
                }
            } else {
                l
            };
            if !vcopy_push_located(cx, out, l, &mut specs, &mut copied, &mut src_doc) {
                return;
            }
        } else {
            inexpressible(out, format!("vcopy from {s:?}: neither a doc nor a groundable region"));
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
    // A dest-less vcopy aims at the doc whose later probe shows the copied
    // bytes embedded (endsets/endsets_transcluded_source: the script's
    // second doc, which the register never pointed at), preferring a doc
    // other than the source; the register serves only evidence-less ops.
    let to_raw = str_field(op, &["to", "dest", "target", "target_doc"]);
    let dest: Option<String> = match to_raw {
        // "end"/"start"/"end of doc" are position markers over the source
        // doc itself (vcopy_to_same_document's self-transclusion).
        Some(s) if crate::ground::is_position_marker(s) => src_doc.clone(),
        Some(s) => cx.shadow.resolve_doc(s),
        None => str_field(op, &["doc", "docid"])
            .and_then(|s| cx.shadow.resolve_doc(s))
            .or_else(|| {
                let copied_s = String::from_utf8_lossy(&copied).into_owned();
                let evidenced: Vec<String> = cx
                    .shadow
                    .all_docs()
                    .into_iter()
                    .filter(|d| {
                        next_content_probe(cx.ops, index, d, cx.shadow)
                            .is_some_and(|p| p.contains(&copied_s))
                    })
                    .collect();
                let pick = evidenced
                    .iter()
                    .find(|d| Some(d.as_str()) != src_doc.as_deref())
                    .or_else(|| evidenced.first())
                    .cloned();
                if pick.is_some() {
                    out.adaptations.push("vcopy-dest-from-evidence".into());
                }
                pick
            })
            .or_else(|| cx.doc_arg(op, out, &["doc", "docid"])),
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
            if to_raw.is_some_and(|s| s.trim().to_ascii_lowercase().starts_with("start")) {
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
                        if let Some(sides) = e.get(*k).and_then(&ground) {
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
                    if let Some(sides) = field(op, &["result"]).and_then(&ground) {
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

/// One recorded endset span: a normal (subspace, ordinal, width) span, or
/// the udanax type-marker local address `1.0.2.X…` (client.py's LINK_TYPES
/// encoding — 4-plus components that are not a V-position).
enum SetSpan {
    Plain(u64, u64, u64),
    Marker(Vec<u64>),
}

/// Parse a `fromset`/`toset`/`threeset` list: vspec dicts whose spans may be
/// plain or marker-form. Errors carry the offending shape for the
/// inexpressible reason.
fn parse_set_spans(v: &Value) -> Result<Vec<(String, Vec<SetSpan>)>, String> {
    let Some(arr) = v.as_array() else {
        return Err("set field is not a list".into());
    };
    let mut sides = Vec::new();
    for item in arr {
        let Some(o) = item.as_object() else {
            return Err("set entry is not a vspec dict".into());
        };
        let Some(docid) = o.get("docid").and_then(Value::as_str) else {
            return Err("set entry has no docid".into());
        };
        let span_values: Vec<&Value> = match (o.get("spans").and_then(Value::as_array), o.get("span"))
        {
            (Some(list), _) => list.iter().collect(),
            (None, Some(sp)) => vec![sp],
            (None, None) => return Err(format!("set entry for {docid} has no spans")),
        };
        let mut spans = Vec::new();
        for sp in span_values {
            if let Some((s, ord, w)) = span_dict(sp) {
                spans.push(SetSpan::Plain(s, ord, w));
                continue;
            }
            let start = sp
                .get("start")
                .and_then(Value::as_str)
                .and_then(parse_dotted)
                .ok_or_else(|| format!("set span in {docid} has an unparseable start"))?;
            spans.push(SetSpan::Marker(start));
        }
        sides.push((docid.to_string(), spans));
    }
    Ok(sides)
}

/// client.py's LINK_TYPES local addresses (version.0.link_subspace.type):
/// 2.2 jump, 2.3 quote, 2.6 footnote, 2.6.2 margin. The docid the recordings
/// attach carries no information — LINK_TYPES_DOC is the constant first doc.
fn marker_type_name(comps: &[u64]) -> Option<&'static str> {
    match comps {
        [1, 0, 2, 2] => Some("jump"),
        [1, 0, 2, 3] => Some("quote"),
        [1, 0, 2, 6] => Some("footnote"),
        [1, 0, 2, 6, 2] => Some("margin"),
        _ => None,
    }
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
    let from_triples = op.get("fromset").map(&triples).unwrap_or_default();
    let to_triples = op.get("toset").map(&triples).unwrap_or_default();

    match cx.rig.exec(Op::MakeLink { home, from, to, ty }) {
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

fn h_create_link(cx: &mut Cx, index: usize, op: &Value, out: &mut OpOutcome) {
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
        let r = cx.rig.exec(Op::MakeLink { home, from, to, ty: vec![ty] });
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

/// Resolve a link-slot name to M7's positional index (FROM=1, TO=2, TYPE=3).
/// "three" is the new corpus's name for the third endset (`end: "three"`).
fn slot_of(name: &str) -> Option<usize> {
    if name.contains("source") || name == "from" {
        return Some(1);
    }
    if name.contains("target") || name == "to" {
        return Some(2);
    }
    if name.contains("type") || name.contains("three") {
        return Some(3);
    }
    None
}

fn h_follow_link(cx: &mut Cx, op: &Value, out: &mut OpOutcome, grants: &Grants) {
    out.adaptations.push("follow_as_projection".into());
    let label = label_of(op);
    let explicit_slot = str_field(op, &["end", "direction", "linkend", "which"])
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
        });
    let (mut slot, defaulted) = match explicit_slot {
        Some(s) => (s, false),
        None => {
            // Bare follow records the SOURCE end (pinned by isolation/
            // insert_text_does_not_affect_links_in_same_document, whose
            // recorded before/after results are the source spans).
            out.adaptations.push("default-slot:source".into());
            (1, true)
        }
    };
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
        // No recorded result but a recorded FAILURE (nary_empty_endset_shapes:
        // green's `?` following an empty or marker-typed end): ask skep to
        // follow the slot and reconcile. An empty/invalid answer is the same
        // observable — nothing followable — as green's refusal; delivered
        // spans are a divergence.
        if let Some(err) = expected_failure(op) {
            match cx.rig.exec(Op::FollowLink { a: link.clone(), slot }) {
                Response::Follow { result: Err(_), .. } => {
                    out.status = Status::Agreed;
                    out.comparator = Some("expected-failure".into());
                    out.note = Some("both sides refuse the slot (skep: invalid slot)".into());
                }
                Response::Follow { result: Ok(set), .. } => {
                    // Types-doc spans are harness infrastructure (policy
                    // `type_registry`) — a marker-typed link's slot 3 holds
                    // only the registry position, which the golden cannot
                    // speak; excluded before judging.
                    let real = set
                        .iter()
                        .filter(|sp| {
                            skep_address::validate(sp.start().clone())
                                .map(|a| !cx.rig.is_types_addr(&a))
                                .unwrap_or(true)
                        })
                        .count();
                    if real == 0 {
                        out.adaptations.push("type_registry".into());
                        out.status = Status::Agreed;
                        out.comparator = Some("expected-failure".into());
                        out.note = Some(
                            "both sides surface nothing followable (green: ?, skep: empty or \
                             registry-only endset)"
                                .into(),
                        );
                    } else {
                        out.status = Status::Disagreed;
                        out.comparator = Some("expected-failure".into());
                        out.expected = Some(format!("failure: {err:?}"));
                        out.actual =
                            Some(format!("skep followed the slot to {real} span(s)"));
                    }
                }
                other => {
                    out.status = Status::Agreed;
                    out.comparator = Some("expected-failure".into());
                    out.note = Some(format!(
                        "both sides failed (skep: {})",
                        rejection_code(&other).unwrap_or_else(|| "?".into())
                    ));
                }
            }
            return;
        }
        out.status = Status::NotCompared;
        out.note = Some("follow_link with nothing recorded to compare".into());
        return;
    };
    // A defaulted slot yields to the recorded result's own document: the
    // slot whose projection lands in it is the end the script followed
    // (subspace/insert_text_check_both_link_positions's bare follow records
    // the TARGET vspec).
    if defaulted {
        if let Some((Some(docid), spans)) = expect_spans_raw(expected) {
            if !spans.is_empty() {
                if let Some(d) = cx.alpha.peek_translate(&docid) {
                    let nonempty = |cx: &mut Cx, s: usize| -> bool {
                        matches!(
                            cx.rig.exec(Op::Project { a: link.clone(), slot: s, d: d.clone() }),
                            Response::SpanSet { set, .. } if set.iter().next().is_some()
                        )
                    };
                    if !nonempty(cx, 1) && nonempty(cx, 2) {
                        slot = 2;
                        out.adaptations.push("slot-from-evidence-doc".into());
                    }
                }
            }
        }
    }
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
    // Shape 3: strings (endset CONTENT) or the empty list — operator ruling
    // 11 (policy `render-by-identity`): render the RECORDED endset's bytes
    // once per I-span, in span order, never once per projected occurrence.
    let Some(strings) = expect_strings(expected) else {
        inexpressible(out, "follow_link expectation in an unrecognized shape".into());
        return;
    };
    out.adaptations.push("render-by-identity".into());
    out.comparator = Some("follow-recorded-endset".into());
    match cx.render_recorded_endset(link, slot) {
        Ok((rendered, notes)) => {
            let want = strings.join("");
            if !notes.is_empty() {
                out.note = Some(notes.join("; "));
            }
            if rendered == want {
                out.status = Status::Agreed;
            } else {
                out.status = Status::Disagreed;
                out.expected = Some(format!("{want:?}"));
                out.actual = Some(format!("{rendered:?}"));
            }
        }
        Err(code) => {
            out.status = Status::Disagreed;
            out.expected = Some(format!("{:?}", strings.join("")));
            out.actual = Some(format!("followlink: {code}"));
        }
    }
}

/// Traversal macros: reverse_traversal / traverse_* / follow_links_* —
/// per-entry link follows with optional per-hop find_links checks. An op in
/// this family without a step list is a single follow (follow_links_target).
///
/// Hop links resolve from the WORLD (policy `traverse-hops-from-world`):
/// arrow-keyed edges first, then the shadow's link registry — the link
/// whose FROM endset lives in the hop's from-doc (narrowed by the to-doc
/// when the entry names one). Text is never re-searched to find a link.
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
    out.adaptations.push("traverse-hops-from-world".into());
    let mut fails: Vec<(String, String)> = Vec::new();
    let mut compared = 0usize;
    // The traversal's current position (a golden doc) and the last link
    // followed — landing-content entries compare against them.
    let mut current: Option<String> = None;
    let mut last_followed: Option<String> = None;
    for entry in entries {
        let Some(e) = entry.as_object() else { continue };
        // The entry's own doc anchors (step token / step "F->T" / from / at).
        let step_raw = e.get("step").and_then(Value::as_str);
        let (step_from, step_to) = match step_raw.and_then(|s| s.split_once("->")) {
            Some((f, t)) => (
                Some(f.trim().to_string()),
                t.split_whitespace().next().map(str::to_string),
            ),
            None => (
                step_raw.and_then(|s| s.split_whitespace().next()).map(str::to_string),
                None,
            ),
        };
        let from_tok = e
            .get("from")
            .and_then(Value::as_str)
            .map(|s| s.trim().to_string())
            .or(step_from);
        let to_tok = e
            .get("to")
            .and_then(Value::as_str)
            .and_then(|t| t.split_whitespace().next())
            .map(str::to_string)
            .or(step_to);
        let from_doc = from_tok.as_deref().and_then(|t| cx.shadow.resolve_doc(t));
        let to_doc = to_tok.as_deref().and_then(|t| cx.shadow.resolve_doc(t));
        if let Some(d) = &from_doc {
            current = Some(d.clone());
        }

        // links_found — a count (u64) or a golden id list — checked with a
        // REAL FindLinksFtt at the hop's doc.
        if let Some(v) = e.get("links_found") {
            let at = e
                .get("at")
                .and_then(Value::as_str)
                .and_then(|s| cx.shadow.resolve_doc(s))
                .or_else(|| from_doc.clone())
                .or_else(|| current.clone());
            if let Some(atdoc) = at {
                let found = find_links_at(cx, &atdoc, reverse);
                if let Some(n) = v.as_u64() {
                    compared += 1;
                    if found.len() as u64 != n {
                        fails.push((
                            format!("{atdoc}: {n} links"),
                            format!("{atdoc}: {}", found.len()),
                        ));
                    }
                } else if let Some(arr) = v.as_array() {
                    let want: Vec<String> =
                        arr.iter().filter_map(|x| x.as_str().map(str::to_string)).collect();
                    compared += 1;
                    let rig = &*cx.rig;
                    let mut adaptations = std::mem::take(&mut out.adaptations);
                    let verdict = compare_addr_sets(
                        &want,
                        &found,
                        cx.alpha,
                        |a| rig.is_types_addr(a),
                        &mut adaptations,
                    );
                    out.adaptations = adaptations;
                    if let Err((exp, act)) = verdict {
                        fails.push((format!("{atdoc}: {exp}"), format!("{atdoc}: {act}")));
                    }
                }
            }
            // A links_found entry may still carry landing content below.
            if !e.contains_key("content") && !e.contains_key("text") {
                continue;
            }
        }

        // The link this hop follows: recorded arrows first, then the world
        // registry (links FROM the hop's doc, narrowed by its to-doc).
        let link_golden: Option<String> = e
            .get("link")
            .and_then(Value::as_str)
            .filter(|s| fields::is_link_address(s))
            .map(str::to_string)
            .or_else(|| {
                let (f, t) = (from_tok.as_deref()?, to_tok.as_deref()?);
                cx.shadow.arrow_links.get(&(f.to_string(), t.to_string())).cloned()
            })
            .or_else(|| {
                // reverse_traversal: at X, the link ARRIVING from
                // found_link_from — the arrow (from, X).
                let at = e.get("at").and_then(Value::as_str)?.trim();
                let from = e.get("found_link_from").and_then(Value::as_str)?.trim();
                cx.shadow.arrow_links.get(&(from.to_string(), at.to_string())).cloned()
            })
            .or_else(|| {
                let d = from_doc.as_deref()?;
                let hits = cx.shadow.links_from(d, to_doc.as_deref());
                hits.first().map(|l| l.golden.clone())
            });

        let expectation: Option<(usize, &Value)> = if let Some(t) = e.get("target_text") {
            Some((2, t))
        } else if let Some(t) = e.get("source_text") {
            Some((1, t))
        } else if let Some(t) = e.get("text") {
            Some((default_slot, t))
        } else if let Some(t) = e.get("content") {
            Some((default_slot, t))
        } else if let Some(t) = e.get("result") {
            Some((default_slot, t))
        } else {
            None
        };

        let link_golden = link_golden.or_else(|| {
            // A landing-content entry without an outgoing link: the link
            // ARRIVING at this entry's doc (preferring the one leaving the
            // previous position), else the last followed link.
            if expectation.is_none() {
                return None;
            }
            let land = from_doc.clone().or_else(|| current.clone())?;
            let inbound = cx.shadow.links_to(&land);
            inbound
                .iter()
                .find(|l| {
                    last_followed.as_deref() == Some(l.golden.as_str())
                        || l.from.iter().any(|(d, _, _)| Some(d) == current.as_ref())
                })
                .or_else(|| inbound.first())
                .map(|l| l.golden.clone())
                .or_else(|| last_followed.clone())
        });

        let Some((slot, expected)) = expectation else { continue };
        let Some(link_golden) = link_golden else {
            fails.push(("hop link".into(), "no link resolvable for this hop".into()));
            continue;
        };
        let Some(link) = cx.alpha.translate(&link_golden) else {
            fails.push((link_golden.clone(), "unresolvable link".into()));
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
        // Land: the followed link's TO doc becomes the current position.
        last_followed = Some(link_golden.clone());
        if slot == 2 {
            if let Some(l) = cx.shadow.links.iter().find(|l| l.golden == link_golden) {
                if let Some((d, _, _)) = l.to.first() {
                    current = Some(d.clone());
                }
            }
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

/// One query side of a find_links: golden V-space (doc, spans) pairs to be
/// imaged live, or a pre-resolved I-space endset (deleted-content reach).
enum SideSpec {
    V(Vec<DocSpans>),
    I(Endset),
}

/// Links whose TO (reverse) / FROM (forward) endset touches `doc`'s extent
/// — the traversal macros' real per-hop FindLinksFtt query.
fn find_links_at(cx: &mut Cx, doc: &str, reverse: bool) -> Vec<skep_address::Address> {
    let n = cx.shadow.text_len(doc);
    let (e, _, _) = cx.image_endset(doc, &[(1, 1, n.max(1))]);
    let spec = if e.is_empty() { SlotSpec::Empty } else { SlotSpec::Spans(e) };
    let q = if reverse {
        FourSet { home: SlotSpec::Any, from: SlotSpec::Any, to: spec, ty: SlotSpec::Any }
    } else {
        FourSet { home: SlotSpec::Any, from: spec, to: SlotSpec::Any, ty: SlotSpec::Any }
    };
    match cx.rig.exec(Op::FindLinksFtt { q }) {
        Response::Addrs { addrs, .. } => addrs,
        _ => Vec::new(),
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
                let ispans = cx.rig.locate_deleted(s.as_bytes())?;
                icov_tag = true;
                return Some(SideSpec::I(Endset::from_spans(ispans.into_iter())));
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
            let ispans = cx.rig.locate_deleted(t.as_bytes())?;
            icov_tag = true;
            return Some(SideSpec::I(Endset::from_spans(ispans.into_iter())));
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
                        let deleted = cx.rig.deleted_ispans_of(doc);
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
                    let e = Endset::from_spans(all.into_iter());
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

fn h_find_documents(cx: &mut Cx, op: &Value, out: &mut OpOutcome) {
    let xf = expected_failure(op);
    let mut regions: Vec<Region> = Vec::new();
    let mut ground_failed: Option<String> = None;
    // A search text whose live location is gone: FINDDOCSCONTAINING takes
    // V-regions only, so the I-coverage reach re-locates the doc's DELETED
    // bytes in whichever doc still holds the identity live (the
    // transclusion sharer) — ruling 10's mechanism for this op.
    let relocate = |cx: &mut Cx, out: &mut OpOutcome, needle: &str| -> Option<Region> {
        let l = locate(cx.shadow, None, needle)?;
        out.adaptations.push("i-coverage-search".into());
        let d = cx.alpha.translate(&l.doc)?;
        Some(Region { doc: d, spans: vspan(1, l.ord, l.width).into_iter().collect() })
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
            regions.push(Region { doc: d, spans: vec![span] });
        }
    } else if let Some(doc) = bare_find_documents_aim(cx, op, out) {
        let n = cx.shadow.text_len(&doc);
        if n == 0 {
            // The aimed doc is empty: the search the script repeated was
            // over content this doc has DELETED — reach it through the doc
            // that still holds the identity live (spanfilade/
            // delete_all_transcluded_content's post-delete find_documents).
            let mut relocated = false;
            for bytes in cx.rig.deleted_bytes_of(&doc) {
                let needle = String::from_utf8_lossy(&bytes).into_owned();
                if let Some(r) = relocate(cx, out, &needle) {
                    regions.push(r);
                    relocated = true;
                    break;
                }
            }
            if !relocated {
                if let Some(d) = cx.alpha.translate(&doc) {
                    regions.push(Region { doc: d, spans: Vec::new() });
                }
            }
        } else if let Some(d) = cx.alpha.translate(&doc) {
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

/// The retrieve specs for a doc-less retrieve that follows a follow op whose
/// recorded result is a vspec — the landing the script read (policy
/// `retrieve-follow-landing`). `None` when the shape does not apply.
fn follow_landing_specs(cx: &mut Cx, index: usize, op: &Value) -> Option<Vec<Spec>> {
    if str_field(op, &["doc", "docid"]).is_some() {
        return None;
    }
    let prev = cx.ops.get(index.checked_sub(1)?)?;
    let prev_label = label_of(prev).to_ascii_lowercase();
    if !(prev_label.starts_with("follow") || prev_label.starts_with("traverse")) {
        return None;
    }
    let (docid, spans) = expect_spans_raw(field(prev, &["result"])?)?;
    let docid = docid?;
    if spans.is_empty() {
        return None;
    }
    let d = cx.alpha.translate(&docid)?;
    let mut specs = Vec::new();
    for (start, w) in &spans {
        let (sub, ord) = crate::tum::parse_vpos(start)?;
        let w = crate::tum::parse_width(w)?;
        if let Some(span) = vspan(sub, ord, w) {
            specs.push(Spec { doc: d.clone(), span });
        }
    }
    (!specs.is_empty()).then_some(specs)
}

fn h_contents(cx: &mut Cx, index: usize, op: &Value, out: &mut OpOutcome, label: &str) {
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

    // Per-target probe list: `targets: [{doc|docid, contents}]` —
    // identity/identity_multi_document_sharing records every created
    // target's content only here.
    if let Some(entries) = op.get("targets").and_then(Value::as_array) {
        let mut fails: Vec<(String, String)> = Vec::new();
        let mut compared = false;
        for e in entries {
            let docid = e
                .get("docid")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| {
                    e.get("doc").and_then(Value::as_str).and_then(|n| cx.shadow.resolve_doc(n))
                });
            let (Some(docid), Some(strings)) =
                (docid, e.get("contents").or_else(|| e.get("content")).and_then(expect_strings))
            else {
                continue;
            };
            compared = true;
            match cx.read_content(&docid) {
                Ok(items) => {
                    if let Err((exp, act)) = compare_content(&strings, &items, cx.alpha) {
                        fails.push((format!("{docid}: {exp}"), format!("{docid}: {act}")));
                    }
                }
                Err(code) => fails.push((format!("{docid}: contents"), format!("{docid}: {code}"))),
            }
        }
        if compared {
            out.adaptations.push("contents:content-subspace".into());
            out.comparator = Some("content".into());
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

    // Per-doc keyed probe: two or more fields whose KEY resolves as a doc
    // reference and whose VALUE is a string array are the recorded
    // per-document replies of one retrieve (policy `contents:per-doc-keyed`;
    // internal/ispan_partial_overlap op 4 records `source: ["CDEFG"],
    // dest: ["CDEFG"], expected: "CDEFG in both"` — the arrays are the data,
    // `expected` is prose, and reading it as the expectation while dropping
    // the arrays is what this branch replaces). The script's unrecorded
    // specset is reconstructed GOLDEN-side: a single recorded string that is
    // a proper substring of the doc's shadow content locates in the SHADOW
    // and that span is read from skep (policy
    // `read-span-from-recorded-strings` — the query derives from golden data
    // only, so skep still has to deliver the right bytes at those
    // positions); everything else reads the whole document and any mismatch
    // surfaces loudly.
    if str_field(op, &["doc", "docid"]).is_none()
        && field(op, &["result", "specset", "specs", "contents", "content"]).is_none()
    {
        const NOT_DOC_KEYS: &[&str] = &[
            "op", "comment", "note", "label", "description", "interpretation", "expected",
            "error", "status", "before", "after", "sample", "remaining", "empty", "value",
            "text", "texts", "strings", "cuts", "spans", "targets", "docs", "positions",
        ];
        let keyed: Vec<(String, String, Vec<String>)> = op
            .as_object()
            .map(|o| {
                o.iter()
                    .filter(|(k, v)| !NOT_DOC_KEYS.contains(&k.as_str()) && v.is_array())
                    .filter_map(|(k, v)| {
                        let strings = expect_strings(v)?;
                        let doc = cx.shadow.resolve_doc(k)?;
                        Some((k.clone(), doc, strings))
                    })
                    .collect()
            })
            .unwrap_or_default();
        if keyed.len() >= 2 {
            let mut fails: Vec<(String, String)> = Vec::new();
            for (name, doc, strings) in &keyed {
                let Some(d) = cx.skep_doc(doc) else {
                    fails.push((
                        format!("{name}: contents"),
                        format!("{name}: {doc} unresolvable"),
                    ));
                    continue;
                };
                // Reconstructed narrowing: exactly one recorded string,
                // strictly inside the shadow's content, located there.
                let narrowed = match strings.as_slice() {
                    [s] if !s.is_empty()
                        && !fields::is_link_address(s)
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
                    match vspan(1, ord, w).map(|span| {
                        cx.rig.exec(Op::RetrieveV { specs: vec![Spec { doc: d, span }] })
                    }) {
                        Some(Response::Delivery { items, .. }) => Ok(items.0),
                        Some(r) => Err(rejection_code(&r)
                            .unwrap_or_else(|| "unexpected response".into())),
                        None => Ok(Vec::new()),
                    }
                } else {
                    cx.read_content(doc)
                };
                match items {
                    Ok(items) => {
                        if let Err((e, a)) = compare_content(strings, &items, cx.alpha) {
                            fails.push((format!("{name}: {e}"), format!("{name}: {a}")));
                        }
                    }
                    Err(code) => {
                        fails.push((format!("{name}: contents"), format!("{name}: {code}")))
                    }
                }
            }
            out.adaptations.push("contents:per-doc-keyed".into());
            out.comparator = Some("content".into());
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
                    // One-position comparison through the shared content
                    // comparator, so an address value goes through α
                    // (bind + element lift) like every delivered address —
                    // never compared as a rendered string.
                    if want.is_empty() && items.0.is_empty() {
                        continue;
                    }
                    if let Err((e, a)) =
                        compare_content(&[want.to_string()], &items.0, cx.alpha)
                    {
                        fails.push((format!("{pos}={e}"), format!("{pos}={a}")));
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
    // Link-subspace reads issued as a SECOND RetrieveV so a link-side
    // absence localizes to the missing segment instead of rejecting the
    // whole delivery (policy `contents:both-subspaces`). The golden doc the
    // link read targets is kept so an empty answer can be classified (a
    // VERSION missing its source's links is the carryover family).
    let mut link_specs: Vec<Spec> = Vec::new();
    let mut link_read_doc: Option<String> = None;
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
            } else if let Some((start, width)) = deep_span_dict(item) {
                // A NESTED local V-address ("1.1.1" width "0.0.1" —
                // boundary_deep_vaddress_reads): built as an arbitrary-depth
                // tumbler span and asked of skep raw; M6's answer (empty
                // delivery or a depth/absence rejection) is compared as
                // recorded (policy `deep-vaddress-span`).
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
    } else if let Some(landing) = (!label.to_ascii_lowercase().starts_with("full_"))
        .then(|| follow_landing_specs(cx, index, op))
        .flatten()
    {
        // Policy `retrieve-follow-landing`: a doc-less retrieve right after
        // a follow whose recorded result names a vspec reads THOSE spans —
        // the script retrieved the link destination it had just followed
        // (links/follow_link op8), never the register. A `full_*` label is
        // by its own words a whole-document read, never a landing read
        // (round-5 item 4: insert_text_check_both_link_positions op7).
        out.adaptations.push("retrieve-follow-landing".into());
        specs = landing;
    } else {
        // Full probes aim at the doc the last CONTENT write touched, not
        // whatever the register drifted to (policy
        // `full-probe-targets-last-write`).
        let full_probe = label.to_ascii_lowercase().starts_with("full_");
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
            // Whole document. The reply's SHAPE follows the golden (round-5
            // item 5): text-only recorded contents read the CONTENT
            // subspace only (policy `contents:content-subspace` — udanax's
            // plain retrieve_contents never lists link items); a recorded
            // reply that includes a link address read BOTH subspaces —
            // content plus the link positions — and the link addresses
            // compare through α (policy `contents:both-subspaces`). One
            // evidence-driven narrowing: when the recorded TEXT is a strict
            // prefix of the shadow's (recorded-reality) content, the
            // script's specset was that much narrower — read only that many
            // positions (policy `read-scoped-to-recorded-extent`).
            let n = cx.shadow.text_len(&doc);
            let mut read_n = n;
            let has_addr = strings
                .as_ref()
                .is_some_and(|ss| ss.iter().any(|s| fields::is_link_address(s)));
            if let Some(ss) = &strings {
                let text_len: usize =
                    ss.iter().filter(|s| !fields::is_link_address(s)).map(String::len).sum();
                let shadow_text = cx.shadow.text_string(&doc);
                // Bounded at 2 elements: a larger shortfall is a
                // world-construction failure that must diverge loudly, not
                // a narrower script read.
                if (text_len as u64) < n
                    && n - text_len as u64 <= 2
                    && text_len > 0
                    && shadow_text.as_bytes().len() >= text_len
                    && ss
                        .iter()
                        .find(|s| !fields::is_link_address(s))
                        .is_some_and(|first| shadow_text.starts_with(first.as_str()))
                {
                    out.adaptations.push("read-scoped-to-recorded-extent".into());
                    read_n = text_len as u64;
                }
            }
            out.adaptations.push(
                if has_addr { "contents:both-subspaces" } else { "contents:content-subspace" }
                    .to_string(),
            );
            if let Some(span) = vspan(1, 1, read_n) {
                specs.push(Spec { doc: d.clone(), span });
            }
            if has_addr {
                let n_addr = strings
                    .as_ref()
                    .map(|ss| ss.iter().filter(|s| fields::is_link_address(s)).count() as u64)
                    .unwrap_or(0);
                let links = cx.shadow.link_count(&doc).max(n_addr);
                if let Some(span) = vspan(2, 1, links) {
                    link_specs.push(Spec { doc: d, span });
                    link_read_doc = Some(doc.clone());
                }
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
                // Absence encodings (policy `empty-as-absent`): an
                // expected-EMPTY probe and a skep absence-class rejection
                // both say "nothing there" (link_at_2_3_after probes a
                // vacant link position; udanax answered [], skep answers
                // RangeNotPresent).
                // DepthIncompatible joins the absence classes for the
                // deep-vaddress reads: a nested local address holds nothing
                // addressable on skep, and green's nested reads answered []
                // — the same observable (boundary_deep_vaddress_reads).
                let absence = matches!(
                    rejection_code(&other).as_deref(),
                    Some("RangeNotPresent")
                        | Some("EmptySubspace")
                        | Some("NoSuchSubspace")
                        | Some("EmptyResult")
                        | Some("DepthIncompatible")
                );
                if absence && xf.is_none() && strings.as_ref().is_some_and(Vec::is_empty) {
                    out.adaptations.push("empty-as-absent".into());
                    Vec::new()
                } else {
                    settle_ack(out, xf, rejection_code(&other));
                    return;
                }
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
                    // adjudication-ready carryover family.
                    let versioned = link_read_doc
                        .as_deref()
                        .is_some_and(|g| cx.shadow.version_of.contains_key(g));
                    let msg = if versioned {
                        VERSION_LINK_CARRYOVER_ANALYSIS.to_string()
                    } else {
                        "link-subspace read fired and delivered no items (subspace \
                         unoccupied on the skep side)"
                            .to_string()
                    };
                    out.note = Some(match out.note.take() {
                        Some(n) => format!("{n}; {msg}"),
                        None => msg,
                    });
                }
                items.extend(more.0);
            }
            r => {
                let code = rejection_code(&r).unwrap_or_else(|| "unexpected response".into());
                out.note = Some(match out.note.take() {
                    Some(n) => format!("{n}; link-subspace read: {code}"),
                    None => format!("link-subspace read: {code}"),
                });
            }
        }
    }
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
            // Policy `empty-as-absent`, spanset form: udanax renders an
            // empty document's extent as a zero span (cleaned to the empty
            // set — see expect_spans_raw); a skep absence-class rejection
            // encodes the same observable (documents/retrieve_vspan_empty).
            let absence = matches!(
                rejection_code(&other).as_deref(),
                Some("RangeNotPresent")
                    | Some("EmptySubspace")
                    | Some("NoSuchSubspace")
                    | Some("EmptyResult")
                    | Some("NotArranged")
            );
            let expected_empty =
                harvested.as_ref().is_some_and(|(_, _, spans)| spans.is_empty());
            if absence && xf.is_none() && expected_empty {
                out.adaptations.push("empty-as-absent".into());
                out.status = Status::Agreed;
                out.comparator = Some("vspanset".into());
                return;
            }
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
    out.comparator = Some("endsets-coverage".into());
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
    let mut fails: Vec<(String, String)> = Vec::new();
    for (slot_keys, slot) in [
        (&["from", "source"][..], 1usize),
        (&["to", "target"][..], 2),
        (&["three"][..], 3),
    ] {
        let Some(exp) = field(exp_root, slot_keys) else { continue };
        // Golden side → I-coverage via the live image.
        let mut want_ranges: Vec<(String, u64, u64)> = Vec::new();
        if let Some(arr) = exp.as_array() {
            for v in arr {
                if let Some((docid, spans)) = vspec_dict(v) {
                    let (e, notes, _) = cx.image_endset(&docid, &spans);
                    for n in notes {
                        out.note = Some(match out.note.take() {
                            Some(prev) => format!("{prev}; {n}"),
                            None => n,
                        });
                    }
                    for sp in e.spans() {
                        if let Some(r) = elem_range(sp) {
                            want_ranges.push((r.0, r.1, r.1 + r.2));
                        }
                    }
                }
            }
        }
        // Skep side: the recorded endset spans, types-doc spans excluded.
        let mut got_ranges: Vec<(String, u64, u64)> = Vec::new();
        for (i, e) in &pairs {
            if *i != slot {
                continue;
            }
            for sp in e.spans() {
                if let Ok(a) = skep_address::validate(sp.start().clone()) {
                    if cx.rig.is_types_addr(&a) {
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
        if want != got {
            fails.push((
                format!("slot{slot}:cov{}", render_ranges(&want)),
                format!("slot{slot}:cov{}", render_ranges(&got)),
            ));
        }
    }
    // TYPE slot: (origin doc, width) multiset as before.
    if let Some(exp) = field(op, &["type"]) {
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
            if *i != 3 {
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
            fails.push((format!("slot3:{want:?}"), format!("slot3:{got:?}")));
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
    win_a: Option<Vec<(u64, u64)>>,
    win_b: Option<Vec<(u64, u64)>>,
) -> Option<()> {
    let (Some(da), Some(db)) = (cx.alpha.translate(ga), cx.alpha.translate(gb)) else {
        out.status = Status::Disagreed;
        out.comparator = Some("alpha".into());
        out.note = Some("compare over unresolvable documents".into());
        return None;
    };
    // An operand window (compare_partial's "shared (13-18)"; the corpus
    // extension's operand vspec spans) narrows that side's ρ; without one
    // the side is the whole extent.
    let region_of =
        |cx: &Cx, g: &str, d: &skep_address::Address, win: Option<Vec<(u64, u64)>>| -> Region {
            let spans = match win {
                Some(list) => {
                    list.into_iter().filter_map(|(ord, w)| vspan(1, ord, w)).collect()
                }
                None => {
                    let n = cx.shadow.text_len(g);
                    vspan(1, 1, n).into_iter().collect()
                }
            };
            Region { doc: d.clone(), spans }
        };
    let rho1 = vec![region_of(cx, ga, &da, win_a)];
    let rho2 = vec![region_of(cx, gb, &db, win_b)];
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
    // Corpus-extension operands (policy `compare-operands-explicit`): two
    // top-level role-keyed vspec-dict fields name the sides and their
    // windows explicitly (ms_version_race `version_a1`/`original`, fanout
    // `dest`/`source` and self-compare `whole`/`whole_again`, the marathon's
    // `doc`/`vbase`). The original/version convention never applies when
    // they exist — it aims at the LATEST version, which these recordings
    // demonstrably do not mean. Verified absent from the 263-scenario
    // corpus, so the legacy paths are untouched.
    const NOT_OPERAND: &[&str] = &["result", "pairs", "shared", "shared_spans"];
    let operands: Vec<(String, String, Vec<(u64, u64)>)> = op
        .as_object()
        .map(|o| {
            o.iter()
                .filter(|(k, _)| !NOT_OPERAND.contains(&k.as_str()))
                .filter_map(|(k, v)| {
                    let (docid, spans) = vspec_dict(v)?;
                    let wins: Vec<(u64, u64)> = spans
                        .iter()
                        .filter(|(s, _, _)| *s == 1)
                        .map(|(_, ord, w)| (*ord, *w))
                        .collect();
                    Some((k.clone(), docid, wins))
                })
                .collect()
        })
        .unwrap_or_default();
    if operands.len() == 2 {
        out.adaptations.push("compare-operands-explicit".into());
        let (ka, da, wa) = operands[0].clone();
        let (kb, db, wb) = operands[1].clone();
        let shared: Vec<Value> = field(op, &["result", "shared", "pairs"])
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let win_a = (!wa.is_empty()).then_some(wa);
        let win_b = (!wb.is_empty()).then_some(wb);
        if run_compare_pair(cx, out, &da, &db, &ka, &kb, &shared, win_a, win_b).is_none() {
            return;
        }
        // A bare pair_count (no recorded pair list) re-judges as a count.
        if let (Some(n), true) =
            (field(op, &["pair_count"]).and_then(Value::as_u64), shared.is_empty())
        {
            if out.status == Status::Disagreed && out.expected.as_deref() == Some("[]") {
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
        return;
    }

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
                run_compare_pair(cx, &mut sub, &dest, &src, "target", "source", &shared, None, None);
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

    // The two documents, as referenced by the golden (names or addresses):
    // explicit fields, then the op's own label when it is a "<x>_vs_<y>"
    // pair (identity_mixed_sources's "target_vs_source1"), then the
    // original/version convention.
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
    } else if let Some((a, b)) = str_field(op, &["label"])
        .and_then(|l| l.split_once("_vs_"))
        .filter(|(a, b)| {
            cx.shadow.resolve_doc(a).is_some() && cx.shadow.resolve_doc(b).is_some()
        })
    {
        (a.to_string(), b.to_string())
    } else {
        ("original".to_string(), "version".to_string())
    };
    // Shared pairs: a bare array, or wrapped in a result object
    // (`result: {shared_span_pairs, shared: […]}` —
    // iaddress_allocation/delete_does_not_affect_next_insert's
    // compare_via_transclusion).
    let shared: Vec<Value> = field(op, &["shared", "result", "pairs", "shared_spans"])
        .and_then(|v| {
            v.as_array().cloned().or_else(|| v.get("shared").and_then(Value::as_array).cloned())
        })
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
    // Operand windows: top-level `<ref>_span` keys narrow that side's ρ —
    // compare ops honor their windows (compare_partial's descriptive
    // "shared (13-18)" grounds to doc1[13..19]; round 2 ran whole-document).
    let mut win_a: Option<Vec<(u64, u64)>> = None;
    let mut win_b: Option<Vec<(u64, u64)>> = None;
    if let Some(o) = op.as_object() {
        for (k, v) in o {
            let Some(stem) = k.strip_suffix("_span") else { continue };
            let Some(side_doc) = cx.shadow.resolve_doc(stem) else { continue };
            let win = if let Some((sub, ord, w)) = span_dict(v) {
                (sub == 1).then_some((ord, w))
            } else if let Some(s) = v.as_str() {
                locate(cx.shadow, Some(&side_doc), s).map(|l| (l.ord, l.width))
            } else {
                None
            };
            let Some(win) = win else { continue };
            if side_doc == ga && win_a.is_none() {
                win_a = Some(vec![win]);
                out.adaptations.push("compare-window".into());
            } else if side_doc == gb && win_b.is_none() {
                win_b = Some(vec![win]);
                out.adaptations.push("compare-window".into());
            }
        }
    }
    if run_compare_pair(cx, out, &ga, &gb, &ref_a, &ref_b, &shared, win_a, win_b).is_none() {
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
            // Multisession: `account` ops carrying a session field bind (or
            // re-bind) the label to this account (ms_create_race re-binds B).
            if let Some(sess) = str_field(op, &["session"]) {
                cx.rig.bind_session_label(sess, &a);
                out.adaptations.push(format!("session-bind:{sess}"));
            }
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
        // Address strings and recording-client python reprs are never
        // content-subspace bytes; skip rather than fabricate a comparison.
        let addr_like = strings.iter().any(|s| {
            (s.contains('.') && parse_dotted(s).is_some()) || fields::is_python_repr(s)
        });
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
fn h_observe(cx: &mut Cx, index: usize, op: &Value, out: &mut OpOutcome, grants: &Grants) {
    // docs-map / targets-list / positions bundles compare several documents.
    if op.get("docs").and_then(Value::as_object).is_some()
        || op.get("targets").and_then(Value::as_array).is_some()
        || op.get("positions").and_then(Value::as_object).is_some()
    {
        h_contents(cx, index, op, out, label_of(op));
        return;
    }
    // A probe green FAILED with no observation data recorded
    // (boundary_foreign_and_malformed_opens: probes of never-created docs
    // through validation-free opens). Never-created target → joint absence;
    // a real bound target → issue the vspanset read and reconcile the
    // recorded failure against skep's own verdict.
    let xf = expected_failure(op);
    if xf.is_some() && !has_observation_fields(op) {
        if let Some(docref) = str_field(op, &["doc", "docid"]) {
            if joint_absence(cx, out, &xf, docref) {
                return;
            }
            if let Some(d) = cx.alpha.peek_translate(docref) {
                let r = cx.rig.exec(Op::RetrieveDocVSpanSet { doc: d });
                let rejected = match &r {
                    Response::SpanSet { .. } => None,
                    other => rejection_code(other)
                        .or_else(|| Some("unexpected response shape".into())),
                };
                settle_ack(out, xf, rejected);
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
    probe_state(cx, op, out, grants, &doc, Probe::Bundle);
}
