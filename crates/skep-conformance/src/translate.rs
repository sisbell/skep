//! The translator: canonical verb + fields → skep `Op`, executed and
//! compared in place. The catalogue is deliberately boring — one arm per
//! verb, exhaustive; a reader auditing "what does the harness do with
//! `vcopy`" finds one function that says so. Every adaptation policy is
//! named and recorded per-op; a label or field shape that cannot be
//! translated is classified `inexpressible` with the reason recorded —
//! never silently skipped.
//!
//! Layout: this file is the dispatch — `normalize` and `run_op` — and what
//! more than one verb family calls: the `Cx` context and its reads over the
//! rig, the outcome helpers, document creation and plan execution, endset
//! sides, and the state probe. Each family's handlers are a child module
//! holding the helpers no other family uses; a child sees this file's
//! private items and none of its siblings'.
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
use skep_febe::{Deposit, Op, Response, SlotArg};
use skep_links::Endset;
use skep_retrieval::{DeliveryItem, Spec};

use crate::alpha::Alpha;
use crate::compare::{
    collapsed_subspace_shape, compare_content, compare_expected_failure, compare_spansets,
    COLLAPSED_SUBSPACE_ANALYSIS,
};
use crate::fields::{
    self, arrow_results, client_side_failure, cuts_of, doc_from_label, expect_spans_raw,
    expect_strings, field, harvest_spanset, label_of, locate, span_dict, str_field, vspec_dict,
    DocSpans,
};
use crate::ground::SetupStep;
use crate::harness::Rig;
use crate::outcome::{OpOutcome, Status};
use crate::shadow::Shadow;
use crate::tum::{is_link_address, link_home_docid, parse_dotted, vspan};

// Creation: documents, chains, `setup` plans, open, versions, accounts.
mod create;
// Content writes: insert and its forms, delete, vcopy, pivot and swap.
mod write;
// Link creation, in the legacy recordings and the explicit-set shape.
mod link;
// Following links: single follows and the traversal macros.
mod follow;
// The searches: find_links, find_documents, retrieve_endsets.
mod find;
// Content reads: retrieve_contents, the vspan/vspanset probes, observation bundles.
mod read;
// Correspondence: compare_versions against the recorded shared-span pairs.
mod correspondence;

use correspondence::h_compare;
use create::{
    h_account, h_create_chain, h_create_document, h_create_documents, h_create_node,
    h_create_version, h_open_document, h_setup,
};
use find::{h_endsets, h_find_documents, h_find_links};
use follow::{h_follow_link, h_traverse};
use link::h_create_link;
use read::{h_contents, h_observe, h_vspanset};
use write::{h_delete, h_insert, h_insert_loop, h_interior_typing, h_pivot_swap, h_vcopy};

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
            "result" | "before" | "after" | "empty"
                if expect_strings(v).is_some() || fields::looks_like_spanset(v) =>
            {
                return true;
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
            if !arr.is_empty() && arr.iter().all(|v| v.as_str().is_some_and(is_link_address))
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

// ──────────────────────────── small shared bits ────────────────────────────

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
        match self.rig.create_private_document() {
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
                match self.rig.exec(Op::Insert { doc: d, at: vpos(1, at), values, deposit: Deposit::Undeclared }) {
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
                match self.rig.exec(Op::MakeLink {
                    home,
                    from: SlotArg::Resolve(f),
                    to: SlotArg::Resolve(t),
                    ty: SlotArg::Resolve(vec![ty]),
                    replaces: None,
                }) {
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
    fn image_rows(&mut self, docid: &str) -> Vec<ImageRow> {
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
}

/// One row of a golden doc's V→I image: (I-prefix, I-ordinal, width,
/// V-start), as `Cx::image_rows` lists them.
type ImageRow = (String, u64, u64, u64);

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
    let last: u64 = st.get(n)?.to_string().parse().ok()?;
    let prefix: Vec<String> = st.iter().take(n - 1).map(|c| c.to_string()).collect();
    Some((prefix.join("."), last, w))
}

// ─────────────────── document creation & expansion plans ───────────────────

fn create_one(cx: &mut Cx, out: &mut OpOutcome, id: &str, name: Option<&str>) {
    if cx.shadow.knows(id) {
        if let Some(n) = name {
            cx.shadow.bind_name(n, id);
        }
        cx.shadow.set_current(id);
        return;
    }
    match cx.rig.create_private_document() {
        Response::AckAddr { addr, .. } => {
            cx.alpha.bind(id, &addr);
            cx.shadow.create_doc(id, name);
        }
        other => fail_response(out, "rejection", "document creation", &other),
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

// ────────────────────────────── endset sides ───────────────────────────────

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

// ────────────────────────────── state probes ───────────────────────────────

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
