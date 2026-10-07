//! The translator: canonical verb + fields → skep `Op`, executed and
//! compared in place. The catalogue is deliberately boring — one arm per
//! verb, exhaustive; a reader auditing "what does the harness do with
//! `vcopy`" finds one function that says so. Every adaptation policy is
//! named and recorded per-op; a label or field shape that cannot be
//! translated is classified `inexpressible` with the reason recorded —
//! never silently skipped.
//!
//! Layout: this file is the dispatch — `run_op`, over the verbs
//! `fields::normalize` reads a label as — and what more than one verb family
//! calls: the `Cx` context with its reads over the rig and its world-change
//! methods (the shadow's one owner in the play pass), the outcome helpers
//! and the `Tally` an op judged part by part settles through, document
//! creation and plan execution, endset sides, and the state probe. Each
//! family's handlers are a child module holding the helpers no other family
//! uses; a child sees this file's private items and none of its siblings'.
//!
//! ## Adaptation policies (each recorded per-op when applied)
//!
//! * `open_document:noop` — skep has no bert/open layer (access control
//!   descoped); the op's `result` address still binds in the α-map.
//! * `open_document:conflict_copy→version` — the golden's own recorded
//!   result (a new sub-address of the source) shows CONFLICT_COPY forked.
//! * `close_document:noop` — no open layer, nothing to close.
//! * `client-error:no-op` — the recording CLIENT crashed before the op
//!   reached udanax (`fields::client_side_failure`: a result of
//!   "OPERATION_FAILED: …", a "FAILED: …" result naming a missing session
//!   attribute, or an error naming one); udanax never executed the op, so
//!   neither does the harness, and the shadow does not change.
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
//! * `allowlist-grant:width` / `allowlist-grant:count` — a comparator agreed
//!   only because an allowlist entry's declared width tolerance or count
//!   delta covered the difference; the runner allowlists such an agreement
//!   (the entry's existence is the adjudicated divergence).
//! * `compare:self` — a compare naming one resolvable document and a second
//!   reference the recording never uses (the harness's original/version
//!   default, keying no recorded pair) compares that document with itself,
//!   as internal/insert_only_baseline's script did. A second reference the
//!   recording does use — a `docs` pair, `doc_a`/`doc_b`, a `<x>_vs_<y>`
//!   label, or a shared-pair key — that the shadow cannot ground leaves the
//!   op inexpressible instead.
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

use crate::allowlist::Grants;
use crate::alpha::Alpha;
use crate::compare::{
    collapsed_subspace_shape, compare_content, compare_expected_failure, compare_spansets,
    Comparison, COLLAPSED_SUBSPACE_ANALYSIS,
};
use crate::deletions::Deletions;
use crate::fields::{
    self, client_side_failure, cuts_of, doc_from_label, expect_spans_raw, expect_strings, field,
    harvest_spanset, label_of, locate, normalize, span_dict, str_field, vspec_dict, CopySource,
    DocSpans, Verb,
};
use crate::ground::SetupStep;
use crate::harness::Rig;
use crate::outcome::{OpOutcome, Status};
use crate::shadow::{Shadow, ShadowLink};
use crate::tum::{link_home_docid, parse_dotted, vspan};

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

pub struct Cx<'a> {
    pub rig: &'a mut Rig,
    pub alpha: &'a mut Alpha,
    pub shadow: &'a mut Shadow,
    /// The scenario's deleted-content history (ruling 10).
    pub deletions: &'a mut Deletions,
    /// The whole scenario, for bounded forward-evidence scans.
    pub ops: &'a [Value],
    /// Pre-pass expansion plans, keyed by op index.
    pub plans: &'a BTreeMap<usize, Vec<SetupStep>>,
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

/// How an op judged part by part — documents, positions, slots, steps,
/// hops — becomes one status. Every such handler folds through this, so
/// `Agreed` always means "compared, and every comparison matched", and a
/// part the recording names that could not be aimed at skep is never
/// silently dropped.
#[derive(Default)]
struct Tally {
    /// Parts compared, agreeing or not.
    compared: usize,
    /// The disagreeing parts, (expected, actual) each.
    differ: Vec<(String, String)>,
    /// The parts that could not be aimed, each with its reason.
    unaimed: Vec<String>,
}

impl Tally {
    /// A part compared, and matching.
    fn agree(&mut self) {
        self.compared += 1;
    }

    /// A part compared, and disagreeing.
    fn differ(&mut self, expected: String, actual: String) {
        self.compared += 1;
        self.differ.push((expected, actual));
    }

    /// A part a comparator judged, each side of a disagreement labelled.
    fn judge(&mut self, c: Comparison, expected_label: &str, actual_label: &str) {
        match c {
            Ok(()) => self.agree(),
            Err((e, a)) => {
                self.differ(format!("{expected_label}{e}"), format!("{actual_label}{a}"))
            }
        }
    }

    /// A part the recording names that could not be aimed at skep.
    fn unaimed(&mut self, reason: String) {
        self.unaimed.push(reason);
    }

    /// Write the status the parts add up to: any disagreeing part
    /// disagrees, with the unaimed parts noted alongside; else any unaimed
    /// part leaves the op inexpressible; else a comparison agrees; else
    /// nothing was compared and `out` is `NotCompared`. Notes already on
    /// `out` are kept.
    fn settle(self, out: &mut OpOutcome, comparator: &str) {
        let unaimed =
            (!self.unaimed.is_empty()).then(|| format!("not aimed: {}", self.unaimed.join("; ")));
        if !self.differ.is_empty() {
            out.status = Status::Disagreed;
            out.comparator = Some(comparator.to_string());
            out.expected =
                Some(self.differ.iter().map(|d| d.0.clone()).collect::<Vec<_>>().join(" | "));
            out.actual =
                Some(self.differ.iter().map(|d| d.1.clone()).collect::<Vec<_>>().join(" | "));
            if let Some(u) = unaimed {
                out.add_note(u);
            }
        } else if let Some(u) = unaimed {
            inexpressible(out, u);
        } else if self.compared > 0 {
            out.status = Status::Agreed;
            out.comparator = Some(comparator.to_string());
        } else {
            out.status = Status::NotCompared;
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
        match self.create_document(&id, None, true) {
            Response::AckAddr { .. } => {
                out.adaptations.push("implied-create:first-touch".into());
                Some(id)
            }
            _ => None,
        }
    }

    fn skep_doc(&mut self, golden: &str) -> Option<skep_address::Address> {
        self.alpha.translate(golden)
    }

    /// Execute one reconstruction step (lead-in or expansion plan) through
    /// the world-change methods: inferred setup is golden-side by
    /// construction, so it is mirrored whatever skep answers.
    pub fn exec_setup_step(&mut self, s: &SetupStep) -> Result<(), String> {
        let refused = |what: String, r: &Response| {
            format!("{what}: {}", rejection_code(r).unwrap_or_else(|| "?".into()))
        };
        match s {
            SetupStep::Insert { doc, bytes } => {
                let at = self.shadow.text_len(doc) + 1;
                match self.insert(doc, 1, at, bytes, true) {
                    Err(g) => Err(format!("setup insert: {g} unbound")),
                    Ok(Response::AckAddr { .. }) => Ok(()),
                    Ok(r) => Err(refused(format!("setup insert into {doc}"), &r)),
                }
            }
            SetupStep::Copy { doc, src, ord, width } => {
                if *width == 0 {
                    return Err("setup copy: empty span".into());
                }
                let at = self.shadow.text_len(doc) + 1;
                let source = CopySource { doc: src.clone(), sub: 1, ord: *ord, width: *width };
                match self.copy(doc, at, &[source], true) {
                    Err(g) => Err(format!("setup copy: {g} unbound")),
                    Ok(Response::Ack { .. }) => Ok(()),
                    Ok(r) => Err(refused(format!("setup copy into {doc}"), &r)),
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
                // The scripts' default type (policy default_type_jump).
                let ty = self
                    .rig
                    .type_vspec("jump")
                    .ok_or_else(|| "setup link: type registry exhausted".to_string())?;
                let link = golden
                    .as_ref()
                    .map(|g| ShadowLink { golden: g.clone(), from: from.clone(), to: to.clone() });
                match self.make_link(&home_golden, [f, t, vec![ty]], link, None, true) {
                    Err(h) => Err(format!("setup link: home {h} unbound")),
                    Ok(Response::AckAddr { .. }) => Ok(()),
                    Ok(r) => Err(refused(format!("setup link in {home_golden}"), &r)),
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

// ───────────────────── world changes: the shadow's one owner ─────────────────
//
// Every change the play pass makes to the golden-side world goes through
// the methods below, and each follows one rule. The shadow follows the
// RECORDING; α follows skep. A content write is mirrored into the shadow
// first — when the recording says udanax made it (`recorded`: callers pass
// `evidence::took_effect`, or `true` for the pre-pass's inferred setup) and
// the shadow holds the document — and then skep is asked through α, so
// neither skep's verdict nor an α miss bends what the shadow holds. A
// CREATION's golden name enters the shadow, bound in α, only when skep made
// it and udanax did too: every name the translator resolves has an
// α-image. A creation skep refuses — a version of a private source,
// PUB-2.9 — therefore leaves its later name-references ungroundable, the
// class rulings 20 and 20a freeze. `tests/it/tidy.rs` holds every other
// play-pass file to changing the shadow's world through these methods.

impl Cx<'_> {
    /// Does a write into golden `doc` reach the shadow?
    fn mirrors(&self, doc: &str, recorded: bool) -> bool {
        recorded && self.shadow.knows(doc)
    }

    /// CREATENEWDOCUMENT for golden `golden`, named `name` when the
    /// recording names it. The document enters the shadow, `golden` bound
    /// in α, when skep made it and `recorded`.
    pub fn create_document(
        &mut self,
        golden: &str,
        name: Option<&str>,
        recorded: bool,
    ) -> Response {
        let r = self.rig.create_private_document();
        if let (true, Response::AckAddr { addr, .. }) = (recorded, &r) {
            self.alpha.bind(golden, addr);
            self.shadow.create_doc(golden, name);
        }
        r
    }

    /// VERSION of golden `src`, recorded as golden `golden` when the
    /// recording kept the result. The version enters the shadow when skep
    /// made it and `recorded`: `golden` binds in α, and each of `names` —
    /// the op's own names for the new version — that is no address and
    /// names no document yet comes to name it. `Err` names a source with no
    /// α-image; skep was asked nothing.
    fn create_version(
        &mut self,
        src: &str,
        golden: Option<&str>,
        names: &[&str],
        recorded: bool,
    ) -> Result<Response, String> {
        let d_src = self.alpha.translate(src).ok_or_else(|| src.to_string())?;
        let r = self.rig.exec(Op::Version { d_src, published: None });
        if let (true, Response::AckAddr { addr, .. }, Some(g)) = (recorded, &r, golden) {
            self.alpha.bind(g, addr);
            self.shadow.version(src, g);
            for n in names {
                if parse_dotted(n).is_none() && self.shadow.resolve_doc(n).is_none() {
                    self.shadow.bind_name(n, g);
                }
            }
        }
        Ok(r)
    }

    /// INSERT `bytes` at `(sub, ord)` of golden `doc`, a content-subspace
    /// insert mirrored first. `Err` names a document with no α-image; skep
    /// was asked nothing.
    fn insert(
        &mut self,
        doc: &str,
        sub: u64,
        ord: u64,
        bytes: &[u8],
        recorded: bool,
    ) -> Result<Response, String> {
        if sub == 1 && self.mirrors(doc, recorded) {
            self.shadow.insert(doc, ord, bytes);
        }
        let d = self.alpha.translate(doc).ok_or_else(|| doc.to_string())?;
        let values: Vec<Val> = bytes.iter().map(|b| Val::new(vec![*b])).collect();
        Ok(self.rig.exec(Op::Insert {
            doc: d,
            at: vpos(sub, ord),
            values,
            deposit: Deposit::Undeclared,
        }))
    }

    /// COPY the golden `sources` to content ordinal `ord` of golden `doc`,
    /// the copied content-subspace bytes mirrored first. `Err` names a
    /// document with no α-image, the sources' ahead of the destination's;
    /// skep was asked nothing.
    fn copy(
        &mut self,
        doc: &str,
        ord: u64,
        sources: &[CopySource],
        recorded: bool,
    ) -> Result<Response, String> {
        if self.mirrors(doc, recorded) {
            let bytes: Vec<u8> = sources
                .iter()
                .filter(|s| s.sub == 1)
                .flat_map(|s| self.shadow.slice(&s.doc, s.ord, s.width))
                .collect();
            self.shadow.insert(doc, ord, &bytes);
        }
        let mut specs = Vec::new();
        for s in sources {
            let source = self.alpha.translate(&s.doc).ok_or_else(|| s.doc.clone())?;
            if let Some(span) = vspan(s.sub, s.ord, s.width) {
                specs.push(VSpec { source, span });
            }
        }
        let d = self.alpha.translate(doc).ok_or_else(|| doc.to_string())?;
        Ok(self.rig.exec(Op::Copy { doc: d, at: vpos(1, ord), specs }))
    }

    /// DELETE `width` positions at `(sub, ord)` of golden `doc`, a
    /// content-subspace delete mirrored first. Just before skep is asked,
    /// the doomed region's I-extents are imaged — while the arrangement
    /// still speaks for them — into the scenario's deletion history
    /// (ruling 10); an image failure is swallowed, and a later I-coverage
    /// search over the missing record fails to ground, surfacing as its own
    /// honest outcome. `Err` names a document with no α-image; skep was
    /// asked nothing.
    fn delete(
        &mut self,
        doc: &str,
        sub: u64,
        ord: u64,
        width: u64,
        recorded: bool,
    ) -> Result<Response, String> {
        let removed = if sub == 1 { self.shadow.slice(doc, ord, width) } else { Vec::new() };
        if sub == 1 && self.mirrors(doc, recorded) {
            self.shadow.delete(doc, ord, width);
        }
        let d = self.alpha.translate(doc).ok_or_else(|| doc.to_string())?;
        if let Some(span) = vspan(1, ord, removed.len() as u64) {
            if let Response::Runs { runs, .. } =
                self.rig.exec(Op::Image { d: d.clone(), region: vec![span] })
            {
                self.deletions.record(doc, removed, runs.iter().map(Run::iextent).collect());
            }
        }
        Ok(self.rig.exec(Op::Delete { doc: d, p: vpos(sub, ord), width: Nat::from(width) }))
    }

    /// REARRANGE golden `doc` at content `cuts` — three cuts pivot, four
    /// swap — mirrored first. `Err` names a document with no α-image; skep
    /// was asked nothing.
    fn rearrange(&mut self, doc: &str, cuts: &[u64], recorded: bool) -> Result<Response, String> {
        if self.mirrors(doc, recorded) {
            match *cuts {
                [a, b, c] => self.shadow.pivot(doc, a, b, c),
                [s1, e1, s2, e2] => self.shadow.swap(doc, s1, e1, s2, e2),
                _ => {}
            }
        }
        let d = self.alpha.translate(doc).ok_or_else(|| doc.to_string())?;
        let cuts = cuts.iter().map(|&c| vpos(1, c)).collect();
        Ok(self.rig.exec(Op::Rearrange { doc: d, cuts }))
    }

    /// MAKELINK homed in golden `home` over endsets already resolved
    /// through α, in M7's slot order: FROM, TO, TYPE. When skep made the
    /// link and `recorded`, it enters the shadow: seated in its home, the
    /// register moved there; with the recorded `link`, its golden id bound
    /// in α, made the last link and registered for traversal with the
    /// golden content endsets it was grounded with; and the recorded arrow
    /// edge, `(from-name, to-name, link id)`. `Err` names a home with no
    /// α-image; skep was asked nothing.
    fn make_link(
        &mut self,
        home: &str,
        slots: [Vec<VSpec>; 3],
        link: Option<ShadowLink>,
        arrow: Option<(String, String, String)>,
        recorded: bool,
    ) -> Result<Response, String> {
        let h = self.alpha.translate(home).ok_or_else(|| home.to_string())?;
        let [from, to, ty] = slots;
        let r = self.rig.exec(Op::MakeLink {
            home: h,
            from: SlotArg::Resolve(from),
            to: SlotArg::Resolve(to),
            ty: SlotArg::Resolve(ty),
            replaces: None,
        });
        if let (true, Response::AckAddr { addr, .. }) = (recorded, &r) {
            self.shadow.seat_link(home);
            self.shadow.set_current(home);
            if let Some(l) = link {
                self.alpha.bind(&l.golden, addr);
                self.shadow.last_link = Some(l.golden.clone());
                self.shadow.record_link(&l.golden, l.from, l.to);
            }
            if let Some((f, t, id)) = arrow {
                self.shadow.arrow_links.insert((f, t), id);
            }
        }
        Ok(r)
    }
}

// ─────────────────── document creation & expansion plans ───────────────────

/// Create golden document `id` for an op that records it, unless the shadow
/// already holds it (an implied create, or a plan's earlier step): then the
/// name binds and the register moves to it. A refused creation is the op's
/// disagreement.
fn create_one(cx: &mut Cx, out: &mut OpOutcome, id: &str, name: Option<&str>, recorded: bool) {
    if cx.shadow.knows(id) {
        if let Some(n) = name {
            cx.shadow.bind_name(n, id);
        }
        cx.shadow.set_current(id);
        return;
    }
    let r = cx.create_document(id, name, recorded);
    if !matches!(r, Response::AckAddr { .. }) {
        fail_response(out, "rejection", "document creation", &r);
    }
}

/// Execute the pre-pass expansion plan attached to this op — every step of
/// it. A step skep refuses, or one naming a document with no α-image, does
/// not stop the rest: the shadow keeps following the reconstruction, and
/// the op reports the first failure.
fn run_plan(cx: &mut Cx, index: usize, out: &mut OpOutcome) {
    let Some(plan) = cx.plans.get(&index).cloned() else {
        out.status = Status::NotCompared;
        out.note = Some("no expansion plan derived; nothing executed".into());
        return;
    };
    out.adaptations.push(format!("expansion-plan:{}", plan.len()));
    let mut first_failure: Option<String> = None;
    for step in &plan {
        // Copies/inserts target docs the plan may create implicitly.
        if let SetupStep::Copy { doc, .. } | SetupStep::Insert { doc, .. } = step {
            if !cx.shadow.knows(doc) {
                create_one(cx, out, doc, None, true);
            }
        }
        if let Err(e) = cx.exec_setup_step(step) {
            first_failure.get_or_insert(e);
        }
    }
    match first_failure {
        Some(e) => {
            out.status = Status::Disagreed;
            out.comparator = Some("expansion-plan".into());
            out.expected = Some("reconstructed setup executes".into());
            out.actual = Some(e);
        }
        None => out.status = Status::NotCompared,
    }
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
    let mut tally = Tally::default();

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
                    let c = compare_spansets(&spans, &set, grants, &mut out.adaptations);
                    if c.is_err() && collapsed_subspace_shape(&spans) {
                        out.note = Some(COLLAPSED_SUBSPACE_ANALYSIS.to_string());
                    }
                    tally.judge(c, "vspanset ", "");
                }
                r => tally
                    .differ("vspanset".into(), rejection_code(&r).unwrap_or_else(|| "?".into())),
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
                    tally.judge(compare_content(&strings, &items, cx.alpha), "content ", "")
                }
                Err(code) => tally.differ("content".into(), code),
            }
        }
    }

    tally.settle(out, "state-probe");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn settled(tally: Tally) -> OpOutcome {
        let mut out = OpOutcome::new(0, "op");
        tally.settle(&mut out, "parts");
        out
    }

    /// `Agreed` means compared, and every comparison matched: nothing
    /// compared is not compared; a part that could not be aimed leaves the
    /// op inexpressible; a disagreement wins, the unaimed parts noted
    /// beside it.
    #[test]
    fn a_tally_agrees_only_over_comparisons() {
        assert_eq!(settled(Tally::default()).status, Status::NotCompared);

        let mut agreeing = Tally::default();
        agreeing.agree();
        assert_eq!(settled(agreeing).status, Status::Agreed);

        let mut partial = Tally::default();
        partial.agree();
        partial.unaimed("a part".into());
        assert_eq!(settled(partial).status, Status::Inexpressible);

        let mut differing = Tally::default();
        differing.unaimed("a part".into());
        differing.judge(Err(("want".into(), "got".into())), "e: ", "a: ");
        let out = settled(differing);
        assert_eq!(out.status, Status::Disagreed);
        assert_eq!(out.expected.as_deref(), Some("e: want"));
        assert_eq!(out.actual.as_deref(), Some("a: got"));
        assert_eq!(out.note.as_deref(), Some("not aimed: a part"));
    }
}
