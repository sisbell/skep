//! The play pass: canonical verb + fields → skep `Op`, executed and
//! compared in place. The catalogue is deliberately boring — one arm per
//! verb, exhaustive; a reader auditing "what does the harness do with
//! `vcopy`" finds one function that says so. Every adaptation policy is
//! named and recorded per-op; an op name or field shape with no expression
//! on skep's surface is classified `inexpressible` with the reason recorded
//! — never silently skipped — and so is a read whose recorded answer no
//! reader reaches (`compared_nothing`, the unread keys named): a read ends
//! `NotCompared` only when its recording kept no answer.
//!
//! Layout: this file is the dispatch — `run_op`, over the verbs
//! `fields::normalize` reads an op's name as — and what more than one verb
//! family calls: the `Cx` context with its reads over the rig and its
//! world-change methods (the shadow's one owner in the play pass), the
//! outcome helpers — skep's answer settled against the failure the golden
//! recorded (`settle_accepted`, `settle_unaccepted`), the `Tally` an op
//! judged part by part settles through, and the end of a read that compared
//! nothing — document creation, plan execution and the pre-pass's lead-in
//! (`run_lead_in`), endset sides, and the state probe. Each family's
//! handlers are a child module holding the helpers no other family uses; a
//! child sees this file's private items and none of its siblings'.
//!
//! ## Adaptation policies (each recorded per-op when applied)
//!
//! Grouped by the family that records each tag. A tag the dispatch records,
//! or more than one family does, is under Every family; one a shared reader
//! in `fields` or `evidence` records is under the family that calls it.
//!
//! ### Every family — the dispatch, and what more than one family records
//!
//! * `client-error:no-op` — the recording CLIENT crashed before the op
//!   reached udanax (`fields::client_side_failure`: a result of
//!   "OPERATION_FAILED: …", a "FAILED: …" result naming a missing session
//!   attribute, or an error naming one); udanax never executed the op, so
//!   neither does the harness, and the shadow does not change.
//! * `close_document:noop` — no open layer, nothing to close.
//! * `connect:session` — green's `connect` opens a TCP session; skep
//!   sessions open at account binding, so the op executes nothing.
//! * `session-route:<label>` — the op carried a `session` field and executed
//!   under that label's account session (label→account bound by `account`
//!   ops; two labels on one account share its session).
//! * `session-label-implicit-bind` — an op used a session label no `account`
//!   op had bound; it bound to the then-current account.
//! * `raw wire request codes` are inexpressible by construction: skep's
//!   surface is typed `Op`s; unknown-code handling lives in the transport's
//!   `OpKind::Unparseable`, which a library harness cannot reach.
//! * `doc-from-op-name` / `doc-from-register` — document scope grounding
//!   (the current-document register mirrors the recording scripts' implicit
//!   scope).
//! * `implied-create:first-touch` — an op needed a document before any
//!   create; one is created, exactly as the recording script must have.
//! * `expansion-plan:N` — the op executed a pre-pass reconstruction plan of
//!   N steps (create_chain / setup / vcopy_multiple / create_and_transclude).
//! * `text-located` / `text-located:*` / `span-from-description` /
//!   `range-from-description` / `whole-extent` — decorated-description
//!   grounding (fields::locate); a `text-located:*` tag names the field, or
//!   the occurrence, the text was located for.
//! * `position-end` / `position-start` / `position-from-description` /
//!   `position-after-text` / `position-before-text` / `position-from-op-name`
//!   — position grounding: a position the recording described ("end",
//!   "start", "position 6", "after X", "before X") grounded against the
//!   shadow, the after/before forms by finding the text there; or one the
//!   op's name carries.
//! * `types_document` — link-type names denote positions in a
//!   harness-created types document; udanax encoded them as vspecs into an
//!   unoccupied link subspace (unresolvable I-space). Type-slot data inside
//!   the types doc is harness infrastructure, excluded from comparisons.
//! * `threeset-marker→types-document` — a threeset span at the udanax
//!   type-marker local address `1.0.2.X` (client.py's LINK_TYPES encoding)
//!   denotes the type name (2.2 jump / 2.3 quote / 2.6 footnote / 2.6.2
//!   margin) the types document holds — the same `types_document` mapping
//!   the name-based path uses.
//! * `empty-specset` — a NOSPECS (or "empty") spec set is sent as no
//!   regions: udanax's empty query, asked as recorded.
//! * `joint-absence` — the golden recorded a failure against an object that
//!   was never created (green's OPEN validates nothing, A7); the reference
//!   has no α-image, so there is nothing to address on skep either — both
//!   systems refuse, compared as agreement via the expected-failure
//!   comparator (α's never-bound finding is deliberately not emitted: the
//!   absence IS the expected answer).
//! * `allowlist-adjusted:width` / `allowlist-adjusted:count` — a comparator
//!   agreed only because an allowlist entry's declared width tolerance or
//!   count delta covered the difference; the runner allowlists such an
//!   agreement (the entry's existence is the adjudicated divergence).
//! * `alpha-bind-from-result:N` — N unbound golden result addresses were
//!   bound to skep response addresses positionally (the α-map's sanctioned
//!   move; a wrong pairing surfaces later as a double-bind finding).
//! * `golden-duplicate-result` — the golden's expected list names one
//!   address twice (a recording defect); compared as a set, the dedup
//!   tagged so the defect stays visible.
//!
//! ### Creation — `create`
//!
//! * `open_document:noop` — skep has no bert/open layer (access control
//!   descoped); the op's `result` address still binds in the α-map.
//! * `open_document:conflict_copy→version` — the golden's own recorded
//!   result (a new sub-address of the source) shows CONFLICT_COPY forked.
//! * `open-noop-vs-recorded-failure` — green REFUSED the open (bert
//!   enforcement / account gating, manifest A1/A2); skep has no open layer
//!   to refuse with, so the recorded failure is surfaced as a raw
//!   divergence, never absorbed into the open no-op.
//! * `docid-synthesized:N` — the recording kept no address for N of the
//!   documents a create made: each was minted under a golden id the harness
//!   synthesized (the next root ordinal, `Shadow::synthesize_docid`), bound
//!   in α but recorded nowhere, so the op compares nothing (address-binding
//!   agrees only over recorded addresses).
//! * `account_as_delegate` / `create_node_as_delegate` — udanax account
//!   selection / sub-account minting map onto M3 delegation.
//! * `session-bind:<label>` — an `account` op carrying a `session` field
//!   binds that label to the account it made current.
//!
//! ### Content writes — `write`, through `evidence`'s readings
//!
//! * `insert-all:distributed` — an `insert_all` texts array fills one
//!   created document per text, in creation order.
//! * `args-from-op-name` — an insert recording no `text` field takes its text
//!   from its op's name (`insert_A` inserts "A"; `insert_1_AAA`, "AAA").
//! * `insert-aim-from-recorded-vspanset` — a doc-less insert re-aims at the
//!   doc whose next recorded vspanset shows the width grew by this insert
//!   (insert_vspace_mapping: the register held the version snapshot).
//! * `insert-position-from-post-state` — a doc-less, position-less insert
//!   whose own recorded post-state shows its text mid-document lands at the
//!   single gap that explains that post-state
//!   (iaddress_allocation/interleaved_insert_delete's insert_2).
//! * `insert-padded-to-recorded-vspanset:+N` — the recorded vspanset width
//!   is the authority for how much the script inserted; the field text is
//!   padded (with spaces) to match, never the comparison adjusted. DECLINED
//!   when links seated between the insert and the probe explain the surplus
//!   — that is udanax's version link carryover (see
//!   `VERSION_LINK_CARRYOVER_ANALYSIS`), and padding would fabricate a
//!   ghost content byte (createnewversion_text_vs_links' own retrieve
//!   delivers 33 text chars plus the link marker for its recorded 0.34).
//! * `insert-loop:a-z-cycle` — an `insert_loop` inserts one byte per count,
//!   cycling A–Z, each appended (edgecases/many_small_inserts' recorded
//!   sample).
//! * `interior-typing:per-step` — an `interior_typing` op's `results` list
//!   plays step by step: each character inserted at its recorded position,
//!   then compared against that step's own recorded probes.
//! * `delete-noop-from-post-state` — the recorded post-delete content
//!   equals the pre-delete content byte-for-byte: udanax removed nothing,
//!   so neither does the harness (delete_all_with_links' whole-doc remove).
//! * `delete_all:empty-noop` — a delete_all of a document already empty
//!   executes nothing: there is nothing to remove, and skep's DELETE takes
//!   no zero width (T12).
//! * `delete-span-from-post-state` / `delete-span-widened-boundary` — a
//!   text-located delete span corrected by the recorded post-delete content
//!   (diff pins exactly what udanax removed), or widened by the flanking
//!   space that convention shows the scripts deleted.
//! * `delete-text-from-op-name` — a bare `delete_A` op's removed text comes
//!   from its name, post-state-diff first
//!   (iaddress_allocation/delete_does_not_affect_next_insert).
//! * `vcopy-source-reaimed` — a from-description that grounded OUTSIDE its
//!   doc's live extent (the register pointing at the just-created empty
//!   destination) re-grounds against the content-holding docs excluding the
//!   destination; the recorded post-state confirms the span
//!   (internal/ispan_partial_overlap's "positions 3-7 (CDEFG)").
//! * `vcopy-dest-from-evidence` — a dest-less vcopy aimed at the doc whose
//!   later probe shows the copied bytes embedded, instead of the register.
//!
//! ### Link creation — `link`
//!
//! * `default_type_jump` — create_link without a type: the recording
//!   scripts' default.
//! * `default_source_first_word` / `default_target_whole_doc` /
//!   `default_target_self` — bare create_link endset conventions, evidence
//!   first (see `endset_evidence`), then the scripts' defaults
//!   (links/link_retrieval_via_endsets pins first-word; links/follow_link
//!   pins evidence-target).
//! * `endset-evidence` — a bare link endset recovered from a LATER recorded
//!   follow/endsets result for the same link — vspec-shaped or content
//!   strings — accepted only when no write intervenes; it also refines
//!   whole-extent doc-ref endsets, so stored links carry the extents the
//!   scripts actually made.
//! * `endset-from-transcluded-region` — a create_link `on:` field naming
//!   transcluded content grounds the endset to the home document's
//!   foreign-origin (copied-in) regions, read from the live V→I image.
//! * `create_links:repeat` — a plural create repeats one MakeLink per
//!   recorded result.
//! * `explicit-empty-endset` — a create_link `fromset`/`toset`/`threeset`
//!   recorded as an EMPTY list is passed to MakeLink empty (green accepts
//!   all three, A11); the default-endset conventions never substitute.
//! * `threeset-content-type` — a threeset carrying real content spans
//!   becomes the link's TYPE endset via α (green's content-span third
//!   endsets are first-class, A8).
//!
//! ### Following — `follow`
//!
//! * `follow_as_projection` — follow_link renders through `Op::Project`
//!   (I→V into a document); skep's raw FOLLOWLINK returns permanent
//!   I-spans, which the goldens never speak.
//! * `implicit_last_link` / `default-slot:source` — follow_link without a
//!   link/end field: the most recent link, the SOURCE end (pinned by
//!   isolation/insert_text_does_not_affect_links_in_same_document, whose
//!   bare follow recorded the source spans).
//! * `slot-from-evidence-doc` — a bare follow whose recorded result names a
//!   document: the slot whose projection lands in that document is the one
//!   the script followed (the golden's own result disambiguates the end).
//! * `render-by-identity` — operator ruling 11: a followed endset renders
//!   bytes once per RECORDED I-span, in span order, from whichever live
//!   arrangement speaks for each portion — never once per projected
//!   occurrence (shared content used to render "DEF" as "DEFEFDEF").
//! * `traverse-hops-from-world` — traversal hop links resolve from the
//!   shadow's links (every created link's endsets), never by text
//!   re-search; `links_found` lists compare against a real FindLinksFtt.
//!
//! ### The searches — `find`
//!
//! * `doc-from-source-role` — a bare find_links/find_documents searches from
//!   the source-role document when the scenario names one.
//! * `by-routes-explicit-side` — find_links `by: "target"` routes the
//!   explicit from-doc into the TO slot: the field named the doc searched
//!   FROM, `by` named the endset constrained
//!   (interactions/link_both_endpoints_transcluded op11).
//! * `set-empty:unconstrained:<key>` — an EMPTY `fromset`/`toset`/`threeset`
//!   (the `<key>`) on a find_links is the recording client's NOSPECS: no
//!   constraint on that slot (create_link's empty means empty; the query's
//!   empty means any).
//! * `transcluded-region-search` — a find_links `via_transcluded_content`
//!   query searches exactly the register's document's foreign-origin
//!   regions.
//! * `i-coverage-search` — a search aimed at content the shadow knows was
//!   deleted (or at a doc whose current extent no longer covers the
//!   recorded region) is built from I-coverage captured at delete time —
//!   ruling 10: deleted content stays findable via I-history, never by
//!   loosening V-queries.
//! * `query-clamped-to-extent` — a recorded SEARCH region wider than the
//!   doc's live extent is intersected with it before imaging (udanax's
//!   sparse V tolerated fat query spans; the golden's RESULT is still
//!   compared untouched).
//! * `endset-coverage-translated` — operator ruling 11: retrieve_endsets
//!   compares the golden's (docid, V-span) endsets mapped through Image to
//!   I-coverage against skep's recorded endset spans — coverage equality,
//!   not coordinate equality (udanax resolved into the query doc's V-space).
//! * `endsets-bare-result-as-from` — a retrieve_endsets whose `result` is a
//!   bare vspec list, naming no slot, recorded the FROM endset: each of the
//!   three recordings of this shape (links/delete_at_root_origin_height_1,
//!   delete_from_middle_affects_later_links, delete_width_larger_than_
//!   content) lists its link's source span, never its target.
//! * `endsets-as-followlink` — a retrieve_endsets addressed to the link's
//!   own space compares each slot's recorded widths, as a multiset, against
//!   the widths of the I-spans FOLLOWLINK reports (links/
//!   link_retrieval_via_endsets): udanax rendered the endsets in the link's
//!   V-space, skep reports them permanent.
//!
//! ### Content reads — `read`
//!
//! * `contents:content-subspace` — whole-document retrieves read the
//!   CONTENT subspace only, matching udanax's retrieve_contents (its
//!   recorded results never include link-subspace items) — all of it, as
//!   skep's own extent reports it, never sized from the recording.
//! * `contents:both-subspaces` — a retrieve whose recorded result lists a
//!   link address alongside text read the link subspace too, as a second
//!   RetrieveV, so a refusal of the link side cannot void the content read;
//!   the link addresses compare through α (the version scenarios'
//!   whole-document retrieves surfaced the copied link). The reply's shape
//!   follows the golden.
//! * `read-scoped-to-recorded-extent` — a whole-document retrieve read only
//!   as many content positions as the golden's reply carries, when the
//!   shadow (the recorded reality) holds more — the script's specset was
//!   narrower than the doc (createnewversion_text_vs_links reads 33 of 34).
//! * `full-probe-targets-last-write` — a `full_text_*`/`full_content_*`
//!   probe reads the doc the last CONTENT write touched, never a follow
//!   landing and never the drifted register
//!   (subspace/insert_text_check_both_link_positions op7).
//! * `retrieve-follow-landing` — a doc-less retrieve right after a follow
//!   whose recorded result names a vspec reads THOSE spans (links/
//!   follow_link op8 retrieves the link destination, not the register).
//! * `contents:per-doc-keyed` — `<docname>: [strings]` fields, or
//!   `<docname>_content: [strings]`, are the recorded per-document replies
//!   of one retrieve or snapshot (ispan_partial_overlap's `source:/dest:`
//!   arrays, the `expected` string alongside being prose;
//!   cross_document_transclusion_isolation's `A_content`/`C_content`).
//! * `read-span-from-recorded-strings` — a per-doc-keyed reply that is a
//!   proper substring of the doc's shadow content locates in the SHADOW
//!   (golden-side data only) and that span is read from skep — the script's
//!   unrecorded specset reconstructed without consulting skep's answer.
//! * `specset-from-description` — a "First N chars from each document" spec
//!   set reads the first N positions of every document created
//!   (content/retrieve_multiple_documents).
//! * `deep-vaddress-span` — a span dict at a NESTED local address ("1.1.1")
//!   is built as an arbitrary-depth tumbler span and asked of skep raw;
//!   M6's answer — empty (a well-formed nested span resolves to nothing,
//!   R6) or `MalformedSpan` (ruling 17) — is compared as recorded
//!   (boundary_deep_vaddress_reads).
//! * `vspan-count-by-role` — a `<role>_vspan_count` field counts the spans
//!   of the role document's vspanset (internal/ispan_consolidation_bulk's
//!   `source_vspan_count`, `dest_vspan_count`).
//! * `poom-empty` — `poom_empty: true` (false) records that the document's
//!   POOM — udanax's V-space arrangement — is (is not) empty: compared as
//!   skep's vspanset being empty (bert/bert_failure_leaves_ispace_
//!   corruption).
//!
//! ### Correspondence — `correspondence`
//!
//! * `compare-operands-explicit` — a compare op's two operands read from its
//!   own role-keyed vspec-dict fields (ms_version_race's `version_a1`/
//!   `original`), never from the original/version convention.
//! * `compare-window` — a `<ref>_span` field narrows that side of a compare
//!   to the window it names (compare_partial's "shared (13-18)").
//! * `compare:self` — a compare naming one resolvable document and a second
//!   reference the recording never uses (the harness's original/version
//!   default in a one-document scenario, keying no recorded pair) compares
//!   that document with itself, as internal/insert_only_baseline's script
//!   did. A second reference the recording does use — a `docs` pair,
//!   `doc_a`/`doc_b`, a `<x>_vs_<y>` `label` field, a shared-pair key, or
//!   the default's version when the recording made one — that the shadow
//!   cannot ground leaves the op inexpressible instead: a version skep
//!   refused to make names nothing (rulings 20, 20a).
//! * `compare-default:second-document` — a compare that names no document,
//!   in a scenario whose recording made no version, compares the scenario's
//!   first two documents created: the pair the version-less scripts
//!   compared (edgecases/compare_disjoint_documents, internal/
//!   ispan_partial_overlap). After a version the recording made, the
//!   default's second document is that version, whether or not skep made it.
//! * `identity-pairs-by-position` — a compare over `positions` with a
//!   `results` map `{"i_j": bool}` records whether positions i and j (1-based
//!   into the list) share their I-address: each pair compared through the
//!   positions' live images (internal/internal_transclusion_multiple_copies).
//!
//! ### The pre-pass's reconstructions — `ground`, among the groundings
//!
//! * `vcopy-cover-from-comparisons` / `vcopy-embed-plan` /
//!   `vcopy-span-from-comparison` / `vcopy-prefix-from-comparison` —
//!   grounding-pre-pass reconstructions of append-shaped vcopys from the
//!   scenario's own probes and recorded comparison pairs (the round-4
//!   unrecorded-prefix cluster); surfaced in the groundings list and
//!   executed as expansion plans.

use std::collections::BTreeMap;

use serde_json::Value;

use skep_address::{is_prefix, Nat, Span, Tumbler};
use skep_arrangement::{Run, VSpec};
use skep_content::Val;
use skep_febe::{Deposit, Op, Response, SlotArg};
use skep_links::Endset;
use skep_retrieval::{DeliveryItem, Spec};

use crate::allowlist::Adjustments;
use crate::alpha::Alpha;
use crate::compare::{
    compare_content, compare_spansets, is_collapsed_subspace_shape, Comparison,
    COLLAPSED_SUBSPACE_ANALYSIS,
};
use crate::deletions::Deletions;
use crate::evidence::Effect;
use crate::fields::{
    aim_doc, as_text, client_side_failure, cuts_of, field, locate, normalize, op_name,
    raw_spanset_of, recorded_content, recorded_spanset, span_dict, str_field, strings_of,
    vspec_dict, CopySource, DocAim, DocSpans, Verb, ANNOTATION_KEYS, POST_WRITE_KEYS,
};
use crate::ground::{ImpliedSetup, SetupStep};
use crate::rig::{brief, Rig};
use crate::outcome::{Disagreement, OpOutcome, Status};
use crate::shadow::{Shadow, ShadowLink};
use crate::tum::{last_component, link_home_docid, parse_dotted, span_elem_width, VPoint, VRegion};

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

use correspondence::h_compare_versions;
use create::{
    h_account, h_create_chain, h_create_document, h_create_documents, h_create_node,
    h_create_version, h_open_document, h_setup,
};
use find::{h_find_documents, h_find_links, h_retrieve_endsets};
use follow::{h_follow_link, h_traverse};
use link::h_create_link;
use read::{h_observe, h_retrieve_contents, h_retrieve_vspanset};
use write::{
    h_delete, h_insert, h_insert_loop, h_interior_typing, h_rearrange, h_vcopy, Rearrangement,
};

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

/// The op, or a part of it, has no expression on skep's surface: `reason`
/// says why. The caller owes an op not yet disagreed (`OpOutcome`'s
/// invariant): a part that cannot be aimed beside a disagreement is a
/// `Tally`'s to settle, which keeps the disagreement and notes the part.
fn inexpressible(out: &mut OpOutcome, reason: String) {
    assert!(
        out.status != Status::Disagreed,
        "op {} `{}` is disagreed already: a disagreement stands",
        out.index,
        out.op_name
    );
    out.status = Status::Inexpressible;
    // Keep any resolution note already attached (doc_arg's resolves-to-
    // nothing detail) alongside the classification reason.
    out.note = Some(match out.note.take() {
        Some(n) => format!("{reason}; {n}"),
        None => reason,
    });
}

/// An answer that is not the op's success answer, as the report renders
/// it: `Rejected(code)` for a refusal, else that the answer's shape lies
/// outside the op's contract.
fn refusal(r: &Response) -> String {
    match r {
        Response::Rejected(rej) => format!("Rejected({:?})", rej.code),
        _ => "unexpected response shape".to_string(),
    }
}

/// The end of a READ that compared nothing. A read exists to observe, so
/// each non-null field it carries is one its handler reads (`reads`: its
/// arguments, plus any expectation key it deliberately set aside — an id
/// map, an address list), an annotation ([`ANNOTATION_KEYS`]), or an answer
/// the handler cannot read. Any of the last leaves the op inexpressible,
/// the keys named ("not read: `result`"); `NotCompared`, which no verdict
/// fails on, is left only for a read whose recording kept no answer.
fn compared_nothing(out: &mut OpOutcome, op: &Value, reads: &[&str]) {
    let unread: Vec<String> = op
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(k, v)| {
            !v.is_null() && !reads.contains(&k.as_str()) && !ANNOTATION_KEYS.contains(&k.as_str())
        })
        .map(|(k, _)| format!("`{k}`"))
        .collect();
    if unread.is_empty() {
        out.status = Status::NotCompared;
    } else {
        inexpressible(out, format!("not read: {}", unread.join(", ")));
    }
}

/// Policy `joint-absence`: the golden recorded a FAILURE
/// (`recorded_failure`) against a document reference that was never created
/// in this scenario (green's OPEN validates nothing — A7 — so its scripts
/// could aim ops at garbage docids and fail at first use). The reference
/// has no α-image, so there is nothing to address on skep either: both
/// systems refuse the object, compared as agreement. Peek only — α's
/// never-bound finding is deliberately not emitted, because the absence IS
/// the expected answer here, not a translation the harness needed and
/// missed. Returns `true` when the outcome was written.
fn joint_absence(
    cx: &Cx,
    out: &mut OpOutcome,
    recorded_failure: Option<&str>,
    docref: &str,
) -> bool {
    if recorded_failure.is_none()
        || cx.shadow.knows(docref)
        || cx.alpha.peek_translate(docref).is_some()
    {
        return false;
    }
    out.adaptations.push("joint-absence".into());
    out.agree("expected-failure");
    out.add_note(format!(
        "golden recorded failure and `{docref}` was never created — no α-image, nothing to \
         address on skep; both systems refuse the object"
    ));
    true
}

/// skep gave the op's success answer, reconciled with the failure the golden
/// recorded (`recorded_failure`, if any). `true` when the golden recorded
/// success too and the caller goes on to compare; `false` when it recorded a
/// failure, which is then the op's disagreement.
fn settle_accepted(out: &mut OpOutcome, recorded_failure: Option<String>) -> bool {
    match recorded_failure {
        None => true,
        Some(err) => {
            let expected = format!("failure: {err:?}");
            let actual = "skep accepted the operation".to_string();
            out.disagree("expected-failure", Disagreement { expected, actual });
            false
        }
    }
}

/// skep refused the op — `refused`, the refusal as the report renders it —
/// reconciled with the failure the golden recorded (`recorded_failure`):
/// agreement when the golden recorded a failure too, else the op's
/// disagreement.
fn settle_rejected(out: &mut OpOutcome, recorded_failure: Option<String>, refused: String) {
    match recorded_failure {
        Some(_) => {
            out.agree("expected-failure");
            out.add_note(format!("both sides failed (skep: {refused})"));
        }
        None => {
            let expected = "success (golden recorded no error)".to_string();
            out.disagree("rejection", Disagreement { expected, actual: refused });
        }
    }
}

/// skep's answer was not the op's success answer — the counterpart of
/// [`settle_accepted`]. A refusal is reconciled with the failure the golden
/// recorded ([`settle_rejected`]); any other answer lies outside skep's
/// contract and disagrees whatever the golden recorded.
fn settle_unaccepted(out: &mut OpOutcome, recorded_failure: Option<String>, r: &Response) {
    match r {
        Response::Rejected(_) => settle_rejected(out, recorded_failure, refusal(r)),
        _ => {
            let expected = "the op's success answer".to_string();
            out.disagree("response", Disagreement { expected, actual: refusal(r) });
        }
    }
}

/// How an op judged part by part — documents, positions, slots, steps,
/// hops — becomes one status. Every such handler folds through this, so
/// `Agreed` always means "compared, and every comparison matched", and a
/// part the recording names that could not be aimed at skep is never
/// silently dropped.
#[derive(Debug, Default)]
struct Tally {
    /// Parts compared, agreeing or not.
    compared: usize,
    /// The disagreeing parts.
    disagreements: Vec<Disagreement>,
    /// The parts that could not be aimed, each with its reason.
    unaimed: Vec<String>,
}

impl Tally {
    /// A part compared, and matching.
    fn agree(&mut self) {
        self.compared += 1;
    }

    /// A part compared, and disagreeing.
    fn differ(&mut self, d: Disagreement) {
        self.compared += 1;
        self.disagreements.push(d);
    }

    /// A part a comparator judged, both sides of a disagreement labelled
    /// with the part's `label`.
    fn judge(&mut self, c: Comparison, label: &str) {
        match c {
            Ok(()) => self.agree(),
            Err(d) => self.differ(Disagreement {
                expected: format!("{label}{}", d.expected),
                actual: format!("{label}{}", d.actual),
            }),
        }
    }

    /// A part judged as an op of its own — an interior-typing step, a
    /// traversal hop, one source of a per-source comparison — folded in as
    /// one part: its disagreement's expected side labelled, its
    /// inexpressibility unaimed, and its adaptations and note carried up to
    /// `parent`, so an adjustment that made the part agree
    /// ([`WIDTH_ADJUSTED`](crate::allowlist::WIDTH_ADJUSTED)) reaches the op
    /// `Allowlist::classify` judges. A part that disagreed with no rendered
    /// disagreement (a never-bound address) offers its note as skep's side.
    fn absorb(&mut self, parent: &mut OpOutcome, part: OpOutcome, label: &str) {
        parent.adaptations.extend(part.adaptations);
        let mut note = part.note;
        match (part.status, part.disagreement) {
            (Status::Disagreed, Some(Disagreement { expected, actual })) => {
                self.differ(Disagreement { expected: format!("{label}{expected}"), actual })
            }
            (Status::Disagreed, None) => {
                let actual = note.take().unwrap_or_default();
                self.differ(Disagreement { expected: label.to_string(), actual })
            }
            (Status::Inexpressible, _) => {
                let reason = note.take().unwrap_or_default();
                self.unaimed(format!("{label}{reason}"))
            }
            (Status::Agreed, _) => self.agree(),
            (Status::NotCompared | Status::Meta, _) => {}
        }
        // Evidence the part noted and the fold did not spend travels with it.
        if let Some(n) = note {
            parent.add_note(n);
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
    fn settle(self, out: &mut OpOutcome, comparator: &'static str) {
        let not_aimed =
            (!self.unaimed.is_empty()).then(|| format!("not aimed: {}", self.unaimed.join("; ")));
        if !self.disagreements.is_empty() {
            let (expected, actual): (Vec<String>, Vec<String>) =
                self.disagreements.into_iter().map(|d| (d.expected, d.actual)).unzip();
            let (expected, actual) = (expected.join(" | "), actual.join(" | "));
            out.disagree(comparator, Disagreement { expected, actual });
            if let Some(u) = not_aimed {
                out.add_note(u);
            }
        } else if let Some(u) = not_aimed {
            inexpressible(out, u);
        } else if self.compared > 0 {
            out.agree(comparator);
        } else {
            out.status = Status::NotCompared;
        }
    }

    /// [`Tally::settle`] for a READ (`reads`: its handler's arguments):
    /// where nothing was compared and nothing failed to aim, the end is
    /// [`compared_nothing`]'s — a recorded answer the read could not reach
    /// leaves the op inexpressible.
    fn settle_read(
        self,
        out: &mut OpOutcome,
        comparator: &'static str,
        op: &Value,
        reads: &[&str],
    ) {
        if self.compared == 0 && self.unaimed.is_empty() {
            compared_nothing(out, op, reads);
        } else {
            self.settle(out, comparator);
        }
    }
}

impl Cx<'_> {
    /// The op's document argument, read by `fields::aim_doc` — the one
    /// reading the grounding pre-pass shares — and tagged here: a token of
    /// the op's name is `doc-from-op-name`, the register
    /// `doc-from-register`. An explicit reference that resolves to nothing
    /// is surfaced in the op's note, never silently re-aimed at whatever the
    /// register held; a scenario with no document yet gets a first-touch
    /// document, created through skep.
    fn doc_arg(&mut self, op: &Value, out: &mut OpOutcome, keys: &[&str]) -> Option<String> {
        match aim_doc(self.shadow, op, keys) {
            DocAim::Named(d) => Some(d),
            DocAim::FromOpName(d) => {
                out.adaptations.push("doc-from-op-name".into());
                Some(d)
            }
            DocAim::Register(d) => {
                out.adaptations.push("doc-from-register".into());
                Some(d)
            }
            DocAim::Unresolved(s) => {
                out.add_note(format!("document reference `{s}` resolves to nothing"));
                None
            }
            DocAim::FirstTouch => {
                let id = self.shadow.synthesize_docid();
                match self.create_document(&id, None, Effect::Inferred) {
                    Response::AckAddr { .. } => {
                        out.adaptations.push("implied-create:first-touch".into());
                        Some(id)
                    }
                    _ => None,
                }
            }
        }
    }

    fn skep_doc(&mut self, golden: &str) -> Option<skep_address::Address> {
        self.alpha.translate(golden)
    }

    /// Execute one reconstruction step (lead-in or expansion plan) through
    /// the world-change methods: inferred setup is golden-side by
    /// construction (`Effect::Inferred`), so it is mirrored whatever skep
    /// answers.
    fn exec_setup_step(&mut self, step: &SetupStep) -> Result<(), String> {
        let refused = |what: String, r: &Response| format!("{what}: {}", refusal(r));
        match step {
            SetupStep::Insert { doc, bytes } => {
                let at = VPoint::content(self.shadow.text_len(doc) + 1);
                match self.insert(doc, at, bytes, Effect::Inferred) {
                    Err(NeverBound(g)) => Err(format!("setup insert: {g} never bound")),
                    Ok(Response::AckAddr { .. }) => Ok(()),
                    Ok(r) => Err(refused(format!("setup insert into {doc}"), &r)),
                }
            }
            SetupStep::Copy { doc, src, ord, width } => {
                if *width == 0 {
                    return Err("setup copy: empty span".into());
                }
                let at = self.shadow.text_len(doc) + 1;
                let region = VPoint::content(*ord).region(*width);
                let source = CopySource { doc: src.clone(), region };
                match self.copy(doc, at, &[source], Effect::Inferred) {
                    Err(
                        CopyNeverBound::Source(NeverBound(g))
                        | CopyNeverBound::Destination(NeverBound(g)),
                    ) => Err(format!("setup copy: {g} never bound")),
                    Ok(Response::Ack { .. }) => Ok(()),
                    Ok(r) => Err(refused(format!("setup copy into {doc}"), &r)),
                }
            }
            SetupStep::Link { from, to, golden } => {
                let sides =
                    |cx: &mut Cx, list: &[(String, u64, u64)]| -> Result<Vec<VSpec>, String> {
                        let mut specs = Vec::new();
                        for (doc, ord, w) in list {
                            let sd = cx
                                .skep_doc(doc)
                                .ok_or_else(|| format!("setup link: {doc} never bound"))?;
                            let span = VPoint::content(*ord)
                                .region(*w)
                                .span()
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
                    .ok_or_else(|| "setup link: types document capacity exhausted".to_string())?;
                let link = golden
                    .as_ref()
                    .map(|g| ShadowLink { golden: g.clone(), from: from.clone(), to: to.clone() });
                match self.make_link(&home_golden, [f, t, vec![ty]], link, None, Effect::Inferred)
                {
                    Err(NeverBound(h)) => Err(format!("setup link: home {h} never bound")),
                    Ok(Response::AckAddr { .. }) => Ok(()),
                    Ok(r) => Err(refused(format!("setup link in {home_golden}"), &r)),
                }
            }
        }
    }

    /// Golden `doc`'s CONTENT subspace as skep delivers it — every content
    /// span skep's own extent reports ([`Cx::skep_content_spans`]), read in
    /// one RetrieveV (policy `contents:content-subspace`: udanax's
    /// retrieve_contents results never include link-subspace items).
    fn read_content(&mut self, doc: &str) -> Result<Vec<DeliveryItem>, String> {
        let d = self.skep_doc(doc).ok_or_else(|| format!("{doc} never bound"))?;
        let specs: Vec<Spec> = self
            .skep_content_spans(&d)
            .map_err(|r| refusal(&r))?
            .into_iter()
            .map(|span| Spec { doc: d.clone(), span })
            .collect();
        if specs.is_empty() {
            return Ok(Vec::new());
        }
        match self.rig.exec(Op::RetrieveV { specs }) {
            Response::Delivery { items, .. } => Ok(items.0),
            r => Err(refusal(&r)),
        }
    }

    /// The content-subspace spans skep's document `d` holds, from skep's own
    /// extent (`Op::RetrieveDocVSpanSet`): what a whole-document read asks
    /// skep for. Never sized from the shadow — a whole-document read must
    /// see what skep holds beyond the recording, and must ask even when the
    /// recording says the document is empty. skep answers a registered
    /// document's extent with ⟨⟩ when it is empty (M6, ASN-0113), never a
    /// refusal; any answer that is not a span set is returned for the caller
    /// to settle.
    fn skep_content_spans(&self, d: &skep_address::Address) -> Result<Vec<Span>, Box<Response>> {
        let content_subspace = Nat::from(1u64);
        match self.rig.exec(Op::RetrieveDocVSpanSet { doc: d.clone() }) {
            Response::SpanSet { set, .. } => Ok(set
                .iter()
                .filter(|s| s.start().get(1) == Some(&content_subspace))
                .cloned()
                .collect()),
            r => Err(Box::new(r)),
        }
    }

    /// V→I image of a set of golden QUERY regions in one doc (the sanctioned
    /// V→I surface for building query endsets). Content-subspace regions are
    /// clamped to the doc's live extent first — udanax's sparse V tolerated
    /// recorded search spans wider than the content
    /// (find_links_homedocids_multiple queries width 25 over a 20-char doc)
    /// while skep's dense Image rejects them; clamping the QUERY (never a
    /// compared result) is policy `query-clamped-to-extent`, reported via
    /// the returned flag.
    fn image_endset(&mut self, docid: &str, regions: &[VRegion]) -> (Endset, Vec<String>, bool) {
        let mut notes = Vec::new();
        let mut clamped = false;
        let Some(d) = self.alpha.translate(docid) else {
            notes.push(format!("{docid}: never bound"));
            return (Endset::from_spans(std::iter::empty()), notes, clamped);
        };
        let text_len = self.shadow.text_len(docid);
        let region: Vec<Span> = regions
            .iter()
            .filter_map(|r| {
                let (live, cut) = clamp_query(*r, text_len);
                clamped |= cut;
                live?.span()
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
                notes.push(format!("{docid}: image {}", refusal(&r)));
                (Endset::from_spans(std::iter::empty()), notes, clamped)
            }
        }
    }

    /// The whole-content V→I image of one golden doc as rows in V order —
    /// the raw material for identity rendering and transcluded-region
    /// detection.
    fn image_rows(&self, docid: &str) -> Vec<ImageRow> {
        let whole = VPoint::content(1).region(self.shadow.text_len(docid));
        let (Some(d), Some(span)) = (self.alpha.peek_exact(docid), whole.span()) else {
            return Vec::new();
        };
        let Response::Runs { runs, .. } = self.rig.exec(Op::Image { d, region: vec![span] })
        else {
            return Vec::new();
        };
        let mut rows = Vec::new();
        let mut v_ord = 1u64;
        for run in &runs {
            if let Some(iextent) = elem_range(&run.iextent()) {
                rows.push(ImageRow { iextent, v_ord });
            }
            v_ord += u64::try_from(run.width()).unwrap_or(0);
        }
        rows
    }

    /// A golden doc's foreign-origin (transcluded) content regions, as
    /// golden (ordinal, width) V-ranges — a run whose I-prefix does not lie
    /// under the doc's own skep address arrived by COPY.
    fn transcluded_regions_golden(&self, docid: &str) -> Vec<(u64, u64)> {
        let Some(own) = self.alpha.peek_exact(docid) else { return Vec::new() };
        self.image_rows(docid)
            .into_iter()
            .filter(|row| !is_prefix(own.tumbler(), &row.iextent.prefix))
            .map(|row| (row.v_ord, row.iextent.width))
            .collect()
    }
}

/// A recorded QUERY region narrowed to a document's live content extent of
/// `text_len` positions (policy `query-clamped-to-extent`): what of it is
/// live — `None` for a zero width, or a start past the extent — and whether
/// the extent cut it. The end saturates, so a recorded width at the top of
/// the range clamps rather than overflows. A link-subspace region passes as
/// recorded. The one reading every query clamp in the play pass shares.
fn clamp_query(r: VRegion, text_len: u64) -> (Option<VRegion>, bool) {
    if r.width == 0 {
        return (None, false);
    }
    if r.sub != 1 {
        return (Some(r), false);
    }
    if r.ord > text_len {
        return (None, true);
    }
    let last = r.ord.saturating_add(r.width - 1);
    let end = last.min(text_len);
    (Some(VRegion { width: end + 1 - r.ord, ..r }), end < last)
}

/// A contiguous element-level span as numbers: the I-prefix its elements
/// share, the first element's final component under it, and how many
/// elements — the shape `Run::iextent` and recorded content endset spans
/// carry ([`elem_range`]).
#[derive(Clone, Debug, PartialEq, Eq)]
struct ElemRange {
    prefix: Tumbler,
    lo: u64,
    width: u64,
}

impl ElemRange {
    /// One past the last element's final component.
    fn hi(&self) -> u64 {
        self.lo + self.width
    }
}

/// One row of a golden doc's V→I image, as `Cx::image_rows` lists them: its
/// I-extent, as an element range, and the V-ordinal its first element sits
/// at.
#[derive(Clone, Debug)]
struct ImageRow {
    iextent: ElemRange,
    v_ord: u64,
}

/// `s` as an element range — sound exactly for the single-I-extent shape
/// `Run::iextent` and recorded content endset spans carry. `None` for
/// coarser spans.
fn elem_range(s: &Span) -> Option<ElemRange> {
    let width = span_elem_width(s)?;
    let start = s.start();
    let n = start.len();
    if n < 2 {
        return None;
    }
    let lo = last_component(start)?;
    let prefix = Tumbler::new(start.iter().take(n - 1).cloned()).ok()?;
    Some(ElemRange { prefix, lo, width })
}

// ───────────────────── world changes: the shadow's one owner ─────────────────
//
// Every change the play pass makes to the golden-side world goes through
// the methods below, and each follows one rule. The shadow follows the
// RECORDING; α follows skep. A content write is mirrored into the shadow
// first, when its `Effect` reaches the shadow (callers pass `Effect::of` the
// op, or `Effect::Inferred` for the pre-pass's setup) — the shadow itself
// changes only a document it holds, an edit of any other changing nothing —
// and then skep is asked through α, so neither skep's answer nor an α miss
// bends what the shadow holds; a golden reference with no α-image comes
// back as `NeverBound`, and skep was asked nothing. A CREATION's golden name
// enters the shadow, bound in α, only when skep made it and its effect
// reaches the shadow: every document the play pass resolves, and every name
// it binds, has an α-image. A document is minted once: a golden id the
// shadow already holds keeps naming the document it holds, and α's
// double-bind finding reports the clash. A creation skep refuses — a version
// of a private source, PUB-2.9 — therefore leaves its later name-references
// ungroundable, the class rulings 20 and 20a freeze. `tests/it/tidy.rs`
// holds every other play-pass file to changing the shadow's world through
// these methods.

/// A golden reference α holds no image for: the request naming it was never
/// sent to skep.
#[derive(Debug)]
struct NeverBound(String);

/// Why a COPY was never sent: a source, or the destination, has no α-image.
/// The sources are translated first, so a destination that is also a
/// source reports as one.
#[derive(Debug)]
enum CopyNeverBound {
    Source(NeverBound),
    Destination(NeverBound),
}

impl Cx<'_> {
    /// The skep image of golden `golden`, or the reference as never bound.
    fn bound(&mut self, golden: &str) -> Result<skep_address::Address, NeverBound> {
        self.alpha.translate(golden).ok_or_else(|| NeverBound(golden.to_string()))
    }

    /// CREATENEWDOCUMENT for golden `golden`, named `name` when the
    /// recording names it. The document enters the shadow, `golden` bound
    /// in α, when skep made it and `effect` reaches the shadow. The caller
    /// owes that the shadow does not hold `golden` yet ([`ensure_document`]
    /// asks first): a document is minted once.
    fn create_document(&mut self, golden: &str, name: Option<&str>, effect: Effect) -> Response {
        let r = self.rig.create_private_document();
        if let (true, Response::AckAddr { addr, .. }) = (effect.reaches_shadow(), &r) {
            self.alpha.bind(golden, addr);
            self.shadow.create_doc(golden, name);
        }
        r
    }

    /// VERSION of golden `src`, recorded as golden `golden` when the
    /// recording kept the result. When skep made it and `effect` reaches the
    /// shadow, `golden` binds in α; and unless the shadow already holds
    /// `golden` — another document, which α's double-bind finding then
    /// reports — the version enters the shadow, each of `names` (the op's
    /// own names for the new version) that is no address and names no
    /// document yet coming to name it.
    fn create_version(
        &mut self,
        src: &str,
        golden: Option<&str>,
        names: &[&str],
        effect: Effect,
    ) -> Result<Response, NeverBound> {
        let d_src = self.bound(src)?;
        let r = self.rig.exec(Op::Version { d_src, published: None });
        let made = effect.reaches_shadow();
        if let (true, Response::AckAddr { addr, .. }, Some(g)) = (made, &r, golden) {
            self.alpha.bind(g, addr);
            if !self.shadow.knows(g) {
                self.shadow.version(src, g);
                for n in names {
                    if parse_dotted(n).is_none() && self.shadow.resolve_doc(n).is_none() {
                        self.shadow.bind_name(n, g);
                    }
                }
            }
        }
        Ok(r)
    }

    /// Name golden document `golden` `name`, when the shadow holds it; a
    /// document it does not hold — skep refused it, or the recording says
    /// udanax never made it — is named nothing, so every name the play pass
    /// resolves has an α-image. The first binding of a name stands
    /// (`Shadow::bind_name`).
    fn name_document(&mut self, golden: &str, name: &str) {
        if self.shadow.knows(golden) {
            self.shadow.bind_name(name, golden);
        }
    }

    /// INSERT `bytes` at `at` in golden `doc`, a content-subspace insert
    /// mirrored first.
    fn insert(
        &mut self,
        doc: &str,
        at: VPoint,
        bytes: &[u8],
        effect: Effect,
    ) -> Result<Response, NeverBound> {
        if at.sub == 1 && effect.reaches_shadow() {
            self.shadow.insert(doc, at.ord, bytes);
        }
        let d = self.bound(doc)?;
        let values: Vec<Val> = bytes.iter().map(|b| Val::new(vec![*b])).collect();
        Ok(self.rig.exec(Op::Insert {
            doc: d,
            at: at.vpos(),
            values,
            deposit: Deposit::Undeclared,
        }))
    }

    /// COPY the golden `sources` to content ordinal `ord` of golden `doc`,
    /// the copied content-subspace bytes mirrored first.
    fn copy(
        &mut self,
        doc: &str,
        ord: u64,
        sources: &[CopySource],
        effect: Effect,
    ) -> Result<Response, CopyNeverBound> {
        if effect.reaches_shadow() {
            let bytes: Vec<u8> = sources
                .iter()
                .filter(|s| s.region.sub == 1)
                .flat_map(|s| self.shadow.slice(&s.doc, s.region.ord, s.region.width))
                .collect();
            self.shadow.insert(doc, ord, &bytes);
        }
        let mut specs = Vec::new();
        for s in sources {
            let source = self.bound(&s.doc).map_err(CopyNeverBound::Source)?;
            if let Some(span) = s.region.span() {
                specs.push(VSpec { source, span });
            }
        }
        let d = self.bound(doc).map_err(CopyNeverBound::Destination)?;
        Ok(self.rig.exec(Op::Copy { doc: d, at: VPoint::content(ord).vpos(), specs }))
    }

    /// DELETE `region` of golden `doc`, a content-subspace delete mirrored
    /// first. The deletion history (ruling 10) is golden-side too: for a
    /// content-subspace delete whose effect reaches the shadow, just before
    /// skep is asked, the doomed region's I-extents are imaged — while the
    /// arrangement still speaks for them — into the scenario's history of
    /// deleted content; an image failure is swallowed, and a later
    /// I-coverage search over the missing record fails to ground, surfacing
    /// as its own honest outcome.
    fn delete(
        &mut self,
        doc: &str,
        region: VRegion,
        effect: Effect,
    ) -> Result<Response, NeverBound> {
        let mirrored = region.sub == 1 && effect.reaches_shadow();
        let removed = if mirrored {
            let removed = self.shadow.slice(doc, region.ord, region.width);
            self.shadow.delete(doc, region.ord, region.width);
            removed
        } else {
            Vec::new()
        };
        let d = self.bound(doc)?;
        let imaged = VRegion { width: removed.len() as u64, ..region };
        if let Some(span) = imaged.span() {
            if let Response::Runs { runs, .. } =
                self.rig.exec(Op::Image { d: d.clone(), region: vec![span] })
            {
                self.deletions.record(doc, removed, runs.iter().map(Run::iextent).collect());
            }
        }
        let p = region.at().vpos();
        Ok(self.rig.exec(Op::Delete { doc: d, p, width: Nat::from(region.width) }))
    }

    /// REARRANGE golden `doc` at content `cuts` — three cuts pivot, four
    /// swap — mirrored first.
    fn rearrange(
        &mut self,
        doc: &str,
        cuts: &[u64],
        effect: Effect,
    ) -> Result<Response, NeverBound> {
        if effect.reaches_shadow() {
            match *cuts {
                [a, b, c] => self.shadow.pivot(doc, a, b, c),
                [s1, e1, s2, e2] => self.shadow.swap(doc, s1, e1, s2, e2),
                _ => {}
            }
        }
        let d = self.bound(doc)?;
        let cuts = cuts.iter().map(|&c| VPoint::content(c).vpos()).collect();
        Ok(self.rig.exec(Op::Rearrange { doc: d, cuts }))
    }

    /// MAKELINK homed in golden `home` over endsets already resolved
    /// through α, in M7's slot order: FROM, TO, TYPE. When skep made the
    /// link and `effect` reaches the shadow, it enters the shadow: seated
    /// in its home, the register moved there; with the recorded `link`, its
    /// golden id bound in α, made the last link and recorded for traversal
    /// with the golden content endsets it was grounded with; and the
    /// recorded arrow edge, `(from-name, to-name, link id)`.
    fn make_link(
        &mut self,
        home: &str,
        slots: [Vec<VSpec>; 3],
        link: Option<ShadowLink>,
        arrow: Option<(String, String, String)>,
        effect: Effect,
    ) -> Result<Response, NeverBound> {
        let h = self.bound(home)?;
        let [from, to, ty] = slots;
        let r = self.rig.exec(Op::MakeLink {
            home: h,
            from: SlotArg::Resolve(from),
            to: SlotArg::Resolve(to),
            ty: SlotArg::Resolve(ty),
            replaces: None,
        });
        if let (true, Response::AckAddr { addr, .. }) = (effect.reaches_shadow(), &r) {
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

/// Golden document `id`, for an op that records it: when the shadow already
/// holds it (an implied create, or a plan's earlier step), `name` names it
/// and the register moves to it; else skep is asked to create it
/// ([`Cx::create_document`]). `Ok` when the shadow held it, or skep made it —
/// whether or not the creation's effect reaches the shadow: one the
/// recording says udanax never made stays unheld and unnamed, and the
/// caller settles the op against that recorded failure. `Err` is skep's
/// answer to a creation it did not acknowledge, for the caller to settle.
fn ensure_document(
    cx: &mut Cx,
    id: &str,
    name: Option<&str>,
    effect: Effect,
) -> Result<(), Box<Response>> {
    if cx.shadow.knows(id) {
        if let Some(n) = name {
            cx.name_document(id, n);
        }
        cx.shadow.set_current(id);
        return Ok(());
    }
    match cx.create_document(id, name, effect) {
        Response::AckAddr { .. } => Ok(()),
        r => Err(Box::new(r)),
    }
}

/// Execute the pre-pass expansion plan attached to op `index` — every step
/// of it — and tag the op `expansion-plan:N`. A step skep refuses, or one
/// naming a document with no α-image, does not stop the rest: the shadow
/// keeps following the reconstruction. Returns the first failure for the
/// caller to report ([`plan_failed`]); `None` when every step executed.
fn run_plan(cx: &mut Cx, index: usize, out: &mut OpOutcome) -> Option<String> {
    let plans = cx.plans;
    let plan = plans.get(&index).map_or(&[][..], Vec::as_slice);
    out.adaptations.push(format!("expansion-plan:{}", plan.len()));
    let mut first_failure: Option<String> = None;
    for step in plan {
        // Copies/inserts target docs the plan may create implicitly.
        if let SetupStep::Copy { doc, .. } | SetupStep::Insert { doc, .. } = step {
            if !cx.shadow.knows(doc) {
                if let Err(r) = ensure_document(cx, doc, None, Effect::Inferred) {
                    first_failure.get_or_insert(format!("create {doc}: {}", refusal(&r)));
                }
            }
        }
        if let Err(e) = cx.exec_setup_step(step) {
            first_failure.get_or_insert(e);
        }
    }
    first_failure
}

/// A reconstructed plan that did not execute is the op's disagreement.
fn plan_failed(out: &mut OpOutcome, failure: String) {
    let expected = "reconstructed setup executes".to_string();
    out.disagree("expansion-plan", Disagreement { expected, actual: failure });
}

/// The pre-pass's implied setup, carried out before op 0 through the
/// world-change methods — inferred, so golden-side by construction: each
/// implied create, then each lead-in step, its document created first when
/// the shadow does not hold it; then the register returns to the first
/// document the scenario names. Returns a line for each part skep did not
/// carry out, for the groundings; nothing stops the run, and the ops that
/// depend on a part that failed then disagree honestly.
pub fn run_lead_in(cx: &mut Cx, setup: &ImpliedSetup) -> Vec<String> {
    let mut failures = Vec::new();
    for docid in &setup.implied_creates {
        if cx.alpha.peek_exact(docid).is_some() {
            continue; // already bound (defensive; should not happen)
        }
        let r = cx.create_document(docid, None, Effect::Inferred);
        if !matches!(r, Response::AckAddr { .. }) {
            failures.push(format!("implied-create FAILED for {docid}: {}", brief(&r)));
        }
    }
    'lead_in: for step in &setup.lead_in {
        // Lead-in inserts may target docs the scenario creates itself
        // later only via implied paths; ensure existence first. (Link
        // steps live in expansion plans, never the lead-in, but the
        // match stays total.)
        if let SetupStep::Insert { doc, .. } | SetupStep::Copy { doc, .. } = step {
            if !cx.shadow.knows(doc) {
                let r = cx.create_document(doc, None, Effect::Inferred);
                if !matches!(r, Response::AckAddr { .. }) {
                    failures.push(format!("lead-in create FAILED for {doc}: {}", brief(&r)));
                    continue 'lead_in;
                }
            }
        }
        if let Err(e) = cx.exec_setup_step(step) {
            failures.push(format!("lead-in FAILED: {e}"));
        }
    }
    // The register belongs to the first document the SCENARIO names,
    // not the last lead-in target.
    if let Some(first) = cx.shadow.created().first().cloned() {
        cx.shadow.set_current(&first);
    }
    failures
}

// ────────────────────────────── endset sides ───────────────────────────────

/// One endset side resolved to golden (doc, regions) pairs.
fn side_specs(cx: &mut Cx, out: &mut OpOutcome, v: &Value) -> Result<Vec<DocSpans>, String> {
    if let Some(arr) = v.as_array() {
        let mut sides = Vec::new();
        for item in arr {
            if let Some((docid, regions)) = vspec_dict(item) {
                sides.push((docid, regions));
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
        return Ok(vec![(doc, vec![VPoint::content(1).region(n)])]);
    }
    match locate(cx.shadow, None, s) {
        Some(l) => {
            out.adaptations.push(l.how.tag().into());
            let region = l.region();
            Ok(vec![(l.doc, vec![region])])
        }
        None => Err(format!("endset text {s:?} not found")),
    }
}

/// One recorded endset span: a normal V-region, or the udanax type-marker
/// local address `1.0.2.X…` (client.py's LINK_TYPES encoding — 4-plus
/// components that are not a V-position).
#[derive(Debug)]
enum SetSpan {
    Plain(VRegion),
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
            if let Some(region) = span_dict(sp) {
                spans.push(SetSpan::Plain(region));
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Probe {
    /// Observation bundle (initial_state, after_first_insert…): the reply
    /// a read's recording answers with (`fields::recorded_content`). A
    /// bundle is a read, and settles as one (`Tally::settle_read`).
    Bundle,
    /// After a write (insert/delete/vcopy): only the post-write keys
    /// (`fields::POST_WRITE_KEYS`) are expectations.
    PostWrite,
    /// One interior-typing step entry: its own vspanset/contents fields.
    Step,
}

/// The arguments an observation bundle carries: the document it observes.
const BUNDLE_READS: &[&str] = &["doc", "docid", "doc_label"];

/// A state probe: compare whatever vspanset/contents data the op (or one
/// interior-typing step) carries against the doc's live state.
fn probe_state(
    cx: &mut Cx,
    op: &Value,
    out: &mut OpOutcome,
    adjustments: &Adjustments,
    doc: &str,
    kind: Probe,
) {
    let mut tally = Tally::default();

    // Vspanset-shaped expectation.
    let recorded = match kind {
        Probe::Step => {
            op.get("vspanset").and_then(raw_spanset_of).map(|(d, s)| ("vspanset".to_string(), d, s))
        }
        _ => recorded_spanset(op),
    };
    if let Some((key, docid, spans)) = recorded {
        let target =
            docid.and_then(|d| cx.shadow.resolve_doc(&d)).unwrap_or_else(|| doc.to_string());
        match cx.skep_doc(&target) {
            Some(d) => match cx.rig.exec(Op::RetrieveDocVSpanSet { doc: d }) {
                Response::SpanSet { set, .. } => {
                    let c = compare_spansets(&spans, &set, adjustments, &mut out.adaptations);
                    if c.is_err() && is_collapsed_subspace_shape(&spans) {
                        out.note = Some(COLLAPSED_SUBSPACE_ANALYSIS.to_string());
                    }
                    tally.judge(c, "vspanset ");
                }
                r => {
                    let actual = refusal(&r);
                    tally.differ(Disagreement { expected: "vspanset".into(), actual })
                }
            },
            None => tally.differ(Disagreement {
                expected: format!("{key} of {target}"),
                actual: format!("{target} never bound"),
            }),
        }
    }

    // Contents expectation: the reply, and for a bundle the key it lives
    // under — an address list or a client repr there is set aside, not
    // compared, and not an unread answer either.
    let (reply_key, strings) = match kind {
        Probe::Step => (None, field(op, &["contents", "content"]).and_then(strings_of)),
        Probe::PostWrite => (None, field(op, POST_WRITE_KEYS).and_then(strings_of)),
        Probe::Bundle => match recorded_content(op, BUNDLE_READS) {
            Some((k, strings)) => (Some(k), Some(strings)),
            None => (None, None),
        },
    };
    let mut set_aside: Vec<String> = Vec::new();
    if let Some(strings) = strings {
        if as_text(&strings).is_some() {
            match cx.read_content(doc) {
                Ok(items) => tally.judge(compare_content(&strings, &items, cx.alpha), "content "),
                Err(code) => {
                    tally.differ(Disagreement { expected: "content".into(), actual: code })
                }
            }
        } else {
            set_aside.extend(reply_key);
        }
    }

    match kind {
        Probe::Bundle => {
            let mut reads = BUNDLE_READS.to_vec();
            reads.extend(set_aside.iter().map(String::as_str));
            tally.settle_read(out, "state-probe", op, &reads);
        }
        Probe::PostWrite | Probe::Step => tally.settle(out, "state-probe"),
    }
}

// ────────────────────────────── the catalogue ──────────────────────────────

/// Play one golden operation: its name normalized to a verb, executed on
/// skep, compared — its one `OpOutcome`, for every op it plays to an end. A
/// panic raised while it plays, skep's or the harness's, leaves it instead,
/// for the runner to stop the scenario at this op.
pub fn run_op(cx: &mut Cx, index: usize, op: &Value, adjustments: &Adjustments) -> OpOutcome {
    let name = op_name(op).to_string();
    let mut out = OpOutcome::new(index, &name);
    if name.is_empty() {
        // A recorder ANNOTATION entry ({note: "…"} with no op at all,
        // ms_create_race) is commentary, not an operation — meta. Anything
        // else without an `op` field stays inexpressible.
        let annotation_only = op.as_object().is_some_and(|o| {
            !o.is_empty()
                && o.keys().all(|k| matches!(k.as_str(), "note" | "comment" | "description"))
        });
        if annotation_only {
            out.verb = Verb::Meta.name();
            out.status = Status::Meta;
            out.note = str_field(op, &["note", "comment", "description"]).map(str::to_string);
            return out;
        }
        inexpressible(&mut out, "operation has no `op` field".into());
        return out;
    }
    // Raw wire request codes (prov_request_surface): green's dispatch-table
    // probe. skep's surface is typed `Op`s — an unknown code is the
    // TRANSPORT's `OpKind::Unparseable`, unreachable from the library
    // harness — so the op is inexpressible by construction, code recorded.
    if name == "raw_request" {
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
    let Some(verb) = normalize(&name, op) else {
        let keys: Vec<&str> =
            op.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        inexpressible(&mut out, format!("op `{name}` (fields {keys:?}) has no canonical verb"));
        return out;
    };
    out.verb = verb.name();
    // Multi-session routing: an op carrying a `session` label executes under
    // that label's account session (policy `session-route`). `account` binds
    // labels itself and `connect`/meta execute nothing, so they skip routing;
    // ops without the field leave the working session untouched, so
    // single-session scenarios are undisturbed.
    if !matches!(verb, Verb::Account | Verb::Connect | Verb::Meta) {
        if let Some(session_label) = str_field(op, &["session"]) {
            match cx.rig.route_session(session_label) {
                Ok(implicit) => {
                    out.adaptations.push(format!("session-route:{session_label}"));
                    if implicit {
                        out.adaptations.push("session-label-implicit-bind".into());
                    }
                }
                Err(e) => {
                    let expected = format!("op executes under session {session_label}");
                    out.disagree("session", Disagreement { expected, actual: e });
                    return out;
                }
            }
        }
    }
    match verb {
        Verb::Meta => out.status = Status::Meta,
        Verb::Observe => h_observe(cx, index, op, &mut out, adjustments),
        Verb::Setup => h_setup(cx, index, &mut out),
        Verb::CreateDocument => h_create_document(cx, op, &mut out),
        Verb::CreateDocuments => h_create_documents(cx, index, op, &mut out),
        Verb::CreateChain => h_create_chain(cx, index, op, &mut out),
        Verb::OpenDocument => h_open_document(cx, op, &mut out),
        Verb::CloseDocument => {
            out.adaptations.push("close_document:noop".into());
            out.status = Status::NotCompared;
        }
        Verb::Insert => h_insert(cx, index, op, &mut out, adjustments),
        Verb::InsertLoop => h_insert_loop(cx, op, &mut out, adjustments),
        Verb::InteriorTyping => h_interior_typing(cx, op, &mut out, adjustments),
        Verb::Delete | Verb::DeleteAll => h_delete(cx, index, op, &mut out, adjustments, verb),
        Verb::Vcopy => h_vcopy(cx, index, op, &mut out, adjustments),
        Verb::Pivot => h_rearrange(cx, op, &mut out, Rearrangement::Pivot),
        Verb::Swap => h_rearrange(cx, op, &mut out, Rearrangement::Swap),
        Verb::Rearrange => {
            let n = cuts_of(op).len();
            match Rearrangement::with_cuts(n) {
                Some(shape) => h_rearrange(cx, op, &mut out, shape),
                None => inexpressible(
                    &mut out,
                    format!("rearrange needs 3 or 4 cuts, could derive {n}"),
                ),
            }
        }
        Verb::CreateVersion => h_create_version(cx, op, &mut out),
        Verb::CreateLink => h_create_link(cx, index, op, &mut out),
        Verb::FollowLink => h_follow_link(cx, op, &mut out, adjustments),
        Verb::Traverse => h_traverse(cx, op, &mut out, adjustments),
        Verb::FindLinks => h_find_links(cx, op, &mut out, adjustments),
        Verb::FindDocuments => h_find_documents(cx, op, &mut out),
        Verb::RetrieveContents => h_retrieve_contents(cx, index, op, &mut out),
        Verb::RetrieveVspan | Verb::RetrieveVspanset => {
            h_retrieve_vspanset(cx, op, &mut out, adjustments, verb)
        }
        Verb::RetrieveEndsets => h_retrieve_endsets(cx, op, &mut out),
        Verb::CompareVersions => h_compare_versions(cx, index, op, &mut out),
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
    use serde_json::json;
    use skep_febe::{OpKind, RejectCode, Rejection};
    use skep_kernel::Seq;

    use super::*;
    use crate::allowlist::WIDTH_ADJUSTED;

    fn settled(tally: Tally) -> OpOutcome {
        let mut out = OpOutcome::new(0, "op");
        tally.settle(&mut out, "parts");
        out
    }

    /// `Agreed` means compared, and every comparison matched: nothing
    /// compared is not compared; a part that could not be aimed leaves the
    /// op inexpressible; a disagreement wins, labelled on both sides, the
    /// unaimed parts noted beside it.
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
        let got = Disagreement { expected: "want".into(), actual: "got".into() };
        differing.judge(Err(got), "part: ");
        let out = settled(differing);
        assert_eq!(out.status, Status::Disagreed);
        let labelled = Disagreement { expected: "part: want".into(), actual: "part: got".into() };
        assert_eq!(out.disagreement, Some(labelled));
        assert_eq!(out.note.as_deref(), Some("not aimed: a part"));
    }

    /// A part judged as an op of its own folds in as one part and carries
    /// what it recorded up to its op: an adjustment that made it agree
    /// leaves its tag where `Allowlist::classify` looks, and its note
    /// survives; a disagreeing part's expected side is labelled; an
    /// inexpressible part is unaimed under its label.
    #[test]
    fn an_absorbed_part_carries_its_adjustment_and_note_up() {
        let mut step = OpOutcome::new(0, "interior_typing");
        step.agree("state-probe");
        step.adaptations.push(WIDTH_ADJUSTED.into());
        step.add_note("step note".into());
        let mut parent = OpOutcome::new(0, "interior_typing");
        let mut tally = Tally::default();
        tally.absorb(&mut parent, step, "step 'X': ");
        tally.settle(&mut parent, "state-probe");
        assert_eq!(parent.status, Status::Agreed);
        assert_eq!(parent.adaptations, [WIDTH_ADJUSTED]);
        assert_eq!(parent.note.as_deref(), Some("step note"));

        let mut hop = OpOutcome::new(0, "traverse");
        hop.disagree("projection", Disagreement { expected: "want".into(), actual: "got".into() });
        let mut lost = OpOutcome::new(0, "traverse");
        lost.status = Status::Inexpressible;
        lost.add_note("no shape".into());
        let mut parent = OpOutcome::new(0, "traverse");
        let mut tally = Tally::default();
        tally.absorb(&mut parent, hop, "1.1: ");
        tally.absorb(&mut parent, lost, "1.2: ");
        tally.settle(&mut parent, "traversal");
        let labelled = Disagreement { expected: "1.1: want".into(), actual: "got".into() };
        assert_eq!(parent.disagreement, Some(labelled));
        assert_eq!(parent.note.as_deref(), Some("not aimed: 1.2: no shape"));
    }

    /// A read that compared nothing is `NotCompared` only when its recording
    /// kept no answer: a field that is neither one of its arguments nor an
    /// annotation is an answer it could not read, named.
    #[test]
    fn a_read_that_compared_nothing_names_the_answer_it_left_unread() {
        let reads = ["doc", "docid"];
        let mut out = OpOutcome::new(0, "retrieve");
        Tally::default().settle_read(
            &mut out,
            "content",
            &json!({"op": "retrieve", "doc": "d", "after_first": ["X"], "comment": "prose"}),
            &reads,
        );
        assert_eq!(out.status, Status::Inexpressible);
        assert_eq!(out.note.as_deref(), Some("not read: `after_first`"));

        let mut out = OpOutcome::new(0, "retrieve");
        let bare = json!({"op": "retrieve", "doc": "d", "label": "x", "session": "A"});
        Tally::default().settle_read(&mut out, "content", &bare, &reads);
        assert_eq!(out.status, Status::NotCompared);
    }

    /// An answer that is not the op's success answer disagrees whatever the
    /// golden recorded unless it is a refusal, which the golden's own
    /// recorded failure meets as agreement.
    #[test]
    fn only_a_refusal_can_meet_a_recorded_failure() {
        let failed = || Some("request failed (?)".to_string());
        let actual = |out: OpOutcome| out.disagreement.map(|d| d.actual);
        let mut out = OpOutcome::new(0, "insert");
        settle_unaccepted(&mut out, failed(), &Response::Ack { at: Seq(1) });
        assert_eq!(out.status, Status::Disagreed);
        assert_eq!(actual(out).as_deref(), Some("unexpected response shape"));

        let rejected = Response::Rejected(Rejection::classified(
            OpKind::Insert,
            RejectCode::OutOfBounds,
            None,
        ));
        let mut out = OpOutcome::new(0, "insert");
        settle_unaccepted(&mut out, failed(), &rejected);
        assert_eq!(out.status, Status::Agreed);
        let mut out = OpOutcome::new(0, "insert");
        settle_unaccepted(&mut out, None, &rejected);
        assert_eq!(out.status, Status::Disagreed);
        assert_eq!(actual(out).as_deref(), Some("Rejected(OutOfBounds)"));
    }

    /// An acceptance meets a recorded failure as a disagreement — the
    /// caller compares nothing — and only a recording of success lets the
    /// caller go on to compare, nothing judged yet.
    #[test]
    fn an_acceptance_meets_a_recorded_failure_as_a_disagreement() {
        let mut out = OpOutcome::new(0, "insert");
        assert!(!settle_accepted(&mut out, Some("request failed (?)".into())));
        assert_eq!(out.status, Status::Disagreed);
        let accepted = Disagreement {
            expected: "failure: \"request failed (?)\"".into(),
            actual: "skep accepted the operation".into(),
        };
        assert_eq!(out.disagreement, Some(accepted));
        let mut out = OpOutcome::new(0, "insert");
        assert!(settle_accepted(&mut out, None));
        assert_eq!(out.status, Status::NotCompared);
    }

    /// A rearrangement's shape is its cut count, both ways.
    #[test]
    fn a_rearrangement_is_named_by_its_cut_count() {
        for shape in [Rearrangement::Pivot, Rearrangement::Swap] {
            assert_eq!(Rearrangement::with_cuts(shape.cuts()), Some(shape));
        }
        assert_eq!(Rearrangement::with_cuts(2), None);
    }

    /// A query region clamps to the live extent without overflowing, a
    /// width at the top of the range included; a region past the extent is
    /// cut away whole, and a link-subspace region passes as recorded.
    #[test]
    fn a_query_region_clamps_without_overflow() {
        let content = |ord: u64, width: u64| VPoint::content(ord).region(width);
        assert_eq!(clamp_query(content(2, u64::MAX), 5), (Some(content(2, 4)), true));
        assert_eq!(clamp_query(content(2, 3), 5), (Some(content(2, 3)), false));
        assert_eq!(clamp_query(content(2, 0), 5), (None, false));
        assert_eq!(clamp_query(content(6, 1), 5), (None, true));
        let link = VPoint { sub: 2, ord: 9 }.region(u64::MAX);
        assert_eq!(clamp_query(link, 5), (Some(link), false));
    }
}
