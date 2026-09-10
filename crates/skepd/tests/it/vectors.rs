//! §2 OF THE CONFORMANCE PACK — THE VECTOR SETS AS MATRICES (PUB round 2,
//! lane 4): each matrix the daemon can answer as one test per row or one
//! parameterized test per matrix, the cell named in the failure message.
//! TESTS ONLY: a red is a SPEC-VS-CODE FINDING, `#[ignore]`d with its
//! assertion intact and its cell named — never a fix.
//!
//! The matrices here: 2.5 (the publish-class gate's input rows, bare and
//! signed), 2.6 (the write-side order, pair by pair), 2.7 (the audit-view
//! class's members by prefix), 2.10's own-rule cells (PUB-6.2, PUB-6.4,
//! PUB-6.24) and 2.11's read-row cells (PUB-6.15's unfiltered answers,
//! PUB-6.50's exempt surfaces). A cell an existing suite already pins is
//! RECORDED here and not walked again.
//!
//! COVERED-BY, recorded rather than duplicated:
//! * 2.5 — the first-mint pair (a flagless or explicit-`true` first mint
//!   honored bare, the explicit-`false` one `mint_home_public`) and the
//!   session-kind axis: `auth_wire.rs`; `version(doc 1, published:false)` →
//!   `private_version_of_published` and a flagless `version` of a draft →
//!   `private_source_versionless`: `version_chain.rs`; the bare owner's
//!   `nullify` of a doc-1-homed record (an empty address, a grant) →
//!   `signed_session_required`, the signed owner's reaching the store:
//!   `nullify_class.rs`.
//! * 2.6 — slot 2's door (`auth_wire.rs`); slot 3 ahead of slot 4 (2.5's
//!   PUB-6.37 cells, this file); slot 4 ahead of slot 5 on a bare
//!   `version(draft, published:true)` and the signed half's
//!   `private_source_versionless` (`version_chain.rs`); the grant-typed
//!   `nullify` pair — bare `signed_session_required`, signed
//!   `nullify_not_revocation` (`nullify_class.rs`); slot 1, 3 and 6 on
//!   `copy`/`make_link`/`edit_link`/`assert_sup` — a stranger's write INTO
//!   the owner's draft `not_owner` ahead of the consult, an unregistered
//!   source `source_not_registered` ahead of it, and the consult's own
//!   `withheld` (`source_gate.rs`); PUB-6.9's ω-first `nullify` target order
//!   (`nullify_class.rs`).
//! * 2.7 — the seven classes, both tokens, the steward's second key, and the
//!   R20 edition class's members (`…3.14`, `…3.14.2`) admitted under the
//!   ACTIVE view: `nullify_class.rs`.
//! * 2.8 — the three refusals and their one-code faces: `version_chain.rs`,
//!   `publish.rs`. 2.9 — PUB-3.19's separating vector (a retracted claim
//!   listed `active:false` under the audit view, absent from the active set):
//!   `publication_reads.rs`.
//! * 2.10 — the first-mint flag pair (`auth_wire.rs`); the `/events` row and
//!   the straddle feed entries (`feed_class.rs`); the grain per-run cell and
//!   the dual row's guest cells (`read_surface.rs`); the emit/assert_sup
//!   dedup cells (`dedup_class.rs`); the layered credential cell
//!   (`auth_wire.rs`, `nullify_class.rs`); the doc-metadata row and
//!   `edition_claims`' consult (`publication_reads.rs`, `read_surface.rs`);
//!   the unregistered-argument cell (`auth_wire.rs`, `read_surface.rs`,
//!   `source_gate.rs`); PUB-6.8/6.9/6.27/6.30/6.49 (`read_surface.rs`,
//!   `nullify_class.rs`, `dedup_class.rs`, `history.rs`); the `window_*`
//!   paging and `/changes?under=` rows (`read_surface.rs`, `feed_class.rs`);
//!   PUB-8.1's composite cell (`publish.rs`); the three oracles
//!   (`feed_class.rs`, `publication_reads.rs`).
//! * 2.11 — the link-address row (`read_surface.rs`, `source_gate.rs`,
//!   `h1_residue.rs`).
//!
//! COPY — not the daemon's: 2.1 (the loss face), 2.2 (the singular face),
//! 2.3 (the rail copy), 2.4 (the rail's exempt rows: no rail is consulted
//! here), 2.5's split faces, 2.12–2.15 (the ceremony's origin classes,
//! remedies, born-published class table and the adopt's target). The daemon
//! carries codes, sites and dispositions, never a face. UNOBSERVABLE: the
//! I-addressed-value-read row (AUTH's op, not landed); PUB-6.11's `emit`
//! endpoint cell (the one open `emit` class is Unary — its `to` is empty by
//! shape, so no endpoint can be named); 2.9's audit/active, published-journal
//! and succession-pair vectors (client derivations over records the daemon
//! refuses to retract); the `show_deletions` row's non-empty instance
//! (PUB-6.15) — a published arrangement never loses a run, so over two
//! published arguments both halves are empty by construction and only the
//! answer's shape and class-invariance can be pinned (2.11, below).

use crate::common;

use std::collections::BTreeSet;

use common::*;
use serde_json::{json, Value};

/// Walk a table of `(cell, token, frame, expected verdict)` and report every
/// divergence at once, cell by cell.
fn walk(port: u16, matrix: &str, cells: &[(&str, &str, String, &str)]) {
    let mut mismatches: Vec<String> = Vec::new();
    for (cell, token, frame, expected) in cells {
        let got = verdict(&op(port, Some(*token), frame));
        if got.as_str() != *expected {
            mismatches.push(format!("  {cell}: expected {expected}, got {got}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "FINDING ({matrix}): {} of {} cells diverge from the spec's table:\n{}",
        mismatches.len(),
        cells.len(),
        mismatches.join("\n")
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 2.5 — the publish-class gate's input rows (PUB-6.43)
// ═══════════════════════════════════════════════════════════════════════

/// 2.5 — PUB-6.43's four input rows × {bare, signed} and PUB-6.37's
/// registered-only evaluation: an explicit flag is the argument itself; a
/// flagless `version` reads `published(d_src)`; a write homed in an existing
/// document reads `published(home)` — every homed op kind alike; a
/// `nullify` reads `published(home) ∨ published(document_of(target))`. The
/// refusal is ONE code; the split faces are the client's.
#[test]
fn m2_5_the_publish_class_gate_s_input_rows_bare_and_signed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let (sg, br) = (signed.as_str(), bare.as_str());
    let draft = owner_draft(port, br);
    let draft_link = ghost_link(port, br, &draft, 1);
    let pub_a = ghost_link(port, sg, CLAIMANT_DOC1, 1);
    let pub_b = ghost_link(port, sg, CLAIMANT_DOC1, 2);
    let never = format!("{CLAIMANT_ACCOUNT}.0.99");
    let ordinal = next_content_ordinal(port, None, CLAIMANT_DOC1);

    let cells: Vec<(&str, &str, String, &str)> = vec![
        // ── row 1: an EXPLICIT flag — the argument itself, resolved pre-dispatch ──
        ("row 1: create published:true, bare", br, create_frame(CLAIMANT_ACCOUNT, Some(true)), GATED),
        ("row 1: create published:true, signed", sg, create_frame(CLAIMANT_ACCOUNT, Some(true)), "ok"),
        ("row 1: create published:false, bare — a draft, outside the gate", br, create_frame(CLAIMANT_ACCOUNT, Some(false)), "ok"),
        ("row 1: fork published:true, bare", br, fork_frame(Some(true)), GATED),
        ("row 1: fork published:false, bare — a draft", br, fork_frame(Some(false)), "ok"),
        ("row 1: version(doc 1) published:true, bare", br, version_frame(CLAIMANT_DOC1, Some(true)), GATED),
        ("row 1: version(doc 1) published:true, signed", sg, version_frame(CLAIMANT_DOC1, Some(true)), "ok"),
        // ── row 2: a flagless `version` reads published(d_src) ──
        ("row 2: a flagless version of the published doc 1, bare", br, version_frame(CLAIMANT_DOC1, None), GATED),
        ("row 2: a flagless version of the published doc 1, signed", sg, version_frame(CLAIMANT_DOC1, None), "ok"),
        // ── PUB-6.37: published() on REGISTERED addresses only — registration speaks ahead of the gate ──
        ("registration ahead of the gate: an insert into an unregistered document, bare", br, insert_frame(&never, 1, "x", false), "doc_not_registered"),
        ("registration ahead of the gate: a version of an unregistered source, bare", br, version_frame(&never, None), "source_not_registered"),
        ("registration ahead of the gate: a nullify from an unregistered home, bare", br, nullify_frame(&never, &pub_a), "home_not_registered"),
        // ── row 3: a write homed in an existing document reads published(home), whatever the op ──
        ("row 3: a declared deposit into doc 1, bare", br, insert_frame(CLAIMANT_DOC1, ordinal, "x", true), GATED),
        ("row 3: the same deposit, signed", sg, insert_frame(CLAIMANT_DOC1, ordinal, "x", true), "ok"),
        ("row 3: a link homed in doc 1, bare", br, link_frame(CLAIMANT_DOC1, r#"{"addrs":[]}"#, r#"{"addrs":[]}"#, &ghost_ty(CLAIMANT_DOC1, 9)), GATED),
        ("row 3: an emit homed in doc 1, bare", br, emit_frame(CLAIMANT_DOC1), GATED),
        ("row 3: an assert_sup homed in doc 1, bare", br, assert_sup_frame(CLAIMANT_DOC1, &pub_a, &pub_b), GATED),
        ("row 3: an edit_link whose successor lands in doc 1, bare", br, edit_link_frame(&pub_a, CLAIMANT_DOC1, &draft, "[]", &ghost_ty(CLAIMANT_DOC1, 10)), GATED),
        ("row 3: a write homed in a draft, bare — the mode's disclosed cost", br, insert_frame(&draft, 1, "d", false), "ok"),
        // ── row 4: nullify reads published(home) ∨ published(document_of(target)) ──
        ("row 4: nullify — a draft-homed record against a published-homed target, bare", br, nullify_frame(&draft, &pub_b), GATED),
        ("row 4: nullify — a draft-homed record against a draft-homed target: a draft write, bare", br, nullify_frame(&draft, &draft_link), "ok"),
        ("row 4: nullify — a draft-homed record against a published-homed target, signed", sg, nullify_frame(&draft, &pub_b), "ok"),
    ];
    walk(port, "2.5, PUB-6.43's input table", &cells);
    sd.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════
// 2.6 — the write-side order (PUB-6.36)
// ═══════════════════════════════════════════════════════════════════════

/// 2.6 — PUB-6.36's six slots, pair by pair, the pairs no suite pins yet:
/// the destination's `not_owner` (1) ahead of the mint door (2); MINT-FIRST
/// (2) ahead of registration (3) and of the gate (4); ownership (1) ahead of
/// the gate (4) and of the model's refusals (5) — a bare stranger at a
/// published home is told `not_owner`, never to sign and never
/// `published_target`; the gate (4) ahead of the model's refusals (5); and
/// the gate (4) ahead of the per-source consult (6). The pairs an existing
/// suite pins are recorded in the module doc. The one pair the door cannot
/// order (5 ahead of 6) is its own test below.
#[test]
fn m2_6_the_write_side_order_pair_by_pair() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let (sg, br) = (signed.as_str(), bare.as_str());
    let d = draft_with(port, br, "s");
    let pub_l = ghost_link(port, sg, CLAIMANT_DOC1, 1);
    let s = seat_stranger(port, 961);
    let (x_acct, x_sess) = bootstrap_delegate(port, 963); // an EMPTY account
    let never = format!("{CLAIMANT_ACCOUNT}.0.99");

    let cells: Vec<(&str, &str, String, &str)> = vec![
        ("slot 1 ahead of slot 2: the owner's explicit-false first mint into X's EMPTY account", br, create_frame(&x_acct, Some(false)), "not_owner"),
        ("slot 2 ahead of slot 3: X's version of an UNREGISTERED source", x_sess.as_str(), version_frame(&never, None), "credential_refused:mint_home_first"),
        ("slot 2 ahead of slot 4: X's bare version of the published doc 1", x_sess.as_str(), version_frame(CLAIMANT_DOC1, None), "credential_refused:mint_home_first"),
        ("slot 1 ahead of slot 4: a stranger's bare declared deposit into the published doc 1", s.session.as_str(), insert_frame(CLAIMANT_DOC1, 2, "x", true), "not_owner"),
        ("slot 1 ahead of slot 4: a stranger's bare nullify naming the published doc 1 as home", s.session.as_str(), nullify_frame(CLAIMANT_DOC1, &pub_l), "not_owner"),
        ("slot 1 ahead of slot 5: a stranger's undeclared insert into the published doc 1 is never published_target", s.session.as_str(), insert_frame(CLAIMANT_DOC1, 2, "x", false), "not_owner"),
        ("slot 4 ahead of slot 5: the bare owner's in-place edit of doc 1", br, insert_frame(CLAIMANT_DOC1, 2, "x", false), GATED),
        ("slot 4 ahead of slot 6: a bare stranger's copy from the owner's draft into ITS OWN published doc 1", s.session.as_str(), copy_frame(&s.doc1, 1, &d, 1, 1), GATED),
    ];
    walk(port, "2.6, PUB-6.36's write-side order", &cells);
    sd.shutdown();
}

/// 2.6 — slot 5 ahead of slot 6: PUB-6.36 evaluates THE MODEL'S REFUSALS
/// (the in-place advance refusal, PUB-2.11) in slot 5 and the per-source
/// consult (PUB-6.23) in slot 6, so a `copy` from a source the caller may
/// not read INTO a published destination the caller owns answers
/// `published_target`, never `withheld`.
#[test]
fn m2_6_slot_5_the_model_s_refusal_speaks_ahead_of_the_per_source_consult() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let d = draft_with(port, &owner, "s");
    let a = seat_stranger(port, 971);
    let a_signed = hire(port, &signed, CLAIMANT_DOC1, &a.account, 971, &distinct_key(71));

    let v = op(port, Some(&a_signed), &copy_frame(&a.doc1, 1, &d, 1, 1));
    assert_eq!(verdict(&v), "published_target", "2.6: slot 5 speaks ahead of slot 6: {v}");
    sd.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════
// 2.7 — the audit-view-class refusal (PUB-6.64)
// ═══════════════════════════════════════════════════════════════════════

/// 2.7 — the classes are the members' list and a SUBTYPE BY PREFIX is its
/// class's member (L10): the delegator endorsement's `endorse.trust`
/// (`…3.42.2`) answers `nullify_audit_view` to its owner, permanent, and the
/// record stands. (The class list itself, and the R20 edition class's
/// members outside it, are `nullify_class.rs`'s.)
#[test]
fn m2_7_a_subtype_by_prefix_is_its_audit_view_class_s_member() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let (subject, _) = bootstrap_delegate(port, 981);

    let trust = format!("{T_ENDORSE_CLASS}.2");
    let endorsement = acked_addr(&typed_link(port, &signed, CLAIMANT_DOC1, &[CLAIMANT_ACCOUNT], &[subject.as_str()], &trust));
    let v = op(port, Some(&signed), &nullify_frame(CLAIMANT_DOC1, &endorsement));
    assert_eq!(verdict(&v), "credential_refused:nullify_audit_view", "2.7 / L10: endorse.trust is the endorsement class's member: {v}");
    assert_eq!(v["disposition"].as_str(), Some("permanent"), "{v}");
    assert!(!read_link(port, None, &endorsement).is_null(), "nothing was retracted");
    sd.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════
// 2.10 — cells pinned at their own rules
// ═══════════════════════════════════════════════════════════════════════

/// 2.10 / PUB-6.2 — the readability check runs immediately after
/// registration and BEFORE any other validation: a span past a draft's
/// extent, a bad region, an out-of-bounds preview — each answers `withheld`
/// to the guest and to a non-entitled principal, never the extent oracle
/// the owner reaches, and never with a `detail`; and the dual row's reads
/// consult the document first for a stranger as they do for the guest.
#[test]
fn m2_10_the_doc_consult_runs_ahead_of_every_shape_check() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let d = draft_with(port, &owner, "ab");
    let pub_l = ghost_link(port, &signed, CLAIMANT_DOC1, 1);
    let s = seat_stranger(port, 991);

    let past_the_extent: Vec<(&str, String)> = vec![
        ("retrieve_v past the extent", retrieve_frame(&d, 1, 99)),
        ("image past the extent", image_frame(&d, 5, 99)),
        ("show_origin past the extent", show_origin_frame(&d, 5, 9)),
        ("count_v past the extent", format!(r#"{{"op":"count_v",{}}}"#, region(&d, 9, 9))),
        ("window_v past the extent", format!(r#"{{"op":"window_v","cur":null,"n":16,{}}}"#, region(&d, 9, 9))),
        ("retrieve_endsets past the extent", format!(r#"{{"op":"retrieve_endsets",{}}}"#, region(&d, 9, 9))),
        ("delete_orphans past the extent", format!(r#"{{"op":"delete_orphans","d":"{d}","p":{{"subspace":"1","ordinal":"9"}},"width":"9"}}"#)),
    ];
    let withheld_for = |what: &str, token: Option<&str>, frame: &str| {
        let v = op(port, token, frame);
        let rej = expect_resp(&v, "rejected");
        assert_eq!(rej["code"].as_str(), Some("withheld"), "2.10 / PUB-6.2: {what}: existence is the only observable: {v}");
        assert_eq!(rej["site"]["addr"].as_str(), Some(d.as_str()), "{what}: {v}");
        assert!(rej.get("detail").is_none(), "{what}: no detail, ever: {v}");
    };
    for (what, frame) in &past_the_extent {
        withheld_for(what, None, frame);
        withheld_for(what, Some(&s.session), frame);
        let v = op(port, Some(&owner), frame);
        assert_ne!(verdict(&v), "withheld", "{what}: the owner reaches the op's own answer: {v}");
    }
    // The dual row (PUB-6.8) for a STRANGER: the document first (the guest's
    // cells are `read_surface.rs`'s).
    for (what, frame) in [
        ("project onto the draft", format!(r#"{{"op":"project","a":"{pub_l}","slot":1,"d":"{d}"}}"#)),
        ("discoverable_from the draft", format!(r#"{{"op":"discoverable_from","a":"{pub_l}","d":"{d}"}}"#)),
    ] {
        withheld_for(what, Some(&s.session), &frame);
        assert_ne!(verdict(&op(port, Some(&owner), &frame)), "withheld", "{what}: the owner is answered");
    }
    sd.shutdown();
}

/// 2.10 / PUB-6.4 — `site.addr` names the FIRST unreadable argument taken
/// ACROSS the op's argument lists in DECLARATION order and within each by
/// INDEX: `compare`'s `rho1` before `rho2`, `show_deletions`' `d_a` before
/// `d_b`, `retrieve_v`'s specs and `find_docs_containing`'s regions by index,
/// and the link writes' V-spec slots `from`, `to`, `ty`.
#[test]
fn m2_10_site_addr_names_the_first_unreadable_argument_in_declaration_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let d1 = draft_with(port, &owner, "a");
    let d2 = draft_with(port, &owner, "b");
    let pub_l = ghost_link(port, &signed, CLAIMANT_DOC1, 1);
    let s = seat_stranger(port, 992);
    let s_draft = create_doc(port, &s.session, &s.account);
    let spec = |doc: &str| format!(r#"{{"doc":"{doc}","span":{{"start":"1.1","width":"0.1"}}}}"#);

    let (a1, a2) = (d1.as_str(), d2.as_str());
    let reads: Vec<(&str, String, &str)> = vec![
        ("compare: rho1 readable, rho2 unreadable", format!(r#"{{"op":"compare","rho1":[{}],"rho2":[{}]}}"#, region_spec(CLAIMANT_DOC1, 1, 1), region_spec(a2, 1, 1)), a2),
        ("compare: both unreadable — rho1 first", format!(r#"{{"op":"compare","rho1":[{}],"rho2":[{}]}}"#, region_spec(a1, 1, 1), region_spec(a2, 1, 1)), a1),
        ("compare: rho1's second region ahead of rho2's first", format!(r#"{{"op":"compare","rho1":[{},{}],"rho2":[{}]}}"#, region_spec(CLAIMANT_DOC1, 1, 1), region_spec(a2, 1, 1), region_spec(a1, 1, 1)), a2),
        ("show_deletions: d_a readable, d_b unreadable", format!(r#"{{"op":"show_deletions","d_a":"{CLAIMANT_DOC1}","d_b":"{a1}"}}"#), a1),
        ("show_deletions: both unreadable — d_a first", format!(r#"{{"op":"show_deletions","d_a":"{a2}","d_b":"{a1}"}}"#), a2),
        ("retrieve_v: specs by index", format!(r#"{{"op":"retrieve_v","specs":[{},{},{}]}}"#, spec(CLAIMANT_DOC1), spec(a1), spec(a2)), a1),
        ("find_docs_containing: regions by index", format!(r#"{{"op":"find_docs_containing","regions":[{},{},{}]}}"#, region_spec(CLAIMANT_DOC1, 1, 1), region_spec(a2, 1, 1), region_spec(a1, 1, 1)), a2),
    ];
    for (what, frame, first) in &reads {
        for token in [None, Some(s.session.as_str())] {
            let v = op(port, token, frame);
            assert_withheld(&v, first);
            assert_eq!(v["site"]["addr"].as_str(), Some(*first), "2.10 / PUB-6.4: {what}: {v}");
        }
    }
    // The link writes' V-spec slots, in the declared order `from`, `to`, `ty`.
    let writes: Vec<(&str, String, &str)> = vec![
        ("make_link: from resolving d1, to resolving d2", link_frame(&s_draft, &vspec(a1, 1, 1), &vspec(a2, 1, 1), &ghost_ty(&s_draft, 1)), a1),
        ("make_link: to resolving d2 ahead of ty resolving d1", link_frame(&s_draft, r#"{"addrs":[]}"#, &vspec(a2, 1, 1), &vspec(a1, 1, 1)), a2),
        // The successor's `ty` is an OBJECT — `{"resolve": […]}` for the
        // content-resolved form — where `make_link`'s slots take the bare
        // V-spec array (wire.md §Operations, `edit_link`).
        ("edit_link: the successor's to ahead of its ty", edit_link_frame(&pub_l, &s_draft, &s_draft, &vspec(a2, 1, 1), &resolve_slot(&vspec(a1, 1, 1))), a2),
    ];
    for (what, frame, first) in &writes {
        let v = op(port, Some(&s.session), frame);
        assert_withheld(&v, first);
        assert_eq!(v["site"]["addr"].as_str(), Some(*first), "2.10 / PUB-6.4: {what}: {v}");
    }
    sd.shutdown();
}

/// 2.10 / PUB-6.24 — the gate is per ARGUMENT document, delivery per
/// ORIGIN: a non-entitled principal MAY `copy` and `version` from a PUBLIC
/// source over its draft-origin runs and mint a document holding those
/// I-positions — withheld to it in the minted document as in the source.
/// The `version` is the cross-owner arm (PUB-2.18): a fresh document in the
/// caller's own account; its flagless form is the gate's.
#[test]
fn m2_10_a_non_entitled_copy_and_version_from_a_public_source_over_draft_origin_runs_is_allowed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let d = draft_with(port, &owner, "abcde");
    let member = shot(port, &signed, CLAIMANT_DOC1, None, None, &[run(&d, &format!("{d}.0.1.1"), 2)]);
    let s = seat_stranger(port, 993);
    let s_draft = create_doc(port, &s.session, &s.account);
    let masked = json!([withheld_item(&d, 2)]);
    assert_eq!(delivery(port, Some(&s.session), &member, 1, 2), masked, "the public source, to the stranger");

    expect_resp(&copy_span(port, &s.session, &s_draft, 1, &member, 1, 2), "ack");
    assert_eq!(delivery(port, Some(&s.session), &s_draft, 1, 2), masked, "2.10 / PUB-6.24: the copy holds the positions, withheld as in the source");
    assert_eq!(image_runs(port, Some(&s.session), &s_draft, 1, 2), vec![(format!("{d}.0.1.1"), 2)]);

    let fork = acked_addr(&version_of(port, &s.session, &member, Some(false)));
    assert!(fork.starts_with(&format!("{}.0.", s.account)), "a fresh private document in the stranger's own account: {fork}");
    assert_eq!(delivery(port, Some(&s.session), &fork, 1, 2), masked);
    assert_eq!(verdict(&version_of(port, &s.session, &member, None)), GATED, "the inherit arm of a published source is the gate's");
    sd.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════
// 2.11 — the read-row answer cells
// ═══════════════════════════════════════════════════════════════════════

/// The union of `show_deletions`' two halves.
fn deletion_addrs(v: &Value) -> BTreeSet<String> {
    let rep = &expect_resp(v, "deletions")["rep"];
    ["a_with_b", "b_with_a"]
        .iter()
        .flat_map(|half| rep[*half].as_array().expect("a half").iter())
        .map(|a| a.as_str().expect("an address").to_string())
        .collect()
}

/// 2.11 / PUB-6.15 — the UNFILTERED cells: over a published member that
/// windows a draft, `show_origin` returns the origin addresses whole, `image`
/// the runs whole, `show_deletions` its answer whole (see below),
/// `follow_link` the slot's endset verbatim, `compare` the correspondences
/// whole, `retrieve_endsets` unfiltered at origin, and the extents count the
/// positions draft-origin runs occupy — to the guest and a stranger exactly
/// as to the owner.
///
/// The `show_deletions` row has NO non-empty published instance the daemon
/// can show: `DELETED(a, d)` is an I-address `a` that `d` once placed and no
/// longer arranges, and a published arrangement never loses a run — the in-place
/// edits refuse (PUB-2.11), a pinned member is immutable (PUB-2.50), a
/// deposit only appends (PUB-2.59) — so over two published arguments both
/// halves are empty BY CONSTRUCTION, whoever asks. What the cell can pin is
/// the row's unfiltered shape: the guest and a stranger get a `deletions`
/// answer — never `withheld` — byte-equal to the owner's; and the read
/// itself is shown live on the owner's own draft, where a cut run names its
/// draft-origin I-address.
#[test]
fn m2_11_the_unfiltered_cells_answer_whole_at_origin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let d = draft_with(port, &owner, "abcde");
    let i1 = format!("{d}.0.1.1");
    let i4 = format!("{d}.0.1.4");
    let m1 = shot(port, &signed, CLAIMANT_DOC1, None, None, &[run(&d, &i1, 2), run(&d, &i4, 2)]);
    let m2 = shot(port, &signed, CLAIMANT_DOC1, Some((&m1, 4)), None, &[run(&d, &i1, 2)]);
    let p = acked_addr(&op(port, Some(&signed), &link_frame(CLAIMANT_DOC1, r#"{"addrs":[]}"#, &vspec(&d, 1, 2), &ghost_ty(CLAIMANT_DOC1, 81))));
    let s = seat_stranger(port, 994);
    // The read, live, on the owner's own draft: J copies D's first two runs
    // and cuts the first, so `show_deletions(J, D)` names D's I-address
    // whole (`a_with_b` = current in D ∧ deleted from J).
    let j = owner_draft(port, &owner);
    expect_resp(&copy_span(port, &owner, &j, 1, &d, 1, 2), "ack");
    expect_resp(&op(port, Some(&owner), &delete_frame(&j, 1, 1)), "ack");
    let control = deletion_addrs(&op(port, Some(&owner), &deletions_frame(&j, &d)));
    assert_eq!(control, BTreeSet::from([i1.clone()]), "the control: the cut run's draft-origin I-address, itself");
    // …and over the two published members, the owner's own answer — empty
    // by construction — is what every class is answered below.
    let members_frame = deletions_frame(&m1, &m2);
    let owner_deletions = deletion_addrs(&op(port, Some(&owner), &members_frame));
    let owner_pairs = endset_pairs(port, Some(&owner), &m1, 1, 2);
    assert!(
        owner_pairs.iter().any(|pair| pair["slot"].as_u64() == Some(2) && pair["endset"][0]["start"].as_str() == Some(i1.as_str())),
        "the fixture: the link's TO endset, at origin: {owner_pairs:?}"
    );

    for token in [None, Some(s.session.as_str())] {
        assert_eq!(origins_of(port, token, &m1, 1, 4), vec![d.clone()], "show_origin, whole");
        assert_eq!(image_runs(port, token, &m1, 1, 4), vec![(i1.clone(), 2), (i4.clone(), 2)], "image, whole");
        assert_eq!(
            deletion_addrs(&op(port, token, &members_frame)),
            owner_deletions,
            "show_deletions: a `deletions` answer whole — the owner's own, never withheld or filtered"
        );
        assert_eq!(compare_positions(port, token, &m1, 4, &m2, 2), shared_prefix(2), "compare, whole");
        let v = op(port, token, &format!(r#"{{"op":"follow_link","a":"{p}","slot":2}}"#));
        assert_eq!(expect_resp(&v, "follow")["result"]["ok"][0]["start"].as_str(), Some(i1.as_str()), "follow_link, verbatim: {v}");
        assert_eq!(endset_pairs(port, token, &m1, 1, 2), owner_pairs, "retrieve_endsets, unfiltered at origin");
        assert_eq!(content_extent(port, token, &m1), 4, "the extent counts the positions draft-origin runs occupy");
        assert_withheld(&op(port, token, &read1_frame(&d)), &d);
    }
    sd.shutdown();
}

/// 2.11 / PUB-6.50 — a surface is EXEMPT iff its answer is invariant across
/// visibility classes: `/health`, `next_account_prefix`, `principal_prefix`
/// and `key_set` answer the guest, the owner and a stranger byte-identically.
#[test]
fn m2_11_the_exempt_surfaces_answer_every_class_alike() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let s = seat_stranger(port, 995);
    let tokens: [Option<&str>; 3] = [None, Some(owner.as_str()), Some(s.session.as_str())];

    let health: Vec<Vec<u8>> = tokens.iter().map(|t| http(port, "GET", "/health", *t, b"").1).collect();
    assert!(health.iter().all(|b| *b == health[0]), "/health is class-invariant");
    for frame in [
        r#"{"op":"next_account_prefix","parent":"1"}"#.to_string(),
        format!(r#"{{"op":"principal_prefix","principal":{CLAIMANT_PRINCIPAL}}}"#),
        format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#),
    ] {
        let bodies: Vec<Vec<u8>> = tokens.iter().map(|t| http(port, "POST", "/op", *t, frame.as_bytes()).1).collect();
        assert!(bodies.iter().all(|b| *b == bodies[0]), "2.11 / PUB-6.50: {frame} is class-invariant");
        assert_ne!(json(&bodies[0])["resp"].as_str(), Some("rejected"), "{frame}: answered");
    }
    sd.shutdown();
}
