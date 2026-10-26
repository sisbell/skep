//! EDITLINK's successor, the one request M10 assembles itself (§4), over the
//! public surface: both forms of the type slot, a slot built from every spec,
//! the per-slot span budget charged as the slot is built — refused before any
//! transaction where the door judges the write, ahead of any spec behind the
//! crossing, and a slot at the budget still accepted — the per-slot work
//! budget charged before each walk, at the boundary MAKELINK's slots are held
//! to on both of its sides, the first offending slot the one that speaks,
//! an unarranged source committing an empty slot exactly as MAKELINK's would,
//! and the I-span form on the successor's ends (W6 (a)): deposited
//! verbatim, resolving nothing, held to the content clause by slot and index
//! and to the span budget, the address form refused on an end.

use crate::common;

use common::*;
use skep_address::{elem_addr, subtree_of, Address, ElemPos, Span};
use skep_febe::{
    Disposition, Endset, Op, OpKind, RejectCode, Run, SlotArg, SuccessorSpec, FROM, TO, TYPE,
};
use skep_links::{enc, MAX_SLOT_RESOLVE_STEPS, MAX_SLOT_SPANS};

/// The content I-span of `width` positions from `doc`'s content I-ordinal
/// `start` — the span `Run::iextent` yields, which the wire's `{"spans"}`
/// form carries.
fn ispan(doc: &Address, start: u32, width: u32) -> Span {
    let start = elem_addr(ElemPos { doc: doc.clone(), subspace: nat(1), ordinal: nat(start) })
        .unwrap_or_else(|_| panic!("a content position"));
    Run::new(start, nat(width)).expect("a content run").iextent()
}

/// §4: `SuccessorSpec.ty`'s other form. `SlotArg::Addrs` builds an
/// address-denoting (managed-relation) type slot through `enc`, and it is the
/// only way a FEBE client gives a successor one — the content-resolved form
/// every other case uses cannot reach it.
#[test]
fn an_address_denoting_successor_type_slot_is_deposited_verbatim() {
    let fx = setup();
    let (d, original) = linked_doc(&fx);
    let (succ, _, _) = ack_edit(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original,
            successor: SuccessorSpec {
                from: vec![vspec(&d, 1, 1)].into(),
                to: vec![vspec(&d, 2, 1)].into(),
                ty: SlotArg::Addrs(vec![d.clone()]),
            },
            d_s: d.clone(),
            d_a: d.clone(),
        },
    ));

    let link =
        link_value(ex(&fx.febe, fx.user, Op::ReadLink { a: succ })).expect("the successor is resident");
    assert_eq!(link.type_slot(), &enc([&d]), "the address names ride into TYPE verbatim");
    assert!(!link.from_slot().is_empty(), "the content-resolved FROM is still resolved");
}

/// §4: a successor slot is built from ALL of its specs. Two non-adjacent
/// ordinals cannot merge into one span, and `Endset::from_spans` stores what
/// it is given, so the count is exact — a slot that kept only the last spec
/// would name one region where the client named two, commit, and read back
/// wrong.
#[test]
fn a_multi_spec_successor_slot_accumulates_every_spec() {
    let fx = setup();
    let (d, original) = linked_doc(&fx);
    let (succ, _, _) = ack_edit(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original,
            successor: SuccessorSpec {
                from: vec![vspec(&d, 1, 1), vspec(&d, 3, 1)].into(),
                to: vec![vspec(&d, 2, 1)].into(),
                ty: SlotArg::Addrs(vec![d.clone()]),
            },
            d_s: d.clone(),
            d_a: d.clone(),
        },
    ));

    let link =
        link_value(ex(&fx.febe, fx.user, Op::ReadLink { a: succ })).expect("the successor is resident");
    assert_eq!(link.from_slot().len(), 2, "both specs contributed a span to the slot");
}

/// §4: the successor slot's span budget, and where it is charged. A spec's
/// expansion is the SOURCE document's fragmentation, not the request's size —
/// one spec over a two-run region is two spans — so a short list of specs
/// names spans without bound. The slot is counted as it is built, so the
/// owner's request past [`MAX_SLOT_SPANS`] — a write the door judges — is
/// refused by M10 itself, naming the slot, having held one slot's worth of
/// spans rather than every spec's, and with no transaction opened. The
/// refusal is raised as the slot crosses, so a spec after the crossing is
/// never reached: one the request gets wrong there changes nothing about the
/// answer. (A caller the store's own gate refuses is answered that refusal
/// instead: `write_door.rs`.)
#[test]
fn a_successor_slot_over_the_span_budget_is_refused_before_any_transaction() {
    let fx = setup();
    let (d, original) = linked_doc(&fx);
    // Delete the middle element: the V gap closes, and what is left is two
    // elements at non-adjacent I-addresses — a two-run arrangement.
    ack(ex(&fx.febe, fx.user, Op::Delete { doc: d.clone(), p: vp(1, 2), width: nat(1) }));
    let region = || vspan(1, 1, 2);
    assert_eq!(
        runs(ex(&fx.febe, fx.user, Op::Image { d: d.clone(), region: vec![region()] })).len(),
        2,
        "the fixture is fragmented: one spec over this region resolves to two spans"
    );
    let two_spans = || skep_arrangement::VSpec { source: d.clone(), span: region() };
    // One spec past the halfway mark crosses the budget; `after` is appended
    // behind the crossing.
    let edit = |after: Option<skep_arrangement::VSpec>| {
        let mut from = vec![two_spans(); MAX_SLOT_SPANS / 2 + 1];
        from.extend(after);
        Op::EditLink {
            original: original.clone(),
            successor: SuccessorSpec {
                from: from.into(),
                to: vec![].into(),
                ty: SlotArg::Addrs(vec![d.clone()]),
            },
            d_s: d.clone(),
            d_a: d.clone(),
        }
    };

    let before = fx.febe.log_position();
    let rej = rejected(ex(&fx.febe, fx.user, edit(None)));
    assert_eq!(rej.op, OpKind::EditLink);
    assert_eq!(rej.code, RejectCode::SlotTooLarge);
    assert_eq!(rej.disposition, Disposition::Permanent, "no retry shrinks the slot");
    assert_eq!(
        rej.site.as_ref().and_then(|s| s.slot),
        Some(FROM),
        "M10's own refusal names the slot"
    );
    assert_eq!(fx.febe.log_position(), before, "the refusal opened no transaction");

    // A link-subspace span is the request's own fault, and behind the
    // crossing it is never reached: the same refusal comes back.
    let ill_formed = skep_arrangement::VSpec { source: d.clone(), span: vspan(2, 1, 1) };
    assert_eq!(
        rejected(ex(&fx.febe, fx.user, edit(Some(ill_formed)))),
        rej,
        "the crossing answers ahead of a later spec's fault"
    );
    assert_eq!(fx.febe.log_position(), before, "and that refusal opened no transaction either");
}

/// §4, the other side of that boundary: a slot of exactly [`MAX_SLOT_SPANS`]
/// spans is the largest M7 accepts, and it is still accepted here. What the
/// budget refuses is what M7 would refuse; the counting moves where the
/// refusal happens, never which requests it answers.
#[test]
fn a_successor_slot_at_the_span_budget_is_still_accepted() {
    let fx = setup();
    let (d, original) = linked_doc(&fx);
    let one_span = || skep_arrangement::VSpec { source: d.clone(), span: vspan(1, 1, 1) };

    let (succ, _, _) = ack_edit(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original,
            successor: SuccessorSpec {
                from: vec![one_span(); MAX_SLOT_SPANS].into(),
                to: vec![].into(),
                ty: SlotArg::Addrs(vec![d.clone()]),
            },
            d_s: d.clone(),
            d_a: d.clone(),
        },
    ));
    let link =
        link_value(ex(&fx.febe, fx.user, Op::ReadLink { a: succ })).expect("the successor is resident");
    assert_eq!(link.from_slot().len(), MAX_SLOT_SPANS, "every span at the budget was deposited");
}

/// §4: the successor slot's WORK budget, beside its span budget, at the
/// boundary MAKELINK's `Resolve` slots are held to. A spec's walk to its
/// opening ordinal passes every run of its source before it, whatever the spec
/// keeps — all of them for a span opening past the arranged end, which keeps
/// nothing — so no span count sees such a slot, and each walk is charged
/// before it is taken, at its source's whole run count, against
/// [`MAX_SLOT_RESOLVE_STEPS`]. The owner's request one walk past it — a write
/// the door judges — is refused by M10, naming the slot, with no transaction
/// opened, as MAKELINK refuses the same slot; one walk fewer is the budget
/// exactly, and commits the empty slot MAKELINK deposits too. (A caller the
/// store's own gate refuses is answered that refusal instead:
/// `write_door.rs`.)
#[test]
fn a_successor_slot_is_held_to_the_work_budget_makelink_is() {
    let fx = setup();
    let (d, original) = linked_doc(&fx);
    let run_count = 2048;
    let source = fragmented_doc(&fx, run_count);
    let at_budget = MAX_SLOT_RESOLVE_STEPS / run_count as usize;
    // Opening past the source's arranged end: it keeps nothing, walking every
    // run to find so.
    let past_the_end =
        || skep_arrangement::VSpec { source: source.clone(), span: vspan(1, run_count + 1, 1) };
    let edit = |specs: usize| Op::EditLink {
        original: original.clone(),
        successor: SuccessorSpec {
            from: vec![past_the_end(); specs].into(),
            to: vec![].into(),
            ty: SlotArg::Addrs(vec![d.clone()]),
        },
        d_s: d.clone(),
        d_a: d.clone(),
    };
    let make = |specs: usize| Op::MakeLink {
        home: d.clone(),
        from: SlotArg::Resolve(vec![past_the_end(); specs]),
        to: SlotArg::Addrs(vec![]),
        ty: SlotArg::Addrs(vec![d.clone()]),
        replaces: None,
    };

    let before = fx.febe.log_position();
    let rej = rejected(ex(&fx.febe, fx.user, edit(at_budget + 1)));
    assert_eq!(rej.op, OpKind::EditLink);
    assert_eq!(rej.code, RejectCode::SlotTooLarge);
    assert_eq!(rej.disposition, Disposition::Permanent, "no retry shortens the walk");
    let site = rej.site.expect("M10's own refusal names the slot");
    assert_eq!(site.slot, Some(FROM));
    assert!(site.index.is_none(), "the slot is at fault, not one spec in it");
    assert_eq!(fx.febe.log_position(), before, "the refusal opened no transaction");
    let make_rej = rejected(ex(&fx.febe, fx.user, make(at_budget + 1)));
    assert_eq!(make_rej.code, RejectCode::SlotTooLarge, "MAKELINK refuses the same slot");

    let (succ, _, _) = ack_edit(ex(&fx.febe, fx.user, edit(at_budget)));
    let link =
        link_value(ex(&fx.febe, fx.user, Op::ReadLink { a: succ })).expect("the successor is resident");
    assert!(link.from_slot().is_empty(), "the budget exactly: an empty slot, its specs keeping nothing");
    let (made, _) = ack_addr(ex(&fx.febe, fx.user, make(at_budget)));
    let made = link_value(ex(&fx.febe, fx.user, Op::ReadLink { a: made })).expect("the link is resident");
    assert!(made.from_slot().is_empty(), "the same empty slot MAKELINK deposits");
}

/// §4: the request-level refusal precedence, and what makes a successor's
/// `site.index` readable. Every slot offends here — the slots are built
/// `from`, then `to`, then `ty`, and the first refusal is the only answer —
/// so an index is a position within the slot that order arrives at, and a
/// client reading it against another slot would be pointed at the wrong spec.
#[test]
fn the_first_offending_successor_slot_is_the_one_that_speaks() {
    let fx = setup();
    let (d, original) = linked_doc(&fx);
    let unregistered =
        skep_arrangement::VSpec { source: addr(&[1, 0, 1, 0, 78]), span: vspan(1, 1, 1) };
    let ill_formed = skep_arrangement::VSpec { source: d.clone(), span: vspan(2, 1, 1) };

    // FROM offends at index 1; TO and TYPE each offend at index 0.
    let rej = rejected(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original,
            successor: SuccessorSpec {
                from: vec![vspec(&d, 1, 1), unregistered].into(),
                to: vec![ill_formed.clone()].into(),
                ty: SlotArg::Resolve(vec![ill_formed]),
            },
            d_s: d.clone(),
            d_a: d,
        },
    ));
    assert_eq!(
        rej.code,
        RejectCode::SourceNotRegistered,
        "FROM is built first, so FROM's fault is the one surfaced"
    );
    let site = rej.site.expect("M10 localizes its own successor faults");
    assert_eq!(
        site.slot,
        Some(FROM),
        "the answer says which slot that index is in, rather than leaving it to be deduced"
    );
    assert_eq!(site.index, Some(1), "the index is the offender's position within FROM");
}

/// §4: what M10's successor guard does NOT type. A source M3 has registered
/// but M5 has not yet arranged passes both checks and resolves to ⟨⟩, so the
/// successor commits with an empty FROM under an ordinary `AckEdit` — the
/// same empty slot MAKELINK's `Resolve` form deposits off the same run list,
/// and the boundary of what a client may conclude from a successful edit.
#[test]
fn an_unarranged_source_commits_an_empty_successor_slot() {
    let fx = setup();
    let d = create_doc(&fx);
    insert3(&fx, &d);
    let (original, _) = ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::MakeLink {
            home: d.clone(),
            from: SlotArg::Resolve(vec![vspec(&d, 1, 1)]),
            to: SlotArg::Resolve(vec![vspec(&d, 2, 1)]),
            ty: SlotArg::Resolve(vec![vspec(&d, 3, 1)]),
            replaces: None,
        },
    ));

    // Registered by CREATENEWDOCUMENT, arranged by nothing: M5 arranges a
    // document only when something is written into it.
    let fresh = create_doc(&fx);
    let (succ, _, _) = ack_edit(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original,
            successor: SuccessorSpec {
                from: vec![vspec(&fresh, 1, 1)].into(),
                to: vec![vspec(&d, 2, 1)].into(),
                ty: SlotArg::Resolve(vec![vspec(&d, 3, 1)]),
            },
            d_s: d.clone(),
            d_a: d.clone(),
        },
    ));
    let link = link_value(ex(&fx.febe, fx.user, Op::ReadLink { a: succ })).expect("successor is resident");
    assert!(link.from_slot().is_empty(), "the unarranged source contributed no spans");
    assert!(!link.to_slot().is_empty(), "the arranged source did");
}

/// THE I-SPAN FORM on a successor's ends and type (W6 (a)): an I-span slot
/// is deposited VERBATIM — the spans as given, the shape the V-spec form
/// stores after resolving — with nothing resolved and nothing consulted, so
/// positions no mint issued (past the document's frontier) deposit exactly
/// as its occupied ones do. A re-made end is the original's I-spans cut in
/// I-space; this is the surface that writes it.
#[test]
fn an_ispan_successor_end_is_deposited_verbatim_and_resolves_nothing() {
    let fx = setup();
    let (d, original) = linked_doc(&fx);
    let (succ, _, _) = ack_edit(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original: original.clone(),
            successor: SuccessorSpec {
                from: SlotArg::Spans(vec![ispan(&d, 2, 2)]),
                to: SlotArg::Spans(vec![]),
                ty: SlotArg::Spans(vec![ispan(&d, 3, 1)]),
            },
            d_s: d.clone(),
            d_a: d.clone(),
        },
    ));
    let link =
        link_value(ex(&fx.febe, fx.user, Op::ReadLink { a: succ })).expect("the successor is resident");
    assert_eq!(link.from_slot(), &Endset::from_spans([ispan(&d, 2, 2)]), "the spans as given");
    assert!(link.to_slot().is_empty(), "an empty I-span slot is ⟨⟩");
    assert_eq!(link.type_slot(), &Endset::from_spans([ispan(&d, 3, 1)]), "a content extent types the successor");

    // Past the frontier — positions no mint issued — the same deposit.
    let (succ, _, _) = ack_edit(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original,
            successor: SuccessorSpec {
                from: SlotArg::Spans(vec![ispan(&d, 40, 5), ispan(&d, 1, 1)]),
                to: vec![vspec(&d, 2, 1)].into(),
                ty: SlotArg::Addrs(vec![d.clone()]),
            },
            d_s: d.clone(),
            d_a: d.clone(),
        },
    ));
    let link =
        link_value(ex(&fx.febe, fx.user, Op::ReadLink { a: succ })).expect("the successor is resident");
    assert_eq!(
        link.from_slot(),
        &Endset::from_spans([ispan(&d, 40, 5), ispan(&d, 1, 1)]),
        "ghosts and occupied positions alike, in argument order"
    );
    assert_eq!(link.to_slot().len(), 1, "the V-spec end beside it still resolves");
}

/// THE CONTENT CLAUSE on a successor's I-span end (the wire-lane decision 5),
/// by slot and index: a span whose start is no content-subspace element
/// position — a link-subspace element, a subspace-3 type address — is
/// `not_content_subspace`, permanent, `site.slot` the slot in M7's
/// numbering and `site.index` the span, with no transaction opened; and the
/// ADDRESS FORM on an end is `ill_formed_successor` naming the slot — the
/// narrowing the successor keeps.
#[test]
fn an_ispan_successor_end_is_held_to_the_content_clause_by_slot_and_index() {
    let fx = setup();
    let (d, original) = linked_doc(&fx);
    let link_pos = elem_addr(ElemPos { doc: d.clone(), subspace: nat(2), ordinal: nat(1) })
        .unwrap_or_else(|_| panic!("a link position"));
    let before = fx.febe.log_position();
    let edit = |from: SlotArg, to: SlotArg, ty: SlotArg| Op::EditLink {
        original: original.clone(),
        successor: SuccessorSpec { from, to, ty },
        d_s: d.clone(),
        d_a: d.clone(),
    };

    let rej = rejected(ex(
        &fx.febe,
        fx.user,
        edit(
            SlotArg::Spans(vec![ispan(&d, 1, 1)]),
            SlotArg::Spans(vec![ispan(&d, 1, 1), subtree_of(link_pos.tumbler())]),
            SlotArg::Addrs(vec![d.clone()]),
        ),
    ));
    assert_eq!(rej.op, OpKind::EditLink);
    assert_eq!(rej.code, RejectCode::NotContentSubspace);
    assert_eq!(rej.disposition, Disposition::Permanent, "the span's own bytes are what is wrong");
    let site = rej.site.expect("localized");
    assert_eq!(site.slot, Some(TO), "the TO slot");
    assert_eq!(site.index, Some(1), "its second span");

    // The type slot: a credential type's unit span has the I-span shape,
    // and the clause refuses it ahead of every classifier.
    let credential = addr(&[1, 1, 0, 1, 0, 1, 0, 3, 1]);
    let rej = rejected(ex(
        &fx.febe,
        fx.user,
        edit(
            SlotArg::Spans(vec![]),
            SlotArg::Spans(vec![]),
            SlotArg::Spans(vec![subtree_of(credential.tumbler())]),
        ),
    ));
    assert_eq!(rej.code, RejectCode::NotContentSubspace);
    assert_eq!(rej.site.expect("localized").slot, Some(TYPE));

    // The address form on an end: the narrowing kept.
    let rej = rejected(ex(
        &fx.febe,
        fx.user,
        edit(SlotArg::Addrs(vec![d.clone()]), vec![].into(), SlotArg::Addrs(vec![d.clone()])),
    ));
    assert_eq!(rej.code, RejectCode::IllFormedSuccessor);
    assert_eq!(rej.site.expect("localized").slot, Some(FROM), "the slot in the address form is named");
    assert_eq!(fx.febe.log_position(), before, "no refusal opened a transaction");
}

/// THE SPAN BUDGET on an I-span end: the count is the request's own, so
/// M10 answers it whoever judges — `slot_too_large` naming the slot and no
/// index, no transaction opened — and a slot at the budget deposits whole.
#[test]
fn an_ispan_successor_end_is_held_to_the_span_budget() {
    let fx = setup();
    let (d, original) = linked_doc(&fx);
    let edit = |count: usize| Op::EditLink {
        original: original.clone(),
        successor: SuccessorSpec {
            from: SlotArg::Spans(vec![ispan(&d, 1, 1); count]),
            to: vec![].into(),
            ty: SlotArg::Addrs(vec![d.clone()]),
        },
        d_s: d.clone(),
        d_a: d.clone(),
    };
    let before = fx.febe.log_position();
    let rej = rejected(ex(&fx.febe, fx.user, edit(MAX_SLOT_SPANS + 1)));
    assert_eq!(rej.code, RejectCode::SlotTooLarge);
    assert_eq!(rej.disposition, Disposition::Permanent);
    let site = rej.site.expect("the slot is named");
    assert_eq!(site.slot, Some(FROM));
    assert!(site.index.is_none(), "the slot is at fault, not one span in it");
    assert_eq!(fx.febe.log_position(), before, "the refusal opened no transaction");

    let (succ, _, _) = ack_edit(ex(&fx.febe, fx.user, edit(MAX_SLOT_SPANS)));
    let link =
        link_value(ex(&fx.febe, fx.user, Op::ReadLink { a: succ })).expect("the successor is resident");
    assert_eq!(link.from_slot().len(), MAX_SLOT_SPANS, "every span at the budget was deposited");
}
