//! Evaluation (`eval`, `decide`): the slice each view reads and the UV rewrite
//! over it, the BH2 walk over the operative claims, a draft-homed claim's
//! invisibility, the denotation of every former, and the doors' preconditions.

use crate::common::*;
use crate::terms::*;

use skep_address::Address;
use skep_coordination::{Dom, Sort, Term, Value, View};
use skep_links::{coverage_class, Caller, CoverageClass, Endset, HasLinks, ShippedType, Tip};

/// The atom dispatch end-to-end: active/audit/default readings, the UV
/// `K_queried` self-exclusion (settled OQ1), `L_dom`, reflection, BH3, the
/// binder guard, and `is_doc`.
#[test]
fn a_verdict_reads_its_view_s_slice_and_uv_drops_only_other_bh1_classes() {
    let k = kernel();
    let c = coord(&k);
    let writer = link_writer(&k);

    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2)); // pred_stable class, F=ca1, G=ca2
    deposit_rel(&k, PRED_STABLE, &ca(3), &ca(2));

    // is_K / member counting / L_dom / reflection membership.
    assert!(decide_now(&k, &c, View::Active, is_k(&pred_stable_ty(), lit_addr(&ca(1)))));
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::MembersDom(concrete(&pred_stable_ty()))), lit_nat(2))));
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::LinkDom), lit_nat(2))));
    assert!(decide_now(&k, &c, View::Active, set_mem(lit_addr(&la(1)), reflect(Dom::LinkDom))));

    // Retraction: the active reading shrinks, the audit reading persists —
    // the term view selects (PR-VIEW: the view is an eval parameter).
    writer.nullify(Caller::System, &doc1(), &l1).expect("retract rel 1");
    assert!(!decide_now(&k, &c, View::Active, is_k(&pred_stable_ty(), lit_addr(&ca(1)))));
    assert!(decide_now(&k, &c, View::Audit, is_k(&pred_stable_ty(), lit_addr(&ca(1)))));
    // The audit tuple slice still carries l1 (∃ t ∈ L_rel :: ca1 ∈ cov_F(t)).
    assert!(decide_now(
        &k,
        &c,
        View::Active,
        exists(1, Dom::AuditSlice(concrete(&pred_stable_ty())), in_coverage_f(lit_addr(&ca(1)), 1))
    ));

    // UV default view: members(K, default) drops elements filtered by BH1
    // types OTHER than K — and never by K itself (retired's own default
    // reading is unrewritten — the OQ1 commitment).
    writer.emit(Caller::System, &doc1(), &retired_ty(), &ca(3), &[]).expect("retire ca3");
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::MembersDom(concrete(&pred_stable_ty()))), lit_nat(1))));
    assert!(decide_now(&k, &c, View::Default, nat_eq(count(Dom::MembersDom(concrete(&pred_stable_ty()))), lit_nat(0))));
    assert!(decide_now(&k, &c, View::Default, nat_eq(count(Dom::MembersDom(concrete(&retired_ty()))), lit_nat(1))));

    // V-DOC: residence is M3 registration.
    assert!(decide_now(&k, &c, View::Active, is_doc(lit_addr(&doc1()))));
    assert!(!decide_now(&k, &c, View::Active, is_doc(lit_addr(&ca(1)))));

    // The binder guard: IfSome narrows an optional through its `var`, and
    // the else-branch answers when the optional is ⊥. (The BH3 atoms —
    // TargetOf/TargetsKeyed — are out of the vocabulary in this format: no
    // cataloged class declares ReverseLookup, which
    // `typing::type_check_refuses_at_each_gamma_and_catalog_gate` pins.)
    assert!(decide_now(&k, &c, View::Active, if_some(bot_addr(), 2, fls(), tru())));
}

/// UV never rewrites a verdict atom: `is_K(x)@default` answers for an
/// element the default MEMBER reading of the same class has dropped.
#[test]
fn is_k_at_default_is_never_uv_filtered() {
    let k = kernel();
    let c = coord(&k);
    let writer = link_writer(&k);
    writer.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(3), &[]).expect("rel");
    writer.emit(Caller::System, &doc1(), &retired_ty(), &ca(3), &[]).expect("retire ca3");
    assert!(decide_now(&k, &c, View::Default, nat_eq(count(Dom::MembersDom(concrete(&pred_stable_ty()))), lit_nat(0))));
    assert!(decide_now(&k, &c, View::Default, is_k(&pred_stable_ty(), lit_addr(&ca(3)))));
}

/// UV on the target side: `targets_of(K, x)@default` drops the targets
/// filtered by a BH1 class other than K, and BH1's `is_filtered_J` is J's
/// own active membership (D2).
#[test]
fn targets_of_at_default_drops_filtered_targets() {
    let k = kernel();
    let c = coord(&k);
    deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    deposit_rel(&k, PRED_STABLE, &ca(1), &ca(4));
    link_writer(&k).emit(Caller::System, &doc1(), &retired_ty(), &ca(4), &[]).expect("retire ca4");
    let tof = || targets_of(&pred_stable_ty(), lit_addr(&ca(1)));
    assert!(decide_now(&k, &c, View::Active, nat_eq(count_set(tof()), lit_nat(2))));
    assert!(decide_now(&k, &c, View::Default, nat_eq(count_set(tof()), lit_nat(1))));
    assert!(!decide_now(&k, &c, View::Default, set_mem(lit_addr(&ca(4)), tof())));
    assert!(decide_now(&k, &c, View::Default, set_mem(lit_addr(&ca(2)), tof())));
    assert!(decide_now(&k, &c, View::Active, is_filtered(&retired_ty(), lit_addr(&ca(4)))));
    assert!(!decide_now(&k, &c, View::Active, is_filtered(&retired_ty(), lit_addr(&ca(2)))));
}

/// `targets_of` matches its source by COVERAGE of F at `Active`/`Default`
/// and by DENOTATION at `Audit`: a probe strictly under a denoted address
/// has targets at the first two views and none at the third, while the
/// denoted address itself has them at all three — and `is_K` is by
/// coverage at every view.
#[test]
fn targets_of_matches_the_source_by_coverage_at_active_and_by_denotation_at_audit() {
    let k = kernel();
    let c = coord(&k);
    // F = enc({doc1}): its coverage is doc1's whole subtree, its denotation
    // the one address doc1.
    deposit_rel(&k, PRED_STABLE, &doc1(), &ca(2));
    let under = || targets_of(&pred_stable_ty(), lit_addr(&ca(1)));
    let denoted = || targets_of(&pred_stable_ty(), lit_addr(&doc1()));
    assert!(decide_now(&k, &c, View::Active, set_mem(lit_addr(&ca(2)), under())));
    assert!(decide_now(&k, &c, View::Default, set_mem(lit_addr(&ca(2)), under())));
    assert!(!decide_now(&k, &c, View::Audit, set_mem(lit_addr(&ca(2)), under())));
    for view in [View::Active, View::Default, View::Audit] {
        assert!(decide_now(&k, &c, view, set_mem(lit_addr(&ca(2)), denoted())), "{view:?}");
        assert!(
            decide_now(&k, &c, view, is_k(&pred_stable_ty(), lit_addr(&ca(1)))),
            "is_K matches by coverage at {view:?}"
        );
    }
}

/// The audit slice is the whole record: after a retraction, the retired
/// tuple's F members and G targets persist in an `audit` reading and vanish
/// from an `active` one. Asserted of each read in ABSOLUTE terms — the
/// term/domain law `domains_have_set_semantics_and_binders_bind_the_element`
/// states holds even when both of its sides read the wrong slice. The two
/// tuple domains are fixed slices, whatever the term view says.
#[test]
fn an_audit_reading_keeps_what_a_retraction_removes_from_the_active_one() {
    let k = kernel();
    let c = coord(&k);
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    link_writer(&k).nullify(Caller::System, &doc1(), &l1).expect("retract the ca1 tuple");
    let ps = pred_stable_ty();
    let decide_at = |view: View, t: Term| decide_now(&k, &c, view, t);

    // members / M_K
    assert!(decide_at(View::Audit, set_mem(lit_addr(&ca(1)), members(&ps))));
    assert!(!decide_at(View::Active, set_mem(lit_addr(&ca(1)), members(&ps))));
    assert!(decide_at(View::Audit, nat_eq(count(Dom::MembersDom(concrete(&ps))), lit_nat(2))));
    assert!(decide_at(View::Active, nat_eq(count(Dom::MembersDom(concrete(&ps))), lit_nat(1))));
    // targets_of
    let tof = || targets_of(&ps, lit_addr(&ca(1)));
    assert!(decide_at(View::Audit, set_mem(lit_addr(&ca(2)), tof())));
    assert!(!decide_at(View::Active, set_mem(lit_addr(&ca(2)), tof())));
    // A_K and L_K name their own slice at every term view.
    assert!(decide_at(View::Audit, nat_eq(count(Dom::ActiveSlice(concrete(&ps))), lit_nat(1))));
    assert!(decide_at(View::Active, nat_eq(count(Dom::AuditSlice(concrete(&ps))), lit_nat(2))));
}

/// The atoms PR-VIEW's scan calls view-INDEPENDENT must DENOTE the same at
/// every view — the scan's half of that claim is watched
/// (`dynamics::view_independence_refuses_every_view_parameterized_and_uv_rewritten_form`),
/// and this is the evaluator's, which is what `certify_stable` certifies on.
/// Each reads a FIXED slice, so a retracted witness the AUDIT slice still
/// holds must not move the answer; every row is stated absolutely, and the
/// `audit` row is the one a view-parameterized read would fail. (`is_doc`
/// reads M3 and no slice; the rest of the list is dormant in this format or
/// reads a tuple-bound variable.)
#[test]
fn a_fixed_slice_atom_denotes_the_same_at_every_view() {
    let k = kernel();
    let c = coord(&k);
    let sup = c.reserved_type(ShippedType::Supersedes).clone();
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let writer = link_writer(&k);
    // A claim the audit slice keeps and the active slice does not …
    let (claim, _) = writer.assert_sup(Caller::System, &doc1(), &l1, &l2).expect("l1 → l2");
    writer.nullify(Caller::System, &doc1(), &claim).expect("retract the claim");
    // … and a BH1 membership likewise.
    let (retirement, _) =
        writer.emit(Caller::System, &doc1(), &retired_ty(), &ca(5), &[]).expect("retire ca5");
    writer.nullify(Caller::System, &doc1(), &retirement).expect("un-retire ca5");
    for view in [View::Active, View::Audit, View::Default] {
        assert!(
            !decide_now(&k, &c, view, is_filtered(&retired_ty(), lit_addr(&ca(5)))),
            "is_filtered reads the ACTIVE retired slice at {view:?}"
        );
        assert!(
            decide_now(&k, &c, view, tip_is(&sup, &l1, &l1)),
            "the walk follows only OPERATIVE claims at {view:?}"
        );
        assert!(
            !decide_now(&k, &c, view, is_in_chain(&sup, lit_addr(&l1), lit_addr(&l2))),
            "the chain halts at l1 at {view:?}"
        );
    }
}

/// BH2 over a linear lineage: `succs` is the one forward step, `chain` the
/// inclusive path from its start, `tip` the successor-free head — a sink's
/// head is itself — and `is_in_chain` is membership in the walk from its
/// FIRST argument, so it runs one way; `current_version` is `tip` at the
/// shipped class.
#[test]
fn over_a_linear_lineage_the_tip_is_the_sink_and_the_chain_runs_forward() {
    let k = kernel();
    let c = coord(&k);
    let sup = c.reserved_type(ShippedType::Supersedes).clone();
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let l3 = deposit_rel(&k, PRED_STABLE, &ca(5), &ca(6));
    let writer = link_writer(&k);
    writer.assert_sup(Caller::System, &doc1(), &l1, &l2).expect("l1 → l2");
    writer.assert_sup(Caller::System, &doc1(), &l2, &l3).expect("l2 → l3");
    let d = |t: Term| decide_now(&k, &c, View::Active, t);

    assert!(d(set_mem(lit_addr(&l2), succs(&sup, lit_addr(&l1)))));
    assert!(d(nat_eq(count_set(succs(&sup, lit_addr(&l1))), lit_nat(1))));
    assert!(d(is_empty(succs(&sup, lit_addr(&l3)))));
    assert!(d(nat_eq(count_set(elems(chain(&sup, lit_addr(&l1)))), lit_nat(3))));
    assert!(d(set_mem(lit_addr(&l1), elems(chain(&sup, lit_addr(&l1))))), "the chain includes its start");
    assert!(d(tip_is(&sup, &l1, &l3)));
    assert!(d(tip_is(&sup, &l3, &l3)), "a sink's head is itself");
    assert!(d(is_in_chain(&sup, lit_addr(&l1), lit_addr(&l3))));
    assert!(d(is_in_chain(&sup, lit_addr(&l1), lit_addr(&l1))));
    assert!(!d(is_in_chain(&sup, lit_addr(&l3), lit_addr(&l1))), "membership runs forward only");
    assert!(!d(is_in_chain(&sup, lit_addr(&l2), lit_addr(&l1))));
    assert_eq!(c.current_version(&l1, &k.snapshot()), Tip::Sink(l3));
}

/// BH2 at a branch and at a cycle: the head is indeterminate, the chain
/// truncates where the walk halts — so a claimed successor past a branch is
/// NOT in the chain — and a cycle's members are each in the other's chain.
#[test]
fn bh2_tip_is_indeterminate_at_a_branch_and_a_cycle() {
    let k = kernel();
    let c = coord(&k);
    let sup = c.reserved_type(ShippedType::Supersedes).clone();
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let l3 = deposit_rel(&k, PRED_STABLE, &ca(5), &ca(6));
    let l4 = deposit_rel(&k, PRED_STABLE, &ca(7), &ca(8));
    let l5 = deposit_rel(&k, PRED_STABLE, &ca(9), &ca(10));
    let writer = link_writer(&k);
    writer.assert_sup(Caller::System, &doc1(), &l1, &l2).expect("l1 → l2");
    writer.assert_sup(Caller::System, &doc1(), &l1, &l3).expect("l1 → l3: a branch");
    writer.assert_sup(Caller::System, &doc1(), &l4, &l5).expect("l4 → l5");
    writer.assert_sup(Caller::System, &doc1(), &l5, &l4).expect("l5 → l4: a cycle");
    let d = |t: Term| decide_now(&k, &c, View::Active, t);

    // The branch.
    assert!(!d(def(tip(&sup, lit_addr(&l1)))));
    assert!(d(nat_eq(count_set(succs(&sup, lit_addr(&l1))), lit_nat(2))));
    assert!(d(nat_eq(count_set(elems(chain(&sup, lit_addr(&l1)))), lit_nat(1))));
    assert!(!d(is_in_chain(&sup, lit_addr(&l1), lit_addr(&l2))), "the chain halts at the branch");
    assert_eq!(c.current_version(&l1, &k.snapshot()), Tip::Indeterminate);
    // The cycle.
    assert!(!d(def(tip(&sup, lit_addr(&l4)))));
    assert!(d(nat_eq(count_set(elems(chain(&sup, lit_addr(&l4)))), lit_nat(2))));
    assert!(d(is_in_chain(&sup, lit_addr(&l4), lit_addr(&l5))));
    assert!(d(is_in_chain(&sup, lit_addr(&l5), lit_addr(&l4))));
    assert_eq!(c.current_version(&l4, &k.snapshot()), Tip::Indeterminate);
}

/// A claim is operative iff unnullified (Df-SUCC): the walk reads the ACTIVE
/// claims, so retracting the CLAIM — not its endpoints — removes the edge and
/// the head falls back to the node itself.
#[test]
fn a_nullified_claim_is_not_operative_so_the_walk_does_not_follow_it() {
    let k = kernel();
    let c = coord(&k);
    let sup = c.reserved_type(ShippedType::Supersedes).clone();
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let writer = link_writer(&k);
    let (claim, _) = writer.assert_sup(Caller::System, &doc1(), &l1, &l2).expect("l1 → l2");
    assert!(decide_now(&k, &c, View::Active, tip_is(&sup, &l1, &l2)));
    assert_eq!(c.current_version(&l1, &k.snapshot()), Tip::Sink(l2.clone()));

    writer.nullify(Caller::System, &doc1(), &claim).expect("retract the claim");
    let d = |t: Term| decide_now(&k, &c, View::Active, t);
    assert!(d(is_empty(succs(&sup, lit_addr(&l1)))));
    assert!(d(tip_is(&sup, &l1, &l1)), "the head falls back to l1 itself");
    assert!(d(nat_eq(count_set(elems(chain(&sup, lit_addr(&l1)))), lit_nat(1))));
    assert!(!d(is_in_chain(&sup, lit_addr(&l1), lit_addr(&l2))));
    assert_eq!(c.current_version(&l1, &k.snapshot()), Tip::Sink(l1));
}

/// UV over the BH2 family: a `default`-view term's `chain`/`succs` drop the
/// elements another BH1 class filters, while `tip`/`is_in_chain` read the
/// unrewritten walk — the same membership answers differently through the
/// collection and through the verdict.
#[test]
fn uv_drops_retired_elements_from_chain_and_succs_but_never_from_the_walk() {
    let k = kernel();
    let c = coord(&k);
    let sup = c.reserved_type(ShippedType::Supersedes).clone();
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let l3 = deposit_rel(&k, PRED_STABLE, &ca(5), &ca(6));
    let writer = link_writer(&k);
    writer.assert_sup(Caller::System, &doc1(), &l1, &l2).expect("l1 → l2");
    writer.assert_sup(Caller::System, &doc1(), &l2, &l3).expect("l2 → l3");
    writer.emit(Caller::System, &doc1(), &retired_ty(), &l2, &[]).expect("retire l2");
    let chain_len = |view: View, len: u32| {
        decide_now(&k, &c, view, nat_eq(count_set(elems(chain(&sup, lit_addr(&l1)))), lit_nat(len)))
    };
    assert!(chain_len(View::Active, 3));
    assert!(chain_len(View::Audit, 3));
    assert!(chain_len(View::Default, 2));
    assert!(!decide_now(&k, &c, View::Default, set_mem(lit_addr(&l2), elems(chain(&sup, lit_addr(&l1))))));
    assert!(decide_now(&k, &c, View::Default, is_empty(succs(&sup, lit_addr(&l1)))));
    assert!(!decide_now(&k, &c, View::Active, is_empty(succs(&sup, lit_addr(&l1)))));
    assert!(decide_now(&k, &c, View::Default, tip_is(&sup, &l1, &l3)), "the walk runs through l2");
    assert!(decide_now(&k, &c, View::Default, is_in_chain(&sup, lit_addr(&l1), lit_addr(&l2))));
}

/// The walk is rebuilt over the VISIBLE operative claims: a claim homed in
/// a document the guest predicate refuses moves no walk for the refusing
/// coordinator, and moves it for one that reads everything.
#[test]
fn a_draft_homed_claim_moves_no_walk() {
    let k = kernel();
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    link_writer(&k).assert_sup(Caller::System, &doc2(), &l1, &l2).expect("a claim homed in doc2");
    let refusing = coord_with_guest(&k, |_, d| *d != doc2());
    let sup = refusing.reserved_type(ShippedType::Supersedes).clone();
    assert!(decide_now(&k, &refusing, View::Active, is_empty(succs(&sup, lit_addr(&l1)))));
    assert!(decide_now(&k, &refusing, View::Active, tip_is(&sup, &l1, &l1)));
    let seeing = coord(&k);
    assert!(decide_now(&k, &seeing, View::Active, set_mem(lit_addr(&l2), succs(&sup, lit_addr(&l1)))));
    assert!(decide_now(&k, &seeing, View::Active, tip_is(&sup, &l1, &l2)));
}

/// PC2a set semantics and the binders: an address domain deduplicates
/// while a tuple slice counts tuples; `M_K` the term and `M_K` the domain
/// agree at every view; `Filter`, `⋃`, ∀ and `Let` bind their variable to
/// each element.
#[test]
fn domains_have_set_semantics_and_binders_bind_the_element() {
    let k = kernel();
    let c = coord(&k);
    deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    deposit_rel(&k, PRED_STABLE, &ca(1), &ca(4));
    deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let ps = pred_stable_ty();
    let d = |t: Term| decide_now(&k, &c, View::Active, t);

    // Three tuples, two distinct members.
    assert!(d(nat_eq(count(Dom::MembersDom(concrete(&ps))), lit_nat(2))));
    assert!(d(nat_eq(count(Dom::ActiveSlice(concrete(&ps))), lit_nat(3))));
    assert!(d(nat_eq(count_set(members(&ps)), lit_nat(2))));
    // The law: the term and the domain are one reading, at every view.
    for view in [View::Active, View::Audit, View::Default] {
        assert!(decide_now(&k, &c, view, set_eq(members(&ps), reflect(Dom::MembersDom(concrete(&ps))))), "{view:?}");
        assert!(
            decide_now(&k, &c, view, nat_eq(count_set(members(&ps)), count(Dom::MembersDom(concrete(&ps))))),
            "{view:?}"
        );
    }
    // Filter binds each element, address or tuple.
    assert!(d(nat_eq(count(filter(Dom::MembersDom(concrete(&ps)), 2, addr_eq(var(2), lit_addr(&ca(1))))), lit_nat(1))));
    assert!(d(nat_eq(count(filter(Dom::ActiveSlice(concrete(&ps)), 2, in_coverage_g(lit_addr(&ca(4)), 2))), lit_nat(2))));
    // ⋃ over the tuple slice of each tuple's G; ∀ over each tuple's F.
    let targets = || big_union(Dom::ActiveSlice(concrete(&ps)), 2, tup_addrs_g(2));
    assert!(d(nat_eq(count_set(targets()), lit_nat(2))));
    assert!(d(set_mem(lit_addr(&ca(4)), targets())));
    assert!(d(forall(
        2,
        Dom::ActiveSlice(concrete(&ps)),
        or(set_mem(lit_addr(&ca(1)), tup_addrs_f(2)), set_mem(lit_addr(&ca(3)), tup_addrs_f(2)))
    )));
    // Let binds a set value …
    assert!(d(let_(
        3,
        members(&ps),
        and(set_mem(lit_addr(&ca(1)), var(3)), not(set_mem(lit_addr(&ca(2)), var(3))))
    )));
    // … and rebinds a tuple a binder bound, which V-TUP then reads.
    assert!(d(exists(
        2,
        Dom::ActiveSlice(concrete(&ps)),
        let_(3, var(2), in_coverage_g(lit_addr(&ca(2)), 3))
    )));
}

/// PC1's two quantifiers denote `all` and `any`: over ONE domain and ONE body
/// that some elements satisfy and others do not, `∀` is false while `∃` is
/// true — so neither is a constant and `∀` is not `∃`. The empty domain is the
/// other edge: `∀` is vacuously true there and `∃` false.
#[test]
fn the_quantifiers_denote_all_and_any() {
    let k = kernel();
    let c = coord(&k);
    deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let slice = || Dom::ActiveSlice(concrete(&pred_stable_ty()));
    let d = |t: Term| decide_now(&k, &c, View::Active, t);
    // ca1 is the F of one tuple of two.
    assert!(d(exists(2, slice(), in_coverage_f(lit_addr(&ca(1)), 2))));
    assert!(!d(forall(2, slice(), in_coverage_f(lit_addr(&ca(1)), 2))));
    // A body no element satisfies, and one every element satisfies.
    assert!(!d(exists(2, slice(), in_coverage_f(lit_addr(&ca(9)), 2))));
    assert!(d(forall(2, slice(), not(in_coverage_f(lit_addr(&ca(9)), 2)))));
    // The empty domain: ∀ vacuous, ∃ false.
    let empty = || Dom::MembersDom(concrete(&marker_ty()));
    assert!(d(forall(2, empty(), fls())));
    assert!(!d(exists(2, empty(), tru())));
}

/// V-TUP reads a slot two ways (ASN-0129): `addrs_F(t)` is the slot's DENOTED
/// set, `t ∈ coverage_F(x)` a COVERAGE test — so where a tuple's F is
/// `enc({doc1})`, an element of doc1 is in F's coverage and not among its
/// addresses, and G's pair reads the other slot alike. ASN-0129 derives the
/// audit `is_K` from the coverage test, and the two agree at every probe:
/// under a denoted document, at it, and outside it.
#[test]
fn in_coverage_reads_coverage_not_denotation_and_derives_the_audit_is_k() {
    let k = kernel();
    let c = coord(&k);
    let in_doc2 = a(&[1, 0, 1, 0, 2, 0, 1, 1]);
    deposit_rel(&k, PRED_STABLE, &doc1(), &ca(2)); // F denotes doc1, covers its subtree
    deposit_rel(&k, PRED_STABLE, &ca(5), &doc2()); // G denotes doc2, covers its subtree
    let some_tuple = |body: Term| exists(2, Dom::AuditSlice(concrete(&pred_stable_ty())), body);
    let d = |t: Term| decide_now(&k, &c, View::Audit, t);
    assert!(d(some_tuple(in_coverage_f(lit_addr(&ca(1)), 2))), "ca1 is in F's coverage");
    assert!(!d(some_tuple(set_mem(lit_addr(&ca(1)), tup_addrs_f(2)))), "… not among F's addresses");
    assert!(d(some_tuple(set_mem(lit_addr(&doc1()), tup_addrs_f(2)))), "doc1 is");
    assert!(
        d(some_tuple(in_coverage_g(lit_addr(&in_doc2), 2))),
        "doc2's element is in G's coverage"
    );
    assert!(
        !d(some_tuple(set_mem(lit_addr(&in_doc2), tup_addrs_g(2)))),
        "… not among G's addresses"
    );
    for probe in [ca(1), doc1(), ca(5), doc2(), in_doc2.clone()] {
        let derived = some_tuple(in_coverage_f(lit_addr(&probe), 2));
        assert!(d(iff(derived, is_k(&pred_stable_ty(), lit_addr(&probe)))), "{probe}");
    }
}

/// `L_dom` is the typed-relation sublayer and nothing else: a link deposited
/// through the open surface in an UNCATALOGED type is outside PL's universe —
/// it seeds no domain element and enters no reflection — while the cataloged
/// links do, at every term view (the domain is fixed-audit), and stay once
/// retracted, the `[R]` tuple joining them as a cataloged link of its own.
#[test]
fn link_dom_holds_the_cataloged_links_only_and_reads_the_audit_slice() {
    let k = kernel();
    let c = coord(&k);
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    let l2 = deposit_rel(&k, PRED_DEF, &ca(3), &ca(4));
    let open = deposit_rel(&k, 20, &ca(5), &ca(6)); // an uncataloged type number
    assert!(
        k.snapshot().world().links().readlink(&open).is_some(),
        "M7's store holds the open link — it is PL's universe that must not"
    );
    let in_ldom = |view: View, x: &Address| {
        decide_now(&k, &c, view, set_mem(lit_addr(x), reflect(Dom::LinkDom)))
    };
    for view in [View::Active, View::Audit, View::Default] {
        assert!(in_ldom(view, &l1), "{view:?}");
        assert!(in_ldom(view, &l2), "{view:?}");
        assert!(!in_ldom(view, &open), "an open link is outside PL's universe at {view:?}");
    }
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::LinkDom), lit_nat(2))));

    // The sublayer is the AUDIT record: a retracted cataloged link stays.
    link_writer(&k).nullify(Caller::System, &doc1(), &l1).expect("retract l1");
    assert!(in_ldom(View::Active, &l1));
    assert!(decide_now(&k, &c, View::Active, nat_eq(count(Dom::LinkDom), lit_nat(3))));
}

/// The T1 extrema over an address domain — max and min, ⊥ on an empty one
/// (the else-branch answers, nothing panics), and prefix-smaller order (a
/// document address is below its elements) — read through the binder guard.
#[test]
fn t1_extrema_answer_max_min_and_bot_through_the_binder_guard() {
    let k = kernel();
    let c = coord(&k);
    deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let stable_dom = || Dom::MembersDom(concrete(&pred_stable_ty()));
    let d = |t: Term| decide_now(&k, &c, View::Active, t);
    assert!(d(if_some(Term::MaxT1(ad(stable_dom())), 2, addr_eq(var(2), lit_addr(&ca(3))), fls())));
    assert!(d(if_some(Term::MinT1(ad(stable_dom())), 2, addr_eq(var(2), lit_addr(&ca(1))), fls())));
    let empty_dom = || Dom::MembersDom(concrete(&marker_ty()));
    assert!(!d(def(Term::MaxT1(ad(empty_dom())))));
    assert!(d(if_some(Term::MinT1(ad(empty_dom())), 2, fls(), tru())));
    deposit_rel(&k, PRED_STABLE, &doc1(), &ca(6));
    assert!(d(if_some(Term::MinT1(ad(stable_dom())), 2, addr_eq(var(2), lit_addr(&doc1())), fls())));
    assert!(d(if_some(Term::MaxT1(ad(stable_dom())), 2, addr_eq(var(2), lit_addr(&ca(3))), fls())));
}

/// V-PRIM at the equal cases: ≼ is reflexive and directed, T1's order is
/// strict, ≤ admits equality, definedness and the guard at both optional
/// sorts, the set prims on the empty set — and the connectives over every
/// cell of their tables.
#[test]
fn prims_answer_their_equal_cases_and_the_connectives_their_tables() {
    let k = kernel();
    let c = coord(&k);
    let d = |t: Term| decide_now(&k, &c, View::Active, t);
    assert!(d(prefix(lit_addr(&doc1()), lit_addr(&ca(1)))));
    assert!(d(prefix(lit_addr(&ca(1)), lit_addr(&ca(1)))));
    assert!(!d(prefix(lit_addr(&ca(1)), lit_addr(&doc1()))));
    assert!(!d(prefix(lit_addr(&ca(1)), lit_addr(&ca(2)))));
    assert!(d(t1_lt(lit_addr(&doc1()), lit_addr(&ca(1)))));
    assert!(!d(t1_lt(lit_addr(&ca(1)), lit_addr(&ca(1)))));
    assert!(d(t1_lt(lit_addr(&ca(1)), lit_addr(&ca(2)))));
    assert!(!d(t1_lt(lit_addr(&ca(2)), lit_addr(&ca(1)))));
    assert!(d(nat_eq(nat_add(lit_nat(1), lit_nat(2)), lit_nat(3))));
    assert!(d(nat_le(lit_nat(3), lit_nat(3))));
    assert!(!d(nat_le(lit_nat(4), lit_nat(3))));
    assert!(!d(def(bot_addr())));
    assert!(!d(def(bot_nat())));
    assert!(d(if_some(bot_nat(), 2, fls(), tru())));
    assert!(d(is_empty(members(&marker_ty()))));
    assert!(d(set_eq(members(&marker_ty()), members(&marker_ty()))));
    let b = |x: bool| if x { tru() } else { fls() };
    for (x, y) in [(false, false), (false, true), (true, false), (true, true)] {
        assert_eq!(d(and(b(x), b(y))), x && y, "and {x} {y}");
        assert_eq!(d(or(b(x), b(y))), x || y, "or {x} {y}");
        assert_eq!(d(implies(b(x), b(y))), !x || y, "implies {x} {y}");
        assert_eq!(d(iff(b(x), b(y))), x == y, "iff {x} {y}");
    }
    for x in [false, true] {
        assert_eq!(d(not(b(x))), !x, "not {x}");
    }
}

/// Every V-PRIM Boolean denotes a FUNCTION, not a constant: the two equalities
/// answer false at some input and definedness answers true at some input.
/// Without this the suite's count assertions — all of them `nat_eq` — hold
/// under an always-true `NatEq`, and PC2a's set semantics, the UV
/// member-count rewrite, `count(Reg)` and `L_dom`'s population go dark.
#[test]
fn every_boolean_prim_answers_both_ways() {
    let k = kernel();
    let c = coord(&k);
    deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let ps = pred_stable_ty();
    let d = |t: Term| decide_now(&k, &c, View::Active, t);
    let sources = || members(&ps); // {ca1, ca3}
    let targets = || big_union(Dom::ActiveSlice(concrete(&ps)), 2, tup_addrs_g(2)); // {ca2, ca4}

    // ℕ `=` — the suite's count instrument.
    assert!(d(nat_eq(lit_nat(2), lit_nat(2))));
    assert!(!d(nat_eq(lit_nat(2), lit_nat(3))));
    assert!(!d(nat_eq(count(Dom::MembersDom(concrete(&ps))), lit_nat(3))));
    // ℘_fin(T) `=` — two sets of the SAME size and different elements, so a
    // cardinality-only equality is caught as well as a constant one.
    assert!(d(set_eq(sources(), sources())));
    assert!(!d(set_eq(sources(), targets())));
    assert!(!d(set_eq(sources(), members(&marker_ty()))));
    // Definedness, true at a defined optional.
    assert!(d(def(Term::MinT1(ad(Dom::MembersDom(concrete(&ps)))))));
    assert!(!d(def(bot_addr())));
}

/// V-PRIM's `·[K]` keys a map by K's CATALOGED class, and an absent key
/// denotes ⊥. No cataloged class serves `targets_keyed`, but a `Map`-sorted
/// parameter is a map's other source, so the lookup is reachable — and the
/// key is what decides: a map holding two classes answers each at its own.
#[test]
fn map_get_keys_by_the_cataloged_class_and_an_absent_key_is_bot() {
    let k = kernel();
    let c = coord(&k);
    let s = k.snapshot();
    let decide_over = |m: im::HashMap<CoverageClass, Address>, t: Term| {
        let tt = c.type_check(vec![(v(1), Sort::Map)], t).expect("a Map-parameter term");
        c.decide(&tt, &[Value::Map(m)], View::Active, &s)
    };
    let at_key = |key: &Endset, x: &Address| {
        if_some(map_get(var(1), key), 2, addr_eq(var(2), lit_addr(x)), fls())
    };
    let pd = coverage_class(&pred_def_ty());
    let ps = coverage_class(&pred_stable_ty());
    let both = im::HashMap::new().update(pd.clone(), ca(1)).update(ps, ca(2));
    assert!(decide_over(both.clone(), at_key(&pred_def_ty(), &ca(1))));
    assert!(decide_over(both, at_key(&pred_stable_ty(), &ca(2))));
    let only_pd = im::HashMap::unit(pd, ca(1));
    assert!(decide_over(only_pd.clone(), def(map_get(var(1), &pred_def_ty()))));
    assert!(!decide_over(only_pd, def(map_get(var(1), &pred_stable_ty()))), "an absent key is ⊥");
    assert!(!decide_over(im::HashMap::new(), def(map_get(var(1), &pred_def_ty()))));
}

/// A set verdict hands back ADDRESSES: ℘_fin(T) is a set of `Address`, each
/// element lifted from the slot that denotes it as the set is gathered, so a
/// caller acts on an element as it stands — here, binding each straight into
/// a second verdict — with nothing to convert and nothing that can fail.
#[test]
fn a_set_verdict_hands_back_the_addresses_it_holds() {
    let k = kernel();
    let c = coord(&k);
    deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    deposit_rel(&k, PRED_STABLE, &ca(3), &ca(4));
    let s = k.snapshot();
    let sources = c.type_check(vec![], members(&pred_stable_ty())).expect("members(K)");
    let Value::AddrSet(held) = c.eval(&sources, &[], View::Active, &s) else {
        panic!("members(K) denotes a set");
    };
    assert_eq!(held, [ca(1), ca(3)].into_iter().collect::<im::OrdSet<_>>());
    let heads =
        c.type_check(vec![(v(1), Sort::Addr)], is_k(&pred_stable_ty(), var(1))).expect("is_K(x)");
    for x in held {
        assert!(c.decide(&heads, &[Value::Addr(x)], View::Active, &s));
    }
}

/// A verdict is "as of `snap.seq()`" (M2 V1 retrospective): the same term
/// answers differently at two pinned snapshots on either side of a deposit.
#[test]
fn a_verdict_is_as_of_its_snapshot() {
    let k = kernel();
    let c = coord(&k);
    let s0 = k.snapshot();
    link_writer(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let s1 = k.snapshot();
    let tt = c.type_check(vec![], is_k(&pred_stable_ty(), lit_addr(&ca(1)))).expect("checks");
    assert!(!c.decide(&tt, &[], View::Active, &s0));
    assert!(c.decide(&tt, &[], View::Active, &s1));
    assert!(s0.seq() < s1.seq());
}

/// A binder's name is bound only within its subterm: an inner `Let` that
/// rebinds a Γ_D parameter's name — at another sort — shadows it inside, and
/// the name reads the argument passed for it again once the inner scope
/// ends. The argument binds by position, to the parameter's own name.
#[test]
fn a_binder_shadows_an_outer_name_only_within_its_scope() {
    let k = kernel();
    let c = coord(&k);
    let tt = c
        .type_check(
            vec![(v(2), Sort::Nat)],
            and(
                let_(2, lit_addr(&ca(1)), addr_eq(var(2), lit_addr(&ca(1)))),
                nat_eq(var(2), lit_nat(7)),
            ),
        )
        .expect("v2: Addr inside the let, the Nat parameter outside it");
    let s = k.snapshot();
    assert!(c.decide(&tt, &[Value::Nat(n(7))], View::Active, &s));
    assert!(!c.decide(&tt, &[Value::Nat(n(8))], View::Active, &s));
}

#[test]
#[should_panic(expected = "decide precondition")]
fn decide_panics_on_a_non_boolean_codomain() {
    let k = kernel();
    let c = coord(&k);
    let tt = c.type_check(vec![], lit_nat(1)).expect("Nat-codomain term");
    let s = k.snapshot();
    let _ = c.decide(&tt, &[], View::Active, &s);
}

/// `eval`'s door: an argument at the wrong sort for its Γ_D parameter is a
/// precondition violation named at the door, not a failure somewhere inside
/// the walk.
#[test]
#[should_panic(expected = "eval precondition violated: ArgSortMismatch")]
fn eval_panics_on_a_mis_sorted_argument() {
    let k = kernel();
    let c = coord(&k);
    let tt = c.type_check(vec![(v(1), Sort::Addr)], tru()).expect("one-param term");
    let s = k.snapshot();
    let _ = c.eval(&tt, &[Value::Nat(n(1))], View::Active, &s);
}

/// `eval`'s door, the other half: an argument list one short leaves a Γ_D
/// parameter unbound, and is named at the door too.
#[test]
#[should_panic(expected = "eval precondition violated: ArgArityMismatch")]
fn eval_panics_on_a_missing_argument() {
    let k = kernel();
    let c = coord(&k);
    let tt = c.type_check(vec![(v(1), Sort::Addr)], tru()).expect("one-param term");
    let s = k.snapshot();
    let _ = c.eval(&tt, &[], View::Active, &s);
}

/// `eval`'s door, the other way round: an extra argument binds no
/// parameter, and is named at the door rather than ignored.
#[test]
#[should_panic(expected = "eval precondition violated: ArgArityMismatch")]
fn eval_panics_on_an_extra_argument() {
    let k = kernel();
    let c = coord(&k);
    let tt = c.type_check(vec![(v(1), Sort::Addr)], tru()).expect("one-param term");
    let s = k.snapshot();
    let _ = c.eval(&tt, &[Value::Addr(ca(1)), Value::Addr(ca(2))], View::Active, &s);
}

/// `eval`'s ref-free door is the precondition itself, not the evaluator's
/// `Ref` arm behind it: the reference sits where evaluation never reaches it,
/// `⊥ ∧ P`, so only the door can refuse the term, and the panic must be the
/// door's own. (A bare `Ref` cannot tell the two apart: the `Ref` arm's panic
/// opens "eval precondition violated" too.)
#[test]
#[should_panic(expected = "eval precondition violated: ref-bearing TypedTerm")]
fn eval_panics_on_a_ref_bearing_term() {
    let k = kernel();
    let c = coord(&k);
    let (p, _) = c
        .define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("closed True"))
        .expect("define");
    let tt = c
        .type_check(vec![], and(fls(), Term::Ref { addr: p, args: vec![] }))
        .expect("ref-bearing checks");
    assert!(!tt.is_ref_free());
    let s = k.snapshot();
    let _ = c.eval(&tt, &[], View::Active, &s);
}
