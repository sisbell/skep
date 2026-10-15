//! The merge's unit suite: the merge record's §9 vectors, each row one
//! test over `compose_runs` with the row's literal runs, asserting M as
//! runs, the gap kinds, the `settled` flags and the value log as the table
//! stands after the rulings; the resolutions, one per unsettled kind; the
//! fences the module promises; the one rule as a property over generated
//! inputs; `base_of` over §1.2's address forms; `script` over three pairs.
//! No board: every value read is a closure over a table the test writes.
//!
//! The notation is the record's: `(D,s,w)` is the run of `w` positions of
//! `D` from `D·s`; the base `D.2` is `[(D,1,11)]` "the cat sat" — `D·1–4`
//! "the ", `5–7` "cat", `8–11` " sat"; A's fresh identity takes `D·12…`,
//! B's the ordinals after it.

use std::collections::BTreeSet;

use skep_address::Address;

use crate::address::parse_address;

use super::*;

// ── the notation ─────────────────────────────────────────────────────────

fn addr(s: &str) -> Address {
    parse_address(s).unwrap()
}

/// `D`, the document.
fn d() -> Address {
    addr("1.0.1.0.1")
}

/// `Z`, another document of the same account.
fn z() -> Address {
    addr("1.0.1.0.2")
}

/// `F`, a cross-owner fork in another account.
fn f() -> Address {
    addr("1.0.2.0.1")
}

/// `(D,s,w)`.
fn rd(s: u64, w: u64) -> Run {
    Run::new(d(), s, w)
}

/// `D·n`, the address of the document's position `n`.
fn d_at(n: u64) -> Address {
    rd(n, 1).address_at(0).unwrap()
}

/// The base `D.2`.
fn base() -> Vec<Run> {
    vec![rd(1, 11)]
}

fn two(a: Vec<Run>, b: Vec<Run>) -> Vec<(SideIx, Vec<Run>)> {
    vec![(SideIx(0), a), (SideIx(1), b)]
}

/// No value read answers.
fn unread(_: SideIx, _: &Run) -> Option<Vec<Item>> {
    None
}

/// A value read over the document's bytes: `table` names what stands at
/// each run of `D`, one item per position; a position outside it, or
/// another origin, answers `None`.
fn text(table: &'static [(u64, &'static str)]) -> impl Fn(SideIx, &Run) -> Option<Vec<Item>> {
    move |_: SideIx, run: &Run| {
        if run.origin != d() {
            return None;
        }
        (run.i_start..run.reach())
            .map(|n| {
                table.iter().find_map(|(start, s)| {
                    let k = n.checked_sub(*start)? as usize;
                    s.as_bytes().get(k).map(|b| vec![*b])
                })
            })
            .collect()
    }
}

fn compose(base: &[Run], sides: &[(SideIx, Vec<Run>)]) -> Composed {
    compose_runs(base, sides, None, &Options::default(), &unread)
}

fn runs(c: &Composed) -> Vec<Run> {
    c.runs.iter().map(|p| p.run.clone()).collect()
}

fn kinds(c: &Composed) -> Vec<(GapKind, bool)> {
    c.gaps.iter().map(|g| (g.kind, g.settled)).collect()
}

/// The ordinal an anchor names, or none.
fn ordinal(a: &Option<Address>) -> Option<u64> {
    a.as_ref().map(|a| u64::try_from(a.tumbler().iter().last().unwrap()).unwrap())
}

fn anchors(c: &Composed) -> Vec<(Option<u64>, Option<u64>)> {
    c.gaps.iter().map(|g| (ordinal(&g.after), ordinal(&g.before))).collect()
}

fn gap_runs(c: &Composed) -> Vec<Vec<(u8, Run)>> {
    c.gaps.iter().map(|g| g.runs.iter().map(|(s, r)| (s.0, r.clone())).collect()).collect()
}

fn resolve(gap: u32, choice: Choice) -> Options {
    Options {
        resolutions: vec![Resolution { gap: GapId(gap), choice, by: ResolvedBy::Person }],
        ..Options::default()
    }
}

// ── the §9 vectors ───────────────────────────────────────────────────────

/// (a) disjoint: "big " at `D·4|D·5` on A, `8–11` removed on B — the two
/// sides touched different material, so M holds both and nothing is asked.
#[test]
fn case_a_disjoint() {
    let c = compose(&base(), &two(vec![rd(1, 4), rd(12, 4), rd(5, 7)], vec![rd(1, 7)]));
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 4), rd(5, 3)], "the big cat");
    assert_eq!(kinds(&c), vec![]);
    assert_eq!(c.counts, RunCounts { a: 3, b: 1, m: 3 });
    assert_eq!(c.runs.iter().map(|p| p.side).collect::<Vec<_>>(), vec![None, Some(SideIx(0)), None]);
}

/// (b) one gap, both add: "big " and "fat " at `D·4|D·5` — an `order` gap,
/// unsettled, the default `[A,B]` shown, A's and B's fresh runs coalescing.
#[test]
fn case_b_one_gap_both_add_is_an_order_gap_unsettled() {
    let c = compose(&base(), &two(vec![rd(1, 4), rd(12, 4), rd(5, 7)], vec![rd(1, 4), rd(16, 4), rd(5, 7)]));
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 8), rd(5, 7)], "the big fat cat sat");
    assert_eq!(kinds(&c), vec![(GapKind::Order, false)]);
    assert_eq!(anchors(&c), vec![(Some(4), Some(5))]);
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(0), SideIx(1)]));
    assert_eq!(c.gaps[0].resolved_by, None);
    assert_eq!(gap_runs(&c), vec![vec![(0, rd(12, 4)), (1, rd(16, 4))]]);
    assert_eq!(c.counts, RunCounts { a: 3, b: 3, m: 3 });
}

/// (c) A edits, B deletes: "dog" for `5–7` against `5–11` removed — the
/// removals overlap, a `collision`, unsettled, the default after `D·4`.
#[test]
fn case_c_an_edit_against_a_deletion_is_a_collision_unsettled() {
    let c = compose(&base(), &two(vec![rd(1, 4), rd(12, 3), rd(8, 4)], vec![rd(1, 4)]));
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 3)], "the dog");
    assert_eq!(kinds(&c), vec![(GapKind::Collision, false)]);
    assert_eq!(anchors(&c), vec![(Some(4), None)]);
    assert_eq!(c.gaps[0].placed, Placement::After);
    assert_eq!(gap_runs(&c), vec![vec![(0, rd(12, 3))]]);
}

/// (d) the mirror of (c): the same answer whichever side landed first.
#[test]
fn case_d_the_mirror_collision_is_order_independent() {
    let c = compose(&base(), &two(vec![rd(1, 4)], vec![rd(1, 4), rd(12, 3), rd(8, 4)]));
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 3)], "the dog");
    assert_eq!(kinds(&c), vec![(GapKind::Collision, false)]);
    assert_eq!(gap_runs(&c), vec![vec![(1, rd(12, 3))]]);
}

/// (e) a move with an edit inside it: A swaps the two halves, B adds "fat "
/// inside the moved half — no gap; the spine is A's order.
#[test]
fn case_e_a_move_with_an_edit_inside_takes_the_movers_order_and_asks_nothing() {
    let c = compose(&base(), &two(vec![rd(5, 7), rd(1, 4)], vec![rd(1, 7), rd(12, 4), rd(8, 4)]));
    assert_eq!(runs(&c), vec![rd(5, 3), rd(12, 4), rd(8, 4), rd(1, 4)], "catfat  satthe ");
    assert_eq!(kinds(&c), vec![]);
    assert_eq!(c.counts, RunCounts { a: 2, b: 3, m: 4 });
}

/// (e′) the cut: B's "fat " at `D·4|D·5`, which A's move pulled apart — a
/// `cut`, unsettled, the default after the left anchor.
#[test]
fn case_e_prime_an_addition_at_a_cut_is_unsettled_with_the_left_default() {
    let c = compose(&base(), &two(vec![rd(5, 7), rd(1, 4)], vec![rd(1, 4), rd(12, 4), rd(5, 7)]));
    assert_eq!(runs(&c), vec![rd(5, 7), rd(1, 4), rd(12, 4)], "cat satthe fat ");
    assert_eq!(kinds(&c), vec![(GapKind::Cut, false)]);
    assert_eq!(anchors(&c), vec![(Some(4), None)]);
    assert_eq!(c.gaps[0].placed, Placement::After);
}

/// (f) a retype beside an edit: A retyped "cat", B added "!" at `D·7|D·8`
/// — an `anchor` for B's "!", its left anchor gone, placed immediately
/// before `D·8`, so after A's group: different spots, settled, retype off.
#[test]
fn case_f_a_retype_beside_an_addition_is_an_anchor_settled() {
    let c = compose(&base(), &two(vec![rd(1, 4), rd(12, 3), rd(8, 4)], vec![rd(1, 7), rd(15, 1), rd(8, 4)]));
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 4), rd(8, 4)], "the cat! sat");
    assert_eq!(kinds(&c), vec![(GapKind::Anchor, true)]);
    assert_eq!(c.gaps[0].resolved_by, Some(ResolvedBy::Rule));
    assert_eq!(c.gaps[0].placed, Placement::Before);
    assert_eq!(anchors(&c), vec![(Some(4), Some(8))]);
    assert_eq!(gap_runs(&c), vec![vec![(1, rd(15, 1))]]);
    assert_eq!(c.values, ValueLog { dedup: true, retype: false, applied: vec![] });
}

/// (f′) an edit inside the retyped word, retype off: B's "-" at `D·5|D·6`
/// lost both anchors to A's retype — a `corner`, unsettled, the left
/// default shown after A's "cat".
#[test]
fn case_f_prime_an_edit_inside_a_retyped_word_is_a_corner_unsettled() {
    let c = compose(&base(), &two(vec![rd(1, 4), rd(12, 3), rd(8, 4)], vec![rd(1, 5), rd(16, 1), rd(6, 6)]));
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 3), rd(16, 1), rd(8, 4)], "the cat- sat");
    assert_eq!(kinds(&c), vec![(GapKind::Corner, false)]);
    assert_eq!(anchors(&c), vec![(Some(4), Some(8))]);
    assert_eq!(c.gaps[0].placed, Placement::After);
    assert_eq!(gap_runs(&c), vec![vec![(1, rd(16, 1))]]);
}

/// (f′) with the retype normalization on: A's "cat" equals the "cat" it
/// replaced, so the base's identity is kept and B's "-" keeps its anchors.
#[test]
fn case_f_prime_with_retype_on_keeps_the_base_identity() {
    let values = text(&[(1, "the cat sat"), (12, "cat"), (16, "-")]);
    let options = Options { retype: true, ..Options::default() };
    let sides = two(vec![rd(1, 4), rd(12, 3), rd(8, 4)], vec![rd(1, 5), rd(16, 1), rd(6, 6)]);
    let c = compose_runs(&base(), &sides, None, &options, &values);
    assert_eq!(runs(&c), vec![rd(1, 5), rd(16, 1), rd(6, 6)], "the c-at sat");
    assert_eq!(kinds(&c), vec![]);
    assert_eq!(c.values, ValueLog { dedup: true, retype: true, applied: vec![] });
    // The retype is undone only where the bytes are equal.
    let other = text(&[(1, "the cat sat"), (12, "dog"), (16, "-")]);
    let c = compose_runs(&base(), &sides, None, &options, &other);
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 3), rd(16, 1), rd(8, 4)]);
    assert_eq!(kinds(&c), vec![(GapKind::Corner, false)]);
}

/// (g) the same text both sides, dedup on: "big " added at one spot by
/// both — kept once, A's identity, the gap settled by the value rule and
/// logged under `values.applied`.
#[test]
fn case_g_the_same_words_added_by_both_are_kept_once_under_dedup() {
    let values = text(&[(1, "the cat sat"), (12, "big "), (16, "big ")]);
    let sides = two(vec![rd(1, 4), rd(12, 4), rd(5, 7)], vec![rd(1, 4), rd(16, 4), rd(5, 7)]);
    let c = compose_runs(&base(), &sides, None, &Options::default(), &values);
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 4), rd(5, 7)], "the big cat sat");
    assert_eq!(kinds(&c), vec![(GapKind::Order, true)]);
    assert_eq!(c.gaps[0].resolved_by, Some(ResolvedBy::Rule));
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(0)]));
    assert_eq!(gap_runs(&c), vec![vec![(0, rd(12, 4)), (1, rd(16, 4))]], "the dropped run is listed");
    assert_eq!(c.values.applied, vec![GapId(1)]);
}

/// (g) with dedup off: both kept at an `order` gap, unsettled — and never
/// coalesced on value: I-adjacent runs join, equal bytes apart stay apart.
#[test]
fn case_g_with_dedup_off_keeps_both_and_never_coalesces_on_value() {
    let values = text(&[(1, "the cat sat"), (12, "big "), (16, "big "), (17, "big ")]);
    let options = Options { dedup: false, ..Options::default() };
    let a = vec![rd(1, 4), rd(12, 4), rd(5, 7)];
    let c = compose_runs(&base(), &two(a.clone(), vec![rd(1, 4), rd(16, 4), rd(5, 7)]), None, &options, &values);
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 8), rd(5, 7)], "the big big cat sat");
    assert_eq!(kinds(&c), vec![(GapKind::Order, false)]);
    assert_eq!(c.values, ValueLog { dedup: false, retype: false, applied: vec![] });
    let c = compose_runs(&base(), &two(a, vec![rd(1, 4), rd(17, 4), rd(5, 7)]), None, &options, &values);
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 4), rd(17, 4), rd(5, 7)], "equal bytes, apart: two runs");
    assert_eq!(c.counts.m, 4);
}

/// (h) a window deleted under: A's "hello" from `Z` at `D·4|D·5`, B
/// removed `5–7` — an `anchor`, settled, the window kept after `D·4`.
#[test]
fn case_h_a_window_beside_a_removal_is_an_anchor_settled() {
    let w = Run::new(z(), 1, 5);
    let c = compose(&base(), &two(vec![rd(1, 4), w.clone(), rd(5, 7)], vec![rd(1, 4), rd(8, 4)]));
    assert_eq!(runs(&c), vec![rd(1, 4), w, rd(8, 4)], "the hello sat");
    assert_eq!(kinds(&c), vec![(GapKind::Anchor, true)]);
    assert_eq!(c.gaps[0].placed, Placement::After);
    assert_eq!(anchors(&c), vec![(Some(4), Some(8))]);
}

/// (i) an atom replaced on one side, the other untouched: no gap.
#[test]
fn case_i_an_atom_replaced_on_one_side_asks_nothing() {
    let c = compose(&base(), &two(vec![rd(1, 2), rd(12, 1), rd(4, 8)], vec![rd(1, 11)]));
    assert_eq!(runs(&c), vec![rd(1, 2), rd(12, 1), rd(4, 8)]);
    assert_eq!(kinds(&c), vec![]);
}

/// (i′) both replace the atom: a `collision` at the atom's grain,
/// unsettled, both replacements kept in the commit order as the default.
#[test]
fn case_i_prime_an_atom_replaced_on_both_sides_is_a_collision() {
    let c = compose(&base(), &two(vec![rd(1, 2), rd(12, 1), rd(4, 8)], vec![rd(1, 2), rd(13, 1), rd(4, 8)]));
    assert_eq!(runs(&c), vec![rd(1, 2), rd(12, 2), rd(4, 8)]);
    assert_eq!(kinds(&c), vec![(GapKind::Collision, false)]);
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(0), SideIx(1)]));
    assert_eq!(anchors(&c), vec![(Some(2), Some(4))]);
    assert_eq!(gap_runs(&c), vec![vec![(0, rd(12, 1)), (1, rd(13, 1))]]);
}

/// (j) a fork merged back, as the composition it will serve: A's "big " at
/// `D·4|D·5`, F's "dog" for `5–7` — an `anchor` for A's, its right anchor
/// gone, settled; F's group last, not in the chain. The refusal of the
/// shape until the fork-source read lands is the reads', not the core's.
#[test]
fn case_j_a_fork_merged_back_composes_with_the_fork_last() {
    let dog = Run::new(f(), 1, 3);
    let c = compose(&base(), &two(vec![rd(1, 4), rd(12, 4), rd(5, 7)], vec![rd(1, 4), dog.clone(), rd(8, 4)]));
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 4), dog, rd(8, 4)], "the big dog sat");
    assert_eq!(kinds(&c), vec![(GapKind::Anchor, true)]);
    assert_eq!(c.gaps[0].placed, Placement::After);
    assert_eq!(gap_runs(&c), vec![vec![(0, rd(12, 4))]]);
    assert_eq!(c.counts, RunCounts { a: 3, b: 3, m: 4 });
}

/// Two daughters folded over one base, three sides in: an `order` gap at
/// `D·4|D·5` between A's "big " and B1's "fat ", unsettled, the default
/// `[A,B1]`; B2's "!" at its own spot asks nothing.
#[test]
fn case_two_daughters_fold_as_three_sides_over_one_base() {
    let sides = vec![
        (SideIx(0), vec![rd(1, 4), rd(12, 4), rd(5, 7)]),
        (SideIx(1), vec![rd(1, 4), rd(16, 4), rd(5, 7)]),
        (SideIx(2), vec![rd(1, 7), rd(20, 1), rd(8, 4)]),
    ];
    let c = compose(&base(), &sides);
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 8), rd(5, 3), rd(20, 1), rd(8, 4)], "the big fat cat! sat");
    assert_eq!(kinds(&c), vec![(GapKind::Order, false)]);
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(0), SideIx(1)]));
    assert_eq!(anchors(&c), vec![(Some(4), Some(5))]);
    assert_eq!(c.counts, RunCounts { a: 3, b: 6, m: 5 });
}

/// The corner, all gone: A's "X" at `D·6|D·7`, B removed everything — a
/// `corner` at the start, unsettled, the default shown.
#[test]
fn case_the_corner_with_nothing_surviving_defaults_to_the_start() {
    let c = compose(&base(), &two(vec![rd(1, 6), rd(12, 1), rd(7, 5)], vec![]));
    assert_eq!(runs(&c), vec![rd(12, 1)], "X");
    assert_eq!(kinds(&c), vec![(GapKind::Corner, false)]);
    assert_eq!(anchors(&c), vec![(None, None)]);
    assert_eq!(c.gaps[0].placed, Placement::After);
    assert_eq!(c.counts, RunCounts { a: 3, b: 0, m: 1 });
}

/// The corner, a left survivor: B removed `5–11` — a `corner` after `D·4`
/// as the default shown, unsettled.
#[test]
fn case_the_corner_with_a_left_survivor_defaults_after_it() {
    let c = compose(&base(), &two(vec![rd(1, 6), rd(12, 1), rd(7, 5)], vec![rd(1, 4)]));
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 1)], "the X");
    assert_eq!(kinds(&c), vec![(GapKind::Corner, false)]);
    assert_eq!(anchors(&c), vec![(Some(4), None)]);
}

/// The agent case: "dog" and "kitten" both for `5–7` — a `collision` with
/// both runs in the gap, unsettled; the preview shows both in order.
#[test]
fn case_the_agent_case_lists_both_rewrites_in_one_collision() {
    let c = compose(&base(), &two(vec![rd(1, 4), rd(12, 3), rd(8, 4)], vec![rd(1, 4), rd(16, 6), rd(8, 4)]));
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 3), rd(16, 6), rd(8, 4)], "the dogkitten sat");
    assert_eq!(kinds(&c), vec![(GapKind::Collision, false)]);
    assert_eq!(gap_runs(&c), vec![vec![(0, rd(12, 3)), (1, rd(16, 6))]]);
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(0), SideIx(1)]));
    assert_eq!(anchors(&c), vec![(Some(4), Some(8))]);
}

/// A collision with nothing put in its place is still listed, by its
/// anchors (decision 3, widened): `5–7` removed on A, `5–11` on B.
#[test]
fn a_collision_with_nothing_placed_is_listed_by_its_anchors() {
    let c = compose(&base(), &two(vec![rd(1, 4), rd(8, 4)], vec![rd(1, 4)]));
    assert_eq!(runs(&c), vec![rd(1, 4)]);
    assert_eq!(kinds(&c), vec![(GapKind::Collision, false)]);
    assert_eq!(anchors(&c), vec![(Some(4), None)]);
    assert!(c.gaps[0].runs.is_empty());
}

/// Both sides moved overlapping material — base `X Y Z`, A `Y X Z`, B
/// `X Z Y` — a `moves` gap, unsettled, the earlier side's order the
/// default and the later side's reorder not applied.
#[test]
fn case_moves_both_sides_reordering_overlapping_material() {
    let c = compose(&[rd(1, 3)], &two(vec![rd(2, 1), rd(1, 1), rd(3, 1)], vec![rd(1, 1), rd(3, 1), rd(2, 1)]));
    assert_eq!(runs(&c), vec![rd(2, 1), rd(1, 1), rd(3, 1)], "A's order");
    assert_eq!(kinds(&c), vec![(GapKind::Moves, false)]);
    assert_eq!(anchors(&c), vec![(None, None)]);
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(0)]));
    assert_eq!(gap_runs(&c), vec![vec![(0, rd(2, 1)), (1, rd(3, 1))]], "what each side moved");
}

/// Two reorders of different material compose: base `X Y Z W`, A moved X
/// after Y, B moved Z after W — both applied, no gap.
#[test]
fn two_reorders_of_different_material_compose_without_a_gap() {
    let c = compose(&[rd(1, 4)], &two(vec![rd(2, 1), rd(1, 1), rd(3, 2)], vec![rd(1, 2), rd(4, 1), rd(3, 1)]));
    assert_eq!(runs(&c), vec![rd(2, 1), rd(1, 1), rd(4, 1), rd(3, 1)], "Y X W Z");
    assert_eq!(kinds(&c), vec![]);
}

/// `spine_hint` names the side whose order the spine takes: under B's
/// order, A's move of (e) is a `moves` gap instead of the spine.
#[test]
fn the_spine_hint_picks_the_side_whose_order_the_spine_takes() {
    let sides = two(vec![rd(5, 7), rd(1, 4)], vec![rd(1, 7), rd(12, 4), rd(8, 4)]);
    let c = compose_runs(&base(), &sides, Some(SideIx(1)), &Options::default(), &unread);
    assert_eq!(runs(&c), vec![rd(1, 7), rd(12, 4), rd(8, 4)]);
    assert_eq!(kinds(&c), vec![(GapKind::Moves, false)]);
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(1)]));
}

/// A fresh identity two sides hold — a daughter chain's shared text — is
/// placed once, where the earlier side holds it.
#[test]
fn a_fresh_identity_two_sides_hold_is_placed_once() {
    let c = compose(&base(), &two(vec![rd(1, 4), rd(12, 4), rd(5, 7)], vec![rd(1, 4), rd(12, 4), rd(5, 7)]));
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 4), rd(5, 7)]);
    assert_eq!(kinds(&c), vec![]);
}

// ── the resolutions ──────────────────────────────────────────────────────

/// An `order` gap resolved `Order([B,A])`: the groups swapped, the gap
/// settled by the person.
#[test]
fn an_order_gap_takes_the_mergers_order() {
    let sides = two(vec![rd(1, 4), rd(12, 4), rd(5, 7)], vec![rd(1, 4), rd(16, 4), rd(5, 7)]);
    let options = resolve(1, Choice::Order(vec![SideIx(1), SideIx(0)]));
    let c = compose_runs(&base(), &sides, None, &options, &unread);
    assert_eq!(runs(&c), vec![rd(1, 4), rd(16, 4), rd(12, 4), rd(5, 7)], "the fat big cat sat");
    assert_eq!(kinds(&c), vec![(GapKind::Order, true)]);
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(1), SideIx(0)]));
    assert_eq!(c.gaps[0].resolved_by, Some(ResolvedBy::Person));
    assert!(c.ignored.is_empty());
}

/// A `collision` resolved `KeepOnly(B)` keeps one rewrite; `KeepBoth`
/// confirms the default; either settles it.
#[test]
fn a_collision_takes_keep_only_and_keep_both() {
    let sides = two(vec![rd(1, 4), rd(12, 3), rd(8, 4)], vec![rd(1, 4), rd(16, 6), rd(8, 4)]);
    let c = compose_runs(&base(), &sides, None, &resolve(1, Choice::KeepOnly(SideIx(1))), &unread);
    assert_eq!(runs(&c), vec![rd(1, 4), rd(16, 6), rd(8, 4)], "the kitten sat");
    assert_eq!(kinds(&c), vec![(GapKind::Collision, true)]);
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(1)]));
    assert_eq!(c.gaps[0].resolved_by, Some(ResolvedBy::Person));
    let c = compose_runs(&base(), &sides, None, &resolve(1, Choice::KeepBoth), &unread);
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 3), rd(16, 6), rd(8, 4)]);
    assert_eq!(kinds(&c), vec![(GapKind::Collision, true)]);
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(0), SideIx(1)]));
}

/// A `cut` resolved `Before(D·5)`: "fat " placed where the writer meant
/// it, before the moved "cat sat".
#[test]
fn a_cut_takes_a_before_placement() {
    let sides = two(vec![rd(5, 7), rd(1, 4)], vec![rd(1, 4), rd(12, 4), rd(5, 7)]);
    let c = compose_runs(&base(), &sides, None, &resolve(1, Choice::Before(d_at(5))), &unread);
    assert_eq!(runs(&c), vec![rd(12, 4), rd(5, 7), rd(1, 4)], "fat cat satthe ");
    assert_eq!(kinds(&c), vec![(GapKind::Cut, true)]);
    assert_eq!(c.gaps[0].placed, Placement::Before);
    assert_eq!(anchors(&c), vec![(None, Some(5))]);
    assert_eq!(c.gaps[0].resolved_by, Some(ResolvedBy::Person));
}

/// A `corner` resolved `Omit` drops the run from M and logs it as omitted;
/// resolved `Before(D·1)` it moves.
#[test]
fn a_corner_takes_omit_and_a_placement() {
    let sides = two(vec![rd(1, 6), rd(12, 1), rd(7, 5)], vec![rd(1, 4)]);
    let c = compose_runs(&base(), &sides, None, &resolve(1, Choice::Omit), &unread);
    assert_eq!(runs(&c), vec![rd(1, 4)], "the ");
    assert_eq!(kinds(&c), vec![(GapKind::Corner, true)]);
    assert_eq!(c.gaps[0].placed, Placement::Omitted);
    assert_eq!(gap_runs(&c), vec![vec![(0, rd(12, 1))]], "the omitted run stays listed");
    assert_eq!(c.gaps[0].resolved_by, Some(ResolvedBy::Person));
    let c = compose_runs(&base(), &sides, None, &resolve(1, Choice::Before(d_at(1))), &unread);
    assert_eq!(runs(&c), vec![rd(12, 1), rd(1, 4)], "Xthe ");
    assert_eq!(anchors(&c), vec![(None, Some(1))]);
}

/// A `moves` gap resolved `Order([B])` re-walks under B's order and marks
/// the gap settled by the chooser.
#[test]
fn a_moves_gap_takes_the_other_sides_order() {
    let sides = two(vec![rd(2, 1), rd(1, 1), rd(3, 1)], vec![rd(1, 1), rd(3, 1), rd(2, 1)]);
    let by = ResolvedBy::Agent;
    let options = Options {
        resolutions: vec![Resolution { gap: GapId(1), choice: Choice::Order(vec![SideIx(1)]), by: by.clone() }],
        ..Options::default()
    };
    let c = compose_runs(&[rd(1, 3)], &sides, None, &options, &unread);
    assert_eq!(runs(&c), vec![rd(1, 1), rd(3, 1), rd(2, 1)], "B's order");
    assert_eq!(kinds(&c), vec![(GapKind::Moves, true)]);
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(1)]));
    assert_eq!(c.gaps[0].resolved_by, Some(by));
    assert!(c.ignored.is_empty());
}

/// A resolution naming a gap the rules settled, a gap not in the report,
/// or a choice the gap cannot take is ignored and returned untouched.
#[test]
fn a_resolution_on_a_settled_gap_is_ignored_and_reported() {
    let sides = two(vec![rd(1, 4), rd(12, 3), rd(8, 4)], vec![rd(1, 7), rd(15, 1), rd(8, 4)]);
    let on_settled = Resolution { gap: GapId(1), choice: Choice::Omit, by: ResolvedBy::Person };
    let unknown = Resolution { gap: GapId(9), choice: Choice::Omit, by: ResolvedBy::Person };
    let options = Options { resolutions: vec![on_settled.clone(), unknown.clone()], ..Options::default() };
    let c = compose_runs(&base(), &sides, None, &options, &unread);
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 4), rd(8, 4)], "unchanged");
    assert_eq!(kinds(&c), vec![(GapKind::Anchor, true)]);
    assert_eq!(c.gaps[0].resolved_by, Some(ResolvedBy::Rule));
    assert_eq!(c.ignored, vec![on_settled, unknown]);
    // A choice the kind cannot take: `KeepBoth` at a one-sided corner.
    let sides = two(vec![rd(1, 6), rd(12, 1), rd(7, 5)], vec![rd(1, 4)]);
    let c = compose_runs(&base(), &sides, None, &resolve(1, Choice::KeepBoth), &unread);
    assert_eq!(kinds(&c), vec![(GapKind::Corner, false)]);
    assert_eq!(c.ignored.len(), 1);
}

// ── the fences ───────────────────────────────────────────────────────────

/// Every vector of §9 and the record's additions, named, as composed by
/// the defaults with the values the row needs.
fn vectors() -> Vec<(&'static str, Composed)> {
    let same = text(&[(1, "the cat sat"), (12, "big "), (16, "big ")]);
    let a = || vec![rd(1, 4), rd(12, 4), rd(5, 7)];
    let edit = || vec![rd(1, 4), rd(12, 3), rd(8, 4)];
    let moved = || vec![rd(5, 7), rd(1, 4)];
    vec![
        ("a", compose(&base(), &two(a(), vec![rd(1, 7)]))),
        ("b", compose(&base(), &two(a(), vec![rd(1, 4), rd(16, 4), rd(5, 7)]))),
        ("c", compose(&base(), &two(edit(), vec![rd(1, 4)]))),
        ("d", compose(&base(), &two(vec![rd(1, 4)], edit()))),
        ("e", compose(&base(), &two(moved(), vec![rd(1, 7), rd(12, 4), rd(8, 4)]))),
        ("e′", compose(&base(), &two(moved(), a()))),
        ("f", compose(&base(), &two(edit(), vec![rd(1, 7), rd(15, 1), rd(8, 4)]))),
        ("f′", compose(&base(), &two(edit(), vec![rd(1, 5), rd(16, 1), rd(6, 6)]))),
        ("g", compose_runs(&base(), &two(a(), vec![rd(1, 4), rd(16, 4), rd(5, 7)]), None, &Options::default(), &same)),
        ("h", compose(&base(), &two(vec![rd(1, 4), Run::new(z(), 1, 5), rd(5, 7)], vec![rd(1, 4), rd(8, 4)]))),
        ("i", compose(&base(), &two(vec![rd(1, 2), rd(12, 1), rd(4, 8)], vec![rd(1, 11)]))),
        ("i′", compose(&base(), &two(vec![rd(1, 2), rd(12, 1), rd(4, 8)], vec![rd(1, 2), rd(13, 1), rd(4, 8)]))),
        ("j", compose(&base(), &two(a(), vec![rd(1, 4), Run::new(f(), 1, 3), rd(8, 4)]))),
        (
            "two daughters",
            compose(
                &base(),
                &[
                    (SideIx(0), a()),
                    (SideIx(1), vec![rd(1, 4), rd(16, 4), rd(5, 7)]),
                    (SideIx(2), vec![rd(1, 7), rd(20, 1), rd(8, 4)]),
                ],
            ),
        ),
        ("corner, all gone", compose(&base(), &two(vec![rd(1, 6), rd(12, 1), rd(7, 5)], vec![]))),
        ("corner, a left survivor", compose(&base(), &two(vec![rd(1, 6), rd(12, 1), rd(7, 5)], vec![rd(1, 4)]))),
        ("the agent case", compose(&base(), &two(edit(), vec![rd(1, 4), rd(16, 6), rd(8, 4)]))),
        ("moves", compose(&[rd(1, 3)], &two(vec![rd(2, 1), rd(1, 1), rd(3, 1)], vec![rd(1, 1), rd(3, 1), rd(2, 1)]))),
    ]
}

/// Six kinds, exactly, and one of them settles by rule: the only gap the
/// composition marks settled with no resolution is an `anchor`, or an
/// `order` gap the value rule emptied — over every vector.
#[test]
fn six_kinds_and_only_the_anchor_settles_by_rule() {
    let all = [GapKind::Order, GapKind::Anchor, GapKind::Corner, GapKind::Cut, GapKind::Collision, GapKind::Moves];
    for kind in all {
        // A seventh variant fails to compile here.
        let _: &str = match kind {
            GapKind::Order => "order",
            GapKind::Anchor => "anchor",
            GapKind::Corner => "corner",
            GapKind::Cut => "cut",
            GapKind::Collision => "collision",
            GapKind::Moves => "moves",
        };
    }
    assert_eq!(all.iter().collect::<BTreeSet<_>>().len(), 6);
    let mut seen = BTreeSet::new();
    for (name, c) in vectors() {
        for gap in &c.gaps {
            seen.insert(gap.kind);
            if gap.settled {
                assert_eq!(gap.resolved_by, Some(ResolvedBy::Rule), "{name}: settled by no rule");
                let emptied = gap.kind == GapKind::Order && c.values.applied.contains(&gap.id);
                assert!(gap.kind == GapKind::Anchor || emptied, "{name}: {:?} settled by rule", gap.kind);
            } else {
                assert_eq!(gap.resolved_by, None, "{name}");
            }
        }
    }
    assert_eq!(seen.len(), 6, "every kind arises in some vector: {seen:?}");
}

/// The §8 bound at every vector: `runs(M) ≤ runs(A) + runs(B) + G − 1`,
/// `G` the gaps listed; and `counts.m` is the coalesced list's length.
#[test]
fn the_run_count_bound_holds_at_every_vector() {
    for (name, c) in vectors() {
        let RunCounts { a, b, m } = c.counts;
        assert_eq!(m, c.runs.len(), "{name}: m is the coalesced length");
        assert!(m + 1 <= a + b + c.gaps.len(), "{name}: {m} runs from {a} + {b} with {} gaps", c.gaps.len());
        for pair in c.runs.windows(2) {
            let (left, right) = (&pair[0].run, &pair[1].run);
            assert!(left.origin != right.origin || left.reach() != right.i_start, "{name}: not coalesced");
        }
    }
}

/// The deletion rule, implicit and exact: an address either side removed
/// is absent from M; every stretch either side added is in M at exactly
/// one place — over every vector, by expansion.
#[test]
fn every_vector_keeps_every_addition_once_and_no_removal() {
    for (name, c) in vectors() {
        let positions: Vec<(Address, u64)> =
            c.runs.iter().flat_map(|p| (p.run.i_start..p.run.reach()).map(move |n| (p.run.origin.clone(), n))).collect();
        let distinct: BTreeSet<&(Address, u64)> = positions.iter().collect();
        assert_eq!(distinct.len(), positions.len(), "{name}: a position twice in M");
    }
}

// ── the one rule, as a property ──────────────────────────────────────────

/// splitmix64, the one generator the property draws from.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// One side's edits over a base of `n` positions, drawn at random.
struct Side {
    removed: BTreeSet<u64>,
    /// Each insert: the base position it follows (0 the start), its fresh
    /// start and width.
    inserts: Vec<(u64, u64, u64)>,
}

impl Side {
    fn draw(rng: &mut Rng, n: u64, fresh_from: u64) -> Side {
        let mut side = Side { removed: BTreeSet::new(), inserts: Vec::new() };
        for k in 0..rng.below(3) {
            if rng.below(2) == 0 {
                let from = 1 + rng.below(n);
                for p in from..(from + 1 + rng.below(3)).min(n + 1) {
                    side.removed.insert(p);
                }
            } else {
                side.inserts.push((rng.below(n + 1), fresh_from + 10 * k, 1 + rng.below(3)));
            }
        }
        side
    }

    /// The side's run list: the base less its removals, each insert after
    /// the position it follows.
    fn runs(&self, n: u64) -> Vec<Run> {
        let mut out: Vec<Run> = Vec::new();
        let mut push = |run: Run| match out.last_mut() {
            Some(last) if last.reach() == run.i_start => last.width += run.width,
            _ => out.push(run),
        };
        for p in 0..=n {
            if p >= 1 && !self.removed.contains(&p) {
                push(rd(p, 1));
            }
            for &(_, start, width) in self.inserts.iter().filter(|(after, _, _)| *after == p) {
                push(rd(start, width));
            }
        }
        out
    }

    /// Each insert's spot in the side's own sequence: the surviving base
    /// positions before and after it, 0 and `n + 1` at the ends.
    fn spots(&self, n: u64) -> Vec<(u64, u64)> {
        self.inserts
            .iter()
            .map(|&(after, _, _)| {
                let x = (1..=after).rev().find(|p| !self.removed.contains(p)).unwrap_or(0);
                let y = (after + 1..=n).find(|p| !self.removed.contains(p)).unwrap_or(n + 1);
                (x, y)
            })
            .collect()
    }

    fn fresh(&self) -> Vec<u64> {
        self.inserts.iter().flat_map(|&(_, start, width)| start..start + width).collect()
    }
}

/// Whether the two sides touched the same material or the same spot: a
/// base position both removed; a spot both added at; or a spot one added
/// at whose anchors the other both removed (§1.4's "touched": removed, or
/// inserted beside).
fn touched_the_same(a: &Side, b: &Side, n: u64) -> bool {
    let inside = |spot: &(u64, u64), other: &Side| other.removed.contains(&spot.0) && other.removed.contains(&spot.1);
    let (sa, sb) = (a.spots(n), b.spots(n));
    a.removed.intersection(&b.removed).next().is_some()
        || sa.iter().any(|s| sb.contains(s))
        || sa.iter().any(|s| inside(s, b))
        || sb.iter().any(|s| inside(s, a))
}

/// THE ONE RULE as a property: where the two sides touched different
/// material every gap is settled and M holds every run of both sides;
/// where they touched the same material or the same spot, at least one gap
/// is unsettled. And in either case M holds the base less both removals
/// and every addition, each once. Four thousand cases, both arms reached.
#[test]
fn the_one_rule_holds_over_generated_inputs() {
    let mut rng = Rng(0x5EED_2026_10_15);
    let (mut safe, mut conflicts) = (0, 0);
    for _ in 0..4000 {
        let n = 4 + rng.below(7);
        let (a, b) = (Side::draw(&mut rng, n, 100), Side::draw(&mut rng, n, 200));
        let c = compose(&[rd(1, n)], &two(a.runs(n), b.runs(n)));
        let unsettled = c.gaps.iter().any(|g| !g.settled);
        let same = touched_the_same(&a, &b, n);
        assert_eq!(unsettled, same, "A {:?} {:?}; B {:?} {:?}; gaps {:?}", a.removed, a.inserts, b.removed, b.inserts, c.gaps);
        if same {
            conflicts += 1;
        } else {
            safe += 1;
        }
        let mut expected: Vec<u64> =
            (1..=n).filter(|p| !a.removed.contains(p) && !b.removed.contains(p)).chain(a.fresh()).chain(b.fresh()).collect();
        expected.sort_unstable();
        let mut got: Vec<u64> = c.runs.iter().flat_map(|p| p.run.i_start..p.run.reach()).collect();
        got.sort_unstable();
        assert_eq!(got, expected, "A {:?} {:?}; B {:?} {:?}", a.removed, a.inserts, b.removed, b.inserts);
        assert_eq!(c.counts.m, c.runs.len());
    }
    assert!(safe > 500 && conflicts > 500, "{safe} safe, {conflicts} conflicts");
}

// ── base_of ──────────────────────────────────────────────────────────────

/// The base by §1.2's address forms: a trunk member against a daughter of
/// an earlier member, two daughters, a daughter's daughter against the
/// head, daughters of different members; none across chains or for a bare
/// document, a draft or an element.
#[test]
fn base_of_finds_the_nearest_common_ancestor_along_the_anchor_chains() {
    let m = |s: &str| addr(&format!("1.0.1.0.1.{s}"));
    assert_eq!(base_of(&m("3"), &m("2.1")), Some(m("2")), "D.k+1 against D.k.m");
    assert_eq!(base_of(&m("9"), &m("2.1")), Some(m("2")), "D.k+7 against D.k.m");
    assert_eq!(base_of(&m("2.1"), &m("2.2")), Some(m("2")), "two daughters");
    assert_eq!(base_of(&m("2.1.1"), &m("5")), Some(m("2")), "D.k.1.1 against the head");
    assert_eq!(base_of(&m("3.1"), &m("1.1")), Some(m("1")), "D.k.1 against D.j.1, j < k");
    assert_eq!(base_of(&m("2.1"), &m("3")), Some(m("2")), "the order of the two does not matter");
    assert_eq!(base_of(&m("2"), &m("2")), Some(m("2")), "a member against itself");
    assert_eq!(base_of(&m("2"), &m("5")), Some(m("2")), "a member against its descendant");
    assert_eq!(base_of(&m("1"), &m("1.1")), Some(m("1")), "the first member against its daughter");
    assert_eq!(base_of(&m("2"), &addr("1.0.1.0.2.2")), None, "across chains");
    assert_eq!(base_of(&d(), &m("2")), None, "a bare document — a draft's shape");
    assert_eq!(base_of(&d_at(4), &m("2")), None, "an element");
    assert_eq!(base_of(&addr("1.0.1"), &m("2")), None, "an account");
}

// ── script ───────────────────────────────────────────────────────────────

/// A draft's positions, expanded.
fn expand(runs: &[Run]) -> Vec<(Address, u64)> {
    runs.iter().flat_map(|r| (r.i_start..r.reach()).map(move |n| (r.origin.clone(), n))).collect()
}

/// The ops applied to a draft, in order, position by position.
fn apply(current: &[Run], ops: &[InPlaceOp]) -> Vec<(Address, u64)> {
    let mut draft = expand(current);
    for op in ops {
        match op {
            InPlaceOp::Delete { p, width } => {
                let at = (*p - 1) as usize;
                assert!(at + *width as usize <= draft.len(), "a delete past the draft: {op:?}");
                draft.drain(at..at + *width as usize);
            }
            InPlaceOp::Reinstate { at, runs } => {
                let at = (*at - 1) as usize;
                assert!(at <= draft.len(), "a reinstate past the draft: {op:?}");
                let placed = expand(runs);
                assert!(placed.iter().all(|p| !draft.contains(p)), "a position placed twice: {op:?}");
                draft.splice(at..at, placed);
            }
        }
    }
    draft
}

/// An insert is one `reinstate`; a delete one `delete`; a move a `delete`
/// then a `reinstate` — each script turning `current` into `target`.
#[test]
fn script_spells_an_insert_a_delete_and_a_move() {
    let insert = (vec![rd(1, 4)], vec![rd(1, 2), rd(9, 3), rd(3, 2)]);
    assert_eq!(script(&insert.0, &insert.1), vec![InPlaceOp::Reinstate { at: 3, runs: vec![rd(9, 3)] }]);
    let delete = (vec![rd(1, 6)], vec![rd(1, 2), rd(5, 2)]);
    assert_eq!(script(&delete.0, &delete.1), vec![InPlaceOp::Delete { p: 3, width: 2 }]);
    let moved = (vec![rd(1, 2), rd(3, 2)], vec![rd(3, 2), rd(1, 2)]);
    let ops = script(&moved.0, &moved.1);
    assert_eq!(ops.len(), 2, "{ops:?}");
    assert!(matches!(ops[0], InPlaceOp::Delete { .. }), "the delete comes first: {ops:?}");
    assert!(matches!(ops[1], InPlaceOp::Reinstate { .. }), "{ops:?}");
    for (current, target) in [insert, delete, moved] {
        assert_eq!(apply(&current, &script(&current, &target)), expand(&target));
    }
    assert!(script(&[rd(1, 4)], &[rd(1, 4)]).is_empty());
}

/// Two deletes are listed last-to-first, so each position holds when the
/// one before it has been applied.
#[test]
fn script_lists_deletes_last_to_first() {
    let (current, target) = (vec![rd(1, 9)], vec![rd(1, 2), rd(4, 2), rd(7, 3)]);
    let ops = script(&current, &target);
    assert_eq!(ops, vec![InPlaceOp::Delete { p: 6, width: 1 }, InPlaceOp::Delete { p: 3, width: 1 }]);
    assert_eq!(apply(&current, &ops), expand(&target));
}

/// `script` over generated pairs: every script turns `current` into
/// `target`, with no position placed twice.
#[test]
fn script_turns_current_into_target_over_generated_pairs() {
    let mut rng = Rng(7);
    for _ in 0..500 {
        let n = 3 + rng.below(6);
        let (a, b) = (Side::draw(&mut rng, n, 100), Side::draw(&mut rng, n, 200));
        let (current, target) = (a.runs(n), b.runs(n));
        let ops = script(&current, &target);
        assert_eq!(apply(&current, &ops), expand(&target), "{current:?} → {target:?}: {ops:?}");
    }
}

// ── the public types ─────────────────────────────────────────────────────

/// `Run::address_at` names the position at an offset inside the run and
/// nothing outside it; the defaults are decision 10's.
#[test]
fn a_run_names_its_positions_and_the_options_default_as_ruled() {
    let run = rd(12, 4);
    assert_eq!(run.address_at(0), Some(addr("1.0.1.0.1.0.1.12")));
    assert_eq!(run.address_at(3), Some(addr("1.0.1.0.1.0.1.15")));
    assert_eq!(run.address_at(4), None);
    assert_eq!(run.reach(), 16);
    assert_eq!(Run::new(addr("1.0.1"), 1, 1).address_at(0), None, "an account is no origin");
    let options = Options::default();
    assert!(options.dedup && !options.retype && options.resolutions.is_empty() && options.retries == 0);
}

// ── THE READS, THE LANDING AND THE RECORD over a scripted board ──────────
//
// A `Dialer` whose answers come from a `World` the test writes — each
// document's arrangement and values, the links, the claims, the feed —
// keeping every frame it served, so a walk pins what the module reads and
// writes, in what order, and what it makes of each answer, with no daemon.
// The one whole merge against the daemon is `tests/it/merge.rs`.

mod scripted {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex};

    use serde_json::{json, Value};
    use skep_address::Address;
    use skep_identity::{
        entry_body_publish, entry_frame, DocTerm, Fingerprint, PublicKey, ShotBase,
        ShotSegmentPiece,
    };
    use skep_signature::HybridSigner;

    use crate::address::parse_address;
    use crate::board::{frames, Board, Scope, HEAD_MEMBER_1};
    use crate::ceremony::handshake::{handshake, Session, Site};
    use crate::dial::{
        DialError, Dialer, Headers, Request, RequestHead, Response, StreamedResponse,
    };
    use crate::halt::Halt;
    use crate::merge::*;
    use crate::origin::Origin;
    use crate::sign::Signer;

    const TOKEN: &str = "9f3a6c21d4b8e07a5c1b2d4e6f708192";
    /// The merger's account and its doc 1.
    const ACCOUNT: &str = "1.0.1";
    const DOC1: &str = "1.0.1.0.1";
    /// `D`, the published document merged; `Z` another published document;
    /// `S` the merger's staging draft; `K` the document standing as the
    /// record kind; `F` a fork in another account, `OTHER_DOC1` that
    /// account's doc 1.
    const D: &str = "1.0.1.0.2";
    const Z: &str = "1.0.1.0.3";
    const S: &str = "1.0.1.0.4";
    const K: &str = "1.0.1.0.9";
    const F: &str = "1.0.2.0.7";
    const OTHER_DOC1: &str = "1.0.2.0.1";

    fn a(text: &str) -> Address {
        parse_address(text).expect("an address")
    }

    /// `(doc, s, w)`.
    fn run(doc: &str, s: u64, w: u64) -> Run {
        Run::new(a(doc), s, w)
    }

    fn i_addr(origin: &Address, ordinal: u64) -> String {
        format!("{origin}.0.1.{ordinal}")
    }

    fn reply(status: u16, body: Value) -> Response {
        Response { status, headers: Headers::default(), body: body.to_string().into_bytes() }
    }

    fn chain_hex(position: u64) -> String {
        format!("{position:064x}")
    }

    /// A V-span `{"start": "1.N", "width": "0.W"}` as `(from, width)`.
    fn span(v: &Value) -> (u64, u64) {
        let from = v["start"].as_str().unwrap().strip_prefix("1.").unwrap().parse().unwrap();
        let width = v["width"].as_str().unwrap().strip_prefix("0.").unwrap().parse().unwrap();
        (from, width)
    }

    /// The runs clipped to V-positions `from .. from + width`, each with the
    /// V-ordinal it begins at.
    fn clip(runs: &[Run], from: u64, width: u64) -> Vec<(u64, Run)> {
        let end = from + width;
        let mut out = Vec::new();
        let mut v = 1u64;
        for r in runs {
            let (lo, hi) = (v.max(from), (v + r.width).min(end));
            if lo < hi {
                out.push((lo, Run::new(r.origin.clone(), r.i_start + (lo - v), hi - lo)));
            }
            v += r.width;
        }
        out
    }

    fn expand(runs: &[Run]) -> Vec<(Address, u64)> {
        runs.iter()
            .flat_map(|r| (r.i_start..r.reach()).map(move |n| (r.origin.clone(), n)))
            .collect()
    }

    fn coalesce(positions: Vec<(Address, u64)>) -> Vec<Run> {
        let mut out: Vec<Run> = Vec::new();
        for (origin, n) in positions {
            if let Some(last) = out.last_mut() {
                if last.origin == origin && last.reach() == n {
                    last.width += 1;
                    continue;
                }
            }
            out.push(Run::new(origin, n, 1));
        }
        out
    }

    /// One position's value as the world holds it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Val {
        Byte(u8),
        Atom(String),
    }

    /// One document as the world holds it.
    #[derive(Debug, Clone, Default)]
    struct DocState {
        runs: Vec<Run>,
        published: bool,
        owner: String,
        placed: Option<u64>,
        base_extent: Option<u64>,
        /// The arrangement as of each position it changed at, for `/op-at`.
        history: BTreeMap<u64, Vec<Run>>,
    }

    #[derive(Debug, Clone)]
    struct LinkRow {
        addr: String,
        home: String,
        from: Vec<String>,
        to: Vec<String>,
        ty: String,
    }

    #[derive(Debug, Clone)]
    struct ClaimRow {
        claim: String,
        home: String,
        old: String,
        new: String,
    }

    #[derive(Debug, Clone)]
    struct FeedRow {
        at: u64,
        op: &'static str,
        docs: Vec<String>,
    }

    /// The board as the test writes it.
    #[derive(Default)]
    struct World {
        position: u64,
        docs: BTreeMap<String, DocState>,
        values: BTreeMap<(String, u64), Val>,
        links: Vec<LinkRow>,
        claims: Vec<ClaimRow>,
        rows: Vec<FeedRow>,
        /// Each origin's next fresh content ordinal.
        next_fresh: BTreeMap<String, u64>,
        /// The next document ordinal a mint takes.
        next_doc: u64,
        /// Each trunk's head member.
        trunk_head: BTreeMap<String, String>,
        /// The per-session idempotency memo: an id's acknowledgment.
        memo: BTreeMap<String, Value>,
        /// `image` refuses `image_too_large` past this many runs.
        image_cap: usize,
        /// `retrieve_v` refuses `too_many_items` past this width.
        delivery_cap: u64,
        /// `compare` refuses `too_many_blocks` past this many blocks an
        /// operand.
        compare_cap: usize,
        /// The next N acknowledgments are lost at the transport, the write
        /// applied.
        drop_acks: usize,
        /// `/op-at` answers `history_busy` this many times first.
        busy: usize,
        /// Every shot lands as its base's daughter: the head moved.
        head_moved: bool,
        /// Documents this reader may not read.
        withheld: BTreeSet<String>,
        /// The merger's enrolled key.
        key: Option<PublicKey>,
    }

    impl World {
        /// A claimed permissive board with the merger's doc 1 and `K`, the
        /// kind's document.
        fn new() -> World {
            let mut w = World {
                position: 10,
                image_cap: 1 << 12,
                delivery_cap: 1 << 17,
                compare_cap: 1 << 12,
                next_doc: 10,
                ..World::default()
            };
            w.doc(DOC1, true, ACCOUNT, Vec::new());
            w.doc(K, false, ACCOUNT, Vec::new());
            w.doc(OTHER_DOC1, true, "1.0.2", Vec::new());
            w
        }

        fn doc(&mut self, text: &str, published: bool, owner: &str, runs: Vec<Run>) {
            let mut history = BTreeMap::new();
            history.insert(0, runs.clone());
            self.docs.insert(
                text.to_string(),
                DocState {
                    runs,
                    published,
                    owner: owner.to_string(),
                    placed: None,
                    base_extent: None,
                    history,
                },
            );
        }

        /// A member of a chain with its shot terms.
        fn member(&mut self, text: &str, runs: Vec<Run>, base_extent: Option<u64>) {
            let placed = runs.iter().map(|r| r.width).sum();
            self.doc(text, true, ACCOUNT, runs);
            let d = self.docs.get_mut(text).unwrap();
            d.placed = Some(placed);
            d.base_extent = base_extent;
            self.position += 1;
            self.rows.push(FeedRow {
                at: self.position,
                op: "publish",
                docs: vec![text.to_string()],
            });
        }

        /// `text`'s bytes as the values of `origin`'s positions from `from`.
        fn text(&mut self, origin: &str, from: u64, text: &str) {
            for (k, b) in text.bytes().enumerate() {
                self.values.insert((origin.to_string(), from + k as u64), Val::Byte(b));
            }
            let next = self.next_fresh.entry(origin.to_string()).or_insert(1);
            *next = (*next).max(from + text.len() as u64);
        }

        /// The race shape of the record's §9: the base `D.1` "the cat sat",
        /// the head `D.2` adding "big " at `D·4|D·5` (fresh `D·12–15`), the
        /// daughter `D.1.1` removing " sat".
        fn race() -> World {
            let mut w = World::new();
            w.text(D, 1, "the cat sat");
            w.text(D, 12, "big ");
            let head = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)];
            w.doc(D, true, ACCOUNT, head.clone());
            w.member(&format!("{D}.1"), vec![run(D, 1, 11)], None);
            w.member(&format!("{D}.2"), head, Some(11));
            w.member(&format!("{D}.1.1"), vec![run(D, 1, 7)], Some(11));
            w.trunk_head.insert(D.to_string(), format!("{D}.2"));
            w
        }

        /// Shape (2) with a window: the head `D.2` `[(D,1,4),(Z,1,5),(D,5,7)]`
        /// — "hello" windowed from `Z` — and the staging draft `S`, a copy
        /// of the base with "!!!" typed at its end.
        fn window_and_draft() -> World {
            let mut w = World::new();
            w.text(D, 1, "the cat sat");
            w.text(Z, 1, "hello");
            w.text(S, 1, "!!!");
            w.doc(Z, true, ACCOUNT, vec![run(Z, 1, 5)]);
            let head = vec![run(D, 1, 4), run(Z, 1, 5), run(D, 5, 7)];
            w.doc(D, true, ACCOUNT, head.clone());
            w.member(&format!("{D}.1"), vec![run(D, 1, 11)], None);
            w.member(&format!("{D}.2"), head, Some(11));
            w.trunk_head.insert(D.to_string(), format!("{D}.2"));
            w.doc(S, false, ACCOUNT, vec![run(D, 1, 11), run(S, 1, 3)]);
            w.position += 1;
            let at = w.position;
            w.docs.get_mut(S).unwrap().history.insert(at, vec![run(D, 1, 11), run(S, 1, 3)]);
            w
        }

        fn arrangement(&self, doc: &str, at: Option<u64>) -> Option<Vec<Run>> {
            let d = self.docs.get(doc)?;
            Some(match at {
                None => d.runs.clone(),
                Some(at) => {
                    d.history.range(..=at).next_back().map(|(_, r)| r.clone()).unwrap_or_default()
                }
            })
        }

        fn fresh(&mut self, origin: &str) -> u64 {
            let next = self.next_fresh.entry(origin.to_string()).or_insert(1);
            let n = *next;
            *next += 1;
            n
        }

        fn commit(&mut self, op: &'static str, docs: Vec<String>) -> u64 {
            self.position += 1;
            self.rows.push(FeedRow { at: self.position, op, docs });
            self.position
        }

        /// The delivery items over clipped runs: adjacent bytes one
        /// `content` item, an atom its own.
        fn items(&self, clipped: &[(u64, Run)]) -> Vec<Value> {
            let mut out = Vec::new();
            let mut text = String::new();
            for (_, r) in clipped {
                for n in r.i_start..r.reach() {
                    match self
                        .values
                        .get(&(r.origin.to_string(), n))
                        .unwrap_or_else(|| panic!("no value at {}", i_addr(&r.origin, n)))
                    {
                        Val::Byte(b) => text.push(*b as char),
                        Val::Atom(s) => {
                            if !text.is_empty() {
                                out.push(json!({"content": std::mem::take(&mut text)}));
                            }
                            out.push(json!({"atom": s}));
                        }
                    }
                }
            }
            if !text.is_empty() {
                out.push(json!({"content": text}));
            }
            out
        }

        fn health(&self) -> Value {
            let origin = "http://127.0.0.1:8642";
            json!({"ok": true, "log_position": self.position, "chain_head": chain_hex(self.position), "auth": {"claimant": ACCOUNT, "local_trust": true, "origins": [origin], "signed_origins": [origin]}})
        }

        fn changes(&self, path: &str) -> Response {
            let query = path.splitn(2, '?').nth(1).unwrap_or("");
            let (mut since, mut under, mut limit) = (0u64, None::<String>, 256usize);
            for pair in query.split('&') {
                match pair.split_once('=') {
                    Some(("since", v)) => since = v.parse().unwrap(),
                    Some(("under", v)) => under = Some(v.to_string()),
                    Some(("limit", v)) => limit = v.parse().unwrap(),
                    Some(("drafts", _)) => {}
                    _ => panic!("an unknown `/changes` member: {pair}"),
                }
            }
            let visible: Vec<&FeedRow> = self
                .rows
                .iter()
                .filter(|r| r.at > since)
                .filter(|r| {
                    under.as_ref().is_none_or(|u| {
                        r.docs.iter().any(|d| d == u || d.starts_with(&format!("{u}.")))
                    })
                })
                .collect();
            let page: Vec<Value> = visible.iter().take(limit).map(|r| json!({"at": r.at, "op": r.op, "docs": r.docs, "key": "bare", "time": null})).collect();
            let last = page.last().and_then(|r| r["at"].as_u64()).unwrap_or(since);
            reply(200, json!({"changes": page, "last": last, "more": visible.len() > page.len()}))
        }

        fn op(&mut self, frame: &Value, at: Option<u64>) -> Result<Response, DialError> {
            let op = frame["op"].as_str().unwrap_or("?").to_string();
            let position = self.position;
            let rejected = |code: &str| {
                reply(
                    200,
                    json!({"resp": "rejected", "code": code, "disposition": "reorder", "op": op}),
                )
            };
            match op.as_str() {
                "principal_prefix" => Ok(reply(200, json!({"resp": "addr", "as_of": position, "addr": ACCOUNT}))),
                "key_set" => {
                    let key = self.key.clone().expect("the merger's key");
                    Ok(reply(200, json!({"resp": "key_set", "as_of": position, "retired": [], "enrolled": [{"alg": key.alg(), "key": key.to_hex(), "fingerprint": Fingerprint::of(&key).to_hex(), "anchor": false}]})))
                }
                "doc_metadata" => {
                    let doc = frame["doc"].as_str().unwrap();
                    if self.withheld.contains(doc) {
                        return Ok(rejected("withheld"));
                    }
                    let Some(d) = self.docs.get(doc) else { return Ok(rejected("doc_not_registered")) };
                    Ok(reply(200, json!({"resp": "doc_metadata", "as_of": position, "doc": doc, "published": d.published, "owner": d.owner, "placed": d.placed.map(|p| p.to_string()), "base_extent": d.base_extent.map(|e| e.to_string())})))
                }
                "retrieve_doc_v_span_set" => {
                    let doc = frame["doc"].as_str().unwrap();
                    if self.withheld.contains(doc) {
                        return Ok(rejected("withheld"));
                    }
                    let Some(runs) = self.arrangement(doc, at) else { return Ok(rejected("doc_not_registered")) };
                    let extent: u64 = runs.iter().map(|r| r.width).sum();
                    let set = if extent == 0 { json!([]) } else { json!([{"start": "1.1", "width": format!("0.{extent}")}]) };
                    Ok(reply(200, json!({"resp": "span_set", "as_of": position, "set": set})))
                }
                "image" => {
                    let doc = frame["d"].as_str().unwrap();
                    if self.withheld.contains(doc) {
                        return Ok(rejected("withheld"));
                    }
                    let (from, width) = span(&frame["region"][0]);
                    let Some(runs) = self.arrangement(doc, at) else { return Ok(rejected("doc_not_registered")) };
                    let clipped = clip(&runs, from, width);
                    if clipped.len() > self.image_cap {
                        return Ok(rejected("image_too_large"));
                    }
                    let runs: Vec<Value> = clipped.iter().map(|(_, r)| json!({"i_start": i_addr(&r.origin, r.i_start), "width": r.width.to_string()})).collect();
                    Ok(reply(200, json!({"resp": "runs", "as_of": position, "runs": runs})))
                }
                "retrieve_v" => {
                    let spec = &frame["specs"][0];
                    let doc = spec["doc"].as_str().unwrap();
                    if doc == HEAD_MEMBER_1 {
                        let record = json!({"type": "skep-head", "position": 1, "chain": chain_hex(1)}).to_string();
                        return Ok(reply(200, json!({"resp": "delivery", "as_of": position, "items": [{"atom": record}]})));
                    }
                    if self.withheld.contains(doc) {
                        return Ok(rejected("withheld"));
                    }
                    let (from, width) = span(&spec["span"]);
                    if width > self.delivery_cap {
                        return Ok(rejected("too_many_items"));
                    }
                    let Some(runs) = self.arrangement(doc, at) else { return Ok(rejected("doc_not_registered")) };
                    let items = self.items(&clip(&runs, from, width));
                    Ok(reply(200, json!({"resp": "delivery", "as_of": position, "items": items})))
                }
                "compare" => {
                    let operand = |rho: &Value| -> Result<Vec<(String, Vec<(u64, Run)>)>, Response> {
                        let mut out = Vec::new();
                        let mut blocks = 0;
                        for region in rho.as_array().unwrap() {
                            let doc = region["doc"].as_str().unwrap();
                            let (from, width) = span(&region["spans"][0]);
                            let Some(runs) = self.arrangement(doc, at) else { return Err(rejected("doc_not_registered")) };
                            let clipped = clip(&runs, from, width);
                            blocks += clipped.len();
                            out.push((doc.to_string(), clipped));
                        }
                        if blocks > self.compare_cap {
                            return Err(rejected("too_many_blocks"));
                        }
                        Ok(out)
                    };
                    let rho1 = match operand(&frame["rho1"]) {
                        Ok(r) => r,
                        Err(r) => return Ok(r),
                    };
                    let rho2 = match operand(&frame["rho2"]) {
                        Ok(r) => r,
                        Err(r) => return Ok(r),
                    };
                    let mut pairs = Vec::new();
                    for (d1, runs1) in &rho1 {
                        for (d2, runs2) in &rho2 {
                            for (v1, r1) in runs1 {
                                for (v2, r2) in runs2 {
                                    if r1.origin != r2.origin {
                                        continue;
                                    }
                                    let (lo, hi) = (r1.i_start.max(r2.i_start), r1.reach().min(r2.reach()));
                                    if lo < hi {
                                        pairs.push(json!({"d1": d1, "d2": d2, "u1": {"subspace": "1", "ordinal": (v1 + (lo - r1.i_start)).to_string()}, "u2": {"subspace": "1", "ordinal": (v2 + (lo - r2.i_start)).to_string()}, "width": (hi - lo).to_string()}));
                                    }
                                }
                            }
                        }
                    }
                    Ok(reply(200, json!({"resp": "compare", "as_of": position, "pairs": pairs})))
                }
                "find_links_ftt" => {
                    let q = &frame["q"];
                    let start = |slot: &Value| slot.as_array().and_then(|s| s.first()).and_then(|s| s["start"].as_str()).map(str::to_string);
                    let (ty, to, home, from) = (start(&q["ty"]), start(&q["to"]), start(&q["home"]), start(&q["from"]));
                    assert!(to.is_some() || home.is_some() || from.is_some(), "a class scan: {q}");
                    let addrs: Vec<&str> = self
                        .links
                        .iter()
                        .filter(|l| ty.as_ref().is_none_or(|t| &l.ty == t) && to.as_ref().is_none_or(|t| l.to.contains(t)) && home.as_ref().is_none_or(|h| &l.home == h) && from.as_ref().is_none_or(|f| l.from.contains(f)))
                        .map(|l| l.addr.as_str())
                        .collect();
                    Ok(reply(200, json!({"resp": "addrs", "as_of": position, "addrs": addrs})))
                }
                "read_link" => {
                    let addr = frame["a"].as_str().unwrap();
                    let Some(l) = self.links.iter().find(|l| l.addr == addr) else {
                        return Ok(reply(200, json!({"resp": "link_value", "as_of": position, "link": null})));
                    };
                    let unit = |addr: &str| json!({"start": addr, "width": format!("{}1", "0.".repeat(addr.split('.').count() - 1))});
                    let slot = |addrs: &[String]| addrs.iter().map(|x| unit(x)).collect::<Vec<_>>();
                    Ok(reply(200, json!({"resp": "link_value", "as_of": position, "link": {"slots": [slot(&l.from), slot(&l.to), vec![unit(&l.ty)]]}})))
                }
                "in_claims" => {
                    let y = frame["y"].as_str().unwrap();
                    let claims: Vec<Value> = self.claims.iter().filter(|c| c.old == y).map(|c| json!({"active": true, "claim": c.claim, "home": c.home, "new": c.new, "old": c.old})).collect();
                    Ok(reply(200, json!({"resp": "claims", "as_of": position, "claims": claims})))
                }
                "assert_sup" => panic!("the merge files no `assert_sup` on this wire, whose endpoints are links: {frame}"),
                "publish" | "insert" | "make_link" | "create_new_document" | "delete" | "reinstate" => self.write(frame),
                other => panic!("the merge sent an op the scripted board does not answer: {other}"),
            }
        }

        /// A write: the id's memo answered where one stands, else the write
        /// applied and its acknowledgment kept; the next `drop_acks`
        /// acknowledgments lost at the transport.
        fn write(&mut self, frame: &Value) -> Result<Response, DialError> {
            let id = frame["id"].as_str().map(str::to_string);
            let ack = match id.as_ref().and_then(|id| self.memo.get(id)).cloned() {
                Some(ack) => ack,
                None => {
                    let ack = self.apply(frame);
                    if let (Some(id), true) = (&id, ack["resp"] != "rejected") {
                        self.memo.insert(id.clone(), ack.clone());
                    }
                    ack
                }
            };
            if self.drop_acks > 0 {
                self.drop_acks -= 1;
                return Err(DialError::Io("the acknowledgment was lost".into()));
            }
            Ok(reply(200, ack))
        }

        fn apply(&mut self, frame: &Value) -> Value {
            let op = frame["op"].as_str().unwrap();
            match op {
                "create_new_document" => {
                    let account = frame["account"].as_str().unwrap().to_string();
                    let published = frame["published"].as_bool().unwrap_or(false);
                    let addr = format!("{account}.0.{}", self.next_doc);
                    self.next_doc += 1;
                    self.doc(&addr, published, &account, Vec::new());
                    let at = self.commit("create_new_document", vec![addr.clone()]);
                    json!({"resp": "ack_addr", "addr": addr, "at": at})
                }
                "insert" => {
                    let doc = frame["doc"].as_str().unwrap().to_string();
                    assert!(
                        frame.get("deposit").is_none(),
                        "a journal append is a PLAIN insert: {frame}"
                    );
                    let ordinal: u64 = frame["at"]["ordinal"].as_str().unwrap().parse().unwrap();
                    let atom = frame["values"][0]["atom"].as_str().expect("one atom").to_string();
                    let n = self.fresh(&doc);
                    self.values.insert((doc.clone(), n), Val::Atom(atom));
                    let d = self.docs.get(&doc).expect("a registered draft");
                    assert!(
                        !d.published,
                        "an insert into a published document is `published_target`"
                    );
                    let mut positions = expand(&d.runs);
                    assert!(
                        ordinal >= 1 && ordinal as usize <= positions.len() + 1,
                        "out of bounds: {ordinal}"
                    );
                    positions.insert(ordinal as usize - 1, (a(&doc), n));
                    let runs = coalesce(positions);
                    let at = self.commit("insert", vec![doc.clone()]);
                    let d = self.docs.get_mut(&doc).unwrap();
                    d.runs = runs.clone();
                    d.history.insert(at, runs);
                    json!({"resp": "ack_addr", "addr": i_addr(&a(&doc), n), "at": at})
                }
                "make_link" => {
                    let home = frame["home"].as_str().unwrap().to_string();
                    let addrs = |slot: &Value| {
                        slot["addrs"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|x| x.as_str().unwrap().to_string())
                            .collect::<Vec<_>>()
                    };
                    let n = self.links.iter().filter(|l| l.home == home).count() + 1;
                    let addr = format!("{home}.0.2.{n}");
                    self.links.push(LinkRow {
                        addr: addr.clone(),
                        home: home.clone(),
                        from: addrs(&frame["from"]),
                        to: addrs(&frame["to"]),
                        ty: addrs(&frame["ty"])[0].clone(),
                    });
                    let at = self.commit("make_link", vec![home]);
                    json!({"resp": "ack_addr", "addr": addr, "at": at})
                }
                "publish" => {
                    let doc = frame["doc"].as_str().unwrap().to_string();
                    let base = frame["base"].as_str().unwrap().to_string();
                    let base_extent: u64 = frame["base_extent"].as_str().unwrap().parse().unwrap();
                    let draft = frame["draft"].as_str().map(str::to_string);
                    let mut positions = Vec::new();
                    for r in frame["runs"].as_array().unwrap() {
                        let origin = r["origin"].as_str().unwrap().to_string();
                        let i_start: u64 = r["i_start"]
                            .as_str()
                            .unwrap()
                            .rsplit('.')
                            .next()
                            .unwrap()
                            .parse()
                            .unwrap();
                        let width: u64 = r["width"].as_str().unwrap().parse().unwrap();
                        for k in 0..width {
                            if draft.as_deref() == Some(origin.as_str()) {
                                let n = self.fresh(&doc);
                                let v = self
                                    .values
                                    .get(&(origin.clone(), i_start + k))
                                    .expect("the draft's value")
                                    .clone();
                                self.values.insert((doc.clone(), n), v);
                                positions.push((a(&doc), n));
                            } else {
                                positions.push((a(&origin), i_start + k));
                            }
                        }
                    }
                    let runs = coalesce(positions);
                    let placed: u64 = runs.iter().map(|r| r.width).sum();
                    let head = self.trunk_head.get(&doc).cloned().expect("a chain");
                    let member = if self.head_moved || base != head {
                        let k = 1 + self
                            .docs
                            .keys()
                            .filter(|m| {
                                m.strip_prefix(&format!("{base}."))
                                    .is_some_and(|rest| !rest.contains('.'))
                            })
                            .count();
                        format!("{base}.{k}")
                    } else {
                        let n: u64 = head.rsplit('.').next().unwrap().parse().unwrap();
                        format!("{doc}.{}", n + 1)
                    };
                    self.doc(&member, true, ACCOUNT, runs.clone());
                    let d = self.docs.get_mut(&member).unwrap();
                    d.placed = Some(placed);
                    d.base_extent = Some(base_extent);
                    if !member.strip_prefix(&format!("{doc}.")).unwrap().contains('.') {
                        self.trunk_head.insert(doc.clone(), member.clone());
                        self.docs.get_mut(&doc).unwrap().runs = runs;
                    }
                    let at = self.commit("publish", vec![member.clone()]);
                    json!({"resp": "ack_addr", "addr": member, "at": at})
                }
                "delete" | "reinstate" => {
                    let doc = frame["doc"].as_str().unwrap().to_string();
                    let d = self.docs.get(&doc).expect("a registered draft");
                    assert!(!d.published, "`{op}` into a published document is `published_target`");
                    let mut positions = expand(&d.runs);
                    if op == "delete" {
                        let p: usize = frame["p"]["ordinal"].as_str().unwrap().parse().unwrap();
                        let width: usize = frame["width"].as_str().unwrap().parse().unwrap();
                        positions.drain(p - 1..p - 1 + width);
                    } else {
                        let at: usize = frame["at"]["ordinal"].as_str().unwrap().parse().unwrap();
                        let mut placed = Vec::new();
                        for r in frame["runs"].as_array().unwrap() {
                            let origin = a(r["origin"].as_str().unwrap());
                            let i_start: u64 = r["i_start"]
                                .as_str()
                                .unwrap()
                                .rsplit('.')
                                .next()
                                .unwrap()
                                .parse()
                                .unwrap();
                            let width: u64 = r["width"].as_str().unwrap().parse().unwrap();
                            placed.extend((i_start..i_start + width).map(|n| (origin.clone(), n)));
                        }
                        assert!(
                            placed.iter().all(|p| !positions.contains(p)),
                            "a position placed twice"
                        );
                        positions.splice(at - 1..at - 1, placed);
                    }
                    let runs = coalesce(positions);
                    let at = self.commit(
                        if op == "delete" { "delete" } else { "reinstate" },
                        vec![doc.clone()],
                    );
                    let d = self.docs.get_mut(&doc).unwrap();
                    d.runs = runs.clone();
                    d.history.insert(at, runs);
                    json!({"resp": "ack", "at": at})
                }
                other => panic!("no write named {other}"),
            }
        }
    }

    /// The dialer over a world, every frame it served kept.
    struct Scripted {
        world: Arc<Mutex<World>>,
        served: Mutex<Vec<(String, Value)>>,
    }

    impl Scripted {
        /// The ops served, in order — `op` for `/op`, `at:op` for `/op-at`,
        /// the path for anything else — the handshake's own lines dropped.
        fn ops(&self) -> Vec<String> {
            self.served
                .lock()
                .unwrap()
                .iter()
                .map(|(line, _)| line.clone())
                .filter(|l| {
                    !l.starts_with("GET /health")
                        && !l.starts_with("GET /challenge")
                        && !l.starts_with("POST /session")
                        && l != "principal_prefix"
                        && l != "key_set"
                })
                .collect()
        }

        /// The frames of one op, in order.
        fn frames(&self, op: &str) -> Vec<Value> {
            self.served
                .lock()
                .unwrap()
                .iter()
                .filter(|(line, _)| line == op || line == &format!("at:{op}"))
                .map(|(_, f)| f.clone())
                .collect()
        }

        fn clear(&self) {
            self.served.lock().unwrap().clear();
        }

        fn world(&self) -> std::sync::MutexGuard<'_, World> {
            self.world.lock().unwrap()
        }
    }

    impl Dialer for Scripted {
        fn exchange(&self, _origin: &Origin, req: &Request) -> Result<Response, DialError> {
            let frame: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let (line, inner) = match req.path.as_str() {
                "/op" => (frame["op"].as_str().unwrap_or("?").to_string(), frame.clone()),
                "/op-at" => (
                    format!("at:{}", frame["frame"]["op"].as_str().unwrap_or("?")),
                    frame["frame"].clone(),
                ),
                p => (format!("{} {p}", req.method.as_str()), Value::Null),
            };
            self.served.lock().unwrap().push((line, inner));
            let mut w = self.world.lock().unwrap();
            match req.path.as_str() {
                "/health" => Ok(reply(200, w.health())),
                "/op" => w.op(&frame, None),
                "/op-at" => {
                    if w.busy > 0 {
                        w.busy -= 1;
                        return Ok(reply(503, json!({"error": "history_busy"})));
                    }
                    let at = frame["at"].as_u64();
                    w.op(&frame["frame"], at)
                }
                "/session" => Ok(reply(200, json!({"session": TOKEN}))),
                "/session/close" => {
                    Ok(Response { status: 204, headers: Headers::default(), body: Vec::new() })
                }
                p if p.starts_with("/challenge") => Ok(reply(
                    200,
                    json!({"nonce": "ab".repeat(32), "principal": 1, "ttl_ms": 60000}),
                )),
                p if p.starts_with("/changes?") => Ok(w.changes(p)),
                p => panic!("the merge dialed a path the scripted board does not answer: {p}"),
            }
        }

        fn stream(
            &self,
            _: &Origin,
            _: &RequestHead,
            _: &mut dyn std::io::Read,
            _: &mut dyn FnMut(&Headers),
        ) -> Result<StreamedResponse, DialError> {
            unreachable!("no read of the scripted board streams")
        }
    }

    fn signer() -> HybridSigner {
        crate::sign::signer_from_seed(&[42; 32])
    }

    /// A board over `world`, the merger's key enrolled.
    fn open(mut world: World) -> (Arc<Scripted>, Board, HybridSigner) {
        let signer = signer();
        world.key = Some(Signer::public_key(&signer).clone());
        let dialer = Arc::new(Scripted {
            world: Arc::new(Mutex::new(world)),
            served: Mutex::new(Vec::new()),
        });
        let board = Board::new(Origin::parse("http://127.0.0.1:8642").unwrap(), dialer.clone());
        (dialer, board, signer)
    }

    /// The merger's content-scoped session, through the one handshake.
    fn sign_in<'b>(board: &'b Board, signer: &HybridSigner) -> Session<'b> {
        handshake(board, Scope::Content, signer, 1, Site::Session).expect("the session opens")
    }

    fn token() -> crate::board::Token {
        crate::board::Token::parse(TOKEN).unwrap()
    }

    /// The race shape's inputs: the head `D.2`, the daughter `D.1.1`, the
    /// base derived.
    fn race_inputs() -> Inputs {
        Inputs {
            doc: a(D),
            head: a(&format!("{D}.2")),
            base: None,
            sides: vec![Side::Member(a(&format!("{D}.1.1")))],
            options: Options::default(),
            kind: a(K),
        }
    }

    fn m_runs(merged: &Merged) -> Vec<Run> {
        merged.composed.runs.iter().map(|p| p.run.clone()).collect()
    }

    /// The merger's facts off the session it opened, with its hand.
    fn merger<'s>(session: &'s Session<'_>, signer: &'s HybridSigner) -> Merger<'s> {
        Merger { token: session.token(), account: session.account(), signer }
    }

    fn shot<'s>(session: &'s Session<'_>, signer: &'s HybridSigner) -> Landing<'s> {
        Landing::Shot { merger: merger(session, signer), draft: None, journal: None }
    }

    // ── compose ──────────────────────────────────────────────────────────

    /// §1.3's reads IN ORDER: the document's metadata, the head's extent,
    /// the base's extent and image, the head's image, the daughter's extent
    /// and image, then the prior records by the links of the kind to each
    /// side — and nothing written. The result is the race shape's M with
    /// its counts, key, cap and unlanded record.
    #[test]
    fn compose_reads_in_the_records_order_and_writes_nothing() {
        let (dialer, board, _) = open(World::race());
        let merged = compose(&board, Some(&token()), &race_inputs()).expect("composed");
        assert_eq!(
            dialer.ops(),
            [
                "doc_metadata",
                "retrieve_doc_v_span_set",
                "retrieve_doc_v_span_set",
                "image",
                "image",
                "retrieve_doc_v_span_set",
                "image",
                "find_links_ftt",
                "find_links_ftt"
            ]
        );
        let docs: Vec<String> = dialer
            .frames("retrieve_doc_v_span_set")
            .iter()
            .map(|f| f["doc"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            docs,
            [format!("{D}.2"), format!("{D}.1"), format!("{D}.1.1")],
            "the head's extent, then the base's, then the daughter's"
        );
        let imaged: Vec<String> =
            dialer.frames("image").iter().map(|f| f["d"].as_str().unwrap().to_string()).collect();
        assert_eq!(
            imaged,
            [format!("{D}.1"), format!("{D}.2"), format!("{D}.1.1")],
            "the base, the head, the daughter"
        );
        assert_eq!(m_runs(&merged), vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 3)], "the big cat");
        assert_eq!(merged.composed.counts, RunCounts { a: 3, b: 1, m: 3 });
        assert_eq!(merged.families, vec![Family::Own, Family::Own, Family::Own]);
        assert_eq!((merged.cap, merged.head_extent), (SHOT_RUN_CAP, 15));
        assert_eq!(
            merged.key,
            RecordKey::new(
                a(D),
                a(&format!("{D}.1")),
                [a(&format!("{D}.2")), a(&format!("{D}.1.1"))]
            )
        );
        assert_eq!(
            merged.key.sides,
            vec![a(&format!("{D}.1.1")), a(&format!("{D}.2"))],
            "the sides a sorted set"
        );
        assert_eq!(
            (
                merged.record.landed.clone(),
                merged.record.claims.len(),
                merged.record.replaces.clone(),
                merged.prior.clone()
            ),
            (None, 0, None, None)
        );
        assert_eq!(
            merged.record.sides.iter().map(SideAt::role).collect::<Vec<_>>(),
            [Role::Head, Role::Alternative]
        );
        assert_eq!(merged.record.to_value()["type"].as_str(), Some("merge"));
        let w = dialer.world();
        assert_eq!(w.rows.len(), 3, "nothing written");
        assert_eq!(merged.as_of, w.position);
    }

    /// The fence on cross-account sides: a `Fork`, a member of another
    /// document and a draft of another account each refuse `BaseUnknown`
    /// before any `image`; two drafts refuse `TwoDrafts`; a draft with no
    /// named base refuses `BaseUnknown`.
    #[test]
    fn a_fork_or_a_foreign_side_refuses_before_any_image() {
        let (dialer, board, _) = open(World::race());
        let with =
            |sides: Vec<Side>, base: Option<Address>| Inputs { sides, base, ..race_inputs() };
        let fork = Side::Fork(a(F));
        assert_eq!(
            compose(&board, Some(&token()), &with(vec![fork.clone()], None)),
            Err(Refusal::BaseUnknown(fork))
        );
        assert!(dialer.ops().is_empty(), "no read at all for a fork: {:?}", dialer.ops());
        let foreign = Side::Member(a(&format!("{Z}.1")));
        assert_eq!(
            compose(&board, Some(&token()), &with(vec![foreign.clone()], None)),
            Err(Refusal::BaseUnknown(foreign))
        );
        let other_account = Side::Draft { at: a("1.0.2.0.3"), position: None };
        assert_eq!(
            compose(
                &board,
                Some(&token()),
                &with(vec![other_account.clone()], Some(a(&format!("{D}.1"))))
            ),
            Err(Refusal::BaseUnknown(other_account))
        );
        assert!(
            !dialer.ops().iter().any(|o| o == "image"),
            "no image before the refusal: {:?}",
            dialer.ops()
        );
        let unbased = Side::Draft { at: a(S), position: None };
        assert_eq!(
            compose(&board, Some(&token()), &with(vec![unbased.clone()], None)),
            Err(Refusal::BaseUnknown(unbased))
        );
        let two = vec![
            Side::Draft { at: a(S), position: None },
            Side::Draft { at: a("1.0.1.0.5"), position: None },
        ];
        assert_eq!(
            compose(&board, Some(&token()), &with(two, Some(a(&format!("{D}.1"))))),
            Err(Refusal::TwoDrafts)
        );
    }

    /// `image` IN PARTS: a head of three runs refused `image_too_large`
    /// whole is re-asked in halves, the parts re-joined by I-adjacency —
    /// the run a part boundary cut is one run again — so `counts.a` is 3,
    /// not 4, and M is the same list.
    #[test]
    fn an_image_in_parts_is_rejoined_and_coalesced_before_counting() {
        let (dialer, board, _) = open(World::race());
        dialer.world().image_cap = 2;
        let merged = compose(&board, Some(&token()), &race_inputs()).expect("composed");
        let head: Vec<(u64, u64)> = dialer
            .frames("image")
            .iter()
            .filter(|f| f["d"] == format!("{D}.2"))
            .map(|f| span(&f["region"][0]))
            .collect();
        assert_eq!(head, [(1, 15), (1, 7), (8, 8)], "the whole region refused, then its halves");
        assert_eq!(merged.composed.counts, RunCounts { a: 3, b: 1, m: 3 });
        assert_eq!(m_runs(&merged), vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 3)]);
        // Down to one position still refused: the fragmentation measured.
        dialer.world().image_cap = 0;
        assert!(matches!(
            compose(&board, Some(&token()), &race_inputs()),
            Err(Refusal::TooFragmented { runs_seen: 0, .. })
        ));
    }

    /// A SUB-RUN value read is mapped to the side's own V-ordinals (the
    /// fragment model): with the retype normalization on, the base bytes a
    /// side retyped are read through the other side's copy as the fragments
    /// of that side's runs — `D·5` at V 5 of one run, `D·6–7` at V 6 of the
    /// next — and the retyped bytes at the retyping side's V 5.
    #[test]
    fn a_sub_run_value_read_is_mapped_to_the_sides_v_ordinals() {
        let mut w = World::new();
        w.text(D, 1, "the cat sat");
        w.text(D, 12, "cat");
        w.text(D, 16, "-");
        let head = vec![run(D, 1, 4), run(D, 12, 3), run(D, 8, 4)];
        w.doc(D, true, ACCOUNT, head.clone());
        w.member(&format!("{D}.1"), vec![run(D, 1, 11)], None);
        w.member(&format!("{D}.2"), head, Some(11));
        w.member(&format!("{D}.1.1"), vec![run(D, 1, 5), run(D, 16, 1), run(D, 6, 6)], Some(11));
        w.trunk_head.insert(D.to_string(), format!("{D}.2"));
        let (dialer, board, _) = open(w);
        let inputs =
            Inputs { options: Options { retype: true, ..Options::default() }, ..race_inputs() };
        let merged = compose(&board, Some(&token()), &inputs).expect("composed");
        assert_eq!(
            m_runs(&merged),
            vec![run(D, 1, 5), run(D, 16, 1), run(D, 6, 6)],
            "the c-at sat: the base identity kept"
        );
        let reads: Vec<(String, u64, u64)> = dialer
            .frames("retrieve_v")
            .iter()
            .map(|f| {
                let (from, width) = span(&f["specs"][0]["span"]);
                (f["specs"][0]["doc"].as_str().unwrap().to_string(), from, width)
            })
            .collect();
        assert_eq!(reads, [(format!("{D}.1.1"), 5, 1), (format!("{D}.1.1"), 7, 2), (format!("{D}.2"), 5, 3)], "D·5 at the daughter's V 5, D·6–7 at its V 7 past the '-', the retyped 'cat' at the head's V 5");
    }

    /// Origins are BARE documents: an I-address minted under a member
    /// resolves to the trunk, so the core's anchors are the trunk's
    /// positions and a merger's `After` names one and is applied, never
    /// ignored.
    #[test]
    fn origins_are_bare_documents_so_anchors_resolve() {
        assert_eq!(origin_of(&format!("{D}.0.1.12")), Some(a(D)));
        assert_eq!(
            origin_of(&format!("{D}.2.0.1.12")),
            Some(a(D)),
            "a version-qualified mint is the trunk's"
        );
        assert_eq!(origin_of(&format!("{D}.1.1.0.1.3")), Some(a(D)));
        assert_eq!(origin_of("1.0.1.0.1"), None);
        let mut w = World::race();
        w.text(D, 16, "fat ");
        w.member(&format!("{D}.1.2"), vec![run(D, 1, 4), run(D, 16, 4), run(D, 5, 7)], Some(11));
        let (_, board, _) = open(w);
        let both = Inputs { sides: vec![Side::Member(a(&format!("{D}.1.2")))], ..race_inputs() };
        let merged = compose(&board, Some(&token()), &both).expect("composed");
        assert_eq!(merged.composed.gaps.len(), 1);
        let gap = &merged.composed.gaps[0];
        assert_eq!(
            (gap.kind, gap.after.clone(), gap.before.clone()),
            (GapKind::Order, Some(a(&format!("{D}.0.1.4"))), Some(a(&format!("{D}.0.1.5"))))
        );
        let swapped = Inputs {
            options: Options {
                resolutions: vec![Resolution {
                    gap: GapId(1),
                    choice: Choice::Order(vec![SideIx(1), SideIx(0)]),
                    by: ResolvedBy::Person,
                }],
                ..Options::default()
            },
            ..both.clone()
        };
        let merged = compose(&board, Some(&token()), &swapped).expect("composed");
        assert!(
            merged.composed.ignored.is_empty(),
            "the resolution names a gap the anchors resolve: {:?}",
            merged.composed.ignored
        );
        assert_eq!(
            m_runs(&merged),
            vec![run(D, 1, 4), run(D, 16, 4), run(D, 12, 4), run(D, 5, 7)],
            "the fat big cat sat"
        );
        assert_eq!(merged.record.gaps[0].resolved_by, Some(ResolvedBy::Person));
    }

    /// A draft side at a position is read through `/op-at`: one
    /// `history_busy` is retried and the read answers; past the bounded
    /// retries the composition refuses `HistoryBusy`.
    #[test]
    fn a_draft_at_a_position_retries_history_busy_then_refuses() {
        let (dialer, board, _) = open(World::window_and_draft());
        let at = dialer.world().position;
        dialer.world().busy = 1;
        let inputs = Inputs {
            sides: vec![Side::Draft { at: a(S), position: Some(at) }],
            base: Some(a(&format!("{D}.1"))),
            ..race_inputs()
        };
        let merged = compose(&board, Some(&token()), &inputs).expect("composed");
        assert_eq!(m_runs(&merged), vec![run(D, 1, 4), run(Z, 1, 5), run(D, 5, 7), run(S, 1, 3)]);
        assert_eq!(
            merged.families,
            vec![Family::Own, Family::Window, Family::Own, Family::DraftNative]
        );
        assert_eq!(
            dialer.ops().iter().filter(|o| *o == "at:retrieve_doc_v_span_set").count(),
            2,
            "one busy, one answered: {:?}",
            dialer.ops()
        );
        dialer.world().busy = 10;
        assert_eq!(compose(&board, Some(&token()), &inputs), Err(Refusal::HistoryBusy));
    }

    // ── the landing ──────────────────────────────────────────────────────

    /// THE SHOT and its body, byte-checked: the three families — the
    /// document's own runs by reference, a window onto `Z`, a draft side's
    /// fresh text — in one frame from the head with `base`, `base_extent`,
    /// the `draft` named without asking, the runs in V-order, the id; and
    /// the `attest` verifying over the entry frame whose body is the one
    /// `entry_body_publish` spells from the same pieces.
    #[test]
    fn the_shot_frame_and_its_body_are_byte_checked() {
        let (dialer, board, signer) = open(World::window_and_draft());
        let session = sign_in(&board, &signer);
        let inputs = Inputs {
            sides: vec![Side::Draft { at: a(S), position: None }],
            base: Some(a(&format!("{D}.1"))),
            ..race_inputs()
        };
        let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
        dialer.clear();
        let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
        let Landed::Member { address, position, claims, record, retries } = &landed else {
            panic!("{landed:?}")
        };
        assert_eq!((address.to_string(), *retries, claims.len()), (format!("{D}.3"), 0, 0));
        assert!(
            record.to_string().starts_with(&format!("{DOC1}.0.2.")),
            "the record's link is homed in doc 1: {record}"
        );
        let frames = dialer.frames("publish");
        assert_eq!(frames.len(), 1);
        let frame = &frames[0];
        assert_eq!(frame["doc"], D);
        assert_eq!(
            (frame["base"].as_str(), frame["base_extent"].as_str(), frame["draft"].as_str()),
            (Some(format!("{D}.2").as_str()), Some("16"), Some(S))
        );
        assert_eq!(frame["id"].as_str(), Some(format!("{}.publish", merged.key.text()).as_str()));
        let runs: Vec<(String, String, String)> = frame["runs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["origin"].as_str().unwrap().into(),
                    r["i_start"].as_str().unwrap().into(),
                    r["width"].as_str().unwrap().into(),
                )
            })
            .collect();
        assert_eq!(
            runs,
            [
                (D.into(), format!("{D}.0.1.1"), "4".into()),
                (Z.into(), format!("{Z}.0.1.1"), "5".into()),
                (D.into(), format!("{D}.0.1.5"), "7".into()),
                (S.into(), format!("{S}.0.1.1"), "3".into())
            ]
        );
        // The body, hand-built from the same pieces, verifies the attest.
        let window = a(&format!("{Z}.0.1.1"));
        let values: Vec<[u8; 1]> = b"the cat sat!!!".iter().map(|b| [*b]).collect();
        let pieces: Vec<ShotSegmentPiece<'_>> = values[..4]
            .iter()
            .map(|v| ShotSegmentPiece::Value(v))
            .chain(std::iter::once(ShotSegmentPiece::Window {
                start: &window,
                width: std::num::NonZeroU64::new(5).unwrap(),
            }))
            .chain(values[4..].iter().map(|v| ShotSegmentPiece::Value(v)))
            .collect();
        let head = a(&format!("{D}.2"));
        let body = entry_body_publish(pieces, Some(ShotBase { member: &head, extent: 16 }));
        let term = board.board_term().unwrap().unwrap();
        let alg = Signer::public_key(&signer).alg();
        assert_eq!(frame["attest"]["alg"].as_str(), Some(alg));
        let sig = crate::hex::decode(frame["attest"]["sig"].as_str().unwrap()).unwrap();
        let expected = entry_frame(alg, term, &a(ACCOUNT), DocTerm::One(&a(D)), &body);
        assert_eq!(
            skep_signature::verify(
                Signer::tag(&signer),
                Signer::public_key(&signer),
                &expected,
                &sig
            ),
            Ok(()),
            "the attest signs the body the pieces spell"
        );
        // The values were read through the sides that hold them: D's through
        // the head, the draft's through the draft.
        let reads: Vec<(String, u64, u64)> = dialer
            .frames("retrieve_v")
            .iter()
            .filter(|f| f["specs"][0]["doc"] != HEAD_MEMBER_1)
            .map(|f| {
                let (from, width) = span(&f["specs"][0]["span"]);
                (f["specs"][0]["doc"].as_str().unwrap().to_string(), from, width)
            })
            .collect();
        assert_eq!(reads, [(format!("{D}.2"), 1, 4), (format!("{D}.2"), 10, 7), (S.into(), 12, 3)]);
        assert_eq!(
            *position,
            dialer
                .world()
                .rows
                .iter()
                .find(|r| r.op == "publish" && r.docs[0] == format!("{D}.3"))
                .unwrap()
                .at
        );
        let member = dialer.world().docs.get(&format!("{D}.3")).unwrap().clone();
        assert_eq!(member.runs, vec![run(D, 1, 4), run(Z, 1, 5), run(D, 5, 10)], "the draft's text re-minted under D at D·12, I-adjacent to D·5–11 and so one run with it");
        assert_eq!((member.placed, member.base_extent), (Some(19), Some(16)));
    }

    /// After the shot, in order: the claim's read at the daughter (and no
    /// `assert_sup` — the scripted board panics on one), the record's read
    /// by the links of the kind to the member, the journal found by the
    /// account's links from doc 1 then MINTED private, the atom appended as
    /// a PLAIN insert at the journal's end, the link from doc 1 to the
    /// member and the daughter under the kind. A second `land` reads each
    /// of the three writes standing and writes nothing.
    #[test]
    fn the_claim_is_read_and_the_record_is_written_after_the_shot_each_read_first() {
        let (dialer, board, signer) = open(World::race());
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
        dialer.clear();
        let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
        let Landed::Member { address, position, claims, record, .. } = &landed else {
            panic!("{landed:?}")
        };
        assert_eq!(address.to_string(), format!("{D}.3"));
        assert!(claims.is_empty());
        let ops = dialer.ops();
        let after_values: Vec<&str> =
            ops.iter().map(String::as_str).skip_while(|o| *o != "publish").collect();
        assert_eq!(
            after_values,
            [
                "publish",
                "in_claims",
                "find_links_ftt",
                "find_links_ftt",
                "create_new_document",
                "retrieve_doc_v_span_set",
                "insert",
                "make_link"
            ]
        );
        assert_eq!(ops[0], "doc_metadata", "the shot reads the trunk's next member first: {ops:?}");
        assert_eq!(dialer.frames("doc_metadata")[0]["doc"], format!("{D}.3"));
        assert_eq!(
            dialer.frames("in_claims")[0],
            json!({"op": "in_claims", "view": "active", "y": format!("{D}.1.1")})
        );
        let links = dialer.frames("find_links_ftt");
        assert_eq!(
            links[0]["q"]["to"][0]["start"],
            format!("{D}.3"),
            "the record's read-first: the links of the kind to the member"
        );
        assert_eq!(
            (links[1]["q"]["home"][0]["start"].as_str(), links[1]["q"]["to"].as_str()),
            (Some(DOC1), Some("any")),
            "the journal's find: the account's links from doc 1"
        );
        assert_eq!(
            dialer.frames("create_new_document")[0],
            json!({"op": "create_new_document", "account": ACCOUNT, "published": false, "id": format!("merge.journal:{ACCOUNT}")})
        );
        let insert = &dialer.frames("insert")[0];
        let journal = insert["doc"].as_str().unwrap().to_string();
        assert_eq!(journal, "1.0.1.0.10", "the minted journal");
        assert_eq!((insert["at"]["ordinal"].as_str(), insert.get("deposit")), (Some("1"), None));
        let atom: Value =
            serde_json::from_str(insert["values"][0]["atom"].as_str().unwrap()).unwrap();
        assert_eq!(atom["type"], "merge");
        assert_eq!(atom["landed"], json!({"member": format!("{D}.3"), "position": position}));
        let written = Record::from_value(&atom).expect("a record");
        assert_eq!((written.key(), written.landed.is_some()), (merged.key.clone(), true));
        let link = &dialer.frames("make_link")[0];
        assert_eq!(link["home"], DOC1);
        assert_eq!(link["from"]["addrs"], json!([format!("{journal}.0.1.1")]));
        assert_eq!(link["to"]["addrs"], json!([format!("{D}.3"), format!("{D}.1.1")]));
        assert_eq!(link["ty"]["addrs"], json!([K]));
        assert!(link["attest"]["sig"].is_string(), "the link into the published doc 1 is attested");
        assert_eq!(record.to_string(), format!("{DOC1}.0.2.1"));
        // The claim's read records a claim another writer filed.
        dialer.world().claims.push(ClaimRow {
            claim: format!("{DOC1}.0.2.9"),
            home: DOC1.into(),
            old: format!("{D}.1.1"),
            new: format!("{D}.3"),
        });
        // A second landing: every write standing, nothing written.
        dialer.clear();
        let rows = dialer.world().rows.len();
        let again = land(&board, &merged, shot(&session, &signer)).expect("landed again");
        let Landed::Member { claims, record: again_record, .. } = &again else {
            panic!("{again:?}")
        };
        assert_eq!((claims.clone(), again_record), (vec![a(&format!("{DOC1}.0.2.9"))], record));
        assert_eq!(dialer.world().rows.len(), rows, "nothing written twice");
        let ops = dialer.ops();
        assert!(
            !ops.iter()
                .any(|o| ["publish", "insert", "make_link", "create_new_document"]
                    .contains(&o.as_str())),
            "{ops:?}"
        );
        assert_eq!(ops.iter().filter(|o| *o == "in_claims").count(), 1);
    }

    /// THE LOST ACK: the dialer drops the shot's acknowledgment and the one
    /// re-ask's under the same id — the write applied once, the memo
    /// answering the re-ask — so `land` halts at the transport; `resume`
    /// finds the member whose first `placed` positions equal M, with its
    /// position off the feed, and completes the claim's read and the record;
    /// a second `resume` writes nothing.
    #[test]
    fn a_lost_ack_is_completed_by_resume_and_nothing_is_written_twice() {
        let (dialer, board, signer) = open(World::race());
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
        dialer.clear();
        dialer.world().drop_acks = 2;
        let err = land(&board, &merged, shot(&session, &signer)).expect_err("the ack was lost");
        assert!(matches!(err, Refusal::Halt(Halt::Dial(_))), "{err}");
        let publishes = dialer.frames("publish");
        assert_eq!(publishes.len(), 2, "one re-ask under the same id");
        assert_eq!(publishes[0]["id"], publishes[1]["id"]);
        assert!(dialer.world().docs.contains_key(&format!("{D}.3")), "the write applied once");
        assert_eq!(dialer.world().rows.iter().filter(|r| r.op == "publish").count(), 4);
        assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty());
        dialer.clear();
        let resumed = resume(&board, &merged, shot(&session, &signer)).expect("resumed");
        let Some(Landed::Member { address, position, record, .. }) = &resumed else {
            panic!("{resumed:?}")
        };
        assert_eq!(address.to_string(), format!("{D}.3"));
        assert_eq!(
            *position,
            dialer.world().rows.iter().find(|r| r.docs[0] == format!("{D}.3")).unwrap().at,
            "the position off the feed"
        );
        let ops = dialer.ops();
        assert!(!ops.iter().any(|o| o == "publish"), "the shot is not re-sent: {ops:?}");
        assert_eq!(ops.iter().filter(|o| *o == "insert").count(), 1);
        assert_eq!(ops.iter().filter(|o| *o == "make_link").count(), 1);
        assert!(
            ops.iter().any(|o| o.starts_with("GET /changes?")),
            "the member's position off the feed"
        );
        dialer.clear();
        let twice = resume(&board, &merged, shot(&session, &signer)).expect("resumed again");
        assert_eq!(
            twice.as_ref().map(|l| match l {
                Landed::Member { record, .. } => record.clone(),
                _ => unreachable!(),
            }),
            Some(record.clone())
        );
        assert!(
            !dialer
                .ops()
                .iter()
                .any(|o| ["publish", "insert", "make_link", "create_new_document"]
                    .contains(&o.as_str())),
            "{:?}",
            dialer.ops()
        );
        // Where nothing landed, resume writes nothing and answers none.
        let (dialer, board, signer) = open(World::race());
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
        dialer.clear();
        assert_eq!(resume(&board, &merged, shot(&session, &signer)), Ok(None));
        assert_eq!(dialer.ops(), ["doc_metadata"]);
    }

    /// A DAUGHTER in the acknowledgment — the head moved under the merge —
    /// is reported at once with its position: ONE `publish`, no second, no
    /// claim read, no record. The embedder's `retries` rides into the next
    /// composition's record.
    #[test]
    fn a_daughter_is_reported_at_once_and_never_retried() {
        let (dialer, board, signer) = open(World::race());
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
        dialer.world().head_moved = true;
        dialer.clear();
        let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
        assert!(
            matches!(&landed, Landed::AsDaughter { address, .. } if address.to_string() == format!("{D}.2.1")),
            "{landed:?}"
        );
        let ops = dialer.ops();
        assert_eq!(ops.iter().filter(|o| *o == "publish").count(), 1);
        assert_eq!(ops.last().map(String::as_str), Some("publish"), "the library stops: {ops:?}");
        // The re-run the embedder makes carries `retries` one higher.
        let again =
            Inputs { options: Options { retries: 1, ..Options::default() }, ..race_inputs() };
        let merged = compose(&board, Some(session.token()), &again).expect("composed");
        assert_eq!(
            (merged.record.retries, merged.record.to_value()["retries"].as_u64()),
            (1, Some(1))
        );
        // A standing daughter holding M is found by the read-first too: the
        // trunk moved on by another's shot (which is why ours landed under
        // the head), so the trunk's next is another's and the daughter ours.
        {
            let mut w = dialer.world();
            w.text(D, 16, "!");
            w.member(
                &format!("{D}.3"),
                vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(D, 16, 1)],
                Some(15),
            );
            w.trunk_head.insert(D.to_string(), format!("{D}.3"));
            w.head_moved = false;
        }
        dialer.clear();
        let found = land(&board, &merged, shot(&session, &signer)).expect("landed");
        assert!(
            matches!(&found, Landed::AsDaughter { address, .. } if address.to_string() == format!("{D}.2.1")),
            "{found:?}"
        );
        assert!(!dialer.ops().iter().any(|o| o == "publish"), "{:?}", dialer.ops());
    }

    /// OVER THE CAP: a merged list past the shot's run cap is refused with
    /// the count before ANY frame — no read, no write.
    #[test]
    fn over_the_cap_refuses_with_the_count_before_any_frame() {
        let (dialer, board, signer) = open(World::race());
        let session = sign_in(&board, &signer);
        let mut merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
        assert_eq!(merged.cap, 1 << 12);
        merged.cap = 2;
        dialer.clear();
        assert_eq!(
            land(&board, &merged, shot(&session, &signer)),
            Err(Refusal::OverCap { runs: 3, cap: 2 })
        );
        assert_eq!(
            resume(&board, &merged, shot(&session, &signer)),
            Err(Refusal::OverCap { runs: 3, cap: 2 })
        );
        assert!(dialer.ops().is_empty(), "{:?}", dialer.ops());
    }

    /// THE DRAFT LANDING: the draft imaged, the core's script applied — one
    /// `reinstate` of the head's "big " by identity at position 5 — the
    /// record with `landed` the draft and its position, no `publish`, no
    /// claim read; a second landing finds the draft holding M and writes
    /// nothing.
    #[test]
    fn the_draft_landing_applies_the_script_and_writes_the_record() {
        let mut w = World::window_and_draft();
        w.text(D, 12, "big ");
        let head = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)];
        w.docs.get_mut(D).unwrap().runs = head.clone();
        w.docs.get_mut(&format!("{D}.2")).unwrap().runs = head;
        let (dialer, board, signer) = open(w);
        let session = sign_in(&board, &signer);
        let inputs = Inputs {
            sides: vec![Side::Draft { at: a(S), position: None }],
            base: Some(a(&format!("{D}.1"))),
            ..race_inputs()
        };
        let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
        assert_eq!(m_runs(&merged), vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(S, 1, 3)]);
        dialer.clear();
        let landing =
            || Landing::Draft { merger: merger(&session, &signer), into: a(S), journal: None };
        let landed = land(&board, &merged, landing()).expect("landed");
        let Landed::Draft { into, ops, record } = &landed else { panic!("{landed:?}") };
        assert_eq!((into.to_string(), *ops), (S.to_string(), 1));
        let frames = dialer.frames("reinstate");
        assert_eq!(frames.len(), 1);
        assert_eq!(
            (frames[0]["doc"].as_str(), frames[0]["at"]["ordinal"].as_str()),
            (Some(S), Some("5"))
        );
        assert_eq!(
            frames[0]["runs"],
            json!([{"origin": D, "i_start": format!("{D}.0.1.12"), "width": "4"}])
        );
        assert_eq!(
            dialer.world().docs.get(S).unwrap().runs,
            vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(S, 1, 3)]
        );
        let ops = dialer.ops();
        assert!(
            !ops.iter().any(|o| o == "publish" || o == "in_claims" || o == "delete"),
            "{ops:?}"
        );
        let atom: Value =
            serde_json::from_str(dialer.frames("insert")[0]["values"][0]["atom"].as_str().unwrap())
                .unwrap();
        assert_eq!(atom["landed"]["draft"], S);
        assert_eq!(dialer.frames("make_link")[0]["to"]["addrs"], json!([S]));
        dialer.clear();
        let rows = dialer.world().rows.len();
        assert_eq!(
            land(&board, &merged, landing()).expect("landed again"),
            Landed::Draft { into: a(S), ops: 0, record: record.clone() }
        );
        assert_eq!(dialer.world().rows.len(), rows, "nothing written twice");
    }

    /// Every refusal the shot can answer, each mapped: `withheld` naming the
    /// origin, `signed_session_required`, `doc_not_registered`, the
    /// library's own faults as halts — and nothing after the refusal.
    #[test]
    fn the_shots_refusals_are_mapped() {
        let (dialer, board, signer) = open(World::race());
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
        let refuse = |code: &str, site: Option<&str>| {
            let mut rej = json!({"resp": "rejected", "code": code, "disposition": "permanent", "op": "publish"});
            if let Some(s) = site {
                rej["site"] = json!({"addr": s});
            }
            dialer.world().memo.insert(format!("{}.publish", merged.key.text()), rej);
        };
        refuse("withheld", Some(Z));
        assert_eq!(
            land(&board, &merged, shot(&session, &signer)),
            Err(Refusal::WindowWithheld(a(Z)))
        );
        refuse("signed_session_required", None);
        assert_eq!(
            land(&board, &merged, shot(&session, &signer)),
            Err(Refusal::NeedsSignedSession)
        );
        refuse("doc_not_registered", None);
        assert_eq!(
            land(&board, &merged, shot(&session, &signer)),
            Err(Refusal::NoSuchDocument(a(D)))
        );
        refuse("base_superseded", None);
        let err = land(&board, &merged, shot(&session, &signer)).expect_err("own fault");
        assert!(
            matches!(&err, Refusal::Halt(h) if h.exit_code() == 3 && h.to_string().contains("base_superseded")),
            "{err}"
        );
        assert!(
            dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
            "nothing after a refused shot"
        );
    }

    // ── the record and the journal ───────────────────────────────────────

    /// A record with its atom in `journal` and its public link from `home`
    /// to `to`, typed `K`.
    fn file(w: &mut World, home: &str, journal: &str, record: &Record, to: &[&str]) -> String {
        let n = w.fresh(journal);
        w.values.insert((journal.to_string(), n), Val::Atom(record.to_value().to_string()));
        let d = w.docs.entry(journal.to_string()).or_insert_with(|| DocState {
            published: false,
            owner: ACCOUNT.into(),
            ..DocState::default()
        });
        d.runs.push(run(journal, n, 1));
        let k = w.links.iter().filter(|l| l.home == home).count() + 1;
        let addr = format!("{home}.0.2.{k}");
        w.links.push(LinkRow {
            addr: addr.clone(),
            home: home.into(),
            from: vec![i_addr(&a(journal), n)],
            to: to.iter().map(|t| t.to_string()).collect(),
            ty: K.into(),
        });
        addr
    }

    /// `current` finds the newest record per key, the trunk owner's home
    /// over another account's: another account's landed record loses to
    /// the owner's question; two in the owner's home, the later link wins;
    /// a record of another key is no candidate, nor one whose journal is
    /// unreadable. The atom is read THROUGH the journal's arrangement.
    #[test]
    fn current_prefers_the_trunk_owners_home_then_the_newest() {
        let (dialer, board, _) = open(World::race());
        let merged = compose(&board, Some(&token()), &race_inputs()).expect("composed");
        assert_eq!(merged.prior, None);
        let daughter = format!("{D}.1.1");
        let mut other = merged.record.clone();
        other.landed = Some(RecordLanding::Member { member: a(&format!("{D}.3")), position: 99 });
        let other_link = {
            let mut w = dialer.world();
            w.doc("1.0.2.0.5", false, "1.0.2", Vec::new());
            file(&mut w, OTHER_DOC1, "1.0.2.0.5", &other, &[&format!("{D}.3"), &daughter])
        };
        let found = current(&board, Some(&token()), &a(K), &merged.key)
            .expect("the lookup")
            .expect("a record");
        assert_eq!(
            (found.link.as_ref().map(ToString::to_string), found.landed.clone()),
            (Some(other_link.clone()), other.landed.clone()),
            "the one record stands"
        );
        let question = merged.record.clone();
        let owners_link = {
            let mut w = dialer.world();
            w.doc("1.0.1.0.5", false, ACCOUNT, Vec::new());
            file(&mut w, DOC1, "1.0.1.0.5", &question, &[&daughter])
        };
        let found = current(&board, Some(&token()), &a(K), &merged.key)
            .expect("the lookup")
            .expect("a record");
        assert_eq!(
            (found.link.as_ref().map(ToString::to_string), found.landed.clone()),
            (Some(owners_link), None),
            "the trunk owner's home is current over another's"
        );
        let mut later = merged.record.clone();
        later.landed = Some(RecordLanding::Member { member: a(&format!("{D}.3")), position: 120 });
        let later_link =
            file(&mut dialer.world(), DOC1, "1.0.1.0.5", &later, &[&format!("{D}.3"), &daughter]);
        let mut another_key = merged.record.clone();
        another_key.base = a(&format!("{D}.2"));
        file(&mut dialer.world(), DOC1, "1.0.1.0.5", &another_key, &[&daughter]);
        dialer.clear();
        let found = current(&board, Some(&token()), &a(K), &merged.key)
            .expect("the lookup")
            .expect("a record");
        assert_eq!(
            (found.link.as_ref().map(ToString::to_string), found.landed.clone()),
            (Some(later_link.clone()), later.landed.clone()),
            "the newest in the owner's home"
        );
        let ops = dialer.ops();
        assert!(!ops.iter().any(|o| o == "retrieve_i"), "{ops:?}");
        assert!(
            ops.contains(&"image".to_string()) && ops.contains(&"retrieve_v".to_string()),
            "read through the arrangement: {ops:?}"
        );
        // A later compose carries the current record as prior and names it
        // as what the next record replaces.
        let merged = compose(&board, Some(&token()), &race_inputs()).expect("composed");
        assert_eq!(
            merged.prior.as_ref().and_then(|p| p.link.as_ref()).map(ToString::to_string),
            Some(later_link.clone())
        );
        assert_eq!(merged.record.replaces.as_ref().map(ToString::to_string), Some(later_link));
        // The owner's journal unreadable: the other account's record stands.
        dialer.world().withheld.insert("1.0.1.0.5".into());
        let found = current(&board, Some(&token()), &a(K), &merged.key)
            .expect("the lookup")
            .expect("a record");
        assert_eq!(found.link.map(|l| l.to_string()), Some(other_link));
    }

    /// `journal::of`: the journal named is answered with no read; the
    /// default is the document the account's first link of the kind from
    /// doc 1 points into; with none, a PRIVATE draft is minted.
    #[test]
    fn the_journal_is_named_found_or_minted() {
        let (dialer, board, signer) = open(World::race());
        let session = sign_in(&board, &signer);
        let merger = merger(&session, &signer);
        dialer.clear();
        assert_eq!(
            journal::of(&board, &merger, &a(K), Some(a("1.0.1.0.7"))).expect("named"),
            a("1.0.1.0.7")
        );
        assert!(dialer.ops().is_empty());
        let minted = journal::of(&board, &merger, &a(K), None).expect("minted");
        assert_eq!(minted, a("1.0.1.0.10"));
        assert_eq!(dialer.frames("create_new_document")[0]["published"], false);
        assert_eq!(dialer.ops(), ["find_links_ftt", "create_new_document"]);
        let record = compose(&board, Some(&token()), &race_inputs()).expect("composed").record;
        {
            let mut w = dialer.world();
            w.doc("1.0.1.0.6", false, ACCOUNT, Vec::new());
            file(&mut w, DOC1, "1.0.1.0.6", &record, &[&format!("{D}.1.1")]);
        }
        dialer.clear();
        assert_eq!(journal::of(&board, &merger, &a(K), None).expect("found"), a("1.0.1.0.6"));
        assert_eq!(dialer.ops(), ["find_links_ftt", "read_link"]);
    }

    /// `verify`'s three verdicts: Equal where the member holds M over its
    /// `placed` positions, Differs at the first V-ordinal where it does not,
    /// Unreadable where the member is withheld — M recomputed from the
    /// record's inputs, `compare` asked once as the oracle of the join.
    #[test]
    fn verify_answers_equal_differs_and_unreadable() {
        let (dialer, board, signer) = open(World::race());
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
        land(&board, &merged, shot(&session, &signer)).expect("landed");
        let record = current(&board, Some(&token()), &a(K), &merged.key)
            .expect("the lookup")
            .expect("the record");
        dialer.clear();
        assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal));
        let ops = dialer.ops();
        assert_eq!(ops.iter().filter(|o| *o == "compare").count(), 1, "{ops:?}");
        assert!(!ops.iter().any(|o| ["publish", "insert", "make_link"].contains(&o.as_str())));
        let compare = &dialer.frames("compare")[0];
        assert_eq!(compare["rho1"][0]["doc"], format!("{D}.1"));
        assert_eq!(
            compare["rho2"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["doc"].as_str().unwrap().to_string())
                .collect::<Vec<_>>(),
            [format!("{D}.2"), format!("{D}.1.1")]
        );
        let mut differs = record.clone();
        differs.landed = Some(RecordLanding::Member { member: a(&format!("{D}.2")), position: 0 });
        assert_eq!(
            verify(&board, Some(&token()), &differs),
            Ok(Verdict::Differs { at: 12 }),
            "the head keeps ' sat' past M's eleven positions"
        );
        let mut another = record.clone();
        another.landed =
            Some(RecordLanding::Member { member: a(&format!("{D}.1.1")), position: 0 });
        assert_eq!(
            verify(&board, Some(&token()), &another),
            Ok(Verdict::Differs { at: 5 }),
            "the daughter has no 'big ' at V 5"
        );
        dialer.world().withheld.insert(format!("{D}.3"));
        assert_eq!(
            verify(&board, Some(&token()), &record),
            Ok(Verdict::Unreadable(a(&format!("{D}.3"))))
        );
        let mut question = record.clone();
        question.landed = None;
        assert!(matches!(verify(&board, Some(&token()), &question), Err(Refusal::Halt(_))));
        // The oracle in parts: a compare budget of one block is halved until
        // each part answers, and the join still agrees.
        dialer.world().withheld.clear();
        dialer.world().compare_cap = 1;
        dialer.clear();
        assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal));
        assert!(dialer.frames("compare").len() > 1, "{:?}", dialer.ops());
    }

    /// The `Record` round trip through its JSON, `type` fixed `merge`, the
    /// gaps with their runs and resolutions, a draft side and a draft
    /// landing included; an object of another type or version is no record.
    #[test]
    fn the_record_round_trips_and_names_its_type() {
        let (_, board, _) = open(World::race());
        let mut merged = compose(&board, Some(&token()), &race_inputs()).expect("composed");
        merged.record.sides.push(SideAt::Draft { at: a(S), position: Some(7) });
        merged.record.landed = Some(RecordLanding::Draft { draft: a(S), position: 9 });
        merged.record.claims = vec![a(&format!("{DOC1}.0.2.4"))];
        merged.record.replaces = Some(a(&format!("{DOC1}.0.2.2")));
        merged.record.gaps = vec![
            Gap {
                id: GapId(1),
                kind: GapKind::Order,
                after: Some(a(&format!("{D}.0.1.4"))),
                before: Some(a(&format!("{D}.0.1.5"))),
                runs: vec![(SideIx(0), run(D, 12, 4)), (SideIx(1), run(D, 16, 4))],
                placed: Placement::Order(vec![SideIx(1), SideIx(0)]),
                settled: true,
                resolved_by: Some(ResolvedBy::Agent),
            },
            Gap {
                id: GapId(2),
                kind: GapKind::Corner,
                after: None,
                before: Some(a(&format!("{D}.0.1.1"))),
                runs: vec![(SideIx(1), run(Z, 3, 2))],
                placed: Placement::Omitted,
                settled: true,
                resolved_by: Some(ResolvedBy::Answer(a(&format!("{DOC1}.0.1.7")))),
            },
            Gap {
                id: GapId(3),
                kind: GapKind::Anchor,
                after: Some(a(&format!("{D}.0.1.4"))),
                before: Some(a(&format!("{D}.0.1.8"))),
                runs: vec![(SideIx(1), run(D, 15, 1))],
                placed: Placement::Before,
                settled: true,
                resolved_by: Some(ResolvedBy::Rule),
            },
        ];
        merged.record.values.applied = vec![GapId(1)];
        let v = merged.record.to_value();
        assert_eq!(
            (v["type"].as_str(), v["v"].as_u64(), v["rules"].as_str()),
            (Some("merge"), Some(1), Some("merge-rules-1"))
        );
        assert_eq!(
            v["gaps"][0]["runs"][0],
            json!({"side": 0, "i_start": format!("{D}.0.1.12"), "width": "4"})
        );
        assert_eq!(
            (
                v["gaps"][0]["placed"].clone(),
                v["gaps"][1]["placed"].clone(),
                v["gaps"][2]["placed"].clone()
            ),
            (json!([1, 0]), json!("omitted"), json!("before"))
        );
        assert_eq!(v["gaps"][1]["resolved_by"], format!("answer:{DOC1}.0.1.7"));
        assert_eq!(v["sides"][2], json!({"at": {"draft": S, "position": 7}, "role": "draft"}));
        assert_eq!(v["landed"], json!({"draft": S, "position": 9}));
        assert!(v.get("link").is_none(), "the link is no member of the body");
        let back = Record::from_value(&v).expect("a record");
        assert_eq!(back, merged.record);
        assert_eq!(
            back.options().resolutions,
            vec![
                Resolution {
                    gap: GapId(1),
                    choice: Choice::Order(vec![SideIx(1), SideIx(0)]),
                    by: ResolvedBy::Agent
                },
                Resolution {
                    gap: GapId(2),
                    choice: Choice::Omit,
                    by: ResolvedBy::Answer(a(&format!("{DOC1}.0.1.7")))
                }
            ]
        );
        let mut other = v.clone();
        other["type"] = json!("skep-head");
        assert_eq!(Record::from_value(&other), None);
        other["type"] = json!("merge");
        other["v"] = json!(2);
        assert_eq!(Record::from_value(&other), None);
    }

    // ── the fences ───────────────────────────────────────────────────────

    /// NO CLASS SCAN: every `find_links_ftt` the module sends — composing,
    /// landing, looking a record up, finding the journal — constrains `to`
    /// or `home`; and the three frame constructors constrain a second slot.
    #[test]
    fn no_frame_this_module_sends_is_a_class_scan() {
        let (dialer, board, signer) = open(World::race());
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
        land(&board, &merged, shot(&session, &signer)).expect("landed");
        current(&board, Some(&token()), &a(K), &merged.key).expect("the lookup");
        journal::of(&board, &merger(&session, &signer), &a(K), None).expect("the journal");
        let queries = dialer.frames("find_links_ftt");
        assert!(queries.len() >= 5, "{}", queries.len());
        for q in &queries {
            let q = &q["q"];
            assert!(
                q["to"] != "any" || q["home"] != "any" || q["from"] != "any",
                "a class scan: {q}"
            );
        }
        for frame in [
            frames::find_links_ftt(K, D),
            frames::find_links_ftt_from(K, D),
            frames::find_links_ftt_home(K, DOC1),
        ] {
            let q = &frame["q"];
            assert!(
                q["to"] != "any" || q["home"] != "any" || q["from"] != "any",
                "a class scan: {q}"
            );
        }
    }

    /// THE HEAD-MEMBER FALLBACK: `head_of` walks the document's feed rows
    /// to the last `publish` row naming a TRUNK member — a daughter's row
    /// after it does not move the head — and follows the trunk after a
    /// shot; `None` for a document with no member.
    #[test]
    fn head_of_walks_the_feed_to_the_last_trunk_publish() {
        let (dialer, board, signer) = open(World::race());
        assert_eq!(
            head_of(&board, Some(&token()), &a(D)).expect("walked"),
            Some(a(&format!("{D}.2"))),
            "the daughter's later row does not move the head"
        );
        assert_eq!(head_of(&board, Some(&token()), &a(Z)).expect("walked"), None);
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
        land(&board, &merged, shot(&session, &signer)).expect("landed");
        assert_eq!(
            head_of(&board, Some(&token()), &a(D)).expect("walked"),
            Some(a(&format!("{D}.3")))
        );
        let under: Vec<String> =
            dialer.ops().into_iter().filter(|o| o.starts_with("GET /changes?")).collect();
        assert!(
            under.iter().all(|u| u.contains("&under=")),
            "every walk is narrowed to its document: {under:?}"
        );
        assert_eq!(
            under.iter().filter(|u| u.ends_with(&format!("under={D}"))).count(),
            2,
            "{under:?}"
        );
    }
}
