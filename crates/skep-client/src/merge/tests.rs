//! The merge's unit suite: the merge record's §9 vectors, each row one
//! test over `compose_runs` with the row's literal runs, asserting M as
//! runs, the gap kinds, the `settled` flags and the value log as the table
//! stands after the rulings; the resolutions, one per unsettled kind; the
//! record's re-statement of them as a law over every place a gap is moved
//! to; the fences the module promises; the one rule as a property over
//! generated inputs; `base_of` over §1.2's address forms; `script` over
//! three pairs. No board: every value read is a closure over a table the
//! test writes.
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

/// (h′) an addition at the END whose left anchor was removed: A appended
/// "!" after `D·11` (`⊤` its right anchor), B removed ` sat` (`8–11`) — an
/// `anchor`, settled, placed BEFORE the end, so M reads "the cat!" and
/// never "!the cat" (R2: "immediately before ⊤"; found by the command's
/// walk, 2026-10-15).
#[test]
fn case_h_prime_an_addition_at_the_end_beside_a_removal_stays_at_the_end() {
    let c = compose(&base(), &two(vec![rd(1, 11), rd(12, 1)], vec![rd(1, 7)]));
    assert_eq!(runs(&c), vec![rd(1, 7), rd(12, 1)], "the cat!");
    assert_eq!(kinds(&c), vec![(GapKind::Anchor, true)]);
    assert_eq!(c.gaps[0].placed, Placement::Before);
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

/// (j) a fork merged back, as the composition serves it: A's "big " at
/// `D·4|D·5`, F's "dog" for `5–7` — an `anchor` for A's, its right anchor
/// gone, settled; F's group last, not in the chain. The fork's base is the
/// reads' to find (its served source); the core composes the pair as any.
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

/// A move and an order at one gap combine, whichever the merger gave first.
///
/// At (b)'s gap of two groups, `Order([B,A])` and `After(D·11)` together
/// place B's "fat " then A's "big " after the base's last position, with
/// the anchors as M holds them.
#[test]
fn a_move_and_an_order_compose_at_one_gap() {
    let sides = two(vec![rd(1, 4), rd(12, 4), rd(5, 7)], vec![rd(1, 4), rd(16, 4), rd(5, 7)]);
    let order = Choice::Order(vec![SideIx(1), SideIx(0)]);
    let moved = Choice::After(d_at(11));
    for choices in [[order.clone(), moved.clone()], [moved, order]] {
        let resolutions = choices
            .iter()
            .map(|choice| Resolution { gap: GapId(1), choice: choice.clone(), by: ResolvedBy::Person })
            .collect();
        let c = compose_runs(&base(), &sides, None, &Options { resolutions, ..Options::default() }, &unread);
        assert_eq!(runs(&c), vec![rd(1, 11), rd(16, 4), rd(12, 4)], "the cat satfat big : {choices:?}");
        assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(1), SideIx(0)]), "{choices:?}");
        assert_eq!(anchors(&c), vec![(Some(11), None)], "{choices:?}");
        assert!(c.ignored.is_empty(), "{choices:?}");
    }
}

// ── the record's re-statement ────────────────────────────────────────────

/// The record a landing of `c` writes, read back from its JSON.
///
/// Its inputs are fixed; its gaps, its value log and its counts are the
/// composition's, so its options are what a verifier composes from.
///
/// # Panics
///
/// Panics if the record does not read back from the JSON it writes.
fn recorded(c: &Composed) -> Record {
    let record = Record {
        doc: d(),
        base: addr("1.0.1.0.1.2"),
        sides: vec![
            SideAt::Member { at: addr("1.0.1.0.1.3"), role: Role::Head },
            SideAt::Member { at: addr("1.0.1.0.1.2.1"), role: Role::Alternative },
        ],
        landed: None,
        claims: Vec::new(),
        runs: c.counts,
        retries: 0,
        gaps: c.gaps.clone(),
        values: c.values.clone(),
        replaces: None,
        by: "skep-client".into(),
        link: None,
    };
    Record::from_value(&record.to_value()).expect("the record reads back")
}

/// A record's options compose the same M and gaps as its merger's choices.
///
/// It is the record's re-statement law (merge record §4), over every
/// unsettled shape of gap — an order gap, a cut, a corner beside one
/// survivor or between two, a collision of no, one and two groups. Each
/// gap is moved after or before every base position, or not moved, then
/// ordered, kept or omitted, the move given first or last; the options its
/// record re-states compose again to the runs and the gaps the merger's
/// own choices composed. Every shape's gap is moved somewhere, so the law
/// never holds by the default place alone.
#[test]
fn a_record_recomposes_every_place_and_choice_its_merger_made() {
    let shapes = [
        ("(b)", two(vec![rd(1, 4), rd(12, 4), rd(5, 7)], vec![rd(1, 4), rd(16, 4), rd(5, 7)])),
        ("(c)", two(vec![rd(1, 4), rd(12, 3), rd(8, 4)], vec![rd(1, 4)])),
        ("(e′)", two(vec![rd(5, 7), rd(1, 4)], vec![rd(1, 4), rd(12, 4), rd(5, 7)])),
        ("(f′)", two(vec![rd(1, 4), rd(12, 3), rd(8, 4)], vec![rd(1, 5), rd(16, 1), rd(6, 6)])),
        ("(i′)", two(vec![rd(1, 2), rd(12, 1), rd(4, 8)], vec![rd(1, 2), rd(13, 1), rd(4, 8)])),
        ("the corner, a left survivor", two(vec![rd(1, 6), rd(12, 1), rd(7, 5)], vec![rd(1, 4)])),
        ("the agent case", two(vec![rd(1, 4), rd(12, 3), rd(8, 4)], vec![rd(1, 4), rd(16, 6), rd(8, 4)])),
        ("a collision with nothing placed", two(vec![rd(1, 4), rd(8, 4)], vec![rd(1, 4)])),
    ];
    let places: Vec<Option<Choice>> = std::iter::once(None)
        .chain((1..=11).flat_map(|n| [Some(Choice::After(d_at(n))), Some(Choice::Before(d_at(n)))]))
        .collect();
    let picks = [
        None,
        Some(Choice::Order(vec![SideIx(0), SideIx(1)])),
        Some(Choice::Order(vec![SideIx(1), SideIx(0)])),
        Some(Choice::KeepOnly(SideIx(0))),
        Some(Choice::KeepOnly(SideIx(1))),
        Some(Choice::KeepBoth),
        Some(Choice::Omit),
    ];
    for (name, sides) in &shapes {
        let unmoved = anchors(&compose(&base(), sides));
        let mut moved = 0;
        for place in &places {
            for pick in &picks {
                for given in [[place, pick], [pick, place]] {
                    let resolutions: Vec<Resolution> = given
                        .into_iter()
                        .flatten()
                        .map(|choice| Resolution { gap: GapId(1), choice: choice.clone(), by: ResolvedBy::Person })
                        .collect();
                    let options = Options { resolutions: resolutions.clone(), ..Options::default() };
                    let first = compose_runs(&base(), sides, None, &options, &unread);
                    let again = compose_runs(&base(), sides, None, &recorded(&first).options(), &unread);
                    assert_eq!((runs(&again), &again.gaps), (runs(&first), &first.gaps), "{name}: {resolutions:?}");
                    moved += usize::from(anchors(&first) != unmoved);
                }
            }
        }
        assert!(moved > 0, "{name}: no place moved its gap");
    }
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

/// The ops applied to a draft, in order, position by position — the
/// suite's reading of the preview `script` is.
///
/// A reinstate may place a position the draft already holds: a draft places
/// a run twice as two placements (skep #763).
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
                draft.splice(at..at, expand(runs));
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

// ── a run placed twice (skep #763) ───────────────────────────────────────

/// A RUN PLACED TWICE IN EVERY LIST composes keeping both placements (skep
/// #763): the base "abcd abcd" — `D·1–4` twice — the head placing both and
/// adding "!" at the end, the side placing both; M holds both placements
/// and the addition, and asks nothing. A side that drops the second
/// placement removes that placement alone, as any base position — the
/// head's "!" beside it then an `anchor` gap settled by rule (§2 R2), as
/// beside any removal; a side that places a run of the base a second time
/// adds that placement where it put it; the same second copy on both sides
/// is one addition. Debug builds panicked here ("a position placed twice in
/// one list") and release builds dropped the copy.
#[test]
fn a_run_placed_twice_in_every_list_composes_keeping_both_placements() {
    let twice = vec![rd(1, 4), rd(1, 4)];
    let c = compose(&twice, &two(vec![rd(1, 4), rd(1, 4), rd(12, 1)], vec![rd(1, 4), rd(1, 4)]));
    assert_eq!(runs(&c), vec![rd(1, 4), rd(1, 4), rd(12, 1)], "abcd abcd!");
    assert_eq!(kinds(&c), vec![]);
    assert_eq!(c.counts, RunCounts { a: 3, b: 2, m: 3 });
    // B drops the second placement: it alone goes, and A's "!" beside it is
    // an anchor gap, settled — the second copy was its left anchor.
    let c = compose(&twice, &two(vec![rd(1, 4), rd(1, 4), rd(12, 1)], vec![rd(1, 4)]));
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 1)], "abcd!");
    assert_eq!(kinds(&c), vec![(GapKind::Anchor, true)]);
    // A drops the second placement, B keeps both: a removal alone, no gap.
    let c = compose(&twice, &two(vec![rd(1, 4)], vec![rd(1, 4), rd(1, 4)]));
    assert_eq!(runs(&c), vec![rd(1, 4)], "abcd");
    assert_eq!(kinds(&c), vec![]);
    // A side places a run of the base a second time: an addition at the end,
    // both anchors standing together, no gap.
    let c = compose(&base(), &two(vec![rd(1, 11), rd(5, 3)], vec![rd(1, 11)]));
    assert_eq!(runs(&c), vec![rd(1, 11), rd(5, 3)], "the cat satcat");
    assert_eq!(kinds(&c), vec![]);
    assert_eq!(c.runs[1].side, Some(SideIx(0)));
    // Both sides place the same second copy: one shared addition, as any
    // identical addition.
    let c = compose(&base(), &two(vec![rd(1, 11), rd(5, 3)], vec![rd(1, 11), rd(5, 3)]));
    assert_eq!(runs(&c), vec![rd(1, 11), rd(5, 3)]);
    assert_eq!(kinds(&c), vec![]);
}

/// `script` over a draft placing a run twice turns it into its target,
/// both placements accounted for (skep #763): a draft "abcd abcd" gaining
/// "!" between the copies, and a draft placing a run of itself a second
/// time — each script applied reads back as the target, and no build
/// panics.
#[test]
fn script_turns_a_draft_placing_a_run_twice_into_its_target() {
    let current = vec![rd(1, 4), rd(1, 4)];
    let target = vec![rd(1, 4), rd(12, 1), rd(1, 4)];
    let ops = script(&current, &target);
    assert_eq!(ops, vec![InPlaceOp::Reinstate { at: 5, runs: vec![rd(12, 1)] }], "{ops:?}");
    assert_eq!(apply(&current, &ops), expand(&target));
    let doubled = vec![rd(1, 4), rd(1, 4)];
    let ops = script(&[rd(1, 4)], &doubled);
    assert_eq!(ops, vec![InPlaceOp::Reinstate { at: 5, runs: vec![rd(1, 4)] }], "{ops:?}");
    assert_eq!(apply(&[rd(1, 4)], &ops), expand(&doubled));
    let ops = script(&doubled, &[rd(1, 4)]);
    assert_eq!(ops, vec![InPlaceOp::Delete { p: 5, width: 4 }], "{ops:?}");
    assert_eq!(apply(&doubled, &ops), expand(&[rd(1, 4)]));
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
    use crate::board::{acked_addr, acked_at, frames, Answer, AtAnswer, Board, Scope, HEAD_MEMBER_1};
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

    /// The merge marker a draft carries (wire.md §The response envelope,
    /// `doc_metadata`'s `merge`).
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Marker {
        sides: Vec<String>,
        head: String,
        head_copied: u64,
        at: u64,
    }

    /// One document as the world holds it.
    #[derive(Debug, Clone, Default)]
    struct DocState {
        runs: Vec<Run>,
        published: bool,
        owner: String,
        placed: Option<u64>,
        base_extent: Option<u64>,
        /// The source a `version` minted the document sharing, or a `stage`
        /// copied into it — its `doc_metadata` `source`; `None` where
        /// neither did.
        source: Option<String>,
        /// The base the board records for a staged draft as of each
        /// position it changed at, with the extent the copy took of it — its
        /// `doc_metadata` `base` and `base_copied`, recorded by `stage`,
        /// moved by each `publish` naming the draft as its rendering `draft`
        /// (wire.md §Namespace, `stage`) and by each `set_arrangement`
        /// naming a base to record, served as of `at` on `/op-at`; empty
        /// where the board records none.
        staged: BTreeMap<u64, (String, u64)>,
        /// The merge marker beside the base as of each position it changed
        /// at — set or cleared by a `set_arrangement` naming a base, cleared
        /// by the `publish` that moves the base, inherited at a `stage` of a
        /// marked draft (wire.md §The response envelope, `doc_metadata`'s
        /// `merge`); `None` at a position is no marker.
        markers: BTreeMap<u64, Option<Marker>>,
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
        /// A `set_arrangement` row's two terms — the base it recorded and
        /// the request's merge beside its head, whether or not a marker was
        /// recorded, each `null` where none rides (wire.md §The change
        /// feed); `None` on every other op's row, which carries neither
        /// member.
        terms: Option<(Option<String>, Option<Value>)>,
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
        /// `/op-at` answers `history_reclaimed` below this position, where
        /// one is set: the journal reclaimed there.
        floor: Option<u64>,
        /// Numbers inside one multi-record commit, each `not_a_position`.
        ///
        /// `/op-at` answers each with `nearest` the greatest number below it
        /// that is none of them (wire.md §Reading history); a number past
        /// `position` answers `beyond_head`.
        inside_commits: BTreeSet<u64>,
        /// Another hand's edit landing in the middle of a walk: before the
        /// N-th frame the dialer serves is answered, the document's
        /// arrangement becomes these runs, one commit.
        interleave: Option<(usize, String, Vec<Run>)>,
        /// The journal reclaimed in the middle of a walk.
        ///
        /// Before the N-th frame the dialer serves is answered, `floor`
        /// becomes this position.
        reclaim: Option<(usize, u64)>,
        /// A grant withdrawn in the middle of a walk.
        ///
        /// Before the N-th frame the dialer serves is answered, this
        /// document joins `withheld`.
        withhold: Option<(usize, String)>,
        /// Every shot lands as its base's daughter: the head moved.
        head_moved: bool,
        /// Documents this reader may not read.
        withheld: BTreeSet<String>,
        /// `/health` names the merger's account the board's claimant.
        claimed: bool,
        /// `H.1` answers its record.
        head: bool,
        /// The merger's enrolled key.
        key: Option<PublicKey>,
    }

    impl World {
        /// A claimed permissive board with the merger's doc 1 and `K`, the
        /// kind's document, serving its head record.
        fn new() -> World {
            let mut w = World {
                position: 10,
                image_cap: 1 << 12,
                delivery_cap: 1 << 17,
                compare_cap: 1 << 12,
                next_doc: 10,
                claimed: true,
                head: true,
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
                    source: None,
                    staged: BTreeMap::new(),
                    markers: BTreeMap::new(),
                    history,
                },
            );
        }

        /// Another hand's edit: `doc`'s arrangement becomes `runs`, one
        /// commit at the next position.
        fn change(&mut self, doc: &str, runs: Vec<Run>) -> u64 {
            let at = self.commit("delete", vec![doc.to_string()]);
            let d = self.docs.get_mut(doc).expect("a document of the world");
            d.runs = runs.clone();
            d.history.insert(at, runs);
            at
        }

        /// The draft's recorded base and marker as they stand.
        fn standing(&self, doc: &str) -> (Option<(String, u64)>, Option<Marker>) {
            let d = self.docs.get(doc).expect("a document of the world");
            (
                d.staged.values().next_back().cloned(),
                d.markers.values().next_back().cloned().flatten(),
            )
        }

        /// Records `text`, a draft of the world, as STAGED from `base` with
        /// `copied` positions taken of it — its `doc_metadata` `base`,
        /// `base_copied` and `source`, as the board's `stage` records them
        /// (wire.md §Namespace), standing from the world's first position.
        /// The draft's arrangement is the cell's.
        fn staged(&mut self, text: &str, base: &str, copied: u64) {
            let d = self.docs.get_mut(text).expect("a draft of the world");
            d.staged.insert(0, (base.to_string(), copied));
            d.source = Some(base.to_string());
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
                terms: None,
            });
        }

        /// A cross-owner FORK: a private document of `owner`'s account that a
        /// `version` minted off `source` — the member or bare document it
        /// was born sharing, its `doc_metadata` `source` — arranged as
        /// `runs` since, with its `version` row on the feed.
        fn fork(&mut self, text: &str, owner: &str, source: &str, runs: Vec<Run>) {
            self.doc(text, false, owner, runs);
            self.docs.get_mut(text).unwrap().source = Some(source.to_string());
            self.position += 1;
            self.rows.push(FeedRow {
                at: self.position,
                op: "version",
                docs: vec![text.to_string()],
                terms: None,
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
        /// — "hello" windowed from `Z` — and the staging draft `S`, staged
        /// from the base `D.1` (its recorded base) with "!!!" typed at its
        /// end.
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
            w.staged(S, &format!("{D}.1"), 11);
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
            self.rows.push(FeedRow { at: self.position, op, docs, terms: None });
            self.position
        }

        /// One commit of `records` records: the position advances by each,
        /// the numbers inside the commit answer `not_a_position` on `/op-at`
        /// (wire.md §Reading history), and the row's `at` is the commit's
        /// last — the ack's.
        fn commit_records(&mut self, op: &'static str, docs: Vec<String>, records: u64) -> u64 {
            let first = self.position + 1;
            self.position += records;
            self.inside_commits.extend(first..self.position);
            self.rows.push(FeedRow { at: self.position, op, docs, terms: None });
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
            let claimant = if self.claimed { json!(ACCOUNT) } else { Value::Null };
            json!({"ok": true, "log_position": self.position, "chain_head": chain_hex(self.position), "auth": {"claimant": claimant, "local_trust": true, "origins": [origin], "signed_origins": [origin]}})
        }

        /// Answers a `/changes` page: the rows past `since`, narrowed to
        /// `under` and, with `drafts=true`, to the rows naming a draft (the
        /// supplement's page, wire.md §The change feed); a
        /// `set_arrangement` row carries its two terms.
        fn changes(&self, path: &str) -> Response {
            let query = path.splitn(2, '?').nth(1).unwrap_or("");
            let (mut since, mut under, mut limit, mut drafts) = (0u64, None::<String>, 256usize, false);
            for pair in query.split('&') {
                match pair.split_once('=') {
                    Some(("since", v)) => since = v.parse().unwrap(),
                    Some(("under", v)) => under = Some(v.to_string()),
                    Some(("limit", v)) => limit = v.parse().unwrap(),
                    Some(("drafts", v)) => drafts = v == "true",
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
                .filter(|r| !drafts || r.docs.iter().any(|d| self.docs.get(d).is_some_and(|x| !x.published)))
                .collect();
            let page: Vec<Value> = visible
                .iter()
                .take(limit)
                .map(|r| {
                    let mut row = json!({"at": r.at, "op": r.op, "docs": r.docs, "key": "bare", "time": null});
                    if let Some((base, merge)) = &r.terms {
                        row["base"] = base.clone().map_or(Value::Null, Value::from);
                        row["merge"] = merge.clone().unwrap_or(Value::Null);
                    }
                    row
                })
                .collect();
            let last = page.last().and_then(|r| r["at"].as_u64()).unwrap_or(since);
            reply(200, json!({"changes": page, "last": last, "more": visible.len() > page.len()}))
        }

        fn op(&mut self, frame: &Value, at: Option<u64>) -> Result<Response, DialError> {
            let op = frame["op"].as_str().unwrap_or("?").to_string();
            // Every answer names where it sits: `at` on `/op-at`, the head
            // on `/op` (wire.md §Reading history).
            let position = at.unwrap_or(self.position);
            let rejected = |code: &str| {
                reply(
                    200,
                    json!({"resp": "rejected", "code": code, "disposition": "reorder", "op": op}),
                )
            };
            // A document argument this reader may not read: `withheld`,
            // `site.addr` the document (wire.md §The read predicate).
            let masked = |doc: &str| {
                reply(
                    200,
                    json!({"resp": "rejected", "code": "withheld", "disposition": "reorder", "op": op, "site": {"addr": doc}}),
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
                        return Ok(masked(doc));
                    }
                    let Some(d) = self.docs.get(doc) else { return Ok(rejected("doc_not_registered")) };
                    // A document minted after `position` did not exist then
                    // (wire.md §Reading history: "that position's own
                    // `doc_not_registered`").
                    if d.history.keys().next().is_some_and(|minted| *minted > position) {
                        return Ok(rejected("doc_not_registered"));
                    }
                    // The recorded base and the marker as they stood at
                    // `position`.
                    let staged = d.staged.range(..=position).next_back().map(|(_, s)| s);
                    let marker = d.markers.range(..=position).next_back().and_then(|(_, m)| m.clone());
                    let merge = marker.map(|m| json!({"sides": m.sides, "head": m.head, "head_copied": m.head_copied.to_string(), "at": m.at}));
                    Ok(reply(200, json!({"resp": "doc_metadata", "as_of": position, "doc": doc, "published": d.published, "owner": d.owner, "placed": d.placed.map(|p| p.to_string()), "base_extent": d.base_extent.map(|e| e.to_string()), "source": d.source, "base": staged.map(|(b, _)| b.clone()), "base_copied": staged.map(|(_, c)| c.to_string()), "merge": merge})))
                }
                "retrieve_doc_v_span_set" => {
                    let doc = frame["doc"].as_str().unwrap();
                    if self.withheld.contains(doc) {
                        return Ok(masked(doc));
                    }
                    let Some(runs) = self.arrangement(doc, at) else { return Ok(rejected("doc_not_registered")) };
                    let extent: u64 = runs.iter().map(|r| r.width).sum();
                    let set = if extent == 0 { json!([]) } else { json!([{"start": "1.1", "width": format!("0.{extent}")}]) };
                    Ok(reply(200, json!({"resp": "span_set", "as_of": position, "set": set})))
                }
                "image" => {
                    let doc = frame["d"].as_str().unwrap();
                    if self.withheld.contains(doc) {
                        return Ok(masked(doc));
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
                        let items = if self.head { json!([{"atom": record}]) } else { json!([]) };
                        return Ok(reply(200, json!({"resp": "delivery", "as_of": position, "items": items})));
                    }
                    if self.withheld.contains(doc) {
                        return Ok(masked(doc));
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
                    // Every region's document consulted in declaration
                    // order, ρ₁'s before ρ₂'s, before the read runs.
                    let regions = frame["rho1"].as_array().unwrap().iter().chain(frame["rho2"].as_array().unwrap());
                    if let Some(doc) = regions.filter_map(|r| r["doc"].as_str()).find(|d| self.withheld.contains(*d)) {
                        return Ok(masked(doc));
                    }
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
                "publish" | "insert" | "make_link" | "create_new_document" | "delete" | "reinstate" | "stage" | "set_arrangement" => {
                    assert!(at.is_none(), "a write on `/op-at` is `write_at_history`: {frame}");
                    self.write(frame)
                }
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
                    // The row names the minted member first, then the
                    // rendering draft (wire.md §The change feed, `docs`).
                    let docs = std::iter::once(member.clone()).chain(draft.clone()).collect();
                    let at = self.commit("publish", docs);
                    // THE BASE MOVES at the shot's position: the rendering
                    // draft's recorded base becomes the member the shot
                    // minted, `base_copied` its whole count, and the marker
                    // is cleared — the merge is the member's now (wire.md
                    // §Namespace, `stage`); a read as of an earlier position
                    // answers the base that stood.
                    if let Some(s) = draft.as_ref().and_then(|s| self.docs.get_mut(s)) {
                        s.staged.insert(at, (member.clone(), placed));
                        s.markers.insert(at, None);
                    }
                    json!({"resp": "ack_addr", "addr": member, "at": at})
                }
                "stage" => {
                    // THE STAGING ACT (wire.md §Namespace, `stage`): a private
                    // draft of the account holding `from` by identity, its
                    // base the surface copied at its count — or a draft's
                    // own base and marker inherited, the marker's `at` this
                    // stage's position — in one commit.
                    let from = frame["from"].as_str().unwrap().to_string();
                    let Some(src) = self.docs.get(&from).cloned() else {
                        return permanent("stage", "source_not_registered", Value::Null);
                    };
                    let addr = format!("{ACCOUNT}.0.{}", self.next_doc);
                    self.next_doc += 1;
                    let extent: u64 = src.runs.iter().map(|r| r.width).sum();
                    self.doc(&addr, false, ACCOUNT, src.runs.clone());
                    // ONE COMMIT of three records (the skepd suite's
                    // `an_alternative_inherits_the_marker_at_the_stages_position_and_the_shot_clears_it`),
                    // so the number below the ack's `at` lies inside it.
                    let at = self.commit_records("stage", vec![addr.clone()], 3);
                    let d = self.docs.get_mut(&addr).unwrap();
                    d.source = Some(from.clone());
                    d.history = BTreeMap::from([(at, src.runs.clone())]);
                    if src.published {
                        d.staged.insert(at, (from, extent));
                    } else {
                        if let Some(s) = src.staged.values().next_back() {
                            d.staged.insert(at, s.clone());
                        }
                        if let Some(Some(m)) = src.markers.values().next_back() {
                            d.markers.insert(at, Some(Marker { at, ..m.clone() }));
                        }
                    }
                    json!({"resp": "ack_addr", "addr": addr, "at": at})
                }
                "set_arrangement" => self.set_arrangement(frame),
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

        /// Answers `set_arrangement` as the store judges it.
        ///
        /// The order is wire.md §Arrangement's and
        /// `crates/skep-arrangement/src/ops/set_arrangement.rs`'s: the
        /// destination's own four refusals; the head's registration on
        /// every draft, then its chain and its extent where the draft has a
        /// chain — its recorded base's, else its fork source's; the fork
        /// gate; the base's `no_base_to_record`, then its registration, its
        /// chain and its extent; then each run's origin registered and a
        /// value at every address it names. The whole arrangement is
        /// replaced in one commit, the base re-recorded and the marker set
        /// or cleared where a base is named, the row carrying the request's
        /// merge whatever the base, and `head_moved` rides the ack where the
        /// trunk has moved past the head named.
        ///
        /// It judges no `bad_run` or `too_many_runs`: the landing spells
        /// each run's start from its own origin and refuses a list past
        /// `SHOT_RUN_CAP` before any frame. The door's answers — `malformed`,
        /// `withheld` — are no judgment of it either: a test that needs one
        /// plants it in `memo` under the frame's id.
        fn set_arrangement(&mut self, frame: &Value) -> Value {
            let reject = |code: &str, site: Value| permanent("set_arrangement", code, site);
            let doc = frame["doc"].as_str().unwrap().to_string();
            let Some(d) = self.docs.get(&doc).cloned() else { return reject("doc_not_registered", Value::Null) };
            if d.owner != ACCOUNT {
                return reject("not_owner", json!({"addr": doc}));
            }
            if d.published {
                return reject("published_target", Value::Null);
            }
            // The typed state: `as_of` REQUIRED, refused below the position
            // the arrangement last changed at, with nothing written.
            let as_of = frame["as_of"].as_u64().expect("`as_of` is REQUIRED on `set_arrangement`");
            let current = d.history.keys().next_back().copied().unwrap_or(0);
            if as_of < current {
                return reject("arrangement_moved", json!({"as_of": as_of, "current": current}));
            }
            let pair = |v: &Value| -> Option<(String, u64)> {
                v.as_object().map(|p| (p["at"].as_str().expect("a pair's `at`").to_string(), p["extent"].as_str().expect("a pair's `extent`, a decimal string").parse().unwrap()))
            };
            let (head, base) = (pair(&frame["head"]), pair(&frame["base"]));
            let standing = d.staged.values().next_back().cloned();
            let trunk = |member: &str| crate::address::document_of(member).unwrap_or_else(|| member.to_string());
            // The fork (P5): no recorded base, and a source that is a
            // published surface.
            let fork_source = match (&standing, &d.source) {
                (None, Some(src)) if self.docs.get(src).is_some_and(|s| s.published) => Some(src.clone()),
                _ => None,
            };
            let chain = standing.as_ref().map(|(b, _)| trunk(b)).or_else(|| fork_source.as_ref().map(|s| trunk(s)));
            // A pair as the store judges it (`judge_pair`,
            // `judge_registration`): its registration first, on every draft;
            // then, on a draft with a chain, its address against the chain
            // and its extent against its own count.
            let judge = |p: &(String, u64), chain: Option<&String>| -> Option<&'static str> {
                let Some(member) = self.docs.get(&p.0) else {
                    return Some("source_not_registered");
                };
                let chain = chain?;
                if trunk(&p.0) != *chain && p.0 != *chain {
                    return Some("base_not_in_chain");
                }
                let count: u64 = member.runs.iter().map(|r| r.width).sum();
                (p.1 > count).then_some("base_extent_too_large")
            };
            if let Some(h) = &head {
                if let Some(code) = judge(h, chain.as_ref()) {
                    return reject(code, Value::Null);
                }
                if let Some(src) = &fork_source {
                    if *src != h.0 {
                        return reject("fork_base_moved", json!({"addr": src}));
                    }
                }
            }
            if let Some(b) = &base {
                let Some((sb, _)) = &standing else { return reject("no_base_to_record", Value::Null) };
                if let Some(code) = judge(b, Some(&trunk(sb))) {
                    return reject(code, Value::Null);
                }
            }
            let mut positions = Vec::new();
            for r in frame["runs"].as_array().expect("`runs`, a list") {
                let origin = r["origin"].as_str().unwrap().to_string();
                if !self.docs.contains_key(&origin) {
                    return reject("source_not_registered", Value::Null);
                }
                let i_start: u64 = r["i_start"].as_str().unwrap().rsplit('.').next().unwrap().parse().unwrap();
                let width: u64 = r["width"].as_str().unwrap().parse().unwrap();
                for k in 0..width {
                    if !self.values.contains_key(&(origin.clone(), i_start + k)) {
                        return reject("dangling_source", Value::Null);
                    }
                    positions.push((a(&origin), i_start + k));
                }
            }
            // The tell (R5): the trunk's current head where it is not the
            // one named.
            let head_moved = head.as_ref().and_then(|(h, _)| self.trunk_head.get(&trunk(h)).filter(|cur| **cur != *h).cloned());
            let runs = coalesce(positions);
            // ONE COMMIT of two records — the removal and the placement —
            // and a third where a base is recorded (the skepd suite's
            // `a_landing_sets_the_arrangement_records_the_base_and_the_marker_in_one_commit`),
            // so the number below the ack's `at` lies inside it.
            let recorded = base.as_ref().filter(|_| standing.is_some()).cloned();
            let at = self.commit_records("set_arrangement", vec![doc.clone()], if recorded.is_some() { 3 } else { 2 });
            let d = self.docs.get_mut(&doc).unwrap();
            d.runs = runs.clone();
            d.history.insert(at, runs);
            // The request's merge beside its head: the marker where a base
            // is recorded, and the row's term whatever the base.
            let merge = match (&head, frame["merge"].as_object()) {
                (Some((h, e)), Some(m)) => Some((m["sides"].as_array().expect("`merge.sides`").iter().map(|s| s.as_str().unwrap().to_string()).collect::<Vec<_>>(), h.clone(), *e)),
                _ => None,
            };
            if let Some(b) = &recorded {
                d.staged.insert(at, b.clone());
                d.markers.insert(at, merge.clone().map(|(sides, head, head_copied)| Marker { sides, head, head_copied, at }));
            }
            // The row's two terms: the base recorded, and the request's merge.
            let row = self.rows.last_mut().expect("the commit's row");
            row.terms = Some((recorded.map(|(b, _)| b), merge.map(|(sides, head, _)| json!({"sides": sides, "head": head}))));
            let mut ack = json!({"resp": "ack", "at": at});
            if let Some(h) = head_moved {
                ack["head_moved"] = json!(h);
            }
            ack
        }
    }

    /// A permanent rejection of `op` carrying `code` and `site`.
    fn permanent(op: &str, code: &str, site: Value) -> Value {
        let mut rej = json!({"resp": "rejected", "code": code, "disposition": "permanent", "op": op});
        if !site.is_null() {
            rej["site"] = site;
        }
        rej
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

        /// The ops served as [`Scripted::ops`] lists them, each `/op-at`
        /// read by its inner op's name — the order of the reads whatever
        /// position each was made at.
        fn names(&self) -> Vec<String> {
            self.ops().into_iter().map(|o| o.strip_prefix("at:").map_or(o.clone(), str::to_string)).collect()
        }

        /// The frames of one op, in order — an `/op-at` read's inner frame.
        fn frames(&self, op: &str) -> Vec<Value> {
            let at_line = format!("at:{op}");
            self.served
                .lock()
                .unwrap()
                .iter()
                .filter_map(|(line, f)| {
                    if line == op {
                        Some(f.clone())
                    } else if *line == at_line {
                        Some(f["frame"].clone())
                    } else {
                        None
                    }
                })
                .collect()
        }

        /// The positions the `/op-at` reads of one op were asked as of, in
        /// order — a read answered `history_busy` counted with its position.
        fn positions(&self, op: &str) -> Vec<u64> {
            let at_line = format!("at:{op}");
            self.served
                .lock()
                .unwrap()
                .iter()
                .filter(|(line, _)| *line == at_line)
                .map(|(_, f)| f["at"].as_u64().expect("an `/op-at` body names its position"))
                .collect()
        }

        fn clear(&self) {
            self.served.lock().unwrap().clear();
        }

        /// The 1-based place of the first `op` among every request served
        /// since the last clear — the N a `World::interleave` names to land
        /// an edit before that frame is answered.
        fn served_index(&self, op: &str) -> usize {
            self.served
                .lock()
                .unwrap()
                .iter()
                .position(|(line, _)| line == op)
                .map(|i| i + 1)
                .unwrap_or_else(|| panic!("no `{op}` was served: {:?}", self.ops()))
        }

        fn world(&self) -> std::sync::MutexGuard<'_, World> {
            self.world.lock().unwrap()
        }
    }

    impl Dialer for Scripted {
        fn exchange(&self, _origin: &Origin, req: &Request) -> Result<Response, DialError> {
            let frame: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            // The body kept whole: an `/op-at` read's `at` beside its frame.
            let (line, body) = match req.path.as_str() {
                "/op" => (frame["op"].as_str().unwrap_or("?").to_string(), frame.clone()),
                "/op-at" => {
                    (format!("at:{}", frame["frame"]["op"].as_str().unwrap_or("?")), frame.clone())
                }
                p => (format!("{} {p}", req.method.as_str()), Value::Null),
            };
            let served = {
                let mut served = self.served.lock().unwrap();
                served.push((line, body));
                served.len()
            };
            let mut w = self.world.lock().unwrap();
            // Another hand's edit lands before this frame is answered.
            if w.interleave.as_ref().is_some_and(|(n, _, _)| *n == served) {
                let (_, doc, runs) = w.interleave.take().unwrap();
                w.change(&doc, runs);
            }
            // The journal reclaimed before this frame is answered.
            if w.reclaim.is_some_and(|(n, _)| n == served) {
                let (_, floor) = w.reclaim.take().unwrap();
                w.floor = Some(floor);
            }
            // A grant withdrawn before this frame is answered.
            if w.withhold.as_ref().is_some_and(|(n, _)| *n == served) {
                let (_, doc) = w.withhold.take().unwrap();
                w.withheld.insert(doc);
            }
            match req.path.as_str() {
                "/health" => Ok(reply(200, w.health())),
                "/op" => w.op(&frame, None),
                "/op-at" => {
                    if w.busy > 0 {
                        w.busy -= 1;
                        return Ok(reply(503, json!({"error": "history_busy"})));
                    }
                    let at = frame["at"].as_u64();
                    // A number past the committed head, or inside one commit.
                    if let Some(at) = at {
                        if at > w.position {
                            return Ok(reply(
                                400,
                                json!({"error": "beyond_head", "head": w.position}),
                            ));
                        }
                        if w.inside_commits.contains(&at) {
                            let nearest = (0..at).rev().find(|n| !w.inside_commits.contains(n));
                            return Ok(reply(
                                400,
                                json!({"error": "not_a_position", "nearest": nearest}),
                            ));
                        }
                    }
                    if let (Some(floor), Some(at)) = (w.floor, at) {
                        if at < floor {
                            return Ok(reply(410, json!({"error": "history_reclaimed", "floor": floor})));
                        }
                    }
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

    /// §1.3's reads IN ORDER: the document's metadata at the head, then —
    /// each at the ONE POSITION that read answered (skep #762) — the head's
    /// extent, the base's extent and image, the head's image, the
    /// daughter's extent and image, then the prior records by the links of
    /// the kind to each side at the head — and nothing written. The result
    /// is the race shape's M with its counts, key, cap and unlanded record,
    /// its `as_of` that one position.
    #[test]
    fn compose_reads_in_the_records_order_and_writes_nothing() {
        let (dialer, board, _) = open(World::race());
        let merged = compose(&board, Some(&token()), &race_inputs()).expect("composed");
        assert_eq!(
            dialer.ops(),
            [
                "doc_metadata",
                "at:retrieve_doc_v_span_set",
                "at:retrieve_doc_v_span_set",
                "at:image",
                "at:image",
                "at:retrieve_doc_v_span_set",
                "at:image",
                "find_links_ftt",
                "find_links_ftt"
            ],
            "the first read at the head, every read of the shape after it at its position, the journal's at the head"
        );
        let p = dialer.world().position;
        for op in ["retrieve_doc_v_span_set", "image"] {
            assert!(
                dialer.positions(op).iter().all(|at| *at == p),
                "`{op}` at the one position {p}: {:?}",
                dialer.positions(op)
            );
        }
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

    /// The fence on sides whose base the board does not serve: a member of
    /// another document and a draft of another account each refuse
    /// `BaseUnknown` before any `image`; two drafts refuse `TwoDrafts`. A
    /// DRAFT is read before it is judged — its `doc_metadata`, for the base
    /// the board records for it (skep #743) — and composes with no base
    /// named where one is recorded, refusing, still before any `image`:
    /// `BaseUnknown` where the board records none (a draft never staged) or
    /// where its recorded base lies in another document; `BareSource`, with
    /// its own reason, where its recorded base is the bare document — a
    /// draft staged before the document's first version. A FORK is read
    /// before it is judged — its `doc_metadata`, for the source it was born
    /// sharing — and refuses, still before any `image`: `BaseUnknown` where
    /// no `version` minted it (no source) or where its source lies in
    /// another document; `BareSource`, with its own reason, where its source
    /// is the bare document — a fork taken before the document's first
    /// version; `Unreadable` where the merger may not read the fork at all.
    /// A base the caller names beside a fork side refuses `ForkBaseNamed`
    /// before any read.
    #[test]
    fn a_foreign_side_or_a_side_without_a_served_base_refuses_before_any_image() {
        let mut w = World::race();
        // Another published document `Z` with a member, and four forks in
        // another account: one no `version` minted, one of `Z`'s member, one
        // of the bare `D`, and one the merger may not read.
        let (unminted, of_z, of_bare, hidden) = ("1.0.2.0.3", "1.0.2.0.4", "1.0.2.0.5", "1.0.2.0.6");
        w.text(Z, 1, "hello");
        w.doc(Z, true, ACCOUNT, vec![run(Z, 1, 5)]);
        w.member(&format!("{Z}.1"), vec![run(Z, 1, 5)], None);
        w.doc(unminted, false, "1.0.2", Vec::new());
        w.fork(of_z, "1.0.2", &format!("{Z}.1"), vec![run(Z, 1, 5)]);
        w.fork(of_bare, "1.0.2", D, vec![run(D, 1, 11)]);
        w.fork(hidden, "1.0.2", &format!("{D}.1"), vec![run(D, 1, 7)]);
        w.withheld.insert(hidden.to_string());
        // Four drafts of the merger's account: `S` staged from the base
        // `D.1` with "!!!" typed at its end; one never staged, so the board
        // records no base; one staged from `Z`'s member; one staged from the
        // bare `D`.
        let (unstaged, of_z_draft, of_bare_draft) = ("1.0.1.0.5", "1.0.1.0.6", "1.0.1.0.8");
        w.text(S, 1, "!!!");
        w.doc(S, false, ACCOUNT, vec![run(D, 1, 11), run(S, 1, 3)]);
        w.staged(S, &format!("{D}.1"), 11);
        w.doc(unstaged, false, ACCOUNT, vec![run(D, 1, 11)]);
        w.doc(of_z_draft, false, ACCOUNT, vec![run(Z, 1, 5)]);
        w.staged(of_z_draft, &format!("{Z}.1"), 5);
        w.doc(of_bare_draft, false, ACCOUNT, vec![run(D, 1, 11)]);
        w.staged(of_bare_draft, D, 11);
        let (dialer, board, _) = open(w);
        let with =
            |sides: Vec<Side>, base: Option<Address>| Inputs { sides, base, ..race_inputs() };
        let refuses = |side: Side, base: Option<Address>, want: Refusal| {
            dialer.clear();
            assert_eq!(compose(&board, Some(&token()), &with(vec![side], base)), Err(want));
            assert!(
                !dialer.names().iter().any(|o| o == "image"),
                "no image before the refusal: {:?}",
                dialer.ops()
            );
        };
        let fork = |text: &str| Side::Fork(a(text));
        refuses(fork(unminted), None, Refusal::BaseUnknown(fork(unminted)));
        assert_eq!(
            dialer.ops(),
            ["doc_metadata", "at:doc_metadata"],
            "the trunk's metadata, then the fork's for its source at the one position, and nothing after"
        );
        assert_eq!(dialer.frames("doc_metadata")[1]["doc"], unminted);
        refuses(fork(of_z), None, Refusal::BaseUnknown(fork(of_z)));
        refuses(fork(of_bare), None, Refusal::BareSource { side: fork(of_bare), source: a(D) });
        refuses(fork(hidden), None, Refusal::Unreadable(a(hidden)));
        refuses(
            fork(F),
            Some(a(&format!("{D}.1"))),
            Refusal::ForkBaseNamed { fork: a(F), base: a(&format!("{D}.1")) },
        );
        assert!(
            dialer.ops().is_empty(),
            "no read at all for a base named beside a fork: {:?}",
            dialer.ops()
        );
        let foreign = Side::Member(a(&format!("{Z}.1")));
        refuses(foreign.clone(), None, Refusal::BaseUnknown(foreign));
        let other_account = Side::Draft { at: a("1.0.2.0.9"), position: None };
        refuses(
            other_account.clone(),
            Some(a(&format!("{D}.1"))),
            Refusal::BaseUnknown(other_account),
        );
        // The drafts: the staged one composes with no base named, its base
        // read off the board right after the trunk's metadata; the others
        // refuse after that read and before any image.
        let draft = |text: &str| Side::Draft { at: a(text), position: None };
        dialer.clear();
        let merged =
            compose(&board, Some(&token()), &with(vec![draft(S)], None)).expect("composed");
        assert_eq!(merged.key.base, a(&format!("{D}.1")), "the base the board records for the draft");
        assert_eq!(m_runs(&merged), vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(S, 1, 3)]);
        assert_eq!(
            dialer.frames("doc_metadata")[1]["doc"],
            S,
            "the draft's metadata, for its base: {:?}",
            dialer.ops()
        );
        refuses(draft(unstaged), None, Refusal::BaseUnknown(draft(unstaged)));
        assert_eq!(
            dialer.ops(),
            ["doc_metadata", "at:doc_metadata"],
            "the trunk's metadata, then the draft's for its base at the one position, and nothing after"
        );
        refuses(draft(of_z_draft), None, Refusal::BaseUnknown(draft(of_z_draft)));
        refuses(
            draft(of_bare_draft),
            None,
            Refusal::BareSource { side: draft(of_bare_draft), source: a(D) },
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

    /// CASE (j): a cross-owner fork of a PUBLISHED version merges from the
    /// source the board serves for it. The fork `F`, another account's
    /// private document minted by `version` off the base `D.1` ("the cat
    /// sat"), has removed " sat"; the head added "big ". The reads, in
    /// order: the trunk's metadata, THE FORK'S METADATA for its `source`,
    /// the head's extent, the base's extent and image — the base `D.1`,
    /// derived from the source and never named — the head's image, the
    /// fork's extent and image, the prior records. M is the race shape's
    /// "the big cat", the fork's role `fork`, the merge lands as the trunk's
    /// next member, and `verify` recomputes its record against the source
    /// the board serves.
    #[test]
    fn case_j_a_fork_of_a_published_version_merges_from_the_source_the_board_serves() {
        let mut w = World::race();
        w.fork(F, "1.0.2", &format!("{D}.1"), vec![run(D, 1, 7)]);
        let (dialer, board, signer) = open(w);
        let inputs = Inputs { sides: vec![Side::Fork(a(F))], ..race_inputs() };
        let merged = compose(&board, Some(&token()), &inputs).expect("composed");
        assert_eq!(
            dialer.ops(),
            [
                "doc_metadata",
                "at:doc_metadata",
                "at:retrieve_doc_v_span_set",
                "at:retrieve_doc_v_span_set",
                "at:image",
                "at:image",
                "at:retrieve_doc_v_span_set",
                "at:image",
                "find_links_ftt",
                "find_links_ftt"
            ]
        );
        let metadata: Vec<String> = dialer
            .frames("doc_metadata")
            .iter()
            .map(|f| f["doc"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(metadata, [D.to_string(), F.to_string()], "the trunk's, then the fork's");
        let imaged: Vec<String> =
            dialer.frames("image").iter().map(|f| f["d"].as_str().unwrap().to_string()).collect();
        assert_eq!(
            imaged,
            [format!("{D}.1"), format!("{D}.2"), F.to_string()],
            "the base the source names, the head, the fork"
        );
        assert_eq!(m_runs(&merged), vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 3)], "the big cat");
        assert_eq!(merged.composed.counts, RunCounts { a: 3, b: 1, m: 3 });
        assert!(merged.composed.gaps.is_empty(), "{:?}", merged.composed.gaps);
        assert_eq!(merged.families, vec![Family::Own, Family::Own, Family::Own]);
        assert_eq!(merged.key.base, a(&format!("{D}.1")), "the base is the fork's source");
        assert_eq!(merged.key.sides, vec![a(&format!("{D}.2")), a(F)]);
        assert_eq!(
            merged.record.sides.iter().map(SideAt::role).collect::<Vec<_>>(),
            [Role::Head, Role::Fork]
        );
        assert_eq!(merged.record.base, a(&format!("{D}.1")));
        assert_eq!(dialer.world().rows.len(), 4, "nothing written");
        // LANDED as the shot: the fork's runs are all the document's own, so
        // nothing is windowed, and the member is the trunk's next.
        let session = sign_in(&board, &signer);
        let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
        let Landed::Member { address, record: link, .. } = &landed else { panic!("{landed:?}") };
        assert_eq!(address.to_string(), format!("{D}.3"));
        let member = dialer.world().docs.get(&format!("{D}.3")).unwrap().clone();
        assert_eq!(member.runs, vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 3)]);
        // The record names the fork's base — the served source — and
        // `verify` re-reads it off the board and recomputes M.
        let record = current(&board, Some(&token()), &a(K), &merged.key)
            .expect("the lookup")
            .expect("a current record");
        assert_eq!(record.base, a(&format!("{D}.1")));
        assert_eq!(record.link.as_ref(), Some(link));
        assert_eq!(verify(&board, Some(&token()), &record).expect("verified"), Verdict::Equal);
    }

    /// Case (j) with the fork's OWN text: the fork typed "fat " where the
    /// head typed "big ", both at `D·4|D·5` — an `order` gap, unsettled, as
    /// between two members (§9 (b)) — and the fork's fresh run is a WINDOW
    /// onto the fork in M: the owner's shot keeps it by reference, and
    /// `show_origin` names the forker for those bytes.
    #[test]
    fn a_forks_own_text_is_a_window_in_the_merge() {
        let mut w = World::race();
        let f2 = "1.0.2.0.8";
        w.text(f2, 1, "fat ");
        w.fork(f2, "1.0.2", &format!("{D}.1"), vec![run(D, 1, 4), run(f2, 1, 4), run(D, 5, 7)]);
        let (_dialer, board, _) = open(w);
        let inputs = Inputs { sides: vec![Side::Fork(a(f2))], ..race_inputs() };
        let merged = compose(&board, Some(&token()), &inputs).expect("composed");
        assert_eq!(
            m_runs(&merged),
            vec![run(D, 1, 4), run(D, 12, 4), run(f2, 1, 4), run(D, 5, 7)],
            "the big fat cat sat"
        );
        assert_eq!(
            merged.families,
            vec![Family::Own, Family::Own, Family::Window, Family::Own],
            "the fork's fresh text is a window onto the fork"
        );
        assert_eq!(
            merged.composed.gaps.iter().map(|g| (g.kind, g.settled)).collect::<Vec<_>>(),
            vec![(GapKind::Order, false)]
        );
        assert_eq!(merged.key.base, a(&format!("{D}.1")));
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

    /// A draft side at a position is read through `/op-at` — its recorded
    /// base first, then its extent and its image, each as of the position —
    /// and the record's side names that position: one `history_busy` is
    /// retried and the read answers; past the bounded retries the
    /// composition refuses `HistoryBusy`.
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
            dialer.positions("doc_metadata"),
            [at, at, at],
            "the named position is every read's: the trunk's metadata, one busy, one answered, then the draft's base: {:?}",
            dialer.ops()
        );
        assert_eq!(dialer.positions("retrieve_doc_v_span_set"), [at, at, at], "the head's, the base's, the draft's extent");
        assert_eq!(dialer.positions("image"), [at, at, at], "the base, the head, the draft");
        assert!(
            dialer.ops().iter().all(|o| o.starts_with("at:") || o == "find_links_ftt"),
            "nothing of the shape read at the head: {:?}",
            dialer.ops()
        );
        assert_eq!(merged.as_of, at, "the one position the reads were taken at");
        assert_eq!(
            merged.record.sides[1],
            SideAt::Draft { at: a(S), position: Some(at) },
            "the record's side names the position named"
        );
        dialer.world().busy = 10;
        assert_eq!(compose(&board, Some(&token()), &inputs), Err(Refusal::HistoryBusy));
    }

    /// THE RECORD NAMES THE POSITION A DRAFT SIDE WAS READ AT (skep #453): a
    /// draft side named with no position is read at the position the
    /// composition's first read answered — the head when it began — which
    /// every read after the first is made at, and the record's side carries
    /// it, the inputs as given. `verify` then reads the draft AND its
    /// recorded base as of that position — its `doc_metadata`, its extent,
    /// its image and the join's `compare` each through `/op-at` at it — so
    /// once the shot that rendered the draft has moved its base to the
    /// member minted, and once the draft is edited past the shot, the record
    /// still verifies Equal; the premise, the board's `doc_metadata` as of
    /// the position answering the base that stood. A record naming no
    /// position reads the draft as it stands, and is refused by name against
    /// the moved base.
    #[test]
    fn a_draft_sides_record_names_the_position_read_and_verifies_as_of_it() {
        let (dialer, board, signer) = open(World::window_and_draft());
        let session = sign_in(&board, &signer);
        let read_at = dialer.world().position;
        let inputs =
            Inputs { sides: vec![Side::Draft { at: a(S), position: None }], ..race_inputs() };
        let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
        assert_eq!(
            merged.record.sides[1],
            SideAt::Draft { at: a(S), position: Some(read_at) },
            "the position the first read answered"
        );
        assert_eq!(merged.inputs, inputs, "the inputs as given");
        let ops = dialer.ops();
        assert_eq!(ops[0], "doc_metadata", "the first read, at the head, fixes the position: {ops:?}");
        assert!(
            ops[1..].iter().take_while(|o| *o != "find_links_ftt").all(|o| o.starts_with("at:")),
            "every read of the shape after the first at that position: {ops:?}"
        );
        // The shot renders the draft, and the board moves its recorded base
        // to the member minted; the record read back names the position.
        let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
        let Landed::Member { address, .. } = &landed else { panic!("{landed:?}") };
        assert_eq!(address.to_string(), format!("{D}.3"));
        let record = current(&board, Some(&token()), &a(K), &merged.key)
            .expect("the lookup")
            .expect("the record");
        assert_eq!(record.sides[1], SideAt::Draft { at: a(S), position: Some(read_at) });
        let base_as_of = |at: Option<u64>| -> Option<String> {
            let frame = frames::doc_metadata(S);
            let v = match at {
                None => match board.op(Some(&token()), &frame).expect("the read") {
                    Answer::Document(v) => v,
                    Answer::Closed => panic!("closed"),
                },
                Some(at) => match board.op_at(Some(&token()), at, &frame).expect("the read") {
                    AtAnswer::Document(v) => v,
                    other => panic!("{other:?}"),
                },
            };
            v["base"].as_str().map(str::to_string)
        };
        assert_eq!(base_as_of(None), Some(format!("{D}.3")), "the base moved with the shot");
        assert_eq!(
            base_as_of(Some(read_at)),
            Some(format!("{D}.1")),
            "the premise: as of the record's position, the base that stood"
        );
        dialer.clear();
        assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal));
        for op in ["doc_metadata", "retrieve_doc_v_span_set", "image", "compare"] {
            let positions = dialer.positions(op);
            assert!(
                !positions.is_empty() && positions.iter().all(|p| *p == read_at),
                "`{op}` read as of the record's position: {positions:?}; {:?}",
                dialer.ops()
            );
        }
        assert_eq!(
            dialer.frames("doc_metadata").iter().map(|f| f["doc"].clone()).collect::<Vec<_>>(),
            [json!(D), json!(S), json!(format!("{D}.3"))],
            "the trunk's and the draft's as of the position, the landed member's as it stands"
        );
        // The draft edited past the shot — its "!!!" deleted — and the record
        // still testifies to the state it composed from.
        let typed = dialer.world().position;
        match board.op(Some(session.token()), &frames::delete(S, 12, 3, typed, None)) {
            Ok(Answer::Document(v)) => assert_eq!(v["resp"], "ack", "{v}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(dialer.world().docs.get(S).unwrap().runs, vec![run(D, 1, 11)]);
        assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal));
        let mut headless = record.clone();
        headless.sides[1] = SideAt::Draft { at: a(S), position: None };
        assert_eq!(
            verify(&board, Some(&token()), &headless),
            Err(Refusal::DraftBaseDisagrees {
                side: Side::Draft { at: a(S), position: None },
                named: a(&format!("{D}.1")),
                served: a(&format!("{D}.2")),
            }),
            "a record naming no position reads the draft as it stands"
        );
    }

    /// A DRAFT SIDE's BASE IS READ OFF THE BOARD (skep #743): the draft's
    /// `doc_metadata` is read for the base the board records for it — right
    /// after the trunk's, as a fork's is for its source — and the merge's
    /// base is derived from it, so the caller names none; the reads then run
    /// in the record's order and nothing is written. A base the caller names
    /// is checked, never trusted: one equal to the derived base is taken; a
    /// different one refuses `DraftBaseDisagrees`, naming both, before any
    /// `image`.
    #[test]
    fn a_draft_sides_base_is_read_off_the_board_and_a_named_one_must_agree() {
        let (dialer, board, _) = open(World::window_and_draft());
        let rows = dialer.world().rows.len();
        let side = Side::Draft { at: a(S), position: None };
        let inputs = Inputs { sides: vec![side.clone()], ..race_inputs() };
        let merged = compose(&board, Some(&token()), &inputs).expect("composed");
        assert_eq!(
            dialer.ops(),
            [
                "doc_metadata",
                "at:doc_metadata",
                "at:retrieve_doc_v_span_set",
                "at:retrieve_doc_v_span_set",
                "at:image",
                "at:image",
                "at:retrieve_doc_v_span_set",
                "at:image",
                "find_links_ftt",
                "find_links_ftt"
            ]
        );
        let metadata: Vec<String> = dialer
            .frames("doc_metadata")
            .iter()
            .map(|f| f["doc"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(metadata, [D.to_string(), S.to_string()], "the trunk's, then the draft's");
        let imaged: Vec<String> =
            dialer.frames("image").iter().map(|f| f["d"].as_str().unwrap().to_string()).collect();
        assert_eq!(
            imaged,
            [format!("{D}.1"), format!("{D}.2"), S.to_string()],
            "the base the board records for the draft, the head, the draft"
        );
        assert_eq!(m_runs(&merged), vec![run(D, 1, 4), run(Z, 1, 5), run(D, 5, 7), run(S, 1, 3)]);
        assert_eq!(
            merged.families,
            vec![Family::Own, Family::Window, Family::Own, Family::DraftNative]
        );
        assert_eq!(
            (merged.key.base.clone(), merged.record.base.clone()),
            (a(&format!("{D}.1")), a(&format!("{D}.1"))),
            "the base the board records for the draft, never named"
        );
        assert_eq!(
            merged.record.sides.iter().map(SideAt::role).collect::<Vec<_>>(),
            [Role::Head, Role::Draft]
        );
        assert_eq!(dialer.world().rows.len(), rows, "nothing written");
        // A named base equal to the derived one is taken; a different one is
        // refused by name, with the base the records derive, before any image.
        let named = |b: &str| Inputs { base: Some(a(b)), ..inputs.clone() };
        let agreed = compose(&board, Some(&token()), &named(&format!("{D}.1"))).expect("composed");
        assert_eq!((agreed.key.base.clone(), m_runs(&agreed)), (merged.key.base.clone(), m_runs(&merged)));
        dialer.clear();
        assert_eq!(
            compose(&board, Some(&token()), &named(&format!("{D}.2"))),
            Err(Refusal::DraftBaseDisagrees {
                side: side.clone(),
                named: a(&format!("{D}.2")),
                served: a(&format!("{D}.1")),
            })
        );
        assert!(
            !dialer.names().iter().any(|o| o == "image"),
            "no image before the refusal: {:?}",
            dialer.ops()
        );
        assert_eq!(dialer.world().rows.len(), rows, "nothing written");
    }

    /// THE MERGE's BASE IS DERIVED FROM THE DRAFT's RECORDED BASE, never the
    /// recorded base itself: a draft staged from the daughter `D.1.1`, "!"
    /// typed at its end, merged with the head `D.2` composes over `D.1` —
    /// the nearest common ancestor of the head and the daughter — with no
    /// base named, so the daughter's removal of " sat" is the draft's and
    /// never an addition of the head's: "the big cat!". Naming the recorded
    /// base `D.1.1` is refused `DraftBaseDisagrees` with `D.1` as the base
    /// the board's record derives — the comparison is with the derived base
    /// — while naming `D.1` is taken.
    #[test]
    fn a_draft_staged_from_a_daughter_composes_over_the_daughters_base() {
        let mut w = World::race();
        let t = "1.0.1.0.5";
        w.text(t, 1, "!");
        w.doc(t, false, ACCOUNT, vec![run(D, 1, 7), run(t, 1, 1)]);
        w.staged(t, &format!("{D}.1.1"), 7);
        let (dialer, board, _) = open(w);
        let side = Side::Draft { at: a(t), position: None };
        let inputs = Inputs { sides: vec![side.clone()], ..race_inputs() };
        let merged = compose(&board, Some(&token()), &inputs).expect("composed");
        assert_eq!(
            merged.key.base,
            a(&format!("{D}.1")),
            "the nearest common ancestor of the head and the recorded base"
        );
        assert_eq!(
            m_runs(&merged),
            vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 3), run(t, 1, 1)],
            "the big cat!"
        );
        assert_eq!(
            merged.families,
            vec![Family::Own, Family::Own, Family::Own, Family::DraftNative]
        );
        assert!(merged.composed.gaps.is_empty(), "{:?}", merged.composed.gaps);
        let imaged: Vec<String> =
            dialer.frames("image").iter().map(|f| f["d"].as_str().unwrap().to_string()).collect();
        assert_eq!(
            imaged,
            [format!("{D}.1"), format!("{D}.2"), t.to_string()],
            "the derived base imaged, never the daughter"
        );
        let named = |b: &str| Inputs { base: Some(a(b)), ..inputs.clone() };
        assert_eq!(
            compose(&board, Some(&token()), &named(&format!("{D}.1.1"))),
            Err(Refusal::DraftBaseDisagrees {
                side: side.clone(),
                named: a(&format!("{D}.1.1")),
                served: a(&format!("{D}.1")),
            }),
            "the comparison is with the derived base, not the recorded one"
        );
        assert_eq!(
            compose(&board, Some(&token()), &named(&format!("{D}.1"))).expect("composed").key.base,
            a(&format!("{D}.1"))
        );
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

    /// The draft landing's world: shape (2) — the head `D.2` "the big cat
    /// sat" (the race shape's head, "big " fresh at `D·12`) and the staging
    /// draft `S`, staged from the base `D.1` with "!!!" typed at its end.
    fn draft_landing_world() -> World {
        let mut w = World::window_and_draft();
        w.text(D, 12, "big ");
        let head = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)];
        for doc in [D.to_string(), format!("{D}.2")] {
            let d = w.docs.get_mut(&doc).unwrap();
            d.runs = head.clone();
            // The head as it stood from the start: every read is made at a
            // position, through the history.
            d.history = BTreeMap::from([(0, head.clone())]);
        }
        w
    }

    /// The draft side's inputs: `S` read at the composition's position.
    fn draft_inputs() -> Inputs {
        Inputs {
            sides: vec![Side::Draft { at: a(S), position: None }],
            base: Some(a(&format!("{D}.1"))),
            ..race_inputs()
        }
    }

    /// M of the draft landing's world: "the big cat sat!!!".
    fn draft_m() -> Vec<Run> {
        vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(S, 1, 3)]
    }

    /// A draft landing into `into`, or into a fresh draft where `None`.
    fn draft_landing<'s>(session: &'s Session<'_>, signer: &'s HybridSigner, into: Option<Address>) -> Landing<'s> {
        Landing::Draft { merger: merger(session, signer), into, journal: None }
    }

    /// M's runs as a `set_arrangement` frame spells them.
    fn frame_runs(m: &[Run]) -> Value {
        Value::Array(m.iter().map(|r| json!({"origin": r.origin.to_string(), "i_start": i_addr(&r.origin, r.i_start), "width": r.width.to_string()})).collect())
    }

    /// THE DRAFT LANDING IS ONE WRITE (the landing lane's rulings R1, R4,
    /// R5; skep #764): one `set_arrangement` of M into the draft — its
    /// runs, `as_of` the ONE position the merge was composed at, `head` the
    /// head and its extent as read, `base` the same pair since the board
    /// records a base for the draft, `merge` the sides but the draft itself
    /// (none: the draft was the side), the id `<stem>.draft` — no `delete`,
    /// no `reinstate`, no `publish`, no claim read; the draft holds M, its
    /// base re-recorded on the head and the marker beside it at the write's
    /// position; the record with `landed` the draft and THE WRITE's
    /// position. A second landing over the same `merged` in the session is
    /// answered by the board's memo for the id: the same landing, nothing
    /// written twice.
    #[test]
    fn the_draft_landing_is_one_set_arrangement_typed_at_the_composition_and_writes_the_record() {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
        assert_eq!(m_runs(&merged), draft_m());
        let p = merged.as_of;
        assert_eq!(p, dialer.world().position, "the one position: the head when the composition began");
        dialer.clear();
        let landed = land(&board, &merged, draft_landing(&session, &signer, Some(a(S)))).expect("landed");
        let Landed::Draft { into, position, record, head_moved } = &landed else { panic!("{landed:?}") };
        assert_eq!((into.to_string(), head_moved.clone()), (S.to_string(), None));
        let frames = dialer.frames("set_arrangement");
        assert_eq!(frames.len(), 1, "one write: {:?}", dialer.ops());
        let frame = &frames[0];
        assert_eq!(frame["doc"], S);
        assert_eq!(frame["as_of"].as_u64(), Some(p), "typed against the composition's position: {frame}");
        assert_eq!(frame["runs"], frame_runs(&draft_m()));
        assert_eq!(frame["head"], json!({"at": format!("{D}.2"), "extent": "15"}), "the head and its extent as read");
        assert_eq!(frame["base"], json!({"at": format!("{D}.2"), "extent": "15"}), "the base to record: the head's pair");
        assert_eq!(frame["merge"], json!({"sides": []}), "every side but the draft itself");
        assert_eq!(frame["id"].as_str(), Some(format!("{}.draft", merged.key.text()).as_str()));
        let ops = dialer.ops();
        assert!(
            !ops.iter().any(|o| ["publish", "in_claims", "delete", "reinstate", "stage"].contains(&o.as_str())),
            "{ops:?}"
        );
        assert_eq!(ops[0], "at:doc_metadata", "the draft's base, read at the composition's position: {ops:?}");
        assert_eq!(dialer.positions("doc_metadata"), [p]);
        // The draft holds M; the base re-recorded on the head at the extent
        // read; the marker beside it, at the write's position.
        let w = dialer.world();
        assert_eq!(w.docs.get(S).unwrap().runs, draft_m());
        assert_eq!(
            w.standing(S),
            (Some((format!("{D}.2"), 15)), Some(Marker { sides: vec![], head: format!("{D}.2"), head_copied: 15, at: *position }))
        );
        assert_eq!(*position, w.rows.iter().find(|r| r.op == "set_arrangement").unwrap().at, "the write's `at`");
        drop(w);
        // The record: the draft and the write's position.
        let atom: Value =
            serde_json::from_str(dialer.frames("insert")[0]["values"][0]["atom"].as_str().unwrap())
                .unwrap();
        assert_eq!(atom["landed"], json!({"draft": S, "position": position}));
        assert_eq!(dialer.frames("make_link")[0]["to"]["addrs"], json!([S]));
        // Again over the same `merged`: the memo answers the id, nothing
        // written twice, the same landing.
        dialer.clear();
        let rows = dialer.world().rows.len();
        assert_eq!(
            land(&board, &merged, draft_landing(&session, &signer, Some(a(S)))).expect("landed again"),
            Landed::Draft { into: a(S), position: *position, record: record.clone(), head_moved: None }
        );
        assert_eq!(dialer.world().rows.len(), rows, "nothing written twice");
        assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty());
        // `resume` finds the draft holding M and answers the marker's
        // position, the record standing; a draft holding another list is no
        // landing to resume.
        dialer.clear();
        assert_eq!(
            resume(&board, &merged, draft_landing(&session, &signer, Some(a(S)))).expect("resumed"),
            Some(Landed::Draft { into: a(S), position: *position, record: record.clone(), head_moved: None })
        );
        assert!(dialer.frames("set_arrangement").is_empty(), "a resume sends nothing: {:?}", dialer.ops());
        dialer.world().change(S, vec![run(D, 1, 11)]);
        assert_eq!(resume(&board, &merged, draft_landing(&session, &signer, Some(a(S)))).expect("resumed"), None);
    }

    /// AN EDIT TO THE DRAFT BETWEEN COMPOSE AND LAND IS REFUSED WHOLE (THE
    /// PROVENANCE, skep #762's landing half): the merge composed at P;
    /// another hand deletes the draft's "!!!" after it; the one write, typed
    /// against P, is refused `arrangement_moved` — the board's verdict, its
    /// detail naming the draft that changed after the merge was composed
    /// and that nothing was merged — the draft left as the other hand left
    /// it, nothing written, no record. The hole this closes: a landing typed
    /// against a fresh read of the draft lands M over the edit and deletes
    /// it as absent from M.
    #[test]
    fn an_edit_to_the_draft_between_compose_and_land_is_refused_whole() {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
        let p = merged.as_of;
        // Another hand's edit: the draft's "!!!" deleted.
        let typed = dialer.world().position;
        match board.op(Some(session.token()), &frames::delete(S, 12, 3, typed, None)) {
            Ok(Answer::Document(v)) => assert_eq!(v["resp"], "ack", "{v}"),
            other => panic!("{other:?}"),
        }
        let edited = dialer.world().docs.get(S).unwrap().runs.clone();
        assert_eq!(edited, vec![run(D, 1, 11)]);
        let rows = dialer.world().rows.len();
        dialer.clear();
        let err = land(&board, &merged, draft_landing(&session, &signer, Some(a(S)))).expect_err("the draft changed");
        let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
        assert_eq!(refused.code, "arrangement_moved");
        let detail = refused.detail.as_deref().expect("the person's words");
        assert!(detail.contains(S) && detail.contains("changed after the merge was composed") && detail.contains("nothing was merged"), "{detail}");
        assert!(detail.contains(&format!("composed at position {p}")), "{detail}");
        assert_eq!(dialer.frames("set_arrangement")[0]["as_of"].as_u64(), Some(p), "typed against the composition's position, never a fresh read");
        let w = dialer.world();
        assert_eq!(w.docs.get(S).unwrap().runs, edited, "the other hand's edit stands: nothing wiped");
        assert_eq!(w.rows.len(), rows, "nothing written");
        assert_eq!(w.standing(S), (Some((format!("{D}.1"), 11)), None), "the base and no marker, as they stood");
        drop(w);
        assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(), "no record");
    }

    /// EVERY READ OF THE COMPOSITION IS MADE AT ONE POSITION (skep #762): an
    /// edit to the draft landing between the composition's first read and
    /// its second — the draft's "!!!" deleted — changes nothing the
    /// composition read: M holds the "!!!", every `/op-at` read was asked at
    /// the first read's position, `as_of` is that position and the record's
    /// draft side names it. Read at the head as it went, the composition
    /// would pair the draft's base and extent from one moment with an image
    /// from the next.
    #[test]
    fn every_read_of_the_composition_is_made_at_the_first_reads_position() {
        let mut w = draft_landing_world();
        w.interleave = Some((2, S.to_string(), vec![run(D, 1, 11)]));
        let (dialer, board, _) = open(w);
        let p = dialer.world().position;
        let merged = compose(&board, Some(&token()), &draft_inputs()).expect("composed");
        assert!(dialer.world().interleave.is_none(), "the edit landed mid-walk");
        assert_eq!(dialer.world().docs.get(S).unwrap().runs, vec![run(D, 1, 11)], "the draft as the other hand left it");
        assert_eq!(m_runs(&merged), draft_m(), "M as of the one position: the \"!!!\" the edit removed is in it");
        assert_eq!(merged.as_of, p, "the first read's position, not the edit's");
        assert_eq!(merged.record.sides[1], SideAt::Draft { at: a(S), position: Some(p) });
        for op in ["doc_metadata", "retrieve_doc_v_span_set", "image"] {
            let positions = dialer.positions(op);
            assert!(!positions.is_empty() && positions.iter().all(|at| *at == p), "`{op}`: {positions:?}");
        }
        let ops = dialer.ops();
        assert_eq!(ops[0], "doc_metadata", "{ops:?}");
        assert!(ops[1..].iter().take_while(|o| *o != "find_links_ftt").all(|o| o.starts_with("at:")), "every read after the first at the one position: {ops:?}");
    }

    /// A POSITION THE BOARD HAS RECLAIMED is refused by name and never read
    /// at the head instead (skep #762): a draft side naming a position below
    /// the journal's floor refuses `HistoryReclaimed` at the first read, the
    /// position and the floor named, with no read at the head.
    #[test]
    fn a_reclaimed_position_is_refused_and_never_read_at_the_head() {
        let mut w = draft_landing_world();
        let p = w.position - 2;
        w.floor = Some(w.position);
        let (dialer, board, _) = open(w);
        let inputs = Inputs { sides: vec![Side::Draft { at: a(S), position: Some(p) }], ..draft_inputs() };
        let floor = dialer.world().floor;
        assert_eq!(compose(&board, Some(&token()), &inputs), Err(Refusal::HistoryReclaimed { at: p, floor }));
        assert_eq!(dialer.ops(), ["at:doc_metadata"], "the one read, at the position; nothing at the head");
        let said = Refusal::HistoryReclaimed { at: p, floor }.to_string();
        assert!(said.contains(&format!("position {p}")) && said.contains("nothing was read at another"), "{said}");
    }

    /// A named position the board never answered is refused as the caller's.
    ///
    /// A draft side named past the board's head refuses `BeyondHead` with
    /// the head, and one inside a commit `NotAPosition` with the nearest
    /// position, each at the first read with no record named, nothing read
    /// at the head, and the face advising a position the board has answered
    /// (skep #761).
    #[test]
    fn a_named_position_past_the_head_or_inside_a_commit_is_refused_as_the_callers() {
        let (dialer, board, _) = open(draft_landing_world());
        let head = dialer.world().position;
        let named = |p: u64| Inputs {
            sides: vec![Side::Draft { at: a(S), position: Some(p) }],
            ..draft_inputs()
        };
        let refused = compose(&board, Some(&token()), &named(head + 5));
        assert_eq!(
            refused,
            Err(Refusal::BeyondHead { at: head + 5, head: Some(head), recorded: None })
        );
        assert_eq!(
            dialer.ops(),
            ["at:doc_metadata"],
            "the one read, at the position; nothing at the head"
        );
        let said = refused.unwrap_err().to_string();
        assert!(
            said.contains(&format!("position {}", head + 5))
                && said.contains(&format!("head at position {head}")),
            "{said}"
        );
        assert!(
            said.contains("beyond_head") && said.contains("or at the head"),
            "the caller's advice: {said}"
        );
        dialer.world().inside_commits.insert(head - 1);
        dialer.clear();
        let refused = compose(&board, Some(&token()), &named(head - 1));
        assert_eq!(
            refused,
            Err(Refusal::NotAPosition { at: head - 1, nearest: Some(head - 2), recorded: None })
        );
        assert_eq!(dialer.ops(), ["at:doc_metadata"]);
        let said = refused.unwrap_err().to_string();
        assert!(
            said.contains(&format!("position {}", head - 1))
                && said.contains(&format!("at or below it is {}", head - 2)),
            "{said}"
        );
        assert!(said.contains("not_a_position") && said.contains("or at the head"), "{said}");
    }

    /// Returns the draft side's record and the position its side names.
    ///
    /// `S` is read at the composition's first position, and the merge is
    /// landed as the shot and its record read back.
    fn landed_draft_side_record(
        dialer: &Scripted,
        board: &Board,
        signer: &HybridSigner,
    ) -> (Record, u64) {
        let session = sign_in(board, signer);
        let read_at = dialer.world().position;
        let inputs =
            Inputs { sides: vec![Side::Draft { at: a(S), position: None }], ..race_inputs() };
        let merged = compose(board, Some(session.token()), &inputs).expect("composed");
        land(board, &merged, shot(&session, signer)).expect("landed");
        let record = current(board, Some(&token()), &a(K), &merged.key)
            .expect("the lookup")
            .expect("the record");
        assert_eq!(record.sides[1], SideAt::Draft { at: a(S), position: Some(read_at) });
        (record, read_at)
    }

    /// A reclaimed position a record names withholds the verdict.
    ///
    /// The draft side's record verifies Equal as of the position it names;
    /// once the journal's floor passes that position, `verify` answers
    /// Unreadable naming the draft — never the composition's refusal, whose
    /// advice is to compose again — after the one refused read, with
    /// nothing read at the head or at another position in its place (skep
    /// #761; D14).
    #[test]
    fn a_reclaimed_position_a_record_names_withholds_the_verdict() {
        let (dialer, board, signer) = open(World::window_and_draft());
        let (record, read_at) = landed_draft_side_record(&dialer, &board, &signer);
        assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal), "the premise");
        dialer.world().floor = Some(read_at + 1);
        dialer.clear();
        assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Unreadable(a(S))));
        assert_eq!(dialer.ops(), ["at:doc_metadata"], "the one read, at the record's position");
        assert_eq!(dialer.positions("doc_metadata"), [read_at]);
    }

    /// A draft side the reader may not read withholds the verdict.
    ///
    /// The draft side's record verifies Equal; once the draft is withheld
    /// from the reader, `verify` answers Unreadable naming the draft — never
    /// the composition's refusal — after the trunk's metadata and the
    /// draft's own, each at the record's position, with nothing read past
    /// the refused one (merge record §4, testimony; D14).
    #[test]
    fn a_withheld_draft_side_withholds_the_verdict() {
        let (dialer, board, signer) = open(World::window_and_draft());
        let (record, read_at) = landed_draft_side_record(&dialer, &board, &signer);
        assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal), "the premise");
        dialer.world().withheld.insert(S.to_string());
        dialer.clear();
        assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Unreadable(a(S))));
        assert_eq!(
            dialer.ops(),
            ["at:doc_metadata", "at:doc_metadata"],
            "the trunk's metadata, then the draft's, refused"
        );
        let read: Vec<String> = dialer
            .frames("doc_metadata")
            .iter()
            .map(|f| f["doc"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(read, [D, S]);
        assert_eq!(dialer.positions("doc_metadata"), [read_at, read_at]);
    }

    /// A reclaimed draft landing position withholds the verdict.
    ///
    /// The race shape landed into a fresh draft verifies Equal by identity
    /// as of the landing's position. Once the journal's floor passes that
    /// position — the recomputation's own reads, at the head, still answered
    /// — `verify` answers Unreadable naming the draft, the draft read no
    /// further than the refused read; and so it does where the floor passes
    /// the position between the draft's extent and its image (skep #761;
    /// D14).
    #[test]
    fn a_reclaimed_draft_landing_position_withholds_the_verdict() {
        let (dialer, board, signer) = open(World::race());
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
        let landed = land(&board, &merged, draft_landing(&session, &signer, None)).expect("landed");
        let Landed::Draft { into: fresh, position, .. } = &landed else { panic!("{landed:?}") };
        let record = current(&board, Some(&token()), &a(K), &merged.key)
            .expect("the lookup")
            .expect("the record");
        assert_eq!(
            record.landed,
            Some(RecordLanding::Draft { draft: fresh.clone(), position: *position })
        );
        assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal), "the premise");
        assert!(
            *position < dialer.world().position,
            "the premise: the head the recomputation reads at stands above the floor"
        );
        dialer.world().floor = Some(position + 1);
        dialer.clear();
        assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Unreadable(fresh.clone())));
        let ops = dialer.ops();
        assert_eq!(
            ops.last().map(String::as_str),
            Some("at:retrieve_doc_v_span_set"),
            "the refused read is the last: {ops:?}"
        );
        assert_eq!(dialer.positions("retrieve_doc_v_span_set").last(), Some(position));
        let fresh_text = fresh.to_string();
        assert!(
            dialer.frames("image").iter().all(|f| f["d"].as_str() != Some(fresh_text.as_str())),
            "no image of the draft: {ops:?}"
        );
        // The floor passing the landing's position after the draft's extent
        // was read there and before its image: the image's refusal withholds
        // the verdict too.
        dialer.world().floor = None;
        dialer.clear();
        assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal));
        let image_at = dialer
            .served
            .lock()
            .unwrap()
            .iter()
            .position(|(line, f)| {
                line == "at:image" && f["frame"]["d"].as_str() == Some(fresh_text.as_str())
            })
            .expect("the draft's image");
        dialer.world().reclaim = Some((image_at + 1, position + 1));
        dialer.clear();
        assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Unreadable(fresh.clone())));
        assert!(dialer.world().reclaim.is_none(), "the journal reclaimed mid-walk");
        let ops = dialer.ops();
        assert_eq!(
            ops.last().map(String::as_str),
            Some("at:image"),
            "the refused image is the last read: {ops:?}"
        );
        assert_eq!(
            dialer.positions("retrieve_doc_v_span_set").last(),
            Some(position),
            "the extent answered at the landing's position"
        );
        assert_eq!(dialer.positions("image").last(), Some(position));
    }

    /// A position a record names that the board never answered is refused.
    ///
    /// A draft side's record naming a position past the board's head
    /// refuses `BeyondHead`, and one naming a number inside one commit
    /// `NotAPosition`, each carrying the board's head or nearest position
    /// and naming the draft as the record's. The face says the record
    /// cannot be checked here and advises no read elsewhere; after the one
    /// refused read nothing is read at another position (skep #761).
    #[test]
    fn a_position_a_record_names_past_the_head_or_inside_a_commit_is_refused_as_the_records() {
        let (dialer, board, signer) = open(World::window_and_draft());
        let (record, _) = landed_draft_side_record(&dialer, &board, &signer);
        let head = dialer.world().position;
        let naming = |p: u64| {
            let mut r = record.clone();
            r.sides[1] = SideAt::Draft { at: a(S), position: Some(p) };
            r
        };
        dialer.clear();
        let refused = verify(&board, Some(&token()), &naming(head + 5));
        assert_eq!(
            refused,
            Err(Refusal::BeyondHead { at: head + 5, head: Some(head), recorded: Some(a(S)) })
        );
        assert_eq!(dialer.ops(), ["at:doc_metadata"], "the one read, at the record's position");
        let said = refused.unwrap_err().to_string();
        assert!(
            said.contains(&format!("position {} for {S}", head + 5))
                && said.contains(&format!("head at position {head}")),
            "{said}"
        );
        assert!(said.contains("beyond_head") && said.contains("cannot be checked here"), "{said}");
        assert!(!said.contains("or at the head"), "no read elsewhere advised: {said}");
        dialer.world().inside_commits.insert(head - 1);
        dialer.clear();
        let refused = verify(&board, Some(&token()), &naming(head - 1));
        assert_eq!(
            refused,
            Err(Refusal::NotAPosition {
                at: head - 1,
                nearest: Some(head - 2),
                recorded: Some(a(S))
            })
        );
        assert_eq!(dialer.ops(), ["at:doc_metadata"]);
        let said = refused.unwrap_err().to_string();
        assert!(
            said.contains(&format!("position {} for {S}", head - 1))
                && said.contains(&format!("at or below it is {}", head - 2)),
            "{said}"
        );
        assert!(
            said.contains("not_a_position") && said.contains("cannot be checked here"),
            "{said}"
        );
        assert!(!said.contains("or at the head"), "no read elsewhere advised: {said}");
    }

    /// LAND AND TELL (R5, P1): version 3 published after the merge was
    /// composed on version 2 refuses nothing — the write lands, the base is
    /// recorded on the head USED at the extent read, the marker names that
    /// head, and the landing carries the trunk's current head as
    /// `head_moved`.
    #[test]
    fn a_newer_head_published_since_the_compose_is_told_and_the_landing_stands() {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
        {
            let mut w = dialer.world();
            w.text(D, 16, "?");
            w.member(&format!("{D}.3"), vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(D, 16, 1)], Some(15));
            w.trunk_head.insert(D.to_string(), format!("{D}.3"));
        }
        let landed = land(&board, &merged, draft_landing(&session, &signer, Some(a(S)))).expect("landed");
        let Landed::Draft { into, position, head_moved, .. } = &landed else { panic!("{landed:?}") };
        assert_eq!((into.to_string(), head_moved.as_ref().map(ToString::to_string)), (S.to_string(), Some(format!("{D}.3"))));
        let w = dialer.world();
        assert_eq!(w.docs.get(S).unwrap().runs, draft_m());
        assert_eq!(
            w.standing(S),
            (Some((format!("{D}.2"), 15)), Some(Marker { sides: vec![], head: format!("{D}.2"), head_copied: 15, at: *position })),
            "recorded on the head used"
        );
    }

    /// A BASELESS DRAFT (N4): landing into a plain draft the board records
    /// no base for — never staged — sends `head` and `merge` and NO `base`,
    /// so the board admits it with nothing moved: the draft holds M, no
    /// base, no marker.
    #[test]
    fn a_landing_into_a_baseless_draft_sends_no_base() {
        let plain = "1.0.1.0.5";
        let mut w = draft_landing_world();
        w.doc(plain, false, ACCOUNT, Vec::new());
        let (dialer, board, signer) = open(w);
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
        dialer.clear();
        let landed = land(&board, &merged, draft_landing(&session, &signer, Some(a(plain)))).expect("landed");
        let Landed::Draft { into, head_moved, .. } = &landed else { panic!("{landed:?}") };
        assert_eq!((into.to_string(), head_moved.clone()), (plain.to_string(), None));
        let frame = &dialer.frames("set_arrangement")[0];
        assert_eq!(frame["doc"], plain);
        assert!(frame.get("base").is_none(), "no base the board must refuse `no_base_to_record`: {frame}");
        assert_eq!(frame["head"], json!({"at": format!("{D}.2"), "extent": "15"}));
        assert_eq!(frame["merge"], json!({"sides": [S]}), "the side, which is not the draft landed into");
        let w = dialer.world();
        assert_eq!(w.docs.get(plain).unwrap().runs, draft_m());
        assert_eq!(w.standing(plain), (None, None), "nothing moved");
    }

    /// THE FORK GATE (N4, P5): a fork — a document the board records no base
    /// for, born sharing a published version, its `source` — takes a landing
    /// composed on another head than its source as `fork_base_moved`,
    /// refused by name with the source, the head and the way out, nothing
    /// written; a fork whose source IS the head is admitted, gaining no base
    /// and no marker.
    #[test]
    fn a_fork_is_refused_fork_base_moved_and_admitted_where_its_source_is_the_head() {
        let (moved, fresh) = ("1.0.1.0.7", "1.0.1.0.8");
        let mut w = World::race();
        // A fork of version 1 that removed " sat", and a fork of version 2
        // that did the same.
        w.fork(moved, ACCOUNT, &format!("{D}.1"), vec![run(D, 1, 7)]);
        w.fork(fresh, ACCOUNT, &format!("{D}.2"), vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 3)]);
        let (dialer, board, signer) = open(w);
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &Inputs { sides: vec![Side::Fork(a(moved))], ..race_inputs() }).expect("composed");
        assert_eq!(m_runs(&merged), vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 3)], "the big cat");
        let rows = dialer.world().rows.len();
        dialer.clear();
        assert_eq!(
            land(&board, &merged, draft_landing(&session, &signer, Some(a(moved)))),
            Err(Refusal::ForkBaseMoved { fork: a(moved), source: a(&format!("{D}.1")), head: a(&format!("{D}.2")) })
        );
        let frame = &dialer.frames("set_arrangement")[0];
        assert!(frame.get("base").is_none(), "a fork records no base: {frame}");
        assert_eq!(frame["merge"], json!({"sides": []}));
        assert_eq!(dialer.world().docs.get(moved).unwrap().runs, vec![run(D, 1, 7)], "nothing written");
        assert_eq!(dialer.world().rows.len(), rows);
        assert!(dialer.frames("insert").is_empty(), "no record");
        let said = Refusal::ForkBaseMoved { fork: a(moved), source: a(&format!("{D}.1")), head: a(&format!("{D}.2")) }.to_string();
        assert!(said.contains(&format!("forked from {D}.1")) && said.contains(&format!("fork {D}.2 afresh")), "{said}");
        // The fork of the head: admitted, nothing moved.
        let merged = compose(&board, Some(session.token()), &Inputs { sides: vec![Side::Fork(a(fresh))], ..race_inputs() }).expect("composed");
        assert_eq!(merged.key.base, a(&format!("{D}.2")), "the fork's source is the head, so the base is the head");
        dialer.clear();
        let landed = land(&board, &merged, draft_landing(&session, &signer, Some(a(fresh)))).expect("landed");
        let Landed::Draft { into, head_moved, .. } = &landed else { panic!("{landed:?}") };
        assert_eq!((into.to_string(), head_moved.clone()), (fresh.to_string(), None));
        let frame = &dialer.frames("set_arrangement")[0];
        assert_eq!(frame["head"], json!({"at": format!("{D}.2"), "extent": "15"}));
        assert!(frame.get("base").is_none());
        assert_eq!(dialer.world().standing(fresh), (None, None), "no base, no marker gained");
    }

    /// The scripted board judges `set_arrangement` in the store's order.
    ///
    /// A head's registration is asked on every draft, ahead of its chain,
    /// its extent and the fork gate, and is all a plain draft's head meets;
    /// a base's follows `no_base_to_record`, ahead of its chain and its
    /// extent (wire.md §Arrangement) — cell by cell over the staged draft
    /// `S`, the merger's fork of `D.1` and a plain draft. Every refused
    /// frame carries a run of no value, so `dangling_source` answers where
    /// no judgment ahead of the runs spoke, and leaves the feed, the draft
    /// and its base as they stood; the admitted frames, last, commit once
    /// each and record no base.
    #[test]
    fn the_scripted_board_judges_set_arrangement_as_the_store_does() {
        let (plain, fork) = ("1.0.1.0.5", "1.0.1.0.7");
        let mut w = draft_landing_world();
        w.doc(plain, false, ACCOUNT, Vec::new());
        w.fork(fork, ACCOUNT, &format!("{D}.1"), vec![run(D, 1, 7)]);
        let v1: &str = &format!("{D}.1");
        let v2: &str = &format!("{D}.2");
        // Addresses no mint made: a member, a daughter and a document.
        let no_member: &str = &format!("{D}.9");
        let no_daughter: &str = &format!("{D}.1.9");
        let no_document = "1.0.1.0.99";
        let cells = [
            // `S`, whose chain is `D`'s: the head's three checks, then the
            // base's.
            (S, Some((no_member, 0)), Some((v1, 11)), "source_not_registered"),
            (S, Some((no_document, 99)), None, "source_not_registered"),
            (S, Some((Z, 5)), None, "base_not_in_chain"),
            (S, Some((v2, 16)), None, "base_extent_too_large"),
            (S, None, Some((no_daughter, 0)), "source_not_registered"),
            (S, None, Some((no_document, 99)), "source_not_registered"),
            (S, None, Some((Z, 5)), "base_not_in_chain"),
            (S, None, Some((v1, 12)), "base_extent_too_large"),
            // The fork, whose chain is its source's: the head judged ahead
            // of the gate.
            (fork, Some((no_member, 0)), None, "source_not_registered"),
            (fork, Some((D, 99)), None, "base_extent_too_large"),
            (fork, Some((v2, 15)), None, "fork_base_moved"),
            // The plain draft, with no chain: the head's registration
            // alone, ahead of the base's `no_base_to_record`.
            (plain, Some((no_member, 5)), None, "source_not_registered"),
            (plain, Some((no_document, 99)), Some((v2, 15)), "source_not_registered"),
            (plain, Some((v2, 99)), None, "dangling_source"),
            (plain, None, Some((no_document, 99)), "no_base_to_record"),
        ];
        let dangling = [frames::shot_run(D, &i_addr(&a(D), 99), 1)];
        for (doc, head, base, code) in cells {
            let cell = format!("{doc}, head {head:?}, base {base:?}");
            let before = (w.rows.len(), w.docs[doc].runs.clone(), w.standing(doc));
            let frame = frames::set_arrangement(doc, &dangling, w.position, head, base, None, None);
            let answer = w.set_arrangement(&frame);
            assert_eq!(answer["code"].as_str(), Some(code), "{cell}: {answer}");
            assert_eq!(
                (w.rows.len(), w.docs[doc].runs.clone(), w.standing(doc)),
                before,
                "{cell}: nothing written"
            );
        }
        // Admitted: the trunk's head told where the head named is not it,
        // and no base or marker recorded for a draft that records none.
        let whole = [frames::shot_run(D, &i_addr(&a(D), 1), 11)];
        for (doc, head, told) in
            [(plain, (v2, 99), None), (plain, (v1, 11), Some(v2)), (fork, (v1, 11), Some(v2))]
        {
            let cell = format!("{doc}, head {head:?}");
            let rows = w.rows.len();
            let frame =
                frames::set_arrangement(doc, &whole, w.position, Some(head), None, None, None);
            let answer = w.set_arrangement(&frame);
            assert_eq!(
                (answer["resp"].as_str(), answer["head_moved"].as_str()),
                (Some("ack"), told),
                "{cell}: {answer}"
            );
            assert_eq!(w.rows.len(), rows + 1, "{cell}: one commit");
            assert_eq!(
                (w.docs[doc].runs.clone(), w.standing(doc)),
                (vec![run(D, 1, 11)], (None, None)),
                "{cell}: the runs placed, nothing recorded"
            );
        }
    }

    /// A FRESH DRAFT (R3 (i)): with no draft named, `stage {from: the head}`
    /// under the id `<stem>.stage`, then the one write into the staged draft
    /// typed against the stage's position, the base sent — the stage
    /// recorded one — and the merge's side; two commits, the state between a
    /// plain staged draft. Over the same `merged` the memo answers both ids:
    /// nothing twice. Composed again, the standing record for the key names
    /// the landing: it is reported, and NOTHING is staged.
    #[test]
    fn a_fresh_draft_is_staged_from_the_head_then_landed_in_and_a_re_run_stages_nothing() {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
        dialer.clear();
        let landed = land(&board, &merged, draft_landing(&session, &signer, None)).expect("landed");
        let Landed::Draft { into: fresh, position, record, head_moved } = &landed else { panic!("{landed:?}") };
        assert_eq!((fresh.to_string(), head_moved.clone()), ("1.0.1.0.10".to_string(), None), "the fresh draft minted");
        let ops = dialer.ops();
        let writes: Vec<&str> = ops.iter().map(String::as_str).filter(|o| ["stage", "set_arrangement", "insert", "make_link", "create_new_document"].contains(o)).collect();
        assert_eq!(writes, ["stage", "set_arrangement", "create_new_document", "insert", "make_link"], "{ops:?}");
        let stage = &dialer.frames("stage")[0];
        assert_eq!(stage, &json!({"op": "stage", "from": format!("{D}.2"), "id": format!("{}.stage", merged.key.text())}));
        let stage_at = dialer.world().rows.iter().find(|r| r.op == "stage").unwrap().at;
        let frame = &dialer.frames("set_arrangement")[0];
        assert_eq!(frame["doc"].as_str(), Some(fresh.to_string().as_str()));
        assert_eq!(frame["as_of"].as_u64(), Some(stage_at), "typed against the stage's position: {frame}");
        assert_eq!(frame["base"], json!({"at": format!("{D}.2"), "extent": "15"}), "the stage recorded a base, so it is re-recorded");
        assert_eq!(frame["merge"], json!({"sides": [S]}));
        assert_eq!(dialer.positions("doc_metadata"), [stage_at], "the fresh draft's base read at the stage's position");
        let w = dialer.world();
        assert_eq!(w.docs.get(&fresh.to_string()).unwrap().runs, draft_m());
        assert_eq!(
            w.standing(&fresh.to_string()),
            (Some((format!("{D}.2"), 15)), Some(Marker { sides: vec![S.to_string()], head: format!("{D}.2"), head_copied: 15, at: *position }))
        );
        assert_eq!(*position, w.rows.iter().find(|r| r.op == "set_arrangement").unwrap().at);
        let rows = w.rows.len();
        drop(w);
        // The same `merged` again: the memo answers both ids, nothing twice.
        dialer.clear();
        assert_eq!(land(&board, &merged, draft_landing(&session, &signer, None)).expect("landed again"), landed);
        assert_eq!(dialer.world().rows.len(), rows, "nothing written twice");
        // Composed again: the standing record names the landing — reported,
        // nothing staged, nothing written, no `stage` frame.
        let again = compose(&board, Some(session.token()), &draft_inputs()).expect("composed again");
        assert_eq!(again.prior.as_ref().and_then(|p| p.link.clone()), Some(record.clone()));
        dialer.clear();
        assert_eq!(
            land(&board, &again, draft_landing(&session, &signer, None)).expect("landed"),
            Landed::Draft { into: fresh.clone(), position: *position, record: record.clone(), head_moved: None }
        );
        assert!(dialer.ops().is_empty(), "nothing read, nothing staged, nothing written: {:?}", dialer.ops());
        assert_eq!(dialer.world().rows.len(), rows);
        assert_eq!(resume(&board, &again, draft_landing(&session, &signer, None)).expect("resumed"), Some(landed.clone()));
        // With no standing record a resume of a fresh landing has nothing to read.
        assert_eq!(resume(&board, &merged, draft_landing(&session, &signer, None)).expect("resumed"), None);
    }

    /// Every refusal the shot can answer, each mapped: `withheld` naming the
    /// origin, `signed_session_required`, `doc_not_registered`, the
    /// library's own faults as halts, the board's `board_unavailable` as the
    /// head it owes — and nothing after the refusal.
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
        // The publication family's arms: `not_owner` naming the DRAFT side is
        // the unowned draft, named — never the library's own fault — while
        // naming `doc` is the own fault; the twin fence's member and the
        // budget's detail ride verbatim; a place's token, which this frame
        // never carries, the library's own fault.
        let drafted = || Landing::Shot { merger: merger(&session, &signer), draft: Some(a(S)), journal: None };
        let verbatim = |err: Refusal, code: &str| -> crate::halt::Refused {
            match err {
                Refusal::Halt(Halt::Refused(r)) if r.code == code => r,
                other => panic!("not the board's {code} verbatim: {other:?}"),
            }
        };
        refuse("not_owner", Some(S));
        assert_eq!(land(&board, &merged, drafted()).unwrap_err(), Refusal::UnownedDraft { draft: a(S) }, "the draft side named");
        refuse("not_owner", Some(D));
        let err = land(&board, &merged, drafted()).expect_err("own fault");
        assert!(matches!(&err, Refusal::Halt(Halt::Halt(_))), "{err}");
        assert!(err.to_string().contains("not_owner"), "{err}");
        refuse("already_published", Some(&format!("{D}.3")));
        let twin = verbatim(land(&board, &merged, drafted()).unwrap_err(), "already_published");
        assert_eq!(twin.body["site"]["addr"].as_str(), Some(format!("{D}.3").as_str()));
        dialer.world().memo.insert(
            format!("{}.publish", merged.key.text()),
            json!({"resp": "rejected", "code": "publication_over_budget", "detail": "70000 in-lock reads priced over the budget of 65536", "disposition": "permanent", "op": "publish"}),
        );
        let budget = verbatim(land(&board, &merged, drafted()).unwrap_err(), "publication_over_budget");
        assert_eq!(budget.detail.as_deref(), Some("70000 in-lock reads priced over the budget of 65536"));
        refuse("kept_place_moved", None);
        let err = land(&board, &merged, drafted()).expect_err("own fault");
        assert!(matches!(&err, Refusal::Halt(h) if h.to_string().contains("kept_place_moved")), "{err}");
        // The head the board owes past the landing's read of it: the board's
        // state, a retry its act — never this library's fault.
        dialer.world().memo.insert(
            format!("{}.publish", merged.key.text()),
            json!({"resp": "rejected", "code": "credential_refused", "detail": "attestation_invalid:board_unavailable", "disposition": "reorder", "op": "publish"}),
        );
        let err = land(&board, &merged, shot(&session, &signer)).expect_err("the head owed");
        let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{err:?}") };
        assert!(
            face.state.contains("H.1")
                && face.cause.contains("attestation_invalid:board_unavailable"),
            "{face}"
        );
        assert!(
            face.act.contains("retry once the board has written its head")
                && !face.act.contains("fault in this library"),
            "{face}"
        );
        assert!(
            dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
            "nothing after a refused shot"
        );
    }

    /// Every refusal the draft landing's one write can answer is mapped.
    ///
    /// A draft staged from another document's member meets the board's own
    /// `base_not_in_chain` as `Refusal::BaseNotInChain`. Planted under the
    /// write's id, `withheld` names the origin, `signed_session_required`
    /// and `doc_not_registered` answer theirs, every refusal of the frame's
    /// substance is the library's own fault and any other code rides
    /// verbatim. Each leaves the feed as it stood, the refused write the
    /// last frame sent: no journal and no record.
    #[test]
    fn the_draft_landings_refusals_are_mapped() {
        // `T`, a draft staged from `Z`'s first member: its chain is `Z`'s.
        let t = "1.0.1.0.5";
        let mut w = draft_landing_world();
        w.member(&format!("{Z}.1"), vec![run(Z, 1, 5)], None);
        w.doc(t, false, ACCOUNT, vec![run(Z, 1, 5)]);
        w.staged(t, &format!("{Z}.1"), 5);
        let (dialer, board, signer) = open(w);
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
        let rows = dialer.world().rows.len();
        let stopped = |cell: &str| {
            let ops = dialer.ops();
            assert_eq!(ops.last().map(String::as_str), Some("set_arrangement"), "{cell}: {ops:?}");
            assert_eq!(dialer.world().rows.len(), rows, "{cell}: nothing committed");
        };
        dialer.clear();
        assert_eq!(
            land(&board, &merged, draft_landing(&session, &signer, Some(a(t)))),
            Err(Refusal::BaseNotInChain { into: a(t), head: a(&format!("{D}.2")) })
        );
        assert_eq!(
            dialer.frames("set_arrangement")[0]["base"],
            json!({"at": format!("{D}.2"), "extent": "15"}),
            "the head's pair, the base to record: the board records one for T"
        );
        stopped("base_not_in_chain");
        assert_eq!(
            dialer.world().standing(t),
            (Some((format!("{Z}.1"), 5)), None),
            "T's base as it stood"
        );
        // The codes planted under the write's id, each answered to a landing
        // into `S`.
        let id = format!("{}.draft", merged.key.text());
        let refused = |code: &str, site: Option<&str>| -> Refusal {
            let site = site.map_or(Value::Null, |s| json!({"addr": s}));
            dialer.world().memo.insert(id.clone(), permanent("set_arrangement", code, site));
            dialer.clear();
            let err = land(&board, &merged, draft_landing(&session, &signer, Some(a(S))))
                .expect_err(code);
            stopped(code);
            err
        };
        assert_eq!(refused("withheld", Some(Z)), Refusal::WindowWithheld(a(Z)));
        assert_eq!(refused("signed_session_required", None), Refusal::NeedsSignedSession);
        assert_eq!(refused("doc_not_registered", None), Refusal::NoSuchDocument(a(S)));
        for code in [
            "source_not_registered",
            "no_base_to_record",
            "base_extent_too_large",
            "published_target",
            "not_owner",
            "bad_run",
            "dangling_source",
            "too_many_runs",
            "malformed",
        ] {
            let err = refused(code, None);
            let Refusal::Halt(halt) = &err else { panic!("{code}: {err:?}") };
            assert_eq!(halt.exit_code(), 3, "{code}: {err:?}");
            let Halt::Halt(face) = halt else { panic!("{code}: {err:?}") };
            assert!(
                face.cause.contains(code) && face.act.contains("fault in this library"),
                "{code}: {face}"
            );
        }
        let err = refused("txn_over_budget", None);
        let Refusal::Halt(Halt::Refused(verbatim)) = &err else { panic!("{err:?}") };
        assert_eq!(verbatim.code, "txn_over_budget");
    }

    /// A CLAIMED BOARD WHOSE HEAD IS OWED LANDS NOTHING (SP-14): `/health`
    /// names a claimant and `H.1` serves no record, so the shot, a draft
    /// landing into `S` and a fresh draft each halt naming `H.1` before
    /// their first write — no `publish`, `stage`, `set_arrangement`,
    /// journal mint, `insert` or `make_link` sent, no commit made — and a
    /// `resume` that finds nothing landed answers none with no head read.
    /// The same board unclaimed lands each, the shot and the record's link
    /// carrying no `attest`.
    #[test]
    fn a_claimed_board_serving_no_head_record_lands_nothing_and_an_unclaimed_one_lands_unsigned() {
        let writes =
            ["publish", "stage", "set_arrangement", "create_new_document", "insert", "make_link"];
        for cell in ["the shot", "a landing into S", "a fresh draft"] {
            let (mut world, inputs) = match cell {
                "the shot" => (World::race(), race_inputs()),
                _ => (draft_landing_world(), draft_inputs()),
            };
            world.head = false;
            let (dialer, board, signer) = open(world);
            let session = sign_in(&board, &signer);
            let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
            let landing = || match cell {
                "the shot" => shot(&session, &signer),
                "a landing into S" => draft_landing(&session, &signer, Some(a(S))),
                _ => draft_landing(&session, &signer, None),
            };
            let rows = dialer.world().rows.len();
            dialer.clear();
            let err = land(&board, &merged, landing()).expect_err("the head is owed");
            let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{cell}: {err:?}") };
            assert!(
                face.state.contains("H.1") && face.state.contains("cannot land"),
                "{cell}: {face}"
            );
            assert!(
                face.cause.contains(&format!("names {ACCOUNT} its claimant")),
                "{cell}: {face}"
            );
            assert!(face.act.contains("nothing was written"), "{cell}: {face}");
            for op in writes {
                assert!(dialer.frames(op).is_empty(), "{cell}: no `{op}`: {:?}", dialer.ops());
            }
            assert_eq!(dialer.world().rows.len(), rows, "{cell}: no commit");
            dialer.clear();
            assert_eq!(resume(&board, &merged, landing()), Ok(None), "{cell}: nothing landed");
            assert!(
                dialer.frames("retrieve_v").iter().all(|f| f["specs"][0]["doc"] != HEAD_MEMBER_1),
                "{cell}: a resume with nothing to write reads no head: {:?}",
                dialer.ops()
            );
            // The same board, no one its claimant: landed, unsigned.
            dialer.world().claimed = false;
            dialer.clear();
            land(&board, &merged, landing()).unwrap_or_else(|e| panic!("{cell}: {e}"));
            let links = dialer.frames("make_link");
            assert_eq!(links.len(), 1, "{cell}: the record's link: {:?}", dialer.ops());
            for frame in dialer.frames("publish").iter().chain(&links) {
                assert!(frame.get("attest").is_none(), "{cell}: unsigned: {frame}");
            }
        }
    }

    /// A LANDING THAT STANDS WITH ITS RECORD OWED (SP-14): the shot lands
    /// and the record's link is refused `attestation_invalid:board_unavailable`
    /// — the head owed past the landing's read — faced as the merge standing
    /// with `resume` its act, never the library's fault. Read afresh with the
    /// head still owed, the residue walk halts before the record's first
    /// write — no journal mint, `insert` or `make_link` — and once the head
    /// is written it writes the record, signed.
    #[test]
    fn a_landing_that_stands_writes_its_record_only_once_the_head_is_written() {
        let (dialer, board, signer) = open(World::race());
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
        let link_id = format!("{}.link", merged.key.text());
        dialer.world().memo.insert(
            link_id.clone(),
            json!({"resp": "rejected", "code": "credential_refused", "detail": "attestation_invalid:board_unavailable", "disposition": "reorder", "op": "make_link"}),
        );
        let member = format!("{D}.3");
        let err = land(&board, &merged, shot(&session, &signer)).expect_err("the link refused");
        let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{err:?}") };
        assert!(
            face.state.contains(&format!("the merge stands at {member}"))
                && face.state.contains("H.1"),
            "{face}"
        );
        assert!(face.cause.contains("attestation_invalid:board_unavailable"), "{face}");
        assert!(
            face.act.starts_with("resume") && !face.act.contains("fault in this library"),
            "{face}"
        );
        assert!(dialer.world().docs.contains_key(&member), "the premise: the shot landed");
        // A board read afresh, its head still owed: no write of the record.
        dialer.world().memo.remove(&link_id);
        dialer.world().head = false;
        let afresh = Board::new(Origin::parse("http://127.0.0.1:8642").unwrap(), dialer.clone());
        dialer.clear();
        let err = resume(&afresh, &merged, shot(&session, &signer)).expect_err("the head is owed");
        let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{err:?}") };
        assert!(face.state.contains(&format!("the merge stands at {member}")), "{face}");
        assert!(face.cause.contains(&format!("names {ACCOUNT} its claimant")), "{face}");
        for op in ["publish", "create_new_document", "insert", "make_link"] {
            assert!(dialer.frames(op).is_empty(), "no `{op}`: {:?}", dialer.ops());
        }
        // The head written: the residue walk writes the record, signed.
        dialer.world().head = true;
        let resumed = resume(&afresh, &merged, shot(&session, &signer)).expect("resumed");
        assert!(
            matches!(&resumed, Some(Landed::Member { address, .. }) if address.to_string() == member),
            "{resumed:?}"
        );
        let links = dialer.frames("make_link");
        assert_eq!(links.len(), 1, "{:?}", dialer.ops());
        assert!(
            links[0]["attest"]["sig"].is_string(),
            "signed over the head written: {}",
            links[0]
        );
    }

    // ── the undo and the withdrawal ──────────────────────────────────────

    /// Lands M into `S` as the draft landing does — the base re-recorded on
    /// `D.2` at fifteen, the marker beside it, the record written — and
    /// answers the composition with the landing.
    fn landed_in_s(board: &Board, session: &Session<'_>, signer: &HybridSigner) -> (Merged, Landed) {
        let merged = compose(board, Some(session.token()), &draft_inputs()).expect("composed");
        let landed = land(board, &merged, draft_landing(session, signer, Some(a(S)))).expect("landed");
        (merged, landed)
    }

    /// A draft landing's position and its record's link.
    fn landing_of(landed: &Landed) -> (u64, Address) {
        let Landed::Draft { position, record, .. } = landed else { panic!("{landed:?}") };
        (*position, record.clone())
    }

    /// C, the draft landing's `S` before the landing: the base's text by
    /// identity and "!!!" after it.
    fn draft_c() -> Vec<Run> {
        vec![run(D, 1, 11), run(S, 1, 3)]
    }

    /// Runs as a `set_arrangement` frame built by hand spells them.
    fn shot_runs(m: &[Run]) -> Vec<Value> {
        m.iter().map(|r| frames::shot_run(&r.origin.to_string(), &i_addr(&r.origin, r.i_start), r.width)).collect()
    }

    /// The record a take-back appended, read off the one `insert` served.
    fn appended_record(dialer: &Scripted) -> Value {
        let inserts = dialer.frames("insert");
        assert_eq!(inserts.len(), 1, "one record appended: {:?}", dialer.ops());
        serde_json::from_str(inserts[0]["values"][0]["atom"].as_str().expect("the atom")).expect("a record")
    }

    /// THE UNDO (the landing lane's R6; P1, P3, P4; skep #783): after a
    /// landing into `S`, `undo` reads the draft's `doc_metadata` live — a
    /// base and a marker — then the state before the landing at ONE
    /// position, `/op-at`'s `nearest` for the marker's `at − 1`: a landing
    /// is one commit of three records, so `at − 1` lies inside it and the
    /// board answers `not_a_position`; `doc_metadata` there for the old
    /// base, address and extent, and `image` for C. ONE `set_arrangement`
    /// follows — C as the runs, `as_of` the landing's position (P3), `base`
    /// the old pair (P1), no `head`, no `merge`, the id naming the draft and
    /// the position — so the draft holds C again, its base is `D.1` at
    /// eleven and the marker is cleared; the replacing record, `landed`
    /// none and `replaces` the landing's link, is appended and linked to
    /// the draft.
    #[test]
    fn undo_after_a_landing_restores_c_and_the_old_base_and_clears_the_marker_in_one_frame() {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let before = dialer.world().position;
        let (_, landed) = landed_in_s(&board, &session, &signer);
        let (at, link) = landing_of(&landed);
        assert_eq!(at, before + 3, "the premise: one commit of three records");
        assert_eq!(dialer.world().standing(S).1.map(|m| m.at), Some(at), "the premise: the marker at the landing");
        dialer.clear();
        let undone = undo(&board, merger(&session, &signer), &a(S), &a(K), None).expect("undone");
        assert_eq!(undone.draft, a(S));
        assert_eq!(undone.restored, Some((a(&format!("{D}.1")), 11)), "the pair read before the landing");
        let replacing = undone.record.clone().expect("a record stood, so one replaces it");
        assert_ne!(replacing, link);
        // The pre-landing read: `at − 1` refused `not_a_position`, then the
        // one position `nearest` for the metadata and the image.
        assert_eq!(dialer.positions("doc_metadata"), [at - 1, before], "at − 1 asked, then nearest: {:?}", dialer.ops());
        assert_eq!(dialer.positions("retrieve_doc_v_span_set"), [before]);
        assert_eq!(dialer.positions("image"), [before]);
        // The one write.
        let frames = dialer.frames("set_arrangement");
        assert_eq!(frames.len(), 1, "one write: {:?}", dialer.ops());
        let frame = &frames[0];
        assert_eq!(frame["doc"], S);
        assert_eq!(frame["as_of"].as_u64(), Some(at), "typed against the landing's position: {frame}");
        assert_eq!(frame["runs"], frame_runs(&draft_c()), "C, read before the landing");
        assert_eq!(frame["base"], json!({"at": format!("{D}.1"), "extent": "11"}), "the old base, address and extent");
        assert!(frame.get("head").is_none() && frame.get("merge").is_none(), "no head, no merge: {frame}");
        assert_eq!(frame["id"].as_str(), Some(format!("undo:{S}:{at}.arrangement").as_str()));
        let w = dialer.world();
        assert_eq!(w.docs.get(S).unwrap().runs, draft_c(), "C again");
        assert_eq!(w.standing(S), (Some((format!("{D}.1"), 11)), None), "the base restored, the marker cleared");
        let row = w.rows.iter().rev().find(|r| r.op == "set_arrangement").expect("the undo's row");
        assert_eq!((row.at, &row.terms), (undone.position, &Some((Some(format!("{D}.1")), None))), "the write's `at`; its row names the base restored and no merge");
        drop(w);
        // The record: the landing's with `landed` none and `replaces` its
        // link, under the act's stem, linked to the draft.
        let atom = appended_record(&dialer);
        assert!(atom["landed"].is_null(), "{atom}");
        assert_eq!(atom["replaces"].as_str(), Some(link.to_string().as_str()));
        assert_eq!((atom["doc"].as_str(), atom["base"].as_str()), (Some(D), Some(format!("{D}.1").as_str())));
        assert_eq!(dialer.frames("insert")[0]["id"].as_str(), Some(format!("undo:{S}:{at}.record").as_str()));
        assert_eq!(dialer.frames("make_link")[0]["to"]["addrs"], json!([S]));
    }

    /// ANOTHER HAND's EDIT SINCE THE LANDING: the undo, typed against the
    /// landing's position, is refused `arrangement_moved` by the board — its
    /// words the person's, naming the draft and that nothing was changed —
    /// with the edit standing, nothing committed, the base and the marker as
    /// they stood and no record.
    #[test]
    fn undo_after_another_hands_edit_is_refused_arrangement_moved_with_nothing_committed() {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let (_, landed) = landed_in_s(&board, &session, &signer);
        let (at, _) = landing_of(&landed);
        // Another hand's edit after the landing: the "!!!" deleted.
        let edited = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)];
        let edit_at = dialer.world().change(S, edited.clone());
        let (rows, standing) = {
            let w = dialer.world();
            (w.rows.len(), w.standing(S))
        };
        dialer.clear();
        let err = undo(&board, merger(&session, &signer), &a(S), &a(K), None).expect_err("the draft changed since");
        let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
        assert_eq!(refused.code, "arrangement_moved");
        let detail = refused.detail.as_deref().expect("the person's words");
        assert!(detail.contains(S) && detail.contains("changed since the merge landed") && detail.contains("nothing was changed"), "{detail}");
        assert!(detail.contains(&format!("position {at}")) && detail.contains(&format!("changed at {edit_at}")), "{detail}");
        assert_eq!(dialer.frames("set_arrangement")[0]["as_of"].as_u64(), Some(at), "typed against the landing's position, never a fresh read");
        let w = dialer.world();
        assert_eq!(w.docs.get(S).unwrap().runs, edited, "the other hand's edit stands: nothing wiped");
        assert_eq!(w.rows.len(), rows, "nothing committed");
        assert_eq!(w.standing(S), standing, "the base and the marker as they stood");
        drop(w);
        assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(), "no record");
    }

    /// A BASE RECORDED AND NO MARKER (P4's second case): the merge was
    /// published from the draft — the shot moved its base to the member
    /// minted and cleared the marker — so there is nothing to undo, and an
    /// undo from the feed would re-record the base backward (N4). The words
    /// come from the draft's own latest marker-ending feed row, read on the
    /// supplement and never acted on: a `publish` row, P4's words with the
    /// recorded base as the version. Nothing is sent and no history is read.
    #[test]
    fn undo_after_a_publication_answers_nothing_to_undo_with_p4s_words_and_sends_nothing() {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        landed_in_s(&board, &session, &signer);
        // The merge published from the draft.
        let runs = shot_runs(&draft_m());
        let head = format!("{D}.2");
        let frame = frames::publication(&frames::PublishFrame { doc: Some(D), base: Some((&head, 15)), draft: Some(S), runs: &runs, ..frames::PublishFrame::default() });
        let Answer::Document(ack) = board.op(Some(session.token()), &frame).expect("the shot") else { panic!("closed") };
        assert_eq!(acked_addr(&ack), Some(format!("{D}.3").as_str()), "{ack}");
        assert_eq!(dialer.world().standing(S), (Some((format!("{D}.3"), 18)), None), "the premise: the base moved, the marker cleared");
        let rows = dialer.world().rows.len();
        dialer.clear();
        let err = undo(&board, merger(&session, &signer), &a(S), &a(K), None).expect_err("nothing to undo");
        assert_eq!(err, Refusal::NothingToUndo { draft: a(S), why: NoUndo::Published { version: a(&format!("{D}.3")) } });
        assert_eq!(err.to_string(), format!("nothing to undo; the merge is version {D}.3 — to take it back, publish the older text again"));
        let ops = dialer.ops();
        assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty(), "nothing sent: {ops:?}");
        assert!(ops.iter().any(|o| o.starts_with("GET /changes?") && o.contains(&format!("under={S}")) && o.contains("drafts=true")), "the words off the draft's own rows, on the supplement: {ops:?}");
        assert!(dialer.positions("doc_metadata").is_empty() && dialer.positions("image").is_empty(), "no read of history: {ops:?}");
        assert_eq!(dialer.world().rows.len(), rows, "nothing committed");
    }

    /// AN INHERITED MARKER (P2): a `stage` of the marked draft puts the
    /// marker on the alternative at the stage's own position, one commit of
    /// three records; the undo reads before it — `at − 1` refused
    /// `not_a_position`, then `nearest` — and meets the alternative's own
    /// `doc_not_registered`: nothing of its own to take back, said in P2's
    /// words, with nothing sent.
    #[test]
    fn undo_at_an_inherited_marker_answers_p2s_words_with_nothing_sent() {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        landed_in_s(&board, &session, &signer);
        let before_stage = dialer.world().position;
        let Answer::Document(ack) = board.op(Some(session.token()), &frames::stage(S, None)).expect("the stage") else { panic!("closed") };
        let t = acked_addr(&ack).expect("the alternative").to_string();
        let staged_at = acked_at(&ack).expect("its position");
        assert_eq!(staged_at, before_stage + 3, "the premise: a stage is one commit of three records");
        assert_eq!(
            dialer.world().standing(&t),
            (Some((format!("{D}.2"), 15)), Some(Marker { sides: vec![], head: format!("{D}.2"), head_copied: 15, at: staged_at })),
            "the premise: the marker inherited, stamped at the stage"
        );
        let rows = dialer.world().rows.len();
        dialer.clear();
        let err = undo(&board, merger(&session, &signer), &a(&t), &a(K), None).expect_err("inherited");
        assert_eq!(err, Refusal::NothingToUndo { draft: a(&t), why: NoUndo::Inherited });
        assert_eq!(err.to_string(), format!("nothing to undo: {t} inherited the merge when it was staged; discard it or edit it"));
        assert_eq!(dialer.positions("doc_metadata"), [staged_at - 1, before_stage], "at − 1 inside the stage's commit, then nearest, where the alternative is unregistered: {:?}", dialer.ops());
        assert!(dialer.positions("image").is_empty(), "nothing imaged");
        assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty(), "nothing sent: {:?}", dialer.ops());
        assert_eq!(dialer.world().rows.len(), rows);
    }

    /// NO BASE RECORD (N4's baseless case): the landing's position is the
    /// draft's own latest `set_arrangement` row on the supplement that
    /// carries a `merge` term — the request's merge beside a null base, the
    /// row being the one place the board keeps a baseless landing's
    /// position (wire.md §The change feed; skep #784) — and the undo sends C
    /// read before it with no `base`, no `head` and no `merge`, `as_of` the
    /// row's `at`. A re-run finds the landing's row again: in the same
    /// session the board answers the ids again, the same undo with nothing
    /// written twice; in a fresh session it is refused `arrangement_moved`
    /// by the board, nothing committed.
    #[test]
    fn undo_of_a_baseless_landing_goes_by_its_feed_row_with_no_base_sent() {
        let plain = "1.0.1.0.5";
        let mut w = draft_landing_world();
        w.doc(plain, false, ACCOUNT, vec![run(D, 1, 11)]);
        let (dialer, board, signer) = open(w);
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
        let before = dialer.world().position;
        let landed = land(&board, &merged, draft_landing(&session, &signer, Some(a(plain)))).expect("landed");
        let (at, link) = landing_of(&landed);
        assert_eq!(at, before + 2, "the premise: a baseless landing is one commit of two records, the removal and the placement");
        let feed_row = |w: &World| w.rows.iter().rev().find(|r| r.op == "set_arrangement").map(|r| (r.at, r.terms.clone())).expect("the row");
        assert_eq!(
            feed_row(&dialer.world()),
            (at, Some((None, Some(json!({"sides": [S], "head": format!("{D}.2")}))))),
            "the premise: the landing's row, the request's merge beside no base"
        );
        assert_eq!(dialer.world().standing(plain), (None, None), "the premise: nothing recorded");
        dialer.clear();
        let undone = undo(&board, merger(&session, &signer), &a(plain), &a(K), None).expect("undone");
        let ops = dialer.ops();
        assert!(ops.iter().any(|o| o.starts_with("GET /changes?") && o.contains(&format!("under={plain}")) && o.contains("drafts=true")), "the lookup walks the draft's own rows on the supplement: {ops:?}");
        assert_eq!(undone.restored, None, "no base to restore");
        assert!(undone.record.is_some(), "the landing's record stood, so one replaces it");
        assert_eq!(dialer.positions("doc_metadata"), [at - 1, before], "the pre-landing read at nearest");
        let frame = &dialer.frames("set_arrangement")[0];
        assert_eq!(frame["as_of"].as_u64(), Some(at), "the row's at");
        assert_eq!(frame["runs"], frame_runs(&[run(D, 1, 11)]), "C");
        assert!(frame.get("base").is_none() && frame.get("head").is_none() && frame.get("merge").is_none(), "a baseless document is never sent a base: {frame}");
        assert_eq!(frame["id"].as_str(), Some(format!("undo:{plain}:{at}.arrangement").as_str()));
        let w = dialer.world();
        assert_eq!(w.docs.get(plain).unwrap().runs, vec![run(D, 1, 11)]);
        assert_eq!(w.standing(plain), (None, None), "nothing recorded");
        assert_eq!(feed_row(&w), (undone.position, Some((None, None))), "the undo's row, both terms null");
        drop(w);
        let atom = appended_record(&dialer);
        assert!(atom["landed"].is_null());
        assert_eq!(atom["replaces"].as_str(), Some(link.to_string().as_str()));
        // A re-run finds the landing's row again. In the same session the
        // board answers the ids again — the same undo, nothing written
        // twice; in a fresh session the write is refused by the board, the
        // arrangement having moved at the undo, nothing committed.
        let rows = dialer.world().rows.len();
        dialer.clear();
        assert_eq!(undo(&board, merger(&session, &signer), &a(plain), &a(K), None), Ok(undone.clone()), "the memo's answer");
        assert_eq!(dialer.world().rows.len(), rows, "nothing written twice");
        dialer.world().memo.clear();
        dialer.clear();
        let err = undo(&board, merger(&session, &signer), &a(plain), &a(K), None).expect_err("the undo moved the arrangement");
        let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
        assert_eq!(refused.code, "arrangement_moved");
        assert_eq!(dialer.world().rows.len(), rows, "nothing committed");
        assert!(dialer.frames("insert").is_empty());
    }

    /// THE PRE-LANDING POSITION RECLAIMED: the journal's floor stands at the
    /// landing, so `nearest` lies below it; the read there is
    /// `history_reclaimed`, typed as the refusal — the state before the merge
    /// is no longer on this board — with nothing sent and nothing read at
    /// another position.
    #[test]
    fn undo_where_the_pre_landing_position_is_reclaimed_is_refused_with_nothing_sent() {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let before = dialer.world().position;
        let (_, landed) = landed_in_s(&board, &session, &signer);
        let (at, _) = landing_of(&landed);
        dialer.world().floor = Some(at);
        let rows = dialer.world().rows.len();
        dialer.clear();
        assert_eq!(
            undo(&board, merger(&session, &signer), &a(S), &a(K), None),
            Err(Refusal::HistoryReclaimed { at: before, floor: Some(at) }),
            "the position before the landing, reclaimed"
        );
        assert_eq!(dialer.positions("doc_metadata"), [at - 1, before], "at − 1 inside the commit, then nearest, reclaimed: {:?}", dialer.ops());
        assert!(dialer.positions("image").is_empty(), "nothing read elsewhere");
        assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty(), "nothing sent: {:?}", dialer.ops());
        assert_eq!(dialer.world().rows.len(), rows);
        assert_eq!(dialer.world().standing(S).1.map(|m| m.at), Some(at), "the marker stands");
    }

    /// THE PRE-LANDING READ GOES TO `nearest`, NEVER TO `at − 1` ITSELF: the
    /// world answers `not_a_position` at `at − 1`, naming the position
    /// before the landing's commit, and every read of the state before the
    /// merge is made there — the metadata, the extent and the image — so
    /// the write carries C as it stood then, never M.
    #[test]
    fn the_pre_landing_read_goes_to_nearest_never_to_at_minus_one_itself() {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let before = dialer.world().position;
        let (_, landed) = landed_in_s(&board, &session, &signer);
        let (at, _) = landing_of(&landed);
        {
            let w = dialer.world();
            assert!(w.inside_commits.contains(&(at - 1)) && w.inside_commits.contains(&(at - 2)), "the premise: the numbers inside the landing's commit");
            assert!(!w.inside_commits.contains(&before));
        }
        dialer.clear();
        undo(&board, merger(&session, &signer), &a(S), &a(K), None).expect("undone");
        let asked: Vec<u64> = dialer.served.lock().unwrap().iter().filter(|(line, _)| line.starts_with("at:")).map(|(_, f)| f["at"].as_u64().unwrap()).collect();
        assert_eq!(asked, [at - 1, before, before, before], "doc_metadata at at − 1, then doc_metadata, the span set and the image at nearest: {:?}", dialer.ops());
        assert_eq!(dialer.frames("set_arrangement")[0]["runs"], frame_runs(&draft_c()), "C as it stood at nearest, never M");
    }

    /// THE WITHDRAWAL (ruled 1 (a); skep #783): the draft's `doc_metadata`
    /// read live, its image at THAT read's position through `/op-at`, and
    /// ONE `set_arrangement` — the current image as the runs, `as_of` the
    /// read's position, the recorded base re-sent unmoved (address and
    /// extent as read), no `head`, no `merge`, the id naming the draft and
    /// the position — so the marker is cleared and the draft's words and
    /// base stay as they are; the replacing record follows.
    #[test]
    fn the_withdrawal_clears_the_marker_and_keeps_the_runs_and_the_base_in_one_frame() {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let (_, landed) = landed_in_s(&board, &session, &signer);
        let (at, link) = landing_of(&landed);
        let read_at = dialer.world().position;
        dialer.clear();
        let withdrawn = withdraw(&board, merger(&session, &signer), &a(S), &a(K), None).expect("withdrawn");
        assert_eq!(withdrawn.draft, a(S));
        assert!(withdrawn.position > at);
        let replacing = withdrawn.record.clone().expect("a record stood, so one replaces it");
        assert_ne!(replacing, link);
        assert_eq!(dialer.positions("retrieve_doc_v_span_set"), [read_at], "the image at the metadata read's position");
        assert_eq!(dialer.positions("image"), [read_at]);
        assert!(dialer.positions("doc_metadata").is_empty(), "the metadata read live, at the head: {:?}", dialer.ops());
        let frames = dialer.frames("set_arrangement");
        assert_eq!(frames.len(), 1, "one write: {:?}", dialer.ops());
        let frame = &frames[0];
        assert_eq!(frame["doc"], S);
        assert_eq!(frame["as_of"].as_u64(), Some(read_at), "typed against the read's position: {frame}");
        assert_eq!(frame["runs"], frame_runs(&draft_m()), "the current image, M, sent back whole");
        assert_eq!(frame["base"], json!({"at": format!("{D}.2"), "extent": "15"}), "the recorded base re-sent unmoved");
        assert!(frame.get("head").is_none() && frame.get("merge").is_none(), "no head, no merge: {frame}");
        assert_eq!(frame["id"].as_str(), Some(format!("withdraw:{S}:{read_at}.arrangement").as_str()));
        let w = dialer.world();
        assert_eq!(w.docs.get(S).unwrap().runs, draft_m(), "the words stay");
        assert_eq!(w.standing(S), (Some((format!("{D}.2"), 15)), None), "the base stays, the marker cleared");
        let row = w.rows.iter().rev().find(|r| r.op == "set_arrangement").expect("the withdrawal's row");
        assert_eq!((row.at, &row.terms), (withdrawn.position, &Some((Some(format!("{D}.2")), None))));
        drop(w);
        let atom = appended_record(&dialer);
        assert!(atom["landed"].is_null());
        assert_eq!(atom["replaces"].as_str(), Some(link.to_string().as_str()));
        assert_eq!(dialer.frames("insert")[0]["id"].as_str(), Some(format!("withdraw:{S}:{read_at}.record").as_str()));
        assert_eq!(dialer.frames("make_link")[0]["to"]["addrs"], json!([S]));
    }

    /// AN EDIT BETWEEN THE WITHDRAWAL's READ AND ITS WRITE: another hand's
    /// edit lands before the one write is answered, so the write, typed
    /// against the read's position, is refused `arrangement_moved` — the
    /// draft as the other hand left it, the marker standing, nothing
    /// committed but the edit, no record.
    #[test]
    fn the_withdrawal_is_refused_arrangement_moved_after_an_edit_since_its_read() {
        // The place of the one write among a withdrawal's requests, off one
        // that lands.
        let n = {
            let (dialer, board, signer) = open(draft_landing_world());
            let session = sign_in(&board, &signer);
            landed_in_s(&board, &session, &signer);
            dialer.clear();
            withdraw(&board, merger(&session, &signer), &a(S), &a(K), None).expect("withdrawn");
            dialer.served_index("set_arrangement")
        };
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let (_, landed) = landed_in_s(&board, &session, &signer);
        let (at, _) = landing_of(&landed);
        let edited = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)];
        let (rows, read_at) = {
            let w = dialer.world();
            (w.rows.len(), w.position)
        };
        dialer.clear();
        dialer.world().interleave = Some((n, S.to_string(), edited.clone()));
        let err = withdraw(&board, merger(&session, &signer), &a(S), &a(K), None).expect_err("the draft changed since the read");
        assert!(dialer.world().interleave.is_none(), "the premise: the edit landed before the write was answered");
        let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
        assert_eq!(refused.code, "arrangement_moved");
        let detail = refused.detail.as_deref().expect("the person's words");
        assert!(detail.contains(S) && detail.contains("changed since it was read") && detail.contains("nothing was changed"), "{detail}");
        let frame = &dialer.frames("set_arrangement")[0];
        assert_eq!(frame["as_of"].as_u64(), Some(read_at), "typed against the read's position: {frame}");
        assert_eq!(frame["runs"], frame_runs(&draft_m()), "the image as read");
        let w = dialer.world();
        assert_eq!(w.docs.get(S).unwrap().runs, edited, "the other hand's edit stands");
        assert_eq!(w.rows.len(), rows + 1, "the edit's commit alone");
        assert_eq!(w.standing(S), (Some((format!("{D}.2"), 15)), Some(Marker { sides: vec![], head: format!("{D}.2"), head_copied: 15, at })), "the marker stands");
        drop(w);
        assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(), "no record");
    }

    /// NO MARKER: a withdrawal of a draft carrying no merge has nothing to
    /// take out, with nothing sent — the one read is the draft's metadata.
    #[test]
    fn the_withdrawal_at_no_marker_answers_nothing_to_take_out() {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let rows = dialer.world().rows.len();
        dialer.clear();
        let err = withdraw(&board, merger(&session, &signer), &a(S), &a(K), None).expect_err("no merge");
        assert_eq!(err, Refusal::NoMerge { draft: a(S) });
        assert_eq!(err.to_string(), format!("{S} carries no merge: nothing to undo, nothing to take out"));
        assert_eq!(dialer.ops(), ["doc_metadata"], "the one read, at the head; nothing sent");
        assert_eq!(dialer.world().rows.len(), rows);
    }

    /// THE RECORD (the operator's choice): each call writes a record
    /// composed from the current one naming the draft as landed in —
    /// `landed` none, `replaces` its link, the sides and the base the
    /// landing's — and writes none where none stands, the act standing all
    /// the same: a landing made by hand with no record is undone and
    /// withdrawn with no `insert` and no `make_link`, the links of the kind
    /// to the draft read first.
    #[test]
    fn each_call_writes_the_replaces_record_where_a_record_stands_and_none_where_none_stands() {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let m = merger(&session, &signer);
        let (merged, landed) = landed_in_s(&board, &session, &signer);
        let (_, link) = landing_of(&landed);
        dialer.clear();
        let withdrawn = withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn");
        let atom = appended_record(&dialer);
        let landing_record = merged.record.to_value();
        assert!(atom["landed"].is_null() && landing_record["landed"].is_null(), "{atom}");
        assert_eq!(atom["replaces"].as_str(), Some(link.to_string().as_str()), "the landing's link replaced");
        for member in ["type", "v", "doc", "base", "sides", "runs", "gaps", "values"] {
            assert_eq!(atom[member], landing_record[member], "`{member}` the landing's: {atom}");
        }
        let links = dialer.frames("make_link");
        assert_eq!(links[0]["to"]["addrs"], json!([S]), "linked to the draft");
        assert!(withdrawn.record.is_some(), "the link written is answered");
        assert!(links[0]["attest"]["sig"].is_string(), "signed over the head: {}", links[0]);
        // A landing by hand on a board holding no record of the kind: the
        // undo and the withdrawal write none, the links of the kind to the
        // draft read first.
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let m = merger(&session, &signer);
        let head = format!("{D}.2");
        for (act, name) in [("undo", "the undo"), ("withdraw", "the withdrawal")] {
            let typed = dialer.world().position;
            let frame = frames::set_arrangement(S, &shot_runs(&draft_m()), typed, Some((&head, 15)), Some((&head, 15)), Some(&[]), None);
            let Answer::Document(ack) = board.op(Some(session.token()), &frame).expect("the landing by hand") else { panic!("closed") };
            assert_eq!(ack["resp"], "ack", "{name}: {ack}");
            assert!(dialer.world().standing(S).1.is_some(), "{name}: the premise, the marker stands");
            let rows = dialer.world().rows.len();
            dialer.clear();
            let record = match act {
                "undo" => undo(&board, m, &a(S), &a(K), None).expect("undone").record,
                _ => withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn").record,
            };
            assert_eq!(record, None, "{name}: no record stood, none written");
            assert!(dialer.frames("set_arrangement").len() == 1, "{name}: the act stands: {:?}", dialer.ops());
            assert!(dialer.ops().contains(&"find_links_ftt".to_string()), "{name}: the links of the kind to the draft read: {:?}", dialer.ops());
            assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty() && dialer.frames("create_new_document").is_empty(), "{name}: nothing of a record: {:?}", dialer.ops());
            assert_eq!(dialer.world().rows.len(), rows + 1, "{name}: the one write alone");
            assert!(dialer.world().standing(S).1.is_none(), "{name}: the marker cleared");
        }
    }

    /// A RE-RUN OF EITHER WRITES NOTHING TWICE: after an undo the draft
    /// records a base and no marker, and its latest marker-ending row is
    /// the undo's — nothing to undo, the merge already taken back; after a
    /// withdrawal the draft carries no marker — nothing to take out. Each
    /// re-run sends nothing and commits nothing.
    #[test]
    fn a_re_run_of_either_take_back_writes_nothing_twice() {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let m = merger(&session, &signer);
        landed_in_s(&board, &session, &signer);
        undo(&board, m, &a(S), &a(K), None).expect("undone");
        let rows = dialer.world().rows.len();
        dialer.clear();
        let err = undo(&board, m, &a(S), &a(K), None).expect_err("already taken back");
        assert_eq!(err, Refusal::NothingToUndo { draft: a(S), why: NoUndo::TakenBack });
        assert_eq!(err.to_string(), format!("nothing to undo: the merge in {S} was already taken back"));
        assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty(), "nothing sent: {:?}", dialer.ops());
        assert!(dialer.positions("doc_metadata").is_empty(), "no read of history");
        assert_eq!(dialer.world().rows.len(), rows, "nothing written twice");
        // Landed again in a fresh session — the memo answers the first
        // landing's id in this one — and withdrawn: a second withdrawal
        // finds no merge.
        dialer.world().memo.clear();
        landed_in_s(&board, &session, &signer);
        withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn");
        let rows = dialer.world().rows.len();
        dialer.clear();
        assert_eq!(withdraw(&board, m, &a(S), &a(K), None), Err(Refusal::NoMerge { draft: a(S) }));
        assert_eq!(undo(&board, m, &a(S), &a(K), None), Err(Refusal::NothingToUndo { draft: a(S), why: NoUndo::TakenBack }), "an undo after a withdrawal: taken back");
        assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty(), "{:?}", dialer.ops());
        assert_eq!(dialer.world().rows.len(), rows, "nothing written twice");
    }

    /// Every refusal the one write can answer, each mapped (item 4):
    /// `not_owner` naming the draft, `published_target`, `withheld` naming
    /// the origin, `signed_session_required`, `doc_not_registered` naming
    /// the draft; `source_not_registered`, `no_base_to_record`,
    /// `base_not_in_chain`, `base_extent_too_large` and the runs' codes as
    /// the library's own faults, since it sends only the base and the runs
    /// it read; the board's others verbatim — and nothing after the
    /// refusal. A published document is refused at the metadata read, before
    /// any position is read.
    #[test]
    fn the_take_backs_refusals_are_mapped() {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let m = merger(&session, &signer);
        let (_, landed) = landed_in_s(&board, &session, &signer);
        let (at, _) = landing_of(&landed);
        let rows = dialer.world().rows.len();
        let id = format!("undo:{S}:{at}.arrangement");
        let refused = |code: &str, site: Option<&str>| -> Refusal {
            let site = site.map_or(Value::Null, |s| json!({"addr": s}));
            dialer.world().memo.insert(id.clone(), permanent("set_arrangement", code, site));
            dialer.clear();
            let err = undo(&board, m, &a(S), &a(K), None).expect_err(code);
            assert_eq!(dialer.ops().last().map(String::as_str), Some("set_arrangement"), "{code}: nothing after the refusal: {:?}", dialer.ops());
            assert_eq!(dialer.world().rows.len(), rows, "{code}: nothing committed");
            err
        };
        assert_eq!(refused("not_owner", Some(S)), Refusal::NotOwner { draft: a(S) });
        assert_eq!(refused("published_target", None), Refusal::Published { doc: a(S) });
        assert_eq!(refused("withheld", Some(Z)), Refusal::WindowWithheld(a(Z)));
        assert_eq!(refused("signed_session_required", None), Refusal::NeedsSignedSession);
        assert_eq!(refused("doc_not_registered", None), Refusal::NoSuchDocument(a(S)));
        for code in ["source_not_registered", "no_base_to_record", "base_not_in_chain", "base_extent_too_large", "fork_base_moved", "bad_run", "dangling_source", "too_many_runs", "malformed"] {
            let err = refused(code, None);
            let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{code}: {err:?}") };
            assert!(face.cause.contains(code) && face.act.contains("fault in this library"), "{code}: {face}");
        }
        let err = refused("txn_over_budget", None);
        let Refusal::Halt(Halt::Refused(verbatim)) = &err else { panic!("{err:?}") };
        assert_eq!(verbatim.code, "txn_over_budget");
        let said = Refusal::NotOwner { draft: a(S) }.to_string();
        assert!(said.contains("not_owner") && said.contains("nothing was changed"), "{said}");
        // A published document: refused at the metadata read.
        dialer.world().docs.get_mut(S).unwrap().published = true;
        dialer.clear();
        assert_eq!(undo(&board, m, &a(S), &a(K), None), Err(Refusal::Published { doc: a(S) }));
        assert_eq!(withdraw(&board, m, &a(S), &a(K), None), Err(Refusal::Published { doc: a(S) }));
        assert_eq!(dialer.ops(), ["doc_metadata", "doc_metadata"], "the one read each, nothing sent");
    }

    /// A CLAIMED BOARD WHOSE HEAD IS OWED TAKES NOTHING BACK (SP-14; skep
    /// #729): `/health` names a claimant and `H.1` serves no record — read
    /// afresh, since a board keeps the head it read — so the undo and the
    /// withdrawal each halt naming `H.1` before the one write: the reads
    /// made, no `set_arrangement`, no record, no commit.
    #[test]
    fn a_claimed_board_serving_no_head_record_takes_nothing_back() {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        landed_in_s(&board, &session, &signer);
        dialer.world().head = false;
        let afresh = Board::new(Origin::parse("http://127.0.0.1:8642").unwrap(), dialer.clone());
        let session = sign_in(&afresh, &signer);
        let m = merger(&session, &signer);
        let rows = dialer.world().rows.len();
        dialer.clear();
        for (name, err) in [("the undo", undo(&afresh, m, &a(S), &a(K), None).map(|_| ()).expect_err("the head is owed")), ("the withdrawal", withdraw(&afresh, m, &a(S), &a(K), None).map(|_| ()).expect_err("the head is owed"))] {
            let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{name}: {err:?}") };
            assert!(face.state.contains("H.1") && face.state.contains(S), "{name}: {face}");
            assert!(face.cause.contains(&format!("names {ACCOUNT} its claimant")), "{name}: {face}");
            assert!(face.act.contains("nothing was written"), "{name}: {face}");
        }
        for op in ["set_arrangement", "create_new_document", "insert", "make_link"] {
            assert!(dialer.frames(op).is_empty(), "no `{op}`: {:?}", dialer.ops());
        }
        assert_eq!(dialer.world().rows.len(), rows, "no commit");
        assert!(dialer.world().standing(S).1.is_some(), "the marker stands");
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
        let ops = dialer.names();
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

    /// A withheld input withholds the verdict; an unregistered one is refused.
    ///
    /// The race shape landed by a shot verifies Equal; with the trunk, the
    /// head, the base or the daughter withheld alone, `verify` answers
    /// Unreadable naming it. A grant withdrawn between the daughter's image
    /// and the join's `compare` refuses the compare naming the daughter in
    /// its `site.addr`, and the verdict names the daughter, not the base the
    /// compare's first region holds. A side the board has never registered
    /// is no withheld document: it is refused `NoSuchDocument` (merge record
    /// §4, testimony; D14; wire.md §The read predicate).
    #[test]
    fn a_withheld_input_withholds_the_verdict_and_an_unregistered_one_is_refused() {
        let (dialer, board, signer) = open(World::race());
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
        land(&board, &merged, shot(&session, &signer)).expect("landed");
        let record = current(&board, Some(&token()), &a(K), &merged.key)
            .expect("the lookup")
            .expect("the record");
        dialer.clear();
        assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal), "the premise");
        let compare_at = dialer
            .served
            .lock()
            .unwrap()
            .iter()
            .position(|(line, _)| line == "at:compare")
            .expect("the join's compare");
        let daughter = format!("{D}.1.1");
        for hidden in [D.to_string(), format!("{D}.2"), format!("{D}.1"), daughter.clone()] {
            dialer.world().withheld = BTreeSet::from([hidden.clone()]);
            assert_eq!(
                verify(&board, Some(&token()), &record),
                Ok(Verdict::Unreadable(a(&hidden))),
                "{hidden} withheld"
            );
        }
        // The daughter's grant withdrawn after its image, before the compare.
        dialer.world().withheld.clear();
        dialer.world().withhold = Some((compare_at + 1, daughter.clone()));
        dialer.clear();
        assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Unreadable(a(&daughter))));
        assert!(dialer.world().withhold.is_none(), "the grant withdrawn mid-walk");
        let ops = dialer.ops();
        assert!(
            dialer.frames("image").iter().any(|f| f["d"].as_str() == Some(daughter.as_str())),
            "the daughter imaged before its grant was withdrawn: {ops:?}"
        );
        assert_eq!(
            ops.last().map(String::as_str),
            Some("at:compare"),
            "the refused compare is the last read: {ops:?}"
        );
        // A side the board has never registered: refused, no verdict.
        dialer.world().withheld.clear();
        assert_eq!(record.sides[1], SideAt::Member { at: a(&daughter), role: Role::Alternative });
        let unregistered = a(&format!("{D}.1.7"));
        let mut naming = record.clone();
        naming.sides[1] = SideAt::Member { at: unregistered.clone(), role: Role::Alternative };
        assert_eq!(
            verify(&board, Some(&token()), &naming),
            Err(Refusal::NoSuchDocument(unregistered))
        );
    }

    /// A gap of two groups the merger moved lands, and its record verifies.
    ///
    /// The race shape with a second daughter adding "fat " at `D·4|D·5`:
    /// the merger moves the order gap after `D·11`, so M is one run; the
    /// record read back holds the gap where M holds it and re-states the
    /// move, so `verify` composes the landed M again and answers `Equal`
    /// (merge record §4).
    #[test]
    fn a_moved_gap_of_two_groups_lands_and_verifies_equal() {
        let mut w = World::race();
        w.text(D, 16, "fat ");
        w.member(&format!("{D}.1.2"), vec![run(D, 1, 4), run(D, 16, 4), run(D, 5, 7)], Some(11));
        let (_, board, signer) = open(w);
        let session = sign_in(&board, &signer);
        let end = a(&format!("{D}.0.1.11"));
        let inputs = Inputs {
            sides: vec![Side::Member(a(&format!("{D}.1.2")))],
            options: Options {
                resolutions: vec![Resolution {
                    gap: GapId(1),
                    choice: Choice::After(end.clone()),
                    by: ResolvedBy::Person,
                }],
                ..Options::default()
            },
            ..race_inputs()
        };
        let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
        assert!(merged.composed.ignored.is_empty(), "{:?}", merged.composed.ignored);
        assert_eq!(m_runs(&merged), vec![run(D, 1, 19)], "the cat satbig fat ");
        land(&board, &merged, shot(&session, &signer)).expect("landed");
        let record = current(&board, Some(&token()), &a(K), &merged.key)
            .expect("the lookup")
            .expect("the record");
        let gap = &record.gaps[0];
        assert_eq!(
            (gap.kind, gap.after.clone(), gap.before.clone()),
            (GapKind::Order, Some(end), None),
            "the gap where M holds it"
        );
        assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal));
    }

    /// The `Record` round-trips through its JSON, its `type` fixed `merge`.
    ///
    /// Its gaps keep their runs and the resolutions they re-state, a draft
    /// side and a draft landing included; an object of another type or
    /// version is no record.
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
        let answer = ResolvedBy::Answer(a(&format!("{DOC1}.0.1.7")));
        assert_eq!(
            back.options().resolutions,
            vec![
                Resolution {
                    gap: GapId(1),
                    choice: Choice::After(a(&format!("{D}.0.1.4"))),
                    by: ResolvedBy::Agent
                },
                Resolution {
                    gap: GapId(1),
                    choice: Choice::Order(vec![SideIx(1), SideIx(0)]),
                    by: ResolvedBy::Agent
                },
                Resolution {
                    gap: GapId(2),
                    choice: Choice::Before(a(&format!("{D}.0.1.1"))),
                    by: answer.clone()
                },
                Resolution { gap: GapId(2), choice: Choice::Omit, by: answer }
            ],
            "each gap a merger settled re-stated as its place, then its placement"
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
