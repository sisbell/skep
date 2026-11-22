//! The merge's unit suite: the merge record's §9 vectors, each row one
//! test over `compose_runs` with the row's literal runs, asserting M as
//! runs, the gap kinds, the `settled` flags and the value log as the table
//! stands after the rulings, beside a base of no positions, the base a side
//! begun before the first version was begun from and the document's chain
//! the order rule reads whatever the base holds; the resolutions, one per
//! unsettled kind; the
//! record's re-statement of them as a law over every place a gap is moved
//! to; the fences the module promises; the one rule as a property over
//! generated inputs; `base_of` over §1.2's address forms; `script` over
//! three pairs. No board: every value read is a closure over a table the
//! test writes.
//!
//! The notation is the record's: `(D,s,w)` is the run of `w` positions of
//! `D` from `D·s`; the base `D.2` is `[(D,1,11)]` "the cat sat" — `D·1–4`
//! "the ", `5–7` "cat", `8–11` " sat"; A's fresh identity takes `D·12…`,
//! B's the ordinals after it. `(T,s,w)` is a run of `T`, a trunk addressed
//! above `D`, in the cells where a window onto `D` meets the trunk's own
//! text.

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
    addr("1.0.1.0.64")
}

/// `F`, a cross-owner fork in another account.
fn f() -> Address {
    addr("1.0.2.0.1")
}

/// `T`, a trunk addressed above `D` and `Z`.
fn t() -> Address {
    addr("1.0.1.0.70")
}

/// `(D,s,w)`.
fn rd(s: u64, w: u64) -> Run {
    Run::new(d(), s, w)
}

/// `(T,s,w)`.
fn rt(s: u64, w: u64) -> Run {
    Run::new(t(), s, w)
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
    compose_runs(base, &d(), sides, None, &Options::default(), &unread)
}

/// Composes onto the trunk `T` under `values`, the defaults otherwise.
///
/// # Panics
///
/// Panics unless `D` is addressed below `T`: the premise of every cell that
/// windows `D` into `T`, without which the address order alone would put
/// `T`'s text first.
fn compose_t(
    base: &[Run],
    sides: &[(SideIx, Vec<Run>)],
    values: &dyn Fn(SideIx, &Run) -> Option<Vec<Item>>,
) -> Composed {
    assert!(d() < t(), "the premise: `D` is addressed below the trunk `T`");
    compose_runs(base, &t(), sides, None, &Options::default(), values)
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
    let c = compose_runs(&base(), &d(), &sides, None, &options, &values);
    assert_eq!(runs(&c), vec![rd(1, 5), rd(16, 1), rd(6, 6)], "the c-at sat");
    assert_eq!(kinds(&c), vec![]);
    assert_eq!(c.values, ValueLog { dedup: true, retype: true, applied: vec![] });
    // The retype is undone only where the bytes are equal.
    let other = text(&[(1, "the cat sat"), (12, "dog"), (16, "-")]);
    let c = compose_runs(&base(), &d(), &sides, None, &options, &other);
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
    let c = compose_runs(&base(), &d(), &sides, None, &Options::default(), &values);
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
    let c = compose_runs(&base(), &d(), &two(a.clone(), vec![rd(1, 4), rd(16, 4), rd(5, 7)]), None, &options, &values);
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 8), rd(5, 7)], "the big big cat sat");
    assert_eq!(kinds(&c), vec![(GapKind::Order, false)]);
    assert_eq!(c.values, ValueLog { dedup: false, retype: false, applied: vec![] });
    let c = compose_runs(&base(), &d(), &two(a, vec![rd(1, 4), rd(17, 4), rd(5, 7)]), None, &options, &values);
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
/// gone, settled; F's "dog" at its own spot, after A's by the base order of
/// their anchors (`D·5` before `D·8`). The fork's base is the reads' to
/// find (its served source); the core composes the pair as any.
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

/// A BASE OF NO POSITIONS (skep #1113): the document's own arrangement from
/// before its first version, empty on most documents, is the base of a side
/// begun then. The head's "the fox" (`D·1–7`) and the side's "the cat"
/// (`D·20–26`) both add at the one spot an empty spine has, between the
/// document's two ends: ONE `order` gap, unsettled, both kept, the head's
/// first.
#[test]
fn an_empty_base_takes_both_texts_in_one_order_gap() {
    let c = compose(&[], &two(vec![rd(1, 7)], vec![rd(20, 7)]));
    assert_eq!(runs(&c), vec![rd(1, 7), rd(20, 7)]);
    assert_eq!(kinds(&c), vec![(GapKind::Order, false)]);
    assert_eq!(anchors(&c), vec![(None, None)], "between the document's two ends");
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(0), SideIx(1)]));
}

/// THE DOCUMENT'S CHAIN over a base of no positions (skep #1115; R1): the
/// head's "the fox" (`T·1–7`), the trunk's own text, and the side's window
/// onto `D` both add at the one spot — the head's first, its text in the
/// chain whatever the base holds, where by address alone the window would
/// lead: ONE `order` gap, unsettled.
#[test]
fn an_empty_base_puts_the_documents_own_text_before_a_window_addressed_below_it() {
    let c = compose_t(&[], &two(vec![rt(1, 7)], vec![rd(1, 7)]), &unread);
    assert_eq!(runs(&c), vec![rt(1, 7), rd(1, 7)], "the trunk's text, then the window");
    assert_eq!(kinds(&c), vec![(GapKind::Order, false)]);
    assert_eq!(anchors(&c), vec![(None, None)], "between the document's two ends");
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(0), SideIx(1)]));
}

/// The same words on both sides over a base of no positions, dedup on
/// (skep #1115; §5 (g)): "the fox" kept once, the trunk's own identity —
/// the one already in the chain, the group R1 lists first — the gap
/// settled by the value rule and the window's copy listed, not placed.
#[test]
fn an_empty_base_keeps_the_documents_own_identity_where_a_window_says_the_same() {
    let fox = |_: SideIx, run: &Run| -> Option<Vec<Item>> {
        (run.i_start..run.reach())
            .map(|n| b"the fox".get(usize::try_from(n.checked_sub(1)?).ok()?).map(|b| vec![*b]))
            .collect()
    };
    let c = compose_t(&[], &two(vec![rt(1, 7)], vec![rd(1, 7)]), &fox);
    assert_eq!(runs(&c), vec![rt(1, 7)], "the fox, once");
    assert_eq!(kinds(&c), vec![(GapKind::Order, true)]);
    assert_eq!(c.gaps[0].resolved_by, Some(ResolvedBy::Rule));
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(0)]));
    assert_eq!(gap_runs(&c), vec![vec![(0, rt(1, 7)), (1, rd(1, 7))]], "the dropped copy is listed");
    assert_eq!(c.values.applied, vec![GapId(1)]);
}

/// The chain before the address (R1): over a base holding the trunk's
/// "the " (`T·1–4`), the head adds "fox" (`T·5–7`) and the side a window
/// onto `D` at the one spot after it — the head's first though `D` is
/// addressed below `T`, as the order rule reads whether a group's first run
/// is in the chain before it reads any address.
#[test]
fn the_order_rule_reads_the_chain_before_the_address() {
    let c = compose_t(&[rt(1, 4)], &two(vec![rt(1, 4), rt(5, 3)], vec![rt(1, 4), rd(1, 3)]), &unread);
    assert_eq!(runs(&c), vec![rt(1, 7), rd(1, 3)], "the fox, then the window");
    assert_eq!(kinds(&c), vec![(GapKind::Order, false)]);
    assert_eq!(anchors(&c), vec![(Some(4), None)]);
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(0), SideIx(1)]));
}

/// The document's own text is in the chain over a base holding none of it
/// (skep #1115; R1): the base is a window onto `Z` alone, the head adds the
/// trunk's own "fox" (`T·1–3`) after it and the side a window onto `D` at
/// the same spot — the head's first, `T` in the chain though no base run
/// names it.
#[test]
fn the_documents_own_text_is_in_the_chain_over_a_base_holding_none_of_it() {
    let hello = Run::new(z(), 1, 5);
    let sides = two(vec![hello.clone(), rt(1, 3)], vec![hello.clone(), rd(1, 3)]);
    let c = compose_t(std::slice::from_ref(&hello), &sides, &unread);
    assert_eq!(runs(&c), vec![hello, rt(1, 3), rd(1, 3)], "the base's window, the trunk's text, the side's window");
    assert_eq!(kinds(&c), vec![(GapKind::Order, false)]);
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(0), SideIx(1)]));
}

/// THE BASE A SIDE WAS BEGUN FROM decides whether a removal stands (skep
/// #1113; the arrangement suite's shape, `stage.rs`'s): `D` held "abcz"
/// (`D·1–4`) before its first version, version 1 is "abc", and the
/// daughter begun from `D` "abcwz" (`w` at `D·5`). Over "abcz" M is "abcw":
/// the head's removal of "z" stands, the "w" placed beside the surviving
/// "c" by the rules. Over "abc" — the base the daughter's address names —
/// "z" reads as the daughter's addition and comes back: "abcwz".
#[test]
fn the_base_a_side_was_begun_from_decides_whether_a_removal_stands() {
    let (head, daughter) = (vec![rd(1, 3)], vec![rd(1, 3), rd(5, 1), rd(4, 1)]);
    let c = compose(&[rd(1, 4)], &two(head.clone(), daughter.clone()));
    assert_eq!(runs(&c), vec![rd(1, 3), rd(5, 1)], "abcw");
    assert_eq!(kinds(&c), vec![(GapKind::Anchor, true)]);
    let by_address = compose(&[rd(1, 3)], &two(head, daughter));
    assert_eq!(runs(&by_address), vec![rd(1, 3), rd(5, 1), rd(4, 1)], "abcwz");
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
    let c = compose_runs(&base(), &d(), &sides, Some(SideIx(1)), &Options::default(), &unread);
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
    let c = compose_runs(&base(), &d(), &sides, None, &options, &unread);
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
    let c = compose_runs(&base(), &d(), &sides, None, &resolve(1, Choice::KeepOnly(SideIx(1))), &unread);
    assert_eq!(runs(&c), vec![rd(1, 4), rd(16, 6), rd(8, 4)], "the kitten sat");
    assert_eq!(kinds(&c), vec![(GapKind::Collision, true)]);
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(1)]));
    assert_eq!(c.gaps[0].resolved_by, Some(ResolvedBy::Person));
    let c = compose_runs(&base(), &d(), &sides, None, &resolve(1, Choice::KeepBoth), &unread);
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 3), rd(16, 6), rd(8, 4)]);
    assert_eq!(kinds(&c), vec![(GapKind::Collision, true)]);
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(0), SideIx(1)]));
}

/// A `cut` resolved `Before(D·5)`: "fat " placed where the writer meant
/// it, before the moved "cat sat".
#[test]
fn a_cut_takes_a_before_placement() {
    let sides = two(vec![rd(5, 7), rd(1, 4)], vec![rd(1, 4), rd(12, 4), rd(5, 7)]);
    let c = compose_runs(&base(), &d(), &sides, None, &resolve(1, Choice::Before(d_at(5))), &unread);
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
    let c = compose_runs(&base(), &d(), &sides, None, &resolve(1, Choice::Omit), &unread);
    assert_eq!(runs(&c), vec![rd(1, 4)], "the ");
    assert_eq!(kinds(&c), vec![(GapKind::Corner, true)]);
    assert_eq!(c.gaps[0].placed, Placement::Omitted);
    assert_eq!(gap_runs(&c), vec![vec![(0, rd(12, 1))]], "the omitted run stays listed");
    assert_eq!(c.gaps[0].resolved_by, Some(ResolvedBy::Person));
    let c = compose_runs(&base(), &d(), &sides, None, &resolve(1, Choice::Before(d_at(1))), &unread);
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
    let c = compose_runs(&[rd(1, 3)], &d(), &sides, None, &options, &unread);
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
    let c = compose_runs(&base(), &d(), &sides, None, &options, &unread);
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 4), rd(8, 4)], "unchanged");
    assert_eq!(kinds(&c), vec![(GapKind::Anchor, true)]);
    assert_eq!(c.gaps[0].resolved_by, Some(ResolvedBy::Rule));
    assert_eq!(c.ignored, vec![on_settled, unknown]);
    // A choice the kind cannot take: `KeepBoth` at a one-sided corner.
    let sides = two(vec![rd(1, 6), rd(12, 1), rd(7, 5)], vec![rd(1, 4)]);
    let c = compose_runs(&base(), &d(), &sides, None, &resolve(1, Choice::KeepBoth), &unread);
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
        let c = compose_runs(&base(), &d(), &sides, None, &Options { resolutions, ..Options::default() }, &unread);
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
        answers: Vec::new(),
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
                    let first = compose_runs(&base(), &d(), sides, None, &options, &unread);
                    let again = compose_runs(&base(), &d(), sides, None, &recorded(&first).options(), &unread);
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
        ("g", compose_runs(&base(), &d(), &two(a(), vec![rd(1, 4), rd(16, 4), rd(5, 7)]), None, &Options::default(), &same)),
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
    assert_eq!(base_of(&m("2"), &addr("1.0.1.0.64.2")), None, "across chains");
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

/// The two `withheld` refusals name the document and the code alone, the
/// same words at every act that returns them (SP-10): `Unreadable` answers
/// the composition, the shot's value reads, the draft landing's read of its
/// draft and the take-backs' reads; `WindowWithheld` the shot's, the draft
/// landing's and the take-backs' writes. Neither says what the act did,
/// which the embedder says.
#[test]
fn the_withheld_refusals_name_the_document_and_leave_the_outcome_to_the_embedder() {
    let doc = addr("1.0.2.0.70");
    let unreadable = Refusal::Unreadable(doc.clone()).to_string();
    assert_eq!(unreadable, "1.0.2.0.70 is not readable to this reader (withheld)");
    let windowed = Refusal::WindowWithheld(doc).to_string();
    assert!(windowed.starts_with("1.0.2.0.70 is not shared with you (withheld)"), "{windowed}");
    for said in [&unreadable, &windowed] {
        for outcome in ["nothing", "composed", "published", "shot", "merged"] {
            assert!(!said.contains(outcome), "`{outcome}`: {said}");
        }
    }
}

// ── the draft's kept places (`windows::kept_places`) ─────────────────────

mod kept_places {
    use super::super::windows::{kept_places, AnsweredRun};
    use super::*;
    use crate::board::answers::IRun;

    fn s() -> Address {
        addr("1.0.1.0.66")
    }

    fn o() -> Address {
        addr("1.0.1.0.67")
    }

    /// A run of the draft's own words, as the shot re-mints it.
    fn native(first: u64, width: u64) -> AnsweredRun {
        let run = Run::new(s(), first, width);
        AnsweredRun { run: run.clone(), family: Family::DraftNative, side: None, through: run }
    }

    /// A part answered by its counterpart: `width` published words of `d`
    /// from `to`, whose words the draft holds as a window onto `O` from
    /// `from`.
    fn counterpart(to: u64, from: u64, width: u64) -> AnsweredRun {
        AnsweredRun {
            run: Run::new(d(), to, width),
            family: Family::Own,
            side: None,
            through: Run::new(o(), from, width),
        }
    }

    /// One stretch of the draft's image: `width` of its own words from
    /// `first`, arranged at `ordinal`.
    fn held(first: u64, width: u64, ordinal: u64) -> IRun {
        IRun { prefix: format!("{}.0.1", s()), first, width, ordinal }
    }

    fn held_of_o(first: u64, width: u64, ordinal: u64) -> IRun {
        IRun { prefix: format!("{}.0.1", o()), first, width, ordinal }
    }

    #[test]
    fn a_run_the_draft_holds_whole_takes_its_one_place() {
        assert_eq!(
            kept_places(&[native(1, 3)], Some(&[held(1, 3, 12)])),
            vec![(native(1, 3), Some(12))]
        );
    }

    /// Cut where the draft cuts it, tiled in I-order, each piece at its own
    /// place, whatever order the draft arranges the pieces in.
    #[test]
    fn a_run_the_draft_cuts_is_tiled_in_i_order_each_piece_at_its_own_place() {
        let image = [held(3, 2, 1), held(1, 2, 3)];
        assert_eq!(
            kept_places(&[native(1, 4)], Some(&image)),
            vec![(native(1, 2), Some(3)), (native(3, 2), Some(1))]
        );
    }

    /// Words the draft does not arrange go with no place, the pieces around
    /// them each at theirs.
    #[test]
    fn words_the_draft_does_not_arrange_go_with_no_place() {
        assert_eq!(
            kept_places(&[native(1, 6)], Some(&[held(3, 2, 7)])),
            vec![(native(1, 2), None), (native(3, 2), Some(7)), (native(5, 2), None)]
        );
    }

    /// No place is named twice: a position of the draft an earlier piece
    /// named holds no later one, so a copy takes the draft's next occurrence
    /// and a copy past the draft's occurrences goes with no place.
    #[test]
    fn no_place_is_named_twice_and_a_copy_takes_the_next_occurrence() {
        let image = [held(1, 4, 1), held(1, 2, 10)];
        assert_eq!(
            kept_places(&[native(1, 2), native(1, 4)], Some(&image)),
            vec![(native(1, 2), Some(1)), (native(1, 2), Some(10)), (native(3, 2), Some(3))],
            "the later, wider run takes the rest of the first occurrence and the whole of the second"
        );
        assert_eq!(
            kept_places(&[native(1, 4), native(1, 2)], Some(&image)),
            vec![(native(1, 4), Some(1)), (native(1, 2), Some(10))],
            "the wider run first takes its occurrence whole"
        );
        assert_eq!(
            kept_places(&[native(1, 3), native(1, 3)], Some(&[held(1, 3, 5)])),
            vec![(native(1, 3), Some(5)), (native(1, 3), None)],
            "a copy the draft does not hold goes with no place"
        );
    }

    /// A part answered by its counterpart is cut where the draft cuts the
    /// window it stands for, the published words and the window's own span
    /// moving together.
    #[test]
    fn a_counterpart_part_is_cut_where_the_draft_cuts_its_window() {
        let part = counterpart(20, 1, 5);
        assert_eq!(
            kept_places(std::slice::from_ref(&part), Some(&[held_of_o(1, 5, 9)])),
            vec![(part.clone(), Some(9))]
        );
        assert_eq!(
            kept_places(
                std::slice::from_ref(&part),
                Some(&[held_of_o(1, 2, 9), held_of_o(3, 3, 40)])
            ),
            vec![(counterpart(20, 1, 2), Some(9)), (counterpart(22, 3, 3), Some(40))]
        );
    }

    /// A run that takes no place stands uncut, whatever the draft holds, and
    /// with no draft's image no run is cut or placed.
    #[test]
    fn a_run_that_takes_no_place_stands_uncut_and_no_image_cuts_nothing() {
        let trunk = AnsweredRun {
            run: Run::new(d(), 1, 4),
            family: Family::Own,
            side: None,
            through: Run::new(d(), 1, 4),
        };
        let window = AnsweredRun {
            run: Run::new(o(), 1, 4),
            family: Family::Window,
            side: None,
            through: Run::new(o(), 1, 4),
        };
        let image = [
            IRun { prefix: format!("{}.0.1", d()), first: 1, width: 2, ordinal: 1 },
            held_of_o(1, 2, 3),
        ];
        assert_eq!(
            kept_places(&[trunk.clone(), window.clone()], Some(&image)),
            vec![(trunk.clone(), None), (window.clone(), None)]
        );
        assert_eq!(
            kept_places(&[trunk.clone(), native(1, 2)], None),
            vec![(trunk, None), (native(1, 2), None)]
        );
    }
}

// ── THE READS, THE LANDING AND THE RECORD over a scripted board ──────────
//
// A `Dialer` whose answers come from a `World` the test writes — each
// document's arrangement and values, the links, the claims, the feed —
// keeping every frame it served, so a walk pins what the module reads and
// writes, in what order, and what it makes of each answer, with no daemon.
// The one whole merge against the daemon is `tests/it/merge.rs`.

// The scripted suite's session, named here for its files below:
// `tests/it/tidy.rs` exempts a test from the ceremony's layers only in a
// file named `tests.rs`.
use crate::ceremony::handshake::{handshake, Session, Site};

mod scripted;
