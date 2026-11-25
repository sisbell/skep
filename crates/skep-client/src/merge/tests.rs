//! The merge's unit suite: the merge record's §9 vectors, each row one
//! test over `compose_runs` with the row's literal runs, asserting M as
//! runs, the gap kinds, the `settled` flags and the value log as the table
//! stands after the rulings, beside a base of no positions, the base a side
//! begun before the first version was begun from and the document's chain
//! the order rule reads whatever the base holds; one fresh identity two
//! sides placed at two spots, a `moves` gap with spots (CM-I33) — a
//! neighbour one holder removed moving nothing, an overlapping quote
//! contested where it overlaps, a holder's choice, and the numbers the
//! other gaps keep under it and across the spine's re-walk; the report's
//! numbers every choice beside a side's order names, a gap the order
//! removes taking none and one it makes numbered after the report's last;
//! the resolutions, one per unsettled kind, `keep_both` confirming what
//! the dedup kept, a move at a gap the rules settled moving nothing and the
//! last of two choices at a spine's `moves` gap standing; two sides'
//! additions met at a line's edge (skep #1173) — a rewrite inside a line
//! beside lines after its break, the mirror at a line's start and at the
//! document's start, the additions it leaves unasked, its choices, its
//! numbers under a holder's choice and a chosen order, the gaps a holder's
//! choice unmakes, a read of another count of items, and the rule over
//! generated lines; a removal one side alone made beside another side's
//! addition there (skep #1176) — inside a line beside an addition after its
//! break, the mirror, the pairs it leaves unasked, a removal at a line's
//! start met past a nearer one, many removals beside one addition read a
//! line or two from it, many inside one line reading it once, the
//! addition's choices with the removal standing, and the record keeping the
//! removal the gap names; the line rule's laws — an addition another side
//! anchored meeting at a line's edge as it stands, a word both sides placed
//! alike meeting no line's edge of either, and as properties over generated
//! lines the rule asked alike whichever side is listed first and of no side
//! whose every change the other made too, an anchored addition, and a
//! removal judged as its rewrite would be; a word both
//! groups at a place kept once list no copy the dedup dropped; words two
//! sides added at one spot, over every order of them, asking exactly where
//! neither side's words hold the other's in order and laid once; three
//! sides' moves folded in the order listed, and two
//! reorders into one slot ordered in time quadratic in what they move; the
//! record's re-statement of them as a law over every place a gap is moved
//! to, of a holder's choice and of a move over a run the base places twice;
//! the fences the module promises; and the laws as properties over
//! generated inputs — the one rule, a run both sides place among them, kept
//! once wherever it keeps both sides' orders and asked alike whichever side
//! is listed first; a move is no touch; the dedup settling exactly the
//! equal groups; a choice moving its gap alone and a record re-stating it,
//! over a base that places a run twice among them; three sides keeping
//! every addition once and, where every gap is settled, composing as the
//! fold of two-sided merges; `base_of` over §1.2's
//! address forms; `script` over three pairs.
//! No board: every value read is a closure over a table the test writes.
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

use super::compose::{AskedValues, LINE_READ};
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
    assert_eq!(c.values, ValueLog { dedup: true, retype: false, applied: vec![], retyped: vec![] });
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
    // The retyped run left M, and the log names it with its side (§5, case
    // (f)): A's "cat" stays in A, with any link on it.
    assert_eq!(
        c.values,
        ValueLog {
            dedup: true,
            retype: true,
            applied: vec![],
            retyped: vec![(SideIx(0), rd(12, 3))]
        }
    );
    // The retype is undone only where the bytes are equal, and logged only
    // where it is undone.
    let other = text(&[(1, "the cat sat"), (12, "dog"), (16, "-")]);
    let c = compose_runs(&base(), &d(), &sides, None, &options, &other);
    assert_eq!(runs(&c), vec![rd(1, 4), rd(12, 3), rd(16, 1), rd(8, 4)]);
    assert_eq!(kinds(&c), vec![(GapKind::Corner, false)]);
    assert_eq!(c.values.retyped, vec![]);
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
    assert_eq!(
        c.values,
        ValueLog { dedup: false, retype: false, applied: vec![], retyped: vec![] }
    );
    let c = compose_runs(
        &base(),
        &d(),
        &two(a, vec![rd(1, 4), rd(17, 4), rd(5, 7)]),
        None,
        &options,
        &values,
    );
    assert_eq!(
        runs(&c),
        vec![rd(1, 4), rd(12, 4), rd(17, 4), rd(5, 7)],
        "equal bytes, apart: two runs"
    );
    assert_eq!(c.counts.m, 4);
}

/// (g) as its record names it: the place kept once, A's copy kept and B's
/// run dropped, read back from the record's JSON; none with the dedup off;
/// at three sides, C's copy of A's words dropped beside A's and B's, the
/// gap unsettled; and none where `values.applied` names no gap, nor where
/// the gap was resolved by a person since, as a build that let a
/// resolution rewrite it wrote it (the mutants that keep B's run in
/// `dropped`, read `kept` off the runs, panic on a missing gap, or name the
/// person's choice as the dedup's). `recorded`'s two sides stand for the
/// three: `deduped` reads the gaps alone.
#[test]
fn case_g_the_record_names_the_place_kept_once_and_the_run_it_dropped() {
    let values = text(&[(1, "the cat sat"), (12, "big "), (16, "big "), (20, "fat ")]);
    let a = || vec![rd(1, 4), rd(12, 4), rd(5, 7)];
    let b = || vec![rd(1, 4), rd(16, 4), rd(5, 7)];
    let c = compose_runs(&base(), &d(), &two(a(), b()), None, &Options::default(), &values);
    let record = recorded(&c);
    let dropped = vec![(SideIx(1), rd(16, 4))];
    assert_eq!(record.deduped(), vec![Deduped { gap: GapId(1), kept: vec![SideIx(0)], dropped }]);
    let off = Options { dedup: false, ..Options::default() };
    let both = compose_runs(&base(), &d(), &two(a(), b()), None, &off, &values);
    assert_eq!(recorded(&both).deduped(), vec![]);
    let fat = vec![rd(1, 4), rd(20, 4), rd(5, 7)];
    let three = [(SideIx(0), a()), (SideIx(1), fat), (SideIx(2), b())];
    let c3 = compose_runs(&base(), &d(), &three, None, &Options::default(), &values);
    assert_eq!(kinds(&c3), vec![(GapKind::Order, false)], "two copies kept: unsettled");
    assert_eq!(c3.gaps[0].resolved_by, None);
    let (kept, dropped) = (vec![SideIx(0), SideIx(1)], vec![(SideIx(2), rd(16, 4))]);
    assert_eq!(recorded(&c3).deduped(), vec![Deduped { gap: GapId(1), kept, dropped }]);
    let mut no_gap = record.clone();
    no_gap.values.applied = vec![GapId(9)];
    assert_eq!(no_gap.deduped(), vec![], "an id naming no gap");
    let mut resolved = record.clone();
    resolved.gaps[0].placed = Placement::Order(vec![SideIx(1)]);
    resolved.gaps[0].resolved_by = Some(ResolvedBy::Person);
    assert_eq!(resolved.deduped(), vec![], "a person's choice is no dedup's");
}

/// A word both sides placed alike beside the copies the dedup keeps once is
/// no copy dropped (§5, case (g); `Run::without`).
///
/// Both sides place one fresh "cat " (`D·30–33`, one identity) after "the "
/// and add "big " after it, each its own identity: both groups list the quote
/// (`Gap::runs`), the dedup keeps the head's group, and the record's
/// `deduped` names B's "big " alone, the quote standing in M (the mutant that
/// drops every run of a side left out names the quote dropped too).
#[test]
fn a_word_both_groups_list_is_no_copy_the_dedup_dropped() {
    let values = text(&[(1, "the cat sat"), (12, "big "), (16, "big "), (30, "cat ")]);
    let a = vec![rd(1, 4), rd(30, 4), rd(12, 4), rd(5, 7)];
    let b = vec![rd(1, 4), rd(30, 4), rd(16, 4), rd(5, 7)];
    let c = compose_runs(&base(), &d(), &two(a, b), None, &Options::default(), &values);
    assert_eq!(runs(&c), vec![rd(1, 4), rd(30, 4), rd(12, 4), rd(5, 7)], "the cat big cat sat");
    assert_eq!(kinds(&c), vec![(GapKind::Order, true)], "kept once, settled by the dedup");
    assert_eq!(
        gap_runs(&c),
        vec![vec![(0, rd(30, 4)), (0, rd(12, 4)), (1, rd(30, 4)), (1, rd(16, 4))]],
        "the quote under both sides"
    );
    let dropped = vec![(SideIx(1), rd(16, 4))];
    assert_eq!(
        recorded(&c).deduped(),
        vec![Deduped { gap: GapId(1), kept: vec![SideIx(0)], dropped }]
    );
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

/// An addition where two other sides removed stands in their collision.
///
/// Over "a b c" (`D·1–3`), A removes `b` and writes "X" (`D·12`) in its
/// place; B moves `b` after `c` and writes "Y" (`D·16`) between `a` and
/// `c`; C removes `b`. X and Y stand at one spot, so both are in the one
/// `collision` A's and C's removals make (R1, R4 (ii)), X first by the
/// commit order, M "a X Y c" whichever side is listed first. Keeping A
/// alone lays X alone, and the other order lays Y first (the mutant that
/// calls a stretch a collision only where its own side removed some of the
/// material leaves Y out of the gap, laid whatever is chosen, its place
/// decided by the listing).
#[test]
fn an_addition_where_two_other_sides_removed_stands_in_their_collision() {
    let (x, y) =
        (vec![rd(1, 1), rd(12, 1), rd(3, 1)], vec![rd(1, 1), rd(16, 1), rd(3, 1), rd(2, 1)]);
    let c_side = vec![rd(1, 1), rd(3, 1)];
    let (a, b) = (SideIx(0), SideIx(1));
    for (sides, (ix, iy), name) in [
        (vec![(a, x.clone()), (b, y.clone()), (SideIx(2), c_side.clone())], (a, b), "A, B, C"),
        (vec![(a, y.clone()), (b, x.clone()), (SideIx(2), c_side.clone())], (b, a), "B, A, C"),
    ] {
        let c = compose(&[rd(1, 3)], &sides);
        assert_eq!(runs(&c), vec![rd(1, 1), rd(12, 1), rd(16, 1), rd(3, 1)], "{name}: a X Y c");
        assert_eq!(kinds(&c), vec![(GapKind::Collision, false)], "{name}");
        assert_eq!(anchors(&c), vec![(Some(1), Some(3))], "{name}");
        assert_eq!(
            gap_runs(&c),
            vec![vec![(ix.0, rd(12, 1)), (iy.0, rd(16, 1))]],
            "{name}: X and Y in the one gap"
        );
        assert_eq!(c.gaps[0].placed, Placement::Order(vec![ix, iy]), "{name}: the commit order");
        let with = |choice: Choice| {
            compose_runs(&[rd(1, 3)], &d(), &sides, None, &resolve(1, choice), &unread)
        };
        let kept = with(Choice::KeepOnly(ix));
        assert_eq!(
            (runs(&kept), kept.ignored.len()),
            (vec![rd(1, 1), rd(12, 1), rd(3, 1)], 0),
            "{name}: X alone"
        );
        let other = with(Choice::Order(vec![iy, ix]));
        assert_eq!(
            (runs(&other), other.ignored.len()),
            (vec![rd(1, 1), rd(16, 1), rd(12, 1), rd(3, 1)], 0),
            "{name}: Y first"
        );
    }
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

/// Three sides' moves fold in the order listed (§2 R4 (iii); §1.2's fold).
///
/// Over `W X Y Z` (`D·1–4`) the head moves `X` before `W`, the first
/// daughter `Z` before `Y`, the second `Z` to the front. The head's and the
/// first daughter's moves touch different material and both apply; the
/// second daughter's overlaps the first's and is the one `moves` gap, the
/// first daughter's order its default — M `X W Z Y`, as the first two
/// composed, then the third over them, give. Taking the second daughter's
/// order there applies it first and folds the rest: the head's move kept, M
/// `Z X W Y`, that gap alone settled, by the person. A third daughter moving
/// `X` to the end overlaps the head's move: a second `moves` gap, the head's
/// order its default, which the choice at the first leaves unsettled (the
/// mutants that void every move on one overlap, or settle every `moves` gap
/// on one choice, give another M or another gap).
#[test]
fn three_sides_moves_fold_in_the_order_listed() {
    let wxyz = [rd(1, 4)];
    let second = vec![rd(4, 1), rd(1, 3)];
    let sides = vec![
        (SideIx(0), vec![rd(2, 1), rd(1, 1), rd(3, 2)]),
        (SideIx(1), vec![rd(1, 2), rd(4, 1), rd(3, 1)]),
        (SideIx(2), second.clone()),
    ];
    let c = compose(&wxyz, &sides);
    assert_eq!(runs(&c), vec![rd(2, 1), rd(1, 1), rd(4, 1), rd(3, 1)], "X W Z Y");
    assert_eq!(kinds(&c), vec![(GapKind::Moves, false)]);
    assert_eq!(c.gaps[0].placed, Placement::Order(vec![SideIx(1)]));
    assert_eq!(gap_runs(&c), vec![vec![(1, rd(4, 1)), (2, rd(4, 1))]], "what each daughter moved");
    let two_first = compose(&wxyz, &sides[..2]);
    assert_eq!(kinds(&two_first), vec![], "the head's and the first daughter's moves compose");
    let folded = compose(&wxyz, &two(runs(&two_first), second));
    assert_eq!(
        (runs(&folded), kinds(&folded)),
        (runs(&c), kinds(&c)),
        "the third over the first two"
    );
    let chosen = compose_runs(
        &wxyz,
        &d(),
        &sides,
        None,
        &resolve(1, Choice::Order(vec![SideIx(2)])),
        &unread,
    );
    assert_eq!(runs(&chosen), vec![rd(4, 1), rd(2, 1), rd(1, 1), rd(3, 1)], "Z X W Y");
    assert_eq!(kinds(&chosen), vec![(GapKind::Moves, true)]);
    assert_eq!(
        (chosen.gaps[0].id, chosen.gaps[0].placed.clone(), chosen.gaps[0].resolved_by.clone()),
        (GapId(1), Placement::Order(vec![SideIx(2)]), Some(ResolvedBy::Person))
    );
    assert!(chosen.ignored.is_empty(), "{:?}", chosen.ignored);
    let again = compose_runs(&wxyz, &d(), &sides, None, &recorded(&chosen).options(), &unread);
    assert_eq!((runs(&again), &again.gaps), (runs(&chosen), &chosen.gaps));
    let mut four = sides.clone();
    four.push((SideIx(3), vec![rd(1, 1), rd(3, 2), rd(2, 1)]));
    let c = compose(&wxyz, &four);
    assert_eq!(runs(&c), vec![rd(2, 1), rd(1, 1), rd(4, 1), rd(3, 1)], "X W Z Y, four sides");
    assert_eq!(kinds(&c), vec![(GapKind::Moves, false), (GapKind::Moves, false)]);
    assert_eq!(c.gaps[1].placed, Placement::Order(vec![SideIx(0)]), "the head's order");
    let chosen = compose_runs(
        &wxyz,
        &d(),
        &four,
        None,
        &resolve(1, Choice::Order(vec![SideIx(2)])),
        &unread,
    );
    assert_eq!(runs(&chosen), vec![rd(4, 1), rd(2, 1), rd(1, 1), rd(3, 1)], "Z X W Y, four sides");
    assert_eq!(
        kinds(&chosen),
        vec![(GapKind::Moves, true), (GapKind::Moves, false)],
        "the gap chosen at alone settled"
    );
}

/// Two reorders into one slot compose in time quadratic in the survivors
/// they move (§2 R4 (iii)).
///
/// Over `N` single positions apart, the head reverses the first `N − 1` and
/// the daughter moves the last to the front: every moved survivor lands in
/// the one slot before the first, in the reverse of the base's order, and M
/// is the base reversed, with no gap. At `N` = 1500 that slot holds 1,499
/// survivors, which the scores order in about 2.2e6 pair tests; the mutant
/// that orders a slot by picking again and again the survivor that comes
/// before every other one left makes about 5.6e8 there and passes the
/// bound many times over in a debug build.
#[test]
fn two_reorders_into_one_slot_compose_in_quadratic_time() {
    const N: usize = 1500;
    let base: Vec<Run> = (0..N as u64).map(|i| rd(2 * i + 1, 1)).collect();
    let mut head: Vec<Run> = base[..N - 1].iter().rev().cloned().collect();
    head.push(base[N - 1].clone());
    let mut daughter = vec![base[N - 1].clone()];
    daughter.extend(base[..N - 1].iter().cloned());
    let began = std::time::Instant::now();
    let c = compose(&base, &two(head, daughter));
    let took = began.elapsed();
    assert_eq!(runs(&c), base.iter().rev().cloned().collect::<Vec<_>>(), "the base reversed");
    assert_eq!(kinds(&c), vec![]);
    assert!(took < std::time::Duration::from_secs(2), "composed in {took:?}");
}

/// A quote both sides hold at one spot composes in time about linear in
/// its words: both sides place the same 6,000 one-position runs of `Z`
/// between `D·1` and `D·2`, and the quote is kept once with no gap, in a
/// debug build well inside 2 s. What each shared word's keeping reads of
/// its stretches and its spot is read once for them all (the mutant that
/// asks again, for every word, whether each holder orders the spot's words
/// otherwise, and where in its stretch the word stands, reads every word
/// once more per word, past the bound).
#[test]
fn a_quote_both_sides_hold_at_one_spot_composes_in_linear_time() {
    const W: u64 = 6000;
    let quote = (0..W).map(|i| Run::new(z(), 2 * i + 1, 1));
    let side: Vec<Run> = std::iter::once(rd(1, 1)).chain(quote).chain([rd(2, 1)]).collect();
    let began = std::time::Instant::now();
    let c = compose(&[rd(1, 2)], &two(side.clone(), side.clone()));
    let took = began.elapsed();
    assert_eq!(runs(&c), side, "the quote kept once");
    assert_eq!(kinds(&c), vec![]);
    assert!(took < std::time::Duration::from_secs(2), "composed in {took:?}");
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

/// Every ordering of a choice of `pool`'s words, the empty one first.
fn arrangements(pool: &[u64]) -> Vec<Vec<u64>> {
    let mut out: Vec<Vec<u64>> = vec![Vec::new()];
    let mut grown: Vec<Vec<u64>> = vec![Vec::new()];
    while !grown.is_empty() {
        let mut next = Vec::new();
        for words in &grown {
            for &w in pool.iter().filter(|w| !words.contains(*w)) {
                let mut more = words.clone();
                more.push(w);
                next.push(more);
            }
        }
        out.extend(next.iter().cloned());
        grown = next;
    }
    out
}

/// Whether `part` stands in `whole` in its own order.
fn in_order_part(part: &[u64], whole: &[u64]) -> bool {
    let mut rest = whole.iter();
    part.iter().all(|w| rest.any(|v| v == w))
}

/// The base `p q` (`D·1–2`) with `words`, each a position of `D`, between
/// the two, as `image` delivers it.
fn between_p_and_q(words: &[u64]) -> Vec<Run> {
    let positions = std::iter::once(1).chain(words.iter().copied()).chain([2]);
    positions.fold(Vec::new(), |mut out: Vec<Run>, w| {
        match out.last_mut() {
            Some(last) if last.reach() == w => last.width += 1,
            _ => out.push(rd(w, 1)),
        }
        out
    })
}

/// The words M lays between `p` and `q`, in M's order.
fn between_in(c: &Composed) -> Vec<u64> {
    expand(&runs(c)).into_iter().map(|(_, w)| w).filter(|w| *w != 1 && *w != 2).collect()
}

/// WORDS BOTH SIDES PLACED ALIKE AT ONE SPOT, exhaustively (merge record §2,
/// the one rule; R1): over the base `p q` (`D·1–2`), each side places
/// between `p` and `q` an ordered choice of the words y (`D·20`) and S
/// (`D·30`), which a side placing them shares with the other, and a word of
/// its own (A's `D·12`, B's `D·16`) — sixteen a side, every pair composed
/// listed both ways. The spot asks exactly where neither side's words are an
/// in-order part of the other's; the default M is the same whichever side is
/// listed first and holds every word once; where nothing asks, each side's
/// words stand in M in its own order; and where the spot asks, keeping one
/// side alone lays exactly the words it placed, in its order, and putting it
/// first lays them first and the other side's after (the mutants that strip
/// a shared word from a side that orders it otherwise, strip it from a side
/// with a word of its own beside it, order two groups whose first word is
/// one by the side listed first, or lay a word two sides list twice each
/// break one of these).
#[test]
fn shared_words_at_one_spot_ask_unless_one_sides_words_hold_the_others() {
    let base = [rd(1, 2)];
    let (mut asked_spots, mut kept_alone) = (0, 0);
    for words_a in arrangements(&[20, 30, 12]) {
        for words_b in arrangements(&[20, 30, 16]) {
            let (a, b) = (between_p_and_q(&words_a), between_p_and_q(&words_b));
            let say = format!("A {words_a:?}, B {words_b:?}");
            let asks = !in_order_part(&words_a, &words_b) && !in_order_part(&words_b, &words_a);
            let listings = [(two(a.clone(), b.clone()), 0, 1), (two(b.clone(), a.clone()), 1, 0)];
            let composed: Vec<Composed> =
                listings.iter().map(|(sides, _, _)| compose(&base, sides)).collect();
            for (c, name) in composed.iter().zip(["A first", "B first"]) {
                let unsettled: Vec<&Gap> = c.gaps.iter().filter(|g| !g.settled).collect();
                assert_eq!(!unsettled.is_empty(), asks, "{say}, {name}: gaps {:?}", c.gaps);
                assert!(
                    unsettled.len() <= 1,
                    "{say}, {name}: one spot, one question: {:?}",
                    c.gaps
                );
            }
            assert_eq!(
                runs(&composed[1]),
                runs(&composed[0]),
                "{say}: the default, listed the other way round"
            );
            let mut every: Vec<u64> = words_a.iter().chain(&words_b).copied().collect();
            every.sort_unstable();
            every.dedup();
            let mut laid = between_in(&composed[0]);
            laid.sort_unstable();
            assert_eq!(laid, every, "{say}: every word once");
            if !asks {
                for (name, side) in [("A", &a), ("B", &b)] {
                    assert!(keeps_order(&runs(&composed[0]), side), "{say}: {name}'s order broken");
                }
                continue;
            }
            asked_spots += 1;
            for ((sides, a_at, b_at), c) in listings.iter().zip(&composed) {
                let gap = c.gaps.iter().find(|g| !g.settled).expect("the spot asks");
                let listed: BTreeSet<u8> = gap.runs.iter().map(|(s, _)| s.0).collect();
                assert_eq!(
                    listed,
                    BTreeSet::from([0, 1]),
                    "{say}: both sides at the gap: {:?}",
                    gap.runs
                );
                let (a_ix, b_ix) = (SideIx(*a_at), SideIx(*b_at));
                for (mine, theirs, s, t) in
                    [(&words_a, &words_b, a_ix, b_ix), (&words_b, &words_a, b_ix, a_ix)]
                {
                    let with = |choice: Choice| {
                        compose_runs(&base, &d(), sides, None, &resolve(gap.id.0, choice), &unread)
                    };
                    let alone = with(Choice::KeepOnly(s));
                    assert_eq!(&between_in(&alone), mine, "{say}: side {} kept alone", s.0);
                    let first = with(Choice::Order(vec![s, t]));
                    let mut expected = mine.clone();
                    expected.extend(theirs.iter().filter(|w| !mine.contains(w)));
                    assert_eq!(between_in(&first), expected, "{say}: side {} put first", s.0);
                    kept_alone += 1;
                }
            }
        }
    }
    assert!(
        asked_spots > 100 && kept_alone > 400,
        "{asked_spots} spots asked, {kept_alone} choices"
    );
}

// ── one identity at two spots (CM-I33) ───────────────────────────────────

/// The sides of the first case: both hold "big" (`D·20–22`), the head after
/// `D·4`, the side after `D·8`.
fn apart() -> Vec<(SideIx, Vec<Run>)> {
    two(vec![rd(1, 4), rd(20, 3), rd(5, 7)], vec![rd(1, 8), rd(20, 3), rd(9, 3)])
}

/// One identity two sides placed at two spots is a `moves` gap, unsettled:
/// the head's placement the default, the side's copy left out, its spots
/// naming `D·4|D·5` and `D·8|D·9`, nothing logged (the mutants that keep
/// the earliest copy with no gap, or read both spots off one holder,
/// answer no gap or one spot twice).
#[test]
fn a_fresh_identity_two_sides_place_apart_is_a_moves_gap_naming_both_spots() {
    let c = compose(&base(), &apart());
    assert_eq!(runs(&c), vec![rd(1, 4), rd(20, 3), rd(5, 7)], "the head's placement");
    assert_eq!(kinds(&c), vec![(GapKind::Moves, false)]);
    assert_eq!((c.gaps[0].id, anchors(&c)), (GapId(1), vec![(None, None)]));
    assert_eq!((c.gaps[0].placed.clone(), c.gaps[0].resolved_by.clone()), (Placement::Order(vec![SideIx(0)]), None));
    assert_eq!(gap_runs(&c), vec![vec![(0, rd(20, 3)), (1, rd(20, 3))]], "each holder's placement of the one identity");
    assert_eq!(
        c.gaps[0].spots,
        vec![
            Spot { side: SideIx(0), after: Some(d_at(4)), before: Some(d_at(5)) },
            Spot { side: SideIx(1), after: Some(d_at(8)), before: Some(d_at(9)) },
        ]
    );
    assert_eq!(c.values, ValueLog { dedup: true, retype: false, applied: vec![], retyped: vec![] });
}

/// A neighbour one holder removed moves nothing: the side removed `D·5`,
/// right after both sides' "big", and a spot is read by the base positions
/// every holder keeps — `D·4|D·6` on each — so the one gap is the head's
/// "big" beside the removal, an `anchor`, settled (the mutant that reads
/// each holder's own anchors raises a `moves` gap).
#[test]
fn a_neighbour_one_holder_removed_moves_no_identity() {
    let c = compose(&base(), &two(vec![rd(1, 4), rd(20, 3), rd(5, 7)], vec![rd(1, 4), rd(20, 3), rd(6, 6)]));
    assert_eq!(runs(&c), vec![rd(1, 4), rd(20, 3), rd(6, 6)]);
    assert_eq!(kinds(&c), vec![(GapKind::Anchor, true)]);
}

/// A quote two sides window overlapping is contested only where it
/// overlaps: the head windows `Z·20–29` after `D·2`, the side `Z·25–39`
/// after `D·9` — one `moves` gap over `Z·25–29`, the head's quote whole at
/// the default and the rest of the side's at its own place (the mutant that
/// contests or drops the later run whole answers another M).
#[test]
fn an_overlapping_quote_is_contested_only_where_it_overlaps() {
    let zr = |s, w| Run::new(z(), s, w);
    let c = compose(&base(), &two(vec![rd(1, 2), zr(20, 10), rd(3, 9)], vec![rd(1, 9), zr(25, 15), rd(10, 2)]));
    assert_eq!(runs(&c), vec![rd(1, 2), zr(20, 10), rd(3, 7), zr(30, 10), rd(10, 2)]);
    assert_eq!(kinds(&c), vec![(GapKind::Moves, false)]);
    assert_eq!(gap_runs(&c), vec![vec![(0, zr(25, 5)), (1, zr(25, 5))]]);
}

/// The merger's choice at a gap with spots keeps one holder's placement:
/// `Order` or `KeepOnly` of the side puts "big" after `D·8`, settled by the
/// person, nothing ignored; every other choice — `Omit`, `KeepBoth`, a side
/// that holds nothing there, two sides, a place — leaves the default and
/// stands in `ignored`; of two naming the gap the later stands (the mutants
/// that route the choice into the spine's re-walk, or apply it and list it
/// ignored too, answer another M or a non-empty `ignored`).
#[test]
fn a_gap_with_spots_takes_one_holders_placement_and_no_other_choice() {
    let sides = apart();
    for choice in [Choice::Order(vec![SideIx(1)]), Choice::KeepOnly(SideIx(1))] {
        let c = compose_runs(&base(), &d(), &sides, None, &resolve(1, choice.clone()), &unread);
        assert_eq!(runs(&c), vec![rd(1, 8), rd(20, 3), rd(9, 3)], "{choice:?}: the words after D·8");
        assert_eq!(kinds(&c), vec![(GapKind::Moves, true)], "{choice:?}");
        assert_eq!(
            (c.gaps[0].placed.clone(), c.gaps[0].resolved_by.clone()),
            (Placement::Order(vec![SideIx(1)]), Some(ResolvedBy::Person)),
            "{choice:?}"
        );
        assert!(c.ignored.is_empty(), "{choice:?}: {:?}", c.ignored);
    }
    for choice in [
        Choice::Omit,
        Choice::KeepBoth,
        Choice::Order(vec![SideIx(2)]),
        Choice::KeepOnly(SideIx(2)),
        Choice::Order(vec![SideIx(1), SideIx(0)]),
        Choice::After(d_at(8)),
    ] {
        let c = compose_runs(&base(), &d(), &sides, None, &resolve(1, choice.clone()), &unread);
        assert_eq!(runs(&c), vec![rd(1, 4), rd(20, 3), rd(5, 7)], "{choice:?}: the default stands");
        assert_eq!(kinds(&c), vec![(GapKind::Moves, false)], "{choice:?}");
        assert_eq!(c.ignored, vec![Resolution { gap: GapId(1), choice: choice.clone(), by: ResolvedBy::Person }]);
    }
    let resolutions = vec![
        Resolution { gap: GapId(1), choice: Choice::Order(vec![SideIx(1)]), by: ResolvedBy::Person },
        Resolution { gap: GapId(1), choice: Choice::Order(vec![SideIx(0)]), by: ResolvedBy::Agent },
    ];
    let c = compose_runs(&base(), &d(), &sides, None, &Options { resolutions, ..Options::default() }, &unread);
    assert_eq!(runs(&c), vec![rd(1, 4), rd(20, 3), rd(5, 7)], "the later choice, the head's");
    assert_eq!((c.gaps[0].settled, c.gaps[0].resolved_by.clone()), (true, Some(ResolvedBy::Agent)));
    assert!(c.ignored.is_empty());
}

/// A gap with spots is numbered before the spine's: both sides hold "xy"
/// (`D·20–21`), the head after `Z` at the end, the side at the start, and
/// their reorders of `X Y Z` do not compose. Resolving the spine's gap 2
/// re-walks under the side's order and leaves gap 1 as it was; resolving
/// gap 1 moves the words and re-walks nothing, the spine the head's, a
/// `cut` the words open there numbered after the defaults' last (the
/// mutants that number the spine's gaps first, or re-walk at gap 1,
/// answer another gap 1 or another spine).
#[test]
fn the_gaps_with_spots_keep_their_numbers_across_a_spine_re_walk() {
    let sides = two(vec![rd(2, 1), rd(1, 1), rd(3, 1), rd(20, 2)], vec![rd(20, 2), rd(1, 1), rd(3, 1), rd(2, 1)]);
    let c = compose(&[rd(1, 3)], &sides);
    assert_eq!(runs(&c), vec![rd(2, 1), rd(1, 1), rd(3, 1), rd(20, 2)], "the head's order, its words");
    assert_eq!(kinds(&c), vec![(GapKind::Moves, false), (GapKind::Moves, false)]);
    assert!(!c.gaps[0].spots.is_empty() && c.gaps[1].spots.is_empty(), "the gap with spots first: {:?}", c.gaps);
    let by_spine = compose_runs(&[rd(1, 3)], &d(), &sides, None, &resolve(2, Choice::Order(vec![SideIx(1)])), &unread);
    assert_eq!(by_spine.gaps[0], c.gaps[0], "gap 1 as it was");
    assert_eq!((by_spine.gaps[1].id, by_spine.gaps[1].settled), (GapId(2), true));
    assert_eq!(runs(&by_spine), vec![rd(1, 1), rd(3, 1), rd(20, 2), rd(2, 1)], "the side's order");
    let by_claim = compose_runs(&[rd(1, 3)], &d(), &sides, None, &resolve(1, Choice::Order(vec![SideIx(1)])), &unread);
    assert_eq!(runs(&by_claim), vec![rd(20, 2), rd(2, 1), rd(1, 1), rd(3, 1)], "the head's order, the side's place");
    assert_eq!(kinds(&by_claim), vec![(GapKind::Moves, true), (GapKind::Moves, false), (GapKind::Cut, false)]);
    assert_eq!((by_claim.gaps[1].placed.clone(), by_claim.gaps[2].id), (Placement::Order(vec![SideIx(0)]), GapId(3)));
    assert!(by_claim.ignored.is_empty());
}

/// The sides of two crossed reorders over the base `D·1–5` (skep #1155).
///
/// Read as `A B C D E`, the head is `C r0 D A q0 B E` and the side
/// `A q1 B E C r1 D`, with `r0`, `q0`, `q1` and `r1` at `D·20`, `D·30`,
/// `D·31` and `D·21`. The reorders overlap, so the spine is the head's and
/// the side's reorder is `moves` gap 1; at that order the gap inside `C D`
/// is 2 and the one inside `A B` 3, and under the side's order they trade
/// places in M.
fn crossed() -> Vec<(SideIx, Vec<Run>)> {
    two(
        vec![rd(3, 1), rd(20, 1), rd(4, 1), rd(1, 1), rd(30, 1), rd(2, 1), rd(5, 1)],
        vec![rd(1, 1), rd(31, 1), rd(2, 1), rd(5, 1), rd(3, 1), rd(21, 1), rd(4, 1)],
    )
}

/// [`crossed`] with the head's `w` after `D` and the side's `z` after `E`.
///
/// `w` is `D·40` and `z` `D·50`. At the head's order `z`'s anchors stand
/// apart, a `cut`, gap 4, and `w`'s together; under the side's order the
/// two trade.
fn crossed_ends() -> Vec<(SideIx, Vec<Run>)> {
    two(
        vec![rd(3, 1), rd(20, 1), rd(4, 1), rd(40, 1), rd(1, 1), rd(30, 1), rd(2, 1), rd(5, 1)],
        vec![rd(1, 1), rd(31, 1), rd(2, 1), rd(5, 1), rd(50, 1), rd(3, 1), rd(21, 1), rd(4, 1)],
    )
}

/// A choice beside the side's order names the gap the report numbers.
///
/// Over [`crossed`], `1=Order([1])` and `2=KeepOnly(0)` give M the side's
/// order with `r0` alone inside `C D` — gap 2 at the default order, settled
/// by the person — and both words inside `A B`, gap 3, which asks still;
/// nothing is ignored, and the record's options compose the same M and gaps
/// (skep #1155; the mutant that numbers the gaps by their places under the
/// chosen order gives the keep to the gap inside `A B`).
#[test]
fn a_choice_beside_a_sides_order_names_the_gap_the_report_numbers() {
    let sides = crossed();
    let report = compose(&[rd(1, 5)], &sides);
    assert_eq!(kinds(&report), vec![(GapKind::Moves, false), (GapKind::Order, false), (GapKind::Order, false)]);
    assert_eq!(gap_runs(&report)[1], vec![(0, rd(20, 1)), (1, rd(21, 1))], "gap 2 inside C D");
    let resolutions = vec![
        Resolution { gap: GapId(1), choice: Choice::Order(vec![SideIx(1)]), by: ResolvedBy::Person },
        Resolution { gap: GapId(2), choice: Choice::KeepOnly(SideIx(0)), by: ResolvedBy::Person },
    ];
    let c = compose_runs(&[rd(1, 5)], &d(), &sides, None, &Options { resolutions, ..Options::default() }, &unread);
    assert_eq!(
        runs(&c),
        vec![rd(1, 1), rd(30, 2), rd(2, 1), rd(5, 1), rd(3, 1), rd(20, 1), rd(4, 1)],
        "A q0 q1 B E C r0 D"
    );
    assert_eq!(c.gaps.iter().map(|g| g.id.0).collect::<Vec<_>>(), vec![1, 2, 3]);
    assert_eq!(gap_runs(&c)[1], gap_runs(&report)[1], "gap 2 inside C D still");
    assert_eq!(
        (c.gaps[1].placed.clone(), c.gaps[1].resolved_by.clone()),
        (Placement::Order(vec![SideIx(0)]), Some(ResolvedBy::Person))
    );
    assert_eq!((gap_runs(&c)[2].clone(), c.gaps[2].settled), (gap_runs(&report)[2].clone(), false), "gap 3 inside A B");
    assert!(c.ignored.is_empty(), "{:?}", c.ignored);
    let again = compose_runs(&[rd(1, 5)], &d(), &sides, None, &recorded(&c).options(), &unread);
    assert_eq!((runs(&again), &again.gaps), (runs(&c), &c.gaps));
}

/// The dedup's log names the report's number under the side's order.
///
/// Over [`crossed`] with `q0` and `q1` the same bytes, the dedup keeps the
/// head's copy inside `A B`, gap 3 at the head's order; under the side's
/// order, `1=Order([1])`, it logs gap 3 still, that gap settled by the rule
/// and placed `[0]` (skep #1155; the mutant that leaves the log's ids as
/// the walk under that order first numbered them logs gap 2).
#[test]
fn the_dedups_log_names_the_reports_number_under_a_sides_order() {
    let same = text(&[(30, "q"), (31, "q")]);
    let c = compose_runs(&[rd(1, 5)], &d(), &crossed(), None, &resolve(1, Choice::Order(vec![SideIx(1)])), &same);
    assert_eq!(c.values.applied, vec![GapId(3)]);
    assert_eq!(gap_runs(&c)[2], vec![(0, rd(30, 1)), (1, rd(31, 1))], "gap 3 inside A B");
    assert_eq!(
        (c.gaps[2].placed.clone(), c.gaps[2].resolved_by.clone()),
        (Placement::Order(vec![SideIx(0)]), Some(ResolvedBy::Rule))
    );
    assert!(c.ignored.is_empty(), "{:?}", c.ignored);
}

/// An omission beside the side's order omits the report's gap or nothing.
///
/// Over [`crossed_ends`] the report is the `moves` gap, the gaps inside
/// `C D` and `A B`, and `z`'s `cut`. Beside `1=Order([1])`, `Omit` at each
/// of gaps 2 to 4 leaves out of M that gap's runs alone, the gap holding the
/// report's runs and placed `Omitted` — or, at the `cut` the side's order
/// closes, stands in `ignored` and leaves M whole (skep #1155; the mutant
/// that numbers the gaps by their places under the chosen order omits the
/// words inside `A B` at 2 and `w` at 4).
#[test]
fn an_omission_beside_a_sides_order_omits_the_reports_gap_or_nothing() {
    let sides = crossed_ends();
    let report = compose(&[rd(1, 5)], &sides);
    let numbered: Vec<(u32, GapKind)> = report.gaps.iter().map(|g| (g.id.0, g.kind)).collect();
    assert_eq!(numbered, vec![(1, GapKind::Moves), (2, GapKind::Order), (3, GapKind::Order), (4, GapKind::Cut)]);
    let order = Resolution { gap: GapId(1), choice: Choice::Order(vec![SideIx(1)]), by: ResolvedBy::Person };
    let with = |more: &[Resolution]| {
        let resolutions = std::iter::once(order.clone()).chain(more.iter().cloned()).collect();
        compose_runs(&[rd(1, 5)], &d(), &sides, None, &Options { resolutions, ..Options::default() }, &unread)
    };
    let whole = expand(&runs(&with(&[])));
    let mut ignored = Vec::new();
    for g in 2..=4 {
        let omit = Resolution { gap: GapId(g), choice: Choice::Omit, by: ResolvedBy::Person };
        let c = with(std::slice::from_ref(&omit));
        let Some(gap) = c.gaps.iter().find(|x| x.id == GapId(g)) else {
            assert_eq!(
                (c.ignored.clone(), expand(&runs(&c))),
                (vec![omit], whole.clone()),
                "gap {g}: ignored, M whole"
            );
            ignored.push(g);
            continue;
        };
        let reported = report.gaps.iter().find(|x| x.id == GapId(g)).expect("the report's gap");
        assert_eq!((gap.kind, &gap.runs, &gap.placed), (reported.kind, &reported.runs, &Placement::Omitted), "gap {g}");
        let left_out = expand(&gap.runs.iter().map(|(_, run)| run.clone()).collect::<Vec<_>>());
        let rest: Vec<(Address, u64)> = whole.iter().filter(|p| !left_out.contains(p)).cloned().collect();
        assert_eq!(expand(&runs(&c)), rest, "gap {g}: its runs alone left out");
        assert!(c.ignored.is_empty(), "gap {g}: {:?}", c.ignored);
    }
    assert_eq!(ignored, vec![4], "the cut the side's order closes takes no choice");
}

/// A choice naming a gap the chosen order removes is ignored.
///
/// Over [`crossed_ends`] the side's order alone numbers its gaps 1, 2, 3
/// and 5: `z`'s `cut`, gap 4 at the head's order, is gone, and the `cut` the
/// side's order opens at `w` is numbered after the report's last. So `Omit`
/// naming gap 4 beside it stands in `ignored`, and M holds `w` and `z` both
/// (skep #1155; the mutant that numbers the gaps by their places under the
/// chosen order omits `w`, and the one that numbers a new gap from the
/// report's last names it 4).
#[test]
fn a_choice_naming_a_gap_the_chosen_order_removes_is_ignored() {
    let sides = crossed_ends();
    let order = Resolution { gap: GapId(1), choice: Choice::Order(vec![SideIx(1)]), by: ResolvedBy::Person };
    let options = Options { resolutions: vec![order.clone()], ..Options::default() };
    let alone = compose_runs(&[rd(1, 5)], &d(), &sides, None, &options, &unread);
    let numbered: Vec<(u32, GapKind)> = alone.gaps.iter().map(|g| (g.id.0, g.kind)).collect();
    assert_eq!(numbered, vec![(1, GapKind::Moves), (2, GapKind::Order), (3, GapKind::Order), (5, GapKind::Cut)]);
    assert_eq!(gap_runs(&alone)[3], vec![(0, rd(40, 1))], "gap 5 is w's cut");
    let omit = Resolution { gap: GapId(4), choice: Choice::Omit, by: ResolvedBy::Person };
    let options = Options { resolutions: vec![order, omit.clone()], ..Options::default() };
    let c = compose_runs(&[rd(1, 5)], &d(), &sides, None, &options, &unread);
    assert_eq!(c.ignored, vec![omit]);
    assert_eq!(runs(&c), runs(&alone));
    assert!(runs(&c).contains(&rd(40, 1)) && runs(&c).contains(&rd(50, 1)), "w and z both: {:?}", runs(&c));
}

/// A holder's choice and the side's order in one list name the report's gaps.
///
/// [`crossed`] with "xy" (`D·60–61`) at the head's end and the side's
/// start: the report numbers the gap with spots 1, the spine's `moves` gap
/// 2, and the gaps inside `C D` and `A B` 3 and 4. `1=Order([1])`,
/// `2=Order([1])` and `3=KeepOnly(0)` put "xy" first, take the side's order
/// and keep `r0` alone inside `C D`, nothing ignored, and the record's
/// options compose the same (skep #1155; the mutant that numbers the gaps
/// as the claims' defaults under the chosen order gives the keep to the gap
/// inside `A B`).
#[test]
fn a_holders_choice_and_a_sides_order_in_one_list_name_the_reports_gaps() {
    let sides = two(
        vec![rd(3, 1), rd(20, 1), rd(4, 1), rd(1, 1), rd(30, 1), rd(2, 1), rd(5, 1), rd(60, 2)],
        vec![rd(60, 2), rd(1, 1), rd(31, 1), rd(2, 1), rd(5, 1), rd(3, 1), rd(21, 1), rd(4, 1)],
    );
    let report = compose(&[rd(1, 5)], &sides);
    assert_eq!(
        kinds(&report),
        vec![(GapKind::Moves, false), (GapKind::Moves, false), (GapKind::Order, false), (GapKind::Order, false)]
    );
    assert!(!report.gaps[0].spots.is_empty() && report.gaps[1].spots.is_empty(), "{:?}", report.gaps);
    assert_eq!(gap_runs(&report)[2], vec![(0, rd(20, 1)), (1, rd(21, 1))], "gap 3 inside C D");
    let resolutions = vec![
        Resolution { gap: GapId(1), choice: Choice::Order(vec![SideIx(1)]), by: ResolvedBy::Person },
        Resolution { gap: GapId(2), choice: Choice::Order(vec![SideIx(1)]), by: ResolvedBy::Person },
        Resolution { gap: GapId(3), choice: Choice::KeepOnly(SideIx(0)), by: ResolvedBy::Person },
    ];
    let c = compose_runs(&[rd(1, 5)], &d(), &sides, None, &Options { resolutions, ..Options::default() }, &unread);
    assert_eq!(
        runs(&c),
        vec![rd(60, 2), rd(1, 1), rd(30, 2), rd(2, 1), rd(5, 1), rd(3, 1), rd(20, 1), rd(4, 1)],
        "xy A q0 q1 B E C r0 D"
    );
    assert_eq!(c.gaps.iter().map(|g| g.id.0).collect::<Vec<_>>(), vec![1, 2, 3, 4]);
    assert_eq!(
        (gap_runs(&c)[2].clone(), c.gaps[2].placed.clone()),
        (gap_runs(&report)[2].clone(), Placement::Order(vec![SideIx(0)]))
    );
    assert!(c.ignored.is_empty(), "{:?}", c.ignored);
    let again = compose_runs(&[rd(1, 5)], &d(), &sides, None, &recorded(&c).options(), &unread);
    assert_eq!((runs(&again), &again.gaps), (runs(&c), &c.gaps));
}

/// Among three sides, every gap keeps its number under a chosen order.
///
/// Base `X Y Z` (`D·1–3`), side 0 `Y X a Z`, side 1 `X b Z Y`, side 2
/// `X Z Y`: side 0's order is the spine, sides 1 and 2 hold `moves` gaps 1
/// and 2, and `a` and `b` an `order` gap, 3. `2=Order([2])` takes side 2's
/// order, which side 1 shares, so gap 1 is gone and gap 2 holds side 0's
/// reorder, settled by the person; `3=KeepOnly(1)` keeps `b`; nothing is
/// ignored, and the record's options compose the same (skep #1155; the
/// mutant that numbers the `moves` gaps by side ignores both choices).
#[test]
fn among_three_sides_every_gap_keeps_its_number_under_a_chosen_order() {
    let sides = vec![
        (SideIx(0), vec![rd(2, 1), rd(1, 1), rd(20, 1), rd(3, 1)]),
        (SideIx(1), vec![rd(1, 1), rd(21, 1), rd(3, 1), rd(2, 1)]),
        (SideIx(2), vec![rd(1, 1), rd(3, 1), rd(2, 1)]),
    ];
    let numbered = |c: &Composed| c.gaps.iter().map(|g| (g.id.0, g.kind)).collect::<Vec<_>>();
    assert_eq!(
        numbered(&compose(&[rd(1, 3)], &sides)),
        vec![(1, GapKind::Moves), (2, GapKind::Moves), (3, GapKind::Order)]
    );
    let resolutions = vec![
        Resolution { gap: GapId(2), choice: Choice::Order(vec![SideIx(2)]), by: ResolvedBy::Person },
        Resolution { gap: GapId(3), choice: Choice::KeepOnly(SideIx(1)), by: ResolvedBy::Person },
    ];
    let c = compose_runs(&[rd(1, 3)], &d(), &sides, None, &Options { resolutions, ..Options::default() }, &unread);
    assert_eq!(runs(&c), vec![rd(1, 1), rd(21, 1), rd(3, 1), rd(2, 1)], "X b Z Y");
    assert_eq!(numbered(&c), vec![(2, GapKind::Moves), (3, GapKind::Order)]);
    let placed: Vec<(Placement, Option<ResolvedBy>)> =
        c.gaps.iter().map(|g| (g.placed.clone(), g.resolved_by.clone())).collect();
    let by_person = |side| (Placement::Order(vec![SideIx(side)]), Some(ResolvedBy::Person));
    assert_eq!(placed, vec![by_person(2), by_person(1)]);
    assert!(c.ignored.is_empty(), "{:?}", c.ignored);
    let again = compose_runs(&[rd(1, 3)], &d(), &sides, None, &recorded(&c).options(), &unread);
    assert_eq!((runs(&again), &again.gaps), (runs(&c), &c.gaps));
}

/// The gaps only a chosen order makes are numbered after the report's last.
///
/// Base `X Y Z` (`D·1–3`), sides 0 and 1 `Y X Z`, side 0 with `w` between
/// `Y` and `X`, side 2 `X Z Y`: the report is side 2's `moves` gap alone.
/// Under side 2's order, `1=Order([2])`, that gap holds side 0's reorder
/// and keeps 1; side 1's reorder is a `moves` gap the report did not have,
/// 2, and the `cut` that order opens at `w` comes after it, 3 — the `moves`
/// gaps first (skep #1155; the mutant that numbers the new `cut` first
/// gives it 2).
#[test]
fn the_gaps_a_chosen_order_makes_are_numbered_after_the_reports_last_moves_first() {
    let sides = vec![
        (SideIx(0), vec![rd(2, 1), rd(20, 1), rd(1, 1), rd(3, 1)]),
        (SideIx(1), vec![rd(2, 1), rd(1, 1), rd(3, 1)]),
        (SideIx(2), vec![rd(1, 1), rd(3, 1), rd(2, 1)]),
    ];
    assert_eq!(kinds(&compose(&[rd(1, 3)], &sides)), vec![(GapKind::Moves, false)]);
    let c = compose_runs(&[rd(1, 3)], &d(), &sides, None, &resolve(1, Choice::Order(vec![SideIx(2)])), &unread);
    assert_eq!(runs(&c), vec![rd(1, 1), rd(3, 1), rd(2, 1), rd(20, 1)], "X Z Y w");
    let numbered: Vec<(u32, GapKind)> = c.gaps.iter().map(|g| (g.id.0, g.kind)).collect();
    assert_eq!(numbered, vec![(1, GapKind::Moves), (2, GapKind::Moves), (3, GapKind::Cut)]);
    assert_eq!(gap_runs(&c)[0], vec![(2, rd(3, 1)), (0, rd(2, 1))], "gap 1 holds side 0's reorder");
    assert!(c.ignored.is_empty(), "{:?}", c.ignored);
    let again = compose_runs(&[rd(1, 3)], &d(), &sides, None, &recorded(&c).options(), &unread);
    assert_eq!((runs(&again), &again.gaps), (runs(&c), &c.gaps));
}

/// Two collisions no side filled keep their numbers under a chosen order.
///
/// Base `A B P C D Q E` (`D·1–7`), the head `C D A B E` and the side
/// `A B E C D`, each removing `P` and `Q`: at the head's order the
/// collision at `Q`, after `D`, is gap 2 and the one at `P`, after `B`, gap
/// 3. Under the side's order they stand the other way round in M and keep
/// their numbers, each known by the base positions it covers, so `Omit` at
/// gap 2 settles the one at `Q` (skep #1155; the mutant that matches such a
/// collision by its kind alone settles the one at `P`).
#[test]
fn two_collisions_no_side_filled_keep_their_numbers_under_a_chosen_order() {
    let sides = two(vec![rd(4, 2), rd(1, 2), rd(7, 1)], vec![rd(1, 2), rd(7, 1), rd(4, 2)]);
    let report = compose(&[rd(1, 7)], &sides);
    assert_eq!(kinds(&report), vec![(GapKind::Moves, false), (GapKind::Collision, false), (GapKind::Collision, false)]);
    assert_eq!(anchors(&report)[1..], [(Some(5), Some(1)), (Some(2), Some(7))], "Q after D, then P after B");
    let resolutions = vec![
        Resolution { gap: GapId(1), choice: Choice::Order(vec![SideIx(1)]), by: ResolvedBy::Person },
        Resolution { gap: GapId(2), choice: Choice::Omit, by: ResolvedBy::Person },
    ];
    let c = compose_runs(&[rd(1, 7)], &d(), &sides, None, &Options { resolutions, ..Options::default() }, &unread);
    assert_eq!(runs(&c), vec![rd(1, 2), rd(7, 1), rd(4, 2)], "A B E C D");
    assert_eq!(c.gaps.iter().map(|g| g.id.0).collect::<Vec<_>>(), vec![1, 2, 3]);
    assert_eq!(anchors(&c)[1..], [(Some(5), None), (Some(2), Some(7))], "Q after D at the end, P after B");
    assert_eq!((c.gaps[1].placed.clone(), c.gaps[1].settled, c.gaps[2].settled), (Placement::Omitted, true, false));
    assert!(c.ignored.is_empty(), "{:?}", c.ignored);
    let again = compose_runs(&[rd(1, 7)], &d(), &sides, None, &recorded(&c).options(), &unread);
    assert_eq!((runs(&again), &again.gaps), (runs(&c), &c.gaps));
}

/// A holder's choice numbers every other gap as at its default: sides 0 and
/// 1 place "big" apart, side 2 adds "xx" at side 1's spot and a rewrite
/// colliding with the head's removal at the end. At the defaults the
/// `collision` is gap 2; with side 1's placement chosen an `order` gap
/// arises at its spot and is numbered after the defaults' last, the
/// `collision` keeping 2, and a resolution naming 2 omits the rewrite in
/// both (the mutant that numbers from the chosen walk gives the `order`
/// gap 2 and the omission to it).
#[test]
fn a_holders_choice_numbers_the_other_gaps_as_at_its_default() {
    let sides = vec![
        (SideIx(0), vec![rd(1, 4), rd(20, 3), rd(5, 6)]),
        (SideIx(1), vec![rd(1, 8), rd(20, 3), rd(9, 3)]),
        (SideIx(2), vec![rd(1, 8), rd(30, 2), rd(9, 1), rd(40, 2)]),
    ];
    let at_default = compose(&base(), &sides);
    assert_eq!(kinds(&at_default), vec![(GapKind::Moves, false), (GapKind::Collision, false)]);
    assert_eq!(runs(&at_default), vec![rd(1, 4), rd(20, 3), rd(5, 4), rd(30, 2), rd(9, 1), rd(40, 2)]);
    let chosen = Resolution { gap: GapId(1), choice: Choice::Order(vec![SideIx(1)]), by: ResolvedBy::Person };
    let c = compose_runs(&base(), &d(), &sides, None, &Options { resolutions: vec![chosen.clone()], ..Options::default() }, &unread);
    assert_eq!(runs(&c), vec![rd(1, 8), rd(20, 3), rd(30, 2), rd(9, 1), rd(40, 2)], "big, then xx, at D·8|D·9");
    assert_eq!(
        c.gaps.iter().map(|g| (g.id.0, g.kind)).collect::<Vec<_>>(),
        vec![(1, GapKind::Moves), (2, GapKind::Collision), (3, GapKind::Order)]
    );
    assert_eq!(gap_runs(&c)[2], vec![(1, rd(20, 3)), (2, rd(30, 2))]);
    let omit = Resolution { gap: GapId(2), choice: Choice::Omit, by: ResolvedBy::Person };
    let c = compose_runs(&base(), &d(), &sides, None, &Options { resolutions: vec![omit.clone()], ..Options::default() }, &unread);
    assert_eq!(runs(&c), vec![rd(1, 4), rd(20, 3), rd(5, 4), rd(30, 2), rd(9, 1)], "the rewrite omitted at the defaults");
    let both = Options { resolutions: vec![chosen, omit], ..Options::default() };
    let c = compose_runs(&base(), &d(), &sides, None, &both, &unread);
    assert_eq!(runs(&c), vec![rd(1, 8), rd(20, 3), rd(30, 2), rd(9, 1)], "and with side 1's placement");
    assert_eq!((c.gaps[1].kind, c.gaps[1].placed.clone()), (GapKind::Collision, Placement::Omitted));
    assert!(c.ignored.is_empty());
}

/// A gap holding other words beside the moved ones keeps its number: the
/// head adds "ab" and "big" at `D·4|D·5`, the side "cd" there and "big"
/// after `D·8`. At the defaults the `order` gap 2 holds "ab", "big" and
/// "cd"; with side 1's placement chosen it holds "ab" and "cd", still gap
/// 2, so an order naming 2 given with that choice applies there, and the
/// record's options compose the same M (the mutant that matches the gaps
/// by their whole runs numbers it 3 and ignores the order).
#[test]
fn a_gap_that_keeps_other_words_beside_the_moved_ones_keeps_its_number() {
    let sides = two(vec![rd(1, 4), rd(12, 2), rd(20, 3), rd(5, 7)], vec![rd(1, 4), rd(16, 2), rd(5, 4), rd(20, 3), rd(9, 3)]);
    let at_default = compose(&base(), &sides);
    assert_eq!(kinds(&at_default), vec![(GapKind::Moves, false), (GapKind::Order, false)]);
    assert_eq!(gap_runs(&at_default)[1], vec![(0, rd(12, 2)), (0, rd(20, 3)), (1, rd(16, 2))]);
    let resolutions = vec![
        Resolution { gap: GapId(1), choice: Choice::Order(vec![SideIx(1)]), by: ResolvedBy::Person },
        Resolution { gap: GapId(2), choice: Choice::Order(vec![SideIx(1), SideIx(0)]), by: ResolvedBy::Person },
    ];
    let c = compose_runs(&base(), &d(), &sides, None, &Options { resolutions, ..Options::default() }, &unread);
    assert_eq!(runs(&c), vec![rd(1, 4), rd(16, 2), rd(12, 2), rd(5, 4), rd(20, 3), rd(9, 3)]);
    assert_eq!(c.gaps.iter().map(|g| g.id.0).collect::<Vec<_>>(), vec![1, 2]);
    assert_eq!(kinds(&c), vec![(GapKind::Moves, true), (GapKind::Order, true)]);
    assert!(c.ignored.is_empty(), "{:?}", c.ignored);
    let again = compose_runs(&base(), &d(), &sides, None, &recorded(&c).options(), &unread);
    assert_eq!((runs(&again), &again.gaps), (runs(&c), &c.gaps));
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

/// `KeepBoth` confirms the placement the dedup left at a gap of three.
///
/// At three sides' `order` gap where the dedup kept the head's "big " and
/// the first daughter's "fat " and dropped the second daughter's "big ",
/// `KeepBoth` settles it with those two alone, the dropped copy out of M
/// (§5, case (g); the mutant that places every side's group puts it back).
#[test]
fn keep_both_confirms_the_placement_the_dedup_left() {
    let values = text(&[(1, "the cat sat"), (12, "big "), (16, "big "), (20, "fat ")]);
    let sides = [
        (SideIx(0), vec![rd(1, 4), rd(12, 4), rd(5, 7)]),
        (SideIx(1), vec![rd(1, 4), rd(20, 4), rd(5, 7)]),
        (SideIx(2), vec![rd(1, 4), rd(16, 4), rd(5, 7)]),
    ];
    let at_default = compose_runs(&base(), &d(), &sides, None, &Options::default(), &values);
    assert_eq!(at_default.gaps[0].placed, Placement::Order(vec![SideIx(0), SideIx(1)]));
    let c = compose_runs(&base(), &d(), &sides, None, &resolve(1, Choice::KeepBoth), &values);
    assert_eq!(runs(&c), runs(&at_default), "the dropped copy stays out of M");
    assert_eq!(
        (c.gaps[0].placed.clone(), c.gaps[0].settled, c.gaps[0].resolved_by.clone()),
        (Placement::Order(vec![SideIx(0), SideIx(1)]), true, Some(ResolvedBy::Person))
    );
    assert_eq!(c.values.applied, vec![GapId(1)]);
    assert!(c.ignored.is_empty());
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
///
/// Of two choices at it, the later stands, as at every gap: `Order([B])`
/// then `Order([A])` gives A's order, settled by the second, the first in
/// `ignored`; the two the other way round give B's (the mutant that walks
/// again under the first choice of B whatever follows it gives B's order
/// with A's choice ignored).
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
    let order = |side: u8, by: ResolvedBy| Resolution {
        gap: GapId(1),
        choice: Choice::Order(vec![SideIx(side)]),
        by,
    };
    let a_order = vec![rd(2, 1), rd(1, 1), rd(3, 1)];
    let b_order = vec![rd(1, 1), rd(3, 1), rd(2, 1)];
    for (first, last, m) in [(1, 0, a_order), (0, 1, b_order)] {
        let given = vec![order(first, ResolvedBy::Person), order(last, ResolvedBy::Agent)];
        let options = Options { resolutions: given.clone(), ..Options::default() };
        let c = compose_runs(&[rd(1, 3)], &d(), &sides, None, &options, &unread);
        assert_eq!(runs(&c), m, "the later of {given:?} stands");
        assert_eq!(
            (c.gaps[0].placed.clone(), c.gaps[0].settled, c.gaps[0].resolved_by.clone()),
            (Placement::Order(vec![SideIx(last)]), true, Some(ResolvedBy::Agent)),
            "{given:?}"
        );
        assert_eq!(c.ignored, vec![given[0].clone()], "the earlier of {given:?} not applied");
    }
}

/// A resolution naming a gap the rules settled, a gap not in the report,
/// or a choice the gap cannot take is ignored and returned untouched.
///
/// A move is as little a choice at a gap the rules settled as any other: at
/// (f)'s `anchor` and at (g)'s `order` gap the dedup settled, `After(D·11)`
/// and `Before(D·1)` leave M and the gaps as composed and stand in `ignored`
/// (the mutant whose moves skip the rule's test moves the gap and reports
/// the move ignored, which a record re-states nowhere).
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
    let same = text(&[(1, "the cat sat"), (12, "big "), (16, "big ")]);
    let dedup = two(vec![rd(1, 4), rd(12, 4), rd(5, 7)], vec![rd(1, 4), rd(16, 4), rd(5, 7)]);
    for (name, sides, values) in [
        ("(f)", &sides, &unread as &dyn Fn(SideIx, &Run) -> Option<Vec<Item>>),
        ("(g)", &dedup, &same),
    ] {
        let composed = compose_runs(&base(), &d(), sides, None, &Options::default(), values);
        assert!(composed.gaps[0].settled, "{name}: the rules settle gap 1");
        for choice in [Choice::After(d_at(11)), Choice::Before(d_at(1))] {
            let res = Resolution { gap: GapId(1), choice: choice.clone(), by: ResolvedBy::Person };
            let options = Options { resolutions: vec![res.clone()], ..Options::default() };
            let moved = compose_runs(&base(), &d(), sides, None, &options, values);
            assert_eq!(
                (runs(&moved), &moved.gaps),
                (runs(&composed), &composed.gaps),
                "{name}: {choice:?} moved a settled gap"
            );
            assert_eq!(moved.ignored, vec![res], "{name}: {choice:?}");
        }
    }
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

// ── a line's edge (skep #1173) ───────────────────────────────────────────

/// The lined base, `D·1–35`: "one\n" at `D·1–4`, "two reads the model.
/// The\n" at `D·5–29` — its break `D·29` — and "three\n" at `D·30–35`.
fn lined() -> Vec<Run> {
    vec![rd(1, 35)]
}

/// The lined cells' bytes: the base, the head's "h1\nh2 The\n" at
/// `D·36–45`, the side's "Every\ns1 " at `D·46–54`, and one-letter words
/// at `D·60…`.
const LINED: &[(u64, &str)] = &[
    (1, "one\ntwo reads the model. The\nthree\n"),
    (36, "h1\nh2 The\n"),
    (46, "Every\ns1 "),
    (60, "xytu"),
];

/// A side of the lined base adding `fresh` right after `D·at`, `0` the
/// document's start.
fn adding_after(at: u64, fresh: Run) -> Vec<Run> {
    let mut side = Vec::new();
    if at > 0 {
        side.push(rd(1, at));
    }
    side.push(fresh);
    if at < 35 {
        side.push(rd(at + 1, 35 - at));
    }
    side
}

/// The reproduction: the head's lines after line 2's break, the side's
/// rewrite inside line 2, before its kept "The\n".
fn rewrite_beside_lines() -> Vec<(SideIx, Vec<Run>)> {
    two(adding_after(29, rd(36, 10)), adding_after(25, rd(46, 9)))
}

/// Composes over the lined base with `options` under the lined bytes.
fn compose_lined(sides: &[(SideIx, Vec<Run>)], options: &Options) -> Composed {
    compose_runs(&lined(), &d(), sides, None, options, &text(LINED))
}

/// A rewrite inside a line beside another side's lines right after its
/// break asks twice: each side's words a `line` gap, unsettled, at its own
/// place, so M is as composed with no rule — the head's lines after
/// `D·29`, the side's words after `D·25` — whatever the value rule's
/// switches; read by no value, nothing asks (the mutant whose check never
/// fires answers no gap).
#[test]
fn a_rewrite_inside_a_line_beside_lines_after_its_break_is_two_line_gaps() {
    let m = vec![rd(1, 25), rd(46, 9), rd(26, 4), rd(36, 10), rd(30, 6)];
    for options in [Options::default(), Options { dedup: false, ..Options::default() }] {
        let c = compose_lined(&rewrite_beside_lines(), &options);
        assert_eq!(runs(&c), m, "{options:?}: M at the defaults");
        assert_eq!(kinds(&c), vec![(GapKind::Line, false), (GapKind::Line, false)], "{options:?}");
        assert_eq!(anchors(&c), vec![(Some(25), Some(26)), (Some(29), Some(30))], "{options:?}");
        assert_eq!(gap_runs(&c), vec![vec![(1, rd(46, 9))], vec![(0, rd(36, 10))]], "{options:?}");
        assert_eq!(
            c.gaps
                .iter()
                .map(|g| (g.id, g.placed.clone(), g.resolved_by.clone()))
                .collect::<Vec<_>>(),
            vec![(GapId(1), Placement::After, None), (GapId(2), Placement::After, None)],
            "{options:?}"
        );
        assert_eq!(c.counts, RunCounts { a: 3, b: 3, m: 5 }, "{options:?}");
    }
    let c = compose(&lined(), &rewrite_beside_lines());
    assert_eq!((runs(&c), kinds(&c)), (m, vec![]), "no value read, nothing asked");
}

/// The mirror asks too: an addition at a line's start beside another
/// side's inside that line — after `D·29` and after `D·31`, line 3 — and
/// at the document's start beside one inside line 1, after `D·2`.
#[test]
fn an_addition_at_a_lines_start_beside_one_inside_that_line_is_two_line_gaps() {
    for (start, inside, expected) in [
        (29, 31, vec![(Some(29), Some(30)), (Some(31), Some(32))]),
        (0, 2, vec![(None, Some(1)), (Some(2), Some(3))]),
    ] {
        let c = compose_lined(
            &two(adding_after(start, rd(36, 10)), adding_after(inside, rd(46, 9))),
            &Options::default(),
        );
        assert_eq!(
            kinds(&c),
            vec![(GapKind::Line, false), (GapKind::Line, false)],
            "after D·{start} and D·{inside}"
        );
        assert_eq!(anchors(&c), expected, "after D·{start} and D·{inside}");
        let unasked = compose(
            &lined(),
            &two(adding_after(start, rd(36, 10)), adding_after(inside, rd(46, 9))),
        );
        assert_eq!(runs(&c), runs(&unasked), "after D·{start} and D·{inside}: M at the defaults");
    }
}

/// Two additions that do not meet at one line's edge ask nothing: both
/// inside line 2 (after `D·8` and `D·17`); a whole line apart (line 2's
/// start, `D·4`, and its break, `D·29`); two lines apart (`D·2` and
/// `D·29`); inside line 2 and inside line 3, one break between not its
/// last byte (`D·25` and `D·31`).
#[test]
fn additions_inside_one_line_or_a_line_apart_ask_nothing() {
    for (a, b) in [(8, 17), (4, 29), (2, 29), (25, 31)] {
        let c = compose_lined(
            &two(adding_after(a, rd(36, 10)), adding_after(b, rd(46, 9))),
            &Options::default(),
        );
        assert_eq!(kinds(&c), vec![], "after D·{a} and D·{b}");
    }
}

/// Words both sides add at one spot after a break stay one `order` gap; a
/// side's words inside the line beside it are a `line` gap, the gap of
/// both sides' words left to the order rule (the mutant that marks every
/// caught gap a `line` gap answers two).
#[test]
fn words_two_sides_add_at_one_spot_stay_an_order_gap() {
    let c = compose_lined(
        &two(adding_after(29, rd(36, 3)), adding_after(29, rd(46, 9))),
        &Options::default(),
    );
    assert_eq!(
        (kinds(&c), anchors(&c)),
        (vec![(GapKind::Order, false)], vec![(Some(29), Some(30))])
    );
    let side = vec![rd(1, 25), rd(46, 9), rd(26, 4), rd(60, 1), rd(30, 6)];
    let c = compose_lined(&two(adding_after(29, rd(36, 3)), side), &Options::default());
    assert_eq!(kinds(&c), vec![(GapKind::Line, false), (GapKind::Order, false)]);
    assert_eq!(anchors(&c), vec![(Some(25), Some(26)), (Some(29), Some(30))]);
}

/// A rewrite of the whole line is no `line` gap: the side removing line 2
/// and typing its words in its place keeps R2's `anchor`, settled by the
/// rule, the head's lines after the side's words.
#[test]
fn a_whole_line_rewritten_beside_lines_after_it_stays_an_anchor() {
    let c = compose_lined(
        &two(adding_after(29, rd(36, 10)), vec![rd(1, 4), rd(46, 9), rd(30, 6)]),
        &Options::default(),
    );
    assert_eq!(runs(&c), vec![rd(1, 4), rd(46, 9), rd(36, 10), rd(30, 6)]);
    assert_eq!(kinds(&c), vec![(GapKind::Anchor, true)]);
    assert_eq!(c.gaps[0].resolved_by, Some(ResolvedBy::Rule));
}

/// A `line` gap takes the choices a one-group gap takes: `Omit` leaves the
/// side's words out, `KeepOnly` of its side and `Order` of it keep them
/// where they stand, `After` moves them, each settling the gap by the
/// chooser; `KeepBoth` is no choice there and stands in `ignored`.
#[test]
fn a_line_gap_takes_omit_keep_only_and_a_move() {
    let sides = rewrite_beside_lines();
    let at_defaults = runs(&compose_lined(&sides, &Options::default()));
    let c = compose_lined(&sides, &resolve(1, Choice::Omit));
    assert_eq!(runs(&c), vec![rd(1, 29), rd(36, 10), rd(30, 6)], "the side's words out");
    assert_eq!(kinds(&c), vec![(GapKind::Line, true), (GapKind::Line, false)]);
    assert_eq!(
        (c.gaps[0].placed.clone(), c.gaps[0].resolved_by.clone()),
        (Placement::Omitted, Some(ResolvedBy::Person))
    );
    for choice in [Choice::KeepOnly(SideIx(1)), Choice::Order(vec![SideIx(1)])] {
        let c = compose_lined(&sides, &resolve(1, choice.clone()));
        assert_eq!(runs(&c), at_defaults, "{choice:?}");
        assert_eq!(kinds(&c), vec![(GapKind::Line, true), (GapKind::Line, false)], "{choice:?}");
        assert!(c.ignored.is_empty(), "{choice:?}");
    }
    let c = compose_lined(&sides, &resolve(2, Choice::After(d_at(25))));
    assert_eq!(
        runs(&c),
        vec![rd(1, 25), rd(46, 9), rd(36, 10), rd(26, 10)],
        "the head's lines moved after D·25"
    );
    assert_eq!((kinds(&c)[1], anchors(&c)[1]), ((GapKind::Line, true), (Some(25), Some(26))));
    let c = compose_lined(&sides, &resolve(1, Choice::KeepBoth));
    assert_eq!(
        (runs(&c), kinds(&c)),
        (at_defaults, vec![(GapKind::Line, false), (GapKind::Line, false)])
    );
    assert_eq!(c.ignored.len(), 1);
}

/// The `line` gaps keep their numbers under every choice that walks again.
///
/// Beside a `moves` gap with spots — both sides hold "xy" (`D·60–61`), the
/// head after `D·1`, the side after `D·2` — and an `order` gap at the end,
/// choosing the side's placement of "xy" leaves the `line` gaps 2 and 3
/// and the `order` gap 4 as numbered (the mutant whose walk at the claims'
/// defaults reads no base text numbers the `order` gap 2). Beside a spine's
/// `moves` gap — crossed reorders of `D·31–33` — choosing the side's order
/// walks the spine again and leaves the `line` gaps 2 and 3.
#[test]
fn the_line_gaps_keep_their_numbers_under_a_holders_choice_and_a_chosen_order() {
    let ends = |side: Vec<Run>, word: u64| {
        let mut side = side;
        side.push(rd(word, 1));
        side
    };
    let head = ends(vec![rd(1, 1), rd(60, 2), rd(2, 28), rd(36, 10), rd(30, 6)], 62);
    let side = ends(vec![rd(1, 2), rd(60, 2), rd(3, 23), rd(46, 9), rd(26, 10)], 63);
    let sides = two(head, side);
    let numbered = |c: &Composed| c.gaps.iter().map(|g| (g.id, g.kind)).collect::<Vec<_>>();
    let at_defaults = compose_lined(&sides, &Options::default());
    let expected = vec![
        (GapId(1), GapKind::Moves),
        (GapId(2), GapKind::Line),
        (GapId(3), GapKind::Line),
        (GapId(4), GapKind::Order),
    ];
    assert_eq!(numbered(&at_defaults), expected, "the premise");
    let chosen = compose_lined(&sides, &resolve(1, Choice::Order(vec![SideIx(1)])));
    assert_eq!(runs(&chosen)[..3], [rd(1, 2), rd(60, 2), rd(3, 23)], "the side's placement of xy");
    assert_eq!(numbered(&chosen), expected);
    assert_eq!(
        gap_runs(&chosen)[1..],
        gap_runs(&at_defaults)[1..],
        "the same gaps by their numbers"
    );
    let head = vec![rd(1, 29), rd(36, 10), rd(30, 1), rd(32, 1), rd(31, 1), rd(33, 3)];
    let side = vec![rd(1, 25), rd(46, 9), rd(26, 5), rd(31, 1), rd(33, 1), rd(32, 1), rd(34, 2)];
    let crossed = two(head, side);
    let at_defaults = compose_lined(&crossed, &Options::default());
    let expected =
        vec![(GapId(1), GapKind::Moves), (GapId(2), GapKind::Line), (GapId(3), GapKind::Line)];
    assert_eq!(numbered(&at_defaults), expected, "the premise");
    let chosen = compose_lined(&crossed, &resolve(1, Choice::Order(vec![SideIx(1)])));
    assert_eq!(
        runs(&chosen)[4..],
        [rd(30, 2), rd(33, 1), rd(32, 1), rd(34, 2)],
        "the side's order"
    );
    assert_eq!(numbered(&chosen), expected);
    assert_eq!(
        gap_runs(&chosen)[1..],
        gap_runs(&at_defaults)[1..],
        "the same gaps by their numbers"
    );
}

/// A holder's choice unmakes the `line` gaps its moved words partnered.
///
/// Both sides hold "x" (`D·60`), the head after `D·25` and the side after
/// `D·2`, and the side writes lines after line 2's break besides. At the
/// defaults "x" stands at the head's place, inside line 2: a `moves` gap
/// with spots, and "x" and the side's lines `line` gaps 2 and 3. Choosing
/// the side's placement moves "x" beside the side's own words, which meet
/// no other side's change: no `line` gap stands, gap 3's number is left
/// unused and a choice naming it stands in `ignored`.
#[test]
fn a_holders_choice_that_unmakes_a_line_gap_leaves_its_number_unused() {
    let side = vec![rd(1, 2), rd(60, 1), rd(3, 27), rd(46, 9), rd(30, 6)];
    let sides = two(adding_after(25, rd(60, 1)), side.clone());
    let numbered =
        |c: &Composed| c.gaps.iter().map(|g| (g.id, g.kind, g.settled)).collect::<Vec<_>>();
    let at_defaults = compose_lined(&sides, &Options::default());
    assert_eq!(
        numbered(&at_defaults),
        vec![
            (GapId(1), GapKind::Moves, false),
            (GapId(2), GapKind::Line, false),
            (GapId(3), GapKind::Line, false)
        ],
        "the premise"
    );
    let mut choices = resolve(1, Choice::Order(vec![SideIx(1)])).resolutions;
    choices.extend(resolve(3, Choice::KeepOnly(SideIx(1))).resolutions);
    let chosen =
        compose_lined(&sides, &Options { resolutions: choices.clone(), ..Options::default() });
    assert_eq!(runs(&chosen), side, "the side's placement of x");
    assert_eq!(numbered(&chosen), vec![(GapId(1), GapKind::Moves, true)]);
    assert_eq!(chosen.ignored, choices[1..], "gap 3's number unused");
}

/// A read not answering one item a position decides nothing: a reader
/// answering a run of more than one position with its last item alone
/// leaves the reproduction unasked (the mutant that weighs the items
/// whatever their count reads "\n" as the text between and asks).
#[test]
fn a_read_answering_another_count_of_items_decides_nothing() {
    let bytes = text(LINED);
    let last_alone = |side: SideIx, run: &Run| -> Option<Vec<Item>> {
        let items = bytes(side, run)?;
        Some(if run.width > 1 { items.last().into_iter().cloned().collect() } else { items })
    };
    let c = compose_runs(
        &lined(),
        &d(),
        &rewrite_beside_lines(),
        None,
        &Options::default(),
        &last_alone,
    );
    assert_eq!(kinds(&c), vec![]);
}

/// The line rule as a property: over short bases of lines — empty lines
/// among them — and two sides each adding one word at a place drawn at
/// random, the two are `line` gaps exactly where the base text between
/// them is one break, its last byte, and the first is not at a line's
/// start, or holds no break and the first is; at one place they are one
/// `order` gap; and M is the composition read by no value.
#[test]
fn the_line_rule_holds_over_generated_lines() {
    let mut rng = Rng(0x11E5_ED6E);
    let mut asked = 0;
    for case in 0..3000 {
        let n = 1 + rng.below(8);
        let base: Vec<u8> = (0..n).map(|_| b"ab\n"[rng.below(3) as usize]).collect();
        let mut table = vec![(100u64, b'x'), (101, b'y')];
        table.extend(base.iter().enumerate().map(|(k, b)| (1 + k as u64, *b)));
        let values = |_: SideIx, run: &Run| -> Option<Vec<Item>> {
            (run.i_start..run.reach())
                .map(|p| table.iter().find(|(q, _)| *q == p).map(|(_, b)| vec![*b]))
                .collect()
        };
        let (i, j) = (rng.below(n + 1), rng.below(n + 1));
        let at = |k: u64, fresh: u64| {
            let mut side = Vec::new();
            if k > 0 {
                side.push(rd(1, k));
            }
            side.push(rd(fresh, 1));
            if k < n {
                side.push(rd(k + 1, n - k));
            }
            side
        };
        let sides = two(at(i, 100), at(j, 101));
        let c = compose_runs(&[rd(1, n)], &d(), &sides, None, &Options::default(), &values);
        let say = format!("case {case}: {:?}, after {i} and {j}", String::from_utf8_lossy(&base));
        assert_eq!(runs(&c), runs(&compose(&[rd(1, n)], &sides)), "{say}: M at the defaults");
        if i == j {
            assert_eq!(kinds(&c), vec![(GapKind::Order, false)], "{say}");
            continue;
        }
        let (lo, hi) = (i.min(j) as usize, i.max(j) as usize);
        let between = &base[lo..hi];
        let start = lo == 0 || base[lo - 1] == b'\n';
        let breaks = between.iter().filter(|b| **b == b'\n').count();
        let meets =
            (breaks == 1 && between.last() == Some(&b'\n') && !start) || (breaks == 0 && start);
        let expected =
            if meets { vec![(GapKind::Line, false), (GapKind::Line, false)] } else { vec![] };
        assert_eq!(kinds(&c), expected, "{say}");
        asked += usize::from(meets);
    }
    assert!(asked > 100, "the line rule fired in {asked} cases");
}

/// Composes over a base of `bytes` at `D·1…`, one side adding "x" right
/// after `D·i` and the other "y" right after `D·j`, `0` the document's
/// start, reading every value through a closure that counts the positions
/// asked; answers the composition and that count.
fn compose_over_bytes(bytes: &[u8], i: u64, j: u64) -> (Composed, u64) {
    let n = bytes.len() as u64;
    let (x, y) = (n + 10, n + 20);
    let asked = std::cell::Cell::new(0u64);
    let values = |_: SideIx, run: &Run| -> Option<Vec<Item>> {
        asked.set(asked.get() + run.width);
        (run.i_start..run.reach())
            .map(|p| match p {
                p if p == x => Some(vec![b'x']),
                p if p == y => Some(vec![b'y']),
                p if (1..=n).contains(&p) => Some(vec![bytes[p as usize - 1]]),
                _ => None,
            })
            .collect()
    };
    let at = |k: u64, fresh: u64| {
        let mut side = Vec::new();
        if k > 0 {
            side.push(rd(1, k));
        }
        side.push(rd(fresh, 1));
        if k < n {
            side.push(rd(k + 1, n - k));
        }
        side
    };
    let sides = two(at(i, x), at(j, y));
    let c = compose_runs(&[rd(1, n)], &d(), &sides, None, &Options::default(), &values);
    (c, asked.get())
}

/// Whether additions right after `D·i` and `D·j` of `bytes` meet at a
/// line's edge, the rule read off the whole text between them.
fn meets_directly(bytes: &[u8], i: u64, j: u64) -> bool {
    let (lo, hi) = (i.min(j) as usize, i.max(j) as usize);
    let between = &bytes[lo..hi];
    let start = lo == 0 || bytes[lo - 1] == b'\n';
    let breaks = between.iter().filter(|b| **b == b'\n').count();
    (breaks == 1 && between.last() == Some(&b'\n') && !start) || (breaks == 0 && start)
}

/// A line longer than the first read is read on to its end: inside a line
/// of `LINE_READ` + 10 bytes, its last its break, an addition after `D·1`
/// and another right after that break are two `line` gaps, the whole text
/// between them read; a break `LINE_READ` + 5 into that text, found by the
/// reads on, asks nothing; one 10 into it, found by the first reads, asks
/// nothing and reads no further (the mutant that never reads past the
/// first reads asks nothing in the first cell).
#[test]
fn a_line_longer_than_the_first_read_is_read_on_to_its_end() {
    let width = LINE_READ + 10;
    let lined = |breaks: &[u64]| {
        let mut bytes = vec![b'a'];
        let mut text = vec![b'b'; width as usize];
        text[width as usize - 1] = b'\n';
        for &k in breaks {
            text[k as usize] = b'\n';
        }
        bytes.extend(text);
        bytes.push(b'c');
        bytes
    };
    let (c, asked) = compose_over_bytes(&lined(&[]), 1, 1 + width);
    assert_eq!(kinds(&c), vec![(GapKind::Line, false), (GapKind::Line, false)]);
    assert_eq!(asked, 1 + width, "the position before and the whole text");
    let (c, _) = compose_over_bytes(&lined(&[LINE_READ + 5]), 1, 1 + width);
    assert_eq!(kinds(&c), vec![], "a break the reads on find");
    let (c, asked) = compose_over_bytes(&lined(&[10]), 1, 1 + width);
    assert_eq!(kinds(&c), vec![], "a break the first reads find");
    assert_eq!(asked, 1 + LINE_READ + 1, "the first reads alone");
}

/// The line rule reads what decides it: over ten times `LINE_READ`
/// positions of short lines, additions at the document's two ends, or
/// inside its first and last lines, are asked at most `LINE_READ` + 2
/// positions, and ask nothing (the mutant that reads the whole text asks
/// for every position).
#[test]
fn the_line_rule_reads_what_decides_it_whatever_the_texts_length() {
    let bytes: Vec<u8> = b"ab\n".iter().copied().cycle().take(10 * LINE_READ as usize).collect();
    let n = bytes.len() as u64;
    for (i, j) in [(0, n), (1, n - 1)] {
        let (c, asked) = compose_over_bytes(&bytes, i, j);
        assert_eq!(kinds(&c), vec![], "after D·{i} and D·{j}");
        assert!(asked <= LINE_READ + 2, "after D·{i} and D·{j}: {asked} positions asked");
    }
}

/// The line rule as a property over texts about `LINE_READ` long and
/// longer: whatever the text's width — drawn at the edges of the first
/// read and of the reads on, or at random up to four times it — its breaks
/// at those edges or at random, its last byte a break or not, and the
/// first addition at the document's start, after a break or inside a
/// line, the two are `line` gaps exactly where the rule read off the whole
/// text says; no read asks more than the text and the position before it;
/// an answer the first reads decide is read no further; and a meet is read
/// whole, since only the whole text says no break stands before its last
/// byte.
#[test]
fn the_line_rule_reads_on_exactly_as_far_as_its_answer_needs() {
    let lr = LINE_READ;
    let edges = [
        1,
        2,
        3,
        lr - 1,
        lr,
        lr + 1,
        lr + 2,
        3 * lr - 1,
        3 * lr,
        3 * lr + 1,
        3 * lr + 2,
        7 * lr + 1,
    ];
    let mut rng = Rng(0x00C0_FFEE);
    let mut met = 0;
    for case in 0..600 {
        let w = if case % 2 == 0 {
            edges[rng.below(edges.len() as u64) as usize]
        } else {
            1 + rng.below(4 * lr)
        };
        let mut text = vec![b'a'; w as usize];
        for _ in 0..rng.below(3) {
            let at = match rng.below(3) {
                0 => rng.below(w),
                _ => [lr - 1, lr, lr + 1, 3 * lr - 1, 3 * lr][rng.below(5) as usize].min(w - 1),
            };
            text[at as usize] = b'\n';
        }
        if rng.below(2) == 0 {
            text[w as usize - 1] = b'\n';
        }
        let prefix: &[u8] = [&b""[..], &b"\n"[..], &b"a"[..]][rng.below(3) as usize];
        let mut bytes = prefix.to_vec();
        bytes.extend(&text);
        bytes.push(b'z');
        let (i, j) = (prefix.len() as u64, prefix.len() as u64 + w);
        let (c, asked) = compose_over_bytes(&bytes, i, j);
        let breaks: Vec<usize> =
            text.iter().enumerate().filter(|(_, b)| **b == b'\n').map(|(k, _)| k).collect();
        let say = format!("case {case}: width {w}, prefix {prefix:?}, breaks at {breaks:?}");
        let meets = meets_directly(&bytes, i, j);
        let expected =
            if meets { vec![(GapKind::Line, false), (GapKind::Line, false)] } else { vec![] };
        assert_eq!(kinds(&c), expected, "{say}");
        let before = u64::from(!prefix.is_empty());
        assert!(asked <= before + w, "{say}: {asked} positions asked");
        let start = prefix != b"a";
        let first_break = breaks.first().map(|&k| k as u64).filter(|&k| k + 1 < w);
        if (text[w as usize - 1] == b'\n') == start || first_break.is_some_and(|k| k < lr) {
            assert!(
                asked <= before + lr.min(w - 1) + 1,
                "{say}: decided by the first reads, {asked} positions asked"
            );
        }
        if meets {
            assert_eq!(asked, before + w, "{say}: a meet reads the whole text");
            met += 1;
        }
    }
    assert!(met > 50, "the rule met in {met} cases");
}

// ── a removal beside a line's edge (skep #1176) ──────────────────────────

/// A side of the lined base removing `D·from–to` and keeping the rest.
fn removing(from: u64, to: u64) -> Vec<Run> {
    let mut side = Vec::new();
    if from > 1 {
        side.push(rd(1, from - 1));
    }
    if to < 35 {
        side.push(rd(to + 1, 35 - to));
    }
    side
}

/// The removal beside lines: the head removes "eads " (`D·10–14`) inside
/// line 2, and the side adds "h1\nh2 The\n" (`D·36–45`) right after line
/// 2's break.
fn removal_beside_lines() -> Vec<(SideIx, Vec<Run>)> {
    two(removing(10, 14), adding_after(29, rd(36, 10)))
}

/// The removal `D·10–14` as a `line` gap names it: by `side`, between
/// `D·9` and `D·15`.
fn removed_inside_line_2(side: u8) -> Vec<Removed> {
    vec![Removed { side: SideIx(side), after: Some(d_at(9)), before: Some(d_at(15)) }]
}

/// A removal inside a line beside another side's addition right after its
/// break asks: the addition is a `line` gap, unsettled, at its own place,
/// naming the removal by its side and its anchors `D·9` and `D·15`, and M
/// is as composed with no rule, whatever the value rule's switches and
/// whichever side is listed first; read by no value, nothing asks (the
/// mutant that weighs no removal answers no gap).
#[test]
fn a_removal_inside_a_line_beside_an_addition_after_its_break_is_a_line_gap_naming_it() {
    let m = vec![rd(1, 9), rd(15, 15), rd(36, 10), rd(30, 6)];
    for options in [Options::default(), Options { dedup: false, ..Options::default() }] {
        let c = compose_lined(&removal_beside_lines(), &options);
        assert_eq!(runs(&c), m, "{options:?}: M at the defaults");
        assert_eq!(kinds(&c), vec![(GapKind::Line, false)], "{options:?}");
        assert_eq!(anchors(&c), vec![(Some(29), Some(30))], "{options:?}");
        assert_eq!(gap_runs(&c), vec![vec![(1, rd(36, 10))]], "{options:?}");
        assert_eq!(
            (c.gaps[0].placed.clone(), c.gaps[0].resolved_by.clone()),
            (Placement::After, None),
            "{options:?}"
        );
        assert_eq!(c.gaps[0].removed, removed_inside_line_2(0), "{options:?}");
    }
    let swapped =
        compose_lined(&two(adding_after(29, rd(36, 10)), removing(10, 14)), &Options::default());
    assert_eq!(runs(&swapped), m, "the side listed first adds: M");
    assert_eq!(kinds(&swapped), vec![(GapKind::Line, false)], "the side listed first adds");
    assert_eq!(swapped.gaps[0].removed, removed_inside_line_2(1), "the side listed first adds");
    let c = compose(&lined(), &removal_beside_lines());
    assert_eq!((runs(&c), kinds(&c)), (m, vec![]), "no value read, nothing asked");
}

/// The mirror asks too: an addition at a line's start beside another
/// side's removal inside that line — after `D·4`, line 2's start, beside
/// `D·10–14` — and at the document's start beside a removal inside line 1,
/// `D·2–3`.
#[test]
fn an_addition_at_a_lines_start_beside_a_removal_inside_that_line_is_a_line_gap() {
    for (start, (from, to), place, (after, before)) in
        [(4, (10, 14), (Some(4), Some(5)), (9, 15)), (0, (2, 3), (None, Some(1)), (1, 4))]
    {
        let sides = two(adding_after(start, rd(36, 10)), removing(from, to));
        let c = compose_lined(&sides, &Options::default());
        let say = format!("after D·{start}, D·{from}–{to} removed");
        assert_eq!(kinds(&c), vec![(GapKind::Line, false)], "{say}");
        assert_eq!(anchors(&c), vec![place], "{say}");
        assert_eq!(
            c.gaps[0].removed,
            vec![Removed { side: SideIx(1), after: Some(d_at(after)), before: Some(d_at(before)) }],
            "{say}"
        );
        assert_eq!(runs(&c), runs(&compose(&lined(), &sides)), "{say}: M at the defaults");
    }
}

/// A removal and an addition apart from one line's edge ask nothing:
/// `D·10–14` beside an addition after `D·35`, two lines on; a removal from
/// line 2's start, `D·5–9`, beside an addition right after its break, a
/// whole line apart; `D·10–14` beside an addition after `D·25`, inside
/// line 2; a removal inside line 1, `D·2–3`, beside an addition after line
/// 2's break. Nor does a side's removal beside its own addition, nor a
/// removal its side set words in place of: that rewrite is an addition,
/// which asks beside the other side's as two additions do, naming no
/// removal (the mutant that weighs a rewritten removal names it).
#[test]
fn a_removal_and_an_addition_apart_from_one_lines_edge_ask_nothing() {
    for ((from, to), at) in [((10, 14), 35), ((5, 9), 29), ((10, 14), 25), ((2, 3), 29)] {
        let c = compose_lined(
            &two(removing(from, to), adding_after(at, rd(36, 10))),
            &Options::default(),
        );
        assert_eq!(kinds(&c), vec![], "D·{from}–{to} removed, an addition after D·{at}");
    }
    let own = vec![rd(1, 9), rd(15, 15), rd(36, 10), rd(30, 6)];
    let c = compose_lined(&two(lined(), own), &Options::default());
    assert_eq!(kinds(&c), vec![], "one side's removal beside its own addition");
    let rewrite = vec![rd(1, 9), rd(60, 2), rd(15, 21)];
    let c = compose_lined(&two(rewrite, adding_after(29, rd(36, 10))), &Options::default());
    assert_eq!(
        kinds(&c),
        vec![(GapKind::Line, false), (GapKind::Line, false)],
        "a rewrite inside line 2"
    );
    assert!(c.gaps.iter().all(|g| g.removed.is_empty()), "no removal named: {:?}", c.gaps);
}

/// A removal farther from an addition than another removal still meets it:
/// one side removes "tw" from line 2's start (`D·5–6`) and "ea" inside it
/// (`D·10–11`), the other adds "x" inside that line, after `D·25`. The
/// nearer removal, inside the line, meets nothing, and the walk goes on
/// past it, no break between: the farther one, at the line's start, meets
/// the addition inside that line, and the gap names it alone (the mutants
/// that weigh only a removal's nearest neighbour among the changes, or end
/// the walk at a pair that does not meet, ask nothing).
#[test]
fn a_removal_at_a_lines_start_meets_an_addition_inside_it_past_a_nearer_removal() {
    let sides = two(vec![rd(1, 4), rd(7, 3), rd(12, 24)], adding_after(25, rd(60, 1)));
    let c = compose_lined(&sides, &Options::default());
    assert_eq!(runs(&c), vec![rd(1, 4), rd(7, 3), rd(12, 14), rd(60, 1), rd(26, 10)], "M");
    assert_eq!(kinds(&c), vec![(GapKind::Line, false)]);
    assert_eq!(anchors(&c), vec![(Some(25), Some(26))]);
    assert_eq!(
        c.gaps[0].removed,
        vec![Removed { side: SideIx(0), after: Some(d_at(4)), before: Some(d_at(7)) }]
    );
}

/// Many removals beside one addition are read a line or two from it: over
/// 2,000 lines of "ab\n", one side removes every line's "a" and the other
/// adds "x" after the last line's break, which meets nothing, or after line
/// 1's "b", which meets the removals on either side of it, at the
/// document's start and right after line 1's break. Each walk from the
/// addition stops at the first break its reads show, so the line rule asks
/// at most `LINE_READ` + 2 positions a side, however many removals share
/// the addition (the mutant that weighs every removal beside it reads each
/// one's text, millions of positions).
#[test]
fn many_removals_beside_one_addition_are_read_a_line_or_two_from_it() {
    let lines = 2000u64;
    let n = 3 * lines;
    let bytes: Vec<u8> = b"ab\n".iter().copied().cycle().take(n as usize).collect();
    let x = n + 10;
    let asked = std::cell::Cell::new(0u64);
    let values = |_: SideIx, run: &Run| -> Option<Vec<Item>> {
        asked.set(asked.get() + run.width);
        (run.i_start..run.reach())
            .map(|p| match p {
                p if p == x => Some(vec![b'x']),
                p if (1..=n).contains(&p) => Some(vec![bytes[p as usize - 1]]),
                _ => None,
            })
            .collect()
    };
    let removing: Vec<Run> = (0..lines).map(|k| rd(3 * k + 2, 2)).collect();
    let at_end = vec![rd(1, n), rd(x, 1)];
    let inside = vec![rd(1, 2), rd(x, 1), rd(3, n - 2)];
    for (adding, expected, removed) in [
        (at_end, vec![], vec![]),
        (
            inside,
            vec![(GapKind::Line, false)],
            vec![
                Removed { side: SideIx(0), after: None, before: Some(d_at(2)) },
                Removed { side: SideIx(0), after: Some(d_at(3)), before: Some(d_at(5)) },
            ],
        ),
    ] {
        asked.set(0);
        let sides = two(removing.clone(), adding);
        let c = compose_runs(&[rd(1, n)], &d(), &sides, None, &Options::default(), &values);
        assert_eq!(kinds(&c), expected, "{:?}", c.gaps);
        assert_eq!(c.gaps.iter().flat_map(|g| g.removed.clone()).collect::<Vec<_>>(), removed);
        assert!(asked.get() <= 2 * (LINE_READ + 2), "{} positions asked", asked.get());
        assert_eq!(runs(&c), runs(&compose(&[rd(1, n)], &sides)), "M at the defaults");
    }
}

/// Many removals inside one line beside one addition read that line once:
/// over one line of "ab" 500 times, one side removes every "a" and the
/// other adds "x" right after the line's break. Every removal but the one
/// at the line's start meets the addition, and the gap names the 499 in
/// M's order; the walk reaches each farther one through the nearer ones'
/// text, already read, so the line rule asks the line's positions once,
/// at most its width and two more, however many pairs share them (the
/// mutant that keeps no read asks each pair's text again, about 125,000
/// positions).
#[test]
fn many_removals_inside_one_line_beside_one_addition_read_the_line_once() {
    let pairs = 500u64;
    let n = 2 * pairs + 1;
    let mut bytes = b"ab".repeat(pairs as usize);
    bytes.push(b'\n');
    let x = n + 10;
    let asked = std::cell::Cell::new(0u64);
    let values = |_: SideIx, run: &Run| -> Option<Vec<Item>> {
        asked.set(asked.get() + run.width);
        (run.i_start..run.reach())
            .map(|p| match p {
                p if p == x => Some(vec![b'x']),
                p if (1..=n).contains(&p) => Some(vec![bytes[p as usize - 1]]),
                _ => None,
            })
            .collect()
    };
    let removing: Vec<Run> = (0..pairs).map(|k| rd(2 * k + 2, 1)).chain([rd(n, 1)]).collect();
    let sides = two(removing, vec![rd(1, n), rd(x, 1)]);
    let c = compose_runs(&[rd(1, n)], &d(), &sides, None, &Options::default(), &values);
    assert_eq!(kinds(&c), vec![(GapKind::Line, false)], "{:?}", c.gaps);
    assert_eq!(anchors(&c), vec![(Some(n), None)]);
    let removed: Vec<Removed> = (1..pairs)
        .map(|k| Removed { side: SideIx(0), after: Some(d_at(2 * k)), before: Some(d_at(2 * k + 2)) })
        .collect();
    assert_eq!(c.gaps[0].removed, removed, "each removal but the line's first, in M's order");
    assert!(asked.get() <= n + 2, "{} positions asked over a line of {n}", asked.get());
    assert_eq!(runs(&c), runs(&compose(&[rd(1, n)], &sides)), "M at the defaults");
}

/// A `line` gap a removal asks takes the addition's choices: `KeepOnly` and
/// `Order` of the adding side keep it where it stands, `After` and `Before`
/// move it, `Omit` leaves it out, each settling the gap by the chooser;
/// `KeepBoth` and `KeepOnly` of the remover are no choice there and stand
/// in `ignored`. The removal stands in every M, and the gap names it
/// wherever the addition goes.
#[test]
fn a_line_gap_a_removal_asks_takes_the_additions_choices_and_the_removal_stands() {
    let sides = removal_beside_lines();
    let at_defaults = vec![rd(1, 9), rd(15, 15), rd(36, 10), rd(30, 6)];
    for (choice, m, place) in [
        (Choice::KeepOnly(SideIx(1)), at_defaults.clone(), (Some(29), Some(30))),
        (Choice::Order(vec![SideIx(1)]), at_defaults.clone(), (Some(29), Some(30))),
        (Choice::After(d_at(9)), vec![rd(1, 9), rd(36, 10), rd(15, 21)], (Some(9), Some(15))),
        (Choice::Before(d_at(1)), vec![rd(36, 10), rd(1, 9), rd(15, 21)], (None, Some(1))),
        (Choice::Omit, vec![rd(1, 9), rd(15, 21)], (Some(29), Some(30))),
    ] {
        let c = compose_lined(&sides, &resolve(1, choice.clone()));
        assert_eq!(runs(&c), m, "{choice:?}: the removal stands");
        assert_eq!(kinds(&c), vec![(GapKind::Line, true)], "{choice:?}");
        assert_eq!(anchors(&c), vec![place], "{choice:?}");
        assert_eq!(c.gaps[0].resolved_by, Some(ResolvedBy::Person), "{choice:?}");
        assert_eq!(c.gaps[0].removed, removed_inside_line_2(0), "{choice:?}: the removal named");
        assert!(c.ignored.is_empty(), "{choice:?}");
    }
    for choice in [Choice::KeepBoth, Choice::KeepOnly(SideIx(0))] {
        let c = compose_lined(&sides, &resolve(1, choice.clone()));
        assert_eq!(
            (runs(&c), kinds(&c)),
            (at_defaults.clone(), vec![(GapKind::Line, false)]),
            "{choice:?}"
        );
        assert_eq!(c.ignored.len(), 1, "{choice:?}");
    }
}

/// A record keeps the removal a `line` gap names: a merge that left the
/// addition beside `D·10–14` out reads back from its JSON with its
/// `removed`, spelled `{side, after, before}`, and its options compose
/// again to the same M and gaps; a gap no removal asks carries no
/// `removed`, and one spelled with none reads with none, as a record
/// written before a gap named its removals (the mutants that drop the
/// removal on the write or refuse a gap without it fail the round trip or
/// the read).
#[test]
fn a_record_keeps_the_removal_a_line_gap_names() {
    let first = compose_lined(&removal_beside_lines(), &resolve(1, Choice::Omit));
    let record = recorded(&first);
    assert_eq!(record.gaps, first.gaps, "the gaps read back, the removal and all");
    let mut v = record.to_value();
    assert_eq!(
        v["gaps"][0]["removed"],
        serde_json::json!([{"side": 0, "after": d_at(9).to_string(), "before": d_at(15).to_string()}])
    );
    let again = compose_lined(&removal_beside_lines(), &record.options());
    assert_eq!((runs(&again), &again.gaps), (runs(&first), &first.gaps));
    let plain = recorded(&compose_lined(&rewrite_beside_lines(), &Options::default())).to_value();
    assert!(plain["gaps"][0].get("removed").is_none(), "a gap no removal asks carries none: {plain}");
    v["gaps"][0].as_object_mut().expect("a gap object").remove("removed");
    let read = Record::from_value(&v).expect("a gap with no removed reads");
    assert!(read.gaps[0].removed.is_empty(), "{:?}", read.gaps);
}

// ── the line rule's laws (skep #1173, #1176) ─────────────────────────────

/// The sides of one composition, in the order `compose_runs` takes them.
type Listing = Vec<(SideIx, Vec<Run>)>;

/// Both listings of two sides, each named.
fn both_ways(a: &[Run], b: &[Run]) -> [(Listing, &'static str); 2] {
    [(two(a.to_vec(), b.to_vec()), "A first"), (two(b.to_vec(), a.to_vec()), "B first")]
}

/// An addition another side anchored still meets at a line's edge.
///
/// The head removes "T" (`D·26`) and writes lines right after line 2's
/// break, and the side writes "Every\ns1 " right after `D·25`, inside line
/// 2: R2's `anchor`, its right anchor gone. Both are `line` gaps,
/// unsettled, the side's at R2's place after `D·25`. With the head removing
/// `D·25` instead, the side's left anchor, the side's words stand before
/// `D·26`, and both ask too. Each holds whichever side is listed first; M
/// is the composition read by no value, where the side's words are an
/// `anchor` the rule settles (the mutant that weighs no anchor answers one
/// settled `anchor` gap).
#[test]
fn an_addition_another_side_anchored_still_meets_at_a_lines_edge() {
    let side = adding_after(25, rd(46, 9));
    for (head, m, place, placed) in [
        (
            vec![rd(1, 25), rd(27, 3), rd(36, 10), rd(30, 6)],
            vec![rd(1, 25), rd(46, 9), rd(27, 3), rd(36, 10), rd(30, 6)],
            (Some(25), Some(27)),
            Placement::After,
        ),
        (
            vec![rd(1, 24), rd(26, 4), rd(36, 10), rd(30, 6)],
            vec![rd(1, 24), rd(46, 9), rd(26, 4), rd(36, 10), rd(30, 6)],
            (Some(24), Some(26)),
            Placement::Before,
        ),
    ] {
        for (sides, name) in both_ways(&head, &side) {
            let say = format!("the side's words beside {place:?}, {name}");
            let c = compose_lined(&sides, &Options::default());
            assert_eq!(runs(&c), m, "{say}: M at the defaults");
            assert_eq!(kinds(&c), vec![(GapKind::Line, false), (GapKind::Line, false)], "{say}");
            assert_eq!(anchors(&c), vec![place, (Some(29), Some(30))], "{say}");
            assert_eq!(c.gaps[0].placed, placed, "{say}: R2's place, the default");
            assert!(
                c.gaps.iter().all(|g| g.resolved_by.is_none() && g.removed.is_empty()),
                "{say}: {:?}",
                c.gaps
            );
            let unread = compose(&lined(), &sides);
            assert_eq!(
                (runs(&unread), kinds(&unread)),
                (m.clone(), vec![(GapKind::Anchor, true)]),
                "{say}: read by no value"
            );
        }
    }
}

/// A word both sides placed alike meets no line's edge of either.
///
/// S (`D·60`) right after `D·25` on both sides, the side's lines after line
/// 2's break beside it, asks nothing: the head's one change, S, is the
/// side's too. Nor does the side's removal of `D·30` beside S. Either way,
/// in either listing, M is the side's own list. The head writing `D·61` of
/// its own beside S asks twice in either listing (the mutant that reads a
/// word kept once as its keeper's alone asks where the head, listed first,
/// keeps it; the one that weighs no pair a side touched at both places
/// asks nothing in the last cell).
#[test]
fn a_word_both_sides_placed_alike_meets_no_line_edge_of_either() {
    let head = adding_after(25, rd(60, 1));
    let lines = vec![rd(1, 25), rd(60, 1), rd(26, 4), rd(46, 9), rd(30, 6)];
    let removal = vec![rd(1, 25), rd(60, 1), rd(26, 4), rd(31, 5)];
    for side in [&lines, &removal] {
        for (sides, name) in both_ways(&head, side) {
            let c = compose_lined(&sides, &Options::default());
            assert_eq!((runs(&c), kinds(&c)), (side.clone(), vec![]), "{side:?}, {name}");
        }
    }
    let own = vec![rd(1, 25), rd(60, 2), rd(26, 10)];
    for (sides, name) in both_ways(&own, &lines) {
        let c = compose_lined(&sides, &Options::default());
        assert_eq!(kinds(&c), vec![(GapKind::Line, false), (GapKind::Line, false)], "{name}");
        assert_eq!(anchors(&c), vec![(Some(25), Some(26)), (Some(29), Some(30))], "{name}");
        assert_eq!(
            runs(&c),
            vec![rd(1, 25), rd(60, 2), rd(26, 4), rd(46, 9), rd(30, 6)],
            "{name}: M"
        );
    }
}

/// The values of a lined base of `bytes` at `D·1…`: A's fresh words
/// (`D·100…`, and `D·400…`) "x", B's (`D·200…`) "y", S's (`D·300…`) "z".
fn lined_bytes(bytes: &[u8]) -> impl Fn(SideIx, &Run) -> Option<Vec<Item>> + '_ {
    move |_: SideIx, run: &Run| {
        (run.i_start..run.reach())
            .map(|p| match p {
                p if (1..=bytes.len() as u64).contains(&p) => Some(vec![bytes[p as usize - 1]]),
                100..=199 | 400..=499 => Some(vec![b'x']),
                200..=299 => Some(vec![b'y']),
                300..=399 => Some(vec![b'z']),
                _ => None,
            })
            .collect()
    }
}

/// THE LINE RULE ASKS ALIKE WHICHEVER SIDE IS LISTED FIRST, as a property.
///
/// The inputs are lined bases of four to twelve bytes of "ab\n" and two
/// sides of removals and inserts. In half the cases both sides add S
/// (`D·300`, one or two positions) after one base position, each at a
/// place drawn among its own inserts there; in a quarter A's one change is
/// S, which B adds too. The same inputs give the same composition; the
/// sides listed the other way round ask the same and give the same M, every
/// unsettled gap at its default; M is the composition read by no value,
/// every base position both sides keep and every addition in it once; no
/// gap names a removal of a side whose words it holds; and where A's one
/// change is S, nothing asks in either listing and M is B's own list, a
/// side whose every change the other made too (the mutants that read a word
/// kept once as its keeper's alone, pair a removal with its own side's
/// addition, or order a `collision`'s groups by the listing break one of
/// these). In more than fifty of those cases A, writing a word of its own
/// in S's place, is asked a `line` gap.
#[test]
fn the_line_rule_asks_alike_whichever_side_is_listed_first() {
    let mut rng = Rng(0x5EED_2026_1124);
    let (mut shared_asked, mut absorbed, mut own_asked) = (0, 0, 0);
    for case in 0..4000 {
        let n = 4 + rng.below(9);
        let bytes: Vec<u8> = (0..n).map(|_| b"ab\n"[rng.below(3) as usize]).collect();
        let values = lined_bytes(&bytes);
        let arm = rng.below(4);
        let mut a = match arm {
            3 => Side { removed: BTreeSet::new(), inserts: Vec::new(), order: (1..=n).collect() },
            _ => Side::draw(&mut rng, n, 100),
        };
        let mut b = Side::draw(&mut rng, n, 200);
        let (own_a, own_b) = (a.clone(), b.clone());
        let shared = (arm != 0).then(|| (rng.below(n + 1), 1 + rng.below(2)));
        if let Some((after, width)) = shared {
            a.place(&mut rng, (after, 300, width));
            b.place(&mut rng, (after, 300, width));
        }
        let say = format!(
            "case {case}: {:?}; A {:?} {:?}; B {:?} {:?}",
            String::from_utf8_lossy(&bytes),
            a.removed,
            a.inserts,
            b.removed,
            b.inserts
        );
        let base = [rd(1, n)];
        let compose_with = |sides: &[(SideIx, Vec<Run>)]| {
            compose_runs(&base, &d(), sides, None, &Options::default(), &values)
        };
        let [(sides, _), (swapped_sides, _)] = both_ways(&a.runs(n), &b.runs(n));
        let c = compose_with(&sides);
        assert_eq!(c, compose_with(&sides), "{say}: the same inputs, another composition");
        assert_eq!(runs(&c), runs(&compose(&base, &sides)), "{say}: M read by no value");
        let swapped = compose_with(&swapped_sides);
        assert_eq!(
            asked(&swapped),
            asked(&c),
            "{say}: listed the other way round, another question"
        );
        // Both sides place S after one position: no `moves` gap, so M at the
        // defaults reads no listing.
        assert_eq!(runs(&swapped), runs(&c), "{say}: listed the other way round, another M");
        let kept = |p: &u64| !a.removed.contains(p) && !b.removed.contains(p);
        let mut expected: Vec<u64> =
            (1..=n).filter(kept).chain(own_a.fresh()).chain(own_b.fresh()).collect();
        expected.extend(shared.map(|(_, width)| 300..300 + width).into_iter().flatten());
        expected.sort_unstable();
        let mut got: Vec<u64> = c.runs.iter().flat_map(|p| p.run.i_start..p.run.reach()).collect();
        got.sort_unstable();
        assert_eq!(got, expected, "{say}: every addition once, no removal");
        for (c, name) in [(&c, "A first"), (&swapped, "B first")] {
            for g in &c.gaps {
                assert!(
                    g.removed.iter().all(|r| g.runs.iter().all(|(s, _)| *s != r.side)),
                    "{say}, {name}: a gap names its own side's removal: {g:?}"
                );
            }
        }
        if shared.is_some() && c.gaps.iter().any(|g| g.kind == GapKind::Line) {
            shared_asked += 1;
        }
        let Some((after, width)) = shared.filter(|_| arm == 3) else { continue };
        absorbed += 1;
        for (c, name) in [(&c, "A first"), (&swapped, "B first")] {
            assert!(
                c.gaps.iter().all(|g| g.settled),
                "{say}, {name}: A's one change is B's too; gaps {:?}",
                c.gaps
            );
            assert_eq!(runs(c), b.runs(n), "{say}, {name}: M is B's own list");
        }
        let mut own = own_a.clone();
        own.inserts.push((after, 400, width));
        let own = compose_with(&two(own.runs(n), b.runs(n)));
        own_asked += usize::from(own.gaps.iter().any(|g| g.kind == GapKind::Line));
    }
    assert!(
        shared_asked > 100 && absorbed > 500 && own_asked > 50,
        "a line gap beside S in {shared_asked} cases; A's one change S {absorbed} times, \
         one of its own asked in {own_asked}"
    );
}

/// AN ANCHORED ADDITION MEETS AT A LINE'S EDGE AS IT STANDS, as a property.
///
/// Over bases of one to eight bytes of "ab\n", A writes "x" right after one
/// base position and B "y" after another; half the time A removes one of
/// y's anchors besides, never one of its own, and y is then R2's `anchor`.
/// Read off M's surviving text — each word's place counted in the base
/// positions that survive, the text between and the byte before the first —
/// the two are `line` gaps exactly where the rule meets; else y is one
/// `anchor` the rule settles where A removed its anchor, and nothing asks
/// where it did not; at one place they are one `order` gap. This holds
/// whichever side is listed first, M the composition read by no value (the
/// mutant that weighs no anchor asks nothing where y's anchor is gone).
#[test]
fn an_anchored_addition_meets_at_a_lines_edge_as_it_stands() {
    let mut rng = Rng(0x5EED_A2C4_1173);
    let (mut anchored, mut met_anchored) = (0, 0);
    for case in 0..3000 {
        let n = 1 + rng.below(8);
        let bytes: Vec<u8> = (0..n).map(|_| b"ab\n"[rng.below(3) as usize]).collect();
        let values = lined_bytes(&bytes);
        let (i, j) = (rng.below(n + 1), rng.below(n + 1));
        let gone = (rng.below(2) == 0)
            .then(|| j + rng.below(2))
            .filter(|&k| (1..=n).contains(&k) && k != i && k != i + 1);
        // A side keeping the base but `gone`, `fresh` right after `D·after`.
        let side = |after: u64, fresh: u64, gone: Option<u64>| {
            let mut out: Vec<Run> = Vec::new();
            let mut push = |run: Run| match out.last_mut() {
                Some(last) if last.reach() == run.i_start => last.width += run.width,
                _ => out.push(run),
            };
            for p in 0..=n {
                if p >= 1 && Some(p) != gone {
                    push(rd(p, 1));
                }
                if p == after {
                    push(rd(fresh, 1));
                }
            }
            out
        };
        let (a, b) = (side(i, 100, gone), side(j, 200, None));
        let say = format!(
            "case {case}: {:?}, x after {i}, y after {j}, {gone:?} gone",
            String::from_utf8_lossy(&bytes)
        );
        let expected = if i == j {
            vec![(GapKind::Order, false)]
        } else {
            let surviving: Vec<u8> = (1..=n)
                .filter(|p| Some(*p) != gone)
                .map(|p| bytes[p as usize - 1])
                .collect();
            let place = |after: u64| (1..=after).filter(|p| Some(*p) != gone).count() as u64;
            let (x, y) = (place(i), place(j));
            assert_ne!(x, y, "{say}: the premise, two places apart");
            if meets_directly(&surviving, x, y) {
                met_anchored += usize::from(gone.is_some());
                vec![(GapKind::Line, false), (GapKind::Line, false)]
            } else if gone.is_some() {
                vec![(GapKind::Anchor, true)]
            } else {
                vec![]
            }
        };
        anchored += usize::from(gone.is_some());
        for (sides, name) in both_ways(&a, &b) {
            let c = compose_runs(&[rd(1, n)], &d(), &sides, None, &Options::default(), &values);
            assert_eq!(kinds(&c), expected, "{say}, {name}: {:?}", c.gaps);
            assert_eq!(runs(&c), runs(&compose(&[rd(1, n)], &sides)), "{say}, {name}: M");
        }
    }
    assert!(
        anchored > 500 && met_anchored > 100,
        "an anchor gone {anchored} times, met at a line's edge in {met_anchored}"
    );
}

/// A REMOVAL MEETS AT A LINE'S EDGE AS ITS REWRITE WOULD, as a property.
///
/// Over bases of two to ten bytes of "ab\n", A writes "x" right after one
/// base position, and B removes a stretch of one to three positions apart
/// from x's anchors, where B′ makes the same removal and writes "y" in its
/// place. x is a `line` gap beside B exactly where it is one beside B′,
/// whichever side is listed first; beside B its gap names B's removal by
/// the anchors B′'s "y" has, and beside B′ "y" asks with it (the mutants
/// that weigh a walk's pair from the wrong end, or read the byte before a
/// removal on its far side, break one of these).
#[test]
fn a_removal_meets_at_a_lines_edge_as_its_rewrite_would() {
    let mut rng = Rng(0x5EED_1176_C0DE);
    let (mut checked, mut met) = (0, 0);
    for case in 0..3000 {
        let n = 2 + rng.below(9);
        let bytes: Vec<u8> = (0..n).map(|_| b"ab\n"[rng.below(3) as usize]).collect();
        let values = lined_bytes(&bytes);
        let i = rng.below(n + 1);
        let first = 1 + rng.below(n);
        let last = (first + rng.below(3)).min(n);
        if (first..=last).contains(&i) || (first..=last).contains(&(i + 1)) {
            continue;
        }
        checked += 1;
        let keep = |p: &u64| !(first..=last).contains(p);
        let mut a = vec![];
        if i > 0 {
            a.push(rd(1, i));
        }
        a.push(rd(100, 1));
        if i < n {
            a.push(rd(i + 1, n - i));
        }
        let kept: Vec<Run> = (1..=n).filter(keep).fold(Vec::new(), |mut out: Vec<Run>, p| {
            match out.last_mut() {
                Some(last) if last.reach() == p => last.width += 1,
                _ => out.push(rd(p, 1)),
            }
            out
        });
        let mut rewrite = Vec::new();
        if first > 1 {
            rewrite.push(rd(1, first - 1));
        }
        rewrite.push(rd(200, 1));
        if last < n {
            rewrite.push(rd(last + 1, n - last));
        }
        let say = format!(
            "case {case}: {:?}, x after {i}, D·{first}–{last} removed",
            String::from_utf8_lossy(&bytes)
        );
        let compose_with = |sides: &[(SideIx, Vec<Run>)]| {
            compose_runs(&[rd(1, n)], &d(), sides, None, &Options::default(), &values)
        };
        // The gap holding `word` of side `side`, where one does.
        let gap_of = |c: &Composed, side: SideIx, word: u64| -> Option<Gap> {
            c.gaps.iter().find(|g| g.runs.contains(&(side, rd(word, 1)))).cloned()
        };
        let line = |gap: &Option<Gap>| gap.as_ref().is_some_and(|g| g.kind == GapKind::Line);
        let asks = line(&gap_of(&compose_with(&two(a.clone(), rewrite.clone())), SideIx(0), 100));
        met += usize::from(asks);
        let listings = both_ways(&a, &kept).into_iter().zip(both_ways(&a, &rewrite));
        for (k, ((removal_sides, name), (rewrite_sides, _))) in listings.enumerate() {
            let (x, b) = if k == 0 { (SideIx(0), SideIx(1)) } else { (SideIx(1), SideIx(0)) };
            let say = format!("{say}, {name}");
            let (beside_b, beside_rewrite) =
                (compose_with(&removal_sides), compose_with(&rewrite_sides));
            let x_gap = gap_of(&beside_b, x, 100);
            assert_eq!(line(&x_gap), asks, "{say}: beside the removal {:?}", beside_b.gaps);
            let y_gap = gap_of(&beside_rewrite, b, 200);
            assert_eq!(
                (line(&gap_of(&beside_rewrite, x, 100)), line(&y_gap)),
                (asks, asks),
                "{say}: beside the rewrite {:?}",
                beside_rewrite.gaps
            );
            let named = x_gap.map_or_else(Vec::new, |g| g.removed);
            let expected = match y_gap.filter(|_| asks) {
                Some(y) => vec![Removed { side: b, after: y.after, before: y.before }],
                None => vec![],
            };
            assert_eq!(named, expected, "{say}: the removal named by its rewrite's anchors");
            assert_eq!(runs(&beside_b), runs(&compose(&[rd(1, n)], &removal_sides)), "{say}: M");
        }
    }
    assert!(checked > 1000 && met > 100, "{checked} cases checked, {met} met at a line's edge");
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

/// A value read as `compose_runs` takes one.
type Values<'a> = &'a dyn Fn(SideIx, &Run) -> Option<Vec<Item>>;

/// A record's options compose the same M and gaps as its merger's choices.
///
/// It is the record's re-statement law (merge record §4), over every
/// unsettled shape of gap — an order gap, a cut, a corner beside one
/// survivor or between two, a collision of no, one and two groups, a
/// `line` gap over the lined base read through its bytes, beside another
/// side's addition and beside its removal (skep #1173, #1176). Each
/// gap is moved after or before every base position, or not moved, then
/// ordered, kept or omitted, the move given first or last; the options its
/// record re-states, its gaps read back from its JSON, compose again to the
/// runs and the gaps the merger's own choices composed. Every shape's gap is
/// moved somewhere, so the law never holds by the default place alone.
#[test]
fn a_record_recomposes_every_place_and_choice_its_merger_made() {
    let lines = text(LINED);
    let shapes: [(&str, Vec<Run>, _, Values<'_>); 10] = [
        (
            "(b)",
            base(),
            two(vec![rd(1, 4), rd(12, 4), rd(5, 7)], vec![rd(1, 4), rd(16, 4), rd(5, 7)]),
            &unread,
        ),
        ("(c)", base(), two(vec![rd(1, 4), rd(12, 3), rd(8, 4)], vec![rd(1, 4)]), &unread),
        (
            "(e′)",
            base(),
            two(vec![rd(5, 7), rd(1, 4)], vec![rd(1, 4), rd(12, 4), rd(5, 7)]),
            &unread,
        ),
        (
            "(f′)",
            base(),
            two(vec![rd(1, 4), rd(12, 3), rd(8, 4)], vec![rd(1, 5), rd(16, 1), rd(6, 6)]),
            &unread,
        ),
        (
            "(i′)",
            base(),
            two(vec![rd(1, 2), rd(12, 1), rd(4, 8)], vec![rd(1, 2), rd(13, 1), rd(4, 8)]),
            &unread,
        ),
        (
            "the corner, a left survivor",
            base(),
            two(vec![rd(1, 6), rd(12, 1), rd(7, 5)], vec![rd(1, 4)]),
            &unread,
        ),
        (
            "the agent case",
            base(),
            two(vec![rd(1, 4), rd(12, 3), rd(8, 4)], vec![rd(1, 4), rd(16, 6), rd(8, 4)]),
            &unread,
        ),
        (
            "a collision with nothing placed",
            base(),
            two(vec![rd(1, 4), rd(8, 4)], vec![rd(1, 4)]),
            &unread,
        ),
        ("a line's edge", lined(), rewrite_beside_lines(), &lines),
        ("a removal at a line's edge", lined(), removal_beside_lines(), &lines),
    ];
    let picks = [
        None,
        Some(Choice::Order(vec![SideIx(0), SideIx(1)])),
        Some(Choice::Order(vec![SideIx(1), SideIx(0)])),
        Some(Choice::KeepOnly(SideIx(0))),
        Some(Choice::KeepOnly(SideIx(1))),
        Some(Choice::KeepBoth),
        Some(Choice::Omit),
    ];
    for (name, base, sides, values) in &shapes {
        let width: u64 = base.iter().map(|r| r.width).sum();
        let places: Vec<Option<Choice>> = std::iter::once(None)
            .chain(
                (1..=width)
                    .flat_map(|n| [Some(Choice::After(d_at(n))), Some(Choice::Before(d_at(n)))]),
            )
            .collect();
        let unmoved = anchors(&compose_runs(base, &d(), sides, None, &Options::default(), values));
        let mut moved = 0;
        for place in &places {
            for pick in &picks {
                for given in [[place, pick], [pick, place]] {
                    let resolutions: Vec<Resolution> = given
                        .into_iter()
                        .flatten()
                        .map(|choice| Resolution {
                            gap: GapId(1),
                            choice: choice.clone(),
                            by: ResolvedBy::Person,
                        })
                        .collect();
                    let options =
                        Options { resolutions: resolutions.clone(), ..Options::default() };
                    let first = compose_runs(base, &d(), sides, None, &options, values);
                    let again =
                        compose_runs(base, &d(), sides, None, &recorded(&first).options(), values);
                    assert_eq!(
                        (runs(&again), &again.gaps),
                        (runs(&first), &first.gaps),
                        "{name}: {resolutions:?}"
                    );
                    moved += usize::from(anchors(&first) != unmoved);
                }
            }
        }
        assert!(moved > 0, "{name}: no place moved its gap");
    }
    let line = recorded(&compose_lined(&rewrite_beside_lines(), &Options::default()));
    assert_eq!(line.to_value()["gaps"][0]["kind"], "line", "the kind as the record spells it");
    assert_eq!(
        line.gaps.iter().map(|g| g.kind).collect::<Vec<_>>(),
        [GapKind::Line, GapKind::Line],
        "read back"
    );
}

/// A record re-states a move over a base that places one run twice.
///
/// The base `abcd abcd` (skep #763), the head and the side each adding at
/// the end: an `order` gap after the second copy. Each move after or before
/// each of `D·1`–`D·4` — a position of either copy — with each pick, given
/// first or last, composes again from the record's options to the same
/// runs and gaps: a move takes the copy nearest the gap's default place,
/// and the record's two anchors name the copy it took (§4; the mutant that
/// takes a run's first copy re-states the gap at the end after the first
/// copy).
#[test]
fn a_record_restates_a_move_over_a_run_placed_twice() {
    let twice = [rd(1, 4), rd(1, 4)];
    let sides = two(vec![rd(1, 4), rd(1, 4), rd(12, 4)], vec![rd(1, 4), rd(1, 4), rd(16, 4)]);
    let places: Vec<Option<Choice>> = std::iter::once(None)
        .chain((1..=4).flat_map(|n| [Some(Choice::After(d_at(n))), Some(Choice::Before(d_at(n)))]))
        .collect();
    let picks = [
        None,
        Some(Choice::Order(vec![SideIx(0), SideIx(1)])),
        Some(Choice::Order(vec![SideIx(1), SideIx(0)])),
        Some(Choice::KeepOnly(SideIx(1))),
        Some(Choice::KeepBoth),
        Some(Choice::Omit),
    ];
    let mut between = 0;
    for place in &places {
        for pick in &picks {
            for given in [[place, pick], [pick, place]] {
                let resolutions: Vec<Resolution> = given
                    .into_iter()
                    .flatten()
                    .map(|choice| Resolution {
                        gap: GapId(1),
                        choice: choice.clone(),
                        by: ResolvedBy::Person,
                    })
                    .collect();
                let options = Options { resolutions: resolutions.clone(), ..Options::default() };
                let first = compose_runs(&twice, &d(), &sides, None, &options, &unread);
                let again =
                    compose_runs(&twice, &d(), &sides, None, &recorded(&first).options(), &unread);
                assert_eq!(
                    (runs(&again), &again.gaps),
                    (runs(&first), &first.gaps),
                    "{resolutions:?}"
                );
                between += usize::from(anchors(&first) == vec![(Some(4), Some(1))]);
            }
        }
    }
    assert!(between > 0, "no move put the gap between the copies");
}

/// A record re-states the holder a gap with spots took (CM-I33).
///
/// A gap with spots takes no place: its record keeps its spots and its
/// holder, which the options re-state by the order alone, so a composition
/// with the side's placement chosen, by either choice, or the head's
/// confirmed, round-trips through the record's JSON with its spots and
/// composes again to the same M and gaps. A gap carries `spots` only where
/// it has them, and one spelled with none reads with none, as a record
/// written before a gap carried them (the mutants that drop the spots on
/// the write or refuse a gap without them fail the round trip or the read).
#[test]
fn a_record_re_states_the_holder_a_gap_with_spots_took() {
    let sides = apart();
    for choice in [Choice::Order(vec![SideIx(1)]), Choice::KeepOnly(SideIx(1)), Choice::Order(vec![SideIx(0)])] {
        let first = compose_runs(&base(), &d(), &sides, None, &resolve(1, choice.clone()), &unread);
        let record = recorded(&first);
        assert_eq!(record.gaps, first.gaps, "{choice:?}: the gaps read back, spots and all");
        let again = compose_runs(&base(), &d(), &sides, None, &record.options(), &unread);
        assert_eq!((runs(&again), &again.gaps), (runs(&first), &first.gaps), "{choice:?}");
    }
    let mut v = recorded(&compose(&base(), &apart())).to_value();
    assert_eq!(v["gaps"][0]["spots"][1]["after"], d_at(8).to_string(), "{v}");
    let order = recorded(&compose(&base(), &two(vec![rd(1, 4), rd(12, 4), rd(5, 7)], vec![rd(1, 4), rd(16, 4), rd(5, 7)]))).to_value();
    assert!(order["gaps"][0].get("spots").is_none(), "an order gap carries none: {order}");
    v["gaps"][0].as_object_mut().expect("a gap object").remove("spots");
    let read = Record::from_value(&v).expect("a gap with no spots reads");
    assert!(read.gaps[0].spots.is_empty() && read.gaps[0].kind == GapKind::Moves, "{:?}", read.gaps);
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
        ("one identity at two spots", compose(&base(), &apart())),
        ("a line's edge", compose_lined(&rewrite_beside_lines(), &Options::default())),
    ]
}

/// Seven kinds, exactly, and one of them settles by rule: the only gap the
/// composition marks settled with no resolution is an `anchor`, or an
/// `order` gap the value rule emptied — over every vector.
#[test]
fn seven_kinds_and_only_the_anchor_settles_by_rule() {
    let all = [
        GapKind::Order,
        GapKind::Anchor,
        GapKind::Corner,
        GapKind::Cut,
        GapKind::Collision,
        GapKind::Moves,
        GapKind::Line,
    ];
    for kind in all {
        // An eighth variant fails to compile here.
        let _: &str = match kind {
            GapKind::Order => "order",
            GapKind::Anchor => "anchor",
            GapKind::Corner => "corner",
            GapKind::Cut => "cut",
            GapKind::Collision => "collision",
            GapKind::Moves => "moves",
            GapKind::Line => "line",
        };
    }
    assert_eq!(all.iter().collect::<BTreeSet<_>>().len(), 7);
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
    assert_eq!(seen.len(), 7, "every kind arises in some vector: {seen:?}");
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
#[derive(Clone)]
struct Side {
    removed: BTreeSet<u64>,
    /// Each insert: the base position it follows (0 the start), its fresh
    /// start and width.
    inserts: Vec<(u64, u64, u64)>,
    /// The base positions in the side's own order: the base's, save where
    /// the side moved a stretch (`Side::move_one`).
    order: Vec<u64>,
}

impl Side {
    fn draw(rng: &mut Rng, n: u64, fresh_from: u64) -> Side {
        let order = (1..=n).collect();
        let mut side = Side { removed: BTreeSet::new(), inserts: Vec::new(), order };
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

    /// Places `insert` among the side's inserts after the same position, at
    /// a place drawn at random: before all of them, between two, or after.
    fn place(&mut self, rng: &mut Rng, insert: (u64, u64, u64)) {
        let same: Vec<usize> = self
            .inserts
            .iter()
            .enumerate()
            .filter(|(_, i)| i.0 == insert.0)
            .map(|(k, _)| k)
            .collect();
        let at = rng.below(same.len() as u64 + 1) as usize;
        self.inserts.insert(same.get(at).copied().unwrap_or(self.inserts.len()), insert);
    }

    /// The side's run list: the base less its removals, each insert after
    /// the position it follows.
    fn runs(&self, n: u64) -> Vec<Run> {
        self.runs_over(n, |p| p)
    }

    /// The side's run list over a base of `n` positions whose position `p`
    /// holds the document's ordinal `ordinal(p)`.
    ///
    /// # Panics
    ///
    /// Panics unless the side's order holds the `n` positions.
    fn runs_over(&self, n: u64, ordinal: impl Fn(u64) -> u64) -> Vec<Run> {
        assert_eq!(self.order.len() as u64, n, "the side was drawn over {n} positions");
        let mut out: Vec<Run> = Vec::new();
        let mut push = |run: Run| match out.last_mut() {
            Some(last) if last.reach() == run.i_start => last.width += run.width,
            _ => out.push(run),
        };
        for p in self.walk() {
            if p >= 1 && !self.removed.contains(&p) {
                push(rd(ordinal(p), 1));
            }
            for &(_, start, width) in self.inserts.iter().filter(|(after, _, _)| *after == p) {
                push(rd(start, width));
            }
        }
        out
    }

    /// The places an insert can follow, in the side's own order: the start,
    /// then each base position.
    fn walk(&self) -> Vec<u64> {
        std::iter::once(0).chain(self.order.iter().copied()).collect()
    }

    /// Moves one stretch of one to three base positions elsewhere in the
    /// side's own order (§2 R4: a single-sided move, which the spine takes).
    fn move_one(&mut self, rng: &mut Rng) {
        let from = rng.below(self.order.len() as u64) as usize;
        let width = (1 + rng.below(3) as usize).min(self.order.len() - from);
        let moved: Vec<u64> = self.order.drain(from..from + width).collect();
        let to = rng.below(self.order.len() as u64 + 1) as usize;
        self.order.splice(to..to, moved);
    }

    /// Whether the side moved base material.
    fn moved(&self) -> bool {
        self.order.windows(2).any(|w| w[0] > w[1])
    }

    /// The stretch holding the insert from `start`: its spot, and the fresh
    /// starts of the side's other inserts in it, before that one and after
    /// it in the side's own order.
    fn around(&self, n: u64, start: u64) -> ((u64, u64), Vec<u64>, Vec<u64>) {
        let spots = self.spots(n);
        let me = self.inserts.iter().position(|i| i.1 == start).expect("the side holds the insert");
        let mut members: Vec<usize> =
            (0..self.inserts.len()).filter(|&k| spots[k] == spots[me]).collect();
        let walk = self.walk();
        let rank = |after: u64| walk.iter().position(|&p| p == after);
        members.sort_by_key(|&k| (rank(self.inserts[k].0), k));
        let at = members.iter().position(|&k| k == me).expect("the insert is in its stretch");
        let starts = |ks: &[usize]| ks.iter().map(|&k| self.inserts[k].1).collect();
        (spots[me], starts(&members[..at]), starts(&members[at + 1..]))
    }

    /// The positions of the side's stretch holding the insert from `start`,
    /// in the side's own order: every word it placed at that spot.
    fn stretch_words(&self, n: u64, start: u64) -> Vec<u64> {
        let (_, before, after) = self.around(n, start);
        let width = |s: u64| self.inserts.iter().find(|i| i.1 == s).map_or(0, |i| i.2);
        let starts = before.into_iter().chain([start]).chain(after);
        starts.flat_map(|s| s..s + width(s)).collect()
    }

    /// The spot of a place after `after` in the side's own order, read by the
    /// base positions `kept` keeps: 0 and `n + 1` at the ends.
    fn common_spot(&self, after: u64, n: u64, kept: impl Fn(&u64) -> bool) -> (u64, u64) {
        let walk = self.walk();
        let at = walk.iter().position(|&p| p == after).expect("a place after a position");
        let x = walk[..=at].iter().rev().copied().find(|&p| p >= 1 && kept(&p)).unwrap_or(0);
        let y = walk[at + 1..].iter().copied().find(|p| kept(p)).unwrap_or(n + 1);
        (x, y)
    }

    /// Whether the side holds a stretch whose spot lies strictly between
    /// `lo` and `hi`, spots ordered as pairs.
    fn between(&self, n: u64, lo: (u64, u64), hi: (u64, u64)) -> bool {
        self.spots(n).iter().any(|s| lo < *s && *s < hi)
    }

    /// Each insert's spot in the side's own sequence: the surviving base
    /// positions before and after it, 0 and `n + 1` at the ends.
    fn spots(&self, n: u64) -> Vec<(u64, u64)> {
        let kept = |p: &u64| !self.removed.contains(p);
        self.inserts.iter().map(|&(after, _, _)| self.common_spot(after, n, kept)).collect()
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

/// Whether the positions `side` holds stand in `m` in the side's own order.
fn keeps_order(m: &[Run], side: &[Run]) -> bool {
    let mine = expand(side);
    let in_m: Vec<(Address, u64)> = expand(m).into_iter().filter(|p| mine.contains(p)).collect();
    let mine_in_m: Vec<(Address, u64)> = mine.into_iter().filter(|p| in_m.contains(p)).collect();
    in_m == mine_in_m
}

/// The unsettled gaps as their kinds and places, sorted: what a merger is
/// asked, whichever side is listed first.
fn asked(c: &Composed) -> Vec<(GapKind, Option<Address>, Option<Address>)> {
    let mut out: Vec<_> = c
        .gaps
        .iter()
        .filter(|g| !g.settled)
        .map(|g| (g.kind, g.after.clone(), g.before.clone()))
        .collect();
    out.sort();
    out
}

/// Each word a `moves` gap with spots contests, with the places its holders
/// put it, sorted, whichever side holds which (CM-I33).
///
/// It is read word by word: the gaps group contested words that stand
/// together in their earliest holder's sequence, which the order the sides
/// are listed in decides.
fn placed_apart(c: &Composed) -> Vec<(u64, Vec<(Option<Address>, Option<Address>)>)> {
    let mut out: Vec<(u64, Vec<_>)> = Vec::new();
    for g in c.gaps.iter().filter(|g| !g.spots.is_empty()) {
        let mut places: Vec<_> =
            g.spots.iter().map(|s| (s.after.clone(), s.before.clone())).collect();
        places.sort();
        for (_, run) in &g.runs {
            out.extend((run.i_start..run.reach()).map(|p| (p, places.clone())));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// THE ONE RULE as a property, over two sides of removals and inserts.
///
/// Where the two sides touched different material every gap is settled;
/// where they touched the same material or the same spot, some gap is
/// unsettled; and in either case M holds the base less both removals and
/// every addition, each once. Half the cases give both sides one fresh run
/// S, the same identity, each after a base position of its own and at a
/// place drawn among that side's other inserts there; half of those give
/// them a second, S2, after the positions S follows half the time, so the
/// sides can order S and S2 apart at one spot. A shared run's two spots,
/// read by the base positions both sides keep, differing is a touch of the
/// same material (CM-I33), and so is S and S2 ordered apart at one spot. At
/// one spot, S is an identical addition, kept once: where either side added
/// nothing of its own beside it and neither holds material laid between the
/// two stretches holding it, the sides touched the same material exactly
/// where their own inserts did or they ordered S and S2 apart. At every
/// unsettled gap holding S or S2, keeping one side alone, or putting it
/// first, lays every word that side placed in that word's stretch, in that
/// side's order. Half the cases let the first side move a stretch of the
/// base besides, which the spine takes: there a cut — an insert whose two
/// surviving anchors the spine's order parts — asks too. Wherever every gap
/// is settled, each side's positions stand in M in that side's own order,
/// the mover's alone where one moved. The sides listed the other way round
/// ask the same and give the same M, every unsettled gap at its default —
/// save where a shared run stands at two spots, whose default is the
/// earliest holder's placement (CM-I33), which raises the gaps its place
/// raises: there both listings ask about it at the same two places. The
/// same inputs give the same composition (the mutants that keep S by the
/// first side listed, lay a side's runs out of its own order, keep a
/// removed position, strip a shared word from a side that orders it
/// otherwise, list it under one side alone, or order a `collision`'s groups
/// by the listing and not by the commit each break one of these). Six
/// thousand cases, every arm reached.
#[test]
fn the_one_rule_holds_over_generated_inputs() {
    let mut rng = Rng(0x5EED_2026_10_15);
    let (mut safe, mut conflicts, mut together, mut apart, mut beside) = (0, 0, 0, 0, 0);
    let (mut crossed_cases, mut movers, mut cuts, mut laid_alone, mut listed_alike) =
        (0, 0, 0, 0, 0);
    for case in 0..6000 {
        let n = 4 + rng.below(7);
        let (mut a, mut b) = (Side::draw(&mut rng, n, 100), Side::draw(&mut rng, n, 200));
        if rng.below(2) == 0 {
            a.move_one(&mut rng);
        }
        let mover = a.moved();
        // Each side without S and S2: the material the oracle reads as its own.
        let (own_a, own_b) = (a.clone(), b.clone());
        let shared =
            (rng.below(2) == 0).then(|| (rng.below(n + 1), rng.below(n + 1), 1 + rng.below(3)));
        let mut second = None;
        if let Some((after_a, after_b, _)) = shared {
            if rng.below(2) == 0 {
                let width = 1 + rng.below(3);
                second = Some(if rng.below(2) == 0 {
                    (after_a, after_b, width)
                } else {
                    (rng.below(n + 1), rng.below(n + 1), width)
                });
            }
        }
        for (word, placed) in [(300, shared), (310, second)] {
            if let Some((after_a, after_b, width)) = placed {
                a.place(&mut rng, (after_a, word, width));
                b.place(&mut rng, (after_b, word, width));
            }
        }
        let say = format!(
            "case {case}: n {n}; A {:?} {:?} {:?}; B {:?} {:?}",
            a.order, a.removed, a.inserts, b.removed, b.inserts
        );
        let c = compose(&[rd(1, n)], &two(a.runs(n), b.runs(n)));
        assert_eq!(
            c,
            compose(&[rd(1, n)], &two(a.runs(n), b.runs(n))),
            "{say}: the same inputs, another composition"
        );
        let unsettled = c.gaps.iter().any(|g| !g.settled);
        let kept = |p: &u64| !a.removed.contains(p) && !b.removed.contains(p);
        let at_two_spots = |placed: Option<(u64, u64, u64)>| {
            placed.is_some_and(|(after_a, after_b, _)| {
                a.common_spot(after_a, n, kept) != b.common_spot(after_b, n, kept)
            })
        };
        let moved = at_two_spots(shared) || at_two_spots(second);
        // S and S2 in one stretch on each side, in two orders.
        let with_s = |side: &Side| {
            let (_, before, after) = side.around(n, 300);
            (before.contains(&310) || after.contains(&310), before.contains(&310))
        };
        let crossed = second.is_some() && !moved && {
            let ((a_with, a_first), (b_with, b_first)) = (with_s(&a), with_s(&b));
            a_with && b_with && a_first != b_first
        };
        crossed_cases += usize::from(crossed);
        // A cut: an insert of a side's own whose two anchors both survive and
        // stand apart in the spine, the mover's order of the survivors.
        let spine: Vec<u64> = a.order.iter().copied().filter(kept).collect();
        let survives = |p: u64| p == 0 || p == n + 1 || kept(&p);
        let together_in_spine = |(x, y): (u64, u64)| match (x, y) {
            (0, y) if y == n + 1 => spine.is_empty(),
            (0, y) => spine.first() == Some(&y),
            (x, y) if y == n + 1 => spine.last() == Some(&x),
            (x, y) => spine.windows(2).any(|w| w == [x, y]),
        };
        let cut = [&own_a, &own_b].iter().any(|side| {
            side.spots(n)
                .into_iter()
                .any(|(x, y)| survives(x) && survives(y) && !together_in_spine((x, y)))
        });
        movers += usize::from(mover);
        cuts += usize::from(cut);
        let touched = touched_the_same(&own_a, &own_b, n);
        if touched || moved || crossed || cut {
            assert!(unsettled, "{say}: a touch asks nothing; gaps {:?}", c.gaps);
        }
        match shared {
            None if !mover => assert_eq!(unsettled, touched, "{say}; gaps {:?}", c.gaps),
            None => {}
            Some(_) if moved => apart += 1,
            Some(_) => {
                together += 1;
                let ((ka, a_before, a_after), (kb, b_before, b_after)) =
                    (a.around(n, 300), b.around(n, 300));
                let (lo, hi) = (ka.min(kb), ka.max(kb));
                let clear = !mover && !a.between(n, lo, hi) && !b.between(n, lo, hi);
                // Beside S, the words a side placed of its own: S2 is shared.
                let of_its_own = |words: &Vec<u64>| words.iter().any(|&s| s != 310);
                let alone =
                    |before: &Vec<u64>, after: &Vec<u64>| !of_its_own(before) && !of_its_own(after);
                let s2_with_s = second.is_none() || (with_s(&a).0 && with_s(&b).0);
                if clear && s2_with_s && (alone(&a_before, &a_after) || alone(&b_before, &b_after))
                {
                    beside +=
                        usize::from(!alone(&a_before, &a_after) || !alone(&b_before, &b_after));
                    assert_eq!(
                        unsettled,
                        touched || crossed,
                        "{say}: S kept once; gaps {:?}",
                        c.gaps
                    );
                }
            }
        }
        if unsettled {
            conflicts += 1;
        } else {
            safe += 1;
            let named: &[(&str, &Side)] =
                if mover { &[("A", &a)] } else { &[("A", &a), ("B", &b)] };
            for (name, side) in named {
                assert!(
                    keeps_order(&runs(&c), &side.runs(n)),
                    "{say}: {name}'s order broken in M {:?}",
                    runs(&c)
                );
            }
        }
        let mut expected: Vec<u64> =
            (1..=n).filter(kept).chain(own_a.fresh()).chain(own_b.fresh()).collect();
        for (word, placed) in [(300, shared), (310, second)] {
            expected.extend(placed.map(|(_, _, width)| word..word + width).into_iter().flatten());
        }
        expected.sort_unstable();
        let mut got: Vec<u64> = c.runs.iter().flat_map(|p| p.run.i_start..p.run.reach()).collect();
        got.sort_unstable();
        assert_eq!(got, expected, "{say}");
        assert_eq!(c.counts.m, c.runs.len());
        // Each side kept alone, or put first, at an unsettled gap holding a
        // shared run at one spot: every word it placed in that run's stretch,
        // in order, for each side whose runs there hold it.
        for (word, placed) in [(300, shared), (310, second)] {
            if placed.is_none() || at_two_spots(placed) {
                continue;
            }
            let holding = |side: &SideIx, g: &Gap| {
                g.runs.iter().any(|(s, r)| s == side && r.i_start <= word && word < r.reach())
            };
            let holds = |g: &&Gap| {
                !g.settled && g.kind != GapKind::Moves && g.runs.iter().any(|(s, _)| holding(s, g))
            };
            let Some(gap) = c.gaps.iter().find(holds) else { continue };
            let mut sides_at: Vec<SideIx> = Vec::new();
            for (side, _) in &gap.runs {
                if !sides_at.contains(side) {
                    sides_at.push(*side);
                }
            }
            // A run at two spots is the claim's, laid where its holder put it.
            let claimed = |w: &u64| {
                [(300, shared), (310, second)].into_iter().any(|(start, placed)| {
                    at_two_spots(placed)
                        && placed.is_some_and(|(_, _, width)| (start..start + width).contains(w))
                })
            };
            for &s in sides_at.iter().filter(|s| holding(s, gap)) {
                let side = if s.0 == 0 { &a } else { &b };
                let words: Vec<u64> =
                    side.stretch_words(n, word).into_iter().filter(|w| !claimed(w)).collect();
                let mut choices = vec![Choice::KeepOnly(s)];
                choices.extend(
                    sides_at.iter().filter(|t| **t != s).map(|t| Choice::Order(vec![s, *t])),
                );
                for choice in choices {
                    let one = compose_runs(
                        &[rd(1, n)],
                        &d(),
                        &two(a.runs(n), b.runs(n)),
                        None,
                        &resolve(gap.id.0, choice.clone()),
                        &unread,
                    );
                    assert!(
                        one.ignored.is_empty(),
                        "{say}: {choice:?} at gap {:?} not applied",
                        gap.id
                    );
                    let m = expand(&runs(&one));
                    let at: Option<Vec<usize>> =
                        words.iter().map(|w| m.iter().position(|p| *p == (d(), *w))).collect();
                    assert!(
                        at.is_some_and(|at| at.windows(2).all(|w| w[0] < w[1])),
                        "{say}: {choice:?} at gap {:?} lays {words:?} out of side {}'s order: M {:?}",
                        gap.id,
                        s.0,
                        runs(&one)
                    );
                    laid_alone += 1;
                }
            }
        }
        let swapped = compose(&[rd(1, n)], &two(b.runs(n), a.runs(n)));
        if moved {
            assert_eq!(
                placed_apart(&swapped),
                placed_apart(&c),
                "{say}: listed the other way round, S asked at other places"
            );
            continue;
        }
        assert_eq!(
            asked(&swapped),
            asked(&c),
            "{say}: listed the other way round, another question"
        );
        // M at the defaults reads no listing, a `moves` gap's default aside.
        if !c.gaps.iter().any(|g| g.kind == GapKind::Moves) {
            assert_eq!(runs(&swapped), runs(&c), "{say}: listed the other way round, another M");
            listed_alike += usize::from(unsettled);
        }
    }
    assert!(safe > 500 && conflicts > 500, "{safe} safe, {conflicts} conflicts");
    assert!(listed_alike > 500, "an unsettled M the same in both listings {listed_alike} times");
    assert!(
        together > 100 && apart > 500 && beside > 50,
        "S at one spot {together} times, beside another insert {beside}, at two {apart}"
    );
    assert!(
        crossed_cases > 20 && movers > 1000 && cuts > 200 && laid_alone > 500,
        "S and S2 crossed {crossed_cases} times, {movers} movers, {cuts} cuts, {laid_alone} choices laid"
    );
}

/// A MOVE IS NO TOUCH, as a property: one side moves a stretch of one to
/// three positions, the other removes and inserts at random. A gap is
/// unsettled exactly where an insert's own anchors stand apart in the
/// mover's order once the other side's removals are applied — a `cut` —
/// and each insert's stretch stands in M right after its left anchor, or
/// at M's start where it has none (§2 R4 (i); the mutants that count a move
/// as a touch, or place a cut's default on the right, break one of the
/// two). Two thousand cases, both arms reached.
#[test]
fn a_move_is_no_touch_and_a_cut_defaults_after_its_left_anchor() {
    let mut rng = Rng(0x5EED_2026_1123);
    let (mut cuts, mut clean) = (0, 0);
    for case in 0..2000 {
        let n = 4 + rng.below(7);
        let from = 1 + rng.below(n);
        let moved: Vec<u64> = (from..(from + 1 + rng.below(3)).min(n + 1)).collect();
        let rest: Vec<u64> = (1..=n).filter(|p| !moved.contains(p)).collect();
        let to = rng.below(rest.len() as u64 + 1) as usize;
        let order: Vec<u64> = rest[..to].iter().chain(&moved).chain(&rest[to..]).copied().collect();
        let mover: Vec<Run> = order.iter().fold(Vec::new(), |mut out: Vec<Run>, &p| {
            match out.last_mut() {
                Some(last) if last.reach() == p => last.width += 1,
                _ => out.push(rd(p, 1)),
            }
            out
        });
        let editor = Side::draw(&mut rng, n, 200);
        let say = format!(
            "case {case}: n {n}; order {order:?}; editor {:?} {:?}",
            editor.removed, editor.inserts
        );
        let c = compose(&[rd(1, n)], &two(mover, editor.runs(n)));
        let spine: Vec<u64> =
            order.iter().copied().filter(|p| !editor.removed.contains(p)).collect();
        let together = |(x, y): (u64, u64)| match (x, y) {
            (0, y) if y == n + 1 => spine.is_empty(),
            (0, y) => spine.first() == Some(&y),
            (x, y) if y == n + 1 => spine.last() == Some(&x),
            (x, y) => spine.windows(2).any(|w| w == [x, y]),
        };
        let spots = editor.spots(n);
        let apart = spots.iter().any(|s| !together(*s));
        assert_eq!(c.gaps.iter().any(|g| !g.settled), apart, "{say}; gaps {:?}", c.gaps);
        if apart {
            cuts += 1;
        } else {
            clean += 1;
        }
        let m = expand(&runs(&c));
        for (k, &(after, start, _)) in editor.inserts.iter().enumerate() {
            let first = editor
                .inserts
                .iter()
                .enumerate()
                .filter(|(j, i)| spots[*j] == spots[k] && (i.0, *j) < (after, k))
                .count()
                == 0;
            if !first {
                continue;
            }
            let at = m.iter().position(|p| *p == (d(), start)).expect("the insert is in M");
            let left = spots[k].0;
            match left {
                0 => assert_eq!(at, 0, "{say}: the stretch at the start of M"),
                x => assert_eq!(
                    m.get(at.wrapping_sub(1)),
                    Some(&(d(), x)),
                    "{say}: the stretch after its left anchor D·{x}"
                ),
            }
        }
    }
    assert!(cuts > 200 && clean > 200, "{cuts} cuts, {clean} clean");
}

/// THE DEDUP, as a property: over a base of one to three positions, two
/// sides each insert a word or two of one to three letters over the two
/// letters `a` and `b`, beside removals at random. An `order` gap is settled
/// exactly where its two groups' bytes are equal, `values.applied` names
/// exactly those gaps, and the record's `deduped` names each with the copy
/// kept and every run dropped (§5, case (g); the mutants that drop a copy
/// without logging it, or keep a copy whose bytes differ, break one of the
/// three). Five thousand cases, both arms reached.
#[test]
fn the_dedup_settles_an_order_gap_exactly_where_its_groups_bytes_are_equal() {
    let mut rng = Rng(0x5EED_D0D0);
    let (mut kept_once, mut asked_order) = (0, 0);
    for case in 0..5000 {
        let n = 1 + rng.below(3);
        let mut draw = |from: u64| {
            let mut side = Side::draw(&mut rng, n, from);
            side.inserts.push((rng.below(n + 1), from + 50, 1 + rng.below(2)));
            side
        };
        let (a, b) = (draw(100), draw(200));
        let letters: Vec<(u64, u8)> = a
            .fresh()
            .into_iter()
            .chain(b.fresh())
            .map(|p| (p, if rng.below(2) == 0 { b'a' } else { b'b' }))
            .collect();
        let values = |_: SideIx, run: &Run| -> Option<Vec<Item>> {
            (run.i_start..run.reach())
                .map(|p| letters.iter().find(|(q, _)| *q == p).map(|(_, l)| vec![*l]))
                .collect()
        };
        let c = compose_runs(
            &[rd(1, n)],
            &d(),
            &two(a.runs(n), b.runs(n)),
            None,
            &Options::default(),
            &values,
        );
        let say = format!(
            "case {case}: n {n}; A {:?} {:?}; B {:?} {:?}; {letters:?}",
            a.removed, a.inserts, b.removed, b.inserts
        );
        let mut expected = Vec::new();
        for gap in c.gaps.iter().filter(|g| g.kind == GapKind::Order) {
            let group = |s: u8| -> Vec<Item> {
                gap.runs
                    .iter()
                    .filter(|(side, _)| side.0 == s)
                    .flat_map(|(side, run)| values(*side, run).expect("a word's letters"))
                    .collect()
            };
            let equal = group(0) == group(1);
            assert_eq!(gap.settled, equal, "{say}: gap {:?}", gap);
            if equal {
                kept_once += 1;
                let dropped: Vec<(SideIx, Run)> =
                    gap.runs.iter().filter(|(side, _)| side.0 == 1).cloned().collect();
                assert_eq!(
                    gap.placed,
                    Placement::Order(vec![SideIx(0)]),
                    "{say}: the copy kept is the earlier group's"
                );
                expected.push(Deduped { gap: gap.id, kept: vec![SideIx(0)], dropped });
            } else {
                asked_order += 1;
            }
        }
        let applied: Vec<GapId> = expected.iter().map(|x| x.gap).collect();
        assert_eq!(c.values.applied, applied, "{say}");
        assert_eq!(recorded(&c).deduped(), expected, "{say}");
    }
    assert!(kept_once > 100 && asked_order > 100, "{kept_once} kept once, {asked_order} asked");
}

/// A CHOICE MOVES ITS GAP ALONE, AND A RECORD RE-STATES IT, as a property
/// over the one rule's inputs — half of them over a base that places one
/// run twice (skep #763). Resolving every unsettled gap at its default
/// leaves M and every gap's number, kind and runs as they were. Each single
/// choice at an unsettled gap that is no `moves` gap — each order of its
/// sides, each side kept alone, the omission, and a move after or before
/// every anchor any gap names — leaves every other gap whole as it was,
/// its number, kind, runs, anchors and placement, and M as it was once the
/// chosen gap's words are taken out of both. Each choice at a gap the rules
/// settled leaves M and every gap as they were, and stands in `ignored`.
/// Each holder chosen at a `moves` gap with spots settles that gap at the
/// holder's placement, and every other gap keeps its number with its kind
/// and its runs besides the moved words, or no gap holds its number, any
/// gap the moved words make numbered past the report's last (CM-I33). And
/// the record of each composition re-states it, its options composing again
/// to the same M and the same gaps (§1.4 step 7, §4; the mutants that
/// renumber a gap on a choice, move a gap beside the chosen one, move a gap
/// the rules settled, or re-state a move by the first placement of a run
/// placed twice, break one of these). Half the cases read no value; the
/// other half read a base of "ab\n" bytes, a quarter with each side's fresh
/// words a letter of its own and a quarter with every side's over two
/// letters, so the line rule asks `line` gaps — a choice at one leaves
/// every other gap whole, its kind and `removed` among it — and the dedup
/// keeps equal words once (skep #1173, #1176; §5 (g)). Fifteen hundred
/// cases, more than two thousand choices among them.
#[test]
fn a_choice_moves_its_gap_alone_and_a_record_restates_it() {
    let mut rng = Rng(0x5EED_C40C);
    let (mut choices_made, mut doubled_made, mut on_settled, mut holders_chosen) = (0, 0, 0, 0);
    let (mut at_line, mut removals_named, mut deduped) = (0, 0, 0);
    for case in 0..1500 {
        let doubled = rng.below(2) == 0;
        let (base, n, half) = if doubled {
            let m = 2 + rng.below(3);
            (vec![rd(1, m), rd(1, m)], 2 * m, m)
        } else {
            let n = 4 + rng.below(5);
            (vec![rd(1, n)], n, n)
        };
        let ordinal = |p: u64| (p - 1) % half + 1;
        let (mut a, mut b) = (Side::draw(&mut rng, n, 100), Side::draw(&mut rng, n, 200));
        if rng.below(2) == 0 {
            let (after_a, after_b, width) = (rng.below(n + 1), rng.below(n + 1), 1 + rng.below(3));
            a.place(&mut rng, (after_a, 300, width));
            b.place(&mut rng, (after_b, 300, width));
        }
        // The values the composition reads: none, or a base of "ab\n" bytes
        // beside fresh words of one letter a side, or of two letters drawn
        // by each position's last digit, alike on every side — where B
        // writes the letters of A's first word at its place too.
        let arm = rng.below(4);
        if let Some(&(after, _, width)) = a.inserts.first().filter(|_| arm == 3) {
            b.place(&mut rng, (after, 250, width));
        }
        let sides = two(a.runs_over(n, ordinal), b.runs_over(n, ordinal));
        let bytes: Vec<u8> = (0..half).map(|_| b"ab\n"[rng.below(3) as usize]).collect();
        let letters: Vec<u8> = (0..10).map(|_| b"ab"[rng.below(2) as usize]).collect();
        let values: Box<AskedValues<'_>> = match arm {
            0 | 1 => Box::new(unread),
            2 => Box::new(lined_bytes(&bytes)),
            _ => Box::new(|_: SideIx, run: &Run| {
                (run.i_start..run.reach())
                    .map(|p| match p {
                        p if (1..=half).contains(&p) => Some(vec![bytes[p as usize - 1]]),
                        p if p >= 100 => Some(vec![letters[(p % 10) as usize]]),
                        _ => None,
                    })
                    .collect()
            }),
        };
        let say = format!(
            "case {case}: base {base:?} {:?}, arm {arm}; sides {sides:?}",
            String::from_utf8_lossy(&bytes)
        );
        let with = |options: &Options| compose_runs(&base, &d(), &sides, None, options, &*values);
        let c = with(&Options::default());
        deduped += usize::from(!c.values.applied.is_empty());
        removals_named += usize::from(c.gaps.iter().any(|g| !g.removed.is_empty()));
        let named = |c: &Composed| {
            c.gaps.iter().map(|g| (g.id, g.kind, g.runs.clone())).collect::<Vec<_>>()
        };
        let one = |gap: &Gap, choice: &Choice| {
            let res = Resolution { gap: gap.id, choice: choice.clone(), by: ResolvedBy::Person };
            (with(&Options { resolutions: vec![res.clone()], ..Options::default() }), res)
        };
        let restated = |one: &Composed, what: &str| {
            let again = with(&recorded(one).options());
            assert_eq!(
                (runs(&again), &again.gaps),
                (runs(one), &one.gaps),
                "{say}: {what}, re-stated"
            );
        };
        // Each unsettled gap resolved as it stands: its order, or the one
        // side it holds, or nothing where it holds none.
        let defaults: Vec<Resolution> = c
            .gaps
            .iter()
            .filter(|g| !g.settled)
            .map(|g| {
                let choice = match (&g.placed, g.runs.first()) {
                    (Placement::Order(sides), _) => Choice::Order(sides.clone()),
                    (Placement::After | Placement::Before, Some((side, _))) => {
                        Choice::Order(vec![*side])
                    }
                    (Placement::After | Placement::Before | Placement::Omitted, _) => Choice::Omit,
                };
                Resolution { gap: g.id, choice, by: ResolvedBy::Person }
            })
            .collect();
        let at_defaults = with(&Options { resolutions: defaults, ..Options::default() });
        assert_eq!(
            (runs(&at_defaults), named(&at_defaults)),
            (runs(&c), named(&c)),
            "{say}: every gap at its default"
        );
        assert!(
            at_defaults.gaps.iter().all(|g| g.settled) && at_defaults.ignored.is_empty(),
            "{say}: {:?}",
            at_defaults
        );
        restated(&at_defaults, "the defaults");
        let anchors: Vec<Address> =
            c.gaps.iter().flat_map(|g| g.after.iter().chain(&g.before)).cloned().collect();
        let last = c.gaps.iter().map(|g| g.id).max();
        for gap in c.gaps.iter().filter(|g| !(g.kind == GapKind::Moves && g.spots.is_empty())) {
            let mut sides_at: Vec<SideIx> = Vec::new();
            for (side, _) in &gap.runs {
                if !sides_at.contains(side) {
                    sides_at.push(*side);
                }
            }
            if !gap.spots.is_empty() {
                if gap.settled {
                    continue;
                }
                // A holder chosen: its placement, every other gap's number kept.
                let moved: BTreeSet<u64> =
                    gap.runs.iter().flat_map(|(_, r)| r.i_start..r.reach()).collect();
                // A gap's words by side besides the moved ones: the moved
                // words leaving a group can change which group R1 lays first.
                let besides = |g: &Gap| -> BTreeSet<(u8, u64)> {
                    let positions = g
                        .runs
                        .iter()
                        .flat_map(|(s, r)| (r.i_start..r.reach()).map(move |p| (s.0, p)));
                    positions.filter(|(_, p)| !moved.contains(p)).collect()
                };
                for holder in &sides_at {
                    let (chosen, _) = one(gap, &Choice::Order(vec![*holder]));
                    let at =
                        chosen.gaps.iter().find(|g| g.id == gap.id).expect("the gap chosen at");
                    assert_eq!(
                        (at.placed.clone(), at.settled),
                        (Placement::Order(vec![*holder]), true),
                        "{say}: holder {} at gap {:?}",
                        holder.0,
                        gap.id
                    );
                    for other in c.gaps.iter().filter(|g| g.id != gap.id) {
                        if let Some(now) = chosen.gaps.iter().find(|g| g.id == other.id) {
                            assert_eq!(
                                (now.kind, besides(now)),
                                (other.kind, besides(other)),
                                "{say}: holder {} at gap {:?} renumbered gap {:?}",
                                holder.0,
                                gap.id,
                                other.id
                            );
                        }
                    }
                    for made in chosen.gaps.iter().filter(|g| !c.gaps.iter().any(|o| o.id == g.id))
                    {
                        assert!(
                            Some(made.id) > last,
                            "{say}: a gap the holder makes numbered {:?}",
                            made.id
                        );
                    }
                    restated(&chosen, &format!("holder {} at gap {:?}", holder.0, gap.id));
                    holders_chosen += 1;
                }
                continue;
            }
            let mut choices = vec![Choice::Omit];
            choices.extend(sides_at.iter().map(|s| Choice::KeepOnly(*s)));
            if let [x, y] = sides_at[..] {
                choices.extend([Choice::Order(vec![x, y]), Choice::Order(vec![y, x])]);
            }
            choices.extend(
                anchors.iter().flat_map(|a| [Choice::After(a.clone()), Choice::Before(a.clone())]),
            );
            let words: BTreeSet<(Address, u64)> =
                expand(&gap.runs.iter().map(|(_, r)| r.clone()).collect::<Vec<_>>())
                    .into_iter()
                    .collect();
            let besides_gap = |c: &Composed| -> Vec<(Address, u64)> {
                expand(&runs(c)).into_iter().filter(|p| !words.contains(p)).collect()
            };
            for choice in choices {
                let (one, res) = one(gap, &choice);
                if gap.settled {
                    // A gap the rules settled takes no choice, a move among them.
                    assert_eq!(
                        (runs(&one), &one.gaps, &one.ignored),
                        (runs(&c), &c.gaps, &vec![res]),
                        "{say}: {choice:?} at settled gap {:?}",
                        gap.id
                    );
                    on_settled += 1;
                    continue;
                }
                assert_eq!(named(&one), named(&c), "{say}: {choice:?} at gap {:?}", gap.id);
                let at = one.gaps.iter().find(|g| g.id == gap.id).expect("the gap chosen at");
                assert!(
                    one.ignored.is_empty()
                        && at.settled
                        && at.resolved_by == Some(ResolvedBy::Person),
                    "{say}: {choice:?} at gap {:?} not applied: {:?}",
                    gap.id,
                    one.ignored
                );
                for (now, was) in one.gaps.iter().zip(&c.gaps).filter(|(g, _)| g.id != gap.id) {
                    assert_eq!(
                        now, was,
                        "{say}: {choice:?} at gap {:?} moved gap {:?}",
                        gap.id, was.id
                    );
                }
                assert_eq!(
                    besides_gap(&one),
                    besides_gap(&c),
                    "{say}: {choice:?} at gap {:?} moved words beside it",
                    gap.id
                );
                restated(&one, &format!("{choice:?} at gap {:?}", gap.id));
                choices_made += 1;
                doubled_made += usize::from(doubled);
                at_line += usize::from(gap.kind == GapKind::Line);
            }
        }
    }
    assert!(
        choices_made > 2000 && doubled_made > 500 && on_settled > 500 && holders_chosen > 100,
        "{choices_made} choices, {doubled_made} over a run placed twice, {on_settled} at settled gaps, {holders_chosen} holders chosen"
    );
    assert!(
        at_line > 800 && removals_named > 20 && deduped > 70,
        "{at_line} choices at a line gap, {removals_named} compositions naming a removal, {deduped} kept once by the dedup"
    );
}

/// THREE SIDES, as a property (§1.2's fold; the one rule): three sides of
/// removals and inserts, half the cases with one fresh run S two of them
/// hold, each after a base position of its own, and half with the head
/// moving a stretch of the base besides, which the spine takes. The same
/// inputs give the same composition; M holds the base less every removal
/// and every addition once, S once; a touch between any two of the sides
/// asks, and so does a cut — an insert whose two surviving anchors the
/// head's order parts — and S at two spots (CM-I33); with no S, two sides'
/// inserts at one spot stand in one gap that holds both (R1), whatever
/// either side did with the material between their anchors. Where nothing
/// asks, the three-way merge with the daughters listed the other way round
/// gives the same M, and where the head moved nothing, the head's and the
/// first daughter's merge, folded with the second daughter, asks nothing
/// either and gives the same M: a move beside a third side's removal can
/// part two anchors in the fold that the removal leaves no cut between in
/// the three-way merge. One case in eight draws, on purpose, the head
/// moving a base position out from between an insert's anchors while the
/// two daughters remove it, one writing at its place (the mutants that drop
/// a third side's additions, lay S twice, settle a pair's touch beside a
/// third side's changes, or call a stretch a collision only where its own
/// side removed some of the material between its anchors each break one of
/// these). Two thousand cases, every arm reached.
#[test]
fn three_sides_keep_every_addition_once_and_fold_as_two() {
    let mut rng = Rng(0x005E_ED35_1DE5);
    let (mut settled, mut asked, mut with_s, mut movers, mut forced, mut at_one_spot) =
        (0, 0, 0, 0, 0, 0);
    for case in 0..2000 {
        let n = 4 + rng.below(7);
        let shaped = rng.below(8) == 0;
        let mut sides: Vec<Side> = if shaped {
            // The head moves `p` to the end and writes right after `p − 1`;
            // both daughters remove `p`, one writing in its place.
            forced += 1;
            let p = 2 + rng.below(n - 2);
            let order = (1..=n).filter(|&q| q != p).chain([p]).collect();
            let head = Side {
                removed: BTreeSet::new(),
                inserts: vec![(p - 1, 100, 1 + rng.below(2))],
                order,
            };
            let remover = |inserts: Vec<(u64, u64, u64)>| Side {
                removed: BTreeSet::from([p]),
                inserts,
                order: (1..=n).collect(),
            };
            let writes = vec![(p, 200, 1 + rng.below(2))];
            match rng.below(2) {
                0 => vec![head, remover(writes), remover(vec![])],
                _ => vec![head, remover(vec![]), remover(writes)],
            }
        } else {
            let mut drawn: Vec<Side> =
                (0..3u64).map(|k| Side::draw(&mut rng, n, 100 * (k + 1))).collect();
            if rng.below(2) == 0 {
                drawn[0].move_one(&mut rng);
            }
            drawn
        };
        let mover = sides[0].moved();
        movers += usize::from(mover);
        let owns = sides.clone();
        let shared = (!shaped && rng.below(2) == 0).then(|| {
            let x = rng.below(3) as usize;
            let y = (x + 1 + rng.below(2) as usize) % 3;
            ((x, y), (rng.below(n + 1), rng.below(n + 1)), 1 + rng.below(3))
        });
        if let Some(((x, y), (after_x, after_y), width)) = shared {
            sides[x].place(&mut rng, (after_x, 400, width));
            sides[y].place(&mut rng, (after_y, 400, width));
            with_s += 1;
        }
        let lists: Vec<(SideIx, Vec<Run>)> =
            sides.iter().enumerate().map(|(k, side)| (SideIx(k as u8), side.runs(n))).collect();
        let say = format!(
            "case {case}: n {n}; the head's order {:?}; {}",
            sides[0].order,
            sides
                .iter()
                .map(|s| format!("{:?} {:?}", s.removed, s.inserts))
                .collect::<Vec<_>>()
                .join("; ")
        );
        let base = [rd(1, n)];
        let c = compose(&base, &lists);
        assert_eq!(c, compose(&base, &lists), "{say}: the same inputs, another composition");
        let kept = |p: &u64| sides.iter().all(|side| !side.removed.contains(p));
        let mut expected: Vec<u64> =
            (1..=n).filter(kept).chain(owns.iter().flat_map(Side::fresh)).collect();
        expected.extend(shared.map(|(_, _, width)| 400..400 + width).into_iter().flatten());
        expected.sort_unstable();
        let mut got: Vec<u64> = c.runs.iter().flat_map(|p| p.run.i_start..p.run.reach()).collect();
        got.sort_unstable();
        assert_eq!(got, expected, "{say}: every addition once, no removal");
        let unsettled = c.gaps.iter().any(|g| !g.settled);
        // S at two spots: read by the base positions its two holders keep.
        let apart = shared.is_some_and(|((x, y), (after_x, after_y), _)| {
            let both = |p: &u64| !sides[x].removed.contains(p) && !sides[y].removed.contains(p);
            sides[x].common_spot(after_x, n, both) != sides[y].common_spot(after_y, n, both)
        });
        let pairs = [(0, 1), (0, 2), (1, 2)];
        let touched = pairs.iter().any(|&(i, j)| touched_the_same(&owns[i], &owns[j], n));
        // A cut: an insert whose two surviving anchors stand apart in the
        // spine, the head's order of the survivors.
        let spine: Vec<u64> = sides[0].order.iter().copied().filter(kept).collect();
        let survives = |p: u64| p == 0 || p == n + 1 || kept(&p);
        let together_in_spine = |(x, y): (u64, u64)| match (x, y) {
            (0, y) if y == n + 1 => spine.is_empty(),
            (0, y) => spine.first() == Some(&y),
            (x, y) if y == n + 1 => spine.last() == Some(&x),
            (x, y) => spine.windows(2).any(|w| w == [x, y]),
        };
        let cut = owns.iter().any(|side| {
            side.spots(n)
                .into_iter()
                .any(|(x, y)| survives(x) && survives(y) && !together_in_spine((x, y)))
        });
        if touched || apart || cut {
            assert!(unsettled, "{say}: a touch asks nothing; gaps {:?}", c.gaps);
        }
        // Two sides' inserts at one spot stand in one gap that holds both.
        if shared.is_none() {
            let holds = |g: &Gap, side: usize, start: u64| {
                g.runs
                    .iter()
                    .any(|(s, r)| s.0 as usize == side && r.i_start <= start && start < r.reach())
            };
            for &(i, j) in &pairs {
                let (spots_i, spots_j) = (owns[i].spots(n), owns[j].spots(n));
                for (k, &(_, start_i, _)) in owns[i].inserts.iter().enumerate() {
                    for (l, &(_, start_j, _)) in owns[j].inserts.iter().enumerate() {
                        if spots_i[k] != spots_j[l] {
                            continue;
                        }
                        at_one_spot += 1;
                        assert!(
                            c.gaps.iter().any(|g| holds(g, i, start_i) && holds(g, j, start_j)),
                            "{say}: D·{start_i} and D·{start_j} at one spot {:?}, in no one gap: {:?}",
                            spots_i[k],
                            c.gaps
                        );
                    }
                }
            }
        }
        if unsettled {
            asked += 1;
            continue;
        }
        settled += 1;
        if !mover {
            let first_two = compose(&base, &lists[..2]);
            let folded = compose(&base, &two(runs(&first_two), lists[2].1.clone()));
            assert!(
                first_two.gaps.iter().chain(&folded.gaps).all(|g| g.settled),
                "{say}: the fold asks where the three do not: {:?} then {:?}",
                first_two.gaps,
                folded.gaps
            );
            assert_eq!(runs(&folded), runs(&c), "{say}: the fold, another M");
        }
        let swapped = vec![
            lists[0].clone(),
            (SideIx(1), lists[2].1.clone()),
            (SideIx(2), lists[1].1.clone()),
        ];
        assert_eq!(
            runs(&compose(&base, &swapped)),
            runs(&c),
            "{say}: the daughters swapped, another M"
        );
    }
    assert!(
        settled > 200 && asked > 500 && with_s > 500,
        "{settled} settled, {asked} asked, {with_s} with S"
    );
    assert!(
        movers > 600 && forced > 150 && at_one_spot > 200,
        "{movers} movers, {forced} drawn on purpose, {at_one_spot} pairs of inserts at one spot"
    );
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

/// The three `withheld` refusals name the document and the code, the same
/// words at every act that returns them (SP-10): `Unreadable` answers the
/// composition, the shot's value reads, the draft landing's read of its
/// draft and the take-backs' reads; `LineTextWithheld` the composition's
/// read of the text that decides the line rule, naming beside the document
/// the place of the pair of changes — each by its anchor, or the document's
/// edge — and the ways on, a share or the words published (skep #1174,
/// #1176);
/// `WindowWithheld` the shot's, the draft landing's, the take-backs' and
/// the restore's writes, naming beside the document the words refused — a
/// stretch by its first and last position, a stretch of one by that
/// position alone, the document and the code alone where it names none.
/// None says what the act did, which the embedder says.
#[test]
fn the_withheld_refusals_name_the_document_and_leave_the_outcome_to_the_embedder() {
    let doc = addr("1.0.2.0.70");
    let unreadable = Refusal::Unreadable(doc.clone()).to_string();
    assert_eq!(unreadable, "1.0.2.0.70 is not readable to this reader (withheld)");
    let line = |after: Option<&str>, before: Option<&str>| {
        Refusal::LineTextWithheld { doc: doc.clone(), after: after.map(addr), before: before.map(addr) }
            .to_string()
    };
    let between = line(Some("1.0.1.0.64.0.1.1"), Some("1.0.1.0.64.0.1.3"));
    assert_eq!(between, "1.0.2.0.70 is not readable to this reader (withheld), and a window onto it stands in the text the merge reads, whatever its switches, to tell whether two sides' changes meet at a line's edge — the first after 1.0.1.0.64.0.1.1, the second before 1.0.1.0.64.0.1.3: the merge composes once 1.0.2.0.70 is shared with this reader or its words are published");
    let edges = line(None, None);
    assert!(edges.contains("— the first at the document's start, the second at its end:"), "{edges}");
    for said in [&between, &edges] {
        assert!(
            !said.replace("its words are published", "").contains("published"),
            "published only as the way on: {said}"
        );
    }
    let windowed = |positions: Vec<(u64, u64)>| {
        Refusal::WindowWithheld { origin: doc.clone(), positions }.to_string()
    };
    let unplaced = windowed(Vec::new());
    assert_eq!(
        unplaced,
        "1.0.2.0.70 is not shared with you (withheld), and a run this write sends windows it"
    );
    let placed = windowed(vec![(4, 6), (20, 1)]);
    assert_eq!(placed, "1.0.2.0.70 is not shared with you (withheld), and the words at positions 4–9 and 20 of the state this write sends window it");
    let one = windowed(vec![(20, 1)]);
    assert_eq!(one, "1.0.2.0.70 is not shared with you (withheld), and the word at position 20 of the state this write sends windows it");
    let three = windowed(vec![(1, 2), (4, 1), (9, 3)]);
    assert!(three.contains("the words at positions 1–2, 4 and 9–11 of the state"), "{three}");
    for said in [&unreadable, &unplaced, &placed, &one, &three] {
        for outcome in ["nothing", "composed", "published", "shot", "merged"] {
            assert!(!said.contains(outcome), "`{outcome}`: {said}");
        }
    }
    for said in [&between, &edges] {
        for outcome in ["nothing", "composed", "shot", "merged"] {
            assert!(!said.contains(outcome), "`{outcome}`: {said}");
        }
    }
}

/// The words a `WindowWithheld` names are the stretches its write's refused
/// runs fill: refused runs back to back are one stretch whatever their
/// I-addresses, a run not refused parts the stretches either side of it,
/// and every stretch opens at its first position counted from 1 (the
/// mutants that count from 0, join across a run not refused, or leave runs
/// back to back apart answer another list).
#[test]
fn the_words_withheld_are_the_stretches_the_refused_runs_fill_counted_from_one() {
    use super::reads::stretches;
    assert_eq!(stretches([(true, 2), (true, 3), (false, 11), (true, 4)]), vec![(1, 5), (17, 4)]);
    assert_eq!(stretches([(false, 3), (true, 1)]), vec![(4, 1)]);
    assert_eq!(stretches([(false, 3), (false, 1)]), Vec::new(), "nothing refused");
    assert_eq!(stretches([]), Vec::new());
}

/// A run the shot's base carries is one the base's runs on its chain hold
/// whole, joined where they overlap or abut, wherever the base arranges
/// them — the board's own test (PUB-6.24): two runs adjoining in I-space
/// and apart in V carry a run neither holds whole, and none carries a run
/// reaching past them or one of another chain (the mutant that asks one
/// base run to hold the run whole carries none of the first).
#[test]
fn a_run_the_base_carries_is_one_its_runs_on_the_runs_chain_hold_joined() {
    use super::windows::carried;
    use crate::board::answers::IRun;
    let held = |first: u64, width: u64, ordinal: u64| IRun {
        prefix: format!("{}.0.1", z()),
        first,
        width,
        ordinal,
    };
    let head = [held(1, 2, 1), held(3, 3, 10)];
    assert!(carried(&head, &Run::new(z(), 1, 5)), "the two adjoining runs hold it together");
    assert!(carried(&head, &Run::new(z(), 2, 3)), "inside the two");
    assert!(!carried(&head, &Run::new(z(), 2, 5)), "it reaches past them");
    assert!(!carried(&head[..1], &Run::new(z(), 1, 5)), "the first alone holds two of its words");
    assert!(!carried(&head, &Run::new(d(), 1, 5)), "another chain");
    assert!(
        carried(&[held(1, 4, 1), held(3, 3, 5)], &Run::new(z(), 2, 4)),
        "overlapping runs joined"
    );
    assert!(!carried(&[], &Run::new(z(), 1, 1)), "no base run");
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
