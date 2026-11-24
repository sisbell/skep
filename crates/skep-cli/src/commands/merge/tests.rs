use skep_client::merge::{Flag, Spot};

use super::*;

/// One window part, its words and pair as a test names them.
fn part(version: Option<&str>, named_since: bool) -> WindowPart {
    let span =
        skep_client::publication::ISpan { chain: "1.0.1.0.69.0.1".to_string(), first: 1, width: 5 };
    WindowPart {
        key: skep_client::publication::PartKey { run: 1, part: 0 },
        words: Some("quote".to_string()),
        after: Some("the cat".to_string()),
        ordinal: 8,
        origin: parse_address("1.0.1.0.69").expect("an address"),
        owner: None,
        span,
        record: version.map(|_| parse_address("1.0.1.0.69.0.2.1").expect("an address")),
        counterpart: None,
        version: version.map(|v| parse_address(v).expect("an address")),
        sides: Vec::new(),
        admits: Vec::new(),
        answer: None,
        named_since,
    }
}

/// A part a record named after its answer was given says the version
/// that published it and the two answers it takes (§6); the wording the
/// run cannot stage over a real daemon, a record landing between one
/// process's two reads.
#[test]
fn a_part_named_since_its_answer_says_the_version_that_published_it() {
    let line = named_since_line(&part(Some("1.0.1.0.64.1"), true));
    assert_eq!(line, "nothing was published — 1.0.1.0.69’s words were published in 1.0.1.0.64.1 after you answered; answer for them again: --window 1.0.1.0.64.1 or --leave-out 1.0.1.0.64.1");
}

/// A passage's words are rendered one line and inert before a line
/// quotes them (SP-15): a newline or an escape in a document's words
/// cannot forge a line of the terminal's.
#[test]
fn a_quoted_passage_cannot_forge_a_line() {
    assert_eq!(quoted(Some("a\nb\x1b[31m"), "unread"), "“a<U+000A>b<U+001B>[31m”");
    assert_eq!(quoted(None, "a passage you cannot read"), "a passage you cannot read");
}

/// An address a test spells.
fn a(text: &str) -> Address {
    parse_address(text).expect("an address")
}

/// Gap 2 as the gap lines' tests build it: side 0's three words at
/// `D·20`, of `kind`, its left anchor `after`, placed as `placed`, with
/// `spots`.
fn gap_at(kind: GapKind, after: Option<Address>, placed: Placement, spots: Vec<Spot>) -> Gap {
    Gap {
        id: GapId(2),
        kind,
        after,
        before: None,
        runs: vec![(SideIx(0), skep_client::merge::Run::new(a("1.0.1.0.1"), 20, 3))],
        placed,
        settled: false,
        resolved_by: None,
        spots,
    }
}

/// Each side's spot of one set of words two sides placed apart (CM-I33):
/// side 0's between `D·4` and `D·5`, side 1's before `D·1`.
fn spots_apart() -> Vec<Spot> {
    vec![
        Spot {
            side: SideIx(0),
            after: Some(a("1.0.1.0.1.0.1.4")),
            before: Some(a("1.0.1.0.1.0.1.5")),
        },
        Spot { side: SideIx(1), after: None, before: Some(a("1.0.1.0.1.0.1.1")) },
    ]
}

/// Returns the code and the detail a stop says as the board's refusal.
fn board_said(stop: Stop) -> (String, String) {
    match stop {
        Stop::Halt(Halt::Refused(r)) => (r.code, r.detail.unwrap_or_default()),
        other => panic!("the board's refusal: {other:?}"),
    }
}

/// A default's line says where the gap stands (§1.5): a `moves` gap
/// with spots at each side's place for the one set of words, a spine's
/// `moves` gap in the order of the side the spine took and never "at
/// the document's start", and every other gap by its anchor, a `line`
/// gap (skep #1173) among them (the mutants that keep the anchors' line
/// for a `moves` gap say the start).
#[test]
fn a_default_line_names_each_sides_place_and_no_place_for_the_spines_order() {
    assert_eq!(
        default_line(&gap_at(GapKind::Moves, None, Placement::Order(vec![SideIx(0)]), spots_apart())),
        "left at its default: gap 2 (moves) side 0 after 1.0.1.0.1.0.1.4, side 1 before 1.0.1.0.1.0.1.1, placed order:0"
    );
    assert_eq!(
        default_line(&gap_at(GapKind::Moves, None, Placement::Order(vec![SideIx(1)]), Vec::new())),
        "left at its default: gap 2 (moves) in side 1's order, placed order:1"
    );
    assert_eq!(
        default_line(&gap_at(
            GapKind::Cut,
            Some(a("1.0.1.0.1.0.1.4")),
            Placement::After,
            Vec::new()
        )),
        "left at its default: gap 2 (cut) after 1.0.1.0.1.0.1.4, placed after:1.0.1.0.1.0.1.4"
    );
    assert_eq!(
        default_line(&gap_at(GapKind::Corner, None, Placement::After, Vec::new())),
        "left at its default: gap 2 (corner) at the document's start, placed order:0"
    );
    assert_eq!(
        default_line(&gap_at(
            GapKind::Line,
            Some(a("1.0.1.0.1.0.1.25")),
            Placement::After,
            Vec::new()
        )),
        "left at its default: gap 2 (line) after 1.0.1.0.1.0.1.25, placed after:1.0.1.0.1.0.1.25"
    );
}

/// A gap needing a choice is named where it stands in the composition's
/// talk (the merge record's §6: the talk naming each side's place), as
/// its default line names it: one set of words two sides placed apart
/// at each side's place, beside them the choice that takes one side's
/// place; a spine's `moves` gap in the order of the side the spine took;
/// every other gap by its anchor, a `line` gap among them (the mutant that
/// names the kind and the default alone fails each).
#[test]
fn a_gap_needing_a_choice_is_named_where_it_stands() {
    assert_eq!(
        choice_named(&gap_at(GapKind::Moves, None, Placement::Order(vec![SideIx(0)]), spots_apart())),
        "gap 2 (moves) side 0 after 1.0.1.0.1.0.1.4, side 1 before 1.0.1.0.1.0.1.1, default order:0 — order:<side> or keep:<side> takes that side's place"
    );
    assert_eq!(
        choice_named(&gap_at(GapKind::Moves, None, Placement::Order(vec![SideIx(1)]), Vec::new())),
        "gap 2 (moves) in side 1's order, default order:1"
    );
    assert_eq!(
        choice_named(&gap_at(
            GapKind::Order,
            Some(a("1.0.1.0.1.0.1.4")),
            Placement::Order(vec![SideIx(0), SideIx(1)]),
            Vec::new()
        )),
        "gap 2 (order) after 1.0.1.0.1.0.1.4, default order:0,1"
    );
    assert_eq!(
        choice_named(&gap_at(
            GapKind::Line,
            Some(a("1.0.1.0.1.0.1.25")),
            Placement::After,
            Vec::new()
        )),
        "gap 2 (line) after 1.0.1.0.1.0.1.25, default after:1.0.1.0.1.0.1.25"
    );
}

/// A landing's refusals whose library words name acts this command has
/// none of are said naming its own flags (SP-10), each exit 1 under its
/// code: `landing_begun` names `--into` the draft — and that it replaces
/// any edit made there since — `--undo` and `--withdraw`; `head_holds`
/// the `--head` before the head, and none at version 1; `fork_base_moved`
/// `--new`. None says `resume`, a draft discarded or a fork made afresh
/// (the mutants that fall back to the library's words fail each).
#[test]
fn a_landings_refusals_name_this_commands_own_ways_on() {
    let library = ["resume", "discard", "afresh"];
    let begun = Refusal::LandingBegun { draft: a("1.0.1.0.72"), position: 21 };
    let (code, words) = board_said(refused_landing(begun.clone(), Step::Draft));
    assert_eq!(code, "landing_begun");
    for said in [
        "this merge already landed in 1.0.1.0.72 at position 21",
        "run this again with --into 1.0.1.0.72, which lands the merged list there again and writes its record, replacing any edit made in 1.0.1.0.72 since",
        "--undo 1.0.1.0.72 puts 1.0.1.0.72 back",
        "--withdraw 1.0.1.0.72 takes the merge out",
    ] {
        assert!(words.contains(said), "the words say {said:?}: {words}");
    }
    assert!(library.iter().all(|act| !words.contains(act)), "no act this command lacks: {words}");
    assert_eq!(crate::commands::finish(Err(refused_landing(begun, Step::Draft))), 1);
    let (code, words) =
        board_said(refused_landing(Refusal::HeadHolds { head: a("1.0.1.0.64.3") }, Step::Publish));
    assert_eq!(code, "head_holds");
    for said in [
        "1.0.1.0.64.3 already holds this merge",
        "nothing was published",
        "run this again with --head 1.0.1.0.64.2, the head that run composed on: it finds 1.0.1.0.64.3 and writes its record",
    ] {
        assert!(words.contains(said), "the words say {said:?}: {words}");
    }
    assert!(library.iter().all(|act| !words.contains(act)), "no act this command lacks: {words}");
    let (_, words) =
        board_said(refused_landing(Refusal::HeadHolds { head: a("1.0.1.0.64.1") }, Step::Publish));
    assert!(!words.contains("--head"), "no merge's shot minted version 1: {words}");
    let moved = Refusal::ForkBaseMoved {
        fork: a("1.0.1.2.0.70"),
        source: a("1.0.1.0.64.1"),
        head: a("1.0.1.0.64.2"),
    };
    let (code, words) = board_said(refused_landing(moved, Step::Draft));
    assert_eq!(code, "fork_base_moved");
    assert!(
        words.contains("run this again with --new in place of --into 1.0.1.2.0.70: it stages a fresh draft of yours from 1.0.1.0.64.2 and lands the merge there"),
        "{words}"
    );
    assert!(library.iter().all(|act| !words.contains(act)), "no act this command lacks: {words}");
}

/// A take-back's refusals whose library words name no act of this
/// command's are said naming its own (SP-10), each exit 1 under its
/// code: an inherited marker's `nothing_to_undo` names `--withdraw`,
/// never a draft discarded; at a withdrawal, `no_merge` names `--undo`,
/// which takes back a landing in a draft with no recorded base, and
/// never says "nothing to undo"; at an undo, `no_merge` keeps the
/// library's words (the mutants that fall back to the library's words
/// at either fail).
#[test]
fn a_take_backs_refusals_name_this_commands_own_ways_on() {
    let draft = a("1.0.1.0.72");
    let inherited = Refusal::NothingToUndo { draft: draft.clone(), why: NoUndo::Inherited };
    let (code, words) = board_said(refused_taking_out(&draft, inherited.clone(), Step::Undo));
    assert_eq!(code, "nothing_to_undo");
    for said in [
        "1.0.1.0.72 inherited the merge when it was staged",
        "nothing was taken back",
        "--withdraw 1.0.1.0.72 takes that merge out and keeps the words",
    ] {
        assert!(words.contains(said), "the words say {said:?}: {words}");
    }
    assert!(!words.contains("discard"), "{words}");
    assert_eq!(crate::commands::finish(Err(refused_taking_out(&draft, inherited, Step::Undo))), 1);
    let no_merge = Refusal::NoMerge { draft: draft.clone() };
    let (code, words) = board_said(refused_taking_out(&draft, no_merge.clone(), Step::Withdraw));
    assert_eq!(code, "no_merge");
    for said in [
        "1.0.1.0.72 carries no merge marker",
        "nothing was taken out",
        "--undo 1.0.1.0.72 takes such a landing back",
    ] {
        assert!(words.contains(said), "the words say {said:?}: {words}");
    }
    assert!(!words.contains("nothing to undo"), "a withdrawal says nothing of an undo: {words}");
    assert_eq!(
        board_said(refused_taking_out(&draft, no_merge.clone(), Step::Undo)),
        ("no_merge".to_string(), no_merge.to_string()),
        "an undo keeps the library's words"
    );
}

/// The help says `--into` replaces what the draft held and that
/// `--undo` puts it back, and refuses a draft of another account while
/// taking its fork (the mutant that says "a side of another account is
/// refused" fails it).
#[test]
fn the_help_says_what_into_replaces_and_which_side_is_refused() {
    let help = crate::args::HELP.split_whitespace().collect::<Vec<_>>().join(" ");
    for said in [
        "--into sets a draft's whole text to the merged text in one write — what the draft held is replaced, and --undo <draft> puts it back while nothing else is written there",
        "--into <draft> (the draft's whole text set to the merged text, what it held replaced: --undo <draft> puts it back while nothing else is written there)",
        "a draft of another account is refused (another account's fork goes as --fork)",
    ] {
        assert!(help.contains(said), "the help says {said:?}");
    }
    assert!(
        !help.contains("a side of another account is refused"),
        "another account's fork is taken"
    );
}

/// A gap that holds no runs — a collision no side filled — at an end of
/// M is spelled by its other anchor, the same place, and with no anchor
/// at all as `omit`: every default is a choice `--resolve` takes back
/// (the mutant that keeps the order of the gap's sides spells `order:`,
/// which the grammar refuses).
#[test]
fn a_default_of_a_gap_holding_no_runs_is_a_choice_the_command_takes_back() {
    let a = |s: &str| parse_address(s).expect("an address");
    let gap = |after: Option<Address>, before: Option<Address>| Gap {
        id: GapId(1),
        kind: GapKind::Collision,
        after,
        before,
        runs: Vec::new(),
        placed: Placement::After,
        settled: false,
        resolved_by: None,
        spots: Vec::new(),
    };
    let spelled = |g: &Gap| {
        let default = default_of(g);
        let parsed = resolution(&format!("1={default}"), &ResolvedBy::Person)
            .expect("a choice the command takes");
        (default, parsed.choice)
    };
    assert_eq!(
        spelled(&gap(None, Some(a("1.0.1.0.1.0.1.5")))),
        ("before:1.0.1.0.1.0.1.5".to_string(), Choice::Before(a("1.0.1.0.1.0.1.5")))
    );
    assert_eq!(spelled(&gap(None, None)), ("omit".to_string(), Choice::Omit));
    assert_eq!(
        spelled(&gap(Some(a("1.0.1.0.1.0.1.4")), None)),
        ("after:1.0.1.0.1.0.1.4".to_string(), Choice::After(a("1.0.1.0.1.0.1.4")))
    );
}

/// A place the merge kept once is said and reported (§5, case (g)): the
/// gap, the head whose copy M holds, and the side's address, where its
/// copy and any link on it stay; `deduped` spells the dropped run as the
/// record spells a gap's; a record whose dedup kept nothing once says
/// and reports nothing (the mutants that name the wrong side or leave
/// the place unsaid).
#[test]
fn a_place_kept_once_names_the_copy_kept_and_where_the_other_stays() {
    use skep_client::merge::{Role, Run, RunCounts, SideAt, ValueLog};
    let a = |s: &str| parse_address(s).expect("an address");
    let doc = a("1.0.1.0.1");
    let gap = Gap {
        id: GapId(2),
        kind: GapKind::Order,
        after: Some(a("1.0.1.0.1.0.1.7")),
        before: None,
        runs: vec![
            (SideIx(0), Run::new(doc.clone(), 8, 6)),
            (SideIx(1), Run::new(doc.clone(), 17, 6)),
        ],
        placed: Placement::Order(vec![SideIx(0)]),
        settled: true,
        resolved_by: Some(ResolvedBy::Rule),
        spots: Vec::new(),
    };
    let mut record = Record {
        doc: doc.clone(),
        base: a("1.0.1.0.1.1"),
        sides: vec![
            SideAt::Member { at: a("1.0.1.0.1.2"), role: Role::Head },
            SideAt::Member { at: a("1.0.1.0.1.1.1"), role: Role::Alternative },
        ],
        landed: None,
        claims: Vec::new(),
        runs: RunCounts { a: 2, b: 3, m: 3 },
        retries: 0,
        gaps: vec![gap],
        values: ValueLog {
            dedup: true,
            retype: false,
            applied: vec![GapId(2)],
            retyped: Vec::new(),
        },
        answers: Vec::new(),
        replaces: None,
        by: "skep-client".into(),
        link: None,
    };
    assert_eq!(
        dedup_lines(&record),
        ["gap 2: matching words were added on both sides — kept once, as the head has them; the side's copy stays in 1.0.1.0.1.1.1, and any links on it stay there, not carried into the merge"]
    );
    assert_eq!(
        deduped_value(&record),
        json!([{"gap": 2, "kept": [0], "dropped": [{"side": 1, "i_start": "1.0.1.0.1.0.1.17", "width": "6"}]}])
    );
    record.values.applied.clear();
    assert_eq!((dedup_lines(&record), deduped_value(&record)), (Vec::<String>::new(), json!([])));
}

/// Each misfit keeps its command's words (§6): an answer that fits
/// nothing, one naming words already published, one naming words a
/// second answer also names.
#[test]
fn a_misfit_says_which_answer_fits_nothing_or_names_the_same_words_twice() {
    let key = parse_address("1.0.1.0.64.1").expect("an address");
    let origin = parse_address("1.0.1.0.69").expect("an address");
    assert_eq!(misfit_line(&Misfit::FitsNothing { flag: Flag::Window, key: key.clone(), published_in: vec![] }), "--window 1.0.1.0.64.1 answers nothing here — no words in this merge are published in 1.0.1.0.64.1");
    assert_eq!(misfit_line(&Misfit::FitsNothing { flag: Flag::KeepPrivate, key: origin.clone(), published_in: vec![key.clone()] }), "--keep-private 1.0.1.0.69 answers nothing here — 1.0.1.0.69’s words in this merge are already published in 1.0.1.0.64.1; answer --window 1.0.1.0.64.1 or --leave-out 1.0.1.0.64.1");
    assert_eq!(misfit_line(&Misfit::FitsNothing { flag: Flag::LeaveOut, key: origin.clone(), published_in: vec![] }), "--leave-out 1.0.1.0.69 answers nothing here — this merge asks nothing about 1.0.1.0.69’s words");
    assert_eq!(
        misfit_line(&Misfit::TwoAnswers {
            first: Flag::Window,
            second: Flag::LeaveOut,
            key: key.clone()
        }),
        "--window 1.0.1.0.64.1 and --leave-out 1.0.1.0.64.1 both answer the same words — give one"
    );
}
