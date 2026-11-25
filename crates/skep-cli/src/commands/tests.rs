use super::*;

/// `retire`'s door, as `commands/retire.rs` names it.
const RETIRE: Door = Door { form: "retire", moments: "the preview's typed confirmation" };

#[test]
fn the_host_name_is_a_sources_first_line_cut_and_lowercased() {
    assert_eq!(host_name_of("Notebook.local\nsecond\n".into()).as_deref(), Some("notebook"));
    assert_eq!(host_name_of(" Notebook \n".into()).as_deref(), Some("notebook"));
    assert_eq!(host_name_of(".local\n".into()), None, "a name the cut leaves empty answers nothing, and the next source is asked");
    assert_eq!(host_name_of("  \n".into()), None, "an empty source answers nothing, and the next is asked");
    assert_eq!(host_name_of(String::new()), None);
    let BoxDefault { host_name: host, date } = host_name_and_date();
    assert!(!host.is_empty() && !host.contains('.') && host == host.to_lowercase(), "{host}");
    assert_eq!(civil_date(0), "1970-01-01");
    assert_eq!(date.len(), "yyyy-mm-dd".len(), "{date}");
}

/// Checks `civil_date` against the Gregorian calendar, day by day.
///
/// It names every day as the Gregorian calendar counts it — the date a
/// permanent byline's default carries (§4.2 step 2) — checked over
/// 100 000 days from the epoch, to 2243 (2000's leap day, and 2100's and
/// 2200's skipped), at each day's first and last second, against a
/// calendar counted day by day.
#[test]
fn civil_date_names_every_day_as_the_gregorian_calendar_counts_it() {
    let (mut y, mut m, mut d) = (1970u32, 1u32, 1u32);
    for day in 0..100_000u64 {
        let want = format!("{y:04}-{m:02}-{d:02}");
        assert_eq!(civil_date(day * 86_400), want, "the first second of day {day}");
        assert_eq!(civil_date(day * 86_400 + 86_399), want, "the last second of day {day}");
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let length = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m as usize - 1];
        d += 1;
        if d > length {
            (d, m) = (1, m + 1);
            if m > 12 {
                (m, y) = (1, y + 1);
            }
        }
    }
    assert_eq!((y, m, d), (2243, 10, 17), "the count reached past 2200: day 100 000 is 2243-10-17");
}

/// Checks that the commands' own stops answer §2.3's code.
///
/// The code comes from the one renderer: a person door without a
/// terminal a halt of the family, 3, and a label the record refuses a
/// halt, 3 — beside the stops `shared.rs` holds to their codes.
#[test]
fn the_commands_own_stops_finish_with_their_exit_codes() {
    assert_eq!(finish(Ok(())), 0);
    assert_eq!(finish(Err(no_terminal(RETIRE).into())), 3);
    assert_eq!(finish(Err(record_refused(LabelError::Newline).into())), 3);
}

/// Checks that a merge's session's end keeps its own face and code.
///
/// The library's `SessionEnded` comes to its face itself — the step the
/// death signal met, its cause, the way on — exit 3, at every step: never
/// the board's refusal, exit 1, and never with a step's words of what was
/// not done beside it, which a landing that stands makes false.
#[test]
fn a_merges_session_end_keeps_its_face_and_finishes_with_exit_three() {
    let face = Halt::face(
        "the session ended while linking the record",
        "the board answered `Skepd-Session: closed` (wire.md §Sessions)",
        "open a session again and resume: every step of the landing resumes by reading",
    );
    for step in [Step::Compose, Step::Publish, Step::Draft, Step::Undo, Step::Withdraw, Step::Restore] {
        let Stop::Halt(h) = refused(Refusal::SessionEnded(face.clone()), step) else { panic!("a halt") };
        assert_eq!(h, face, "the face itself, nothing of {:?} beside it", step.outcome());
    }
    assert_eq!(finish(Err(refused(Refusal::SessionEnded(face), Step::Publish))), 3);
}

/// Checks that a published journal is the board's refusal in the
/// command's words.
///
/// The refusal is exit 1 under `published_target` at every step a
/// journal is checked at, its detail the journal and why it takes no
/// record, what the step left undone, and the two ways on — never the
/// library's own fault.
#[test]
fn a_published_journal_is_the_boards_refusal_in_the_commands_words() {
    let journal = skep_client::address::parse_address("1.0.1.0.1").expect("an address");
    let steps = [(Step::Publish, "nothing was merged"), (Step::Draft, "nothing was merged"), (Step::Undo, "nothing was taken back"), (Step::Withdraw, "nothing was taken out")];
    for (step, undone) in steps {
        let Stop::Halt(Halt::Refused(r)) = refused(Refusal::PublishedJournal { journal: journal.clone() }, step) else { panic!("the board's refusal") };
        assert_eq!(r.code, "published_target");
        assert_eq!(
            r.detail.as_deref(),
            Some(format!("1.0.1.0.1 is published, and a merge record is kept only in a private document — {undone} and nothing was written. Name a private document of yours with --journal, or leave --journal out to use your private journal.").as_str())
        );
        assert_eq!(finish(Err(refused(Refusal::PublishedJournal { journal: journal.clone() }, step))), 1);
    }
}

/// Checks that a shot too large for one request is the board's refusal
/// `payload_too_large`, exit 1, its detail the library's words naming
/// the body's size and the most — never a halt of this library's own.
#[test]
fn a_shot_too_large_for_one_request_is_payload_too_large() {
    let refusal = Refusal::BodyOverBudget { bytes: 9 << 20, budget: 8 << 20 };
    let words = refusal.to_string();
    let Stop::Halt(Halt::Refused(r)) = refused(refusal.clone(), Step::Publish) else { panic!("the board's refusal") };
    assert_eq!((r.code.as_str(), r.detail.as_deref()), ("payload_too_large", Some(words.as_str())));
    assert!(words.contains("9437184 bytes") && words.contains("8388608"), "{words}");
    assert_eq!(finish(Err(refused(refusal, Step::Publish))), 1);
}

/// Checks that the refusals of a side and of its line of recorded bases
/// are the board's refusals under their own codes (skep #1113, #1107).
///
/// A fork of the document owner's own account is `fork_of_owner`, a hop
/// the board records no base for `hop_unrecorded`, a named base the
/// recorded bases do not derive `base_disagrees`, and a side begun
/// before the document's first version on a board serving no count of
/// its words before it `bare_source`, each exit 1, its detail the
/// library's own words.
#[test]
fn the_refusals_of_a_sides_line_are_the_boards_under_their_own_codes() {
    let a = |text: &str| skep_client::address::parse_address(text).expect("an address");
    let side = skep_client::merge::Side::Member(a("1.0.1.0.64.1.1"));
    for (refusal, code) in [
        (Refusal::ForkOfOwner { fork: a("1.0.1.0.66") }, "fork_of_owner"),
        (Refusal::HopUnrecorded { side: side.clone(), hop: a("1.0.1.0.64.1.1") }, "hop_unrecorded"),
        (Refusal::NamedBaseDisagrees { named: a("1.0.1.0.64.1"), served: a("1.0.1.0.64") }, "base_disagrees"),
        (Refusal::BareSource { side: side.clone(), source: a("1.0.1.0.64"), hop: Some(a("1.0.1.0.64.1.1")) }, "bare_source"),
    ] {
        let words = refusal.to_string();
        let Stop::Halt(Halt::Refused(r)) = refused(refusal.clone(), Step::Compose) else { panic!("the board's refusal") };
        assert_eq!((r.code.as_str(), r.detail.as_deref()), (code, Some(words.as_str())));
        assert_eq!(finish(Err(refused(refusal, Step::Compose))), 1);
    }
}

/// Checks that a window withheld is the board's refusal naming the words.
///
/// A write's run windowing a document the person may not read is
/// `withheld`, exit 1, its detail the library's words — the document and
/// the positions of its words in the state the write sends — with the
/// step's outcome beside them, at the restore and at the undo alike.
#[test]
fn a_window_withheld_is_the_boards_refusal_naming_the_words_and_the_steps_outcome() {
    let origin = skep_client::address::parse_address("1.0.2.0.65").expect("an address");
    let refusal = Refusal::WindowWithheld { origin, positions: vec![(4, 6), (20, 1)] };
    let words = refusal.to_string();
    assert!(words.contains("1.0.2.0.65") && words.contains("positions 4–9 and 20"), "{words}");
    for (step, outcome) in
        [(Step::Restore, "nothing was restored"), (Step::Undo, "nothing was taken back")]
    {
        let Stop::Halt(Halt::Refused(r)) = refused(refusal.clone(), step) else {
            panic!("the board's refusal")
        };
        assert_eq!(
            (r.code.as_str(), r.detail),
            ("withheld", Some(format!("{words}; {outcome}")))
        );
        assert_eq!(finish(Err(refused(refusal.clone(), step))), 1);
    }
}

/// Checks that a window withheld in the text the line rule reads is the
/// board's refusal naming the window, its place and the ways on.
///
/// The composition's `LineTextWithheld` is `withheld`, exit 1, its detail
/// the library's words — the document, the two additions' anchors or the
/// document's edge, the line rule read whatever the switches, a share of
/// the document or its words published — with "nothing was composed"
/// beside them, the composition the one step that meets it (skep #1174).
#[test]
fn a_line_text_withheld_is_the_boards_refusal_naming_the_window_its_place_and_the_ways_on() {
    let a = |text: &str| skep_client::address::parse_address(text).expect("an address");
    for (after, before, place) in [
        (None, Some(a("1.0.1.0.64.0.1.1")), "the first at the document's start, the second before 1.0.1.0.64.0.1.1"),
        (Some(a("1.0.1.0.64.0.1.3")), None, "the first after 1.0.1.0.64.0.1.3, the second at its end"),
    ] {
        let refusal = Refusal::LineTextWithheld { doc: a("1.0.1.3.0.64"), after, before };
        let words = refusal.to_string();
        for said in ["1.0.1.3.0.64 is not readable to this reader (withheld)", place, "whatever its switches", "at a line's edge", "once 1.0.1.3.0.64 is shared with this reader or its words are published"] {
            assert!(words.contains(said), "the detail says {said:?}: {words}");
        }
        let Stop::Halt(Halt::Refused(r)) = refused(refusal.clone(), Step::Compose) else { panic!("the board's refusal") };
        assert_eq!((r.code.as_str(), r.detail), ("withheld", Some(format!("{words}; nothing was composed"))));
        assert_eq!(finish(Err(refused(refusal, Step::Compose))), 1);
    }
}

/// Checks that a landing begun is the board's refusal naming its draft.
///
/// A `--new` landing that found the merge landed in a draft of the
/// merger's with no record is `landing_begun`, exit 1, its detail the
/// library's own words: the draft, the position, and the command's
/// `--into` and `--undo` naming the draft (skep #1103).
#[test]
fn a_landing_begun_is_the_boards_refusal_naming_the_draft_and_the_ways_on() {
    let draft = skep_client::address::parse_address("1.0.1.0.72").expect("an address");
    let refusal = Refusal::LandingBegun { draft, position: 21 };
    let words = refusal.to_string();
    let Stop::Halt(Halt::Refused(r)) = refused(refusal.clone(), Step::Draft) else { panic!("the board's refusal") };
    assert_eq!((r.code.as_str(), r.detail.as_deref()), ("landing_begun", Some(words.as_str())));
    for said in ["1.0.1.0.72 at position 21", "--into 1.0.1.0.72", "--undo 1.0.1.0.72"] {
        assert!(words.contains(said), "the detail says {said:?}: {words}");
    }
    assert_eq!(finish(Err(refused(refusal, Step::Draft))), 1);
}

/// Checks that a side that moved is the board's refusal naming the side.
///
/// A side that changed while the composition read it, or after the
/// position it stands at, is `side_moved`, exit 1, its detail the
/// library's own words: the side, that nothing was merged, and that the
/// merge is run again (skep #1144).
#[test]
fn a_side_moved_is_the_boards_refusal_naming_the_side_and_the_way_on() {
    let side = skep_client::address::parse_address("1.0.1.0.66").expect("an address");
    let refusal = Refusal::SideMoved { side, at: 13, before: Some(13), after: Some(14) };
    let words = refusal.to_string();
    let Stop::Halt(Halt::Refused(r)) = refused(refusal.clone(), Step::Draft) else { panic!("the board's refusal") };
    assert_eq!((r.code.as_str(), r.detail.as_deref()), ("side_moved", Some(words.as_str())));
    for said in ["1.0.1.0.66 changed while this merge was reading it", "nothing was merged", "compose the merge again"] {
        assert!(words.contains(said), "the detail says {said:?}: {words}");
    }
    assert_eq!(finish(Err(refused(refusal, Step::Draft))), 1);
}

/// Checks that a person door's refusal is a halt naming its own moments.
///
/// The refusal is a halt's face — the state, its cause, the one act —
/// naming the moments a person answers at that door, and the backup
/// moment only where the door runs one.
#[test]
fn a_person_door_without_a_terminal_is_a_halt_naming_its_own_moments() {
    let Halt::Halt(face) = no_terminal(RETIRE) else { panic!("a HALT AND SURFACE member") };
    assert_eq!(face.state, "`retire` is a person door and requires a controlling terminal");
    assert!(face.cause.contains("what a person answers here — the preview's typed confirmation —"), "{}", face.cause);
    assert!(!face.cause.contains("backup moment"), "retire runs no backup moment: {}", face.cause);
    assert!(face.act.contains("scripted Person in-process"), "{}", face.act);
}
