//! T5 — THE SIDECAR's ANSWER: the six DATA lines exactly as the `skep`
//! command's own suite pins them parse to the claim, the dialed origin held;
//! each value — the claimant, the account, the principal and the origin —
//! the one a fresh alpha board names, one changed at a time refused naming
//! its line; the one line `claimed by 1.0.1` is the claimed board's; every
//! other shape is refused; each exit code maps to its failure; a value
//! carrying `<U+000A>` stays one line.

use super::*;

/// THE SIX LINES, as LITERALS: what `skep claim --board
/// http://127.0.0.1:8642 --hosted -` prints on a fresh board, line by line
/// as `skep-cli`'s `tests/it/cli.rs` pins them in its hosted-claim loop
/// (`out[0] == "claimant 1.0.1"`, `out[1] == "account 1.0.1"`, `out[2] ==
/// "principal 1"`, `out[3] == format!("origin {board}")`, `out[4]` and
/// `out[5]` by their `first act: ` and `second act: ` prefixes, `out.len()
/// == 6`) — the two acts written whole from `commands/claim.rs`'s format
/// strings with the dialed board in place.
const SIX: [&str; 6] = [
    "claimant 1.0.1",
    "account 1.0.1",
    "principal 1",
    "origin http://127.0.0.1:8642",
    "first act: from the device that generated the payload run `skep verify --board http://127.0.0.1:8642 --principal 1 --payload <the record it printed>` (or `--anchor <a> --anchor <b>`): the genesis record compared entry for entry, fingerprint and anchor flag, against what that device composed — it confirms the keys on the board, and it cannot tell you the board will open a session for you",
    "second act: in your first signed session the setup act runs — `skep claim --board <origin> --dir <store>` from that device performs it: creating your account also creates a space for your agents beneath it, and its home",
];

/// An exit-0 answer whose stdout is `lines`, each ended by `\n` as the
/// binary's `data` ends it.
fn answered(lines: &[&str]) -> Exit {
    Exit { code: Some(0), stdout: lines.iter().map(|l| format!("{l}\n")).collect::<String>().into_bytes(), stderr: Vec::new() }
}

/// The shape refusal, or a panic naming what was read instead.
fn shape(exit: &Exit) -> String {
    match read(exit) {
        Err(Failure::Shape(why)) => why,
        other => panic!("not a shape refusal: {other:?}"),
    }
}

/// T5: THE SIX LINES PARSE TO THE CLAIM, every value held — the dialed
/// origin among them — and the two acts whole; the last line's `\n` or its
/// absence alike.
#[test]
fn the_six_lines_parse_to_the_claim_with_the_dialed_origin_held() {
    let want = Claimed { claimant: "1.0.1".into(), account: "1.0.1".into(), principal: "1".into(), origin: "http://127.0.0.1:8642".into(), first_act: SIX[4].into(), second_act: SIX[5].into() };
    assert_eq!(read(&answered(&SIX)), Ok(Answer::Claimed(want.clone())));
    let unended = Exit { code: Some(0), stdout: SIX.join("\n").into_bytes(), stderr: b"payload entry: \xe2\x80\xa6\n".to_vec() };
    assert_eq!(read(&unended), Ok(Answer::Claimed(want)));
}

/// T5: `claimed by 1.0.1` ALONE is the claimed board's answer.
#[test]
fn claimed_by_alone_is_the_claimed_boards_answer() {
    assert_eq!(read(&answered(&["claimed by 1.0.1"])), Ok(Answer::AlreadyClaimed { claimant: "1.0.1".into() }));
}

/// T5: A SEVENTH LINE, A MISSING LINE, A SWAPPED LINE, a fifth or sixth line
/// without its prefix, a value other than the alpha's — each refused, never
/// read as a claim.
#[test]
fn every_other_shape_is_refused() {
    let mut seven = SIX.to_vec();
    seven.push("extra");
    assert!(shape(&answered(&seven)).contains("7 lines"));
    assert!(shape(&answered(&SIX[..5])).contains("5 lines"));
    let mut swapped = SIX.to_vec();
    swapped.swap(1, 2);
    assert!(shape(&answered(&swapped)).contains("line 2"));
    let mut no_prefix = SIX.to_vec();
    no_prefix[4] = &SIX[4]["first act: ".len()..];
    assert!(shape(&answered(&no_prefix)).contains("line 5"));
    let mut no_second = SIX.to_vec();
    no_second[5] = "the setup act";
    assert!(shape(&answered(&no_second)).contains("line 6"));
    let mut other_account = SIX.to_vec();
    other_account[0] = "claimant 1.0.2";
    assert!(shape(&answered(&other_account)).contains("another account"));
    let mut other_origin = SIX.to_vec();
    other_origin[3] = "origin https://alice.skep.host";
    assert!(shape(&answered(&other_origin)).contains("line 4"));
    assert!(shape(&answered(&[])).contains("lines"), "an empty stdout");
    assert!(shape(&Exit { code: Some(0), stdout: vec![0xff], stderr: Vec::new() }).contains("not text"));
}

/// T5: EACH VALUE IS THE ONE A FRESH ALPHA BOARD NAMES — the claimant, the
/// account and the principal the reply states as facts, and the origin
/// dialed: one line's value changed at a time, the read refuses it naming
/// the line, never reading a claim whose facts the reply would misstate.
#[test]
fn each_value_is_the_one_a_fresh_alpha_board_names() {
    for (at, changed, why) in [
        (0, "claimant 1.0.2", "lines 1 and 2 name another account than 1.0.1"),
        (1, "account 1.0.2", "lines 1 and 2 name another account than 1.0.1"),
        (2, "principal 2", "line 3 names another principal than 1"),
        (3, "origin http://127.0.0.1:8643", "line 4 names another origin than the one dialed, http://127.0.0.1:8642"),
    ] {
        let mut lines = SIX.to_vec();
        lines[at] = changed;
        assert_eq!(shape(&answered(&lines)), why, "{changed}");
    }
}

/// T5: EACH EXIT CODE maps to its named failure — 2 usage, 3 halt, 1 the
/// board's refusal, 4 transport — and any other code, or a signal, to
/// itself.
#[test]
fn each_exit_code_maps_to_its_failure() {
    let exit = |code| Exit { code, stdout: answered(&SIX).stdout, stderr: Vec::new() };
    assert_eq!(read(&exit(Some(2))), Err(Failure::Usage));
    assert_eq!(read(&exit(Some(3))), Err(Failure::Halt));
    assert_eq!(read(&exit(Some(1))), Err(Failure::Refused));
    assert_eq!(read(&exit(Some(4))), Err(Failure::Transport));
    assert_eq!(read(&exit(Some(125))), Err(Failure::OtherExit(Some(125))));
    assert_eq!(read(&exit(None)), Err(Failure::OtherExit(None)));
    let said: Vec<String> =
        [Failure::Usage, Failure::Halt, Failure::Refused, Failure::Transport, Failure::OtherExit(Some(125)), Failure::OtherExit(None), Failure::Shape("line 5 is not the first act".into())]
            .iter()
            .map(|failure| (failure as &dyn std::error::Error).to_string())
            .collect();
    assert_eq!(
        said,
        ["exit 2 (a usage refusal)", "exit 3 (a halt)", "exit 1 (the board refused)", "exit 4 (transport)", "exit 125", "ended by a signal", "exit 0 and line 5 is not the first act"],
        "each failure as the log says it"
    );
}

/// T5: A VALUE CARRYING `<U+000A>` STAYS ONE LINE: the binary renders a line
/// break inside a value as its code point, so it forges no line — in an act
/// it is the act's text, and in the claimant's place it is no claimant and
/// no `claimed by`.
#[test]
fn a_value_carrying_a_rendered_line_break_stays_one_line() {
    let mut carrying = SIX.to_vec();
    let act = format!("{}<U+000A>claimed by 9.9.9", SIX[4]);
    carrying[4] = &act;
    match read(&answered(&carrying)) {
        Ok(Answer::Claimed(c)) => assert!(c.first_act.ends_with("<U+000A>claimed by 9.9.9")),
        other => panic!("{other:?}"),
    }
    let mut forged = SIX.to_vec();
    forged[0] = "claimant 1.0.1<U+000A>claimed by 9.9.9";
    assert!(shape(&answered(&forged)).contains("another account"));
    assert!(shape(&answered(&["claimant 1.0.1<U+000A>account 1.0.1"])).contains("1 lines"));
}
