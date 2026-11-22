//! The session's end over the scripted board.
//!
//! The suite checks that a death at any request under the token is the
//! typed session end, and that each way on says what the act it stopped
//! leaves.

use super::*;

/// The way on each death of an act's walk must name.
#[derive(Clone, Copy)]
enum Ends {
    /// Every death under the token names this one.
    Alike(OnEnd),
    /// A take-back's: the act run again up to and at its one write,
    /// `set_arrangement`, and the act standing with its record unwritten
    /// after it, this way on.
    TakeBack(OnEnd),
}

/// What the deaths staged over one act answered: how many ended the
/// session, and how many were a token-free read's, the board's fault.
struct Deaths {
    ended: usize,
    faulted: usize,
}

/// Stages the session's death at every request of an act (skep #812).
///
/// The act is run once whole over a fresh `world`, its `setup` made
/// first, and its requests numbered; then once per request, over a
/// fresh world and setup, the session dying before that request is
/// answered, and nothing is asked past it. One presenting the token must
/// answer `Refusal::SessionEnded`, its face naming the session's end and
/// the way on `ends` names — never another refusal, an absence or an
/// answer; a token-free one, `H.1`'s read, the board's fault
/// (`guest_closed`), never a session's end. `/health` reads no header,
/// so no death is staged at it.
fn deaths_of<S>(
    cell: &str,
    world: fn() -> World,
    setup: impl Fn(&Scripted, &Board, &Session<'_>, &HybridSigner) -> S,
    act: impl Fn(&Board, &Session<'_>, &HybridSigner, &S) -> Result<(), Refusal>,
    ends: Ends,
) -> Deaths {
    let run = |die_at: Option<usize>| {
        let (dialer, board, signer) = open(world());
        let session = sign_in(&board, &signer);
        let made = setup(&dialer, &board, &session, &signer);
        dialer.clear();
        dialer.world().die_at = die_at;
        let answer = act(&board, &session, &signer, &made);
        (answer, dialer.requests())
    };
    let (whole, requests) = run(None);
    assert_eq!(whole, Ok(()), "{cell}: the premise, the act whole");
    let write = requests.iter().position(|(line, _)| line == "set_arrangement");
    let mut deaths = Deaths { ended: 0, faulted: 0 };
    for (k, (line, presented)) in requests.iter().enumerate() {
        if line == "GET /health" {
            continue;
        }
        let n = k + 1;
        let (answer, asked) = run(Some(n));
        assert_eq!(
            asked.len(),
            n,
            "{cell}: nothing asked past the death signal at {line} (#{n}): {:?}",
            &asked[n.min(asked.len())..]
        );
        if !presented {
            assert_eq!(
                answer,
                Err(Refusal::Halt(guest_closed())),
                "{cell}: the signal at the token-free {line} (#{n}) is the board's fault"
            );
            deaths.faulted += 1;
            continue;
        }
        let on_end = match ends {
            Ends::Alike(on_end) => on_end,
            Ends::TakeBack(after) if write.is_some_and(|w| k > w) => after,
            Ends::TakeBack(_) => OnEnd::Rerun,
        };
        let Err(Refusal::SessionEnded(Halt::Halt(face))) = &answer else {
            panic!("{cell}: the death signal at {line} (#{n}) answered {answer:?}");
        };
        assert!(
            face.state.contains("the session ended while")
                && face.cause.contains("Skepd-Session: closed"),
            "{cell}: at {line} (#{n}): {face:?}"
        );
        assert_eq!(face.act, on_end.act(), "{cell}: the way on at {line} (#{n})");
        deaths.ended += 1;
    }
    assert!(deaths.ended + deaths.faulted > 0, "{cell}: the premise, a death staged");
    deaths
}

fn nothing(_: &Scripted, _: &Board, _: &Session<'_>, _: &HybridSigner) {}

fn race_composed(
    _: &Scripted,
    board: &Board,
    session: &Session<'_>,
    _: &HybridSigner,
) -> Merged {
    compose(board, Some(session.token()), &race_inputs()).expect("composed")
}

fn draft_composed(
    _: &Scripted,
    board: &Board,
    session: &Session<'_>,
    _: &HybridSigner,
) -> Merged {
    compose(board, Some(session.token()), &draft_inputs()).expect("composed")
}

/// The race shape landed by a shot, its record written.
fn race_landed(
    dialer: &Scripted,
    board: &Board,
    session: &Session<'_>,
    signer: &HybridSigner,
) -> Merged {
    let merged = race_composed(dialer, board, session, signer);
    land(board, &merged, shot(session, signer)).expect("landed");
    merged
}

fn landed_in_draft(_: &Scripted, board: &Board, session: &Session<'_>, signer: &HybridSigner) {
    landed_in_s(board, session, signer);
}

/// A death at any request under the token is the typed session end.
///
/// Skep #812: the death signal staged at each request of each act —
/// `compose`, with no record and with one standing for the key; the
/// shot, a draft landing named and a fresh one, and one found standing,
/// its draft read as it stands (skep #980); `resume` after a lost
/// acknowledgment; `record_published`; the undo by its marker and by a
/// baseless draft's feed row; the withdrawal; the undo over an earlier
/// landing, its marker put back; `verify`; `current`; `head_of`;
/// `journal::of` minting and finding — answers `Refusal::SessionEnded`
/// with the act's way on: a landing resumed, every other act run again,
/// a take-back past its one write standing with its record unwritten,
/// the earlier landing's merge back in the draft where its marker was
/// put back (skep #964). A record lookup's read is no absence: a
/// composition the signal meets at its prior records' journal reads
/// ends, never composes with no record standing (SP-14). `H.1`'s
/// token-free read, and every read of a composition made as a guest,
/// meets the signal as the board's fault, never as a session's end.
#[test]
fn a_death_at_any_request_under_the_token_is_the_typed_session_end() {
    let resume_on = Ends::Alike(OnEnd::Resume);
    let rerun = Ends::Alike(OnEnd::Rerun);
    let composing = deaths_of(
        "compose",
        World::race,
        nothing,
        |board, session, _, _| compose(board, Some(session.token()), &race_inputs()).map(drop),
        rerun,
    );
    assert!(
        composing.ended > 0 && composing.faulted == 0,
        "compose: the premise, its reads under the token"
    );
    let prior = deaths_of(
        "compose over a standing record",
        World::race,
        race_landed,
        |board, session, _, _| {
            compose(board, Some(session.token()), &race_inputs()).map(|m| assert!(m.prior.is_some(), "the record stands: a composition answering none read a failure as an absence"))
        },
        rerun,
    );
    assert!(
        prior.ended > composing.ended,
        "the prior records' journal read: {} deaths past compose's {}",
        prior.ended,
        composing.ended
    );
    let guest = deaths_of(
        "compose as a guest",
        World::race,
        nothing,
        |board, _, _, _| compose(board, None, &race_inputs()).map(drop),
        rerun,
    );
    assert!(
        guest.ended == 0 && guest.faulted > 0,
        "a guest's every read is token-free: no session stood to end"
    );
    let shot_landing = deaths_of(
        "the shot",
        World::race,
        race_composed,
        |board, session, signer, merged| land(board, merged, shot(session, signer)).map(drop),
        resume_on,
    );
    assert_eq!(shot_landing.faulted, 1, "the head's read, before the first write");
    for (cell, into) in [("a draft landing named", Some(a(S))), ("a fresh draft landing", None)]
    {
        let landing = deaths_of(
            cell,
            draft_landing_world,
            draft_composed,
            |board, session, signer, merged| {
                land(board, merged, draft_landing(session, signer, into.clone())).map(drop)
            },
            resume_on,
        );
        assert!(
            landing.ended > 0 && landing.faulted == 0,
            "{cell}: every request under the token, no head read"
        );
    }
    let standing = deaths_of(
        "a fresh landing found standing",
        draft_landing_world,
        |_: &Scripted, board: &Board, session: &Session<'_>, signer: &HybridSigner| {
            landed_in_s(board, session, signer).0
        },
        |board, session, signer, merged| {
            land(board, merged, draft_landing(session, signer, None)).map(|l| {
                assert!(matches!(l, Landed::Draft { staged: false, .. }), "the premise: {l:?}")
            })
        },
        resume_on,
    );
    assert!(
        standing.ended > 0 && standing.faulted == 0,
        "a fresh landing found standing: the record's reads and its draft's, no head read"
    );
    let lost =
        |dialer: &Scripted, board: &Board, session: &Session<'_>, signer: &HybridSigner| {
            let merged = race_composed(dialer, board, session, signer);
            dialer.world().drop_acks = 2;
            assert!(
                matches!(
                    land(board, &merged, shot(session, signer)),
                    Err(Refusal::Halt(Halt::Dial(_)))
                ),
                "the premise: the ack lost"
            );
            merged
        };
    deaths_of(
        "resume",
        World::race,
        lost,
        |board, session, signer, merged| {
            resume(board, merged, shot(session, signer)).map(|l| {
                assert!(
                    matches!(l, Some(Landed::Member { .. })),
                    "the premise: the member found"
                )
            })
        },
        resume_on,
    );
    let published =
        |dialer: &Scripted, board: &Board, session: &Session<'_>, signer: &HybridSigner| {
            let merged = race_composed(dialer, board, session, signer);
            let mut w = dialer.world();
            w.text(D, 16, "!");
            w.member(
                &format!("{D}.3"),
                vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 3), run(D, 16, 1)],
                Some(15),
            );
            w.trunk_head.insert(D.to_string(), format!("{D}.3"));
            w.claims.push(ClaimRow {
                claim: format!("{D}.0.2.1"),
                home: D.into(),
                old: format!("{D}.1.1"),
                new: format!("{D}.3"),
            });
            (merged, a(&format!("{D}.3")), w.position)
        };
    let recording = deaths_of(
        "record_published",
        World::race,
        published,
        |board, session, signer, (merged, member, at)| {
            record_published(board, merged, merger(session, signer), member, *at, None, &[])
                .map(drop)
        },
        rerun,
    );
    assert_eq!(recording.faulted, 0, "no head read: the record signs nothing");
    let undo_s = |board: &Board, session: &Session<'_>, signer: &HybridSigner, _: &()| {
        undo(board, merger(session, signer), &a(S), &a(K), None, None).map(drop)
    };
    let undoing = deaths_of(
        "the undo by its marker",
        draft_landing_world,
        landed_in_draft,
        undo_s,
        Ends::TakeBack(OnEnd::TakenOut),
    );
    assert!(undoing.ended > 0 && undoing.faulted == 0, "no head read: the undo signs nothing");
    const PLAIN: &str = "1.0.1.0.67";
    let baseless = || {
        let mut w = draft_landing_world();
        w.doc(PLAIN, false, ACCOUNT, vec![run(D, 1, 11)]);
        w
    };
    let landed_plain =
        |dialer: &Scripted, board: &Board, session: &Session<'_>, signer: &HybridSigner| {
            let merged = draft_composed(dialer, board, session, signer);
            land(board, &merged, draft_landing(session, signer, Some(a(PLAIN))))
                .expect("landed");
        };
    deaths_of(
        "the undo by a feed row",
        baseless,
        landed_plain,
        |board, session, signer, _| {
            undo(board, merger(session, signer), &a(PLAIN), &a(K), None, None).map(drop)
        },
        Ends::TakeBack(OnEnd::TakenOut),
    );
    deaths_of(
        "the withdrawal",
        draft_landing_world,
        landed_in_draft,
        |board, session, signer, _| {
            withdraw(board, merger(session, signer), &a(S), &a(K), None).map(drop)
        },
        Ends::TakeBack(OnEnd::TakenOut),
    );
    // A merge landed over another, both recorded: the undo puts the
    // first one's marker back and replaces the second's record.
    const OVER: &str = "1.0.1.0.67";
    let two_drafts = || {
        let mut w = World::race();
        w.doc(OVER, false, ACCOUNT, vec![run(D, 1, 11)]);
        w.staged(OVER, &format!("{D}.1"), 11);
        w
    };
    let landed_twice =
        |_: &Scripted, board: &Board, session: &Session<'_>, signer: &HybridSigner| {
            let into = || draft_landing(session, signer, Some(a(OVER)));
            let first =
                compose(board, Some(session.token()), &race_inputs()).expect("composed");
            land(board, &first, into()).expect("landed");
            let over = Inputs {
                sides: vec![Side::Draft { at: a(OVER), position: None }],
                ..race_inputs()
            };
            let over = compose(board, Some(session.token()), &over).expect("composed over it");
            land(board, &over, into()).expect("landed over it");
        };
    let earlier = deaths_of(
        "the undo over an earlier landing",
        two_drafts,
        landed_twice,
        |board, session, signer, _| {
            undo(board, merger(session, signer), &a(OVER), &a(K), None, None).map(|u| {
                assert!(u.marker.is_some() && u.record.is_some(), "the premise: {u:?}")
            })
        },
        Ends::TakeBack(OnEnd::EarlierBack),
    );
    assert!(
        earlier.ended > undoing.ended,
        "the feed walk and the record's writes past the plain undo's"
    );
    let recorded =
        |dialer: &Scripted, board: &Board, session: &Session<'_>, signer: &HybridSigner| {
            let merged = race_landed(dialer, board, session, signer);
            current(board, Some(session.token()), &a(K), &merged.key)
                .expect("the lookup")
                .expect("the record")
        };
    deaths_of(
        "verify",
        World::race,
        recorded,
        |board, session, _, record| {
            verify(board, Some(session.token()), record)
                .map(|v| assert_eq!(v, Verdict::Equal, "the premise"))
        },
        rerun,
    );
    deaths_of(
        "current",
        World::race,
        race_landed,
        |board, session, _, merged| {
            current(board, Some(session.token()), &a(K), &merged.key).map(|r| {
                assert!(
                    r.is_some(),
                    "the record stands: a lookup answering none read a failure as an absence"
                )
            })
        },
        rerun,
    );
    deaths_of(
        "head_of",
        World::race,
        nothing,
        |board, session, _, _| {
            head_of(board, Some(session.token()), &a(D))
                .map(|h| assert_eq!(h, Some(a(&format!("{D}.2"))), "the premise"))
        },
        rerun,
    );
    deaths_of(
        "journal::of minting",
        World::race,
        nothing,
        |board, session, signer, _| {
            journal::of(board, &merger(session, signer), &a(K), None).map(drop)
        },
        rerun,
    );
    let filed =
        |dialer: &Scripted, board: &Board, session: &Session<'_>, signer: &HybridSigner| {
            let record = race_composed(dialer, board, session, signer).record;
            let mut w = dialer.world();
            w.doc("1.0.1.0.68", false, ACCOUNT, Vec::new());
            file(&mut w, "1.0.1.0.68", &record, &[&format!("{D}.1.1")], None);
        };
    let finding = deaths_of(
        "journal::of finding",
        World::race,
        filed,
        |board, session, signer, _| {
            journal::of(board, &merger(session, signer), &a(K), None)
                .map(|j| assert_eq!(j, a("1.0.1.0.68"), "the premise"))
        },
        rerun,
    );
    assert_eq!(
        finding.ended, 3,
        "the find, the record's link and the journal's `doc_metadata`"
    );
}

/// The ways on say what each act leaves: a landing resumed, every other
/// act run again reading first, a take-back's write standing with
/// nothing more written — the words a take-back's owed record says too —
/// and, where an undo put an earlier landing's marker back, that a re-run
/// takes that merge back too (skep #964).
#[test]
fn each_way_on_says_what_the_act_it_stopped_leaves() {
    let [rerun, resume, taken_out] =
        [OnEnd::Rerun, OnEnd::Resume, OnEnd::TakenOut].map(OnEnd::act);
    assert!(rerun.contains("run this again") && !rerun.contains("resume"), "{rerun}");
    assert!(resume.contains("resume"), "{resume}");
    assert!(
        taken_out.starts_with("nothing more is written")
            && taken_out.contains("a re-run writes no record"),
        "{taken_out}"
    );
    let earlier_back = OnEnd::EarlierBack.act();
    assert!(
        earlier_back.starts_with("nothing more is written")
            && earlier_back.contains("a re-run takes that merge back too"),
        "{earlier_back}"
    );
    let Refusal::SessionEnded(Halt::Halt(face)) =
        session_ended("linking the record", OnEnd::EarlierBack)
    else {
        panic!("the arm")
    };
    assert_eq!(face.state, "the merge is out of the draft, the merge landed before it standing again, and its record is not written: the session ended while linking the record");
    let Refusal::SessionEnded(Halt::Halt(face)) =
        session_ended("linking the record", OnEnd::TakenOut)
    else {
        panic!("the arm")
    };
    assert_eq!(face.state, "the merge is out of the draft, and its record is not written: the session ended while linking the record");
    assert_eq!(
        Refusal::SessionEnded(Halt::Halt(face.clone())).to_string(),
        face.to_string(),
        "the arm says its face"
    );
}
