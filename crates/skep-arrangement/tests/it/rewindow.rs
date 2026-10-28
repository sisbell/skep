//! THE IN-TRANSACTION RE-WINDOW OF THE DRAFT AT ITS KEPT PLACES, CHECKED BY
//! IDENTITY — the link-sets design's first gate (§5.7; the lane S site
//! survey's S-gate), proved in M5 alone. The design's words: "at commit the
//! daemon checks that `D` still arranges that run's I-span at that place
//! (M5's I→V projection, `M5State::project(doc, coverage)` …) and replaces it
//! THERE by the member's run it became: a `reinstate` of the fresh I-run at
//! the run's place and a `delete` of the draft-native run, staged in the same
//! commit and applied in turn so positions stay true, a piece of a run by the
//! same piece of the fresh run at its offset, at cost `#runs(D) × |coverage|`;
//! where the check fails — `D` moved the run, split it, deleted it or
//! arranged it elsewhere since P4 — the request is REFUSED … never a guess";
//! and §5.7's ONE COMMIT: "ONE `publish` request and ONE transaction, which
//! either stands whole or not at all".
//!
//! What is composed is ONE `Kernel::transact` over the union of the three
//! stagings' keys, its closure `stage_publish` (the member), the pairing of
//! the shot's draft-native run with the fresh run it became (the member's
//! run of the same index, read off the working M5), the check by identity
//! (`project` on `stg.working()` against the kept place the client read
//! before the transaction), `stage_reinstate_at` at that place and
//! `stage_delete_at` at the draft-native run's position re-derived AFTER the
//! placement — the composite the public ops cannot make, each opening a
//! transaction of its own and M2 refusing a nested one. The kept place is a
//! value the test holds; the request member that will carry it, the token
//! a failed check refuses with and the daemon's check are the lane's later
//! steps, and nothing here is on the wire.
//!
//! What a transaction's records do after a crash — replayed whole or not at
//! all — is M2's promise and not M5's to re-prove: `recovery.rs`
//! (`the_arrangement_survives_durable_recovery_by_checkpoint_and_replay`)
//! replays a shot among every other record kind through checkpoint and
//! tail, so this suite stages, commits and reads, and nothing more. SP-21 is
//! kept as it stands: the re-window removes the draft-native run by a
//! `ContentRemove`, and R keeps the address it removed.

use skep_address::{Address, SpanSet};
use skep_arrangement::{
    head_lock_key, stage_delete_at, stage_publish, stage_reinstate_at, trunk_head, trunk_of,
    DeleteError, Deposit, HasM5, PublishError, ReinstateError, Run, Shot, ShotRun, Vstream,
};
use skep_content::HasContent;
use skep_kernel::{Kernel, Seq, TxnError};
use skep_namespace::{HasM3, M3State, PrincipalId};
use tempfile::tempdir;

use crate::common::*;

/// The composite's refusal: one of the three stagings' own, or the check by
/// identity failing — `D` no longer arranges the run's I-span at the kept
/// place. Test-local: the token the lane refuses with on the wire is S2's.
#[derive(Debug)]
enum Refused {
    Publish(PublishError),
    Reinstate(ReinstateError),
    Delete(DeleteError),
    /// `project(D, the run's I-span)` on the working world is not the kept
    /// place: `D` moved the run, split it, deleted it or arranged it
    /// elsewhere since the place was read.
    Moved {
        kept: SpanSet,
        now: SpanSet,
    },
}

impl From<PublishError> for Refused {
    fn from(e: PublishError) -> Refused {
        Refused::Publish(e)
    }
}
impl From<ReinstateError> for Refused {
    fn from(e: ReinstateError) -> Refused {
        Refused::Reinstate(e)
    }
}
impl From<DeleteError> for Refused {
    fn from(e: DeleteError) -> Refused {
        Refused::Delete(e)
    }
}

/// THE COMPOSITE the gate proves, in M5's own primitives and nothing else:
/// one transaction over the union of the three stagings' keys — the shot's
/// (`head_lock_key`, the edition's `content_lock_key`; no base, so no base
/// key) and the draft's `content_lock_key` — whose closure (i) stages the
/// shot of `shot`'s one draft-native run from `draft` into `pdoc()`, (ii)
/// pairs that run with the fresh run it became, the member's run of the same
/// index (0) read off the working M5, (iii) checks by identity that `draft`
/// still arranges the run's I-span at `kept`, exactly, (iv) stages the fresh
/// run's placement at that place and (v) re-derives the draft-native run's
/// position off the working world — it moved by the fresh run's width — and
/// stages its removal there. Returns the member and the one commit's `Seq`;
/// an `Err` at any step commits nothing.
fn rewindow(
    k: &Kernel<World>,
    draft: &Address,
    shot: &Shot,
    kept: &SpanSet,
) -> Result<(Address, Seq), TxnError<Refused>> {
    let doc = pdoc();
    assert_eq!(shot.runs.len(), 1, "the gate's shots name one draft-native run");
    let run = &shot.runs[0].run;
    let coverage = coverage_of(run);
    let keys = [
        head_lock_key(&doc),
        M3State::content_lock_key(&trunk_of(&doc)),
        M3State::content_lock_key(draft),
    ];
    let readable = readable_by(PrincipalId(1));
    k.transact(&keys, |stg| {
        // (i) The member, the shot's fresh identity minted under the
        // edition's own content chain.
        let member = stage_publish(stg, P1, &doc, shot, &readable)?;
        // (ii) The fresh run the draft-native run became: the member's run
        // at the shot run's index, off the working M5.
        let fresh = stg
            .working()
            .m5()
            .content_runs(&member)
            .next()
            .cloned()
            .expect("the member arranges the run the shot placed");
        // (iii) The check by identity, against the place the client read:
        // one V-span, the run's width, at the place — exactly.
        let now = stg.working().m5().project(draft, &coverage);
        if now != *kept {
            return Err(Refused::Moved { kept: kept.clone(), now });
        }
        // (iv) The fresh I-run at the run's place.
        let placed = [ShotRun { origin: trunk_of(&doc), run: fresh }];
        stage_reinstate_at(stg, P1, draft, place_of(kept), &placed)?;
        // (v) The draft-native run, where the placement left it — read off
        // the working world, never carried over from before it.
        let after = stg.working().m5().project(draft, &coverage);
        stage_delete_at(stg, P1, draft, place_of(&after), run.width().clone())?;
        Ok(member)
    })
}

/// A shot of `D`'s one run `[start, start + width)` into the edition, the
/// birth shape, from the draft `D`.
fn shot_of(draft: &Address, start: &Address, width: u32) -> Shot {
    Shot { base: None, draft: Some(draft.clone()), runs: vec![shot_run(draft, start, width)] }
}

/// SAME COMMIT, CHECKED BY IDENTITY. The invariant, §5.7's: the member minted
/// and `D` re-windowed at its kept place are ONE transaction, "which either
/// stands whole or not at all", the fresh run placed "THERE" — at the place
/// the client read — "a piece of a run by the same piece of the fresh run at
/// its offset". A draft `D` holding a, b, c (one insert of three one-byte
/// values: M5 lists them as ONE run, b a strict piece of it); the shot names
/// b; the kept place is b's V-position in `D`, read by `project` BEFORE the
/// transaction (the client's P4 reading). After the one commit, on ONE
/// snapshot: `D` reads the same at every position; its run at the place IS
/// the member's fresh I-run, the draft-native one arranged nowhere in `D`;
/// the member reads the shot's bytes; and exactly one commit boundary stands
/// above the position before the act. Journaled, so the boundaries can be
/// read back.
#[test]
fn a_shots_fresh_run_replaces_the_drafts_run_at_its_kept_place_in_the_same_commit() {
    let dir = tempdir().expect("tempdir");
    let k = Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("open");
    insert_abc(&k);
    let b = Run::new(ca(2), n(1)).expect("b's I-run");
    let before = k.snapshot();
    assert_eq!(
        content_runs_of(&before, &doc1()),
        vec![Run::new(ca(1), n(3)).expect("one run")],
        "the premise: M5 lists a, b, c as one run, b a strict piece of it"
    );
    let bytes_before = bytes_of(&before, &doc1());
    assert_eq!(bytes_before, vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    // The client's P4 reading: where `D` arranges b — one V-span of b's
    // width, at content ordinal 2.
    let kept = before.world().m5().project(&doc1(), &coverage_of(&b));
    assert_eq!(kept, SpanSet::singleton(vspan(1, 2, 1)));
    assert_eq!(place_of(&kept), vp(1, 2));

    let (member, seq) = rewindow(&k, &doc1(), &shot_of(&doc1(), &ca(2), 1), &kept)
        .expect("the one commit stands whole");
    assert_eq!(member, vdoc(), "the edition's first member");

    let s = k.snapshot();
    let m5 = s.world().m5();
    // One commit: the `Seq` the one transaction answered is the head, and
    // it is the only boundary above the position before the act.
    assert_eq!(s.seq(), seq);
    assert_eq!(
        k.boundaries_above(before.seq()).expect("a journaled kernel answers its boundaries"),
        vec![(seq, None)],
        "exactly one commit position was taken"
    );
    // `D` reads the same at every position…
    assert_eq!(bytes_of(&s, &doc1()), bytes_before, "D's bytes are what they were");
    // …and its run at the place IS the member's fresh I-run: the draft's
    // piece replaced by the same piece of the fresh run, the rest of the run
    // untouched at its own addresses.
    let fresh = Run::new(pca(1), n(1)).expect("the fresh run, the edition's first content address");
    assert_eq!(m5.content_runs(&member).cloned().collect::<Vec<_>>(), vec![fresh.clone()]);
    assert_eq!(
        content_runs_of(&s, &doc1()),
        vec![Run::new(ca(1), n(1)).expect("a"), fresh.clone(), Run::new(ca(3), n(1)).expect("c")],
        "D's run at the place is the fresh I-run, not the draft-native one"
    );
    assert!(
        m5.project(&doc1(), &coverage_of(&b)).is_empty(),
        "the draft-native run is arranged nowhere in D"
    );
    assert_eq!(
        m5.project(&doc1(), &coverage_of(&fresh)),
        kept,
        "the fresh run holds the kept place"
    );
    assert_eq!(bytes_of(&s, &member), vec![b"b".to_vec()], "the member reads the shot's bytes");
    // SP-21: the removed address stays in R, as every delete leaves it.
    let d = m5.deletions(&doc1());
    assert_eq!(
        d.iter().map(|span| span.start().clone()).collect::<Vec<_>>(),
        vec![ca(2).tumbler().clone()]
    );
    assert_eq!(m5.content_count(&doc1()), n(3));
    assert_eq!(trunk_head(s.world().m3(), &pdoc()), Some(member));
}

/// What `D` did to the named run between the kept place's reading and the
/// commit — "`D` moved the run, split it, deleted it or arranged it
/// elsewhere since P4" — and the footprint the check finds instead.
struct Since {
    what: &'static str,
    /// The named run: `[ca(start), start + width)` of the one run a, b, c.
    start: u32,
    width: u32,
    /// The edit `D` takes after the place is read.
    disturb: fn(&Vstream<'_, World>),
    /// Where `D` arranges the named span afterwards.
    now: fn() -> SpanSet,
}

/// REFUSED, NOTHING WRITTEN. The invariant, §5.7's: "where the check fails —
/// `D` moved the run, split it, deleted it or arranged it elsewhere since P4
/// — the request is REFUSED … never a guess", and the one transaction
/// "either stands whole or not at all": the shot's mints and placement are
/// staged before the check, and the refusal discards them with it. Three
/// cells: b moved (a rearrangement puts it first); the named span split (an
/// insert inside `b c` — a one-position run cannot be split, so this cell
/// names two); b deleted. In each the closure refuses at the check, with the
/// kept place and the footprint found; afterwards no member is minted, the
/// edition has no head, `D` is what the disturbance left at every position
/// and in every run, no fresh identity was written, and the kernel's `Seq`
/// is unchanged.
#[test]
fn a_run_moved_split_or_deleted_since_the_place_was_read_refuses_and_nothing_is_written() {
    let cells = [
        Since {
            what: "moved",
            start: 2,
            width: 1,
            disturb: |vs| {
                vs.rearrange(P1, &doc1(), &[vp(1, 1), vp(1, 2), vp(1, 3)])
                    .expect("a | b → b a: b first");
            },
            now: || SpanSet::singleton(vspan(1, 1, 1)),
        },
        Since {
            what: "split",
            start: 2,
            width: 2,
            disturb: |vs| {
                vs.insert(P1, &doc1(), vp(1, 3), vec![val(b"x")], Deposit::Undeclared)
                    .expect("a b x c: x inside the named b c");
            },
            now: || [vspan(1, 2, 1), vspan(1, 4, 1)].into_iter().collect(),
        },
        Since {
            what: "deleted",
            start: 2,
            width: 1,
            disturb: |vs| {
                vs.delete(P1, &doc1(), vp(1, 2), n(1)).expect("a c: b gone");
            },
            now: SpanSet::empty,
        },
    ];
    for cell in cells {
        let k = mem_kernel();
        let vs = insert_abc(&k);
        let named = Run::new(ca(cell.start), n(cell.width)).expect("the named run");
        let kept = k.snapshot().world().m5().project(&doc1(), &coverage_of(&named));
        assert_eq!(kept, SpanSet::singleton(vspan(1, cell.start, cell.width)), "{}", cell.what);
        (cell.disturb)(&vs);
        let disturbed = k.snapshot();
        let runs_before = content_runs_of(&disturbed, &doc1());
        let bytes_before = bytes_of(&disturbed, &doc1());
        let stored_before = disturbed.world().content().len();

        let refused =
            rejected(rewindow(&k, &doc1(), &shot_of(&doc1(), &ca(cell.start), cell.width), &kept));
        let (said, now) = match refused {
            Refused::Moved { kept, now } => (kept, now),
            Refused::Publish(e) => panic!("{}: the shot itself refused: {e:?}", cell.what),
            Refused::Reinstate(e) => panic!("{}: the placement refused: {e:?}", cell.what),
            Refused::Delete(e) => panic!("{}: the removal refused: {e:?}", cell.what),
        };
        assert_eq!(said, kept, "{}: the refusal carries the place the client read", cell.what);
        assert_eq!(now, (cell.now)(), "{}: and where D arranges the span now", cell.what);

        let s = k.snapshot();
        assert_eq!(s.seq(), disturbed.seq(), "{}: nothing committed", cell.what);
        assert_eq!(trunk_head(s.world().m3(), &pdoc()), None, "{}: no member minted", cell.what);
        assert!(
            !s.world().m3().is_registered_document(&vdoc()),
            "{}: vdoc does not exist",
            cell.what
        );
        assert_eq!(content_runs_of(&s, &doc1()), runs_before, "{}: D's runs unchanged", cell.what);
        assert_eq!(
            bytes_of(&s, &doc1()),
            bytes_before,
            "{}: D unchanged at every position",
            cell.what
        );
        assert_eq!(
            s.world().content().len(),
            stored_before,
            "{}: no fresh identity written",
            cell.what
        );
    }
}

/// WHOLE RUN AND PIECE. The invariant, §5.7's: the fresh run replaces the
/// draft-native run at its place whether the named span is a whole run of
/// `D` or a strict piece of one — "a piece of a run by the same piece of the
/// fresh run at its offset" — the rest of the run untouched at its own
/// addresses. Two cells: b inserted by its own `insert` between a and c, so
/// it is a run of its own (a at `ca(1)`, c at `ca(2)`, b at `ca(3)`); and
/// the one-run draft of `insert_abc`, b the piece at offset 1. In both, after
/// the one commit, `D` reads a, b, c with the fresh run at ordinal 2 between
/// the draft's own a and c.
#[test]
fn the_named_span_is_re_windowed_whether_a_whole_run_of_the_draft_or_a_piece_of_one() {
    let whole = |k: &Kernel<World>| {
        let vs = Vstream::new(k);
        vs.insert(P1, &doc1(), vp(1, 1), vec![val(b"a")], Deposit::Undeclared).expect("a at ca(1)");
        vs.insert(P1, &doc1(), vp(1, 2), vec![val(b"c")], Deposit::Undeclared).expect("c at ca(2)");
        vs.insert(P1, &doc1(), vp(1, 2), vec![val(b"b")], Deposit::Undeclared)
            .expect("b at ca(3), between");
    };
    let piece = |k: &Kernel<World>| {
        insert_abc(k);
    };
    let run = |start: u32, width: u32| Run::new(ca(start), n(width)).expect("a run");
    let cells: [(&str, &dyn Fn(&Kernel<World>), u32, Vec<Run>, Vec<Run>); 2] = [
        ("whole", &whole, 3, vec![run(1, 1), run(3, 1), run(2, 1)], vec![run(1, 1), run(2, 1)]),
        ("piece", &piece, 2, vec![run(1, 3)], vec![run(1, 1), run(3, 1)]),
    ];
    for (what, build, b_at, runs_before, kept_runs) in cells {
        let k = mem_kernel();
        build(&k);
        let before = k.snapshot();
        assert_eq!(content_runs_of(&before, &doc1()), runs_before, "{what}: the draft's shape");
        assert_eq!(bytes_of(&before, &doc1()), vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        let b = run(b_at, 1);
        let kept = before.world().m5().project(&doc1(), &coverage_of(&b));
        assert_eq!(kept, SpanSet::singleton(vspan(1, 2, 1)), "{what}: b at ordinal 2");

        let (member, seq) = rewindow(&k, &doc1(), &shot_of(&doc1(), &ca(b_at), 1), &kept)
            .expect("the one commit stands whole");
        let s = k.snapshot();
        let m5 = s.world().m5();
        assert_eq!(s.seq(), seq, "{what}: one commit");
        let fresh = Run::new(pca(1), n(1)).expect("the fresh run");
        assert_eq!(
            content_runs_of(&s, &doc1()),
            vec![kept_runs[0].clone(), fresh.clone(), kept_runs[1].clone()],
            "{what}: the fresh run at the place, the rest of the draft at its own addresses"
        );
        assert_eq!(
            bytes_of(&s, &doc1()),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
            "{what}"
        );
        assert!(
            m5.project(&doc1(), &coverage_of(&b)).is_empty(),
            "{what}: the draft-native run is gone from D"
        );
        assert_eq!(
            m5.project(&doc1(), &coverage_of(&fresh)),
            kept,
            "{what}: the fresh run holds the place"
        );
        assert_eq!(bytes_of(&s, &member), vec![b"b".to_vec()], "{what}: the member reads b");
    }
}
