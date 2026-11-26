//! The retry memo through `execute` (§7): a sequential retry replays the
//! acknowledgment its write committed — every acknowledging shape, the bare
//! `Ack`, EDITLINK's two addresses unswapped and an EDIT's one commit of
//! several changes among them — and commits
//! nothing; the key is confined to its session and matched on op-kind, so a
//! fresh session or another kind executes afresh; since only the kind is
//! matched, a different write of the same kind under a reused id is answered
//! from the memo and runs nothing; a key past `MAX_REQ_ID_BYTES` is
//! answered and not memoized; the memo is bounded at the capacity the
//! front door's constructor was handed, the entry it drops the least
//! recently used; and a retry of a write that committed nothing is told so,
//! as the write was.

use std::num::NonZeroUsize;

use crate::common;

use common::*;
use skep_address::SpanSet;
use skep_febe::{Deposit, Disposition, Op, RejectCode, SlotArg, SuccessorSpec, MAX_REQ_ID_BYTES};

/// THE RECALL AHEAD OF `execute` (the link-sets design §5.7's ruling 4;
/// lane S3): `recall` answers the memoized committed-write ack as the
/// `Response` a retry would be answered with — the same address and
/// position — for the session, id and kind that committed it, executing
/// nothing and moving the log by nothing; it answers `None` for a foreign
/// session, an id this session never committed under, the same id under
/// another kind, and an id the memo declined (past `MAX_REQ_ID_BYTES`) —
/// each the miss `execute` itself would meet.
#[test]
fn recall_answers_the_memoized_ack_ahead_of_execute_and_misses_as_execute_would() {
    use skep_febe::{OpKind, ReqId, Response};

    let fx = setup();
    let d = create_doc(&fx);
    let insert = Op::Insert {
        doc: d.clone(),
        at: vp(1, 1),
        values: vec![skep_content::Val::new(vec![b'x'])],
        deposit: Deposit::Undeclared,
        as_of: head(&fx),
    };
    let id = ReqId(b"ins-recall".to_vec());
    assert_eq!(fx.febe.recall(fx.user, &id, OpKind::Insert), None, "nothing committed under the id yet");
    let (addr, at) = ack_addr(ex_id(&fx.febe, fx.user, b"ins-recall", insert));
    let before = fx.febe.log_position();
    assert_eq!(
        fx.febe.recall(fx.user, &id, OpKind::Insert),
        Some(Response::AckAddr { addr, at, committed: true, head_moved: None }),
        "the committed write's ack, as the retry would be answered"
    );
    assert_eq!(fx.febe.log_position(), before, "a recall executes nothing");
    assert_eq!(fx.febe.recall(fx.user, &id, OpKind::Delete), None, "another kind under the id misses");
    let s2 = fx.febe.open_session(USER);
    assert_eq!(fx.febe.recall(s2, &id, OpKind::Insert), None, "a foreign session misses");
    let long = ReqId(vec![b'k'; MAX_REQ_ID_BYTES + 1]);
    assert_eq!(fx.febe.recall(fx.user, &long, OpKind::Insert), None, "an id the memo never admits misses");
}

/// §7: sequential lost-ack retries replay the committed ack without
/// re-executing; the key is per-session and op-kind-matched; reads are never
/// memoized; a fresh session re-executes (best-effort, by design).
#[test]
fn a_sequential_retry_replays_its_ack_and_a_fresh_session_re_executes() {
    let fx = setup();
    let d = create_doc(&fx);
    let insert = || Op::Insert {
        doc: d.clone(),
        at: vp(1, 1),
        values: vec![skep_content::Val::new(vec![b'x'])],
        deposit: Deposit::Undeclared,
        as_of: head(&fx),
    };

    let (addr1, at1) = ack_addr(ex_id(&fx.febe, fx.user, b"ins-1", insert()));
    let before = fx.febe.log_position();

    // Sequential retry: the rebuilt memoized ack, no re-execution.
    let (addr2, at2) = ack_addr(ex_id(&fx.febe, fx.user, b"ins-1", insert()));
    assert_eq!(addr2, addr1);
    assert_eq!(at2, at1);
    assert_eq!(fx.febe.log_position(), before);

    // A READ under the same ReqId reads no memo at all — the memo holds
    // committed-write acks alone — so it executes, is itself never memoized,
    // and leaves the write's entry untouched.
    let (set, _) = spanset(ex_id(&fx.febe, fx.user, b"ins-1", Op::RetrieveDocVSpan { doc: d.clone() }));
    assert_ne!(set, SpanSet::empty());
    let (addr3, at3) = ack_addr(ex_id(&fx.febe, fx.user, b"ins-1", insert()));
    assert_eq!(addr3, addr1);
    assert_eq!(at3, at1);
    assert_eq!(fx.febe.log_position(), before);

    // A replay under a fresh session misses and re-executes (per-session
    // confinement): new address, advanced log.
    let s2 = fx.febe.open_session(USER);
    let (addr4, at4) = ack_addr(ex_id(&fx.febe, s2, b"ins-1", insert()));
    assert_ne!(addr4, addr1);
    assert!(at4 > at1);
    assert!(fx.febe.log_position() > before);

    // The original session's memo is still confined and intact…
    let (addr5, at5) = ack_addr(ex_id(&fx.febe, fx.user, b"ins-1", insert()));
    assert_eq!(addr5, addr1);
    assert_eq!(at5, at1);

    // …until close_session retires the binding (a later write on the retired
    // id is Unauthenticated — and its memo entries are purged, §6).
    fx.febe.close_session(fx.user);
    let rej = rejected(ex_id(&fx.febe, fx.user, b"ins-1", insert()));
    assert_eq!(rej.code, RejectCode::Unauthenticated);
    assert_eq!(rej.disposition, Disposition::Permanent);
}

/// §7: the memo's op-kind tag, through `execute` — where only a WRITE now
/// reaches it, the memo holding committed-write acks alone. A second write
/// under a `ReqId` its session has already committed under, of a DIFFERENT
/// kind, is never answered from that entry: it executes and commits on its
/// own account. The SHAPES are what make the alternative intolerable —
/// replaying the insert's entry would answer a DELETE with an `AckAddr`
/// naming an address the client never asked about — so `ack`'s refusal of
/// any other shape is half the assertion. Its own retry then replays ITS
/// ack, so the key still works for the kind that now holds it.
#[test]
fn a_write_reusing_a_req_id_under_another_kind_executes_rather_than_replaying() {
    let fx = setup();
    let d = create_doc(&fx);
    insert3(&fx, &d);
    let (_, at_ins) = ack_addr(ex_id(
        &fx.febe,
        fx.user,
        b"same",
        Op::Insert {
            doc: d.clone(),
            at: vp(1, 1),
            values: vec![skep_content::Val::new(vec![b'x'])],
            deposit: Deposit::Undeclared,
            as_of: head(&fx),
        },
    ));

    let del = || Op::Delete { doc: d.clone(), p: vp(1, 1), width: nat(1), as_of: head(&fx) };
    let at_del = ack(ex_id(&fx.febe, fx.user, b"same", del()));
    assert!(at_del > at_ins, "the cross-kind write executed and committed on its own account");

    let before = fx.febe.log_position();
    assert_eq!(ack(ex_id(&fx.febe, fx.user, b"same", del())), at_del, "its own retry replays");
    assert_eq!(fx.febe.log_position(), before, "…and a replayed ack commits nothing");
}

/// §7, the caller's half of the key: an id names ONE request. The memo
/// matches by session, id and op-KIND and compares nothing else of the op, so
/// a second write of the SAME kind under an id this session already committed
/// under is answered with the FIRST write's acknowledgment and does not run —
/// the obligation `ReqId` states, pinned so that a change to what the memo
/// compares is a change to that contract and goes red.
#[test]
fn an_id_reused_for_a_different_write_of_the_same_kind_answers_the_first_ack_and_runs_nothing() {
    let fx = setup();
    let d = create_doc(&fx);
    let insert = |byte: u8| Op::Insert {
        doc: d.clone(),
        at: vp(1, 1),
        values: vec![skep_content::Val::new(vec![byte])],
        deposit: Deposit::Undeclared,
        as_of: head(&fx),
    };
    let first = ack_addr(ex_id(&fx.febe, fx.user, b"reused", insert(b'x')));
    let before = fx.febe.log_position();
    let second = ack_addr(ex_id(&fx.febe, fx.user, b"reused", insert(b'y')));
    assert_eq!(second, first, "the first write's acknowledgment answers the second");
    assert_eq!(fx.febe.log_position(), before, "…and the second write is not executed");
}

/// §7/[`MAX_REQ_ID_BYTES`]: the memo's SECOND check, through `execute`. An id
/// past the bound is answered like any other — the never-silent contract is
/// about the operation, and the operation is answered — and simply not
/// memoized, so the retry re-executes and the client is never told. An id
/// exactly at the bound is an ordinary key.
#[test]
fn an_oversized_request_id_is_answered_and_its_retry_re_executes() {
    let fx = setup();
    let d = create_doc(&fx);
    let insert = || Op::Insert {
        doc: d.clone(),
        at: vp(1, 1),
        values: vec![skep_content::Val::new(vec![b'y'])],
        deposit: Deposit::Undeclared,
        as_of: head(&fx),
    };

    let over = vec![b'k'; MAX_REQ_ID_BYTES + 1];
    let (first, at1) = ack_addr(ex_id(&fx.febe, fx.user, &over, insert()));
    let before = fx.febe.log_position();
    let (second, at2) = ack_addr(ex_id(&fx.febe, fx.user, &over, insert()));
    assert_ne!(second, first, "an unmemoized retry re-executes");
    assert!(at2 > at1);
    assert!(fx.febe.log_position() > before, "…and commits");

    let at_cap = vec![b'k'; MAX_REQ_ID_BYTES];
    let (first, _) = ack_addr(ex_id(&fx.febe, fx.user, &at_cap, insert()));
    let before = fx.febe.log_position();
    let (second, _) = ack_addr(ex_id(&fx.febe, fx.user, &at_cap, insert()));
    assert_eq!(second, first, "a key at the bound is an ordinary key");
    assert_eq!(fx.febe.log_position(), before, "so its retry commits nothing");
}

/// §7/§1(d): the memo replays the acknowledgment SHAPE the write produced,
/// not merely its coordinate. EDITLINK's ack carries two same-typed addresses
/// — the successor link, and the claim that says it supersedes the original —
/// and a retry that handed them back swapped would send a client to read,
/// nullify or supersede the wrong link on the engine's own word.
#[test]
fn a_retried_editlink_replays_both_addresses_unswapped() {
    let fx = setup();
    let (d, original) = linked_doc(&fx);
    let edit = || Op::EditLink {
        original: original.clone(),
        successor: SuccessorSpec {
            from: vec![vspec(&d, 1, 1)].into(),
            to: vec![vspec(&d, 2, 1)].into(),
            ty: SlotArg::Resolve(vec![vspec(&d, 3, 1)]),
        },
        d_s: d.clone(),
        d_a: d.clone(),
    };

    let (succ, claim, at) = ack_edit(ex_id(&fx.febe, fx.user, b"edit-1", edit()));
    assert_ne!(succ, claim, "the successor and its supersession claim are two distinct links");
    let before = fx.febe.log_position();

    let (succ2, claim2, at2) = ack_edit(ex_id(&fx.febe, fx.user, b"edit-1", edit()));
    assert_eq!(succ2, succ, "the replayed successor is the successor that committed");
    assert_eq!(claim2, claim, "the replayed claim is the claim, not the successor again");
    assert_eq!(at2, at, "the replayed coordinate is the one the edit committed at");
    assert_eq!(fx.febe.log_position(), before, "a replayed ack commits nothing");
}

/// §7: the bare-`Seq` acknowledgment round-trips too. [`Response::Ack`] is the
/// one committed shape carrying no address, and a DELETE that re-executed on
/// a lost ack would remove a second element the client never asked to lose.
#[test]
fn a_retried_delete_replays_its_bare_ack() {
    let fx = setup();
    let d = create_doc(&fx);
    insert3(&fx, &d);
    let del = || Op::Delete { doc: d.clone(), p: vp(1, 1), width: nat(1), as_of: head(&fx) };

    let at = ack(ex_id(&fx.febe, fx.user, b"del-1", del()));
    let before = fx.febe.log_position();
    let (spans_before, _) = spanset(ex(
        &fx.febe,
        fx.user,
        Op::RetrieveDocVSpanSet { doc: d.clone() },
    ));

    let at2 = ack(ex_id(&fx.febe, fx.user, b"del-1", del()));
    assert_eq!(at2, at, "the replayed ack carries the coordinate the delete committed at");
    assert_eq!(fx.febe.log_position(), before, "a replayed ack commits nothing");
    let (spans_after, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpanSet { doc: d }));
    assert_eq!(
        spans_after, spans_before,
        "the remaining elements survive: the delete did not re-execute"
    );
}

/// §7: an EDIT of several changes is one commit, and its retry replays it.
/// The acknowledgment names the first address minted and the one position
/// every change landed at; the same frame under the same id answers that
/// acknowledgment again and commits nothing — a retry that re-executed would
/// place the changes a second time over the draft the first left — and under
/// a fresh id it is judged afresh and refused as typed against an older
/// state, the first's own commit having moved the draft.
#[test]
fn a_retried_edit_replays_its_one_commit_and_a_fresh_id_meets_the_typed_state() {
    use skep_arrangement::{Change, Edit, Placed};
    let fx = setup();
    let d = create_doc(&fx);
    insert3(&fx, &d);
    let typed = head(&fx);
    let change = |ordinal: u32, width: u32, byte: u8| Change { at: vp(1, ordinal), width: nat(width), placed: Placed::Values(vec![skep_content::Val::new(vec![byte])]) };
    let edit = || Op::Edit { doc: d.clone(), edit: Edit { changes: vec![change(1, 1, b'x'), change(3, 0, b'y')], head: None, base: None, merge: None }, as_of: typed };
    let (addr, at) = ack_addr(ex_id(&fx.febe, fx.user, b"edit-1", edit()));
    assert_eq!(at.0, typed.0 + 3, "one commit: the range minted, its stretch stored and the one record of the changes");
    let before = fx.febe.log_position();
    assert_eq!(ack_addr(ex_id(&fx.febe, fx.user, b"edit-1", edit())), (addr, at), "the replayed ack names the first address minted and the commit");
    assert_eq!(fx.febe.log_position(), before, "a replayed ack commits nothing");
    let refused = rejected(ex_id(&fx.febe, fx.user, b"edit-2", edit()));
    assert_eq!(refused.code, RejectCode::ArrangementMoved, "judged afresh, typed before its own first commit");
    assert_eq!(fx.febe.log_position(), before, "and nothing lands twice");
}

/// §7, THE CAPACITY IS THE CALLER's (the operations design §2.6, op-D5): the
/// memo is bounded at the figure `OperationSurface::new` was handed and at
/// nothing else — a front door built at TWO holds two committed acks and
/// drops the least recently used at the third, so that write's retry
/// re-executes while the two kept entries still replay. The daemon hands its
/// own pin; this suite hands two, which is what makes the bound observable
/// through the front door rather than through the memo alone.
#[test]
fn a_front_door_built_at_two_evicts_the_first_entry_at_the_third() {
    let fx = fixture_on(surface_with_memo(kernel(), NonZeroUsize::new(2).expect("2 is nonzero")));
    let d = create_doc(&fx);
    let insert = |byte: u8| Op::Insert {
        doc: d.clone(),
        at: vp(1, 1),
        values: vec![skep_content::Val::new(vec![byte])],
        deposit: Deposit::Undeclared,
        as_of: head(&fx),
    };

    let first = ack_addr(ex_id(&fx.febe, fx.user, b"one", insert(b'a')));
    let second = ack_addr(ex_id(&fx.febe, fx.user, b"two", insert(b'b')));
    // Two entries fill a memo of two, and nothing is dropped yet: the first
    // replays — which also makes it the most recently used of the two.
    let before = fx.febe.log_position();
    assert_eq!(ack_addr(ex_id(&fx.febe, fx.user, b"one", insert(b'a'))), first);
    assert_eq!(fx.febe.log_position(), before, "a memo at capacity has evicted nothing");

    // The third entry is one past the bound: the least recently used — the
    // second — goes; the first, just replayed, and the third stay.
    let third = ack_addr(ex_id(&fx.febe, fx.user, b"three", insert(b'c')));
    let before = fx.febe.log_position();
    assert_eq!(ack_addr(ex_id(&fx.febe, fx.user, b"three", insert(b'c'))), third);
    assert_eq!(ack_addr(ex_id(&fx.febe, fx.user, b"one", insert(b'a'))), first);
    assert_eq!(fx.febe.log_position(), before, "the two kept entries replay and commit nothing");
    let (addr, at) = ack_addr(ex_id(&fx.febe, fx.user, b"two", insert(b'b')));
    assert_ne!((addr, at), second, "the evicted entry's retry re-executes…");
    assert!(fx.febe.log_position() > before, "…and commits");
}

/// Checks that a retry of a write that committed nothing is told so.
///
/// An `emit` answered with the incumbent it deduplicated against —
/// `committed: false`, `at` the base it was found in, another write's
/// position — is memoized with its `committed`, so its retry under the same
/// id and `recall` answer `committed: false` at that `at`, never the ack of a
/// commit a client would count as its own; the emit that committed is
/// replayed as committing (skep #1043; the mutant that drops the member at
/// the memo answers the retry as a commit).
#[test]
fn a_retry_of_a_write_that_committed_nothing_is_told_it_committed_nothing() {
    use skep_febe::{OpKind, ReqId, Response};

    let fx = setup();
    let d = create_doc(&fx);
    let (start, _) = insert3(&fx, &d);
    let emit = || Op::Emit { home: d.clone(), ty: pred_def_ty(), from: start.clone(), to: vec![] };
    let Response::AckAddr { addr: incumbent, at: minted_at, committed: true, .. } =
        ex_id(&fx.febe, fx.user, b"emit-mint", emit())
    else {
        panic!("the first emit commits, and says so");
    };
    let hit = ex_id(&fx.febe, fx.user, b"emit-hit", emit());
    let head = fx.febe.log_position();
    let told = Response::AckAddr { addr: incumbent.clone(), at: head, committed: false, head_moved: None };
    assert_eq!(hit, told, "the hit: the incumbent at the base, committing nothing");

    assert_eq!(ex_id(&fx.febe, fx.user, b"emit-hit", emit()), told, "the retry is told what the hit was");
    assert_eq!(
        fx.febe.recall(fx.user, &ReqId(b"emit-hit".to_vec()), OpKind::Emit),
        Some(told),
        "and so is the recall ahead of execute"
    );
    assert_eq!(
        ex_id(&fx.febe, fx.user, b"emit-mint", emit()),
        Response::AckAddr { addr: incumbent, at: minted_at, committed: true, head_moved: None },
        "the minting emit's retry replays its commit"
    );
    assert_eq!(fx.febe.log_position(), head, "no retry committed");
}
