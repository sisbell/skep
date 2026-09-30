//! The retry memo through `execute` (§7): a sequential retry replays the
//! acknowledgment its write committed — every acknowledging shape, the bare
//! `Ack` and EDITLINK's two addresses unswapped among them — and commits
//! nothing; the key is confined to its session and matched on op-kind, so a
//! fresh session or another kind executes afresh; and a key past
//! `MAX_REQ_ID_BYTES` is answered and not memoized.

use crate::common;

use common::*;
use skep_address::SpanSet;
use skep_febe::{Deposit, Disposition, Op, RejectCode, SlotArg, SuccessorSpec, MAX_REQ_ID_BYTES};

/// §7: sequential lost-ack retries replay the committed ack without
/// re-executing; the key is per-session and op-kind-matched; reads are never
/// memoized; a fresh session re-executes (best-effort, by design).
#[test]
fn a_sequential_retry_replays_its_ack_and_a_fresh_session_re_executes() {
    let fx = setup();
    let d = create_doc(&fx);
    let ins = || Op::Insert {
        doc: d.clone(),
        at: vp(1, 1),
        values: vec![skep_content::Val::new(vec![b'x'])],
        deposit: Deposit::Undeclared,
    };

    let (addr1, at1) = ack_addr(ex_id(&fx.febe, fx.user, b"ins-1", ins()));
    let log0 = fx.febe.log_position();

    // Sequential retry: the rebuilt cached ack, no re-execution.
    let (addr2, at2) = ack_addr(ex_id(&fx.febe, fx.user, b"ins-1", ins()));
    assert_eq!(addr2, addr1);
    assert_eq!(at2, at1);
    assert_eq!(fx.febe.log_position(), log0);

    // A READ under the same ReqId consults no memo at all — the memo holds
    // committed-write acks alone — so it executes, is itself never memoized,
    // and leaves the write's entry untouched.
    let (set, _) = spanset(ex_id(&fx.febe, fx.user, b"ins-1", Op::RetrieveDocVSpan { doc: d.clone() }));
    assert_ne!(set, SpanSet::empty());
    let (addr3, at3) = ack_addr(ex_id(&fx.febe, fx.user, b"ins-1", ins()));
    assert_eq!(addr3, addr1);
    assert_eq!(at3, at1);
    assert_eq!(fx.febe.log_position(), log0);

    // A replay under a fresh session misses and re-executes (per-session
    // confinement): new address, advanced log.
    let s2 = fx.febe.open_session(USER);
    let (addr4, at4) = ack_addr(ex_id(&fx.febe, s2, b"ins-1", ins()));
    assert_ne!(addr4, addr1);
    assert!(at4 > at1);
    assert!(fx.febe.log_position() > log0);

    // The original session's memo is still confined and intact…
    let (addr5, at5) = ack_addr(ex_id(&fx.febe, fx.user, b"ins-1", ins()));
    assert_eq!(addr5, addr1);
    assert_eq!(at5, at1);

    // …until close_session retires the binding (a later write on the retired
    // id is Unauthenticated — and its idem entries are purged, §6).
    fx.febe.close_session(fx.user);
    let rej = rejected(ex_id(&fx.febe, fx.user, b"ins-1", ins()));
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
        },
    ));

    let del = || Op::Delete { doc: d.clone(), p: vp(1, 1), width: nat(1) };
    let at_del = ack(ex_id(&fx.febe, fx.user, b"same", del()));
    assert!(at_del > at_ins, "the cross-kind write executed and committed on its own account");

    let log = fx.febe.log_position();
    assert_eq!(ack(ex_id(&fx.febe, fx.user, b"same", del())), at_del, "its own retry replays");
    assert_eq!(fx.febe.log_position(), log, "…and a replayed ack commits nothing");
}

/// §7/[`MAX_REQ_ID_BYTES`]: the memo's SECOND door, through `execute`. An id
/// past the bound is answered like any other — the never-silent contract is
/// about the operation, and the operation is answered — and simply not
/// memoized, so the retry re-executes and the client is never told. An id
/// exactly at the bound is an ordinary key.
#[test]
fn an_oversized_request_id_is_answered_and_its_retry_re_executes() {
    let fx = setup();
    let d = create_doc(&fx);
    let ins = || Op::Insert {
        doc: d.clone(),
        at: vp(1, 1),
        values: vec![skep_content::Val::new(vec![b'y'])],
        deposit: Deposit::Undeclared,
    };

    let over = vec![b'k'; MAX_REQ_ID_BYTES + 1];
    let (first, at1) = ack_addr(ex_id(&fx.febe, fx.user, &over, ins()));
    let log0 = fx.febe.log_position();
    let (second, at2) = ack_addr(ex_id(&fx.febe, fx.user, &over, ins()));
    assert_ne!(second, first, "an unmemoized retry re-executes");
    assert!(at2 > at1);
    assert!(fx.febe.log_position() > log0, "…and commits");

    let at_cap = vec![b'k'; MAX_REQ_ID_BYTES];
    let (a, _) = ack_addr(ex_id(&fx.febe, fx.user, &at_cap, ins()));
    let log1 = fx.febe.log_position();
    let (b, _) = ack_addr(ex_id(&fx.febe, fx.user, &at_cap, ins()));
    assert_eq!(b, a, "a key at the bound is an ordinary key");
    assert_eq!(fx.febe.log_position(), log1, "so its retry commits nothing");
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
            from: vec![vspec(&d, 1, 1)],
            to: vec![vspec(&d, 2, 1)],
            ty: SlotArg::Resolve(vec![vspec(&d, 3, 1)]),
        },
        d_s: d.clone(),
        d_a: d.clone(),
    };

    let (succ, claim, at) = ack_edit(ex_id(&fx.febe, fx.user, b"edit-1", edit()));
    assert_ne!(succ, claim, "the successor and its supersession claim are two distinct links");
    let log0 = fx.febe.log_position();

    let (succ2, claim2, at2) = ack_edit(ex_id(&fx.febe, fx.user, b"edit-1", edit()));
    assert_eq!(succ2, succ, "the replayed successor is the successor that committed");
    assert_eq!(claim2, claim, "the replayed claim is the claim, not the successor again");
    assert_eq!(at2, at, "the replayed coordinate is the one the edit committed at");
    assert_eq!(fx.febe.log_position(), log0, "a replayed ack commits nothing");
}

/// §7: the bare-`Seq` acknowledgment round-trips too. [`Response::Ack`] is the
/// one committed shape carrying no address, and a DELETE that re-executed on
/// a lost ack would remove a second element the client never asked to lose.
#[test]
fn a_retried_delete_replays_its_bare_ack() {
    let fx = setup();
    let d = create_doc(&fx);
    insert3(&fx, &d);
    let del = || Op::Delete { doc: d.clone(), p: vp(1, 1), width: nat(1) };

    let at = ack(ex_id(&fx.febe, fx.user, b"del-1", del()));
    let log0 = fx.febe.log_position();
    let (before, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpanSet { doc: d.clone() }));

    let at2 = ack(ex_id(&fx.febe, fx.user, b"del-1", del()));
    assert_eq!(at2, at, "the replayed ack carries the coordinate the delete committed at");
    assert_eq!(fx.febe.log_position(), log0, "a replayed ack commits nothing");
    let (after, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpanSet { doc: d }));
    assert_eq!(after, before, "the remaining elements survive: the delete did not re-execute");
}
