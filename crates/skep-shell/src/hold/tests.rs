//! The hold's classification table, and the ground its child suites stand on.
//!
//! The table (T6) takes every `DialError`, every disposition, `poisoned`,
//! `internal_panic`, `write_busy` once and twice, `durability` once, twice and
//! three times, `arrangement_moved`, and an ack, each to exactly its row — a
//! request the board never answered to its own, apart from an answer it gave
//! that this client cannot read, and a `/health` refused before any
//! connection no verdict on the board (skep #863) — the table the one owner of
//! every reissue's bound; the failed send, which starts and runs a line's
//! clock (`HAND_OVER_DEADLINE`), is every answer but an ack, the death signal,
//! a request the board gave no answer to and a dial that never left, each
//! with its token — a second `write_busy` among them, held as a connection
//! never made is; every hand's key a declared `HandKey` word; the
//! five kinds are bursts and the eleven other
//! `WRITE_KINDS` are not; the five held states are the declared ones, a
//! line's its cause's whatever refusal stands beside it, and the two acts of
//! `resolve` the declared words and no other spelling; the whys a drop that
//! reads first refuses by the declared words; and the class of why a line
//! stands off disk is its refusal's kind's row, every kind of no row
//! `other`, the three classes the declared words, set with the words; and a
//! board's state is the most severe that holds, its five words the declared
//! ones.
//!
//! The ground is a fake board (`Fake`) — its `H.1`, or an answer armed in the
//! record's place, whether it names a claimant, the position its `/health`
//! names and that `/health` unanswered where a cell arms it; the
//! `find_links_ftt` reads of a label read, none of which finds a link, each
//! counted, and an answer armed in their place; its `/changes` rows, or no
//! answer to them, and
//! the reads of them counted, each read slowed where a cell asks, and a look
//! taken once as the next reaches the board; its commit
//! stream, none or endless; a draft's text, its content image and the
//! reads of it counted, a look taken as each image read reaches the board,
//! the death signal, no answer or a refusal at either read where a cell arms
//! it, the position its
//! arrangement last changed at as a cell sets it — a burst typed below it
//! refused `arrangement_moved`, the fake's own acks moving nothing, so every
//! frame typed at the fake's head meets no refusal — the frames POSTed to
//! `/op` recorded, a look taken as each is recorded, and a refusal or the
//! death signal armed for a send, an insert's ack naming the address it
//! minted where a cell arms it, and an `/op-at` image of the draft, no
//! answer or a refusal where a cell arms it — the holds over it with a
//! session opened as the shell opens one and every line the hold says on
//! `Talk` recorded
//! (`Ground`), the clock a line's deadline reads moved forward by a cell
//! where it waits past one (`Holds::advance`), a burst held through the
//! hold's own door at the base a hold takes now, and each `held` event,
//! `held` row and `held` answer, and each `another-window` event, held to
//! its declaration.
//! The ground's session is a writer's — signed, under a key its store
//! generates, since a bare session reads alone and no probe resends under it —
//! save where a cell asks for a bare one (`bare_ground`) or for a key no store
//! holds (`keyed_facts`), and its board one someone has claimed, save where a
//! cell asks for one no one has over a store the device refuses
//! (`unclaimed_ground`), whose lines stand in memory alone, owed, no copy
//! synced; a cell runs the board's feed thread over the ground's holds
//! where it asks (`feed_threads`). `write` holds the one path of a session's
//! `op` — a burst's door and its hold, and a write the hold never holds;
//! `resend` the probe and the resend walk; `labels` the label another
//! device's key goes by; `classes` the held store's defect classes, each
//! pinned as an expected failure until the brief that closes it lands, and
//! the measure of the syncs each act makes. The store's two
//! enums are held to their variants here: `Directory`'s three standings
//! and `Custody`'s three, a state added later a red before it is a pen.

use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;
use skep_client::board::{Token, HEAD_MEMBER_1};
use skep_client::dial::{DialError, Dialer, Headers, Method, Request, RequestHead, Response, StreamedResponse};
use skep_client::store::{KeyId, KeyStore};
use skep_client::Origin;
use tempfile::TempDir;

use super::*;
use crate::events::Event;
use crate::sessions::{Facts, Open, SessionKind, Supplements};

mod classes;
mod labels;
mod resend;
mod write;

/// The five burst kinds are bursts; the thirteen other write kinds are not.
#[test]
fn the_five_kinds_are_bursts_and_no_other_write_kind_is() {
    for op in BURST_KINDS {
        assert!(is_burst(&json!({"op": op})), "{op}");
    }
    for op in crate::shell::WRITE_KINDS {
        let burst = BURST_KINDS.contains(&op);
        assert_eq!(is_burst(&json!({"op": op})), burst, "{op}");
    }
    assert!(!is_burst(&json!({"op": "publish"})));
    assert!(!is_burst(&json!({"op": "doc_metadata"})), "a read is no burst");
    assert!(!is_burst(&json!({})), "a frame with no op is no burst");
}

fn rej(code: &str, disposition: &str) -> Decision {
    classify(DialOutcome::Rejected { code, disposition }, &Reissues::default())
}

/// The reissues a burst has been given: `write_busy` ones and `durability`
/// ones.
fn given(write_busy: u32, durability: u32) -> Reissues {
    Reissues { write_busy, durability, ..Reissues::default() }
}

/// A `rejected` document of `code` at the retry disposition.
fn retry(code: &str) -> Value {
    json!({"resp": "rejected", "code": code, "disposition": "retry", "op": "insert"})
}

/// Checks the classification table (§3c.4): each outcome to exactly its row.
///
/// The own node stopped, an ack and the death signal sit outside `classify`
/// (`DialOutcome`'s doc); a write the hold never holds is read through it as
/// a burst is, and faced where a burst is held (`write`'s suite). A request
/// the board never answered — no connection, no answer within its bound, a
/// connection closed before any answer — has its own row apart from an
/// answer it gave that this client cannot read (skep #863). The mutant that
/// leaves `arrangement_moved` to the disposition's row holds a stale burst as
/// a refused run, whose resend meets the same refusal; the one that faces the
/// reissue's own `write_busy` hands the page a burst the board was briefly
/// too full to take (skep #786); the one that reads a timeout as an answer
/// lost walks the resend on into a board that is not there.
#[test]
fn every_outcome_classifies_to_exactly_its_row() {
    // No connection made — the board gave the burst no answer, and it did
    // not leave (`sent: false`).
    for e in [DialError::Connect("x".into()), DialError::Resolve("x".into()), DialError::Tls("x".into())] {
        assert_eq!(classify(DialOutcome::Dial(&e), &Reissues::default()), Decision::Unanswered { sent: false }, "{e}");
    }
    // The request left and the board gave it no answer — it MAY have landed
    // (`sent: true`).
    for e in [DialError::Timeout("x".into()), DialError::Io("x".into()), DialError::Truncated { declared: 9, got: 1 }] {
        assert_eq!(classify(DialOutcome::Dial(&e), &Reissues::default()), Decision::Unanswered { sent: true }, "{e}");
    }
    // The board answered with bytes this client cannot read — an answer lost
    // on the way, which MAY have landed (`sent: true`).
    for e in [DialError::Response("x".into()), DialError::TooLarge { cap: 1 }] {
        assert_eq!(classify(DialOutcome::Dial(&e), &Reissues::default()), Decision::Hold { cause: "unreachable", sent: true }, "{e}");
    }
    // The scheme this build does not hold, or a request refused before any
    // connection — faced as built, no probe ends either.
    for e in [DialError::NotHeld("https".into()), DialError::Request("x".into())] {
        assert_eq!(classify(DialOutcome::Dial(&e), &Reissues::default()), Decision::Neither, "{e}");
    }
    // The codes. `poisoned` MAY have landed (§3c.2): the frames reached the
    // journal and a restart replays them, so its line says `sent: true`.
    assert_eq!(rej("poisoned", "halt"), Decision::Hold { cause: "poisoned", sent: true });
    // The board's `500 internal_panic` may have landed too: its write may
    // have committed before the handler panicked, its body riding no
    // disposition — held as a lost answer is, `sent: true`.
    assert_eq!(rej("internal_panic", ""), Decision::Hold { cause: "unreachable", sent: true });
    // `write_busy` once → reissue, after the short wait; the reissue's own →
    // a burst held `unreachable`, `sent: false`: nothing was committed.
    let busy = DialOutcome::Rejected { code: "write_busy", disposition: "retry" };
    assert_eq!(classify(busy, &given(0, 0)), Decision::Reissue(Reissue::WriteBusy));
    assert_eq!(classify(busy, &given(1, 0)), Decision::Hold { cause: "unreachable", sent: false });
    // `durability` once, twice → reissue as-is; a THIRD on the same burst →
    // hold; a `write_busy` given beside counts nothing toward the rider.
    let durability = DialOutcome::Rejected { code: "durability", disposition: "retry" };
    assert_eq!(classify(durability, &given(0, 0)), Decision::Reissue(Reissue::Durability));
    assert_eq!(classify(durability, &given(1, 1)), Decision::Reissue(Reissue::Durability));
    assert_eq!(classify(durability, &given(0, 2)), Decision::Hold { cause: "durability", sent: false });
    assert_eq!((Reissue::WriteBusy.wait(), Reissue::Durability.wait()), (WRITE_BUSY_WAIT, Duration::ZERO));
    let mut noted = Reissues::default();
    for kind in [Reissue::WriteBusy, Reissue::Durability, Reissue::Durability] {
        noted.note(kind);
    }
    assert_eq!(noted, given(1, 2), "each reissue counted under its own kind");
    // A `permanent` or `reorder` refusal → a REFUSED run.
    assert_eq!(rej("out_of_bounds", "permanent"), Decision::Refused);
    assert_eq!(rej("not_registered", "reorder"), Decision::Refused);
    // A burst typed against an older state of its document, `permanent` → a
    // MOVED document, never a refused run.
    assert_eq!(rej("arrangement_moved", "permanent"), Decision::Moved);
    // Any other retry-class rejection on a burst → faced, not held.
    assert_eq!(rej("history_busy", "retry"), Decision::Neither);
}

/// THE FAILED SEND (§3c.4): the one rule a line's clock starts and runs by.
///
/// A dial's answer starts or runs its line's clock (`HAND_OVER_DEADLINE`) where
/// the send left, or was answered, and did not land — a lost answer,
/// `poisoned`, `durability`, a refused run, a move, a reissue-class answer, a
/// second `write_busy` held as a connection never made is, any refusal of the
/// board's faced — and never where it landed, where the session died, or
/// where no dial left: a connection never made, a request refused before any
/// connection, an attest that could not be composed, a signature not made, a
/// hold before any dial; nor does a line held at the death, nor at once a
/// request the board gave no answer to, which the next probe's verdict
/// settles (skep #863). Its token is the
/// held cause, or the board's in the `code:detail` convention (the mutant
/// that reads a connection never made as a failure hands an outage's line to
/// the person; the one that reads the shell's own refusal as the board's
/// hands a line over that the board never judged; the one that reads a held
/// `write_busy` by its reason alone starts no clock on a busy board's line,
/// which is resent for ever).
#[test]
fn a_failed_send_is_every_answer_but_an_ack_the_death_and_a_dial_that_never_left() {
    let held = |cause: &str, sent: bool| Dialed::Held { reason: Reason::of(cause, sent), refusal: Refusal::malformed("x") };
    let board = |v: Value| Refusal::from(skep_client::board::Rejection::of(&v).expect("a rejected document").refused(&v));
    let face = skep_client::halt::Face { state: "s".into(), cause: "c".into(), act: "a".into(), path: None };
    let cells: Vec<(&str, Dialed, Option<&str>)> = vec![
        ("an ack", Dialed::Acked(json!({"resp": "ack", "at": 1})), None),
        ("the death signal", Dialed::Died, None),
        ("a request the board gave no answer to, settled by the next probe's verdict", Dialed::unanswered(true, Refusal::Unreachable(DialError::Timeout("x".into()))), None),
        ("a connection never made", Dialed::Held { reason: Reason::of("unreachable", false), refusal: Refusal::Unreachable(DialError::Connect("x".into())) }, None),
        ("an answer lost", held("unreachable", true), Some("unreachable")),
        ("poisoned", held("poisoned", true), Some("poisoned")),
        ("a third durability", held("durability", false), Some("durability")),
        ("a move", Dialed::Held { reason: Reason { cause: "moved".into(), refusal: Some(arrangement_moved(40, 45)), sent: false }, refusal: Refusal::malformed("x") }, Some("moved")),
        ("a refused run", Dialed::Held { reason: Reason::refused("out_of_bounds", json!({})), refusal: Refusal::malformed("x") }, Some("out_of_bounds")),
        ("a signature not made", held("head_unreadable", false), None),
        ("a reissue", Dialed::Reissue { kind: Reissue::WriteBusy, refusal: Refusal::board(503, json!({"error": "write_busy"})) }, Some("write_busy")),
        ("a write_busy past its reissue, held as a connection never made is", Dialed::Held { reason: Reason::of("unreachable", false), refusal: Refusal::board(503, json!({"error": "write_busy"})) }, Some("write_busy")),
        ("a code the table holds nowhere", Dialed::Faced(board(json!({"resp": "rejected", "code": "credential_refused", "detail": "index_rebuilding", "disposition": "retry"}))), Some("credential_refused:index_rebuilding")),
        ("a request refused before any connection", Dialed::Faced(Refusal::Unreachable(DialError::Request("x".into()))), None),
        ("the attest's composer halted", Dialed::Faced(Refusal::named(Name::ATTEST_NOT_COMPOSED, face)), None),
        ("an attest whose read went unanswered", Dialed::from(Unattested::Refused(Refusal::Unreachable(DialError::Timeout("x".into())))), None),
    ];
    for (cell, dialed, token) in cells {
        assert_eq!(dialed.failure().as_deref(), token, "{cell}");
    }
    for cause in ["halted", "stopped", "behind"] {
        assert_eq!(failed_send(&Reason::of(cause, false)), None, "{cause}: a hold before any dial");
    }
    assert_eq!(failed_send(&Reason::of("session_died", false)), None, "a line held at the death: the death is neither");
}

/// Checks that a `/health` refused before any connection is no verdict.
///
/// It reached no board (`DialError::NotHeld`, `DialError::Request`): neither
/// the board's silence nor its answer. The read answers `Verdict::Undialed`
/// and the hold stands as it stood — a board answering stays so, a burst
/// there dialed, and a silence already found stands — while a read the board
/// gave no answer to is its silence (the mutant that reads the refusal as the
/// board's silence holds every later burst `unreachable` where no probe could
/// send it; the one that reads it as an answer ends a silence on a read that
/// reached no board).
#[test]
fn a_health_read_refused_before_any_connection_is_no_verdict() {
    let g = ground();
    let verdict_of = |e: DialError| g.holds.note_health_read("b-1", &Err(Halt::Dial(e)));
    for e in [DialError::NotHeld("https".into()), DialError::Request("x".into())] {
        assert_eq!(verdict_of(e.clone()), Verdict::Undialed, "{e:?}");
        assert!(!g.holds.silent("b-1"), "{e:?}: the board answering stays so");
    }
    let OpAnswer::Answered(Ok(ack)) = g.holds.send(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("dialed") };
    assert_eq!((ack["resp"].as_str(), g.fake.sends()), (Some("ack"), 1), "a burst there is dialed: {ack}");
    assert_eq!(verdict_of(DialError::Timeout("x".into())), Verdict::Silent, "a read the board gave no answer to is its silence");
    assert_eq!(verdict_of(DialError::NotHeld("https".into())), Verdict::Undialed);
    assert!(g.holds.silent("b-1"), "the silence found stands");
}

/// Checks that a line's state is its cause's, whatever refusal stands beside.
///
/// A refused run's line reads `refused` and a moved one's `moved`, each
/// awaiting the person's act; a line held `head_unreadable` or `session_died`
/// carries a refusal that says why it waits — the head's, or the death's
/// with its arm — and reads `holding`, awaiting no act (P10), so the probe
/// sends it once the head reads or a session that may write stands (the
/// mutant that reads every line carrying a refusal as a refused run's leaves
/// a burst held at the death waiting for an act no face asks for).
#[test]
fn a_lines_state_is_its_causes_whatever_refusal_stands_beside_it() {
    let with = |cause: &str, refusal: Value| Reason { cause: cause.to_string(), refusal: Some(refusal), sent: false };
    let died = Refusal::shell(Name::SESSION_DIED, json!({"session": "s-1", "reason": crate::sessions::restart_reason(None, None)})).to_value();
    let cells = [
        ("a refused run", with("out_of_bounds", json!({"code": "out_of_bounds"})), HeldState::Refused),
        ("a moved document", with("moved", arrangement_moved(40, 45)), HeldState::Moved),
        ("a head that will not read", with("head_unreadable", json!({"name": "head_unreadable"})), HeldState::Holding),
        ("a burst held at the death, its reason beside it", with("session_died", died), HeldState::Holding),
        ("a burst held at the death, its reason not yet derived", Reason::of("session_died", false), HeldState::Holding),
        ("a lost answer", Reason::of("unreachable", true), HeldState::Holding),
    ];
    for (cell, reason, state) in cells {
        assert_eq!(line_state(&reason), state, "{cell}");
    }
}

/// The five held states are the declared `HeldEvent.state` union's words,
/// each spelled as the event carries it (the mutant that misspells one says
/// a state no page renders).
#[test]
fn the_held_states_are_the_declared_five() {
    let states = [HeldState::Holding, HeldState::Sending, HeldState::Kept, HeldState::Refused, HeldState::Moved];
    let declared = crate::shapes::shape("HeldEvent").unwrap().fields.iter().find(|f| f.name == "state").unwrap().ty;
    let spelled: std::collections::BTreeSet<String> = states.iter().map(|s| format!("'{}'", s.as_str())).collect();
    let words: std::collections::BTreeSet<String> = declared.split(" | ").map(str::to_string).collect();
    assert_eq!((spelled.len(), spelled), (5, words), "{declared}");
}

/// Checks that an I/O refusal's class is its kind's row, `other` for no row.
///
/// It is the one table (`UnwritableClass::of`; skep #820), one cell per row:
/// a full disk and a spent quota read `full`, a read-only volume and a write
/// this shell has no right to make read `read_only`. A kind of no row reads
/// `other` — the writer's own refusal of a line past the bound
/// (`InvalidInput`), which no freed space ends, a name another file or a
/// directory takes, a file not found, a file past the volume's size, a write
/// that would block and the OS's `Other` (the mutant that reads
/// `PermissionDenied` as `other` gives a locked data directory no act of its
/// own; the one that reads a kind of no row as `full` tells the person to free
/// space the copy does not want).
#[test]
fn the_unwritable_class_of_each_kind_is_its_row() {
    use std::io::ErrorKind;
    let rows = [
        (ErrorKind::StorageFull, UnwritableClass::Full),
        (ErrorKind::QuotaExceeded, UnwritableClass::Full),
        (ErrorKind::ReadOnlyFilesystem, UnwritableClass::ReadOnly),
        (ErrorKind::PermissionDenied, UnwritableClass::ReadOnly),
    ];
    for (kind, class) in rows {
        assert_eq!(UnwritableClass::of(kind), class, "{kind:?}");
    }
    for kind in [ErrorKind::Other, ErrorKind::InvalidInput, ErrorKind::AlreadyExists, ErrorKind::IsADirectory, ErrorKind::NotFound, ErrorKind::FileTooLarge, ErrorKind::WouldBlock] {
        assert_eq!(UnwritableClass::of(kind), UnwritableClass::Other, "{kind:?}: a kind of no row");
    }
}

/// Checks that the three classes are the declared words, set beside the why.
///
/// They are the `HeldAnswer.unwritable_class` union's words, each spelled as
/// the answer carries it; the answer's two members are set from one cause
/// (`Unwritable`): an I/O refusal's words — alone, or after what of the
/// store was refused (`store_refused`) — with its kind's class, a kind
/// outside the table `other`, each answer held to its declaration (the
/// mutant that misspells a class says one no page keys an act by; the one
/// that sets the words alone leaves the page no class to read).
#[test]
fn the_three_unwritable_classes_are_the_declared_words() {
    let classes = [UnwritableClass::Full, UnwritableClass::ReadOnly, UnwritableClass::Other];
    let declared = crate::shapes::shape("HeldAnswer").unwrap().fields.iter().find(|f| f.name == "unwritable_class").unwrap().ty;
    let spelled: std::collections::BTreeSet<String> = classes.iter().map(|c| format!("'{}'", c.as_str())).collect();
    let words: std::collections::BTreeSet<String> = declared.split(" | ").map(str::to_string).collect();
    assert_eq!((spelled.len(), spelled), (3, words), "{declared}");
    let refused = std::io::Error::new(std::io::ErrorKind::ReadOnlyFilesystem, "Read-only file system (os error 30)");
    let cells = [
        ("the refusal alone", Unwritable::from(&refused), "Read-only file system (os error 30)", "read_only"),
        (
            "the refusal after what of the store was refused",
            Unwritable::from(&store_refused("the held store could not be made or locked", &refused)),
            "the held store could not be made or locked: Read-only file system (os error 30)",
            "read_only",
        ),
        ("a kind outside the table", Unwritable::from(&std::io::Error::other("the held file is a directory")), "the held file is a directory", "other"),
    ];
    for (cell, why, words, class) in cells {
        let mut answer = json!({"resp": "held", "held": 1, "cause": "unreachable"});
        why.answer_in(&mut answer);
        crate::shapes::assert_declared("HeldAnswer", &answer);
        assert_eq!((answer["unwritable"].as_str(), answer["unwritable_class"].as_str()), (Some(words), Some(class)), "{cell}: {answer}");
    }
}

/// Checks that the whys of a drop's `landing_unread` are the declared words.
///
/// They are the `LandingUnreadRefusal.why` union's words, in its order, each
/// spelled as the refusal carries it, and every refusal the drop answers is
/// held to its declaration (skep #866; the mutant that misspells a why names
/// one no page keys its statement by).
#[test]
fn the_landing_unread_whys_are_the_declared_words() {
    let declared = crate::shapes::shape("LandingUnreadRefusal").unwrap().fields.iter().find(|f| f.name == "why").unwrap().ty;
    let spelled: Vec<String> = LandingUnread::ALL.iter().map(|why| format!("'{}'", why.as_str())).collect();
    assert_eq!(spelled, declared.split(" | ").collect::<Vec<_>>(), "{declared}");
    for why in LandingUnread::ALL {
        let refused = landing_unread(7, why).to_value();
        crate::shapes::assert_declared("LandingUnreadRefusal", &refused);
        assert_eq!((refused["held"].as_u64(), refused["why"].as_str()), (Some(7), Some(why.as_str())), "{refused}");
    }
}

/// The store's states are three and three (the record
/// `2026-11-06-held-store-investigation` §7: the state count, which the
/// reviews read the classes closed by): every variant of `Directory` and of
/// `Custody` is named here, and a match with no wildcard arm holds the
/// count, so a state added later is a red here before it is a pen (the
/// mutant that adds a memory custody, or a fourth standing of the store,
/// fails to compile).
#[test]
fn the_directory_has_three_states_and_the_custody_three() {
    let store = TempDir::new().unwrap();
    let pending = HeldDir::pending(store.path(), &Origin::parse("http://127.0.0.1:1").unwrap());
    pending.ensure().unwrap();
    let lock = pending.try_lock().unwrap().expect("the pending lock is free");
    let directories = [Directory::NotYet(std::io::Error::other("refused")), Directory::AnotherWindow { pending: None }, Directory::ThisWindow { pending: LockedDir { dir: pending, _lock: lock }, chain: None }];
    let names: Vec<&str> = directories
        .iter()
        .map(|directory| match directory {
            Directory::NotYet(_) => "NotYet",
            Directory::AnotherWindow { .. } => "AnotherWindow",
            Directory::ThisWindow { .. } => "ThisWindow",
        })
        .collect();
    assert_eq!(names, ["NotYet", "AnotherWindow", "ThisWindow"], "the store's three standings: a device's refusal, another shell's, this shell's");
    let custodies = [Custody::Unopened, Custody::File, Custody::Halted { path: PathBuf::new(), why: HaltWhy::Damaged }];
    let names: Vec<&str> = custodies
        .iter()
        .map(|custody| match custody {
            Custody::Unopened => "Unopened",
            Custody::File => "File",
            Custody::Halted { .. } => "Halted",
        })
        .collect();
    assert_eq!(names, ["Unopened", "File", "Halted"], "a principal's three custodies: the file not yet read, the file, the halt");
}

/// Checks that every hand's key is a declared `HandKey` word (§4b.2).
///
/// The keys a moved face's hands carry — this store's own, another key's, an
/// unsigned hand, a testimony lost, the hands not read and the hands no read
/// can name — are exactly the declared union's words (the mutant that spells
/// the unread hands `lost` tells the page the board lost what it never
/// answered; one that spells a word the union lacks hands the page a hand it
/// cannot draw).
#[test]
fn every_hand_key_is_a_declared_word() {
    let g = ground();
    let row = |at: u64, key: &str| json!({"at": at, "op": "insert", "key": key, "docs": [DOC]});
    let rows = [row(1, &g.own_key()), row(2, &"ff".repeat(32)), row(3, "bare"), lost_row()];
    let mut spelled: std::collections::BTreeSet<&str> = g.holds.hands_of(&g.session, &rows).iter().map(|hand| hand.key).collect();
    spelled.extend([Hand::UNREAD.key, Hand::UNKNOWABLE.key]);
    let declarations = crate::shapes::declarations();
    let line = declarations.lines().find(|l| l.starts_with("export type HandKey")).expect("`HandKey` is declared");
    let declared: std::collections::BTreeSet<&str> = line.split('\'').skip(1).step_by(2).collect();
    assert_eq!(spelled, declared, "{line}");
}

/// The two acts are the declared `Resolve.act` union's words, each naming
/// its act, and no other spelling names one (the mutant that reads a near
/// spelling as an act drops a run the page never asked to drop).
#[test]
fn the_two_acts_are_the_declared_words_and_no_other() {
    let declared = crate::shapes::shape("Resolve").unwrap().fields.iter().find(|f| f.name == "act").unwrap().ty;
    let named: Vec<Option<ResolveAct>> = declared.split(" | ").map(|word| ResolveAct::named(word.trim_matches('\''))).collect();
    assert_eq!(named, [Some(ResolveAct::Drop), Some(ResolveAct::Send)], "{declared}");
    for other in ["dropp", "Drop", "", "send "] {
        assert_eq!(ResolveAct::named(other), None, "{other:?}");
    }
}

/// Checks that a board's state is the most severe that holds (§4b.2; P37).
///
/// Every combination of the own node stopped, the board silent, its writes
/// halted and its head unreadable reads as the first of those that holds,
/// else `running`, `reason` beside `head_unreadable` alone; a request of the
/// hold's unanswered, its verdict pending, is no silence yet (skep #865; the
/// mutant that orders the halt below the head says `head_unreadable` while
/// the head is not even read, and the one that reads a pending request as
/// silence flickers `unreachable` over a board that answers).
#[test]
fn a_boards_state_is_the_most_severe_that_holds() {
    let g = ground();
    let mut hold = g.holds.lock("b-1");
    for cell in 0..16u8 {
        let (stopped, silent, halted, unreadable) = (cell & 1 != 0, cell & 2 != 0, cell & 4 != 0, cell & 8 != 0);
        hold.node_stopped = stopped;
        hold.answering = if silent { Answering::Silent { since: Instant::now() } } else { Answering::Answers };
        hold.writes_halted = halted;
        hold.head = if unreadable { HeadState::Unreadable("why".into()) } else { HeadState::Reads };
        let want = if stopped {
            "stopped"
        } else if silent {
            "unreachable"
        } else if halted {
            "halted"
        } else if unreadable {
            "head_unreadable"
        } else {
            "running"
        };
        let state = hold.state();
        assert_eq!((state.as_str(), state.reason()), (want, (want == "head_unreadable").then_some("why")), "stopped {stopped}, silent {silent}, halted {halted}, unreadable {unreadable}");
    }
    (hold.node_stopped, hold.writes_halted, hold.head) = (false, false, HeadState::Reads);
    hold.answering = Answering::Unanswered { since: Instant::now(), cut: Vec::new() };
    assert_eq!(hold.state(), BoardState::Running, "a request unanswered, its verdict pending, is no silence yet");
}

/// The five board states are the declared unions' words, each spelled as the
/// `daemon` event and `probe()` carry it (the mutant that misspells one tells
/// the page a state it cannot draw).
#[test]
fn the_board_states_are_the_declared_five() {
    let states = [BoardState::Stopped, BoardState::Unreachable, BoardState::Halted, BoardState::HeadUnreadable("why".into()), BoardState::Running];
    let spelled: std::collections::BTreeSet<String> = states.iter().map(|s| format!("'{}'", s.as_str())).collect();
    for (shape, member) in [("DaemonEvent", "state"), ("Probe", "daemon")] {
        let declared = crate::shapes::shape(shape).unwrap().fields.iter().find(|f| f.name == member).unwrap().ty;
        let words: std::collections::BTreeSet<String> = declared.split(" | ").map(str::to_string).collect();
        assert_eq!((spelled.len(), spelled.clone()), (5, words), "{shape}.{member}: {declared}");
    }
}

/// A lost answer the fake's `/op` gives a send it recorded.
#[derive(Debug, Clone, Copy)]
enum Lost {
    /// The answer does not come in time: `DialError::Timeout`.
    Timeout,
    /// A `200` whose body is no JSON, as a proxy's page is: the client's
    /// `DialError::Response`.
    Garbled,
}

/// An answer armed at the fake's `/op`: given to every send, or to the
/// next `n` alone.
struct Armed<T>(Mutex<Option<(T, Option<usize>)>>);

impl<T: Clone> Armed<T> {
    fn none() -> Armed<T> {
        Armed(Mutex::new(None))
    }

    /// `answer` given to every send from now on.
    fn every(&self, answer: T) {
        *self.0.lock().unwrap() = Some((answer, None));
    }

    /// `answer` given to the next `n` sends alone.
    fn next(&self, n: usize, answer: T) {
        *self.0.lock().unwrap() = Some((answer, Some(n)));
    }

    /// Nothing armed.
    fn clear(&self) {
        *self.0.lock().unwrap() = None;
    }

    /// The answer armed for this send, where one is — one fewer left.
    fn take(&self) -> Option<T> {
        let mut armed = self.0.lock().unwrap();
        let (answer, left) = armed.as_mut()?;
        let answer = answer.clone();
        let spent = left.as_mut().is_some_and(|n| {
            *n -= 1;
            *n == 0
        });
        if spent {
            *armed = None;
        }
        Some(answer)
    }
}

/// A board under test, its every answer armed or recorded.
///
/// It holds the chain `board_term` reads — or no `H.1` at all, where one is
/// armed missing; the death signal, where its read is armed closed; an answer
/// lost on the way, where it is armed unanswered; a garbled answer, no JSON or
/// past the cap, where it is armed so; or the answer armed in its place, a
/// record that cannot be read among them — the reads of it counted — and
/// whether `/health` names a claimant, as it does unless armed unclaimed, and
/// answers at all, as it does unless armed unanswered, and the position it
/// names, as a cell sets it. It answers the `find_links_ftt` reads of a label
/// read, counted, with no link, or with the answer armed in its place. It
/// holds the `/changes`
/// rows the read sees, each served only past the query's `since` and at or
/// under its `under`, or a refusal armed in the page's place — the page
/// budget's for the next few reads among them — or the death signal where every
/// read is armed closed, or no answer where every read is armed unanswered, and
/// the reads of them counted, a look the cell takes once as the next reaches
/// the board; the draft's text, of which a `retrieve_v` answers
/// the positions it names — or no answer, the death signal, or one position
/// more than it names, where the site is armed so; the draft's content image,
/// of which an `image` answers the runs its region covers, clipped as the board
/// clips them — or no answer, the death signal, or a refusal, where the read is
/// armed so — the reads of it counted, a look the cell takes as each reaches
/// the board, and each answered at the board's position; the position each
/// document's arrangement last changed at, as a cell sets it, a burst typed
/// below it refused `arrangement_moved` naming both; the frames POSTed to `/op`
/// recorded, a look the cell takes as each is recorded, the n-th one's answer
/// lost on the way where one is armed lost, and the death signal, a scripted
/// rejection or a non-200 answered where one is armed — to every send, or to
/// the next few alone, the death first and the non-200 next — and an insert's
/// ack naming the address its words were minted at where a cell arms the fake
/// to mint; an `/op-at` `image` answering the draft's image at the position
/// asked, each asked position recorded, or no answer, a refusal or the runs a
/// cell arms in its place; the `/health`
/// reads counted, one armed to panic once, and each held at a gate while it is
/// shut; and its `/events` stream, none, a commit a millisecond without end
/// where a cell arms one, or a live stream that says nothing where a cell arms
/// that.
struct Fake {
    chain: String,
    no_head: AtomicBool,
    head_closed: AtomicBool,
    head_unreachable: AtomicBool,
    /// The head record's read answered a `200` whose body is no JSON, as a
    /// proxy's page is: the client's `DialError::Response`, a garbled answer
    /// (skep #728).
    head_garbled: AtomicBool,
    /// The head record's read answered past the client's answer cap:
    /// `DialError::TooLarge`, a garbled answer too (skep #728).
    head_too_large: AtomicBool,
    /// The head record's reads made, whatever each answered.
    head_reads: AtomicUsize,
    /// The answer armed for the head record's read, in the record's place.
    ///
    /// It is a status and its body, a `200`'s body the document served.
    head_answer: Mutex<Option<(u16, Value)>>,
    /// Whether `/health` names no claimant: a board no one has claimed.
    unclaimed: AtomicBool,
    /// Every `/health` read goes unanswered: the board's silence.
    ///
    /// Each read answers `DialError::Timeout`.
    health_unanswered: AtomicBool,
    rows: Mutex<Vec<Value>>,
    changes_refused: Mutex<Option<(u16, Value)>>,
    /// The page budget's refusal armed for the next `/changes` reads: `400
    /// malformed_changes` naming the `fits` armed, the page then served at
    /// the limit re-asked.
    changes_too_large: Armed<u64>,
    /// Every `/changes` read answers the death signal.
    changes_closed: AtomicBool,
    /// Every `/changes` read goes unanswered (`DialError::Timeout`).
    changes_unanswered: AtomicBool,
    /// The `/changes` reads made, a page or a refusal answered alike.
    changes_reads: AtomicUsize,
    /// A look taken once, as the next `/changes` read reaches the board.
    ///
    /// It runs before the read answers: an act of the person's while a read
    /// is out.
    at_changes: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    text: Mutex<String>,
    site_unread: AtomicBool,
    site_closed: AtomicBool,
    over_deliver: AtomicBool,
    /// The draft's content image: its runs in V-order from the first
    /// position, each `{i_start, width}` as the board answers one.
    image: Mutex<Vec<Value>>,
    /// Every `image` read fails at the connect: no image is read.
    image_unread: AtomicBool,
    /// Every `image` read answers the death signal.
    image_closed: AtomicBool,
    /// Every `image` read is refused `image_too_large`.
    ///
    /// It is an answer that carries no image.
    image_refused: AtomicBool,
    /// A look the cell takes as an `image` read reaches the board, before it
    /// answers: a burst sent while the shift reads.
    at_image: Mutex<Option<Box<dyn Fn() + Send>>>,
    /// The `image` reads made.
    image_reads: AtomicUsize,
    /// The position each document's arrangement last changed at, as a cell
    /// sets it (`move_arrangement`): a burst typed below it is refused
    /// `arrangement_moved`. The fake's own acks move nothing, so every frame
    /// typed at the fake's head meets no refusal.
    arrangement: Mutex<HashMap<String, u64>>,
    sends: Mutex<Vec<Value>>,
    /// A look the cell takes as `/op` records a send, before it answers.
    ///
    /// It reads the held file as the dial leaves, or moves the file out of
    /// the way of what follows the answer.
    at_send: Mutex<Option<Box<dyn Fn() + Send>>>,
    op_closed: AtomicBool,
    /// Every `/op` dial fails at the connect: the board is not answering,
    /// and no request leaves.
    op_unreachable: AtomicBool,
    /// The ordinal, from 1, of the frame POSTed to `/op` whose answer is lost.
    ///
    /// The frame is recorded, then answered no answer (`DialError::Io`): a
    /// write that may have landed. It is 0 where none is armed lost.
    op_lost_at: AtomicUsize,
    /// A lost answer armed for the sends `/op` records: each recorded, then
    /// answered with the loss armed.
    op_lost: Armed<Lost>,
    op_rejected: Armed<Value>,
    op_refused: Armed<(u16, Value)>,
    next_at: AtomicU64,
    /// The `find_links_ftt` reads made: a label read's, the fake's only.
    links_reads: AtomicUsize,
    /// The answer armed for a `find_links_ftt` read, in the empty one's place.
    links_answer: Armed<Response>,
    writes_halted: AtomicBool,
    /// The position `/health` names.
    log_position: AtomicU64,
    panic_next_health: AtomicBool,
    health_reads: AtomicUsize,
    health_gate: (Mutex<bool>, Condvar),
    /// Whether `/events` serves a commit a millisecond, endlessly, as a
    /// board another writer keeps busy does; it serves no stream otherwise.
    commits: AtomicBool,
    /// Whether `/events` serves a live stream that says nothing, as a board
    /// no one writes to does.
    quiet_stream: AtomicBool,
    /// How long each `/changes` read takes, in milliseconds, as across a
    /// network.
    changes_delay_ms: AtomicU64,
    /// Whether an insert's ack names the first I-address its words were
    /// minted at (`ack_addr`, A-63), as the board's does, the fake minting
    /// in the document's own content I-space from `next_i` on.
    minting: AtomicBool,
    /// The I-ordinal the next insert the fake mints takes its first.
    next_i: AtomicU64,
    /// The position each `/op-at` read asked, in order.
    at_reads: Mutex<Vec<u64>>,
    /// Every `/op-at` read goes unanswered (`DialError::Timeout`).
    at_unanswered: AtomicBool,
    /// A refusal armed for every `/op-at` read, in its answer's place: a
    /// status and its body.
    at_refused: Mutex<Option<(u16, Value)>>,
    /// The runs every `/op-at` `image` answers, as armed, in the image's
    /// place.
    at_runs: Mutex<Option<Vec<Value>>>,
}

impl Fake {
    fn new() -> Arc<Fake> {
        Fake::on_chain(&"ab".repeat(32))
    }

    /// A board whose `H.1` names `chain`.
    fn on_chain(chain: &str) -> Arc<Fake> {
        Arc::new(Fake {
            chain: chain.to_string(),
            no_head: AtomicBool::new(false),
            head_closed: AtomicBool::new(false),
            head_unreachable: AtomicBool::new(false),
            head_garbled: AtomicBool::new(false),
            head_too_large: AtomicBool::new(false),
            head_reads: AtomicUsize::new(0),
            head_answer: Mutex::new(None),
            unclaimed: AtomicBool::new(false),
            health_unanswered: AtomicBool::new(false),
            rows: Mutex::new(Vec::new()),
            changes_refused: Mutex::new(None),
            changes_too_large: Armed::none(),
            changes_closed: AtomicBool::new(false),
            changes_unanswered: AtomicBool::new(false),
            changes_reads: AtomicUsize::new(0),
            at_changes: Mutex::new(None),
            text: Mutex::new(String::new()),
            site_unread: AtomicBool::new(false),
            site_closed: AtomicBool::new(false),
            over_deliver: AtomicBool::new(false),
            image: Mutex::new(Vec::new()),
            image_unread: AtomicBool::new(false),
            image_closed: AtomicBool::new(false),
            image_refused: AtomicBool::new(false),
            at_image: Mutex::new(None),
            image_reads: AtomicUsize::new(0),
            arrangement: Mutex::new(HashMap::new()),
            sends: Mutex::new(Vec::new()),
            at_send: Mutex::new(None),
            op_closed: AtomicBool::new(false),
            op_unreachable: AtomicBool::new(false),
            op_lost_at: AtomicUsize::new(0),
            op_lost: Armed::none(),
            op_rejected: Armed::none(),
            op_refused: Armed::none(),
            next_at: AtomicU64::new(50),
            links_reads: AtomicUsize::new(0),
            links_answer: Armed::none(),
            writes_halted: AtomicBool::new(false),
            log_position: AtomicU64::new(10),
            panic_next_health: AtomicBool::new(false),
            health_reads: AtomicUsize::new(0),
            health_gate: (Mutex::new(false), Condvar::new()),
            commits: AtomicBool::new(false),
            quiet_stream: AtomicBool::new(false),
            changes_delay_ms: AtomicU64::new(0),
            minting: AtomicBool::new(false),
            next_i: AtomicU64::new(100),
            at_reads: Mutex::new(Vec::new()),
            at_unanswered: AtomicBool::new(false),
            at_refused: Mutex::new(None),
            at_runs: Mutex::new(None),
        })
    }

    fn sends(&self) -> usize {
        self.sends.lock().unwrap().len()
    }

    /// The board's head as the fake stands: the `at` of its last ack, the
    /// state a burst built now is typed against (`as_of`, wire.md
    /// §Arrangement; skep #442). The fake judges a burst's `as_of` against
    /// the position a cell set its document's arrangement at
    /// (`move_arrangement`) alone — never against its own acks — so every
    /// frame the suites build at the head is the wire's frame, member and
    /// all, and meets no refusal.
    fn head(&self) -> u64 {
        self.next_at.load(Ordering::SeqCst) - 1
    }

    /// Sets the position `doc`'s arrangement last changed at: a burst on it
    /// typed against an older state is refused `arrangement_moved` from now.
    fn move_arrangement(&self, doc: &str, at: u64) {
        self.arrangement.lock().unwrap().insert(doc.to_string(), at);
    }

    /// The position a read answers in its `as_of`: the board's head, past
    /// every arrangement change a cell set.
    fn read_as_of(&self) -> u64 {
        self.arrangement.lock().unwrap().values().copied().fold(self.head(), u64::max)
    }

    /// The image's runs clipped to the region `width` positions from `from`,
    /// as the board clips an `image` to the arrangement: a run the window
    /// cuts answered from its first position inside, a window past the
    /// arrangement answering what the arrangement holds.
    fn image_runs(&self, from: u64, width: u64) -> Vec<Value> {
        let (lo, hi) = (from, from.saturating_add(width));
        let mut v = 1u64;
        let mut runs = Vec::new();
        for run in self.image.lock().unwrap().iter() {
            let (prefix, first) = run["i_start"].as_str().and_then(|s| s.rsplit_once('.')).map(|(p, n)| (p.to_string(), n.parse::<u64>().unwrap())).unwrap();
            let w: u64 = run["width"].as_str().unwrap().parse().unwrap();
            let (run_lo, run_hi) = (v.max(lo), (v + w).min(hi));
            if run_lo < run_hi {
                runs.push(json!({"i_start": format!("{prefix}.{}", first + (run_lo - v)), "width": (run_hi - run_lo).to_string()}));
            }
            v += w;
        }
        runs
    }

    /// The `/health` gate shut: each read waits there until it opens.
    fn shut_health(&self) {
        *self.health_gate.0.lock().unwrap() = true;
    }

    /// The `/health` gate opened, every read waiting at it let through.
    fn open_health(&self) {
        *self.health_gate.0.lock().unwrap() = false;
        self.health_gate.1.notify_all();
    }
}

fn respond(status: u16, v: Value) -> Response {
    Response { status, headers: Headers::default(), body: v.to_string().into_bytes() }
}

fn ok(v: Value) -> Response {
    respond(200, v)
}

/// The death signal: an answer whose `Skepd-Session` says `closed`.
fn closed() -> Response {
    Response { status: 200, headers: Headers(vec![("Skepd-Session".into(), "closed".into())]), body: Vec::new() }
}

/// The text a query names under `key`, where it names one.
fn query_text<'p>(path: &'p str, key: &str) -> Option<&'p str> {
    path.split_once('?')?.1.split('&').find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
}

/// The number a query names under `key`, where it names one.
fn query(path: &str, key: &str) -> Option<u64> {
    query_text(path, key)?.parse().ok()
}

/// Whether a row passes a read's `under` (wire.md §The change feed): every
/// row where the read names none; a row naming a document at or under it;
/// and a row whose testimony was lost (`docs` null), which this board places
/// on every document.
fn names_under(row: &Value, under: Option<&str>) -> bool {
    let (Some(under), Some(docs)) = (under, row["docs"].as_array()) else { return true };
    docs.iter().filter_map(Value::as_str).any(|doc| doc.strip_prefix(under).is_some_and(|rest| rest.is_empty() || rest.starts_with('.')))
}

/// A V-spec's `1.<from>` and `0.<width>`, as numbers.
fn span(spec: &Value) -> Option<(usize, usize)> {
    let from = spec["span"]["start"].as_str()?.strip_prefix("1.")?.parse().ok()?;
    let width = spec["span"]["width"].as_str()?.strip_prefix("0.")?.parse().ok()?;
    Some((from, width))
}

impl Dialer for Fake {
    fn exchange(&self, _origin: &Origin, req: &Request) -> Result<Response, DialError> {
        if req.method == Method::Get && req.path.starts_with("/health") {
            self.health_reads.fetch_add(1, Ordering::SeqCst);
            // The gate's guard is dropped before the armed panic, which would
            // otherwise poison the gate for every later read.
            let (gate, opened) = &self.health_gate;
            drop(opened.wait_while(gate.lock().unwrap(), |shut| *shut).unwrap());
            assert!(!self.panic_next_health.swap(false, Ordering::SeqCst), "the health read is made to panic");
            if self.health_unanswered.load(Ordering::SeqCst) {
                return Err(DialError::Timeout("the board takes the read and sends nothing".into()));
            }
            let halted = self.writes_halted.load(Ordering::SeqCst);
            let claimant = if self.unclaimed.load(Ordering::SeqCst) { Value::Null } else { Value::from("1.0.1") };
            let log_position = self.log_position.load(Ordering::SeqCst);
            return Ok(ok(
                json!({"ok": true, "log_position": log_position, "chain_head": self.chain, "auth": {"claimant": claimant, "local_trust": true, "origins": [], "signed_origins": []}, "media": {"uploads": true}, "head_time": 1, "writes": {"halted": halted}}),
            ));
        }
        if req.method == Method::Get && req.path.starts_with("/changes") {
            self.changes_reads.fetch_add(1, Ordering::SeqCst);
            let look = self.at_changes.lock().unwrap().take();
            if let Some(look) = look {
                look();
            }
            thread::sleep(Duration::from_millis(self.changes_delay_ms.load(Ordering::SeqCst)));
            if self.changes_closed.load(Ordering::SeqCst) {
                return Ok(closed());
            }
            if self.changes_unanswered.load(Ordering::SeqCst) {
                return Err(DialError::Timeout("the board takes the read and sends nothing".into()));
            }
            if let Some((status, body)) = self.changes_refused.lock().unwrap().clone() {
                return Ok(respond(status, body));
            }
            if let Some(fits) = self.changes_too_large.take() {
                return Ok(respond(400, json!({"error": "malformed_changes", "fits": fits})));
            }
            let since = query(&req.path, "since").unwrap_or(0);
            let limit = query(&req.path, "limit").unwrap_or(256) as usize;
            let under = query_text(&req.path, "under");
            let past: Vec<Value> = self.rows.lock().unwrap().iter().filter(|r| r["at"].as_u64().unwrap_or(0) > since && names_under(r, under)).cloned().collect();
            let page: Vec<Value> = past.iter().take(limit).cloned().collect();
            let last = page.last().and_then(|r| r["at"].as_u64()).unwrap_or(since);
            return Ok(ok(json!({"changes": page, "last": last, "more": past.len() > limit})));
        }
        if req.method == Method::Post && req.path == "/op" {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            if body["op"].as_str() == Some("find_links_ftt") {
                self.links_reads.fetch_add(1, Ordering::SeqCst);
                return Ok(self.links_answer.take().unwrap_or_else(|| ok(json!({"resp": "addrs", "addrs": [], "as_of": 10}))));
            }
            if body["op"].as_str() == Some("image") {
                self.image_reads.fetch_add(1, Ordering::SeqCst);
                if let Some(look) = self.at_image.lock().unwrap().as_ref() {
                    look();
                }
                if self.image_unread.load(Ordering::SeqCst) {
                    return Err(DialError::Connect("the image read is not answered".into()));
                }
                if self.image_closed.load(Ordering::SeqCst) {
                    return Ok(closed());
                }
                if self.image_refused.load(Ordering::SeqCst) {
                    return Ok(ok(json!({"resp": "rejected", "code": "image_too_large", "disposition": "permanent", "op": "image"})));
                }
                let region = &body["region"][0];
                let from = region["start"].as_str().and_then(|s| s.strip_prefix("1.")).and_then(|s| s.parse().ok()).unwrap_or(1);
                let width = region["width"].as_str().and_then(|s| s.strip_prefix("0.")).and_then(|s| s.parse().ok()).unwrap_or(0);
                return Ok(ok(json!({"resp": "runs", "runs": self.image_runs(from, width), "as_of": self.read_as_of()})));
            }
            if body["op"].as_str() == Some("retrieve_v") {
                if body["specs"][0]["doc"].as_str() == Some(HEAD_MEMBER_1) {
                    self.head_reads.fetch_add(1, Ordering::SeqCst);
                    if self.head_closed.load(Ordering::SeqCst) {
                        return Ok(closed());
                    }
                    if self.head_unreachable.load(Ordering::SeqCst) {
                        return Err(DialError::Io("the head read's answer was lost".into()));
                    }
                    if self.head_garbled.load(Ordering::SeqCst) {
                        return Ok(Response { status: 200, headers: Headers::default(), body: b"<html>a proxy's page</html>".to_vec() });
                    }
                    if self.head_too_large.load(Ordering::SeqCst) {
                        return Err(DialError::TooLarge { cap: 1 });
                    }
                    if let Some((status, answer)) = self.head_answer.lock().unwrap().clone() {
                        return Ok(respond(status, answer));
                    }
                    if self.no_head.load(Ordering::SeqCst) {
                        return Ok(ok(json!({"resp": "delivery", "items": []})));
                    }
                    let head = json!({"type": "skep-head", "position": 1, "chain": self.chain}).to_string();
                    return Ok(ok(json!({"resp": "delivery", "items": [{"atom": head}]})));
                }
                if self.site_unread.load(Ordering::SeqCst) {
                    return Err(DialError::Connect("the site read is not answered".into()));
                }
                if self.site_closed.load(Ordering::SeqCst) {
                    return Ok(closed());
                }
                let text = self.text.lock().unwrap().clone();
                let (from, width) = span(&body["specs"][0]).unwrap_or((0, 0));
                let width = width + usize::from(self.over_deliver.load(Ordering::SeqCst));
                return Ok(match text.get(from.saturating_sub(1)..from.saturating_sub(1) + width) {
                    Some(cut) if from > 0 => ok(json!({"resp": "delivery", "items": [{"content": cut}], "as_of": self.read_as_of()})),
                    _ => ok(json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent", "op": "retrieve_v"})),
                });
            }
            if self.op_unreachable.load(Ordering::SeqCst) {
                return Err(DialError::Connect("the board is not answering".into()));
            }
            let sent = {
                let mut sends = self.sends.lock().unwrap();
                sends.push(body.clone());
                sends.len()
            };
            if let Some(look) = self.at_send.lock().unwrap().as_ref() {
                look();
            }
            if sent == self.op_lost_at.load(Ordering::SeqCst) {
                return Err(DialError::Io("the answer was lost on the way".into()));
            }
            if let Some(lost) = self.op_lost.take() {
                return match lost {
                    Lost::Timeout => Err(DialError::Timeout("the answer did not come in time".into())),
                    Lost::Garbled => Ok(Response { status: 200, headers: Headers::default(), body: b"<html>a proxy's page</html>".to_vec() }),
                };
            }
            if self.op_closed.load(Ordering::SeqCst) {
                return Ok(closed());
            }
            if let Some((status, refusal)) = self.op_refused.take() {
                return Ok(respond(status, refusal));
            }
            if let Some(r) = self.op_rejected.take() {
                return Ok(ok(r));
            }
            // The typed state (wire.md §Arrangement): a burst typed below
            // the position its document's arrangement last changed at — as a
            // cell set it — is refused, naming both.
            if let (Some(op), Some(doc), Some(typed)) = (body["op"].as_str().filter(|op| BURST_KINDS.contains(op)), body["doc"].as_str(), body["as_of"].as_u64()) {
                if let Some(current) = self.arrangement.lock().unwrap().get(doc).copied().filter(|current| typed < *current) {
                    return Ok(ok(arrangement_moved_on(op, typed, current)));
                }
            }
            let at = self.next_at.fetch_add(1, Ordering::SeqCst);
            if body["op"] == "insert" && self.minting.load(Ordering::SeqCst) {
                let positions = crate::wire::values_of(&body["values"]).map_or(1, |values| values.len() as u64);
                let first = self.next_i.fetch_add(positions, Ordering::SeqCst);
                return Ok(ok(json!({"resp": "ack_addr", "addr": format!("{}.0.1.{first}", body["doc"].as_str().unwrap_or("?")), "at": at})));
            }
            return Ok(ok(json!({"resp": "ack", "at": at})));
        }
        if req.method == Method::Post && req.path == "/op-at" {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let at = body["at"].as_u64().unwrap_or(0);
            self.at_reads.lock().unwrap().push(at);
            if self.at_unanswered.load(Ordering::SeqCst) {
                return Err(DialError::Timeout("the board takes the read and sends nothing".into()));
            }
            if let Some((status, refusal)) = self.at_refused.lock().unwrap().clone() {
                return Ok(respond(status, refusal));
            }
            let region = &body["frame"]["region"][0];
            let from = region["start"].as_str().and_then(|s| s.strip_prefix("1.")).and_then(|s| s.parse().ok()).unwrap_or(1);
            let width = region["width"].as_str().and_then(|s| s.strip_prefix("0.")).and_then(|s| s.parse().ok()).unwrap_or(0);
            let runs = self.at_runs.lock().unwrap().clone().unwrap_or_else(|| self.image_runs(from, width));
            return Ok(ok(json!({"resp": "runs", "runs": runs, "as_of": at})));
        }
        Ok(ok(json!({})))
    }

    fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        if self.commits.load(Ordering::SeqCst) {
            return Ok(StreamedResponse { status: 200, headers: Headers::default(), body: Box::new(EndlessCommits { at: 10 }) });
        }
        if self.quiet_stream.load(Ordering::SeqCst) {
            return Ok(StreamedResponse { status: 200, headers: Headers::default(), body: Box::new(QuietStream) });
        }
        Err(DialError::Connect("no stream here".into()))
    }
}

/// A commit stream that never ends: one `commit` event a millisecond, each a
/// position past the one before.
struct EndlessCommits {
    at: u64,
}

impl Read for EndlessCommits {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        thread::sleep(Duration::from_millis(1));
        self.at += 1;
        let event = format!("event: commit\ndata: {{\"log_position\": {}}}\n\n", self.at);
        let n = event.len().min(buf.len());
        buf[..n].copy_from_slice(&event.as_bytes()[..n]);
        Ok(n)
    }
}

/// A live stream that says nothing: each read waits a moment and times out,
/// as a stream with no commit does, its reader neither ticking nor failing.
struct QuietStream;

impl Read for QuietStream {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        thread::sleep(Duration::from_millis(20));
        Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
    }
}

/// The board's two threads over the ground's holds: the feed thread the
/// shell runs for the ground's board, its `Talk` said nowhere.
fn feed_threads(g: &Ground) -> crate::feed::FeedThreads {
    let talk: Talk = Arc::new(|_: &str| {});
    let shared = crate::feed::Shared { bus: Arc::clone(&g.bus), sessions: Arc::clone(&g.sessions), data_dir: g.store.path().to_path_buf(), talk, holds: Arc::clone(&g.holds) };
    crate::feed::FeedThreads::spawn(Arc::clone(&g.entry), shared)
}

struct NoSupplements;
impl Supplements for NoSupplements {
    fn widen(&mut self, _: &Arc<SessionEntry>) {}
    fn narrow(&mut self, _: u64) {}
}

/// The holds over the fake board, a session registered and its open read as
/// the shell reads it — the ground every resend cell stands on; every line
/// the hold says on TALK, in order; the store directory kept for the ground's
/// life; and the board's entry, the session table and the bus, which a cell
/// hands the board's feed thread to run over the same holds.
struct Ground {
    holds: Arc<Holds>,
    fake: Arc<Fake>,
    session: Arc<SessionEntry>,
    rx: Receiver<Event>,
    said: Arc<Mutex<Vec<String>>>,
    store: TempDir,
    entry: Arc<BoardEntry>,
    sessions: Arc<Sessions>,
    bus: Arc<EventBus>,
}

/// A `held` event held to its declaration (`shapes`' `HeldEvent`): every
/// required member present, none outside the table, `session` a
/// reference — never null, as the declared type says — and each line its
/// `landed` names held to `LandedLine`'s.
fn assert_held_event_declared(event: &Value) {
    crate::shapes::assert_declared("HeldEvent", event);
    let shape = crate::shapes::shape("HeldEvent").expect("HeldEvent is declared");
    let session = shape.fields.iter().find(|f| f.name == "session").expect("`session` is declared");
    assert!(session.required && !session.ty.contains("null") && event["session"].is_string(), "{event}: the session is named, never null");
    if let Some(landed) = event.get("landed") {
        let entries = landed.as_array().unwrap_or_else(|| panic!("{event}: `landed` is a list"));
        entries.iter().for_each(|entry| crate::shapes::assert_declared("LandedLine", entry));
    }
}

impl Ground {
    /// The `held` event states seen since the last look, each event held to
    /// its declaration.
    fn states(&self) -> Vec<String> {
        self.rx
            .try_iter()
            .filter(|e| e.name == EventName::Held)
            .map(|e| {
                assert_held_event_declared(&e.data);
                e.data["state"].as_str().unwrap_or("?").to_string()
            })
            .collect()
    }

    /// `held(session)`'s lines, each held to its declaration (`HeldRow`).
    fn lines(&self) -> Vec<Value> {
        let lines = self.holds.lines(&self.session).unwrap().as_array().unwrap().clone();
        for line in &lines {
            crate::shapes::assert_declared("HeldRow", line);
        }
        lines
    }

    /// `frame` admitted at the ground's session — a test's own frame, which
    /// the burst's door lets in.
    fn burst(&self, frame: &Value) -> Burst {
        Burst::admit(frame.clone(), &self.session).unwrap()
    }

    /// A burst held for `cause`, `sent` as a lost answer's would be: the
    /// `held` answer, held to its declaration (`HeldAnswer`).
    fn hold(&self, frame: &Value, cause: &str, sent: bool) -> Value {
        let answer = self.hold_for(frame, Reason::of(cause, sent)).unwrap();
        crate::shapes::assert_declared("HeldAnswer", &answer);
        answer
    }

    /// A burst held for `reason` through the hold's own door, at the base a
    /// hold on its document takes now — as a dial's answer holds it, no dial
    /// between, the failed send the reason says (`failed_send`) its clock's
    /// start: the `held` answer, or the hold's refusal, no death armed.
    fn hold_for(&self, frame: &Value, reason: Reason) -> Result<Value, Refusal> {
        let burst = self.burst(frame);
        let base = self.base_of(&burst.doc);
        let failed = failed_send(&reason).map(str::to_owned);
        self.holds.hold(&self.session, burst, reason, failed, base).answered()
    }

    /// A burst carrying `anchors` held for `cause`, `sent` as a lost answer's
    /// would be — the page's burst, which the shift can move: the `held`
    /// answer, held to its declaration.
    fn hold_anchored(&self, frame: &Value, anchors: Anchors, cause: &str, sent: bool) -> Value {
        let burst = self.burst(frame).with_anchors(Some(anchors));
        let base = self.base_of(&burst.doc);
        let reason = Reason::of(cause, sent);
        let failed = failed_send(&reason).map(str::to_owned);
        let answer = self.holds.hold(&self.session, burst, reason, failed, base).answered().unwrap();
        crate::shapes::assert_declared("HeldAnswer", &answer);
        answer
    }

    /// The base a line held on `doc` under the ground's session takes now
    /// (§3c.2): its principal's latest acked write there, else the session's
    /// open.
    fn base_of(&self, doc: &str) -> u64 {
        let (board, principal, opened_at) = (self.session.board_reference.as_str(), self.session.facts.principal, self.session.opened_at);
        self.holds.with_principal(board, principal, |ph| ph.base_of(doc, opened_at)).unwrap_or(opened_at)
    }

    /// The session's own hand as a `/changes` row's `key` names it (wire.md
    /// §`/changes`): its key's fingerprint, or `bare`.
    fn own_key(&self) -> String {
        match &self.session.facts.kind {
            SessionKind::Signed { fingerprint, .. } => fingerprint.to_hex(),
            SessionKind::Bare => "bare".to_string(),
        }
    }
}

impl Resolved {
    /// Returns a drop's answer naming the lines `may_have_landed`.
    fn dropped(may_have_landed: &[u64]) -> Resolved {
        Resolved::Dropped { may_have_landed: may_have_landed.to_vec() }
    }
}

/// The facts of a bare session as principal 1: the keyless session, which
/// reads alone.
fn bare_facts() -> Facts {
    Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare }
}

/// The facts of a session that holds a key — the signed mode's, its set the
/// account's own — its key in no store, for the cells that sign nothing.
fn keyed_facts() -> Facts {
    let fingerprint = skep_identity::Fingerprint::parse_hex(&"5a".repeat(32)).unwrap();
    Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Signed { fingerprint, set_account: "1.0.1".into() } }
}

/// The facts of a writer as `principal`, acting as `account`: a signed
/// session under a key generated into the key store under `store`, its set
/// the account's own — a session that may write (`SessionEntry::may_write`),
/// whose every write of the checked set the composer attests.
fn writer_facts_as(store: &TempDir, principal: u64, account: &str) -> Facts {
    let KeyId(fingerprint) = FileStore::open(store.path().join("store")).generate(None).unwrap();
    Facts { principal, account: Some(account.into()), kind: SessionKind::Signed { fingerprint, set_account: account.into() } }
}

/// The facts of the ground's writer: principal 1, acting as `1.0.1`.
fn writer_facts(store: &TempDir) -> Facts {
    writer_facts_as(store, 1, "1.0.1")
}

/// The ground under a writer opened at position 0.
fn ground() -> Ground {
    writer_at(0)
}

/// The ground under a writer opened at `opened_at`.
fn writer_at(opened_at: u64) -> Ground {
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    ground_in(store, facts, opened_at)
}

/// The ground under a bare session opened at position 0: the keyless
/// session, which reads alone, so no probe resends a line it holds.
fn bare_ground() -> Ground {
    ground_in(TempDir::new().unwrap(), bare_facts(), 0)
}

/// The ground over `store`, under a session of `facts` opened at `opened_at`.
fn ground_in(store: TempDir, facts: Facts, opened_at: u64) -> Ground {
    ground_over(Fake::new(), store, facts, opened_at)
}

/// The ground over `fake` — armed before the session opens and the holds
/// read its `H.1` — and `store`, under a session of `facts` opened at
/// `opened_at`.
fn ground_over(fake: Arc<Fake>, store: TempDir, facts: Facts, opened_at: u64) -> Ground {
    let entry = Arc::new(BoardEntry { reference: "b-1".into(), board: Arc::new(Board::new(Origin::parse("http://127.0.0.1:1").unwrap(), Arc::clone(&fake))) });
    let sessions = Arc::new(Sessions::new(None, Arc::new(|_: &str| {})));
    let bus = Arc::new(EventBus::new());
    let rx = bus.subscribe();
    let keys = Arc::new(FileStore::open(store.path().join("store")));
    let said = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&said);
    let talk: Talk = Arc::new(move |line: &str| kept.lock().unwrap().push(line.to_string()));
    let holds = Holds::new(Arc::clone(&sessions), Arc::clone(&bus), keys, store.path().to_path_buf(), talk, [Arc::clone(&entry)]);
    let open = Open { token: Token::parse(&"9f".repeat(16)).unwrap(), facts, opened_at };
    let session = sessions.register(&entry, open, &mut NoSupplements);
    holds.open_session(&session);
    Ground { holds, fake, session, rx, said, store, entry, sessions, bus }
}

/// The ground under a writer at a board no one has claimed, which serves no
/// head record, over a store the device refuses — `held/` sealed, so no
/// held directory can be made under it: its lines held in memory alone,
/// every copy owed, the one memory case left (§3c.3), and none owing an
/// attest — the drain's walk at the speed of its own bookkeeping, no copy
/// synced.
fn unclaimed_ground() -> Ground {
    let fake = Fake::new();
    fake.no_head.store(true, Ordering::SeqCst);
    fake.unclaimed.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let held = store.path().join("held");
    std::fs::create_dir(&held).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&held, std::fs::Permissions::from_mode(0o500)).unwrap();
    }
    let facts = writer_facts(&store);
    ground_over(fake, store, facts, 0)
}

/// An `insert` of `values` at the document's first position, typed against
/// `as_of` (wire.md §Arrangement, the typed state): the fake board's head
/// as the cell read it (`Fake::head`), which is what a page holding the
/// board's text at that state sends.
fn insert(doc: &str, values: Value, as_of: u64) -> Value {
    json!({"op": "insert", "doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": values, "as_of": as_of})
}

/// A `delete` of the document's first position, in the wire's own form
/// (wire.md §Arrangement: `p` and `width`) — a burst whose site no read
/// confirms — typed against `as_of` as [`insert`]'s is.
fn delete(doc: &str, as_of: u64) -> Value {
    json!({"op": "delete", "doc": doc, "p": {"subspace": "1", "ordinal": "1"}, "width": "1", "as_of": as_of})
}

/// The board's refusal of a burst typed against an older state (wire.md
/// §Rejection codes, `arrangement_moved`): `as_of` the state it was typed
/// against, echoed, and `current` the position the document's arrangement
/// last changed at.
fn arrangement_moved(as_of: u64, current: u64) -> Value {
    arrangement_moved_on("insert", as_of, current)
}

/// The board's `arrangement_moved` on a burst of kind `op`.
fn arrangement_moved_on(op: &str, as_of: u64, current: u64) -> Value {
    json!({"resp": "rejected", "op": op, "code": "arrangement_moved", "disposition": "permanent", "site": {"as_of": as_of, "current": current}})
}

/// An `insert` of `values` at the document's position `at`, typed against
/// `as_of`.
fn insert_at(doc: &str, at: u64, values: Value, as_of: u64) -> Value {
    json!({"op": "insert", "doc": doc, "at": {"subspace": "1", "ordinal": at.to_string()}, "values": values, "as_of": as_of})
}

/// A `delete` of `width` positions from the document's position `p`, typed
/// against `as_of`.
fn delete_at(doc: &str, p: u64, width: u64, as_of: u64) -> Value {
    json!({"op": "delete", "doc": doc, "p": {"subspace": "1", "ordinal": p.to_string()}, "width": width.to_string(), "as_of": as_of})
}

/// A `copy` of the other document's first position into `doc` at `at`,
/// typed against `as_of`.
fn copy_at(doc: &str, at: u64, as_of: u64) -> Value {
    json!({"op": "copy", "doc": doc, "at": {"subspace": "1", "ordinal": at.to_string()}, "specs": [{"source": OTHER, "span": {"start": "1.1", "width": "0.1"}}], "as_of": as_of})
}

/// A `reinstate` of one run of `doc`'s own ninth I-position into `doc` at
/// `at`, typed against `as_of`.
fn reinstate_at(doc: &str, at: u64, as_of: u64) -> Value {
    json!({"op": "reinstate", "doc": doc, "at": {"subspace": "1", "ordinal": at.to_string()}, "runs": [{"origin": doc, "i_start": i(9), "width": "1"}], "as_of": as_of})
}

/// A `rearrange` of `doc` about `cuts`, typed against `as_of`.
fn rearrange_at(doc: &str, cuts: &[u64], as_of: u64) -> Value {
    let cuts: Vec<Value> = cuts.iter().map(|c| json!({"subspace": "1", "ordinal": c.to_string()})).collect();
    json!({"op": "rearrange", "doc": doc, "cuts": cuts, "as_of": as_of})
}

/// The I-address of `DOC`'s content position `n`, as the board spells one.
fn i(n: u64) -> String {
    format!("{DOC}.0.1.{n}")
}

/// One run of a content image: `width` positions from the I-address
/// `i_start`, as the board answers it.
fn run(i_start: &str, width: u64) -> Value {
    json!({"i_start": i_start, "width": width.to_string()})
}

/// The anchors a page sends: `before` and `after`, each an I-address or none
/// at the document's edge.
fn anchors(before: Option<&str>, after: Option<&str>) -> Anchors {
    Anchors::of(&json!({"before": before, "after": after})).expect("the anchors' form")
}

/// The anchors a page sends for a delete or a rearrange (skep #751).
///
/// They are `before` and `after`, and the span's runs as its `image` read
/// gave them, each `width` units from the I-address `start`.
fn spanned(before: Option<&str>, after: Option<&str>, runs: &[(&str, u64)]) -> Anchors {
    let span: Vec<Value> = runs.iter().map(|(start, width)| json!({"start": start, "width": width.to_string()})).collect();
    Anchors::of(&json!({"before": before, "after": after, "span": span})).expect("the anchors' form")
}

/// A piece of an edge, as a page sends it (skep #969).
///
/// It names the unit `offset` positions into the words of the burst the
/// page sent with the envelope `id` `burst`.
fn piece(burst: &str, offset: u64) -> Value {
    json!({"burst": burst, "offset": offset})
}

/// The anchors a page sends whose edges are `before` and `after`.
///
/// Each is an I-address, a [`piece`] or `null`, read through their one door.
fn pieced(before: Value, after: Value) -> Anchors {
    Anchors::of(&json!({"before": before, "after": after})).expect("the anchors' form")
}

/// `frame` carrying the page's envelope `id` (A-60).
fn with_id(mut frame: Value, id: &str) -> Value {
    frame["id"] = Value::from(id);
    frame
}

/// The anchors of their form whose spelling is exactly `bytes` long, read
/// through their one door (`held::anchors_spelled`).
fn anchors_of_len(bytes: usize) -> Anchors {
    Anchors::of(&crate::held::anchors_spelled(bytes)).expect("the anchors' form")
}

/// The principal's held file under the ground's store, at the fake's chain.
fn held_file(g: &Ground) -> std::path::PathBuf {
    g.store.path().join("held").join("ab".repeat(32)).join("principal-1.held")
}

/// The principal's PENDING held file under the ground's store (§3c.1): under
/// `held/pending/<hash>/`, the hash the SHA-256 of the origin the ground's
/// board dials, as the shell names the directory.
fn pending_file(g: &Ground) -> std::path::PathBuf {
    use sha2::{Digest, Sha256};
    let hash = Chain::from_bytes(Sha256::digest(g.session.board.dialed().as_str().as_bytes()).into());
    g.store.path().join("held").join("pending").join(hash.to_string()).join("principal-1.held")
}

/// The TALK lines the hold said that contain `text`, in order.
fn said_containing(g: &Ground, text: &str) -> Vec<String> {
    g.said.lock().unwrap().iter().filter(|line| line.contains(text)).cloned().collect()
}

/// The states the `another-window` events `rx` holds carry, in order.
///
/// Each event is held to its declaration (`AnotherWindowEvent`) and names
/// the ground's board; every other event `rx` holds is read and dropped.
fn edges(rx: &Receiver<Event>) -> Vec<bool> {
    rx.try_iter()
        .filter(|e| e.name == EventName::AnotherWindow)
        .map(|e| {
            crate::shapes::assert_declared("AnotherWindowEvent", &e.data);
            assert_eq!(e.data["board"], "b-1", "{}", e.data);
            e.data["another_window"].as_bool().unwrap_or_else(|| panic!("the state, a boolean: {}", e.data))
        })
        .collect()
}

/// The `held` lines a held file's text holds, each parsed, in file order.
fn file_lines(text: &str) -> Vec<Value> {
    text.lines().skip(1).filter_map(|line| serde_json::from_str::<Value>(line).ok()).filter(|line| line.get("held").is_some()).collect()
}

/// A `/changes` row whose testimony the board lost (wire.md §`/changes`):
/// every member but its `at` the reserved null.
fn lost_row() -> Value {
    json!({"at": 77, "docs": null, "key": null, "time": null, "op": null, "new_prefix": null, "new_id": null, "link": null, "placed": null, "base_extent": null})
}

const DOC: &str = "1.0.1.0.1";

/// A second document of the session's account.
const OTHER: &str = "1.0.1.0.2";
