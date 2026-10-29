//! THE RETRACTED-LINKS READ over the wire (the link-sets design §7, lane 7;
//! the owner's rulings of 2026-10-28; wire.md §Link discovery reads,
//! `find_links_v_history`): the "as published" switch at a version wants
//! every link that stood on its words while it stood, those retracted since
//! included, each with its own commit position and, where retracted, its
//! retraction's. Every other region read answers the active view, so a
//! retracted link could be found from the words it stood on by no live
//! read; `find_links_v_history {d, region, cur, n}` answers the AUDIT view,
//! windowed over homes as `window_v` is, each row `{a, at, retracted_at}` —
//! the link, the position of the commit that minted it, and the position of
//! its EARLIEST retraction across every home, `null` where it is active.
//!
//! The board: the claimant's published doc 1, holding the ceremony's record
//! atom at content ordinal 1, is the page; links homed in doc 1 FROM that
//! atom are made from the claimant's signed session, retracted by `nullify`
//! from doc 1, from a private draft `D` of the claimant's, and by a
//! publication's `retract` entry. What is asserted is the wire: a link made
//! reads active at its commit's position; retracted from its home, its row
//! carries that commit's position; retracted again from a second home, its
//! row is UNCHANGED (the earliest decides); retracted through a shot, its
//! row carries the shot's position; a window of one resumed past the
//! retracted link lands on the next row (a retracted link is a ROW, never
//! skipped); the read takes the per-document permit and is refused
//! `scan_busy` with the document's sentence; an unreadable `d` answers
//! `withheld`; and a GUEST reading the public page whose link was retracted
//! from the owner's private draft is served the retraction's POSITION and no
//! address of the retraction (ruling B (4); PUB-6.47).

use crate::common;

use common::*;
use serde_json::Value;

/// The ceremony atom: doc 1's one content element, the position every link
/// here touches.
const ATOM: &str = "1.0.1.0.1.0.1.1";

/// An ordinary link type the plain path admits: the registry's `citation`.
const T_CITATION: &str = "1.1.0.1.0.1.0.3.13";

/// The claim ceremony's two links in the claimant's doc 1, whose slots name
/// the account and so touch every region of the claimant's documents: the
/// floor every answer here carries ahead of the page's own links.
const CEREMONY_LINKS: [&str; 2] = ["1.0.1.0.1.0.2.1", "1.0.1.0.1.0.2.2"];

/// The width's refusal sentence, as §Link discovery reads spells it.
const DOCUMENT_BUSY: &str = "all region-read permits of this document are in use; retry shortly";

/// One row: the link, its position, its earliest retraction's.
type Row = (String, Option<u64>, Option<u64>);

/// The read over content ordinal 1 of `doc`, as the wire spells it.
fn frame(doc: &str, cur: Option<&str>, n: u64) -> String {
    let cur = cur.map_or("null".to_string(), |c| format!("\"{c}\""));
    format!(
        r#"{{"cur":{cur},"d":"{doc}","n":{n},"op":"find_links_v_history","region":[{{"start":"1.1","width":"0.1"}}]}}"#
    )
}

/// A `links` answer's rows, its `next` and its `exhausted`.
fn page(v: &Value) -> (Vec<Row>, Option<String>, bool) {
    let r = expect_resp(v, "links");
    let rows = r["links"]
        .as_array()
        .expect("links")
        .iter()
        .map(|row| (row["a"].as_str().expect("a").to_string(), row["at"].as_u64(), row["retracted_at"].as_u64()))
        .collect();
    (rows, r["next"].as_str().map(str::to_string), r["exhausted"].as_bool().expect("exhausted"))
}

/// The whole answer over doc 1's atom as `token`, in one window.
fn rows(port: u16, token: Option<&str>) -> Vec<Row> {
    page(&op(port, token, &frame(CLAIMANT_DOC1, None, 64))).0
}

/// The row for `a` among `rows`.
fn row_of<'r>(rows: &'r [Row], a: &str) -> &'r Row {
    rows.iter().find(|(row, _, _)| row == a).unwrap_or_else(|| panic!("{a} is a row: {rows:?}"))
}

/// The active rows' addresses, in order: what `find_links_v` answers.
fn active(rows: &[Row]) -> Vec<String> {
    rows.iter().filter(|(_, _, r)| r.is_none()).map(|(a, _, _)| a.clone()).collect()
}

/// One link homed in doc 1 FROM the atom, from the signed session: its
/// address and its commit's position.
fn link_from_atom(port: u16, signed: &str) -> (String, u64) {
    let v = op(port, Some(signed), &link_frame(CLAIMANT_DOC1, &addrs_slot(&[ATOM]), &addrs_slot(&[]), &addrs_slot(&[T_CITATION])));
    (acked_addr(&v), acked_at(&v))
}

/// A retraction of `target` homed in `home`, from the signed session: the
/// retraction's address and its commit's position.
fn retract(port: u16, signed: &str, home: &str, target: &str) -> (String, u64) {
    let v = op(port, Some(signed), &nullify_frame(home, target));
    assert_eq!(verdict(&v), "ok", "{v}");
    (acked_addr(&v), acked_at(&v))
}

/// The page's frame with `members` set beside the shot's own.
fn with_members(frame: &str, members: Value) -> String {
    let mut v: Value = serde_json::from_str(frame).expect("a JSON frame");
    for (k, val) in members.as_object().expect("an object of members") {
        v[k] = val.clone();
    }
    v.to_string()
}

/// THE ROWS, end to end: a link made reads active at its commit's position
/// to every class; retracted from its home, its row carries that commit's
/// position and the retraction is an active row of its own; retracted again
/// from the owner's private draft, the row is UNCHANGED — the earliest
/// retraction decides, whatever its home — and the draft's record is no
/// row; a second link retracted ONLY from the draft is served to the GUEST
/// with the retraction's position and no address under the draft, the
/// guest's rows the owner's; a third retracted through a publication's
/// `retract` entry carries the shot's position; at every step the active
/// rows are `find_links_v`'s answer; and a window of one resumed row by row
/// drains the same rows, the retracted links among them.
#[test]
fn the_retracted_links_read_lists_each_link_with_its_earliest_retractions_position() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let floor: Vec<String> = CEREMONY_LINKS.iter().map(|a| a.to_string()).collect();
    let active_is_find_links_v = |token: Option<&str>| {
        assert_eq!(active(&rows(port, token)), find_links_v(port, token, CLAIMANT_DOC1, 1, 1), "the active rows are find_links_v's");
    };

    // Made: active, at its commit, to the guest and the owner alike.
    let (l1, l1_at) = link_from_atom(port, &signed);
    let guests = rows(port, None);
    assert_eq!(guests.iter().map(|(a, _, _)| a.clone()).collect::<Vec<_>>(), [floor.clone(), vec![l1.clone()]].concat());
    assert_eq!(*row_of(&guests, &l1), (l1.clone(), Some(l1_at), None));
    assert!(guests.iter().all(|(_, at, _)| at.is_some()), "every row carries its position: {guests:?}");
    assert_eq!(rows(port, Some(&bare)), guests, "the owner reads the same rows of the public page");
    active_is_find_links_v(None);

    // Retracted from its home: the row carries the retraction's position;
    // the retraction, whose FROM covers doc 1, is an active row of its own.
    let (r1, r1_at) = retract(port, &signed, CLAIMANT_DOC1, &l1);
    let guests = rows(port, None);
    assert_eq!(*row_of(&guests, &l1), (l1.clone(), Some(l1_at), Some(r1_at)), "retracted at the retraction's commit");
    assert_eq!(*row_of(&guests, &r1), (r1.clone(), Some(r1_at), None), "the retraction record, active");
    assert!(!find_links_v(port, None, CLAIMANT_DOC1, 1, 1).contains(&l1), "off the active read");
    active_is_find_links_v(None);

    // Retracted again, from the owner's private draft: a distinct record, a
    // later position — and the row UNCHANGED: the earliest decides.
    let draft = owner_draft(port, &bare);
    let (r2, r2_at) = retract(port, &signed, &draft, &l1);
    assert!(r2_at > r1_at && r2 != r1);
    assert!(r2.starts_with(&format!("{draft}.")), "homed in the draft");
    for token in [None, Some(bare.as_str())] {
        let seen = rows(port, token);
        assert_eq!(*row_of(&seen, &l1), (l1.clone(), Some(l1_at), Some(r1_at)), "the earliest retraction decides, whatever its home");
        assert!(seen.iter().all(|(a, _, _)| *a != r2), "the draft-homed record touches nothing of doc 1's content");
    }

    // The GUEST's row for a link retracted ONLY from the draft (ruling B
    // (4)): the position crosses, class-invariant; no address under the
    // draft leaves the read; the owner's rows are the guest's.
    let (l2, l2_at) = link_from_atom(port, &signed);
    let (r3, r3_at) = retract(port, &signed, &draft, &l2);
    assert!(r3.starts_with(&format!("{draft}.")));
    let guests = rows(port, None);
    assert_eq!(*row_of(&guests, &l2), (l2.clone(), Some(l2_at), Some(r3_at)), "the draft-homed retraction's position, served to the guest");
    assert!(guests.iter().all(|(a, _, _)| !a.starts_with(&format!("{draft}."))), "no address of the draft: {guests:?}");
    assert_eq!(rows(port, Some(&bare)), guests, "the owner, who may read the draft, is served the same rows");
    assert!(!find_links_v(port, None, CLAIMANT_DOC1, 1, 1).contains(&l2));
    active_is_find_links_v(None);
    active_is_find_links_v(Some(&bare));

    // Retracted through a publication's `retract` entry: the birth shot of
    // doc 1 re-supplying the atom by reference, the retraction tuple landing
    // in doc 1 at the shot's own position.
    let (l3, l3_at) = link_from_atom(port, &signed);
    let shot = with_members(
        &publish_frame(CLAIMANT_DOC1, None, None, &[run(CLAIMANT_DOC1, ATOM, 1)]),
        serde_json::json!({"retract": [l3]}),
    );
    let v = op(port, Some(&signed), &shot);
    assert_eq!(verdict(&v), "ok", "{v}");
    let (member, shot_at) = (acked_addr(&v), acked_at(&v));
    assert_eq!(member, format!("{CLAIMANT_DOC1}.1"));
    let guests = rows(port, None);
    assert_eq!(*row_of(&guests, &l3), (l3.clone(), Some(l3_at), Some(shot_at)), "retracted at the shot's position");
    assert_eq!(*row_of(&guests, &l1), (l1.clone(), Some(l1_at), Some(r1_at)), "the earlier rows stand");
    assert_eq!(*row_of(&guests, &l2), (l2.clone(), Some(l2_at), Some(r3_at)));
    let retraction_by_shot = guests.iter().find(|(a, at, r)| *at == Some(shot_at) && r.is_none() && a.starts_with(&format!("{CLAIMANT_DOC1}.0.2."))).map(|(a, _, _)| a.clone());
    assert!(retraction_by_shot.is_some(), "the shot's retraction record, homed in doc 1, is an active row: {guests:?}");
    active_is_find_links_v(None);

    // A window of one, resumed row by row: the same rows, the retracted
    // links among them — a retracted link is a row, so a cursor naming one
    // resumes at the next row — and exhausted exactly where the pass ends.
    let whole = rows(port, None);
    let mut drained: Vec<Row> = Vec::new();
    let mut cur: Option<String> = None;
    for _ in 0..=whole.len() {
        let (rows, next, exhausted) = page(&op(port, None, &frame(CLAIMANT_DOC1, cur.as_deref(), 1)));
        assert!(rows.len() <= 1);
        assert_eq!(exhausted, rows.is_empty(), "exhausted iff short");
        assert_eq!(next, rows.first().map(|(a, _, _)| a.clone()).or(cur.clone()), "next is the row's address, else the cursor");
        drained.extend(rows);
        if exhausted {
            break;
        }
        cur = next;
    }
    assert_eq!(drained, whole, "a pass of one drains the whole answer");
    let (past_l1, _, _) = page(&op(port, None, &frame(CLAIMANT_DOC1, Some(&l1), 1)));
    assert_eq!(past_l1.len(), 1);
    assert_eq!(past_l1[0].0, whole[whole.iter().position(|(a, _, _)| *a == l1).expect("l1 is a row") + 1].0, "resumed past the retracted link: the next row");
    sd.shutdown();
}

/// THE DOOR AND THE BOUND: an unreadable `d` is `withheld` naming it, before
/// anything is read (the doc-argument consult, PUB-6.12) — a guest over the
/// claimant's draft, which the owner reads as an empty window; and the read
/// draws on the per-document pool — with doc 1's two region permits held it
/// is refused `503 scan_busy` with the document's sentence, while the same
/// read of another document is admitted, and once the permits return it
/// answers again.
#[test]
fn the_retracted_links_read_is_withheld_and_bounded_by_its_document() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = owner_draft(port, &bare);

    // Withheld: the guest and a stranger over the owner's draft; the owner
    // reads it — an empty window, the cursor unchanged, exhausted.
    assert_withheld(&op(port, None, &frame(&draft, None, 64)), &draft);
    let stranger = seat_stranger(port, 905);
    assert_withheld(&op(port, Some(&stranger.session), &frame(&draft, None, 64)), &draft);
    assert_eq!(page(&op(port, Some(&bare), &frame(&draft, None, 64))), (vec![], None, true));

    // The bound: doc 1's width held, the read of doc 1 is refused with the
    // document's sentence, a read of the draft admitted.
    let daemon = sd.daemon();
    let doc1 = {
        let comps = CLAIMANT_DOC1
            .split('.')
            .map(|c| skep_address::Nat::from(c.parse::<u64>().expect("a component")));
        skep_address::validate(skep_address::Tumbler::new(comps).expect("nonempty")).expect("a valid address")
    };
    let r1 = daemon.try_hold_region_permit(&doc1).expect("doc 1's region permit 1 of 2");
    let r2 = daemon.try_hold_region_permit(&doc1).expect("doc 1's region permit 2 of 2");
    let (st, body) = http(port, "POST", "/op", None, frame(CLAIMANT_DOC1, None, 64).as_bytes());
    assert_eq!(st, 503, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        String::from_utf8_lossy(&body),
        format!(r#"{{"detail":"{DOCUMENT_BUSY}","error":"scan_busy","op":"find_links_v_history"}}"#)
    );
    let (st, body) = http(port, "POST", "/op", Some(&bare), frame(&draft, None, 64).as_bytes());
    assert_eq!(st, 200, "another document's read is admitted: {}", String::from_utf8_lossy(&body));
    expect_resp(&json(&body), "links");
    drop((r1, r2));
    let (st, body) = http(port, "POST", "/op", None, frame(CLAIMANT_DOC1, None, 64).as_bytes());
    assert_eq!(st, 200, "the permits returned: {}", String::from_utf8_lossy(&body));
    expect_resp(&json(&body), "links");
    sd.shutdown();
}
