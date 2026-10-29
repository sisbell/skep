//! THE COUNT BY HOME THAT LIFTS NO LINK over the wire (the link-sets design
//! §7, W10 (a); the owner's rulings of 2026-10-28; wire.md §Link discovery
//! reads, `count_v_by_home`): the reader's default view wants everyone
//! else's links on the words in view only as a NUMBER — the corner's
//! "+⟨n⟩" and the card's per-set counts — while the applied sets are read
//! by home. `count_v_by_home {d, region, n, except}` answers, per readable
//! home holding a link on the region, in address order, how many distinct
//! links it has there, counted without lifting one, the homes `except` names
//! passed uncounted, the walk stopped at the home whose count brings the
//! sum to `n` and `exhausted` saying whether it ended under the budget.
//!
//! The board: the claimant's published doc 1, holding the ceremony's record
//! atom at content ordinal 1, is the page; two private drafts of the
//! claimant's and one of a stranger's home links FROM that atom — the sets
//! on the words in view — beside whatever public link of doc 1's own
//! touches it. What is asserted is the wire: the rows' sum is `count_v`'s
//! answer at every class, with `except` naming the author's own drafts the
//! sum drops by exactly their links and their rows go, a budget under the
//! flood answers `exhausted: false` with the sum at least the budget, the
//! read takes the per-document permit and is refused `scan_busy` with the
//! document's sentence under the page's width, an unreadable `d` answers
//! `withheld`, and an `except` list past the wire-list cap is refused at the
//! parse as every over-long list is.

use crate::common;

use common::*;
use serde_json::{json, Value};

/// The ceremony atom: doc 1's one content element, the position every link
/// here touches.
const ATOM: &str = "1.0.1.0.1.0.1.1";

/// An ordinary link type the plain path admits into a draft: the registry's
/// `citation`.
const T_CITATION: &str = "1.1.0.1.0.1.0.3.13";

/// The width's refusal sentence, as §Link discovery reads spells it.
const DOCUMENT_BUSY: &str = "all region-read permits of this document are in use; retry shortly";

/// The read over content ordinal 1 of `doc`, as the wire spells it, the
/// `except` list as given (each already a quoted address).
fn frame(doc: &str, n: u64, except: &[&str]) -> String {
    let except: Vec<String> = except.iter().map(|h| format!("\"{h}\"")).collect();
    format!(
        r#"{{"d":"{doc}","except":[{}],"n":{n},"op":"count_v_by_home","region":[{{"start":"1.1","width":"0.1"}}]}}"#,
        except.join(",")
    )
}

/// A `homes` answer's rows and its `exhausted`.
fn rows(v: &Value) -> (Vec<(String, u64)>, bool) {
    let r = expect_resp(v, "homes");
    let homes = r["homes"]
        .as_array()
        .expect("homes")
        .iter()
        .map(|row| {
            (row["home"].as_str().expect("a home").to_string(), row["n"].as_u64().expect("a count"))
        })
        .collect();
    (homes, r["exhausted"].as_bool().expect("exhausted"))
}

/// The rows' sum: the corner's number.
fn sum(rows: &[(String, u64)]) -> u64 {
    rows.iter().map(|(_, n)| n).sum()
}

/// One link homed in `home` FROM doc 1's atom, from `session`: the address.
fn link_from_atom(port: u16, session: &str, home: &str) -> String {
    acked_addr(&op(
        port,
        Some(session),
        &format!(
            r#"{{"op":"make_link","home":"{home}","from":{{"addrs":["{ATOM}"]}},"to":{{"addrs":["{home}"]}},"ty":{{"addrs":["{T_CITATION}"]}}}}"#
        ),
    ))
}

/// The claimant's two drafts with three and two links on the atom, and a
/// stranger's draft with one: `(owner session, [draft a, draft b], the
/// stranger's seat and draft)`.
struct Board {
    owner: String,
    drafts: [String; 2],
    stranger: Seat,
    stranger_draft: String,
}

fn seed(port: u16) -> Board {
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let a = create_doc(port, &owner, CLAIMANT_ACCOUNT);
    let b = create_doc(port, &owner, CLAIMANT_ACCOUNT);
    for _ in 0..3 {
        link_from_atom(port, &owner, &a);
    }
    for _ in 0..2 {
        link_from_atom(port, &owner, &b);
    }
    let stranger = seat_stranger(port, 905);
    let stranger_draft = create_doc(port, &stranger.session, &stranger.account);
    link_from_atom(port, &stranger.session, &stranger_draft);
    Board { owner, drafts: [a, b], stranger, stranger_draft }
}

/// THE ROWS AND THEIR SUM, at every class: the sum is `count_v`'s answer to
/// the same reader — the owner's rows its two drafts beside doc 1's public
/// links, the guest's doc 1's alone, the stranger's its own draft beside
/// them — in address order, a row only for a home holding a link; with
/// `except` naming the owner's drafts the rows are the guest's and the sum
/// drops by exactly the five links homed there; a budget under the flood
/// answers the first homes whole and `exhausted: false`, the sum at least
/// the budget; a budget past it answers every row and `exhausted: true`; an
/// excepted home the reader may not read changes nothing, and `n = 0` is
/// clamped to one.
#[test]
fn the_count_by_home_sums_to_the_census_and_drops_the_excepted_homes_links() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = seed(port);
    let [a, b] = &board.drafts;
    let census = |token: Option<&str>| count_v(port, token, CLAIMANT_DOC1, 1, 1);
    let read = |token: Option<&str>, n: u64, except: &[&str]| {
        rows(&op(port, token, &frame(CLAIMANT_DOC1, n, except)))
    };

    // The owner: every readable home, the sum the census.
    let (owners, exhausted) = read(Some(&board.owner), 1_000, &[]);
    assert!(exhausted, "a budget past the flood: the walk ends under it");
    assert_eq!(sum(&owners), census(Some(&board.owner)), "Σ count_v_by_home = count_v: {owners:?}");
    let public: Vec<(String, u64)> = owners.iter().filter(|(h, _)| h == CLAIMANT_DOC1).cloned().collect();
    assert_eq!(
        owners,
        [public.clone(), vec![(a.clone(), 3), (b.clone(), 2)]].concat(),
        "doc 1's public links, then the two drafts, three and two links, in address order"
    );
    assert!(owners.iter().all(|(_, n)| *n > 0), "no row for a home holding nothing");
    // The guest: doc 1's public links alone, the drafts dropped at their home.
    let (guests, exhausted) = read(None, 1_000, &[]);
    assert!(exhausted);
    assert_eq!(guests, public, "the guest's rows are the public home's");
    assert_eq!(sum(&guests), census(None));
    // The stranger: the public links and its own draft's, never the owner's.
    let (theirs, _) = read(Some(&board.stranger.session), 1_000, &[]);
    assert_eq!(theirs, [public.clone(), vec![(board.stranger_draft.clone(), 1)]].concat());
    assert_eq!(sum(&theirs), census(Some(&board.stranger.session)));

    // `except` the author's own drafts: their rows go, the sum drops by
    // exactly their five links — the corner's "+⟨n⟩" with the applied sets
    // out of the count.
    let (rest, exhausted) = read(Some(&board.owner), 1_000, &[a, b]);
    assert!(exhausted);
    assert_eq!(rest, public, "the applied sets' homes passed: {rest:?}");
    assert_eq!(sum(&rest), census(Some(&board.owner)) - 5);
    let (one_out, _) = read(Some(&board.owner), 1_000, &[a]);
    assert_eq!(one_out, [public.clone(), vec![(b.clone(), 2)]].concat());
    // An excepted home the reader may not read, or that holds nothing on
    // the page, changes nothing.
    let (same, _) = read(Some(&board.owner), 1_000, &[&board.stranger_draft, "1.0.1.0.9"]);
    assert_eq!(same, owners);

    // A budget under the flood: the first homes whole, `exhausted: false`,
    // the sum at least the budget and the rows a prefix of the whole.
    for n in 1..=sum(&owners) {
        let (page, exhausted) = read(Some(&board.owner), n, &[]);
        assert!(!exhausted, "n = {n}: the flood is past the budget");
        assert!(sum(&page) >= n, "n = {n}: the sum reaches the budget: {page:?}");
        assert!(owners.starts_with(&page), "n = {n}: a prefix of the whole: {page:?}");
        let last = page.last().map_or(0, |(_, c)| *c);
        assert!(sum(&page) - last < n, "n = {n}: the home that fills the budget is counted whole");
    }
    let (clamped, exhausted) = read(Some(&board.owner), 0, &[]);
    assert_eq!((clamped, exhausted), (owners[..1].to_vec(), false), "n = 0 is clamped to 1");
    // One budget past the whole: every row, and the terminal signal.
    let whole = sum(&owners);
    assert_eq!(read(Some(&board.owner), whole + 1, &[]), (owners.clone(), true));
    assert_eq!(read(Some(&board.owner), whole, &[]), (owners.clone(), false), "the budget met exactly: not exhausted");

    // The documented bytes of one answer, exactly (canonical key order).
    let (_, body) = http(port, "POST", "/op", None, frame(CLAIMANT_DOC1, 64, &[]).as_bytes());
    let answer: Value = json(&body);
    let as_of = answer["as_of"].as_u64().expect("as_of");
    let expected_rows: Vec<Value> = guests.iter().map(|(h, n)| json!({"home": h, "n": n})).collect();
    assert_eq!(
        String::from_utf8_lossy(&body),
        json!({"as_of": as_of, "exhausted": true, "homes": expected_rows, "resp": "homes"}).to_string()
    );
    sd.shutdown();
}

/// THE DOOR AND THE BOUND: an unreadable `d` is `withheld` naming it, before
/// anything is counted (the doc-argument consult, PUB-6.12) — a guest over
/// the claimant's draft, with the draft's own links on the page as a
/// readable `d` for the owner; the read draws on the per-document pool —
/// with doc 1's two region permits held it is refused `503 scan_busy` with
/// the document's sentence, while the same read of another document is
/// admitted, and once the permits return it answers again; and an `except`
/// list one past the wire-list cap is refused at the parse, `malformed`
/// under `unparseable` with the cap named in `detail`, as every over-long
/// list is — the list at the cap admitted.
#[test]
fn the_count_by_home_is_withheld_bounded_by_its_document_and_refuses_an_over_long_except() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = seed(port);
    let [a, _] = &board.drafts;

    // Withheld: the guest over the owner's draft; the owner reads it.
    let v = op(port, None, &frame(a, 64, &[]));
    assert_withheld(&v, a);
    let (own, _) = rows(&op(port, Some(&board.owner), &frame(a, 64, &[])));
    assert_eq!(own, vec![], "the draft arranges no content at ordinal 1: no row");
    let v = op(port, Some(&board.stranger.session), &frame(a, 64, &[]));
    assert_withheld(&v, a);

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
    let (st, body) = http(port, "POST", "/op", None, frame(CLAIMANT_DOC1, 64, &[]).as_bytes());
    assert_eq!(st, 503, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        String::from_utf8_lossy(&body),
        format!(r#"{{"detail":"{DOCUMENT_BUSY}","error":"scan_busy","op":"count_v_by_home"}}"#)
    );
    let (st, body) = http(port, "POST", "/op", Some(&board.owner), frame(a, 64, &[]).as_bytes());
    assert_eq!(st, 200, "another document's read is admitted: {}", String::from_utf8_lossy(&body));
    expect_resp(&json(&body), "homes");
    drop((r1, r2));
    let (st, body) = http(port, "POST", "/op", None, frame(CLAIMANT_DOC1, 64, &[]).as_bytes());
    assert_eq!(st, 200, "the permits returned: {}", String::from_utf8_lossy(&body));
    expect_resp(&json(&body), "homes");

    // The `except` bound: at the cap admitted, one past it refused at the
    // parse with the cap named.
    let cap = skep_links::MAX_SLOT_SPANS;
    let at_cap: Vec<&str> = vec!["1.0.1.0.9"; cap];
    let (at, _) = rows(&op(port, None, &frame(CLAIMANT_DOC1, 64, &at_cap)));
    let (free, _) = rows(&op(port, None, &frame(CLAIMANT_DOC1, 64, &[])));
    assert_eq!(at, free, "a list at the cap is admitted, a home holding nothing passed to no effect");
    let over: Vec<&str> = vec!["1.0.1.0.9"; cap + 1];
    let v = op(port, None, &frame(CLAIMANT_DOC1, 64, &over));
    let rej = expect_resp(&v, "rejected");
    assert_eq!((rej["code"].as_str(), rej["op"].as_str()), (Some("malformed"), Some("unparseable")), "{v}");
    let detail = rej["detail"].as_str().expect("the refusal names the cap");
    assert!(detail.contains("except") && detail.contains(&format!("{cap}-element wire cap")), "{detail}");
    sd.shutdown();
}
