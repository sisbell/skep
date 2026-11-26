//! The paged image over the wire and through `/op-at` (wire.md §Link
//! discovery reads, `image`; §Reading history): an `image` past the run
//! budget answers the page that fits under a `resp` of its own, the go-on
//! beside it, and its continuation the rest; a draft's continuation is
//! refused `page_moved` once the draft is written, and a published
//! document's is answered from the member its first page read; and a paged
//! read at a past position is one reconstruction, kept from its first page
//! to its last and let go when it ends, when its reader begins it again, or
//! when no page is asked of it for the idle bound.
//!
//! Every claim about cost is a count: the pages answered, the bases the
//! kernel loaded, the permits the pool still hands out. None is a time.

use crate::common;

use common::*;
use serde_json::{json, Value};

/// The board's run budget, `MAX_IMAGE_RUNS`: the most runs one page
/// carries, restated here on purpose — a budget that moves is a visible
/// event at this file, not a claim that quietly measures less.
const PAGE: u64 = 4_096;

/// The history surface's idle bound for a kept read, `KEPT_READ_IDLE`, 10 s,
/// restated as `edges.rs` restates the hold-down: the two advances below are
/// measured against it, so a bound that moves fails here.
const KEPT_READ_IDLE_MS: u64 = 10_000;

/// A clock advance short of the idle bound: half of it, so the time the
/// suite's own requests take, which the seam's clock counts too, never
/// carries a read to the bound.
const SHORT_OF_THE_IDLE_BOUND_MS: u64 = KEPT_READ_IDLE_MS / 2;

/// A draft of the claimant's cut into `2 * pieces + 1` one-position runs
/// ([`fragmented_draft_in`]).
fn fragmented_draft(port: u16, owner: &str, pieces: u64) -> (String, u64, u64) {
    fragmented_draft_in(port, owner, CLAIMANT_ACCOUNT, pieces)
}

/// A draft in `account`, written under `owner`, cut into `2 * pieces + 1`
/// one-position runs: `pieces + 1` bytes of one run, then a byte placed
/// before every position from the second, as many changes a call as the
/// wire's list cap admits. Answers the draft, its extent, and the position
/// its last cut landed at.
fn fragmented_draft_in(port: u16, owner: &str, account: &str, pieces: u64) -> (String, u64, u64) {
    let draft = create_doc(port, owner, account);
    expect_resp(&insert_text(port, owner, &draft, 1, &"a".repeat(pieces as usize + 1)), "ack_addr");
    let (mut cut, mut at) = (0, 0);
    while cut < pieces {
        let step = (pieces - cut).min(PAGE);
        // The positions already cut hold two bytes apiece; the uncut tail
        // begins after them, and each of its positions from the second
        // takes a byte before it.
        let tail = 2 * cut + 1;
        let cuts: Vec<(u64, u64, &str)> = (1..=step).map(|k| (tail + k, 0, "b")).collect();
        at = acked_at(expect_resp(&op(port, Some(owner), &edit_frame(&draft, &cuts, None)), "ack_addr"));
        cut += step;
    }
    let extent = 2 * pieces + 1;
    assert_eq!(content_extent(port, Some(owner), &draft), extent);
    (draft, extent, at)
}

/// The continuation of an `image` of `[from, from + width)`: the rest of the
/// span from the go-on's ordinal, the go-on sent back whole as `cur`.
fn continued(doc: &str, from: u64, width: u64, next: &Value, own: bool) -> String {
    let at: u64 = next["at"].as_str().expect("a go-on's ordinal").parse().expect("a natural");
    let mut frame = json!({
        "op": "image", "d": doc, "cur": next,
        "region": [{"start": format!("1.{at}"), "width": format!("0.{}", from + width - at)}],
    });
    if own {
        frame["own"] = json!(true);
    }
    frame.to_string()
}

/// One page's runs, whichever of the two shapes it answered under.
fn page_runs(v: &Value) -> Vec<(String, u64)> {
    let member = if v["resp"] == "image_page" { "ispans" } else { "runs" };
    v[member]
        .as_array()
        .unwrap_or_else(|| panic!("a page or an image: {v}"))
        .iter()
        .map(|r| (r["i_start"].as_str().expect("i_start").to_string(), r["width"].as_str().expect("width").parse().expect("a count")))
        .collect()
}

/// Reads `[1, 1 + extent)` of `doc` whole, page after page, at the head or
/// through `/op-at` at `at`: the runs, and each page's document.
fn read_whole(port: u16, token: Option<&str>, at: Option<u64>, doc: &str, extent: u64) -> (Vec<(String, u64)>, Vec<Value>) {
    let send = |frame: &str| match at {
        None => op(port, token, frame),
        Some(at) => op_at_ok(port, token, at, frame),
    };
    let (mut runs, mut pages) = (Vec::new(), Vec::new());
    let mut page = send(&image_frame(doc, 1, extent));
    loop {
        runs.extend(page_runs(&page));
        let next = page["next"].clone();
        let short = page["resp"] == "image_page";
        pages.push(page);
        if !short {
            return (runs, pages);
        }
        page = send(&continued(doc, 1, extent, &next, false));
    }
}

/// The image of `[1, 1 + extent)` read a budget's width at a time, each part
/// a first page of its own that fits: the whole image by reads no page
/// continues, at the head or each through a reconstruction of its own.
fn read_in_parts(port: u16, token: Option<&str>, at: Option<u64>, doc: &str, extent: u64) -> Vec<(String, u64)> {
    let mut runs = Vec::new();
    let mut from = 1;
    while from <= extent {
        let width = PAGE.min(extent + 1 - from);
        let frame = image_frame(doc, from, width);
        let part = match at {
            None => op(port, token, &frame),
            Some(at) => op_at_ok(port, token, at, &frame),
        };
        runs.extend(runs_in(&part));
        from += width;
    }
    runs
}

/// How many reconstruction permits the pool hands out right now.
fn free_permits(sd: &skepd::Skepd) -> usize {
    let held: Vec<_> = std::iter::from_fn(|| sd.daemon().try_hold_reconstruction_permit()).collect();
    held.len()
}

/// **An image past the run budget is answered in pages.** A draft of 5,001 runs
/// answers its first 4,096 under `image_page`, its runs under `ispans` and
/// never `runs`, with `next` naming the next ordinal, the draft and the
/// position its last write landed at — the `arranged_at` its metadata
/// serves; the continuation answers the other 905 under `runs` with no
/// go-on; and the two pages are the draft's every run, in order. A region of
/// 4,096 runs or fewer answers `runs` alone, as it did.
#[test]
fn an_image_past_the_run_budget_is_answered_in_pages_over_the_wire() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (draft, extent, cut_at) = fragmented_draft(port, &owner, 2_500);
    assert_eq!(extent, 5_001);

    let first = op(port, Some(&owner), &image_frame(&draft, 1, extent));
    let page = expect_resp(&first, "image_page");
    let keys: Vec<&str> = page.as_object().expect("an object").keys().map(String::as_str).collect();
    assert_eq!(keys, ["as_of", "ispans", "next", "resp"], "no `runs` member for a reader of one to take: {page}");
    assert_eq!(page["ispans"].as_array().map(Vec::len), Some(PAGE as usize));
    assert_eq!(page["next"], json!({"arranged_at": cut_at, "at": (PAGE + 1).to_string(), "surface": draft}));
    assert_eq!(doc_metadata(port, Some(&owner), &draft)["arranged_at"], json!(cut_at));
    assert_eq!(page["as_of"].as_u64(), Some(head_position(port)));

    let second = op(port, Some(&owner), &continued(&draft, 1, extent, &page["next"], false));
    let rest = expect_resp(&second, "runs");
    assert!(rest.get("next").is_none(), "the last page names no rest: {rest}");
    assert_eq!(runs_in(rest).len(), 905);

    // Every run of the draft: the original bytes one position apiece, a
    // minted byte between each two.
    let own = |ordinal: u64| (format!("{draft}.0.1.{ordinal}"), 1);
    let expected: Vec<(String, u64)> =
        (1..=extent).map(|position| if position % 2 == 1 { own(position.div_ceil(2)) } else { own(2_501 + position / 2) }).collect();
    let (read, pages) = read_whole(port, Some(&owner), None, &draft, extent);
    assert_eq!((read.len(), pages.len()), (5_001, 2));
    assert_eq!(read, expected, "the pages are the whole image, run for run");
    assert_eq!(read_in_parts(port, Some(&owner), None, &draft, extent), expected);

    // Within the budget: `runs`, and nothing beside it.
    let fits = op(port, Some(&owner), &image_frame(&draft, 1, PAGE));
    let fits = expect_resp(&fits, "runs");
    let keys: Vec<&str> = fits.as_object().expect("an object").keys().map(String::as_str).collect();
    assert_eq!(keys, ["as_of", "resp", "runs"]);
    assert_eq!(runs_in(fits).len(), PAGE as usize);
    sd.shutdown();
}

/// **One state a page set.** A draft read one page and then written refuses its
/// continuation `page_moved`, permanent, naming the draft, nothing answered,
/// and the read begun again answers the new state whole. A continuation
/// naming an arrangement that is not the draft's is refused `bad_region`,
/// and one of a draft its reader may not read is withheld ahead of both.
#[test]
fn a_drafts_continuation_is_refused_page_moved_once_the_draft_is_written() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let stranger = seat_stranger(port, 77);
    let (draft, extent, _) = fragmented_draft(port, &owner, 2_500);
    let first = op(port, Some(&owner), &image_frame(&draft, 1, extent));
    let next = expect_resp(&first, "image_page")["next"].clone();
    let continuation = continued(&draft, 1, extent, &next, false);

    // Another document's write moves the board, not the draft.
    draft_with(port, &owner, "elsewhere");
    assert_eq!(runs_in(&op(port, Some(&owner), &continuation)).len(), 905);

    let elsewhere = json!({"arranged_at": next["arranged_at"], "at": next["at"], "surface": stranger.doc1});
    let refused = op(port, Some(&owner), &continued(&draft, 1, extent, &elsewhere, false));
    assert_eq!(expect_resp(&refused, "rejected")["code"], "bad_region", "{refused}");
    assert_withheld(&op(port, Some(&stranger.session), &continuation), &draft);

    // The draft's own write: one byte at its front.
    expect_resp(&insert_text(port, &owner, &draft, 1, "Z"), "ack_addr");
    let before = head_position(port);
    let moved = op(port, Some(&owner), &continuation);
    let rejection = expect_resp(&moved, "rejected");
    assert_eq!(
        *rejection,
        json!({"code": "page_moved", "disposition": "permanent", "op": "image", "resp": "rejected", "site": {"addr": draft}}),
    );
    assert_eq!(head_position(port), before, "a read moves nothing");
    let (again, pages) = read_whole(port, Some(&owner), None, &draft, extent + 1);
    assert_eq!((again.len(), pages.len()), (5_002, 2), "the byte at the front cut no run and joined none");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 3), "Zab");
    sd.shutdown();
}

/// **A published document's page set is one member's.** A published document
/// whose head holds 5,001 runs is read one page; a version then lands and a
/// deposit on the new head, so the document's readers float elsewhere; and
/// the continuation is answered from the member the first page read — the
/// page set that member's image, never the new head's. A continuation under
/// `own`, and one of the member named itself, are answered across the
/// landing too.
#[test]
fn a_published_documents_continuation_is_answered_from_the_member_its_first_page_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    // A sub-account's draft, which the claimant reads and does not own, so
    // its `version` of it mints a document of its own sharing the draft's
    // arrangement — published: the one way a published document comes to
    // hold 5,001 runs, a shot placing at most the budget.
    let seat = seat_sub_account(port, &owner, 41);
    let (draft, extent, _) = fragmented_draft_in(port, &seat.session, &seat.account, 2_500);
    let published = acked_addr(&version_of(port, &signed, &draft, Some(true)));
    let own_image = read_whole(port, None, None, &published, extent).0;
    assert_eq!(own_image.len(), 5_001);
    let own_first = op(port, None, &format!(r#"{{"op":"image","d":"{published}","own":true,"region":[{{"start":"1.1","width":"0.{extent}"}}]}}"#));
    let own_next = expect_resp(&own_first, "image_page")["next"].clone();
    assert_eq!(own_next["surface"], json!(published), "memberless, it is its own surface");

    let member = acked_addr(&version_of(port, &signed, &published, None));
    assert_eq!(member, format!("{published}.1"));
    let floated = op(port, None, &image_frame(&published, 1, extent + 1));
    let next = expect_resp(&floated, "image_page")["next"].clone();
    assert_eq!(next["surface"], json!(member), "the head the bare address floated to");
    let named = op(port, None, &image_frame(&member, 1, extent + 1));
    let named_next = expect_resp(&named, "image_page")["next"].clone();

    // The landing: a second version, and a deposit on it alone.
    let head = acked_addr(&version_of(port, &signed, &published, None));
    assert_eq!(head, format!("{published}.2"));
    deposit_text(port, &signed, &published, extent + 1, "!");
    assert_eq!(content_extent(port, None, &published), extent + 1, "the readers float to the new head");
    assert_eq!(content_extent(port, None, &member), extent);

    let rest = runs_in(&op(port, None, &continued(&published, 1, extent + 1, &next, false)));
    let read: Vec<(String, u64)> = page_runs(&floated).into_iter().chain(rest).collect();
    assert_eq!(read, own_image, "the first page's member, whole: the runs the draft held");
    assert_eq!(read_whole(port, None, None, &published, extent + 1).0.len(), 5_002, "a read begun now is the new head's");

    let rest = runs_in(&op(port, None, &continued(&member, 1, extent + 1, &named_next, false)));
    assert_eq!(rest.len(), 905, "a member's continuation, whatever has landed");
    let rest = runs_in(&op(port, None, &continued(&published, 1, extent, &own_next, true)));
    assert_eq!(rest, own_image[PAGE as usize..], "the document's own arrangement, frozen");
    sd.shutdown();
}

/// **A paged read at a position is one reconstruction.** A draft of 5,001 runs
/// is two pages and one of 12,289 four, each read whole through `/op-at` at
/// one past position: every page stamped that position, the pages the
/// position's image run for run — the image a read by parts takes, each
/// part a reconstruction of its own — and the kernel loading one base for
/// the whole read, where the parts load one apiece. After the last page the
/// pool hands out both its permits.
#[test]
fn a_paged_read_at_a_position_is_one_reconstruction() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    for (pieces, pages_expected) in [(2_500u64, 2usize), (6_144, 4)] {
        let (draft, extent, at) = fragmented_draft(port, &owner, pieces);
        // Written since: the position read is a past one.
        expect_resp(&insert_text(port, &owner, &draft, 1, "since"), "ack_addr");
        let loaded = sd.daemon().bases_loaded();
        let stood = sd.daemon().held_bases_stood_on();
        let (read, pages) = read_whole(port, Some(&owner), Some(at), &draft, extent);
        let one_read = (sd.daemon().bases_loaded() - loaded, sd.daemon().held_bases_stood_on() - stood);
        assert_eq!(pages.len(), pages_expected, "⌈{extent} ÷ {PAGE}⌉ pages");
        assert_eq!(one_read.0, 1, "one base for the whole read, not one a page");
        assert!(pages.iter().all(|page| page["as_of"].as_u64() == Some(at)), "every page stamped the position asked");
        assert_eq!(free_permits(&sd), 2, "the read ended: both permits are the pool's again");

        // The same image by reads no page continues, a base apiece.
        let loaded = sd.daemon().bases_loaded();
        let stood = sd.daemon().held_bases_stood_on();
        let parts = read_in_parts(port, Some(&owner), Some(at), &draft, extent);
        assert_eq!(sd.daemon().bases_loaded() - loaded, pages_expected as u64);
        assert_eq!(
            sd.daemon().held_bases_stood_on() - stood,
            one_read.1 * pages_expected as u64,
            "each part stands where the one read stood, once apiece"
        );
        assert_eq!(read.len() as u64, extent);
        assert_eq!(read, parts, "the pages are the position's image, run for run");
        assert_eq!(read, read_in_parts(port, Some(&owner), None, &draft, extent + 5)[1..], "which the draft still holds past the run written since");
    }
    sd.shutdown();
}

/// **A read nobody continues holds no permit.** A paged read left part-way
/// — after its second page of three — keeps its permit while it may yet be
/// continued; the same reader beginning that read again lets the one it
/// left go, so one read is kept and never two; and a read idle for the
/// bound is let go by the next historical question, which finds both
/// permits — short of the bound it still holds one. A continuation of a
/// read let go is answered all the same, from a reconstruction of its own,
/// and is kept for its own next page.
#[test]
fn an_abandoned_paged_read_is_let_go_and_frees_its_permit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (draft, extent, at) = fragmented_draft(port, &owner, PAGE + 1);
    let first_page = image_frame(&draft, 1, extent);
    let loaded = sd.daemon().bases_loaded();
    let first = op_at_ok(port, Some(&owner), at, &first_page);
    let first_next = expect_resp(&first, "image_page")["next"].clone();
    assert_eq!(free_permits(&sd), 1, "the read's reconstruction is kept, its permit held");
    let second = op_at_ok(port, Some(&owner), at, &continued(&draft, 1, extent, &first_next, false));
    assert_ne!(expect_resp(&second, "image_page")["next"], first_next, "the second page of three");
    assert_eq!((sd.daemon().bases_loaded() - loaded, free_permits(&sd)), (1, 1), "one read, kept at its second page");

    // Begun again by its reader: the read it left at its second page is
    // let go, one kept.
    let again = op_at_ok(port, Some(&owner), at, &first_page);
    let next = expect_resp(&again, "image_page")["next"].clone();
    assert_eq!(next, first_next, "the same first page");
    assert_eq!(sd.daemon().bases_loaded() - loaded, 2, "a first page is a reconstruction of its own");
    assert_eq!(free_permits(&sd), 1, "one read kept, never two");

    // Idle, short of the bound: a historical question finds it kept.
    sd.daemon().advance_edge_clock_ms(SHORT_OF_THE_IDLE_BOUND_MS);
    expect_resp(&op_at_ok(port, Some(&owner), at, &spanset_frame(&draft)), "span_set");
    assert_eq!(free_permits(&sd), 1);
    // Past it: the next historical question lets it go before it asks.
    sd.daemon().advance_edge_clock_ms(KEPT_READ_IDLE_MS - SHORT_OF_THE_IDLE_BOUND_MS);
    expect_resp(&op_at_ok(port, Some(&owner), at, &spanset_frame(&draft)), "span_set");
    assert_eq!(free_permits(&sd), 2, "a read nobody continues holds no permit");

    // Its continuation is answered all the same, from a reconstruction of
    // its own — the same page — and kept for the page after it, which ends
    // the read and returns the permit.
    let loaded = sd.daemon().bases_loaded();
    let rest = op_at_ok(port, Some(&owner), at, &continued(&draft, 1, extent, &next, false));
    assert_eq!(page_runs(&rest), page_runs(&second), "the same second page");
    assert_eq!((sd.daemon().bases_loaded() - loaded, free_permits(&sd)), (1, 1));
    let last = op_at_ok(port, Some(&owner), at, &continued(&draft, 1, extent, &rest["next"], false));
    assert_eq!(runs_in(&last).len() as u64, extent - 2 * PAGE);
    assert_eq!((sd.daemon().bases_loaded() - loaded, free_permits(&sd)), (1, 2));
    sd.shutdown();
}

/// **A kept read answers its own pages alone.** A continuation sent at another
/// position, or of another document at the same one, joins no kept read: it
/// is answered by its own position's world, through a reconstruction of its
/// own, and the read kept beside it stands for its own continuation, which
/// loads no base.
#[test]
fn a_page_of_another_position_or_document_is_not_answered_from_a_kept_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (draft, extent, cut_at) = fragmented_draft(port, &owner, 2_500);
    // The position read: both drafts stand cut, neither written since.
    let (other, _, at) = fragmented_draft(port, &owner, 2_500);
    // The draft written after it: at `later` its arrangement has moved.
    let later = acked_at(expect_resp(&insert_text(port, &owner, &draft, 1, "Z"), "ack_addr"));

    let first = op_at_ok(port, Some(&owner), at, &image_frame(&draft, 1, extent));
    let next = expect_resp(&first, "image_page")["next"].clone();
    assert_eq!(next["arranged_at"], json!(cut_at));
    let continuation = continued(&draft, 1, extent, &next, false);
    assert_eq!(free_permits(&sd), 1);

    // The same continuation at another position: that position's verdict.
    let loaded = sd.daemon().bases_loaded();
    let (status, moved) = op_at(port, Some(&owner), later, &continuation);
    assert_eq!((status, moved["code"].as_str()), (200, Some("page_moved")), "{moved}");
    assert_eq!(sd.daemon().bases_loaded() - loaded, 1, "a reconstruction of its own");

    // A continuation of another document at the kept read's own position:
    // the other document's page, from a reconstruction of its own.
    let other_next = json!({"arranged_at": at, "at": next["at"], "surface": other});
    let loaded = sd.daemon().bases_loaded();
    let page = op_at_ok(port, Some(&owner), at, &continued(&other, 1, extent, &other_next, false));
    assert_eq!(runs_in(&page).len(), 905);
    assert!(runs_in(&page).iter().all(|(i_start, _)| i_start.starts_with(&format!("{other}.0.1."))), "the other document's runs");
    assert_eq!(sd.daemon().bases_loaded() - loaded, 1);

    // The kept read stood through both, and answers its own continuation
    // with no base loaded.
    assert_eq!(free_permits(&sd), 1);
    let loaded = sd.daemon().bases_loaded();
    let rest = op_at_ok(port, Some(&owner), at, &continuation);
    assert_eq!(runs_in(&rest).len(), 905);
    assert_eq!(rest["as_of"].as_u64(), Some(at));
    assert_eq!(sd.daemon().bases_loaded() - loaded, 0, "answered from the world its first page kept");
    assert_eq!(free_permits(&sd), 2, "its last page answered, the read is let go");
    sd.shutdown();
}

/// **The pool is two, kept reads among them.** While two paged reads are kept, a
/// third historical question is refused `history_busy` at once, as it is
/// with two reconstructions in flight, and each kept read's own continuation
/// is answered all the same, asking the pool nothing; once one ends, the
/// third is admitted.
#[test]
fn a_third_historical_reader_is_refused_while_two_paged_reads_are_kept() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (draft, extent, at) = fragmented_draft(port, &owner, 2_500);
    let (other, _, other_at) = fragmented_draft(port, &owner, 2_500);
    let first = op_at_ok(port, Some(&owner), at, &image_frame(&draft, 1, extent));
    let second = op_at_ok(port, Some(&owner), other_at, &image_frame(&other, 1, extent));
    assert_eq!(free_permits(&sd), 0, "two reads kept: the pool is spent");

    let third = spanset_frame(&draft);
    let (status, busy) = op_at(port, Some(&owner), at, &third);
    assert_eq!((status, busy["error"].as_str()), (503, Some("history_busy")), "{busy}");
    let rest = op_at_ok(port, Some(&owner), other_at, &continued(&other, 1, extent, &second["next"], false));
    assert_eq!(runs_in(&rest).len(), 905, "a kept read's continuation asks no permit");
    assert_eq!(free_permits(&sd), 1);
    expect_resp(&op_at_ok(port, Some(&owner), at, &third), "span_set");
    let rest = op_at_ok(port, Some(&owner), at, &continued(&draft, 1, extent, &first["next"], false));
    assert_eq!(runs_in(&rest).len(), 905);
    assert_eq!(free_permits(&sd), 2);
    sd.shutdown();
}
