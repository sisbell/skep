//! The paged image (`image_page_on`) — a region past the run budget answered
//! in pages, never refused for its runs: the page that fits and where the
//! rest begins; a page ending at a run's reach, never inside one; a
//! continuation answered from the arrangement its first page read — a
//! draft's only while the draft stands as it did, a member's whatever has
//! landed since — and held to the arrangement and the place its go-on names;
//! the walk's square kept; and the region family, which reads through
//! `image_on` and is refused past the budget.

use crate::common;
use crate::heap::settled_heap_bytes;

use common::*;
use skep_address::{Address, Nat, Span};
use skep_arrangement::{AsOf, HasM5, Run, Vstream};
use skep_discovery::{
    count_v_on, findlinks_v_on, image_on, image_page_on, GoOn, ImagePage, QueryError,
    MAX_IMAGE_RUNS,
};
use skep_kernel::{Kernel, Snapshot};
use skep_links::LinkWriter;
use skep_namespace::PrincipalId;

/// The budget as a count of positions, runs or spans in a `u32`.
const MAX: u32 = MAX_IMAGE_RUNS as u32;

/// Places one run per width into `doc`, each a copy of doc1's first `width`
/// positions, so no run abuts the next: the document holds as many runs as
/// `widths` names. `k` must arrange at least the widest in doc1.
fn place_runs(k: &Kernel<World>, doc: &Address, widths: impl IntoIterator<Item = u32>) {
    let specs: Vec<_> = widths.into_iter().map(|width| spec(&doc1(), 1, 1, width)).collect();
    Vstream::new(k)
        .copy(SYS, doc, vp(1, 1), &specs, AsOf::Typed(k.current_seq()))
        .expect("copy succeeds");
}

/// A kernel whose doc2 — a private draft — holds `runs` one-position runs.
fn draft_of(runs: u32) -> Kernel<World> {
    let k = kernel();
    seed_content(&k, &doc1(), 9);
    place_runs(&k, &doc2(), std::iter::repeat_n(1, runs as usize));
    k
}

/// A kernel whose doc2 holds `runs` runs of widths 1 to 9, in turn.
fn draft_of_mixed_widths(runs: u32) -> Kernel<World> {
    let k = kernel();
    seed_content(&k, &doc1(), 9);
    place_runs(&k, &doc2(), (0..runs).map(|i| 1 + i % 9));
    k
}

/// Every run `doc` arranges, off M5's own resolution: what a whole image
/// read in pages must equal, run for run.
fn arranged(snap: &Snapshot<World>, doc: &Address) -> Vec<Run> {
    snap.world().m5().content_runs(doc).cloned().collect()
}

/// The rest of the one span `[from, from + width)` from the go-on on.
fn rest_of(from: u32, width: u32, next: &GoOn) -> [Span; 1] {
    let at = u32::try_from(&next.at).expect("a small ordinal");
    [vspan(1, at, from + width - at)]
}

/// Reads the one span `[from, from + width)` of `d` whole, each page off the
/// kernel's state as it then stands, and answers the runs and the pages.
///
/// # Panics
///
/// Where a go-on names no ordinal past the one its page began at: a read
/// that follows it would never end.
fn read_whole(
    k: &Kernel<World>,
    d: &Address,
    from: u32,
    width: u32,
    own: bool,
) -> Result<(Vec<Run>, usize), QueryError> {
    let reads = Reads(k);
    let mut page = reads.image_page(d, &[vspan(1, from, width)], own, None)?;
    let (mut runs, mut pages, mut begun) = (Vec::new(), 1, n(from));
    loop {
        runs.append(&mut page.runs);
        let Some(next) = page.next else { return Ok((runs, pages)) };
        assert!(next.at > begun, "a go-on advances past {begun}: {next:?}");
        begun = next.at.clone();
        page = reads.image_page(d, &rest_of(from, width, &next), own, Some(&next))?;
        pages += 1;
    }
}

/// A region resolving past the run budget is answered, never refused: the
/// first `MAX` runs and a go-on naming the next ordinal, the draft and its
/// `arranged_at`; the continuation answers the rest with no go-on; and the
/// two pages together are every run the draft arranges, in order.
#[test]
fn a_region_past_the_run_budget_is_answered_in_pages() {
    let k = draft_of(5_000);
    let snap = k.snapshot();
    let whole = [vspan(1, 1, 5_000)];
    assert_eq!(image_on(&snap, &doc2(), &whole), Err(QueryError::ImageTooLarge));

    let first = image_page_on(&snap, &doc2(), &whole, false, None).expect("a first page");
    assert_eq!(first.runs.len(), MAX_IMAGE_RUNS);
    let next = first.next.clone().expect("a short page names where the rest begins");
    assert_eq!(
        next,
        GoOn {
            at: n(MAX + 1),
            surface: doc2(),
            arranged_at: snap.world().m5().arranged_at(&doc2()),
        }
    );
    assert!(next.arranged_at.is_some(), "a written draft has a position");

    let second = image_page_on(&snap, &doc2(), &rest_of(1, 5_000, &next), false, Some(&next))
        .expect("the continuation");
    assert_eq!(second.runs.len(), 904);
    assert_eq!(second.next, None, "the last page names no rest");

    let read: Vec<Run> = first.runs.into_iter().chain(second.runs).collect();
    assert_eq!(read, arranged(&snap, &doc2()), "the pages are the whole image, run for run");
    assert_eq!(read_whole(&k, &doc2(), 1, 5_000, false).map(|(_, pages)| pages), Ok(2));
    assert_eq!(read_whole(&k, &doc2(), 1, 5_000, true).map(|(runs, _)| runs), Ok(read));
}

/// A region within the run budget answers exactly what `image_on` answers
/// and names no rest — at the budget itself, under it, over several spans,
/// and of a document that arranges nothing.
#[test]
fn a_region_within_the_run_budget_answers_whole_with_no_go_on() {
    let k = draft_of(MAX);
    let snap = k.snapshot();
    let regions: [&[Span]; 4] = [
        &[vspan(1, 1, MAX)],
        &[vspan(1, 7, 100)],
        &[vspan(1, 1, 2_000), vspan(1, 2_001, 2_096)],
        &[],
    ];
    for region in regions {
        for own in [false, true] {
            assert_eq!(
                image_page_on(&snap, &doc2(), region, own, None),
                Ok(ImagePage {
                    runs: image_on(&snap, &doc2(), region).expect("within the budget"),
                    next: None,
                }),
                "{region:?}, own {own}"
            );
        }
    }
    assert_eq!(
        image_page_on(&snap, &pdoc(), &[vspan(1, 1, 5)], false, None),
        Ok(ImagePage { runs: vec![], next: None }),
        "registered and empty"
    );
}

/// No page cuts a run: over runs of mixed widths the go-on is the reach of
/// the page's last run, the continuation's first run is the next run whole,
/// and a region that itself begins inside a run still ends its page at a
/// run's reach.
#[test]
fn no_page_cuts_a_run() {
    let k = draft_of_mixed_widths(5_000);
    let snap = k.snapshot();
    let all = arranged(&snap, &doc2());
    assert_eq!(all.len(), 5_000);
    let width_of = |runs: &[Run]| runs.iter().fold(Nat::from(0u32), |sum, r| sum + r.width());
    let extent = u32::try_from(&width_of(&all)).expect("a small extent");

    let first = image_page_on(&snap, &doc2(), &[vspan(1, 1, extent)], false, None)
        .expect("a first page");
    assert_eq!(first.runs, all[..MAX_IMAGE_RUNS], "whole runs, as the draft holds them");
    let next = first.next.expect("a go-on");
    assert_eq!(next.at, n(1) + width_of(&first.runs), "the reach of the page's last run");
    let second =
        image_page_on(&snap, &doc2(), &rest_of(1, extent, &next), false, Some(&next))
            .expect("the continuation");
    assert_eq!(second.runs[0], all[MAX_IMAGE_RUNS], "the next run begins there, whole");
    assert_eq!(second.runs, all[MAX_IMAGE_RUNS..]);

    // From the second position of the draft's second run: the region's own
    // edge cuts that run, and the page still ends at a run's reach.
    let (from, cut) = (3, 1);
    assert_eq!(all[1].width(), &n(2), "the second run is two wide, at positions 2 and 3");
    let clipped = image_page_on(&snap, &doc2(), &[vspan(1, from, extent)], false, None)
        .expect("a first page");
    assert_eq!(clipped.runs[0].width(), &n(cut), "the region's edge clips its first run");
    assert_eq!(clipped.runs[1..], all[2..=MAX_IMAGE_RUNS]);
    let next = clipped.next.expect("a go-on");
    assert_eq!(next.at, n(from) + width_of(&clipped.runs));
    let (runs, pages) = read_whole(&k, &doc2(), from, extent, false).expect("read whole");
    assert_eq!((runs[1..].to_vec(), pages), (all[2..].to_vec(), 2));
}

/// A draft's continuation is refused once the draft is written: the page
/// read and the page asked for would be of two states, so nothing is
/// answered. A draft left alone continues, whatever else the board commits.
#[test]
fn a_drafts_continuation_is_refused_once_the_draft_is_written() {
    let k = draft_of(5_000);
    let reads = Reads(&k);
    let whole = [vspan(1, 1, 5_000)];
    let next = reads.image_page(&doc2(), &whole, false, None).expect("a page").next.expect("a go-on");
    let rest = rest_of(1, 5_000, &next);

    // Another document's write moves the board and not the draft.
    seed_content(&k, &doc1(), 1);
    let unmoved = reads.image_page(&doc2(), &rest, false, Some(&next)).expect("the draft stands");
    assert_eq!(unmoved.runs.len(), 904);

    // The draft's own write: one position placed at its front.
    seed_content(&k, &doc2(), 1);
    for own in [false, true] {
        assert_eq!(
            reads.image_page(&doc2(), &rest, own, Some(&next)),
            Err(QueryError::PageMoved),
            "own {own}"
        );
    }
    // The read begun again is answered: the new state, whole.
    let (runs, pages) = read_whole(&k, &doc2(), 1, 5_001, false).expect("read again");
    assert_eq!((runs, pages), (arranged(&k.snapshot(), &doc2()), 2));
}

/// A bare published document's continuation is answered from the member its
/// first page floated to: a version landed since and a deposit on the new
/// head move where the document's readers float, and the page set is still
/// the first member's image, never a mix of two members' runs.
#[test]
fn a_published_documents_continuation_reads_the_member_its_first_page_read() {
    let k = fragmented_head_world(5_000);
    let reads = Reads(&k);
    let whole = [vspan(1, 1, 5_001)];
    let first = reads.image_page(&pdoc(), &whole, false, None).expect("a first page");
    let next = first.next.clone().expect("a go-on");
    assert_eq!(next.surface, phead(), "the head the bare address floated to");

    let (new_head, _) = Vstream::new(&k)
        .version(PrincipalId(1), &pdoc(), None)
        .expect("the owner versions its published document again");
    seed_published_content(&k, &pdoc(), 1); // one more run, on the new head alone
    let snap = k.snapshot();
    assert_eq!(arranged(&snap, &new_head).len(), 5_001);
    assert_eq!(arranged(&snap, &phead()).len(), 5_000);

    let second = image_page_on(&snap, &pdoc(), &rest_of(1, 5_001, &next), false, Some(&next))
        .expect("the continuation is answered across the landing");
    assert_eq!(second.next, None);
    let read: Vec<Run> = first.runs.into_iter().chain(second.runs).collect();
    assert_eq!(read, arranged(&snap, &phead()), "the first page's member, whole");
    // A read begun now floats to the new head.
    let (now, _) = read_whole(&k, &pdoc(), 1, 5_001, false).expect("read whole");
    assert_eq!(now, arranged(&snap, &new_head));
}

/// A continuation of a version member, and one under `own`, are answered
/// across a landing: a member answers itself whatever lands after it, a
/// deposit standing past its end, and a published document's own arrangement
/// is frozen from its first version on.
#[test]
fn a_members_continuation_and_one_under_own_are_answered_across_a_landing() {
    // The member named itself, a deposit landing on it between its pages and
    // then a version pinning it.
    let k = fragmented_head_world(5_000);
    let reads = Reads(&k);
    let whole = [vspan(1, 1, 5_002)];
    let first = reads.image_page(&phead(), &whole, false, None).expect("a first page");
    let next = first.next.clone().expect("a go-on");
    assert_eq!(next.surface, phead());
    seed_published_content(&k, &pdoc(), 1); // lands past the head's end
    Vstream::new(&k)
        .version(PrincipalId(1), &pdoc(), None)
        .expect("the owner versions its published document again");
    seed_published_content(&k, &pdoc(), 1); // on the new head alone
    let second = reads
        .image_page(&phead(), &rest_of(1, 5_002, &next), false, Some(&next))
        .expect("a member's continuation is answered whatever has landed");
    let read: Vec<Run> = first.runs.into_iter().chain(second.runs).collect();
    assert_eq!(read, arranged(&k.snapshot(), &phead()), "its prefix never moved");
    assert_eq!(read.len(), 5_001, "the deposit that landed on it stands past its end");

    // A published document holding 5,000 runs of its own: a cross-owner
    // version of the draft, memberless, so its own arrangement is what its
    // readers answer from until its first version lands.
    let k = kernel_with_a_second_account();
    seed_content(&k, &doc1(), 9);
    place_runs(&k, &doc2(), std::iter::repeat_n(1, 5_000));
    let (published, _) = Vstream::new(&k)
        .version(PrincipalId(2), &doc2(), Some(true))
        .expect("the second account versions the draft as a published document");
    let reads = Reads(&k);
    let whole = [vspan(1, 1, 5_000)];
    let own_next = reads.image_page(&published, &whole, true, None).expect("a page").next;
    let own_next = own_next.expect("a go-on");
    let floated_next = reads.image_page(&published, &whole, false, None).expect("a page").next;
    assert_eq!(floated_next.as_ref(), Some(&own_next), "memberless, it is its own surface");
    let own = arranged(&k.snapshot(), &published);

    let (member, _) = Vstream::new(&k)
        .version(PrincipalId(2), &published, None)
        .expect("its owner versions it");
    seed_published_content(&k, &published, 1); // on the member alone
    let snap = k.snapshot();
    assert_eq!(arranged(&snap, &published), own, "its own arrangement is frozen");
    assert_eq!(arranged(&snap, &member).len(), 5_001);
    let rest = rest_of(1, 5_000, &own_next);
    for own_asked in [true, false] {
        let page = image_page_on(&snap, &published, &rest, own_asked, Some(&own_next))
            .expect("the continuation is answered from the arrangement it names");
        assert_eq!(page.runs, own[MAX_IMAGE_RUNS..], "own {own_asked}");
        assert_eq!(page.next, None);
    }
}

/// A continuation is held to its go-on: the arrangement it names is the
/// document's own or, for a read that floats, a registered member of the
/// bare published document's own chain; its region begins where the go-on
/// says the rest does; and the document and region gates come first.
#[test]
fn a_continuation_is_held_to_the_arrangement_and_the_place_its_go_on_names() {
    let k = fragmented_head_world(5_000);
    seed_content(&k, &doc1(), 9);
    place_runs(&k, &doc2(), std::iter::repeat_n(1, 5_000));
    Vstream::new(&k)
        .version(PrincipalId(1), &pdoc(), None)
        .expect("a second member");
    let snap = k.snapshot();
    let whole = [vspan(1, 1, 5_000)];
    let page = |d: &Address, own: bool| {
        image_page_on(&snap, d, &whole, own, None).expect("a page").next.expect("a go-on")
    };
    let asked = |d: &Address, region: &[Span], own: bool, cur: &GoOn| {
        image_page_on(&snap, d, region, own, Some(cur)).map(|page| page.runs.len())
    };
    let draft = page(&doc2(), false);
    let member = page(&phead(), false);
    let rest = rest_of(1, 5_000, &draft);

    // The control: each go-on continues its own read, and a pinned member's
    // continues the bare document's.
    assert_eq!(asked(&doc2(), &rest, false, &draft), Ok(904));
    assert_eq!(asked(&phead(), &rest, false, &member), Ok(904));
    assert_eq!(asked(&pdoc(), &rest, false, &member), Ok(904));

    let named = |surface: Address| GoOn { surface, ..draft.clone() };
    let second_member = a(&[1, 0, 1, 0, nth_doc(3), 2]);
    let refused: [(&str, Address, bool, GoOn); 7] = [
        ("another document's arrangement", doc2(), false, named(doc1())),
        ("a member, under `own`", pdoc(), true, member.clone()),
        ("a member, for a member", second_member, false, member.clone()),
        ("a member no version minted", pdoc(), false, named(a(&[1, 0, 1, 0, nth_doc(3), 9]))),
        ("a daughter chain's member", pdoc(), false, named(a(&[1, 0, 1, 0, nth_doc(3), 1, 1]))),
        ("a member, for a private document", doc2(), false, named(a(&[1, 0, 1, 0, nth_doc(2), 1]))),
        ("an element of the document", doc2(), false, named(ca2(1))),
    ];
    for (what, d, own, cur) in &refused {
        assert_eq!(asked(d, &rest, *own, cur), Err(QueryError::BadRegion), "{what}");
    }

    // The region goes on where the go-on says: not before, not after, and
    // not nowhere.
    for region in [&[vspan(1, MAX, 904)][..], &[vspan(1, MAX + 2, 903)], &[]] {
        assert_eq!(asked(&doc2(), region, false, &draft), Err(QueryError::BadRegion), "{region:?}");
    }
    // The gates come first, as on a first page.
    assert_eq!(
        asked(&unregistered_doc(), &rest, false, &draft),
        Err(QueryError::DocNotRegistered)
    );
    assert_eq!(asked(&doc2(), &[vspan(2, 1, 1)], false, &draft), Err(QueryError::BadRegion));
}

/// Several spans are paged in region order: the page ends where the budget
/// does, and the go-on names an ordinal of the span the first run not
/// answered belongs to — the start of the next span where the page ended at
/// a span's end.
#[test]
fn several_spans_are_paged_in_region_order() {
    let k = draft_of(3_000);
    let snap = k.snapshot();
    let all = arranged(&snap, &doc2());
    // The draft twice over: the page holds it once and 1,096 runs more.
    let twice = [vspan(1, 1, 3_000), vspan(1, 1, 3_000)];
    assert_eq!(image_on(&snap, &doc2(), &twice), Err(QueryError::ImageTooLarge));
    let first = image_page_on(&snap, &doc2(), &twice, false, None).expect("a first page");
    let cut = MAX_IMAGE_RUNS - 3_000;
    assert_eq!(first.runs[..3_000], all[..]);
    assert_eq!(first.runs[3_000..], all[..cut]);
    let next = first.next.expect("a go-on");
    assert_eq!(next.at, n(cut as u32 + 1), "an ordinal of the second span");
    let second = image_page_on(&snap, &doc2(), &rest_of(1, 3_000, &next), false, Some(&next))
        .expect("the continuation: the rest of the span the page stopped in");
    assert_eq!((second.runs, second.next), (all[cut..].to_vec(), None));

    // A page that ends with its span: the rest begins at the next span.
    let k = draft_of(5_000);
    let snap = k.snapshot();
    let all = arranged(&snap, &doc2());
    let split = [vspan(1, 1, MAX), vspan(1, MAX + 101, 800)];
    let first = image_page_on(&snap, &doc2(), &split, false, None).expect("a first page");
    assert_eq!(first.runs, all[..MAX_IMAGE_RUNS]);
    let next = first.next.expect("a go-on");
    assert_eq!(next.at, n(MAX + 101), "the next span's own start");
    let second = image_page_on(&snap, &doc2(), &split[1..], false, Some(&next))
        .expect("the continuation: the spans after it");
    assert_eq!((second.runs, second.next), (all[MAX_IMAGE_RUNS + 100..][..800].to_vec(), None));
}

/// The walk's square still refuses the paged image, first page and
/// continuation alike: a region whose walk of the run-list is past the
/// square of the run budget is refused though it resolves few runs or none.
#[test]
fn the_walks_square_still_refuses_the_paged_image() {
    let k = draft_of(MAX + 1);
    let reads = Reads(&k);
    // `MAX` spans, each one position: the draft's last, and one past its end.
    let flat_at_end: Vec<Span> = vec![vspan(1, MAX + 1, 1); MAX_IMAGE_RUNS];
    let past_end: Vec<Span> = vec![vspan(1, MAX + 2, 1); MAX_IMAGE_RUNS];
    for region in [&flat_at_end, &past_end] {
        for own in [false, true] {
            assert_eq!(
                reads.image_page(&doc2(), region, own, None),
                Err(QueryError::ImageTooLarge)
            );
        }
    }
    assert_eq!(
        reads.image_page(&doc2(), &flat_at_end[..1], false, None).map(|page| page.runs.len()),
        Ok(1),
        "one walk is never refused for its reach"
    );
    let next = reads.image_page(&doc2(), &[vspan(1, 1, MAX + 1)], false, None).expect("a page");
    let next = next.next.expect("a go-on");
    assert_eq!(
        reads.image_page(&doc2(), &flat_at_end, false, Some(&next)),
        Err(QueryError::ImageTooLarge),
        "a continuation's walk is priced as a first page's"
    );
}

/// The region family keeps its refusal past the run budget: `image_on`
/// refuses the region the paged image answers, and `find_links_v` and
/// `count_v`, which read through it, are refused with it — never answered
/// the links of a first page as the whole region's.
#[test]
fn the_region_family_keeps_its_refusal_past_the_run_budget() {
    let k = draft_of(5_000);
    // One link reaching the draft's every position: doc1's first is the word
    // each of its runs places.
    let store = LinkWriter::new(&k, &EVERYONE);
    let touching = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let snap = k.snapshot();
    let whole = [vspan(1, 1, 5_000)];
    assert_eq!(image_on(&snap, &doc2(), &whole), Err(QueryError::ImageTooLarge));
    assert_eq!(
        findlinks_v_on(&snap, &doc2(), &whole, &every_home),
        Err(QueryError::ImageTooLarge)
    );
    assert_eq!(count_v_on(&snap, &doc2(), &whole, &every_home), Err(QueryError::ImageTooLarge));
    assert!(image_page_on(&snap, &doc2(), &whole, false, None).is_ok_and(|p| p.next.is_some()));
    // Within the budget the family answers as it did.
    let part = [vspan(1, 1, MAX)];
    assert_eq!(image_on(&snap, &doc2(), &part).map(|runs| runs.len()), Ok(MAX_IMAGE_RUNS));
    assert_eq!(findlinks_v_on(&snap, &doc2(), &part, &every_home), Ok(vec![touching]));
}

/// A page costs its own runs whatever the region resolves past it: one span
/// across the draft at two run counts past the budget ends its page at the
/// same pulled run over both, so it asks the same heap bytes of both, and
/// the runs past that one are never built.
#[test]
fn a_page_resolves_no_run_past_the_one_that_ends_it() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let (fewer, more) = doc2_past_the_run_budget_at_two_run_counts(&k);
    let region = [vspan(1, 1, 2 * MAX)];
    let heap_of = |snap: &Snapshot<World>| -> u64 {
        let (page, bytes) =
            settled_heap_bytes(|| image_page_on(snap, &doc2(), &region, false, None));
        let page = page.expect("a page");
        assert_eq!((page.runs.len(), page.next.is_some()), (MAX_IMAGE_RUNS, true));
        bytes
    };
    assert_eq!(heap_of(&more), heap_of(&fewer), "no run past the page's end is built");
}
