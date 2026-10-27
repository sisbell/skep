use super::*;

/// The merge unions its sources in order and emits each position once.
#[test]
fn the_merge_dedups_by_position_across_every_source() {
    let a = [1u64, 4, 9];
    let b = [4u64, 5, 9, 12];
    let c: [u64; 0] = [];
    let sources: Vec<Box<dyn Iterator<Item = u64> + '_>> = vec![
        Box::new(a.iter().copied()),
        Box::new(b.iter().copied()),
        Box::new(c.iter().copied()),
        Box::new(a.iter().copied()),
    ];
    let out: Vec<u64> = Merge::new(sources).collect();
    assert_eq!(out, vec![1, 4, 5, 9, 12]);
}

/// The descendant range is the owner accounts strictly beneath.
///
/// It holds those beneath the requester's own, and nothing else: its own
/// stream is keyed beside it and never ranged, a sibling's is past the
/// cut, and containment is by component — `1.0.21` is no account under
/// `1.0.2`, though its text extends it.
#[test]
fn the_descendant_range_is_the_owner_accounts_strictly_beneath() {
    let a = |s: &str| parse_dotted(s).expect("a test address");
    let streams: BTreeMap<Address, Vec<u64>> =
        ["1.0.2", "1.0.2.1", "1.0.2.1.1", "1.0.2.2", "1.0.3", "1.0.21"]
            .iter()
            .zip(1u64..)
            .map(|(owner, at)| (a(owner), vec![at]))
            .collect();
    let beneath = |account: &str| -> Vec<String> {
        streams_beneath(&streams, &a(account)).map(|(owner, _)| owner.to_string()).collect()
    };
    assert_eq!(beneath("1.0.2"), ["1.0.2.1", "1.0.2.1.1", "1.0.2.2"]);
    assert_eq!(beneath("1.0.2.1"), ["1.0.2.1.1"], "the middle of a chain ranges what is below it");
    assert!(beneath("1.0.2.2").is_empty() && beneath("1.0.3").is_empty(), "a leaf ranges nothing");
    // The range hands back each stream it admits, not merely its key.
    let middle = a("1.0.2.1");
    let positions: Vec<&[u64]> = streams_beneath(&streams, &middle).map(|(_, p)| p).collect();
    assert_eq!(positions, [&[3u64][..]]);
}

/// A list starts at its first member at or above the fence.
///
/// The fence is the one every slice-backed source is narrowed by, and the
/// reason a page never carries a position at or below `since`.
#[test]
fn a_list_starts_at_the_fence() {
    let s = [3u64, 7, 8, 20];
    assert_eq!(at_or_above(&s, 8).collect::<Vec<_>>(), vec![8, 20]);
    assert_eq!(at_or_above(&s, 9).collect::<Vec<_>>(), vec![20]);
    assert_eq!(at_or_above(&s, 21).count(), 0);
    assert_eq!(at_or_above(&s, 0).count(), 4);
}

/// A position is placed in an ascending list once, wherever it lands.
///
/// The record step pushes above the last; the walk's landings place a
/// position the open found unsorted or uncovered below the ones recorded
/// while the walk ran; a member is never repeated — the invariant
/// [`at_or_above`]'s `partition_point` reads.
#[test]
fn a_position_is_placed_in_order_once() {
    let mut list = vec![3u64, 7, 20];
    push_in_order(&mut list, 25);
    assert_eq!(list, [3, 7, 20, 25], "above the last: pushed");
    push_in_order(&mut list, 25);
    assert_eq!(list, [3, 7, 20, 25], "the last again: held once");
    push_in_order(&mut list, 8);
    assert_eq!(list, [3, 7, 8, 20, 25], "below the window: placed at its rank");
    push_in_order(&mut list, 7);
    assert_eq!(list, [3, 7, 8, 20, 25], "a member below the last: not repeated");
    push_in_order(&mut list, 1);
    assert_eq!(list, [1, 3, 7, 8, 20, 25], "below every member: first");
    let mut empty: Vec<u64> = Vec::new();
    push_in_order(&mut empty, 4);
    assert_eq!(empty, [4], "an empty list takes its first");
}

/// A derived cut says it is re-derived, and a failure names its file.
///
/// Row 9's words for a derived file are the head with the last trusted
/// position and the bytes, then that the cut part is re-derived — and
/// the open's failures name their file ahead of the OS's text, the kind
/// kept.
#[test]
fn a_derived_cut_says_it_is_re_derived_and_a_failure_names_its_file() {
    let cut = Cut {
        valid_end: 120,
        len: 131,
        trusted: 32,
        first: Some(33),
        whole_after: None,
        fence_alone: false,
    };
    assert_eq!(
        DerivedCutLine { name: INDEX_FILE, cut }.to_string(),
        "feed-index.log: trust ends at position 32 (byte 120 of 131); the 11 bytes after it \
         are cut; the cut part is re-derived"
    );
    let refused = with_file(MASKED_FILE)(io::Error::new(io::ErrorKind::StorageFull, "no room"));
    assert_eq!(refused.kind(), io::ErrorKind::StorageFull, "the kind is kept");
    assert_eq!(refused.to_string(), "feed-masked.log: no room");
}

/// The walk's sort lines and the open's own lines render at fixed figures.
///
/// They are the walk thread's three for the bare positions the index lost
/// (m15) — the `open:` line ahead of the cost, the `progress:` line while
/// it sorts and the `landing:` line once done, with the lock's span — the
/// journal's refusal of that classification in the kernel's words, the hole
/// the files opened with, where one stands, with and without a line held
/// above it, and, last, how far back `/changes` answers, what waits on the
/// walk where anything pends — the region, the set, or both — and how long
/// the open took.
#[test]
fn the_walks_sort_lines_and_the_opens_lines_render_the_ruled_words() {
    assert_eq!(
        BareClassificationLine { coverage: 12, positions: 3, reconstructions: 4 }.to_string(),
        "feed-index.log covers to position 12: 3 bare positions are classified from the \
         journal behind the listener, 4 world reconstructions in all"
    );
    assert_eq!(
        BareClassifyingLine { position: 2_040, done: 1_000, of: 3_000, elapsed_ms: 9_800 }
            .to_string(),
        "feed-index.log: the bare classification at position 2040, 1000 of 3000, 9800 ms in"
    );
    let classified = BareClassifiedLine {
        classified: 2_999,
        of: 3_000,
        reconstructions: 3_000,
        elapsed_ms: 29_400,
        held_ms: 12,
    };
    assert_eq!(
        classified.to_string(),
        "feed-index.log: 2999 of 3000 bare positions classified from the journal, 3000 world \
         reconstructions, in 29400 ms; the landing held the change feed's lock 12 ms"
    );
    let reach = |pending| FeedOpenLine {
        floor: Some(2_049),
        head: 3_100,
        entries: 1_052,
        bare: 6,
        pending,
        elapsed_ms: 41,
    };
    let region = Some((3_000, 3_100));
    let set = Some(Unsorted { count: 6, first: 2_100, last: 2_900 });
    assert_eq!(
        reach(FeedPending::default()).to_string(),
        "the change feed answers from position 2049 to position 3100: commits.log 1052 \
         entries, 6 of them bare, in 41 ms"
    );
    assert_eq!(
        reach(FeedPending { region, unsorted: None }).to_string(),
        "the change feed answers from position 2049 to position 3100: commits.log 1052 \
         entries, 6 of them bare; positions (3000, 3100] wait on the walk, in 41 ms"
    );
    assert_eq!(
        reach(FeedPending { region: None, unsorted: set }).to_string(),
        "the change feed answers from position 2049 to position 3100: commits.log 1052 \
         entries, 6 of them bare; 6 bare positions the index lost wait on the walk, in 41 ms"
    );
    assert_eq!(
        reach(FeedPending { region, unsorted: set }).to_string(),
        "the change feed answers from position 2049 to position 3100: commits.log 1052 \
         entries, 6 of them bare; positions (3000, 3100] and 6 bare positions the index lost \
         wait on the walk, in 41 ms"
    );
    let empty = FeedOpenLine {
        floor: None,
        head: 0,
        entries: 0,
        bare: 0,
        pending: FeedPending::default(),
        elapsed_ms: 2,
    };
    assert_eq!(
        empty.to_string(),
        "the change feed answers no position yet, the head at position 0, in 2 ms"
    );
    let refused = ClassificationRefusedLine {
        positions: 3,
        first: 13,
        account: "journal corrupt at rest".into(),
    };
    assert_eq!(
        refused.to_string(),
        "feed-index.log: the journal refused to classify 3 bare positions, the first at \
         position 13 (journal corrupt at rest): each is served to every class, its position \
         alone"
    );
    assert_eq!(
        OpenHoleLine { fence: 2048, floor: Some(2049) }.to_string(),
        "the change feed's files hold no line at or below position 2048: an earlier build's \
         compaction, or a walk the journal refused, left the fence there; /changes answers 410 \
         history_reclaimed for every since below position 2049, the first line held"
    );
    assert_eq!(
        OpenHoleLine { fence: 2048, floor: None }.to_string(),
        "the change feed's files hold no line at or below position 2048: an earlier build's \
         compaction, or a walk the journal refused, left the fence there; no line is held above \
         it"
    );
}

/// What the walk has yet to land is two states, described as one phrase.
///
/// The region, the set, or both; empty where neither pends — what the
/// open's line, the dead walk's lines and a checkpoint's landing line say.
#[test]
fn what_pends_is_described_by_its_two_states() {
    let set = Some(Unsorted { count: 4, first: 10, last: 40 });
    assert!(FeedPending::default().is_empty());
    assert_eq!(FeedPending::default().to_string(), "");
    let region_only = FeedPending { region: Some((9, 12)), unsorted: None };
    assert!(!region_only.is_empty());
    assert_eq!(region_only.to_string(), "positions (9, 12]");
    let set_only = FeedPending { region: None, unsorted: set };
    assert!(!set_only.is_empty());
    assert_eq!(set_only.to_string(), "4 bare positions the index lost");
    let both = FeedPending { region: Some((9, 12)), unsorted: set };
    assert_eq!(both.to_string(), "positions (9, 12] and 4 bare positions the index lost");
    assert_eq!(
        SortFigures { of: 7, refused: 2, reconstructions: 9, elapsed_ms: 3 }.classified(),
        5
    );
}
