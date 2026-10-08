use serde_json::json;

use super::*;

/// An op changed the golden-side world unless its recording client
/// crashed or the recording marks it failed.
#[test]
fn an_op_takes_effect_unless_the_client_crashed_or_the_recording_says_it_failed() {
    assert!(took_effect(&json!({"op": "insert", "text": "A"})));
    assert!(took_effect(&json!({"op": "insert", "text": "A", "error": "N/A"})));
    assert!(!took_effect(&json!({"op": "create_version", "error": "request failed (?)"})));
    assert!(!took_effect(&json!({"op": "insert", "status": "failed"})));
    assert!(!took_effect(&json!({
        "op": "rearrange",
        "result": "FAILED: 'XuSession' object has no attribute 'rearrange'",
    })));
}

/// A change reaches the shadow when the recording made it or the
/// pre-pass inferred it — never when the recording says it failed.
#[test]
fn a_made_or_inferred_change_reaches_the_shadow() {
    let made = Effect::of(&json!({"op": "insert", "text": "A"}));
    let failed = Effect::of(&json!({"op": "insert", "status": "failed"}));
    assert_eq!((made, failed), (Effect::Made, Effect::NotMade));
    assert!(made.reaches_shadow() && Effect::Inferred.reaches_shadow());
    assert!(!failed.reaches_shadow());
}

/// The recorded vspanset pads an insert that appends, never one its own
/// post-state lands mid-document: there the recorded content, not the
/// width, is the authority.
#[test]
fn only_an_appended_insert_is_padded_to_the_recorded_vspanset() {
    const DOC: &str = "1.1.0.1.0.1";
    let mut shadow = Shadow::new();
    shadow.create_doc(DOC, None);
    shadow.insert(DOC, 1, b"AA");
    let probe =
        json!({"op": "vspanset", "doc": DOC, "result": [{"start": "1.1", "width": "0.6"}]});
    let landing = |ord: u64, bytes: &[u8], appended: bool| InsertLanding {
        doc: DOC.into(),
        at: VPoint::content(ord),
        bytes: bytes.to_vec(),
        appended,
    };

    let append = [json!({"op": "insert", "doc": DOC, "text": "BBB"}), probe.clone()];
    let mut adaptations = Vec::new();
    let landed = resolve_insert(&append, 0, &shadow, DOC, &mut adaptations);
    assert_eq!(landed, Ok(landing(3, b"BBB ", true)));
    assert_eq!(adaptations, ["position-end", "insert-padded-to-recorded-vspanset:+1"]);

    let pinned =
        [json!({"op": "insert", "doc": DOC, "text": "BBB", "result": ["ABBBA"]}), probe];
    let mut adaptations = Vec::new();
    let landed = resolve_insert(&pinned, 0, &shadow, DOC, &mut adaptations);
    assert_eq!(landed, Ok(landing(2, b"BBB", false)));
    assert_eq!(adaptations, ["insert-position-from-post-state"]);

    let lost = json!({"op": "insert", "doc": DOC, "text": "C", "position": "somewhere"});
    let lone = std::slice::from_ref(&lost);
    let err = resolve_insert(lone, 0, &shadow, DOC, &mut Vec::new());
    assert_eq!(err, Err("insert position `somewhere` is not groundable".into()));
}

/// The recorded vspanset pads an appended insert by its surplus — never
/// when links seated between them explain it (the version link
/// carryover, ruling 15), and never past two elements.
#[test]
fn a_pad_is_declined_when_links_explain_the_surplus_and_bounded_at_two() {
    const DOC: &str = "1.1.0.1.0.1";
    let mut shadow = Shadow::new();
    shadow.create_doc(DOC, None);
    let insert = json!({"op": "insert", "doc": DOC, "text": "ABC"});
    let probe = |w: &str| {
        json!({"op": "vspanset", "doc": DOC, "result": [{"start": "1.1", "width": w}]})
    };
    let link = json!({"op": "create_link", "result": "1.1.0.1.0.1.0.2.1"});
    let bytes = |ops: &[Value]| {
        let landed = resolve_insert(ops, 0, &shadow, DOC, &mut Vec::new());
        landed.map(|l| String::from_utf8_lossy(&l.bytes).into_owned())
    };
    assert_eq!(bytes(&[insert.clone(), probe("0.4")]).as_deref(), Ok("ABC "));
    assert_eq!(bytes(&[insert.clone(), link, probe("0.4")]).as_deref(), Ok("ABC"));
    assert_eq!(bytes(&[insert, probe("0.6")]).as_deref(), Ok("ABC"));
}

/// A forward scan reads a later read's reply as the play pass reads it
/// (`fields::recorded_content`): an `expected_contents` array, or a list the
/// recording client stringified under `after`, is the document's content
/// after the write before it.
#[test]
fn a_forward_scan_reads_a_reply_as_the_play_pass_reads_it() {
    const DOC: &str = "1.1.0.1.0.1";
    let mut shadow = Shadow::new();
    shadow.create_doc(DOC, None);
    shadow.insert(DOC, 1, b"Hello");
    let probed = [
        json!({"op": "insert", "doc": DOC, "text": "!"}),
        json!({"op": "retrieve_contents", "doc": DOC, "expected_contents": ["Hello!"]}),
    ];
    assert_eq!(next_content_probe(&probed, 0, &shadow, DOC).as_deref(), Some("Hello!"));
    let unchanged = [
        json!({"op": "delete", "doc": DOC, "span": "llo"}),
        json!({"op": "retrieve", "after": "['Hello']"}),
    ];
    assert!(delete_is_noop(&unchanged, 0, &shadow, DOC));
}

/// A version the recording made is one udanax carried out before the op
/// that asks — never one recorded failed, and never the op's own.
#[test]
fn a_version_was_made_only_by_an_earlier_create_version_that_took_effect() {
    let ops = [
        json!({"op": "create_version", "from": "source", "error": "request failed (?)"}),
        json!({"op": "compare_versions"}),
        json!({"op": "create_version", "from": "source", "result": "1.1.0.1.0.1.1"}),
        json!({"op": "compare_versions"}),
    ];
    assert!(!version_made_before(&ops, 1), "a failed version made nothing");
    assert!(!version_made_before(&ops, 2), "an op's own version is not before it");
    assert!(version_made_before(&ops, 3));
}

/// Every string over {A, B} up to `max` bytes, shortest first.
fn strings(max: usize) -> Vec<Vec<u8>> {
    let mut all = vec![Vec::new()];
    for len in 1..=max {
        for bits in 0..1u32 << len {
            all.push((0..len).map(|k| if bits >> k & 1 == 0 { b'A' } else { b'B' }).collect());
        }
    }
    all
}

/// The gap diff trying every start, each checked whole — the reference
/// the narrowed scan must reproduce.
fn gap_diff_every_start(pre: &[u8], post: &[u8]) -> Option<VRegion> {
    if post.len() >= pre.len() {
        return None;
    }
    let width = pre.len() - post.len();
    let mut a = pre.iter().zip(post).take_while(|(x, y)| x == y).count();
    loop {
        if pre[a + width..] == post[a..] {
            return Some(VPoint::content(a as u64 + 1).region(width as u64));
        }
        if a == 0 {
            return None;
        }
        a -= 1;
    }
}

/// The insert gap trying every ordinal, each checked whole — the
/// reference the narrowed scan must reproduce.
fn insert_gap_every_ordinal(pre: &[u8], text: &[u8], post: &[u8]) -> Option<u64> {
    if post.len() != pre.len() + text.len() {
        return None;
    }
    let n = text.len();
    (0..=pre.len())
        .find(|&k| {
            post[..k] == pre[..k] && post[k..k + n] == *text && post[k + n..] == pre[k..]
        })
        .map(|k| k as u64 + 1)
}

/// The narrowed gap scans answer exactly as the full scans do, over
/// every pair of strings on {A, B} short enough to enumerate — single
/// deletions and insertions, and every pair no single gap explains.
#[test]
fn the_narrowed_gap_scans_answer_as_the_full_scans_do() {
    let short = strings(6);
    for pre in &short {
        for post in &short {
            let (want, got) = (gap_diff_every_start(pre, post), single_gap_diff(pre, post));
            assert_eq!(got, want, "delete {pre:?} → {post:?}");
        }
    }
    let posts = strings(7);
    for pre in &strings(5) {
        for text in strings(2).iter().filter(|t| !t.is_empty()) {
            for post in &posts {
                let want = insert_gap_every_ordinal(pre, text, post);
                assert_eq!(insert_gap(pre, text, post), want, "{pre:?} + {text:?} → {post:?}");
            }
        }
    }
}

/// A delete grounds its region as the recording gave it, and says how: a
/// start sent as a V-position carries no tag; one the recording described
/// carries the position's tag, a numeric description the description's —
/// and only a start found by searching the shadow for text leaves the
/// position unpinned, an undo trying the document's end first.
#[test]
fn a_described_delete_is_tagged_and_pinned_unless_text_found() {
    const DOC: &str = "1.1.0.1.0.1";
    let mut shadow = Shadow::new();
    shadow.create_doc(DOC, None);
    shadow.insert(DOC, 1, b"Hello world");
    let delete = |mut op: Value| {
        op["op"] = json!("delete");
        op["doc"] = json!(DOC);
        let (region, how) = resolve_delete_span(&[op], 0, &shadow, DOC).expect("a region");
        (region, how.tag(), how.position_pinned())
    };
    let five = |ord: u64| VPoint::content(ord).region(5);
    let sent = delete(json!({"start": "1.2", "width": "0.5"}));
    assert_eq!(sent, (five(2), None, true));
    let after = delete(json!({"start": "after Hello", "width": "0.5"}));
    assert_eq!(after, (five(6), Some("position-after-text"), false));
    let numbered = delete(json!({"start": "position 1", "width": "0.5"}));
    assert_eq!(numbered, (five(1), Some("position-from-description"), true));
    let described = delete(json!({"span": "1.1 length 3"}));
    assert_eq!(described, (VPoint::content(1).region(3), Some("span-from-description"), true));
}

/// A vcopy copies into the document its recording names — a position
/// marker naming the first source's — and a reference that names nothing
/// is refused, never re-aimed; one naming none aims by the probe that holds
/// the copied bytes, a document other than the source's preferred, and
/// otherwise leaves the aim to each pass.
#[test]
fn a_vcopy_copies_into_the_document_its_recording_names() {
    const SOURCE: &str = "1.1.0.1.0.1";
    const OTHER: &str = "1.1.0.1.0.2";
    let mut shadow = Shadow::new();
    shadow.create_doc(SOURCE, Some("source"));
    shadow.insert(SOURCE, 1, b"Hello");
    shadow.create_doc(OTHER, Some("other"));
    let sources = [CopySource { doc: SOURCE.into(), region: VPoint::content(1).region(5) }];
    let aimed = |ops: &[Value]| {
        let mut adaptations = Vec::new();
        let dest = vcopy_destination(ops, 0, &shadow, &sources, &mut adaptations);
        (dest, adaptations)
    };
    let untagged = |dest: Result<Option<String>, String>| (dest, Vec::<String>::new());
    let marker = [json!({"op": "vcopy", "to": "end of doc"})];
    assert_eq!(aimed(&marker), untagged(Ok(Some(SOURCE.into()))));
    assert_eq!(aimed(&[json!({"op": "vcopy", "to": "other"})]), untagged(Ok(Some(OTHER.into()))));
    let ghost = Err("vcopy destination `ghost` resolves to nothing".to_string());
    assert_eq!(aimed(&[json!({"op": "vcopy", "to": "ghost"})]), untagged(ghost.clone()));
    assert_eq!(aimed(&[json!({"op": "vcopy", "doc": "ghost"})]), untagged(ghost));

    let probe = |doc: &str, text: &str| json!({"op": "retrieve", "doc": doc, "result": [text]});
    let bare = json!({"op": "vcopy"});
    let evidenced = [bare.clone(), probe("source", "HelloHello"), probe("other", "Hello")];
    let tagged = (Ok(Some(OTHER.to_string())), vec!["vcopy-dest-from-evidence".to_string()]);
    assert_eq!(aimed(&evidenced), tagged);
    assert_eq!(aimed(&[bare]), untagged(Ok(None)));
}

/// A vcopy lands at the position it records, at ordinal 1 when it copies to
/// the start, and otherwise at the end, which each pass reads off its own
/// shadow; a position no content ordinal grounds is refused.
#[test]
fn a_vcopy_lands_at_its_recorded_position_or_the_end() {
    const DOC: &str = "1.1.0.1.0.1";
    let mut shadow = Shadow::new();
    shadow.create_doc(DOC, None);
    shadow.insert(DOC, 1, b"Hello");
    let landed = |op: Value| {
        let mut adaptations = Vec::new();
        let at = vcopy_ordinal(&op, &shadow, DOC, &mut adaptations);
        (at, adaptations)
    };
    let at = |ord: Option<u64>, tags: &[&str]| {
        (Ok(ord), tags.iter().map(|t| t.to_string()).collect::<Vec<_>>())
    };
    assert_eq!(landed(json!({"op": "vcopy", "at": "1.3"})), at(Some(3), &[]));
    let after = json!({"op": "vcopy", "at": "after He"});
    assert_eq!(landed(after), at(Some(3), &["position-after-text"]));
    let start = json!({"op": "vcopy", "to": " Start of doc"});
    assert_eq!(landed(start), at(Some(1), &["position-start"]));
    assert_eq!(landed(json!({"op": "vcopy", "to": "end"})), at(None, &["position-end"]));
    let link_subspace = landed(json!({"op": "vcopy", "at": "2.1"}));
    assert_eq!(link_subspace.0, Err("vcopy position `2.1` is not groundable".to_string()));
}
